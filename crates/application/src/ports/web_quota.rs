//! 0.4.0 Web Application Runtime（§42.2）——per-Component HTTP quotas /
//! backpressure。
//!
//! per-Component HTTP quotas / backpressure（§42.2）在 bridge 层执行：
//! 超配额以确定 HTTP 语义拒绝（429 / 503），不进 guest 错误空间，guest 侧
//! 无背压回调面（actions.wit / route-dispatch.wit 明文；polling / realtime
//! 形态顺延，§42.3）。配额是 **per-Component**（按安装实例隔离），与 0.1
//! 的 `max_actions_per_minute`（每安装独立窗口）同一隔离语义。
//!
//! 本 port 表达三个上限（§15.2 有界语义 / §7.4 预算）：
//! - **速率**：固定窗口（分钟）请求数上限（[`WebQuotaLimits::max_requests_per_minute`]）；
//! - **并发**：同时 in-flight 的调用数上限（[`WebQuotaLimits::max_concurrent`]）；
//! - **队列**：已准入但尚未开始执行的调用数上限（[`WebQuotaLimits::max_queued`]；
//!   异步调用方（HTTP 层）的 bounded 队列，§15.2）。
//!
//! 准入形态：[`WebQuotaPort::admit`] 返回 [`WebQuotaGuard`]（RAII——
//! 守卫生命周期内占有一个配额槽位；调用结束后 drop 释放）。同步分发型
//! 调用方在 guest 调用开始前调用 [`WebQuotaGuard::begin`]（队列槽 → 执行
//! 槽）；异步调用方在等待实例租约期间持有守卫（队列槽）。
//!
//! 拒绝闭集 [`WebQuotaDenied`] 是封闭 typed（§14.1）：HTTP 层把
//! `RateLimited` / `OverConcurrency` / `OverQueue` 映射为确定 HTTP 语义
//! （429 / 503），不进 guest 错误空间。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use operune_domain::{ComponentVersion, InstallationId};

/// 固定速率窗口长度（秒；对齐 0.1 `max_actions_per_minute` 的窗口语义）。
const RATE_WINDOW_SECS: u64 = 60;

/// per-Component HTTP quota 上限（§42.2；全部上限必须为正，§13.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebQuotaLimits {
    /// 速率：固定窗口（分钟）内每个安装实例允许的请求数。
    pub max_requests_per_minute: u32,
    /// 并发：每个安装实例同时 in-flight 的调用数上限。
    pub max_concurrent: u32,
    /// 队列：每个安装实例已准入但未开始的调用数上限（bounded queue，
    /// §15.2）。
    pub max_queued: u32,
}

impl Default for WebQuotaLimits {
    fn default() -> Self {
        Self {
            max_requests_per_minute: 600,
            max_concurrent: 8,
            max_queued: 64,
        }
    }
}

impl WebQuotaLimits {
    /// 校验（validate-on-construct 精神，§13.3）：全部上限必须为正。
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_requests_per_minute == 0 {
            return Err("max_requests_per_minute must be non-zero");
        }
        if self.max_concurrent == 0 {
            return Err("max_concurrent must be non-zero");
        }
        if self.max_queued == 0 {
            return Err("max_queued must be non-zero");
        }
        Ok(())
    }
}

/// quota 准入的上下文（per-Component：按安装实例隔离计数，§42.2）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebQuotaContext {
    /// 绑定安装实例。
    pub installation_id: InstallationId,
    /// 绑定当前版本（§21.5 原子版本）。
    pub version: ComponentVersion,
}

/// quota 拒绝类别（§42.2：超配额以确定 HTTP 语义拒绝 429 / 503，不进
/// guest 错误空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebQuotaDenied {
    /// 超出速率上限（固定窗口；HTTP 429）。
    RateLimited,
    /// 超出并发上限（全部 in-flight + 队列槽已占满；HTTP 503）。
    OverConcurrency,
    /// 超出队列上限（bounded queue 已满，§15.2；HTTP 429）。
    OverQueue,
    /// 检查无法完成（配额状态锁异常等内部故障）。
    Unknown,
}

impl std::fmt::Display for WebQuotaDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::RateLimited => "web request rate limit exceeded",
            Self::OverConcurrency => "web request concurrency limit reached",
            Self::OverQueue => "web request queue is full",
            Self::Unknown => "web quota check failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for WebQuotaDenied {}

/// per-Component HTTP quota port（§42.2；HTTP 层注入实现完整链）。
pub trait WebQuotaPort: Send + Sync {
    /// 请求准入检查（§15.2 有界语义）。拒绝返回 [`WebQuotaDenied`]。
    ///
    /// 返回的 [`WebQuotaGuard`] 持有一个配额槽位：同步分发型调用方在
    /// guest 调用前调用 [`WebQuotaGuard::begin`]，调用结束后 drop 守卫
    ///（RAII 释放）。
    fn admit(&self, context: &WebQuotaContext) -> Result<WebQuotaGuard, WebQuotaDenied>;
}

/// 单安装实例的配额窗口状态（速率计数 + 并发/队列槽位）。
#[derive(Debug)]
struct QuotaWindow {
    /// 速率窗口起点（过期 → 重置计数，回收旧状态，保持有界）。
    start: Instant,
    /// 窗口内已准入请求数。
    count: u32,
    /// 已准入但尚未开始的调用数（队列槽）。
    queued: u32,
    /// 正在执行的调用数（执行槽）。
    in_flight: u32,
}

/// 准入守卫（§15.2 RAII）：持有期间占有一个配额槽位；`begin` 把队列槽
/// 转为执行槽；drop 释放。
#[derive(Debug)]
pub struct WebQuotaGuard {
    window: Arc<Mutex<QuotaWindow>>,
    /// 是否已 begin（队列槽 → 执行槽；drop 时按状态归还）。
    begun: AtomicBool,
}

impl WebQuotaGuard {
    /// 调用开始：队列槽 → 执行槽（同步分发型调用方在 guest 调用前调用）。
    pub fn begin(&self) {
        if self.begun.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Ok(mut window) = self.window.lock() {
            window.queued = window.queued.saturating_sub(1);
            window.in_flight = window.in_flight.saturating_add(1);
        }
    }
}

impl Drop for WebQuotaGuard {
    fn drop(&mut self) {
        if let Ok(mut window) = self.window.lock() {
            if self.begun.load(Ordering::Acquire) {
                window.in_flight = window.in_flight.saturating_sub(1);
            } else {
                window.queued = window.queued.saturating_sub(1);
            }
        }
    }
}

/// 默认进程内 quota 实现（速率 + 并发 + 队列；每安装独立窗口，§42.2
/// per-Component 语义）。
pub struct InProcessWebQuota {
    limits: WebQuotaLimits,
    /// 每安装实例的窗口（惰性创建；条目数有界 = 安装实例数有界）。
    windows: Mutex<HashMap<InstallationId, Arc<Mutex<QuotaWindow>>>>,
}

impl InProcessWebQuota {
    /// 构造（上限非法返回 `Err`，validate-on-construct，§13.3）。
    pub fn new(limits: WebQuotaLimits) -> Result<Self, &'static str> {
        limits.validate()?;
        Ok(Self {
            limits,
            windows: Mutex::new(HashMap::new()),
        })
    }
}

impl WebQuotaPort for InProcessWebQuota {
    fn admit(&self, context: &WebQuotaContext) -> Result<WebQuotaGuard, WebQuotaDenied> {
        let mut windows = self.windows.lock().map_err(|_| WebQuotaDenied::Unknown)?;
        let window = match windows.get(&context.installation_id) {
            Some(window) => Arc::clone(window),
            None => {
                let window = Arc::new(Mutex::new(QuotaWindow {
                    start: Instant::now(),
                    count: 0,
                    queued: 0,
                    in_flight: 0,
                }));
                windows.insert(context.installation_id, Arc::clone(&window));
                window
            }
        };
        {
            let mut state = window.lock().map_err(|_| WebQuotaDenied::Unknown)?;
            // 窗口过期 → 重置（回收旧窗口状态，保持有界；§15.2）。
            if Instant::now().duration_since(state.start) >= Duration::from_secs(RATE_WINDOW_SECS) {
                state.start = Instant::now();
                state.count = 0;
            }
            // 检查顺序（确定性 first-denial-wins）：速率 → 队列 → 并发。
            if state.count >= self.limits.max_requests_per_minute {
                return Err(WebQuotaDenied::RateLimited);
            }
            let active = state.in_flight.saturating_add(state.queued);
            if state.queued >= self.limits.max_queued {
                return Err(WebQuotaDenied::OverQueue);
            }
            if active >= self.limits.max_concurrent {
                return Err(WebQuotaDenied::OverConcurrency);
            }
            state.count = state.count.saturating_add(1);
            state.queued = state.queued.saturating_add(1);
        }
        Ok(WebQuotaGuard {
            window,
            begun: AtomicBool::new(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(installation: InstallationId) -> WebQuotaContext {
        WebQuotaContext {
            installation_id: installation,
            version: ComponentVersion::from_parts(1, 0, 0),
        }
    }

    #[test]
    fn limits_must_be_positive() {
        assert!(WebQuotaLimits::default().validate().is_ok());
        let zero_rate = WebQuotaLimits {
            max_requests_per_minute: 0,
            ..WebQuotaLimits::default()
        };
        assert!(zero_rate.validate().is_err());
        let zero_concurrent = WebQuotaLimits {
            max_concurrent: 0,
            ..WebQuotaLimits::default()
        };
        assert!(zero_concurrent.validate().is_err());
        let zero_queue = WebQuotaLimits {
            max_queued: 0,
            ..WebQuotaLimits::default()
        };
        assert!(zero_queue.validate().is_err());
    }

    #[test]
    fn rate_limit_denies_beyond_window() {
        // 速率：固定窗口每安装独立计数；超限确定拒绝（429 语义）。
        let quota = match InProcessWebQuota::new(WebQuotaLimits {
            max_requests_per_minute: 2,
            max_concurrent: 8,
            max_queued: 64,
        }) {
            Ok(quota) => quota,
            Err(_) => crate::test_support::test_failure("quota construction failed"),
        };
        let installation = InstallationId::new();
        for _ in 0..2 {
            let guard = quota.admit(&context(installation));
            assert!(guard.is_ok(), "admission within the rate limit");
        }
        assert!(
            matches!(
                quota.admit(&context(installation)),
                Err(WebQuotaDenied::RateLimited)
            ),
            "third admission must be rate limited"
        );
        // 不同安装实例互不影响（per-Component 隔离，§42.2）。
        let other = InstallationId::new();
        assert!(quota.admit(&context(other)).is_ok());
    }

    #[test]
    fn concurrency_limit_denies_when_all_slots_occupied() {
        let quota = match InProcessWebQuota::new(WebQuotaLimits {
            max_requests_per_minute: 100,
            max_concurrent: 2,
            max_queued: 64,
        }) {
            Ok(quota) => quota,
            Err(_) => crate::test_support::test_failure("quota construction failed"),
        };
        let installation = InstallationId::new();
        let first = match quota.admit(&context(installation)) {
            Ok(guard) => guard,
            Err(_) => crate::test_support::test_failure("first admission failed"),
        };
        first.begin();
        let second = match quota.admit(&context(installation)) {
            Ok(guard) => guard,
            Err(_) => crate::test_support::test_failure("second admission failed"),
        };
        assert!(
            matches!(
                quota.admit(&context(installation)),
                Err(WebQuotaDenied::OverConcurrency)
            ),
            "in-flight + queued at max_concurrent must deny admission"
        );
        drop(second);
        drop(first);
        // 守卫释放后槽位归还：后续准入成功（RAII，§15.2）。
        assert!(quota.admit(&context(installation)).is_ok());
    }

    #[test]
    fn queue_limit_denies_when_queue_is_full() {
        let quota = match InProcessWebQuota::new(WebQuotaLimits {
            max_requests_per_minute: 100,
            max_concurrent: 8,
            max_queued: 1,
        }) {
            Ok(quota) => quota,
            Err(_) => crate::test_support::test_failure("quota construction failed"),
        };
        let installation = InstallationId::new();
        let first = match quota.admit(&context(installation)) {
            Ok(guard) => guard,
            Err(_) => crate::test_support::test_failure("first admission failed"),
        };
        // 未 begin 的守卫占用队列槽（异步调用方等待实例租约的形态）。
        assert!(
            matches!(
                quota.admit(&context(installation)),
                Err(WebQuotaDenied::OverQueue)
            ),
            "queue full must deny admission"
        );
        drop(first);
        assert!(quota.admit(&context(installation)).is_ok());
    }

    #[test]
    fn begin_moves_queued_slot_to_in_flight() {
        // begin 后占用的是执行槽而非队列槽：max_queued=2 下 begin 后的
        // 二次准入取决于并发而非队列。
        let quota = match InProcessWebQuota::new(WebQuotaLimits {
            max_requests_per_minute: 100,
            max_concurrent: 2,
            max_queued: 2,
        }) {
            Ok(quota) => quota,
            Err(_) => crate::test_support::test_failure("quota construction failed"),
        };
        let installation = InstallationId::new();
        let first = match quota.admit(&context(installation)) {
            Ok(guard) => guard,
            Err(_) => crate::test_support::test_failure("first admission failed"),
        };
        first.begin();
        let second = quota.admit(&context(installation));
        assert!(second.is_ok(), "in-flight slot is not a queued slot");
        assert!(
            matches!(
                quota.admit(&context(installation)),
                Err(WebQuotaDenied::OverConcurrency)
            ),
            "with both slots occupied the next admission is denied by concurrency"
        );
    }

    #[test]
    fn begin_is_idempotent() {
        let quota = match InProcessWebQuota::new(WebQuotaLimits::default()) {
            Ok(quota) => quota,
            Err(_) => crate::test_support::test_failure("quota construction failed"),
        };
        let guard = match quota.admit(&context(InstallationId::new())) {
            Ok(guard) => guard,
            Err(_) => crate::test_support::test_failure("admission failed"),
        };
        guard.begin();
        guard.begin();
        drop(guard);
    }
}
