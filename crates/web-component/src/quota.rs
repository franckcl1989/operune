//! per-Component HTTP quotas / backpressure（§42.2；Core 在 bridge 层执行）。
//!
//! §42.2：per-Component HTTP quotas / backpressure 在 bridge 层执行——超
//! 配额以确定 HTTP 语义拒绝（429 / 503），不进 guest 错误空间，guest 侧
//! 无背压回调面（polling / realtime 形态顺延，§42.3）。本模块是 HTTP 层的
//! **每安装实例**配额门（安装实例 ≈ Component 的 Web 面，§21.3）：
//!
//! - **速率**：固定窗口限流（次/分钟，§15.2 有界语义；与 application 的
//!   `InProcessActionPolicy` 窗口语义一致）→ 超限 429；
//! - **并发**：同一安装实例的 in-flight 调用数上限（§7.4 max_concurrent
//!   精神在 bridge 层的形态）→ 超限 503；
//! - body / 响应体积上限在 [`crate::router::BridgeLimits`]（请求体经
//!   `DefaultBodyLimit` + handler 重检）。
//!
//! application 的 policy（grant / body / rate / 配额）是**另一层**独立检查
//! （Core-mediated 服务端重做，§21.3）；两层都拒绝时以先命中者为准，语义
//! 都是确定 HTTP 拒绝。

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use operune_domain::InstallationId;

/// 固定窗口长度（秒；§15.2 有界语义）。
const RATE_WINDOW_SECS: u64 = 60;

/// HTTP 层配额拒绝类别（§42.2：超配额以确定 HTTP 语义拒绝，不进 guest
/// 错误空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaDenied {
    /// 并发超限（该安装实例的 in-flight 调用数已达上限 → 503）。
    Busy,
    /// 速率超限（固定窗口内调用数已达上限 → 429）。
    RateLimited,
}

impl fmt::Display for QuotaDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("concurrency limit exceeded"),
            Self::RateLimited => f.write_str("rate limit exceeded"),
        }
    }
}

/// 每安装实例的配额门（§42.2 per-Component HTTP quotas / backpressure）。
///
/// 线程安全（`Mutex` 保护窗口表）；窗口表按安装实例惰性创建并在窗口
/// 过期时重置（有界状态，§15.2）。
pub struct QuotaGate {
    max_in_flight: usize,
    rate_per_minute: u32,
    state: Mutex<HashMap<InstallationId, GateState>>,
}

/// 单个安装实例的配额状态。
#[derive(Debug, Clone, Copy)]
struct GateState {
    /// 当前 in-flight 调用数（配额守卫持有期间 +1，drop 时 -1）。
    in_flight: usize,
    /// 当前固定窗口起点。
    window_start: Instant,
    /// 窗口内已计数调用。
    window_count: u32,
}

impl Default for GateState {
    fn default() -> Self {
        Self {
            in_flight: 0,
            window_start: Instant::now(),
            window_count: 0,
        }
    }
}

/// 并发槽守卫（RAII）：drop 时释放该安装实例的并发槽（无泄漏路径；
/// handler future 被丢弃——客户端断开——时同样释放，§42.2）。
pub struct QuotaGuard<'a> {
    gate: &'a QuotaGate,
    installation: InstallationId,
}

impl QuotaGate {
    /// 构造配额门（上限来自 [`crate::router::BridgeLimits`] 装配快照）。
    pub fn new(max_in_flight: usize, rate_per_minute: u32) -> Self {
        Self {
            max_in_flight,
            rate_per_minute,
            state: Mutex::new(HashMap::new()),
        }
    }

    /// 入口检查（速率 → 并发，先命中者拒绝）；通过时返回并发槽守卫。
    ///
    /// 配额拒绝是确定 HTTP 语义（429 / 503），调用方映射后直接返回；
    /// 守卫必须在调用期间保持存活。
    pub fn enter(&self, installation: InstallationId) -> Result<QuotaGuard<'_>, QuotaDenied> {
        let mut state = self.state.lock().map_err(|_| QuotaDenied::Busy)?;
        let now = Instant::now();
        let entry = state.entry(installation).or_insert_with(GateState::default);
        // 固定窗口速率检查（窗口过期 → 重置，保持有界）。
        if now.duration_since(entry.window_start) >= Duration::from_secs(RATE_WINDOW_SECS) {
            entry.window_start = now;
            entry.window_count = 0;
        }
        if entry.window_count >= self.rate_per_minute {
            return Err(QuotaDenied::RateLimited);
        }
        if entry.in_flight >= self.max_in_flight {
            return Err(QuotaDenied::Busy);
        }
        entry.window_count = entry.window_count.saturating_add(1);
        entry.in_flight = entry.in_flight.saturating_add(1);
        Ok(QuotaGuard {
            gate: self,
            installation,
        })
    }

    /// 释放并发槽（由 [`QuotaGuard`] 的 drop 调用；对未知安装实例无害；
    /// 锁中毒时跳过释放，饱和运算保持计数不退化）。
    fn release(&self, installation: InstallationId) {
        if let Ok(mut state) = self.state.lock()
            && let Some(entry) = state.get_mut(&installation)
        {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }
}

impl Drop for QuotaGuard<'_> {
    fn drop(&mut self) {
        self.gate.release(self.installation);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn gate_accepts_within_limits() {
        let gate = QuotaGate::new(2, 3);
        let installation = InstallationId::new();
        let first = ok(gate.enter(installation), "first enter");
        let second = ok(gate.enter(installation), "second enter");
        drop(first);
        drop(second);
        // 并发槽已释放：可再次进入。
        let again = ok(gate.enter(installation), "re-enter after release");
        drop(again);
    }

    #[test]
    fn gate_rate_limits_in_window() {
        let gate = QuotaGate::new(8, 2);
        let installation = InstallationId::new();
        let first = ok(gate.enter(installation), "first");
        drop(first);
        let second = ok(gate.enter(installation), "second");
        drop(second);
        // 窗口内第三次 → 429 语义。
        assert!(
            matches!(gate.enter(installation), Err(QuotaDenied::RateLimited)),
            "third enter in the window must be rate-limited"
        );
    }

    #[test]
    fn gate_busy_when_in_flight_at_cap() {
        let gate = QuotaGate::new(1, 100);
        let installation = InstallationId::new();
        let held = ok(gate.enter(installation), "first enter holds the slot");
        assert!(
            matches!(gate.enter(installation), Err(QuotaDenied::Busy)),
            "second concurrent enter must be busy"
        );
        drop(held);
        let after = ok(gate.enter(installation), "slot released after guard drop");
        drop(after);
    }

    #[test]
    fn gate_instances_are_independent() {
        let gate = QuotaGate::new(1, 2);
        let a = InstallationId::new();
        let b = InstallationId::new();
        let held_a = ok(gate.enter(a), "a first");
        let held_b = ok(gate.enter(b), "b first (independent window)");
        // 各自独立槽位：并发上限互不影响（速率先于并发检查，此处窗口
        // 余量足够，命中并发 Busy）。
        assert!(matches!(gate.enter(a), Err(QuotaDenied::Busy)));
        assert!(matches!(gate.enter(b), Err(QuotaDenied::Busy)));
        drop(held_a);
        drop(held_b);
    }
}
