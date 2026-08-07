//! 0.3.0 Stateful Runtime（§41.2）——墙上时钟抽象（scheduler 的 UTC 硬时刻
//! 语义）。
//!
//! scheduler.wit 明文：`fire-at` / `next-fire-at` 是 **UTC 硬时刻**（自
//! Unix epoch 起），不是相对延迟；"目标时刻已过去 → `invalid-trigger`" 是
//! application 层判定（本契约不含时间读取）。本模块承载该判定与 fire 时刻
//! 计算所需的时钟面：
//!
//! - [`Clock::now`]：当前 UTC 时刻（[`operune_domain::UtcInstant`]，与
//!   scheduler 契约 `datetime` 严格对齐）；
//! - [`Clock::sleep`]：单调 sleep（**tokio 定时器驱动**——UTC 硬时刻
//!   换算为单调延迟后由 tokio 时间线推进；§15.1）。
//!
//! 注入面（§24.2 端口注入）：生产装配注入 [`SystemClock`]；测试注入受控
//! 时钟（test_support 的 `PausedClock`——tokio paused-time 下与
//! `tokio::time::advance` 锁步推进，测试无需真实等待）。

use std::future::Future;
use std::pin::Pin;

use operune_domain::{Duration, UtcInstant};

/// 时钟错误（封闭 typed error，§14.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ClockError {
    /// 墙上时钟返回不可表示的 UTC 时刻（time crate 表示范围边界，
    /// §13.3；正常路径不可达）。
    #[error("wall clock returned an unrepresentable UTC instant")]
    OutOfRange,
}

/// 墙上时钟抽象（scheduler 的 UTC 硬时刻语义；§41.2）。
///
/// `Send + Sync`：驱动任务（scheduler driver / 测试）跨任务共享。
pub trait Clock: Send + Sync {
    /// 当前 UTC 时刻（`invalid-trigger` 判定与 fire 依据）。
    fn now(&self) -> Result<UtcInstant, ClockError>;

    /// 单调 sleep（tokio 定时器驱动；§15.1）。返回的 future 由调用方
    /// poll（`tokio::select!`），可被取消令牌中断。
    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}

/// 系统时钟：`std::time::SystemTime` 墙上时钟（UTC，自 Unix epoch 起）
/// + tokio 定时器 sleep。
///
/// 实现说明：不引入 `time` crate 的直接依赖（§23.1 依赖最小化）——UTC
/// 墙上时刻经 `SystemTime::duration_since(UNIX_EPOCH)` 换算为 WIT
/// `datetime` wire 形态（秒 + 纳秒偏移），由 domain 边界校验
/// （[`UtcInstant::from_unix_parts`]，§13.3）。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl SystemClock {
    /// 新建系统时钟。
    pub fn new() -> Self {
        Self
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Result<UtcInstant, ClockError> {
        let since_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ClockError::OutOfRange)?;
        // as_secs 已是 u64（std Duration）；epoch 前（负）由
        // duration_since 拒绝。
        let seconds = since_epoch.as_secs();
        let nanoseconds = since_epoch.subsec_nanos();
        // §13.3 validate-on-construct：当前时刻恒在表示范围内（2026 年 ≪
        // 年 -9999..=9999 边界），构造失败仅在不变量被破坏时。
        UtcInstant::from_unix_parts(seconds, nanoseconds).map_err(|_| ClockError::OutOfRange)
    }

    fn sleep(&self, duration: Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration.as_std()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use operune_domain::Duration as DomainDuration;

    #[test]
    fn system_clock_now_is_representable_and_epoch_or_later() {
        let clock = SystemClock::new();
        let now = clock
            .now()
            .unwrap_or_else(|_| crate::test_support::test_failure("clock"));
        // 当前时刻 ≥ Unix epoch（2026 年远大于 1970）。
        assert!(now.as_unix_parts().0 >= 1_752_000_000);
        // WIT datetime 不变量：nanoseconds < 1e9。
        assert!(now.as_unix_parts().1 < 1_000_000_000);
    }

    #[tokio::test]
    async fn system_clock_sleep_elapses() {
        let clock = SystemClock::new();
        let started = tokio::time::Instant::now();
        clock.sleep(DomainDuration::from_millis(5)).await;
        assert!(started.elapsed() >= std::time::Duration::from_millis(5));
    }
}
