use std::time::{Duration as StdDuration, Instant};

use crate::error::{DomainError, ValueKind};

/// 非负时间间隔（§13.1 Duration；§13.2 推荐 `std::time::Duration` 作为基础
/// 表示，再包一层领域语义类型）。
///
/// 领域语义：资源预算、drain / descriptor / 单次调用 deadline 的间隔
/// （§7.4 / §19.3 / §20.4）。
///
/// 构造校验（validate-on-construct，§13.3）：有符号转换构造拒绝负数；
/// 算术使用 checked / saturating（§14.4），禁止回绕。
///
/// 错误：转换 / 算术失败返回 [`DomainError::InvalidValue`] 或
/// [`DomainError::Overflow`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Duration(StdDuration);

impl Duration {
    /// 零间隔。
    pub const ZERO: Duration = Duration(StdDuration::ZERO);

    /// 从整秒构造（不可失败；任何非负秒数都是合法间隔）。
    pub const fn from_secs(secs: u64) -> Duration {
        Duration(StdDuration::from_secs(secs))
    }

    /// 从整毫秒构造（不可失败）。
    pub const fn from_millis(millis: u64) -> Duration {
        Duration(StdDuration::from_millis(millis))
    }

    /// 从 `std::time::Duration` 包装（适配层边界输入，§13.3）。
    pub const fn from_std(duration: StdDuration) -> Duration {
        Duration(duration)
    }

    /// 有符号秒转换构造：负数拒绝（validate-on-construct，§13.3）。
    pub fn try_from_secs_i64(secs: i64) -> Result<Duration, DomainError> {
        u64::try_from(secs)
            .map(Self::from_secs)
            .map_err(|_| DomainError::invalid_value(ValueKind::Duration, "must not be negative"))
    }

    /// 有符号毫秒转换构造：负数拒绝（validate-on-construct，§13.3）。
    pub fn try_from_millis_i64(millis: i64) -> Result<Duration, DomainError> {
        u64::try_from(millis)
            .map(Self::from_millis)
            .map_err(|_| DomainError::invalid_value(ValueKind::Duration, "must not be negative"))
    }

    /// 整秒数（向下取整）。
    pub const fn as_secs(self) -> u64 {
        self.0.as_secs()
    }

    /// 是否为零间隔。
    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }

    /// 检查加法（溢出即 Err，§14.4）。
    pub fn checked_add(self, rhs: Duration) -> Result<Duration, DomainError> {
        self.0
            .checked_add(rhs.0)
            .map(Duration)
            .ok_or(DomainError::Overflow {
                operation: "duration addition",
            })
    }

    /// 检查减法（`rhs > self` 即 Err，§14.4）。
    pub fn checked_sub(self, rhs: Duration) -> Result<Duration, DomainError> {
        self.0
            .checked_sub(rhs.0)
            .map(Duration)
            .ok_or(DomainError::Overflow {
                operation: "duration subtraction",
            })
    }

    /// 饱和加法（溢出饱和到 `std::time::Duration::MAX`）。
    pub fn saturating_add(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_add(rhs.0))
    }

    /// 饱和减法（`rhs > self` 时饱和为零）。
    pub fn saturating_sub(self, rhs: Duration) -> Duration {
        Duration(self.0.saturating_sub(rhs.0))
    }
}

/// 绝对截止时间（§13.1 Deadline），基于单调时钟 `std::time::Instant`，
/// 不受墙上时钟跳变影响。
///
/// 领域语义：drain deadline（§20.4）、单次调用截止时间（§7.4）、descriptor
/// 调用 deadline（§19.3）等宿主侧超时的截止时刻。
///
/// 不变量（validate-on-construct，§13.3）：构造时 deadline 严格在未来
/// （`after` 拒绝零间隔——一个已经到期的 deadline 是调用方错误）。
/// 瞬态类型：不可序列化（不实现 serde）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`] 或
/// [`DomainError::Overflow`]。
#[derive(Debug, Clone, Copy)]
pub struct Deadline(Instant);

impl Deadline {
    /// 从现在起 `duration` 后到期。`duration` 必须严格为正。
    pub fn after(duration: Duration) -> Result<Deadline, DomainError> {
        if duration.is_zero() {
            return Err(DomainError::invalid_value(
                ValueKind::Deadline,
                "deadline interval must be strictly positive",
            ));
        }
        let now = Instant::now();
        let deadline = now.checked_add(duration.0).ok_or(DomainError::Overflow {
            operation: "deadline creation",
        })?;
        Ok(Deadline(deadline))
    }

    /// 剩余时间；已到期时饱和为零（不失败——是否过期由
    /// [`Deadline::is_expired`] 判定）。
    pub fn remaining(self) -> Duration {
        self.0
            .checked_duration_since(Instant::now())
            .map(Duration)
            .unwrap_or(Duration::ZERO)
    }

    /// 是否已到期（`remaining == 0`）。
    pub fn is_expired(self) -> bool {
        self.remaining().is_zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn secs_millis_roundtrip() {
        assert_eq!(Duration::from_secs(30).as_secs(), 30);
        assert_eq!(Duration::from_millis(1500).as_secs(), 1);
        assert_eq!(Duration::from_secs(0), Duration::ZERO);
        assert!(Duration::ZERO.is_zero());
        assert!(!Duration::from_secs(1).is_zero());
        // 1 小时在秒域内可精确表示。
        assert_eq!(Duration::from_secs(3600).as_secs(), 3600);
    }

    #[test]
    fn try_from_signed_rejects_negative() {
        for value in [-1i64, -60, i64::MIN] {
            assert!(
                matches!(
                    Duration::try_from_secs_i64(value),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::Duration,
                        ..
                    })
                ),
                "{value}s must be rejected"
            );
            assert!(
                matches!(
                    Duration::try_from_millis_i64(value),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::Duration,
                        ..
                    })
                ),
                "{value}ms must be rejected"
            );
        }
        assert_eq!(Duration::try_from_secs_i64(0), Ok(Duration::ZERO));
        assert_eq!(
            Duration::try_from_millis_i64(1500),
            Ok(Duration::from_millis(1500))
        );
    }

    #[test]
    fn checked_add_rejects_overflow() {
        let max = Duration::from_std(StdDuration::MAX);
        assert!(matches!(
            max.checked_add(Duration::from_secs(1)),
            Err(DomainError::Overflow { .. })
        ));
        assert_eq!(
            Duration::from_secs(10).checked_add(Duration::from_secs(5)),
            Ok(Duration::from_secs(15))
        );
        assert_eq!(max.saturating_add(Duration::from_secs(1)), max);
    }

    #[test]
    fn checked_sub_ok_and_overflow() {
        assert_eq!(
            Duration::from_secs(5).checked_sub(Duration::from_secs(3)),
            Ok(Duration::from_secs(2))
        );
        assert!(matches!(
            Duration::from_secs(3).checked_sub(Duration::from_secs(5)),
            Err(DomainError::Overflow { .. })
        ));
    }

    #[test]
    fn saturating_sub_clamps_zero() {
        assert_eq!(
            Duration::from_secs(3).saturating_sub(Duration::from_secs(5)),
            Duration::ZERO
        );
        assert_eq!(
            Duration::from_secs(5).saturating_sub(Duration::from_secs(3)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn from_std_wraps() {
        assert_eq!(
            Duration::from_std(StdDuration::from_secs(7)),
            Duration::from_secs(7)
        );
    }

    #[test]
    fn deadline_after_rejects_zero() {
        assert!(matches!(
            Deadline::after(Duration::ZERO),
            Err(DomainError::InvalidValue {
                kind: ValueKind::Deadline,
                ..
            })
        ));
    }

    #[test]
    fn deadline_fresh_is_not_expired() {
        // 1 小时后到期的 deadline 在构造后必然仍有剩余（单调时钟）。
        let deadline = ok(Deadline::after(Duration::from_secs(3600)), "1h deadline");
        assert!(!deadline.is_expired());
        assert!(!deadline.remaining().is_zero());
    }

    #[test]
    fn deadline_expires() {
        let deadline = ok(Deadline::after(Duration::from_millis(1)), "1ms deadline");
        let mut waited_ms = 0u32;
        while !deadline.is_expired() && waited_ms < 100 {
            std::thread::sleep(StdDuration::from_millis(1));
            waited_ms += 1;
        }
        assert!(
            deadline.is_expired(),
            "deadline did not expire within 100ms"
        );
    }
}
