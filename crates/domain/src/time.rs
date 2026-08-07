use std::time::{Duration as StdDuration, Instant};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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

    /// 转换为 `std::time::Duration`（与 [`Duration::from_std`] 互为逆操作；
    /// §13.3 适配层边界输出）。
    ///
    /// `Duration` 为 `Copy`，返回内部值的拷贝，不改变 validate-on-construct
    /// 语义（构造时已保证非负，无需再次校验）。
    pub const fn as_std(self) -> StdDuration {
        self.0
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

/// `Duration` 的持久化形态：`{seconds, nanoseconds}`（与 `std::time::Duration`
/// 的内部表示一致，无精度损失；nanoseconds < 1e9）。供内部持久 / 配置边界
/// 序列化（§13.3；0.3.0 scheduler 的 periodic interval 等携带 Duration 的
/// 记录因此可以 derive serde）。
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct WireDuration {
    seconds: u64,
    nanoseconds: u32,
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        WireDuration {
            seconds: self.0.as_secs(),
            nanoseconds: self.0.subsec_nanos(),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireDuration::deserialize(deserializer)?;
        // `std::time::Duration::new` 在 nanoseconds >= 1e9 时 panic（§14.2
        // 禁止）；先显式校验，失败返回 serde 错误而非 panic。
        if wire.nanoseconds >= 1_000_000_000 {
            return Err(serde::de::Error::custom(
                "nanoseconds must be < 1_000_000_000",
            ));
        }
        Ok(Duration(StdDuration::new(wire.seconds, wire.nanoseconds)))
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

/// `UtcInstant` 的持久化形态：WIT `datetime` 的 wire 形状 `{seconds, nanoseconds}`
/// （秒 + 纳秒偏移，§13.3 边界形态与领域内部表示分离）。
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
struct WireUtcInstant {
    seconds: u64,
    nanoseconds: u32,
}

/// UTC 硬时刻（绝对墙上时钟时刻，§13.2 Timestamp 语义；0.3.0 scheduler 的
/// `datetime` 契约表达，§41.2）。
///
/// 与 WIT `operune:scheduler@0.1.0` 的 `datetime` record 严格对齐：语义为
/// 自 Unix epoch 起的 UTC 秒 + 纳秒偏移，不变量 `nanoseconds < 1_000_000_000`
/// （WIT 明文）；WIT 的 wire 形态不含时区/日历语义（"不含时区/日历语义"），
/// 本类型同样不暴露日历/时区运算。
///
/// 内部表示 `time::OffsetDateTime`（UTC 偏移；§13.2："UTC 时间：
/// `time::OffsetDateTime`，但 Domain API 应区分 Timestamp/Expiry 等语义"）。
/// 与 [`Duration`]（非负间隔）和 [`Deadline`]（单调时钟截止）的类型关系：
/// `UtcInstant` 是**墙上时钟**绝对时刻（Timestamp），`Deadline` 是**单调
/// 时钟**绝对截止（Expiry/deadline 语义）——两者语义不同、不存在转换；
/// 时刻的**算术**（计划时刻偏移）使用 [`Duration`]（checked 运算，§14.4）。
///
/// 表示范围（确定性文档边界）：`time` crate 的 `OffsetDateTime` 可表示
/// 公元 -9999..=9999 年；WIT 的 u64 秒值超出该范围时构造返回
/// [`DomainError::InvalidValue`]（超出范围的调度时刻无实际语义；
/// WIT 的宿主侧上限由 Core 策略施加，§7.4）。自 Unix epoch 之前的时刻
/// 不可表示（WIT `seconds: u64` 非负）。
///
/// 不变量（validate-on-construct，§13.3）：`nanoseconds < 1_000_000_000`；
/// 时刻 ≥ Unix epoch；可被 `time` crate 表示（年 -9999..=9999）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]；算术溢出返回
/// [`DomainError::Overflow`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UtcInstant(time::OffsetDateTime);

impl UtcInstant {
    /// 从 WIT `datetime` wire 形态构造（§13.3 边界解析一次）：
    /// 自 Unix epoch 起的 `seconds` 秒 + `nanoseconds` 纳秒偏移。
    ///
    /// 校验（validate-on-construct，§13.3）：`nanoseconds < 1_000_000_000`
    /// （WIT 不变量）；秒值必须可被内部表示承载（见类型文档范围边界）。
    pub fn from_unix_parts(seconds: u64, nanoseconds: u32) -> Result<Self, DomainError> {
        if nanoseconds >= 1_000_000_000 {
            return Err(DomainError::invalid_value(
                ValueKind::UtcInstant,
                "nanoseconds must be < 1_000_000_000 (WIT datetime invariant)",
            ));
        }
        let nanos_total = i128::from(seconds) * 1_000_000_000 + i128::from(nanoseconds);
        let datetime =
            time::OffsetDateTime::from_unix_timestamp_nanos(nanos_total).map_err(|e| {
                DomainError::invalid_value(
                    ValueKind::UtcInstant,
                    format!("{seconds}s + {nanoseconds}ns is outside the representable range: {e}"),
                )
            })?;
        Ok(Self(datetime))
    }

    /// WIT `datetime` wire 形态视图（与 [`UtcInstant::from_unix_parts`]
    /// 互为逆操作；§13.3 适配层边界输出）。
    ///
    /// 不可失败：构造不变量保证时刻 ≥ Unix epoch 且可表示（见类型文档），
    /// 因此 `unix_timestamp_nanos()` 恒非负，拆分为秒/纳秒后必在
    /// u64/u32 范围内（下式 `try_from` 在不变式下不可失败，`unwrap_or_default`
    /// 仅防御性占位，绝不产生错误的 wire 值）。
    pub fn as_unix_parts(self) -> (u64, u32) {
        let nanos_total = self.0.unix_timestamp_nanos();
        let seconds = u64::try_from(nanos_total / 1_000_000_000).unwrap_or_default();
        let nanoseconds = u32::try_from(nanos_total % 1_000_000_000).unwrap_or_default();
        (seconds, nanoseconds)
    }

    /// 内部表示视图（UTC）：供宿主侧与墙上时钟（`time::OffsetDateTime` /
    /// wasi:clocks 适配结果）比较，如 scheduler 的"目标时刻已过去"
    /// （`invalid-trigger`，scheduler.wit）判定在 application 层执行。
    pub fn as_offset_date_time(self) -> time::OffsetDateTime {
        self.0
    }

    /// 检查加法（溢出即 Err，§14.4；如接近表示范围边界的计划时刻）。
    ///
    /// 内部表示（`time::OffsetDateTime`）的加法接受 time crate 的
    /// 有符号 `Duration`；本类型以 [`Duration`]（非负 std 间隔）为领域
    /// 算术单位，转换失败（超出有符号可表示范围，§14.4 禁止回绕）与
    /// 时刻溢出统一为 [`DomainError::Overflow`]。
    pub fn checked_add(self, duration: Duration) -> Result<UtcInstant, DomainError> {
        let duration = time::Duration::try_from(duration.0).map_err(|_| DomainError::Overflow {
            operation: "utc-instant addition",
        })?;
        self.0
            .checked_add(duration)
            .map(UtcInstant)
            .ok_or(DomainError::Overflow {
                operation: "utc-instant addition",
            })
    }

    /// 检查减法（`duration > self` 即 Err，§14.4）。
    ///
    /// 不变量补强：结果必须仍 ≥ Unix epoch（[`UtcInstant`] 构造不变量——
    /// WIT `datetime.seconds` 是 u64，无负时刻）；减到 epoch 之前的时刻
    /// 统一为 [`DomainError::Overflow`]。
    pub fn checked_sub(self, duration: Duration) -> Result<UtcInstant, DomainError> {
        let duration = time::Duration::try_from(duration.0).map_err(|_| DomainError::Overflow {
            operation: "utc-instant subtraction",
        })?;
        let result = self.0.checked_sub(duration).ok_or(DomainError::Overflow {
            operation: "utc-instant subtraction",
        })?;
        if result < time::OffsetDateTime::UNIX_EPOCH {
            return Err(DomainError::Overflow {
                operation: "utc-instant subtraction",
            });
        }
        Ok(UtcInstant(result))
    }
}

impl Serialize for UtcInstant {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (seconds, nanoseconds) = self.as_unix_parts();
        WireUtcInstant {
            seconds,
            nanoseconds,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for UtcInstant {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireUtcInstant::deserialize(deserializer)?;
        Self::from_unix_parts(wire.seconds, wire.nanoseconds).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

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
    fn as_std_roundtrip() {
        // from_std ↔ as_std 互逆（§13.3 适配层边界输入/输出成对）。
        let std_duration = StdDuration::from_millis(1234);
        assert_eq!(Duration::from_std(std_duration).as_std(), std_duration);
        assert_eq!(Duration::from_secs(30).as_std(), StdDuration::from_secs(30));
        assert_eq!(Duration::ZERO.as_std(), StdDuration::ZERO);
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

    #[test]
    fn duration_serde_roundtrip() {
        let duration = Duration::from_millis(1500);
        let json = ok(serde_json::to_string(&duration), "serialize");
        assert_eq!(json, "{\"seconds\":1,\"nanoseconds\":500000000}");
        assert_eq!(
            ok(serde_json::from_str::<Duration>(&json), "deserialize"),
            duration
        );
        // 反序列化边界同样校验 nanoseconds < 1e9（§13.3）。
        assert!(
            serde_json::from_str::<Duration>("{\"seconds\":1,\"nanoseconds\":1000000000}").is_err()
        );
    }

    #[test]
    fn utc_instant_from_unix_parts_accepts_wit_shape() {
        let epoch = ok(UtcInstant::from_unix_parts(0, 0), "epoch");
        assert_eq!(epoch.as_unix_parts(), (0, 0));
        let noon = ok(
            UtcInstant::from_unix_parts(1_752_000_000, 123_456_789),
            "noon",
        );
        assert_eq!(noon.as_unix_parts(), (1_752_000_000, 123_456_789));
        // WIT 不变量边界：nanoseconds == 1_000_000_000 - 1 合法。
        let boundary = ok(
            UtcInstant::from_unix_parts(1_752_000_000, 999_999_999),
            "boundary",
        );
        assert_eq!(boundary.as_unix_parts(), (1_752_000_000, 999_999_999));
    }

    #[test]
    fn utc_instant_rejects_invalid_parts() {
        // WIT 明文不变量：nanoseconds < 1_000_000_000。
        assert!(matches!(
            UtcInstant::from_unix_parts(0, 1_000_000_000),
            Err(DomainError::InvalidValue {
                kind: ValueKind::UtcInstant,
                ..
            })
        ));
        assert!(matches!(
            UtcInstant::from_unix_parts(0, u32::MAX),
            Err(DomainError::InvalidValue {
                kind: ValueKind::UtcInstant,
                ..
            })
        ));
    }

    #[test]
    fn utc_instant_rejects_out_of_representable_range() {
        // time crate 表示范围：年 -9999..=9999（类型文档明文边界）。
        // 公元 10000-01-01T00:00:00Z = 253_402_300_800 秒。
        assert!(matches!(
            UtcInstant::from_unix_parts(253_402_300_800, 0),
            Err(DomainError::InvalidValue {
                kind: ValueKind::UtcInstant,
                ..
            })
        ));
        assert!(matches!(
            UtcInstant::from_unix_parts(u64::MAX, 0),
            Err(DomainError::InvalidValue {
                kind: ValueKind::UtcInstant,
                ..
            })
        ));
        // 边界内（公元 9999-12-31T23:59:59Z = 253_402_300_799 秒）合法。
        assert!(UtcInstant::from_unix_parts(253_402_300_799, 999_999_999).is_ok());
    }

    #[test]
    fn utc_instant_checked_arithmetic() {
        let t = ok(UtcInstant::from_unix_parts(1_752_000_000, 500_000_000), "t");
        let plus = ok(t.checked_add(Duration::from_millis(1500)), "add");
        assert_eq!(plus.as_unix_parts(), (1_752_000_002, 0));
        let minus = ok(t.checked_sub(Duration::from_millis(500)), "sub");
        assert_eq!(minus.as_unix_parts(), (1_752_000_000, 0));
        // 减法下溢：duration 大于自身 → Overflow（§14.4）。
        assert!(matches!(
            t.checked_sub(Duration::from_secs(1_752_000_001)),
            Err(DomainError::Overflow { .. })
        ));
        // 加法溢出：接近表示范围边界 → Overflow。
        let top = ok(
            UtcInstant::from_unix_parts(253_402_300_799, 999_999_999),
            "top",
        );
        assert!(matches!(
            top.checked_add(Duration::from_millis(1)),
            Err(DomainError::Overflow { .. })
        ));
        // 单位往返：+60s 再 -60s 回到原时刻。
        assert_eq!(
            ok(t.checked_add(Duration::from_secs(60)), "add 60s")
                .checked_sub(Duration::from_secs(60)),
            Ok(t)
        );
    }

    #[test]
    fn utc_instant_ord_follows_wall_clock() {
        let early = ok(UtcInstant::from_unix_parts(1_752_000_000, 0), "early");
        let late = ok(UtcInstant::from_unix_parts(1_752_000_000, 1), "late");
        let later = ok(UtcInstant::from_unix_parts(1_752_000_001, 0), "later");
        assert!(early < late);
        assert!(late < later);
        assert_eq!(
            ok(UtcInstant::from_unix_parts(1_752_000_000, 0), "same"),
            early
        );
    }

    #[test]
    fn utc_instant_serde_roundtrip() {
        let t = ok(UtcInstant::from_unix_parts(1_752_000_000, 123_456_789), "t");
        let json = ok(serde_json::to_string(&t), "serialize");
        // 持久化形态 = WIT datetime wire 形状（秒 + 纳秒偏移）。
        assert_eq!(json, "{\"seconds\":1752000000,\"nanoseconds\":123456789}");
        assert_eq!(
            ok(serde_json::from_str::<UtcInstant>(&json), "deserialize"),
            t
        );
        // 反序列化边界同样执行 WIT 不变量校验（§13.3）。
        assert!(
            serde_json::from_str::<UtcInstant>("{\"seconds\":0,\"nanoseconds\":1000000000}")
                .is_err()
        );
    }

    #[test]
    fn utc_instant_offset_date_time_interop() {
        // §13.2 互操作：内部表示是 time::OffsetDateTime（UTC）。
        let t = ok(UtcInstant::from_unix_parts(1_752_000_000, 0), "t");
        let dt = t.as_offset_date_time();
        assert_eq!(dt.unix_timestamp(), 1_752_000_000);
        // 与墙上时钟比较的用途：scheduler 的"目标时刻已过去"判定
        // （application 层执行，本契约不含时间读取）。
        let epoch = ok(UtcInstant::from_unix_parts(0, 0), "epoch");
        assert!(epoch < t);
        assert!(epoch.as_offset_date_time() < dt);
    }

    proptest! {
        #[test]
        fn utc_instant_parts_roundtrip(seconds in 0u64..253_402_300_800, nanoseconds in 0u32..1_000_000_000) {
            let t = ok(UtcInstant::from_unix_parts(seconds, nanoseconds), "instant");
            prop_assert_eq!(t.as_unix_parts(), (seconds, nanoseconds));
        }
    }
}
