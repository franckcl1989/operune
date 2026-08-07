use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};

/// 字节数量（§13.1 Byte Size；§13.2：项目 `ByteSize(u64)` newtype）。
///
/// 任意非负 u64 都是合法字节数（0 是合法数量，如空字节流 / 零预算），因此
/// 直接构造不可失败；构造校验集中在转换与算术（§14.4，禁止整数回绕）：
/// - 有符号转换拒绝负数（validate-on-construct，§13.3）；
/// - `checked_*` 运算溢出即失败，绝不回绕。
///
/// 用作资源上限（linear memory / host buffer / body / 并发等，§7.4）时，
/// 上层用 [`ByteSize::exceeds`] 比较或直接使用 `Ord`。
///
/// 错误：转换 / 算术失败返回 [`DomainError::InvalidValue`] 或
/// [`DomainError::Overflow`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ByteSize(u64);

impl ByteSize {
    /// 零字节。
    pub const ZERO: ByteSize = ByteSize(0);

    /// 可表示的最大字节数。
    pub const MAX: ByteSize = ByteSize(u64::MAX);

    /// 从无符号字节数构造（不可失败；任何非负 u64 都是合法数量）。
    pub const fn from_bytes(bytes: u64) -> Self {
        Self(bytes)
    }

    /// 有符号转换构造：负数拒绝（validate-on-construct，§13.3）；
    /// 超出 u64 范围返回 [`DomainError::Overflow`]。
    pub fn try_from_i128(value: i128) -> Result<Self, DomainError> {
        if value < 0 {
            return Err(DomainError::invalid_value(
                ValueKind::ByteSize,
                "must not be negative",
            ));
        }
        u64::try_from(value)
            .map(Self)
            .map_err(|_| DomainError::Overflow {
                operation: "byte-size conversion",
            })
    }

    /// 原始字节数。
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// 是否为零。
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// 是否严格超过 `limit`（资源上限检查，§7.4）。
    pub const fn exceeds(self, limit: ByteSize) -> bool {
        self.0 > limit.0
    }

    /// 检查加法（溢出即 Err，§14.4）。
    pub fn checked_add(self, rhs: ByteSize) -> Result<ByteSize, DomainError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "byte-size addition",
            })
    }

    /// 检查减法（`rhs > self` 即 Err，§14.4）。
    pub fn checked_sub(self, rhs: ByteSize) -> Result<ByteSize, DomainError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "byte-size subtraction",
            })
    }

    /// 检查乘法（溢出即 Err，§14.4）。
    pub fn checked_mul(self, rhs: ByteSize) -> Result<ByteSize, DomainError> {
        self.0
            .checked_mul(rhs.0)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "byte-size multiplication",
            })
    }

    /// 饱和加法（溢出饱和到 [`ByteSize::MAX`]）。
    pub const fn saturating_add(self, rhs: ByteSize) -> ByteSize {
        Self(self.0.saturating_add(rhs.0))
    }

    /// 饱和乘法（溢出饱和到 [`ByteSize::MAX`]）。
    pub const fn saturating_mul(self, rhs: ByteSize) -> ByteSize {
        Self(self.0.saturating_mul(rhs.0))
    }

    /// KiB 单位构造（1 KiB = 1024 字节；溢出即 Err）。
    pub fn kib(n: u64) -> Result<ByteSize, DomainError> {
        n.checked_mul(1024).map(Self).ok_or(DomainError::Overflow {
            operation: "kib conversion",
        })
    }

    /// MiB 单位构造（1 MiB = 1024 KiB = 1_048_576 字节；溢出即 Err）。
    pub fn mib(n: u64) -> Result<ByteSize, DomainError> {
        n.checked_mul(1 << 20)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "mib conversion",
            })
    }

    /// GiB 单位构造（1 GiB = 1024 MiB = 1_073_741_824 字节；溢出即 Err）。
    pub fn gib(n: u64) -> Result<ByteSize, DomainError> {
        n.checked_mul(1 << 30)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "gib conversion",
            })
    }
}

impl Serialize for ByteSize {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_bytes(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    #[test]
    fn zero_and_max_consts() {
        assert!(ByteSize::ZERO.is_zero());
        assert_eq!(ByteSize::ZERO.as_u64(), 0);
        assert_eq!(ByteSize::MAX.as_u64(), u64::MAX);
        // 零是合法数量：空字节流 / 零预算可表示。
        assert_eq!(ByteSize::from_bytes(0), ByteSize::ZERO);
    }

    #[test]
    fn try_from_i128_rejects_negative() {
        for value in [-1i128, -1_000_000, i128::MIN] {
            assert!(
                matches!(
                    ByteSize::try_from_i128(value),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ByteSize,
                        ..
                    })
                ),
                "{value} must be rejected"
            );
        }
    }

    #[test]
    fn try_from_i128_rejects_overflow() {
        assert!(matches!(
            ByteSize::try_from_i128(u64::MAX as i128 + 1),
            Err(DomainError::Overflow { .. })
        ));
        assert_eq!(ByteSize::try_from_i128(u64::MAX as i128), Ok(ByteSize::MAX));
    }

    #[test]
    fn checked_ops_ok() {
        assert_eq!(
            ByteSize::from_bytes(5).checked_add(ByteSize::from_bytes(3)),
            Ok(ByteSize::from_bytes(8))
        );
        assert_eq!(
            ByteSize::from_bytes(5).checked_sub(ByteSize::from_bytes(3)),
            Ok(ByteSize::from_bytes(2))
        );
        assert_eq!(
            ByteSize::from_bytes(5).checked_mul(ByteSize::from_bytes(3)),
            Ok(ByteSize::from_bytes(15))
        );
    }

    #[test]
    fn checked_ops_reject_overflow() {
        assert!(matches!(
            ByteSize::MAX.checked_add(ByteSize::from_bytes(1)),
            Err(DomainError::Overflow { .. })
        ));
        assert!(matches!(
            ByteSize::from_bytes(3).checked_sub(ByteSize::from_bytes(5)),
            Err(DomainError::Overflow { .. })
        ));
        assert!(matches!(
            ByteSize::from_bytes(1 << 32).checked_mul(ByteSize::from_bytes(1 << 32)),
            Err(DomainError::Overflow { .. })
        ));
        // 回绕绝不发生：饱和到 MAX 而不是绕回。
        assert_eq!(
            ByteSize::MAX.saturating_add(ByteSize::from_bytes(1)),
            ByteSize::MAX
        );
        assert_eq!(
            ByteSize::from_bytes(1 << 32).saturating_mul(ByteSize::from_bytes(1 << 32)),
            ByteSize::MAX
        );
    }

    #[test]
    fn unit_helpers() {
        assert_eq!(ByteSize::kib(1), Ok(ByteSize::from_bytes(1024)));
        assert_eq!(ByteSize::mib(1), Ok(ByteSize::from_bytes(1 << 20)));
        assert_eq!(ByteSize::gib(1), Ok(ByteSize::from_bytes(1 << 30)));
        assert_eq!(ByteSize::mib(1), ByteSize::kib(1024));
        assert_eq!(ByteSize::gib(1), ByteSize::mib(1024));
        // 单位换算溢出即 Err。
        assert!(matches!(
            ByteSize::gib(u64::MAX),
            Err(DomainError::Overflow { .. })
        ));
        assert!(matches!(
            ByteSize::kib(u64::MAX / 1024 + 1),
            Err(DomainError::Overflow { .. })
        ));
    }

    #[test]
    fn exceeds_and_ordering() {
        let limit = ok(ByteSize::mib(1), "1 MiB");
        let larger = ok(ByteSize::mib(2), "2 MiB");
        assert!(larger.exceeds(limit));
        assert!(!ByteSize::ZERO.exceeds(limit));
        assert_eq!(limit, limit);
        assert!(ByteSize::ZERO < limit);
    }

    #[test]
    fn serde_roundtrip() {
        let size = ok(ByteSize::mib(16), "16 MiB");
        let json = ok(serde_json::to_string(&size), "serialize");
        assert_eq!(json, "16777216");
        assert_eq!(
            ok(serde_json::from_str::<ByteSize>(&json), "deserialize"),
            size
        );
    }

    proptest! {
        #[test]
        fn checked_add_never_wraps(a: u64, b: u64) {
            let sum = ByteSize::from_bytes(a).checked_add(ByteSize::from_bytes(b));
            match sum {
                Ok(sum) => prop_assert_eq!(sum.as_u64(), a.wrapping_add(b)),
                Err(_) => prop_assert_eq!(
                    ByteSize::from_bytes(a).saturating_add(ByteSize::from_bytes(b)),
                    ByteSize::MAX
                ),
            }
        }

        #[test]
        fn checked_sub_semantics(a: u64, b: u64) {
            match ByteSize::from_bytes(a).checked_sub(ByteSize::from_bytes(b)) {
                Ok(diff) => prop_assert_eq!(diff.as_u64(), a - b),
                Err(_) => prop_assert!(b > a, "subtraction must only fail when b > a"),
            }
        }
    }
}
