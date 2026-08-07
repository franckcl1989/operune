use std::fmt;
use std::str::FromStr;

use semver::{Comparator, Op, Prerelease, Version, VersionReq};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};

/// 作者声明的发布版本（§19.4 `ComponentVersion`）。
///
/// 与 WIT `operune:component@0.1.0` 的 `component-version` record 严格对齐：
/// 恰好 major / minor / patch 三段 u32（descriptor.wit）。pre-release 与
/// build metadata 语义属于 semver 排序规则，由未来 interface 版本按 semver
/// 规范增量演进（descriptor.wit 注释），本类型在解析边界拒绝二者。
///
/// 排序（`Ord`）按 (major, minor, patch) 数值比较，与 semver precedence
/// （无 pre-release 版本时的规则）一致（§13.2 / semver crate 语义）。
///
/// 错误：`FromStr` 解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl ComponentVersion {
    /// 直接构造：与 WIT `component-version` record 字段一一对应（§13.3 边界
    /// 解析一次；u32 值本身即合法，构造不可失败）。
    pub const fn from_parts(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// 主版本号。
    pub const fn major(self) -> u32 {
        self.major
    }

    /// 次版本号。
    pub const fn minor(self) -> u32 {
        self.minor
    }

    /// 补丁版本号。
    pub const fn patch(self) -> u32 {
        self.patch
    }

    /// semver 兼容规则（§13.2，等价于 Cargo 的 `^` 约束）：
    /// - `1.x.y` 对 `1.w.z`（w ≤ x）兼容：同 major 内 minor / patch 升级兼容；
    /// - `0.x.y` 对 `0.x.z`（z ≤ y）兼容：0.x 中 minor 是破坏性变更；
    /// - `0.0.x` 仅对 `0.0.x` 兼容：0.0 阶段任何发布变更都是破坏性。
    ///
    /// `self` 是候选版本，`required` 是需求方声明的最低可接受版本。
    /// 判定逻辑委托给 `semver::VersionReq`（`^` 比较器），保证与 Cargo /
    /// semver 生态规则逐字一致。
    pub fn is_compatible_with(self, required: ComponentVersion) -> bool {
        let requirement = VersionReq {
            comparators: vec![Comparator {
                op: Op::Caret,
                major: u64::from(required.major),
                minor: Some(u64::from(required.minor)),
                patch: Some(u64::from(required.patch)),
                pre: Prerelease::EMPTY,
            }],
        };
        requirement.matches(&self.to_semver())
    }

    fn to_semver(self) -> Version {
        Version::new(
            u64::from(self.major),
            u64::from(self.minor),
            u64::from(self.patch),
        )
    }
}

impl fmt::Display for ComponentVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for ComponentVersion {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let version = Version::parse(s)
            .map_err(|e| DomainError::invalid_value(ValueKind::ComponentVersion, e.to_string()))?;
        if !version.pre.is_empty() || !version.build.is_empty() {
            return Err(DomainError::invalid_value(
                ValueKind::ComponentVersion,
                "pre-release and build metadata are not part of the 0.1.0 \
                 component-version contract (WIT component-version is major.minor.patch only)",
            ));
        }
        let major = u32::try_from(version.major).map_err(|_| {
            DomainError::invalid_value(
                ValueKind::ComponentVersion,
                format!(
                    "major {} exceeds u32 range of the WIT component-version contract",
                    version.major
                ),
            )
        })?;
        let minor = u32::try_from(version.minor).map_err(|_| {
            DomainError::invalid_value(
                ValueKind::ComponentVersion,
                format!(
                    "minor {} exceeds u32 range of the WIT component-version contract",
                    version.minor
                ),
            )
        })?;
        let patch = u32::try_from(version.patch).map_err(|_| {
            DomainError::invalid_value(
                ValueKind::ComponentVersion,
                format!(
                    "patch {} exceeds u32 range of the WIT component-version contract",
                    version.patch
                ),
            )
        })?;
        Ok(Self::from_parts(major, minor, patch))
    }
}

impl Serialize for ComponentVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ComponentVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    fn parts(major: u32, minor: u32, patch: u32) -> ComponentVersion {
        ComponentVersion::from_parts(major, minor, patch)
    }

    fn any_version() -> impl Strategy<Value = ComponentVersion> {
        (any::<u32>(), any::<u32>(), any::<u32>())
            .prop_map(|(major, minor, patch)| ComponentVersion::from_parts(major, minor, patch))
    }

    #[test]
    fn parse_accepts_valid_versions() {
        assert_eq!("0.0.0".parse::<ComponentVersion>(), Ok(parts(0, 0, 0)));
        assert_eq!("1.2.3".parse::<ComponentVersion>(), Ok(parts(1, 2, 3)));
        assert_eq!(
            "10.20.30".parse::<ComponentVersion>(),
            Ok(parts(10, 20, 30))
        );
        assert_eq!(
            format!("{}.{}.{}", u32::MAX, u32::MAX, u32::MAX).parse::<ComponentVersion>(),
            Ok(parts(u32::MAX, u32::MAX, u32::MAX))
        );
    }

    #[test]
    fn parse_rejects_invalid() {
        for bad in [
            "",
            "1.2",
            "1.2.3.4",
            "v1.2.3",
            "01.2.3",         // semver：前导零非法
            "1.2.3-alpha",    // WIT 0.1.0 契约不含 pre-release
            "1.2.3+build",    // WIT 0.1.0 契约不含 build metadata
            "4294967296.0.0", // 超出 WIT u32 范围
            "1.4294967296.0",
            "1.0.4294967296",
            "abc",
        ] {
            assert!(
                matches!(
                    bad.parse::<ComponentVersion>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ComponentVersion,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn display_roundtrip() {
        assert_eq!(parts(1, 2, 3).to_string(), "1.2.3");
        assert_eq!(parts(0, 0, 0).to_string(), "0.0.0");
    }

    #[test]
    fn ord_follows_numeric_precedence() {
        assert!(parts(1, 0, 0) < parts(1, 0, 1));
        assert!(parts(1, 0, 1) < parts(1, 1, 0));
        assert!(parts(1, 1, 0) < parts(2, 0, 0));
        // 数值比较而非字典序：0.9.9 < 0.10.0。
        assert!(parts(0, 9, 9) < parts(0, 10, 0));
    }

    #[test]
    fn compatible_within_same_major() {
        assert!(parts(1, 2, 3).is_compatible_with(parts(1, 2, 3)));
        assert!(parts(1, 3, 0).is_compatible_with(parts(1, 2, 0)));
        assert!(parts(1, 2, 5).is_compatible_with(parts(1, 2, 0)));
    }

    #[test]
    fn compatible_rejects_breaking() {
        // major 提升：破坏性。
        assert!(!parts(2, 0, 0).is_compatible_with(parts(1, 9, 9)));
        // 候选版本低于需求：不兼容。
        assert!(!parts(1, 2, 0).is_compatible_with(parts(1, 3, 0)));
        // 0.x：minor 提升是破坏性（§semver 规则）。
        assert!(parts(0, 2, 1).is_compatible_with(parts(0, 2, 0)));
        assert!(!parts(0, 3, 0).is_compatible_with(parts(0, 2, 0)));
        // 0.0.x：patch 提升也是破坏性。
        assert!(!parts(0, 0, 2).is_compatible_with(parts(0, 0, 1)));
        assert!(parts(0, 0, 1).is_compatible_with(parts(0, 0, 1)));
        // 跨 0 主版本线：0.5.0 与 1.0.0 互不兼容。
        assert!(!parts(1, 0, 0).is_compatible_with(parts(0, 9, 9)));
        assert!(!parts(0, 9, 9).is_compatible_with(parts(1, 0, 0)));
    }

    #[test]
    fn serde_roundtrip() {
        let v = parts(1, 2, 3);
        let json = ok(serde_json::to_string(&v), "serialize");
        assert_eq!(json, format!("\"{v}\""));
        assert_eq!(
            ok(
                serde_json::from_str::<ComponentVersion>(&json),
                "deserialize"
            ),
            v
        );
        // 反序列化边界同样执行 WIT 契约校验。
        assert!(serde_json::from_str::<ComponentVersion>("\"1.2.3-alpha\"").is_err());
        assert!(serde_json::from_str::<ComponentVersion>("\"not-a-version\"").is_err());
    }

    proptest! {
        #[test]
        fn display_parse_roundtrip(v in any_version()) {
            prop_assert_eq!(v.to_string().parse::<ComponentVersion>(), Ok(v));
        }

        #[test]
        fn compatible_reflexive(v in any_version()) {
            prop_assert!(v.is_compatible_with(v));
        }

        #[test]
        fn compatible_rule_major_nonzero(required in any_version(), candidate in any_version()) {
            if required.major() > 0 {
                // ^1.2.3：同 major 且不低于需求。
                prop_assert_eq!(
                    candidate.is_compatible_with(required),
                    candidate.major() == required.major() && candidate >= required
                );
            }
        }

        #[test]
        fn compatible_rule_zero_major(required in any_version(), candidate in any_version()) {
            if required.major() == 0 && required.minor() > 0 {
                // ^0.2.3：同 0.x minor 且不低于需求。
                prop_assert_eq!(
                    candidate.is_compatible_with(required),
                    candidate.major() == 0 && candidate.minor() == required.minor() && candidate >= required
                );
            }
        }

        #[test]
        fn compatible_rule_zero_zero(required in any_version(), candidate in any_version()) {
            if required.major() == 0 && required.minor() == 0 {
                // ^0.0.3：仅完全相等。
                prop_assert_eq!(candidate.is_compatible_with(required), candidate == required);
            }
        }
    }
}
