//! 0.2.0 Capability Composition（§40.2）：Component-to-Component 契约面
//! （contract surface）类型。
//!
//! 事实源（§40.3）：依赖关系只能来自 WIT imports/exports + Runtime Policy。
//! 本模块建模的是从 Component 二进制中真实可观察的接口契约事实（§6.7
//! Contract Surface Identity：package/interface/version），不是 manifest 或
//! 任何私有声明文件。WIT 文本的语法解析属于 runtime-wasi-p2 适配层职责
//! （§13.3 边界解析一次），Domain 只做结构性校验与强类型区分。
//!
//! 版本语义（§40.2 version compatibility resolution）：提供版本用
//! [`ComponentVersion`](crate::ComponentVersion)（与 §13.2 的 major/minor/
//! patch 兼容规则一致），需求用 semver `VersionReq`（`^1.2.3` / `>=1.2.3,
//! <2.0.0` / `*` 等，§13.2 SemVer 推荐基础类型）。

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use semver::VersionReq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ComponentVersion;
use crate::error::{DomainError, ValueKind};
use crate::id::validate_identifier;

/// WIT package 名（如 `operune:web`、`wasi:http`）。
///
/// 结构性校验（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制
/// 字符（复用 id.rs 的通用标识符规则），且必须是 `namespace:name` 两段
/// （恰好一个 `:`，两段均非空）——阻止把 interface 名或任意字符串误当作
/// package 名；完整 WIT 语法（kebab-case 等）由适配层解析。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageName(String);

impl PackageName {
    /// 从 WIT package 名边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::PackageName)?;
        let (namespace, name) = value.split_once(':').ok_or_else(|| {
            DomainError::invalid_value(ValueKind::PackageName, "must be `namespace:name`")
        })?;
        if namespace.is_empty() || name.is_empty() {
            return Err(DomainError::invalid_value(
                ValueKind::PackageName,
                "must be `namespace:name` with non-empty parts",
            ));
        }
        if name.contains(':') {
            return Err(DomainError::invalid_value(
                ValueKind::PackageName,
                "must contain exactly one `:` separating namespace and name",
            ));
        }
        Ok(Self(value))
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PackageName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PackageName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for PackageName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PackageName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// WIT interface 名（如 `actions`、`outgoing-handler`）。
///
/// 结构性校验（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制
/// 字符；且不得包含 `:`、`/`、`@`——阻止把 package 名或带版本的完整
/// interface 标识误当作 interface 名（完整 WIT 语法由适配层解析）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// 从 WIT interface 名边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::InterfaceName)?;
        for forbidden in [':', '/', '@'] {
            if value.contains(forbidden) {
                return Err(DomainError::invalid_value(
                    ValueKind::InterfaceName,
                    format!("must not contain `{forbidden}`"),
                ));
            }
        }
        Ok(Self(value))
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for InterfaceName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for InterfaceName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// provider 导出的 interface 标识（§40.2 ProvidedInterface）：package 名 +
/// interface 名 + 版本。
///
/// 版本是 WIT package 的接口契约版本（§6.6：WIT package 版本是接口契约
/// 版本，不是 Core Runtime 发布版本的别名），用 [`ComponentVersion`] 表达
/// （与 §13.2 的 major/minor/patch 规则一致）。
///
/// 字符串形态：`namespace:package/interface@major.minor.patch`（如
/// `operune:web/actions@0.1.0`）。
///
/// 错误：`FromStr` 解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceId {
    package: PackageName,
    interface: InterfaceName,
    version: ComponentVersion,
}

impl InterfaceId {
    /// 直接构造（validate-on-construct 由三个组成部分各自承担）。
    pub fn new(package: PackageName, interface: InterfaceName, version: ComponentVersion) -> Self {
        Self {
            package,
            interface,
            version,
        }
    }

    /// package 名。
    pub fn package(&self) -> &PackageName {
        &self.package
    }

    /// interface 名。
    pub fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    /// 接口契约版本。
    pub fn version(&self) -> ComponentVersion {
        self.version
    }
}

impl fmt::Display for InterfaceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.package, self.interface, self.version)
    }
}

impl FromStr for InterfaceId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (left, version) = s.split_once('@').ok_or_else(|| {
            DomainError::invalid_value(
                ValueKind::InterfaceId,
                "must be `package/interface@version`",
            )
        })?;
        let (package, interface) = left.split_once('/').ok_or_else(|| {
            DomainError::invalid_value(
                ValueKind::InterfaceId,
                "must be `package/interface@version`",
            )
        })?;
        if version.is_empty() {
            // semver 把空字符串解析为 0.0.0：空版本段必须显式拒绝。
            return Err(DomainError::invalid_value(
                ValueKind::InterfaceId,
                "version must not be empty",
            ));
        }
        let package = PackageName::new(package)?;
        let interface = InterfaceName::new(interface)?;
        let version = ComponentVersion::from_str(version)?;
        Ok(Self {
            package,
            interface,
            version,
        })
    }
}

impl Serialize for InterfaceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for InterfaceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// consumer 导入的 interface 需求（§40.2 RequiredInterface）：package 名 +
/// interface 名 + semver 版本需求。
///
/// 版本需求用 `semver::VersionReq`（`^1.2.3` / `>=1.2.3, <2.0.0` / `*`），
/// 匹配语义与 Cargo / semver 生态一致（§13.2）。`^x.y.z` 形态与
/// [`ComponentVersion::is_compatible_with`] 的 §13.2 兼容规则一致（同 major
/// 内 minor/patch 升级兼容；0.x 中 minor 是破坏性变更；0.0.x 仅自身）。
///
/// 不变量：
/// - `normalized` 是 `version_req` 的规范字符串形态（`version_req.to_string()`，
///   由 comparators 规范化生成，如 `1.2.3` 显示为 `^1.2.3`）；相等语义与
///   `version_req` 相等语义一致（`VersionReq` 的 Eq/Hash 基于 comparators）。
///
/// 字符串形态：`namespace:package/interface@<version-req>`。
///
/// 错误：`FromStr` 解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceRequirement {
    package: PackageName,
    interface: InterfaceName,
    version_req: VersionReq,
    /// `version_req` 的规范字符串形态（构造时固化，Ord/serde/Display 使用）。
    normalized: String,
}

impl InterfaceRequirement {
    /// 直接构造（validate-on-construct：`version_req` 已解析，`normalized`
    /// 由 `version_req.to_string()` 固化）。
    pub fn new(package: PackageName, interface: InterfaceName, version_req: VersionReq) -> Self {
        let normalized = version_req.to_string();
        Self {
            package,
            interface,
            version_req,
            normalized,
        }
    }

    /// package 名。
    pub fn package(&self) -> &PackageName {
        &self.package
    }

    /// interface 名。
    pub fn interface(&self) -> &InterfaceName {
        &self.interface
    }

    /// semver 版本需求。
    pub fn version_req(&self) -> &VersionReq {
        &self.version_req
    }

    /// 提供方版本是否满足本需求（§40.2 version compatibility resolution；
    /// package/interface 必须精确匹配，版本按 semver `VersionReq::matches`）。
    pub fn satisfied_by(&self, provided: &InterfaceId) -> bool {
        self.package == *provided.package()
            && self.interface == *provided.interface()
            && self
                .version_req
                .matches(&semver_version(provided.version()))
    }
}

impl fmt::Display for InterfaceRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}@{}", self.package, self.interface, self.normalized)
    }
}

impl FromStr for InterfaceRequirement {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (left, req) = s.split_once('@').ok_or_else(|| {
            DomainError::invalid_value(
                ValueKind::InterfaceRequirement,
                "must be `package/interface@<version-req>`",
            )
        })?;
        let (package, interface) = left.split_once('/').ok_or_else(|| {
            DomainError::invalid_value(
                ValueKind::InterfaceRequirement,
                "must be `package/interface@<version-req>`",
            )
        })?;
        let package = PackageName::new(package)?;
        let interface = InterfaceName::new(interface)?;
        let version_req = VersionReq::parse(req).map_err(|e| {
            DomainError::invalid_value(ValueKind::InterfaceRequirement, e.to_string())
        })?;
        Ok(Self::new(package, interface, version_req))
    }
}

/// 排序键：`(package, interface, normalized)`。
///
/// 与 Eq（comparators 相等）一致：相等 comparators ⇒ 相同 `normalized` 字符串
/// （Display 是 comparators 的纯函数）⇒ 相同排序位置；反之相同排序位置（同
/// package/interface + 同 normalized）⇒ 相同 comparators（parse(display(r)) == r）。
impl PartialOrd for InterfaceRequirement {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InterfaceRequirement {
    fn cmp(&self, other: &Self) -> Ordering {
        (&self.package, &self.interface, &self.normalized).cmp(&(
            &other.package,
            &other.interface,
            &other.normalized,
        ))
    }
}

impl Serialize for InterfaceRequirement {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for InterfaceRequirement {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// 0.2.0 契约面兼容判断（§40.2 InterfaceCompatibility）：
/// `provided` 是否满足 `required`（自由函数形态，等价于
/// [`InterfaceRequirement::satisfied_by`]）。
pub fn interface_compatible(provided: &InterfaceId, required: &InterfaceRequirement) -> bool {
    required.satisfied_by(provided)
}

/// 把 [`ComponentVersion`] 转成 semver `Version`（供 `VersionReq::matches`）。
fn semver_version(version: ComponentVersion) -> semver::Version {
    semver::Version::new(
        u64::from(version.major()),
        u64::from(version.minor()),
        u64::from(version.patch()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::strategy::Strategy;

    fn version(major: u32, minor: u32, patch: u32) -> ComponentVersion {
        ComponentVersion::from_parts(major, minor, patch)
    }

    fn pkg(s: &str) -> PackageName {
        ok(PackageName::new(s), "package")
    }

    fn iface(s: &str) -> InterfaceName {
        ok(InterfaceName::new(s), "interface")
    }

    fn provided(package: &str, interface: &str, major: u32, minor: u32, patch: u32) -> InterfaceId {
        InterfaceId::new(pkg(package), iface(interface), version(major, minor, patch))
    }

    fn req(s: &str) -> InterfaceRequirement {
        ok(s.parse::<InterfaceRequirement>(), "requirement")
    }

    fn version_req(s: &str) -> VersionReq {
        ok(VersionReq::parse(s), "version req")
    }

    // ------------------------------------------------------------------
    // PackageName / InterfaceName
    // ------------------------------------------------------------------

    #[test]
    fn package_name_accepts_wit_style() {
        assert!(PackageName::new("operune:web").is_ok());
        assert!(PackageName::new("wasi:http").is_ok());
        assert!(PackageName::new("a:b").is_ok());
    }

    #[test]
    fn package_name_rejects_invalid() {
        for bad in [
            "",          // 空
            "nocolon",   // 缺少 `:`
            ":name",     // 空 namespace
            "ns:",       // 空 name
            "a:b:c",     // 多个 `:`
            "bad\nname", // 控制字符
        ] {
            assert!(
                matches!(
                    PackageName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PackageName,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn package_name_serde_roundtrip() {
        let name = pkg("operune:web");
        let json = ok(serde_json::to_string(&name), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<PackageName>(&json), "deserialize"),
            name
        );
        assert!(serde_json::from_str::<PackageName>("\"bad\"").is_err());
    }

    #[test]
    fn interface_name_accepts_wit_style() {
        assert!(InterfaceName::new("actions").is_ok());
        assert!(InterfaceName::new("outgoing-handler").is_ok());
    }

    #[test]
    fn interface_name_rejects_invalid() {
        for bad in ["", "a:b", "a/b", "a@b", "bad\nname"] {
            assert!(
                matches!(
                    InterfaceName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::InterfaceName,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    // ------------------------------------------------------------------
    // InterfaceId
    // ------------------------------------------------------------------

    #[test]
    fn interface_id_accepts_wit_style() {
        let id = ok(
            "operune:web/actions@0.1.0".parse::<InterfaceId>(),
            "interface id",
        );
        assert_eq!(id.package().as_str(), "operune:web");
        assert_eq!(id.interface().as_str(), "actions");
        assert_eq!(id.version(), version(0, 1, 0));
    }

    #[test]
    fn interface_id_rejects_malformed() {
        for bad in [
            "",                               // 空
            "operune:web",                    // 缺 interface / 版本
            "operune:web/actions",            // 缺版本
            "actions@0.1.0",                  // 缺 package
            "operune:web/actions@",           // 空版本
            "operune:web/actions@abc",        // 非法版本
            "operune:web/actions@1.0.0-rc.1", // pre-release 不在 0.1.0 契约
        ] {
            // 解析失败即拒绝（错误 kind 可能来自子段，如 ComponentVersion）。
            assert!(
                matches!(
                    bad.parse::<InterfaceId>(),
                    Err(DomainError::InvalidValue { .. })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn interface_id_display_parse_roundtrip() {
        let id = provided("operune:web", "actions", 0, 1, 0);
        assert_eq!(id.to_string(), "operune:web/actions@0.1.0");
        assert_eq!(id.to_string().parse::<InterfaceId>(), Ok(id));
    }

    #[test]
    fn interface_id_ord_follows_package_interface_version() {
        let a = provided("a:x", "i", 1, 0, 0);
        let b = provided("b:x", "i", 1, 0, 0);
        let c = provided("a:x", "j", 1, 0, 0);
        let d = provided("a:x", "i", 1, 1, 0);
        assert!(a < b);
        assert!(a < c);
        assert!(a < d);
        assert_eq!(a, provided("a:x", "i", 1, 0, 0));
    }

    #[test]
    fn interface_id_serde_roundtrip() {
        let id = provided("operune:web", "actions", 0, 1, 0);
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "\"operune:web/actions@0.1.0\"");
        assert_eq!(
            ok(serde_json::from_str::<InterfaceId>(&json), "deserialize"),
            id
        );
        assert!(serde_json::from_str::<InterfaceId>("\"bad\"").is_err());
    }

    // ------------------------------------------------------------------
    // InterfaceRequirement
    // ------------------------------------------------------------------

    #[test]
    fn requirement_accepts_semver_forms() {
        assert_eq!(
            req("operune:web/actions@^1.2.3").version_req(),
            &version_req("^1.2.3")
        );
        assert_eq!(
            req("operune:web/actions@>=1.2.3, <2.0.0").version_req(),
            &version_req(">=1.2.3, <2.0.0")
        );
        assert_eq!(
            req("operune:web/actions@*").version_req(),
            &VersionReq::STAR
        );
    }

    #[test]
    fn requirement_normalizes_canonically() {
        // 无操作符的 `1.2.3` 规范化为 `^1.2.3`；再次 parse 是固定点。
        let r = req("operune:web/actions@1.2.3");
        assert_eq!(r.to_string(), "operune:web/actions@^1.2.3");
        assert_eq!(r.to_string().parse::<InterfaceRequirement>(), Ok(r.clone()));
    }

    #[test]
    fn requirement_rejects_invalid() {
        for bad in [
            "",
            "operune:web/actions",            // 缺版本需求
            "operune:web/actions@",           // 空版本需求
            "operune:web/actions@@1.0.0",     // @ 在需求中非法
            "operune:web/actions@>=1.0 <2.0", // 缺少逗号
            "operune:web/actions@abc",
        ] {
            assert!(
                matches!(
                    bad.parse::<InterfaceRequirement>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::InterfaceRequirement,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn requirement_serde_roundtrip() {
        let r = req("operune:web/actions@^1.2.3");
        let json = ok(serde_json::to_string(&r), "serialize");
        assert_eq!(json, "\"operune:web/actions@^1.2.3\"");
        assert_eq!(
            ok(
                serde_json::from_str::<InterfaceRequirement>(&json),
                "deserialize"
            ),
            r
        );
        assert!(serde_json::from_str::<InterfaceRequirement>("\"bad\"").is_err());
    }

    #[test]
    fn requirement_eq_follows_semver_equivalence() {
        // `1.2.3` 与 `^1.2.3` 是同一 comparators（Eq 一致），且 normalized
        // 相同 → Ord 排序位置一致（Ord 与 Eq 一致性）。
        let a = req("operune:web/actions@1.2.3");
        let b = req("operune:web/actions@^1.2.3");
        assert_eq!(a, b);
        assert_eq!(a.cmp(&b), Ordering::Equal);
        // 语义不同的需求不同。
        assert_ne!(
            req("operune:web/actions@^1.2.3"),
            req("operune:web/actions@^1.3.0")
        );
    }

    // ------------------------------------------------------------------
    // 兼容判断（InterfaceCompatibility）
    // ------------------------------------------------------------------

    #[test]
    fn compatibility_matches_exact_version() {
        let provided = provided("operune:web", "actions", 1, 2, 3);
        assert!(req("operune:web/actions@^1.2.3").satisfied_by(&provided));
        assert!(req("operune:web/actions@=1.2.3").satisfied_by(&provided));
        assert!(!req("operune:web/actions@=1.2.4").satisfied_by(&provided));
    }

    #[test]
    fn compatibility_caret_within_major() {
        // ^1.2.0：同 major 内 minor/patch 升级兼容（§13.2 规则）。
        let r = req("operune:web/actions@^1.2.0");
        assert!(r.satisfied_by(&provided("operune:web", "actions", 1, 2, 0)));
        assert!(r.satisfied_by(&provided("operune:web", "actions", 1, 5, 9)));
        assert!(!r.satisfied_by(&provided("operune:web", "actions", 1, 1, 0)));
        assert!(!r.satisfied_by(&provided("operune:web", "actions", 2, 0, 0)));
    }

    #[test]
    fn compatibility_zero_major_rules() {
        // ^0.2.0：0.x 中 minor 是破坏性变更。
        let r = req("operune:web/actions@^0.2.0");
        assert!(r.satisfied_by(&provided("operune:web", "actions", 0, 2, 5)));
        assert!(!r.satisfied_by(&provided("operune:web", "actions", 0, 3, 0)));
        // ^0.0.1：仅完全相等。
        let exact = req("operune:web/actions@^0.0.1");
        assert!(exact.satisfied_by(&provided("operune:web", "actions", 0, 0, 1)));
        assert!(!exact.satisfied_by(&provided("operune:web", "actions", 0, 0, 2)));
    }

    #[test]
    fn compatibility_range_boundaries() {
        let r = req("operune:web/actions@>=1.2.3, <2.0.0");
        assert!(r.satisfied_by(&provided("operune:web", "actions", 1, 2, 3)));
        assert!(r.satisfied_by(&provided("operune:web", "actions", 1, 9, 9)));
        assert!(!r.satisfied_by(&provided("operune:web", "actions", 1, 2, 2)));
        assert!(!r.satisfied_by(&provided("operune:web", "actions", 2, 0, 0)));
    }

    #[test]
    fn compatibility_star_matches_any() {
        let r = req("operune:web/actions@*");
        assert!(r.satisfied_by(&provided("operune:web", "actions", 0, 0, 0)));
        assert!(r.satisfied_by(&provided("operune:web", "actions", 99, 0, 0)));
    }

    #[test]
    fn compatibility_requires_package_and_interface_match() {
        let r = req("operune:web/actions@^1.2.3");
        assert!(!r.satisfied_by(&provided("operune:web", "assets", 1, 2, 3)));
        assert!(!r.satisfied_by(&provided("wasi:http", "actions", 1, 2, 3)));
    }

    #[test]
    fn compatibility_free_function_equals_method() {
        let provided = provided("operune:web", "actions", 1, 2, 3);
        let r = req("operune:web/actions@^1.2.0");
        assert_eq!(
            interface_compatible(&provided, &r),
            r.satisfied_by(&provided)
        );
    }

    // ------------------------------------------------------------------
    // proptest
    // ------------------------------------------------------------------

    fn any_version() -> impl proptest::strategy::Strategy<Value = ComponentVersion> {
        proptest::prelude::any::<(u32, u32, u32)>()
            .prop_map(|(major, minor, patch)| ComponentVersion::from_parts(major, minor, patch))
    }

    fn any_interface_id() -> impl proptest::strategy::Strategy<Value = InterfaceId> {
        (proptest::prelude::any::<u32>(), any_version()).prop_map(|(seed, version)| {
            InterfaceId::new(
                ok(PackageName::new(format!("ns:pk{seed}")), "package"),
                ok(InterfaceName::new(format!("if{seed}")), "interface"),
                version,
            )
        })
    }

    proptest::proptest! {
        #[test]
        fn interface_id_display_parse_roundtrip_prop(id in any_interface_id()) {
            proptest::prop_assert_eq!(id.to_string().parse::<InterfaceId>(), Ok(id));
        }

        #[test]
        fn requirement_display_parse_is_fixed_point(seed in proptest::prelude::any::<u32>(), req_text in proptest::prelude::prop_oneof![
            proptest::prelude::Just("^1.2.3"), proptest::prelude::Just("1.2.3"), proptest::prelude::Just(">=1.2.3, <2.0.0"), proptest::prelude::Just("*"), proptest::prelude::Just("=0.1.0"), proptest::prelude::Just("~0.2.0"), proptest::prelude::Just("^0.0.1"), proptest::prelude::Just("<0.5.0"),
        ]) {
            let text = format!("ns:pk{seed}/if{seed}@{req_text}");
            let parsed = ok(text.parse::<InterfaceRequirement>(), "requirement parse");
            let reparsed = ok(parsed.to_string().parse::<InterfaceRequirement>(), "display reparse");
            proptest::prop_assert_eq!(&parsed, &reparsed);
            proptest::prop_assert_eq!(parsed.to_string(), reparsed.to_string());
        }

        #[test]
        fn satisfaction_is_semver_matches(seed in proptest::prelude::any::<u32>(), v in any_version(), req_text in proptest::prelude::prop_oneof![
            proptest::prelude::Just("^1.2.3"), proptest::prelude::Just(">=1.2.3, <2.0.0"), proptest::prelude::Just("*"), proptest::prelude::Just("^0.2.0"), proptest::prelude::Just("^0.0.1"),
        ]) {
            let package = ok(PackageName::new(format!("ns:pk{seed}")), "package");
            let interface = ok(InterfaceName::new(format!("if{seed}")), "interface");
            let provided = InterfaceId::new(package.clone(), interface.clone(), v);
            let requirement = InterfaceRequirement::new(
                package,
                interface,
                ok(VersionReq::parse(req_text), "version req"),
            );
            let expected = requirement.version_req()
                .matches(&semver::Version::new(u64::from(v.major()), u64::from(v.minor()), u64::from(v.patch())));
            proptest::prop_assert_eq!(requirement.satisfied_by(&provided), expected);
        }
    }
}
