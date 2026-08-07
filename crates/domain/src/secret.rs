//! 0.3.0 Stateful Runtime（§41）——SecretStore port 的领域类型（§41.2 MUST：
//! 独立 SecretStore port 与 secret grant/read semantics）。
//!
//! 契约面：`operune:secret@0.1.0`（secret.wit，已提交稳定）。语义边界
//! （secret.wit 顶部注释 / §16.6）：
//!
//! - Secret 是 **受专门访问控制与防泄漏规则保护的敏感值**（§41.2 三分离）；
//!   读取按 grant（§17.3 "secret names" 是 scope 维度之一，§17.5 四层授权链
//!   第四层 invocation-time enforcement）；
//! - 防泄漏契约（§16.6 明文）：secret 值**永不进入**日志、error context、
//!   panic report、metrics label、audit event；本模块只建模**非敏感元数据**
//!   （名称 / 版本），**绝不携带值**——值的进出（`read-secret` 返回值、
//!   SecretStore 的 secrecy/zeroize 包装）是 application / 适配层与存储层
//!   的职责；
//! - 故意**不区分**"名称不存在"与"无权限"（`denied` 同时覆盖，防止把
//!   secret 契约变成存在性预言机）——错误语义属于 WIT 层，Domain 只建模
//!   名称与版本的强类型。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::id::validate_name_key;

/// secret name 长度上界（字节）。结构性上界（§19.1 输入不可信；
/// secret.wit：长度受 Core 宿主侧上限约束）。
pub(crate) const MAX_SECRET_NAME_LEN: usize = 255;

/// secret 名称（§13.5 record wrapper，非裸 string；与 WIT `secret-name`
/// record 严格对齐）。
///
/// 不变量（validate-on-construct，§13.3；WIT secret-name 明文）：
/// - 非空；
/// - 仅含 `[A-Za-z0-9._-]`（不含 `/`——与 state key 的字符集不同）；
/// - 长度 ≤ [`MAX_SECRET_NAME_LEN`] 字节。
///
/// 语义：名称是 grant scope 的键（§17.3），不是 secret 值的一部分；
/// 名称本身非敏感。`SecretName` 不是 `SecretValue`——值的类型由
/// application/适配层以 secrecy/zeroize 包装（§16.6），Domain 不建模值。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// 从 WIT `secret-name` 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_name_key(&value, MAX_SECRET_NAME_LEN, false, ValueKind::SecretName)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for SecretName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for SecretName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SecretName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// secret 版本（轮换检测；与 WIT `secret-version` record 严格对齐）。
///
/// 语义（secret.wit 明文）：每次轮换递增；供长驻 guest 检测"当前持有的值
/// 已过时"后重新读取。版本号本身不敏感，但审计关联仍记录它（§41.2
/// secret audit：审计事件只含名称、版本、结果与安装实例，**不含值**）。
///
/// 任意 u64 都是合法版本，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretVersion(u64);

impl SecretVersion {
    /// 从 u64 构造（与 WIT `secret-version.value` 字段一一对应；不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SecretVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for SecretVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for SecretVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 已授予 secret 的非敏感元数据（与 WIT `secret-metadata` record 对齐；
/// `list-granted-secrets` 列表项）。
///
/// 防泄漏边界（§16.6 / secret.wit 明文）：**不含 secret 值**——本类型只
/// 承载名称与版本；任何情况下不得向本类型添加值字段（"metadata 不含值"、
/// 审计事件不含值）。derives `Debug` 安全（仅名称/版本，无敏感内容）。
///
/// 构造不可失败（字段各自在构造时已验证）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SecretMetadata {
    name: SecretName,
    version: SecretVersion,
}

impl SecretMetadata {
    /// 构造非敏感元数据（名称 + 版本；§13.3 边界解析一次）。
    pub fn new(name: SecretName, version: SecretVersion) -> Self {
        Self { name, version }
    }

    /// 已授予的 secret 名称。
    pub fn name(&self) -> &SecretName {
        &self.name
    }

    /// 当前版本（轮换检测，§16.6）。
    pub const fn version(&self) -> SecretVersion {
        self.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn secret_name_accepts_wit_charset() {
        for name in [
            "db-password",
            "api_key",
            "tls.cert",
            "a",
            "A0",
            "_",
            ".",
            "-",
        ] {
            assert!(
                SecretName::new(name).is_ok(),
                "{name:?} is in the WIT secret-name charset [A-Za-z0-9._-] and must be accepted"
            );
        }
        let max_len = "x".repeat(MAX_SECRET_NAME_LEN);
        assert_eq!(
            SecretName::new(max_len.clone()).map(|name| name.as_str().len()),
            Ok(MAX_SECRET_NAME_LEN)
        );
    }

    #[test]
    fn secret_name_rejects_invalid() {
        for bad in [
            "", "a/b", // '/' 不在 secret-name 字符集（与 state key 不同）
            "a\\b", "a b", "a\nb", "a\u{0}b", "a@b", "键",
        ] {
            assert!(
                matches!(
                    SecretName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::SecretName,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
        assert!(matches!(
            SecretName::new("x".repeat(MAX_SECRET_NAME_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::SecretName,
                ..
            })
        ));
    }

    #[test]
    fn secret_name_display_fromstr_serde_roundtrip() {
        let name = ok(SecretName::new("db-password"), "name");
        assert_eq!(name.to_string(), "db-password");
        assert_eq!(name.to_string().parse::<SecretName>(), Ok(name.clone()));
        let json = ok(serde_json::to_string(&name), "serialize");
        assert_eq!(json, "\"db-password\"");
        assert_eq!(
            ok(serde_json::from_str::<SecretName>(&json), "deserialize"),
            name
        );
        assert!(serde_json::from_str::<SecretName>("\"a/b\"").is_err());
    }

    #[test]
    fn secret_version_roundtrip() {
        let version = SecretVersion::from_u64(9);
        assert_eq!(version.as_u64(), 9);
        assert_eq!(version.to_string(), "9");
        let json = ok(serde_json::to_string(&version), "serialize");
        assert_eq!(json, "9");
        assert_eq!(
            ok(serde_json::from_str::<SecretVersion>(&json), "deserialize"),
            version
        );
    }

    #[test]
    fn secret_metadata_carries_name_and_version() {
        let name = ok(SecretName::new("db-password"), "name");
        let metadata = SecretMetadata::new(name.clone(), SecretVersion::from_u64(2));
        assert_eq!(metadata.name(), &name);
        assert_eq!(metadata.version(), SecretVersion::from_u64(2));
        let json = ok(serde_json::to_string(&metadata), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<SecretMetadata>(&json), "deserialize"),
            metadata
        );
    }
}
