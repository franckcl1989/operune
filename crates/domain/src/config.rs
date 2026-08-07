//! 0.3.0 Stateful Runtime（§41）——Component config storage/validation
//! （§41.2 MUST）的领域类型。
//!
//! 契约面：`operune:config@0.1.0`（config.wit / declaration.wit /
//! validator.wit，已提交稳定）。语义边界（config.wit 顶部注释）：
//!
//! - Config 是 **管理员/系统提供、具有 validation 和版本语义的输入**
//!   （§41.2 三分离），**不是 Component 产生的权威状态**（与 state 的本质
//!   区别：Config 无平台级 migration——"解释/迁移"由新版本自身的读取逻辑
//!   承担，config.wit）；
//! - **只读给 guest**：写侧不在本契约（管理员/系统写入，Core 执行
//!   validation）；guest 侧契约只有读取；
//! - 敏感值**不得**放进 config（凭据/密钥属于 operune:secret，§16.6；
//!   config 只承载非敏感的业务输入）；
//! - 配置以"有界字节 + 声明格式"表达（config.wit 论证：WIT 无法表达任意
//!   per-component 配置 schema，P6），结构化 typed read 是未来演进。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::BoundedBytes;
use crate::error::{DomainError, ValueKind};

/// config value 长度上界（字节）。结构性上界：config.wit `config-value` 的
/// 宿主侧硬上限（§7.4 / §7.5）在 Domain 侧的结构表达。
pub(crate) const MAX_CONFIG_VALUE_LEN: usize = 1024 * 1024;

/// 配置快照修订号（与 WIT `config-version` record 严格对齐）。
///
/// 语义（config.wit 明文）：每次被接受的配置写入递增（安装实例作用域）；
/// 用于变化检测（`get-config-version` 轮询后重新读取快照）与审计关联
/// （§41.2 config audit）。注意与 [`ConfigSchemaVersion`] 的区别：这是
/// "当前配置值"的修订号，不是配置契约的 schema 版本。
///
/// 任意 u64 都是合法修订号，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfigRevision(u64);

impl ConfigRevision {
    /// 从 u64 构造（与 WIT `config-version.revision` 字段一一对应；
    /// 不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConfigRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ConfigRevision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ConfigRevision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 配置值的声明格式（闭集 enum；与 WIT `config-format` enum 严格对齐，
/// §6.3 enum 表达闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFormat {
    /// JSON 文本。写入时 Core 先做格式解析校验（必须可解析为 JSON，
    /// config.wit）。
    Json,
    /// TOML 文本。写入时 Core 先做格式解析校验。
    Toml,
    /// 平台不透明的原始字节。无格式解析，仅体积与预算校验。
    Raw,
}

impl ConfigFormat {
    /// 与 WIT `config-format` 变体名一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Raw => "raw",
        }
    }

    /// 从 WIT 变体名解析（适配层 / 持久化边界，§13.3 边界解析一次）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "raw" => Ok(Self::Raw),
            _ => Err(DomainError::invalid_value(
                ValueKind::ConfigFormat,
                format!("{s:?} is not a config-format variant (json | toml | raw)"),
            )),
        }
    }
}

impl fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ConfigFormat {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for ConfigFormat {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ConfigFormat {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 配置契约的 schema 版本（与 WIT `config-schema-version` record 严格
/// 对齐）。
///
/// 语义（config.wit 明文）：本 ComponentVersion 期望的配置契约版本；
/// 升级到新声明版本时，现有配置用新版本的 `validator` 重新校验
/// （re-validation，§17.3/§17.5 语义一致）。注意与 [`ConfigRevision`]
/// （快照修订号）的区别。
///
/// 任意 u32 都是合法版本，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ConfigSchemaVersion(u32);

impl ConfigSchemaVersion {
    /// 从 u32 构造（与 WIT `config-schema-version.value` 字段一一对应；
    /// 不可失败）。
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// 原始 u32 视图（持久化 / 展示）。
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ConfigSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ConfigSchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for ConfigSchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Ok(Self::from_u32(value))
    }
}

/// 配置值：有界字节（格式由 config declaration 声明；与 WIT `config-value`
/// record 对齐）。
///
/// 语义（config.wit 明文）：值**通过验证后才成为当前配置**（写入时 Core
/// 调用激活中 ComponentVersion 的 `validator` export，通过才原子切换）；
/// 运行时读取到的永远是已验证快照。激活门禁（§19.2 激活路径）保证存在
/// 当前配置时运行时读取必有快照。**Config 是输入，不是 Component 产生的
/// 状态**：本类型无任何写入口（guest 只读，§41.2）。
///
/// 不变量（validate-on-construct，§13.3）：长度 ≤ [`MAX_CONFIG_VALUE_LEN`]
/// 字节。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConfigValue(BoundedBytes);

impl ConfigValue {
    /// 从有界字节构造（§13.3 边界解析一次；超限返回
    /// [`DomainError::InvalidValue`]）。
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        Ok(Self(BoundedBytes::new(
            data.into(),
            MAX_CONFIG_VALUE_LEN,
            ValueKind::ConfigValue,
        )?))
    }

    /// 原始字节视图（只读）。
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// 字节数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空值。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 取出底层字节（存储层 / 适配层边界输出，§13.3）。
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl Serialize for ConfigValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for ConfigValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Self::new(data).map_err(serde::de::Error::custom)
    }
}

/// 原子配置快照（与 WIT `config-snapshot` record 对齐）。
///
/// 语义（config.wit 明文）：版本与值来自**同一次快照**（原子一致，
/// `get-config` 一次读取内）；guest 用 `get-config-version` 检测变化后
/// 重新读取新快照（0.3.0 无 async push，§8.3 Gate 通过前）。
///
/// 只读语义（§41.2）：Config 是管理员/系统提供的输入，本快照是 guest
/// 侧的唯一读取形态——不存在任何"guest 写入配置"的入口。
///
/// 构造不可失败（`revision` 与 `value` 均在各自构造时已验证）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    revision: ConfigRevision,
    value: ConfigValue,
}

impl ConfigSnapshot {
    /// 构造原子快照（版本 + 值一致；§13.3 边界解析一次，字段各自已校验）。
    pub fn new(revision: ConfigRevision, value: ConfigValue) -> Self {
        Self { revision, value }
    }

    /// 快照修订号。
    pub const fn revision(&self) -> ConfigRevision {
        self.revision
    }

    /// 快照值（已验证配置，§41.2 validation 语义）。
    pub fn value(&self) -> &ConfigValue {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn config_format_parse_display() {
        assert_eq!("json".parse::<ConfigFormat>(), Ok(ConfigFormat::Json));
        assert_eq!("toml".parse::<ConfigFormat>(), Ok(ConfigFormat::Toml));
        assert_eq!("raw".parse::<ConfigFormat>(), Ok(ConfigFormat::Raw));
        assert_eq!(ConfigFormat::Json.as_str(), "json");
        assert_eq!(ConfigFormat::Toml.to_string(), "toml");
        assert_eq!(ConfigFormat::Raw.to_string(), "raw");
        for bad in ["yaml", "JSON", "xml", "", "json "] {
            assert!(
                matches!(
                    bad.parse::<ConfigFormat>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ConfigFormat,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
    }

    #[test]
    fn config_format_serde_roundtrip() {
        for (format, name) in [
            (ConfigFormat::Json, "json"),
            (ConfigFormat::Toml, "toml"),
            (ConfigFormat::Raw, "raw"),
        ] {
            let json = ok(serde_json::to_string(&format), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<ConfigFormat>(&json), "deserialize"),
                format
            );
        }
        assert!(serde_json::from_str::<ConfigFormat>("\"yaml\"").is_err());
    }

    #[test]
    fn config_revision_roundtrip() {
        let revision = ConfigRevision::from_u64(3);
        assert_eq!(revision.as_u64(), 3);
        assert_eq!(revision.to_string(), "3");
        assert!(ConfigRevision::from_u64(2) < revision);
        let json = ok(serde_json::to_string(&revision), "serialize");
        assert_eq!(json, "3");
        assert_eq!(
            ok(serde_json::from_str::<ConfigRevision>(&json), "deserialize"),
            revision
        );
    }

    #[test]
    fn config_schema_version_roundtrip() {
        let version = ConfigSchemaVersion::from_u32(1);
        assert_eq!(version.as_u32(), 1);
        assert_eq!(version.to_string(), "1");
        let json = ok(serde_json::to_string(&version), "serialize");
        assert_eq!(json, "1");
        assert_eq!(
            ok(
                serde_json::from_str::<ConfigSchemaVersion>(&json),
                "deserialize"
            ),
            version
        );
    }

    #[test]
    fn config_value_bounds_and_serde() {
        let empty = ok(ConfigValue::new(Vec::new()), "empty");
        assert!(empty.is_empty());
        let value = ok(ConfigValue::new(b"{\"a\":1}".to_vec()), "value");
        assert_eq!(value.as_slice(), b"{\"a\":1}");
        assert_eq!(value.len(), 7);
        let max = vec![0u8; MAX_CONFIG_VALUE_LEN];
        assert_eq!(
            ok(ConfigValue::new(max.clone()), "max").len(),
            MAX_CONFIG_VALUE_LEN
        );
        assert!(matches!(
            ConfigValue::new(vec![0u8; MAX_CONFIG_VALUE_LEN + 1]),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ConfigValue,
                ..
            })
        ));
        let json = ok(serde_json::to_string(&value), "serialize");
        assert_eq!(json, "[123,34,97,34,58,49,125]");
        assert_eq!(
            ok(serde_json::from_str::<ConfigValue>(&json), "deserialize"),
            value
        );
    }

    #[test]
    fn config_snapshot_carries_revision_and_value() {
        let value = ok(ConfigValue::new(b"{\"a\":1}".to_vec()), "value");
        let snapshot = ConfigSnapshot::new(ConfigRevision::from_u64(3), value.clone());
        assert_eq!(snapshot.revision(), ConfigRevision::from_u64(3));
        assert_eq!(snapshot.value(), &value);
        // 快照保持版本 + 值一致（原子快照，config.wit）。
        let json = ok(serde_json::to_string(&snapshot), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<ConfigSnapshot>(&json), "deserialize"),
            snapshot
        );
    }
}
