use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::{DomainError, ValueKind};

/// 标识符类值对象的结构性上界（字节数）。
///
/// 非空 + 长度上界 + 无控制字符：防止无界 descriptor 元数据（§19.1 输入不可信、
/// §19.3 descriptor 返回值有宿主侧体积上限）与日志注入；同时保证注册表逻辑键
/// 稳定可比（§6.7：Core 只按字符串等价比较，不做语义解析）。
pub(crate) const MAX_IDENTIFIER_LEN: usize = 255;

/// 标识符共用的结构性校验（validate-on-construct，§13.3）。
pub(crate) fn validate_identifier(value: &str, kind: ValueKind) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::invalid_value(kind, "must not be empty"));
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(DomainError::invalid_value(
            kind,
            format!("must not exceed {MAX_IDENTIFIER_LEN} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::invalid_value(
            kind,
            "must not contain control characters",
        ));
    }
    Ok(())
}

/// 名称类键（state key / secret name / event topic）共用的结构性校验
/// （validate-on-construct，§13.3）：非空、≤ `max` 字节、且仅含白名单
/// 可打印 ASCII 字符 `[A-Za-z0-9._-]`（`allow_slash` 为 true 时额外允许
/// `/`）。
///
/// 与 WIT 契约的字符集不变量逐字对齐：
/// - `operune:state` `state-key`：`[A-Za-z0-9._-/]`（含 `/`）；
/// - `operune:secret` `secret-name`：`[A-Za-z0-9._-]`；
/// - `operune:event` `topic`：`[A-Za-z0-9._-]`。
///
/// 白名单即校验：控制字符、空白、`\`（Windows 路径分隔符）及其它任意
/// 字符自动被拒绝（§14.2 日志注入防护；`\` 在任何契约字符集中都不存在）。
pub(crate) fn validate_name_key(
    value: &str,
    max: usize,
    allow_slash: bool,
    kind: ValueKind,
) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::invalid_value(kind, "must not be empty"));
    }
    if value.len() > max {
        return Err(DomainError::invalid_value(
            kind,
            format!("must not exceed {max} bytes"),
        ));
    }
    let all_ascii = value.bytes().all(|b| {
        matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-')
            || (allow_slash && b == b'/')
    });
    if !all_ascii {
        let charset = if allow_slash {
            "[A-Za-z0-9._-/]"
        } else {
            "[A-Za-z0-9._-]"
        };
        return Err(DomainError::invalid_value(
            kind,
            format!(
                "must only contain printable ASCII {charset} (no control characters, whitespace, or other characters)"
            ),
        ));
    }
    Ok(())
}

/// 作者声明的逻辑产品/应用身份（§6.7 / §19.4 `ComponentId`），与 WIT
/// `operune:component@0.1.0` 的 `component-id` record（唯一稳定逻辑键，Core
/// 只按字符串等价比较并作为注册表逻辑键，不做语义解析）语义一致。
///
/// 与 [`InstallationId`]、[`ContentDigest`]、[`ComponentVersion`] 永久分离
/// （§19.4 四种身份必须永久分离）：彼此类型不同，不存在相互转换。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制字符。
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ComponentId(String);

impl ComponentId {
    /// 从作者声明 / 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::ComponentId)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ComponentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ComponentId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for ComponentId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ComponentId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Core 创建的安装实例身份（§19.4 `InstallationId`）：承载 grant、enable/active
/// 状态与本机生命周期（§17 / §19.4），由 Core 创建并持久化（§18.3）。文件、
/// 上传路径与 URL 永远不能成为逻辑身份事实源（§6.7）。
///
/// 与 [`ComponentId`] / [`ComponentVersion`] / [`ContentDigest`] 永久分离
/// （§19.4）：类型不同，不存在相互转换。
///
/// 底层表示 `uuid::Uuid`（UUID v4 随机生成；§13.2：持久 ID 用 `uuid::Uuid`
/// 再包一层领域 newtype）。任意 `Uuid` 都是合法实例身份，故构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InstallationId(Uuid);

impl InstallationId {
    /// 创建新的安装实例身份（随机 UUID v4；Core 在安装流程中创建，§19.2）。
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// 从已有 `Uuid` 包装（持久化恢复 / 适配层边界输入，§13.3）。
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// 底层 `Uuid` 视图（持久化 / 展示）。
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for InstallationId {
    /// 新安装实例身份（同 [`InstallationId::new`]）。
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for InstallationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for InstallationId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| DomainError::invalid_value(ValueKind::InstallationId, e.to_string()))
    }
}

impl Serialize for InstallationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for InstallationId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

/// 平台能力身份（§13.1 Capability ID；§17 Capability 安全模型）。
///
/// 0.1.0 的 Resolution 只覆盖 Host/WASI 与 Operune 平台能力（§17.5）；能力 ID
/// 的语义解析（WIT import 匹配、grant scope 校验）属于 application /
/// runtime-wasm 的 resolution 职责，Domain 只做结构性校验与强类型区分。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制字符。
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// 从 WIT import / policy 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::CapabilityId)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for CapabilityId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for CapabilityId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for CapabilityId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn component_id_accepts_valid() {
        assert!(ComponentId::new("my-component").is_ok());
        assert!(ComponentId::new("组件-1").is_ok());
        assert!(ComponentId::new("a").is_ok());
        // 恰好 255 字节：边界内合法。
        let max_len = "x".repeat(MAX_IDENTIFIER_LEN);
        assert_eq!(
            ComponentId::new(max_len.clone()).map(|id| id.as_str().len()),
            Ok(MAX_IDENTIFIER_LEN)
        );
    }

    #[test]
    fn component_id_rejects_empty() {
        assert!(matches!(
            ComponentId::new(""),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ComponentId,
                ..
            })
        ));
    }

    #[test]
    fn component_id_rejects_too_long() {
        assert!(matches!(
            ComponentId::new("x".repeat(MAX_IDENTIFIER_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ComponentId,
                ..
            })
        ));
    }

    #[test]
    fn component_id_rejects_control_chars() {
        for bad in ["a\nb", "a\tb", "a\u{0}b"] {
            assert!(
                matches!(
                    ComponentId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ComponentId,
                        ..
                    })
                ),
                "control char in {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn component_id_eq_and_ord() {
        let a = ok(ComponentId::new("alpha"), "alpha");
        let a2 = ok(ComponentId::new("alpha"), "alpha");
        let b = ok(ComponentId::new("beta"), "beta");
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert!(a < b);
    }

    #[test]
    fn component_id_display_fromstr_roundtrip() {
        let id = ok(ComponentId::new("my-component"), "id");
        assert_eq!(id.to_string(), "my-component");
        assert_eq!(id.to_string().parse::<ComponentId>(), Ok(id.clone()));
    }

    #[test]
    fn component_id_serde_roundtrip() {
        let id = ok(ComponentId::new("my-component"), "id");
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "\"my-component\"");
        assert_eq!(
            ok(serde_json::from_str::<ComponentId>(&json), "deserialize"),
            id
        );
    }

    #[test]
    fn component_id_serde_rejects_invalid() {
        // 反序列化边界同样校验（§13.3：边界解析一次，不重复校验不变量）。
        assert!(serde_json::from_str::<ComponentId>("\"\"").is_err());
        assert!(serde_json::from_str::<ComponentId>("\"bad\\ncontrol\"").is_err());
    }

    #[test]
    fn installation_id_new_is_random_unique() {
        assert_ne!(InstallationId::new(), InstallationId::new());
        assert_ne!(InstallationId::new(), InstallationId::new());
    }

    #[test]
    fn installation_id_parse_roundtrip() {
        let id = InstallationId::new();
        let s = id.to_string();
        assert_eq!(s.parse::<InstallationId>(), Ok(id));
        // uuid crate 接受无连字符形式（适配层常用）。
        let simple = s.replace('-', "");
        assert_eq!(simple.parse::<InstallationId>(), Ok(id));
    }

    #[test]
    fn installation_id_rejects_invalid_uuid() {
        assert!(matches!(
            "not-a-uuid".parse::<InstallationId>(),
            Err(DomainError::InvalidValue {
                kind: ValueKind::InstallationId,
                ..
            })
        ));
        assert!("".parse::<InstallationId>().is_err());
    }

    #[test]
    fn installation_id_from_uuid_roundtrip() {
        let uuid = Uuid::new_v4();
        let id = InstallationId::from_uuid(uuid);
        assert_eq!(id.as_uuid(), uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn installation_id_serde_roundtrip() {
        let id = InstallationId::new();
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<InstallationId>(&json), "deserialize"),
            id
        );
    }

    #[test]
    fn capability_id_accepts_wit_style() {
        assert!(CapabilityId::new("wasi:http/outgoing-handler").is_ok());
        assert!(CapabilityId::new("operune:component/descriptor").is_ok());
    }

    #[test]
    fn capability_id_rejects_invalid() {
        for bad in ["", "bad\0id", "bad\nid"] {
            assert!(
                matches!(
                    CapabilityId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::CapabilityId,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn capability_id_serde_roundtrip() {
        let id = ok(
            CapabilityId::new("wasi:http/outgoing-handler"),
            "capability",
        );
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<CapabilityId>(&json), "deserialize"),
            id
        );
    }
}
