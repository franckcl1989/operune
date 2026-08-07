//! 0.3.0 Stateful Runtime（§41）——typed Component state service（§41.2 MUST）
//! 的领域类型。
//!
//! 契约面：`operune:state@0.1.0`（state.wit / declaration.wit / migration.wit，
//! 已提交稳定）。语义边界（state.wit 顶部注释）：
//!
//! - State 是 **Component 产生的权威持久业务状态**（§41.2 三分离），不是
//!   管理员输入（Config）、不是凭据（Secret）；权威状态落在 Core-managed
//!   state store（§20.5），**绝不把 linear memory 当持久事实源**（§41.1 /
//!   P8）；
//! - key 命名空间属于**安装实例私有**（InstallationId 作用域，§19.4）：不
//!   存在跨安装实例的 key 引用，因此无 key 级 grant 面（与 operune:secret
//!   不同，见 secret.wit）；
//! - 平台不解析、不解释 value 内容（P6：Core 永远不懂具体运维产品）；值的
//!   结构化形态是 Component 与自身 schema 之间的事实，平台侧的类型化表达
//!   在操作层（事务 / CAS / schema version / 预算 / 预期失败闭集），不在
//!   value 内；
//! - 运行时操作绑定"当前声明的 schema version"（state.wit：`begin-transaction`
//!   显式携带版本参数；升级路径 = 显式 migration，§20.5）。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::bytes::BoundedBytes;
use crate::error::{DomainError, ValueKind};
use crate::id::validate_name_key;

/// state key 长度上界（字节）。结构性上界：防止无界 key（§19.1 输入不可信、
/// §19.3 宿主侧体积上限）；与 `MAX_IDENTIFIER_LEN`（id.rs）同量级。
/// WIT 的"Core 宿主侧上限"是策略层约束（§7.4），Domain 结构性上界必须覆盖
/// 其上。
pub(crate) const MAX_STATE_KEY_LEN: usize = 255;

/// state value 单值长度上界（字节）。结构性上界：`over-budget`（state.wit）
/// 的 Domain 侧硬界；安装实例总预算等策略上限（§7.4）由 application /
/// 适配层在 Domain 界内配置。
pub(crate) const MAX_STATE_VALUE_LEN: usize = 1024 * 1024;

/// 状态键（§13.5 record wrapper，非裸 string；与 WIT `state-key` record
/// 严格对齐）。
///
/// 不变量（validate-on-construct，§13.3；WIT state-key 明文）：
/// - 非空；
/// - 仅含可打印 ASCII `[A-Za-z0-9._-/]`（不含控制字符与空白）——白名单即
///   校验：`\`（Windows 路径分隔符）、控制字符、空白及其它任意字符一律拒绝
///   （§14.2 日志注入防护）；`/` 是 **WIT 契约允许的** key 内分隔符（如
///   `jobs/123`），不属于禁止的路径分隔符；
/// - 长度 ≤ [`MAX_STATE_KEY_LEN`] 字节。
///
/// 命名空间语义：key 命名空间属于安装实例私有（InstallationId 作用域，
/// §19.4；state.wit 明文"本契约不存在跨安装实例的 key 引用"）。Core 只按
/// 字符串等价比较（§6.7），Domain 不做 key 语义解析。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateKey(String);

impl StateKey {
    /// 从 WIT `state-key` 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_name_key(&value, MAX_STATE_KEY_LEN, true, ValueKind::StateKey)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for StateKey {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for StateKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StateKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 状态值：平台不透明的序列化业务字节（与 WIT `state-value` record 对齐）。
///
/// 语义（state.wit 明文）：平台不解析、不解释 value 内容（P6）；值的结构化
/// 形态是 Component 与自身 schema 之间的事实（typed 由 schema version 与
/// Component 自身序列化保证）。空值是合法值（如"清空后的标记"）；值比较按
/// 字节等价（CAS 期望值比较语义，state.wit `cas`）。
///
/// 不变量（validate-on-construct，§13.3）：长度 ≤ [`MAX_STATE_VALUE_LEN`]
/// 字节（超限即 `over-budget` 的 Domain 侧表达）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StateValue(BoundedBytes);

impl StateValue {
    /// 从有界字节构造（§13.3 边界解析一次；超限返回
    /// [`DomainError::InvalidValue`]）。
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        Ok(Self(BoundedBytes::new(
            data.into(),
            MAX_STATE_VALUE_LEN,
            ValueKind::StateValue,
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

    /// 是否为空值（空值是合法值）。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 取出底层字节（存储层 / 适配层边界输出，§13.3）。
    pub fn into_vec(self) -> Vec<u8> {
        self.0.into_vec()
    }
}

impl Serialize for StateValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.as_slice())
    }
}

impl<'de> Deserialize<'de> for StateValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Self::new(data).map_err(serde::de::Error::custom)
    }
}

/// 安装实例 state store 的 schema 版本（契约层 "versioned state"，
/// §41.2 / §20.5；与 WIT `state-schema-version` record 严格对齐）。
///
/// 形态（WIT 明文）：**u32 数值**，不是语义化版本字符串——Core 以
/// `migration` interface 驱动 store 从旧版本迁移到新声明版本（§20.5：
/// Migration 必须是版本化、原子、可失败并具备 rollback policy 的显式
/// 操作），比较按数值相等/序（`Ord`）。
///
/// 任意 u32 都是合法版本，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateSchemaVersion(u32);

impl StateSchemaVersion {
    /// 从 u32 构造（与 WIT `state-schema-version.value` 字段一一对应；
    /// 不可失败）。
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// 原始 u32 视图（持久化 / 展示）。
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

impl fmt::Display for StateSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for StateSchemaVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for StateSchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        Ok(Self::from_u32(value))
    }
}

/// Core 侧 state 事务身份（§41.2 事务/原子更新语义；§18.5 迁移日志 /
/// §41.2 state audit 的操作关联句柄）。
///
/// 与 WIT 的关系：`operune:state` 的 `state-transaction` 是 **resource 句柄**
/// （guest 侧有生命周期的 opaque 句柄，wire 上无数值暴露）；本类型是 Core
/// 内部的事务标识（迁移日志、审计记录"key、操作类型、事务结果、安装实例"，
/// state.wit 审计注释），**不是 guest 可见的 WIT 类型**。
///
/// 任意 u64 都是合法事务标识，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateTransactionId(u64);

impl StateTransactionId {
    /// 从 u64 构造（Core 分配；不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StateTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for StateTransactionId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for StateTransactionId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn state_key_accepts_wit_charset() {
        for key in [
            "a",
            "A0",
            "jobs",
            "jobs/123",
            "a.b_c-d/e",
            "_",
            ".",
            "-",
            "/",
        ] {
            assert!(
                StateKey::new(key).is_ok(),
                "{key:?} is in the WIT state-key charset [A-Za-z0-9._-/] and must be accepted"
            );
        }
        // 恰好 255 字节：边界内合法。
        let max_len = "x".repeat(MAX_STATE_KEY_LEN);
        assert_eq!(
            StateKey::new(max_len.clone()).map(|key| key.as_str().len()),
            Ok(MAX_STATE_KEY_LEN)
        );
    }

    #[test]
    fn state_key_rejects_invalid() {
        for bad in [
            "", "a b",  // 空白不在字符集
            "a\nb", // 控制字符
            "a\tb", "a\u{0}b",
            "a\\b", // Windows 路径分隔符：任何 WIT 字符集都不含
            "a:b", "a@b", "a+b", "a~b", "a=b", "a,b", "键", // 非 ASCII
        ] {
            assert!(
                matches!(
                    StateKey::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::StateKey,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
        assert!(matches!(
            StateKey::new("x".repeat(MAX_STATE_KEY_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::StateKey,
                ..
            })
        ));
    }

    #[test]
    fn state_key_display_fromstr_serde_roundtrip() {
        let key = ok(StateKey::new("jobs/123"), "key");
        assert_eq!(key.to_string(), "jobs/123");
        assert_eq!(key.to_string().parse::<StateKey>(), Ok(key.clone()));
        let json = ok(serde_json::to_string(&key), "serialize");
        assert_eq!(json, "\"jobs/123\"");
        assert_eq!(
            ok(serde_json::from_str::<StateKey>(&json), "deserialize"),
            key
        );
        // 反序列化边界同样执行校验（§13.3）。
        assert!(serde_json::from_str::<StateKey>("\"\"").is_err());
        assert!(serde_json::from_str::<StateKey>("\"a b\"").is_err());
        assert!(serde_json::from_str::<StateKey>("\"a\\\\b\"").is_err());
    }

    #[test]
    fn state_value_accepts_bounded_bytes() {
        let empty = ok(StateValue::new(Vec::new()), "empty");
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        let value = ok(StateValue::new(vec![0u8, 1, 2, 255]), "value");
        assert_eq!(value.as_slice(), &[0u8, 1, 2, 255]);
        assert_eq!(value.len(), 4);
        // 恰好上限字节：合法。
        let max = vec![7u8; MAX_STATE_VALUE_LEN];
        assert_eq!(
            ok(StateValue::new(max.clone()), "max").len(),
            MAX_STATE_VALUE_LEN
        );
    }

    #[test]
    fn state_value_rejects_oversized() {
        let oversized = vec![0u8; MAX_STATE_VALUE_LEN + 1];
        assert!(matches!(
            StateValue::new(oversized),
            Err(DomainError::InvalidValue {
                kind: ValueKind::StateValue,
                ..
            })
        ));
    }

    #[test]
    fn state_value_bytes_equality() {
        // CAS 期望值按字节等价比较（state.wit `cas`）。
        let a = ok(StateValue::new(vec![1, 2, 3]), "a");
        let b = ok(StateValue::new(vec![1, 2, 3]), "b");
        let c = ok(StateValue::new(vec![1, 2, 4]), "c");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn state_value_serde_roundtrip() {
        let value = ok(StateValue::new(vec![0u8, 255, 7]), "value");
        let json = ok(serde_json::to_string(&value), "serialize");
        assert_eq!(json, "[0,255,7]");
        assert_eq!(
            ok(serde_json::from_str::<StateValue>(&json), "deserialize"),
            value
        );
        // 反序列化边界同样校验体积（§13.3）。
        let huge = format!("[{}]", vec!["0"; MAX_STATE_VALUE_LEN + 1].join(","));
        assert!(serde_json::from_str::<StateValue>(&huge).is_err());
    }

    #[test]
    fn state_schema_version_roundtrip() {
        let v = StateSchemaVersion::from_u32(7);
        assert_eq!(v.as_u32(), 7);
        assert_eq!(v.to_string(), "7");
        assert!(StateSchemaVersion::from_u32(0) < v);
        let json = ok(serde_json::to_string(&v), "serialize");
        assert_eq!(json, "7");
        assert_eq!(
            ok(
                serde_json::from_str::<StateSchemaVersion>(&json),
                "deserialize"
            ),
            v
        );
    }

    #[test]
    fn state_transaction_id_roundtrip() {
        let id = StateTransactionId::from_u64(42);
        assert_eq!(id.as_u64(), 42);
        assert_eq!(id.to_string(), "42");
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "42");
        assert_eq!(
            ok(
                serde_json::from_str::<StateTransactionId>(&json),
                "deserialize"
            ),
            id
        );
    }
}
