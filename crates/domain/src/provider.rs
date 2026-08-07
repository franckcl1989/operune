//! 0.2.0 Capability Composition（§40.2）：Capability Provider identity。
//!
//! [`ProviderId`] 是"提供某能力（interface）的 Component 安装实例"的领域身份。
//! 与 [`CapabilityId`](crate::CapabilityId) 的语义关系（§17.5）：
//!
//! - [`CapabilityId`](crate::CapabilityId) 是**能力种类**身份（"需要哪种能力"，
//!   WIT import / policy 的规范化能力 id，0.1.0 Resolution 只覆盖 Host/WASI 与
//!   Operune 平台能力）；
//! - [`ProviderId`] 是**实例**身份（"哪个安装实例提供该能力"，0.2.0
//!   Component-to-Component provider graph 的节点身份）。
//!
//! 两者语义角色不同、类型不同、不存在相互转换。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::InstallationId;
use crate::error::{DomainError, ValueKind};

/// 0.2.0 Capability Provider 身份（§40.2 "Capability Provider identity"）。
///
/// provider 是"提供某能力的 Component 安装实例"（§17.5：Grant 的 durable
/// owner 是 `InstallationId`；provider 身份必须可追溯到 InstallationId，但
/// 不能与 InstallationId 混淆）。因此：
///
/// - [`ProviderId::from_installation`] 从安装实例身份**确定性派生**：同一
///   安装实例永远得到同一 ProviderId（§40.4：同一 Component set + 同一
///   policy → 同一 provider graph；graph persistence/recovery 后可重建相同
///   身份）；
/// - 底层 `Uuid` 与派生来源的 InstallationId 相同，但 [`ProviderId`] 与
///   [`InstallationId`] 是不同类型且**不存在 ProviderId → InstallationId 的
///   转换**：从 ProviderId 取回 InstallationId 只能通过 graph 节点
///   （[`ProviderNode`](crate::ProviderNode)），防止把"provider 角色"与
///   "安装实例"在 API 中混用（§19.4 身份分离精神：不同语义角色不同类型）。
///
/// 与 [`CapabilityId`](crate::CapabilityId)（能力种类）的区分见模块文档。
///
/// 底层表示 `uuid::Uuid`（§13.2：持久 ID 用 `uuid::Uuid` 再包一层领域
/// newtype）。任意 `Uuid` 都是合法 provider 身份，故构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProviderId(Uuid);

impl ProviderId {
    /// 从安装实例身份确定性派生 provider 身份（§17.5：provider 身份锚定
    /// 安装实例，不是独立随机身份）。
    pub fn from_installation(installation: InstallationId) -> Self {
        Self(installation.as_uuid())
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

impl fmt::Display for ProviderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ProviderId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| DomainError::invalid_value(ValueKind::ProviderId, e.to_string()))
    }
}

impl Serialize for ProviderId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ProviderId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn provider_id_derived_deterministically_from_installation() {
        let installation = InstallationId::new();
        let first = ProviderId::from_installation(installation);
        let second = ProviderId::from_installation(installation);
        // 同一安装实例 → 同一 provider 身份（§40.4 确定性）。
        assert_eq!(first, second);
        // 底层 uuid 与安装实例一致（可追溯到 InstallationId）。
        assert_eq!(first.as_uuid(), installation.as_uuid());
        // 不同安装实例 → 不同 provider 身份。
        assert_ne!(first, ProviderId::from_installation(InstallationId::new()));
    }

    #[test]
    fn provider_id_is_distinct_type_from_installation_id() {
        // 类型层面不存在 ProviderId → InstallationId 的转换：以下调用若被
        // 允许将无法编译；这里只验证底层表示可见性边界。
        let installation = InstallationId::new();
        let provider = ProviderId::from_installation(installation);
        assert_eq!(provider.as_uuid(), installation.as_uuid());
        // 显示形态相同（uuid），但类型不同——通过 Display 无法区分，只能在
        // 类型层面区分（本测试验证构造路径不存在交叉）。
        assert_eq!(provider.to_string(), installation.to_string());
    }

    #[test]
    fn provider_id_parse_display_roundtrip() {
        let installation = InstallationId::new();
        let provider = ProviderId::from_installation(installation);
        let s = provider.to_string();
        assert_eq!(s.parse::<ProviderId>(), Ok(provider));
        // uuid crate 接受无连字符形式（适配层常用）。
        let simple = s.replace('-', "");
        assert_eq!(simple.parse::<ProviderId>(), Ok(provider));
    }

    #[test]
    fn provider_id_rejects_invalid_uuid() {
        assert!(matches!(
            "not-a-uuid".parse::<ProviderId>(),
            Err(DomainError::InvalidValue {
                kind: ValueKind::ProviderId,
                ..
            })
        ));
        assert!("".parse::<ProviderId>().is_err());
    }

    #[test]
    fn provider_id_from_uuid_roundtrip() {
        let uuid = Uuid::new_v4();
        let provider = ProviderId::from_uuid(uuid);
        assert_eq!(provider.as_uuid(), uuid);
        assert_eq!(provider.to_string(), uuid.to_string());
    }

    #[test]
    fn provider_id_serde_roundtrip() {
        let provider = ProviderId::from_installation(InstallationId::new());
        let json = ok(serde_json::to_string(&provider), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<ProviderId>(&json), "deserialize"),
            provider
        );
        assert!(serde_json::from_str::<ProviderId>("\"bad\"").is_err());
    }

    #[test]
    fn provider_id_ord_is_stable() {
        let a = ProviderId::from_installation(InstallationId::new());
        let b = ProviderId::from_installation(InstallationId::new());
        // Ord 提供图结构所需的稳定排序键（§40.2 provider selection 确定性）。
        assert!(a < b || b < a);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }
}
