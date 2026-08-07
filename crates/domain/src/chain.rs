//! 0.5.0 Security & Governance（§43.2 / §43.3）——可审计 policy chain。
//!
//! # §43.3 验收
//!
//! "管理员能够解释'某 Component 为什么可以/不可以做某件事'，答案必须来自
//! 可审计 policy chain，而不是散落配置或隐式 Host 权限。"本模块是该验收的
//! **领域基础**：
//!
//! - [`PolicyChain`] 把一次授权判定表达为**有结构、可验证的四层链**
//!   （[`PolicyChainLayer`]，§17.5 四层授权链）：Contract Need（WIT
//!   import 明确需要该能力）→ Resolution（Runtime 解析到正确的
//!   Host/Provider 并满足版本兼容）→ Grant（该安装实例拥有明确、可审计、
//!   带 scope 的授权）→ Invocation Enforcement（实际请求仍在 grant scope、
//!   资源预算和当前 policy snapshot 内）；
//! - [`PolicyChainEntry`] 每层携带**来源**与**授权 / 拒绝依据摘要**
//!   （人类可读的结论面；机器身份——grant 记录、snapshot 版本等——由
//!   application 嵌入摘要文本）；
//! - [`PolicyDecision`]（allow / deny）由链的条目**派生**，不是独立写入
//!   的字段（§13.4：不合法状态不可表示——拒绝链必然以失败层收尾，放行链
//!   必然四层全部通过）。
//!
//! 链的良构性（[`PolicyChain::new`] 校验，§13.4）：
//! - 非空；层严格按 §17.5 顺序且不重复；
//! - 每层**恰有**一边依据（授权或拒绝，二者取其一）；
//! - 拒绝条目必须是**最后一条**（§17.5：判定在首个失败层终止，短路；
//!   后续层不求值）；
//! - 全部通过的链必须**恰好四层**（§17.5：放行必须四层同时满足）。
//!
//! 链是**事实记录**（判定时生成的不可变审计数据，§43.3），不做二次判定；
//! application / security 层负责在调用链上执行各层求值并填充依据。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::{CapabilityId, InstallationId};

/// §17.5 四层授权链的层（顺序即求值顺序；`Ord` 按声明顺序）。
///
/// - [`PolicyChainLayer::ContractNeed`]：Component 的 WIT import 明确需要
///   该能力；
/// - [`PolicyChainLayer::Resolution`]：Runtime 能解析到正确的 Host/Provider，
///   并满足版本兼容规则；
/// - [`PolicyChainLayer::Grant`]：该安装实例拥有明确、可审计、带 scope 的
///   授权；
/// - [`PolicyChainLayer::InvocationEnforcement`]：实际请求仍在 grant scope、
///   资源预算和当前 policy snapshot 内。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyChainLayer {
    /// 第 1 层：契约需求（WIT import）。
    ContractNeed,
    /// 第 2 层：解析（Host/Provider + 版本兼容）。
    Resolution,
    /// 第 3 层：授权（grant + scope）。
    Grant,
    /// 第 4 层：调用期执行（scope / 预算 / 当前 snapshot）。
    InvocationEnforcement,
}

impl PolicyChainLayer {
    /// 与变体一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContractNeed => "contract-need",
            Self::Resolution => "resolution",
            Self::Grant => "grant",
            Self::InvocationEnforcement => "invocation-enforcement",
        }
    }

    /// 从字符串解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集之外
    /// 的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "contract-need" => Ok(Self::ContractNeed),
            "resolution" => Ok(Self::Resolution),
            "grant" => Ok(Self::Grant),
            "invocation-enforcement" => Ok(Self::InvocationEnforcement),
            _ => Err(DomainError::invalid_value(
                ValueKind::PolicyChainLayer,
                format!(
                    "{s:?} is not a policy-chain-layer variant (contract-need | resolution | grant | invocation-enforcement)"
                ),
            )),
        }
    }

    /// 全部四层（§17.5 顺序；链良构性检查用）。
    pub const fn all() -> [PolicyChainLayer; 4] {
        [
            Self::ContractNeed,
            Self::Resolution,
            Self::Grant,
            Self::InvocationEnforcement,
        ]
    }
}

impl fmt::Display for PolicyChainLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PolicyChainLayer {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for PolicyChainLayer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PolicyChainLayer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 链上单层的记录（§43.3 可解释性）：层 + **恰一侧**依据摘要。
///
/// - [`PolicyChainEntry::grant`]：该层**放行**，携带授权依据摘要
///   （如 `imports wasi:http/outgoing-handler` / `grant #42, scope
///   https://prometheus.internal:9090` / `snapshot v7 within budget`）；
/// - [`PolicyChainEntry::deny`]：该层**拒绝**，携带拒绝依据摘要
///   （如 `no WIT import for this capability` / `no grant for this
///   InstallationId` / `request scope outside grant scope`）。
///
/// 摘要是人类可读的结论面（审计展示 / 报告）；机器身份（grant 记录号、
/// snapshot 版本、provider 解析结果）由 application 嵌入摘要文本。
/// 依据是**摘要**而非凭据——不含任何机密（§16.6）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyChainEntry {
    layer: PolicyChainLayer,
    grant_basis: Option<String>,
    deny_basis: Option<String>,
}

impl PolicyChainEntry {
    /// 该层放行（grant 依据；deny 依据为 `None`）。
    pub fn grant(layer: PolicyChainLayer, basis: impl Into<String>) -> Self {
        Self {
            layer,
            grant_basis: Some(basis.into()),
            deny_basis: None,
        }
    }

    /// 该层拒绝（deny 依据；grant 依据为 `None`）。
    pub fn deny(layer: PolicyChainLayer, basis: impl Into<String>) -> Self {
        Self {
            layer,
            grant_basis: None,
            deny_basis: Some(basis.into()),
        }
    }

    /// 该层（§17.5 顺序中的位置）。
    pub const fn layer(&self) -> PolicyChainLayer {
        self.layer
    }

    /// 授权依据摘要（拒绝条目为 `None`）。
    pub fn grant_basis(&self) -> Option<&str> {
        self.grant_basis.as_deref()
    }

    /// 拒绝依据摘要（放行条目为 `None`）。
    pub fn deny_basis(&self) -> Option<&str> {
        self.deny_basis.as_deref()
    }

    /// 该层是否放行。
    pub fn is_allow(&self) -> bool {
        self.grant_basis.is_some()
    }

    /// 该层是否拒绝。
    pub fn is_deny(&self) -> bool {
        self.deny_basis.is_some()
    }
}

/// 授权判定结论（§43.3 报告与 [`PolicyChain::decision`] 的结论面）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PolicyDecision {
    /// 放行（链四层全部通过）。
    Allow,
    /// 拒绝（链在首个失败层终止）。
    Deny,
}

impl PolicyDecision {
    /// 是否放行。
    pub const fn is_allow(self) -> bool {
        matches!(self, Self::Allow)
    }

    /// 是否拒绝。
    pub const fn is_deny(self) -> bool {
        matches!(self, Self::Deny)
    }

    /// 与变体一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// 从字符串解析（§13.3 边界解析一次；闭集之外拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "allow" => Ok(Self::Allow),
            "deny" => Ok(Self::Deny),
            _ => Err(DomainError::invalid_value(
                ValueKind::PolicyDecision,
                format!("{s:?} is not a policy-decision variant (allow | deny)"),
            )),
        }
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PolicyDecision {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for PolicyDecision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PolicyDecision {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 一次授权请求的完整判定记录（§43.3 可审计 policy chain；§17.5 四层）。
///
/// 主体：`subject`（提出请求的安装实例，§17.5 Grant 的 durable owner 是
/// InstallationId）+ `capability`（被请求的能力）。
///
/// 良构性（[`PolicyChain::new`] 校验，§13.4 不合法状态不可表示）：
/// - 链非空；层严格按 §17.5 顺序且不重复；
/// - 每层恰有一侧依据（[`PolicyChainEntry::grant`] / [`PolicyChainEntry::deny`]）；
/// - 拒绝条目必须是最后一条（§17.5 短路：首个失败层终止求值）；
/// - **放行链恰好四层全部通过**（§17.5：一次能力调用成立必须同时满足
///   四层）。
///
/// 结论（[`PolicyChain::decision`]）由条目**派生**：存在拒绝条目（即最后
/// 一条）→ Deny；否则 → Allow。链是不可变审计事实（无修改方法）；
/// [`PolicyChain::explain`] 输出单行可读摘要（§43.3 报告基础）。
///
/// 错误：良构性违反返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyChain {
    subject: InstallationId,
    capability: CapabilityId,
    entries: Vec<PolicyChainEntry>,
}

impl PolicyChain {
    /// 组装判定记录并校验四层链良构性（§13.3 边界解析一次）。
    pub fn new(
        subject: InstallationId,
        capability: CapabilityId,
        entries: Vec<PolicyChainEntry>,
    ) -> Result<Self, DomainError> {
        let invalid = |detail: String| DomainError::invalid_value(ValueKind::PolicyChain, detail);
        if entries.is_empty() {
            return Err(invalid(
                "a policy chain must contain at least one entry".to_string(),
            ));
        }
        // 层严格递增且不重复（§17.5 顺序）；每层恰有一侧依据。
        let mut previous_layer: Option<PolicyChainLayer> = None;
        for entry in &entries {
            if matches!(
                (entry.grant_basis.is_some(), entry.deny_basis.is_some()),
                (true, true) | (false, false)
            ) {
                return Err(invalid(format!(
                    "entry at layer {} must have exactly one basis (grant or deny)",
                    entry.layer
                )));
            }
            if let Some(previous) = previous_layer
                && entry.layer() <= previous
            {
                return Err(invalid(format!(
                    "layers must strictly follow the §17.5 order (contract-need → resolution → grant → invocation-enforcement); got {} after {previous}",
                    entry.layer
                )));
            }
            previous_layer = Some(entry.layer());
        }
        // 拒绝条目必须是最后一条（§17.5 短路）。
        let deny_index = entries.iter().position(PolicyChainEntry::is_deny);
        if let Some(index) = deny_index
            && index + 1 != entries.len()
        {
            return Err(invalid(
                "a denied chain must terminate at the first failing layer (no entries after the deny entry)"
                    .to_string(),
            ));
        }
        // 放行链必须恰好四层（§17.5：四层同时满足才放行）。
        if deny_index.is_none() && entries.len() != PolicyChainLayer::all().len() {
            return Err(invalid(format!(
                "an allowed chain must pass all four §17.5 layers, got {} entries",
                entries.len()
            )));
        }
        Ok(Self {
            subject,
            capability,
            entries,
        })
    }

    /// 提出请求的安装实例（§17.5：grant 的 durable owner）。
    pub const fn subject(&self) -> InstallationId {
        self.subject
    }

    /// 被请求的能力。
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// 链条目（按 §17.5 顺序，只读）。
    pub fn entries(&self) -> &[PolicyChainEntry] {
        &self.entries
    }

    /// 判定结论（由条目派生，确定性）：存在拒绝条目（最后一条）→ Deny；
    /// 否则 → Allow。
    pub fn decision(&self) -> PolicyDecision {
        if self.entries.last().is_some_and(PolicyChainEntry::is_deny) {
            PolicyDecision::Deny
        } else {
            PolicyDecision::Allow
        }
    }

    /// 拒绝链的失败层（放行链为 `None`）。
    pub fn denied_at(&self) -> Option<PolicyChainLayer> {
        self.entries
            .iter()
            .find(|entry| entry.is_deny())
            .map(PolicyChainEntry::layer)
    }

    /// 单行可读摘要（§43.3 报告基础）：结论 + 主体 + 能力 + 逐层依据。
    ///
    /// 示例（放行）：
    /// `allow wasi:http/outgoing-handler for <id>: contract-need (imports …) → resolution (matched provider …) → grant (grant #…, scope …) → invocation-enforcement (within budget, snapshot v…)`
    ///
    /// 示例（拒绝）：
    /// `deny wasi:http/outgoing-handler for <id>: contract-need (imports …) → grant (no grant for this InstallationId)`
    pub fn explain(&self) -> String {
        let chain = self
            .entries
            .iter()
            .map(|entry| match (entry.grant_basis(), entry.deny_basis()) {
                (Some(basis), _) => format!("{} ({basis})", entry.layer),
                (_, Some(basis)) => format!("{} ({basis})", entry.layer),
                (None, None) => format!("{}", entry.layer),
            })
            .collect::<Vec<_>>()
            .join(" → ");
        format!(
            "{} {} for {}: {}",
            self.decision(),
            self.capability,
            self.subject,
            chain
        )
    }
}

impl<'de> Deserialize<'de> for PolicyChain {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            subject: InstallationId,
            capability: CapabilityId,
            entries: Vec<PolicyChainEntry>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.subject, wire.capability, wire.entries).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    fn capability(value: &str) -> CapabilityId {
        ok(CapabilityId::new(value), "capability-id")
    }

    fn four_passing_entries() -> Vec<PolicyChainEntry> {
        vec![
            PolicyChainEntry::grant(
                PolicyChainLayer::ContractNeed,
                "component imports wasi:http/outgoing-handler",
            ),
            PolicyChainEntry::grant(
                PolicyChainLayer::Resolution,
                "matched host provider at compatible version",
            ),
            PolicyChainEntry::grant(
                PolicyChainLayer::Grant,
                "grant #42 with scope network https://prometheus.internal:9090",
            ),
            PolicyChainEntry::grant(
                PolicyChainLayer::InvocationEnforcement,
                "request within grant scope and budget, snapshot v7",
            ),
        ]
    }

    // ---- PolicyChainLayer ----

    #[test]
    fn policy_chain_layer_closed_set_in_order() {
        let layers = [
            PolicyChainLayer::ContractNeed,
            PolicyChainLayer::Resolution,
            PolicyChainLayer::Grant,
            PolicyChainLayer::InvocationEnforcement,
        ];
        for (layer, name) in [
            (PolicyChainLayer::ContractNeed, "contract-need"),
            (PolicyChainLayer::Resolution, "resolution"),
            (PolicyChainLayer::Grant, "grant"),
            (
                PolicyChainLayer::InvocationEnforcement,
                "invocation-enforcement",
            ),
        ] {
            assert_eq!(name.parse::<PolicyChainLayer>(), Ok(layer));
            assert_eq!(layer.to_string(), name);
            let json = ok(serde_json::to_string(&layer), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(
                    serde_json::from_str::<PolicyChainLayer>(&json),
                    "deserialize"
                ),
                layer
            );
        }
        // §17.5 顺序。
        for pair in layers.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        for bad in ["", "GRANT", "execution", "grant "] {
            assert!(
                matches!(
                    bad.parse::<PolicyChainLayer>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PolicyChainLayer,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
    }

    // ---- PolicyChainEntry ----

    #[test]
    fn policy_chain_entry_has_exactly_one_basis() {
        let granted = PolicyChainEntry::grant(PolicyChainLayer::Grant, "grant #1");
        assert!(granted.is_allow());
        assert!(!granted.is_deny());
        assert_eq!(granted.layer(), PolicyChainLayer::Grant);
        assert_eq!(granted.grant_basis(), Some("grant #1"));
        assert_eq!(granted.deny_basis(), None);

        let denied =
            PolicyChainEntry::deny(PolicyChainLayer::Grant, "no grant for this installation");
        assert!(denied.is_deny());
        assert!(!denied.is_allow());
        assert_eq!(denied.grant_basis(), None);
        assert_eq!(denied.deny_basis(), Some("no grant for this installation"));

        let json = ok(serde_json::to_string(&denied), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<PolicyChainEntry>(&json),
                "deserialize"
            ),
            denied
        );
    }

    // ---- PolicyDecision ----

    #[test]
    fn policy_decision_closed_set() {
        for (decision, name) in [
            (PolicyDecision::Allow, "allow"),
            (PolicyDecision::Deny, "deny"),
        ] {
            assert_eq!(name.parse::<PolicyDecision>(), Ok(decision));
            assert_eq!(decision.to_string(), name);
            let json = ok(serde_json::to_string(&decision), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<PolicyDecision>(&json), "deserialize"),
                decision
            );
        }
        assert!(PolicyDecision::Allow.is_allow());
        assert!(PolicyDecision::Deny.is_deny());
        assert!(matches!(
            "maybe".parse::<PolicyDecision>(),
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyDecision,
                ..
            })
        ));
    }

    // ---- PolicyChain ----

    #[test]
    fn policy_chain_allows_when_all_four_layers_pass() {
        let chain = ok(
            PolicyChain::new(
                InstallationId::new(),
                capability("wasi:http/outgoing-handler"),
                four_passing_entries(),
            ),
            "chain",
        );
        assert_eq!(chain.decision(), PolicyDecision::Allow);
        assert_eq!(chain.denied_at(), None);
        assert_eq!(chain.entries().len(), 4);
        // 结论由条目派生：每层都是 grant。
        assert!(chain.entries().iter().all(PolicyChainEntry::is_allow));
        let explain = chain.explain();
        assert!(
            explain.starts_with("allow wasi:http/outgoing-handler"),
            "{explain}"
        );
        assert!(explain.contains("contract-need"), "{explain}");
        assert!(explain.contains("invocation-enforcement"), "{explain}");
    }

    #[test]
    fn policy_chain_denies_at_first_failing_layer() {
        // 在第 3 层（Grant）拒绝：前两层放行，链在该层终止。
        let chain = ok(
            PolicyChain::new(
                InstallationId::new(),
                capability("operune:secret/read"),
                vec![
                    PolicyChainEntry::grant(
                        PolicyChainLayer::ContractNeed,
                        "component imports operune:secret/read",
                    ),
                    PolicyChainEntry::grant(
                        PolicyChainLayer::Resolution,
                        "resolved secret store provider",
                    ),
                    PolicyChainEntry::deny(
                        PolicyChainLayer::Grant,
                        "no grant for this InstallationId (deny-by-default, §17.2)",
                    ),
                ],
            ),
            "chain",
        );
        assert_eq!(chain.decision(), PolicyDecision::Deny);
        assert_eq!(chain.denied_at(), Some(PolicyChainLayer::Grant));
        let explain = chain.explain();
        assert!(explain.starts_with("deny operune:secret/read"), "{explain}");
        assert!(
            explain.contains("grant (no grant for this InstallationId"),
            "{explain}"
        );
        // 后续层不求值：链里没有 enforcement 条目。
        assert!(!explain.contains("invocation-enforcement"), "{explain}");
    }

    #[test]
    fn policy_chain_rejects_empty() {
        assert!(matches!(
            PolicyChain::new(
                InstallationId::new(),
                capability("wasi:http/outgoing-handler"),
                vec![],
            ),
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyChain,
                ..
            })
        ));
    }

    #[test]
    fn policy_chain_rejects_wrong_layer_order() {
        // resolution 出现在 contract-need 之前。
        let out_of_order = PolicyChain::new(
            InstallationId::new(),
            capability("wasi:http/outgoing-handler"),
            vec![
                PolicyChainEntry::grant(PolicyChainLayer::Resolution, "resolved"),
                PolicyChainEntry::grant(PolicyChainLayer::ContractNeed, "imports"),
            ],
        );
        assert!(matches!(
            out_of_order,
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyChain,
                ..
            })
        ));
        // 层重复。
        let duplicate_layer = PolicyChain::new(
            InstallationId::new(),
            capability("wasi:http/outgoing-handler"),
            vec![
                PolicyChainEntry::grant(PolicyChainLayer::ContractNeed, "imports"),
                PolicyChainEntry::grant(PolicyChainLayer::ContractNeed, "imports again"),
            ],
        );
        assert!(matches!(
            duplicate_layer,
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyChain,
                ..
            })
        ));
    }

    #[test]
    fn policy_chain_rejects_deny_before_chain_end() {
        // 拒绝条目后仍有条目（§17.5 短路：判定在首个失败层终止）。
        let deny_mid_chain = PolicyChain::new(
            InstallationId::new(),
            capability("wasi:http/outgoing-handler"),
            vec![
                PolicyChainEntry::grant(PolicyChainLayer::ContractNeed, "imports"),
                PolicyChainEntry::deny(PolicyChainLayer::Resolution, "no provider"),
                PolicyChainEntry::grant(PolicyChainLayer::Grant, "grant #1"),
            ],
        );
        assert!(matches!(
            deny_mid_chain,
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyChain,
                ..
            })
        ));
    }

    #[test]
    fn policy_chain_rejects_partial_allow() {
        // 放行链必须恰好四层（§17.5：四层同时满足才放行）。
        let partial = PolicyChain::new(
            InstallationId::new(),
            capability("wasi:http/outgoing-handler"),
            vec![
                PolicyChainEntry::grant(PolicyChainLayer::ContractNeed, "imports"),
                PolicyChainEntry::grant(PolicyChainLayer::Resolution, "resolved"),
            ],
        );
        assert!(matches!(
            partial,
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyChain,
                ..
            })
        ));
    }

    #[test]
    fn policy_chain_deny_at_first_layer_is_shortest_chain() {
        // 第 1 层即拒绝：单条目链（合法最短拒绝链）。
        let chain = ok(
            PolicyChain::new(
                InstallationId::new(),
                capability("wasi:http/outgoing-handler"),
                vec![PolicyChainEntry::deny(
                    PolicyChainLayer::ContractNeed,
                    "component has no WIT import for this capability",
                )],
            ),
            "chain",
        );
        assert_eq!(chain.decision(), PolicyDecision::Deny);
        assert_eq!(chain.denied_at(), Some(PolicyChainLayer::ContractNeed));
    }

    #[test]
    fn policy_chain_serde_roundtrip() {
        let chain = ok(
            PolicyChain::new(
                InstallationId::new(),
                capability("wasi:http/outgoing-handler"),
                four_passing_entries(),
            ),
            "chain",
        );
        let json = ok(serde_json::to_string(&chain), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<PolicyChain>(&json), "deserialize"),
            chain
        );
        // 反序列化边界同样执行良构性校验（§13.3）：拒绝后还有条目拒绝。
        let invalid = r#"{
            "subject": "00000000-0000-0000-0000-000000000001",
            "capability": "wasi:http/outgoing-handler",
            "entries": [
                {"layer": "contract-need", "grant_basis": "imports", "deny_basis": null},
                {"layer": "grant", "grant_basis": null, "deny_basis": "denied"},
                {"layer": "invocation-enforcement", "grant_basis": "ok", "deny_basis": null}
            ]
        }"#;
        assert!(
            serde_json::from_str::<PolicyChain>(invalid).is_err(),
            "deny entry followed by more entries must be rejected on deserialize"
        );
        // 四层放行链合法反序列化。
        let valid = r#"{
            "subject": "00000000-0000-0000-0000-000000000001",
            "capability": "wasi:http/outgoing-handler",
            "entries": [
                {"layer": "contract-need", "grant_basis": "imports", "deny_basis": null},
                {"layer": "resolution", "grant_basis": "resolved", "deny_basis": null},
                {"layer": "grant", "grant_basis": "grant #1", "deny_basis": null},
                {"layer": "invocation-enforcement", "grant_basis": "ok", "deny_basis": null}
            ]
        }"#;
        assert!(serde_json::from_str::<PolicyChain>(valid).is_ok());
    }
}
