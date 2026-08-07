//! 0.5.0 Security & Governance（§43.2）——permission change impact analysis。
//!
//! 契约语义（§43.2 permission change impact analysis）：策略 / 权限变更
//! 在生效前必须能回答"哪些对象受影响、影响是什么"。本模块提供：
//!
//! - [`PolicyChange`]：单条变更（add / modify / remove 一个能力策略条目），
//!   modify 携带**变更前后对比**（§43.2）；
//! - [`PolicyDiff`]：两个策略快照版本之间的变更集（确定性 diff，按键排序，
//!   §40.4 精神；`to` 版本必须严格晚于 `from`——版本单调性在 diff 边界
//!   复核，§43.2 versioning）；
//! - [`ImpactAnalysis`]：由变更集 + 当前授权索引（application / security
//!   层从 grant store / 用户-角色-组解析结果提供）推导受影响对象——
//!   InstallationId / UserId / GroupId 集合（确定性并集，全部排序）。
//!   application 层据此生成可解释的影响报告（§43.2 / §43.3：变更审批
//!   与审计的基础）。
//!
//! 本模块只做**确定性推导**；授权索引的解析（哪个安装实例持有某能力的
//! grant、哪个用户经角色持有某能力的授权、组的成员）是存储 / application
//! 层的职责，Domain 不建模 grant store。

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{DomainError, ValueKind};
use crate::policy::{CapabilityPolicy, PolicyScope, PolicySnapshot, PolicyVersion};
use crate::{CapabilityId, GroupId, InstallationId, UserId};

/// 单条策略变更（§43.2 permission change impact analysis 的变更描述）：
/// add / modify / remove 一个能力策略条目。
///
/// - [`PolicyChange::AddPolicy`]：新增强制条目（此前该能力无策略 = 隐式
///   拒绝，§17.2）；
/// - [`PolicyChange::ModifyPolicy`]：修改条目，携带**变更前后**的完整
///   策略（scope 集合对比由 [`PolicyChange::modified_scopes`] 提供，
///   §43.2 变更对比）；
/// - [`PolicyChange::RemovePolicy`]：移除条目（移除后该能力回到隐式
///   拒绝）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyChange {
    /// 新增策略条目。
    AddPolicy {
        /// 新增的策略。
        policy: CapabilityPolicy,
    },
    /// 修改策略条目（变更前后对比）。
    ModifyPolicy {
        /// 变更前的策略。
        before: CapabilityPolicy,
        /// 变更后的策略。
        after: CapabilityPolicy,
    },
    /// 移除策略条目。
    RemovePolicy {
        /// 被移除的策略。
        policy: CapabilityPolicy,
    },
}

impl PolicyChange {
    /// 变更涉及的能力（三变体的共同键）。
    pub fn capability(&self) -> &CapabilityId {
        match self {
            Self::AddPolicy { policy } => policy.capability(),
            Self::ModifyPolicy { before, .. } => before.capability(),
            Self::RemovePolicy { policy } => policy.capability(),
        }
    }

    /// 是否为新增条目。
    pub fn is_add(&self) -> bool {
        matches!(self, Self::AddPolicy { .. })
    }

    /// 是否为修改条目。
    pub fn is_modify(&self) -> bool {
        matches!(self, Self::ModifyPolicy { .. })
    }

    /// 是否为移除条目。
    pub fn is_remove(&self) -> bool {
        matches!(self, Self::RemovePolicy { .. })
    }

    /// 修改条目的 scope 集合前后对比（`(before, after)`；非 modify 变体为
    /// `None`）——§43.2 变更对比的 scope 维度。
    pub fn modified_scopes(&self) -> Option<(&BTreeSet<PolicyScope>, &BTreeSet<PolicyScope>)> {
        match self {
            Self::ModifyPolicy { before, after } => {
                Some((before.allowed_scopes(), after.allowed_scopes()))
            }
            _ => None,
        }
    }
}

/// 两个策略快照版本之间的变更集（§43.2 permission change impact analysis
/// 的输入；§43.2 policy snapshot/versioning 的 diff 面）。
///
/// 不变量（构造保证）：
/// - `to_version` 严格晚于 `from_version`（版本单调性复核，§13.4）；
/// - 变更按能力键排序（确定性 diff，§40.4 精神）：
///   - 仅在 after → [`PolicyChange::AddPolicy`]；
///   - 仅在 before → [`PolicyChange::RemovePolicy`]；
///   - 两侧存在且允许的 scope 集合不同 → [`PolicyChange::ModifyPolicy`]
///     （scope 集合相同的"版本空转"不算变更）。
///
/// 错误：版本不单调返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyDiff {
    from_version: PolicyVersion,
    to_version: PolicyVersion,
    changes: Vec<PolicyChange>,
}

impl PolicyDiff {
    /// 从前后两个快照确定性生成变更集（§13.3 边界解析一次）。
    pub fn between(before: &PolicySnapshot, after: &PolicySnapshot) -> Result<Self, DomainError> {
        if after.version() <= before.version() {
            return Err(DomainError::invalid_value(
                ValueKind::PolicyDiff,
                format!(
                    "to-version {} must be strictly newer than from-version {}",
                    after.version(),
                    before.version()
                ),
            ));
        }
        let mut changes = Vec::new();
        for (capability, before_policy) in before.policies() {
            match after.policy_for(capability) {
                None => changes.push(PolicyChange::RemovePolicy {
                    policy: before_policy.clone(),
                }),
                Some(after_policy) => {
                    if before_policy.allowed_scopes() != after_policy.allowed_scopes() {
                        changes.push(PolicyChange::ModifyPolicy {
                            before: before_policy.clone(),
                            after: after_policy.clone(),
                        });
                    }
                }
            }
        }
        for (capability, after_policy) in after.policies() {
            if before.policy_for(capability).is_none() {
                changes.push(PolicyChange::AddPolicy {
                    policy: after_policy.clone(),
                });
            }
        }
        // BTreeMap 按键迭代已排序；add 段跟在 remove/modify 段后，仍按
        // 能力键确定性排序（先 before 后 after 的顺序固定，见类型文档）。
        changes.sort_by(|left, right| left.capability().cmp(right.capability()));
        Ok(Self {
            from_version: before.version(),
            to_version: after.version(),
            changes,
        })
    }

    /// 变更前快照版本。
    pub const fn from_version(&self) -> PolicyVersion {
        self.from_version
    }

    /// 变更后快照版本。
    pub const fn to_version(&self) -> PolicyVersion {
        self.to_version
    }

    /// 变更条目（按能力键排序，只读）。
    pub fn changes(&self) -> &[PolicyChange] {
        &self.changes
    }

    /// 是否为空变更集（版本空转——如仅审计标记的版本提升）。
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }
}

impl<'de> Deserialize<'de> for PolicyDiff {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            from_version: PolicyVersion,
            to_version: PolicyVersion,
            changes: Vec<PolicyChange>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.to_version <= wire.from_version {
            return Err(serde::de::Error::custom(format!(
                "to-version {} must be strictly newer than from-version {}",
                wire.to_version, wire.from_version
            )));
        }
        Ok(Self {
            from_version: wire.from_version,
            to_version: wire.to_version,
            changes: wire.changes,
        })
    }
}

/// 变更影响分析结果（§43.2 permission change impact analysis）——
/// application 层可解释影响报告的数据基础。
///
/// 受影响对象（确定性推导，全部 `BTreeSet` 排序）：
/// - `affected_capabilities`：变更涉及的**能力**集合；
/// - `affected_installations`：持有受影响能力 grant 的**安装实例**并集
///   （`capability_holders` 由 application 从 grant store 提供；
///   §17.5：Grant 的 durable owner 是 InstallationId）；
/// - `affected_users`：经角色持有受影响能力授权的**用户**并集
///   （`user_grants` 由 application 从用户-角色解析结果提供）；
/// - `affected_groups`：包含受影响用户的**组**并集（`group_members`
///   由 application 提供）。
///
/// 构造不可失败（全部输入已校验；推导是纯集合运算，§12.4 无全局状态）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImpactAnalysis {
    diff: PolicyDiff,
    affected_capabilities: BTreeSet<CapabilityId>,
    affected_installations: BTreeSet<InstallationId>,
    affected_users: BTreeSet<UserId>,
    affected_groups: BTreeSet<GroupId>,
}

impl ImpactAnalysis {
    /// 由变更集 + 当前授权索引推导受影响对象（§13.3 边界解析一次）。
    ///
    /// 索引由 application / security 层在变更**生效前**从持久化状态解析
    /// （granularity：影响报告是审批 / 审计的输入，不是 grant store 本身）。
    pub fn new(
        diff: PolicyDiff,
        capability_holders: &BTreeMap<CapabilityId, BTreeSet<InstallationId>>,
        user_grants: &BTreeMap<UserId, BTreeSet<CapabilityId>>,
        group_members: &BTreeMap<GroupId, BTreeSet<UserId>>,
    ) -> Self {
        let affected_capabilities: BTreeSet<CapabilityId> = diff
            .changes()
            .iter()
            .map(PolicyChange::capability)
            .cloned()
            .collect();
        let mut affected_installations = BTreeSet::new();
        for capability in &affected_capabilities {
            if let Some(holders) = capability_holders.get(capability) {
                affected_installations.extend(holders.iter().copied());
            }
        }
        let mut affected_users = BTreeSet::new();
        for (user, grants) in user_grants {
            if grants
                .iter()
                .any(|grant| affected_capabilities.contains(grant))
            {
                affected_users.insert(*user);
            }
        }
        let mut affected_groups = BTreeSet::new();
        for (group, members) in group_members {
            if members.iter().any(|member| affected_users.contains(member)) {
                affected_groups.insert(group.clone());
            }
        }
        Self {
            diff,
            affected_capabilities,
            affected_installations,
            affected_users,
            affected_groups,
        }
    }

    /// 变更集（版本 + 条目；报告的核心内容）。
    pub fn diff(&self) -> &PolicyDiff {
        &self.diff
    }

    /// 受影响的能力集合（排序，只读）。
    pub fn affected_capabilities(&self) -> &BTreeSet<CapabilityId> {
        &self.affected_capabilities
    }

    /// 受影响（持有受影响能力 grant）的安装实例集合（排序，只读）。
    pub fn affected_installations(&self) -> &BTreeSet<InstallationId> {
        &self.affected_installations
    }

    /// 受影响（经角色持有受影响能力授权）的用户集合（排序，只读）。
    pub fn affected_users(&self) -> &BTreeSet<UserId> {
        &self.affected_users
    }

    /// 受影响（包含受影响用户）的组集合（排序，只读）。
    pub fn affected_groups(&self) -> &BTreeSet<GroupId> {
        &self.affected_groups
    }

    /// 变更条目数（报告统计）。
    pub fn change_count(&self) -> usize {
        self.diff.changes().len()
    }

    /// 受影响安装实例数（报告统计）。
    pub fn affected_installation_count(&self) -> usize {
        self.affected_installations.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyScope;
    use crate::test_support::ok;
    use crate::{SecretName, UtcInstant};

    fn capability(value: &str) -> CapabilityId {
        ok(CapabilityId::new(value), "capability-id")
    }

    fn instant(seconds: u64) -> UtcInstant {
        ok(UtcInstant::from_unix_parts(seconds, 0), "utc-instant")
    }

    fn secret_scope(name: &str) -> PolicyScope {
        PolicyScope::Secret(ok(SecretName::new(name), "secret-name"))
    }

    fn scopes(items: &[PolicyScope]) -> BTreeSet<PolicyScope> {
        items.iter().cloned().collect()
    }

    fn policy(cap: &str, allowed: BTreeSet<PolicyScope>) -> CapabilityPolicy {
        CapabilityPolicy::new(capability(cap), allowed)
    }

    fn snapshot(version: u64, policies: Vec<CapabilityPolicy>) -> PolicySnapshot {
        ok(
            PolicySnapshot::new(
                PolicyVersion::from_u64(version),
                policies,
                instant(1_752_000_000),
            ),
            "policy-snapshot",
        )
    }

    // ---- PolicyChange ----

    #[test]
    fn policy_change_variants_and_accessors() {
        let added = PolicyChange::AddPolicy {
            policy: policy("wasi:http/outgoing-handler", scopes(&[PolicyScope::All])),
        };
        assert!(added.is_add());
        assert!(!added.is_modify() && !added.is_remove());
        assert_eq!(
            added.capability(),
            &capability("wasi:http/outgoing-handler")
        );
        assert_eq!(added.modified_scopes(), None);

        let before = policy("operune:secret/read", scopes(&[PolicyScope::All]));
        let after = policy(
            "operune:secret/read",
            scopes(&[secret_scope("db-password")]),
        );
        let modified = PolicyChange::ModifyPolicy {
            before: before.clone(),
            after: after.clone(),
        };
        assert!(modified.is_modify());
        let (before_scopes, after_scopes) = ok(
            modified.modified_scopes().ok_or(DomainError::invalid_value(
                ValueKind::PolicyDiff,
                "expected modify",
            )),
            "modified scopes",
        );
        assert_eq!(before_scopes, before.allowed_scopes());
        assert_eq!(after_scopes, after.allowed_scopes());
        assert_eq!(modified.capability(), &capability("operune:secret/read"));

        let removed = PolicyChange::RemovePolicy {
            policy: before.clone(),
        };
        assert!(removed.is_remove());
        assert_eq!(removed.capability(), &capability("operune:secret/read"));

        let json = ok(serde_json::to_string(&modified), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<PolicyChange>(&json), "deserialize"),
            modified
        );
    }

    // ---- PolicyDiff ----

    #[test]
    fn policy_diff_classifies_add_modify_remove() {
        let before = snapshot(
            1,
            vec![
                policy("wasi:http/outgoing-handler", scopes(&[PolicyScope::All])),
                policy("operune:secret/read", scopes(&[PolicyScope::All])),
                policy("operune:event/publish", scopes(&[PolicyScope::All])),
            ],
        );
        let after = snapshot(
            2,
            vec![
                // modify：scope 收紧。
                policy(
                    "wasi:http/outgoing-handler",
                    scopes(&[secret_scope("db-password")]),
                ),
                // remove：策略移除。
                // add：新能力策略。
                policy("wasi:filesystem/preopens", scopes(&[PolicyScope::All])),
            ],
        );
        let diff = ok(PolicyDiff::between(&before, &after), "diff");
        assert_eq!(diff.from_version(), PolicyVersion::from_u64(1));
        assert_eq!(diff.to_version(), PolicyVersion::from_u64(2));
        // http（modify）+ secret（remove）+ event（remove）+ filesystem（add）。
        assert_eq!(diff.changes().len(), 4);
        // 按能力键确定性排序。
        let capabilities: Vec<&CapabilityId> = diff
            .changes()
            .iter()
            .map(PolicyChange::capability)
            .collect();
        let mut sorted: Vec<&CapabilityId> = capabilities.clone();
        sorted.sort();
        assert_eq!(
            capabilities, sorted,
            "changes must be in deterministic key order"
        );
        assert!(diff.changes().iter().any(
            |change| matches!(change, PolicyChange::RemovePolicy { policy: removed }
                if removed.capability() == &capability("operune:event/publish"))
        ));
        assert!(
            diff.changes()
                .iter()
                .any(|change| matches!(change, PolicyChange::ModifyPolicy { .. }
                if change.capability() == &capability("wasi:http/outgoing-handler")))
        );
        assert!(diff.changes().iter().any(
            |change| matches!(change, PolicyChange::AddPolicy { policy: added }
                if added.capability() == &capability("wasi:filesystem/preopens"))
        ));
    }

    #[test]
    fn policy_diff_requires_monotonic_versions() {
        let before = snapshot(2, vec![policy("a", scopes(&[PolicyScope::All]))]);
        let after = snapshot(2, vec![policy("a", scopes(&[PolicyScope::All]))]);
        assert!(matches!(
            PolicyDiff::between(&before, &after),
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyDiff,
                ..
            })
        ));
        let older = snapshot(1, vec![policy("a", scopes(&[PolicyScope::All]))]);
        assert!(matches!(
            PolicyDiff::between(&after, &older),
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicyDiff,
                ..
            })
        ));
    }

    #[test]
    fn policy_diff_version_bump_without_changes_is_empty() {
        // 版本提升但策略相同：空变更集（如仅审计标记的版本空转）。
        let policies = vec![policy("a", scopes(&[PolicyScope::All]))];
        let before = snapshot(1, policies.clone());
        let after = snapshot(2, policies);
        let diff = ok(PolicyDiff::between(&before, &after), "diff");
        assert!(diff.is_empty());
        assert_eq!(diff.changes().len(), 0);
    }

    #[test]
    fn policy_diff_serde_roundtrip() {
        let before = snapshot(1, vec![policy("a", scopes(&[PolicyScope::All]))]);
        let after = snapshot(2, vec![policy("a", scopes(&[secret_scope("db-password")]))]);
        let diff = ok(PolicyDiff::between(&before, &after), "diff");
        let json = ok(serde_json::to_string(&diff), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<PolicyDiff>(&json), "deserialize"),
            diff
        );
        // 反序列化边界同样校验版本单调（§13.3）。
        let invalid = r#"{
            "from_version": 2,
            "to_version": 1,
            "changes": []
        }"#;
        assert!(serde_json::from_str::<PolicyDiff>(invalid).is_err());
    }

    // ---- ImpactAnalysis ----

    #[test]
    fn impact_analysis_derives_affected_objects() {
        let before = snapshot(
            1,
            vec![
                policy("wasi:http/outgoing-handler", scopes(&[PolicyScope::All])),
                policy("operune:secret/read", scopes(&[PolicyScope::All])),
            ],
        );
        let after = snapshot(
            2,
            vec![
                // 收紧 http scope（受影响能力），移除 secret/read（也受影响）。
                policy(
                    "wasi:http/outgoing-handler",
                    scopes(&[secret_scope("db-password")]),
                ),
            ],
        );
        let diff = ok(PolicyDiff::between(&before, &after), "diff");
        assert_eq!(diff.changes().len(), 2);

        let inst_a = InstallationId::new();
        let inst_b = InstallationId::new();
        let inst_c = InstallationId::new();
        let user_x = UserId::new();
        let user_y = UserId::new();
        let user_z = UserId::new();

        let holders: BTreeMap<CapabilityId, BTreeSet<InstallationId>> = [
            (
                capability("wasi:http/outgoing-handler"),
                [inst_a, inst_b].into_iter().collect(),
            ),
            (
                capability("operune:secret/read"),
                [inst_c].into_iter().collect(),
            ),
        ]
        .into_iter()
        .collect();
        let user_grants: BTreeMap<UserId, BTreeSet<CapabilityId>> = [
            (
                user_x,
                [capability("wasi:http/outgoing-handler")]
                    .into_iter()
                    .collect(),
            ),
            (
                user_y,
                [capability("operune:secret/read")].into_iter().collect(),
            ),
            // user_z 只持有不受影响能力的授权 → 不受影响。
            (
                user_z,
                [capability("wasi:filesystem/preopens")]
                    .into_iter()
                    .collect(),
            ),
        ]
        .into_iter()
        .collect();
        let group_members: BTreeMap<GroupId, BTreeSet<UserId>> = [
            (
                ok(GroupId::new("ops"), "group-id"),
                [user_x, user_z].into_iter().collect(),
            ),
            (
                ok(GroupId::new("auditors"), "group-id"),
                [user_y].into_iter().collect(),
            ),
            (ok(GroupId::new("empty-group"), "group-id"), BTreeSet::new()),
        ]
        .into_iter()
        .collect();

        let analysis = ImpactAnalysis::new(diff, &holders, &user_grants, &group_members);
        assert_eq!(analysis.change_count(), 2);
        // 受影响能力。
        assert_eq!(analysis.affected_capabilities().len(), 2);
        assert!(
            analysis
                .affected_capabilities()
                .contains(&capability("wasi:http/outgoing-handler"))
        );
        // 受影响安装实例：持有这两个能力 grant 的全部实例。
        assert_eq!(analysis.affected_installations().len(), 3);
        assert!(analysis.affected_installations().contains(&inst_a));
        assert!(analysis.affected_installations().contains(&inst_b));
        assert!(analysis.affected_installations().contains(&inst_c));
        // 受影响用户：user_x（http）、user_y（secret）；user_z 不受影响。
        assert_eq!(analysis.affected_users().len(), 2);
        assert!(analysis.affected_users().contains(&user_x));
        assert!(analysis.affected_users().contains(&user_y));
        assert!(!analysis.affected_users().contains(&user_z));
        // 受影响组：ops（含 user_x）、auditors（含 user_y）；empty-group 无成员。
        assert_eq!(analysis.affected_groups().len(), 2);
        assert!(
            analysis
                .affected_groups()
                .contains(&ok(GroupId::new("ops"), "group-id"))
        );
        assert!(
            analysis
                .affected_groups()
                .contains(&ok(GroupId::new("auditors"), "group-id"))
        );
        assert_eq!(analysis.affected_installation_count(), 3);
    }

    #[test]
    fn impact_analysis_with_no_holders_is_empty() {
        let before = snapshot(1, vec![policy("a", scopes(&[PolicyScope::All]))]);
        let after = snapshot(2, vec![policy("a", scopes(&[secret_scope("db-password")]))]);
        let diff = ok(PolicyDiff::between(&before, &after), "diff");
        let analysis =
            ImpactAnalysis::new(diff, &BTreeMap::new(), &BTreeMap::new(), &BTreeMap::new());
        assert_eq!(analysis.change_count(), 1);
        assert!(analysis.affected_installations().is_empty());
        assert!(analysis.affected_users().is_empty());
        assert!(analysis.affected_groups().is_empty());
        // 报告序列化（审批 / 审计持久化）：版本与条目都在报告中。
        let json = ok(serde_json::to_string(&analysis), "serialize");
        assert!(json.contains("\"from_version\":1"), "{json}");
        assert!(json.contains("\"to_version\":2"), "{json}");
    }
}
