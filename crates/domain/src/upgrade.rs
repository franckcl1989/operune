//! 0.2.0 Capability Composition（§40.2）：provider upgrade 前 consumer
//! compatibility analysis。
//!
//! [`ProviderGraph::analyze_upgrade`] 针对**当前快照**中的既有依赖边做纯
//! 分析：给定某 provider 升级后的提供面，哪些直接依赖它的 consumer 仍被
//! 满足、哪些被破坏（interface 被移除 / 版本不兼容）。分析不做重解析
//! （不重新构建图）：升级后的提供面可能吸引新的 consumer，那是 application
//! 层在决定切换快照前重新 `try_build` 的职责（§40.2 graph snapshot atomic
//! switch）。
//!
//! 全部结果按 (consumer, requirement) 排序，完全确定（§40.4）。

use std::collections::BTreeSet;

use crate::graph::{ProviderGraph, ProviderGraphError};
use crate::interface::{InterfaceId, InterfaceRequirement};
use crate::provider::ProviderId;
use crate::{ComponentVersion, InstallationId};

/// provider 升级兼容分析报告（§40.2 provider upgrade 前 consumer
/// compatibility analysis）。
///
/// 语义：只覆盖**当前图中直接依赖该 provider** 的 consumer（不包含其它
/// provider 的 consumer）；每条影响按 (consumer, requirement) 排序。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeCompatibilityReport {
    provider: ProviderId,
    upgraded_provided: BTreeSet<InterfaceId>,
    impacts: Vec<ConsumerUpgradeImpact>,
}

impl UpgradeCompatibilityReport {
    /// 被分析的 provider。
    pub fn provider(&self) -> ProviderId {
        self.provider
    }

    /// 升级后的提供面（分析输入）。
    pub fn upgraded_provided(&self) -> &BTreeSet<InterfaceId> {
        &self.upgraded_provided
    }

    /// 全部受影响的 consumer（按 (consumer, requirement) 排序）。
    pub fn impacts(&self) -> &[ConsumerUpgradeImpact] {
        &self.impacts
    }

    /// 升级是否安全：所有直接 consumer 都仍被满足。
    pub fn is_safe(&self) -> bool {
        self.impacts
            .iter()
            .all(|impact| impact.result.is_compatible())
    }
}

/// 一个 consumer 在 provider 升级后的影响。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerUpgradeImpact {
    consumer: InstallationId,
    requirement: InterfaceRequirement,
    /// 升级前解析到的具体提供版本。
    previously_provided: InterfaceId,
    /// 升级后是否仍被满足。
    result: UpgradeImpact,
}

impl ConsumerUpgradeImpact {
    /// 受影响的 consumer 安装实例。
    pub fn consumer(&self) -> InstallationId {
        self.consumer
    }

    /// 该 consumer 对 provider 的需求。
    pub fn requirement(&self) -> &InterfaceRequirement {
        &self.requirement
    }

    /// 升级前解析到的提供版本。
    pub fn previously_provided(&self) -> &InterfaceId {
        &self.previously_provided
    }

    /// 升级影响判定。
    pub fn result(&self) -> &UpgradeImpact {
        &self.result
    }
}

/// 升级影响判定（闭集 typed enum，§13.1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeImpact {
    /// 升级后的提供面仍满足该 consumer 的需求。
    Compatible,
    /// 升级破坏了该 consumer 的需求。
    Incompatible {
        /// typed 原因。
        reason: UpgradeIncompatibility,
    },
}

impl UpgradeImpact {
    /// 是否兼容。
    pub fn is_compatible(&self) -> bool {
        matches!(self, UpgradeImpact::Compatible)
    }

    /// 不兼容原因（兼容时为 `None`）。
    pub fn reason(&self) -> Option<&UpgradeIncompatibility> {
        match self {
            UpgradeImpact::Compatible => None,
            UpgradeImpact::Incompatible { reason } => Some(reason),
        }
    }
}

/// 不兼容的 typed 原因（§14.1：错误/诊断信息用封闭类型，不用裸 String）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeIncompatibility {
    /// 升级后该 interface 不再提供：consumer 将失去 provider
    /// （重新构建时成为 MissingProvider）。
    InterfaceRemoved,
    /// 升级后该 interface 的版本不满足 consumer 的需求。
    VersionIncompatible {
        /// 升级后提供的最高版本（诊断用，确定性）。
        upgraded_highest: ComponentVersion,
    },
}

impl ProviderGraph {
    /// provider 升级前的 consumer compatibility analysis（§40.2）。
    ///
    /// 给定 provider 升级后的提供面，检查当前图中所有直接依赖它的
    /// consumer：每个 consumer 的需求在升级后的提供面下是否仍被满足。
    /// 判定规则与构建时一致（package/interface 精确匹配 + semver 版本
    /// 满足，见 [`InterfaceRequirement::satisfied_by`]）。
    ///
    /// 错误：provider 不在图中 → [`ProviderGraphError::UnknownProvider`]。
    ///
    /// 语义边界：本分析只针对既有边；升级后的提供面可能使新的 consumer
    /// 变得可解析，也可能使其它 provider 的解析变得不唯一——这些属于
    /// 重新构建（`try_build`）的职责。
    pub fn analyze_upgrade(
        &self,
        provider: ProviderId,
        upgraded_provided: BTreeSet<InterfaceId>,
    ) -> Result<UpgradeCompatibilityReport, ProviderGraphError> {
        if !self.providers().any(|node| node.provider() == provider) {
            return Err(ProviderGraphError::UnknownProvider { provider });
        }

        let mut impacts: Vec<ConsumerUpgradeImpact> = Vec::new();
        for edge in self.direct_consumers(provider) {
            let requirement = edge.requirement().clone();
            // 升级后的提供面中，满足该需求的条目。
            let satisfying: Vec<&InterfaceId> = upgraded_provided
                .iter()
                .filter(|provided| requirement.satisfied_by(provided))
                .collect();
            // 升级后的提供面中，同 (package, interface) 的条目（用于诊断）。
            let same_interface: Vec<&InterfaceId> = upgraded_provided
                .iter()
                .filter(|provided| {
                    provided.package() == requirement.package()
                        && provided.interface() == requirement.interface()
                })
                .collect();

            let result = if !satisfying.is_empty() {
                UpgradeImpact::Compatible
            } else if let Some(highest) = same_interface.last() {
                // 同 interface 存在但版本不满足：报告升级后最高版本。
                UpgradeImpact::Incompatible {
                    reason: UpgradeIncompatibility::VersionIncompatible {
                        upgraded_highest: highest.version(),
                    },
                }
            } else {
                UpgradeImpact::Incompatible {
                    reason: UpgradeIncompatibility::InterfaceRemoved,
                }
            };

            impacts.push(ConsumerUpgradeImpact {
                consumer: edge.consumer(),
                requirement,
                previously_provided: edge.provided().clone(),
                result,
            });
        }

        Ok(UpgradeCompatibilityReport {
            provider,
            upgraded_provided,
            impacts,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::{ConsumerRecord, ProviderRecord};
    use crate::interface::{InterfaceName, PackageName};
    use crate::test_support::ok;
    use proptest::prelude::*;
    use uuid::Uuid;

    fn installation(seed: u64) -> InstallationId {
        InstallationId::from_uuid(Uuid::from_u128(u128::from(seed)))
    }

    fn version(major: u32, minor: u32, patch: u32) -> ComponentVersion {
        ComponentVersion::from_parts(major, minor, patch)
    }

    fn iface(interface: &str, major: u32, minor: u32, patch: u32) -> InterfaceId {
        InterfaceId::new(
            ok(PackageName::new("ns:pkg"), "package"),
            ok(InterfaceName::new(interface), "interface"),
            version(major, minor, patch),
        )
    }

    fn requirement(interface: &str, req: &str) -> InterfaceRequirement {
        ok(
            format!("ns:pkg/{interface}@{req}").parse::<InterfaceRequirement>(),
            "requirement",
        )
    }

    fn set<T: Ord>(items: impl IntoIterator<Item = T>) -> BTreeSet<T> {
        items.into_iter().collect()
    }

    fn provider(seed: u64, provided: &[InterfaceId]) -> ProviderRecord {
        ok(
            ProviderRecord::new(installation(seed), set(provided.iter().cloned())),
            "provider record",
        )
    }

    fn consumer(seed: u64, required: &[InterfaceRequirement]) -> ConsumerRecord {
        ConsumerRecord::new(installation(seed), set(required.iter().cloned()))
    }

    fn graph(providers: &[ProviderRecord], consumers: &[ConsumerRecord]) -> ProviderGraph {
        ok(
            ProviderGraph::try_build(providers, consumers),
            "graph build",
        )
    }

    fn provider_id(seed: u64) -> ProviderId {
        ProviderId::from_installation(installation(seed))
    }

    #[test]
    fn compatible_upgrade_within_same_major() {
        // provider 从 if-a@1.0.0 升到 1.1.0：consumer（^1.0.0）仍满足。
        let graph = graph(
            &[provider(1, &[iface("if-a", 1, 0, 0)])],
            &[consumer(2, &[requirement("if-a", "^1.0.0")])],
        );
        let report = ok(
            graph.analyze_upgrade(
                provider_id(1),
                set([iface("if-a", 1, 1, 0), iface("if-b", 1, 0, 0)]),
            ),
            "upgrade analysis",
        );
        assert_eq!(report.provider(), provider_id(1));
        assert_eq!(report.impacts().len(), 1);
        assert!(report.is_safe());
        let impact = &report.impacts()[0];
        assert_eq!(impact.consumer(), installation(2));
        assert_eq!(impact.requirement(), &requirement("if-a", "^1.0.0"));
        assert_eq!(impact.previously_provided(), &iface("if-a", 1, 0, 0));
        assert_eq!(impact.result(), &UpgradeImpact::Compatible);
    }

    #[test]
    fn removed_interface_breaks_consumers() {
        let graph = graph(
            &[provider(
                1,
                &[iface("if-a", 1, 0, 0), iface("if-b", 1, 0, 0)],
            )],
            &[consumer(2, &[requirement("if-a", "^1.0.0")])],
        );
        let report = ok(
            graph.analyze_upgrade(provider_id(1), set([iface("if-b", 1, 1, 0)])),
            "upgrade analysis",
        );
        assert!(!report.is_safe());
        let impact = &report.impacts()[0];
        assert_eq!(
            impact.result(),
            &UpgradeImpact::Incompatible {
                reason: UpgradeIncompatibility::InterfaceRemoved,
            }
        );
    }

    #[test]
    fn major_bump_reports_version_incompatibility() {
        let graph = graph(
            &[provider(1, &[iface("if-a", 1, 0, 0)])],
            &[consumer(2, &[requirement("if-a", "^1.0.0")])],
        );
        let report = ok(
            graph.analyze_upgrade(provider_id(1), set([iface("if-a", 2, 0, 0)])),
            "upgrade analysis",
        );
        assert!(!report.is_safe());
        let impact = &report.impacts()[0];
        assert_eq!(
            impact.result(),
            &UpgradeImpact::Incompatible {
                reason: UpgradeIncompatibility::VersionIncompatible {
                    upgraded_highest: version(2, 0, 0),
                },
            }
        );
    }

    #[test]
    fn upgrade_affects_only_direct_consumers() {
        // provider 1 提供 if-a，provider 2 提供 if-b；升级 provider 1 只影响
        // 依赖 if-a 的 consumer，不影响依赖 if-b 的 consumer。
        let graph = graph(
            &[
                provider(1, &[iface("if-a", 1, 0, 0)]),
                provider(2, &[iface("if-b", 1, 0, 0)]),
            ],
            &[
                consumer(3, &[requirement("if-a", "^1.0.0")]),
                consumer(4, &[requirement("if-b", "^1.0.0")]),
            ],
        );
        let report = ok(
            graph.analyze_upgrade(provider_id(1), set([iface("if-a", 2, 0, 0)])),
            "upgrade analysis",
        );
        assert_eq!(report.impacts().len(), 1);
        assert_eq!(report.impacts()[0].consumer(), installation(3));
    }

    #[test]
    fn unknown_provider_rejected() {
        let graph = graph(&[provider(1, &[iface("if-a", 1, 0, 0)])], &[]);
        let err = graph.analyze_upgrade(provider_id(99), set([iface("if-a", 1, 1, 0)]));
        assert_eq!(
            err,
            Err(ProviderGraphError::UnknownProvider {
                provider: provider_id(99),
            })
        );
    }

    #[test]
    fn mixed_impacts_sorted_by_consumer() {
        let graph = graph(
            &[provider(
                1,
                &[iface("if-a", 1, 0, 0), iface("if-b", 1, 0, 0)],
            )],
            &[
                consumer(4, &[requirement("if-b", "^1.0.0")]),
                consumer(2, &[requirement("if-a", "^1.0.0")]),
            ],
        );
        // 升级移除 if-a、保留 if-b → consumer 2 不兼容、consumer 4 兼容。
        let report = ok(
            graph.analyze_upgrade(provider_id(1), set([iface("if-b", 1, 2, 0)])),
            "upgrade analysis",
        );
        assert!(!report.is_safe());
        let consumers: Vec<InstallationId> =
            report.impacts().iter().map(|i| i.consumer()).collect();
        assert_eq!(consumers, vec![installation(2), installation(4)]);
        assert!(!report.impacts()[0].result().is_compatible());
        assert!(report.impacts()[1].result().is_compatible());
    }

    #[test]
    fn one_interface_bumped_other_removed() {
        let graph = graph(
            &[provider(
                1,
                &[iface("if-a", 1, 0, 0), iface("if-b", 1, 0, 0)],
            )],
            &[consumer(
                2,
                &[requirement("if-a", "^1.0.0"), requirement("if-b", "^1.0.0")],
            )],
        );
        // if-a 升到 2.0.0（版本不兼容），if-b 移除（interface 移除）。
        let report = ok(
            graph.analyze_upgrade(provider_id(1), set([iface("if-a", 2, 0, 0)])),
            "upgrade analysis",
        );
        assert_eq!(report.impacts().len(), 2);
        let reasons: Vec<UpgradeIncompatibility> = report
            .impacts()
            .iter()
            .map(|impact| match impact.result() {
                UpgradeImpact::Incompatible { reason } => reason.clone(),
                UpgradeImpact::Compatible => unreachable!("both consumers must break"),
            })
            .collect();
        assert!(reasons.contains(&UpgradeIncompatibility::InterfaceRemoved));
        assert!(
            reasons.contains(&UpgradeIncompatibility::VersionIncompatible {
                upgraded_highest: version(2, 0, 0),
            })
        );
    }

    #[test]
    fn version_incompatible_reports_highest_upgraded_version() {
        let graph = graph(
            &[provider(1, &[iface("if-a", 1, 0, 0)])],
            &[consumer(2, &[requirement("if-a", "^1.0.0")])],
        );
        // 升级提供 2.0.0 与 3.0.0：诊断报告最高的 3.0.0。
        let report = ok(
            graph.analyze_upgrade(
                provider_id(1),
                set([iface("if-a", 2, 0, 0), iface("if-a", 3, 0, 0)]),
            ),
            "upgrade analysis",
        );
        assert_eq!(
            report.impacts()[0].result(),
            &UpgradeImpact::Incompatible {
                reason: UpgradeIncompatibility::VersionIncompatible {
                    upgraded_highest: version(3, 0, 0),
                },
            }
        );
    }

    #[test]
    fn analysis_is_deterministic() {
        let graph = graph(
            &[provider(
                1,
                &[iface("if-a", 1, 0, 0), iface("if-b", 1, 0, 0)],
            )],
            &[
                consumer(4, &[requirement("if-b", "^1.0.0")]),
                consumer(2, &[requirement("if-a", "^1.0.0")]),
            ],
        );
        let new_set = set([iface("if-b", 1, 2, 0)]);
        let first = ok(
            graph.analyze_upgrade(provider_id(1), new_set.clone()),
            "first",
        );
        let second = ok(graph.analyze_upgrade(provider_id(1), new_set), "second");
        assert_eq!(first, second);
    }

    // ------------------------------------------------------------------
    // proptest
    // ------------------------------------------------------------------

    fn any_interface_id() -> impl Strategy<Value = InterfaceId> {
        (
            prop_oneof![Just("if-a"), Just("if-b"), Just("if-c")],
            prop_oneof![
                Just(version(1, 0, 0)),
                Just(version(1, 2, 0)),
                Just(version(2, 0, 0)),
            ],
        )
            .prop_map(|(interface, v)| iface(interface, v.major(), v.minor(), v.patch()))
    }

    fn any_requirement() -> impl Strategy<Value = InterfaceRequirement> {
        (
            prop_oneof![Just("if-a"), Just("if-b"), Just("if-c")],
            prop_oneof![
                Just("^1.0.0"),
                Just(">=1.2.0, <2.0.0"),
                Just("*"),
                Just("^2.0.0"),
            ],
        )
            .prop_map(|(interface, req)| requirement(interface, req))
    }

    fn any_components() -> impl Strategy<
        Value = (
            Vec<ProviderRecord>,
            Vec<ConsumerRecord>,
            BTreeSet<InterfaceId>,
        ),
    > {
        (
            proptest::collection::vec(
                (
                    proptest::collection::btree_set(any_interface_id(), 0..=2),
                    proptest::collection::btree_set(any_requirement(), 0..=2),
                ),
                0..=5,
            ),
            proptest::collection::btree_set(any_interface_id(), 0..=3),
        )
            .prop_map(|(components, upgrade_set)| {
                let mut providers = Vec::new();
                let mut consumers = Vec::new();
                for (i, (provided, required)) in components.into_iter().enumerate() {
                    let seed = u64::try_from(i).unwrap_or(u64::MAX);
                    if !provided.is_empty() {
                        providers.push(ok(
                            ProviderRecord::new(installation(seed), provided),
                            "provider record",
                        ));
                    }
                    if !required.is_empty() {
                        consumers.push(ConsumerRecord::new(installation(seed), required));
                    }
                }
                (providers, consumers, upgrade_set)
            })
    }

    proptest! {
        #[test]
        fn upgrade_report_properties(
            (providers, consumers, upgrade_set) in any_components(),
        ) {
            let graph = match ProviderGraph::try_build(&providers, &consumers) {
                Ok(graph) => graph,
                Err(_) => return Ok(()), // 只在合法图上分析
            };
            for provider_id in graph.providers().map(|node| node.provider()) {
                let report = match graph.analyze_upgrade(provider_id, upgrade_set.clone()) {
                    Ok(report) => report,
                    Err(_) => return Ok(()),
                };
                // is_safe 与全部影响兼容一致。
                let all_compatible = report
                    .impacts()
                    .iter()
                    .all(|impact| impact.result().is_compatible());
                prop_assert_eq!(report.is_safe(), all_compatible);
                // 影响只覆盖直接依赖该 provider 的 consumer。
                let direct: Vec<InstallationId> = graph
                    .direct_consumers(provider_id)
                    .iter()
                    .map(|edge| edge.consumer())
                    .collect();
                prop_assert_eq!(report.impacts().len(), direct.len());
                // 独立重算：VersionIncompatible 的 upgraded_highest 必须是
                // 升级集中该 interface 的最高版本。
                for impact in report.impacts() {
                    if let UpgradeImpact::Incompatible {
                        reason: UpgradeIncompatibility::VersionIncompatible {
                            upgraded_highest,
                        },
                    } = impact.result()
                    {
                        let highest = upgrade_set
                            .iter()
                            .filter(|p| p.interface() == impact.requirement().interface())
                            .max_by_key(|p| p.version());
                        let Some(highest) = highest else {
                            prop_assert!(false, "VersionIncompatible requires same-interface entries");
                            return Ok(());
                        };
                        prop_assert_eq!(upgraded_highest, &highest.version());
                    }
                }
                // 确定性。
                let again = graph.analyze_upgrade(provider_id, upgrade_set.clone());
                prop_assert_eq!(again, Ok(report));
            }
        }
    }
}
