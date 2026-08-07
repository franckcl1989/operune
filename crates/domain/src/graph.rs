//! 0.2.0 Capability Composition（§40.2 / §40.3）：Provider dependency graph。
//!
//! # 事实源（§40.3）
//!
//! 依赖关系**只能**来自 WIT imports/exports + Runtime Policy，禁止创建另一份
//! `dependencies.json` 作为事实源。本模块的输入形态：
//!
//! - [`ProviderRecord`]：provider 导出的接口集合——来自 Component 二进制中
//!   真实可观察的 contract surface（§6.7，runtime-wasi-p2 适配层观察 WIT
//!   exports 后构造）；
//! - [`ConsumerRecord`]：consumer 导入的接口需求——来自 WIT imports；
//! - Runtime Policy（授权 / scope / provider 过滤）由 application 层在调用
//!   domain 前应用：policy 决定**哪些** provider 记录进入本模型。
//!
//! Domain 不读取任何 manifest / 私有声明文件，也不实现 provider selection 的
//! policy 规则（§40.2：provider selection 的确定规则在 application 层）。
//!
//! # 确定性（§40.4）
//!
//! 同一 Component set + 同一 policy 必须得到确定结果。本模块保证：
//!
//! - 全部内部结构使用 `BTree*`（`HashMap` 的迭代顺序随机，禁用）；
//! - [`ProviderId`] 从 `InstallationId` 确定性派生（同一安装实例 → 同一
//!   provider 身份）；
//! - 解析、报错、环路径、拓扑排序全部按稳定键（`ProviderId` /
//!   `InstallationId` / [`InterfaceRequirement`] 的 Ord）排序迭代，fail-fast
//!   的首个错误也在排序序中确定；
//! - 无法唯一合法解析时返回 [`ProviderGraphError::AmbiguousProvider`] 拒绝
//!   激活，绝不随机选择 provider（§40.4）。

use std::collections::{BTreeMap, BTreeSet};

use crate::interface::{InterfaceId, InterfaceName, InterfaceRequirement, PackageName};
use crate::provider::ProviderId;
use crate::{ComponentVersion, InstallationId};

/// 一个 provider 节点的输入记录：安装实例 + 提供面（§40.3 事实源：WIT
/// exports + Runtime Policy 过滤后的结果）。
///
/// 不变量：`provided` 非空（"provider" 的定义是至少提供一个 interface；
/// 构造即校验，§13.4 不合法状态不可表示）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRecord {
    installation: InstallationId,
    provided: BTreeSet<InterfaceId>,
}

impl ProviderRecord {
    /// 构造 provider 记录（validate-on-construct：空提供面拒绝）。
    pub fn new(
        installation: InstallationId,
        provided: BTreeSet<InterfaceId>,
    ) -> Result<Self, ProviderGraphError> {
        if provided.is_empty() {
            return Err(ProviderGraphError::EmptyProvidedSet {
                provider: ProviderId::from_installation(installation),
            });
        }
        Ok(Self {
            installation,
            provided,
        })
    }

    /// 该 provider 的安装实例。
    pub fn installation(&self) -> InstallationId {
        self.installation
    }

    /// provider 身份（由安装实例确定性派生，§40.4）。
    pub fn provider_id(&self) -> ProviderId {
        ProviderId::from_installation(self.installation)
    }

    /// 提供的接口集合（只读）。
    pub fn provided(&self) -> &BTreeSet<InterfaceId> {
        &self.provided
    }
}

/// 一个 consumer 的输入记录：安装实例 + 导入需求（§40.3 事实源：WIT
/// imports）。
///
/// `required` 可以为空（无导入的组件不是任何 provider 的 consumer，不会
/// 产生边；是合法输入）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsumerRecord {
    installation: InstallationId,
    required: BTreeSet<InterfaceRequirement>,
}

impl ConsumerRecord {
    /// 构造 consumer 记录（`required` 可为空：无导入的组件）。
    pub fn new(installation: InstallationId, required: BTreeSet<InterfaceRequirement>) -> Self {
        Self {
            installation,
            required,
        }
    }

    /// 该 consumer 的安装实例。
    pub fn installation(&self) -> InstallationId {
        self.installation
    }

    /// 导入需求集合（只读）。
    pub fn required(&self) -> &BTreeSet<InterfaceRequirement> {
        &self.required
    }
}

/// graph 中的 provider 节点（§40.2 dependency graph：节点 = ProviderId +
/// InstallationId + 提供面集合）。
///
/// 不变量（构造保证）：`provider == ProviderId::from_installation(installation)`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderNode {
    provider: ProviderId,
    installation: InstallationId,
    provided: BTreeSet<InterfaceId>,
}

impl ProviderNode {
    fn from_record(record: &ProviderRecord) -> Self {
        Self {
            provider: record.provider_id(),
            installation: record.installation,
            provided: record.provided.clone(),
        }
    }

    /// provider 身份。
    pub fn provider(&self) -> ProviderId {
        self.provider
    }

    /// 该 provider 的安装实例（provider 身份 → 安装实例的唯一路径；§17.5
    /// Grant 的 durable owner 是 InstallationId）。
    pub fn installation(&self) -> InstallationId {
        self.installation
    }

    /// 提供的接口集合（只读）。
    pub fn provided(&self) -> &BTreeSet<InterfaceId> {
        &self.provided
    }
}

/// 一条已解析的依赖边：consumer 需求 → provider 提供（§40.2 dependency
/// graph：边 = Consumer 需求 → Provider 提供）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEdge {
    consumer: InstallationId,
    requirement: InterfaceRequirement,
    provider: ProviderId,
    provided: InterfaceId,
}

impl ResolvedEdge {
    /// 依赖方安装实例。
    pub fn consumer(&self) -> InstallationId {
        self.consumer
    }

    /// 被满足的导入需求。
    pub fn requirement(&self) -> &InterfaceRequirement {
        &self.requirement
    }

    /// 被解析到的 provider。
    pub fn provider(&self) -> ProviderId {
        self.provider
    }

    /// 实际解析到的提供版本（同一 provider 提供多个兼容版本时取最高，
    /// 见 [`ProviderGraph::try_build`] 文档）。
    pub fn provided(&self) -> &InterfaceId {
        &self.provided
    }
}

/// [`ProviderGraphError::IncompatibleVersion`] 的候选诊断：导出该 interface
/// 但版本不满足需求的 provider。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InterfaceCandidate {
    /// 候选 provider。
    pub provider: ProviderId,
    /// 该 provider 导出的版本。
    pub version: ComponentVersion,
}

/// 0.2.0 provider graph 构建错误（§14.1：封闭、可匹配的 typed error）。
///
/// 所有错误携带可诊断信息（哪个 consumer、哪个需求、哪些候选），不含机密。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderGraphError {
    /// 依赖图中存在环（§40.2 cycle detection）。`cycle` 是**闭路径**：首尾
    /// 相同，相邻项之间存在 "consumer 依赖 provider" 边（如 `[p1, p2, p1]`
    /// 表示 p1 依赖 p2 且 p2 依赖 p1；自环为 `[p, p]`）。
    #[error("provider dependency cycle detected: {cycle}", cycle = join_providers(.cycle))]
    CycleDetected {
        /// 环上的 provider（闭路径）。
        cycle: Vec<ProviderId>,
    },

    /// 没有任何 provider 导出该 interface（§40.2 missing provider
    /// diagnostics：指明哪个 consumer 缺哪个 provider）。
    #[error("no provider exports {requirement} required by consumer {consumer}")]
    MissingProvider {
        /// 缺 provider 的 consumer。
        consumer: InstallationId,
        /// 无法满足的需求（Box：控制错误类型体积，§14.1）。
        requirement: Box<InterfaceRequirement>,
    },

    /// 存在导出该 interface 的 provider，但没有版本满足需求。
    #[error("providers export the interface but none satisfies version requirement {requirement} of consumer {consumer} (candidates: {candidates})", candidates = join_candidates(.candidates))]
    IncompatibleVersion {
        /// 需求的 consumer。
        consumer: InstallationId,
        /// 无法满足的需求（Box：控制错误类型体积，§14.1）。
        requirement: Box<InterfaceRequirement>,
        /// 导出该 interface 的候选 provider 及其版本（按 provider 排序）。
        candidates: Vec<InterfaceCandidate>,
    },

    /// 多个 provider 都能满足同一需求，无法唯一合法解析（§40.4：拒绝激活，
    /// 不得随机选择 provider）。选择规则属于 application 层 policy。
    #[error("ambiguous provider for requirement {requirement} of consumer {consumer}: candidates {candidates}", candidates = join_providers(.candidates))]
    AmbiguousProvider {
        /// 需求的 consumer。
        consumer: InstallationId,
        /// 无法唯一解析的需求（Box：控制错误类型体积，§14.1）。
        requirement: Box<InterfaceRequirement>,
        /// 全部兼容候选（按 provider 排序）。
        candidates: Vec<ProviderId>,
    },

    /// 同一 provider 记录出现两次（同安装实例重复提供）。
    #[error("duplicate provider record for installation {provider}")]
    DuplicateProvider {
        /// 重复的 provider。
        provider: ProviderId,
    },

    /// provider 记录没有任何提供面（§13.4 不合法状态不可表示）。
    #[error("provider {provider} exports no interfaces")]
    EmptyProvidedSet {
        /// 空提供面的 provider。
        provider: ProviderId,
    },

    /// 同一 consumer 记录出现两次。
    #[error("duplicate consumer record for installation {consumer}")]
    DuplicateConsumer {
        /// 重复的 consumer。
        consumer: InstallationId,
    },

    /// 查询的 provider 不在图中。
    #[error("provider {provider} is not part of this graph")]
    UnknownProvider {
        /// 未知的 provider。
        provider: ProviderId,
    },
}

/// 错误 Display 辅助：`p1 -> p2 -> p3 -> p1`。
fn join_providers(providers: &[ProviderId]) -> String {
    let mut out = String::new();
    for (i, provider) in providers.iter().enumerate() {
        if i > 0 {
            out.push_str(" -> ");
        }
        out.push_str(&provider.to_string());
    }
    out
}

/// 错误 Display 辅助：`p@1.2.3, q@0.1.0`。
fn join_candidates(candidates: &[InterfaceCandidate]) -> String {
    let mut out = String::new();
    for (i, candidate) in candidates.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!("{}@{}", candidate.provider, candidate.version));
    }
    out
}

/// 0.2.0 provider graph 的不可变快照（§40.2 graph snapshot）。
///
/// 不变量（构造时全部校验，§13.4 不合法状态不可表示）：
/// - provider 身份唯一且可追溯到安装实例；
/// - 每条 consumer 需求恰好解析到一个 provider（无 Missing / Ambiguous /
///   IncompatibleVersion）；
/// - 依赖图**无环**（有环在 [`ProviderGraphError::CycleDetected`] 拒绝）；
/// - 所有查询/迭代/排序完全确定（§40.4）。
///
/// 本类型不实现 `Deserialize`：图的不变量（无环、唯一解析）无法在反序列化
/// 时重新校验；持久化/恢复（§40.2 graph persistence/recovery）的路径是持久化
/// [`ProviderRecord`] / [`ConsumerRecord`]，恢复时重新 `try_build`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderGraph {
    providers: BTreeMap<ProviderId, ProviderNode>,
    edges: BTreeMap<(InstallationId, InterfaceRequirement), ResolvedEdge>,
    /// 激活顺序（provider 先于 consumer；确定性，§40.2 activation/deactivation
    /// ordering）。
    topological_order: Vec<InstallationId>,
}

impl ProviderGraph {
    /// 从 provider / consumer 记录构建不可变快照。
    ///
    /// 解析规则（全部确定性，§40.4）：
    /// - 按 (consumer, requirement) 排序迭代，fail-fast 返回首个错误；
    /// - 候选 = 导出同一 (package, interface) 且版本满足需求的 provider；
    ///   - 无任何 provider 导出该 interface →
    ///     [`ProviderGraphError::MissingProvider`]；
    ///   - 有导出但版本都不满足 → [`ProviderGraphError::IncompatibleVersion`]；
    ///   - 恰好一个候选 provider → 解析成功；同一 provider 提供多个兼容
    ///     版本时取**最高版本**（纯结构规则，不涉及 provider 选择 policy）；
    ///   - 多个候选 provider → [`ProviderGraphError::AmbiguousProvider`]
    ///     （拒绝激活；provider 选择规则属于 application 层 policy）。
    /// - 全部需求解析成功后做环检测（Kahn）；有环 →
    ///   [`ProviderGraphError::CycleDetected`]。
    pub fn try_build(
        providers: &[ProviderRecord],
        consumers: &[ConsumerRecord],
    ) -> Result<Self, ProviderGraphError> {
        // --- 1. 校验输入唯一性（确定性：输入顺序无关） ---
        let mut nodes: BTreeMap<ProviderId, ProviderNode> = BTreeMap::new();
        for record in providers {
            let provider = record.provider_id();
            if nodes.contains_key(&provider) {
                return Err(ProviderGraphError::DuplicateProvider { provider });
            }
            nodes.insert(provider, ProviderNode::from_record(record));
        }

        let mut consumer_requirements: BTreeMap<InstallationId, BTreeSet<InterfaceRequirement>> =
            BTreeMap::new();
        for record in consumers {
            if consumer_requirements.contains_key(&record.installation) {
                return Err(ProviderGraphError::DuplicateConsumer {
                    consumer: record.installation,
                });
            }
            consumer_requirements.insert(record.installation, record.required.clone());
        }

        // --- 2. 接口索引：(package, interface) → 按 (provider, 版本) 排序 ---
        let mut index: BTreeMap<(PackageName, InterfaceName), Vec<(ProviderId, InterfaceId)>> =
            BTreeMap::new();
        for (provider, node) in &nodes {
            for provided in &node.provided {
                index
                    .entry((provided.package().clone(), provided.interface().clone()))
                    .or_default()
                    .push((*provider, provided.clone()));
            }
        }

        // --- 3. 逐条解析需求（排序序，fail-fast） ---
        let mut edges: BTreeMap<(InstallationId, InterfaceRequirement), ResolvedEdge> =
            BTreeMap::new();
        for (consumer, required) in &consumer_requirements {
            for requirement in required {
                let (provider, provided) = resolve(&index, consumer, requirement)?;
                edges.insert(
                    (*consumer, requirement.clone()),
                    ResolvedEdge {
                        consumer: *consumer,
                        requirement: requirement.clone(),
                        provider,
                        provided,
                    },
                );
            }
        }

        // --- 4. 环检测 + 激活顺序 ---
        let topological_order = match compute_activation_order(&nodes, &edges) {
            Ok(order) => order,
            Err(cycle) => return Err(ProviderGraphError::CycleDetected { cycle }),
        };

        Ok(Self {
            providers: nodes,
            edges,
            topological_order,
        })
    }

    /// provider 节点（按 ProviderId 排序）。
    pub fn providers(&self) -> impl Iterator<Item = &ProviderNode> {
        self.providers.values()
    }

    /// 已解析的依赖边（按 (consumer, requirement) 排序）。
    pub fn edges(&self) -> impl Iterator<Item = &ResolvedEdge> {
        self.edges.values()
    }

    /// 激活顺序（§40.2 activation/deactivation ordering）：每条依赖边
    /// consumer → provider 中，provider 的安装实例必然排在 consumer 之前；
    /// 覆盖全部参与组合的安装实例（所有 provider + 有需求的 consumer）；
    /// 确定且无环。deactivation 顺序即其逆序。
    pub fn topological_order(&self) -> &[InstallationId] {
        &self.topological_order
    }

    /// 查询某 consumer 的某需求解析到的边。
    pub fn resolve(
        &self,
        consumer: InstallationId,
        requirement: &InterfaceRequirement,
    ) -> Option<&ResolvedEdge> {
        self.edges.get(&(consumer, requirement.clone()))
    }

    /// 某 provider 自身的依赖（其安装实例作为 consumer 的全部已解析需求），
    /// 按需求排序。
    pub fn dependencies_of(&self, provider: ProviderId) -> Vec<&ResolvedEdge> {
        let Some(node) = self.providers.get(&provider) else {
            return Vec::new();
        };
        self.edges
            .values()
            .filter(|edge| edge.consumer == node.installation)
            .collect()
    }

    /// 直接依赖某 provider 的边（consumer → provider），按 (consumer,
    /// requirement) 排序。
    pub fn direct_consumers(&self, provider: ProviderId) -> Vec<&ResolvedEdge> {
        self.edges
            .values()
            .filter(|edge| edge.provider == provider)
            .collect()
    }

    /// 当前图中能兼容满足该需求的 provider（按 ProviderId 排序；供诊断与
    /// application 层 policy 决策）。
    pub fn providers_satisfying(&self, requirement: &InterfaceRequirement) -> Vec<&ProviderNode> {
        self.providers
            .values()
            .filter(|node| {
                node.provided
                    .iter()
                    .any(|provided| requirement.satisfied_by(provided))
            })
            .collect()
    }
}

/// 解析单个需求的纯函数：返回 (provider, 实际提供的版本)。`index` 条目按
/// (provider, 版本) 排序。
fn resolve(
    index: &BTreeMap<(PackageName, InterfaceName), Vec<(ProviderId, InterfaceId)>>,
    consumer: &InstallationId,
    requirement: &InterfaceRequirement,
) -> Result<(ProviderId, InterfaceId), ProviderGraphError> {
    let Some(entries) = index.get(&(
        requirement.package().clone(),
        requirement.interface().clone(),
    )) else {
        return Err(ProviderGraphError::MissingProvider {
            consumer: *consumer,
            requirement: Box::new(requirement.clone()),
        });
    };

    // 兼容条目（保持 (provider, 版本) 排序）。
    let compatible: Vec<(ProviderId, &InterfaceId)> = entries
        .iter()
        .filter(|(_, provided)| requirement.satisfied_by(provided))
        .map(|(provider, provided)| (*provider, provided))
        .collect();

    if compatible.is_empty() {
        return Err(ProviderGraphError::IncompatibleVersion {
            consumer: *consumer,
            requirement: Box::new(requirement.clone()),
            candidates: entries
                .iter()
                .map(|(provider, provided)| InterfaceCandidate {
                    provider: *provider,
                    version: provided.version(),
                })
                .collect(),
        });
    }

    // 候选 provider 去重（同一 provider 多个兼容版本只算一个候选），保持排序。
    let mut distinct: Vec<ProviderId> = Vec::new();
    for (provider, _) in &compatible {
        if distinct.last() != Some(provider) {
            distinct.push(*provider);
        }
    }

    if distinct.len() > 1 {
        return Err(ProviderGraphError::AmbiguousProvider {
            consumer: *consumer,
            requirement: Box::new(requirement.clone()),
            candidates: distinct,
        });
    }

    // 唯一 provider：取最高兼容版本（纯结构规则；条目按 (provider, 版本)
    // 升序，同 provider 的兼容条目连续，最后一个即最高版本）。
    let provider = match distinct.pop() {
        Some(provider) => provider,
        None => unreachable!("compatible is non-empty, so distinct candidates are non-empty"),
    };
    let mut highest: Option<&InterfaceId> = None;
    for (entry_provider, provided) in &compatible {
        if *entry_provider == provider {
            highest = Some(provided);
        }
    }
    let provided = match highest {
        Some(provided) => provided.clone(),
        None => unreachable!("the chosen provider has at least one compatible entry"),
    };
    Ok((provider, provided))
}

/// 环检测 + 激活顺序（Kahn + 剩余子图确定性 DFS）。
///
/// 图方向：边 `consumer → provider`（"consumer 依赖 provider"）。Kahn 输出
/// "无依赖者优先"序，其**逆序**即激活顺序（provider 先于 consumer）。
///
/// 无环：`Ok(激活顺序)`。有环：`Err(环闭路径)`，路径上相邻项之间存在
/// "consumer 依赖 provider" 边。
///
/// 复杂度：Kahn O(V + E)；环路径提取为剩余子图上的 DFS，O(V + E)。
fn compute_activation_order(
    nodes: &BTreeMap<ProviderId, ProviderNode>,
    edges: &BTreeMap<(InstallationId, InterfaceRequirement), ResolvedEdge>,
) -> Result<Vec<InstallationId>, Vec<ProviderId>> {
    // 参与节点：全部 provider 安装实例 + 有需求的 consumer。
    let mut participants: BTreeSet<InstallationId> = BTreeSet::new();
    for node in nodes.values() {
        participants.insert(node.installation);
    }
    for consumer in edges.values().map(|edge| edge.consumer) {
        participants.insert(consumer);
    }

    // 邻接（depends-on）：consumer 安装实例 → 其依赖的 provider 安装实例。
    // 同一 consumer 的多个需求可指向同一 provider：保留重复边，入度按边计。
    let mut adjacency: BTreeMap<InstallationId, Vec<InstallationId>> = BTreeMap::new();
    let mut in_degree: BTreeMap<InstallationId, usize> =
        participants.iter().map(|&n| (n, 0usize)).collect();
    for edge in edges.values() {
        let provider_installation = match nodes.get(&edge.provider) {
            Some(node) => node.installation,
            // 不变量：边只可能指向图中的 provider（构建保证）。§14.3：
            // 不可恢复不变量失败采用 fail-stop。
            None => unreachable!("edges only reference providers in the graph"),
        };
        adjacency
            .entry(edge.consumer)
            .or_default()
            .push(provider_installation);
        // provider 安装实例必是参与者（构建保证）。
        if let Some(degree) = in_degree.get_mut(&provider_installation) {
            *degree = degree.saturating_add(1);
        }
    }

    // Kahn：入度 0 = 无任何依赖，先激活。
    let mut ready: BTreeSet<InstallationId> = in_degree
        .iter()
        .filter(|(_, degree)| **degree == 0)
        .map(|(&installation, _)| installation)
        .collect();
    let mut processed: Vec<InstallationId> = Vec::with_capacity(participants.len());
    while let Some(node) = ready.pop_first() {
        processed.push(node);
        if let Some(deps) = adjacency.get(&node) {
            for &dependency in deps {
                if let Some(degree) = in_degree.get_mut(&dependency) {
                    *degree = degree.saturating_sub(1);
                    if *degree == 0 {
                        ready.insert(dependency);
                    }
                }
            }
        }
    }

    if processed.len() == participants.len() {
        // 无环：processed 是"consumer 优先"序，逆序即激活顺序。
        let mut activation_order = processed;
        activation_order.reverse();
        return Ok(activation_order);
    }

    // 有环：剩余节点入度全部 ≥ 1，且全部是 provider（非 provider 的
    // consumer 入度为 0，必被 Kahn 移除）。
    let processed_set: BTreeSet<InstallationId> = processed.iter().copied().collect();
    let remaining_providers: BTreeSet<ProviderId> = nodes
        .values()
        .filter(|node| !processed_set.contains(&node.installation))
        .map(|node| node.provider)
        .collect();

    let cycle = match find_cycle(&remaining_providers, &adjacency) {
        Some(cycle) => cycle,
        // 剩余子图每点入度 ≥ 1 ⇒ 必然含环（有限图性质）；未找到是不可恢复
        // 不变量失败，§14.3 fail-stop。
        None => unreachable!("the remaining subgraph always contains a cycle"),
    };

    Err(cycle)
}

/// 在剩余子图中找环（确定性 DFS；返回闭路径）。
///
/// 剩余子图每点入度 ≥ 1（Kahn 剩余性质），有限图必然含环；DFS 从最小
/// provider 出发、按邻接序探索，任一可达环必然命中（经典 DFS 环检测）。
/// ProviderId ↔ InstallationId 直接互转（同一底层 Uuid），无需映射表。
fn find_cycle(
    remaining_providers: &BTreeSet<ProviderId>,
    adjacency: &BTreeMap<InstallationId, Vec<InstallationId>>,
) -> Option<Vec<ProviderId>> {
    let mut visited: BTreeSet<ProviderId> = BTreeSet::new();
    for &start in remaining_providers {
        if visited.contains(&start) {
            continue;
        }
        let start_installation = InstallationId::from_uuid(start.as_uuid());

        let mut path: Vec<ProviderId> = vec![start];
        let mut positions: BTreeMap<ProviderId, usize> = BTreeMap::new();
        positions.insert(start, 0);
        visited.insert(start);

        // 显式栈：(provider, 邻居表, 下一个邻居下标)。
        let mut stack: Vec<(ProviderId, Vec<InstallationId>, usize)> = vec![(
            start,
            adjacency
                .get(&start_installation)
                .cloned()
                .unwrap_or_default(),
            0,
        )];

        while !stack.is_empty() {
            // 取出下一个邻居（借用作用域结束于 match；随后可 push/pop）。
            let next = match stack.last_mut() {
                Some((_, neighbors, next_index)) => {
                    let next = neighbors.get(*next_index).copied();
                    if next.is_some() {
                        *next_index += 1;
                    }
                    next
                }
                // 循环条件保证栈非空（§14.3 fail-stop）。
                None => unreachable!("stack is non-empty by loop condition"),
            };

            let Some(next_installation) = next else {
                // 邻居耗尽：回溯。
                let _ = stack.pop();
                if let Some(popped) = path.pop() {
                    positions.remove(&popped);
                }
                continue;
            };

            // 邻接值只可能是 provider 安装实例（构建保证）；即便防御性失败
            // 也只是跳过该邻居，不产生 panic。
            let next_provider = ProviderId::from_installation(next_installation);

            if let Some(&pos) = positions.get(&next_provider) {
                // 命中当前路径 → 环（闭路径：[path[pos..], next_provider]）。
                let mut cycle = path[pos..].to_vec();
                cycle.push(next_provider);
                return Some(cycle);
            }

            if !visited.contains(&next_provider) {
                visited.insert(next_provider);
                positions.insert(next_provider, path.len());
                path.push(next_provider);
                stack.push((
                    next_provider,
                    adjacency
                        .get(&next_installation)
                        .cloned()
                        .unwrap_or_default(),
                    0,
                ));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::{InterfaceName, PackageName};
    use crate::test_support::ok;
    use proptest::prelude::*;
    use proptest::strategy::Strategy;
    use uuid::Uuid;

    /// 确定性安装实例：seed → 唯一 uuid（排序与 seed 一致）。
    fn installation(seed: u64) -> InstallationId {
        InstallationId::from_uuid(Uuid::from_u128(u128::from(seed)))
    }

    fn version(major: u32, minor: u32, patch: u32) -> ComponentVersion {
        ComponentVersion::from_parts(major, minor, patch)
    }

    fn iface(package: &str, interface: &str, major: u32, minor: u32, patch: u32) -> InterfaceId {
        InterfaceId::new(
            ok(PackageName::new(package), "package"),
            ok(InterfaceName::new(interface), "interface"),
            version(major, minor, patch),
        )
    }

    fn requirement(text: &str) -> InterfaceRequirement {
        ok(text.parse::<InterfaceRequirement>(), "requirement")
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

    fn provider_id(seed: u64) -> ProviderId {
        ProviderId::from_installation(installation(seed))
    }

    fn build(providers: &[ProviderRecord], consumers: &[ConsumerRecord]) -> ProviderGraph {
        ok(
            ProviderGraph::try_build(providers, consumers),
            "graph build",
        )
    }

    /// 断言激活顺序满足每条边：provider 安装实例在 consumer 之前。
    fn assert_order_valid(graph: &ProviderGraph) {
        let positions: BTreeMap<InstallationId, usize> = graph
            .topological_order()
            .iter()
            .enumerate()
            .map(|(i, &installation)| (installation, i))
            .collect();
        for edge in graph.edges() {
            let provider_installation = match graph
                .providers()
                .find(|node| node.provider() == edge.provider())
            {
                Some(node) => node.installation(),
                None => unreachable!("edge provider exists in graph"),
            };
            let consumer_pos = match positions.get(&edge.consumer()) {
                Some(pos) => *pos,
                None => unreachable!("consumer participates in the order"),
            };
            let provider_pos = match positions.get(&provider_installation) {
                Some(pos) => *pos,
                None => unreachable!("provider installation participates in the order"),
            };
            assert!(
                provider_pos < consumer_pos,
                "provider {} must activate before consumer {}",
                provider_installation,
                edge.consumer()
            );
        }
    }

    // ------------------------------------------------------------------
    // 解析（resolution）
    // ------------------------------------------------------------------

    #[test]
    fn resolves_simple_chain() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let graph = build(&[a], &[b]);

        let edge = match graph.resolve(installation(2), &requirement("ns:pkg/if-a@^1.0.0")) {
            Some(edge) => edge,
            None => unreachable!("requirement must be resolved"),
        };
        assert_eq!(edge.provider(), provider_id(1));
        assert_eq!(edge.provided(), &iface("ns:pkg", "if-a", 1, 0, 0));
        assert_eq!(edge.consumer(), installation(2));
        // 激活顺序：provider 先于 consumer。
        assert_eq!(
            graph.topological_order(),
            &[installation(1), installation(2)]
        );
        assert_order_valid(&graph);
    }

    #[test]
    fn picks_highest_compatible_version_within_provider() {
        // 同一 provider 导出两个兼容版本 → 取最高（纯结构规则）。
        let a = provider(
            1,
            &[
                iface("ns:pkg", "if-a", 1, 0, 0),
                iface("ns:pkg", "if-a", 1, 1, 0),
            ],
        );
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let graph = build(&[a], &[b]);
        let edge = match graph.resolve(installation(2), &requirement("ns:pkg/if-a@^1.0.0")) {
            Some(edge) => edge,
            None => unreachable!("requirement must be resolved"),
        };
        assert_eq!(edge.provided(), &iface("ns:pkg", "if-a", 1, 1, 0));
    }

    #[test]
    fn missing_provider_diagnostics() {
        let err = ProviderGraph::try_build(
            &[],
            &[consumer(
                2,
                &[
                    requirement("ns:pkg/if-a@^1.0.0"),
                    requirement("ns:pkg/if-b@^2.0.0"),
                ],
            )],
        );
        // fail-fast：按 (consumer, requirement) 排序，首个缺失被报告。
        let err = match err {
            Err(error) => error,
            Ok(_) => unreachable!("expected missing provider error"),
        };
        assert_eq!(
            err,
            ProviderGraphError::MissingProvider {
                consumer: installation(2),
                requirement: Box::new(requirement("ns:pkg/if-a@^1.0.0")),
            }
        );
        // 错误 Display 必须指明哪个 consumer 缺哪个 provider。
        let message = err.to_string();
        assert!(message.contains(&installation(2).to_string()));
        assert!(message.contains("ns:pkg/if-a@^1.0.0"));
    }

    #[test]
    fn incompatible_version_diagnostics() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = consumer(2, &[requirement("ns:pkg/if-a@^2.0.0")]);
        let err = ProviderGraph::try_build(&[a], &[b]);
        let err = match err {
            Err(error) => error,
            Ok(_) => unreachable!("expected incompatible version error"),
        };
        assert_eq!(
            err,
            ProviderGraphError::IncompatibleVersion {
                consumer: installation(2),
                requirement: Box::new(requirement("ns:pkg/if-a@^2.0.0")),
                candidates: vec![InterfaceCandidate {
                    provider: provider_id(1),
                    version: version(1, 0, 0),
                }],
            }
        );
        let message = err.to_string();
        assert!(message.contains("ns:pkg/if-a@^2.0.0"));
        assert!(message.contains(&provider_id(1).to_string()));
    }

    #[test]
    fn ambiguous_provider_rejected_deterministically() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let c = consumer(3, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let err = ProviderGraph::try_build(&[b, a], &[c]);
        let err = match err {
            Err(error) => error,
            Ok(_) => unreachable!("expected ambiguous provider error"),
        };
        // 候选按 ProviderId 排序（确定性）。
        let mut expected = vec![provider_id(1), provider_id(2)];
        expected.sort();
        assert_eq!(
            err,
            ProviderGraphError::AmbiguousProvider {
                consumer: installation(3),
                requirement: Box::new(requirement("ns:pkg/if-a@^1.0.0")),
                candidates: expected,
            }
        );
        let message = err.to_string();
        assert!(message.contains("ns:pkg/if-a@^1.0.0"));
        assert!(message.contains(" -> "));
    }

    #[test]
    fn same_provider_multiple_versions_not_ambiguous() {
        // 两个兼容版本来自同一 provider → 唯一 provider，不算歧义。
        let a = provider(
            1,
            &[
                iface("ns:pkg", "if-a", 1, 0, 0),
                iface("ns:pkg", "if-a", 1, 2, 0),
            ],
        );
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let graph = build(&[a], &[b]);
        assert_eq!(graph.edges().count(), 1);
    }

    #[test]
    fn diamond_resolves_independently() {
        // provider A 提供 if-a 与 if-b；两个 consumer 各自独立解析。
        let a = provider(
            1,
            &[
                iface("ns:pkg", "if-a", 1, 0, 0),
                iface("ns:pkg", "if-b", 2, 0, 0),
            ],
        );
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let c = consumer(3, &[requirement("ns:pkg/if-b@^2.0.0")]);
        let graph = build(&[a], &[b, c]);
        assert_eq!(graph.edges().count(), 2);
        assert_eq!(
            graph
                .resolve(installation(2), &requirement("ns:pkg/if-a@^1.0.0"))
                .map(|edge| edge.provider()),
            Some(provider_id(1))
        );
        assert_eq!(
            graph
                .resolve(installation(3), &requirement("ns:pkg/if-b@^2.0.0"))
                .map(|edge| edge.provider()),
            Some(provider_id(1))
        );
        assert_order_valid(&graph);
    }

    #[test]
    fn shared_provider_serves_multiple_consumers() {
        let a = provider(
            1,
            &[
                iface("ns:pkg", "if-a", 1, 0, 0),
                iface("ns:pkg", "if-b", 1, 0, 0),
            ],
        );
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let c = consumer(3, &[requirement("ns:pkg/if-b@^1.0.0")]);
        let graph = build(&[a], &[b, c]);
        assert_eq!(graph.direct_consumers(provider_id(1)).len(), 2);
        assert_order_valid(&graph);
    }

    // ------------------------------------------------------------------
    // 环检测（cycle detection）
    // ------------------------------------------------------------------

    #[test]
    fn self_loop_is_a_cycle() {
        // provider 导入自己导出的 interface，且唯一解析到自身 → 自环。
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let a_consumer = consumer(1, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let err = ProviderGraph::try_build(&[a], &[a_consumer]);
        assert_eq!(
            err,
            Err(ProviderGraphError::CycleDetected {
                cycle: vec![provider_id(1), provider_id(1)],
            })
        );
    }

    #[test]
    fn two_node_cycle_detected() {
        // A 提供 if-a、消费 if-b；B 提供 if-b、消费 if-a。
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let a_as_consumer = consumer(1, &[requirement("ns:pkg/if-b@^1.0.0")]);
        let b_as_consumer = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let err = ProviderGraph::try_build(&[a, b], &[a_as_consumer, b_as_consumer]);
        match err {
            Err(ProviderGraphError::CycleDetected { cycle }) => {
                // 闭路径：[x, y, x]，相邻对是 depends-on 边。
                assert_eq!(cycle.len(), 3);
                assert_eq!(cycle[0], cycle[2]);
                assert_ne!(cycle[0], cycle[1]);
                assert!(cycle.contains(&provider_id(1)));
                assert!(cycle.contains(&provider_id(2)));
            }
            other => unreachable!("expected CycleDetected, got {other:?}"),
        }
    }

    #[test]
    fn three_node_cycle_detected() {
        // A 提供 if-a 消费 if-c；B 提供 if-b 消费 if-a；C 提供 if-c 消费 if-b。
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let c = provider(3, &[iface("ns:pkg", "if-c", 1, 0, 0)]);
        let a_as_consumer = consumer(1, &[requirement("ns:pkg/if-c@^1.0.0")]);
        let b_as_consumer = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let c_as_consumer = consumer(3, &[requirement("ns:pkg/if-b@^1.0.0")]);
        let err =
            ProviderGraph::try_build(&[a, b, c], &[a_as_consumer, b_as_consumer, c_as_consumer]);
        match err {
            Err(ProviderGraphError::CycleDetected { cycle }) => {
                assert_eq!(cycle.len(), 4);
                assert_eq!(cycle[0], cycle[3]);
                // 相邻对存在 depends-on 边（a 依赖 c、c 依赖 b、b 依赖 a）。
                let adjacency = |from: ProviderId, to: ProviderId| match (from, to) {
                    (x, y) if x == provider_id(1) && y == provider_id(3) => true,
                    (x, y) if x == provider_id(3) && y == provider_id(2) => true,
                    (x, y) if x == provider_id(2) && y == provider_id(1) => true,
                    _ => false,
                };
                for pair in cycle.windows(2) {
                    assert!(
                        adjacency(pair[0], pair[1]),
                        "cycle edge {} -> {} must exist",
                        pair[0],
                        pair[1]
                    );
                }
            }
            other => unreachable!("expected CycleDetected, got {other:?}"),
        }
    }

    #[test]
    fn diamond_chain_is_acyclic() {
        // 菱形：无环，激活顺序合法。
        let root = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let left = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let right = provider(3, &[iface("ns:pkg", "if-c", 1, 0, 0)]);
        let top = provider(4, &[iface("ns:pkg", "if-d", 1, 0, 0)]);
        let left_as_consumer = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let right_as_consumer = consumer(3, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let top_as_consumer = consumer(
            4,
            &[
                requirement("ns:pkg/if-b@^1.0.0"),
                requirement("ns:pkg/if-c@^1.0.0"),
            ],
        );
        let graph = build(
            &[root, left, right, top],
            &[left_as_consumer, right_as_consumer, top_as_consumer],
        );
        assert_eq!(graph.edges().count(), 4);
        assert_order_valid(&graph);
        assert!(graph.topological_order()[0] == installation(1));
    }

    #[test]
    fn cycle_display_is_readable() {
        let err = ProviderGraphError::CycleDetected {
            cycle: vec![provider_id(1), provider_id(2), provider_id(1)],
        };
        let message = err.to_string();
        assert!(message.contains("cycle"));
        assert!(message.contains(&provider_id(1).to_string()));
        assert!(message.contains(&provider_id(2).to_string()));
        assert!(message.contains(" -> "));
    }

    // ------------------------------------------------------------------
    // 激活顺序（topological order）
    // ------------------------------------------------------------------

    #[test]
    fn chain_activation_order_is_dependencies_first() {
        // A 提供 if-a；B 消费 if-a 并提供 if-b；C 消费 if-b。
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let c = consumer(3, &[requirement("ns:pkg/if-b@^1.0.0")]);
        let b_as_consumer = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let graph = build(&[a, b], &[c, b_as_consumer]);
        assert_eq!(
            graph.topological_order(),
            &[installation(1), installation(2), installation(3)]
        );
    }

    #[test]
    fn non_provider_consumer_placed_after_its_providers() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let graph = build(&[a], &[b]);
        assert_eq!(
            graph.topological_order(),
            &[installation(1), installation(2)]
        );
    }

    #[test]
    fn pure_provider_without_consumers_participates_in_order() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let graph = build(&[a], &[]);
        assert_eq!(graph.topological_order(), &[installation(1)]);
    }

    #[test]
    fn empty_inputs_produce_empty_graph() {
        let graph = build(&[], &[]);
        assert_eq!(graph.edges().count(), 0);
        assert!(graph.topological_order().is_empty());
    }

    // ------------------------------------------------------------------
    // 输入校验与查询
    // ------------------------------------------------------------------

    #[test]
    fn duplicate_provider_rejected() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let duplicate = provider(1, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let err = ProviderGraph::try_build(&[a, duplicate], &[]);
        assert_eq!(
            err,
            Err(ProviderGraphError::DuplicateProvider {
                provider: provider_id(1),
            })
        );
    }

    #[test]
    fn duplicate_consumer_rejected() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let duplicate = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let err = ProviderGraph::try_build(&[a], &[b, duplicate]);
        assert_eq!(
            err,
            Err(ProviderGraphError::DuplicateConsumer {
                consumer: installation(2),
            })
        );
    }

    #[test]
    fn empty_provided_set_rejected_at_record_construction() {
        let err = ProviderRecord::new(installation(1), BTreeSet::new());
        assert_eq!(
            err,
            Err(ProviderGraphError::EmptyProvidedSet {
                provider: provider_id(1),
            })
        );
    }

    #[test]
    fn queries_return_sorted_results() {
        // provider 1：if-a；provider 2：if-b，同时作为 consumer 导入 if-a。
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let b_as_consumer = consumer(2, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let c = consumer(3, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let d = consumer(4, &[requirement("ns:pkg/if-b@^1.0.0")]);
        let graph = build(&[b, a], &[d, c, b_as_consumer]);

        // dependencies_of：provider 自身的依赖（其安装实例的导入）。
        assert!(graph.dependencies_of(provider_id(1)).is_empty());
        let deps = graph.dependencies_of(provider_id(2));
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].consumer(), installation(2));
        assert_eq!(deps[0].provider(), provider_id(1));
        // direct_consumers：按 (consumer, requirement) 排序。
        assert_eq!(
            graph
                .direct_consumers(provider_id(1))
                .iter()
                .map(|edge| edge.consumer())
                .collect::<Vec<_>>(),
            vec![installation(2), installation(3)]
        );
        // providers_satisfying：按 ProviderId 排序。
        assert_eq!(
            graph
                .providers_satisfying(&requirement("ns:pkg/if-a@^1.0.0"))
                .iter()
                .map(|node| node.provider())
                .collect::<Vec<_>>(),
            vec![provider_id(1)]
        );
        assert_eq!(
            graph
                .providers_satisfying(&requirement("ns:pkg/if-b@^1.0.0"))
                .iter()
                .map(|node| node.provider())
                .collect::<Vec<_>>(),
            vec![provider_id(2)]
        );
        // 未知 provider 查询为空。
        assert!(graph.dependencies_of(provider_id(99)).is_empty());
        assert!(graph.direct_consumers(provider_id(99)).is_empty());
    }

    #[test]
    fn providers_iteration_sorted_by_provider_id() {
        let a = provider(5, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(3, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let graph = build(&[a, b], &[]);
        let ids: Vec<ProviderId> = graph.providers().map(|node| node.provider()).collect();
        assert_eq!(ids, {
            let mut sorted = vec![provider_id(3), provider_id(5)];
            sorted.sort();
            sorted
        });
    }

    // ------------------------------------------------------------------
    // 确定性（§40.4）
    // ------------------------------------------------------------------

    #[test]
    fn build_is_deterministic_regardless_of_input_order() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-b", 1, 0, 0)]);
        let c = consumer(3, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let d = consumer(4, &[requirement("ns:pkg/if-b@^1.0.0")]);

        let first = build(&[a.clone(), b.clone()], &[c.clone(), d.clone()]);
        let shuffled = build(&[b, a], &[d, c]);
        assert_eq!(first, shuffled);
        assert_eq!(first.topological_order(), shuffled.topological_order());
    }

    #[test]
    fn error_path_is_deterministic() {
        let a = provider(1, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let b = provider(2, &[iface("ns:pkg", "if-a", 1, 0, 0)]);
        let c = consumer(3, &[requirement("ns:pkg/if-a@^1.0.0")]);
        let err1 = ProviderGraph::try_build(&[a.clone(), b.clone()], std::slice::from_ref(&c));
        let err2 = ProviderGraph::try_build(&[b, a], &[c]);
        assert_eq!(err1, err2);
    }

    // ------------------------------------------------------------------
    // proptest：任意图结构
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
            .prop_map(|(interface, v)| iface("ns:pkg", interface, v.major(), v.minor(), v.patch()))
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
            .prop_map(|(interface, req)| requirement(&format!("ns:pkg/{interface}@{req}")))
    }

    /// 任意 component 集合：seed 决定安装实例；每个 component 可选地提供
    /// 若干 interface、导入若干需求（二者皆空则不入图）。
    fn any_components() -> impl Strategy<Value = (Vec<ProviderRecord>, Vec<ConsumerRecord>)> {
        proptest::collection::vec(
            (
                proptest::collection::btree_set(any_interface_id(), 0..=2),
                proptest::collection::btree_set(any_requirement(), 0..=2),
            ),
            0..=5,
        )
        .prop_map(|components| {
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
            (providers, consumers)
        })
    }

    /// 校验 Err(CycleDetected) 的闭路径：相邻对必须存在 depends-on 边。
    fn cycle_edges_are_real(
        providers: &[ProviderRecord],
        consumers: &[ConsumerRecord],
        cycle: &[ProviderId],
    ) -> Result<(), TestCaseError> {
        prop_assert!(cycle.len() >= 2);
        prop_assert_eq!(cycle.first(), cycle.last());
        // 期望邻接（唯一可解析的需求才产生边；CycleDetected 前提是全部需求
        // 唯一解析）。
        for pair in cycle.windows(2) {
            let from = pair[0];
            let to = pair[1];
            let from_installation = InstallationId::from_uuid(from.as_uuid());
            let Some(consumer_record) = consumers
                .iter()
                .find(|record| record.installation() == from_installation)
            else {
                return Err(TestCaseError::fail(format!(
                    "cycle node {from} has no consumer record"
                )));
            };
            let mut resolved_to = Vec::new();
            for requirement in consumer_record.required() {
                let mut candidates = Vec::new();
                for record in providers {
                    if record
                        .provided()
                        .iter()
                        .any(|provided| requirement.satisfied_by(provided))
                    {
                        candidates.push(record.provider_id());
                    }
                }
                if candidates.len() == 1 {
                    resolved_to.push(candidates[0]);
                }
            }
            prop_assert!(
                resolved_to.contains(&to),
                "cycle edge {} -> {} is not a real dependency",
                from,
                to
            );
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn acyclic_graph_properties(
            (providers, consumers) in any_components(),
        ) {
            match ProviderGraph::try_build(&providers, &consumers) {
                Ok(graph) => {
                    // 边数 = 需求总数（构建成功 ⇒ 每条需求都解析）。
                    let expected_edges: usize = consumers
                        .iter()
                        .map(|record| record.required().len())
                        .sum();
                    prop_assert_eq!(graph.edges().count(), expected_edges);
                    // 拓扑顺序覆盖全部参与者且每条边 provider 先于 consumer。
                    let positions: BTreeMap<InstallationId, usize> = graph
                        .topological_order()
                        .iter()
                        .enumerate()
                        .map(|(i, &installation)| (installation, i))
                        .collect();
                    for edge in graph.edges() {
                        let provider_installation =
                            InstallationId::from_uuid(edge.provider().as_uuid());
                        let p = positions.get(&provider_installation);
                        let c = positions.get(&edge.consumer());
                        prop_assert!(p.is_some(), "provider installation missing from order");
                        prop_assert!(c.is_some(), "consumer missing from order");
                        prop_assert!(
                            p < c,
                            "provider {} must activate before consumer {}",
                            provider_installation,
                            edge.consumer()
                        );
                    }
                    // 确定性：输入乱序重构建 → 相同图。
                    let mut rev_p = providers.clone();
                    rev_p.reverse();
                    let mut rev_c = consumers.clone();
                    rev_c.reverse();
                    let rebuilt = ProviderGraph::try_build(&rev_p, &rev_c);
                    prop_assert_eq!(rebuilt, Ok(graph));
                }
                Err(ProviderGraphError::CycleDetected { cycle }) => {
                    cycle_edges_are_real(&providers, &consumers, &cycle)?;
                    // 确定性：相同输入 → 相同错误。
                    let again = ProviderGraph::try_build(&providers, &consumers);
                    prop_assert_eq!(again, Err(ProviderGraphError::CycleDetected { cycle }));
                }
                Err(first_error) => {
                    // 其它解析错误：确定性即可（相同输入 → 相同错误）。
                    match ProviderGraph::try_build(&providers, &consumers) {
                        Ok(_) => prop_assert!(
                            false,
                            "rebuild of a failing input must fail identically"
                        ),
                        Err(second_error) => prop_assert_eq!(first_error, second_error),
                    }
                }
            }
        }
    }
}
