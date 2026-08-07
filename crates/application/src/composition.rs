//! 0.2.0 Capability Composition（§40）application 层：resolution 引擎与编排。
//!
//! # 分层职责
//!
//! - **domain**（已冻结）：契约面类型、`ProviderGraph::try_build`（解析规则
//!   与环检测）、`analyze_upgrade`（provider 升级兼容分析）、激活顺序。
//! - **本模块（application）**：把 domain 的纯结构规则接到用例编排——
//!   §40.3 事实源的输入推导（WIT imports/exports 观察 → records）、
//!   §40.4 provider selection 的确定规则（[`GraphPolicy`]：显式绑定 /
//!   排除，唯一合法解析）、activation/deactivation 编排、graph snapshot
//!   原子切换（§40.2 / §20.3）、provider 升级前的 consumer 兼容分析门控
//!   （§40.2）、records 持久化与恢复（§40.2）。
//!
//! # §40.3 事实源（严格）
//!
//! 依赖关系**只能**来自 WIT imports/exports + Runtime Policy，禁止创建另一份
//! `dependencies.json` 类来源。本模块的输入推导（[`records_from_surface`]）：
//!
//! - exports → [`ProviderRecord`]：只有**可解析为 `package/interface@version`
//!   且 namespace 不是 `wasi:` / `operune:`** 的导出才算 provider 面
//!   （`wasi:` / `operune:` 导出是 Core/Host 消费的接口，不是
//!   Component-to-Component 提供面；本地实例名如 `descriptor` 无 package
//!   身份，同样不算）；再经 Runtime Policy（[`GraphPolicy`]）过滤；
//! - imports → [`ConsumerRecord`]：`wasi:` / `operune:` import 是宿主能力
//!   （0.1 grant 路径，§17.5），**不进图**；其余 import 是 Component-to-
//!   Component 需求，必须可解析为 `InterfaceRequirement`——带版本的 import
//!   按 semver 解析（WIT import 名的具体版本 `x.y.z` 映射为兼容需求
//!   `^x.y.z`，§13.2 兼容规则），不带版本的 import 映射为 `*`（任意版本）；
//!   **无法解析的 import 按 deny-by-default 拒绝激活**（§17.2 / §19.5：
//!   不得"先运行，失败时 trap"代替权限解析）。
//!
//! # §40.4 确定性 provider selection
//!
//! 同一 Component set + 同一 policy 必须得到确定的 provider graph；无法唯一
//! 合法解析时拒绝激活，不得随机选择 provider。规则分层：
//!
//! 1. **policy 是唯一的 provider 选择规则**（§40.2 "provider selection 的
//!    确定规则"在 application 层）：[`GraphPolicy`] 的绑定
//!    `(interface key → provider)` 与排除 `(provider)` 在进入 domain 前
//!    过滤 provider 记录（绑定 = 非绑定 provider 的提供面去掉该 interface；
//!    排除 = 整体出图）；
//! 2. 过滤后交给 domain `try_build`：恰好一个候选 provider → 解析；同一
//!    provider 提供多个兼容版本时取**最高兼容版本**（domain 纯结构规则，
//!    本模块文档化该选择语义：policy 只回答"哪个 provider"，版本选择由
//!    `try_build` 决定）；多个候选 provider → 拒绝
//!    （[`ProviderGraphError::AmbiguousProvider`]）。
//!
//! 全部迭代/排序使用 `BTree*` 与稳定键（§40.4），policy 是 map 不是 list
//! （应用结果与规则声明顺序无关）。
//!
//! # 激活/停用编排（§40.2 activation/deactivation ordering）
//!
//! 每次变更走"构建新 graph → 验证 → 原子切换"：
//!
//! 1. [`CompositionService::check_activation`]：候选图（store records +
//!    新 records → policy → `try_build`）门控——consumer 的激活依赖其
//!    provider **先**出现在持久化 records 中（provider 未激活时 consumer
//!    的 gate 以 [`ProviderGraphError::MissingProvider`] 拒绝，天然强制
//!    activation ordering）；环 / 缺失 provider / 歧义全部 typed 拒绝并带
//!    诊断（§40.2 missing provider diagnostics 向上传）；
//! 2. [`CompositionService::commit_activation`]：audit（fail-closed）→
//!    记录原子替换落盘 → **单指针快照交换**（[`ActiveGraph`]，§20.3
//!    模式复用）——graph 快照从不分步修改；
//! 3. 停用（[`CompositionService::deactivate`]）同样先重建验证：仍有
//!    consumer 依赖的 provider 拒绝停用。
//!
//! 运行时层（runtime-wasm 集成，另一 agent 并行实现）读取
//! [`CompositionService::graph`] 的 `topological_order()` 驱动实例化顺序
//! （provider 先于 consumer；deactivation 逆序）。
//!
//! # Provider 升级门控（§40.2 provider upgrade 前 consumer compatibility
//! analysis）
//!
//! [`CompositionService::analyze_upgrade`] 在当前快照上对既有直接 consumer
//! 做纯分析（domain `analyze_upgrade`）；[`CompositionService::check_upgrade`]
//! 以 `is_safe()` 门控：不安全 → [`ApplicationError::ProviderUpgradeIncompatible`]
//! 携带报告（哪些 consumer、哪些需求、为什么破坏）拒绝升级；安全后仍须过
//! 全量重建门控（升级后的提供面可能吸引新 consumer / 改变其它解析）。
//!
//! # 持久化 / 恢复（§40.2 graph persistence/recovery）
//!
//! [`ProviderGraphPort`](crate::ports::ProviderGraphPort) 持久化 records；
//! 恢复路径永远是 `load_records` → `try_build` 重校验全部不变量（无环、
//! 唯一解析）——图从不被反序列化。policy 是 Runtime Policy 输入（与 grants
//! 同级，由管理面在运行时设置并审计）；policy 本身的持久化归属存储层
//! （与 records 一起事务化），本层只保证"同 records + 同 policy → 同图"。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use operune_domain::{
    ConsumerRecord, DomainError, InstallationId, InterfaceId, InterfaceName, InterfaceRequirement,
    PackageName, ProviderGraph, ProviderId, ProviderRecord, UpgradeCompatibilityReport, ValueKind,
};

use crate::error::ApplicationError;
use crate::model::ContractSurface;
use crate::ports::{AuditEvent, AuditPort, ProviderGraphPort};

/// 宿主消费的 interface namespace 前缀（§17.5 0.1.0 Resolution 边界：
/// WASI / Operune 平台能力由 Core/Host 提供，不构成 Component-to-Component
/// provider 边）。
fn is_host_interface(name: &str) -> bool {
    name.starts_with("wasi:") || name.starts_with("operune:")
}

/// 从二进制 contract surface 推导 graph records（§40.3 事实源，纯函数）。
///
/// - exports：可解析且非宿主 namespace 的导出 → provider 提供面；
/// - imports：非宿主 namespace 的导入 → consumer 需求（带版本 → `^x.y.z`
///   兼容需求；不带版本 → `*`；无法解析 → [`ApplicationError::UnresolvableImport`]
///   拒绝，deny-by-default §17.2 / §19.5）；
/// - 宿主 namespace（`wasi:` / `operune:`）的 import 属于 0.1 grant 路径，
///   不进图。
///
/// 结果按 `InstallationId` 锚定（§17.5）；无参与时为 [`ContractRecords`]
/// 的 `provider` / `consumer` 均为 `None`。
pub fn records_from_surface(
    installation: InstallationId,
    surface: &ContractSurface,
) -> Result<ContractRecords, ApplicationError> {
    // exports → provider 面（§40.3：WIT exports 观察；宿主接口与本地
    // 实例名不构成 Component-to-Component 提供面，跳过）。
    let mut provided = BTreeSet::new();
    for export in &surface.exports {
        if is_host_interface(export) {
            continue;
        }
        // 本地实例名（如 `descriptor`、`assets`）无 package 身份，解析
        // 失败 = 不是 provider 面——跳过而不是拒绝。
        if let Ok(interface) = export.parse::<InterfaceId>() {
            provided.insert(interface);
        }
    }
    let provider = if provided.is_empty() {
        None
    } else {
        Some(
            ProviderRecord::new(installation, provided)
                .map_err(|source| ApplicationError::ProviderGraphResolution { source })?,
        )
    };

    // imports → consumer 需求（§40.3：WIT imports 观察）。
    let mut required = BTreeSet::new();
    for import in &surface.imports {
        if is_host_interface(import) {
            continue;
        }
        required.insert(parse_requirement(import)?);
    }
    let consumer = if required.is_empty() {
        None
    } else {
        Some(ConsumerRecord::new(installation, required))
    };

    Ok(ContractRecords { provider, consumer })
}

/// 解析非宿主 import 为需求：带版本按 semver（`x.y.z` → `^x.y.z`，§13.2
/// 兼容规则）；不带版本映射为 `*`（WIT 未携带 package 版本声明的任意
/// 版本需求）；两者皆不可解析 → deny-by-default 拒绝。
fn parse_requirement(import: &str) -> Result<InterfaceRequirement, ApplicationError> {
    match import.parse::<InterfaceRequirement>() {
        Ok(requirement) => Ok(requirement),
        Err(_) => {
            // `@` 缺失 = 无版本声明。仅在补 `@*` 后可解析（即带完整
            // package/interface 身份）时接受；否则不可解析 → 拒绝。
            let star = format!("{import}@*");
            star.parse::<InterfaceRequirement>()
                .map_err(|_| ApplicationError::UnresolvableImport(import.to_owned()))
        }
    }
}

/// 一个 WIT interface 的 (package, interface) 键（无版本；policy 绑定 /
/// 排除的定位键，§40.4 确定规则的排序键）。
///
/// 字符串形态：`namespace:package/interface`（如 `acme:svc/checkout`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InterfaceKey {
    package: PackageName,
    interface: InterfaceName,
}

impl InterfaceKey {
    /// 从 package / interface 名构造（validate-on-construct 由 domain 类型
    /// 承担）。
    pub fn new(package: PackageName, interface: InterfaceName) -> Self {
        Self { package, interface }
    }

    /// 从 consumer 需求提取键。
    pub fn from_requirement(requirement: &InterfaceRequirement) -> Self {
        Self {
            package: requirement.package().clone(),
            interface: requirement.interface().clone(),
        }
    }

    /// 从 provider 导出提取键。
    pub fn from_interface(interface: &InterfaceId) -> Self {
        Self {
            package: interface.package().clone(),
            interface: interface.interface().clone(),
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
}

impl fmt::Display for InterfaceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.package, self.interface)
    }
}

impl FromStr for InterfaceKey {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('@') {
            return Err(DomainError::InvalidValue {
                kind: ValueKind::PackageName,
                detail: "interface key must be version-free `package/interface`".to_owned(),
            });
        }
        let (package, interface) = s.split_once('/').ok_or_else(|| DomainError::InvalidValue {
            kind: ValueKind::InterfaceId,
            detail: "interface key must be `package/interface`".to_owned(),
        })?;
        let package = PackageName::new(package)?;
        let interface = InterfaceName::new(interface)?;
        Ok(Self { package, interface })
    }
}

/// 0.2.0 provider selection policy 的 typed 错误（§40.2：确定规则，
/// §14.1 封闭 typed error）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GraphPolicyError {
    /// 同一 interface 被绑定到多个 provider（规则冲突，必须显式消除）。
    #[error("interface {interface} is bound to multiple providers ({existing} and {incoming})")]
    DuplicateBinding {
        /// 被重复绑定的 interface。
        interface: InterfaceKey,
        /// 既有绑定。
        existing: ProviderId,
        /// 试图追加的绑定。
        incoming: ProviderId,
    },
    /// 同一 provider 既被绑定又被排除（规则冲突）。
    #[error("provider {provider} is both bound for interface {interface} and excluded")]
    BoundAndExcluded {
        /// 冲突的绑定 interface。
        interface: InterfaceKey,
        /// 冲突的 provider。
        provider: ProviderId,
    },
    /// 绑定指向的 provider 在观察到的 records 中并不提供该 interface
    /// （policy 引用了不存在的 provider 能力；仅在应用（激活）时才可判定）。
    #[error(
        "bound provider {provider} does not provide interface {interface} in the observed records"
    )]
    BindingUnfulfillable {
        /// 绑定的 interface。
        interface: InterfaceKey,
        /// 绑定的 provider。
        provider: ProviderId,
    },
    /// 内部不变量破坏（防御性失败路径，§14.3 fail-stop 经 typed error
    /// 表达）。
    #[error("graph policy internal invariant violated: {0}")]
    Internal(&'static str),
}

/// 0.2.0 provider selection 的确定规则（§40.2 / §40.4，typed）。
///
/// 规则形态（全部按稳定键排序，应用结果与声明顺序无关）：
///
/// - **绑定** `(interface key → provider)`：该 interface 只允许由绑定的
///   provider 提供——应用时把其它 provider 记录中该 interface 从提供面
///   去掉（记录拆分，不影响它们提供的其它 interface）；绑定的 provider
///   必须真实导出该 interface（否则 [`GraphPolicyError::BindingUnfulfillable`]）；
/// - **排除** `(provider)`：该 provider 整体不进入图。
///
/// 版本选择语义（文档化，§40.4）：绑定定位到 provider 后，具体版本仍由
/// domain 纯结构规则决定——同一 provider 提供多个兼容版本时取**最高兼容
/// 版本**（`ProviderGraph::try_build` 语义；policy 只回答"哪个 provider"，
/// 不回答"哪个版本"）。
///
/// 构造即校验规则冲突（§13.4 不合法状态不可表示）：
/// 重复绑定同一 interface / 绑定已被排除的 provider → typed 拒绝。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphPolicy {
    bindings: BTreeMap<InterfaceKey, ProviderId>,
    exclusions: BTreeSet<ProviderId>,
}

impl GraphPolicy {
    /// 空 policy（无规则；任何歧义都交给 domain 拒绝）。
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            exclusions: BTreeSet::new(),
        }
    }

    /// 绑定 interface → provider（重复绑定 / 绑定被排除的 provider →
    /// [`GraphPolicyError`]；同 (interface, provider) 幂等）。
    pub fn bind(
        &mut self,
        interface: InterfaceKey,
        provider: ProviderId,
    ) -> Result<(), GraphPolicyError> {
        if let Some(existing) = self.bindings.get(&interface) {
            if *existing != provider {
                return Err(GraphPolicyError::DuplicateBinding {
                    interface,
                    existing: *existing,
                    incoming: provider,
                });
            }
            return Ok(());
        }
        if self.exclusions.contains(&provider) {
            return Err(GraphPolicyError::BoundAndExcluded {
                interface,
                provider,
            });
        }
        self.bindings.insert(interface, provider);
        Ok(())
    }

    /// 排除 provider（已被绑定 → [`GraphPolicyError::BoundAndExcluded`]）。
    pub fn exclude(&mut self, provider: ProviderId) -> Result<(), GraphPolicyError> {
        let bound = self
            .bindings
            .iter()
            .find_map(|(interface, bound)| (*bound == provider).then_some(interface.clone()));
        if let Some(interface) = bound {
            return Err(GraphPolicyError::BoundAndExcluded {
                interface,
                provider,
            });
        }
        self.exclusions.insert(provider);
        Ok(())
    }

    /// 绑定规则（按 interface 排序）。
    pub fn bindings(&self) -> impl Iterator<Item = (&InterfaceKey, ProviderId)> {
        self.bindings.iter().map(|(key, provider)| (key, *provider))
    }

    /// 排除规则（按 provider 排序）。
    pub fn exclusions(&self) -> impl Iterator<Item = ProviderId> {
        self.exclusions.iter().copied()
    }

    /// 是否没有规则。
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty() && self.exclusions.is_empty()
    }

    /// 应用规则到观察到的 provider records（§40.4：过滤后交给 domain
    /// `try_build`）。顺序无关（map/set 内部），结果确定。
    ///
    /// - 校验：每个绑定的 provider 必须真实提供该 interface；
    /// - 排除的 provider 整体出图；
    /// - 绑定：非绑定 provider 的提供面去掉被绑定 interface（记录拆分）；
    ///   拆分后提供面为空的记录不再是 provider（可能仍是 consumer）。
    pub fn apply(
        &self,
        records: &[ProviderRecord],
    ) -> Result<Vec<ProviderRecord>, GraphPolicyError> {
        for (key, bound) in &self.bindings {
            let provides = records.iter().any(|record| {
                record.provider_id() == *bound
                    && record
                        .provided()
                        .iter()
                        .any(|provided| InterfaceKey::from_interface(provided) == *key)
            });
            if !provides {
                return Err(GraphPolicyError::BindingUnfulfillable {
                    interface: key.clone(),
                    provider: *bound,
                });
            }
        }

        let mut filtered = Vec::new();
        for record in records {
            if self.exclusions.contains(&record.provider_id()) {
                continue;
            }
            let mut provided = record.provided().clone();
            for (key, bound) in &self.bindings {
                if record.provider_id() != *bound {
                    provided.retain(|candidate| InterfaceKey::from_interface(candidate) != *key);
                }
            }
            if provided.is_empty() {
                continue;
            }
            let filtered_record = ProviderRecord::new(record.installation(), provided)
                .map_err(|_| GraphPolicyError::Internal("non-empty provided set must construct"))?;
            filtered.push(filtered_record);
        }
        Ok(filtered)
    }
}

impl Default for GraphPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// 一次 contract surface 观察推导出的 graph 参与记录（§40.3）。
///
/// `provider` / `consumer` 独立存在：同一安装可以同时是 provider 与
/// consumer（依赖链中间节点）；两者皆 `None` = 该组件不参与
/// Component-to-Component graph（无提供面、无图需求）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractRecords {
    provider: Option<ProviderRecord>,
    consumer: Option<ConsumerRecord>,
}

impl ContractRecords {
    /// provider 记录（无提供面为 `None`）。
    pub fn provider(&self) -> Option<&ProviderRecord> {
        self.provider.as_ref()
    }

    /// consumer 记录（无图需求为 `None`）。
    pub fn consumer(&self) -> Option<&ConsumerRecord> {
        self.consumer.as_ref()
    }

    /// 是否不参与图（provider 与 consumer 皆无）。
    pub fn is_empty(&self) -> bool {
        self.provider.is_none() && self.consumer.is_none()
    }

    /// 升级后的提供面（provider 记录缺省为空集——升级移除了全部提供面）。
    pub(crate) fn provided(&self) -> BTreeSet<InterfaceId> {
        match &self.provider {
            Some(record) => record.provided().clone(),
            None => BTreeSet::new(),
        }
    }
}

/// Active provider graph 快照（§40.2 graph snapshot atomic switch / §20.3）：
/// 不可变 [`ProviderGraph`] + arc-swap 单指针交换。读多写少（§15.5）；
/// 切换永远是一次完整快照替换，不存在 provider/consumer 分步不一致的窗口。
pub struct ActiveGraph {
    current: ArcSwap<ProviderGraph>,
}

impl ActiveGraph {
    /// 空图（composition root 注入起点）。初始快照 = 空输入 `try_build`
    /// （无重复记录、无需求、无环，纯函数可证成功；失败是防御性 typed
    /// 错误路径，§12.3）。
    pub fn new() -> Result<Self, ApplicationError> {
        let graph = ProviderGraph::try_build(&[], &[])
            .map_err(|source| ApplicationError::ProviderGraphResolution { source })?;
        Ok(Self {
            current: ArcSwap::from_pointee(graph),
        })
    }

    /// 读当前快照（Arc 语义：读者持有的快照不被后续交换影响，§15.5）。
    pub fn load(&self) -> Arc<ProviderGraph> {
        self.current.load_full()
    }

    /// 原子切换（单指针交换，§20.3；调用方负责先构建并验证新图）。
    pub(crate) fn swap(&self, graph: Arc<ProviderGraph>) {
        self.current.store(graph);
    }
}

/// 0.2.0 Capability Composition 用例服务：graph 构建 / 门控 / 原子切换 /
/// 升级分析与记录持久化（§40.2 / §40.4）。
pub struct CompositionService {
    store: Arc<dyn ProviderGraphPort>,
    active: Arc<ActiveGraph>,
    audit: Arc<dyn AuditPort>,
    policy: Mutex<GraphPolicy>,
}

impl CompositionService {
    /// 构造（注入 records 存储 port、active graph 快照、audit 与初始 policy）。
    pub fn new(
        store: Arc<dyn ProviderGraphPort>,
        active: Arc<ActiveGraph>,
        audit: Arc<dyn AuditPort>,
        policy: GraphPolicy,
    ) -> Self {
        Self {
            store,
            active,
            audit,
            policy: Mutex::new(policy),
        }
    }

    /// 当前 policy（克隆；管理面读）。
    pub fn policy(&self) -> Result<GraphPolicy, ApplicationError> {
        let guard = self
            .policy
            .lock()
            .map_err(|_| ApplicationError::Internal("composition policy lock poisoned"))?;
        Ok(guard.clone())
    }

    /// 更新 policy（§40.2 provider selection 确定规则；audit fail-closed
    /// §18.7）：先用**当前持久化 records** 在新 policy 下重建图——重建失败
    /// （如新 policy 造成歧义 / 缺失 / 绑定不可满足）→ typed 拒绝且**不
    /// 改变任何状态**（policy 未替换、快照未切换）；成功 → audit →
    /// 替换 policy → 原子切换快照。
    pub fn update_policy(
        &self,
        policy: GraphPolicy,
    ) -> Result<Arc<ProviderGraph>, ApplicationError> {
        let records = self
            .store
            .load_records()
            .map_err(ApplicationError::GraphStore)?;
        let filtered = policy
            .apply(&records.providers)
            .map_err(ApplicationError::ProviderGraphPolicy)?;
        let graph = Arc::new(
            ProviderGraph::try_build(&filtered, &records.consumers)
                .map_err(|source| ApplicationError::ProviderGraphResolution { source })?,
        );
        self.audit
            .append(AuditEvent::GraphPolicyUpdated {
                bindings: policy.bindings.len(),
                exclusions: policy.exclusions.len(),
            })
            .map_err(ApplicationError::Audit)?;
        *self
            .policy
            .lock()
            .map_err(|_| ApplicationError::Internal("composition policy lock poisoned"))? = policy;
        self.active.swap(Arc::clone(&graph));
        Ok(graph)
    }

    /// 激活门控（§40.2：consumer 激活依赖 provider 先激活——provider 未
    /// 先激活时以其缺失诊断拒绝）：store records + 新 records → policy →
    /// `try_build`。失败 → typed 拒绝（缺哪个 consumer 的哪个需求 /
    /// 歧义候选 / 环路径，§40.2 missing provider diagnostics 向上传）。
    pub fn check_activation(
        &self,
        installation: InstallationId,
        records: &ContractRecords,
    ) -> Result<(), ApplicationError> {
        let _ = self.build_candidate(installation, records)?;
        Ok(())
    }

    /// provider 升级前的 consumer 兼容分析（§40.2）：当前快照中该安装是
    /// provider 时返回分析报告；不是 provider（纯 consumer 升级）→ `None`
    /// （由全量重建门控覆盖）。
    pub fn analyze_upgrade(
        &self,
        installation: InstallationId,
        records: &ContractRecords,
    ) -> Result<Option<UpgradeCompatibilityReport>, ApplicationError> {
        let provider = ProviderId::from_installation(installation);
        let current = self.active.load();
        if !current.providers().any(|node| node.provider() == provider) {
            return Ok(None);
        }
        let report = current
            .analyze_upgrade(provider, records.provided())
            .map_err(|source| ApplicationError::ProviderGraphResolution { source })?;
        Ok(Some(report))
    }

    /// provider 升级门控（§40.2）：分析报告 `is_safe()` 不成立 → typed
    /// 拒绝并携带影响面（哪些 consumer、哪些需求、interface 移除还是版本
    /// 不兼容）。安全后仍须过 [`CompositionService::check_activation`]
    /// 的全量重建门控。
    pub fn check_upgrade(
        &self,
        installation: InstallationId,
        records: &ContractRecords,
    ) -> Result<(), ApplicationError> {
        if let Some(report) = self.analyze_upgrade(installation, records)?
            && !report.is_safe()
        {
            return Err(ApplicationError::ProviderUpgradeIncompatible {
                installation,
                report,
            });
        }
        Ok(())
    }

    /// 提交激活 / 升级（§40.2 graph snapshot atomic switch）：gate →
    /// audit（fail-closed，§18.7）→ records 原子替换落盘 → **单指针快照
    /// 交换**。返回新快照（运行时层读取 `topological_order()` 驱动实例化
    /// 顺序）。
    ///
    /// 顺序契约（§18.5 crash consistency 边界在存储层事务）：门控失败 /
    /// audit 失败发生在落盘前，不产生任何持久化变化；落盘成功后快照交换
    /// 不可失败（单指针 store）。
    pub fn commit_activation(
        &self,
        installation: InstallationId,
        records: &ContractRecords,
    ) -> Result<Arc<ProviderGraph>, ApplicationError> {
        let candidate = self.build_candidate(installation, records)?;
        self.audit
            .append(AuditEvent::GraphRecordsCommitted { installation })
            .map_err(ApplicationError::Audit)?;
        self.store
            .replace_records(
                installation,
                records.provider.as_ref(),
                records.consumer.as_ref(),
            )
            .map_err(ApplicationError::GraphStore)?;
        self.active.swap(Arc::clone(&candidate));
        Ok(candidate)
    }

    /// 管理性停用（§40.2 deactivation ordering = 激活逆序）：重建图验证
    /// 移除该安装记录后仍唯一合法解析——仍有 consumer 依赖的 provider
    /// 拒绝停用（诊断影响面）；通过 → audit → 记录移除 → 原子切换。
    pub fn deactivate(&self, installation: InstallationId) -> Result<(), ApplicationError> {
        let empty = ContractRecords {
            provider: None,
            consumer: None,
        };
        let candidate = self.build_candidate(installation, &empty)?;
        self.audit
            .append(AuditEvent::GraphRecordsRemoved { installation })
            .map_err(ApplicationError::Audit)?;
        self.store
            .remove_installation(installation)
            .map_err(ApplicationError::GraphStore)?;
        self.active.swap(candidate);
        Ok(())
    }

    /// 当前 active graph 快照。
    pub fn graph(&self) -> Arc<ProviderGraph> {
        self.active.load()
    }

    /// 候选图构建（纯，无副作用）：store records 中 `installation` 的
    /// **旧记录被新 records 整组替换**（升级 = 新提供面/需求面替换旧面，
    /// 不得与新面叠加）→ policy 过滤 → `try_build`。
    fn build_candidate(
        &self,
        installation: InstallationId,
        records: &ContractRecords,
    ) -> Result<Arc<ProviderGraph>, ApplicationError> {
        let stored = self
            .store
            .load_records()
            .map_err(ApplicationError::GraphStore)?;
        let mut providers: Vec<ProviderRecord> = Vec::new();
        let mut consumers: Vec<ConsumerRecord> = Vec::new();
        for record in stored.providers {
            if record.installation() != installation {
                providers.push(record);
            }
        }
        for record in stored.consumers {
            if record.installation() != installation {
                consumers.push(record);
            }
        }
        if let Some(provider) = &records.provider {
            providers.push(provider.clone());
        }
        if let Some(consumer) = &records.consumer {
            consumers.push(consumer.clone());
        }
        let policy = self.policy()?;
        let filtered = policy
            .apply(&providers)
            .map_err(ApplicationError::ProviderGraphPolicy)?;
        let graph = ProviderGraph::try_build(&filtered, &consumers)
            .map_err(|source| ApplicationError::ProviderGraphResolution { source })?;
        Ok(Arc::new(graph))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RuntimeConfig;
    use crate::ports::AuditEvent;
    use crate::runtime::WasmRuntime;
    use crate::test_support::{Harness, ok, some, test_failure};
    use operune_domain::{ComponentVersion, ProviderGraphError};
    use uuid::Uuid;

    /// 确定性安装实例（与 domain 测试同模式：seed → 排序一致的 uuid）。
    fn installation(seed: u64) -> InstallationId {
        InstallationId::from_uuid(Uuid::from_u128(u128::from(seed)))
    }

    fn provider_id(seed: u64) -> ProviderId {
        ProviderId::from_installation(installation(seed))
    }

    fn version(major: u32, minor: u32, patch: u32) -> ComponentVersion {
        ComponentVersion::from_parts(major, minor, patch)
    }

    fn iface(interface: &str, major: u32, minor: u32, patch: u32) -> InterfaceId {
        InterfaceId::new(
            ok(PackageName::new("acme:svc"), "package"),
            ok(InterfaceName::new(interface), "interface"),
            version(major, minor, patch),
        )
    }

    fn requirement(interface: &str, req: &str) -> InterfaceRequirement {
        ok(
            format!("acme:svc/{interface}@{req}").parse::<InterfaceRequirement>(),
            "requirement",
        )
    }

    fn key(interface: &str) -> InterfaceKey {
        ok(
            format!("acme:svc/{interface}").parse::<InterfaceKey>(),
            "interface key",
        )
    }

    fn surface(imports: &[&str], exports: &[&str]) -> ContractSurface {
        ContractSurface {
            imports: imports.iter().map(|s| (*s).to_owned()).collect(),
            exports: exports.iter().map(|s| (*s).to_owned()).collect(),
        }
    }

    /// 直接构造 records（绕过 surface 推导，聚焦图语义测试）。
    fn records(
        seed: u64,
        provided: &[InterfaceId],
        required: &[InterfaceRequirement],
    ) -> ContractRecords {
        let provider = if provided.is_empty() {
            None
        } else {
            Some(ok(
                ProviderRecord::new(installation(seed), provided.iter().cloned().collect()),
                "provider record",
            ))
        };
        let consumer = if required.is_empty() {
            None
        } else {
            Some(ConsumerRecord::new(
                installation(seed),
                required.iter().cloned().collect(),
            ))
        };
        ContractRecords { provider, consumer }
    }

    /// 断言激活顺序满足每条边（provider 先于 consumer）。
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
                None => test_failure("edge provider missing from graph"),
            };
            let consumer_pos = match positions.get(&edge.consumer()) {
                Some(pos) => *pos,
                None => test_failure("consumer missing from order"),
            };
            let provider_pos = match positions.get(&provider_installation) {
                Some(pos) => *pos,
                None => test_failure("provider installation missing from order"),
            };
            assert!(
                provider_pos < consumer_pos,
                "provider must activate before consumer"
            );
        }
    }

    // ------------------------------------------------------------------
    // §40.3 事实源：surface 推导
    // ------------------------------------------------------------------

    #[test]
    fn surface_derives_provider_record_from_non_host_exports() {
        // 只有可解析且非宿主的导出构成 provider 面：descriptor（本地实例
        // 名，无 package）与 operune:web/actions（宿主消费）都跳过。
        let records = ok(
            records_from_surface(
                installation(1),
                &surface(
                    &[],
                    &[
                        "descriptor",
                        "operune:web/actions@0.1.0",
                        "acme:svc/analytics@0.2.0",
                    ],
                ),
            ),
            "derive records",
        );
        let provider = some(records.provider(), "provider record");
        assert_eq!(provider.installation(), installation(1));
        assert_eq!(
            provider.provided(),
            &BTreeSet::from([iface("analytics", 0, 2, 0)])
        );
        assert!(records.consumer().is_none());
    }

    #[test]
    fn surface_derives_consumer_record_from_graph_imports() {
        // wasi: / operune: import 是宿主能力（0.1 grant 路径），不进图；
        // 其余 import 构成需求；import 版本 x.y.z → 兼容需求 ^x.y.z（§13.2）。
        let records = ok(
            records_from_surface(
                installation(1),
                &surface(
                    &[
                        "wasi:cli/run@0.2.0",
                        "operune:web/actions@0.1.0",
                        "acme:svc/checkout@1.0.0",
                    ],
                    &["descriptor"],
                ),
            ),
            "derive records",
        );
        let consumer = some(records.consumer(), "consumer record");
        assert_eq!(
            consumer.required(),
            &BTreeSet::from([requirement("checkout", "^1.0.0")])
        );
        assert!(records.provider().is_none());
    }

    #[test]
    fn host_only_surface_derives_no_records() {
        let records = ok(
            records_from_surface(
                installation(1),
                &surface(&["wasi:cli/run@0.2.0"], &["descriptor"]),
            ),
            "derive records",
        );
        assert!(records.is_empty());
    }

    #[test]
    fn unversioned_graph_import_maps_to_any_version() {
        // WIT 未携带 package 版本声明的 import → `*`（任意版本需求）。
        let records = ok(
            records_from_surface(installation(1), &surface(&["acme:svc/checkout"], &[])),
            "derive records",
        );
        let consumer = some(records.consumer(), "consumer record");
        assert_eq!(
            consumer.required(),
            &BTreeSet::from([requirement("checkout", "*")])
        );
    }

    #[test]
    fn unparseable_import_is_rejected_deny_by_default() {
        // 本地实例名（无 package 身份）无法构成 provider 边 → 拒绝激活
        // （§17.2 / §19.5：不得静默放行未解析 import）。
        let error = match records_from_surface(installation(1), &surface(&["foo"], &[])) {
            Ok(_) => test_failure("unparseable import must be rejected"),
            Err(error) => error,
        };
        assert!(
            matches!(error, ApplicationError::UnresolvableImport(ref name) if name == "foo"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn same_installation_can_be_provider_and_consumer() {
        let records = ok(
            records_from_surface(
                installation(1),
                &surface(&["acme:svc/checkout@1.0.0"], &["acme:svc/analytics@0.2.0"]),
            ),
            "derive records",
        );
        let provider = some(records.provider(), "provider record");
        let consumer = some(records.consumer(), "consumer record");
        assert_eq!(provider.installation(), installation(1));
        assert_eq!(consumer.installation(), installation(1));
        assert!(!records.is_empty());
    }

    // ------------------------------------------------------------------
    // GraphPolicy（§40.2 / §40.4）
    // ------------------------------------------------------------------

    fn provider_record(seed: u64, provided: &[InterfaceId]) -> ProviderRecord {
        ok(
            ProviderRecord::new(installation(seed), provided.iter().cloned().collect()),
            "provider record",
        )
    }

    #[test]
    fn policy_binding_resolves_ambiguity() {
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(2)), "bind policy");
        let providers = vec![
            provider_record(1, &[iface("checkout", 1, 0, 0)]),
            provider_record(2, &[iface("checkout", 1, 0, 0)]),
        ];
        let filtered = ok(policy.apply(&providers), "apply policy");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].provider_id(), provider_id(2));
    }

    #[test]
    fn policy_exclusion_resolves_ambiguity() {
        let mut policy = GraphPolicy::new();
        ok(policy.exclude(provider_id(1)), "exclude policy");
        let providers = vec![
            provider_record(1, &[iface("checkout", 1, 0, 0)]),
            provider_record(2, &[iface("checkout", 1, 0, 0)]),
        ];
        let filtered = ok(policy.apply(&providers), "apply policy");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].provider_id(), provider_id(2));
    }

    #[test]
    fn policy_duplicate_binding_is_rejected() {
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(1)), "first bind");
        let error = match policy.bind(key("checkout"), provider_id(2)) {
            Ok(_) => test_failure("duplicate binding must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            GraphPolicyError::DuplicateBinding {
                interface: key("checkout"),
                existing: provider_id(1),
                incoming: provider_id(2),
            }
        );
        // 幂等重复（同 interface 同 provider）合法。
        ok(
            policy.bind(key("checkout"), provider_id(1)),
            "idempotent bind",
        );
    }

    #[test]
    fn policy_binding_excluded_provider_is_rejected() {
        let mut policy = GraphPolicy::new();
        ok(policy.exclude(provider_id(1)), "exclude");
        let error = match policy.bind(key("checkout"), provider_id(1)) {
            Ok(_) => test_failure("binding an excluded provider must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            GraphPolicyError::BoundAndExcluded {
                interface: key("checkout"),
                provider: provider_id(1),
            }
        );
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(1)), "bind");
        let error = match policy.exclude(provider_id(1)) {
            Ok(_) => test_failure("excluding a bound provider must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            GraphPolicyError::BoundAndExcluded {
                interface: key("checkout"),
                provider: provider_id(1),
            }
        );
    }

    #[test]
    fn policy_binding_to_non_provider_interface_is_rejected_at_apply() {
        let mut policy = GraphPolicy::new();
        ok(
            policy.bind(key("missing"), provider_id(1)),
            "bind unfulfillable",
        );
        let providers = vec![provider_record(1, &[iface("checkout", 1, 0, 0)])];
        let error = match policy.apply(&providers) {
            Ok(_) => test_failure("unfulfillable binding must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            GraphPolicyError::BindingUnfulfillable {
                interface: key("missing"),
                provider: provider_id(1),
            }
        );
    }

    #[test]
    fn policy_splits_records_per_interface() {
        // provider 1 提供 checkout + analytics；checkout 绑定到 provider 2：
        // provider 1 的记录拆分后只保留 analytics（仍可能是 consumer）。
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(2)), "bind");
        let providers = vec![
            provider_record(
                1,
                &[iface("checkout", 1, 0, 0), iface("analytics", 1, 0, 0)],
            ),
            provider_record(2, &[iface("checkout", 1, 0, 0)]),
        ];
        let filtered = ok(policy.apply(&providers), "apply policy");
        let record_1 = filtered
            .iter()
            .find(|record| record.provider_id() == provider_id(1))
            .unwrap_or_else(|| test_failure("provider 1 must survive with analytics"));
        assert_eq!(
            record_1.provided(),
            &BTreeSet::from([iface("analytics", 1, 0, 0)])
        );
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn policy_apply_is_deterministic_regardless_of_input_order() {
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(2)), "bind");
        let forward = vec![
            provider_record(1, &[iface("checkout", 1, 0, 0)]),
            provider_record(2, &[iface("checkout", 1, 0, 0)]),
        ];
        let mut reversed = forward.clone();
        reversed.reverse();
        assert_eq!(
            ok(policy.apply(&forward), "forward"),
            ok(policy.apply(&reversed), "reversed")
        );
    }

    #[test]
    fn interface_key_parse_display_roundtrip() {
        let parsed = ok("acme:svc/checkout".parse::<InterfaceKey>(), "parse key");
        assert_eq!(parsed.to_string(), "acme:svc/checkout");
        assert_eq!(parsed.package().as_str(), "acme:svc");
        assert_eq!(parsed.interface().as_str(), "checkout");
        assert!("acme:svc/checkout@1.0.0".parse::<InterfaceKey>().is_err());
        assert!("checkout".parse::<InterfaceKey>().is_err());
    }

    // ------------------------------------------------------------------
    // CompositionService：构建 / 拒绝 / 快照切换 / 停用 / 升级门控
    // ------------------------------------------------------------------

    fn service_harness() -> Harness {
        Harness::with_composition(RuntimeConfig::default())
    }

    fn composition(harness: &Harness) -> &CompositionService {
        match &harness.composition {
            Some(composition) => composition,
            None => test_failure("composition harness is not wired"),
        }
    }

    #[test]
    fn commit_activation_persists_records_and_swaps_snapshot() {
        let harness = service_harness();
        let records = records(1, &[iface("checkout", 1, 0, 0)], &[]);
        let graph = ok(
            composition(&harness).commit_activation(installation(1), &records),
            "commit activation",
        );
        assert!(
            graph
                .providers()
                .any(|node| node.provider() == provider_id(1))
        );
        // 快照已切换（graph() 即新图；ActiveGraph 底层同一快照）。
        assert!(
            composition(&harness)
                .graph()
                .providers()
                .any(|node| node.provider() == provider_id(1))
        );
        assert!(
            harness
                .active_graph
                .load()
                .providers()
                .any(|node| node.provider() == provider_id(1))
        );
        // 记录已持久化。
        let stored = some(
            harness.graph_store.provider(installation(1)),
            "stored record",
        );
        assert_eq!(stored.provider_id(), provider_id(1));
        // audit 事件（fail-closed 写入）。
        assert!(harness.audit.contains(|event| matches!(
            event,
            AuditEvent::GraphRecordsCommitted { installation: id }
                if *id == installation(1)
        )));
    }

    #[test]
    fn consumer_activation_requires_provider_activated_first() {
        // §40.2 activation ordering：provider 未先激活时 consumer 的激活
        // 被缺失诊断拒绝，且不产生任何持久化 / 快照变化。
        let harness = service_harness();
        let consumer = records(2, &[], &[requirement("checkout", "^1.0.0")]);
        let error = match composition(&harness).check_activation(installation(2), &consumer) {
            Ok(_) => test_failure("consumer without provider must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderGraphResolution { source } => {
                assert_eq!(
                    source,
                    ProviderGraphError::MissingProvider {
                        consumer: installation(2),
                        requirement: Box::new(requirement("checkout", "^1.0.0")),
                    }
                );
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 未提交：无记录、快照为空。
        assert_eq!(harness.graph_store.count(), 0);
        assert!(harness.graph_store.consumer(installation(2)).is_none());
        assert_eq!(composition(&harness).graph().providers().count(), 0);
        // commit 同样被拒绝（gate 在落盘前）。
        let error = match composition(&harness).commit_activation(installation(2), &consumer) {
            Ok(_) => test_failure("commit without provider must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplicationError::ProviderGraphResolution { .. }
        ));
        assert_eq!(harness.graph_store.count(), 0);
        assert!(harness.graph_store.consumer(installation(2)).is_none());
    }

    #[test]
    fn provider_then_consumer_chain_activates_in_order() {
        // 链：P1 提供 if-a；P2 消费 if-a 并提供 if-b；C 消费 if-b。
        let harness = service_harness();
        ok(
            composition(&harness)
                .commit_activation(installation(1), &records(1, &[iface("if-a", 1, 0, 0)], &[])),
            "activate provider 1",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(
                    2,
                    &[iface("if-b", 1, 0, 0)],
                    &[requirement("if-a", "^1.0.0")],
                ),
            ),
            "activate provider 2",
        );
        ok(
            composition(&harness).commit_activation(
                installation(3),
                &records(3, &[], &[requirement("if-b", "^1.0.0")]),
            ),
            "activate consumer 3",
        );
        let graph = composition(&harness).graph();
        // §40.2 activation ordering：provider 先于 consumer。
        assert_eq!(
            graph.topological_order(),
            &[installation(1), installation(2), installation(3)]
        );
        assert_order_valid(&graph);
    }

    #[test]
    fn ambiguous_provider_rejected_without_policy_and_resolved_with_policy() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider 1",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider 2",
        );
        // 无 policy：歧义 → 拒绝激活（§40.4：不得随机选择）。
        let consumer = records(3, &[], &[requirement("checkout", "^1.0.0")]);
        let error = match composition(&harness).check_activation(installation(3), &consumer) {
            Ok(_) => test_failure("ambiguity must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderGraphResolution { source } => {
                assert!(matches!(
                    source,
                    ProviderGraphError::AmbiguousProvider { .. }
                ));
                // 诊断含候选（按 ProviderId 排序）。
                let message = source.to_string();
                assert!(message.contains(&provider_id(1).to_string()));
                assert!(message.contains(&provider_id(2).to_string()));
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 显式 policy 绑定 → 唯一解析；consumer 提交后快照含解析边。
        let mut policy = GraphPolicy::new();
        ok(policy.bind(key("checkout"), provider_id(2)), "bind");
        ok(composition(&harness).update_policy(policy), "update policy");
        ok(
            composition(&harness).check_activation(installation(3), &consumer),
            "activation with policy must pass",
        );
        let graph = ok(
            composition(&harness).commit_activation(installation(3), &consumer),
            "commit consumer with policy",
        );
        let edge = some(
            graph.resolve(installation(3), &requirement("checkout", "^1.0.0")),
            "resolved edge",
        );
        assert_eq!(edge.provider(), provider_id(2));
    }

    #[test]
    fn cycle_between_providers_is_rejected() {
        let harness = service_harness();
        ok(
            composition(&harness)
                .commit_activation(installation(1), &records(1, &[iface("if-a", 1, 0, 0)], &[])),
            "activate provider 1",
        );
        // P2 提供 if-b、消费 if-a。
        let p2 = records(
            2,
            &[iface("if-b", 1, 0, 0)],
            &[requirement("if-a", "^1.0.0")],
        );
        ok(
            composition(&harness).commit_activation(installation(2), &p2),
            "activate provider 2",
        );
        // P1 升级为消费 if-b → 与 P2 形成环 → 拒绝（§40.2 cycle detection）。
        let p1_cyclic = records(
            1,
            &[iface("if-a", 1, 0, 0)],
            &[requirement("if-b", "^1.0.0")],
        );
        let error = match composition(&harness).commit_activation(installation(1), &p1_cyclic) {
            Ok(_) => test_failure("cycle must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderGraphResolution { source } => {
                assert!(matches!(source, ProviderGraphError::CycleDetected { .. }));
                // 诊断含环路径。
                let message = source.to_string();
                assert!(message.contains(&provider_id(1).to_string()));
                assert!(message.contains(&provider_id(2).to_string()));
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 失败的升级未落盘、未切换：旧图（无环）仍是 active。
        assert_eq!(composition(&harness).graph().edges().count(), 1);
    }

    #[test]
    fn highest_compatible_version_is_selected_within_provider() {
        // §40.4 / 版本选择文档化语义：同一 provider 提供多个兼容版本 →
        // 取最高兼容版本（domain 纯结构规则）。
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(
                    1,
                    &[iface("checkout", 1, 0, 0), iface("checkout", 1, 3, 0)],
                    &[],
                ),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        let graph = composition(&harness).graph();
        let edge = some(
            graph.resolve(installation(2), &requirement("checkout", "^1.0.0")),
            "resolved edge",
        );
        assert_eq!(edge.provided(), &iface("checkout", 1, 3, 0));
    }

    #[test]
    fn deactivation_of_provider_with_consumers_is_rejected() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        let error = match composition(&harness).deactivate(installation(1)) {
            Ok(_) => test_failure("deactivating a provider with consumers must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderGraphResolution { source } => {
                assert!(matches!(source, ProviderGraphError::MissingProvider { .. }));
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 快照未变：provider 仍在图、记录仍在。
        assert!(
            composition(&harness)
                .graph()
                .providers()
                .any(|node| node.provider() == provider_id(1))
        );
    }

    #[test]
    fn deactivation_removes_records_and_swaps_snapshot() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).deactivate(installation(1)),
            "deactivate",
        );
        assert_eq!(harness.graph_store.count(), 0);
        assert_eq!(composition(&harness).graph().providers().count(), 0);
        assert!(harness.audit.contains(|event| matches!(
            event,
            AuditEvent::GraphRecordsRemoved { installation: id }
                if *id == installation(1)
        )));
    }

    // ------------------------------------------------------------------
    // Provider 升级门控（§40.2）
    // ------------------------------------------------------------------

    #[test]
    fn safe_provider_upgrade_is_allowed_and_swaps() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        // 升到 1.2.0：直接 consumer（^1.0.0）仍满足 → 安全。
        let upgrade = records(1, &[iface("checkout", 1, 2, 0)], &[]);
        let report = some(
            ok(
                composition(&harness).analyze_upgrade(installation(1), &upgrade),
                "upgrade analysis",
            ),
            "report",
        );
        assert!(report.is_safe());
        ok(
            composition(&harness).check_upgrade(installation(1), &upgrade),
            "upgrade gate",
        );
        let graph = ok(
            composition(&harness).commit_activation(installation(1), &upgrade),
            "commit upgrade",
        );
        let edge = some(
            graph.resolve(installation(2), &requirement("checkout", "^1.0.0")),
            "resolved edge",
        );
        assert_eq!(edge.provided(), &iface("checkout", 1, 2, 0));
    }

    #[test]
    fn breaking_provider_upgrade_is_rejected_with_impact_report() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        // 升级移除了 checkout interface → 直接 consumer 破坏。
        let upgrade = records(1, &[iface("analytics", 1, 0, 0)], &[]);
        let error = match composition(&harness).check_upgrade(installation(1), &upgrade) {
            Ok(_) => test_failure("breaking upgrade must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderUpgradeIncompatible {
                installation: upgraded,
                report,
            } => {
                assert_eq!(upgraded, installation(1));
                assert!(!report.is_safe());
                // 影响面：哪个 consumer、哪个需求。
                assert_eq!(report.impacts().len(), 1);
                let impact = &report.impacts()[0];
                assert_eq!(impact.consumer(), installation(2));
                assert_eq!(impact.requirement(), &requirement("checkout", "^1.0.0"));
                assert!(!impact.result().is_compatible());
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 快照未切换（v1 仍在服务）。
        let graph = composition(&harness).graph();
        let edge = some(
            graph.resolve(installation(2), &requirement("checkout", "^1.0.0")),
            "v1 edge",
        );
        assert_eq!(edge.provided(), &iface("checkout", 1, 0, 0));
    }

    #[test]
    fn major_version_bump_upgrade_is_rejected_with_reason() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        // 升到 2.0.0（major 破坏性）→ 版本不兼容诊断。
        let upgrade = records(1, &[iface("checkout", 2, 0, 0)], &[]);
        let error = match composition(&harness).check_upgrade(installation(1), &upgrade) {
            Ok(_) => test_failure("breaking upgrade must be rejected"),
            Err(error) => error,
        };
        match &error {
            ApplicationError::ProviderUpgradeIncompatible { report, .. } => {
                assert!(!report.is_safe());
                // 影响面含 consumer 与需求（diagnostics 向上传）。
                let message = format!("{report:?}");
                assert!(message.contains(&installation(2).to_string()));
                assert!(message.contains("^1.0.0"));
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        let message = error.to_string();
        assert!(message.contains(&installation(2).to_string()));
    }

    #[test]
    fn consumer_upgrade_with_unresolvable_imports_is_rejected() {
        // 纯 consumer（非 provider）升级：analyze 为 None，由全量重建门控
        // 拒绝新增的不可解析需求。
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        let upgrade = records(2, &[], &[requirement("analytics", "^1.0.0")]);
        assert!(
            ok(
                composition(&harness).analyze_upgrade(installation(2), &upgrade),
                "analyze non-provider"
            )
            .is_none()
        );
        let error = match composition(&harness).check_activation(installation(2), &upgrade) {
            Ok(_) => test_failure("upgrade with missing provider must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplicationError::ProviderGraphResolution { .. }
        ));
    }

    // ------------------------------------------------------------------
    // 快照切换与持久化 / 恢复（§40.2 graph snapshot / persistence）
    // ------------------------------------------------------------------

    #[test]
    fn snapshot_switch_is_single_pointer_exchange() {
        // 每次 commit 后 load 都返回完整的新快照；旧快照 Arc 保持有效
        // （不可变快照语义，§15.5 / §20.3）。
        let harness = service_harness();
        let first = ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "first commit",
        );
        let second = ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "second commit",
        );
        assert_eq!(second.edges().count(), 1);
        assert_eq!(first.edges().count(), 0);
        assert_eq!(composition(&harness).graph().edges().count(), 1);
    }

    #[test]
    fn records_roundtrip_and_recovery_rebuilds_identical_graph() {
        // §40.2 graph persistence/recovery：持久化 records，恢复时重新
        // try_build → 相同图（不变量重校验）。
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[], &[requirement("checkout", "^1.0.0")]),
            ),
            "activate consumer",
        );
        let original = composition(&harness).graph();
        // 从 store 读回 records（模拟恢复输入）。
        let stored = ok(harness.graph_store.load_records(), "load records");
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(stored.consumers.len(), 1);
        let rebuilt = ok(
            ProviderGraph::try_build(&stored.providers, &stored.consumers),
            "recovery rebuild",
        );
        assert_eq!(&rebuilt, original.as_ref());
    }

    #[test]
    fn upgrade_replaces_records_instead_of_merging() {
        // 升级 = 新提供面整组替换旧提供面（不得与新面叠加）。
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate v1",
        );
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 1, 0)], &[]),
            ),
            "upgrade v1.1",
        );
        let stored = some(
            harness.graph_store.provider(installation(1)),
            "stored record",
        );
        assert_eq!(
            stored.provided(),
            &BTreeSet::from([iface("checkout", 1, 1, 0)])
        );
    }

    #[test]
    fn update_policy_revalidates_graph_and_is_atomic() {
        let harness = service_harness();
        ok(
            composition(&harness).commit_activation(
                installation(1),
                &records(1, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider 1",
        );
        ok(
            composition(&harness).commit_activation(
                installation(2),
                &records(2, &[iface("checkout", 1, 0, 0)], &[]),
            ),
            "activate provider 2",
        );
        // 绑定 provider 1 → policy 更新成功且快照切换。
        let mut bound = GraphPolicy::new();
        ok(bound.bind(key("checkout"), provider_id(1)), "bind");
        ok(composition(&harness).update_policy(bound), "update policy");
        assert!(
            harness.audit.contains(|event| matches!(
                event,
                AuditEvent::GraphPolicyUpdated { bindings: 1, .. }
            ))
        );
        // 消费者提交（绑定 policy 下唯一解析）。
        let consumer = records(3, &[], &[requirement("checkout", "^1.0.0")]);
        ok(
            composition(&harness).commit_activation(installation(3), &consumer),
            "commit consumer under bound policy",
        );
        // 移除绑定（policy 回到空）→ 当前 records（两 provider + consumer）
        // 在空 policy 下歧义 → 拒绝且状态不变（policy 未替换、快照未切换）。
        let error = match composition(&harness).update_policy(GraphPolicy::new()) {
            Ok(_) => test_failure("ambiguous policy must be rejected"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplicationError::ProviderGraphResolution { .. }
        ));
        // 状态不变：policy 仍带绑定；快照仍是绑定 policy 下的图（provider 2
        // 的唯一 interface 被绑定走 → 不再是 provider，图中只有 provider 1）。
        assert_eq!(
            ok(composition(&harness).policy(), "read policy")
                .bindings()
                .count(),
            1
        );
        assert_eq!(composition(&harness).graph().providers().count(), 1);
        assert_eq!(
            composition(&harness).graph().edges().count(),
            1,
            "consumer edge resolved under the bound policy stays active"
        );
    }

    // ------------------------------------------------------------------
    // §40.4 确定性
    // ------------------------------------------------------------------

    #[test]
    fn same_inputs_in_different_activation_order_produce_identical_graphs() {
        // 两个独立 harness，同一组件集以不同的合法激活顺序 commit
        // （§40.2：provider 必须先于 consumer，两种顺序都满足）→ 相同
        // 最终图（§40.4 确定性：同一 Component set + 同一 policy → 同一
        // provider graph）。
        let first = service_harness();
        let second = service_harness();
        let order_a = [
            records(1, &[iface("if-a", 1, 0, 0)], &[]),
            records(2, &[iface("if-b", 1, 0, 0)], &[]),
            records(
                3,
                &[],
                &[requirement("if-a", "^1.0.0"), requirement("if-b", "^1.0.0")],
            ),
        ];
        let order_b = [
            records(2, &[iface("if-b", 1, 0, 0)], &[]),
            records(1, &[iface("if-a", 1, 0, 0)], &[]),
            records(
                3,
                &[],
                &[requirement("if-b", "^1.0.0"), requirement("if-a", "^1.0.0")],
            ),
        ];
        for (harness, order) in [(&first, &order_a[..]), (&second, &order_b[..])] {
            for records in order {
                let installation = records
                    .provider()
                    .map(|record| record.installation())
                    .or_else(|| records.consumer().map(|record| record.installation()))
                    .unwrap_or_else(|| test_failure("records must have an installation"));
                ok(
                    composition(harness).commit_activation(installation, records),
                    "commit",
                );
            }
        }
        assert_eq!(composition(&first).graph(), composition(&second).graph());
        assert_eq!(
            composition(&first).graph().topological_order(),
            composition(&second).graph().topological_order()
        );
    }

    // ------------------------------------------------------------------
    // surface 推导 + 图构建端到端（fake 观察）
    // ------------------------------------------------------------------

    #[test]
    fn derived_records_build_resolvable_graph_end_to_end() {
        let harness = service_harness();
        // provider 组件：导出 acme:svc/checkout@1.0.0。
        let provider_surface = surface(
            &["wasi:cli/run@0.2.0"],
            &["descriptor", "acme:svc/checkout@1.0.0"],
        );
        let provider_records = ok(
            records_from_surface(installation(1), &provider_surface),
            "derive provider",
        );
        assert!(!provider_records.is_empty());
        ok(
            composition(&harness).commit_activation(installation(1), &provider_records),
            "activate provider",
        );
        // consumer 组件：导入 acme:svc/checkout@1.0.0（宿主 import 不进图）。
        let consumer_surface = surface(
            &["wasi:cli/run@0.2.0", "acme:svc/checkout@1.0.0"],
            &["descriptor"],
        );
        let consumer_records = ok(
            records_from_surface(installation(2), &consumer_surface),
            "derive consumer",
        );
        ok(
            composition(&harness).commit_activation(installation(2), &consumer_records),
            "activate consumer",
        );
        let graph = composition(&harness).graph();
        let edge = some(
            graph.resolve(installation(2), &requirement("checkout", "^1.0.0")),
            "resolved edge",
        );
        assert_eq!(edge.provider(), provider_id(1));
        assert_eq!(edge.provided(), &iface("checkout", 1, 0, 0));
        assert_order_valid(&graph);
    }

    // ------------------------------------------------------------------
    // 真实 wasmtime contract surface 观察（§40.3 事实源）
    //
    // 评估结论：application 现有 `WasmtimeRuntime::contract_surface` 观察
    // API 可直接复用（真实编译 Component 后读取二进制 imports/exports），
    // 无需 fake——以下测试用真实 wasmtime + wat 文本构造 Component，
    // 验证记录推导对真实名称形态（`ns:pkg/iface@x.y.z`）成立。
    // ------------------------------------------------------------------

    /// 真实 wasmtime 测试环境（与 runtime.rs 测试同模式）。
    fn real_runtime() -> Arc<crate::runtime::WasmtimeRuntime> {
        let engine = Arc::new(ok(
            operune_runtime_wasm::EngineHandle::new(operune_runtime_wasm::EngineConfig::default()),
            "engine creation",
        ));
        let config = Arc::new(crate::test_support::FakeConfig::new(
            RuntimeConfig::default(),
        ));
        Arc::new(crate::runtime::WasmtimeRuntime::new(engine, config))
    }

    /// 提供 acme:svc/checkout@1.0.0 与 acme:svc/analytics@0.2.0 的真实
    /// Component（wat）：标准 canon lift 模式（core func → 组件 func →
    /// 实例成员）。surface 观察只关心实例名（§40.3 事实源）；成员签名
    /// 是 primitive（复杂 WIT 形状属于 §30 conformance）。
    fn real_provider_wat() -> &'static str {
        r#"(component
            (core module $m
                (func (export "checkout") (result i64) i64.const 7)
                (func (export "track"))
                (memory (export "memory") 1)
            )
            (core instance $i (instantiate $m))
            (func $checkout (result u64) (canon lift (core func $i "checkout")))
            (func $track (canon lift (core func $i "track")))
            (instance $checkout_instance (export "checkout" (func $checkout)))
            (instance $analytics_instance (export "track" (func $track)))
            (export "acme:svc/checkout@1.0.0" (instance $checkout_instance))
            (export "acme:svc/analytics@0.2.0" (instance $analytics_instance))
        )"#
    }

    /// 导入 acme:svc/checkout@1.0.0 的真实 Component（wat；import 侧与
    /// runtime.rs 夹具同模式，primitive 签名可直接文本表达）。
    fn real_consumer_wat() -> &'static str {
        r#"(component
            (import "acme:svc/checkout@1.0.0" (instance $checkout
                (export "checkout" (func (result u64)))
            ))
            (core module $m (memory (export "memory") 1))
            (core instance $i (instantiate $m))
        )"#
    }

    #[test]
    fn real_wasmtime_surface_observation_derives_records() {
        // §40.3：依赖关系来自二进制真实可观察的 contract surface。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(real_provider_wat().as_bytes()),
            "compile wat component",
        );
        let surface = ok(runtime.contract_surface(&component), "contract surface");
        let records = ok(
            records_from_surface(installation(1), &surface),
            "derive records from real surface",
        );
        let provider = some(records.provider(), "provider record");
        assert!(provider.provided().contains(&iface("analytics", 0, 2, 0)));
        assert!(provider.provided().contains(&iface("checkout", 1, 0, 0)));
    }

    #[test]
    fn real_wasmtime_consumer_surface_derives_requirement() {
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(real_consumer_wat().as_bytes()),
            "compile wat component",
        );
        let surface = ok(runtime.contract_surface(&component), "contract surface");
        let records = ok(
            records_from_surface(installation(2), &surface),
            "derive records from real surface",
        );
        let consumer = some(records.consumer(), "consumer record");
        // 真实 import 名 `acme:svc/checkout@1.0.0` → 兼容需求 ^1.0.0（§13.2）。
        assert!(
            consumer
                .required()
                .contains(&requirement("checkout", "^1.0.0"))
        );
    }

    #[test]
    fn real_wasmtime_components_form_resolvable_graph() {
        // 端到端：真实观察 → 推导 → try_build 解析出 provider/consumer 边。
        let runtime = real_runtime();
        let provider_component = ok(
            runtime.compile(real_provider_wat().as_bytes()),
            "compile provider",
        );
        let consumer_component = ok(
            runtime.compile(real_consumer_wat().as_bytes()),
            "compile consumer",
        );
        let provider_surface = ok(
            runtime.contract_surface(&provider_component),
            "provider surface",
        );
        let consumer_surface = ok(
            runtime.contract_surface(&consumer_component),
            "consumer surface",
        );
        let provider_records = ok(
            records_from_surface(installation(1), &provider_surface),
            "derive provider",
        );
        let consumer_records = ok(
            records_from_surface(installation(2), &consumer_surface),
            "derive consumer",
        );
        let mut providers = Vec::new();
        let mut consumers = Vec::new();
        if let Some(record) = &provider_records.provider {
            providers.push(record.clone());
        }
        if let Some(record) = &consumer_records.consumer {
            consumers.push(record.clone());
        }
        let graph = ok(
            ProviderGraph::try_build(&providers, &consumers),
            "build graph from real observations",
        );
        let edge = some(
            graph.resolve(installation(2), &requirement("checkout", "^1.0.0")),
            "resolved edge",
        );
        assert_eq!(edge.provider(), provider_id(1));
        assert_eq!(edge.provided(), &iface("checkout", 1, 0, 0));
        assert_order_valid(&graph);
    }
}
