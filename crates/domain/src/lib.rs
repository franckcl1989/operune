#![forbid(unsafe_code)]

//! Operune Core Domain（规范 §24.2：domain）。
//!
//! 纯领域类型、状态机、不变量、兼容规则。
//! 禁止 Wasmtime / Tokio / Axum / rusqlite（§24.2、§24.3 依赖方向：domain
//! 永不反向依赖 adapter；Domain/Application 不得出现面向 `x86_64` /
//! `aarch64` 或具体设备厂商的条件分支）。
//!
//! # 0.1.0 公开面（§39.2 MUST scope 中的 domain 部分）
//!
//! - 四种身份（§19.4，必须永久分离，彼此类型不同且不存在相互转换）：
//!   - [`ComponentId`]：作者声明的逻辑产品/应用身份（与 WIT
//!     `operune:component@0.1.0` 的 `component-id` 契约对齐）；
//!   - [`ComponentVersion`]：作者声明的发布版本（与 WIT `component-version`
//!     契约对齐：major/minor/patch 三段 u32）；
//!   - [`ContentDigest`]：实际收到的原始字节的不可变内容事实（固定长度
//!     SHA-256，不是任意 `Vec<u8>`，§13.2）；
//!   - [`InstallationId`]：Core 创建并持久化的安装实例身份（§19.4，承载
//!     grant / enable / active 状态与本机生命周期）。
//! - 平台能力身份（§17）：[`CapabilityId`]。
//! - 生命周期状态机（§12.2 / §19）：[`ComponentLifecycleState`] 与
//!   [`ComponentLifecycleEvent`]，闭集 enum + 显式转换校验，非法转换返回
//!   typed error，绝不静默忽略。
//! - 资源语义类型（§13.1 / §13.2）：[`ByteSize`]（字节数量）、[`Duration`]
//!   （非负时间间隔）、[`Deadline`]（单调时钟绝对截止时间）、[`ArtifactPath`]
//!   （受校验的制品相对路径，§18.7 / §21.3）。
//! - 封闭 typed error（§14.1）：[`DomainError`]，禁止 anyhow / eyre /
//!   `Box<dyn Error>` / String error。
//!
//! # 0.3.0 公开面（§41 Stateful Runtime 中的 domain 部分）
//!
//! 契约面 = `operune:state|config|secret|scheduler|event@0.1.0`（已提交
//! 稳定；类型语义与 WIT 契约严格对齐，§41.2）：
//! - State（typed Component state service，§41.2 MUST）：
//!   [`StateKey`]（`state-key`，字符集 `[A-Za-z0-9._-/]`，安装实例私有
//!   命名空间，§19.4）、[`StateValue`]（`state-value`，有界字节，平台
//!   不透明，P6）、[`StateSchemaVersion`]（`state-schema-version`，u32，
//!   显式 migration 的版本面，§20.5）、[`StateTransactionId`]（Core 侧
//!   事务标识，§18.5 / §41.2 audit；非 WIT 类型）；
//! - Config（Component config storage/validation，§41.2 MUST）：
//!   [`ConfigRevision`]（`config-version.revision`，快照修订号）、
//!   [`ConfigFormat`]（`config-format` 闭集：json/toml/raw）、
//!   [`ConfigSchemaVersion`]（`config-schema-version`）、
//!   [`ConfigValue`] / [`ConfigSnapshot`]（`config-value` / `config-snapshot`
//!   原子快照；只读语义——Config 是输入，guest 只读，§41.2）；
//! - Secret（SecretStore port，§41.2 MUST / §16.6）：[`SecretName`]
//!   （`secret-name`，grant scope 的键，§17.3）、[`SecretVersion`]
//!   （`secret-version`，轮换检测）、[`SecretMetadata`]（`secret-metadata`，
//!   非敏感元数据，**不含值**，§16.6 防泄漏）；
//! - Scheduler（§41.2 MUST）：[`UtcInstant`]（`datetime`，UTC 硬时刻，
//!   §13.2 OffsetDateTime 语义）、[`ScheduleTrigger`]（`schedule-trigger`
//!   闭集：one-shot / periodic）、[`ScheduledTaskId`]（`scheduled-task-id`）、
//!   [`TaskState`] / [`TaskStatus`]（`task-state` / `task-status` 闭集）、
//!   [`TriggerPayload`]（`trigger-payload`：task-id/sequence/scheduled-at/
//!   missed-fires）；
//! - Event（event bus，§41.2 MUST / §17.3）：[`EventTopic`]（`topic`，grant
//!   scope 的键）、[`EventId`]（`event-id`，审计关联）、[`EventPayload`]
//!   （`event-payload` 闭集：json/raw 有界形态，§22.4 禁止万能动态值）。
//!
//! # 0.4.0 公开面（§42 Web Application Runtime 中的 domain 部分）
//!
//! 契约面 = `operune:web@0.2.0`（app-descriptor / navigation / routes /
//! permissions / route-dispatch，已提交稳定；类型语义与 WIT 契约严格对齐，
//! §42.2）：
//! - 页面（navigation）：[`PageId`]（`page-id`）、[`PagePath`]（`page-path`，
//!   挂载命名空间下的静态路径）、[`PageDeclaration`]（`page-declaration`）；
//! - 权限（permissions）：[`PermissionName`]（`permission-name`）、
//!   [`PermissionDeclaration`]（`permission-declaration`）；
//! - 路由（routes）：[`RouteId`]（`route-id`）、[`HttpMethod`]（`http-method`
//!   闭集：get/post/put/patch/delete）、[`PathTemplate`]（`path-template`，
//!   "{name}" 段模板）、[`PathSegment`]（模板段：字面 / 参数）、[`ParamType`]
//!   （`param-type` 闭集）、[`RouteParam`]（`route-param`）、[`RouteDeclaration`]
//!   （`route-declaration`，构造校验模板与参数一致）、[`PathConflict`]（同
//!   method 下模板冲突的纯逻辑判定）、[`PathConflictParty`]（冲突当事方：
//!   route / page）；
//! - 运行期参数（route-dispatch）：[`ParamValue`]（`param-value` 闭集，与
//!   `param-type` 一一对应，构造校验值域）、[`TypedParam`]（`typed-param`）；
//! - app 声明（app-descriptor）：[`AssetPath`]（`asset-path`，入口资产路径）、
//!   [`AppFeatures`]（`app-features` flags 闭集）、[`AppDeclaration`]
//!   （`app-descriptor`，组装期冲突诊断）；
//! - 声明期冲突诊断（app-descriptor-error 闭集）：[`WebDeclarationError`]
//!   （route-id / page-id 重复、路径冲突、非法路径模板、参数不一致、非法
//!   权限引用、非法默认页）。
//!
//! # 0.5.0 公开面（§43 Security & Governance 中的 domain 部分）
//!
//! 契约语义与 §43 对齐（无独立 WIT 契约——平台级 RBAC / 策略 / 配额 /
//! 审计是 Core 内部治理面，§5.1；对外暴露经 Root Admin Web 与
//! `operune:web` 权限声明，§42）：
//! - RBAC（§43.2 complete RBAC roles/groups；§5.1 平台级 RBAC 是 Core
//!   责任）：[`RoleId`] / [`RoleName`] / [`Role`]（id + 展示名 + 权限
//!   集合）、[`GroupId`] / [`Group`]（用户集合 + 角色引用集合）、
//!   [`UserId`]、[`PermissionGrant`]（资源 + 动作 + scope，§17.3 资源级
//!   scope 非 boolean）、[`PermissionAction`]（§43.2 fine-grained Component
//!   administration permissions 闭集）、[`PermissionResource`]；
//!   Root Admin/Operator separation（§43.2）：[`Role::root_admin`]（全量
//!   权限，不可移除/降权）与 [`Role::operator`]（非破坏性默认权限集），
//!   id 常量 [`ROOT_ADMIN_ROLE_ID`] / [`OPERATOR_ROLE_ID`]；
//! - Scoped capability policies（§43.2 / §17.3）：[`PolicyScope`]
//!   （17.3 六维 scope 闭集 + All）、[`CapabilityPolicy`]（CapabilityId +
//!   允许 scope 集合）、[`PolicyVersion`] / [`PolicySnapshot`]（§43.2
//!   policy snapshot/versioning：u64 单调版本、不可变快照、`new_after`
//!   单调性由构造保证）；
//! - Resource quota hierarchy（§43.2 / §7.4）：[`QuotaHierarchy`]
//!   （Global → Group → Installation 层级树，构造校验形状与 id 唯一性）、
//!   [`QuotaNode`] / [`QuotaBudget`]（§7.4 七维预算，`None` = 该层不约束）、
//!   [`EffectiveQuota`]（层级求值结果：最严格生效 + 每维绑定层，
//!   见 `quota.rs` 模块文档裁决）、[`QuotaLevel`] / [`QuotaCount`] /
//!   [`BudgetDimension`]；
//! - Permission change impact analysis（§43.2）：[`PolicyChange`]
//!   （add/modify/remove 策略条目，modify 带前后对比）、[`PolicyDiff`]
//!   （两版本快照的确定性 diff）、[`ImpactAnalysis`]（受影响
//!   InstallationId / 用户 / 组集合，application 层生成可解释报告）；
//! - 可审计 policy chain（§43.3 验收 / §17.5 四层授权链）：
//!   [`PolicyChainLayer`]（contract-need → resolution → grant →
//!   invocation-enforcement）、[`PolicyChainEntry`]（层 + 授权/拒绝依据
//!   摘要）、[`PolicyDecision`]、[`PolicyChain`]（四层良构链，结论由条目
//!   派生，`explain()` 输出可读摘要——"管理员能解释为什么"的领域基础）。
//!
//! # 0.2.0 公开面（§40 Capability Composition 中的 domain 部分）
//!
//! - Capability Provider identity（§40.2）：[`ProviderId`]——"提供某能力的
//!   Component 安装实例"的身份，从 [`InstallationId`] 确定性派生（§17.5：
//!   Grant 的 durable owner 是 InstallationId；provider 身份可追溯到
//!   安装实例但不能与它混淆，无 ProviderId → InstallationId 转换）。
//! - 契约面类型（§40.2 / §40.3，事实源 = WIT imports/exports + Runtime
//!   Policy）：[`PackageName`] / [`InterfaceName`] / [`InterfaceId`]
//!   （provider 导出的 interface 标识）、[`InterfaceRequirement`]（consumer
//!   导入的需求，semver `VersionReq` 语义）与兼容判断
//!   [`interface_compatible`]。
//! - Provider graph（§40.2 dependency graph / §40.4 确定性）：
//!   [`ProviderGraph`]（不可变快照）、[`ProviderRecord`] / [`ConsumerRecord`]
//!   （构建输入）、[`ProviderNode`] / [`ResolvedEdge`]（节点与边）、
//!   [`ProviderGraphError`]（封闭 typed error：CycleDetected /
//!   AmbiguousProvider / MissingProvider / IncompatibleVersion 等）、
//!   激活顺序 [`ProviderGraph::topological_order`]。
//! - Provider upgrade 兼容分析（§40.2）：[`UpgradeCompatibilityReport`] /
//!   [`ConsumerUpgradeImpact`] / [`UpgradeImpact`] /
//!   [`UpgradeIncompatibility`]。
//!
//! # 设计约束
//!
//! - 全部值类型 validate-on-construct（§13.3 边界解析一次，内部保持强类型，
//!   §13.1 / §13.2 禁止 primitive obsession）。
//! - 全部算术使用 checked / saturating / try-conversion（§14.4，禁止回绕）。
//! - 所有值对象均为不可变值类型（`Send` + `Sync` 自动成立），无全局可变状态
//!   （§12.4）。

#[cfg(test)]
mod test_support;

mod bytes;
mod chain;
mod config;
mod digest;
mod error;
mod event;
mod graph;
mod id;
mod impact;
mod interface;
mod lifecycle;
mod path;
mod policy;
mod provider;
mod quota;
mod rbac;
mod scheduler;
mod secret;
mod size;
mod state;
mod time;
mod upgrade;
mod version;
mod web;

pub use chain::{PolicyChain, PolicyChainEntry, PolicyChainLayer, PolicyDecision};
pub use config::{ConfigFormat, ConfigRevision, ConfigSchemaVersion, ConfigSnapshot, ConfigValue};
pub use digest::ContentDigest;
pub use error::{DomainError, ValueKind};
pub use event::{EventId, EventPayload, EventPayloadBytes, EventPayloadText, EventTopic};
pub use graph::{
    ConsumerRecord, InterfaceCandidate, ProviderGraph, ProviderGraphError, ProviderNode,
    ProviderRecord, ResolvedEdge,
};
pub use id::{CapabilityId, ComponentId, InstallationId};
pub use impact::{ImpactAnalysis, PolicyChange, PolicyDiff};
pub use interface::{
    InterfaceId, InterfaceName, InterfaceRequirement, PackageName, interface_compatible,
};
pub use lifecycle::{ComponentLifecycleEvent, ComponentLifecycleState};
pub use path::ArtifactPath;
pub use policy::{
    CapabilityPolicy, FileSystemPath, HostName, NetworkScheme, PolicyScope, PolicySnapshot,
    PolicyVersion,
};
pub use provider::ProviderId;
pub use quota::{
    BudgetDimension, EffectiveQuota, QuotaBudget, QuotaCount, QuotaHierarchy, QuotaLevel, QuotaNode,
};
pub use rbac::{
    Group, GroupId, OPERATOR_ROLE_ID, PermissionAction, PermissionGrant, PermissionResource,
    ROOT_ADMIN_ROLE_ID, Role, RoleId, RoleName, UserId,
};
pub use scheduler::{ScheduleTrigger, ScheduledTaskId, TaskState, TaskStatus, TriggerPayload};
pub use secret::{SecretMetadata, SecretName, SecretVersion};
pub use size::ByteSize;
pub use state::{StateKey, StateSchemaVersion, StateTransactionId, StateValue};
pub use time::{Deadline, Duration, UtcInstant};
pub use upgrade::{
    ConsumerUpgradeImpact, UpgradeCompatibilityReport, UpgradeImpact, UpgradeIncompatibility,
};
pub use version::ComponentVersion;
pub use web::{
    AppDeclaration, AppFeatures, AssetPath, HttpMethod, PageDeclaration, PageId, PagePath,
    ParamType, ParamValue, PathConflict, PathConflictParty, PathSegment, PathTemplate,
    PermissionDeclaration, PermissionName, RouteDeclaration, RouteId, RouteParam, TypedParam,
    WebDeclarationError,
};
