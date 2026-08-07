//! application 层统一封闭 typed error（§14.1：thiserror 定义、可穷尽匹配；
//! 禁止 anyhow / eyre / `Box<dyn Error>` / String 作为公开错误类型）。
//!
//! 错误信息只含可诊断信息，不含任何机密（§16.6：secret 不进日志 / 错误）。

use std::error::Error as StdError;

use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest,
    DomainError, InstallationId, ProviderGraphError, StateSchemaVersion,
    UpgradeCompatibilityReport,
};

/// 可诊断错误源：第三方错误装箱（§14.1 适配层转换后保留 source；§16.6
/// 精神：错误路径不携带 secret / 敏感值）。
pub type ErrorSource = Box<dyn StdError + Send + Sync>;

/// application 统一 typed error（§14.1）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ApplicationError {
    /// domain 层错误（值校验 / 非法生命周期转换 / 算术溢出，§14.4）。
    #[error("domain error: {0}")]
    Domain(#[from] DomainError),

    /// 组件字节超过硬大小限制（§19.1 / §19.2）。
    /// 注：domain `ByteSize` 无 Display，这里用 Debug 形态展示字节数。
    #[error("component bytes ({actual:?} bytes) exceed the hard size limit ({limit:?} bytes)")]
    OversizedComponent {
        /// 上限。
        limit: ByteSize,
        /// 实际大小。
        actual: ByteSize,
    },

    /// WebAssembly Component validation 失败（§7.2 / §19.2 阶段二）。
    #[error("component bytes failed validation: {0}")]
    InvalidComponent(#[source] RuntimeExecutionError),

    /// 二进制 contract surface 违反（§6.7 / §19.2：必需导出缺失等）。
    #[error("component violates the operune contract surface: {0}")]
    ContractViolation(&'static str),

    /// descriptor contract violation（§19.3：重复读取不一致 / 形状非法）。
    #[error("descriptor contract violation: {0}")]
    DescriptorViolation(&'static str),

    /// 供应链 / 发布冲突（§19.4：相同逻辑版本不同 digest，显式阻断）。
    #[error(
        "supply chain conflict: {component_id} {version} is already bound to digest {existing}, refusing {incoming}"
    )]
    SupplyChainConflict {
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 作者声明版本。
        version: ComponentVersion,
        /// 已存在的绑定 digest。
        existing: ContentDigest,
        /// 试图安装的 digest。
        incoming: ContentDigest,
    },

    /// imports 解析 / grant policy 失败（§17.2 deny-by-default / §19.5）。
    #[error("import resolution denied by default: {missing:?}")]
    UnresolvedImport {
        /// 未被覆盖的能力。
        missing: Vec<CapabilityId>,
    },

    /// 0.1.0 明确不支持的跨 Component import（§19.5）。
    #[error(
        "capability {0} is not supported by this runtime (component-to-component imports arrive in 0.2.0)"
    )]
    UnsupportedCapability(CapabilityId),

    /// 安装实例不存在。
    #[error("installation {0} not found")]
    InstallationNotFound(InstallationId),

    /// 安装实例当前状态不允许该操作（§12.2：非法转换 typed error）。
    #[error("installation {0} is not in a usable state for this operation")]
    NotActive(InstallationId),

    /// 升级目标不是同一逻辑产品（§20：升级 = 同一 ComponentId 的新版本）。
    #[error("upgrade target component id {actual} does not match installation {expected}")]
    UpgradeComponentMismatch {
        /// 安装实例既有逻辑身份。
        expected: ComponentId,
        /// 升级目标逻辑身份。
        actual: ComponentId,
    },

    /// 回滚目标字节不可用（§18.7 rollback retention 被破坏 / GC 误删）。
    #[error("rollback target artifact {0} is unavailable")]
    RollbackUnavailable(ContentDigest),

    /// 安装没有可回滚的上一已知良好版本（§20：从未激活过 / 已是首个版本）。
    #[error("installation {0} has no rollback target")]
    NoRollbackTarget(InstallationId),

    /// grant 无法转换为运行时能力值（guest path / host path / env 规格
    /// 非法，§17.3）。
    #[error("grant is invalid: {0}")]
    GrantInvalid(#[source] operune_runtime_wasi_p2::error::WasiP2Error),

    /// 注册表失败（§14.1：source 保留可诊断上下文）。
    #[error("component registry failure: {0}")]
    Registry(#[source] crate::ports::RegistryError),

    /// grant store 失败。
    #[error("grant store failure: {0}")]
    Grants(#[source] crate::ports::GrantError),

    /// audit 失败（§18.7 fail closed：需要 durable audit 的变更不得提交）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] crate::ports::AuditError),

    /// config 读取失败。
    #[error("config failure: {0}")]
    ConfigSource(#[source] crate::ports::ConfigError),

    /// config 无效（宿主侧上限必须为正，§13.3）。
    #[error("runtime config invalid: {0}")]
    Config(&'static str),

    /// wasm 执行失败（compile / descriptor / instantiate / invoke，§14.1）。
    #[error("wasm execution failed: {0}")]
    Runtime(#[source] RuntimeExecutionError),

    /// Web asset path 非法（§21.3 契约 / §32 traversal 防护）。
    #[error("invalid web asset path: {0}")]
    InvalidWebAssetPath(&'static str),

    /// action 名称非法（§21.3）。
    #[error("invalid action name: {0}")]
    InvalidActionName(&'static str),

    /// Web bridge 拒绝（§21.3：Core 侧确定语义拒绝）。
    #[error("web action denied: {0}")]
    ActionDenied(#[source] crate::model::ActionDenied),

    /// 安装实例不是 Active（web 用例要求，§21.3）。
    #[error("installation {0} is not active")]
    NotActiveForWeb(InstallationId),

    /// 安装请求携带非法 grant 批准（§17.1：全新安装必须显式批准）。
    #[error("grant approval required: {0}")]
    GrantApprovalRequired(&'static str),

    /// 0.2.0 provider graph 解析失败（§40.2 dependency graph / §40.4：
    /// MissingProvider / AmbiguousProvider / IncompatibleVersion /
    /// CycleDetected，缺失 provider 诊断向上传——错误携带哪个 consumer、
    /// 哪个需求、哪些候选）。
    #[error("provider graph resolution failed: {source}")]
    ProviderGraphResolution {
        /// domain 层解析错误（含全部诊断信息）。
        #[source]
        source: ProviderGraphError,
    },

    /// 0.2.0 provider selection policy 无效（§40.2：显式绑定 / 排除规则
    /// 冲突或引用不存在的 provider 能力）。
    #[error("provider graph policy invalid: {0}")]
    ProviderGraphPolicy(#[source] crate::composition::GraphPolicyError),

    /// 0.2.0 provider 升级被 consumer 兼容分析门控拒绝（§40.2：升级会
    /// 破坏既有直接 consumer；报告携带影响面——哪些 consumer、哪些需求、
    /// interface 移除还是版本不兼容）。
    #[error(
        "provider upgrade of installation {installation} is incompatible with its consumers: {report:?}"
    )]
    ProviderUpgradeIncompatible {
        /// 被升级的安装实例。
        installation: InstallationId,
        /// 兼容分析报告（`is_safe()` 为 false）。
        report: UpgradeCompatibilityReport,
    },

    /// 0.2.0 Component import 无法解析为 Component-to-Component 需求
    /// （无 package 身份的本地实例名；deny-by-default，§17.2 / §19.5——
    /// 未解析 import 不得放行激活）。
    #[error(
        "component import `{0}` cannot be resolved as a component-to-component requirement (deny by default, §17.2)"
    )]
    UnresolvableImport(String),

    /// 0.2.0 provider graph records 存储失败（§40.2 graph
    /// persistence/recovery）。
    #[error("provider graph store failure: {0}")]
    GraphStore(#[source] crate::ports::GraphStoreError),

    /// 0.3.0：声明版本低于存储版本——forward-only 拒绝（WIT：0.1.0 不定义
    /// 已提交迁移后的降级，§20.5；升级 / 回滚被阻止，store 不变）。
    #[error(
        "state schema downgrade rejected for installation {installation}: declared {declared} is below stored {stored} (forward-only, §20.5)"
    )]
    StateSchemaDowngrade {
        /// 安装实例。
        installation: InstallationId,
        /// store 当前版本。
        stored: StateSchemaVersion,
        /// 新 ComponentVersion 声明版本。
        declared: StateSchemaVersion,
    },

    /// 0.3.0：guest state 迁移失败（§41.3）——迁移已 abort 回滚，store
    /// 保持旧版本；升级被阻止，旧 ComponentVersion 保持激活（§20.5
    /// rollback policy）。
    #[error(
        "state migration rejected for installation {installation} (from {from} to {to}): {reason}"
    )]
    StateMigrationRejected {
        /// 安装实例。
        installation: InstallationId,
        /// 迁移源版本。
        from: StateSchemaVersion,
        /// 迁移目标版本。
        to: StateSchemaVersion,
        /// guest 失败原因（kebab-case 静态标签；不含数据，§16.6 精神）。
        reason: &'static str,
    },

    /// 0.3.0：state 迁移编排失败（存储 / 审计 / 窗口冲突，§20.5）——升级
    /// 被阻止，store 不变（尽力 abort）。
    #[error("state migration orchestration failed: {0}")]
    StateMigration(#[from] crate::migration::MigrationError),

    /// 0.3.0：state store 读取失败（§41.2 存储面）。
    #[error("state store failure: {0}")]
    StateStore(#[source] crate::ports::StateStoreError),

    /// 0.4.0（§42.2）：Web app descriptor 校验失败（激活期：get-app-descriptor
    /// → AppDeclaration 组装 → 冲突诊断 / 二进制表面交叉校验）。失败 =
    /// candidate 保持 Failed（quarantine），当前 Active 不受污染（§19.2）。
    #[error("web app descriptor validation failed: {source}")]
    WebAppDescriptor {
        /// 声明期诊断（malformed / conflict diagnostics / contract
        /// violation）。
        #[source]
        source: crate::web_app::AppDescriptorFailure,
    },

    /// 卸载被拒绝：安装实例是 provider 且仍有 active consumer 依赖
    /// （§40 依赖图完整性裁决，§39.2 remove）。
    ///
    /// 裁决记录（选项 (a) vs (b)）：provider 卸载导致依赖图不完整——
    /// 选项 (a) 拒绝卸载（有依赖时）vs (b) 允许并标记受影响 consumer 为
    /// failed/未激活（须重解析）。选 (a)：
    ///
    /// - 确定性：拒绝发生在任何状态变更之前，无部分图、无隐式重解析；
    /// - 安全性：§19.5 禁止把缺失依赖的 Component 当作健康 active 服务，
    ///   §40.4 要求同一 set 确定解析——(b) 会把 graph 留在"已提交但不可
    ///   解析"的中间态；(a) 保持 graph 快照永远可解析；
    /// - 操作语义与既有停用/升级门控一致（[`crate::composition::CompositionService`
    ///   的 deactivate / provider 升级兼容分析同样拒绝仍被依赖的 provider）。
    ///
    /// consumer 卸载直接允许（consumer 移除不破坏任何其它解析）。
    #[error(
        "installation {installation} is a provider with {consumers:?} active consumer(s); refusing to uninstall (§40 graph integrity)"
    )]
    ProviderHasConsumers {
        /// 被卸载的安装实例。
        installation: InstallationId,
        /// 直接依赖它的 consumer 安装实例。
        consumers: Vec<InstallationId>,
    },

    /// enable 前置状态非法（§39.2 enable / §12.2：仅 `Disabled` 终态可
    /// 重新激活）。
    #[error(
        "installation {installation} is in state {state}; only Disabled can be re-enabled (§39.2)"
    )]
    EnableInvalidState {
        /// 安装实例。
        installation: InstallationId,
        /// 当前生命周期状态。
        state: ComponentLifecycleState,
    },

    /// enable 需要显式重新批准（§17.5：既有 grant 被替换/撤销后不得静默
    /// 放行——重新激活前必须补齐缺失能力）。
    #[error(
        "enable requires explicit grant approval for installation {installation}: missing {missing:?} (§17.5)"
    )]
    EnableRequiresApproval {
        /// 安装实例。
        installation: InstallationId,
        /// 未被覆盖的能力。
        missing: Vec<CapabilityId>,
    },

    /// 卸载时后台任务停机失败（§20.4：scheduler/event 未确定停机时卸载
    /// 不得继续——已入队任务可能仍在投递/触发）。
    #[error("background task stop failed during uninstall (aborted, §20.4): {0}")]
    BackgroundStop(#[source] crate::error::ErrorSource),

    /// artifact 字节不可用（§18.7 retention 被破坏：卸载不删除 artifact，
    /// 缺失即外部损坏/GC 误删）。enable 重新激活需要重新验证字节。
    #[error("artifact {0} is unavailable (retention violated, §18.7)")]
    ArtifactUnavailable(ContentDigest),

    /// 内部不变量破坏（视为系统故障，fail-stop 语义，§14.3）。
    #[error("application internal invariant violated: {0}")]
    Internal(&'static str),
}

/// wasm 执行边界错误（§14.1：application 的 runtime 执行错误，封闭 typed）。
///
/// 不泄漏 wasmtime 具体类型：底层错误经 [`crate::error::ErrorSource`]
/// 装箱为可诊断 source（runtime-wasm 的 [`operune_runtime_wasm::RuntimeError`]
/// 同样只承载项目类型，见其 crate 文档）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeExecutionError {
    /// runtime-wasm 层错误（Component 验证 / Store / 执行 / 资源限制，
    /// §7.2 / §7.4）。
    #[error("runtime-wasm failure: {0}")]
    Runtime(#[from] operune_runtime_wasm::RuntimeError),

    /// 组件缺少所需 operune 导出（§19.2 契约面 / §19.3 descriptor 阶段）。
    #[error("component does not export required operune interface `{0}`")]
    MissingOperuneExport(&'static str),

    /// 组件导出形状与契约不符（§19.3 contract violation）。
    #[error("guest data violates the operune contract: {0}")]
    MalformedGuestData(#[source] crate::contract::ContractValueError),

    /// descriptor 调用返回 guest 错误（§19.3：返回非法 metadata 视为失败）。
    #[error("guest returned descriptor error: {0:?}")]
    GuestDescriptorError(crate::contract::GuestDescriptorError),

    /// state-declaration 调用返回 guest 错误（§41.2 声明面：返回非法
    /// metadata 视为失败，declaration.wit）。
    #[error("guest returned state declaration error: {0:?}")]
    GuestStateDeclarationError(crate::contract::GuestStateDeclarationError),

    /// 0.4.0（§42.2）：`get-app-descriptor` 调用返回 guest 错误（返回
    /// 非法 app descriptor 视为失败；冲突诊断的 guest 侧闭集）。
    #[error("guest returned app descriptor error: {0:?}")]
    GuestAppDescriptorError(crate::contract::GuestAppDescriptorError),

    /// web descriptor / assets / actions 调用返回 guest 错误。
    #[error("guest returned web bridge error: {0}")]
    GuestWebError(&'static str),

    /// 单次执行 epoch deadline 到期（§7.5 / §19.3）。
    #[error("wasm execution deadline exceeded")]
    DeadlineExceeded,

    /// config 快照读取失败（§18.0 RuntimeConfig 语义）。
    #[error("runtime config snapshot unavailable")]
    ConfigUnavailable,

    /// 全部实例槽位繁忙（§7.4 并发上限，§21.3 concurrency 检查）。
    #[error("all instance slots are busy")]
    Busy,

    /// 响应体积超限（§21.3：Core 宿主侧硬上限）。
    #[error("response exceeds the host-side limit")]
    ResponseTooLarge,

    /// 内部不变量破坏（fail-stop 语义，§14.3）。
    #[error("runtime execution internal invariant violated: {0}")]
    Internal(&'static str),
}

impl RuntimeExecutionError {
    /// 从 wasmtime 执行错误分类映射（§7.5 时序：调用方已先执行
    /// `begin_execution` 与 `set_deadline`）。
    pub(crate) fn from_classified(
        store: &mut operune_runtime_wasm::StoreHandle,
        error: ErrorSource,
    ) -> Self {
        match operune_runtime_wasm::error::classify_wasm_error(store, error) {
            operune_runtime_wasm::RuntimeError::Execution {
                kind: operune_runtime_wasm::WasmFailure::EpochDeadlineExceeded,
                ..
            } => RuntimeExecutionError::DeadlineExceeded,
            other => RuntimeExecutionError::Runtime(other),
        }
    }
}
