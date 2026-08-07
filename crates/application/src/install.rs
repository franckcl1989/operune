//! 两阶段安装管线（§19.2 严格顺序；§19.3 descriptor 确定性；§20 升级 /
//! 回滚共用）。
//!
//! # 管线顺序（§19.2 逐字实现）
//!
//! ```text
//! receive bytes
//!   -> hard size limit
//!   -> compute ContentDigest
//!   -> WebAssembly Component validation (wasmtime 同步验证, §7.2)
//!   -> inspect binary component type: imports/exports (§6.7)
//!   -> derive preliminary dependency + permission need plan
//!   -> persist digest-keyed quarantine/candidate record (§19.2 "字节事实")
//!   -> descriptor-only Store, zero operational grants (§19.3)
//!   -> call operune:component descriptor export (两次调用比对, §19.3)
//!   -> validate ComponentId + ComponentVersion + metadata
//!   -> persist logical identity/version relationship and InstallationId
//!   -> resolve/link imports with deny-by-default grants (§17.2 / §19.5)
//!   -> instantiate runtime candidate under the grant/resource snapshot
//!   -> readiness/health validation (§19.3)
//!   -> atomic activation (§19.2 末步 / §20.3)
//! ```
//!
//! 任何一步失败都不得污染当前 Active Version（§19.2）：候选（candidate）
//! 进入 `Failed`（quarantine 语义），当前 Active 快照保持不变。
//!
//! # 状态机驱动（§12.2 / §19）
//!
//! 全程由 [`operune_domain::ComponentLifecycleState`] 显式转换驱动：
//! `Installed → Validated → Activating → Active`（失败路径
//! `→ Failed`）；升级时旧版本 `Active → Draining → Disabled`（§20.4）。
//! 非法转换返回 typed error，绝不静默忽略（§12.2）。
//!
//! # audit fail-closed（§18.7）
//!
//! 每个会变更状态 / 权限 / 生命周期的步骤先写 durable audit，写入失败即
//! 中止（fail closed）；被拒绝的输入也写审计（拒绝原因），audit 失败时
//! 以 audit 错误中止。

use std::sync::{Arc, OnceLock};

use operune_domain::{
    AppDeclaration, ByteSize, CapabilityId, ComponentId, ComponentLifecycleEvent,
    ComponentLifecycleState, ComponentVersion, ContentDigest, InstallationId, StateSchemaVersion,
    StateTransactionId,
};
use operune_runtime_wasi_p2::capability::{
    EnvVarSpec, FsPerms, GuestPath, PreopenDirSpec, WasiCapabilities,
};

use crate::active::{ActiveEntry, ActiveInstallation, ActiveRuntimeRegistry};
use crate::composition::{CompositionService, records_from_surface};
use crate::contract::{GuestComponentDescriptor, GuestStateDeclaration};
use crate::error::ApplicationError;
use crate::migration::{MigrationGuestError, MigrationOutcome, StateMigrationService};
use crate::model::{
    CandidateRecord, ContractSurface, DigestVersionBinding, GrantApproval, GrantScope,
    GrantSnapshot, ImportClass, InstallOutcome, InstallRequest, InstallationGrant,
    InstallationRecord, PipelineTarget, RuntimeConfig, WebManifestData,
};
use crate::ports::{
    AuditEvent, AuditPort, ComponentRegistryPort, ConfigPort, GrantStorePort, RegistryError,
    RejectReason, StateStorePort,
};
use crate::runtime::{ActiveRuntime, CompiledWasm, RuntimePlan, WasmRuntime};
use crate::web::AssetCache;
use crate::web_app::{WebAppContext, WebAppService};

/// 展示性文本上限（§19.3 宿主侧体积上限；对齐 descriptor 契约的
/// display-name 语义）。
const MAX_DISPLAY_NAME_LEN: usize = 2048;

/// 管线结果。
#[derive(Debug)]
pub(crate) enum PipelineResult {
    /// 管线完成并原子激活（§19.2 末步）。
    Activated {
        /// 安装实例记录（state = Active）。
        installation: InstallationRecord,
        /// 激活 digest。
        digest: ContentDigest,
    },
    /// 升级 / 回滚等待显式批准（§17.5）：candidate 保持 Validated。
    RequiresApproval {
        /// 安装实例记录（state = Validated）。
        installation: InstallationRecord,
        /// 未被既有 grant 覆盖的能力。
        missing: Vec<CapabilityId>,
    },
}

/// 安装用例服务（§19：两阶段安装）。
pub struct InstallService {
    pipeline: Pipeline,
}

impl InstallService {
    /// 构造（注入全部端口与运行依赖；composition root 组装）。
    ///
    /// 0.2.0 Capability Composition 默认不接线（composition = None，保持
    /// 0.1.0 语义：非宿主 import 以 §19.5 UnsupportedCapability 拒绝）；
    /// 接线见 [`InstallService::set_composition`]。
    pub fn new(
        registry: Arc<dyn ComponentRegistryPort>,
        grants: Arc<dyn GrantStorePort>,
        audit: Arc<dyn AuditPort>,
        config: Arc<dyn ConfigPort>,
        runtime: Arc<dyn WasmRuntime>,
        active: Arc<ActiveRuntimeRegistry>,
        assets: Arc<AssetCache>,
    ) -> Self {
        Self {
            pipeline: Pipeline::new(registry, grants, audit, config, runtime, active, assets),
        }
    }

    /// 接线 0.2.0 Capability Composition（§40：激活前先构建/解析 provider
    /// graph，consumer 激活依赖 provider 先激活；graph records 提交 +
    /// 快照原子切换）。composition root 在启动装配期调用一次；重复接线
    /// → typed 拒绝（§12.4 无全局可变状态，wiring 是一次性事实）。
    pub fn set_composition(
        &self,
        composition: Arc<CompositionService>,
    ) -> Result<(), ApplicationError> {
        self.pipeline
            .composition
            .set(composition)
            .map_err(|_| ApplicationError::Internal("composition is already wired"))
    }

    /// 接线 0.3.0 state schema（§20.5 / §41.2）：激活前读取 guest 的
    /// `state-declaration.schema-version`，与 store 当前版本比较——不匹配
    /// → 触发显式迁移（[`StateMigrationService`]）；匹配 / 空 store /
    /// 无声明 → 直接激活。composition root 在启动装配期调用一次；重复
    /// 接线 → typed 拒绝（§12.4 无全局可变状态，wiring 是一次性事实）。
    /// 未接线（默认）= 0.1.0 语义：管线不读取声明、不触发迁移。
    pub fn set_state(&self, state: Arc<StateWiring>) -> Result<(), ApplicationError> {
        self.pipeline
            .state
            .set(state)
            .map_err(|_| ApplicationError::Internal("state wiring is already wired"))
    }

    /// 接线 0.4.0 Web Application Runtime（§42.2）：激活期读取
    /// `get-app-descriptor`、组装 AppDeclaration、执行声明期冲突诊断与
    /// 二进制表面交叉校验（失败 = candidate Failed 保持 quarantine）；
    /// 激活后 WebAppContext（app descriptor + typed route registry）随
    /// Active 快照原子切换（§21.5）。composition root 在启动装配期调用
    /// 一次；重复接线 → typed 拒绝（§12.4 无全局可变状态，wiring 是一次性
    /// 事实）。未接线（默认）= 0.1.0 语义：管线不读取 app-descriptor。
    pub fn set_web_app(&self, web_app: Arc<WebAppService>) -> Result<(), ApplicationError> {
        self.pipeline
            .web_app
            .set(web_app)
            .map_err(|_| ApplicationError::Internal("web app service is already wired"))
    }

    /// 两阶段安装（§19.2）：成功返回激活结果；失败返回 typed error，
    /// 当前 Active 不受污染。
    pub fn install(&self, request: InstallRequest) -> Result<InstallOutcome, ApplicationError> {
        let outcome = self.pipeline.run(request, PipelineTarget::Install)?;
        match outcome {
            PipelineResult::Activated {
                installation,
                digest,
            } => Ok(InstallOutcome::Activated {
                installation: installation.installation_id,
                version: installation.version,
                digest,
            }),
            PipelineResult::RequiresApproval { .. } => Err(ApplicationError::Internal(
                "fresh install cannot require approval",
            )),
        }
    }

    /// 管线访问（upgrade 用例共用）。
    pub(crate) fn pipeline(&self) -> &Pipeline {
        &self.pipeline
    }

    /// 重新激活（§39.2 enable / §12.2：`Disabled → ActivationRequested →
    /// Activating → Active`）。
    ///
    /// 从 artifact store 读取当前版本的字节（§18.7 rollback retention：
    /// 卸载/停用都不删除 artifact），复用完整激活管线——编译、descriptor
    /// 确定性、imports/grant 解析、实例化与 **readiness 重验证**（§19.3）
    /// ——后原子激活。**不做**"跳过验证直接恢复"。
    ///
    /// 前置：安装实例存在且处于 `Disabled`（§12.2 概念图终点），否则
    /// [`ApplicationError::EnableInvalidState`]；当前版本字节不可用
    /// （§18.7 retention 被破坏）→ [`ApplicationError::ArtifactUnavailable`]；
    /// 既有 grant 不覆盖该版本 imports（§17.5：grants 被替换/撤销后不得
    /// 静默放行）→ [`ApplicationError::EnableRequiresApproval`]。
    pub fn enable(&self, installation: InstallationId) -> Result<(), ApplicationError> {
        let record = self
            .pipeline
            .registry
            .installation(installation)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::InstallationNotFound(installation))?;
        if record.state != ComponentLifecycleState::Disabled {
            return Err(ApplicationError::EnableInvalidState {
                installation,
                state: record.state,
            });
        }
        let digest = record.active_digest.ok_or(ApplicationError::Internal(
            "disabled installation lacks an active digest",
        ))?;
        // §18.7：重新验证需要字节事实可用（卸载不删除 artifact；缺失即
        // retention 被破坏 / GC 误删）。
        let bytes = self
            .pipeline
            .registry
            .artifact_bytes(digest)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::ArtifactUnavailable(digest))?;
        let result = self.pipeline.run(
            InstallRequest {
                bytes,
                grants: GrantApproval::ReuseExisting,
            },
            PipelineTarget::Enable { current: record },
        )?;
        match result {
            PipelineResult::Activated { .. } => Ok(()),
            PipelineResult::RequiresApproval {
                installation,
                missing,
            } => Err(ApplicationError::EnableRequiresApproval {
                installation: installation.installation_id,
                missing,
            }),
        }
    }
}

/// guest `migrate` 调用注入面（WIT `migration` interface 的 Core 侧调用点，
/// §20.5 / §41.2）。
///
/// 实现方（runtime 接线面）把 Core 侧事务身份（domain
/// [`StateTransactionId`]）映射为 WIT `state-transaction` resource 句柄后
/// 调用 guest 导出 `migrate`（from-version / to 透传）；返回
/// [`MigrationGuestError`] = guest 失败或宿主侧观测失败（trap / deadline /
/// 超预算），由 [`StateMigrationService`] 按回滚语义处理（§20.5 rollback
/// policy）。
///
/// 0.3.0 生产接线在 state-transaction resource 注册后提供（
/// `stateful_imports` 模块文档"明确未闭环"）；本 trait 是管线侧注入缝。
pub trait StateMigrationRunner: Send + Sync {
    /// 调用一次 guest 迁移（from-version → to）。
    fn run(
        &self,
        component: &Arc<dyn CompiledWasm>,
        from: StateSchemaVersion,
        to: StateSchemaVersion,
        tx: StateTransactionId,
    ) -> Result<(), MigrationGuestError>;
}

/// 0.3.0 state schema wiring（§20.5 / §41.2）：upgrade/install 管线激活前
/// 读取 guest `state-declaration`、与存储版本比较并触发显式迁移的注入面。
///
/// 构造（composition root）：`store` + `migration` + `guest` 全部由
/// composition root 注入（§24.2 端口注入）；`migration` 与
/// [`crate::state::StateService`] 共享同一 [`crate::state::MigrationGate`]
///（迁移窗口期间运行时操作返回 not-ready，§41.2）。
pub struct StateWiring {
    /// 存储面（存储版本读取）。
    pub(crate) store: Arc<dyn StateStorePort>,
    /// 显式迁移编排服务（协议 1–6 步，§20.5/§41.2）。
    pub(crate) migration: Arc<StateMigrationService>,
    /// guest `migrate` 调用注入点（runtime 接线面实现）。
    pub(crate) guest: Arc<dyn StateMigrationRunner>,
}

impl StateWiring {
    /// 构造（store + migration 服务 + guest 调用注入点）。
    pub fn new(
        store: Arc<dyn StateStorePort>,
        migration: Arc<StateMigrationService>,
        guest: Arc<dyn StateMigrationRunner>,
    ) -> Self {
        Self {
            store,
            migration,
            guest,
        }
    }
}

/// 共享安装管线（§19.2 / §20.1：安装、升级、回滚共用）。
pub(crate) struct Pipeline {
    registry: Arc<dyn ComponentRegistryPort>,
    grants: Arc<dyn GrantStorePort>,
    audit: Arc<dyn AuditPort>,
    config: Arc<dyn ConfigPort>,
    runtime: Arc<dyn WasmRuntime>,
    active: Arc<ActiveRuntimeRegistry>,
    assets: Arc<AssetCache>,
    /// 0.2.0 Capability Composition 接线（§40；`None` = 0.1.0 语义）。
    /// `OnceLock`：composition root 装配期一次性设置，运行期只读。
    composition: OnceLock<Arc<CompositionService>>,
    /// 0.3.0 state schema 接线（§20.5/§41.2；`None` = 0.1.0 语义：管线
    /// 不读取 state-declaration、不触发迁移）。`OnceLock`：composition
    /// root 装配期一次性设置，运行期只读。
    state: OnceLock<Arc<StateWiring>>,
    /// 0.4.0 Web Application Runtime 接线（§42.2；`None` = 0.1.0 语义：
    /// 管线不读取 app-descriptor、不执行声明期冲突诊断）。`OnceLock`：
    /// composition root 装配期一次性设置，运行期只读。
    web_app: OnceLock<Arc<WebAppService>>,
}

impl Pipeline {
    pub(crate) fn new(
        registry: Arc<dyn ComponentRegistryPort>,
        grants: Arc<dyn GrantStorePort>,
        audit: Arc<dyn AuditPort>,
        config: Arc<dyn ConfigPort>,
        runtime: Arc<dyn WasmRuntime>,
        active: Arc<ActiveRuntimeRegistry>,
        assets: Arc<AssetCache>,
    ) -> Self {
        Self {
            registry,
            grants,
            audit,
            config,
            runtime,
            active,
            assets,
            composition: OnceLock::new(),
            state: OnceLock::new(),
            web_app: OnceLock::new(),
        }
    }

    /// 执行管线（严格顺序见模块文档）。
    pub(crate) fn run(
        &self,
        request: InstallRequest,
        target: PipelineTarget,
    ) -> Result<PipelineResult, ApplicationError> {
        let config = self
            .config
            .snapshot()
            .map_err(ApplicationError::ConfigSource)?;
        config.validate()?;

        // 全新安装必须显式批准 grant（§17.1：grant 绑定 InstallationId）；
        // 升级 / 回滚沿用既有安装实例（§20：同一安装的版本演进）。
        let current_record = match &target {
            PipelineTarget::Install => None,
            PipelineTarget::Upgrade { current }
            | PipelineTarget::Rollback { current }
            | PipelineTarget::Enable { current } => Some(current.clone()),
        };
        if matches!(target, PipelineTarget::Install)
            && matches!(request.grants, GrantApproval::ReuseExisting)
        {
            return Err(ApplicationError::GrantApprovalRequired(
                "a fresh install requires explicit grants",
            ));
        }

        // —— 阶段一：字节事实（§19.2 顺序 1–6）——

        let byte_len = u64::try_from(request.bytes.len()).unwrap_or(u64::MAX);
        if byte_len > config.max_component_bytes.as_u64() {
            let digest = ContentDigest::from_bytes(&request.bytes);
            return Err(self.reject(
                AuditEvent::InstallRejected {
                    digest,
                    reason: RejectReason::Oversized,
                },
                ApplicationError::OversizedComponent {
                    limit: config.max_component_bytes,
                    actual: ByteSize::from_bytes(byte_len),
                },
            ));
        }
        let digest = ContentDigest::from_bytes(&request.bytes);

        // §7.2：wasmtime 同步验证 + 编译（失败 = 拒绝，不产生 candidate）。
        let component = self.runtime.compile(&request.bytes).map_err(|error| {
            self.reject(
                AuditEvent::InstallRejected {
                    digest,
                    reason: RejectReason::InvalidBytes,
                },
                ApplicationError::InvalidComponent(error),
            )
        })?;

        // §6.7：二进制 contract surface（不执行 guest 代码）。
        let surface = self
            .runtime
            .contract_surface(&component)
            .map_err(ApplicationError::Runtime)?;
        if !surface.exports_component_descriptor() {
            return Err(self.reject(
                AuditEvent::InstallRejected {
                    digest,
                    reason: RejectReason::MissingComponentDescriptor,
                },
                ApplicationError::ContractViolation(
                    "component must export the operune:component/descriptor interface",
                ),
            ));
        }

        // 初步依赖 + 权限需要计划（§19.2 顺序 6）。composition 未接线
        // （0.1.0）：跨 Component import 明确判定为不支持并拒绝（§19.5）；
        // composition 接线（0.2.0）：非宿主 import 属于 provider graph
        // （§40.3），只推导宿主能力需求（wasi:/operune:，§17.5），
        // Component-to-Component 需求由 graph 门控校验。
        let required = match if self.composition.get().is_some() {
            classify_host_imports(&surface)
        } else {
            classify_imports(&surface)
        } {
            Ok(capabilities) => capabilities,
            Err(error) => {
                return Err(self.reject(
                    AuditEvent::InstallRejected {
                        digest,
                        reason: RejectReason::ContractSurface,
                    },
                    error,
                ));
            }
        };

        // 持久化 digest 主键的 quarantine/candidate（§19.2 顺序 7；
        // upsert = 管线重新进入时重置该次尝试的生命周期）。
        self.audit_ok(AuditEvent::CandidatePersisted { digest })?;
        self.registry
            .persist_artifact(digest, &request.bytes)
            .map_err(ApplicationError::Registry)?;
        self.registry
            .upsert_candidate(&CandidateRecord {
                digest,
                state: ComponentLifecycleState::initial(),
                byte_len: ByteSize::from_bytes(byte_len),
            })
            .map_err(ApplicationError::Registry)?;

        // —— 阶段二a：应用身份（§19.2 顺序 8–11 / §19.3）——

        // descriptor-only Store（零 operational grant）中读取 descriptor；
        // 同一 digest 同一 contract version 重复调用比对 canonical 结果，
        // 不一致 = contract violation（§19.3 / 任务 C）。
        let first = self.runtime.read_descriptor(&component).map_err(|error| {
            self.fail_candidate(
                digest,
                AuditEvent::DescriptorFailed {
                    digest,
                    reason: "descriptor-call",
                },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::Runtime(error),
            )
        })?;
        let second = self.runtime.read_descriptor(&component).map_err(|error| {
            self.fail_candidate(
                digest,
                AuditEvent::DescriptorFailed {
                    digest,
                    reason: "descriptor-call",
                },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::Runtime(error),
            )
        })?;
        if first != second {
            return Err(self.fail_candidate(
                digest,
                AuditEvent::DescriptorMismatch { digest },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::DescriptorViolation(
                    "descriptor result is not deterministic (contract violation, §19.3)",
                ),
            ));
        }
        let (component_id, version) = self.validate_identity(digest, &first)?;

        // §20 / §39.2：升级 / 回滚 / 重新激活目标必须是同一逻辑产品
        //（ComponentId 不变）。
        if let PipelineTarget::Upgrade { current }
        | PipelineTarget::Rollback { current, .. }
        | PipelineTarget::Enable { current } = &target
            && current.component_id != component_id
        {
            return Err(self.fail_candidate(
                digest,
                AuditEvent::DescriptorFailed {
                    digest,
                    reason: "upgrade-identity-mismatch",
                },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::UpgradeComponentMismatch {
                    expected: current.component_id.clone(),
                    actual: component_id,
                },
            ));
        }

        // §19.4：同一 ComponentId + ComponentVersion 已绑定不同 digest =
        // 供应链/发布冲突，显式阻断，不静默覆盖。
        if let Some(existing) = self
            .registry
            .resolve_version(&component_id, version)
            .map_err(ApplicationError::Registry)?
            && existing.digest != digest
        {
            return Err(self.fail_candidate(
                digest,
                AuditEvent::VersionConflict {
                    component_id: component_id.clone(),
                    version,
                    existing: existing.digest,
                    incoming: digest,
                },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::SupplyChainConflict {
                    component_id,
                    version,
                    existing: existing.digest,
                    incoming: digest,
                },
            ));
        }

        // §19.4：InstallationId 由 Core 创建并持久化（§19.2 顺序 11）；
        // 升级 / 回滚沿用既有安装实例身份（§20：同一安装的版本演进）。
        let installation_id = match &current_record {
            Some(current) => current.installation_id,
            None => InstallationId::new(),
        };
        self.audit_ok(AuditEvent::IdentityRegistered {
            installation: installation_id,
            component_id: component_id.clone(),
            version,
            digest,
        })?;
        self.registry
            .bind_version(&DigestVersionBinding {
                component_id: component_id.clone(),
                version,
                digest,
            })
            .map_err(|error| match error {
                RegistryError::VersionBindingConflict {
                    component_id,
                    version,
                    existing,
                    incoming,
                } => ApplicationError::SupplyChainConflict {
                    component_id,
                    version,
                    existing,
                    incoming,
                },
                other => ApplicationError::Registry(other),
            })?;
        // 全新安装：创建 Validated 安装记录（§18.3）。升级 / 回滚期间
        // installation 记录保持 Active（v1 仍在服务，§20.1），直到原子
        // 切换时才更新为新的 active digest。
        let installation = match &current_record {
            Some(current) => current.clone(),
            None => InstallationRecord {
                installation_id,
                component_id: component_id.clone(),
                version,
                active_digest: None,
                last_known_good_digest: None,
                state: ComponentLifecycleState::Validated,
            },
        };
        if current_record.is_none() {
            self.registry
                .insert_installation(&installation)
                .map_err(ApplicationError::Registry)?;
        }
        // "应用身份"阶段完成（§19.2 / §12.2：Installed → Validated）。
        self.transition_candidate(digest, ComponentLifecycleEvent::ValidationSucceeded)?;

        // —— 阶段二b-0：0.2.0 provider graph 门控（§40.2 / §40.3）——
        // composition 接线后，激活前先构建/解析 graph：consumer 的激活
        // 依赖其 provider 已先激活（records 已持久化——缺失则以
        // MissingProvider 诊断拒绝，天然强制 activation ordering）；环 /
        // 歧义 / provider 升级不兼容全部 typed 拒绝。任何失败 → candidate
        // 保持 Failed，当前 Active 不受污染（§19.2）。
        if let Some(composition) = self.composition.get() {
            let records = match records_from_surface(installation_id, &surface) {
                Ok(records) => records,
                Err(error) => {
                    return Err(self.fail_candidate(
                        digest,
                        AuditEvent::ProviderGraphRejected {
                            installation: installation_id,
                            reason: "surface",
                        },
                        ComponentLifecycleEvent::ResolutionFailed,
                        error,
                    ));
                }
            };
            // provider 升级 / 回滚：先做 consumer 兼容分析门控（§40.2）。
            composition
                .check_upgrade(installation_id, &records)
                .map_err(|error| {
                    self.fail_candidate(
                        digest,
                        AuditEvent::ProviderGraphRejected {
                            installation: installation_id,
                            reason: "upgrade-analysis",
                        },
                        ComponentLifecycleEvent::ResolutionFailed,
                        error,
                    )
                })?;
            // 全量重建门控（含新增 consumer 需求 / 新提供面引发的重新解析）。
            composition
                .check_activation(installation_id, &records)
                .map_err(|error| {
                    self.fail_candidate(
                        digest,
                        AuditEvent::ProviderGraphRejected {
                            installation: installation_id,
                            reason: "resolution",
                        },
                        ComponentLifecycleEvent::ResolutionFailed,
                        error,
                    )
                })?;
        }

        // —— 阶段二b：imports 解析与 grant（§17.2 / §17.5 / §19.5）——

        let grants = self.target_grants(&target, &request, installation_id)?;
        // deny-by-default：每个 import 能力必须有 grant 覆盖（§17.2）。
        let missing = required
            .iter()
            .filter(|capability| !grants.iter().any(|grant| &grant.capability == *capability))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            // ReuseExisting（升级/回滚）覆盖不足 = 等待显式批准（§17.5：
            // 旧 grant 只有在新版本 imports 没有扩大需求时才可继续适用）。
            if matches!(request.grants, GrantApproval::ReuseExisting) {
                return Ok(PipelineResult::RequiresApproval {
                    installation,
                    missing,
                });
            }
            return Err(self.fail_candidate(
                digest,
                AuditEvent::ResolutionFailed {
                    installation: installation_id,
                    missing: missing.clone(),
                },
                ComponentLifecycleEvent::ResolutionFailed,
                ApplicationError::UnresolvedImport { missing },
            ));
        }
        let snapshot = self.build_snapshot(installation_id, &grants, &config)?;
        let plan = RuntimePlan {
            installation: installation_id,
            grants: snapshot,
        };
        // 二进制级 link 检查（§17.2：不得"先运行，失败时 trap"代替权限解析）。
        let prepared = self.runtime.prepare(&component, &plan).map_err(|error| {
            self.fail_candidate(
                digest,
                AuditEvent::ResolutionFailed {
                    installation: installation_id,
                    missing: Vec::new(),
                },
                ComponentLifecycleEvent::ResolutionFailed,
                ApplicationError::Runtime(error),
            )
        })?;

        // —— 阶段二b-2：0.3.0 state schema 阶段（§20.5 / §41.2）——
        // 激活前读取 guest 的 state-declaration.schema-version，与 store
        // 当前版本比较：不匹配 → 触发显式迁移（StateMigrationService，
        // §20.5/§41.2 协议 1–6 步）；迁移成功 → 继续激活；guest 失败 /
        // 编排失败 → candidate Failed，store 不变（§20.5 rollback policy），
        // 当前 Active 不受污染（§19.2）。置于 grants/prepare 之后：
        // RequiresApproval（§17.5）路径不触发迁移——未获批准不迁移 store。
        self.run_state_schema_phase(digest, installation_id, &component)?;

        // —— 阶段二c：激活（§19.2 顺序 12–15 / §19.3 / §20.3）——

        self.audit_ok(AuditEvent::ActivationStarted {
            installation: installation_id,
        })?;
        self.transition_candidate(digest, ComponentLifecycleEvent::ActivationRequested)?;
        let active = self.runtime.instantiate(&prepared).map_err(|error| {
            self.fail_activating(
                digest,
                installation_id,
                "instantiate",
                ApplicationError::Runtime(error),
            )
        })?;
        active.check_readiness().map_err(|error| {
            self.fail_activating(
                digest,
                installation_id,
                "readiness",
                ApplicationError::Runtime(error),
            )
        })?;
        let manifest = active.read_web_manifest().map_err(|error| {
            self.fail_activating(
                digest,
                installation_id,
                "web-manifest",
                ApplicationError::Runtime(error),
            )
        })?;
        // §web descriptor 契约：作者声明的能力与二进制 exports 交叉校验，
        // 不一致 = contract violation。
        self.validate_manifest(&manifest, &surface, &config, digest, installation_id)?;
        let cached = self.cache_assets(digest, &active, &manifest, &config, installation_id)?;

        // —— 0.4.0 Web Application Runtime（§42.2）：app-descriptor 激活期
        // 校验（get-app-descriptor → AppDeclaration 组装 → 冲突诊断 →
        // 二进制表面交叉校验）。任何失败 = candidate Failed（quarantine），
        // 当前 Active 不受污染（§19.2）。
        let web_app_declaration =
            self.run_web_app_phase(digest, installation_id, &component, &surface)?;

        // 授权落盘（§17.5 显式批准 / 复用验证通过；fail-closed 审计先行）。
        if matches!(request.grants, GrantApproval::Explicit(_)) {
            self.audit_ok(AuditEvent::GrantsApproved {
                installation: installation_id,
                grants: grants.iter().map(|grant| grant.audit_shape()).collect(),
            })?;
            self.grants
                .replace_grants(installation_id, &grants)
                .map_err(ApplicationError::Grants)?;
        }

        match target {
            PipelineTarget::Install => self.activate_install(
                digest,
                installation_id,
                component_id.clone(),
                version,
                active,
                manifest,
                cached,
                web_app_declaration,
                &surface,
            ),
            PipelineTarget::Upgrade { current } => self.activate_upgrade(
                AuditEvent::UpgradeSwapped {
                    installation: installation_id,
                    from: current.active_digest.ok_or(ApplicationError::Internal(
                        "active installation lacks an active digest",
                    ))?,
                    to: digest,
                },
                digest,
                current,
                installation_id,
                component_id.clone(),
                version,
                active,
                manifest,
                cached,
                web_app_declaration,
                &config,
                &surface,
            ),
            PipelineTarget::Rollback { current } => self.activate_upgrade(
                AuditEvent::Rollback {
                    installation: installation_id,
                    from: current.active_digest.ok_or(ApplicationError::Internal(
                        "active installation lacks an active digest",
                    ))?,
                    to: digest,
                },
                digest,
                current,
                installation_id,
                component_id.clone(),
                version,
                active,
                manifest,
                cached,
                web_app_declaration,
                &config,
                &surface,
            ),
            PipelineTarget::Enable { current } => self.activate_enable(
                digest,
                current,
                installation_id,
                component_id.clone(),
                version,
                active,
                manifest,
                cached,
                web_app_declaration,
                &surface,
            ),
        }
    }

    /// 目标相关的 grant 集合（§17.1：grant 绑定 InstallationId；
    /// `installation_id` 参数保留为签名对齐，实际按目标读取）。
    fn target_grants(
        &self,
        target: &PipelineTarget,
        request: &InstallRequest,
        _installation_id: InstallationId,
    ) -> Result<Vec<InstallationGrant>, ApplicationError> {
        match &request.grants {
            GrantApproval::Explicit(grants) => Ok(grants.clone()),
            GrantApproval::ReuseExisting => match target {
                PipelineTarget::Install => Err(ApplicationError::GrantApprovalRequired(
                    "a fresh install requires explicit grants",
                )),
                PipelineTarget::Upgrade { current }
                | PipelineTarget::Rollback { current, .. }
                | PipelineTarget::Enable { current } => self
                    .grants
                    .grants_for(current.installation_id)
                    .map_err(ApplicationError::Grants),
            },
        }
    }

    /// 0.3.0 state schema 阶段（§20.5 / §41.2）：激活前读取 guest 的
    /// `state-declaration.schema-version`，与 store 当前版本比较。
    ///
    /// - 未接线（composition root 未注入 [`StateWiring`]）= 0.1.0 语义：
    ///   不读取声明、不触发迁移（无状态组件路径不变）；
    /// - 组件无 `declaration` 导出 → 无状态组件路径（0.1 语义保持）；
    /// - 空 store（首次安装 / 首次写入前）→ 无可迁移数据，激活继续
    ///   （§41.3：版本由首次写入建立）；
    /// - 声明版本 == 存储版本 → 直接激活；
    /// - 声明版本 > 存储版本 → 触发 [`StateMigrationService`]（显式迁移
    ///   编排，协议 1–6 步）：迁移提交 → 激活继续；guest 失败
    ///   （[`MigrationOutcome::RolledBack`]，§41.3 回滚）或编排失败 →
    ///   激活拒绝，store 不变，旧 ComponentVersion 保持激活（§20.5）；
    /// - 声明版本 < 存储版本 → 拒绝（forward-only，WIT：0.1.0 不定义
    ///   已提交迁移后的降级）。
    ///
    /// 声明读取遵循 §19.3 descriptor 阶段精神（declaration.wit 明文）：
    /// 同一 digest 同一 contract version 重复调用比对 canonical 结果，
    /// 不一致 = contract violation。全部失败路径 → candidate Failed
    /// （Validated → Failed，§12.2），审计 reason 沿用
    /// [`AuditEvent::DescriptorFailed`] 的 reason 标签惯例（管线既有
    /// `upgrade-identity-mismatch` 同模式，§18.7 fail closed）。
    fn run_state_schema_phase(
        &self,
        digest: ContentDigest,
        installation_id: InstallationId,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<(), ApplicationError> {
        let Some(wiring) = self.state.get() else {
            return Ok(());
        };
        // §19.3 确定性比对（同 read_descriptor 的两次调用惯例）。
        let first = self.read_state_declaration(digest, component)?;
        let second = self.read_state_declaration(digest, component)?;
        if first != second {
            return Err(self.fail_state_schema(
                digest,
                "state-declaration-mismatch",
                ApplicationError::DescriptorViolation(
                    "state-declaration result is not deterministic (contract violation, §19.3/declaration.wit)",
                ),
            ));
        }
        let Some(declared) = first else {
            // 无 declaration 导出 = 无状态组件（0.1 语义保持）。
            return Ok(());
        };
        let stored = wiring
            .store
            .schema_version(installation_id)
            .map_err(ApplicationError::StateStore)?;
        let Some(stored) = stored else {
            // 空 store：无可迁移数据（§41.3 首次写入建立版本）。
            return Ok(());
        };
        let declared_version = StateSchemaVersion::from_u32(declared.schema_version);
        if stored == declared_version {
            return Ok(());
        }
        if declared_version < stored {
            // forward-only（WIT：0.1.0 不定义已提交迁移后的降级）。
            return Err(self.fail_state_schema(
                digest,
                "state-schema-downgrade",
                ApplicationError::StateSchemaDowngrade {
                    installation: installation_id,
                    stored,
                    declared: declared_version,
                },
            ));
        }
        // 声明版本 > 存储版本：触发显式迁移（§20.5/§41.2 协议 4–5 步——
        // guest 调用经 wiring 注入的 runner，宿主侧观测由 runner 映射）。
        let guest = |tx| wiring.guest.run(component, stored, declared_version, tx);
        match wiring
            .migration
            .migrate(installation_id, stored, declared_version, guest)
        {
            // 迁移已原子提交（store 版本推进到声明版本，§41.3）。
            Ok(MigrationOutcome::Migrated { .. }) => Ok(()),
            // 幂等重试（已提交后的重复调用）与空 store 防御分支。
            Ok(MigrationOutcome::AlreadyAtTarget { .. })
            | Ok(MigrationOutcome::NothingToMigrate) => Ok(()),
            // §41.3：guest 失败 → abort 回滚，store 不变 → 激活拒绝，
            // 旧 ComponentVersion 保持激活（§20.5 rollback policy）。
            Ok(MigrationOutcome::RolledBack { from, to, reason }) => Err(self.fail_state_schema(
                digest,
                "state-migration-rolled-back",
                ApplicationError::StateMigrationRejected {
                    installation: installation_id,
                    from,
                    to,
                    reason: reason.audit_label(),
                },
            )),
            // 编排失败（存储 / 审计 / 窗口冲突）→ 升级被阻止。
            Err(error) => Err(self.fail_state_schema(
                digest,
                "state-migration-error",
                ApplicationError::StateMigration(error),
            )),
        }
    }

    /// state-declaration 读取（descriptor-only Store，§19.3 精神）；失败
    /// → candidate Failed（Validated → Failed）。
    fn read_state_declaration(
        &self,
        digest: ContentDigest,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<Option<GuestStateDeclaration>, ApplicationError> {
        self.runtime
            .read_state_declaration(component)
            .map_err(|error| {
                self.fail_candidate(
                    digest,
                    AuditEvent::DescriptorFailed {
                        digest,
                        reason: "state-declaration-call",
                    },
                    ComponentLifecycleEvent::ResolutionFailed,
                    ApplicationError::Runtime(error),
                )
            })
    }

    /// state schema 阶段的拒绝路径（§18.7 fail closed：先写审计，再按
    /// 状态机推进到 Failed，返回原始错误）。审计 reason 沿用
    /// [`AuditEvent::DescriptorFailed`] 的 reason 标签惯例（管线既有
    /// `upgrade-identity-mismatch` 同模式——storage-sqlite 对 AuditEvent
    /// 逐变体穷尽映射，不新增变体）。
    fn fail_state_schema(
        &self,
        digest: ContentDigest,
        reason: &'static str,
        error: ApplicationError,
    ) -> ApplicationError {
        self.fail_candidate(
            digest,
            AuditEvent::DescriptorFailed { digest, reason },
            ComponentLifecycleEvent::ResolutionFailed,
            error,
        )
    }

    /// 构建运行时能力快照（§7.6 / §17.3：grant scope → WASI 能力值；
    /// 非 WASI 能力 0.1.0 无宿主面，仍参与 resolution 与审计）。
    fn build_snapshot(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
        config: &RuntimeConfig,
    ) -> Result<GrantSnapshot, ApplicationError> {
        let mut wasi = WasiCapabilities::empty();
        for grant in grants {
            match &grant.scope {
                GrantScope::WasiPreopen {
                    guest_path,
                    host_path,
                    read,
                    write,
                } => {
                    let guest =
                        GuestPath::new(guest_path).map_err(ApplicationError::GrantInvalid)?;
                    let spec = PreopenDirSpec::new(
                        guest,
                        std::path::PathBuf::from(host_path),
                        FsPerms {
                            read: *read,
                            write: *write,
                        },
                        FsPerms {
                            read: *read,
                            write: *write,
                        },
                    )
                    .map_err(ApplicationError::GrantInvalid)?;
                    wasi.add_preopen(spec)
                        .map_err(ApplicationError::GrantInvalid)?;
                }
                GrantScope::WasiEnv { key, value } => {
                    let spec =
                        EnvVarSpec::new(key, value).map_err(ApplicationError::GrantInvalid)?;
                    wasi.add_env(spec);
                }
                GrantScope::Unscoped | GrantScope::Action { .. } => {}
            }
        }
        Ok(GrantSnapshot {
            installation,
            wasi,
            budget: config.candidate_budget.clone(),
        })
    }

    /// descriptor 身份 / metadata 校验（§19.2 顺序 10 / §19.3）。
    fn validate_identity(
        &self,
        digest: ContentDigest,
        descriptor: &GuestComponentDescriptor,
    ) -> Result<(ComponentId, ComponentVersion), ApplicationError> {
        let fail = |reason: &'static str| {
            self.fail_candidate(
                digest,
                AuditEvent::DescriptorFailed {
                    digest,
                    reason: "invalid-metadata",
                },
                ComponentLifecycleEvent::ValidationFailed,
                ApplicationError::DescriptorViolation(reason),
            )
        };
        let component_id = ComponentId::new(&descriptor.component_id)
            .map_err(|_| fail("component-id is malformed"))?;
        let version =
            ComponentVersion::from_parts(descriptor.major, descriptor.minor, descriptor.patch);
        if descriptor.display_name.is_empty()
            || descriptor.display_name.len() > MAX_DISPLAY_NAME_LEN
        {
            return Err(fail("display-name is empty or exceeds the host-side limit"));
        }
        Ok((component_id, version))
    }

    /// web manifest 交叉校验（§web descriptor 契约：作者声明与二进制
    /// exports 不一致视为 contract violation）。
    fn validate_manifest(
        &self,
        manifest: &Option<WebManifestData>,
        surface: &ContractSurface,
        config: &RuntimeConfig,
        digest: ContentDigest,
        installation_id: InstallationId,
    ) -> Result<(), ApplicationError> {
        let Some(manifest) = manifest else {
            return Ok(());
        };
        if manifest.features.static_assets && !surface.exports_web_assets() {
            return Err(self.fail_activating(
                digest,
                installation_id,
                "web-manifest",
                ApplicationError::ContractViolation(
                    "web descriptor declares static-assets but the binary lacks the assets interface",
                ),
            ));
        }
        if manifest.features.backend_actions && !surface.exports_web_actions() {
            return Err(self.fail_activating(
                digest,
                installation_id,
                "web-manifest",
                ApplicationError::ContractViolation(
                    "web descriptor declares backend-actions but the binary lacks the actions interface",
                ),
            ));
        }
        if manifest.assets.len() > config.max_web_assets {
            return Err(self.fail_activating(
                digest,
                installation_id,
                "web-manifest",
                ApplicationError::ContractViolation(
                    "web asset manifest exceeds the host-side asset limit",
                ),
            ));
        }
        Ok(())
    }

    /// 激活期资产读取与缓存（§6.2 / §21.3：以 ContentDigest + asset path
    /// 为缓存事实；读取 bounded）。
    fn cache_assets(
        &self,
        digest: ContentDigest,
        active: &Arc<dyn ActiveRuntime>,
        manifest: &Option<WebManifestData>,
        config: &RuntimeConfig,
        installation_id: InstallationId,
    ) -> Result<u64, ApplicationError> {
        let Some(manifest) = manifest else {
            return Ok(0);
        };
        let mut cached = 0u64;
        for entry in &manifest.assets {
            if entry.size > config.max_asset_bytes.as_u64() {
                return Err(self.fail_activating(
                    digest,
                    installation_id,
                    "asset-size",
                    ApplicationError::ContractViolation(
                        "asset exceeds the host-side per-asset limit",
                    ),
                ));
            }
            let bytes = active.read_asset(&entry.path).map_err(|error| {
                self.fail_activating(
                    digest,
                    installation_id,
                    "asset-read",
                    ApplicationError::Runtime(error),
                )
            })?;
            if self.assets.register(digest, &entry.path, &bytes) {
                cached += 1;
            }
        }
        Ok(cached)
    }

    /// 0.4.0 Web Application Runtime 激活期阶段（§42.2）：读取
    /// `get-app-descriptor` → [`WebAppService::build_app_declaration`]（
    /// 组装 + 声明期冲突诊断）→ [`WebAppService::validate_contract_surface`]
    /// （features flag 与二进制 exports 交叉校验）。
    ///
    /// - 未接线（composition root 未注入 [`WebAppService`]）= 0.1.0 语义：
    ///   不读取 app-descriptor（返回 `None`）；
    /// - 组件无 app-descriptor 导出 = 0.1-only surface（`Ok(None)`，0.1
    ///   语义保持，无 flag-day，§8.4 精神）；
    /// - 声明读取遵循 §19.3 descriptor 阶段精神（app-descriptor.wit 明文：
    ///   side-effect-free、可重复）：同一 digest 同一 contract version 重复
    ///   调用比对 canonical 结果，不一致 = contract violation；
    /// - 全部失败路径 → candidate Failed（quarantine），当前 Active 不受
    ///   污染（§19.2）。
    fn run_web_app_phase(
        &self,
        digest: ContentDigest,
        installation_id: InstallationId,
        component: &Arc<dyn CompiledWasm>,
        surface: &ContractSurface,
    ) -> Result<Option<AppDeclaration>, ApplicationError> {
        let Some(service) = self.web_app.get() else {
            return Ok(None);
        };
        let guest = self
            .runtime
            .read_app_descriptor(component)
            .map_err(|error| {
                self.fail_activating(
                    digest,
                    installation_id,
                    "app-descriptor",
                    ApplicationError::Runtime(error),
                )
            })?;
        let Some(guest) = guest else {
            // 组件不导出 app-descriptor = 0.1-only surface。
            return Ok(None);
        };
        // §19.3：同一 digest 重复调用比对 canonical 结果。
        let second = self
            .runtime
            .read_app_descriptor(component)
            .map_err(|error| {
                self.fail_activating(
                    digest,
                    installation_id,
                    "app-descriptor",
                    ApplicationError::Runtime(error),
                )
            })?;
        if second.as_ref() != Some(&guest) {
            return Err(self.fail_activating(
                digest,
                installation_id,
                "app-descriptor",
                ApplicationError::DescriptorViolation(
                    "app descriptor result is not deterministic (contract violation, §19.3)",
                ),
            ));
        }
        let declaration = service.build_app_declaration(&guest).map_err(|failure| {
            self.fail_activating(
                digest,
                installation_id,
                "app-descriptor",
                ApplicationError::WebAppDescriptor { source: failure },
            )
        })?;
        service
            .validate_contract_surface(&declaration, surface)
            .map_err(|failure| {
                self.fail_activating(
                    digest,
                    installation_id,
                    "app-descriptor",
                    ApplicationError::WebAppDescriptor { source: failure },
                )
            })?;
        Ok(Some(declaration))
    }

    /// 全新安装的原子激活（§19.2 末步）。
    /// 参数较多（身份 + 运行时 + 清单 + 审计计数），以显式实参保持管线
    /// 步骤的可见性（局部 allow 有原因注释，§26.1）。
    #[allow(clippy::too_many_arguments)]
    fn activate_install(
        &self,
        digest: ContentDigest,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        active: Arc<dyn ActiveRuntime>,
        manifest: Option<WebManifestData>,
        cached: u64,
        web_app_declaration: Option<AppDeclaration>,
        surface: &ContractSurface,
    ) -> Result<PipelineResult, ApplicationError> {
        // 0.2.0：graph records 提交 + 快照原子切换（§40.2）。在任何
        // durable "激活成功" 写入之前执行：失败 → candidate Failed，
        // 无持久化 / 运行时变化。
        self.commit_graph(digest, installation_id, surface)?;
        // §18.7：durable audit 先行（fail closed）。
        self.audit_ok(AuditEvent::ActivationSucceeded {
            installation: installation_id,
            component_id: component_id.clone(),
            version,
            digest,
        })?;
        let asset_count = manifest
            .as_ref()
            .map(|manifest| u64::try_from(manifest.assets.len()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.audit_ok(AuditEvent::WebManifestLoaded {
            installation: installation_id,
            assets: asset_count,
            cached,
        })?;
        let record = InstallationRecord {
            installation_id,
            component_id,
            version,
            active_digest: Some(digest),
            last_known_good_digest: Some(digest),
            state: ComponentLifecycleState::Active,
        };
        self.registry
            .update_installation(&record)
            .map_err(ApplicationError::Registry)?;
        self.transition_candidate(digest, ComponentLifecycleEvent::ReadinessSucceeded)?;
        self.active.swap(
            installation_id,
            Arc::new(ActiveEntry {
                installation: ActiveInstallation {
                    installation_id,
                    component_id: record.component_id.clone(),
                    version: record.version,
                    digest,
                },
                runtime: active,
                manifest,
                web_app: web_app_declaration
                    .map(|declaration| Arc::new(WebAppContext::new(declaration))),
            }),
        )?;
        Ok(PipelineResult::Activated {
            installation: record,
            digest,
        })
    }

    /// 热升级 / 回滚的原子切换（§20.1：swap → 新请求 → 新版本 → drain
    /// 旧版本；§20.2 非 destructive-in-place——candidate 在不破坏现有可用
    /// 版本的前提下验证；§20.3 单指针快照交换）。
    #[allow(clippy::too_many_arguments)]
    fn activate_upgrade(
        &self,
        swap_event: AuditEvent,
        digest: ContentDigest,
        current: InstallationRecord,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        active: Arc<dyn ActiveRuntime>,
        manifest: Option<WebManifestData>,
        cached: u64,
        web_app_declaration: Option<AppDeclaration>,
        config: &RuntimeConfig,
        surface: &ContractSurface,
    ) -> Result<PipelineResult, ApplicationError> {
        let old_digest = current.active_digest.ok_or(ApplicationError::Internal(
            "active installation lacks an active digest",
        ))?;
        if old_digest == digest {
            // 幂等：目标 digest 已是当前 Active（§20 验收：不破坏现状）。
            return Ok(PipelineResult::Activated {
                installation: current,
                digest,
            });
        }
        // 0.2.0：graph records 提交（升级 = 新提供面/需求面整组替换）+ 快照
        // 原子切换（§40.2）。在任何 durable "激活成功" 写入之前执行。
        self.commit_graph(digest, installation_id, surface)?;
        let previous =
            self.active
                .take_previous(installation_id)
                .ok_or(ApplicationError::Internal(
                    "active snapshot misses the previous runtime",
                ))?;

        // §18.7：durable audit 先行（fail closed）。
        self.audit_ok(swap_event)?;
        let asset_count = manifest
            .as_ref()
            .map(|manifest| u64::try_from(manifest.assets.len()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.audit_ok(AuditEvent::WebManifestLoaded {
            installation: installation_id,
            assets: asset_count,
            cached,
        })?;

        // 注册表：旧版本进入 Draining；installation 指向新 digest；
        // 新版本 candidate → Active。
        self.transition_candidate(old_digest, ComponentLifecycleEvent::DrainStarted)?;
        let record = InstallationRecord {
            installation_id,
            component_id,
            version,
            active_digest: Some(digest),
            last_known_good_digest: Some(old_digest),
            state: ComponentLifecycleState::Active,
        };
        self.registry
            .update_installation(&record)
            .map_err(ApplicationError::Registry)?;
        self.transition_candidate(digest, ComponentLifecycleEvent::ReadinessSucceeded)?;

        // §20.3：原子快照交换——单指针交换，新请求 → 新版本（§21.5：
        // UI assets、app descriptor 与 backend exports 随同一
        // ComponentVersion 原子切换）。
        self.active.swap(
            installation_id,
            Arc::new(ActiveEntry {
                installation: ActiveInstallation {
                    installation_id,
                    component_id: record.component_id.clone(),
                    version: record.version,
                    digest,
                },
                runtime: active,
                manifest,
                web_app: web_app_declaration
                    .map(|declaration| Arc::new(WebAppContext::new(declaration))),
            }),
        )?;

        // §20.1 / §20.4：交换后 drain 旧版本（有界 deadline）。
        self.drain_previous(installation_id, old_digest, previous, config)?;

        Ok(PipelineResult::Activated {
            installation: record,
            digest,
        })
    }

    /// 重新激活（§39.2 enable / §12.2：`Disabled → Activating → Active`）。
    ///
    /// 与 [`Pipeline::activate_install`] 同构，但**保留既有
    /// `last_known_good_digest`**（§18.7 rollback retention：停用/重新启用
    /// 不得丢失回滚保留目标），且**没有可 drain 的旧运行句柄**（停用时
    /// 已 drain 并释放 Store 与 Host 资源，§20.4）。readiness 已由管线在
    /// 激活前重新验证（§19.3：enable = 重新激活路径的完整验证，不允许
    /// "跳过验证直接恢复"）。
    #[allow(clippy::too_many_arguments)]
    fn activate_enable(
        &self,
        digest: ContentDigest,
        current: InstallationRecord,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        active: Arc<dyn ActiveRuntime>,
        manifest: Option<WebManifestData>,
        cached: u64,
        web_app_declaration: Option<AppDeclaration>,
        surface: &ContractSurface,
    ) -> Result<PipelineResult, ApplicationError> {
        // 0.2.0：graph records 重新提交（重新激活 = 提供面/需求面重新进入
        // 组合）+ 快照原子切换（§40.2）。在任何 durable "激活成功" 写入
        // 之前执行。
        self.commit_graph(digest, installation_id, surface)?;
        // §18.7：durable audit 先行（fail closed）。
        self.audit_ok(AuditEvent::ActivationSucceeded {
            installation: installation_id,
            component_id: component_id.clone(),
            version,
            digest,
        })?;
        let asset_count = manifest
            .as_ref()
            .map(|manifest| u64::try_from(manifest.assets.len()).unwrap_or(u64::MAX))
            .unwrap_or(0);
        self.audit_ok(AuditEvent::WebManifestLoaded {
            installation: installation_id,
            assets: asset_count,
            cached,
        })?;
        let record = InstallationRecord {
            installation_id,
            component_id,
            version,
            active_digest: Some(digest),
            // §18.7：保留停用前的回滚保留目标。
            last_known_good_digest: current.last_known_good_digest,
            state: ComponentLifecycleState::Active,
        };
        self.registry
            .update_installation(&record)
            .map_err(ApplicationError::Registry)?;
        self.transition_candidate(digest, ComponentLifecycleEvent::ReadinessSucceeded)?;
        self.active.swap(
            installation_id,
            Arc::new(ActiveEntry {
                installation: ActiveInstallation {
                    installation_id,
                    component_id: record.component_id.clone(),
                    version: record.version,
                    digest,
                },
                runtime: active,
                manifest,
                web_app: web_app_declaration
                    .map(|declaration| Arc::new(WebAppContext::new(declaration))),
            }),
        )?;
        Ok(PipelineResult::Activated {
            installation: record,
            digest,
        })
    }

    /// drain 旧版本（§20.4：不接新工作；有界 deadline 内完成；结束后释放
    /// Store 与 Host 资源）。
    ///
    /// 状态转换：`Active → Draining` 已在原子切换前完成（见
    /// [`Pipeline::activate_upgrade`]）；本函数只负责 audit（§18.7
    /// fail-closed）、有界 drain 与 `Draining → Disabled` 终态。
    fn drain_previous(
        &self,
        installation_id: InstallationId,
        digest: ContentDigest,
        previous: Arc<ActiveEntry>,
        config: &RuntimeConfig,
    ) -> Result<(), ApplicationError> {
        self.audit_ok(AuditEvent::DrainStarted {
            installation: installation_id,
            digest,
            deadline_secs: config.drain_deadline.as_secs(),
        })?;
        // §20.4：drain 按值消费运行句柄（Arc<Self> 接收者），drop 释放
        // InstanceSet 与全部 Store。
        Arc::clone(&previous.runtime)
            .drain(config.drain_deadline)
            .map_err(ApplicationError::Runtime)?;
        self.audit_ok(AuditEvent::DrainCompleted {
            installation: installation_id,
            digest,
        })?;
        self.transition_candidate(digest, ComponentLifecycleEvent::DrainCompleted)?;
        Ok(())
    }

    // —— 内部辅助：audit fail-closed 与状态机 ——

    /// 0.2.0：composition 提交（§40.2 graph snapshot atomic switch）——
    /// records 持久化 + graph 快照单指针交换，在管线任何 durable
    /// "激活成功" 写入**之前**执行（§18.5 crash consistency 边界在存储层
    /// 事务；门控/audit 失败发生在落盘前，不产生持久化变化）。返回新图
    /// （运行时层经 `composition.graph()` 读取 `topological_order()` 驱动
    /// 实例化顺序，§40.2 activation ordering）。
    fn commit_graph(
        &self,
        digest: ContentDigest,
        installation_id: InstallationId,
        surface: &ContractSurface,
    ) -> Result<(), ApplicationError> {
        let Some(composition) = self.composition.get() else {
            return Ok(());
        };
        let records = match records_from_surface(installation_id, surface) {
            Ok(records) => records,
            Err(error) => {
                return Err(self.fail_candidate(
                    digest,
                    AuditEvent::ProviderGraphRejected {
                        installation: installation_id,
                        reason: "surface",
                    },
                    ComponentLifecycleEvent::ResolutionFailed,
                    error,
                ));
            }
        };
        // commit 内部重跑 gate（build_candidate）：与门控阶段相同的输入
        // （surface → records 纯函数、store 不变）必然通过；并发变更以
        // typed 错误拒绝。
        composition
            .commit_activation(installation_id, &records)
            .map_err(|error| {
                self.fail_candidate(
                    digest,
                    AuditEvent::ProviderGraphRejected {
                        installation: installation_id,
                        reason: "commit",
                    },
                    ComponentLifecycleEvent::ResolutionFailed,
                    error,
                )
            })?;
        Ok(())
    }

    fn audit_ok(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        self.audit.append(event).map_err(ApplicationError::Audit)
    }

    /// 拒绝路径：先写审计（§18.7 fail closed——audit 失败以 audit 错误
    /// 中止），再返回原始拒绝错误。
    fn reject(&self, event: AuditEvent, error: ApplicationError) -> ApplicationError {
        match self.audit.append(event) {
            Ok(()) => error,
            Err(audit_error) => ApplicationError::Audit(audit_error),
        }
    }

    /// 候选失败路径：先写审计，再按状态机推进到 Failed。
    fn fail_candidate(
        &self,
        digest: ContentDigest,
        event: AuditEvent,
        transition: ComponentLifecycleEvent,
        error: ApplicationError,
    ) -> ApplicationError {
        match self.audit.append(event) {
            Ok(()) => {}
            Err(audit_error) => return ApplicationError::Audit(audit_error),
        }
        match self.transition_candidate(digest, transition) {
            Ok(_) => error,
            Err(transition_error) => transition_error,
        }
    }

    /// Activating 阶段的失败（§19.3：readiness 失败 → Failed）。
    fn fail_activating(
        &self,
        digest: ContentDigest,
        installation_id: InstallationId,
        stage: &'static str,
        error: ApplicationError,
    ) -> ApplicationError {
        self.fail_candidate(
            digest,
            AuditEvent::ActivationFailed {
                installation: installation_id,
                stage,
            },
            ComponentLifecycleEvent::ReadinessFailed,
            error,
        )
    }

    /// 显式状态转换并落盘（§12.2：非法转换返回 typed error）。
    fn transition_candidate(
        &self,
        digest: ContentDigest,
        event: ComponentLifecycleEvent,
    ) -> Result<ComponentLifecycleState, ApplicationError> {
        let record = self
            .registry
            .candidate(digest)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::Internal("candidate record missing"))?;
        let next = record
            .state
            .transition(event)
            .map_err(ApplicationError::Domain)?;
        self.registry
            .update_candidate_state(digest, next)
            .map_err(ApplicationError::Registry)?;
        Ok(next)
    }
}

/// 从二进制 contract surface 推导初步依赖 + 权限需要计划（§19.2 顺序 6；
/// §19.5：0.1.0 的跨 Component import 明确判定为不支持并拒绝激活）。
pub(crate) fn classify_imports(
    surface: &ContractSurface,
) -> Result<Vec<CapabilityId>, ApplicationError> {
    let mut capabilities = Vec::new();
    for import in &surface.imports {
        match ImportClass::normalize(import) {
            ImportClass::Wasi | ImportClass::Operune => {
                capabilities.push(ImportClass::capability_id(import)?);
            }
            ImportClass::Unsupported => {
                let base = import.split('@').next().unwrap_or(import);
                let capability = CapabilityId::new(base).map_err(ApplicationError::Domain)?;
                return Err(ApplicationError::UnsupportedCapability(capability));
            }
        }
    }
    Ok(capabilities)
}

/// 0.2.0 变体（composition 接线时使用）：只推导宿主能力
/// （`wasi:` / `operune:`，§17.5）的权限需求；非宿主 import 属于 provider
/// graph（§40.3 事实源），由 composition 门控校验，不在本分类中拒绝。
pub(crate) fn classify_host_imports(
    surface: &ContractSurface,
) -> Result<Vec<CapabilityId>, ApplicationError> {
    let mut capabilities = Vec::new();
    for import in &surface.imports {
        match ImportClass::normalize(import) {
            ImportClass::Wasi | ImportClass::Operune => {
                capabilities.push(ImportClass::capability_id(import)?);
            }
            ImportClass::Unsupported => {}
        }
    }
    Ok(capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationGuestError;
    use crate::model::{
        GrantScope, RollbackRequest, UpgradeOutcome, UpgradeRequest, WebAssetEntry, WebAssetPath,
        WebManifestData, WebManifestFeatures,
    };
    use crate::ports::StatefulAuditEvent;
    use crate::test_support::{
        Harness, default_descriptor, grant, ok, plain_install_request, some, test_failure,
    };
    use operune_domain::{ComponentVersion, StateKey, StateValue};

    fn harness() -> Harness {
        Harness::new(RuntimeConfig::default())
    }

    #[test]
    fn two_phase_install_happy_path_activates() {
        let harness = harness();
        let bytes = b"v1 bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let outcome = ok(
            harness.install.install(plain_install_request(bytes)),
            "install v1",
        );
        let installation = match outcome {
            InstallOutcome::Activated {
                installation,
                version,
                digest: actual,
            } => {
                assert_eq!(version, ComponentVersion::from_parts(1, 0, 0));
                assert_eq!(actual, digest);
                installation
            }
        };
        // 状态机全程驱动：Installed → Validated → Activating → Active（§12.2）。
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Active)
        );
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.state, ComponentLifecycleState::Active);
        assert_eq!(record.active_digest, Some(digest));
        assert_eq!(record.last_known_good_digest, Some(digest));
        let binding = ok(
            harness.registry.resolve_version(
                &ok(ComponentId::new("demo"), "component id"),
                ComponentVersion::from_parts(1, 0, 0),
            ),
            "version binding",
        );
        assert_eq!(binding.map(|binding| binding.digest), Some(digest));
        // Active 快照（§15.5 / §20.3）。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, digest);
        // 两阶段语义：descriptor 被读取两次（§19.3 确定性比对）。
        assert_eq!(harness.runtime.descriptor_calls(), 2);
        assert_eq!(harness.runtime.compile_calls(), 1);
        assert_eq!(harness.runtime.prepare_calls(), 1);
        assert_eq!(harness.runtime.instantiate_calls(), 1);
        // 审计轨迹（§16.6 / §18.7：不记 secret）。
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::CandidatePersisted { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::IdentityRegistered { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::ActivationSucceeded { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::GrantsApproved { .. }))
        );
    }

    #[test]
    fn install_rejects_oversized_bytes() {
        let config = RuntimeConfig {
            max_component_bytes: ByteSize::from_bytes(8),
            ..RuntimeConfig::default()
        };
        let harness = Harness::new(config);
        let bytes = b"123456789".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(
            matches!(result, Err(ApplicationError::OversizedComponent { .. })),
            "oversized bytes must be rejected: {result:?}"
        );
        // 拒绝路径：不产生 candidate（§19.2：先校验后持久化）。
        assert!(harness.registry.candidate_state(digest).is_none());
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::Oversized,
                    ..
                }
            )
        }));
    }

    #[test]
    fn install_rejects_invalid_bytes() {
        let harness = harness();
        harness.runtime.with_compile_failure();
        let result = harness
            .install
            .install(plain_install_request(b"garbage".to_vec()));
        assert!(
            matches!(result, Err(ApplicationError::InvalidComponent(_))),
            "invalid bytes must be rejected: {result:?}"
        );
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::InvalidBytes,
                    ..
                }
            )
        }));
    }

    #[test]
    fn install_descriptor_mismatch_quarantines() {
        let harness = harness();
        let mut other = default_descriptor();
        other.display_name = "Different".to_owned();
        harness
            .runtime
            .with_descriptors(vec![default_descriptor(), other]);
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(
            matches!(result, Err(ApplicationError::DescriptorViolation(_))),
            "descriptor mismatch must be a contract violation: {result:?}"
        );
        // §19.3：candidate 保持 quarantine/failed。
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::DescriptorMismatch { .. }))
        );
    }

    #[test]
    fn install_prepare_failure_fails_candidate() {
        // 二进制级 link 检查失败（§17.2：不得"先运行，失败时 trap"代替
        // 权限解析）→ resolution 类失败（Validated → Failed）。
        let harness = harness();
        harness.runtime.with_prepare_failure();
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(result.is_err());
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::ResolutionFailed { .. }))
        );
    }

    #[test]
    fn install_readiness_failure_fails_candidate() {
        // §19.3：readiness 验证失败（真实 grant/resource 环境）→
        // Activating → Failed，当前 Active 不受污染。
        let harness = harness();
        harness.runtime.with_readiness_failure();
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(result.is_err());
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::ActivationFailed { .. }))
        );
    }

    #[test]
    fn install_descriptor_failure_fails_candidate() {
        let harness = harness();
        harness.runtime.with_descriptor_failure();
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(result.is_err());
        // §19.3：descriptor 超时 / trap / 超预算 → candidate Failed。
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::DescriptorFailed { .. }))
        );
    }

    #[test]
    fn install_denies_unknown_import() {
        let harness = harness();
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["wasi:cli/run@0.2.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        // deny-by-default（§17.2 / §19.5）：import 未获 grant → 拒绝激活。
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(
            matches!(result, Err(ApplicationError::UnresolvedImport { .. })),
            "ungranted import must be denied: {result:?}"
        );
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::ResolutionFailed { .. }))
        );
    }

    #[test]
    fn install_granted_import_passes_resolution() {
        let harness = harness();
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["wasi:cli/run@0.2.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        let outcome = ok(
            harness.install.install(InstallRequest {
                bytes: b"bytes".to_vec(),
                grants: GrantApproval::Explicit(vec![grant("wasi:cli/run")]),
            }),
            "install with grant",
        );
        // grant 已落盘（§17.5：绑定 InstallationId）。
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        assert_eq!(harness.grants.stored(installation).len(), 1);
    }

    #[test]
    fn install_supply_chain_conflict_blocked() {
        let harness = harness();
        let other_digest = ContentDigest::from_bytes(b"different bytes");
        // 预置：同一逻辑版本已绑定不同 digest（§19.4）。
        ok(
            harness.registry.bind_version(&DigestVersionBinding {
                component_id: ok(ComponentId::new("demo"), "component id"),
                version: ComponentVersion::from_parts(1, 0, 0),
                digest: other_digest,
            }),
            "pre-seed binding",
        );
        let result = harness
            .install
            .install(plain_install_request(b"v1 bytes".to_vec()));
        assert!(
            matches!(result, Err(ApplicationError::SupplyChainConflict { .. })),
            "same logical version with a different digest must be blocked: {result:?}"
        );
        // 既有绑定未被覆盖（不静默覆盖，§19.4）。
        let binding = ok(
            harness.registry.resolve_version(
                &ok(ComponentId::new("demo"), "component id"),
                ComponentVersion::from_parts(1, 0, 0),
            ),
            "version binding",
        );
        assert_eq!(binding.map(|binding| binding.digest), Some(other_digest));
        assert!(harness.active.is_empty());
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::VersionConflict { .. }))
        );
    }

    #[test]
    fn install_rejects_invalid_metadata() {
        let harness = harness();
        let mut invalid = default_descriptor();
        invalid.display_name = String::new(); // 空 display-name = malformed（WIT 契约）
        // 两次调用都返回同一非法 descriptor（通过 §19.3 确定性比对后命中
        // metadata 校验）。
        let invalid_two = invalid.clone();
        harness.runtime.with_descriptors(vec![invalid, invalid_two]);
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(result.is_err());
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::DescriptorFailed { .. }))
        );
    }

    #[test]
    fn install_missing_operune_descriptor_export_rejected() {
        let harness = harness();
        // 无 operune:component/descriptor 导出（§19.2 必需契约）。
        harness.runtime.with_surface(ContractSurface {
            imports: Vec::new(),
            exports: Vec::new(),
        });
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(
            matches!(result, Err(ApplicationError::ContractViolation(_))),
            "missing descriptor export must be rejected: {result:?}"
        );
        // 契约面检查先于持久化（§19.2 顺序 4–7）。
        assert!(harness.registry.candidate_state(digest).is_none());
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::MissingComponentDescriptor,
                    ..
                }
            )
        }));
    }

    #[test]
    fn install_unsupported_component_to_component_import_rejected() {
        let harness = harness();
        // 0.1.0 明确不支持跨 Component import（§19.5：0.2 Provider Graph）。
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["acme:provider/widget@1.0.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        let result = harness
            .install
            .install(plain_install_request(b"bytes".to_vec()));
        assert!(
            matches!(result, Err(ApplicationError::UnsupportedCapability(_))),
            "component-to-component imports must be rejected: {result:?}"
        );
        assert!(harness.active.is_empty());
    }

    #[test]
    fn install_requires_explicit_grants() {
        let harness = harness();
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(InstallRequest {
            bytes,
            grants: GrantApproval::ReuseExisting,
        });
        assert!(
            matches!(result, Err(ApplicationError::GrantApprovalRequired(_))),
            "fresh install must require explicit grants: {result:?}"
        );
        // 拒绝发生在任何持久化之前。
        assert!(harness.registry.candidate_state(digest).is_none());
    }

    #[test]
    fn web_manifest_feature_mismatch_fails_activation() {
        let harness = harness();
        // 声明 backend-actions，但二进制没有 actions 导出（§web descriptor
        // 契约：作者声明与二进制 exports 不一致 = contract violation）。
        harness.runtime.with_surface(ContractSurface {
            imports: Vec::new(),
            exports: vec!["descriptor".to_owned()],
        });
        harness.runtime.with_manifest(Some(WebManifestData {
            entry: ok(WebAssetPath::new("/index.html"), "entry"),
            features: WebManifestFeatures {
                static_assets: false,
                backend_actions: true,
            },
            assets: Vec::new(),
        }));
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(result.is_err());
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::ActivationFailed {
                    stage: "web-manifest",
                    ..
                }
            )
        }));
    }

    #[test]
    fn web_asset_read_and_cache_at_activation() {
        let harness = harness();
        harness.runtime.with_surface(ContractSurface {
            imports: Vec::new(),
            exports: vec![
                "descriptor".to_owned(),
                "assets".to_owned(),
                "actions".to_owned(),
            ],
        });
        harness.runtime.with_manifest(Some(WebManifestData {
            entry: ok(WebAssetPath::new("/index.html"), "entry"),
            features: WebManifestFeatures {
                static_assets: true,
                backend_actions: true,
            },
            assets: vec![WebAssetEntry {
                path: ok(WebAssetPath::new("/index.html"), "asset path"),
                size: 5,
                content_type: Some("text/html".to_owned()),
            }],
        }));
        harness.runtime.with_asset("/index.html", b"hello".to_vec());
        let bytes = b"bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let outcome = ok(
            harness.install.install(plain_install_request(bytes)),
            "install web component",
        );
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        // 资产以 ContentDigest + asset path 为缓存事实（§6.2 / §21.3）。
        let cached = harness
            .assets
            .get(digest, &ok(WebAssetPath::new("/index.html"), "path"));
        assert_eq!(cached.as_deref().map(|b| b.as_slice()), Some(&b"hello"[..]));
        // 缓存命中路径：不再执行 Wasm（§6.2）。
        let response = ok(
            harness
                .web
                .read_asset(installation, &ok(WebAssetPath::new("/index.html"), "path")),
            "read asset",
        );
        assert_eq!(response.bytes.as_slice(), b"hello");
        assert_eq!(response.content_type.as_deref(), Some("text/html"));
        assert_eq!(harness.runtime.asset_reads(), 1);
        // 审计：WebManifestLoaded（§21.3）。
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::WebManifestLoaded {
                    assets: 1,
                    cached: 1,
                    ..
                }
            )
        }));
    }

    #[test]
    fn asset_cache_bounded_by_entry_cap() {
        let config = RuntimeConfig {
            max_web_assets: 1,
            ..RuntimeConfig::default()
        };
        let cache = ok(AssetCache::new(&config), "asset cache");
        let digest = ContentDigest::from_bytes(b"d");
        assert!(cache.register(digest, &ok(WebAssetPath::new("/a"), "a"), b"1"));
        // 超出条目上限 → admission control 拒绝（§18.7），不驱逐既有条目。
        assert!(!cache.register(digest, &ok(WebAssetPath::new("/b"), "b"), b"2"));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn grant_scope_env_value_never_in_audit() {
        // §16.6：环境变量 grant 的 value 不得进入审计。
        let harness = harness();
        let request = InstallRequest {
            bytes: b"bytes".to_vec(),
            grants: GrantApproval::Explicit(vec![InstallationGrant {
                capability: ok(CapabilityId::new("operune:env"), "capability"),
                scope: GrantScope::WasiEnv {
                    key: "TOKEN".to_owned(),
                    value: "super-secret-value".to_owned(),
                },
            }]),
        };
        ok(harness.install.install(request), "install with env grant");
        let events = harness.audit.events();
        for event in &events {
            let serialized = match serde_json::to_string(event) {
                Ok(serialized) => serialized,
                Err(_) => continue,
            };
            assert!(
                !serialized.contains("super-secret-value"),
                "audit must not contain env grant values (§16.6): {serialized}"
            );
        }
    }

    // ------------------------------------------------------------------
    // 0.2.0 composition 接线（§40）：graph 门控与快照切换的管线集成
    // ------------------------------------------------------------------

    /// provider 组件 surface（导出 acme:svc/checkout@1.0.0）。
    fn provider_surface(version: &str) -> ContractSurface {
        ContractSurface {
            imports: vec!["wasi:cli/run@0.2.0".to_owned()],
            exports: vec![
                "descriptor".to_owned(),
                format!("acme:svc/checkout@{version}"),
            ],
        }
    }

    /// consumer 组件 surface（导入 acme:svc/checkout@1.0.0）。
    fn consumer_surface() -> ContractSurface {
        ContractSurface {
            imports: vec![
                "wasi:cli/run@0.2.0".to_owned(),
                "acme:svc/checkout@1.0.0".to_owned(),
            ],
            exports: vec!["descriptor".to_owned()],
        }
    }

    /// 全 0.2.0 流程：composition 接线 + provider/consumer 表面。
    fn composition_harness() -> Harness {
        Harness::with_composition(RuntimeConfig::default())
    }

    /// 携带 wasi:cli/run grant 的安装请求（composition 测试的组件表面
    /// 都带宿主 import，须先满足 §17.5 grant 才能走到 graph 门控）。
    fn graph_install_request(bytes: Vec<u8>) -> InstallRequest {
        InstallRequest {
            bytes,
            grants: GrantApproval::Explicit(vec![grant("wasi:cli/run")]),
        }
    }

    /// consumer 组件 descriptor（独立逻辑身份，避免与 provider 的
    /// demo 1.0.0 绑定冲突，§19.4）。
    fn consumer_descriptor() -> crate::contract::GuestComponentDescriptor {
        crate::contract::GuestComponentDescriptor {
            component_id: "demo-consumer".to_owned(),
            major: 1,
            minor: 0,
            patch: 0,
            display_name: "Demo Consumer".to_owned(),
            author: None,
        }
    }

    /// provider v2 descriptor（同一逻辑产品的新版本，§20 升级语义）。
    fn provider_v2_descriptor() -> crate::contract::GuestComponentDescriptor {
        crate::contract::GuestComponentDescriptor {
            component_id: "demo".to_owned(),
            major: 2,
            minor: 0,
            patch: 0,
            display_name: "Demo Component".to_owned(),
            author: None,
        }
    }

    /// consumer v2 descriptor（consumer 升级到新版本，§20）。
    fn consumer_v2_descriptor() -> crate::contract::GuestComponentDescriptor {
        crate::contract::GuestComponentDescriptor {
            component_id: "demo-consumer".to_owned(),
            major: 2,
            minor: 0,
            patch: 0,
            display_name: "Demo Consumer".to_owned(),
            author: None,
        }
    }

    #[test]
    fn composition_wired_install_commits_graph_records() {
        // §40.2：composition 接线后，组件激活 = 0.1 管线 + graph records
        // 提交 + 快照原子切换。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let bytes = b"provider bytes".to_vec();
        let outcome = ok(
            harness
                .install
                .install(graph_install_request(bytes.clone())),
            "install provider",
        );
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        // graph 快照已切换：provider 在图中，激活顺序含该安装。
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        assert!(
            graph
                .providers()
                .any(|node| node.installation() == installation)
        );
        assert_eq!(graph.topological_order(), &[installation]);
        // records 已持久化（恢复输入）。
        assert!(harness.graph_store.provider(installation).is_some());
        // 宿主 import（wasi:）仍走 0.1 grant 路径：grant 已按 §17.5 落盘。
        assert_eq!(harness.grants.stored(installation).len(), 1);
    }

    #[test]
    fn composition_wired_consumer_without_provider_is_rejected() {
        // §40.2 activation ordering：provider 未先激活时，consumer 的安装
        // 被缺失 provider 诊断拒绝；candidate Failed，Active 快照不受污染。
        let harness = composition_harness();
        harness.runtime.with_surface(consumer_surface());
        let bytes = b"consumer bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(graph_install_request(bytes));
        match result {
            Err(ApplicationError::ProviderGraphResolution { source }) => {
                assert!(
                    matches!(
                        source,
                        operune_domain::ProviderGraphError::MissingProvider { .. }
                    ),
                    "expected missing provider diagnostics: {source}"
                );
            }
            other => test_failure(format_args!(
                "consumer without provider must be rejected: {other:?}"
            )),
        }
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        // 门控拒绝已审计（§18.7 fail-closed 语义）。
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::ProviderGraphRejected { .. }))
        );
        // 未提交任何 records（gate 在落盘前）。
        assert_eq!(harness.graph_store.count(), 0);
    }

    #[test]
    fn composition_wired_consumer_activates_after_provider() {
        // provider 先激活 → consumer 后激活：图按拓扑序解析。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let provider_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"provider bytes".to_vec())),
            "install provider",
        );
        let provider_installation = match provider_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        harness
            .runtime
            .with_surface_for(b"consumer bytes", consumer_surface());
        harness
            .runtime
            .with_descriptor_for(b"consumer bytes", consumer_descriptor());
        let consumer_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"consumer bytes".to_vec())),
            "install consumer",
        );
        let consumer_installation = match consumer_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        // §40.2 activation ordering：provider 先于 consumer。
        assert_eq!(
            graph.topological_order(),
            &[provider_installation, consumer_installation]
        );
        assert!(harness.active.get(consumer_installation).is_some());
    }

    #[test]
    fn composition_wired_0_1_semantics_for_host_only_components() {
        // composition 接线后，纯宿主组件（无 graph 参与）行为与 0.1 相同：
        // 激活成功、无 records 提交、图不变（空）。
        let harness = composition_harness();
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["wasi:cli/run@0.2.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        let outcome = ok(
            harness
                .install
                .install(graph_install_request(b"plain bytes".to_vec())),
            "install plain component",
        );
        assert!(matches!(outcome, InstallOutcome::Activated { .. }));
        assert_eq!(harness.graph_store.count(), 0);
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        assert_eq!(graph.providers().count(), 0);
    }

    #[test]
    fn composition_wired_breaking_provider_upgrade_rejected() {
        // §40.2 provider upgrade 前 consumer 兼容分析门控：破坏性升级被
        // 拒绝，v1 保持 active（graph 快照未切换）。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let provider_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"provider v1".to_vec())),
            "install provider v1",
        );
        let provider_installation = match provider_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        harness
            .runtime
            .with_surface_for(b"consumer bytes", consumer_surface());
        harness
            .runtime
            .with_descriptor_for(b"consumer bytes", consumer_descriptor());
        ok(
            harness
                .install
                .install(graph_install_request(b"consumer bytes".to_vec())),
            "install consumer",
        );
        // provider v2：移除 checkout（只导出 analytics）→ 直接 consumer 破坏。
        harness.runtime.with_surface_for(
            b"provider v2",
            ContractSurface {
                imports: vec!["wasi:cli/run@0.2.0".to_owned()],
                exports: vec![
                    "descriptor".to_owned(),
                    "acme:svc/analytics@0.1.0".to_owned(),
                ],
            },
        );
        harness
            .runtime
            .with_descriptor_for(b"provider v2", provider_v2_descriptor());
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation: provider_installation,
            bytes: b"provider v2".to_vec(),
            grants: GrantApproval::ReuseExisting,
        });
        match result {
            Err(ApplicationError::ProviderUpgradeIncompatible {
                installation,
                report,
            }) => {
                assert!(!report.is_safe());
                assert_eq!(report.impacts().len(), 1);
                assert!(
                    report.impacts()[0].requirement().interface().as_str() == "checkout",
                    "impact must name the checkout requirement"
                );
                // 影响面含被破坏的 consumer（diagnostics 向上传）。
                assert!(report.impacts()[0].consumer() != installation);
            }
            other => test_failure(format_args!(
                "breaking provider upgrade must be rejected: {other:?}"
            )),
        }
        // v1 仍在图与运行时（快照未切换）。
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        assert_eq!(graph.edges().count(), 1);
        assert!(!harness.active.is_empty());
    }

    #[test]
    fn composition_wired_safe_provider_upgrade_swaps_graph() {
        // 同 major 内升级（1.0.0 → 1.2.0）：consumer 仍满足 → 允许切换。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let provider_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"provider v1".to_vec())),
            "install provider v1",
        );
        let provider_installation = match provider_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        harness
            .runtime
            .with_surface_for(b"consumer bytes", consumer_surface());
        harness
            .runtime
            .with_descriptor_for(b"consumer bytes", consumer_descriptor());
        ok(
            harness
                .install
                .install(graph_install_request(b"consumer bytes".to_vec())),
            "install consumer",
        );
        harness
            .runtime
            .with_surface_for(b"provider v2", provider_surface("1.2.0"));
        harness
            .runtime
            .with_descriptor_for(b"provider v2", provider_v2_descriptor());
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation: provider_installation,
                bytes: b"provider v2".to_vec(),
                grants: GrantApproval::ReuseExisting,
            }),
            "safe provider upgrade",
        );
        assert!(matches!(outcome, UpgradeOutcome::Swapped { .. }));
        // 快照已切换：edge 解析到 1.2.0。
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        let edge = some(
            graph
                .edges()
                .find(|edge| edge.consumer() != provider_installation),
            "consumer edge",
        );
        assert_eq!(
            edge.provided().version(),
            ComponentVersion::from_parts(1, 2, 0)
        );
    }

    #[test]
    fn composition_wired_consumer_upgrade_to_missing_provider_rejected() {
        // consumer 升级引入不可解析的新需求 → 全量重建门控拒绝；v1 保持。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let provider_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"provider bytes".to_vec())),
            "install provider",
        );
        let provider_installation = match provider_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        harness
            .runtime
            .with_surface_for(b"consumer v1", consumer_surface());
        harness
            .runtime
            .with_descriptor_for(b"consumer v1", consumer_descriptor());
        ok(
            harness
                .install
                .install(graph_install_request(b"consumer v1".to_vec())),
            "install consumer v1",
        );
        // consumer 安装实例 = 图中唯一非 provider 的边（consumer 端）。
        let graph_before = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        let consumer_installation = graph_before
            .edges()
            .find(|edge| edge.consumer() != provider_installation)
            .map(|edge| edge.consumer())
            .unwrap_or_else(|| test_failure("consumer edge missing"));
        harness.runtime.with_surface_for(
            b"consumer v2",
            ContractSurface {
                imports: vec![
                    "wasi:cli/run@0.2.0".to_owned(),
                    "acme:svc/analytics@1.0.0".to_owned(),
                ],
                exports: vec!["descriptor".to_owned()],
            },
        );
        harness
            .runtime
            .with_descriptor_for(b"consumer v2", consumer_v2_descriptor());
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation: consumer_installation,
            bytes: b"consumer v2".to_vec(),
            grants: GrantApproval::ReuseExisting,
        });
        assert!(
            matches!(
                result,
                Err(ApplicationError::ProviderGraphResolution { .. })
            ),
            "consumer upgrade to missing provider must be rejected: {result:?}"
        );
        // v1 快照保持。
        let graph = match &harness.composition {
            Some(composition) => composition.graph(),
            None => test_failure("composition must be wired"),
        };
        assert_eq!(graph.edges().count(), 1);
    }

    #[test]
    fn composition_wired_rollback_swaps_graph_records() {
        // 回滚 provider 到 v1：graph records 整组替换为旧版本的提供面。
        let harness = composition_harness();
        harness.runtime.with_surface(provider_surface("1.0.0"));
        let provider_outcome = ok(
            harness
                .install
                .install(graph_install_request(b"provider v1".to_vec())),
            "install provider v1",
        );
        let provider_installation = match provider_outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        harness
            .runtime
            .with_surface_for(b"provider v2", provider_surface("1.2.0"));
        harness
            .runtime
            .with_descriptor_for(b"provider v2", provider_v2_descriptor());
        ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation: provider_installation,
                bytes: b"provider v2".to_vec(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade provider v2",
        );
        ok(
            harness.upgrade.rollback(RollbackRequest {
                installation: provider_installation,
            }),
            "rollback provider",
        );
        let stored = some(
            harness.graph_store.provider(provider_installation),
            "rolled back record",
        );
        // 回滚目标 digest 的字节 → surface（v1）→ records（checkout@1.0.0）。
        assert_eq!(
            stored.provided().iter().next().map(|id| id.version()),
            Some(ComponentVersion::from_parts(1, 0, 0))
        );
    }

    // ------------------------------------------------------------------
    // 0.3.0 state schema 阶段（§20.5 / §41.2）：upgrade 管线触发显式迁移
    // 的组合编排（§41.3 1g——state-declaration.schema-version 与存储版本
    // 比较 → 迁移路径）。
    // ------------------------------------------------------------------

    const V1: StateSchemaVersion = StateSchemaVersion::from_u32(1);
    const V2: StateSchemaVersion = StateSchemaVersion::from_u32(2);

    fn state_key(name: &str) -> StateKey {
        ok(StateKey::new(name), "state key")
    }

    fn state_value(bytes: &[u8]) -> StateValue {
        ok(StateValue::new(bytes.to_vec()), "state value")
    }

    /// state-declaration 夹具（展示名 + 声明版本）。
    fn declaration(schema_version: u32) -> crate::contract::GuestStateDeclaration {
        crate::contract::GuestStateDeclaration {
            name: Some("Demo State".to_owned()),
            schema_version,
        }
    }

    /// v2 字节（stateful 升级测试的升级目标）。
    fn state_v2_bytes() -> Vec<u8> {
        b"v2 state bytes".to_vec()
    }

    /// v1（demo 1.0.0，携带 state-declaration）安装并激活；返回
    /// installation id 与 v1 digest。空 store 下声明版本不触发迁移
    ///（§41.3：版本由首次写入建立）。
    fn activate_v1_stateful(
        harness: &Harness,
        schema_version: u32,
    ) -> (InstallationId, ContentDigest) {
        harness
            .runtime
            .with_declaration_for(b"v1 bytes", declaration(schema_version));
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"v1 bytes".to_vec())),
            "install stateful v1",
        );
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        (installation, ContentDigest::from_bytes(b"v1 bytes"))
    }

    /// 把安装实例的 store 预置到指定版本（模拟 v1 运行期写入建立版本，
    /// §41.3 首写建立语义）。
    fn seed_store_version(
        harness: &Harness,
        installation: InstallationId,
        version: StateSchemaVersion,
    ) {
        ok(
            harness.state_store.put(
                installation,
                &state_key("state"),
                version,
                &state_value(b"v1-shape"),
            ),
            "seed store version",
        );
    }

    #[test]
    fn state_declaration_equal_to_store_activates_without_migration() {
        // 声明版本 == 存储版本 → 直接激活（§20.5：不进入迁移路径）。
        let harness = harness();
        let (installation, v1_digest) = activate_v1_stateful(&harness, 1);
        seed_store_version(&harness, installation, V1);
        harness
            .runtime
            .with_descriptor_for(&state_v2_bytes(), provider_v2_descriptor());
        harness
            .runtime
            .with_declaration_for(&state_v2_bytes(), declaration(1));
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: state_v2_bytes(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade with equal declared schema version",
        );
        assert!(matches!(outcome, UpgradeOutcome::Swapped { .. }));
        // 未触发迁移（runner 零调用）；store 版本不变。
        assert!(harness.migration_runner.calls().is_empty());
        assert_eq!(harness.state_store.version_of(installation), Some(V1));
        // v1 正常 drain（§20.4）。
        assert_eq!(
            harness.registry.candidate_state(v1_digest),
            Some(ComponentLifecycleState::Disabled)
        );
    }

    #[test]
    fn state_declaration_above_store_triggers_migration_then_activates() {
        // 声明版本 > 存储版本 → 显式迁移触发（§20.5/§41.2）→ 原子提交
        //（store 推进到声明版本，§41.3）→ 激活继续。
        let harness = harness();
        let (installation, v1_digest) = activate_v1_stateful(&harness, 1);
        seed_store_version(&harness, installation, V1);
        let v2_bytes = state_v2_bytes();
        harness
            .runtime
            .with_descriptor_for(&v2_bytes, provider_v2_descriptor());
        harness
            .runtime
            .with_declaration_for(&v2_bytes, declaration(2));
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes.clone(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade with higher declared schema version",
        );
        assert!(matches!(outcome, UpgradeOutcome::Swapped { .. }));
        // 迁移以 (存储版本, 声明版本) 触发一次。
        assert_eq!(harness.migration_runner.calls(), vec![(V1, V2)]);
        // 声明读取遵循 §19.3 双重调用惯例（v1 安装 2 次 + v2 升级 2 次，
        // 确定性比对，declaration.wit 明文）。
        assert_eq!(harness.runtime.declaration_calls(), 4);
        // store 版本推进到声明版本（§41.3 同事务原子推进）。
        assert_eq!(harness.state_store.version_of(installation), Some(V2));
        // 迁移审计（metadata-only，§41.2 state audit）。
        assert!(harness.state_audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationStarted { from, to, .. }
                if *from == V1 && *to == V2
        )));
        assert!(harness.state_audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationCommitted { from, to, .. }
                if *from == V1 && *to == V2
        )));
        // 激活完成：Active 快照指向 v2；v1 已 drain（§20.4）。
        let v2_digest = ContentDigest::from_bytes(&v2_bytes);
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v2_digest);
        assert_eq!(
            harness.registry.candidate_state(v1_digest),
            Some(ComponentLifecycleState::Disabled)
        );
    }

    #[test]
    fn state_migration_guest_failure_rolls_back_and_rejects_activation() {
        // §41.3：guest 迁移失败 → abort 回滚，store 不变；激活拒绝，
        // 旧 ComponentVersion 保持激活（§20.5 rollback policy）。
        let harness = harness();
        let (installation, v1_digest) = activate_v1_stateful(&harness, 1);
        seed_store_version(&harness, installation, V1);
        harness
            .migration_runner
            .with_guest_result(Err(MigrationGuestError::MalformedSource));
        let v2_bytes = state_v2_bytes();
        harness
            .runtime
            .with_descriptor_for(&v2_bytes, provider_v2_descriptor());
        harness
            .runtime
            .with_declaration_for(&v2_bytes, declaration(2));
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation,
            bytes: v2_bytes.clone(),
            grants: GrantApproval::ReuseExisting,
        });
        match result {
            Err(ApplicationError::StateMigrationRejected {
                from, to, reason, ..
            }) => {
                assert_eq!(from, V1);
                assert_eq!(to, V2);
                assert_eq!(reason, "malformed-source");
            }
            other => test_failure(format_args!(
                "guest migration failure must reject activation: {other:?}"
            )),
        }
        // store 不变（§20.5 rollback policy）。
        assert_eq!(harness.state_store.version_of(installation), Some(V1));
        // v1 保持激活，未被 drain（§20.2 非 destructive-in-place）。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v1_digest);
        assert!(harness.runtime.drains().is_empty());
        // v2 candidate Failed（§19.2：任何一步失败不得污染当前 Active）。
        assert_eq!(
            harness
                .registry
                .candidate_state(ContentDigest::from_bytes(&v2_bytes)),
            Some(ComponentLifecycleState::Failed)
        );
        // 迁移回滚审计（stateful 面）+ 管线拒绝审计（§18.7 fail closed）。
        assert!(harness.state_audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationRolledBack { reason, .. }
                if *reason == "malformed-source"
        )));
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::DescriptorFailed {
                    reason: "state-migration-rolled-back",
                    ..
                }
            )
        }));
    }

    #[test]
    fn state_declaration_below_store_rejected_forward_only() {
        // 声明版本 < 存储版本 → forward-only 拒绝（WIT：0.1.0 不定义已
        // 提交迁移后的降级）；不触发迁移，v1 保持激活。
        let harness = harness();
        let (installation, v1_digest) = activate_v1_stateful(&harness, 2);
        seed_store_version(&harness, installation, V2);
        let v2_bytes = state_v2_bytes();
        harness
            .runtime
            .with_descriptor_for(&v2_bytes, provider_v2_descriptor());
        harness
            .runtime
            .with_declaration_for(&v2_bytes, declaration(1));
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation,
            bytes: v2_bytes.clone(),
            grants: GrantApproval::ReuseExisting,
        });
        match result {
            Err(ApplicationError::StateSchemaDowngrade {
                stored, declared, ..
            }) => {
                assert_eq!(stored, V2);
                assert_eq!(declared, V1);
            }
            other => test_failure(format_args!(
                "declared-below-stored must be rejected: {other:?}"
            )),
        }
        // 未触发迁移；store 不变；v1 保持激活。
        assert!(harness.migration_runner.calls().is_empty());
        assert_eq!(harness.state_store.version_of(installation), Some(V2));
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v1_digest);
        assert_eq!(
            harness
                .registry
                .candidate_state(ContentDigest::from_bytes(&v2_bytes)),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::DescriptorFailed {
                    reason: "state-schema-downgrade",
                    ..
                }
            )
        }));
    }

    #[test]
    fn stateful_upgrade_without_declaration_keeps_stateless_path() {
        // 无 state-declaration 导出 = 无状态组件：0.1 语义保持（§7.3
        // stateless 边界）——不读取声明、不触发迁移、直接激活。
        let harness = harness();
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"v1 bytes".to_vec())),
            "install stateless v1",
        );
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        let v1_digest = ContentDigest::from_bytes(b"v1 bytes");
        seed_store_version(&harness, installation, V1);
        let v2_bytes = state_v2_bytes();
        harness
            .runtime
            .with_descriptor_for(&v2_bytes, provider_v2_descriptor());
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes,
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade without state declaration",
        );
        assert!(matches!(outcome, UpgradeOutcome::Swapped { .. }));
        // 无迁移触发；store 版本不变（管线不触碰 state）；v1 正常 drain。
        assert!(harness.migration_runner.calls().is_empty());
        assert_eq!(harness.state_store.version_of(installation), Some(V1));
        assert_eq!(
            harness.registry.candidate_state(v1_digest),
            Some(ComponentLifecycleState::Disabled)
        );
    }

    #[test]
    fn fresh_install_with_declaration_and_empty_store_activates_directly() {
        // 空 store（首次安装）：无可迁移数据（§41.3 首写建立版本语义）
        // ——声明版本不触发迁移，激活直接成功。
        let harness = harness();
        harness
            .runtime
            .with_declaration_for(b"fresh stateful", declaration(2));
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"fresh stateful".to_vec())),
            "fresh install with declaration",
        );
        let installation = match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        };
        // 无迁移触发；store 保持空（版本由首次写入建立）。
        assert!(harness.migration_runner.calls().is_empty());
        assert_eq!(harness.state_store.version_of(installation), None);
    }

    #[test]
    fn state_declaration_non_deterministic_reads_reject_candidate() {
        // §19.3 确定性（declaration.wit 明文）：同一 digest 同一 contract
        // version 的重复调用必须返回同一 canonical 结果——不一致 =
        // contract violation，candidate 保持 quarantine/failed。
        let harness = harness();
        harness
            .runtime
            .with_declarations(vec![declaration(1), declaration(2)]);
        let bytes = b"non-deterministic declaration".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        let result = harness.install.install(plain_install_request(bytes));
        assert!(
            matches!(result, Err(ApplicationError::DescriptorViolation(_))),
            "non-deterministic state-declaration must be a contract violation: {result:?}"
        );
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Failed)
        );
        assert!(harness.active.is_empty());
        assert!(harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::DescriptorFailed {
                    reason: "state-declaration-mismatch",
                    ..
                }
            )
        }));
    }
}
