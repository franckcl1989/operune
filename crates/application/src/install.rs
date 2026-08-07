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

use std::sync::Arc;

use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleEvent, ComponentLifecycleState,
    ComponentVersion, ContentDigest, InstallationId,
};
use operune_runtime_wasi_p2::capability::{
    EnvVarSpec, FsPerms, GuestPath, PreopenDirSpec, WasiCapabilities,
};

use crate::active::{ActiveEntry, ActiveInstallation, ActiveRuntimeRegistry};
use crate::contract::GuestComponentDescriptor;
use crate::error::ApplicationError;
use crate::model::{
    CandidateRecord, ContractSurface, DigestVersionBinding, GrantApproval, GrantScope,
    GrantSnapshot, ImportClass, InstallOutcome, InstallRequest, InstallationGrant,
    InstallationRecord, PipelineTarget, RuntimeConfig, WebManifestData,
};
use crate::ports::{
    AuditEvent, AuditPort, ComponentRegistryPort, ConfigPort, GrantStorePort, RegistryError,
    RejectReason,
};
use crate::runtime::{ActiveRuntime, RuntimePlan, WasmRuntime};
use crate::web::AssetCache;

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
            PipelineTarget::Upgrade { current } | PipelineTarget::Rollback { current } => {
                Some(current.clone())
            }
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

        // 初步依赖 + 权限需要计划（§19.2 顺序 6）。跨 Component import
        // （0.2 Provider Graph 之外）0.1.0 明确判定为不支持并拒绝（§19.5）。
        let required = match classify_imports(&surface) {
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

        // §20：升级 / 回滚目标必须是同一逻辑产品（ComponentId 不变）。
        if let PipelineTarget::Upgrade { current } | PipelineTarget::Rollback { current, .. } =
            &target
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
                &config,
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
                &config,
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
                PipelineTarget::Upgrade { current } | PipelineTarget::Rollback { current, .. } => {
                    self.grants
                        .grants_for(current.installation_id)
                        .map_err(ApplicationError::Grants)
                }
            },
        }
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
    ) -> Result<PipelineResult, ApplicationError> {
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
        config: &RuntimeConfig,
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
        // UI assets 与 backend exports 随同一 ComponentVersion 原子切换）。
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
            }),
        )?;

        // §20.1 / §20.4：交换后 drain 旧版本（有界 deadline）。
        self.drain_previous(installation_id, old_digest, previous, config)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        GrantScope, WebAssetEntry, WebAssetPath, WebManifestData, WebManifestFeatures,
    };
    use crate::test_support::{
        Harness, default_descriptor, grant, ok, plain_install_request, some,
    };
    use operune_domain::ComponentVersion;

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
}
