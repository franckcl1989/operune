//! application 层 conformance 测试（§19 两阶段安装 / §17.2 deny-by-default /
//! §19.5 link 期拒绝 / §7.6 显式能力授予 / §39.4 非法输入与未授权 import）。
//!
//! 两个层面：
//!
//! 1. **`WasmtimeRuntime` 直接测试**（§24.2 编排层公开 API）：二进制级
//!    enforce——零 grant 下未知 import 以确定性 link 错误拒绝
//!    （§17.2/§19.5，不"先运行，失败时 trap"）；显式 grant 下同一组件
//!    解析 + 实例化 + readiness 成功（能力门控，§7.6）；preopen 能力
//!    fail closed（§17.2）。
//! 2. **`InstallService` 全管线测试**：真实 `WasmtimeRuntime` + conformance
//!    自有的内存 fake ports（`ComponentRegistryPort` / `GrantStorePort` /
//!    `AuditPort` / `ConfigPort`），把 §30 字节类夹具接入两阶段安装——
//!    非法字节 / 缺契约导出 / 超大小输入在正确阶段被拒绝且**不产生
//!    candidate**（§19.2 quarantine 语义，§32 oversized 提前拒绝）。
//!
//! 全管线 happy path（真实 descriptor 导出）属 WIT guest 夹具——本机
//! 工具链缺口，见 [`super::gaps`]；descriptor 驱动的拒绝路径（
//! `UnresolvedImport` / `RequiresApproval`）同样待工具链就绪后补充。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use operune_application::{
    ActiveRuntimeRegistry, ApplicationError, AssetCache, AuditError, AuditEvent, AuditPort,
    ComponentRegistryPort, ConfigError, ConfigPort, GrantApproval, GrantError, GrantSnapshot,
    GrantStorePort, InstallRequest, InstallService, InstallationGrant, RegistryError,
    RuntimeConfig, RuntimeExecutionError, RuntimePlan, WasmRuntime, WasmtimeRuntime,
    ports::RejectReason,
};
use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest,
    InstallationId,
};
use operune_runtime_wasi_p2::capability::{
    EnvVarSpec, FsPerms, GuestPath, PreopenDirSpec, WasiCapabilities,
};
use operune_runtime_wasm::{EngineConfig, EngineHandle, ResourceBudget};

use super::fixtures::{MALFORMED_BYTES, MINIMAL_COMPONENT_WAT, UNKNOWN_IMPORT_COMPONENT_WAT};
use super::test_support::{expect_ok, test_failure};

// ---------------------------------------------------------------------------
// 内存 fake ports（conformance 自有；只实现 InstallService 需要的最小面）
// ---------------------------------------------------------------------------

/// 内存注册表（candidate / 制品 / installation 的最小子集；§18.3 形状对齐
/// application 的 FakeRegistry，仅测试面）。
struct MemRegistry {
    artifacts: Mutex<HashMap<ContentDigest, Vec<u8>>>,
    candidates: Mutex<HashMap<ContentDigest, CandidateRecordMini>>,
}

/// candidate 最小记录（只断言生命周期状态与存在性）。
#[derive(Clone, Copy, PartialEq, Eq)]
struct CandidateRecordMini {
    state: ComponentLifecycleState,
}

impl MemRegistry {
    fn new() -> Self {
        Self {
            artifacts: Mutex::new(HashMap::new()),
            candidates: Mutex::new(HashMap::new()),
        }
    }

    /// 审计探针：当前 candidate 数（§19.2：拒绝路径不得产生 candidate）。
    fn candidate_count(&self) -> usize {
        match self.candidates.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }
}

impl ComponentRegistryPort for MemRegistry {
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError> {
        self.artifacts
            .lock()
            .map(|mut artifacts| artifacts.insert(digest, bytes.to_vec()))
            .map(|_| ())
            .map_err(|_| RegistryError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }

    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError> {
        self.artifacts
            .lock()
            .map(|artifacts| artifacts.get(&digest).cloned())
            .map_err(|_| RegistryError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }

    fn upsert_candidate(
        &self,
        record: &operune_application::CandidateRecord,
    ) -> Result<(), RegistryError> {
        self.candidates
            .lock()
            .map(|mut candidates| {
                candidates.insert(
                    record.digest,
                    CandidateRecordMini {
                        state: record.state,
                    },
                )
            })
            .map(|_| ())
            .map_err(|_| RegistryError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }

    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
    ) -> Result<(), RegistryError> {
        self.candidates
            .lock()
            .map(|mut candidates| {
                let record = candidates
                    .get_mut(&digest)
                    .ok_or(RegistryError::NotFound("candidate"))?;
                record.state = state;
                Ok(())
            })
            .map_err(|_| {
                RegistryError::Storage(Box::from(std::io::Error::other("lock poisoned")))
            })?
    }

    fn candidate(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<operune_application::CandidateRecord>, RegistryError> {
        self.candidates
            .lock()
            .map(|candidates| {
                candidates
                    .get(&digest)
                    .map(|record| operune_application::CandidateRecord {
                        digest,
                        state: record.state,
                        byte_len: ByteSize::from_bytes(0),
                    })
            })
            .map_err(|_| RegistryError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }

    fn resolve_version(
        &self,
        _component_id: &ComponentId,
        _version: ComponentVersion,
    ) -> Result<Option<operune_application::DigestVersionBinding>, RegistryError> {
        Ok(None)
    }

    fn bind_version(
        &self,
        _binding: &operune_application::DigestVersionBinding,
    ) -> Result<(), RegistryError> {
        Ok(())
    }

    fn insert_installation(
        &self,
        _record: &operune_application::InstallationRecord,
    ) -> Result<(), RegistryError> {
        Ok(())
    }

    fn update_installation(
        &self,
        _record: &operune_application::InstallationRecord,
    ) -> Result<(), RegistryError> {
        Ok(())
    }

    fn installation(
        &self,
        _id: InstallationId,
    ) -> Result<Option<operune_application::InstallationRecord>, RegistryError> {
        Ok(None)
    }

    fn list_installations(
        &self,
    ) -> Result<Vec<operune_application::InstallationRecord>, RegistryError> {
        Ok(Vec::new())
    }
}

/// 内存 grant store（§17.1：grant 绑定 InstallationId）。
struct MemGrants {
    grants: Mutex<HashMap<InstallationId, Vec<InstallationGrant>>>,
}

impl MemGrants {
    fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
        }
    }
}

impl GrantStorePort for MemGrants {
    fn grants_for(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<InstallationGrant>, GrantError> {
        self.grants
            .lock()
            .map(|grants| grants.get(&installation).cloned().unwrap_or_default())
            .map_err(|_| GrantError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }

    fn replace_grants(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
    ) -> Result<(), GrantError> {
        self.grants
            .lock()
            .map(|mut stored| {
                stored.insert(installation, grants.to_vec());
            })
            .map_err(|_| GrantError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }
}

/// 内存 audit（§18.7：fail-closed 的拒绝事件可观测）。
struct MemAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemAudit {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// 审计探针：是否存在匹配事件。
    fn contains(&self, predicate: impl Fn(&AuditEvent) -> bool) -> bool {
        match self.events.lock() {
            Ok(events) => events.iter().any(predicate),
            Err(_) => false,
        }
    }
}

impl AuditPort for MemAudit {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        self.events
            .lock()
            .map(|mut events| events.push(event))
            .map_err(|_| AuditError::Storage(Box::from(std::io::Error::other("lock poisoned"))))
    }
}

/// 内存 config（§18.0：不可变快照）。
struct MemConfig {
    config: RuntimeConfig,
}

impl MemConfig {
    fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

impl ConfigPort for MemConfig {
    fn snapshot(&self) -> Result<RuntimeConfig, ConfigError> {
        Ok(self.config.clone())
    }
}

/// 全管线 harness：真实 `WasmtimeRuntime`（共享 Engine）+ 内存 ports。
struct PipelineHarness {
    registry: Arc<MemRegistry>,
    audit: Arc<MemAudit>,
    install: InstallService,
}

impl PipelineHarness {
    fn new(config: RuntimeConfig) -> Self {
        let engine = Arc::new(expect_ok(
            EngineHandle::new(EngineConfig::default()),
            "conformance engine creation",
        ));
        let config_port = Arc::new(MemConfig::new(config.clone()));
        let runtime = Arc::new(WasmtimeRuntime::new(
            Arc::clone(&engine),
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
        ));
        let registry = Arc::new(MemRegistry::new());
        let grants = Arc::new(MemGrants::new());
        let audit = Arc::new(MemAudit::new());
        let active = Arc::new(ActiveRuntimeRegistry::new());
        let assets = Arc::new(expect_ok(AssetCache::new(&config), "asset cache creation"));
        let install = InstallService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
            Arc::clone(&runtime) as Arc<dyn WasmRuntime>,
            Arc::clone(&active),
            Arc::clone(&assets),
        );
        Self {
            registry,
            audit,
            install,
        }
    }

    fn install_bytes(
        &self,
        bytes: Vec<u8>,
    ) -> Result<operune_application::InstallOutcome, ApplicationError> {
        self.install.install(InstallRequest {
            bytes,
            grants: GrantApproval::Explicit(Vec::new()),
        })
    }
}

// ---------------------------------------------------------------------------
// §19 两阶段安装：非法/缺契约面/超大小输入 → 拒绝且不产生 candidate
// ---------------------------------------------------------------------------

#[test]
fn install_rejects_malformed_bytes_without_candidate() {
    // §30 malformed bytes × §19.2：非法字节在 compile（阶段二）被拒绝，
    // 审计 InstallRejected{InvalidBytes}，**不产生 candidate**
    //（quarantine：字节事实从未被持久化，§19.2 顺序 1–6 在 7 之前失败）。
    let harness = PipelineHarness::new(RuntimeConfig::default());
    let result = harness.install_bytes(MALFORMED_BYTES.to_vec());
    match result {
        Ok(_) => test_failure("malformed bytes must be rejected by the install pipeline"),
        Err(error) => {
            assert!(
                matches!(error, ApplicationError::InvalidComponent(_)),
                "malformed bytes must surface as InvalidComponent: {error:?}"
            );
        }
    }
    assert_eq!(harness.registry.candidate_count(), 0);
    assert!(
        harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::InvalidBytes,
                    ..
                }
            )
        }),
        "audit must record the InvalidBytes rejection (§18.7)"
    );
}

#[test]
fn install_rejects_component_without_descriptor_export() {
    // §30 minimal valid Component × §19.2：合法组件但缺
    // `operune:component/descriptor` 导出（§6.7 契约面）→ 在持久化
    // **之前**拒绝（InstallRejected{MissingComponentDescriptor}），不产生
    // candidate——非法/不完整组件不能以任何状态进入注册表。
    let harness = PipelineHarness::new(RuntimeConfig::default());
    let result = harness.install_bytes(MINIMAL_COMPONENT_WAT.as_bytes().to_vec());
    match result {
        Ok(_) => test_failure("component without descriptor export must be rejected"),
        Err(error) => {
            assert!(
                matches!(error, ApplicationError::ContractViolation(_)),
                "missing descriptor export must surface as ContractViolation: {error:?}"
            );
        }
    }
    assert_eq!(harness.registry.candidate_count(), 0);
    assert!(
        harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::MissingComponentDescriptor,
                    ..
                }
            )
        }),
        "audit must record the missing-descriptor rejection (§19.2)"
    );
}

#[test]
fn install_rejects_oversized_bytes_before_wasm_processing() {
    // §32 "oversized input 被提前拒绝" × §19.1/§19.2：超过硬大小限制的
    // 输入在**任何 wasm 处理之前**拒绝（OversizedComponent），不产生
    // candidate、不执行 guest 代码。
    let config = RuntimeConfig {
        max_component_bytes: ByteSize::from_bytes(8),
        ..RuntimeConfig::default()
    };
    let harness = PipelineHarness::new(config);
    let result = harness.install_bytes(b"1234567890".to_vec());
    match result {
        Ok(_) => test_failure("oversized bytes must be rejected"),
        Err(error) => {
            assert!(
                matches!(error, ApplicationError::OversizedComponent { .. }),
                "oversized bytes must surface as OversizedComponent: {error:?}"
            );
        }
    }
    assert_eq!(harness.registry.candidate_count(), 0);
    assert!(
        harness.audit.contains(|event| {
            matches!(
                event,
                AuditEvent::InstallRejected {
                    reason: RejectReason::Oversized,
                    ..
                }
            )
        }),
        "audit must record the oversized rejection (§18.7)"
    );
}

// ---------------------------------------------------------------------------
// §17.2/§19.5 deny-by-default：未知 import / 能力门控（WasmtimeRuntime 面）
// ---------------------------------------------------------------------------

/// 真实 wasmtime 测试环境：共享 Engine + 默认 config + WasmtimeRuntime
///（与 application runtime.rs 测试同构，经公开 API）。
fn real_runtime() -> Arc<WasmtimeRuntime> {
    let engine = Arc::new(expect_ok(
        EngineHandle::new(EngineConfig::default()),
        "conformance engine creation",
    ));
    let config = Arc::new(MemConfig::new(RuntimeConfig::default()));
    Arc::new(WasmtimeRuntime::new(engine, config))
}

/// 零 grant 计划（§7.6 deny-by-default：空 WASI 能力）。
fn zero_grant_plan(installation: InstallationId) -> RuntimePlan {
    RuntimePlan {
        installation,
        grants: GrantSnapshot {
            installation,
            wasi: WasiCapabilities::empty(),
            budget: ResourceBudget::default(),
        },
    }
}

/// 带一个环境变量 grant 的计划（非空 WASI 能力 → 标准 wasi:cli/imports
/// 世界组装，§19.3）。
fn env_grant_plan(installation: InstallationId) -> RuntimePlan {
    let mut caps = WasiCapabilities::empty();
    caps.add_env(match EnvVarSpec::new("OPERUNE_CONFORMANCE", "granted") {
        Ok(spec) => spec,
        Err(_) => test_failure("env spec construction failed"),
    });
    RuntimePlan {
        installation,
        grants: GrantSnapshot {
            installation,
            wasi: caps,
            budget: ResourceBudget::default(),
        },
    }
}

#[test]
fn unknown_import_denied_at_prepare_without_grant() {
    // §39.4 "未授权/未知 import 不能成为 Active"：`WasmtimeRuntime::prepare`
    // 在零 grant 快照下以**确定性 link 错误**拒绝带 WASI import 的组件
    //（§17.2 deny-by-default 的二进制级强制点，§19.5：不"先运行，失败时
    // trap"）。同一逻辑流程在 InstallService 全管线中对应 Resolution 失败
    // → candidate Failed（descriptor 驱动的全管线变体属 WIT 缺口，见
    // [`super::gaps`]）。
    let runtime = real_runtime();
    let component = expect_ok(
        runtime.compile(UNKNOWN_IMPORT_COMPONENT_WAT.as_bytes()),
        "unknown import component compile",
    );
    // §6.7：contract surface 反映二进制真实事实（import 可见，无需运行）。
    let surface = expect_ok(runtime.contract_surface(&component), "contract surface");
    assert!(
        surface
            .imports
            .iter()
            .any(|name| name == "wasi:random/random@0.2.0"),
        "contract surface must expose the binary import: {surface:?}"
    );
    let plan = zero_grant_plan(InstallationId::new());
    let result = runtime.prepare(&component, &plan);
    match result {
        Ok(_) => test_failure("ungranted import must be denied at prepare (link) time"),
        Err(error) => {
            assert!(
                matches!(error, RuntimeExecutionError::Runtime(_)),
                "link-time denial must surface as typed runtime error: {error:?}"
            );
        }
    }
}

#[test]
fn granted_wasi_capability_resolves_and_instantiates() {
    // §30 denied capability 的正面对照（§7.6 能力只经显式构建进入）：
    // 同一组件在显式 grant（非空 WASI 能力）下 prepare（link 解析）+
    // instantiate（有界 Instance Set）+ readiness 全链路成功，随后 drain。
    let runtime = real_runtime();
    let component = expect_ok(
        runtime.compile(UNKNOWN_IMPORT_COMPONENT_WAT.as_bytes()),
        "unknown import component compile",
    );
    let installation = InstallationId::new();
    let plan = env_grant_plan(installation);
    let prepared = expect_ok(runtime.prepare(&component, &plan), "prepare with grant");
    assert_eq!(prepared.installation(), installation);
    let active = expect_ok(runtime.instantiate(&prepared), "instantiate with grant");
    expect_ok(active.check_readiness(), "readiness");
    expect_ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
}

#[test]
fn denied_preopen_capability_fails_closed() {
    // §17.2 fail closed：已声明能力无法满足（preopen host 路径不存在）→
    // 整个 runtime candidate 拒绝（RuntimeError::Wasi），不静默跳过能力
    // ——组件不能带着"部分授权"激活。
    let runtime = real_runtime();
    let component = expect_ok(
        runtime.compile(MINIMAL_COMPONENT_WAT.as_bytes()),
        "minimal component compile",
    );
    let mut caps = WasiCapabilities::empty();
    let guest = match GuestPath::new("data") {
        Ok(path) => path,
        Err(_) => test_failure("guest path construction failed"),
    };
    let spec = match PreopenDirSpec::new(
        guest,
        std::path::PathBuf::from("definitely-missing-conformance-host-path"),
        FsPerms::READ_ONLY,
        FsPerms::READ_ONLY,
    ) {
        Ok(spec) => spec,
        Err(_) => test_failure("preopen spec construction failed"),
    };
    match caps.add_preopen(spec) {
        Ok(()) => {}
        Err(_) => test_failure("add preopen failed"),
    }
    let plan = RuntimePlan {
        installation: InstallationId::new(),
        grants: GrantSnapshot {
            installation: InstallationId::new(),
            wasi: caps,
            budget: ResourceBudget::default(),
        },
    };
    let prepared = expect_ok(runtime.prepare(&component, &plan), "prepare");
    let result = runtime.instantiate(&prepared);
    match result {
        Ok(_) => {
            test_failure("instantiate must fail closed when a granted capability is unsatisfiable")
        }
        Err(error) => {
            assert!(
                matches!(
                    error,
                    RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Wasi(_))
                ),
                "unsatisfiable preopen must surface as RuntimeError::Wasi: {error:?}"
            );
        }
    }
}

#[test]
fn granted_preopen_with_real_directory_instantiates() {
    // §7.6 能力授予的正常路径：真实宿主目录经显式 preopen grant 进入
    // WASI 0.2 context（attach 成功即证明目录被打开并注册）→ 实例化 +
    // readiness + drain 成功。
    let runtime = real_runtime();
    let component = expect_ok(
        runtime.compile(MINIMAL_COMPONENT_WAT.as_bytes()),
        "minimal component compile",
    );
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => test_failure("tempdir creation failed"),
    };
    let mut caps = WasiCapabilities::empty();
    let guest = match GuestPath::new("data") {
        Ok(path) => path,
        Err(_) => test_failure("guest path construction failed"),
    };
    let spec = match PreopenDirSpec::new(
        guest,
        dir.path().to_path_buf(),
        FsPerms::READ_ONLY,
        FsPerms::READ_ONLY,
    ) {
        Ok(spec) => spec,
        Err(_) => test_failure("preopen spec construction failed"),
    };
    match caps.add_preopen(spec) {
        Ok(()) => {}
        Err(_) => test_failure("add preopen failed"),
    }
    let plan = RuntimePlan {
        installation: InstallationId::new(),
        grants: GrantSnapshot {
            installation: InstallationId::new(),
            wasi: caps,
            budget: ResourceBudget::default(),
        },
    };
    let prepared = expect_ok(runtime.prepare(&component, &plan), "prepare");
    let active = expect_ok(runtime.instantiate(&prepared), "instantiate");
    expect_ok(active.check_readiness(), "readiness");
    expect_ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
}

#[test]
fn grant_capability_id_must_match_binary_import() {
    // §17.2：grant 按 WIT import 的规范化能力 id 门控。带 WASI import 的
    // 组件只响应 `wasi:` 命名空间的 grant——错误命名空间（如跨 Component
    // 的 `acme:` 能力，§19.5 不支持）不构成覆盖。此断言验证 resolution
    // 的分类面（ImportClass::normalize）：`acme:` import 属 Unsupported，
    // 不能在 0.1.0 被授予。
    use operune_application::ImportClass;
    assert_eq!(
        ImportClass::normalize("wasi:cli/run@0.2.0"),
        ImportClass::Wasi
    );
    assert_eq!(
        ImportClass::normalize("operune:component/descriptor@0.1.0"),
        ImportClass::Operune
    );
    assert_eq!(
        ImportClass::normalize("acme:provider/widget@1.0.0"),
        ImportClass::Unsupported
    );
    // CapabilityId 构造（grant 侧的 typed 能力 id）。
    let capability = match CapabilityId::new("wasi:random/random") {
        Ok(id) => id,
        Err(_) => test_failure("capability id construction failed"),
    };
    assert_eq!(capability.as_str(), "wasi:random/random");
}
