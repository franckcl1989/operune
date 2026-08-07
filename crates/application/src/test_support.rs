//! 测试支持（仅 `#[cfg(test)]` 编译）：fake ports（内存实现）与 fake
//! wasm 执行边界，供用例级测试注入（§24.2 端口注入 / 任务 G）。
//!
//! workspace lints 对测试代码同样 deny `panic!`/`unwrap`/`expect`
//!（§26.1 / §14.2）；断言式失败辅助见 [`test_failure`]。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use operune_domain::{
    CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ConfigFormat,
    ConfigRevision, ConfigSchemaVersion, ConfigSnapshot, ConfigValue, ConsumerRecord,
    ContentDigest, InstallationId, ProviderRecord, SecretMetadata, SecretName, SecretVersion,
    StateKey, StateSchemaVersion, StateTransactionId, StateValue,
};

use crate::active::ActiveRuntimeRegistry;
use crate::clock::{Clock, ClockError};
use crate::composition::{ActiveGraph, CompositionService, GraphPolicy};
use crate::contract::{
    GuestActionRequest, GuestAppDescriptor, GuestComponentDescriptor, GuestRouteRequest,
    GuestStateDeclaration,
};
use crate::error::RuntimeExecutionError;
use crate::event::DeliveredEvent;
use crate::install::{InstallService, StateMigrationRunner, StateWiring};
use crate::migration::{MigrationGuestError, StateMigrationService};
use crate::model::{
    CandidateRecord, ContractSurface, DigestVersionBinding, GrantApproval, GrantSnapshot,
    InstallRequest, InstallationGrant, InstallationRecord, RuntimeConfig, WebAssetPath,
    WebManifestData,
};
use crate::ports::{
    AuditError, AuditEvent, AuditPort, ComponentConfigStorePort, ComponentRegistryPort, ConfigPort,
    ConfigStoreError, EventDeliveryError, EventDeliveryPort, GrantError, GrantStorePort,
    GraphRecords, GraphStoreError, InProcessActionPolicy, ProviderGraphPort, RegistryError,
    SchedulerDeliveryError, SchedulerDeliveryPort, SecretCiphertextRecord, SecretGrantPort,
    SecretStoreError, SecretStorePort, StateStoreError, StateStorePort, StatefulAuditEvent,
    StatefulAuditPort,
};
use crate::runtime::{ActiveRuntime, CompiledWasm, PreparedRuntime, RuntimePlan, WasmRuntime};
use crate::state::MigrationGate;
use crate::upgrade::UpgradeService;
use crate::web::{AssetCache, WebBridge};
use crate::web_app::WebAppService;
use operune_domain::{TriggerPayload, UtcInstant};

/// 断言式失败：以测试失败语义中止当前测试（返回类型 `!`）。
/// 与 runtime-wasm 的 test_support 同模式（§26.1 允许测试断言语义）。
#[allow(clippy::assertions_on_constants)]
pub(crate) fn test_failure(message: impl std::fmt::Display) -> ! {
    assert!(false, "{message}");
    std::process::abort();
}

/// 断言 `Result` 为 `Ok` 并取出值；否则中止测试。
pub(crate) fn ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => test_failure(format_args!("{what} failed: {error}")),
    }
}

/// 断言 `Option` 为 `Some` 并取出值；否则中止测试。
pub(crate) fn some<T>(option: Option<T>, what: &str) -> T {
    match option {
        Some(value) => value,
        None => test_failure(format_args!("{what} is None")),
    }
}

/// 断言 `Result` 为 `Err` 并取出错误；否则中止测试（替代 unwrap_err，
/// workspace lints deny，§26.1）。
pub(crate) fn err<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> E {
    match result {
        Err(error) => error,
        Ok(_) => test_failure(format_args!("{what} succeeded unexpectedly")),
    }
}

/// 默认契约面：导出 `operune:component/descriptor`（`descriptor` 形态），
/// 无 import，无 web 接口。
pub(crate) fn default_surface() -> ContractSurface {
    ContractSurface {
        imports: Vec::new(),
        exports: vec!["descriptor".to_owned()],
    }
}

/// 默认合法 descriptor（§19.3 canonical 语义）。
pub(crate) fn default_descriptor() -> GuestComponentDescriptor {
    GuestComponentDescriptor {
        component_id: "demo".to_owned(),
        major: 1,
        minor: 0,
        patch: 0,
        display_name: "Demo Component".to_owned(),
        author: None,
    }
}

/// 默认无 import 的安装请求（空 grant 集，deny-by-default 语义下合法）。
pub(crate) fn plain_install_request(bytes: Vec<u8>) -> InstallRequest {
    InstallRequest {
        bytes,
        grants: GrantApproval::Explicit(Vec::new()),
    }
}

/// 构造一个 unscoped grant（§17.3）。
pub(crate) fn grant(capability: &str) -> InstallationGrant {
    InstallationGrant {
        capability: match CapabilityId::new(capability) {
            Ok(id) => id,
            Err(_) => test_failure(format_args!("invalid capability id {capability:?}")),
        },
        scope: crate::model::GrantScope::Unscoped,
    }
}

// ---------------------------------------------------------------------------
// FakeRegistry（内存实现，§18.3 形状对齐）
// ---------------------------------------------------------------------------

pub(crate) struct FakeRegistry {
    artifacts: Mutex<HashMap<ContentDigest, Vec<u8>>>,
    candidates: Mutex<HashMap<ContentDigest, CandidateRecord>>,
    bindings: Mutex<HashMap<(ComponentId, ComponentVersion), DigestVersionBinding>>,
    installations: Mutex<HashMap<InstallationId, InstallationRecord>>,
    artifact_reads_fail: std::sync::atomic::AtomicBool,
}

impl FakeRegistry {
    pub(crate) fn new() -> Self {
        Self {
            artifacts: Mutex::new(HashMap::new()),
            candidates: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
            installations: Mutex::new(HashMap::new()),
            artifact_reads_fail: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// 让 artifact 读取失败（回滚不可用测试，§18.7）。
    pub(crate) fn fail_artifact_reads(&self) {
        self.artifact_reads_fail
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub(crate) fn candidate_state(&self, digest: ContentDigest) -> Option<ComponentLifecycleState> {
        let candidates = match self.candidates.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        candidates.get(&digest).map(|record| record.state)
    }

    pub(crate) fn installation(&self, id: InstallationId) -> Option<InstallationRecord> {
        let installations = match self.installations.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        installations.get(&id).cloned()
    }
}

impl ComponentRegistryPort for FakeRegistry {
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError> {
        let mut artifacts = self.artifacts.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        artifacts.insert(digest, bytes.to_vec());
        Ok(())
    }

    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError> {
        if self
            .artifact_reads_fail
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(RegistryError::Storage(Box::new(std::io::Error::other(
                "injected artifact read failure",
            ))));
        }
        let artifacts = self.artifacts.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(artifacts.get(&digest).cloned())
    }

    fn upsert_candidate(&self, record: &CandidateRecord) -> Result<(), RegistryError> {
        let mut candidates = self.candidates.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        candidates.insert(record.digest, record.clone());
        Ok(())
    }

    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
    ) -> Result<(), RegistryError> {
        let mut candidates = self.candidates.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        if let Some(record) = candidates.get_mut(&digest) {
            record.state = state;
            Ok(())
        } else {
            Err(RegistryError::NotFound("candidate"))
        }
    }

    fn candidate(&self, digest: ContentDigest) -> Result<Option<CandidateRecord>, RegistryError> {
        let candidates = self.candidates.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(candidates.get(&digest).cloned())
    }

    fn resolve_version(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<DigestVersionBinding>, RegistryError> {
        let bindings = self.bindings.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(bindings.get(&(component_id.clone(), version)).cloned())
    }

    fn bind_version(&self, binding: &DigestVersionBinding) -> Result<(), RegistryError> {
        let mut bindings = self.bindings.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        if let Some(existing) = bindings.get(&(binding.component_id.clone(), binding.version))
            && existing.digest != binding.digest
        {
            return Err(RegistryError::VersionBindingConflict {
                component_id: binding.component_id.clone(),
                version: binding.version,
                existing: existing.digest,
                incoming: binding.digest,
            });
        }
        bindings.insert(
            (binding.component_id.clone(), binding.version),
            binding.clone(),
        );
        Ok(())
    }

    fn insert_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        let mut installations = self.installations.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        installations.insert(record.installation_id, record.clone());
        Ok(())
    }

    fn update_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        let mut installations = self.installations.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        installations.insert(record.installation_id, record.clone());
        Ok(())
    }

    fn installation(
        &self,
        id: InstallationId,
    ) -> Result<Option<InstallationRecord>, RegistryError> {
        let installations = self.installations.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(installations.get(&id).cloned())
    }

    fn list_installations(&self) -> Result<Vec<InstallationRecord>, RegistryError> {
        let installations = self.installations.lock().map_err(|_| {
            RegistryError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(installations.values().cloned().collect())
    }
}

// ---------------------------------------------------------------------------
// FakeGraphStore（内存实现，§40.2 graph persistence 的形状对齐）
// ---------------------------------------------------------------------------

pub(crate) struct FakeGraphStore {
    providers: std::sync::Mutex<std::collections::BTreeMap<InstallationId, ProviderRecord>>,
    consumers: std::sync::Mutex<std::collections::BTreeMap<InstallationId, ConsumerRecord>>,
}

impl FakeGraphStore {
    pub(crate) fn new() -> Self {
        Self {
            providers: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            consumers: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    pub(crate) fn provider(&self, installation: InstallationId) -> Option<ProviderRecord> {
        let providers = match self.providers.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        providers.get(&installation).cloned()
    }

    pub(crate) fn consumer(&self, installation: InstallationId) -> Option<ConsumerRecord> {
        let consumers = match self.consumers.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        consumers.get(&installation).cloned()
    }

    /// 全部记录数（provider + consumer）。
    pub(crate) fn count(&self) -> usize {
        let providers = match self.providers.lock() {
            Ok(guard) => guard,
            Err(_) => return 0,
        };
        let consumers = match self.consumers.lock() {
            Ok(guard) => guard,
            Err(_) => return 0,
        };
        providers.len() + consumers.len()
    }
}

impl ProviderGraphPort for FakeGraphStore {
    fn replace_records(
        &self,
        installation: InstallationId,
        provider: Option<&ProviderRecord>,
        consumer: Option<&ConsumerRecord>,
    ) -> Result<(), GraphStoreError> {
        {
            let mut providers = self.providers.lock().map_err(|_| {
                GraphStoreError::Storage(Box::new(std::io::Error::other("lock poisoned")))
            })?;
            match provider {
                Some(record) => {
                    providers.insert(installation, record.clone());
                }
                None => {
                    providers.remove(&installation);
                }
            }
        }
        let mut consumers = self.consumers.lock().map_err(|_| {
            GraphStoreError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        match consumer {
            Some(record) => {
                consumers.insert(installation, record.clone());
            }
            None => {
                consumers.remove(&installation);
            }
        }
        Ok(())
    }

    fn load_records(&self) -> Result<GraphRecords, GraphStoreError> {
        let providers = self.providers.lock().map_err(|_| {
            GraphStoreError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        let consumers = self.consumers.lock().map_err(|_| {
            GraphStoreError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        Ok(GraphRecords {
            providers: providers.values().cloned().collect(),
            consumers: consumers.values().cloned().collect(),
        })
    }
}

// ---------------------------------------------------------------------------
// FakeGrants / FakeAudit / FakeConfig
// ---------------------------------------------------------------------------

pub(crate) struct FakeGrants {
    grants: Mutex<HashMap<InstallationId, Vec<InstallationGrant>>>,
}

impl FakeGrants {
    pub(crate) fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn stored(&self, id: InstallationId) -> Vec<InstallationGrant> {
        let grants = match self.grants.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        grants.get(&id).cloned().unwrap_or_default()
    }
}

impl GrantStorePort for FakeGrants {
    fn grants_for(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<InstallationGrant>, GrantError> {
        let grants = self
            .grants
            .lock()
            .map_err(|_| GrantError::Storage(Box::new(std::io::Error::other("lock poisoned"))))?;
        Ok(grants.get(&installation).cloned().unwrap_or_default())
    }

    fn replace_grants(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
    ) -> Result<(), GrantError> {
        let mut store = self
            .grants
            .lock()
            .map_err(|_| GrantError::Storage(Box::new(std::io::Error::other("lock poisoned"))))?;
        store.insert(installation, grants.to_vec());
        Ok(())
    }
}

pub(crate) struct FakeAudit {
    events: Mutex<Vec<AuditEvent>>,
}

impl FakeAudit {
    pub(crate) fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn events(&self) -> Vec<AuditEvent> {
        match self.events.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) fn contains(&self, predicate: impl Fn(&AuditEvent) -> bool) -> bool {
        self.events().iter().any(predicate)
    }
}

impl AuditPort for FakeAudit {
    fn append(&self, event: AuditEvent) -> Result<(), crate::ports::AuditError> {
        let mut events = self.events.lock().map_err(|_| {
            crate::ports::AuditError::Storage(Box::new(std::io::Error::other("lock poisoned")))
        })?;
        events.push(event);
        Ok(())
    }
}

pub(crate) struct FakeConfig {
    config: RuntimeConfig,
}

impl FakeConfig {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

impl ConfigPort for FakeConfig {
    fn snapshot(&self) -> Result<RuntimeConfig, crate::ports::ConfigError> {
        Ok(self.config.clone())
    }
}

// ---------------------------------------------------------------------------
// FakeRuntime（脚本化 wasm 执行边界）
// ---------------------------------------------------------------------------

/// Fake 运行状态（`RuntimeExecutionError` 不可 Clone，因此本类型不派生
/// Clone、错误以标志位表达（调用时现构造错误）；测试经 [`FakeRuntime`]
/// 的计数访问器读取观测点）。
pub(crate) struct FakeState {
    /// compile 注入失败标志。
    pub(crate) compile_failure: bool,
    pub(crate) surface: ContractSurface,
    /// 按字节内容定制的 contract surface（0.2.0 composition 测试：
    /// v1/v2 不同提供面/需求面的升级场景）。
    pub(crate) surfaces_by_bytes: std::collections::HashMap<Vec<u8>, ContractSurface>,
    /// 脚本化 descriptor 序列（按调用次序；`None` = 注入失败；
    /// §19.3 确定性比对测试用）。
    pub(crate) descriptors: Vec<Option<GuestComponentDescriptor>>,
    pub(crate) descriptor_index: usize,
    /// 按字节内容定制的 descriptor（升级/回滚测试：v1/v2 不同身份）。
    pub(crate) descriptors_by_bytes: HashMap<Vec<u8>, GuestComponentDescriptor>,
    /// 脚本化 state-declaration 序列（按调用次序；§19.3 确定性比对测试用；
    /// `None` = 注入失败）。
    pub(crate) declarations: Vec<Option<GuestStateDeclaration>>,
    pub(crate) declaration_index: usize,
    /// 按字节内容定制的 state-declaration（0.3.0 stateful 升级测试：
    /// v1/v2 不同声明版本）。
    pub(crate) declarations_by_bytes: HashMap<Vec<u8>, GuestStateDeclaration>,
    /// 0.4.0（§42.2）：脚本化 app-descriptor 序列（按调用次序；`None` =
    /// 注入失败；§19.3 确定性比对测试用）。
    pub(crate) app_descriptors: Vec<Option<GuestAppDescriptor>>,
    pub(crate) app_descriptor_index: usize,
    /// 按字节内容定制的 app-descriptor（v1/v2 不同声明的升级测试）。
    pub(crate) app_descriptors_by_bytes: HashMap<Vec<u8>, GuestAppDescriptor>,
    /// 最近一次 compile 的字节（read_descriptor 的按键依据）。
    pub(crate) last_compiled_bytes: Vec<u8>,
    /// prepare 注入失败标志。
    pub(crate) prepare_failure: bool,
    /// instantiate 注入失败标志。
    pub(crate) instantiate_failure: bool,
    /// readiness 注入失败标志。
    pub(crate) readiness_failure: bool,
    pub(crate) manifest: Option<Option<WebManifestData>>,
    pub(crate) assets: HashMap<WebAssetPath, Vec<u8>>,
    /// action 成功响应；`None` = 注入失败（调用时现构造错误）。
    pub(crate) action_result_ok: Option<Vec<u8>>,
    /// 0.4.0（§42.2）：route 成功响应；`None` = 注入失败。
    pub(crate) route_result_ok: Option<Vec<u8>>,
    /// 0.4.0（§42.2）：route 调用注入 deadline 到期（epoch 强制语义的
    /// fake 形态）。
    pub(crate) route_deadline_exceeded: bool,
    pub(crate) compile_calls: usize,
    pub(crate) descriptor_calls: usize,
    pub(crate) declaration_calls: usize,
    pub(crate) app_descriptor_calls: usize,
    pub(crate) prepare_calls: usize,
    pub(crate) instantiate_calls: usize,
    pub(crate) asset_reads: usize,
    pub(crate) action_calls: usize,
    pub(crate) route_calls: usize,
    pub(crate) drains: Vec<Duration>,
}

impl Default for FakeState {
    fn default() -> Self {
        Self {
            compile_failure: false,
            surface: default_surface(),
            surfaces_by_bytes: std::collections::HashMap::new(),
            descriptors: Vec::new(),
            descriptor_index: 0,
            descriptors_by_bytes: HashMap::new(),
            declarations: Vec::new(),
            declaration_index: 0,
            declarations_by_bytes: HashMap::new(),
            app_descriptors: Vec::new(),
            app_descriptor_index: 0,
            app_descriptors_by_bytes: HashMap::new(),
            last_compiled_bytes: Vec::new(),
            prepare_failure: false,
            instantiate_failure: false,
            readiness_failure: false,
            manifest: None,
            assets: HashMap::new(),
            action_result_ok: Some(vec![1, 2, 3]),
            route_result_ok: Some(vec![4, 5, 6]),
            route_deadline_exceeded: false,
            compile_calls: 0,
            descriptor_calls: 0,
            declaration_calls: 0,
            app_descriptor_calls: 0,
            prepare_calls: 0,
            instantiate_calls: 0,
            asset_reads: 0,
            action_calls: 0,
            route_calls: 0,
            drains: Vec::new(),
        }
    }
}

pub(crate) struct FakeRuntime {
    state: Arc<Mutex<FakeState>>,
}

impl FakeRuntime {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    pub(crate) fn compile_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.compile_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn descriptor_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.descriptor_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn declaration_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.declaration_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn prepare_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.prepare_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn instantiate_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.instantiate_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn asset_reads(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.asset_reads,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn action_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.action_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    /// 0.4.0（§42.2）：app-descriptor 读取调用计数。
    pub(crate) fn app_descriptor_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.app_descriptor_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    /// 0.4.0（§42.2）：typed route 调用计数。
    pub(crate) fn route_calls(&self) -> usize {
        match self.state.lock() {
            Ok(guard) => guard.route_calls,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    pub(crate) fn drains(&self) -> Vec<Duration> {
        match self.state.lock() {
            Ok(guard) => guard.drains.clone(),
            Err(_) => test_failure("fake runtime state lock poisoned"),
        }
    }

    /// 脚本化：第 i 次 descriptor 读取返回第 i 个结果（§19.3 确定性比对）。
    pub(crate) fn with_descriptors(&self, descriptors: Vec<GuestComponentDescriptor>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.descriptors = descriptors.into_iter().map(Some).collect();
    }

    pub(crate) fn with_descriptor_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.descriptors.push(None);
    }

    pub(crate) fn with_surface(&self, surface: ContractSurface) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.surface = surface;
    }

    /// 按字节内容定制 contract surface（0.2.0 composition 升级场景：
    /// v1/v2 不同提供面）。
    pub(crate) fn with_surface_for(&self, bytes: &[u8], surface: ContractSurface) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.surfaces_by_bytes.insert(bytes.to_vec(), surface);
    }

    /// 按字节内容定制 descriptor（v1/v2 不同身份的升级测试）。
    pub(crate) fn with_descriptor_for(&self, bytes: &[u8], descriptor: GuestComponentDescriptor) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state
            .descriptors_by_bytes
            .insert(bytes.to_vec(), descriptor);
    }

    /// 脚本化：第 i 次 declaration 读取返回第 i 个结果（§19.3 确定性比对）。
    pub(crate) fn with_declarations(&self, declarations: Vec<GuestStateDeclaration>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.declarations = declarations.into_iter().map(Some).collect();
    }

    /// 按字节内容定制 state-declaration（0.3.0 stateful 升级测试：
    /// v1/v2 不同声明版本）。
    pub(crate) fn with_declaration_for(&self, bytes: &[u8], declaration: GuestStateDeclaration) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state
            .declarations_by_bytes
            .insert(bytes.to_vec(), declaration);
    }

    pub(crate) fn with_compile_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.compile_failure = true;
    }

    pub(crate) fn with_prepare_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.prepare_failure = true;
    }

    pub(crate) fn with_instantiate_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.instantiate_failure = true;
    }

    pub(crate) fn with_readiness_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.readiness_failure = true;
    }

    pub(crate) fn with_manifest(&self, manifest: Option<WebManifestData>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.manifest = Some(manifest);
    }

    pub(crate) fn with_asset(&self, path: &str, bytes: Vec<u8>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.assets.insert(
            match WebAssetPath::new(path) {
                Ok(path) => path,
                Err(_) => test_failure(format_args!("invalid asset path {path:?}")),
            },
            bytes,
        );
    }

    pub(crate) fn with_action_result(&self, result: Result<Vec<u8>, RuntimeExecutionError>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.action_result_ok = result.ok();
    }

    /// 0.4.0（§42.2）：脚本化 app-descriptor（按字节内容定制，两次
    /// 确定性读取返回同一结果）。
    pub(crate) fn with_app_descriptor_for(&self, bytes: &[u8], descriptor: GuestAppDescriptor) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state
            .app_descriptors_by_bytes
            .insert(bytes.to_vec(), descriptor);
    }

    /// 0.4.0（§42.2）：脚本化 app-descriptor 序列（第 i 次读取返回第 i 个
    /// 结果；`None` = 注入失败；§19.3 确定性比对测试用）。
    pub(crate) fn with_app_descriptors(&self, descriptors: Vec<GuestAppDescriptor>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.app_descriptors = descriptors.into_iter().map(Some).collect();
    }

    /// 0.4.0（§42.2）：注入 app-descriptor 读取失败。
    pub(crate) fn with_app_descriptor_failure(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.app_descriptors.push(None);
    }

    /// 0.4.0（§42.2）：脚本化 typed route 结果（`Err` = 注入失败）。
    pub(crate) fn with_route_result(&self, result: Result<Vec<u8>, RuntimeExecutionError>) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.route_result_ok = result.ok();
    }

    /// 0.4.0（§42.2）：注入 route 调用 deadline 到期（§7.5 epoch 语义）。
    pub(crate) fn with_route_deadline(&self) {
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => test_failure("fake runtime state lock poisoned"),
        };
        state.route_deadline_exceeded = true;
    }
}

impl WasmRuntime for FakeRuntime {
    fn compile(&self, bytes: &[u8]) -> Result<Arc<dyn CompiledWasm>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.compile_calls += 1;
        state.last_compiled_bytes = bytes.to_vec();
        if state.compile_failure {
            return Err(compile_error("injected compile failure"));
        }
        Ok(Arc::new(FakeCompiledWasm {
            byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }))
    }

    fn contract_surface(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<ContractSurface, RuntimeExecutionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        if let Some(surface) = state.surfaces_by_bytes.get(&state.last_compiled_bytes) {
            return Ok(surface.clone());
        }
        Ok(state.surface.clone())
    }

    fn read_descriptor(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<GuestComponentDescriptor, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.descriptor_calls += 1;
        if let Some(descriptor) = state.descriptors_by_bytes.get(&state.last_compiled_bytes) {
            return Ok(descriptor.clone());
        }
        if state.descriptor_index < state.descriptors.len() {
            let result = state.descriptors[state.descriptor_index].clone();
            state.descriptor_index += 1;
            return match result {
                Some(descriptor) => Ok(descriptor),
                None => Err(compile_error("injected descriptor failure")),
            };
        }
        Ok(default_descriptor())
    }

    fn read_state_declaration(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<Option<GuestStateDeclaration>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.declaration_calls += 1;
        if let Some(declaration) = state.declarations_by_bytes.get(&state.last_compiled_bytes) {
            return Ok(Some(declaration.clone()));
        }
        if state.declaration_index < state.declarations.len() {
            let result = state.declarations[state.declaration_index].clone();
            state.declaration_index += 1;
            return match result {
                Some(declaration) => Ok(Some(declaration)),
                None => Err(compile_error("injected state declaration failure")),
            };
        }
        // 默认：无 declaration 导出 = 无状态组件（0.1 语义保持）。
        Ok(None)
    }

    fn read_app_descriptor(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<Option<GuestAppDescriptor>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.app_descriptor_calls += 1;
        if let Some(descriptor) = state
            .app_descriptors_by_bytes
            .get(&state.last_compiled_bytes)
        {
            return Ok(Some(descriptor.clone()));
        }
        if state.app_descriptor_index < state.app_descriptors.len() {
            let result = state.app_descriptors[state.app_descriptor_index].clone();
            state.app_descriptor_index += 1;
            return match result {
                Some(descriptor) => Ok(Some(descriptor)),
                None => Err(compile_error("injected app descriptor failure")),
            };
        }
        // 默认：无 app-descriptor 导出 = 0.1-only surface（0.1 语义保持）。
        Ok(None)
    }

    fn prepare(
        &self,
        _component: &Arc<dyn CompiledWasm>,
        plan: &RuntimePlan,
    ) -> Result<Arc<dyn PreparedRuntime>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.prepare_calls += 1;
        if state.prepare_failure {
            return Err(compile_error("injected prepare failure"));
        }
        Ok(Arc::new(FakePrepared {
            installation: plan.installation,
            grants: plan.grants.clone(),
        }))
    }

    fn instantiate(
        &self,
        _prepared: &Arc<dyn PreparedRuntime>,
    ) -> Result<Arc<dyn ActiveRuntime>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.instantiate_calls += 1;
        if state.instantiate_failure {
            return Err(compile_error("injected instantiate failure"));
        }
        Ok(Arc::new(FakeActive {
            state: Arc::clone(&self.state),
        }))
    }
}

pub(crate) struct FakeCompiledWasm {
    byte_len: u64,
}

impl CompiledWasm for FakeCompiledWasm {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

pub(crate) struct FakePrepared {
    installation: InstallationId,
    grants: GrantSnapshot,
}

impl PreparedRuntime for FakePrepared {
    fn installation(&self) -> InstallationId {
        self.installation
    }

    fn grants(&self) -> &GrantSnapshot {
        &self.grants
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub(crate) struct FakeActive {
    state: Arc<Mutex<FakeState>>,
}

impl ActiveRuntime for FakeActive {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn check_readiness(&self) -> Result<(), RuntimeExecutionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        if state.readiness_failure {
            return Err(compile_error("injected readiness failure"));
        }
        Ok(())
    }

    fn read_web_manifest(&self) -> Result<Option<WebManifestData>, RuntimeExecutionError> {
        let state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        match state.manifest.clone() {
            Some(manifest) => Ok(manifest),
            None => Ok(None),
        }
    }

    fn read_asset(&self, path: &WebAssetPath) -> Result<Vec<u8>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.asset_reads += 1;
        match state.assets.get(path) {
            Some(bytes) => Ok(bytes.clone()),
            None => Err(RuntimeExecutionError::GuestWebError("asset not found")),
        }
    }

    fn invoke_action(
        &self,
        _request: &GuestActionRequest,
    ) -> Result<Vec<u8>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.action_calls += 1;
        match state.action_result_ok.clone() {
            Some(bytes) => Ok(bytes),
            None => Err(compile_error("injected action failure")),
        }
    }

    fn invoke_route(&self, _request: &GuestRouteRequest) -> Result<Vec<u8>, RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.route_calls += 1;
        if state.route_deadline_exceeded {
            return Err(RuntimeExecutionError::DeadlineExceeded);
        }
        match state.route_result_ok.clone() {
            Some(bytes) => Ok(bytes),
            None => Err(compile_error("injected route failure")),
        }
    }

    fn drain(self: Arc<Self>, deadline: Duration) -> Result<(), RuntimeExecutionError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("fake state poisoned"))?;
        state.drains.push(deadline);
        Ok(())
    }
}

/// 构造注入用的编译类错误。
pub(crate) fn compile_error(message: &str) -> RuntimeExecutionError {
    RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Component(Box::new(
        std::io::Error::other(message),
    )))
}

// ---------------------------------------------------------------------------
// Harness（端口 + 服务装配）
// ---------------------------------------------------------------------------

pub(crate) struct Harness {
    pub(crate) registry: Arc<FakeRegistry>,
    pub(crate) grants: Arc<FakeGrants>,
    pub(crate) audit: Arc<FakeAudit>,
    pub(crate) runtime: Arc<FakeRuntime>,
    pub(crate) active: Arc<ActiveRuntimeRegistry>,
    pub(crate) assets: Arc<AssetCache>,
    pub(crate) install: InstallService,
    pub(crate) upgrade: UpgradeService,
    pub(crate) web: WebBridge,
    /// 0.2.0 provider graph records 存储（fake）。
    pub(crate) graph_store: Arc<FakeGraphStore>,
    /// 0.2.0 active graph 快照。
    pub(crate) active_graph: Arc<ActiveGraph>,
    /// 0.2.0 composition 服务（未接线为 `None`——0.1.0 语义）。
    pub(crate) composition: Option<Arc<CompositionService>>,
    /// 0.3.0 state schema wiring（§41.2/§20.5）：fake state store + 审计 +
    /// 脚本化 guest migration runner（upgrade 管线触发迁移的组合编排
    /// 测试；migration 服务与 gate 在 wiring 内部，经可观测效果断言）。
    pub(crate) state_store: Arc<FakeStateStore>,
    pub(crate) state_audit: Arc<FakeStatefulAudit>,
    pub(crate) migration_runner: Arc<FakeStateMigrationRunner>,
    /// 0.4.0（§42.2）：WebAppService（已接线进 install/upgrade 管线；
    /// 默认 permission policy = grants 后端，默认 quota = 全上限）。
    pub(crate) web_app: Arc<WebAppService>,
}

impl Harness {
    /// 0.1.0 语义 harness（composition 未接线）。
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self::build(config, false)
    }

    /// 0.2.0 composition 已接线的 harness（graph 门控 / 快照切换生效）。
    pub(crate) fn with_composition(config: RuntimeConfig) -> Self {
        Self::build(config, true)
    }

    fn build(config: RuntimeConfig, wired: bool) -> Self {
        let registry = Arc::new(FakeRegistry::new());
        let grants = Arc::new(FakeGrants::new());
        let audit = Arc::new(FakeAudit::new());
        let config_port = Arc::new(FakeConfig::new(config.clone()));
        let runtime = Arc::new(FakeRuntime::new());
        let active = Arc::new(ActiveRuntimeRegistry::new());
        let assets = Arc::new(match AssetCache::new(&config) {
            Ok(cache) => cache,
            Err(_) => test_failure("asset cache construction failed"),
        });
        let graph_store = Arc::new(FakeGraphStore::new());
        let active_graph = Arc::new(match ActiveGraph::new() {
            Ok(graph) => graph,
            Err(_) => test_failure("active graph construction failed"),
        });
        // 具体 fake 类型 → trait object 的显式 unsize 强制（§24.2 端口注入）。
        let policy = Arc::new(InProcessActionPolicy::new(
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
        ));
        let install = InstallService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
            Arc::clone(&runtime) as Arc<dyn WasmRuntime>,
            Arc::clone(&active),
            Arc::clone(&assets),
        );
        let upgrade = UpgradeService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
            Arc::clone(&runtime) as Arc<dyn WasmRuntime>,
            Arc::clone(&active),
            Arc::clone(&assets),
        );
        let web = WebBridge::new(
            Arc::clone(&active),
            Arc::clone(&assets),
            policy,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
        );
        // 0.4.0（§42.2）：WebAppService——permission 检查点（grants 后端）
        // + per-Component quota（全上限）+ config/audit；接线进 install /
        // upgrade 管线（app-descriptor 激活期校验，§42.2）。
        let web_app = Arc::new(WebAppService::new(
            Arc::clone(&active),
            Arc::new(crate::ports::InProcessWebPermissionPolicy::new(
                Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            )),
            match crate::ports::InProcessWebQuota::new(crate::ports::WebQuotaLimits::default()) {
                Ok(quota) => Arc::new(quota) as Arc<dyn crate::ports::WebQuotaPort>,
                Err(_) => test_failure("web quota construction failed"),
            },
            Arc::clone(&config_port) as Arc<dyn ConfigPort>,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
        ));
        // 0.2.0 composition 接线（§40）：同一 composition 服务注入
        // install / upgrade 两条用例路径。
        let composition = if wired {
            let composition = Arc::new(CompositionService::new(
                Arc::clone(&graph_store) as Arc<dyn ProviderGraphPort>,
                Arc::clone(&active_graph),
                Arc::clone(&audit) as Arc<dyn AuditPort>,
                GraphPolicy::new(),
            ));
            match install.set_composition(Arc::clone(&composition)) {
                Ok(()) => {}
                Err(_) => test_failure("composition wiring failed"),
            }
            match upgrade.set_composition(Arc::clone(&composition)) {
                Ok(()) => {}
                Err(_) => test_failure("composition wiring failed"),
            }
            Some(composition)
        } else {
            None
        };
        // 0.3.0 state schema 接线（§20.5/§41.2）：fake store + 审计 +
        // migration 服务 + 脚本化 guest runner 注入 install / upgrade 两条
        // 用例路径。默认接线：无 declaration 导出的组件（fake 默认返回
        // Ok(None)）走无状态路径，既有测试语义不受影响。
        let state_store = Arc::new(FakeStateStore::new());
        let state_audit = Arc::new(FakeStatefulAudit::new());
        let migration_gate = Arc::new(MigrationGate::new());
        let state_migration = Arc::new(StateMigrationService::new(
            Arc::clone(&state_store) as Arc<dyn StateStorePort>,
            Arc::clone(&state_audit) as Arc<dyn StatefulAuditPort>,
            Arc::clone(&migration_gate),
        ));
        let migration_runner = Arc::new(FakeStateMigrationRunner::new());
        let state_wiring = Arc::new(StateWiring::new(
            Arc::clone(&state_store) as Arc<dyn StateStorePort>,
            Arc::clone(&state_migration),
            Arc::clone(&migration_runner) as Arc<dyn StateMigrationRunner>,
        ));
        match install.set_state(Arc::clone(&state_wiring)) {
            Ok(()) => {}
            Err(_) => test_failure("state wiring failed"),
        }
        match upgrade.set_state(Arc::clone(&state_wiring)) {
            Ok(()) => {}
            Err(_) => test_failure("state wiring failed"),
        }
        // 0.4.0（§42.2）：WebAppService 接线（app-descriptor 激活期校验 +
        // typed route registry 随 Active 快照切换）。
        match install.set_web_app(Arc::clone(&web_app)) {
            Ok(()) => {}
            Err(_) => test_failure("web app wiring failed"),
        }
        match upgrade.set_web_app(Arc::clone(&web_app)) {
            Ok(()) => {}
            Err(_) => test_failure("web app wiring failed"),
        }
        Self {
            registry,
            grants,
            audit,
            runtime,
            active,
            assets,
            install,
            upgrade,
            web,
            graph_store,
            active_graph,
            composition,
            state_store,
            state_audit,
            migration_runner,
            web_app,
        }
    }
}
// ---------------------------------------------------------------------------
// 0.3.0 Stateful Runtime（§41.2）：Fake state/config/secret 存储与审计
// （内存实现，语义对齐 storage-sqlite executor 的 0.3 命令；供用例级
// 测试注入，§24.2 端口注入）。
// ---------------------------------------------------------------------------

/// 确定性测试安装实例（seed → uuid，与 composition 测试同模式）。
pub(crate) fn installation(seed: u64) -> InstallationId {
    InstallationId::from_uuid(uuid::Uuid::from_u128(u128::from(seed)))
}

/// 脚本化 guest `migrate` 调用（[`StateMigrationRunner`] 的 fake 注入面；
/// 默认结果 `Ok(())` = guest 迁移返回 ok——调用即成功提交）。
pub(crate) struct FakeStateMigrationRunner {
    /// 脚本化 guest 结果（`Err` = guest 失败 → 回滚语义，§20.5）。
    result: Mutex<Option<Result<(), MigrationGuestError>>>,
    /// 全部迁移调用记录：(from, to)（断言用）。
    calls: Mutex<Vec<(StateSchemaVersion, StateSchemaVersion)>>,
}

impl FakeStateMigrationRunner {
    pub(crate) fn new() -> Self {
        Self {
            result: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// 全部迁移调用记录：(from, to)（断言用）。
    pub(crate) fn calls(&self) -> Vec<(StateSchemaVersion, StateSchemaVersion)> {
        match self.calls.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => test_failure("fake migration runner calls lock poisoned"),
        }
    }

    /// 脚本化 guest 结果（`Err` = guest 失败 → abort 回滚，store 不变，
    /// 升级被阻止，§20.5 rollback policy）。
    pub(crate) fn with_guest_result(&self, result: Result<(), MigrationGuestError>) {
        match self.result.lock() {
            Ok(mut guard) => {
                *guard = Some(result);
            }
            Err(_) => test_failure("fake migration runner result lock poisoned"),
        }
    }
}

impl StateMigrationRunner for FakeStateMigrationRunner {
    fn run(
        &self,
        _component: &Arc<dyn CompiledWasm>,
        from: StateSchemaVersion,
        to: StateSchemaVersion,
        _tx: StateTransactionId,
    ) -> Result<(), MigrationGuestError> {
        match self.calls.lock() {
            Ok(mut calls) => calls.push((from, to)),
            Err(_) => return Err(MigrationGuestError::Host("fake runner calls lock poisoned")),
        }
        match self.result.lock() {
            Ok(guard) => match *guard {
                Some(result) => result,
                None => Ok(()),
            },
            Err(_) => Err(MigrationGuestError::Host(
                "fake runner result lock poisoned",
            )),
        }
    }
}

/// FakeStateStore（内存实现，语义对齐 storage executor 0.3 state 命令：
/// 版本校验、单连接串行 ⇒ 同一时刻至多一个进行中事务、commit 时推进
/// schema marker）。
pub(crate) struct FakeStateStore {
    inner: Mutex<FakeStateInner>,
}

#[derive(Debug, Default)]
struct FakeStateInner {
    stores: HashMap<InstallationId, FakeStoreData>,
    active_tx: Option<FakeActiveTx>,
    next_tx_handle: u64,
}

#[derive(Debug, Default)]
struct FakeStoreData {
    version: Option<StateSchemaVersion>,
    rows: HashMap<StateKey, StateValue>,
}

#[derive(Debug, Clone)]
struct FakeActiveTx {
    handle: u64,
    installation: InstallationId,
    schema_version: StateSchemaVersion,
    pending: HashMap<StateKey, FakePendingOp>,
}

#[derive(Debug, Clone)]
enum FakePendingOp {
    Write(StateValue),
    Delete,
}

impl FakeStateStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(FakeStateInner::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeStateInner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 测试辅助：读取安装实例 state store 的当前版本（断言用）。
    pub(crate) fn version_of(&self, installation: InstallationId) -> Option<StateSchemaVersion> {
        self.lock()
            .stores
            .get(&installation)
            .and_then(|store| store.version)
    }

    /// 测试辅助：读取单键当前值（断言用）。
    pub(crate) fn value_of(
        &self,
        installation: InstallationId,
        key: &StateKey,
    ) -> Option<StateValue> {
        self.lock()
            .stores
            .get(&installation)
            .and_then(|store| store.rows.get(key).cloned())
    }

    /// 测试辅助：模拟进程崩溃——进行中事务被丢弃（SQLite 原子性语义：
    /// 未提交事务自然回滚，store 不变，§18.5）。
    pub(crate) fn simulate_crash(&self) {
        self.lock().active_tx = None;
    }

    fn tx_id(handle: u64) -> StateTransactionId {
        StateTransactionId::from_u64(handle)
    }

    fn active_tx(&self, tx: StateTransactionId) -> Result<FakeActiveTx, StateStoreError> {
        let inner = self.lock();
        match &inner.active_tx {
            Some(active) if active.handle == tx.as_u64() => Ok(active.clone()),
            _ => Err(StateStoreError::TransactionConflict(
                "commit or operation on a state transaction that is not in progress".into(),
            )),
        }
    }
}

impl StateStorePort for FakeStateStore {
    fn get(
        &self,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        Ok(self
            .lock()
            .stores
            .get(&installation)
            .and_then(|store| store.rows.get(key).cloned()))
    }

    fn put(
        &self,
        installation: InstallationId,
        key: &StateKey,
        schema_version: StateSchemaVersion,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let mut inner = self.lock();
        let store = inner.stores.entry(installation).or_default();
        if let Some(current) = store.version
            && current != schema_version
        {
            return Err(StateStoreError::SchemaVersionMismatch {
                installation,
                current: store.version,
                requested: schema_version,
            });
        }
        // 空 store 首次写入建立版本（存储语义：同一事务内 upsert marker）。
        store.version = Some(schema_version);
        store.rows.insert(key.clone(), value.clone());
        Ok(())
    }

    fn delete(&self, installation: InstallationId, key: &StateKey) -> Result<(), StateStoreError> {
        let mut inner = self.lock();
        let Some(store) = inner.stores.get_mut(&installation) else {
            return Err(StateStoreError::NotFound(format!(
                "state key {key} for installation {installation}"
            )));
        };
        if store.rows.remove(key).is_none() {
            return Err(StateStoreError::NotFound(format!(
                "state key {key} for installation {installation}"
            )));
        }
        Ok(())
    }

    fn schema_version(
        &self,
        installation: InstallationId,
    ) -> Result<Option<StateSchemaVersion>, StateStoreError> {
        Ok(self
            .lock()
            .stores
            .get(&installation)
            .and_then(|store| store.version))
    }

    fn begin_transaction(
        &self,
        installation: InstallationId,
        schema_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let mut inner = self.lock();
        if inner.active_tx.is_some() {
            return Err(StateStoreError::TransactionConflict(
                "a state transaction is already in progress".into(),
            ));
        }
        let current = inner.stores.get(&installation).and_then(|s| s.version);
        if let Some(current) = current
            && current != schema_version
        {
            return Err(StateStoreError::SchemaVersionMismatch {
                installation,
                current: Some(current),
                requested: schema_version,
            });
        }
        inner.next_tx_handle = inner.next_tx_handle.saturating_add(1);
        let handle = inner.next_tx_handle;
        inner.active_tx = Some(FakeActiveTx {
            handle,
            installation,
            schema_version,
            pending: HashMap::new(),
        });
        Ok(Self::tx_id(handle))
    }

    fn begin_migration_transaction(
        &self,
        installation: InstallationId,
        to_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let mut inner = self.lock();
        if inner.active_tx.is_some() {
            return Err(StateStoreError::TransactionConflict(
                "a state transaction is already in progress".into(),
            ));
        }
        let current = inner.stores.get(&installation).and_then(|s| s.version);
        let Some(current) = current else {
            return Err(StateStoreError::InvalidArgument(
                "cannot migrate an empty state store (no schema version established)".into(),
            ));
        };
        if to_version <= current {
            return Err(StateStoreError::SchemaVersionMismatch {
                installation,
                current: Some(current),
                requested: to_version,
            });
        }
        inner.next_tx_handle = inner.next_tx_handle.saturating_add(1);
        let handle = inner.next_tx_handle;
        inner.active_tx = Some(FakeActiveTx {
            handle,
            installation,
            schema_version: to_version,
            pending: HashMap::new(),
        });
        Ok(Self::tx_id(handle))
    }

    fn tx_get(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        let active = self.active_tx(tx)?;
        let inner = self.lock();
        match active.pending.get(key) {
            Some(FakePendingOp::Write(value)) => Ok(Some(value.clone())),
            Some(FakePendingOp::Delete) => Ok(None),
            None => Ok(inner
                .stores
                .get(&installation)
                .and_then(|store| store.rows.get(key).cloned())),
        }
    }

    fn tx_put(
        &self,
        tx: StateTransactionId,
        _installation: InstallationId,
        key: &StateKey,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let mut inner = self.lock();
        let Some(active) = inner.active_tx.as_mut() else {
            return Err(StateStoreError::TransactionConflict(
                "operation on a state transaction that is not in progress".into(),
            ));
        };
        if active.handle != tx.as_u64() {
            return Err(StateStoreError::TransactionConflict(
                "operation on a state transaction that is not in progress".into(),
            ));
        }
        active
            .pending
            .insert(key.clone(), FakePendingOp::Write(value.clone()));
        Ok(())
    }

    fn tx_delete(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<(), StateStoreError> {
        // 存储语义：键必须存在（store 行或本事务已写入），否则 NotFound
        //（存在性检查先于可变借用，避免锁内借用冲突）。
        let exists_in_store = self
            .lock()
            .stores
            .get(&installation)
            .map(|store| store.rows.contains_key(key))
            .unwrap_or(false);
        let mut inner = self.lock();
        let Some(active) = inner.active_tx.as_mut() else {
            return Err(StateStoreError::TransactionConflict(
                "operation on a state transaction that is not in progress".into(),
            ));
        };
        if active.handle != tx.as_u64() {
            return Err(StateStoreError::TransactionConflict(
                "operation on a state transaction that is not in progress".into(),
            ));
        }
        let pending_writes = matches!(active.pending.get(key), Some(FakePendingOp::Write(_)));
        if !exists_in_store && !pending_writes {
            return Err(StateStoreError::NotFound(format!(
                "state key {key} for installation {installation}"
            )));
        }
        active.pending.insert(key.clone(), FakePendingOp::Delete);
        Ok(())
    }

    fn commit(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        let active = self.active_tx(tx)?;
        let mut inner = self.lock();
        // 应用暂存操作 + 推进 schema marker（同一"事务"内，§41.3）。
        let store = inner.stores.entry(active.installation).or_default();
        for (key, op) in &active.pending {
            match op {
                FakePendingOp::Write(value) => {
                    store.rows.insert(key.clone(), value.clone());
                }
                FakePendingOp::Delete => {
                    store.rows.remove(key);
                }
            }
        }
        store.version = Some(active.schema_version);
        inner.active_tx = None;
        Ok(())
    }

    fn abort(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        let mut inner = self.lock();
        // WIT：abort 对已终止事务是 no-op。
        match &inner.active_tx {
            Some(active) if active.handle == tx.as_u64() => {
                inner.active_tx = None;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// 存储行：轮换版本 + 不透明密文 BLOB + 非敏感元数据（§16.6：本 fake 与
/// 真实存储一样只接触密文，不含明文）。
type FakeSecretRow = (u64, Vec<u8>, String);

/// 安装实例 → 名称 → 行。
type FakeSecretData = HashMap<InstallationId, HashMap<SecretName, FakeSecretRow>>;

/// FakeSecretStore（内存实现，语义对齐 storage executor 0.3 secret 命令：
/// 密文 BLOB 原样存取、insert or replace 版本递增；**不含明文**）。
pub(crate) struct FakeSecretStore {
    inner: Mutex<FakeSecretData>,
}

impl FakeSecretStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeSecretData> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SecretStorePort for FakeSecretStore {
    fn put(
        &self,
        installation: InstallationId,
        name: &SecretName,
        ciphertext: Vec<u8>,
        metadata: &str,
    ) -> Result<SecretVersion, SecretStoreError> {
        let mut inner = self.lock();
        let names = inner.entry(installation).or_default();
        let (version, _, _) = names
            .get(name)
            .cloned()
            .unwrap_or((0, Vec::new(), String::new()));
        let new_version = version.saturating_add(1);
        names.insert(name.clone(), (new_version, ciphertext, metadata.to_owned()));
        Ok(SecretVersion::from_u64(new_version))
    }

    fn ciphertext(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<Option<SecretCiphertextRecord>, SecretStoreError> {
        let inner = self.lock();
        Ok(inner
            .get(&installation)
            .and_then(|names| names.get(name))
            .map(|(version, ciphertext, _)| SecretCiphertextRecord {
                name: name.clone(),
                version: SecretVersion::from_u64(*version),
                ciphertext: ciphertext.clone(),
            }))
    }

    fn list(&self, installation: InstallationId) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        let inner = self.lock();
        let mut metadata: Vec<SecretMetadata> = inner
            .get(&installation)
            .map(|names| {
                names
                    .iter()
                    .map(|(name, (version, _, _))| {
                        SecretMetadata::new(name.clone(), SecretVersion::from_u64(*version))
                    })
                    .collect()
            })
            .unwrap_or_default();
        // 名称排序（确定性列表；domain SecretMetadata 无 Ord）。
        metadata.sort_by(|a, b| a.name().as_str().cmp(b.name().as_str()));
        Ok(metadata)
    }

    fn delete(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<(), SecretStoreError> {
        let mut inner = self.lock();
        let removed = inner
            .get_mut(&installation)
            .map(|names| names.remove(name).is_some())
            .unwrap_or(false);
        if !removed {
            return Err(SecretStoreError::NotFound(format!(
                "secret {name} for installation {installation}"
            )));
        }
        Ok(())
    }
}

/// FakeSecretGrants（内存实现；grant 集按安装实例配置，§17.3）。
pub(crate) struct FakeSecretGrants {
    grants: Mutex<HashMap<InstallationId, Vec<SecretName>>>,
}

impl FakeSecretGrants {
    pub(crate) fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
        }
    }

    /// 配置安装实例的 secret grant 集。
    pub(crate) fn set_granted(&self, installation: InstallationId, names: Vec<SecretName>) {
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        grants.insert(installation, names);
    }
}

impl SecretGrantPort for FakeSecretGrants {
    fn granted_names(&self, installation: InstallationId) -> Result<Vec<SecretName>, GrantError> {
        let grants = self
            .grants
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(grants.get(&installation).cloned().unwrap_or_default())
    }
}

/// FakeConfigStore（内存实现，语义对齐 storage executor 0.3 config 命令：
/// 单行快照、revision 单调 +1）。
pub(crate) struct FakeConfigStore {
    inner: Mutex<HashMap<InstallationId, (u64, ConfigFormat, ConfigSchemaVersion, ConfigValue)>>,
}

impl FakeConfigStore {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<
        '_,
        HashMap<InstallationId, (u64, ConfigFormat, ConfigSchemaVersion, ConfigValue)>,
    > {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl ComponentConfigStorePort for FakeConfigStore {
    fn snapshot(
        &self,
        installation: InstallationId,
    ) -> Result<Option<ConfigSnapshot>, ConfigStoreError> {
        let inner = self.lock();
        Ok(inner.get(&installation).map(|(revision, _, _, value)| {
            ConfigSnapshot::new(ConfigRevision::from_u64(*revision), value.clone())
        }))
    }

    fn put(
        &self,
        installation: InstallationId,
        _format: ConfigFormat,
        _schema_version: ConfigSchemaVersion,
        value: &ConfigValue,
    ) -> Result<ConfigRevision, ConfigStoreError> {
        let mut inner = self.lock();
        let (revision, format, schema_version, _) = inner.get(&installation).cloned().unwrap_or((
            0,
            ConfigFormat::Raw,
            ConfigSchemaVersion::from_u32(0),
            ConfigValue::new(Vec::new())
                .map_err(|_| ConfigStoreError::InvalidArgument("empty value".into()))?,
        ));
        let new_revision = revision.saturating_add(1);
        inner.insert(
            installation,
            (new_revision, format, schema_version, value.clone()),
        );
        Ok(ConfigRevision::from_u64(new_revision))
    }
}

/// FakeStatefulAudit（0.3 state/config/secret 审计的内存实现）。
pub(crate) struct FakeStatefulAudit {
    events: Mutex<Vec<StatefulAuditEvent>>,
}

impl FakeStatefulAudit {
    pub(crate) fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn events(&self) -> Vec<StatefulAuditEvent> {
        match self.events.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    pub(crate) fn contains(&self, predicate: impl Fn(&StatefulAuditEvent) -> bool) -> bool {
        self.events().iter().any(predicate)
    }
}

impl StatefulAuditPort for FakeStatefulAudit {
    fn append(&self, event: StatefulAuditEvent) -> Result<(), AuditError> {
        let mut events = self
            .events
            .lock()
            .map_err(|_| AuditError::Storage(Box::new(std::io::Error::other("lock poisoned"))))?;
        events.push(event);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 0.3.0 scheduler/event（§41.2）：交付 fakes 与受控时钟（scheduler/event/
// lifecycle 测试共用）。
// ---------------------------------------------------------------------------

/// FakeTriggerDelivery（scheduler 交付 port 的内存实现）：记录全部 fire
/// 载荷（scheduler/event/lifecycle 测试共用）。
#[derive(Debug, Default)]
pub(crate) struct FakeTriggerDelivery {
    delivered: Mutex<Vec<TriggerPayload>>,
}

impl FakeTriggerDelivery {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 全部已投递的 fire 载荷（断言用）。
    pub(crate) fn delivered(&self) -> Vec<TriggerPayload> {
        match self.delivered.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl SchedulerDeliveryPort for FakeTriggerDelivery {
    fn on_trigger(&self, payload: TriggerPayload) -> Result<(), SchedulerDeliveryError> {
        let mut delivered = self
            .delivered
            .lock()
            .map_err(|_| SchedulerDeliveryError::Guest("delivery fake lock poisoned"))?;
        delivered.push(payload);
        Ok(())
    }
}

/// FakeEventDelivery（event 交付 port 的内存实现）：记录全部投递事件。
#[derive(Debug, Default)]
pub(crate) struct FakeEventDelivery {
    delivered: Mutex<Vec<DeliveredEvent>>,
}

impl FakeEventDelivery {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 全部已投递事件（断言用）。
    pub(crate) fn delivered(&self) -> Vec<DeliveredEvent> {
        match self.delivered.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }
}

impl EventDeliveryPort for FakeEventDelivery {
    fn on_event(&self, event: DeliveredEvent) -> Result<(), EventDeliveryError> {
        let mut delivered = self
            .delivered
            .lock()
            .map_err(|_| EventDeliveryError::Guest("delivery fake lock poisoned"))?;
        delivered.push(event);
        Ok(())
    }
}

/// PausedClock（受控 UTC 时钟）：tokio **paused-time** 测试下与
/// `tokio::time::advance` 锁步推进的时钟——`now()` 返回
/// `start_utc + 单调流逝`（paused-time 下流逝只由 advance 推进），
/// `sleep` 委托 tokio 定时器（同样受 advance 控制）。scheduler 的 UTC 硬
/// 时刻语义测试无需真实等待（确定性，无 sleep 掩盖竞态）。
#[derive(Debug, Clone)]
pub(crate) struct PausedClock {
    start_utc: UtcInstant,
    start_mono: tokio::time::Instant,
}

impl PausedClock {
    /// 新建受控时钟（UTC 锚点 `start_utc`）。
    pub(crate) fn new(start_utc: UtcInstant) -> Self {
        Self {
            start_utc,
            start_mono: tokio::time::Instant::now(),
        }
    }

    /// 当前 UTC 时刻（paused-time 下由 advance 推进；与
    /// `tokio::time::Instant::elapsed` 锁步）。
    pub(crate) fn utc_now(&self) -> UtcInstant {
        let elapsed = self.start_mono.elapsed();
        let duration = operune_domain::Duration::from_std(elapsed);
        match self.start_utc.checked_add(duration) {
            Ok(instant) => instant,
            Err(_) => self.start_utc,
        }
    }
}

impl Clock for PausedClock {
    fn now(&self) -> Result<UtcInstant, ClockError> {
        Ok(self.utc_now())
    }

    fn sleep(
        &self,
        duration: operune_domain::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(duration.as_std()))
    }
}
