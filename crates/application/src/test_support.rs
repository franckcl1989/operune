//! 测试支持（仅 `#[cfg(test)]` 编译）：fake ports（内存实现）与 fake
//! wasm 执行边界，供用例级测试注入（§24.2 端口注入 / 任务 G）。
//!
//! workspace lints 对测试代码同样 deny `panic!`/`unwrap`/`expect`
//!（§26.1 / §14.2）；断言式失败辅助见 [`test_failure`]。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use operune_domain::{
    CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ConsumerRecord,
    ContentDigest, InstallationId, ProviderRecord,
};

use crate::active::ActiveRuntimeRegistry;
use crate::composition::{ActiveGraph, CompositionService, GraphPolicy};
use crate::contract::{GuestActionRequest, GuestComponentDescriptor};
use crate::error::RuntimeExecutionError;
use crate::install::InstallService;
use crate::model::{
    CandidateRecord, ContractSurface, DigestVersionBinding, GrantApproval, GrantSnapshot,
    InstallRequest, InstallationGrant, InstallationRecord, RuntimeConfig, WebAssetPath,
    WebManifestData,
};
use crate::ports::{
    AuditEvent, AuditPort, ComponentRegistryPort, ConfigPort, GrantError, GrantStorePort,
    GraphRecords, GraphStoreError, InProcessActionPolicy, ProviderGraphPort, RegistryError,
};
use crate::runtime::{ActiveRuntime, CompiledWasm, PreparedRuntime, RuntimePlan, WasmRuntime};
use crate::upgrade::UpgradeService;
use crate::web::{AssetCache, WebBridge};

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
    pub(crate) compile_calls: usize,
    pub(crate) descriptor_calls: usize,
    pub(crate) prepare_calls: usize,
    pub(crate) instantiate_calls: usize,
    pub(crate) asset_reads: usize,
    pub(crate) action_calls: usize,
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
            last_compiled_bytes: Vec::new(),
            prepare_failure: false,
            instantiate_failure: false,
            readiness_failure: false,
            manifest: None,
            assets: HashMap::new(),
            action_result_ok: Some(vec![1, 2, 3]),
            compile_calls: 0,
            descriptor_calls: 0,
            prepare_calls: 0,
            instantiate_calls: 0,
            asset_reads: 0,
            action_calls: 0,
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
        }
    }
}
