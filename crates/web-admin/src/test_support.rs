//! 测试支持（仅 `#[cfg(test)]`）：fake ports 与测试装配 harness。
//!
//! - fake ports：application 的 port traits 的内存实现（§24.2 端口注入）；
//! - [`NeverRuntime`]：永不被调用的 [`WasmRuntime`] 桩（application 的
//!   `GuestComponentDescriptor` 字段是 pub(crate)，适配层无法构造真实
//!   descriptor——安装管线不能在 web-admin 测试中端到端执行；HTTP 层测试
//!   使用 [`FakeAdminApi`] 注入，见 crate 文档的 API 缺口说明）；
//! - [`TestHarness`]：装配 [`RealAdminApi`] + 各 port 引用（facade 单元测试）。
//!
//! workspace lints 对测试代码同样 deny `panic!`/`unwrap`/`expect`（§26.1）；
//! 断言式失败辅助见 [`ok_or_fail`]（与 application test_support 同模式）。

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use operune_application::contract::GuestComponentDescriptor;
use operune_application::ports::{
    AuditEvent as AppAuditEvent, AuditPort, ComponentRegistryPort, ConfigError, ConfigPort,
    GrantError, GrantStorePort, RegistryError, UninstallStorePort,
};
use operune_application::{
    ActiveRuntimeRegistry, ContractSurface, InProcessActionPolicy, InstallOutcome, InstallService,
    InstallationGrant, RuntimeConfig, UninstallService, UpgradeOutcome, UpgradeService,
    WasmRuntime, WebBridge,
};
use operune_domain::{
    CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest,
    InstallationId,
};
use operune_security::password::PasswordHasher;
use operune_security::session::{InMemorySessionStore, SessionManager};
use operune_security::tls::TlsIdentity;
use secrecy::{ExposeSecret, SecretString};

use crate::facade::{
    AdminError, AdminUserStore, AuditLogView, InMemoryAdminUserStore, InMemoryAuditLog,
    RealAdminApi, SafeModeState,
};

// ---------------------------------------------------------------------------
// 断言式失败辅助（§26.1 允许测试断言语义）
// ---------------------------------------------------------------------------

/// 断言 `Result` 为 `Ok` 并取出值；否则以测试失败语义中止。
pub(crate) fn ok_or_fail<T, E: fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    assert!(
        result.is_ok(),
        "{what} 应成功，实际 Err: {:?}",
        result.as_ref().err()
    );
    match result {
        Ok(value) => value,
        Err(_) => unreachable!("上面的断言已保证 is_ok"),
    }
}

/// 断言 `Option` 为 `Some` 并取出值；否则以测试失败语义中止。
pub(crate) fn some_or_fail<T>(option: Option<T>, what: &str) -> T {
    assert!(option.is_some(), "{what} 应为 Some");
    match option {
        Some(value) => value,
        None => unreachable!("上面的断言已保证 is_some"),
    }
}

/// TLS 测试身份（提交的 fixture PEM，§16.2 装配测试用）。
pub(crate) fn test_identity() -> TlsIdentity {
    let cert = include_bytes!("../tests/fixtures/server-cert.pem");
    let key = include_bytes!("../tests/fixtures/server-key.pem");
    ok_or_fail(
        TlsIdentity::from_pem(cert, key),
        "load TLS test identity from fixtures",
    )
}

// ---------------------------------------------------------------------------
// Fake ports（application port traits 的内存实现）
// ---------------------------------------------------------------------------

/// Fake 注册表（§18.3 形状对齐 application test_support）。
pub(crate) struct FakeRegistry {
    artifacts: Mutex<HashMap<ContentDigest, Vec<u8>>>,
    candidates: Mutex<HashMap<ContentDigest, CandidateRecordLike>>,
    bindings: Mutex<HashMap<(ComponentId, ComponentVersion), BindingLike>>,
    installations: Mutex<HashMap<InstallationId, operune_application::InstallationRecord>>,
}

/// 记录类型别名（避免导入噪音）。
pub(crate) type CandidateRecordLike = operune_application::CandidateRecord;
pub(crate) type BindingLike = operune_application::DigestVersionBinding;

impl FakeRegistry {
    pub(crate) fn new() -> Self {
        Self {
            artifacts: Mutex::new(HashMap::new()),
            candidates: Mutex::new(HashMap::new()),
            bindings: Mutex::new(HashMap::new()),
            installations: Mutex::new(HashMap::new()),
        }
    }

    /// 插入一条 Active 记录（disable 测试用）；返回安装 id。
    pub(crate) fn insert_active_record(&self) -> InstallationId {
        let installation = InstallationId::new();
        let record = operune_application::InstallationRecord {
            installation_id: installation,
            component_id: ok_or_fail(ComponentId::new("demo"), "component id"),
            version: ComponentVersion::from_parts(1, 0, 0),
            active_digest: Some(ContentDigest::from_bytes(b"demo bytes")),
            last_known_good_digest: None,
            state: ComponentLifecycleState::Active,
        };
        let mut installations = match self.installations.lock() {
            Ok(guard) => guard,
            Err(_) => unreachable!("poisoned fake registry"),
        };
        installations.insert(installation, record);
        installation
    }

    pub(crate) fn installation(
        &self,
        id: InstallationId,
    ) -> Option<operune_application::InstallationRecord> {
        match self.installations.lock() {
            Ok(guard) => guard.get(&id).cloned(),
            Err(_) => None,
        }
    }

    /// 移除安装记录（卸载存储副作用的落点，§39.2 remove）。
    pub(crate) fn remove_installation(&self, id: InstallationId) {
        if let Ok(mut guard) = self.installations.lock() {
            guard.remove(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// FakeUninstallStore（§39.2 remove：记录调用 + 模拟真实存储的单事务删除）
// ---------------------------------------------------------------------------

/// 假卸载存储面：记录调用并可注入"安装记录随卸载消失"的副作用。
pub(crate) struct FakeUninstallStore {
    removed: std::sync::Mutex<Vec<InstallationId>>,
    effect: std::sync::Mutex<Option<RemoveEffect>>,
}

/// 删除副作用（模拟真实存储"单事务删除"的完整性）。
type RemoveEffect = Arc<dyn Fn(InstallationId) + Send + Sync>;

impl FakeUninstallStore {
    pub(crate) fn new() -> Self {
        Self {
            removed: std::sync::Mutex::new(Vec::new()),
            effect: std::sync::Mutex::new(None),
        }
    }

    /// 接线删除副作用（harness 在构造期调用一次）。
    pub(crate) fn with_effect(&self, effect: RemoveEffect) {
        if let Ok(mut slot) = self.effect.lock() {
            *slot = Some(effect);
        }
    }
}

impl UninstallStorePort for FakeUninstallStore {
    fn remove_installation(
        &self,
        installation: InstallationId,
        _audit: AppAuditEvent,
    ) -> Result<(), RegistryError> {
        {
            let mut removed = self
                .removed
                .lock()
                .map_err(|_| RegistryError::Storage(Box::new(std::io::Error::other("poisoned"))))?;
            removed.push(installation);
        }
        let effect = match self.effect.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => None,
        };
        if let Some(effect) = effect {
            effect(installation);
        }
        Ok(())
    }
}

impl ComponentRegistryPort for FakeRegistry {
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError> {
        let mut artifacts = self.artifacts.lock().map_err(|_| storage_err("poisoned"))?;
        artifacts.insert(digest, bytes.to_vec());
        Ok(())
    }

    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError> {
        let artifacts = self.artifacts.lock().map_err(|_| storage_err("poisoned"))?;
        Ok(artifacts.get(&digest).cloned())
    }

    fn upsert_candidate(&self, record: &CandidateRecordLike) -> Result<(), RegistryError> {
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        candidates.insert(record.digest, record.clone());
        Ok(())
    }

    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
    ) -> Result<(), RegistryError> {
        let mut candidates = self
            .candidates
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        match candidates.get_mut(&digest) {
            Some(record) => {
                record.state = state;
                Ok(())
            }
            None => Err(RegistryError::NotFound("candidate")),
        }
    }

    fn candidate(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<CandidateRecordLike>, RegistryError> {
        let candidates = self
            .candidates
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        Ok(candidates.get(&digest).cloned())
    }

    fn resolve_version(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<BindingLike>, RegistryError> {
        let bindings = self.bindings.lock().map_err(|_| storage_err("poisoned"))?;
        Ok(bindings.get(&(component_id.clone(), version)).cloned())
    }

    fn bind_version(&self, binding: &BindingLike) -> Result<(), RegistryError> {
        let mut bindings = self.bindings.lock().map_err(|_| storage_err("poisoned"))?;
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

    fn insert_installation(
        &self,
        record: &operune_application::InstallationRecord,
    ) -> Result<(), RegistryError> {
        let mut installations = self
            .installations
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        installations.insert(record.installation_id, record.clone());
        Ok(())
    }

    fn update_installation(
        &self,
        record: &operune_application::InstallationRecord,
    ) -> Result<(), RegistryError> {
        let mut installations = self
            .installations
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        installations.insert(record.installation_id, record.clone());
        Ok(())
    }

    fn installation(
        &self,
        id: InstallationId,
    ) -> Result<Option<operune_application::InstallationRecord>, RegistryError> {
        let installations = self
            .installations
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        Ok(installations.get(&id).cloned())
    }

    fn list_installations(
        &self,
    ) -> Result<Vec<operune_application::InstallationRecord>, RegistryError> {
        let installations = self
            .installations
            .lock()
            .map_err(|_| storage_err("poisoned"))?;
        Ok(installations.values().cloned().collect())
    }
}

fn storage_err(what: &str) -> RegistryError {
    RegistryError::Storage(Box::new(std::io::Error::other(what)))
}

/// Fake grants（§17.5 绑定 InstallationId）。
pub(crate) struct FakeGrants {
    grants: Mutex<HashMap<InstallationId, Vec<InstallationGrant>>>,
}

impl FakeGrants {
    pub(crate) fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
        }
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
            .map_err(|_| GrantError::Storage(Box::new(std::io::Error::other("poisoned"))))?;
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
            .map_err(|_| GrantError::Storage(Box::new(std::io::Error::other("poisoned"))))?;
        store.insert(installation, grants.to_vec());
        Ok(())
    }
}

/// Fake config（§18.0 快照）。
pub(crate) struct FakeConfig {
    config: RuntimeConfig,
}

impl FakeConfig {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self::new(RuntimeConfig::default())
    }
}

impl ConfigPort for FakeConfig {
    fn snapshot(&self) -> Result<RuntimeConfig, ConfigError> {
        Ok(self.config.clone())
    }
}

/// Fake application audit（管道事件；§18.7）。
pub(crate) struct FakeAppAudit {
    events: Mutex<Vec<AppAuditEvent>>,
}

impl FakeAppAudit {
    pub(crate) fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }
}

impl AuditPort for FakeAppAudit {
    fn append(&self, event: AppAuditEvent) -> Result<(), operune_application::ports::AuditError> {
        let mut events = self.events.lock().map_err(|_| {
            operune_application::ports::AuditError::Storage(Box::new(std::io::Error::other(
                "poisoned",
            )))
        })?;
        events.push(event);
        Ok(())
    }
}

/// 永不被调用的 [`WasmRuntime`] 桩：所有执行方法返回确定性错误。
///
/// application 的 `GuestComponentDescriptor` 字段为 pub(crate)，适配层无法
/// 构造合法 descriptor 返回值，因此 web-admin 测试不能端到端驱动安装管线
/// （API 缺口，见 crate 文档）；`RealAdminApi` 的安装/升级路径以
/// [`FakeAdminApi`] 在 HTTP 层注入假用例覆盖。
pub(crate) struct NeverRuntime;

impl WasmRuntime for NeverRuntime {
    fn compile(
        &self,
        _bytes: &[u8],
    ) -> Result<Arc<dyn operune_application::CompiledWasm>, ApplicationError_> {
        Err(not_executable())
    }

    fn contract_surface(
        &self,
        _component: &Arc<dyn operune_application::CompiledWasm>,
    ) -> Result<ContractSurface, ApplicationError_> {
        Err(not_executable())
    }

    fn read_descriptor(
        &self,
        _component: &Arc<dyn operune_application::CompiledWasm>,
    ) -> Result<GuestComponentDescriptor, ApplicationError_> {
        Err(not_executable())
    }

    fn prepare(
        &self,
        _component: &Arc<dyn operune_application::CompiledWasm>,
        _plan: &operune_application::RuntimePlan,
    ) -> Result<Arc<dyn operune_application::PreparedRuntime>, ApplicationError_> {
        Err(not_executable())
    }

    fn instantiate(
        &self,
        _prepared: &Arc<dyn operune_application::PreparedRuntime>,
    ) -> Result<Arc<dyn operune_application::ActiveRuntime>, ApplicationError_> {
        Err(not_executable())
    }
}

/// application 的 RuntimeExecutionError 别名（WasmRuntime 的 Err 类型）。
type ApplicationError_ = operune_application::RuntimeExecutionError;

fn not_executable() -> ApplicationError_ {
    ApplicationError_::Internal("NeverRuntime stub invoked (web-admin test support)")
}

// ---------------------------------------------------------------------------
// TestHarness（facade 单元测试装配）
// ---------------------------------------------------------------------------

/// facade 单元测试 harness：装配 [`RealAdminApi`] 并暴露各 port 引用。
pub(crate) struct TestHarness {
    pub(crate) api: RealAdminApi,
    pub(crate) registry: Arc<FakeRegistry>,
    pub(crate) admin_audit: Arc<InMemoryAuditLog>,
    pub(crate) users: Arc<InMemoryAdminUserStore>,
    pub(crate) sessions: Arc<InMemorySessionStore>,
    pub(crate) session_manager: SessionManager,
}

impl TestHarness {
    pub(crate) fn new(config: RuntimeConfig) -> Self {
        let registry = Arc::new(FakeRegistry::new());
        let grants = Arc::new(FakeGrants::new());
        let config = Arc::new(FakeConfig::new(config));
        let app_audit = Arc::new(FakeAppAudit::new());
        let admin_audit = Arc::new(InMemoryAuditLog::new());
        let users = Arc::new(InMemoryAdminUserStore::new(PasswordHasher::default()));
        let sessions = Arc::new(InMemorySessionStore::new());
        let session_manager =
            SessionManager::new(operune_security::session::SessionPolicy::DEFAULT);
        let active = Arc::new(ActiveRuntimeRegistry::new());
        let assets = Arc::new(ok_or_fail(
            operune_application::AssetCache::new(&RuntimeConfig::default()),
            "asset cache",
        ));
        let policy = Arc::new(InProcessActionPolicy::new(
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&config) as Arc<dyn ConfigPort>,
        ));
        let runtime = Arc::new(NeverRuntime) as Arc<dyn WasmRuntime>;
        let install = InstallService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&app_audit) as Arc<dyn AuditPort>,
            Arc::clone(&config) as Arc<dyn ConfigPort>,
            Arc::clone(&runtime),
            Arc::clone(&active),
            Arc::clone(&assets),
        );
        let upgrade = UpgradeService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&app_audit) as Arc<dyn AuditPort>,
            Arc::clone(&config) as Arc<dyn ConfigPort>,
            Arc::clone(&runtime),
            Arc::clone(&active),
            Arc::clone(&assets),
        );
        let uninstall_store = Arc::new(FakeUninstallStore::new());
        uninstall_store.with_effect(Arc::new({
            // 模拟真实存储"单事务删除"：安装记录随卸载消失（§42.4）。
            let registry = Arc::clone(&registry);
            move |installation| registry.remove_installation(installation)
        }));
        let uninstall = UninstallService::new(
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&uninstall_store) as Arc<dyn UninstallStorePort>,
            Arc::clone(&app_audit) as Arc<dyn AuditPort>,
            Arc::clone(&config) as Arc<dyn ConfigPort>,
            Arc::clone(&active),
        );
        let _web = WebBridge::new(
            Arc::clone(&active),
            Arc::clone(&assets),
            policy,
            Arc::clone(&app_audit) as Arc<dyn AuditPort>,
        );
        let api = RealAdminApi::new(
            install,
            upgrade,
            uninstall,
            Arc::clone(&active),
            Arc::clone(&registry) as Arc<dyn ComponentRegistryPort>,
            Arc::clone(&grants) as Arc<dyn GrantStorePort>,
            Arc::clone(&config) as Arc<dyn ConfigPort>,
            Arc::clone(&admin_audit) as Arc<dyn operune_observability::AuditSink>,
            Arc::clone(&users) as Arc<dyn AdminUserStore>,
            Arc::clone(&admin_audit) as Arc<dyn AuditLogView>,
            Arc::clone(&sessions) as Arc<dyn crate::compat::SendableSessionStore>,
            session_manager,
            Arc::new(SafeModeState::new()),
            PasswordHasher::default(),
        );
        Self {
            api,
            registry,
            admin_audit,
            users,
            sessions,
            session_manager,
        }
    }

    /// 在用户 store 中创建启用用户（登录/授权测试种子）。
    pub(crate) fn seed_user(&self, subject: &str, password: &str) {
        let hasher = PasswordHasher::default();
        let hash = ok_or_fail(hasher.hash(&SecretString::from(password)), "seed user hash");
        ok_or_fail(
            self.users.create(crate::facade::AdminUser {
                subject: subject.to_owned(),
                enabled: true,
                password_hash: hash,
            }),
            "seed user",
        );
    }

    /// 创建一条 Active 安装记录（component 视图测试）。
    pub(crate) fn insert_active_record(&self) -> InstallationId {
        self.registry.insert_active_record()
    }
}

/// 便捷构造：默认 config 的 harness。
pub(crate) fn harness() -> TestHarness {
    TestHarness::new(RuntimeConfig::default())
}

// ---------------------------------------------------------------------------
// FakeAdminApi（HTTP 层测试的假用例；§32 注入缝）
// ---------------------------------------------------------------------------

/// 记录一次假用例调用（断言用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RecordedCall {
    Status,
    ListComponents,
    Component(InstallationId),
    Install {
        byte_len: usize,
        grants: usize,
    },
    Upgrade {
        id: InstallationId,
        byte_len: usize,
        explicit_grants: bool,
    },
    Rollback(InstallationId),
    Disable(InstallationId),
    Enable(InstallationId),
    Remove(InstallationId),
    GrantsFor(InstallationId),
    ReplaceGrants {
        id: InstallationId,
        grants: usize,
    },
    ListUsers,
    CreateUser {
        subject: String,
        password_len: usize,
    },
    SetUserEnabled {
        subject: String,
        enabled: bool,
    },
    Config,
    AuditRecent(usize),
    SafeModeStatus,
    SetSafeMode(bool),
}

/// 假用例：HTTP 层测试注入（§32：auth/RBAC/CSRF 与路由语义的测试面）。
///
/// 行为配置在共享 `Arc` 上经内部可变性完成（`with_*` 取 `&self`）。
pub(crate) struct FakeAdminApi {
    calls: Mutex<Vec<RecordedCall>>,
    config: Mutex<FakeAdminConfig>,
}

/// 假用例的可配置行为。
#[derive(Default)]
struct FakeAdminConfig {
    users: Vec<crate::facade::AdminUserView>,
    components: Vec<crate::facade::ComponentView>,
    grants: Vec<InstallationGrant>,
    audit: Vec<operune_observability::AuditEvent>,
    safe_mode: bool,
    next_install: Option<Result<InstallOutcome, AdminError>>,
    next_upgrade: Option<Result<UpgradeOutcome, AdminError>>,
    next_remove: Option<Result<(), AdminError>>,
}

impl FakeAdminApi {
    pub(crate) fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            config: Mutex::new(FakeAdminConfig::default()),
        }
    }

    fn with_config(&self, f: impl FnOnce(&mut FakeAdminConfig)) {
        if let Ok(mut config) = self.config.lock() {
            f(&mut config);
        }
    }

    pub(crate) fn with_install(&self, outcome: InstallOutcome) {
        self.with_config(|config| config.next_install = Some(Ok(outcome)));
    }

    pub(crate) fn with_upgrade(&self, outcome: UpgradeOutcome) {
        self.with_config(|config| config.next_upgrade = Some(Ok(outcome)));
    }

    /// 脚本化下一次 remove 的结果（默认 Ok(())；失败用于错误页断言）。
    pub(crate) fn with_remove(&self, result: Result<(), AdminError>) {
        self.with_config(|config| config.next_remove = Some(result));
    }

    /// 预置组件视图（列表 / 详情 / 确认页渲染测试的种子）。
    pub(crate) fn with_components(&self, components: Vec<crate::facade::ComponentView>) {
        self.with_config(|config| config.components = components);
    }

    pub(crate) fn calls(&self) -> Vec<RecordedCall> {
        match self.calls.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn record(&self, call: RecordedCall) {
        if let Ok(mut guard) = self.calls.lock() {
            guard.push(call);
        }
    }
}

impl crate::facade::AdminApi for FakeAdminApi {
    fn status(&self) -> Result<crate::facade::StatusView, AdminError> {
        self.record(RecordedCall::Status);
        let safe_mode = match self.config.lock() {
            Ok(config) => config.safe_mode,
            Err(_) => false,
        };
        Ok(crate::facade::StatusView {
            installations: Vec::new(),
            active: Vec::new(),
            config: crate::facade::ConfigView::from_config(&RuntimeConfig::default()),
            safe_mode,
        })
    }

    fn list_components(&self) -> Result<Vec<crate::facade::ComponentView>, AdminError> {
        self.record(RecordedCall::ListComponents);
        match self.config.lock() {
            Ok(config) => Ok(config.components.clone()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn component(&self, id: InstallationId) -> Result<crate::facade::ComponentView, AdminError> {
        self.record(RecordedCall::Component(id));
        let components = match self.config.lock() {
            Ok(config) => config.components.clone(),
            Err(_) => Vec::new(),
        };
        match components
            .iter()
            .find(|view| view.record.installation_id == id)
        {
            Some(view) => Ok(view.clone()),
            None => Err(AdminError::NotFound(id)),
        }
    }

    fn install(
        &self,
        bytes: Vec<u8>,
        grants: Vec<InstallationGrant>,
    ) -> Result<InstallOutcome, AdminError> {
        let len = bytes.len();
        let grant_count = grants.len();
        self.record(RecordedCall::Install {
            byte_len: len,
            grants: grant_count,
        });
        let mut config = self
            .config
            .lock()
            .map_err(|_| AdminError::Unsupported("fake poisoned"))?;
        config
            .next_install
            .take()
            .ok_or_else(|| AdminError::Unsupported("fake install not configured"))?
    }

    fn upgrade(
        &self,
        id: InstallationId,
        bytes: Vec<u8>,
        grants: Option<Vec<InstallationGrant>>,
    ) -> Result<UpgradeOutcome, AdminError> {
        let len = bytes.len();
        self.record(RecordedCall::Upgrade {
            id,
            byte_len: len,
            explicit_grants: grants.is_some(),
        });
        let mut config = self
            .config
            .lock()
            .map_err(|_| AdminError::Unsupported("fake poisoned"))?;
        config
            .next_upgrade
            .take()
            .ok_or_else(|| AdminError::Unsupported("fake upgrade not configured"))?
    }

    fn rollback(&self, id: InstallationId) -> Result<UpgradeOutcome, AdminError> {
        self.record(RecordedCall::Rollback(id));
        let mut config = self
            .config
            .lock()
            .map_err(|_| AdminError::Unsupported("fake poisoned"))?;
        config
            .next_upgrade
            .take()
            .ok_or_else(|| AdminError::Unsupported("fake rollback not configured"))?
    }

    fn disable(&self, id: InstallationId) -> Result<(), AdminError> {
        self.record(RecordedCall::Disable(id));
        Ok(())
    }

    fn enable(&self, id: InstallationId) -> Result<(), AdminError> {
        self.record(RecordedCall::Enable(id));
        Ok(())
    }

    fn remove(&self, id: InstallationId) -> Result<(), AdminError> {
        self.record(RecordedCall::Remove(id));
        let mut config = self
            .config
            .lock()
            .map_err(|_| AdminError::Unsupported("fake poisoned"))?;
        match config.next_remove.take() {
            Some(result) => result,
            None => Ok(()),
        }
    }

    fn grants_for(&self, id: InstallationId) -> Result<Vec<InstallationGrant>, AdminError> {
        self.record(RecordedCall::GrantsFor(id));
        match self.config.lock() {
            Ok(config) => Ok(config.grants.clone()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn replace_grants(
        &self,
        id: InstallationId,
        grants: Vec<InstallationGrant>,
    ) -> Result<(), AdminError> {
        let count = grants.len();
        self.record(RecordedCall::ReplaceGrants { id, grants: count });
        Ok(())
    }

    fn list_users(&self) -> Result<Vec<crate::facade::AdminUserView>, AdminError> {
        self.record(RecordedCall::ListUsers);
        match self.config.lock() {
            Ok(config) => Ok(config.users.clone()),
            Err(_) => Ok(Vec::new()),
        }
    }

    fn create_user(&self, subject: String, password: SecretString) -> Result<(), AdminError> {
        let len = password.expose_secret().len();
        self.record(RecordedCall::CreateUser {
            subject,
            password_len: len,
        });
        Ok(())
    }

    fn set_user_enabled(&self, subject: String, enabled: bool) -> Result<(), AdminError> {
        self.record(RecordedCall::SetUserEnabled { subject, enabled });
        Ok(())
    }

    fn config(&self) -> Result<RuntimeConfig, AdminError> {
        self.record(RecordedCall::Config);
        Ok(RuntimeConfig::default())
    }

    fn audit_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<operune_observability::AuditEvent>, AdminError> {
        self.record(RecordedCall::AuditRecent(limit));
        let audit = match self.config.lock() {
            Ok(config) => config.audit.clone(),
            Err(_) => Vec::new(),
        };
        let take = limit.min(audit.len());
        Ok(audit[audit.len() - take..].to_vec())
    }

    fn safe_mode_status(&self) -> bool {
        self.record(RecordedCall::SafeModeStatus);
        match self.config.lock() {
            Ok(config) => config.safe_mode,
            Err(_) => false,
        }
    }

    fn set_safe_mode(&self, enabled: bool) -> Result<(), AdminError> {
        self.record(RecordedCall::SetSafeMode(enabled));
        Ok(())
    }
}

/// 构造一个 unscoped grant（测试辅助）。
pub(crate) fn grant(capability: &str) -> InstallationGrant {
    InstallationGrant {
        capability: ok_or_fail(CapabilityId::new(capability), "capability id"),
        scope: operune_application::GrantScope::Unscoped,
    }
}

/// 构造一个 action-scoped grant（测试辅助）。
pub(crate) fn action_grant(capability: &str, action: &str) -> InstallationGrant {
    InstallationGrant {
        capability: ok_or_fail(CapabilityId::new(capability), "capability id"),
        scope: operune_application::GrantScope::Action {
            name: action.to_owned(),
        },
    }
}
