//! application 用例装配（§24.2：server 只做 wiring）。
//!
//! # 缺口声明（见 crate 模块文档"装配缺口"）
//!
//! storage-sqlite 尚未实现 application 的 ports（`ComponentRegistryPort` /
//! `GrantStorePort` / `AuditPort` / `ConfigPort`——storage 的公开面目前是
//! `StorageExecutor` 的 typed 命令 API），因此本模块以**内存 fake** 完成
//! 装配；storage 的 port 实现落地后，替换本模块的 fake 为真实注入即可
//! （`compose_application` 签名不变）。
//!
//! - [`InMemoryRegistry`]：content-addressed 制品/候选/版本绑定/安装记录；
//! - [`InMemoryGrantStore`]：按 InstallationId 的 grant 集（§17.5）；
//! - [`InMemoryAuditLog`]：application 事件审计（内存；durable 审计由
//!   storage 提供——CLI 与存储命令走 storage 的 audit，见 [`crate::audit`]）；
//! - [`StaticConfigPort`]：固定 RuntimeConfig 快照（§18.0 RuntimeConfig
//!   语义：用例层读取的不可变快照）；
//! - [`UnavailableRuntime`]：WasmRuntime 占位——本构建没有任何运行依赖
//!   就绪（runtime-wasm/WASI 接线属其他 agent 的 0.1 微任务），所有调用
//!   返回 [`RuntimeExecutionError::Internal`]（"no runtime available"，
//!   与 application/error.rs 现有错误模型一致）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use operune_application::model::{
    CandidateRecord, DigestVersionBinding, InstallationGrant, InstallationRecord, RuntimeConfig,
};
use operune_application::ports::{
    AuditError, AuditEvent, AuditPort, ComponentRegistryPort, ConfigPort, GrantError,
    GrantStorePort, RegistryError,
};
use operune_application::runtime::{ActiveRuntime, CompiledWasm, PreparedRuntime, RuntimePlan};
use operune_application::{
    ActiveRuntimeRegistry, AssetCache, ContractSurface, InstallService, RuntimeExecutionError,
    UpgradeService, WasmRuntime, contract::GuestComponentDescriptor,
};
use operune_domain::{
    ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest, InstallationId,
};

use crate::error::ServerError;

/// 装配完成的 application 用例层（composition root 注入给 web-admin 与
/// server 状态；0.1 的 InstallService/UpgradeService 以 fake ports 装配）。
pub struct AppServices {
    /// 两阶段安装用例（§19）。
    pub install: InstallService,
    /// 热升级/回滚用例（§20）。
    pub upgrade: UpgradeService,
    /// 不可变 Active 快照注册表（§15.5 / §20.3）。
    pub active: Arc<ActiveRuntimeRegistry>,
    /// Web 资产缓存（§21.3）。
    pub assets: Arc<AssetCache>,
}

/// 装配 application 用例（0.1：内存 fake ports；storage port 实现落地后
/// 在此替换为真实注入）。
pub fn compose_application() -> Result<AppServices, ServerError> {
    let runtime_config = RuntimeConfig::default();
    let registry: Arc<dyn ComponentRegistryPort> = Arc::new(InMemoryRegistry::default());
    let grants: Arc<dyn GrantStorePort> = Arc::new(InMemoryGrantStore::default());
    let audit: Arc<dyn AuditPort> = Arc::new(InMemoryAuditLog::default());
    let config: Arc<dyn ConfigPort> = Arc::new(StaticConfigPort::new(runtime_config.clone()));
    let runtime: Arc<dyn WasmRuntime> = Arc::new(UnavailableRuntime);
    let active = Arc::new(ActiveRuntimeRegistry::new());
    let assets = Arc::new(AssetCache::new(&runtime_config)?);

    let install = InstallService::new(
        Arc::clone(&registry),
        Arc::clone(&grants),
        Arc::clone(&audit),
        Arc::clone(&config),
        Arc::clone(&runtime),
        Arc::clone(&active),
        Arc::clone(&assets),
    );
    let upgrade = UpgradeService::new(
        Arc::clone(&registry),
        Arc::clone(&grants),
        Arc::clone(&audit),
        Arc::clone(&config),
        Arc::clone(&runtime),
        Arc::clone(&active),
        Arc::clone(&assets),
    );

    Ok(AppServices {
        install,
        upgrade,
        active,
        assets,
    })
}

/// 内存注册表状态。
#[derive(Default)]
struct RegistryState {
    /// content-addressed 制品字节（§18.7 final 语义的内存替身）。
    artifacts: HashMap<ContentDigest, Vec<u8>>,
    /// digest 主键的 candidate 记录。
    candidates: HashMap<ContentDigest, CandidateRecord>,
    /// `ComponentId + ComponentVersion -> Digest` 唯一绑定（§19.4）。
    bindings: HashMap<(ComponentId, ComponentVersion), DigestVersionBinding>,
    /// InstallationId 记录。
    installations: HashMap<InstallationId, InstallationRecord>,
}

/// 内存 ComponentRegistryPort fake（缺口声明见模块文档）。
#[derive(Default)]
pub struct InMemoryRegistry {
    inner: Mutex<RegistryState>,
}

impl ComponentRegistryPort for InMemoryRegistry {
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError> {
        let mut state = lock_registry(&self.inner)?;
        state.artifacts.insert(digest, bytes.to_vec());
        Ok(())
    }

    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError> {
        let state = lock_registry(&self.inner)?;
        Ok(state.artifacts.get(&digest).cloned())
    }

    fn upsert_candidate(&self, record: &CandidateRecord) -> Result<(), RegistryError> {
        let mut state = lock_registry(&self.inner)?;
        state.candidates.insert(record.digest, record.clone());
        Ok(())
    }

    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
    ) -> Result<(), RegistryError> {
        let mut inner = lock_registry(&self.inner)?;
        let record = inner
            .candidates
            .get_mut(&digest)
            .ok_or(RegistryError::NotFound("candidate"))?;
        record.state = state;
        Ok(())
    }

    fn candidate(&self, digest: ContentDigest) -> Result<Option<CandidateRecord>, RegistryError> {
        let state = lock_registry(&self.inner)?;
        Ok(state.candidates.get(&digest).cloned())
    }

    fn resolve_version(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<DigestVersionBinding>, RegistryError> {
        let state = lock_registry(&self.inner)?;
        Ok(state
            .bindings
            .get(&(component_id.clone(), version))
            .cloned())
    }

    fn bind_version(&self, binding: &DigestVersionBinding) -> Result<(), RegistryError> {
        let mut state = lock_registry(&self.inner)?;
        let key = (binding.component_id.clone(), binding.version);
        if let Some(existing) = state.bindings.get(&key)
            && existing.digest != binding.digest
        {
            return Err(RegistryError::VersionBindingConflict {
                component_id: binding.component_id.clone(),
                version: binding.version,
                existing: existing.digest,
                incoming: binding.digest,
            });
        }
        state.bindings.insert(key, binding.clone());
        Ok(())
    }

    fn insert_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        let mut state = lock_registry(&self.inner)?;
        state
            .installations
            .insert(record.installation_id, record.clone());
        Ok(())
    }

    fn update_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        self.insert_installation(record)
    }

    fn installation(
        &self,
        id: InstallationId,
    ) -> Result<Option<InstallationRecord>, RegistryError> {
        let state = lock_registry(&self.inner)?;
        Ok(state.installations.get(&id).cloned())
    }

    fn list_installations(&self) -> Result<Vec<InstallationRecord>, RegistryError> {
        let state = lock_registry(&self.inner)?;
        let mut records: Vec<InstallationRecord> = state.installations.values().cloned().collect();
        records.sort_by(|left, right| {
            left.installation_id
                .to_string()
                .cmp(&right.installation_id.to_string())
        });
        Ok(records)
    }
}

fn lock_registry(
    inner: &Mutex<RegistryState>,
) -> Result<std::sync::MutexGuard<'_, RegistryState>, RegistryError> {
    inner
        .lock()
        .map_err(|_| RegistryError::NotFound("registry mutex poisoned"))
}

/// 内存 GrantStorePort fake（§17.5：grant 的 durable owner 是 InstallationId）。
#[derive(Default)]
pub struct InMemoryGrantStore {
    inner: Mutex<HashMap<InstallationId, Vec<InstallationGrant>>>,
}

impl GrantStorePort for InMemoryGrantStore {
    fn grants_for(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<InstallationGrant>, GrantError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| GrantError::NotFound(installation))?;
        Ok(state.get(&installation).cloned().unwrap_or_default())
    }

    fn replace_grants(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
    ) -> Result<(), GrantError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| GrantError::NotFound(installation))?;
        state.insert(installation, grants.to_vec());
        Ok(())
    }
}

/// 内存 AuditPort fake（application 事件审计；durable 审计由 storage 提供）。
#[derive(Default)]
pub struct InMemoryAuditLog {
    inner: Mutex<Vec<AuditEvent>>,
}

impl AuditPort for InMemoryAuditLog {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        let mut state = self.inner.lock().map_err(|_| {
            AuditError::Storage(Box::new(std::io::Error::other(
                "in-memory audit log mutex poisoned",
            )))
        })?;
        state.push(event);
        Ok(())
    }
}

/// 固定 RuntimeConfig 快照的 ConfigPort fake（§18.0 RuntimeConfig 语义）。
#[derive(Debug, Clone)]
pub struct StaticConfigPort {
    config: RuntimeConfig,
}

impl StaticConfigPort {
    /// 以给定快照构造。
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

impl ConfigPort for StaticConfigPort {
    fn snapshot(&self) -> Result<RuntimeConfig, operune_application::ConfigError> {
        Ok(self.config.clone())
    }
}

/// 无可用运行时占位（缺口声明见模块文档）：所有调用返回
/// `RuntimeExecutionError::Internal("no runtime available")`——本构建没有
/// 可实例化的 Component 运行面。
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableRuntime;

impl WasmRuntime for UnavailableRuntime {
    fn compile(&self, _bytes: &[u8]) -> Result<Arc<dyn CompiledWasm>, RuntimeExecutionError> {
        Err(RuntimeExecutionError::Internal(
            "no runtime available in this build (wasm runtime integration pending)",
        ))
    }

    fn contract_surface(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<ContractSurface, RuntimeExecutionError> {
        Err(RuntimeExecutionError::Internal(
            "no runtime available in this build (wasm runtime integration pending)",
        ))
    }

    fn read_descriptor(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<GuestComponentDescriptor, RuntimeExecutionError> {
        Err(RuntimeExecutionError::Internal(
            "no runtime available in this build (wasm runtime integration pending)",
        ))
    }

    fn prepare(
        &self,
        _component: &Arc<dyn CompiledWasm>,
        _plan: &RuntimePlan,
    ) -> Result<Arc<dyn PreparedRuntime>, RuntimeExecutionError> {
        Err(RuntimeExecutionError::Internal(
            "no runtime available in this build (wasm runtime integration pending)",
        ))
    }

    fn instantiate(
        &self,
        _prepared: &Arc<dyn PreparedRuntime>,
    ) -> Result<Arc<dyn ActiveRuntime>, RuntimeExecutionError> {
        Err(RuntimeExecutionError::Internal(
            "no runtime available in this build (wasm runtime integration pending)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use operune_domain::ContentDigest;

    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    #[test]
    fn compose_application_builds() {
        let services = ok(compose_application(), "compose");
        assert!(services.active.list().is_empty());
    }

    #[test]
    fn registry_conflicting_bind_rejected() {
        // §19.4：同一 ComponentId+Version 不同 digest 显式阻断。
        let registry = InMemoryRegistry::default();
        let component = ok(ComponentId::new("com.example.demo"), "component id");
        let version = ok("1.0.0".parse::<ComponentVersion>(), "version");
        let digest_a = ContentDigest::from_bytes(b"a");
        let digest_b = ContentDigest::from_bytes(b"b");
        let binding = DigestVersionBinding {
            component_id: component.clone(),
            version,
            digest: digest_a,
        };
        ok(registry.bind_version(&binding), "first bind");
        let conflict = DigestVersionBinding {
            component_id: component,
            version,
            digest: digest_b,
        };
        assert!(matches!(
            registry.bind_version(&conflict),
            Err(RegistryError::VersionBindingConflict { .. })
        ));
    }

    #[test]
    fn registry_artifact_roundtrip() {
        let registry = InMemoryRegistry::default();
        let digest = ContentDigest::from_bytes(b"payload");
        ok(registry.persist_artifact(digest, b"payload"), "persist");
        assert_eq!(
            ok(registry.artifact_bytes(digest), "read"),
            Some(b"payload".to_vec())
        );
        assert!(
            ok(
                registry.artifact_bytes(ContentDigest::from_bytes(b"other")),
                "missing"
            )
            .is_none()
        );
    }

    #[test]
    fn grant_store_defaults_to_empty() {
        let store = InMemoryGrantStore::default();
        let installation = InstallationId::new();
        assert!(
            ok(store.grants_for(installation), "grants").is_empty(),
            "deny-by-default：未授权 = 空集（§17.2）"
        );
    }

    #[test]
    fn runtime_unavailable_returns_typed_error() {
        // 缺口占位（见模块文档）：typed、可匹配，绝无 panic。
        let runtime = UnavailableRuntime;
        let error = runtime.compile(b"wasm").err();
        assert!(matches!(
            error,
            Some(RuntimeExecutionError::Internal(
                "no runtime available in this build (wasm runtime integration pending)"
            ))
        ));
    }

    #[test]
    fn static_config_snapshot_is_stable() {
        let port = StaticConfigPort::new(RuntimeConfig::default());
        let first = ok(port.snapshot(), "snapshot 1");
        let second = ok(port.snapshot(), "snapshot 2");
        assert_eq!(first, second);
    }
}
