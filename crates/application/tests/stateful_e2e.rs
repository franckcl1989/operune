//! 0.3.0 Stateful Runtime 端到端测试（§41.2 / §41.3）：**真实 storage
//! executor**（tempdir 隔离 data root）上跑通 application 层的
//! StateService / StateMigrationService / ConfigService / SecretService。
//!
//! 本测试同时是 **port 契约形状验证**：把 application 的 0.3 port traits
//! 实现在真实 executor 上（`block_on` 同步桥接，与 storage-sqlite 接线
//! 里程碑同模式），证明签名形状（domain 类型、事务句柄映射、revision/
//! version 返回值）与 executor 的 0.3 命令一一可接。接线层正式实现仍属
//! 下一里程碑（storage-sqlite/src/ports.rs，`submit_blocking`）；本测试的
//! 桥接实现与正式接线的唯一差别是同步驱动方式。
//!
//! 注意：storage 的 [`StateTransactionHandle`] 构造器是 `pub(crate)`，
//! 外部无法从 domain [`StateTransactionId`] 反推——本测试（以及正式接线）
//! 以 begin 时建立的 `id → handle` 映射桥接（executor 单连接串行 ⇒
//! 映射一致，无并发交错）。若正式接线选择让 executor 直接接受
//! [`StateTransactionId`]，需要 storage-sqlite 侧的 API 调整（见任务报告）。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use operune_application::config::ConfigService;
use operune_application::migration::{MigrationOutcome, StateMigrationService};
use operune_application::ports::{
    AuditError, ComponentConfigStorePort, ConfigStoreError, SecretCiphertextRecord,
    SecretGrantPort, SecretStoreError, SecretStorePort, StateStoreError, StateStorePort,
    StatefulAuditEvent, StatefulAuditPort,
};
use operune_application::secret::SecretService;
use operune_application::state::{CasOutcome, MigrationGate, StateService};
use operune_domain::{
    ComponentId, ComponentVersion, ConfigFormat, ConfigRevision, ConfigSchemaVersion,
    ConfigSnapshot, ConfigValue, InstallationId, SecretMetadata, SecretName, SecretVersion,
    StateKey, StateSchemaVersion, StateTransactionId, StateValue,
};
use operune_security::secret::SecretBytes;
use operune_security::secret_store::{KEK_SIZE, SecretCipher};
use operune_storage_sqlite::executor::{ExecutorConfig, StorageExecutor};
use operune_storage_sqlite::model::{
    AuditActor, AuditCategory, AuditEvent, AuditOutcome, ComponentConfigRecord,
    ConfigFormat as StorageConfigFormat, SecretName as StorageSecretName, SecretRecord,
    StateTransactionHandle, StateValueRecord,
};
use operune_storage_sqlite::{DataRoot, StorageError};
use secrecy::ExposeSecret;
use tokio::runtime::Runtime;

/// 断言式失败（workspace lints deny panic!/unwrap!/expect!，§26.1；
/// 与 lib 内 test_support 同模式）。
#[allow(clippy::assertions_on_constants)]
fn test_failure(message: impl std::fmt::Display) -> ! {
    assert!(false, "{message}");
    std::process::abort();
}

fn ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => test_failure(format_args!("{what} failed: {error}")),
    }
}

// ---------------------------------------------------------------------------
// 同步桥接（§18.2：block_on 驱动 async executor；单线程测试，无嵌套
// runtime 风险）。
// ---------------------------------------------------------------------------

struct ExecutorBridge {
    executor: StorageExecutor,
    runtime: Runtime,
    /// domain 事务身份 → storage 事务句柄（begin 时建立；storage 句柄
    /// 构造器 pub(crate)，外部只能经映射引用）。
    tx_map: Mutex<HashMap<StateTransactionId, StateTransactionHandle>>,
    next_tx: Mutex<u64>,
}

impl ExecutorBridge {
    fn open(dir: &std::path::Path) -> Self {
        let data_root = ok(DataRoot::new(dir.to_path_buf()), "data root");
        let config = ok(ExecutorConfig::new(data_root), "executor config");
        let runtime = ok(Runtime::new(), "tokio runtime");
        let executor = ok(
            runtime.block_on(StorageExecutor::open(config)),
            "open executor",
        );
        Self {
            executor,
            runtime,
            tx_map: Mutex::new(HashMap::new()),
            next_tx: Mutex::new(0),
        }
    }

    fn register_component(&self, component: ComponentId) -> InstallationId {
        let limit = ok(operune_domain::ByteSize::mib(16), "limit");
        let version = ok("1.0.0".parse::<ComponentVersion>(), "parse version");
        let staged = ok(
            self.runtime
                .block_on(self.executor.stage_bytes(b"e2e-component".to_vec(), limit)),
            "stage",
        );
        ok(
            self.runtime.block_on(
                self.executor
                    .record_quarantine(staged.clone(), audit("quarantine")),
            ),
            "quarantine",
        );
        ok(
            self.runtime.block_on(self.executor.commit_candidate(
                staged.digest,
                component.clone(),
                version,
                audit("candidate"),
            )),
            "candidate",
        );
        ok(
            self.runtime.block_on(
                self.executor
                    .create_installation(component, audit("install")),
            ),
            "create installation",
        )
    }

    fn remember_tx(&self, handle: StateTransactionHandle) -> StateTransactionId {
        let mut counter = self
            .next_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *counter = counter.saturating_add(1);
        let id = StateTransactionId::from_u64(*counter);
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, handle);
        id
    }

    fn take_tx(&self, tx: StateTransactionId) -> Result<StateTransactionHandle, StateStoreError> {
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&tx)
            .ok_or_else(|| {
                StateStoreError::TransactionConflict(
                    "operation on a state transaction that is not in progress".into(),
                )
            })
    }

    fn handle_of(&self, tx: StateTransactionId) -> Result<StateTransactionHandle, StateStoreError> {
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&tx)
            .copied()
            .ok_or_else(|| {
                StateStoreError::TransactionConflict(
                    "operation on a state transaction that is not in progress".into(),
                )
            })
    }
}

fn audit(action: &'static str) -> AuditEvent {
    ok(
        AuditEvent::new(
            AuditActor::System,
            AuditCategory::ComponentLifecycle,
            action,
            None,
            AuditOutcome::Success,
            None,
        ),
        "audit event",
    )
}

// ---------------------------------------------------------------------------
// storage 错误 → application port 错误映射（与正式接线同模式，§14.1）。
// ---------------------------------------------------------------------------

fn map_state_error(error: StorageError) -> StateStoreError {
    match error {
        StorageError::NotFound(message) => StateStoreError::NotFound(message),
        StorageError::SchemaVersionMismatch {
            installation,
            expected,
            requested,
        } => StateStoreError::SchemaVersionMismatch {
            installation,
            current: Some(StateSchemaVersion::from_u32(expected.as_u32())),
            requested: StateSchemaVersion::from_u32(requested.as_u32()),
        },
        StorageError::StateTransactionConflict(message) => {
            StateStoreError::TransactionConflict(message)
        }
        StorageError::InvalidArgument(message) => StateStoreError::InvalidArgument(message),
        StorageError::CorruptState(message) => StateStoreError::Corrupt(message),
        other => StateStoreError::Storage(Box::new(other)),
    }
}

fn map_secret_error(error: StorageError) -> SecretStoreError {
    match error {
        StorageError::NotFound(message) => SecretStoreError::NotFound(message),
        StorageError::InvalidArgument(message) => SecretStoreError::InvalidArgument(message),
        StorageError::CorruptState(message) => SecretStoreError::Corrupt(message),
        other => SecretStoreError::Storage(Box::new(other)),
    }
}

fn map_config_error(error: StorageError) -> ConfigStoreError {
    match error {
        StorageError::NotFound(message) => ConfigStoreError::NotFound(message),
        StorageError::InvalidArgument(message) => ConfigStoreError::InvalidArgument(message),
        StorageError::CorruptState(message) => ConfigStoreError::Corrupt(message),
        other => ConfigStoreError::Storage(Box::new(other)),
    }
}

// ---------------------------------------------------------------------------
// port traits 的真实 executor 实现（接线形状验证）。
// ---------------------------------------------------------------------------

/// domain `StateKey` → storage `StateKey`（§13.3 边界解析一次；两侧字符集
/// 一致，失败 = 契约违反 fail closed）。
fn to_storage_state_key(
    key: &StateKey,
) -> Result<operune_storage_sqlite::StateKey, StateStoreError> {
    operune_storage_sqlite::StateKey::new(key.as_str()).map_err(map_state_error)
}

/// domain `StateSchemaVersion` → storage `StateSchemaVersion`（u32 一一
/// 对应，不可失败）。
fn to_storage_schema_version(
    version: StateSchemaVersion,
) -> operune_storage_sqlite::StateSchemaVersion {
    operune_storage_sqlite::StateSchemaVersion::new(version.as_u32())
}

struct ExecutorStateStore {
    bridge: Arc<ExecutorBridge>,
}

impl StateStorePort for ExecutorStateStore {
    fn get(
        &self,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        let record = self
            .bridge
            .runtime
            .block_on(self.bridge.executor.get_state(installation, &storage_key))
            .map_err(map_state_error)?;
        record.map(to_domain_state_value).transpose()
    }

    fn put(
        &self,
        installation: InstallationId,
        key: &StateKey,
        schema_version: StateSchemaVersion,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        self.bridge
            .runtime
            .block_on(self.bridge.executor.put_state(
                installation,
                &storage_key,
                to_storage_schema_version(schema_version),
                value.as_slice().to_vec(),
            ))
            .map_err(map_state_error)
    }

    fn delete(&self, installation: InstallationId, key: &StateKey) -> Result<(), StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        self.bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .delete_state(installation, &storage_key),
            )
            .map_err(map_state_error)
    }

    fn schema_version(
        &self,
        installation: InstallationId,
    ) -> Result<Option<StateSchemaVersion>, StateStoreError> {
        self.bridge
            .runtime
            .block_on(self.bridge.executor.get_state_schema_version(installation))
            .map_err(map_state_error)
            .map(|version| version.map(|v| StateSchemaVersion::from_u32(v.as_u32())))
    }

    fn begin_transaction(
        &self,
        installation: InstallationId,
        schema_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let handle =
            self.bridge
                .runtime
                .block_on(self.bridge.executor.begin_state_transaction(
                    installation,
                    to_storage_schema_version(schema_version),
                ))
                .map_err(map_state_error)?;
        Ok(self.bridge.remember_tx(handle))
    }

    fn begin_migration_transaction(
        &self,
        installation: InstallationId,
        to_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let handle = self
            .bridge
            .runtime
            .block_on(self.bridge.executor.begin_state_migration_transaction(
                installation,
                to_storage_schema_version(to_version),
            ))
            .map_err(map_state_error)?;
        Ok(self.bridge.remember_tx(handle))
    }

    fn tx_get(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        let handle = self.bridge.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        let record = self
            .bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .state_tx_get(handle, installation, &storage_key),
            )
            .map_err(map_state_error)?;
        record.map(to_domain_state_value).transpose()
    }

    fn tx_put(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let handle = self.bridge.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        self.bridge
            .runtime
            .block_on(self.bridge.executor.state_tx_put(
                handle,
                installation,
                &storage_key,
                value.as_slice().to_vec(),
            ))
            .map_err(map_state_error)
    }

    fn tx_delete(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<(), StateStoreError> {
        let handle = self.bridge.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        self.bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .state_tx_delete(handle, installation, &storage_key),
            )
            .map_err(map_state_error)
    }

    fn commit(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        let handle = self.bridge.take_tx(tx)?;
        self.bridge
            .runtime
            .block_on(self.bridge.executor.commit_state_transaction(handle))
            .map_err(map_state_error)
    }

    fn abort(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        // WIT：abort 对已终止事务是 no-op——句柄可能已不存在，按 no-op
        // 语义直接调用存储（存储侧对未知句柄 no-op 成功）。
        if let Ok(handle) = self.bridge.handle_of(tx) {
            self.bridge
                .runtime
                .block_on(self.bridge.executor.abort_state_transaction(handle))
                .map_err(map_state_error)?;
            self.bridge.take_tx(tx)?;
        }
        Ok(())
    }
}

/// storage `StateValueRecord` → domain `StateValue`（§13.3 边界解析一次；
/// 超限 = 存储损坏 fail closed）。
fn to_domain_state_value(record: StateValueRecord) -> Result<StateValue, StateStoreError> {
    StateValue::new(record.value).map_err(|_| {
        StateStoreError::Corrupt("state value exceeds the domain bound in store".into())
    })
}

struct ExecutorConfigStore {
    bridge: Arc<ExecutorBridge>,
}

impl ComponentConfigStorePort for ExecutorConfigStore {
    fn snapshot(
        &self,
        installation: InstallationId,
    ) -> Result<Option<ConfigSnapshot>, ConfigStoreError> {
        let record = self
            .bridge
            .runtime
            .block_on(self.bridge.executor.get_component_config(installation))
            .map_err(map_config_error)?;
        record.map(to_domain_config_snapshot).transpose()
    }

    fn put(
        &self,
        installation: InstallationId,
        format: ConfigFormat,
        schema_version: ConfigSchemaVersion,
        value: &ConfigValue,
    ) -> Result<ConfigRevision, ConfigStoreError> {
        self.bridge
            .runtime
            .block_on(self.bridge.executor.put_component_config(
                installation,
                to_storage_config_format(format),
                operune_storage_sqlite::model::StateSchemaVersion::new(schema_version.as_u32()),
                value.as_slice().to_vec(),
            ))
            .map_err(map_config_error)?;
        // 读回新修订号（executor 单连接串行 ⇒ put 后读一致，无交错）。
        let record = self
            .bridge
            .runtime
            .block_on(self.bridge.executor.get_component_config(installation))
            .map_err(map_config_error)?;
        match record {
            Some(record) => Ok(ConfigRevision::from_u64(record.revision)),
            None => Err(ConfigStoreError::Corrupt(
                "config disappeared after write (invariant violation)".into(),
            )),
        }
    }
}

fn to_domain_config_snapshot(
    record: ComponentConfigRecord,
) -> Result<ConfigSnapshot, ConfigStoreError> {
    let value = ConfigValue::new(record.value).map_err(|_| {
        ConfigStoreError::Corrupt("config value exceeds the domain bound in store".into())
    })?;
    Ok(ConfigSnapshot::new(
        ConfigRevision::from_u64(record.revision),
        value,
    ))
}

fn to_storage_config_format(format: ConfigFormat) -> StorageConfigFormat {
    match format {
        ConfigFormat::Json => StorageConfigFormat::Json,
        ConfigFormat::Toml => StorageConfigFormat::Toml,
        ConfigFormat::Raw => StorageConfigFormat::Raw,
    }
}

struct ExecutorSecretStore {
    bridge: Arc<ExecutorBridge>,
}

impl SecretStorePort for ExecutorSecretStore {
    fn put(
        &self,
        installation: InstallationId,
        name: &SecretName,
        ciphertext: Vec<u8>,
        metadata: &str,
    ) -> Result<SecretVersion, SecretStoreError> {
        let storage_name = ok(StorageSecretName::new(name.as_str()), "storage secret name");
        self.bridge
            .runtime
            .block_on(self.bridge.executor.put_secret(
                installation,
                &storage_name,
                ciphertext,
                metadata.to_owned(),
            ))
            .map_err(map_secret_error)?;
        // 读回新版本（insert or replace 版本递增；串行 executor 下无交错）。
        let record = self
            .bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .get_secret_ciphertext(installation, &storage_name),
            )
            .map_err(map_secret_error)?;
        match record {
            Some(record) => Ok(SecretVersion::from_u64(record.version)),
            None => Err(SecretStoreError::Corrupt(
                "secret disappeared after write (invariant violation)".into(),
            )),
        }
    }

    fn ciphertext(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<Option<SecretCiphertextRecord>, SecretStoreError> {
        let storage_name = ok(StorageSecretName::new(name.as_str()), "storage secret name");
        let record = self
            .bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .get_secret_ciphertext(installation, &storage_name),
            )
            .map_err(map_secret_error)?;
        Ok(record.map(to_domain_secret_record))
    }

    fn list(&self, installation: InstallationId) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        let records = self
            .bridge
            .runtime
            .block_on(self.bridge.executor.list_secret_names(installation))
            .map_err(map_secret_error)?;
        let mut metadata: Vec<SecretMetadata> = Vec::with_capacity(records.len());
        for record in records {
            let name = ok(SecretName::new(record.name.as_str()), "domain secret name");
            metadata.push(SecretMetadata::new(
                name,
                SecretVersion::from_u64(record.version),
            ));
        }
        Ok(metadata)
    }

    fn delete(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<(), SecretStoreError> {
        let storage_name = ok(StorageSecretName::new(name.as_str()), "storage secret name");
        self.bridge
            .runtime
            .block_on(
                self.bridge
                    .executor
                    .delete_secret(installation, &storage_name),
            )
            .map_err(map_secret_error)
    }
}

fn to_domain_secret_record(record: SecretRecord) -> SecretCiphertextRecord {
    SecretCiphertextRecord {
        name: ok(SecretName::new(record.name.as_str()), "domain secret name"),
        version: SecretVersion::from_u64(record.version),
        ciphertext: record.ciphertext,
    }
}

/// e2e 测试的 secret grant 集（固定配置；正式接线从 grants 表筛选）。
struct StaticSecretGrants {
    names: Mutex<Vec<SecretName>>,
}

impl StaticSecretGrants {
    fn new(names: Vec<SecretName>) -> Self {
        Self {
            names: Mutex::new(names),
        }
    }
}

impl SecretGrantPort for StaticSecretGrants {
    fn granted_names(
        &self,
        _installation: InstallationId,
    ) -> Result<Vec<SecretName>, operune_application::ports::GrantError> {
        let names = self
            .names
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(names.clone())
    }
}

/// 0.3 state/config/secret 审计收集器（内存实现）。
struct AuditCollector {
    events: Mutex<Vec<StatefulAuditEvent>>,
}

impl AuditCollector {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<StatefulAuditEvent> {
        match self.events.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => Vec::new(),
        }
    }

    fn contains(&self, predicate: impl Fn(&StatefulAuditEvent) -> bool) -> bool {
        self.events().iter().any(predicate)
    }
}

impl StatefulAuditPort for AuditCollector {
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
// 端到端场景。
// ---------------------------------------------------------------------------

#[test]
fn stateful_runtime_e2e_with_real_executor() {
    let dir = ok(tempfile::tempdir(), "tempdir");
    let bridge = Arc::new(ExecutorBridge::open(dir.path()));
    let component = ok(ComponentId::new("e2e-component"), "component id");
    let installation = bridge.register_component(component);

    let gate = Arc::new(MigrationGate::new());
    let audit = Arc::new(AuditCollector::new());
    let state_store = Arc::new(ExecutorStateStore {
        bridge: bridge.clone(),
    });
    let config_store = Arc::new(ExecutorConfigStore {
        bridge: bridge.clone(),
    });
    let secret_store = Arc::new(ExecutorSecretStore {
        bridge: bridge.clone(),
    });

    let state = StateService::new(state_store.clone(), audit.clone(), gate.clone());
    let migration = StateMigrationService::new(state_store.clone(), audit.clone(), gate.clone());
    let config = ConfigService::new(config_store.clone(), audit.clone());
    let cipher = ok(
        SecretCipher::new(&SecretBytes::from_slice(&[0x42; KEK_SIZE])),
        "cipher",
    );
    let secret = SecretService::new(
        secret_store.clone(),
        Arc::new(StaticSecretGrants::new(vec![ok(
            SecretName::new("db-password"),
            "secret name",
        )])),
        cipher,
        audit.clone(),
    );

    let key = |name: &str| ok(StateKey::new(name), "state key");
    let value = |bytes: &[u8]| ok(StateValue::new(bytes.to_vec()), "state value");
    let v1 = StateSchemaVersion::from_u32(1);
    let v2 = StateSchemaVersion::from_u32(2);

    // ---- CAS 建立版本 + 点读（§41.2 atomic update）----
    let outcome = ok(
        state.cas(installation, v1, &key("counter"), None, Some(&value(b"1"))),
        "cas",
    );
    assert_eq!(outcome, CasOutcome::Applied);
    assert_eq!(
        ok(state.get(installation, v1, &key("counter")), "get"),
        Some(value(b"1"))
    );
    // 期望值不匹配 → rejected，不写入。
    let outcome = ok(
        state.cas(
            installation,
            v1,
            &key("counter"),
            Some(&value(b"stale")),
            Some(&value(b"2")),
        ),
        "cas",
    );
    assert_eq!(outcome, CasOutcome::Rejected);

    // ---- 事务：begin → 写 → commit 原子生效（§41.2）----
    let tx = ok(state.begin_transaction(installation, v1), "begin");
    ok(
        state.tx_put(tx, installation, &key("jobs/1"), &value(b"queued")),
        "tx put",
    );
    // 事务内读取看到一致性快照（含自身未提交写入）。
    assert_eq!(
        ok(state.tx_get(tx, installation, &key("jobs/1")), "tx get"),
        Some(value(b"queued"))
    );
    ok(state.commit_transaction(tx), "commit");
    assert_eq!(
        ok(state.get(installation, v1, &key("jobs/1")), "get"),
        Some(value(b"queued"))
    );

    // ---- 显式 migration（§20.5 / §41.2）：guest 写新形态 → 原子提交 ----
    let outcome = ok(
        migration.migrate(installation, v1, v2, |tx| {
            ok(
                state_store.tx_put(tx, installation, &key("schema-v2"), &value(b"new-shape")),
                "guest write",
            );
            Ok(())
        }),
        "migrate",
    );
    assert_eq!(outcome, MigrationOutcome::Migrated { from: v1, to: v2 });
    // 存储版本已推进（§41.3：版本与数据同事务）。
    assert_eq!(
        ok(state_store.schema_version(installation), "schema version"),
        Some(v2)
    );
    assert_eq!(
        ok(state.get(installation, v2, &key("schema-v2")), "get"),
        Some(value(b"new-shape"))
    );
    // 幂等重试：已到达目标 → no-op。
    let outcome = ok(
        migration.migrate(installation, v2, v2, |_tx| Ok(())),
        "migrate retry",
    );
    assert_eq!(outcome, MigrationOutcome::AlreadyAtTarget { version: v2 });

    // ---- config：管理侧写（revision 单调）+ guest 只读快照（§41.2）----
    let config_value = ok(ConfigValue::new(b"{\"worker\":1}".to_vec()), "config value");
    let r1 = ok(
        config.put(
            installation,
            ConfigFormat::Json,
            ConfigSchemaVersion::from_u32(1),
            &config_value,
        ),
        "config put",
    );
    assert_eq!(r1, ConfigRevision::from_u64(1));
    let r2 = ok(
        config.put(
            installation,
            ConfigFormat::Json,
            ConfigSchemaVersion::from_u32(1),
            &config_value,
        ),
        "config put",
    );
    assert_eq!(r2, ConfigRevision::from_u64(2));
    let snapshot = ok(config.snapshot(installation), "config snapshot");
    assert_eq!(snapshot.revision(), ConfigRevision::from_u64(2));
    assert_eq!(snapshot.value().as_slice(), b"{\"worker\":1}");
    assert_eq!(
        ok(config.version(installation), "config version"),
        ConfigRevision::from_u64(2)
    );

    // ---- secret：轮换（密文落库）+ 按 grant 读取 + 拒绝（§41.2/§16.6）----
    let secret_value = SecretBytes::from_slice(b"e2e-db-password");
    let version = ok(
        secret.rotate(
            installation,
            &ok(SecretName::new("db-password"), "name"),
            &secret_value,
            "e2e credential",
        ),
        "rotate",
    );
    assert_eq!(version, SecretVersion::from_u64(1));
    // 存储只含密文：明文绝不进 SQLite（§16.6）——密文 ≠ 明文。
    let stored = ok(
        secret_store.ciphertext(installation, &ok(SecretName::new("db-password"), "name")),
        "ciphertext",
    );
    let stored = ok(stored.ok_or("missing secret record"), "record");
    assert_ne!(stored.ciphertext, secret_value.expose_secret().to_vec());
    // 按 grant 读取 → 明文只在返回值出现。
    let read = ok(
        secret.read_secret(installation, &ok(SecretName::new("db-password"), "name")),
        "read",
    );
    assert_eq!(read.expose_secret(), b"e2e-db-password");
    // grant 之外 → denied（与不存在合并）。
    assert!(matches!(
        secret.read_secret(installation, &ok(SecretName::new("other"), "name")),
        Err(operune_application::secret::SecretError::Denied)
    ));

    // ---- 审计（§41.2 audit MUST；metadata-only）----
    assert!(audit.contains(|event| matches!(event, StatefulAuditEvent::StateCasApplied { .. })));
    assert!(audit.contains(|event| matches!(event, StatefulAuditEvent::StateTxCommitted { .. })));
    assert!(audit.contains(|event| matches!(
        event,
        StatefulAuditEvent::MigrationCommitted { from, to, .. } if *from == v1 && *to == v2
    )));
    assert!(audit.contains(|event| matches!(event, StatefulAuditEvent::ConfigWritten { .. })));
    assert!(audit.contains(|event| matches!(
        event,
        StatefulAuditEvent::SecretRead { name, .. } if name.as_str() == "db-password"
    )));
    // 审计不含值（§16.6）。
    for event in audit.events() {
        let json = ok(serde_json::to_string(&event), "serialize audit");
        assert!(
            !json.contains("e2e-db-password"),
            "audit leaked secret value: {json}"
        );
    }

    // 关闭 executor（排空 worker；Drop 兜底）。
    let bridge = Arc::try_unwrap(bridge).ok();
    if let Some(bridge) = bridge {
        let _ = bridge.runtime.block_on(bridge.executor.shutdown());
    }
}
