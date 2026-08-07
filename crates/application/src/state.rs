//! 0.3.0 Stateful Runtime（§41.2）——typed Component state service 用例层
//! （guest 调用面；契约 `operune:state@0.1.0` state.wit，已提交稳定）。
//!
//! # 职责
//!
//! - **CAS 语义**（§41.2 atomic update）：`cas` 的 get→compare→put 编排
//!   在本服务（executor 单连接串行 ⇒ 读-判-写天然无交错，无需存储层条件
//!   写原语）；期望值按 `state-value` **字节等价**比较（WIT cas），四种
//!   组合（存在/不存在 × 写/删）均可表达；
//! - **事务编排**（§41.2 MUST transaction/atomic update semantics）：
//!   `begin_transaction`（携带声明版本）→ `tx_get`/`tx_put`/`tx_delete`
//!   → `commit`/`abort`；commit 原子生效（all-or-nothing），对已终止事务
//!   的操作 → `conflict`（WIT）；
//! - **schema version 校验**（WIT 明文）：`begin-transaction` 显式携带
//!   声明版本，存储版本不符 → `unsupported-schema-version`；快照点读与
//!   CAS 同样绑定当前声明版本；
//! - **migration 窗口**（§41.2 not-ready）：[`MigrationGate`] 标记
//!   migration 进行中的安装实例，期间运行时操作返回 `not-ready`
//!   （guest 稍后重试，不得视为数据丢失；崩溃恢复由存储原子性 + 重启后
//!   重跑迁移保证，§41.3）；
//! - **审计**（§41.2 state audit MUST）：每次操作写 metadata-only 事件
//!   （key、操作类型、结果、安装实例；**不携带 value 内容**，WIT 明文）。
//!
//! 错误闭集对齐 WIT `state-error`（not-ready / not-found / conflict /
//! corrupt / over-budget / unsupported-schema-version / internal）；
//! `invalid-key` 在 domain 边界（`StateKey` 构造）已拦截，服务层只接收
//! 已验证的 typed 值（§13.3 边界解析一次）。
//!
//! # 事务归属注册表
//!
//! domain [`StateTransactionId`] 不携带安装实例与绑定版本（存储层绑定）；
//! commit/abort 的审计事件需要二者（§41.2：key、操作类型、事务结果、
//! 安装实例），本服务以事务注册表（`tx → (installation, schema_version)`）
//! 记录自己开启的事务，终止（commit 成功或 conflict / abort）时移除。
//! migration 事务由 [`crate::migration::StateMigrationService`] 开启，不进
//! 本注册表（其审计自带 from/to/installation）。

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};

use operune_domain::{
    InstallationId, StateKey, StateSchemaVersion, StateTransactionId, StateValue,
};

use crate::ports::{
    AuditError, StateStoreError, StateStorePort, StatefulAuditEvent, StatefulAuditPort,
};

/// 单键 CAS 的结果（WIT `cas-outcome` 对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CasOutcome {
    /// 期望值匹配，新值已原子写入（或"删除"组合已应用）。
    Applied,
    /// 期望值不匹配，未写入；调用者应重新读取后再试。
    Rejected,
}

/// 每安装实例的 migration 窗口 gate（§41.2：migration 进行中 state 运行
/// 时操作返回 `not-ready`）。
///
/// 进程内状态：崩溃后由 SQLite 原子性保证 store 版本确定性（§41.3——
/// 未提交迁移事务自然回滚，store 保持旧版本），重启后 upgrade 管线以
/// 相同 from/to 重跑迁移（幂等，WIT migration 契约）。本 gate 不持久化。
#[derive(Debug, Default)]
pub struct MigrationGate {
    migrating: Mutex<BTreeSet<InstallationId>>,
}

impl MigrationGate {
    /// 新建空 gate。
    pub fn new() -> Self {
        Self::default()
    }

    /// 安装实例当前是否处于 migration 窗口（not-ready）。
    pub fn is_migrating(&self, installation: InstallationId) -> bool {
        self.lock().contains(&installation)
    }

    fn lock(&self) -> MutexGuard<'_, BTreeSet<InstallationId>> {
        // 毒化锁（panic 期间持有）不构成数据损坏：进入/退出都是幂等集合
        // 操作，直接取 inner 继续。
        self.migrating
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// 标记 migration 窗口开始（迁移服务调用；crate 内部）。
    pub(crate) fn enter(&self, installation: InstallationId) {
        self.lock().insert(installation);
    }

    /// 清除 migration 窗口（迁移服务 / RAII guard 调用；crate 内部）。
    pub(crate) fn exit(&self, installation: InstallationId) {
        self.lock().remove(&installation);
    }
}

/// state 用例层错误（对齐 WIT `state-error` 闭集，§6.3；guest 面的
/// invalid-key 由 domain 边界拦截，不在本层）。
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// state store 未就绪：migration 进行中（not-ready，guest 稍后重试，
    /// 不得视为数据丢失）。
    #[error("state store not ready (migration in progress or crash recovery)")]
    NotReady,

    /// 键不存在（删除/事务内删除不存在的键）。
    #[error("state key not found")]
    NotFound,

    /// 并发修改冲突或对已终止（已 commit/abort）事务的操作（WIT
    /// conflict；整个事务无效果，调用者可重试）。
    #[error("state conflict (concurrent modification or terminated transaction)")]
    Conflict,

    /// 持久数据完整性 / schema 检查失败（WIT corrupt；需管理介入）。
    #[error("state data corrupt")]
    Corrupt,

    /// 超出预算：value 体积 / 事务操作数 / 安装实例总状态预算（WIT
    /// over-budget）。
    #[error("state operation over budget")]
    OverBudget,

    /// 存储的 schema version 与请求的声明版本不符（WIT
    /// unsupported-schema-version；migration 待执行）。
    #[error("store schema version does not match the declared schema version")]
    UnsupportedSchemaVersion,

    /// 存储失败（WIT internal 面；source 保留可诊断上下文）。
    #[error("state store failure: {0}")]
    Store(#[source] StateStoreError),

    /// 审计失败（§18.7 fail closed：需要 durable audit 的操作不得静默
    /// 继续）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] AuditError),

    /// 内部不变量破坏（视为系统故障，fail-stop 语义，§14.3）。
    #[error("application internal invariant violated: {0}")]
    Internal(&'static str),
}

impl StateError {
    /// 审计 reason 标签（kebab-case，静态文本；不含任何 value 内容）。
    pub(crate) fn audit_label(&self) -> &'static str {
        match self {
            Self::NotReady => "not-ready",
            Self::NotFound => "not-found",
            Self::Conflict => "conflict",
            Self::Corrupt => "corrupt",
            Self::OverBudget => "over-budget",
            Self::UnsupportedSchemaVersion => "unsupported-schema-version",
            Self::Store(_) => "store-failure",
            Self::Audit(_) => "audit-failure",
            Self::Internal(_) => "internal",
        }
    }
}

/// 存储错误 → 用例错误映射（§14.1 封闭 typed）。
fn map_store_error(error: StateStoreError) -> StateError {
    match error {
        StateStoreError::NotFound(_) => StateError::NotFound,
        StateStoreError::SchemaVersionMismatch { .. } => StateError::UnsupportedSchemaVersion,
        StateStoreError::TransactionConflict(_) => StateError::Conflict,
        // 存储侧 InvalidArgument 仅由值体积超限产生（§13.3 已拦截的
        // 防御面）→ WIT over-budget。
        StateStoreError::InvalidArgument(_) => StateError::OverBudget,
        StateStoreError::Corrupt(_) => StateError::Corrupt,
        StateStoreError::Storage(_) => StateError::Store(error),
    }
}

/// 本服务开启的事务的归属上下文（审计关联，§41.2）。
#[derive(Debug, Clone, Copy)]
struct TxContext {
    installation: InstallationId,
    schema_version: StateSchemaVersion,
}

/// typed Component state service（guest 调用面，§41.2）。
///
/// 构造：`store`/`audit`/`gate` 由 composition root 注入（§24.2 端口注入）。
/// `gate` 与 [`crate::migration::StateMigrationService`] 共享同一实例——
/// 迁移窗口由迁移服务标记，运行时操作在此检查。
pub struct StateService {
    store: Arc<dyn StateStorePort>,
    audit: Arc<dyn StatefulAuditPort>,
    gate: Arc<MigrationGate>,
    transactions: Mutex<HashMap<StateTransactionId, TxContext>>,
}

impl StateService {
    /// 构造（store + audit + migration gate；§24.2 端口注入）。
    pub fn new(
        store: Arc<dyn StateStorePort>,
        audit: Arc<dyn StatefulAuditPort>,
        gate: Arc<MigrationGate>,
    ) -> Self {
        Self {
            store,
            audit,
            gate,
            transactions: Mutex::new(HashMap::new()),
        }
    }

    /// 快照点读（WIT `get`；side-effect-free 点读）。
    ///
    /// 绑定当前声明的 schema 版本（存储版本不符 →
    /// `unsupported-schema-version`）；migration 窗口 → `not-ready`。
    pub fn get(
        &self,
        installation: InstallationId,
        declared_version: StateSchemaVersion,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateError> {
        if let Err(error) = self.check_version(installation, declared_version) {
            self.audit_failed(installation, "get", &error)?;
            return Err(error);
        }
        match self.store.get(installation, key) {
            Ok(value) => {
                self.audit(StatefulAuditEvent::StateRead {
                    installation,
                    key: key.clone(),
                })?;
                Ok(value)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "get", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 单键原子比较-交换（WIT `cas`；§41.2 atomic update 的基础原语）。
    ///
    /// `expected: None` 表示"键不存在"，`new_value: None` 表示"删除"——
    /// 四种组合均可表达；期望值按字节等价比较。条件满足时原子写入（或
    /// 删除）；条件不满足返回 [`CasOutcome::Rejected`]，不写入。
    ///
    /// 绑定当前声明的 schema 版本（校验同 [`Self::get`]）。
    pub fn cas(
        &self,
        installation: InstallationId,
        declared_version: StateSchemaVersion,
        key: &StateKey,
        expected: Option<&StateValue>,
        new_value: Option<&StateValue>,
    ) -> Result<CasOutcome, StateError> {
        if let Err(error) = self.check_version(installation, declared_version) {
            self.audit_failed(installation, "cas", &error)?;
            return Err(error);
        }
        let current = match self.store.get(installation, key) {
            Ok(value) => value,
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "cas", &mapped)?;
                return Err(mapped);
            }
        };
        if current.as_ref() != expected {
            // 期望值不匹配：未写入（WIT cas-outcome.rejected）。
            self.audit(StatefulAuditEvent::StateCasRejected {
                installation,
                key: key.clone(),
            })?;
            return Ok(CasOutcome::Rejected);
        }
        // 条件满足：写入新值，或删除（键已不存在时删除是 no-op——CAS
        // 条件已满足，无需存储调用）。
        let write_result = match (new_value, current.as_ref()) {
            (Some(new_value), _) => self
                .store
                .put(installation, key, declared_version, new_value),
            (None, Some(_)) => self.store.delete(installation, key),
            (None, None) => Ok(()),
        };
        match write_result {
            Ok(()) => {
                self.audit(StatefulAuditEvent::StateCasApplied {
                    installation,
                    key: key.clone(),
                })?;
                Ok(CasOutcome::Applied)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "cas", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 开启事务（WIT `begin-transaction`），绑定请求的 schema 版本。
    ///
    /// - 版本必须等于 store 当前版本（空 store 由首次提交建立），否则
    ///   `unsupported-schema-version`（迁移前阻止混合版本写入的契约边界）；
    /// - migration 进行中 → `not-ready`；
    /// - 返回 Core 侧事务身份（domain [`StateTransactionId`]；guest 面的
    ///   resource 句柄映射由 runtime 接线面承担）。
    pub fn begin_transaction(
        &self,
        installation: InstallationId,
        declared_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateError> {
        if let Err(error) = self.check_version(installation, declared_version) {
            self.audit_failed(installation, "begin-transaction", &error)?;
            return Err(error);
        }
        match self.store.begin_transaction(installation, declared_version) {
            Ok(tx) => {
                self.remember_transaction(tx, installation, declared_version);
                self.audit(StatefulAuditEvent::StateTxBegan {
                    installation,
                    schema_version: declared_version,
                })?;
                Ok(tx)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "begin-transaction", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 事务内读取（WIT `state-transaction.get`；一致性快照，未写过的键
    /// 读取到 store 当前值）。
    pub fn tx_get(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateError> {
        match self.store.tx_get(tx, installation, key) {
            Ok(value) => Ok(value),
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "tx-get", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 事务内写入（WIT `state-transaction.put`；commit 时原子生效）。
    pub fn tx_put(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
        value: &StateValue,
    ) -> Result<(), StateError> {
        match self.store.tx_put(tx, installation, key, value) {
            Ok(()) => {
                self.audit(StatefulAuditEvent::StateTxPut {
                    installation,
                    key: key.clone(),
                })?;
                Ok(())
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "tx-put", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 事务内删除（WIT `state-transaction.delete`；commit 时原子生效）。
    pub fn tx_delete(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<(), StateError> {
        match self.store.tx_delete(tx, installation, key) {
            Ok(()) => {
                self.audit(StatefulAuditEvent::StateTxDeleted {
                    installation,
                    key: key.clone(),
                })?;
                Ok(())
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "tx-delete", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 原子提交（WIT `state-transaction.commit`）：全部暂存操作一次性
    /// 生效（all-or-nothing）；对已终止事务的 commit → `conflict`（整个
    /// 事务无效果，调用者可重试）。
    ///
    /// 注册表只做审计关联，不 gate 存储调用（WIT 语义保持：已终止事务
    /// 的 commit 由存储以 conflict 表达）。注册表不可关联（migration
    /// 句柄被 guest 违规 commit，WIT：guest 不得 commit 迁移事务本身）而
    /// 存储已提交成功时，返回内部不变量错误——migration 编排随后以
    /// conflict 确定处理（§41.3：状态仍确定，不产生不可恢复状态）。
    pub fn commit_transaction(&self, tx: StateTransactionId) -> Result<(), StateError> {
        match self.store.commit(tx) {
            Ok(()) => {
                let Some(ctx) = self.transaction_context(tx) else {
                    return Err(StateError::Internal(
                        "commit succeeded on a state transaction not opened by this service \
                         (guest contract violation)",
                    ));
                };
                self.forget_transaction(tx);
                self.audit(StatefulAuditEvent::StateTxCommitted {
                    installation: ctx.installation,
                    schema_version: ctx.schema_version,
                })?;
                Ok(())
            }
            Err(error) => {
                let mapped = map_store_error(error);
                if let Some(ctx) = self.transaction_context(tx) {
                    if matches!(mapped, StateError::Conflict) {
                        // 存储已终止事务：注册表同步清理。
                        self.forget_transaction(tx);
                    }
                    self.audit_failed(ctx.installation, "commit", &mapped)?;
                }
                Err(mapped)
            }
        }
    }

    /// 放弃事务（WIT `state-transaction.abort`）：全部暂存操作不生效；
    /// 对已终止事务是 no-op。
    ///
    /// 注册表不可关联（已终止的 no-op，或 guest 对 migration 句柄调用
    /// abort 的契约违规——迁移事务被 guest 自毁，Core 侧随后 commit →
    /// conflict 确定处理）时：存储 abort 按 WIT no-op 语义成功，不产生
    /// 审计事件（原终止已审计）。
    pub fn abort_transaction(&self, tx: StateTransactionId) -> Result<(), StateError> {
        match self.store.abort(tx) {
            Ok(()) => {
                if let Some(ctx) = self.transaction_context(tx) {
                    self.forget_transaction(tx);
                    self.audit(StatefulAuditEvent::StateTxAborted {
                        installation: ctx.installation,
                        schema_version: ctx.schema_version,
                    })?;
                }
                Ok(())
            }
            Err(error) => {
                let mapped = map_store_error(error);
                if let Some(ctx) = self.transaction_context(tx) {
                    if matches!(mapped, StateError::Conflict) {
                        self.forget_transaction(tx);
                    }
                    self.audit_failed(ctx.installation, "abort", &mapped)?;
                }
                Err(mapped)
            }
        }
    }

    /// 运行时接线层的 schema 版��绑定解析（§41.2 / state.wit：运行时操作
    /// 绑定"当前声明的 schema version"）。
    ///
    /// 0.3.0 upgrade 管线（§20.5）在激活前读取 guest 的 `declaration`
    /// 导出并触发显式迁移（install.rs 的 state schema 阶段）——激活后
    /// store 版本 == 声明版本，本方法以 store 当前版本为绑定即与声明
    /// 一致；空 store（首次写入前）绑定 0，版本由首次写入建立（§41.3，
    /// 写入侧一致性由存储层强制）。crate 内部（runtime 接线层专用）。
    pub(crate) fn schema_binding_version(
        &self,
        installation: InstallationId,
    ) -> Result<StateSchemaVersion, StateError> {
        match self.store.schema_version(installation) {
            Ok(Some(version)) => Ok(version),
            Ok(None) => Ok(StateSchemaVersion::from_u32(0)),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// 版本绑定检查（WIT 明文）：migration 窗口 → not-ready；存储版本
    /// ≠ 声明版本 → unsupported-schema-version（空 store 由首次写入建立
    /// 版本，不拦截）。
    fn check_version(
        &self,
        installation: InstallationId,
        declared: StateSchemaVersion,
    ) -> Result<(), StateError> {
        if self.gate.is_migrating(installation) {
            return Err(StateError::NotReady);
        }
        match self.store.schema_version(installation) {
            Ok(Some(current)) if current != declared => Err(StateError::UnsupportedSchemaVersion),
            Ok(_) => Ok(()),
            Err(error) => Err(map_store_error(error)),
        }
    }

    // ---- 事务归属注册表（§41.2 审计关联）----

    fn transactions_lock(&self) -> MutexGuard<'_, HashMap<StateTransactionId, TxContext>> {
        self.transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn remember_transaction(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        schema_version: StateSchemaVersion,
    ) {
        self.transactions_lock().insert(
            tx,
            TxContext {
                installation,
                schema_version,
            },
        );
    }

    fn forget_transaction(&self, tx: StateTransactionId) {
        self.transactions_lock().remove(&tx);
    }

    /// 查询本服务开启的事务归属（审计关联；未知句柄返回 `None`——已终止
    /// 的 no-op 语义或 guest 对迁移句柄的契约违规，见 commit/abort 方法
    /// 文档）。
    fn transaction_context(&self, tx: StateTransactionId) -> Option<TxContext> {
        self.transactions_lock().get(&tx).copied()
    }

    fn audit(&self, event: StatefulAuditEvent) -> Result<(), StateError> {
        self.audit.append(event).map_err(StateError::Audit)
    }

    fn audit_failed(
        &self,
        installation: InstallationId,
        operation: &'static str,
        error: &StateError,
    ) -> Result<(), StateError> {
        self.audit
            .append(StatefulAuditEvent::StateFailed {
                installation,
                operation,
                reason: error.audit_label(),
            })
            .map_err(StateError::Audit)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::ports::StatefulAuditEvent;
    use crate::test_support::{FakeStateStore, FakeStatefulAudit, err, installation, ok};

    use super::*;

    const V1: StateSchemaVersion = StateSchemaVersion::from_u32(1);
    const V2: StateSchemaVersion = StateSchemaVersion::from_u32(2);
    const V5: StateSchemaVersion = StateSchemaVersion::from_u32(5);

    fn key(name: &str) -> StateKey {
        ok(StateKey::new(name), "state key")
    }

    fn value(bytes: &[u8]) -> StateValue {
        ok(StateValue::new(bytes.to_vec()), "state value")
    }

    struct Harness {
        service: StateService,
        store: Arc<FakeStateStore>,
        audit: Arc<FakeStatefulAudit>,
        gate: Arc<MigrationGate>,
    }

    fn harness() -> Harness {
        let store = Arc::new(FakeStateStore::new());
        let audit = Arc::new(FakeStatefulAudit::new());
        let gate = Arc::new(MigrationGate::new());
        let service = StateService::new(store.clone(), audit.clone(), gate.clone());
        Harness {
            service,
            store,
            audit,
            gate,
        }
    }

    #[test]
    fn get_returns_none_for_missing_key_and_audits_read() {
        let harness = harness();
        let inst = installation(1);
        assert!(matches!(
            harness.service.get(inst, V1, &key("missing")),
            Ok(None)
        ));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateRead { installation, key: k }
                if *installation == inst && k.as_str() == "missing"
        )));
    }

    #[test]
    fn get_rejects_when_store_version_mismatches_declared() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        let error = err(harness.service.get(inst, V1, &key("a")), "get");
        assert!(matches!(error, StateError::UnsupportedSchemaVersion));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateFailed { operation, reason, .. }
                if *operation == "get" && *reason == "unsupported-schema-version"
        )));
    }

    #[test]
    fn get_returns_not_ready_during_migration_window() {
        let harness = harness();
        let inst = installation(1);
        harness.gate.enter(inst);
        assert!(matches!(
            harness.service.get(inst, V1, &key("a")),
            Err(StateError::NotReady)
        ));
    }

    #[test]
    fn cas_applies_new_value_when_key_absent() {
        let harness = harness();
        let inst = installation(1);
        let outcome = ok(
            harness
                .service
                .cas(inst, V1, &key("k"), None, Some(&value(b"v1"))),
            "cas",
        );
        assert_eq!(outcome, CasOutcome::Applied);
        assert_eq!(harness.store.value_of(inst, &key("k")), Some(value(b"v1")));
        assert_eq!(harness.store.version_of(inst), Some(V1));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateCasApplied { key: k, .. } if k.as_str() == "k"
        )));
    }

    #[test]
    fn cas_rejects_when_expected_mismatches_and_store_unchanged() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .service
                .cas(inst, V1, &key("k"), None, Some(&value(b"v1"))),
            "seed",
        );
        let outcome = ok(
            harness.service.cas(
                inst,
                V1,
                &key("k"),
                Some(&value(b"stale")),
                Some(&value(b"v2")),
            ),
            "cas",
        );
        assert_eq!(outcome, CasOutcome::Rejected);
        assert_eq!(harness.store.value_of(inst, &key("k")), Some(value(b"v1")));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateCasRejected { key: k, .. } if k.as_str() == "k"
        )));
    }

    #[test]
    fn cas_deletes_existing_key_when_new_is_none() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .service
                .cas(inst, V1, &key("k"), None, Some(&value(b"v1"))),
            "seed",
        );
        let outcome = ok(
            harness
                .service
                .cas(inst, V1, &key("k"), Some(&value(b"v1")), None),
            "cas delete",
        );
        assert_eq!(outcome, CasOutcome::Applied);
        assert_eq!(harness.store.value_of(inst, &key("k")), None);
    }

    #[test]
    fn cas_delete_of_absent_key_is_applied_noop() {
        let harness = harness();
        let inst = installation(1);
        // expected None + new None + 键不存在：条件已满足，无需删除。
        let outcome = ok(
            harness.service.cas(inst, V1, &key("missing"), None, None),
            "cas",
        );
        assert_eq!(outcome, CasOutcome::Applied);
    }

    #[test]
    fn cas_delete_with_stale_expected_is_rejected() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .service
                .cas(inst, V1, &key("k"), None, Some(&value(b"v1"))),
            "seed",
        );
        // expected None（键不存在）但键实际存在 → Rejected，不删除。
        let outcome = ok(harness.service.cas(inst, V1, &key("k"), None, None), "cas");
        assert_eq!(outcome, CasOutcome::Rejected);
        assert_eq!(harness.store.value_of(inst, &key("k")), Some(value(b"v1")));
    }

    #[test]
    fn cas_binds_declared_schema_version() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        assert!(matches!(
            harness
                .service
                .cas(inst, V1, &key("b"), None, Some(&value(b"x"))),
            Err(StateError::UnsupportedSchemaVersion)
        ));
    }

    #[test]
    fn cas_returns_not_ready_during_migration_window() {
        let harness = harness();
        let inst = installation(1);
        harness.gate.enter(inst);
        assert!(matches!(
            harness
                .service
                .cas(inst, V1, &key("a"), None, Some(&value(b"x"))),
            Err(StateError::NotReady)
        ));
    }

    #[test]
    fn begin_transaction_rejects_declared_version_mismatch() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        let error = err(harness.service.begin_transaction(inst, V1), "begin");
        assert!(matches!(error, StateError::UnsupportedSchemaVersion));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateFailed { operation, .. } if *operation == "begin-transaction"
        )));
    }

    #[test]
    fn begin_transaction_returns_not_ready_during_migration() {
        let harness = harness();
        let inst = installation(1);
        harness.gate.enter(inst);
        assert!(matches!(
            harness.service.begin_transaction(inst, V1),
            Err(StateError::NotReady)
        ));
    }

    #[test]
    fn transaction_commit_applies_all_writes_atomically() {
        let harness = harness();
        let inst = installation(1);
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(
            harness.service.tx_put(tx, inst, &key("x"), &value(b"1")),
            "tx put",
        );
        ok(
            harness.service.tx_put(tx, inst, &key("y"), &value(b"2")),
            "tx put",
        );
        ok(harness.service.commit_transaction(tx), "commit");
        assert_eq!(harness.store.value_of(inst, &key("x")), Some(value(b"1")));
        assert_eq!(harness.store.value_of(inst, &key("y")), Some(value(b"2")));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateTxBegan { schema_version, .. } if *schema_version == V1
        )));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateTxPut { key: k, .. } if k.as_str() == "x"
        )));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateTxCommitted { schema_version, .. } if *schema_version == V1
        )));
    }

    #[test]
    fn transaction_abort_discards_all_writes() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .service
                .cas(inst, V1, &key("keep"), None, Some(&value(b"original"))),
            "seed",
        );
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(
            harness
                .service
                .tx_put(tx, inst, &key("keep"), &value(b"changed")),
            "tx put",
        );
        ok(
            harness.service.tx_put(tx, inst, &key("new"), &value(b"x")),
            "tx put",
        );
        ok(harness.service.abort_transaction(tx), "abort");
        assert_eq!(
            harness.store.value_of(inst, &key("keep")),
            Some(value(b"original"))
        );
        assert_eq!(harness.store.value_of(inst, &key("new")), None);
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateTxAborted { schema_version, .. } if *schema_version == V1
        )));
    }

    #[test]
    fn transaction_commit_establishes_empty_store_version() {
        let harness = harness();
        let inst = installation(1);
        let tx = ok(harness.service.begin_transaction(inst, V5), "begin");
        ok(
            harness.service.tx_put(tx, inst, &key("a"), &value(b"v")),
            "tx put",
        );
        ok(harness.service.commit_transaction(tx), "commit");
        // 空 store 由首次提交建立声明版本（§41.3）。
        assert_eq!(harness.store.version_of(inst), Some(V5));
    }

    #[test]
    fn transaction_ops_on_terminated_transaction_conflict() {
        let harness = harness();
        let inst = installation(1);
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(harness.service.commit_transaction(tx), "commit");
        // 已终止事务：commit → conflict（WIT）；tx 操作 → conflict；abort
        // → no-op。
        assert!(matches!(
            harness.service.commit_transaction(tx),
            Err(StateError::Conflict)
        ));
        assert!(matches!(
            harness.service.tx_put(tx, inst, &key("a"), &value(b"v")),
            Err(StateError::Conflict)
        ));
        assert!(harness.service.abort_transaction(tx).is_ok());
        // 原始 commit 已审计；对已终止句柄的重复 commit 是 guest 错误，
        // 注册表已移除该句柄（无安装上下文可关联），不产生失败审计事件。
        assert!(!harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::StateFailed { operation, .. }
                if *operation == "commit"
        )));
    }

    #[test]
    fn tx_delete_of_missing_key_is_not_found() {
        let harness = harness();
        let inst = installation(1);
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        assert!(matches!(
            harness.service.tx_delete(tx, inst, &key("missing")),
            Err(StateError::NotFound)
        ));
    }

    #[test]
    fn transaction_delete_applies_on_commit() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .service
                .cas(inst, V1, &key("doomed"), None, Some(&value(b"x"))),
            "seed",
        );
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(
            harness.service.tx_delete(tx, inst, &key("doomed")),
            "tx delete",
        );
        ok(harness.service.commit_transaction(tx), "commit");
        assert_eq!(harness.store.value_of(inst, &key("doomed")), None);
    }

    #[test]
    fn tx_get_sees_pending_writes() {
        let harness = harness();
        let inst = installation(1);
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(
            harness.service.tx_put(tx, inst, &key("a"), &value(b"new")),
            "tx put",
        );
        // 事务内读取看到一致性快照（含自身未提交写入，WIT）。
        assert_eq!(
            ok(harness.service.tx_get(tx, inst, &key("a")), "tx get"),
            Some(value(b"new"))
        );
    }

    #[test]
    fn state_audit_events_never_contain_value_bytes() {
        let harness = harness();
        let inst = installation(1);
        let payload = b"audit-must-not-see-me";
        ok(
            harness
                .service
                .cas(inst, V1, &key("k"), None, Some(&value(payload))),
            "cas",
        );
        let tx = ok(harness.service.begin_transaction(inst, V1), "begin");
        ok(
            harness
                .service
                .tx_put(tx, inst, &key("k2"), &value(payload)),
            "tx put",
        );
        ok(harness.service.commit_transaction(tx), "commit");
        for event in harness.audit.events() {
            let json = ok(serde_json::to_string(&event), "serialize audit");
            assert!(
                !json.contains("audit-must-not-see-me"),
                "state audit leaked value content: {json}"
            );
        }
    }
}
