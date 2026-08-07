//! 0.3.0 Stateful Runtime（§41.2 / §20.5）——显式 state migration 编排
//! （Core 侧；契约 `operune:state@0.1.0` migration.wit，已提交稳定）。
//!
//! # 编排协议（WIT migration interface 明文 + §41.3 验收）
//!
//! ```text
//! 1. 比较存储版本与目标声明版本：相等 → 幂等 no-op（AlreadyAtTarget）；
//!    空 store → 无可迁移数据（NothingToMigrate，首次写入建立声明版本）；
//!    调用方声明的 from ≠ 存储版本 → 拒绝（UnexpectedStoreVersion，信息
//!    陈旧不猜测）；
//!    降级（to ≤ from）→ 拒绝（UnsupportedVersionRange，WIT 0.1.0 不定义
//!    已提交迁移后的降级）。
//! 2. 打开 migration 窗口（not-ready gate，§41.2）——所有退出路径经
//!    RAII guard 清理，绝无残留窗口。
//! 3. 开启排他的 migration 事务（存储校验 forward-only；空 store 不可迁移）。
//! 4. 调用 guest `migrate`（closure 注入，runtime 接线面把 transaction
//!    id 映射为 WIT resource 句柄；guest 读旧形态、写新形态）。
//! 5. guest ok → 审计先于提交（§18.7 fail closed）→ 原子 commit（schema
//!    版本推进与数据写入同事务，§41.3）；guest 错误 / 宿主侧观测失败 →
//!    abort 回滚，store 不变（§20.5 rollback policy），升级被阻止。
//! 6. 崩溃恢复：SQLite 原子性保证未提交迁移自然回滚（store 保持旧版本），
//!    重启后以相同 from/to 重跑（幂等可重试，WIT：guest 迁移逻辑不得依赖
//!    "仅调用一次"）。
//! ```
//!
//! 审计（§41.2 state audit）：MigrationStarted / MigrationCommitted /
//! MigrationRolledBack / MigrationFailed（metadata-only，不含数据）。
//!
//! # 职责边界
//!
//! 本服务是 **Core 侧编排**：不调用 wasm（guest 调用由 runtime 接线面以
//! closure 注入），不解析 state 值（P6）；upgrade 管线（§20.5）决定何时
//! 迁移（新 ComponentVersion 的 `state-declaration.schema-version` 与存储
//! 版本比较），本服务执行迁移协议。

use std::sync::Arc;

use operune_domain::{InstallationId, StateSchemaVersion, StateTransactionId};

use crate::ports::{
    AuditError, StateStoreError, StateStorePort, StatefulAuditEvent, StatefulAuditPort,
};
use crate::state::MigrationGate;

/// guest 侧迁移结果（WIT `migration-error` 闭集 + 宿主侧观测，§6.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationGuestError {
    /// from/to 超出本 ComponentVersion 支持的迁移范围（WIT
    /// unsupported-version-range；Core 拒绝升级，store 不变）。
    UnsupportedVersionRange,
    /// 旧版本数据无法读取/解析（WIT malformed-source；数据损坏或与 from
    /// 版本不符）。
    MalformedSource,
    /// 迁移超出操作数/体积预算（WIT over-budget）。
    OverBudget,
    /// guest 内部不可恢复错误（WIT internal）。
    Internal,
    /// 宿主侧观测失败（trap / deadline / 超预算，§7.4/§7.5）：等价于迁移
    /// 失败 → 回滚（WIT：返回 ok 后的一切失败按未提交迁移回滚）。
    Host(&'static str),
}

impl MigrationGuestError {
    /// 审计 reason 标签（kebab-case 静态文本；不含数据）。
    pub(crate) fn audit_label(self) -> &'static str {
        match self {
            Self::UnsupportedVersionRange => "unsupported-version-range",
            Self::MalformedSource => "malformed-source",
            Self::OverBudget => "over-budget",
            Self::Internal => "guest-internal",
            Self::Host(reason) => reason,
        }
    }
}

/// 迁移尝试的结果（§41.3 确定性语义；RolledBack 是**预期失败**的结果——
/// WIT 显式建模 guest 失败为 `result<_, migration-error>`，不是编排故障）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// 迁移已原子提交（store schema 版本推进到 to，与数据同事务）。
    Migrated {
        /// 迁移源版本。
        from: StateSchemaVersion,
        /// 迁移目标版本。
        to: StateSchemaVersion,
    },
    /// 存储版本已等于目标（幂等重试：崩溃恢复 / 已提交迁移后的重复调用）。
    AlreadyAtTarget {
        /// 当前存储版本。
        version: StateSchemaVersion,
    },
    /// 空 store：无可迁移数据（首次写入由新声明版本建立，§41.3 确定性
    /// 由存储原子性保证）。
    NothingToMigrate,
    /// guest 迁移失败 → 已 abort 回滚，store 保持原版本（§20.5 rollback
    /// policy；升级被阻止，旧 ComponentVersion 保持激活）。
    RolledBack {
        /// 迁移源版本。
        from: StateSchemaVersion,
        /// 迁移目标版本。
        to: StateSchemaVersion,
        /// guest 失败原因。
        reason: MigrationGuestError,
    },
}

/// 迁移编排错误（**不是** guest 失败——guest 失败是 [`MigrationOutcome::RolledBack`]）。
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// 调用方声明的 from 与存储当前版本不符（信息陈旧；拒绝并保持 store
    /// 不变——升级管线应先读取存储版本再决定迁移）。
    #[error(
        "store schema version {current} does not match the upgrade plan version {expected} for installation {installation}"
    )]
    UnexpectedStoreVersion {
        /// 安装实例。
        installation: InstallationId,
        /// 升级计划声明的源版本。
        expected: StateSchemaVersion,
        /// 存储当前版本。
        current: StateSchemaVersion,
    },

    /// 降级/回退迁移（to ≤ from）——0.1.0 不定义（WIT 明文：已提交迁移后
    /// 的降级是未来 interface 演进）。
    #[error(
        "unsupported version range: migration from {from} to {to} (forward-only, no downgrade)"
    )]
    UnsupportedVersionRange {
        /// 源版本。
        from: StateSchemaVersion,
        /// 目标版本。
        to: StateSchemaVersion,
    },

    /// 迁移窗口无法开启：另一事务进行中（单连接串行 ⇒ 同一时刻至多一个；
    /// 可重试）。
    #[error("another state transaction is in progress; retry later")]
    Busy,

    /// 迁移提交冲突（事务已被终止——如 guest 契约违规自毁迁移事务；store
    /// 不变，可重试）。
    #[error("migration commit conflict; retry later")]
    Conflict,

    /// 存储失败（迁移已尽力 abort，store 不变）。
    #[error("state store failure during migration (store unchanged): {0}")]
    Store(#[source] StateStoreError),

    /// 审计失败（§18.7 fail closed：audit 不落盘不得提交）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] AuditError),

    /// 内部不变量破坏（视为系统故障，fail-stop 语义，§14.3）。
    #[error("application internal invariant violated: {0}")]
    Internal(&'static str),
}

/// migration 窗口 RAII guard：离开作用域（含所有错误路径）必然清除
/// not-ready gate——绝无残留迁移窗口（§41.2）。
struct MigrationWindowGuard {
    gate: Arc<MigrationGate>,
    installation: InstallationId,
}

impl Drop for MigrationWindowGuard {
    fn drop(&mut self) {
        self.gate.exit(self.installation);
    }
}

/// 显式 state migration 编排服务（Core 侧，§20.5 / §41.2）。
///
/// 构造：`store`/`audit`/`gate` 由 composition root 注入；`gate` 与
/// [`crate::state::StateService`] 共享同一实例（迁移窗口期间运行时操作
/// 返回 not-ready）。
pub struct StateMigrationService {
    store: Arc<dyn StateStorePort>,
    audit: Arc<dyn StatefulAuditPort>,
    gate: Arc<MigrationGate>,
}

impl StateMigrationService {
    /// 构造（store + audit + migration gate；§24.2 端口注入）。
    pub fn new(
        store: Arc<dyn StateStorePort>,
        audit: Arc<dyn StatefulAuditPort>,
        gate: Arc<MigrationGate>,
    ) -> Self {
        Self { store, audit, gate }
    }

    /// 执行一次显式状态迁移（WIT `migration.migrate` 的 Core 侧编排；
    /// 模块文档的协议 1-6 步）。
    ///
    /// `guest` 是 guest `migrate` 调用的注入点（runtime 接线面实现）：
    /// 接收 Core 侧事务身份（映射为 WIT `state-transaction` resource
    /// 句柄），返回 guest 结果；宿主侧观测（trap/deadline/超预算）由接线
    /// 面映射为 [`MigrationGuestError::Host`]。
    ///
    /// 幂等：相同 from/to 的重复调用（崩溃恢复后重跑）确定性收敛——
    /// 已提交 → `AlreadyAtTarget`；未提交 → 重新迁移。
    pub fn migrate<G>(
        &self,
        installation: InstallationId,
        from: StateSchemaVersion,
        to: StateSchemaVersion,
        guest: G,
    ) -> Result<MigrationOutcome, MigrationError>
    where
        G: FnOnce(StateTransactionId) -> Result<(), MigrationGuestError>,
    {
        // 1. 存储当前版本：决定 no-op / 前进 / 拒绝（§41.3 确定性）。
        let current = self
            .store
            .schema_version(installation)
            .map_err(MigrationError::Store)?;
        match current {
            None => return Ok(MigrationOutcome::NothingToMigrate),
            Some(current) if current == to => {
                return Ok(MigrationOutcome::AlreadyAtTarget { version: current });
            }
            Some(current) if current != from => {
                return Err(MigrationError::UnexpectedStoreVersion {
                    installation,
                    expected: from,
                    current,
                });
            }
            // current == from：前进迁移路径（向下继续）。
            Some(_) => {}
        }
        if to <= from {
            // forward-only（WIT：0.1.0 不定义降级）。
            return Err(MigrationError::UnsupportedVersionRange { from, to });
        }

        // 2. 打开 migration 窗口（not-ready）；guard 保证所有退出路径清理。
        self.gate.enter(installation);
        let _window = MigrationWindowGuard {
            gate: self.gate.clone(),
            installation,
        };

        // 3. 排他的 migration 事务（存储校验 forward-only）。
        let tx = match self.store.begin_migration_transaction(installation, to) {
            Ok(tx) => tx,
            Err(StateStoreError::TransactionConflict(_)) => return Err(MigrationError::Busy),
            // 防御：存储侧前向校验（本服务已前置检查；并发 begin 不可能，
            // 单连接串行）。
            Err(StateStoreError::SchemaVersionMismatch { .. }) => {
                return Err(MigrationError::UnsupportedVersionRange { from, to });
            }
            Err(other) => {
                self.audit_failed(installation, from, to, "begin")?;
                return Err(MigrationError::Store(other));
            }
        };
        if let Err(audit_error) = self.audit(StatefulAuditEvent::MigrationStarted {
            installation,
            from,
            to,
        }) {
            // fail closed：审计不落盘不迁移；尽力回滚已开启的事务。
            let _ = self.store.abort(tx);
            return Err(MigrationError::Audit(audit_error));
        }

        // 4. guest 迁移（读旧形态、写新形态；返回 ok 即承诺可提交）。
        match guest(tx) {
            Ok(()) => {
                // 5a. 审计先于提交（§18.7 fail closed）。
                if let Err(audit_error) = self.audit(StatefulAuditEvent::MigrationCommitted {
                    installation,
                    from,
                    to,
                }) {
                    let _ = self.store.abort(tx);
                    return Err(MigrationError::Audit(audit_error));
                }
                // 5b. 原子提交：schema 版本推进与数据写入同事务（§41.3）。
                match self.store.commit(tx) {
                    Ok(()) => Ok(MigrationOutcome::Migrated { from, to }),
                    Err(StateStoreError::TransactionConflict(_)) => {
                        self.audit_failed(installation, from, to, "commit")?;
                        Err(MigrationError::Conflict)
                    }
                    Err(other) => {
                        self.audit_failed(installation, from, to, "commit")?;
                        Err(MigrationError::Store(other))
                    }
                }
            }
            Err(reason) => {
                // 5c. guest 失败 → abort 回滚，store 不变（§20.5）。
                let _ = self.audit(StatefulAuditEvent::MigrationRolledBack {
                    installation,
                    from,
                    to,
                    reason: reason.audit_label(),
                });
                match self.store.abort(tx) {
                    Ok(()) => Ok(MigrationOutcome::RolledBack { from, to, reason }),
                    Err(abort_error) => Err(MigrationError::Store(abort_error)),
                }
            }
        }
        // guard drop → gate 清理（协议第 2 步窗口必然关闭）。
    }

    fn audit(&self, event: StatefulAuditEvent) -> Result<(), AuditError> {
        self.audit.append(event)
    }

    /// 迁移故障审计（metadata-only；审计失败本身按 fail closed 传播）。
    fn audit_failed(
        &self,
        installation: InstallationId,
        from: StateSchemaVersion,
        to: StateSchemaVersion,
        stage: &'static str,
    ) -> Result<(), MigrationError> {
        self.audit
            .append(StatefulAuditEvent::MigrationFailed {
                installation,
                from,
                to,
                reason: stage,
            })
            .map_err(MigrationError::Audit)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use operune_domain::{StateKey, StateValue};

    use crate::ports::StatefulAuditEvent;
    use crate::state::{MigrationGate, StateError, StateService};
    use crate::test_support::{FakeStateStore, FakeStatefulAudit, err, installation, ok};

    use super::*;

    const V1: StateSchemaVersion = StateSchemaVersion::from_u32(1);
    const V2: StateSchemaVersion = StateSchemaVersion::from_u32(2);
    const V3: StateSchemaVersion = StateSchemaVersion::from_u32(3);

    fn key(name: &str) -> StateKey {
        ok(StateKey::new(name), "state key")
    }

    fn value(bytes: &[u8]) -> StateValue {
        ok(StateValue::new(bytes.to_vec()), "state value")
    }

    struct Harness {
        service: StateMigrationService,
        state: StateService,
        store: Arc<FakeStateStore>,
        audit: Arc<FakeStatefulAudit>,
    }

    fn harness() -> Harness {
        let store = Arc::new(FakeStateStore::new());
        let audit = Arc::new(FakeStatefulAudit::new());
        let gate = Arc::new(MigrationGate::new());
        let service = StateMigrationService::new(store.clone(), audit.clone(), gate.clone());
        let state = StateService::new(store.clone(), audit.clone(), gate.clone());
        Harness {
            service,
            state,
            store,
            audit,
        }
    }

    #[test]
    fn migrate_success_commits_and_advances_schema_version() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed old-version data",
        );
        let outcome = ok(
            harness.service.migrate(inst, V1, V2, |tx| {
                ok(
                    harness
                        .store
                        .tx_put(tx, inst, &key("new"), &value(b"new-shape")),
                    "guest tx put",
                );
                Ok(())
            }),
            "migrate",
        );
        assert_eq!(outcome, MigrationOutcome::Migrated { from: V1, to: V2 });
        // 数据与 schema 版本同事务原子提交（§41.3）。
        assert_eq!(harness.store.version_of(inst), Some(V2));
        assert_eq!(
            harness.store.value_of(inst, &key("old")),
            Some(value(b"old-shape"))
        );
        assert_eq!(
            harness.store.value_of(inst, &key("new")),
            Some(value(b"new-shape"))
        );
        // 窗口已关闭：运行时操作恢复。
        assert!(harness.state.get(inst, V2, &key("old")).is_ok());
        // 审计（metadata-only）。
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationStarted { from, to, .. }
                if *from == V1 && *to == V2
        )));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationCommitted { from, to, .. }
                if *from == V1 && *to == V2
        )));
    }

    #[test]
    fn migrate_guest_failure_rolls_back_guest_writes() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed",
        );
        let outcome = harness.service.migrate(inst, V1, V2, |tx| {
            // guest 先写入新形态，再返回失败（模拟数据损坏）→ 全部回滚。
            ok(
                harness
                    .store
                    .tx_put(tx, inst, &key("partial"), &value(b"half")),
                "guest write",
            );
            Err(MigrationGuestError::MalformedSource)
        });
        assert!(matches!(
            outcome,
            Ok(MigrationOutcome::RolledBack {
                from: V1,
                to: V2,
                reason: MigrationGuestError::MalformedSource
            })
        ));
        // store 不变（§20.5 rollback policy）。
        assert_eq!(harness.store.version_of(inst), Some(V1));
        assert_eq!(harness.store.value_of(inst, &key("partial")), None);
        assert_eq!(
            harness.store.value_of(inst, &key("old")),
            Some(value(b"old-shape"))
        );
        // 窗口已关闭。
        assert!(harness.state.get(inst, V1, &key("old")).is_ok());
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::MigrationRolledBack { reason, .. }
                if *reason == "malformed-source"
        )));
    }

    #[test]
    fn migrate_host_observed_failure_rolls_back() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed",
        );
        let outcome = harness.service.migrate(inst, V1, V2, |_tx| {
            // 宿主侧观测（trap / deadline / 超预算）等价于迁移失败 → 回滚。
            Err(MigrationGuestError::Host("epoch-deadline-exceeded"))
        });
        assert!(matches!(
            outcome,
            Ok(MigrationOutcome::RolledBack {
                reason: MigrationGuestError::Host("epoch-deadline-exceeded"),
                ..
            })
        ));
        assert_eq!(harness.store.version_of(inst), Some(V1));
    }

    #[test]
    fn migrate_retry_after_crash_is_idempotent() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed",
        );
        // 第一次尝试：guest 写入新形态后进程 crash（未提交事务回滚，§18.5）。
        let first = harness.service.migrate(inst, V1, V2, |tx| {
            ok(
                harness
                    .store
                    .tx_put(tx, inst, &key("new"), &value(b"new-shape")),
                "guest write",
            );
            harness.store.simulate_crash();
            Ok(())
        });
        // crash 后 commit 看到事务已终止 → conflict（确定语义，可重试）。
        assert!(matches!(first, Err(MigrationError::Conflict)));
        assert_eq!(harness.store.version_of(inst), Some(V1));
        assert_eq!(harness.store.value_of(inst, &key("new")), None);
        // 重启后以相同 from/to 重跑 → 幂等成功（WIT：迁移不得依赖仅调用一次）。
        let retry = ok(
            harness.service.migrate(inst, V1, V2, |tx| {
                ok(
                    harness
                        .store
                        .tx_put(tx, inst, &key("new"), &value(b"new-shape")),
                    "guest write",
                );
                Ok(())
            }),
            "retry",
        );
        assert_eq!(retry, MigrationOutcome::Migrated { from: V1, to: V2 });
        assert_eq!(harness.store.version_of(inst), Some(V2));
        assert_eq!(
            harness.store.value_of(inst, &key("new")),
            Some(value(b"new-shape"))
        );
    }

    #[test]
    fn migrate_is_noop_when_already_at_target() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        let called = AtomicBool::new(false);
        let outcome = ok(
            harness.service.migrate(inst, V2, V2, |_tx| {
                called.store(true, Ordering::Relaxed);
                Ok(())
            }),
            "migrate",
        );
        assert_eq!(outcome, MigrationOutcome::AlreadyAtTarget { version: V2 });
        assert!(
            !called.load(Ordering::Relaxed),
            "no-op migration must not invoke the guest"
        );
    }

    #[test]
    fn migrate_empty_store_is_noop() {
        let harness = harness();
        let inst = installation(1);
        let outcome = ok(
            harness.service.migrate(inst, V1, V3, |_tx| Ok(())),
            "migrate",
        );
        assert_eq!(outcome, MigrationOutcome::NothingToMigrate);
    }

    #[test]
    fn migrate_rejects_stale_plan_version() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        let error = err(
            harness.service.migrate(inst, V1, V3, |_tx| Ok(())),
            "migrate",
        );
        assert!(matches!(
            error,
            MigrationError::UnexpectedStoreVersion {
                expected: V1,
                current: V2,
                ..
            }
        ));
    }

    #[test]
    fn migrate_rejects_downgrade() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("a"), V2, &value(b"v")),
            "seed at V2",
        );
        let error = err(
            harness.service.migrate(inst, V2, V1, |_tx| Ok(())),
            "migrate",
        );
        assert!(matches!(
            error,
            MigrationError::UnsupportedVersionRange { from: V2, to: V1 }
        ));
    }

    #[test]
    fn runtime_ops_return_not_ready_during_migration_window() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed",
        );
        // guest 在迁移期间观测到 not-ready（§41.2；gate 由迁移服务标记）。
        let outcome = harness.service.migrate(inst, V1, V2, |_tx| {
            assert!(matches!(
                harness.state.get(inst, V1, &key("old")),
                Err(StateError::NotReady)
            ));
            assert!(matches!(
                harness.state.begin_transaction(inst, V1),
                Err(StateError::NotReady)
            ));
            Ok(())
        });
        assert!(matches!(outcome, Ok(MigrationOutcome::Migrated { .. })));
        // 窗口关闭后恢复。
        assert!(harness.state.get(inst, V2, &key("old")).is_ok());
    }

    #[test]
    fn guest_self_aborting_migration_tx_leads_to_conflict() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness
                .store
                .put(inst, &key("old"), V1, &value(b"old-shape")),
            "seed",
        );
        // guest 契约违规（WIT：guest 不得 commit/abort 迁移事务本身）——
        // Core 侧确定处理：迁移提交 → conflict → 升级被阻止，store 不变。
        let outcome = harness.service.migrate(inst, V1, V2, |tx| {
            ok(harness.state.abort_transaction(tx), "guest self-abort");
            Ok(())
        });
        assert!(matches!(outcome, Err(MigrationError::Conflict)));
        assert_eq!(harness.store.version_of(inst), Some(V1));
        assert!(harness.state.get(inst, V1, &key("old")).is_ok());
    }

    #[test]
    fn migrate_is_busy_while_another_transaction_is_open() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.store.put(inst, &key("old"), V1, &value(b"v")),
            "seed",
        );
        let normal_tx = ok(harness.state.begin_transaction(inst, V1), "begin");
        let error = err(
            harness.service.migrate(inst, V1, V2, |_tx| Ok(())),
            "migrate",
        );
        assert!(matches!(error, MigrationError::Busy));
        // 正常事务结束后可重试。
        ok(harness.state.commit_transaction(normal_tx), "commit");
        let retry = ok(
            harness.service.migrate(inst, V1, V2, |tx| {
                ok(
                    harness.store.tx_put(tx, inst, &key("n"), &value(b"x")),
                    "guest write",
                );
                Ok(())
            }),
            "retry",
        );
        assert!(matches!(retry, MigrationOutcome::Migrated { .. }));
    }

    #[test]
    fn migration_audit_never_contains_data() {
        let harness = harness();
        let inst = installation(1);
        let payload = b"migration-secret-payload";
        ok(
            harness.store.put(inst, &key("old"), V1, &value(payload)),
            "seed",
        );
        let _ = harness.service.migrate(inst, V1, V2, |tx| {
            ok(
                harness.store.tx_put(tx, inst, &key("new"), &value(payload)),
                "guest write",
            );
            Ok(())
        });
        for event in harness.audit.events() {
            let json = ok(serde_json::to_string(&event), "serialize audit");
            assert!(
                !json.contains("migration-secret-payload"),
                "migration audit leaked data: {json}"
            );
        }
    }
}
