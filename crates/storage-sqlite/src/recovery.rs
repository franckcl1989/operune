//! Crash recovery（§18.5）：打开数据库后、开始服务前的确定性对账。
//!
//! 本模块把"安装/升级在任一 crash point 中断"后的数据库 + 文件系统状态收敛
//! 到确定语义，并全部写入 durable audit（§33：audit 能说明最后已提交状态）。
//!
//! # 决策表
//!
//! | 观察到 | 决策 | §18.5 对应 |
//! |---|---|---|
//! | `upgrade_transactions.phase = 'prepared'` 且 active = from | marker → `rolled_back`（**恢复旧版本**；candidate 保留可重试） | switch 中断 → 根据 durable transaction record 恢复旧版 |
//! | `prepared` 但 active ≠ from | CorruptState fail closed（不可恢复歧义：两个版本同时被误认为 active 不可能发生，见下） | 永远不存在两个版本都被误认为唯一 active |
//! | 行 candidate/installed，文件仍在 quarantine | 移动文件 → final（**完成候选提交**） | active 已提交 → 恢复 active |
//! | 行 quarantine，文件已在 final | 移动文件 → quarantine（撤销未提交的文件移动） | candidate 未提交 → 保持 quarantine |
//! | 行 quarantine，文件缺失 | 删除行（quarantine 可清理） | candidate 未提交 → 清理 |
//! | 行 candidate/installed，文件缺失 | **CorruptState fail closed**（promoted artifact 丢失，绝不静默继续） | 恢复必须确定 |
//! | 文件同时在 quarantine 与 final | CorruptState（rename 不可能复制，说明外部干预） | fail closed |
//! | `staging/` 残留 | 清空（瞬态空间，绝不权威） | §18.7 staging 语义 |
//! | final 孤儿文件（无行） | 留给 GC（不可引用，§18.7） | GC/retention |
//!
//! # 为什么"prepared + active = to"不可能出现（歧义消除）
//!
//! active 切换与 marker → `committed` 在**同一个 SQLite 事务**中提交
//! （`repository::switch_active_version` 阶段 B）：SQLite 原子提交保证二者
//! 要么同时生效、要么同时不生效。因此 recovery 只要看到 `prepared`，active
//! 必然仍是 from；反过来的状态直接判定为损坏（CorruptState）。
//!
//! # 幂等性
//!
//! recovery 自身可重复执行（marker 已终态 / 文件已对账 / 审计追加），重复
//! 运行不产生新动作。审计动作在最后以单个事务写入；audit 无法落盘 ⇒
//! 打开失败（fail closed，§18.7：审计要求的变更在提交前失败）。

use rusqlite::{Connection, OptionalExtension, params};

use crate::artifact::{ArtifactSpace, ArtifactStore};
use crate::error::StorageError;
use crate::model::{
    ActiveBinding, ArtifactState, AuditActor, AuditCategory, AuditEvent, AuditOutcome, Timestamp,
    UpgradeTransactionId,
};
use operune_domain::{ComponentVersion, ContentDigest, InstallationId};

/// 一次 recovery 动作（供 audit 与可观测性；顺序即执行顺序）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryAction {
    /// 中断的 switch 被确定性回滚（恢复旧版，§18.5）。
    SwitchRolledBack {
        /// 事务标记。
        transaction_id: UpgradeTransactionId,
        /// 安装实例。
        installation_id: InstallationId,
        /// 切换目标版本。
        to_version: ComponentVersion,
        /// 切换目标 digest。
        to_digest: ContentDigest,
    },
    /// 候选已提交但文件未达 final：把文件移动到 final（完成候选提交）。
    ArtifactPromoted {
        /// digest。
        digest: ContentDigest,
    },
    /// 文件已移动到 final 但候选未提交：把文件移回 quarantine。
    ArtifactDemoted {
        /// digest。
        digest: ContentDigest,
    },
    /// quarantine 行无文件：删除陈旧行（quarantine 可清理）。
    StaleQuarantineRowRemoved {
        /// digest。
        digest: ContentDigest,
    },
    /// staging 瞬态残留被清空。
    StagingCleaned,
}

/// 执行 recovery 对账（worker 打开数据库后、服务请求前调用一次）。
pub(crate) fn run_recovery(
    conn: &mut Connection,
    store: &ArtifactStore,
) -> Result<Vec<RecoveryAction>, StorageError> {
    let mut actions: Vec<RecoveryAction> = Vec::new();

    // 1. staging 瞬态空间清理（绝不权威，§18.7）。
    let (files, _bytes) = store.cleanup_staging()?;
    if files > 0 {
        actions.push(RecoveryAction::StagingCleaned);
    }

    // 2. prepared marker 对账（§18.5：switch 中断 → 恢复旧版）。
    reconcile_prepared_markers(conn, &mut actions)?;

    // 3. artifact 文件/行对账（文件位置是派生态）。
    reconcile_artifact_files(conn, store, &mut actions)?;

    // 4. audit：全部动作落 durable audit（同一事务，fail closed，§18.7）。
    if !actions.is_empty() {
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::sqlite("begin recovery audit transaction", e))?;
        let now = Timestamp::now()?.sql_value()?;
        for action in &actions {
            let (action_name, target, detail) = describe(action);
            let event = AuditEvent::new(
                AuditActor::Recovery,
                AuditCategory::Recovery,
                action_name,
                target,
                AuditOutcome::Success,
                detail,
            )?;
            insert_recovery_audit(&tx, &event, now)?;
        }
        tx.commit()
            .map_err(|e| StorageError::sqlite("commit recovery audit transaction", e))?;
    }

    Ok(actions)
}

/// `prepared` marker 对账：断言 active 仍 = from，然后确定性回滚 marker。
fn reconcile_prepared_markers(
    conn: &mut Connection,
    actions: &mut Vec<RecoveryAction>,
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare(
            "SELECT transaction_id, installation_id,
                    from_component_version, from_content_digest,
                    to_component_version, to_content_digest
             FROM upgrade_transactions WHERE phase = 'prepared'",
        )
        .map_err(|e| StorageError::sqlite("prepare marker scan", e))?;
    let markers = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })
        .map_err(|e| StorageError::sqlite("query markers", e))?;

    let mut pending = Vec::new();
    for marker in markers {
        let (tx_id, installation_str, from_version, from_digest, to_version, to_digest) =
            marker.map_err(|e| StorageError::sqlite("read marker row", e))?;
        pending.push((
            UpgradeTransactionId::from_rowid(tx_id)?,
            parse_installation(&installation_str)?,
            match from_version {
                Some(v) => Some(parse_version(&v)?),
                None => None,
            },
            match from_digest {
                Some(d) => Some(parse_digest(&d)?),
                None => None,
            },
            parse_version(&to_version)?,
            parse_digest(&to_digest)?,
        ));
    }
    drop(stmt);

    for (tx_id, installation_id, from_version, from_digest, to_version, to_digest) in pending {
        let active = read_active(conn, installation_id)?;
        let consistent = match (&active, &from_version, &from_digest) {
            // 初次安装中断：active 未创建，from = NULL。
            (None, None, None) => true,
            // 升级中断：active 必须仍 = from（阶段 B 未运行，§18.5 歧义消除）。
            (Some(binding), Some(version), Some(digest)) => {
                binding.component_version == *version && binding.content_digest == *digest
            }
            _ => false,
        };
        if !consistent {
            return Err(StorageError::CorruptState(format!(
                "prepared upgrade transaction {tx_id} for installation {installation_id} is \
                 inconsistent with active_version; refusing to continue (no ambiguous active)"
            )));
        }
        // 确定性回滚：marker → 'rolled_back'（恢复旧版；candidate 保留可重试）。
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::sqlite("begin marker rollback transaction", e))?;
        let now = Timestamp::now()?.sql_value()?;
        tx.execute(
            "UPDATE upgrade_transactions SET phase = 'rolled_back', completed_at = ?1
             WHERE transaction_id = ?2 AND phase = 'prepared'",
            params![now, tx_id.as_rowid()],
        )
        .map_err(|e| StorageError::sqlite("roll back prepared marker", e))?;
        tx.commit()
            .map_err(|e| StorageError::sqlite("commit marker rollback transaction", e))?;
        actions.push(RecoveryAction::SwitchRolledBack {
            transaction_id: tx_id,
            installation_id,
            to_version,
            to_digest,
        });
    }
    Ok(())
}

/// artifact 文件/行对账：文件位置收敛到 DB 状态决定的派生态。
fn reconcile_artifact_files(
    conn: &mut Connection,
    store: &ArtifactStore,
    actions: &mut Vec<RecoveryAction>,
) -> Result<(), StorageError> {
    let mut stmt = conn
        .prepare("SELECT digest, state FROM artifacts")
        .map_err(|e| StorageError::sqlite("prepare artifact scan", e))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| StorageError::sqlite("query artifacts", e))?;
    let mut artifacts = Vec::new();
    for row in rows {
        let (digest, state) = row.map_err(|e| StorageError::sqlite("read artifact row", e))?;
        artifacts.push((parse_digest(&digest)?, parse_artifact_state(&state)?));
    }
    drop(stmt);

    for (digest, state) in artifacts {
        let in_quarantine = store.file_exists(ArtifactSpace::Quarantine, digest)?;
        let in_final = store.file_exists(ArtifactSpace::Final, digest)?;
        match (state, in_quarantine, in_final) {
            // quarantine 行 + quarantine 文件：一致。
            (ArtifactState::Quarantine, true, false) => {}
            // quarantine 行 + 无文件：陈旧行，删除（quarantine 可清理）。
            (ArtifactState::Quarantine, false, false) => {
                let tx = conn
                    .transaction()
                    .map_err(|e| StorageError::sqlite("begin stale row transaction", e))?;
                tx.execute(
                    "DELETE FROM artifacts WHERE digest = ?1 AND state = 'quarantine'",
                    [digest.to_string()],
                )
                .map_err(|e| StorageError::sqlite("delete stale quarantine row", e))?;
                tx.commit()
                    .map_err(|e| StorageError::sqlite("commit stale row transaction", e))?;
                actions.push(RecoveryAction::StaleQuarantineRowRemoved { digest });
            }
            // quarantine 行 + 文件已在 final：撤销未提交的文件移动。
            (ArtifactState::Quarantine, false, true) => {
                store.demote_final_to_quarantine(digest)?;
                actions.push(RecoveryAction::ArtifactDemoted { digest });
            }
            // candidate/installed 行 + 文件仍在 quarantine：完成候选提交
            // （DB 是 commit point，§18.5 active 已提交 → 恢复 active）。
            (ArtifactState::Candidate | ArtifactState::Installed, true, false) => {
                store.promote_quarantine_to_final(digest)?;
                actions.push(RecoveryAction::ArtifactPromoted { digest });
            }
            // candidate/installed 行 + final 文件：一致。
            (ArtifactState::Candidate | ArtifactState::Installed, false, true) => {}
            // candidate/installed 行 + 无文件：promoted artifact 丢失，
            // fail closed（绝不静默继续运行）。
            (ArtifactState::Candidate | ArtifactState::Installed, false, false) => {
                return Err(StorageError::CorruptState(format!(
                    "artifact {digest} (state {state}) has no file on disk; \
                     refusing to continue"
                )));
            }
            // 文件同时在两个空间：rename 不可能复制文件 → 外部干预/损坏。
            (_, true, true) => {
                return Err(StorageError::CorruptState(format!(
                    "artifact {digest} exists in both quarantine and final spaces"
                )));
            }
        }
    }
    Ok(())
}

/// 动作 → audit 字段（动作名 / target / detail，全部不含机密）。
fn describe(action: &RecoveryAction) -> (&'static str, Option<String>, Option<String>) {
    match action {
        RecoveryAction::SwitchRolledBack {
            transaction_id,
            installation_id,
            to_version,
            to_digest,
        } => (
            "switch-rolled-back",
            Some(installation_id.to_string()),
            Some(format!(
                "transaction {transaction_id}: interrupted switch to {to_version} \
                 ({to_digest}) rolled back; active restored to previous version"
            )),
        ),
        RecoveryAction::ArtifactPromoted { digest } => (
            "artifact-promoted",
            None,
            Some(format!(
                "candidate {digest} committed but file was in quarantine; moved to final"
            )),
        ),
        RecoveryAction::ArtifactDemoted { digest } => (
            "artifact-demoted",
            None,
            Some(format!(
                "quarantine {digest} not committed but file was in final; moved back"
            )),
        ),
        RecoveryAction::StaleQuarantineRowRemoved { digest } => (
            "stale-quarantine-row-removed",
            None,
            Some(format!("quarantine record {digest} had no file; removed")),
        ),
        RecoveryAction::StagingCleaned => (
            "staging-cleaned",
            None,
            Some("transient staging leftovers removed".into()),
        ),
    }
}

fn insert_recovery_audit(
    tx: &rusqlite::Transaction<'_>,
    event: &AuditEvent,
    occurred_at: i64,
) -> Result<(), StorageError> {
    tx.execute(
        "INSERT INTO audit_events (occurred_at, actor, category, action, target, outcome, detail)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            occurred_at,
            event.actor().to_string(),
            event.category().to_string(),
            event.action(),
            event.target(),
            event.outcome().to_string(),
            event.detail(),
        ],
    )
    .map_err(|e| StorageError::sqlite("insert recovery audit event", e))?;
    Ok(())
}

fn read_active(
    conn: &Connection,
    installation_id: InstallationId,
) -> Result<Option<ActiveBinding>, StorageError> {
    let row = conn
        .query_row(
            "SELECT installation_id, component_id, component_version, content_digest
             FROM active_version WHERE installation_id = ?1",
            [installation_id.to_string()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|e| StorageError::sqlite("read active binding", e))?;
    match row {
        Some((id_str, component_str, version_str, digest_str)) => Ok(Some(ActiveBinding {
            installation_id: parse_installation(&id_str)?,
            component_id: parse_component(&component_str)?,
            component_version: parse_version(&version_str)?,
            content_digest: parse_digest(&digest_str)?,
        })),
        None => Ok(None),
    }
}

fn parse_digest(value: &str) -> Result<ContentDigest, StorageError> {
    ContentDigest::from_hex(value)
        .map_err(|_| StorageError::CorruptState(format!("invalid digest in database: {value:?}")))
}

fn parse_installation(value: &str) -> Result<InstallationId, StorageError> {
    value.parse().map_err(|_| {
        StorageError::CorruptState(format!("invalid installation id in database: {value:?}"))
    })
}

fn parse_component(value: &str) -> Result<operune_domain::ComponentId, StorageError> {
    operune_domain::ComponentId::new(value).map_err(|_| {
        StorageError::CorruptState(format!("invalid component id in database: {value:?}"))
    })
}

fn parse_version(value: &str) -> Result<ComponentVersion, StorageError> {
    value.parse().map_err(|_| {
        StorageError::CorruptState(format!("invalid component version in database: {value:?}"))
    })
}

fn parse_artifact_state(value: &str) -> Result<ArtifactState, StorageError> {
    value.parse().map_err(|_| {
        StorageError::CorruptState(format!("invalid artifact state in database: {value:?}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactSpace, DiskBudget};
    use crate::migration::open_authoritative_db;
    use crate::model::{AuditActor, AuditCategory, UpgradePhase};
    use crate::repository::Repository;
    use crate::testutil::{audit, component_id, data_root, err, ok, some, some_ok, tempdir};
    use operune_domain::{ByteSize, ComponentLifecycleEvent, ComponentVersion};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    fn harness(dir: &std::path::Path) -> (rusqlite::Connection, ArtifactStore) {
        let root = data_root(dir);
        ok(root.ensure_layout(), "layout");
        let conn = ok(open_authoritative_db(&root.db_path()), "open db");
        let store = ArtifactStore::new(root, DiskBudget::default());
        (conn, store)
    }

    fn cancel() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    fn version(v: &str) -> ComponentVersion {
        ok(v.parse::<ComponentVersion>(), "parse version")
    }

    /// 建立 v1 active + v2 candidate 的完整状态（供崩溃模拟）。
    fn active_v1_candidate_v2(
        conn: &mut Connection,
        store: &ArtifactStore,
    ) -> (InstallationId, ContentDigest, ContentDigest) {
        let cid = component_id("recover-me");
        let c = cancel();
        {
            let mut repo = Repository::new(conn, store);
            let v1 = version("1.0.0");
            let v2 = version("2.0.0");
            let s1 = ok(
                repo.stage_bytes(b"v1-bytes", ok(ByteSize::mib(16), "limit")),
                "stage v1",
            );
            ok(
                repo.record_quarantine(&s1, &audit("q1"), &c),
                "quarantine v1",
            );
            ok(
                repo.commit_candidate(s1.digest, cid.clone(), v1, &audit("c1"), &c),
                "candidate v1",
            );
            let inst = ok(
                repo.create_installation(cid.clone(), &audit("install"), &c),
                "install",
            );
            ok(
                repo.bind_installation_version(inst, cid.clone(), v1, s1.digest, &audit("b1"), &c),
                "bind v1",
            );
            ok(
                repo.apply_lifecycle_event(
                    inst,
                    ComponentLifecycleEvent::ValidationSucceeded,
                    &audit("v"),
                    &c,
                ),
                "validate",
            );
            ok(
                repo.apply_lifecycle_event(
                    inst,
                    ComponentLifecycleEvent::ActivationRequested,
                    &audit("a"),
                    &c,
                ),
                "activate",
            );
            ok(
                repo.apply_lifecycle_event(
                    inst,
                    ComponentLifecycleEvent::ReadinessSucceeded,
                    &audit("r"),
                    &c,
                ),
                "readiness",
            );
            ok(
                repo.switch_active_version(inst, v1, s1.digest, &audit("switch1"), &c),
                "switch v1",
            );
            let s2 = ok(
                repo.stage_bytes(b"v2-bytes", ok(ByteSize::mib(16), "limit")),
                "stage v2",
            );
            ok(
                repo.record_quarantine(&s2, &audit("q2"), &c),
                "quarantine v2",
            );
            ok(
                repo.commit_candidate(s2.digest, cid.clone(), v2, &audit("c2"), &c),
                "candidate v2",
            );
            ok(
                repo.bind_installation_version(inst, cid, v2, s2.digest, &audit("b2"), &c),
                "bind v2",
            );
            (inst, s1.digest, s2.digest)
        }
    }

    #[test]
    fn prepared_marker_rolled_back_active_preserved() -> Result<(), StorageError> {
        // §18.5：switch 中断（prepared marker）→ 恢复旧版本。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let (inst, d1, d2) = active_v1_candidate_v2(&mut conn, &store);
        let v1 = version("1.0.0");
        let v2 = version("2.0.0");
        // 模拟崩溃：手工插入 prepared marker（阶段 A 已提交，阶段 B 未执行）。
        let now = Timestamp::now()?.sql_value()?;
        conn.execute(
            "INSERT INTO upgrade_transactions
                 (installation_id, from_component_version, from_content_digest,
                  to_component_version, to_content_digest, phase, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
            params![
                inst.to_string(),
                v1.to_string(),
                d1.to_string(),
                v2.to_string(),
                d2.to_string(),
                now
            ],
        )
        .map_err(|e| StorageError::sqlite("insert prepared marker (test)", e))?;

        let actions = run_recovery(&mut conn, &store)?;
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            RecoveryAction::SwitchRolledBack {
                to_version,
                to_digest,
                ..
            } if *to_version == v2 && *to_digest == d2
        ));
        // 决策=恢复旧版：active 仍是 v1；marker 已终态。
        let repo = Repository::new(&mut conn, &store);
        let binding = some_ok(repo.get_active_binding(inst), "active binding");
        assert_eq!(binding.component_version, v1);
        assert_eq!(binding.content_digest, d1);
        let markers = ok(repo.list_upgrade_transactions(inst), "markers");
        assert_eq!(markers.len(), 2);
        assert!(
            markers.iter().all(|m| m.phase != UpgradePhase::Prepared),
            "no prepared marker may survive recovery"
        );
        assert!(
            markers.iter().any(|m| m.phase == UpgradePhase::RolledBack),
            "the interrupted switch must be recorded as rolled back"
        );
        // 恢复动作落入 durable audit（§33：audit 说明最后已提交状态）。
        let events = ok(repo.list_audit_recent(100), "audit");
        let recovery_event = some(
            events
                .iter()
                .find(|e| e.category == AuditCategory::Recovery)
                .cloned(),
            "recovery audit event",
        );
        assert_eq!(recovery_event.actor, AuditActor::Recovery);
        assert_eq!(recovery_event.action, "switch-rolled-back");
        Ok(())
    }

    #[test]
    fn prepared_marker_inconsistent_with_active_fails_closed() -> Result<(), StorageError> {
        // §18.5 歧义消除：prepared marker 存在时 active 必须 = from。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let (inst, _d1, d2) = active_v1_candidate_v2(&mut conn, &store);
        let v2 = version("2.0.0");
        // 伪造损坏状态：marker 声称 from = v2（与真实 active v1 不一致）。
        let now = Timestamp::now()?.sql_value()?;
        conn.execute(
            "INSERT INTO upgrade_transactions
                 (installation_id, from_component_version, from_content_digest,
                  to_component_version, to_content_digest, phase, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
            params![
                inst.to_string(),
                v2.to_string(),
                d2.to_string(),
                v2.to_string(),
                d2.to_string(),
                now
            ],
        )
        .map_err(|e| StorageError::sqlite("insert corrupt marker (test)", e))?;
        let error = err(
            run_recovery(&mut conn, &store),
            "recovery with corrupt marker",
        );
        assert!(
            matches!(error, StorageError::CorruptState(_)),
            "expected CorruptState, got {error:?}"
        );
        Ok(())
    }

    #[test]
    fn artifact_demoted_when_candidate_not_committed() -> Result<(), StorageError> {
        // §18.5 candidate 未提交 → 保持 quarantine：文件在 final、行 quarantine
        // → 移回 quarantine。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let digest = ContentDigest::from_bytes(b"demote-me");
        // 构造：quarantine 行 + 文件已在 final（崩溃于 rename 与 DB commit 之间）。
        conn.execute(
            "INSERT INTO artifacts (digest, byte_size, state, created_at)
             VALUES (?1, 9, 'quarantine', 1)",
            [digest.to_string()],
        )
        .map_err(|e| StorageError::sqlite("insert artifact row (test)", e))?;
        store.write_staging("s", b"demote-me")?;
        store.promote_staging_to_quarantine("s", digest)?;
        store.promote_quarantine_to_final(digest)?;

        let actions = run_recovery(&mut conn, &store)?;
        assert!(
            actions.iter().any(
                |a| matches!(a, RecoveryAction::ArtifactDemoted { digest: d } if *d == digest)
            )
        );
        assert!(store.file_exists(ArtifactSpace::Quarantine, digest)?);
        assert!(!store.file_exists(ArtifactSpace::Final, digest)?);
        Ok(())
    }

    #[test]
    fn artifact_promoted_when_candidate_committed() -> Result<(), StorageError> {
        // §18.5 active 已提交 → 恢复 active：行 candidate、文件在 quarantine
        // → 移动到 final（完成候选提交）。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let digest = ContentDigest::from_bytes(b"promote-me");
        conn.execute(
            "INSERT INTO artifacts (digest, byte_size, state, created_at)
             VALUES (?1, 10, 'candidate', 1)",
            [digest.to_string()],
        )
        .map_err(|e| StorageError::sqlite("insert artifact row (test)", e))?;
        store.write_staging("s", b"promote-me")?;
        store.promote_staging_to_quarantine("s", digest)?;

        let actions = run_recovery(&mut conn, &store)?;
        assert!(
            actions.iter().any(
                |a| matches!(a, RecoveryAction::ArtifactPromoted { digest: d } if *d == digest)
            )
        );
        assert!(!store.file_exists(ArtifactSpace::Quarantine, digest)?);
        assert!(store.file_exists(ArtifactSpace::Final, digest)?);
        Ok(())
    }

    #[test]
    fn stale_quarantine_row_removed() -> Result<(), StorageError> {
        // quarantine 行无文件 → 删除行（§18.5 candidate 未提交 → 清理）。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let digest = ContentDigest::from_bytes(b"ghost-row");
        conn.execute(
            "INSERT INTO artifacts (digest, byte_size, state, created_at)
             VALUES (?1, 9, 'quarantine', 1)",
            [digest.to_string()],
        )
        .map_err(|e| StorageError::sqlite("insert artifact row (test)", e))?;
        let actions = run_recovery(&mut conn, &store)?;
        assert!(actions.iter().any(
            |a| matches!(a, RecoveryAction::StaleQuarantineRowRemoved { digest: d } if *d == digest)
        ));
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM artifacts WHERE digest = ?1",
                [digest.to_string()],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::sqlite("count artifacts (test)", e))?;
        assert_eq!(count, 0);
        Ok(())
    }

    #[test]
    fn missing_promoted_artifact_fails_closed() -> Result<(), StorageError> {
        // candidate/installed 行无文件 → CorruptState（绝不静默继续运行）。
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let digest = ContentDigest::from_bytes(b"lost-artifact");
        conn.execute(
            "INSERT INTO artifacts (digest, byte_size, state, created_at)
             VALUES (?1, 9, 'installed', 1)",
            [digest.to_string()],
        )
        .map_err(|e| StorageError::sqlite("insert artifact row (test)", e))?;
        let error = err(
            run_recovery(&mut conn, &store),
            "recovery with lost artifact",
        );
        assert!(matches!(error, StorageError::CorruptState(_)));
        Ok(())
    }

    #[test]
    fn staging_leftovers_are_cleaned() -> Result<(), StorageError> {
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        store.write_staging("leftover", b"junk")?;
        let actions = run_recovery(&mut conn, &store)?;
        assert!(actions.contains(&RecoveryAction::StagingCleaned));
        assert_eq!(ok(store.staging_usage(), "staging usage").as_u64(), 0);
        Ok(())
    }

    #[test]
    fn recovery_is_idempotent() -> Result<(), StorageError> {
        let dir = tempdir();
        let (mut conn, store) = harness(dir.path());
        let digest = ContentDigest::from_bytes(b"idempotent");
        conn.execute(
            "INSERT INTO artifacts (digest, byte_size, state, created_at)
             VALUES (?1, 10, 'candidate', 1)",
            [digest.to_string()],
        )
        .map_err(|e| StorageError::sqlite("insert artifact row (test)", e))?;
        store.write_staging("s", b"idempotent")?;
        store.promote_staging_to_quarantine("s", digest)?;
        let first = run_recovery(&mut conn, &store)?;
        assert_eq!(first.len(), 1);
        // 第二次运行：状态已收敛，无新动作（staging 已空）。
        let second = run_recovery(&mut conn, &store)?;
        assert!(second.is_empty(), "recovery must be idempotent");
        Ok(())
    }

    #[test]
    fn recovery_action_describe_is_diagnostic_only() {
        // describe() 的 audit 字段（防回归：动作描述不含机密）。
        let action = RecoveryAction::SwitchRolledBack {
            transaction_id: ok(crate::model::UpgradeTransactionId::from_rowid(1), "tx id"),
            installation_id: InstallationId::new(),
            to_version: version("2.0.0"),
            to_digest: ContentDigest::from_bytes(b"x"),
        };
        let (name, target, detail) = describe(&action);
        assert_eq!(name, "switch-rolled-back");
        assert!(target.is_some());
        assert!(detail.is_some());
        assert!(!format!("{detail:?}").contains("secret"));
    }
}
