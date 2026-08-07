//! Typed repository adapter（§24.2：repository adapter；§18.1：SQL 细节不泄漏
//! 到调用方）。
//!
//! 本模块是 SQL 边界：接触字符串/整数 wire 表示，立即 parse/validate 成领域
//! 类型（§13.3 边界解析一次）。所有公开签名使用 domain typed 类型
//! （[`ComponentId`] / [`ComponentVersion`] / [`ContentDigest`] /
//! [`InstallationId`] / [`CapabilityId`] / [`ComponentLifecycleState`]）与本
//! crate 的 typed newtype（`model.rs`）。
//!
//! # 事务边界
//!
//! 每个命令的 SQLite 事务边界在本模块明确（§18.2），统一经 [`Repository::run_tx`]
//! 执行：事务中任何失败（含 audit 写入失败）都整体回滚——不存在半状态。
//! **audit 强制事务**（§18.7）：安全/权限/Component 生命周期变更与其 audit
//! 事件在**同一事务**内写入；audit 无法可靠落盘 ⇒ 变更整体不提交（fail
//! closed）。
//!
//! # 安装/升级 crash consistency 协议（§18.5）
//!
//! 原则：**DB 事务是 commit point，文件位置是派生态（打开时对账，
//! `recovery.rs`）**。文件操作顺序与 crash points 见 `artifact.rs` 模块文档。
//!
//! `switch_active_version` 两阶段协议（消除"两个版本都被误认为唯一 active"
//! 的歧义，§18.5）：
//!
//! ```text
//! 阶段 A（事务 1，commit point #1）：INSERT upgrade_transactions
//!   phase = 'prepared'，记录 from（当前 active 版本/digest）→ to。提交后
//!   marker 已 durable，但 active_version 尚未变化。
//! 阶段 B（事务 2，commit point #2）：UPSERT active_version 指向 to（PK 单行，
//!   DB 强制至多一个 active）+ installation_versions(to) → 'installed' +
//!   artifacts(to) → 'installed' + marker → 'committed' + audit。
//!   全部原子：active 切换与 marker 完成不可能分叉。
//! ```
//!
//! - crash between A and B → recovery 看到 `prepared`：active 仍 = from
//!   （阶段 B 未运行），确定性决策 = **恢复旧版本**（marker → 'rolled_back'，
//!   candidate 保留可重试，§18.5 "根据 durable transaction record 恢复旧版本
//!   或完成新版本"——本实现 0.1.0 策略：恢复旧版）；
//! - crash during B → SQLite 原子提交：要么 B 完整生效（active = to），要么
//!   完全不生效（active 仍 = from）；marker 与 active 永远一致；
//! - recovery 断言：`prepared` marker 存在时 active 必须仍 = from，否则
//!   CorruptState fail closed（不可恢复歧义）。
//!
//! # 取消语义（§18.2）
//!
//! 每个写命令接受 `cancel: &AtomicBool`（caller cancellation 探针）。取消
//! 检查点在**每个事务提交之前**：请求在事务提交前被取消 ⇒ 该事务不提交
//! （回滚），命令返回 [`StorageError::Cancelled`]。已提交事务不受取消影响
//! （提交点之前的检查已通过）——绝不产生半事务状态。

use std::sync::atomic::{AtomicBool, Ordering};

use operune_domain::{
    CapabilityId, ComponentId, ComponentLifecycleEvent, ComponentLifecycleState, ComponentVersion,
    ContentDigest, InstallationId,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::artifact::{ArtifactSpace, ArtifactStore, BudgetUsage, GcPolicy, GcReport};
use crate::error::{BudgetSpace, StorageError};
use crate::model::{
    ActiveBinding, ArtifactRecord, ArtifactState, AuditActor, AuditEvent, AuditRecord,
    CapabilityScope, ConfigEntry, GrantRecord, InstallationRecord, InstallationVersionRecord,
    RollbackResult, SessionId, SessionRecord, StagedArtifact, Timestamp, UpgradeTransactionId,
    UpgradeTransactionRecord, UserId, UserRecord, VersionState,
};

/// 取消检查：提交点之前的取消 → `Cancelled`（§18.2 取消语义）。
fn check_cancel(cancel: &AtomicBool) -> Result<(), StorageError> {
    if cancel.load(Ordering::Relaxed) {
        Err(StorageError::Cancelled)
    } else {
        Ok(())
    }
}

/// 绑定到单个连接的 repository（由 Storage Executor worker 独占使用，
/// 单连接串行 ⇒ 无 SQLite 锁竞争，§18.2）。
pub(crate) struct Repository<'a> {
    conn: &'a mut Connection,
    store: &'a ArtifactStore,
}

impl<'a> Repository<'a> {
    pub(crate) fn new(conn: &'a mut Connection, store: &'a ArtifactStore) -> Self {
        Self { conn, store }
    }

    // ------------------------------------------------------------------
    // 事务 / SQL / 边界解析助手
    // ------------------------------------------------------------------

    /// 事务执行器（§18.2 事务边界明确）：`operation` 内任何 `Err`（含 audit
    /// 写入失败，§18.7）⇒ 事务整体回滚；成功才提交。
    fn run_tx<T>(
        &mut self,
        context: &'static str,
        operation: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<T, StorageError>,
    ) -> Result<T, StorageError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|e| StorageError::sqlite(context, e))?;
        let result = operation(&tx);
        match result {
            Ok(value) => tx
                .commit()
                .map_err(|e| StorageError::sqlite(context, e))
                .map(|()| value),
            Err(error) => {
                drop(tx); // 回滚
                Err(error)
            }
        }
    }

    fn now(&self) -> Result<Timestamp, StorageError> {
        Timestamp::now()
    }

    fn sql_now(&self) -> Result<i64, StorageError> {
        Timestamp::now()?.sql_value()
    }

    fn byte_size_from_i64(&self, value: i64) -> Result<operune_domain::ByteSize, StorageError> {
        u64::try_from(value)
            .map(operune_domain::ByteSize::from_bytes)
            .map_err(|_| StorageError::CorruptState(format!("negative byte size: {value}")))
    }

    fn timestamp_from_i64(value: i64) -> Result<Timestamp, StorageError> {
        u64::try_from(value)
            .map(Timestamp::from_unix_seconds)
            .map_err(|_| {
                StorageError::CorruptState(format!("negative timestamp in database: {value}"))
            })
    }

    fn parse_digest(value: &str) -> Result<ContentDigest, StorageError> {
        ContentDigest::from_hex(value).map_err(|_| {
            StorageError::CorruptState(format!("invalid digest in database: {value:?}"))
        })
    }

    fn parse_component_id(value: &str) -> Result<ComponentId, StorageError> {
        ComponentId::new(value).map_err(|_| {
            StorageError::CorruptState(format!("invalid component id in database: {value:?}"))
        })
    }

    fn parse_version(value: &str) -> Result<ComponentVersion, StorageError> {
        value.parse().map_err(|_| {
            StorageError::CorruptState(format!("invalid component version in database: {value:?}"))
        })
    }

    fn parse_installation_id(value: &str) -> Result<InstallationId, StorageError> {
        value.parse().map_err(|_| {
            StorageError::CorruptState(format!("invalid installation id in database: {value:?}"))
        })
    }

    fn parse_lifecycle_state(value: &str) -> Result<ComponentLifecycleState, StorageError> {
        value.parse().map_err(|_| {
            StorageError::CorruptState(format!("invalid lifecycle state in database: {value:?}"))
        })
    }

    /// 审计事件写入（§18.7：与变更同事务，fail closed）。
    fn insert_audit(
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
        .map_err(|e| StorageError::sqlite("insert audit event", e))?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // 读取助手
    // ------------------------------------------------------------------

    fn read_artifact(&self, digest: ContentDigest) -> Result<Option<ArtifactRecord>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT digest, byte_size, state, created_at FROM artifacts WHERE digest = ?1",
                [digest.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read artifact", e))?;
        match row {
            Some((digest_str, byte_size, state, created_at)) => Ok(Some(ArtifactRecord {
                digest: Self::parse_digest(&digest_str)?,
                byte_size: self.byte_size_from_i64(byte_size)?,
                state: state.parse()?,
                created_at: Self::timestamp_from_i64(created_at)?,
            })),
            None => Ok(None),
        }
    }

    fn read_installation(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<InstallationRecord>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT installation_id, component_id, enabled, lifecycle_state, created_at, updated_at
                 FROM installations WHERE installation_id = ?1",
                [installation_id.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read installation", e))?;
        match row {
            Some((id_str, component_str, enabled, lifecycle_str, created_at, updated_at)) => {
                Ok(Some(InstallationRecord {
                    installation_id: Self::parse_installation_id(&id_str)?,
                    component_id: Self::parse_component_id(&component_str)?,
                    enabled: enabled != 0,
                    lifecycle_state: Self::parse_lifecycle_state(&lifecycle_str)?,
                    created_at: Self::timestamp_from_i64(created_at)?,
                    updated_at: Self::timestamp_from_i64(updated_at)?,
                }))
            }
            None => Ok(None),
        }
    }

    fn read_active_binding(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<ActiveBinding>, StorageError> {
        let row = self
            .conn
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
            Some((id_str, component_str, version_str, digest_str)) => {
                let component_id = Self::parse_component_id(&component_str)?;
                let binding = ActiveBinding {
                    installation_id: Self::parse_installation_id(&id_str)?,
                    component_id: component_id.clone(),
                    component_version: Self::parse_version(&version_str)?,
                    content_digest: Self::parse_digest(&digest_str)?,
                };
                let installation = self.read_installation(installation_id)?.ok_or_else(|| {
                    StorageError::CorruptState("active binding without installation".into())
                })?;
                if installation.component_id != component_id {
                    return Err(StorageError::CorruptState(format!(
                        "active binding component {component_id} does not match installation \
                         component {}",
                        installation.component_id
                    )));
                }
                Ok(Some(binding))
            }
            None => Ok(None),
        }
    }

    fn read_installation_version(
        &self,
        installation_id: InstallationId,
        version: ComponentVersion,
    ) -> Result<Option<InstallationVersionRecord>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT installation_id, component_id, component_version, content_digest, state, created_at
                 FROM installation_versions
                 WHERE installation_id = ?1 AND component_version = ?2",
                params![installation_id.to_string(), version.to_string()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read installation version", e))?;
        match row {
            Some((id_str, component_str, version_str, digest_str, state, created_at)) => {
                Ok(Some(InstallationVersionRecord {
                    installation_id: Self::parse_installation_id(&id_str)?,
                    component_id: Self::parse_component_id(&component_str)?,
                    component_version: Self::parse_version(&version_str)?,
                    content_digest: Self::parse_digest(&digest_str)?,
                    state: state.parse()?,
                    created_at: Self::timestamp_from_i64(created_at)?,
                }))
            }
            None => Ok(None),
        }
    }

    fn read_registry_digest(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<ContentDigest>, StorageError> {
        let value: Option<String> = self
            .conn
            .query_row(
                "SELECT content_digest FROM component_versions
                 WHERE component_id = ?1 AND component_version = ?2",
                params![component_id.to_string(), version.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read registry digest", e))?;
        match value {
            Some(value) => Ok(Some(Self::parse_digest(&value)?)),
            None => Ok(None),
        }
    }

    fn quarantine_usage(&self) -> Result<operune_domain::ByteSize, StorageError> {
        let sum: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(byte_size), 0) FROM artifacts WHERE state = 'quarantine'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::sqlite("quarantine usage", e))?;
        self.byte_size_from_i64(sum)
    }

    fn final_usage(&self) -> Result<operune_domain::ByteSize, StorageError> {
        let sum: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(SUM(byte_size), 0) FROM artifacts
                 WHERE state IN ('candidate', 'installed')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::sqlite("final usage", e))?;
        self.byte_size_from_i64(sum)
    }

    // ------------------------------------------------------------------
    // 字节事实：staging → quarantine → candidate（§19.2）
    // ------------------------------------------------------------------

    /// `stage_bytes`：暂存原始字节并计算内容事实（digest）。
    ///
    /// - 硬大小上限在写入前拒绝（§19.1 oversized input 提前拒绝）；
    /// - staging 预算准入（§18.7）；
    /// - 只写 `staging/`（瞬态，不 fsync，不建行）。
    pub(crate) fn stage_bytes(
        &mut self,
        bytes: &[u8],
        hard_limit: operune_domain::ByteSize,
    ) -> Result<StagedArtifact, StorageError> {
        let size = operune_domain::ByteSize::from_bytes(
            u64::try_from(bytes.len())
                .map_err(|_| StorageError::InvalidArgument("byte length out of range".into()))?,
        );
        if size.exceeds(hard_limit) {
            return Err(StorageError::ArtifactTooLarge {
                size,
                limit: hard_limit,
            });
        }
        let usage = self.store.staging_usage()?;
        if usage
            .checked_add(size)?
            .exceeds(self.store.budget().staging())
        {
            return Err(StorageError::BudgetExceeded {
                space: BudgetSpace::Staging,
                message: format!(
                    "staging usage {} bytes + {} bytes exceeds budget {} bytes",
                    usage.as_u64(),
                    size.as_u64(),
                    self.store.budget().staging().as_u64()
                ),
            });
        }
        let staging_name = new_staging_name(self.now()?);
        self.store.write_staging(&staging_name, bytes)?;
        Ok(StagedArtifact {
            digest: ContentDigest::from_bytes(bytes),
            byte_size: size,
            staging_name,
        })
    }

    /// `record_quarantine`：把 staging 文件提升为 quarantine 记录（字节事实
    /// 阶段完成，§19.2）。重复上传（同 digest 已存在）幂等成功。
    ///
    /// 协议（crash points 见 `artifact.rs` 文档）：预算准入 →
    /// rename(staging → quarantine) → 一个 DB 事务（INSERT artifacts + audit）。
    pub(crate) fn record_quarantine(
        &mut self,
        staged: &StagedArtifact,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        // 重复上传：同 digest 已记录 → 丢弃重复 staging 文件，幂等成功。
        if self.read_artifact(staged.digest)?.is_some() {
            self.store.remove_staging_file(&staged.staging_name)?;
            return Ok(());
        }
        // §18.7 预算准入（写入前检查）。
        let usage = self.quarantine_usage()?;
        if usage
            .checked_add(staged.byte_size)?
            .exceeds(self.store.budget().quarantine())
        {
            return Err(StorageError::BudgetExceeded {
                space: BudgetSpace::Quarantine,
                message: format!(
                    "quarantine usage {} bytes + {} bytes exceeds budget {} bytes",
                    usage.as_u64(),
                    staged.byte_size.as_u64(),
                    self.store.budget().quarantine().as_u64()
                ),
            });
        }
        // 文件：staging → quarantine（同一 volume 原子 rename）。
        self.store
            .promote_staging_to_quarantine(&staged.staging_name, staged.digest)?;
        // DB 事务（commit point）。
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        let result = self.run_tx("begin quarantine transaction", |tx| {
            tx.execute(
                "INSERT INTO artifacts (digest, byte_size, state, created_at)
                 VALUES (?1, ?2, 'quarantine', ?3)",
                params![
                    staged.digest.to_string(),
                    self_sql_bytes(staged.byte_size)?,
                    now
                ],
            )
            .map_err(|e| StorageError::sqlite("insert quarantine artifact", e))?;
            Self::insert_audit(tx, audit, now)
        });
        if let Err(error) = result {
            // 尽力把文件移回 staging（崩溃场景由 recovery 对账兜底）。
            let source = self
                .store
                .data_root()
                .quarantine_dir()
                .join(staged.digest.to_string());
            let target = self
                .store
                .data_root()
                .staging_dir()
                .join(&staged.staging_name);
            let _ = std::fs::rename(source, target);
            return Err(error);
        }
        Ok(())
    }

    /// `commit_candidate`：quarantine → candidate（验证通过、建立注册表绑定，
    /// §19.2 应用身份阶段）。同版本不同 digest 显式阻断（§19.4
    /// DigestConflict，绝不静默覆盖）。
    ///
    /// 协议：注册表冲突预检 → final 预算准入 → rename(quarantine → final) →
    /// 一个 DB 事务（registry 绑定 + artifacts → 'candidate' + audit）。
    pub(crate) fn commit_candidate(
        &mut self,
        digest: ContentDigest,
        component_id: ComponentId,
        version: ComponentVersion,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        let artifact = self
            .read_artifact(digest)?
            .ok_or_else(|| StorageError::NotFound(format!("artifact {digest} is not recorded")))?;
        if artifact.state != ArtifactState::Quarantine {
            return Err(StorageError::InvalidArgument(format!(
                "artifact {digest} is not in quarantine (state = {})",
                artifact.state
            )));
        }
        // §19.4 冲突预检（单连接串行 ⇒ 检查与后续写入之间无交错）。
        if let Some(existing) = self.read_registry_digest(&component_id, version)?
            && existing != digest
        {
            return Err(StorageError::DigestConflict {
                component: component_id,
                version,
                existing,
                incoming: digest,
            });
        }
        // 同 digest 重复接受：幂等（§19.4 同一版本绑定同一 digest 可重入）。
        // §18.7 final 预算准入。
        let usage = self.final_usage()?;
        if usage
            .checked_add(artifact.byte_size)?
            .exceeds(self.store.budget().artifacts())
        {
            return Err(StorageError::BudgetExceeded {
                space: BudgetSpace::Final,
                message: format!(
                    "final usage {} bytes + {} bytes exceeds budget {} bytes",
                    usage.as_u64(),
                    artifact.byte_size.as_u64(),
                    self.store.budget().artifacts().as_u64()
                ),
            });
        }
        // 文件：quarantine → final（同一 volume 原子 rename）。
        self.store.promote_quarantine_to_final(digest)?;
        // DB 事务（commit point）。
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        let result = self.run_tx("begin candidate transaction", |tx| {
            tx.execute(
                "INSERT INTO components (component_id) VALUES (?1)
                 ON CONFLICT(component_id) DO NOTHING",
                [component_id.to_string()],
            )
            .map_err(|e| StorageError::sqlite("register component", e))?;
            tx.execute(
                "INSERT INTO component_versions (component_id, component_version, content_digest, accepted_at)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(component_id, component_version)
                 DO UPDATE SET content_digest = excluded.content_digest",
                params![
                    component_id.to_string(),
                    version.to_string(),
                    digest.to_string(),
                    now
                ],
            )
            .map_err(|e| StorageError::sqlite("bind registry version", e))?;
            tx.execute(
                "UPDATE artifacts SET state = 'candidate' WHERE digest = ?1",
                [digest.to_string()],
            )
            .map_err(|e| StorageError::sqlite("advance artifact state", e))?;
            Self::insert_audit(tx, audit, now)
        });
        if let Err(error) = result {
            // 尽力把文件移回 quarantine（崩溃场景由 recovery 对账兜底）。
            let source = self
                .store
                .data_root()
                .artifacts_dir()
                .join(digest.to_string());
            let target = self
                .store
                .data_root()
                .quarantine_dir()
                .join(digest.to_string());
            let _ = std::fs::rename(source, target);
            return Err(error);
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // 安装实例（§18.3 / §19.2）
    // ------------------------------------------------------------------

    /// `create_installation`：创建安装实例（Core 生成 InstallationId，§19.4）。
    /// 初始 lifecycle = `Installed`（§12.2 初始状态），默认未启用
    /// （deny-by-default，§17.2；由管理面显式启用）。
    pub(crate) fn create_installation(
        &mut self,
        component_id: ComponentId,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<InstallationId, StorageError> {
        check_cancel(cancel)?;
        // 两阶段安装（§19.2）：安装实例必须先有注册表事实（commit_candidate）。
        let component_exists: Option<String> = self
            .conn
            .query_row(
                "SELECT component_id FROM components WHERE component_id = ?1",
                [component_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::sqlite("check component", e))?;
        if component_exists.is_none() {
            return Err(StorageError::NotFound(format!(
                "component {component_id} is not registered; commit a candidate first \
                 (§19.2 two-phase install)"
            )));
        }
        let installation_id = InstallationId::new();
        let now = self.sql_now()?;
        self.run_tx("begin installation transaction", |tx| {
            tx.execute(
                "INSERT INTO installations
                     (installation_id, component_id, enabled, lifecycle_state, created_at, updated_at)
                 VALUES (?1, ?2, 0, 'installed', ?3, ?3)",
                params![
                    installation_id.to_string(),
                    component_id.to_string(),
                    now
                ],
            )
            .map_err(|e| StorageError::sqlite("insert installation", e))?;
            Self::insert_audit(tx, audit, now)
        })?;
        Ok(installation_id)
    }

    /// `bind_installation_version`：把逻辑版本绑定到安装实例（candidate 记录，
    /// §18.3 installation 表语义）。绑定必须在注册表事实之后（§19.2）。
    pub(crate) fn bind_installation_version(
        &mut self,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        digest: ContentDigest,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        if self.read_installation(installation_id)?.is_none() {
            return Err(StorageError::NotFound(format!(
                "installation {installation_id}"
            )));
        }
        let registered = self
            .read_registry_digest(&component_id, version)?
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "component {component_id} version {version} is not registered"
                ))
            })?;
        if registered != digest {
            return Err(StorageError::InvalidArgument(format!(
                "digest {digest} does not match the registered digest {registered} for \
                 {component_id} {version}"
            )));
        }
        let now = self.sql_now()?;
        self.run_tx("begin bind transaction", |tx| {
            tx.execute(
                "INSERT INTO installation_versions
                     (installation_id, component_id, component_version, content_digest, state, created_at)
                 VALUES (?1, ?2, ?3, ?4, 'candidate', ?5)",
                params![
                    installation_id.to_string(),
                    component_id.to_string(),
                    version.to_string(),
                    digest.to_string(),
                    now
                ],
            )
            .map_err(|e| StorageError::sqlite("insert installation version", e))?;
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `apply_lifecycle_event`：领域生命周期状态机（§12.2）的持久化推进。
    /// 转换合法性由 domain 的 `transition()` 判定（单一事实源）——非法转换
    /// 返回 [`StorageError::Domain`]（`InvalidTransition`），绝不静默忽略。
    pub(crate) fn apply_lifecycle_event(
        &mut self,
        installation_id: InstallationId,
        event: ComponentLifecycleEvent,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<ComponentLifecycleState, StorageError> {
        check_cancel(cancel)?;
        let current: Option<String> = self
            .conn
            .query_row(
                "SELECT lifecycle_state FROM installations WHERE installation_id = ?1",
                [installation_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read lifecycle state", e))?;
        let current = current
            .ok_or_else(|| StorageError::NotFound(format!("installation {installation_id}")))?;
        let state = Self::parse_lifecycle_state(&current)?;
        let next = state.transition(event)?; // DomainError → StorageError::Domain
        let now = self.sql_now()?;
        self.run_tx("begin lifecycle transaction", |tx| {
            tx.execute(
                "UPDATE installations SET lifecycle_state = ?1, updated_at = ?2
                 WHERE installation_id = ?3",
                params![next.to_string(), now, installation_id.to_string()],
            )
            .map_err(|e| StorageError::sqlite("update lifecycle state", e))?;
            Self::insert_audit(tx, audit, now)
        })?;
        Ok(next)
    }

    /// `set_installation_enabled`：enable/disable 事实（§39.2）。启用一个
    /// `Failed`（终态，§12.2）的安装被拒绝。
    pub(crate) fn set_installation_enabled(
        &mut self,
        installation_id: InstallationId,
        enabled: bool,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        let lifecycle: Option<String> = self
            .conn
            .query_row(
                "SELECT lifecycle_state FROM installations WHERE installation_id = ?1",
                [installation_id.to_string()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read lifecycle state", e))?;
        let lifecycle = lifecycle
            .ok_or_else(|| StorageError::NotFound(format!("installation {installation_id}")))?;
        let state = Self::parse_lifecycle_state(&lifecycle)?;
        if enabled && state == ComponentLifecycleState::Failed {
            return Err(StorageError::LifecycleConflict(format!(
                "installation {installation_id} is in terminal state failed and cannot be enabled"
            )));
        }
        let now = self.sql_now()?;
        self.run_tx("begin enable transaction", |tx| {
            tx.execute(
                "UPDATE installations SET enabled = ?1, updated_at = ?2 WHERE installation_id = ?3",
                params![enabled, now, installation_id.to_string()],
            )
            .map_err(|e| StorageError::sqlite("update enabled flag", e))?;
            Self::insert_audit(tx, audit, now)
        })
    }

    // ------------------------------------------------------------------
    // 唯一 active 切换 / 回滚（§18.5 两阶段协议）
    // ------------------------------------------------------------------

    /// `switch_active_version`：把安装的 active 绑定原子切换到目标版本。
    ///
    /// 用于初次激活（from = NULL）与热升级（§20.1）。两阶段协议 + 取消语义
    /// 见模块文档：任何 crash point 重启后都能确定唯一 active
    /// （`active_version` 单行 + marker 阶段断言，§18.5）。
    pub(crate) fn switch_active_version(
        &mut self,
        installation_id: InstallationId,
        to_version: ComponentVersion,
        to_digest: ContentDigest,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<ActiveBinding, StorageError> {
        check_cancel(cancel)?;
        let installation = self
            .read_installation(installation_id)?
            .ok_or_else(|| StorageError::NotFound(format!("installation {installation_id}")))?;
        let to_record = self
            .read_installation_version(installation_id, to_version)?
            .ok_or_else(|| {
                StorageError::NotFound(format!(
                    "installation {installation_id} has no bound version {to_version}"
                ))
            })?;
        if to_record.content_digest != to_digest {
            return Err(StorageError::InvalidArgument(format!(
                "digest {to_digest} does not match bound digest {} for version {to_version}",
                to_record.content_digest
            )));
        }
        if to_record.state == VersionState::RolledBack {
            return Err(StorageError::LifecycleConflict(format!(
                "version {to_version} was rolled back and cannot be activated directly"
            )));
        }
        let artifact = self.read_artifact(to_digest)?.ok_or_else(|| {
            StorageError::CorruptState(format!("bound digest {to_digest} has no artifact record"))
        })?;
        if artifact.state == ArtifactState::Quarantine {
            return Err(StorageError::LifecycleConflict(format!(
                "artifact {to_digest} is still quarantined; commit the candidate first"
            )));
        }
        let from = self.read_active_binding(installation_id)?;
        // 幂等：目标已是 active。
        if let Some(current) = &from
            && current.component_version == to_version
            && current.content_digest == to_digest
        {
            return Ok(current.clone());
        }
        let from_version = from.as_ref().map(|b| b.component_version);
        let from_digest = from.as_ref().map(|b| b.content_digest);

        // 阶段 A：durable marker（commit point #1）。取消 ⇒ 未创建 marker。
        check_cancel(cancel)?;
        let now_a = self.sql_now()?;
        let marker_id = self.run_tx("begin prepare marker transaction", |tx| {
            tx.execute(
                "INSERT INTO upgrade_transactions
                     (installation_id,
                      from_component_version, from_content_digest,
                      to_component_version, to_content_digest,
                      phase, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
                params![
                    installation_id.to_string(),
                    from_version.map(|v| v.to_string()),
                    from_digest.map(|d| d.to_string()),
                    to_version.to_string(),
                    to_digest.to_string(),
                    now_a
                ],
            )
            .map_err(|e| StorageError::sqlite("insert prepare marker", e))?;
            let marker_id = UpgradeTransactionId::from_rowid(tx.last_insert_rowid())?;
            Self::insert_audit(tx, audit, now_a)?;
            Ok(marker_id)
        })?;

        // 阶段 B：active 切换 + marker → committed + audit（commit point #2）。
        // 取消 ⇒ 事务回滚（active 未动）+ 确定性收尾（marker → rolled_back，
        // 与 recovery 决策一致：恢复旧版，§18.5）。
        check_cancel(cancel)?;
        let now_b = self.sql_now()?;
        let switched = self.run_tx("begin switch transaction", |tx| {
            tx.execute(
                "INSERT INTO active_version (installation_id, component_id, component_version, content_digest)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(installation_id) DO UPDATE SET
                     component_id = excluded.component_id,
                     component_version = excluded.component_version,
                     content_digest = excluded.content_digest",
                params![
                    installation_id.to_string(),
                    installation.component_id.to_string(),
                    to_version.to_string(),
                    to_digest.to_string()
                ],
            )
            .map_err(|e| StorageError::sqlite("switch active binding", e))?;
            tx.execute(
                "UPDATE installation_versions SET state = 'installed'
                 WHERE installation_id = ?1 AND component_version = ?2",
                params![installation_id.to_string(), to_version.to_string()],
            )
            .map_err(|e| StorageError::sqlite("mark version installed", e))?;
            tx.execute(
                "UPDATE artifacts SET state = 'installed' WHERE digest = ?1",
                [to_digest.to_string()],
            )
            .map_err(|e| StorageError::sqlite("mark artifact installed", e))?;
            tx.execute(
                "UPDATE upgrade_transactions SET phase = 'committed', completed_at = ?1
                 WHERE transaction_id = ?2",
                params![now_b, marker_id.as_rowid()],
            )
            .map_err(|e| StorageError::sqlite("complete transaction marker", e))?;
            Self::insert_audit(tx, audit, now_b)?;
            // 提交前取消检查（§18.2：提交前被取消 ⇒ 事务不提交）。
            check_cancel(cancel)?;
            Ok(())
        });
        if let Err(error) = switched {
            if matches!(error, StorageError::Cancelled) {
                // 确定性收尾：marker → rolled_back（恢复旧版语义，与 recovery
                // 决策一致，§18.5）。
                self.finalize_marker_rolled_back(
                    marker_id,
                    installation_id,
                    to_version,
                    to_digest,
                )?;
            }
            return Err(error);
        }
        Ok(ActiveBinding {
            installation_id,
            component_id: installation.component_id,
            component_version: to_version,
            content_digest: to_digest,
        })
    }

    /// 把 `prepared` marker 确定性标记为 `rolled_back`（在进程内取消或打开时
    /// recovery 中调用；语义 = 恢复旧版，§18.5）。
    fn finalize_marker_rolled_back(
        &mut self,
        marker_id: UpgradeTransactionId,
        installation_id: InstallationId,
        to_version: ComponentVersion,
        to_digest: ContentDigest,
    ) -> Result<(), StorageError> {
        let now = self.sql_now()?;
        self.run_tx("begin finalize transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE upgrade_transactions SET phase = 'rolled_back', completed_at = ?1
                     WHERE transaction_id = ?2 AND phase = 'prepared'",
                    params![now, marker_id.as_rowid()],
                )
                .map_err(|e| StorageError::sqlite("roll back prepared marker", e))?;
            if changed != 1 {
                return Err(StorageError::CorruptState(format!(
                    "cannot finalize marker {marker_id}: unexpected phase"
                )));
            }
            let event = AuditEvent::new(
                AuditActor::Recovery,
                crate::model::AuditCategory::ComponentLifecycle,
                "switch-rolled-back",
                Some(installation_id.to_string()),
                crate::model::AuditOutcome::Failure,
                Some(format!(
                    "cancelled or interrupted switch to {to_version} ({to_digest}); \
                     active restored to previous version"
                )),
            )?;
            Self::insert_audit(tx, &event, now)
        })
    }

    /// `rollback_version`：显式回滚到上一已知良好版本（§20.1 / §18.7 rollback
    /// retention：上一已知良好 artifact 不得被 GC 删除）。
    ///
    /// 目标 = 本安装中 state = 'installed' 且版本号小于当前 active 的最高版本
    /// （同一 switch 协议执行；旧 active 随后标记 'rolled_back'）。
    pub(crate) fn rollback_version(
        &mut self,
        installation_id: InstallationId,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<RollbackResult, StorageError> {
        check_cancel(cancel)?;
        let current = self.read_active_binding(installation_id)?.ok_or_else(|| {
            StorageError::NotFound(format!(
                "installation {installation_id} has no active version to roll back"
            ))
        })?;
        let target: Option<(String, String)> = self
            .conn
            .query_row(
                "SELECT component_version, content_digest FROM installation_versions
                 WHERE installation_id = ?1 AND state = 'installed'
                   AND component_version < ?2
                 ORDER BY component_version DESC LIMIT 1",
                params![
                    installation_id.to_string(),
                    current.component_version.to_string()
                ],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|e| StorageError::sqlite("find rollback target", e))?;
        let (version_str, digest_str) = target.ok_or_else(|| {
            StorageError::NotFound(format!(
                "installation {installation_id} has no previous known-good version"
            ))
        })?;
        let target_version = Self::parse_version(&version_str)?;
        let target_digest = Self::parse_digest(&digest_str)?;
        self.switch_active_version(
            installation_id,
            target_version,
            target_digest,
            audit,
            cancel,
        )?;
        // 旧 active 标记为 rolled_back（digest 仍被本行引用 → 保留，§18.7）。
        self.run_tx("begin rollback mark transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE installation_versions SET state = 'rolled_back'
                     WHERE installation_id = ?1 AND component_version = ?2",
                    params![
                        installation_id.to_string(),
                        current.component_version.to_string()
                    ],
                )
                .map_err(|e| StorageError::sqlite("mark rolled back", e))?;
            if changed != 1 {
                return Err(StorageError::CorruptState(format!(
                    "rollback target record missing for installation {installation_id}"
                )));
            }
            Ok(())
        })?;
        Ok(RollbackResult {
            to_version: target_version,
            to_digest: target_digest,
        })
    }

    // ------------------------------------------------------------------
    // Grants（§17.5：grant 的 durable owner 是 InstallationId）
    // ------------------------------------------------------------------

    /// `grant_capability`：给安装实例授权能力（scope 绑定安装实例，§17.1）。
    pub(crate) fn grant_capability(
        &mut self,
        installation_id: InstallationId,
        capability_id: CapabilityId,
        scope: CapabilityScope,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        if self.read_installation(installation_id)?.is_none() {
            return Err(StorageError::NotFound(format!(
                "installation {installation_id}"
            )));
        }
        let now = self.sql_now()?;
        self.run_tx("begin grant transaction", |tx| {
            tx.execute(
                "INSERT INTO grants (installation_id, capability_id, scope, state, granted_at, revoked_at)
                 VALUES (?1, ?2, ?3, 'granted', ?4, NULL)
                 ON CONFLICT(installation_id, capability_id) DO UPDATE SET
                     scope = excluded.scope,
                     state = 'granted',
                     granted_at = excluded.granted_at,
                     revoked_at = NULL",
                params![
                    installation_id.to_string(),
                    capability_id.to_string(),
                    scope.as_str(),
                    now
                ],
            )
            .map_err(|e| StorageError::sqlite("upsert grant", e))?;
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `revoke_capability`：撤销授权（当前未授权则 NotFound）。
    pub(crate) fn revoke_capability(
        &mut self,
        installation_id: InstallationId,
        capability_id: CapabilityId,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        self.run_tx("begin revoke transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE grants SET state = 'revoked', revoked_at = ?1
                     WHERE installation_id = ?2 AND capability_id = ?3 AND state = 'granted'",
                    params![now, installation_id.to_string(), capability_id.to_string()],
                )
                .map_err(|e| StorageError::sqlite("revoke grant", e))?;
            if changed == 0 {
                return Err(StorageError::NotFound(format!(
                    "installation {installation_id} has no active grant for {capability_id}"
                )));
            }
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `list_grants`：当前生效的授权（§17.5 生效快照）。
    pub(crate) fn list_grants(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<GrantRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT installation_id, capability_id, scope, granted_at, revoked_at
                 FROM grants
                 WHERE installation_id = ?1 AND state = 'granted'
                 ORDER BY capability_id",
            )
            .map_err(|e| StorageError::sqlite("prepare list grants", e))?;
        let rows = stmt
            .query_map([installation_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<i64>>(4)?,
                ))
            })
            .map_err(|e| StorageError::sqlite("query grants", e))?;
        let mut grants = Vec::new();
        for row in rows {
            let (id_str, capability_str, scope, granted_at, revoked_at) =
                row.map_err(|e| StorageError::sqlite("read grant row", e))?;
            grants.push(GrantRecord {
                installation_id: Self::parse_installation_id(&id_str)?,
                capability_id: CapabilityId::new(&capability_str).map_err(|_| {
                    StorageError::CorruptState(format!(
                        "invalid capability id in database: {capability_str:?}"
                    ))
                })?,
                scope: CapabilityScope::new(scope).map_err(|e| {
                    StorageError::CorruptState(format!("invalid scope in database: {e}"))
                })?,
                granted_at: Self::timestamp_from_i64(granted_at)?,
                revoked_at: match revoked_at {
                    Some(value) => Some(Self::timestamp_from_i64(value)?),
                    None => None,
                },
            });
        }
        Ok(grants)
    }

    // ------------------------------------------------------------------
    // Users / password hashes（§16.4 / §18.3）
    // ------------------------------------------------------------------

    /// `create_user`：创建用户。`password_hash` 必须是 Argon2id PHC 哈希字符串
    /// （由 security crate 生成；存储层视其为不透明值，**绝不接受/存储明文
    /// 密码**，§16.4 / §16.6）。
    pub(crate) fn create_user(
        &mut self,
        username: &str,
        password_hash: &str,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<UserId, StorageError> {
        check_cancel(cancel)?;
        crate::model::validate_text(username, "username", 255)?;
        crate::model::validate_text(password_hash, "password hash", 1024)?;
        let now = self.sql_now()?;
        let result = self.run_tx("begin user transaction", |tx| {
            tx.execute(
                "INSERT INTO users (username, password_hash, disabled, created_at, updated_at)
                 VALUES (?1, ?2, 0, ?3, ?3)",
                params![username, password_hash, now],
            )
            .map_err(|e| StorageError::sqlite("insert user", e))?;
            let user_id = UserId::from_rowid(tx.last_insert_rowid())?;
            Self::insert_audit(tx, audit, now)?;
            Ok(user_id)
        });
        match result {
            Ok(user_id) => Ok(user_id),
            Err(error) => Err(map_unique_violation(error, "username already exists")),
        }
    }

    /// `get_user_by_username`。
    pub(crate) fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<UserRecord>, StorageError> {
        self.read_user_by("username = ?1", params![username])
    }

    /// `get_user`。
    pub(crate) fn get_user(&self, user_id: UserId) -> Result<Option<UserRecord>, StorageError> {
        self.read_user_by("user_id = ?1", params![user_id.as_rowid()])
    }

    fn read_user_by<P: rusqlite::Params>(
        &self,
        where_clause: &str,
        param: P,
    ) -> Result<Option<UserRecord>, StorageError> {
        let sql = format!(
            "SELECT user_id, username, password_hash, disabled, created_at, updated_at
             FROM users WHERE {where_clause}"
        );
        let row = self
            .conn
            .query_row(&sql, param, |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .optional()
            .map_err(|e| StorageError::sqlite("read user", e))?;
        match row {
            Some((user_id, username, password_hash, disabled, created_at, updated_at)) => {
                Ok(Some(UserRecord {
                    user_id: UserId::from_rowid(user_id)?,
                    username,
                    password_hash,
                    disabled: disabled != 0,
                    created_at: Self::timestamp_from_i64(created_at)?,
                    updated_at: Self::timestamp_from_i64(updated_at)?,
                }))
            }
            None => Ok(None),
        }
    }

    /// `update_password_hash`：轮换密码哈希（§16.3 / §16.4）。
    /// audit 中绝不含哈希值（§16.6）。
    pub(crate) fn update_password_hash(
        &mut self,
        user_id: UserId,
        new_hash: &str,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        crate::model::validate_text(new_hash, "password hash", 1024)?;
        let now = self.sql_now()?;
        self.run_tx("begin password update transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE users SET password_hash = ?1, updated_at = ?2 WHERE user_id = ?3",
                    params![new_hash, now, user_id.as_rowid()],
                )
                .map_err(|e| StorageError::sqlite("update password hash", e))?;
            if changed == 0 {
                return Err(StorageError::NotFound(format!("user {user_id}")));
            }
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `set_user_disabled`：停用/启用用户。
    pub(crate) fn set_user_disabled(
        &mut self,
        user_id: UserId,
        disabled: bool,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        self.run_tx("begin user disable transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE users SET disabled = ?1, updated_at = ?2 WHERE user_id = ?3",
                    params![disabled, now, user_id.as_rowid()],
                )
                .map_err(|e| StorageError::sqlite("update user disabled", e))?;
            if changed == 0 {
                return Err(StorageError::NotFound(format!("user {user_id}")));
            }
            Self::insert_audit(tx, audit, now)
        })
    }

    // ------------------------------------------------------------------
    // Sessions（§16.5：只存 token 单向摘要，明文绝不落库）
    // ------------------------------------------------------------------

    /// `create_session`：创建服务端 session。`token_digest` 是 bearer token 的
    /// 单向 SHA-256 摘要（由 security crate 计算；**本 API 不接受明文 token**）。
    pub(crate) fn create_session(
        &mut self,
        user_id: UserId,
        token_digest: ContentDigest,
        absolute_expires_at: Timestamp,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<SessionId, StorageError> {
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        if absolute_expires_at.as_unix_seconds() <= Timestamp::now()?.as_unix_seconds() {
            return Err(StorageError::InvalidArgument(
                "session absolute expiry must be in the future".into(),
            ));
        }
        if self.get_user(user_id)?.is_none() {
            return Err(StorageError::NotFound(format!("user {user_id}")));
        }
        let expires = absolute_expires_at.sql_value()?;
        let result = self.run_tx("begin session transaction", |tx| {
            tx.execute(
                "INSERT INTO sessions
                     (user_id, token_digest, created_at, last_used_at, absolute_expires_at, revoked)
                 VALUES (?1, ?2, ?3, ?3, ?4, 0)",
                params![user_id.as_rowid(), token_digest.to_string(), now, expires],
            )
            .map_err(|e| StorageError::sqlite("insert session", e))?;
            let session_id = SessionId::from_rowid(tx.last_insert_rowid())?;
            Self::insert_audit(tx, audit, now)?;
            Ok(session_id)
        });
        match result {
            Ok(session_id) => Ok(session_id),
            Err(error) => Err(map_unique_violation(
                error,
                "a session with this token digest already exists",
            )),
        }
    }

    /// `lookup_session`：按 token 摘要查找**未吊销且未过期**的 session。
    pub(crate) fn lookup_session(
        &self,
        token_digest: ContentDigest,
    ) -> Result<Option<SessionRecord>, StorageError> {
        let now = self.sql_now()?;
        let row = self
            .conn
            .query_row(
                "SELECT session_id, user_id, token_digest, created_at, last_used_at,
                        absolute_expires_at, revoked
                 FROM sessions
                 WHERE token_digest = ?1 AND revoked = 0 AND absolute_expires_at > ?2",
                params![token_digest.to_string(), now],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::sqlite("lookup session", e))?;
        match row {
            Some((
                session_id,
                user_id,
                digest_str,
                created_at,
                last_used_at,
                expires_at,
                revoked,
            )) => Ok(Some(SessionRecord {
                session_id: SessionId::from_rowid(session_id)?,
                user_id: UserId::from_rowid(user_id)?,
                token_digest: Self::parse_digest(&digest_str)?,
                created_at: Self::timestamp_from_i64(created_at)?,
                last_used_at: Self::timestamp_from_i64(last_used_at)?,
                absolute_expires_at: Self::timestamp_from_i64(expires_at)?,
                revoked: revoked != 0,
            })),
            None => Ok(None),
        }
    }

    /// `touch_session`：刷新 `last_used_at`（idle expiry 依据，§16.5）。
    /// 非审计强制写入（§18.7 只要求安全/权限/生命周期变更落 durable audit）。
    pub(crate) fn touch_session(&mut self, session_id: SessionId) -> Result<(), StorageError> {
        let now = self.sql_now()?;
        let changed = self
            .conn
            .execute(
                "UPDATE sessions SET last_used_at = ?1
                 WHERE session_id = ?2 AND revoked = 0",
                params![now, session_id.as_rowid()],
            )
            .map_err(|e| StorageError::sqlite("touch session", e))?;
        if changed == 0 {
            return Err(StorageError::NotFound(format!("session {session_id}")));
        }
        Ok(())
    }

    /// `revoke_session`：吊销单个 session（§16.5 logout / 吊销路径）。
    pub(crate) fn revoke_session(
        &mut self,
        session_id: SessionId,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        self.run_tx("begin session revoke transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE sessions SET revoked = 1 WHERE session_id = ?1 AND revoked = 0",
                    [session_id.as_rowid()],
                )
                .map_err(|e| StorageError::sqlite("revoke session", e))?;
            if changed == 0 {
                return Err(StorageError::NotFound(format!("session {session_id}")));
            }
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `revoke_all_user_sessions`：吊销用户全部 session（§16.5 密码重置 /
    /// 管理员停用等路径）。返回吊销数量。
    pub(crate) fn revoke_all_user_sessions(
        &mut self,
        user_id: UserId,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<u64, StorageError> {
        check_cancel(cancel)?;
        let now = self.sql_now()?;
        let count = self.run_tx("begin revoke all transaction", |tx| {
            let changed = tx
                .execute(
                    "UPDATE sessions SET revoked = 1 WHERE user_id = ?1 AND revoked = 0",
                    [user_id.as_rowid()],
                )
                .map_err(|e| StorageError::sqlite("revoke all sessions", e))?;
            let count = u64::try_from(changed).map_err(|_| {
                StorageError::CorruptState("session revoke count out of range".into())
            })?;
            Self::insert_audit(tx, audit, now)?;
            Ok(count)
        })?;
        Ok(count)
    }

    // ------------------------------------------------------------------
    // Audit（§18.7 append-only）
    // ------------------------------------------------------------------

    /// `append_audit`：独立追加审计事件（供非变更型操作 / 外部编排）。
    /// 返回事件序号（追加顺序）。
    pub(crate) fn append_audit(&mut self, event: &AuditEvent) -> Result<i64, StorageError> {
        let now = self.sql_now()?;
        self.run_tx("begin audit transaction", |tx| {
            Self::insert_audit(tx, event, now)?;
            Ok(tx.last_insert_rowid())
        })
    }

    /// `list_audit_recent`：最近 N 条审计事件（新→旧；有界读取，limit ≤ 1000）。
    pub(crate) fn list_audit_recent(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        if limit > 1000 {
            return Err(StorageError::InvalidArgument(
                "audit read limit must be at most 1000".into(),
            ));
        }
        let limit = i64::try_from(limit)
            .map_err(|_| StorageError::InvalidArgument("audit limit out of range".into()))?;
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, occurred_at, actor, category, action, target, outcome, detail
                 FROM audit_events ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| StorageError::sqlite("prepare list audit", e))?;
        let rows = stmt
            .query_map([limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .map_err(|e| StorageError::sqlite("query audit", e))?;
        let mut events = Vec::new();
        for row in rows {
            let (id, occurred_at, actor, category, action, target, outcome, detail) =
                row.map_err(|e| StorageError::sqlite("read audit row", e))?;
            events.push(AuditRecord {
                id,
                occurred_at: Self::timestamp_from_i64(occurred_at)?,
                actor: actor.parse()?,
                category: category.parse()?,
                action,
                target,
                outcome: outcome.parse()?,
                detail,
            });
        }
        Ok(events)
    }

    // ------------------------------------------------------------------
    // Runtime config（§18.0：事务化、版本化并审计）
    // ------------------------------------------------------------------

    /// `set_config`：写入/更新 RuntimeConfig（版本号每次 +1）。
    pub(crate) fn set_config(
        &mut self,
        key: &str,
        value: &str,
        audit: &AuditEvent,
        cancel: &AtomicBool,
    ) -> Result<(), StorageError> {
        check_cancel(cancel)?;
        crate::model::validate_text(key, "config key", 255)?;
        crate::model::validate_text(value, "config value", 1024 * 1024)?;
        let now = self.sql_now()?;
        self.run_tx("begin config transaction", |tx| {
            tx.execute(
                "INSERT INTO runtime_config (key, value, version, updated_at, updated_by)
                 VALUES (?1, ?2, 1, ?3, ?4)
                 ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     version = runtime_config.version + 1,
                     updated_at = excluded.updated_at,
                     updated_by = excluded.updated_by",
                params![key, value, now, audit.actor().to_string()],
            )
            .map_err(|e| StorageError::sqlite("upsert config", e))?;
            Self::insert_audit(tx, audit, now)
        })
    }

    /// `get_config`。
    pub(crate) fn get_config(&self, key: &str) -> Result<Option<ConfigEntry>, StorageError> {
        let row = self
            .conn
            .query_row(
                "SELECT key, value, version, updated_at, updated_by
                 FROM runtime_config WHERE key = ?1",
                [key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| StorageError::sqlite("read config", e))?;
        match row {
            Some((key, value, version, updated_at, updated_by)) => Ok(Some(ConfigEntry {
                key,
                value,
                version: u64::try_from(version).map_err(|_| {
                    StorageError::CorruptState(format!("config version {version} out of range"))
                })?,
                updated_at: Self::timestamp_from_i64(updated_at)?,
                updated_by,
            })),
            None => Ok(None),
        }
    }

    /// `list_config`。
    pub(crate) fn list_config(&self) -> Result<Vec<ConfigEntry>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT key, value, version, updated_at, updated_by FROM runtime_config ORDER BY key",
            )
            .map_err(|e| StorageError::sqlite("prepare list config", e))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|e| StorageError::sqlite("query config", e))?;
        let mut entries = Vec::new();
        for row in rows {
            let (key, value, version, updated_at, updated_by) =
                row.map_err(|e| StorageError::sqlite("read config row", e))?;
            entries.push(ConfigEntry {
                key,
                value,
                version: u64::try_from(version).map_err(|_| {
                    StorageError::CorruptState(format!("config version {version} out of range"))
                })?,
                updated_at: Self::timestamp_from_i64(updated_at)?,
                updated_by,
            });
        }
        Ok(entries)
    }

    // ------------------------------------------------------------------
    // GC / 预算（§18.7）
    // ------------------------------------------------------------------

    /// `gc`：GC/retention 基线（详见 `artifact.rs` 文档）。quarantine 超龄记录
    /// 清理；被 registry / installation / active / upgrade 事务引用的 digest
    /// 由外键保护，绝不删除（§18.7 rollback retention）。
    pub(crate) fn gc(&mut self, policy: GcPolicy) -> Result<GcReport, StorageError> {
        let mut report = GcReport::default();

        // staging：瞬态空间总是清理。
        let (files, bytes) = self.store.cleanup_staging()?;
        report.removed_files += files;
        report.bytes_freed = report.bytes_freed.saturating_add(bytes);

        let now = self.now()?;

        // quarantine 文件对账。
        for file in self.store.scan_digest_files(ArtifactSpace::Quarantine)? {
            let row = self.read_artifact(file.digest)?;
            match row {
                // 无行文件：孤儿 → 删除（§18.5 candidate 未提交 → 清理）。
                None => {
                    if self
                        .store
                        .remove_file(ArtifactSpace::Quarantine, file.digest)?
                    {
                        report.removed_files += 1;
                        report.bytes_freed = report.bytes_freed.saturating_add(file.byte_size);
                    }
                }
                // 超龄 quarantine 行：文件 + 行一起回收。
                Some(record) if record.state == ArtifactState::Quarantine => {
                    if ArtifactStore::older_than(record.created_at, policy.quarantine_max_age, now)
                    {
                        if self
                            .store
                            .remove_file(ArtifactSpace::Quarantine, file.digest)?
                        {
                            report.removed_files += 1;
                            report.bytes_freed = report.bytes_freed.saturating_add(file.byte_size);
                        }
                        let changed = u64::try_from(
                            self.conn
                                .execute(
                                    "DELETE FROM artifacts WHERE digest = ?1 AND state = 'quarantine'",
                                    [file.digest.to_string()],
                                )
                                .map_err(|e| StorageError::sqlite("delete stale quarantine row", e))?,
                        )
                        .map_err(|_| {
                            StorageError::CorruptState("deleted row count out of range".into())
                        })?;
                        report.removed_rows += changed;
                    }
                }
                // candidate/installed 行：文件位置由 recovery 对账，GC 不动。
                Some(_) => {}
            }
        }

        // quarantine 行无文件（陈旧行）。
        let digests = self.query_quarantine_digests()?;
        for digest in digests {
            if !self.store.file_exists(ArtifactSpace::Quarantine, digest)? {
                let changed = u64::try_from(
                    self.conn
                        .execute(
                            "DELETE FROM artifacts WHERE digest = ?1 AND state = 'quarantine'",
                            [digest.to_string()],
                        )
                        .map_err(|e| StorageError::sqlite("delete stale quarantine row", e))?,
                )
                .map_err(|_| StorageError::CorruptState("deleted row count out of range".into()))?;
                report.removed_rows += changed;
            }
        }

        // final 孤儿文件（无行）：不可引用（行是引用入口）→ 安全删除。
        for file in self.store.scan_digest_files(ArtifactSpace::Final)? {
            if self.read_artifact(file.digest)?.is_none()
                && self.store.remove_file(ArtifactSpace::Final, file.digest)?
            {
                report.removed_files += 1;
                report.bytes_freed = report.bytes_freed.saturating_add(file.byte_size);
            }
        }

        Ok(report)
    }

    fn query_quarantine_digests(&self) -> Result<Vec<ContentDigest>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT digest FROM artifacts WHERE state = 'quarantine'")
            .map_err(|e| StorageError::sqlite("prepare stale quarantine scan", e))?;
        let digests = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::sqlite("query stale quarantine scan", e))?;
        let mut result = Vec::new();
        for digest in digests {
            let digest = digest.map_err(|e| StorageError::sqlite("read stale row", e))?;
            result.push(Self::parse_digest(&digest)?);
        }
        Ok(result)
    }

    /// `budget_usage`：各空间当前占用（§18.7 核算）。
    pub(crate) fn budget_usage(&self) -> Result<BudgetUsage, StorageError> {
        Ok(BudgetUsage {
            staging: self.store.staging_usage()?,
            quarantine: self.quarantine_usage()?,
            final_store: self.final_usage()?,
        })
    }

    // ------------------------------------------------------------------
    // 只读查询
    // ------------------------------------------------------------------

    /// `artifact_exists`。
    pub(crate) fn artifact_exists(&self, digest: ContentDigest) -> Result<bool, StorageError> {
        Ok(self.read_artifact(digest)?.is_some())
    }

    /// `get_artifact`。
    pub(crate) fn get_artifact(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<ArtifactRecord>, StorageError> {
        self.read_artifact(digest)
    }

    /// `get_installation`。
    pub(crate) fn get_installation(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<InstallationRecord>, StorageError> {
        self.read_installation(installation_id)
    }

    /// `list_installations`。
    pub(crate) fn list_installations(&self) -> Result<Vec<InstallationRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare("SELECT installation_id FROM installations ORDER BY created_at")
            .map_err(|e| StorageError::sqlite("prepare list installations", e))?;
        let ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::sqlite("query installations", e))?;
        let mut installations = Vec::new();
        for id in ids {
            let id = id.map_err(|e| StorageError::sqlite("read installation row", e))?;
            let installation_id = Self::parse_installation_id(&id)?;
            if let Some(record) = self.read_installation(installation_id)? {
                installations.push(record);
            }
        }
        Ok(installations)
    }

    /// `get_active_binding`。
    pub(crate) fn get_active_binding(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<ActiveBinding>, StorageError> {
        self.read_active_binding(installation_id)
    }

    /// `list_installation_versions`：安装的全部版本绑定（含 rolled_back 历史，
    /// §18.7 rollback retention 的事实源）。
    pub(crate) fn list_installation_versions(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<InstallationVersionRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT installation_id, component_id, component_version, content_digest, state, created_at
                 FROM installation_versions WHERE installation_id = ?1 ORDER BY component_version",
            )
            .map_err(|e| StorageError::sqlite("prepare list installation versions", e))?;
        let rows = stmt
            .query_map([installation_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })
            .map_err(|e| StorageError::sqlite("query installation versions", e))?;
        let mut records = Vec::new();
        for row in rows {
            let (id_str, component_str, version_str, digest_str, state, created_at) =
                row.map_err(|e| StorageError::sqlite("read installation version row", e))?;
            records.push(InstallationVersionRecord {
                installation_id: Self::parse_installation_id(&id_str)?,
                component_id: Self::parse_component_id(&component_str)?,
                component_version: Self::parse_version(&version_str)?,
                content_digest: Self::parse_digest(&digest_str)?,
                state: state.parse()?,
                created_at: Self::timestamp_from_i64(created_at)?,
            });
        }
        Ok(records)
    }

    /// `list_upgrade_transactions`：安装的升级/回滚事务标记（§18.5 可观测性）。
    pub(crate) fn list_upgrade_transactions(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<UpgradeTransactionRecord>, StorageError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT transaction_id, installation_id,
                        from_component_version, from_content_digest,
                        to_component_version, to_content_digest,
                        phase, created_at, completed_at
                 FROM upgrade_transactions WHERE installation_id = ?1 ORDER BY transaction_id",
            )
            .map_err(|e| StorageError::sqlite("prepare list upgrade transactions", e))?;
        let rows = stmt
            .query_map([installation_id.to_string()], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, Option<i64>>(8)?,
                ))
            })
            .map_err(|e| StorageError::sqlite("query upgrade transactions", e))?;
        let mut records = Vec::new();
        for row in rows {
            let (
                tx_id,
                id_str,
                from_version,
                from_digest,
                to_version,
                to_digest,
                phase,
                created_at,
                completed_at,
            ) = row.map_err(|e| StorageError::sqlite("read upgrade transaction row", e))?;
            records.push(UpgradeTransactionRecord {
                transaction_id: UpgradeTransactionId::from_rowid(tx_id)?,
                installation_id: Self::parse_installation_id(&id_str)?,
                from_version: match from_version {
                    Some(value) => Some(Self::parse_version(&value)?),
                    None => None,
                },
                from_digest: match from_digest {
                    Some(value) => Some(Self::parse_digest(&value)?),
                    None => None,
                },
                to_version: Self::parse_version(&to_version)?,
                to_digest: Self::parse_digest(&to_digest)?,
                phase: phase.parse()?,
                created_at: Self::timestamp_from_i64(created_at)?,
                completed_at: match completed_at {
                    Some(value) => Some(Self::timestamp_from_i64(value)?),
                    None => None,
                },
            });
        }
        Ok(records)
    }
}

/// UNIQUE 约束冲突 → AlreadyExists（其余错误原样返回）。
fn map_unique_violation(error: StorageError, message: &str) -> StorageError {
    match &error {
        StorageError::Sqlite { source, .. } => {
            if let rusqlite::Error::SqliteFailure(ffi_error, _) = source {
                const SQLITE_CONSTRAINT_UNIQUE: i32 = 2067;
                const SQLITE_CONSTRAINT_PRIMARYKEY: i32 = 1555;
                if ffi_error.extended_code == SQLITE_CONSTRAINT_UNIQUE
                    || ffi_error.extended_code == SQLITE_CONSTRAINT_PRIMARYKEY
                {
                    return StorageError::AlreadyExists(message.to_string());
                }
            }
            error
        }
        _ => error,
    }
}

/// ByteSize → SQLite i64 参数（超出范围视为损坏，§14.4 无回绕）。
fn self_sql_bytes(size: operune_domain::ByteSize) -> Result<i64, StorageError> {
    i64::try_from(size.as_u64()).map_err(|_| {
        StorageError::CorruptState(format!("byte size {} out of i64 range", size.as_u64()))
    })
}

/// 生成 staging 临时文件名（唯一性：进程 ID + unix 秒 + 进程内单调计数器；
/// staging 是瞬态空间，打开时清空，无需跨重启唯一）。
fn new_staging_name(now: Timestamp) -> String {
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let counter = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
    format!(
        "stage-{}-{}-{counter}",
        std::process::id(),
        now.as_unix_seconds()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactSpace, DiskBudget};
    use crate::migration::open_authoritative_db;
    use crate::model::UpgradePhase;
    use crate::testutil::{audit, component_id, data_root, err, ok, some, some_ok, tempdir};
    use operune_domain::{ByteSize, DomainError, Duration};
    use std::sync::Arc;

    fn open_harness(dir: &std::path::Path) -> (rusqlite::Connection, ArtifactStore) {
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

    /// 完整字节事实路径：stage → quarantine → candidate。返回 (digest, size)。
    fn stage_candidate(
        conn: &mut Connection,
        store: &ArtifactStore,
        name: &str,
        v: &str,
        bytes: &[u8],
    ) -> (ComponentId, ComponentVersion, ContentDigest) {
        let cid = component_id(name);
        let version = version(v);
        let c = cancel();
        let staged = {
            let mut repo = Repository::new(conn, store);
            let staged = ok(
                repo.stage_bytes(bytes, ok(ByteSize::mib(16), "hard limit")),
                "stage",
            );
            ok(
                repo.record_quarantine(&staged, &audit("quarantine"), &c),
                "quarantine",
            );
            ok(
                repo.commit_candidate(staged.digest, cid.clone(), version, &audit("candidate"), &c),
                "candidate",
            );
            staged
        };
        (cid, version, staged.digest)
    }

    /// 创建安装实例并激活到指定版本（含 enable 与生命周期事件）。
    fn activate(
        conn: &mut Connection,
        store: &ArtifactStore,
        cid: ComponentId,
        v: ComponentVersion,
        digest: ContentDigest,
    ) -> InstallationId {
        let c = cancel();
        let mut repo = Repository::new(conn, store);
        let inst = ok(
            repo.create_installation(cid.clone(), &audit("install"), &c),
            "install",
        );
        ok(
            repo.bind_installation_version(inst, cid.clone(), v, digest, &audit("bind"), &c),
            "bind",
        );
        ok(
            repo.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ValidationSucceeded,
                &audit("validate"),
                &c,
            ),
            "validate",
        );
        ok(
            repo.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ActivationRequested,
                &audit("activate"),
                &c,
            ),
            "activate",
        );
        ok(
            repo.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ReadinessSucceeded,
                &audit("readiness"),
                &c,
            ),
            "readiness",
        );
        ok(
            repo.set_installation_enabled(inst, true, &audit("enable"), &c),
            "enable",
        );
        ok(
            repo.switch_active_version(inst, v, digest, &audit("switch"), &c),
            "switch",
        );
        inst
    }

    fn audit_count(conn: &Connection) -> i64 {
        ok(
            conn.query_row("SELECT COUNT(*) FROM audit_events", [], |row| row.get(0)),
            "audit count",
        )
    }

    #[test]
    fn quarantine_to_candidate_to_active_lifecycle() -> Result<(), StorageError> {
        // §19.2 两阶段安装 + 激活；§18.5 唯一 active 事实。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let cid = component_id("demo");
        let v1 = version("1.0.0");
        // 阶段一：字节事实（§19.2 首段）→ quarantine 记录。
        let staged = {
            let mut repo = Repository::new(&mut conn, &store);
            let staged = ok(
                repo.stage_bytes(b"wasm-v1", ok(ByteSize::mib(16), "limit")),
                "stage",
            );
            ok(
                repo.record_quarantine(&staged, &audit("quarantine"), &c),
                "quarantine",
            );
            let record = some_ok(repo.get_artifact(staged.digest), "artifact record");
            assert_eq!(record.state, ArtifactState::Quarantine);
            assert!(store.file_exists(ArtifactSpace::Quarantine, staged.digest)?);
            staged
        };
        // 阶段二：应用身份（§19.2 第二段）→ candidate（注册表绑定）。
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.commit_candidate(staged.digest, cid.clone(), v1, &audit("candidate"), &c),
                "candidate",
            );
            let record = some_ok(repo.get_artifact(staged.digest), "artifact record");
            assert_eq!(record.state, ArtifactState::Candidate);
            assert!(store.file_exists(ArtifactSpace::Final, staged.digest)?);
        }
        // 阶段三：安装 + 激活。
        let inst = activate(&mut conn, &store, cid.clone(), v1, staged.digest);
        {
            let repo = Repository::new(&mut conn, &store);
            let record = some_ok(repo.get_artifact(staged.digest), "artifact record");
            assert_eq!(record.state, ArtifactState::Installed);
            let binding = some_ok(repo.get_active_binding(inst), "active binding");
            assert_eq!(binding.component_version, v1);
            assert_eq!(binding.content_digest, staged.digest);
            assert_eq!(binding.component_id, cid);
            let installation = some_ok(repo.get_installation(inst), "installation");
            assert!(installation.enabled);
            assert_eq!(
                installation.lifecycle_state,
                ComponentLifecycleState::Active
            );
            // 唯一 active：DB 层面每安装至多一行（PK），且 marker 为 committed。
            let markers = ok(repo.list_upgrade_transactions(inst), "upgrade transactions");
            assert_eq!(markers.len(), 1);
            assert_eq!(markers[0].phase, UpgradePhase::Committed);
            assert_eq!(markers[0].from_version, None);
            assert_eq!(markers[0].to_version, v1);
            // 审计覆盖全程（§18.7）。
            let events = ok(repo.list_audit_recent(100), "audit");
            assert!(events.len() >= 6);
            assert!(events.iter().any(|e| e.action == "switch"));
        }
        let _ = c;
        Ok(())
    }

    #[test]
    fn duplicate_digest_upload_is_idempotent() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let bytes = b"identical-bytes";
        let _cid = component_id("dup");
        let _v = version("1.0.0");
        let staged1 = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.stage_bytes(bytes, ok(ByteSize::mib(16), "limit")),
                "stage 1",
            )
        };
        // 同字节再上传：digest 相同 → record_quarantine 幂等成功。
        let staged2 = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.stage_bytes(bytes, ok(ByteSize::mib(16), "limit")),
                "stage 2",
            )
        };
        assert_eq!(staged1.digest, staged2.digest);
        let mut repo = Repository::new(&mut conn, &store);
        ok(
            repo.record_quarantine(&staged1, &audit("q1"), &c),
            "quarantine 1",
        );
        ok(
            repo.record_quarantine(&staged2, &audit("q2"), &c),
            "quarantine duplicate",
        );
        // 只有一行。
        let count: i64 = ok(
            conn.query_row(
                "SELECT COUNT(*) FROM artifacts WHERE digest = ?1",
                [staged1.digest.to_string()],
                |row| row.get(0),
            ),
            "artifact rows",
        );
        assert_eq!(count, 1);
    }

    #[test]
    fn digest_conflict_is_blocked_not_overwritten() -> Result<(), StorageError> {
        // §19.4：同一 ComponentId + ComponentVersion 绑定不同 digest → 显式阻断。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let cid = component_id("supply-chain");
        let v = version("1.0.0");
        let d1 = {
            let mut repo = Repository::new(&mut conn, &store);
            let s = ok(
                repo.stage_bytes(b"bytes-a", ok(ByteSize::mib(16), "limit")),
                "stage a",
            );
            ok(repo.record_quarantine(&s, &audit("q"), &c), "quarantine a");
            ok(
                repo.commit_candidate(s.digest, cid.clone(), v, &audit("c"), &c),
                "candidate a",
            );
            s.digest
        };
        let d2 = {
            let mut repo = Repository::new(&mut conn, &store);
            let s = ok(
                repo.stage_bytes(b"bytes-b", ok(ByteSize::mib(16), "limit")),
                "stage b",
            );
            ok(repo.record_quarantine(&s, &audit("q"), &c), "quarantine b");
            s.digest
        };
        let mut repo = Repository::new(&mut conn, &store);
        let error = err(
            repo.commit_candidate(d2, cid.clone(), v, &audit("conflict"), &c),
            "conflicting candidate",
        );
        assert!(
            matches!(
                error,
                StorageError::DigestConflict { existing, incoming, .. }
                    if existing == d1 && incoming == d2
            ),
            "expected DigestConflict, got {error:?}"
        );
        // 注册表事实未被覆盖：d2 保持 quarantine，文件退回 quarantine 空间。
        let record = some_ok(repo.get_artifact(d2), "d2 record");
        assert_eq!(record.state, ArtifactState::Quarantine);
        assert!(store.file_exists(ArtifactSpace::Quarantine, d2)?);
        assert!(!store.file_exists(ArtifactSpace::Final, d2)?);
        // d1 仍绑定（bind 使用 d2 会被拒绝）。
        let inst = ok(
            repo.create_installation(cid.clone(), &audit("install"), &c),
            "install",
        );
        let bind_error = err(
            repo.bind_installation_version(inst, cid.clone(), v, d2, &audit("bind"), &c),
            "bind with conflicting digest",
        );
        assert!(matches!(bind_error, StorageError::InvalidArgument(_)));
        Ok(())
    }

    #[test]
    fn switch_atomicity_failure_leaves_no_state() {
        // 目标版本未绑定 → 整个 switch 失败，不产生 marker、active 不变。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, v1, d1) = stage_candidate(&mut conn, &store, "atomic", "1.0.0", b"v1");
        let inst = activate(&mut conn, &store, cid.clone(), v1, d1);
        let v2 = version("2.0.0");
        let d2 = ContentDigest::from_bytes(b"v2-bytes");
        let c = cancel();
        let mut repo = Repository::new(&mut conn, &store);
        let error = err(
            repo.switch_active_version(inst, v2, d2, &audit("switch"), &c),
            "switch to unbound version",
        );
        assert!(matches!(error, StorageError::NotFound(_)));
        // 无 marker 残留（事务整体回滚，§18.2）。
        let markers = ok(repo.list_upgrade_transactions(inst), "markers");
        assert_eq!(markers.len(), 1, "only the original committed switch");
        assert_eq!(markers[0].phase, UpgradePhase::Committed);
        // active 未变化。
        let binding = some_ok(repo.get_active_binding(inst), "binding");
        assert_eq!(binding.component_version, v1);
    }

    #[test]
    fn failed_mutation_rolls_back_audit_with_it() {
        // §18.7：audit 与变更同事务——变更失败 ⇒ audit 也不落盘。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, v1, d1) = stage_candidate(&mut conn, &store, "audit-atomic", "1.0.0", b"v1");
        let inst = activate(&mut conn, &store, cid.clone(), v1, d1);
        let before = audit_count(&conn);
        let v9 = version("9.9.9");
        let c = cancel();
        let mut repo = Repository::new(&mut conn, &store);
        let error = err(
            repo.bind_installation_version(
                inst,
                cid.clone(),
                v9,
                ContentDigest::from_bytes(b"nope"),
                &audit("must-not-be-recorded"),
                &c,
            ),
            "bind unregistered version",
        );
        assert!(matches!(error, StorageError::NotFound(_)));
        assert_eq!(
            audit_count(&conn),
            before,
            "failed mutation must not leave audit"
        );
    }

    #[test]
    fn lifecycle_invalid_transition_is_rejected() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, _v1, _d1) = stage_candidate(&mut conn, &store, "machine", "1.0.0", b"v1");
        let c = cancel();
        let inst = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_installation(cid.clone(), &audit("install"), &c),
                "install",
            )
        };
        let mut repo = Repository::new(&mut conn, &store);
        // Installed 不接受 ReadinessSucceeded（§12.2 转换矩阵由 domain 判定）。
        let error = err(
            repo.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ReadinessSucceeded,
                &audit("illegal"),
                &c,
            ),
            "illegal transition",
        );
        assert!(
            matches!(
                error,
                StorageError::Domain(DomainError::InvalidTransition {
                    state: ComponentLifecycleState::Installed,
                    event: ComponentLifecycleEvent::ReadinessSucceeded,
                })
            ),
            "expected InvalidTransition, got {error:?}"
        );
        let record = some_ok(repo.get_installation(inst), "installation");
        assert_eq!(record.lifecycle_state, ComponentLifecycleState::Installed);
    }

    #[test]
    fn failed_installation_cannot_be_enabled() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, _v1, _d1) = stage_candidate(&mut conn, &store, "failed-once", "1.0.0", b"v1");
        let c = cancel();
        let mut repo = Repository::new(&mut conn, &store);
        let inst = ok(
            repo.create_installation(cid.clone(), &audit("install"), &c),
            "install",
        );
        ok(
            repo.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ValidationFailed,
                &audit("fail"),
                &c,
            ),
            "fail",
        );
        // Failed 是终态（§12.2）：启用被拒绝。
        let error = err(
            repo.set_installation_enabled(inst, true, &audit("enable"), &c),
            "enable failed installation",
        );
        assert!(matches!(error, StorageError::LifecycleConflict(_)));
    }

    #[test]
    fn upgrade_and_rollback_retains_artifacts() -> Result<(), StorageError> {
        // §20.1 热升级 + §18.7 rollback retention：回滚所需的上一已知良好
        // artifact 不得被 GC 删除。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, v1, d1) = stage_candidate(&mut conn, &store, "rolling", "1.0.0", b"v1");
        let inst = activate(&mut conn, &store, cid.clone(), v1, d1);
        // 升级到 v2。
        let (_, v2, d2) = stage_candidate(&mut conn, &store, "rolling", "2.0.0", b"v2");
        let c = cancel();
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.bind_installation_version(inst, cid.clone(), v2, d2, &audit("bind"), &c),
                "bind v2",
            );
            let binding = ok(
                repo.switch_active_version(inst, v2, d2, &audit("switch"), &c),
                "switch to v2",
            );
            assert_eq!(binding.component_version, v2);
        }
        // 回滚到 v1。
        {
            let mut repo = Repository::new(&mut conn, &store);
            let result = ok(
                repo.rollback_version(inst, &audit("rollback"), &c),
                "rollback",
            );
            assert_eq!(result.to_version, v1);
            assert_eq!(result.to_digest, d1);
            let binding = some_ok(repo.get_active_binding(inst), "binding");
            assert_eq!(binding.component_version, v1);
            // v2 标记为 rolled_back，digest 保留（retention）。
            let versions = ok(
                repo.list_installation_versions(inst),
                "installation versions",
            );
            assert_eq!(versions.len(), 2);
            let v2_record = some(
                versions.iter().find(|r| r.component_version == v2).cloned(),
                "v2 record",
            );
            assert_eq!(v2_record.state, VersionState::RolledBack);
            assert_eq!(v2_record.content_digest, d2);
        }
        // GC（立即回收 quarantine）不得删除被引用 digest（§18.7 外键保护）。
        let report = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(repo.gc(GcPolicy::default()), "gc")
        };
        let _ = report;
        {
            let repo = Repository::new(&mut conn, &store);
            assert!(some_ok(repo.get_artifact(d1), "d1").state == ArtifactState::Installed);
            assert!(some_ok(repo.get_artifact(d2), "d2").state == ArtifactState::Installed);
            assert!(store.file_exists(ArtifactSpace::Final, d1)?);
            assert!(store.file_exists(ArtifactSpace::Final, d2)?);
        }
        Ok(())
    }

    #[test]
    fn sessions_never_store_plaintext_token() {
        // §16.5：权威存储只保存 token 单向摘要；明文 bearer token 绝不落库。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let user = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_user(
                    "admin",
                    "argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2h2YWx1ZQ",
                    &audit("create user"),
                    &c,
                ),
                "create user",
            )
        };
        let plaintext = "bearer-token-value-that-must-never-hit-disk";
        let digest = ContentDigest::from_bytes(plaintext.as_bytes());
        let expires = Timestamp::from_unix_seconds(
            ok(Timestamp::now(), "now")
                .as_unix_seconds()
                .saturating_add(3600),
        );
        let session = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_session(user, digest, expires, &audit("create session"), &c),
                "create session",
            )
        };
        // 1) schema 检查：sessions 表不存在可容纳明文的列。
        let columns: Vec<String> = {
            let mut stmt = ok(
                conn.prepare("PRAGMA table_info(sessions)"),
                "prepare pragma",
            );
            let rows = ok(
                stmt.query_map([], |row| row.get::<_, String>(1)),
                "query pragma",
            );
            let mut names = Vec::new();
            for row in rows {
                names.push(ok(row, "read pragma row"));
            }
            names
        };
        assert_eq!(
            columns,
            vec![
                "session_id",
                "user_id",
                "token_digest",
                "created_at",
                "last_used_at",
                "absolute_expires_at",
                "revoked"
            ]
        );
        // 2) 值检查：行内所有文本都不含明文片段。
        let stored_values: Vec<String> = {
            let mut stmt = ok(
                conn.prepare(
                    "SELECT session_id, user_id, token_digest, created_at, last_used_at,
                            absolute_expires_at, revoked FROM sessions",
                ),
                "prepare dump",
            );
            let rows = ok(
                stmt.query_map([], |row| {
                    Ok(format!(
                        "{}|{}|{}|{}|{}|{}|{}",
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                    ))
                }),
                "query dump",
            );
            let mut values = Vec::new();
            for row in rows {
                values.push(ok(row, "read dump row"));
            }
            values
        };
        assert_eq!(stored_values.len(), 1);
        assert!(
            !stored_values[0].contains(plaintext),
            "plaintext token must never be stored"
        );
        assert!(stored_values[0].contains(&digest.to_string()));
        // 3) 摘要查找成功；错误摘要查找失败。
        {
            let repo = Repository::new(&mut conn, &store);
            let record = some(ok(repo.lookup_session(digest), "lookup"), "session record");
            assert_eq!(record.session_id, session);
            assert_eq!(record.user_id, user);
            assert!(!record.revoked);
            assert!(
                ok(
                    repo.lookup_session(ContentDigest::from_bytes(b"other")),
                    "lookup miss"
                )
                .is_none()
            );
        }
    }

    #[test]
    fn session_revoke_and_revoke_all() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let user = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_user(
                    "admin",
                    "argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2h2YWx1ZQ",
                    &audit("create user"),
                    &c,
                ),
                "create user",
            )
        };
        let future = |offset: u64| {
            Timestamp::from_unix_seconds(
                ok(Timestamp::now(), "now")
                    .as_unix_seconds()
                    .saturating_add(offset),
            )
        };
        let s1 = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_session(
                    user,
                    ContentDigest::from_bytes(b"token-1"),
                    future(3600),
                    &audit("session"),
                    &c,
                ),
                "session 1",
            )
        };
        let s2 = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_session(
                    user,
                    ContentDigest::from_bytes(b"token-2"),
                    future(3600),
                    &audit("session"),
                    &c,
                ),
                "session 2",
            )
        };
        // 吊销单个。
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(repo.revoke_session(s1, &audit("revoke"), &c), "revoke s1");
            let error = err(
                repo.revoke_session(s1, &audit("revoke again"), &c),
                "revoke s1 again",
            );
            assert!(matches!(error, StorageError::NotFound(_)));
        }
        // 吊销全部（§16.5 logout-all / 密码重置路径）。
        {
            let mut repo = Repository::new(&mut conn, &store);
            let count = ok(
                repo.revoke_all_user_sessions(user, &audit("revoke all"), &c),
                "revoke all",
            );
            assert_eq!(count, 1);
            assert!(
                ok(
                    repo.lookup_session(ContentDigest::from_bytes(b"token-1")),
                    "s1 gone"
                )
                .is_none()
            );
            assert!(
                ok(
                    repo.lookup_session(ContentDigest::from_bytes(b"token-2")),
                    "s2 gone"
                )
                .is_none()
            );
        }
        let _ = s2;
    }

    #[test]
    fn audit_append_and_ordering() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let mut repo = Repository::new(&mut conn, &store);
        let e1 = ok(repo.append_audit(&audit("first")), "append first");
        let e2 = ok(repo.append_audit(&audit("second")), "append second");
        assert!(e1 < e2, "append order must be monotonic");
        let events = ok(repo.list_audit_recent(10), "list audit");
        // 新→旧（倒序）。
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, "second");
        assert_eq!(events[1].action, "first");
        // 字段往返（actor/category/outcome typed parse，§13.3）。
        assert_eq!(events[1].actor, AuditActor::System);
        assert_eq!(
            events[1].category,
            crate::model::AuditCategory::ComponentLifecycle
        );
        assert_eq!(events[1].outcome, crate::model::AuditOutcome::Success);
        // 有界读取。
        let error = err(repo.list_audit_recent(1001), "over-limit read");
        assert!(matches!(error, StorageError::InvalidArgument(_)));
    }

    #[test]
    fn grants_lifecycle_bound_to_installation() {
        // §17.5：grant 的 durable owner 是 InstallationId。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let (cid, v1, d1) = stage_candidate(&mut conn, &store, "granted", "1.0.0", b"v1");
        let inst = activate(&mut conn, &store, cid, v1, d1);
        let cap = ok(
            CapabilityId::new("wasi:http/outgoing-handler"),
            "capability",
        );
        let scope = ok(
            CapabilityScope::new("https://prometheus.internal:9090"),
            "scope",
        );
        let c = cancel();
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.grant_capability(inst, cap.clone(), scope.clone(), &audit("grant"), &c),
                "grant",
            );
            let grants = ok(repo.list_grants(inst), "list grants");
            assert_eq!(grants.len(), 1);
            assert_eq!(grants[0].capability_id, cap);
            assert_eq!(grants[0].scope, scope);
            assert!(grants[0].revoked_at.is_none());
        }
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.revoke_capability(inst, cap.clone(), &audit("revoke"), &c),
                "revoke",
            );
            assert!(ok(repo.list_grants(inst), "empty grants").is_empty());
        }
        // 重新授权：撤销历史由 audit 覆盖（§18.7）。
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.grant_capability(inst, cap.clone(), scope.clone(), &audit("regrant"), &c),
                "re-grant",
            );
            let grants = ok(repo.list_grants(inst), "grants");
            assert_eq!(grants.len(), 1);
            assert!(grants[0].revoked_at.is_none());
        }
        // 撤销未授权能力 → NotFound。
        {
            let mut repo = Repository::new(&mut conn, &store);
            let other = ok(CapabilityId::new("wasi:fs/preopens"), "capability");
            let error = err(
                repo.revoke_capability(inst, other, &audit("revoke"), &c),
                "revoke un-granted",
            );
            assert!(matches!(error, StorageError::NotFound(_)));
        }
    }

    #[test]
    fn users_lifecycle_and_password_rotation() {
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let hash1 = "argon2id$v=19$m=19456,t=2,p=1$c2FsdDE$aGFzaDE";
        let hash2 = "argon2id$v=19$m=19456,t=2,p=1$c2FsdDI$aGFzaDI";
        let user = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.create_user("operator", hash1, &audit("create user"), &c),
                "create user",
            )
        };
        {
            let repo = Repository::new(&mut conn, &store);
            let record = some(
                ok(repo.get_user_by_username("operator"), "by username"),
                "user record",
            );
            assert_eq!(record.user_id, user);
            assert_eq!(record.password_hash, hash1);
            assert!(!record.disabled);
        }
        // 重名 → AlreadyExists。
        {
            let mut repo = Repository::new(&mut conn, &store);
            let error = err(
                repo.create_user("operator", hash1, &audit("dup"), &c),
                "duplicate username",
            );
            assert!(matches!(error, StorageError::AlreadyExists(_)));
        }
        // 轮换密码哈希（§16.3；audit 不含哈希值——只断言成功与存储）。
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.update_password_hash(user, hash2, &audit("rotate"), &c),
                "rotate hash",
            );
            let record = some(ok(repo.get_user(user), "by id"), "user record");
            assert_eq!(record.password_hash, hash2);
            // audit 事件 detail 不包含哈希。
            let events = ok(repo.list_audit_recent(100), "audit");
            let rotate = some(
                events.iter().find(|e| e.action == "rotate").cloned(),
                "rotate event",
            );
            let dump = format!("{:?}", rotate);
            assert!(!dump.contains(hash2));
        }
        // 停用。
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.set_user_disabled(user, true, &audit("disable"), &c),
                "disable user",
            );
            let record = some(ok(repo.get_user(user), "by id"), "user record");
            assert!(record.disabled);
        }
    }

    #[test]
    fn config_versioning_and_audit() {
        // §18.0：RuntimeConfig 事务化、版本化并审计。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.set_config("feature.x", "1", &audit("config set"), &c),
                "set config 1",
            );
            let entry = some(ok(repo.get_config("feature.x"), "get config"), "entry");
            assert_eq!(entry.value, "1");
            assert_eq!(entry.version, 1);
        }
        {
            let mut repo = Repository::new(&mut conn, &store);
            ok(
                repo.set_config("feature.x", "2", &audit("config set"), &c),
                "set config 2",
            );
            let entry = some(ok(repo.get_config("feature.x"), "get config"), "entry");
            assert_eq!(entry.value, "2");
            assert_eq!(entry.version, 2, "version must increment (§18.0)");
            let entries = ok(repo.list_config(), "list config");
            assert_eq!(entries.len(), 1);
        }
        // 非法键/值校验（validate-on-construct）。
        {
            let mut repo = Repository::new(&mut conn, &store);
            assert!(matches!(
                err(repo.set_config("", "x", &audit("bad"), &c), "empty key"),
                StorageError::InvalidArgument(_)
            ));
            assert!(matches!(
                err(repo.set_config("k", "", &audit("bad"), &c), "empty value"),
                StorageError::InvalidArgument(_)
            ));
        }
    }

    #[test]
    fn gc_cleans_quarantine_and_keeps_referenced() -> Result<(), StorageError> {
        // §18.7：quarantine 可清理；被引用的 digest 由外键保护。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        // 一个只进 quarantine 的字节流。
        let junk = {
            let mut repo = Repository::new(&mut conn, &store);
            let s = ok(
                repo.stage_bytes(b"junk", ok(ByteSize::mib(16), "limit")),
                "stage",
            );
            ok(repo.record_quarantine(&s, &audit("q"), &c), "quarantine");
            s.digest
        };
        // 一个完整 candidate（被 registry 引用）。
        let (_, _, d1) = stage_candidate(&mut conn, &store, "gc-keep", "1.0.0", b"keep-me");
        // 立即回收策略。
        let policy = GcPolicy {
            quarantine_max_age: Duration::ZERO,
        };
        let report = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(repo.gc(policy), "gc")
        };
        assert!(report.removed_rows >= 1);
        assert!(report.removed_files >= 1);
        {
            let repo = Repository::new(&mut conn, &store);
            assert!(repo.get_artifact(junk)?.is_none(), "junk must be GC'd");
            assert!(!store.file_exists(ArtifactSpace::Quarantine, junk)?);
            let keep = some_ok(repo.get_artifact(d1), "kept artifact");
            assert_eq!(keep.state, ArtifactState::Candidate);
            assert!(store.file_exists(ArtifactSpace::Final, d1)?);
        }
        Ok(())
    }

    #[test]
    fn budget_and_hard_limit_are_enforced() {
        // §18.7 预算硬上限 + §19.1 oversized input 提前拒绝。
        let dir = tempdir();
        let root = data_root(dir.path());
        ok(root.ensure_layout(), "layout");
        let mut conn = ok(open_authoritative_db(&root.db_path()), "open db");
        // quarantine 预算只有 10 字节。
        let store = ArtifactStore::new(
            root,
            DiskBudget::new(
                ByteSize::from_bytes(1024),
                ByteSize::from_bytes(10),
                ByteSize::from_bytes(1024),
            ),
        );
        let c = cancel();
        {
            let mut repo = Repository::new(&mut conn, &store);
            // 硬上限：写入前拒绝（§19.1）。
            let error = err(
                repo.stage_bytes(b"12345678901234567890", ByteSize::from_bytes(5)),
                "oversized",
            );
            assert!(
                matches!(error, StorageError::ArtifactTooLarge { .. }),
                "expected ArtifactTooLarge, got {error:?}"
            );
            // 预算：quarantine 10 字节 < 20 字节 → BudgetExceeded。
            let staged = ok(
                repo.stage_bytes(b"12345678901234567890", ok(ByteSize::mib(1), "limit")),
                "stage",
            );
            let error = err(
                repo.record_quarantine(&staged, &audit("q"), &c),
                "quarantine over budget",
            );
            assert!(
                matches!(
                    error,
                    StorageError::BudgetExceeded {
                        space: BudgetSpace::Quarantine,
                        ..
                    }
                ),
                "expected BudgetExceeded(Quarantine), got {error:?}"
            );
            // staging 文件仍在（瞬态，可重试/清理）。
            assert!(ok(store.staging_usage(), "staging usage").as_u64() == 20);
            let usage = ok(repo.budget_usage(), "budget usage");
            assert_eq!(usage.quarantine.as_u64(), 0);
        }
    }

    #[test]
    fn quarantine_record_without_file_is_recoverable_by_gc() -> Result<(), StorageError> {
        // §18.5 candidate 未提交 → 清理：quarantine 行无文件 → GC 删除行。
        let dir = tempdir();
        let (mut conn, store) = open_harness(dir.path());
        let c = cancel();
        let digest = {
            let mut repo = Repository::new(&mut conn, &store);
            let s = ok(
                repo.stage_bytes(b"ghost", ok(ByteSize::mib(16), "limit")),
                "stage",
            );
            ok(repo.record_quarantine(&s, &audit("q"), &c), "quarantine");
            s.digest
        };
        // 模拟文件丢失（外部干预）。
        assert!(ok(
            store.remove_file(ArtifactSpace::Quarantine, digest),
            "remove file"
        ));
        let policy = GcPolicy {
            quarantine_max_age: Duration::ZERO,
        };
        let report = {
            let mut repo = Repository::new(&mut conn, &store);
            ok(repo.gc(policy), "gc")
        };
        assert!(report.removed_rows >= 1);
        {
            let repo = Repository::new(&mut conn, &store);
            assert!(repo.get_artifact(digest)?.is_none());
        }
        Ok(())
    }
}
