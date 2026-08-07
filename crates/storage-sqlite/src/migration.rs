//! Schema migration（§18.4）。
//!
//! # 契约
//!
//! - **版本化**：`schema_version` 表（单行 `id = 1`）记录当前版本；本构建支持
//!   的版本集合由 [`PRODUCTION_MIGRATIONS`] 定义，`current_schema_version()`
//!   返回最新版本；
//! - **事务化**：每个 migration 在一个 SQLite 事务内执行，版本号在同一事务内
//!   推进（SQLite DDL 是事务性的）→ 任一 migration 失败，事务整体回滚，
//!   schema 停留在上一个版本，**Core 绝不半升级继续**（fail closed：
//!   [`open_authoritative_db`] 直接返回 [`StorageError::MigrationFailed`]）；
//! - **打开时校验**：版本高于本构建 → [`StorageError::SchemaTooNew`]
//!   （0.x downgrade 明确拒绝，fail closed）；版本为 0（空库）→ 前向迁移；
//!   版本低于最低可直接升级来源版本（0.1.0 release 契约：最低来源 = 0）→
//!   [`StorageError::SchemaTooOld`]；
//! - **0.x downgrade 语义**（0.1.0 release contract）：**forward-only**。
//!   不提供降级 migration；打开更高版本数据库立即失败，绝不尝试读取/改写
//!   未知 schema。1.0 前长期 compatibility policy 由逐版本 release contract
//!   明确（§18.4）。
//! - **测试模式**：`apply_migrations_to(conn, set, upto)` 可以把数据库停在任意
//!   旧版本（构造 old-version → new-version migration test，§18.4），并验证
//!   前进路径保留数据、失败路径整体回滚。
//!
//! # 打开流程（worker 启动时执行，§18.2 不在 Tokio core worker 上）
//!
//! ```text
//! open_authoritative_db(path)
//!   -> 创建父目录
//!   -> 打开连接 + PRAGMA（foreign_keys ON / journal_mode WAL / synchronous FULL）
//!   -> apply_migrations_to(conn, PRODUCTION_MIGRATIONS, None)
//!   -> verify_core_tables（fail closed）
//!   -> recovery（见 recovery.rs，由 executor 在迁移后执行）
//! ```

use std::path::Path;

use rusqlite::Connection;

use crate::error::StorageError;
use crate::model::Timestamp;
use crate::schema::{DDL_V1, verify_core_tables};

/// 单个版本化 migration。`apply` 在 runner 开启的事务内执行；
/// 版本号由 runner 在同一事务内推进。
pub struct Migration {
    /// 目标版本号（严格递增）。
    pub version: u32,
    /// 名称（release 契约 / 诊断）。
    pub name: &'static str,
    /// 迁移逻辑（DDL + 数据回填）。
    apply: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
}

impl Migration {
    /// 构造 migration（版本必须严格递增，由 runner 校验）。
    pub const fn new(
        version: u32,
        name: &'static str,
        apply: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError>,
    ) -> Self {
        Self {
            version,
            name,
            apply,
        }
    }
}

/// 0.1.0 production migration 集合（§18.4 release contract 的版本事实源）。
///
/// 0.1.0 最低可直接升级来源版本 = 0（空库 / 全新初始化）。
pub const PRODUCTION_MIGRATIONS: &[Migration] = &[
    Migration::new(1, "core-schema-v1", apply_v1),
    Migration::new(2, "candidate-lifecycle-v2", apply_v2),
];

/// 本构建支持的当前 schema 版本（= 最后一个 production migration 版本）。
pub fn current_schema_version() -> u32 {
    last_version(PRODUCTION_MIGRATIONS)
}

fn last_version(set: &[Migration]) -> u32 {
    set.last().map(|m| m.version).unwrap_or(0)
}

/// 打开并迁移权威数据库（fail closed）。
///
/// - 创建 `path` 的父目录；
/// - 打开连接并配置 PRAGMA（§18.1 使用 bundled SQLite）；
/// - 应用 production migrations；
/// - 校验 Core 必备表存在（§18.4：不得以半升级 schema 继续）。
pub fn open_authoritative_db(path: &Path) -> Result<Connection, StorageError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| StorageError::io("create data root", e))?;
    }
    let mut conn = Connection::open(path).map_err(|e| StorageError::sqlite("open database", e))?;
    configure_connection(&conn)?;
    apply_migrations_to(&mut conn, PRODUCTION_MIGRATIONS, None)?;
    verify_core_tables(&conn)?;
    Ok(conn)
}

/// 配置连接级 PRAGMA。
///
/// - `foreign_keys = ON`：digest 引用完整性（GC 安全，§18.7）；
/// - `journal_mode = WAL` + `synchronous = FULL`：已提交事务崩溃后仍然存在
///   （§18.5 数据库提交语义）；
/// - `busy_timeout`：防御性（本 executor 单连接串行，无争用）。
fn configure_connection(conn: &Connection) -> Result<(), StorageError> {
    conn.execute_batch(
        "PRAGMA foreign_keys = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;",
    )
    .map_err(|e| StorageError::sqlite("configure pragmas", e))?;
    let mode: String = conn
        .query_row("PRAGMA journal_mode;", [], |row| row.get(0))
        .map_err(|e| StorageError::sqlite("verify journal mode", e))?;
    if mode != "wal" {
        return Err(StorageError::CorruptState(format!(
            "WAL journal mode was not established (got {mode:?})"
        )));
    }
    let _ = conn.busy_timeout(std::time::Duration::from_secs(5));
    Ok(())
}

/// 读取当前 schema 版本（`schema_version` 表缺失 → 0，即全新数据库）。
fn read_schema_version(conn: &Connection) -> Result<u32, StorageError> {
    let version: Option<i64> = conn
        .query_row(
            "SELECT version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|e| StorageError::sqlite("read schema version", e))?;
    match version {
        Some(v) => u32::try_from(v)
            .map_err(|_| StorageError::CorruptState(format!("schema version {v} out of range"))),
        None => Ok(0),
    }
}

/// 应用 migration（§18.4 事务化前进路径；`upto = None` 表示全部）。
///
/// 测试模式：`upto = Some(n)` 把数据库停在版本 n（构造旧版本数据库），随后用
/// `upto = None`（或更大的 `upto`）执行 old-version → new-version 前进路径。
pub(crate) fn apply_migrations_to(
    conn: &mut Connection,
    migrations: &[Migration],
    upto: Option<u32>,
) -> Result<u32, StorageError> {
    if migrations.is_empty() {
        return Err(StorageError::InvalidArgument(
            "migration set must not be empty".into(),
        ));
    }
    // 版本表属于 migration 框架自身（不绑定任何 release）。
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
             id         INTEGER PRIMARY KEY CHECK (id = 1),
             version    INTEGER NOT NULL,
             applied_at INTEGER NOT NULL
         );
         INSERT INTO schema_version (id, version, applied_at)
             SELECT 1, 0, 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version WHERE id = 1);",
    )
    .map_err(|e| StorageError::sqlite("ensure schema_version table", e))?;

    let current = read_schema_version(conn)?;
    let last = last_version(migrations);
    if current > last {
        return Err(StorageError::SchemaTooNew {
            db: current,
            current: last,
        });
    }
    let minimum = migrations.first().map(|m| m.version).unwrap_or(0);
    if current > 0 && current < minimum {
        return Err(StorageError::SchemaTooOld {
            db: current,
            minimum,
        });
    }

    let limit = upto.unwrap_or(last);
    for migration in migrations
        .iter()
        .filter(|m| m.version > current && m.version <= limit)
    {
        let now = Timestamp::now()?.sql_value()?;
        let tx = conn
            .transaction()
            .map_err(|e| StorageError::sqlite("begin migration transaction", e))?;
        (migration.apply)(&tx).map_err(|e| StorageError::MigrationFailed {
            version: migration.version,
            name: migration.name,
            message: e.to_string(),
        })?;
        tx.execute(
            "UPDATE schema_version SET version = ?1, applied_at = ?2 WHERE id = 1",
            rusqlite::params![i64::from(migration.version), now],
        )
        .map_err(|e| StorageError::MigrationFailed {
            version: migration.version,
            name: migration.name,
            message: format!("failed to advance schema version: {e}"),
        })?;
        tx.commit().map_err(|e| StorageError::MigrationFailed {
            version: migration.version,
            name: migration.name,
            message: format!("migration commit failed (transaction rolled back): {e}"),
        })?;
    }
    Ok(last.min(limit))
}

/// Migration v1：Core 0.1.0 全量 schema（§18.3，DDL 见 schema.rs）。
fn apply_v1(tx: &rusqlite::Transaction<'_>) -> Result<(), StorageError> {
    tx.execute_batch(DDL_V1)
        .map_err(|e| StorageError::sqlite("apply core schema v1", e))
}

/// Migration v2：`artifacts` 表增加 digest 主键的领域生命周期状态列
///（§12.2 / §19.2 的 candidate 生命周期；§18.3 至少持久化
/// quarantine/candidate/install/enable/active state）。
///
/// 背景：v1 的 `artifacts.state`（quarantine/candidate/installed）是存储侧
/// 记录种类（model.rs 文档明确"非 domain 生命周期状态"），只有 3 个取值，
/// 无法表达 application 的 `ComponentRegistryPort` 所需的 domain 状态机
/// 全状态（`installed`/`validated`/`activating`/`active`/`draining`/
/// `disabled`/`failed`）。v2 新增 `lifecycle_state` 列承载该状态：
/// - 新增行默认 `installed`（CHECK 约束对新写入生效）；
/// - 既有行按 `artifacts.state` 回填：quarantine → installed（字节已接收、
///   未验证），candidate → validated（已绑定、等待激活），installed →
///   active（已被某安装 active 引用）。
///
/// SQLite 的 `ALTER TABLE ADD COLUMN` 允许 CHECK 约束（对新写入生效）；
/// 本 migration 在单个事务内执行（§18.4：失败整体回滚）。
fn apply_v2(tx: &rusqlite::Transaction<'_>) -> Result<(), StorageError> {
    tx.execute_batch(
        "ALTER TABLE artifacts ADD COLUMN lifecycle_state TEXT NOT NULL DEFAULT 'installed'
             CHECK (lifecycle_state IN
                 ('installed', 'validated', 'activating', 'active', 'draining', 'disabled', 'failed'));
         UPDATE artifacts SET lifecycle_state =
             CASE state
                 WHEN 'quarantine' THEN 'installed'
                 WHEN 'candidate' THEN 'validated'
                 ELSE 'active'
             END;",
    )
    .map_err(|e| StorageError::sqlite("apply candidate lifecycle v2", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{err, ok, tempdir};
    use rusqlite::OptionalExtension;

    fn db_path(dir: &std::path::Path) -> std::path::PathBuf {
        dir.join("core.db")
    }

    #[test]
    fn fresh_db_migrates_to_current() {
        let dir = tempdir();
        let conn = ok(open_authoritative_db(&db_path(dir.path())), "open");
        assert_eq!(
            ok(read_schema_version(&conn), "version"),
            current_schema_version()
        );
        assert_eq!(current_schema_version(), 2);
    }

    #[test]
    fn reopen_is_idempotent() {
        let dir = tempdir();
        let path = db_path(dir.path());
        drop(ok(open_authoritative_db(&path), "first open"));
        let conn = ok(open_authoritative_db(&path), "second open");
        assert_eq!(
            ok(read_schema_version(&conn), "version"),
            current_schema_version()
        );
    }

    #[test]
    fn schema_too_new_fails_closed() {
        // 0.x downgrade 拒绝（§18.4）：更高版本的数据库打开即失败。
        let dir = tempdir();
        let path = db_path(dir.path());
        {
            let conn = ok(open_authoritative_db(&path), "open");
            ok(
                conn.execute("UPDATE schema_version SET version = 99 WHERE id = 1", []),
                "bump version",
            );
        }
        let error = err(open_authoritative_db(&path), "reopen newer db");
        assert!(
            matches!(error, StorageError::SchemaTooNew { db: 99, current: 2 }),
            "expected SchemaTooNew, got {error:?}"
        );
    }

    #[test]
    fn missing_schema_version_table_treated_as_fresh() {
        // 全新库（无版本表）→ 视为版本 0 → 全量迁移。
        let dir = tempdir();
        let conn = ok(
            Connection::open(db_path(dir.path())),
            "open raw connection (test setup)",
        );
        drop(conn);
        let conn = ok(open_authoritative_db(&db_path(dir.path())), "open");
        assert_eq!(
            ok(read_schema_version(&conn), "version"),
            current_schema_version()
        );
    }

    #[test]
    fn migration_failure_rolls_back_entirely() {
        // §18.4：migration 失败 → 该事务整体回滚，schema 停留在上一个版本。
        let dir = tempdir();
        let mut conn = ok(
            Connection::open(db_path(dir.path())),
            "open raw connection (test setup)",
        );
        ok(configure_connection(&conn), "configure");

        const M1: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError> = |tx| {
            tx.execute_batch("CREATE TABLE t1 (id INTEGER PRIMARY KEY);")
                .map_err(|e| StorageError::sqlite("create t1", e))
        };
        const M2: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError> = |tx| {
            tx.execute_batch("CREATE TABLE t2 (id INTEGER PRIMARY KEY);")
                .map_err(|e| StorageError::sqlite("create t2", e))?;
            // 模拟失败：migration 中途失败（t2 已建，随后报错）。
            Err(StorageError::InvalidArgument(
                "injected migration failure".into(),
            ))
        };
        let set = [
            Migration::new(1, "m1", M1),
            Migration::new(2, "m2-fails", M2),
        ];

        let error = err(
            apply_migrations_to(&mut conn, &set, None),
            "apply with failure",
        );
        assert!(
            matches!(
                error,
                StorageError::MigrationFailed {
                    version: 2,
                    name: "m2-fails",
                    ..
                }
            ),
            "expected MigrationFailed, got {error:?}"
        );
        assert_eq!(ok(read_schema_version(&conn), "version"), 1);
        // t2 必须不存在（事务整体回滚），t1 存在。
        let t2: Option<String> = ok(
            conn.query_row(
                "SELECT name FROM sqlite_master WHERE name = 't2'",
                [],
                |r| r.get(0),
            )
            .optional(),
            "t2 lookup",
        );
        assert!(t2.is_none(), "t2 must not survive the failed migration");
        let t1: Option<String> = ok(
            conn.query_row(
                "SELECT name FROM sqlite_master WHERE name = 't1'",
                [],
                |r| r.get(0),
            )
            .optional(),
            "t1 lookup",
        );
        assert_eq!(t1.as_deref(), Some("t1"));
    }

    #[test]
    fn forward_migration_preserves_data_old_to_new() {
        // §18.4 release contract 的 migration test：old-version → new-version
        // 前进路径 + 数据保留。
        let dir = tempdir();
        let mut conn = ok(
            Connection::open(db_path(dir.path())),
            "open raw connection (test setup)",
        );
        ok(configure_connection(&conn), "configure");

        const M1: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError> = |tx| {
            tx.execute_batch("CREATE TABLE widgets (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")
                .map_err(|e| StorageError::sqlite("create widgets", e))
        };
        const M2: fn(&rusqlite::Transaction<'_>) -> Result<(), StorageError> = |tx| {
            tx.execute_batch(
                "CREATE TABLE gadgets (
                     id INTEGER PRIMARY KEY,
                     widget_id INTEGER NOT NULL,
                     kind TEXT NOT NULL
                 );
                 INSERT INTO gadgets (widget_id, kind)
                     SELECT id, 'widget-derived' FROM widgets;",
            )
            .map_err(|e| StorageError::sqlite("create gadgets", e))
        };
        let set = [
            Migration::new(1, "v1-widgets", M1),
            Migration::new(2, "v2-gadgets", M2),
        ];

        // old-version 数据库：只应用 v1，并写入数据。
        ok(apply_migrations_to(&mut conn, &set, Some(1)), "init at v1");
        assert_eq!(ok(read_schema_version(&conn), "version"), 1);
        ok(
            conn.execute_batch("INSERT INTO widgets (id, name) VALUES (1, 'alpha'), (2, 'beta');"),
            "seed widgets",
        );

        // 前进路径：v1 → v2。
        ok(apply_migrations_to(&mut conn, &set, None), "migrate to v2");
        assert_eq!(ok(read_schema_version(&conn), "version"), 2);
        // 数据保留 + 回填正确。
        let backfilled: Vec<(i64, String)> = ok(
            conn.prepare("SELECT widget_id, kind FROM gadgets ORDER BY widget_id")
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                        .and_then(|rows| rows.collect())
                }),
            "read gadgets",
        );
        assert_eq!(
            backfilled,
            vec![
                (1, "widget-derived".to_string()),
                (2, "widget-derived".to_string())
            ]
        );
    }

    #[test]
    fn migration_set_must_be_sorted_and_ordered() {
        // 防御性断言：production set 版本严格递增且从 1 开始。
        let mut prev = 0u32;
        for m in PRODUCTION_MIGRATIONS {
            assert!(m.version > prev, "migrations must be strictly increasing");
            prev = m.version;
        }
        assert_eq!(prev, current_schema_version());
    }
}
