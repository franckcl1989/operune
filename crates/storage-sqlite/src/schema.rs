//! Core schema（§18.3 0.1.0 数据所有权）。
//!
//! 所有表/列命名与 domain 类型语义一致（§13.3：adapter 层接触字符串/整数 wire
//! 表示，但立即 parse 成领域类型；本模块只定义 DDL，不解析）。
//!
//! # 唯一 active 语义（§18.5）
//!
//! "永远不存在两个版本都被误认为同一逻辑 Component 唯一 active"通过三重机制
//! 保证：
//!
//! 1. `active_version.installation_id` 是主键 → 每个安装实例**至多一行**
//!    active 绑定，由数据库强制；
//! 2. active 切换与 transaction marker 的 committed 阶段位于**同一个 SQLite
//!    事务**（见 `repository` 的 `switch_active_version` 协议）→ 不存在
//!    "marker 已 committed 但 active 未切换"或相反的中间观；
//! 3. 打开时 `recovery` 断言：`prepared` marker 存在时 active 必须仍指向
//!    `from` 版本，否则 CorruptState fail closed。
//!
//! # 引用完整性（GC 安全，§18.7）
//!
//! `artifacts(digest)` 被 `component_versions` / `installation_versions` /
//! `active_version` / `upgrade_transactions` 外键引用（`foreign_keys = ON`
//! 按连接强制）→ 仍被 active / candidate / rollback transaction / 历史引用
//! 的 digest 不可能被 GC 删除，SQLite 直接拒绝。

/// Migration v1：Core 0.1.0 完整 schema（§18.3 数据所有权清单）。
///
/// 注意：`schema_version` 表由 migration 框架自身创建（migration.rs 的
/// `apply_migrations_to`），不属于任何 migration——此处不重复创建。
pub(crate) const DDL_V1: &str = "
-- §18.7 / §19.2：digest 主键的 artifact 记录（字节事实）。
-- byte_size 用于磁盘预算核算（§18.7 硬上限）；state 是记录种类
-- （quarantine → candidate → installed），非 domain 生命周期状态。
CREATE TABLE artifacts (
    digest     TEXT PRIMARY KEY CHECK (length(digest) = 64),
    byte_size  INTEGER NOT NULL CHECK (byte_size >= 0),
    state      TEXT NOT NULL CHECK (state IN ('quarantine', 'candidate', 'installed')),
    created_at INTEGER NOT NULL
);

-- §6.7：逻辑产品身份（作者声明，descriptor 验证后成为注册表事实）。
CREATE TABLE components (
    component_id TEXT PRIMARY KEY CHECK (length(component_id) BETWEEN 1 AND 255)
);

-- §6.7 / §19.4：ComponentId + ComponentVersion 唯一绑定一个已接受 digest。
-- 主键即 UNIQUE(component_id, component_version)：收到同逻辑版本的不同 digest
-- 被数据库显式阻断（DigestConflict，§19.4），绝不静默覆盖。
CREATE TABLE component_versions (
    component_id      TEXT NOT NULL REFERENCES components(component_id),
    component_version TEXT NOT NULL,
    content_digest    TEXT NOT NULL REFERENCES artifacts(digest),
    accepted_at       INTEGER NOT NULL,
    PRIMARY KEY (component_id, component_version)
);

-- §18.3：InstallationId（Core 创建并持久化的安装实例身份，§19.4）。
-- enabled 是 enable/disable 事实（§39.2）；lifecycle_state 是领域生命周期
-- 状态机的持久化（闭集，CHECK 与 domain 枚举字符串一致，§12.2）。
-- 默认 enabled = 0（deny-by-default 精神，§17.2；由管理面显式启用）。
CREATE TABLE installations (
    installation_id TEXT PRIMARY KEY,
    component_id    TEXT NOT NULL REFERENCES components(component_id),
    enabled         INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN
        ('installed', 'validated', 'activating', 'active', 'draining', 'disabled', 'failed')),
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL
);

-- §18.3：安装实例 × 逻辑版本绑定（quarantine/candidate/install/rollback 记录）。
-- 外键到 component_versions：绑定必须先有注册表事实（§19.2 两阶段安装）。
CREATE TABLE installation_versions (
    installation_id   TEXT NOT NULL REFERENCES installations(installation_id),
    component_id      TEXT NOT NULL,
    component_version TEXT NOT NULL,
    content_digest    TEXT NOT NULL REFERENCES artifacts(digest),
    state             TEXT NOT NULL CHECK (state IN ('candidate', 'installed', 'rolled_back')),
    created_at        INTEGER NOT NULL,
    PRIMARY KEY (installation_id, component_id, component_version),
    FOREIGN KEY (component_id, component_version)
        REFERENCES component_versions(component_id, component_version)
);

-- §18.5：唯一 active 事实源。installation_id 主键 ⇒ 每安装至多一行。
-- 外键到 installation_versions：active 必须是已绑定版本。
CREATE TABLE active_version (
    installation_id   TEXT PRIMARY KEY REFERENCES installations(installation_id),
    component_id      TEXT NOT NULL,
    component_version TEXT NOT NULL,
    content_digest    TEXT NOT NULL REFERENCES artifacts(digest),
    FOREIGN KEY (installation_id, component_id, component_version)
        REFERENCES installation_versions(installation_id, component_id, component_version)
);

-- §18.3 / §18.5：upgrade/rollback 事务元数据 + lifecycle journal /
-- transaction marker。phase ∈ {prepared, committed, rolled_back}。
-- CHECK 保证 from 两列同时存在或同时缺失（初次安装 from = NULL）。
CREATE TABLE upgrade_transactions (
    transaction_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    installation_id       TEXT NOT NULL REFERENCES installations(installation_id),
    from_component_version TEXT,
    from_content_digest    TEXT,
    to_component_version  TEXT NOT NULL,
    to_content_digest     TEXT NOT NULL REFERENCES artifacts(digest),
    phase                 TEXT NOT NULL CHECK (phase IN ('prepared', 'committed', 'rolled_back')),
    created_at            INTEGER NOT NULL,
    completed_at          INTEGER,
    CHECK ((from_component_version IS NULL) = (from_content_digest IS NULL))
);
CREATE INDEX idx_upgrade_transactions_installation ON upgrade_transactions(installation_id);

-- §17.5：grant 的 durable owner 是 InstallationId（不得绑定 ComponentId，§17.1）。
-- 每个 (installation_id, capability_id) 一行：state granted/revoked，
-- 重新授权 = 重置 granted（撤销历史由 audit 覆盖，§18.7）。
CREATE TABLE grants (
    installation_id TEXT NOT NULL REFERENCES installations(installation_id),
    capability_id   TEXT NOT NULL CHECK (length(capability_id) BETWEEN 1 AND 255),
    scope           TEXT NOT NULL CHECK (length(scope) BETWEEN 1 AND 4096),
    state           TEXT NOT NULL CHECK (state IN ('granted', 'revoked')),
    granted_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    PRIMARY KEY (installation_id, capability_id)
);

-- §16.4 / §18.3：users/password hashes。password_hash 只存 Argon2id PHC 哈希
-- 字符串（绝不存明文；存储层视其为不透明值，哈希生成/验证属于 security）。
CREATE TABLE users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE CHECK (length(username) BETWEEN 1 AND 255),
    password_hash TEXT NOT NULL CHECK (length(password_hash) BETWEEN 1 AND 1024),
    disabled      INTEGER NOT NULL CHECK (disabled IN (0, 1)),
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

-- §16.5 / §18.3：sessions。权威存储只保存 token 的单向 SHA-256 摘要
-- （token_digest = 64 hex），**明文 bearer token 绝不落库**；此表没有也不会有
-- 任何可容纳明文 token 的列。
CREATE TABLE sessions (
    session_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL REFERENCES users(user_id),
    token_digest       TEXT NOT NULL UNIQUE CHECK (length(token_digest) = 64),
    created_at         INTEGER NOT NULL,
    last_used_at       INTEGER NOT NULL,
    absolute_expires_at INTEGER NOT NULL,
    revoked            INTEGER NOT NULL CHECK (revoked IN (0, 1))
);

-- §18.7：audit metadata（append-only）。未到期/未满足 retention policy 的安全
-- 审计记录不得因磁盘压力被静默删除；audit 写入与变更同事务（fail closed）。
CREATE TABLE audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL,
    actor       TEXT NOT NULL CHECK (length(actor) BETWEEN 1 AND 300),
    category    TEXT NOT NULL CHECK (category IN
        ('auth', 'session', 'user', 'component-lifecycle', 'grant', 'config', 'recovery', 'artifact')),
    action      TEXT NOT NULL CHECK (length(action) BETWEEN 1 AND 255),
    target      TEXT,
    outcome     TEXT NOT NULL CHECK (outcome IN ('success', 'failure')),
    detail      TEXT
);
CREATE INDEX idx_audit_occurred_at ON audit_events(occurred_at);

-- §18.0 / §18.3：RuntimeConfig（事务化、版本化并审计；BootstrapConfig 不进本表）。
CREATE TABLE runtime_config (
    key        TEXT PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 255),
    value      TEXT NOT NULL CHECK (length(value) <= 1048576),
    version    INTEGER NOT NULL CHECK (version >= 1),
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);
";

/// Migration v3：0.2.0 provider graph records（§40.2 graph
/// persistence/recovery；§18.6：0.2 graph 是**节点本地权威**状态——本表与
/// 其余 Core 元数据同属单节点权威事实源，不涉及 cluster 一致性）。
///
/// 表设计（记录 = 安装实例 + 角色 的不可变字节事实，§40.2/§40.3）：
///
/// - **`graph_provider_records`** / **`graph_consumer_records`** 两张表，
///   `installation_id` 为主键（§17.5：graph 记录锚定安装实例；每安装
///   实例至多一条 provider 记录、一条 consumer 记录——同一安装可同时
///   是 provider 与 consumer，依赖链中间节点，§40.3）；
/// - 记录标识 = `installation_id` + 表角色（provider/consumer），不另设
///   序号：port 的 `replace_records` 是"某安装的全部记录"单次原子替换
///   边界，记录本身没有独立于安装的身份；
/// - `provided` / `required` = interface 集合的 **JSON 规范化数组**（每条
///   目为 domain 类型的规范字符串形态，见 schema 模块 doc 的序列化选择）：
///   - `provided`：`["namespace:package/interface@x.y.z", ...]`
///     （[`InterfaceId`](operune_domain::InterfaceId) 的 Display 规范形态）；
///   - `required`：`["namespace:package/interface@<version-req>", ...]`
///     （[`InterfaceRequirement`](operune_domain::InterfaceRequirement) 的
///     Display 规范形态，`VersionReq` 已规范化，如 `1.2.3` → `^1.2.3`）；
///   - 解析失败 / provider 空集 = 持久化损坏，读取时
///     `crate::StorageError::CorruptState` fail closed（repository.rs）；
/// - 外键到 `installations(installation_id)`：graph 记录锚定安装实例
///   （与 `grants` 同约束），对不存在的安装拒绝写入；
/// - 0.x 无历史数据：v2 → v3 时本表为空即可，无需回填（migration.rs）。
pub(crate) const DDL_V3: &str = "
-- §40.2 / §40.3：provider 记录（提供面 = WIT exports + Runtime Policy
-- 过滤后的输入形态；每安装实例至多一行，PK 即记录标识）。
CREATE TABLE graph_provider_records (
    installation_id TEXT PRIMARY KEY REFERENCES installations(installation_id),
    provided        TEXT NOT NULL CHECK (length(provided) BETWEEN 1 AND 65536),
    updated_at      INTEGER NOT NULL
);

-- §40.2 / §40.3：consumer 记录（需求面 = WIT imports；每安装实例至多一行）。
CREATE TABLE graph_consumer_records (
    installation_id TEXT PRIMARY KEY REFERENCES installations(installation_id),
    required        TEXT NOT NULL CHECK (length(required) BETWEEN 1 AND 65536),
    updated_at      INTEGER NOT NULL
);
";

/// 打开后校验 Core 必备表存在（fail closed，§18.4：不得以半升级 schema 继续）。
/// 在 migration 成功之后调用；缺失即持久化状态损坏。
pub(crate) fn verify_core_tables(conn: &rusqlite::Connection) -> Result<(), crate::StorageError> {
    use rusqlite::OptionalExtension;
    for table in [
        "schema_version",
        "artifacts",
        "components",
        "component_versions",
        "installations",
        "installation_versions",
        "active_version",
        "upgrade_transactions",
        "grants",
        "users",
        "sessions",
        "audit_events",
        "runtime_config",
        "graph_provider_records",
        "graph_consumer_records",
    ] {
        let found: Option<String> = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [table],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| crate::StorageError::sqlite("verify core tables", e))?;
        if found.is_none() {
            return Err(crate::StorageError::CorruptState(format!(
                "core table {table:?} is missing after migration; refusing to run on a \
                 half-migrated schema"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::open_authoritative_db;
    use crate::testutil::{err, ok, tempdir};

    #[test]
    fn schema_version_reachable_and_core_tables_present() {
        let dir = tempdir();
        let conn = ok(
            open_authoritative_db(&dir.path().join("core.db")),
            "open db",
        );
        ok(verify_core_tables(&conn), "verify core tables");

        let version: i64 = ok(
            conn.query_row("SELECT version FROM schema_version WHERE id = 1", [], |r| {
                r.get(0)
            }),
            "read schema version",
        );
        assert_eq!(
            version,
            i64::from(crate::migration::current_schema_version())
        );
    }

    #[test]
    fn dropping_a_core_table_fails_closed_on_reopen() {
        let dir = tempdir();
        let db_path = dir.path().join("core.db");
        {
            let conn = ok(open_authoritative_db(&db_path), "open db");
            ok(
                conn.execute_batch("DROP TABLE artifacts;"),
                "drop artifacts",
            );
        }
        let error = err(open_authoritative_db(&db_path), "reopen");
        assert!(
            matches!(
                error,
                crate::StorageError::CorruptState(_) | crate::StorageError::MigrationFailed { .. }
            ),
            "expected fail closed, got {error:?}"
        );
    }
}
