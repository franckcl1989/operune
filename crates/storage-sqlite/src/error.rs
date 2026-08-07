//! 存储层封闭 typed error（§14.1：`thiserror` 定义封闭、可匹配的 typed error；
//! 禁止 anyhow / eyre / `Box<dyn Error>` / String 作为公开错误契约，§22.9）。
//!
//! 第三方错误（rusqlite / std::io）在适配边界转换为项目错误语义，并保存可诊断
//! source/context（§14.1），但绝不把第三方错误类型作为公共契约泄漏。
//! 错误信息只含可诊断信息，不含任何机密（§16.6：password hash / bearer token
//! 明文绝不进入错误与日志）。

use std::fmt;

use thiserror::Error;

use operune_domain::{ComponentId, ComponentVersion, ContentDigest, DomainError, InstallationId};

use crate::model::StateSchemaVersion;

/// 存储空间类别（§18.7 磁盘预算：staging / quarantine / final content-addressed）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSpace {
    /// `data_root/staging`：上传暂存（瞬态，打开时清空，绝不权威）。
    Staging,
    /// `data_root/quarantine`：字节已接收、未验证（§19.2 字节事实阶段）。
    Quarantine,
    /// `data_root/artifacts`：final content-addressed 空间（不可变，§18.7）。
    Final,
}

impl fmt::Display for BudgetSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Staging => "staging",
            Self::Quarantine => "quarantine",
            Self::Final => "final",
        };
        f.write_str(s)
    }
}

/// storage-sqlite 的封闭错误空间。
///
/// 所有存储操作的失败都落在本枚举中，调用方可以穷尽匹配。
/// 不变量：任何变体都不携带机密值（密码、bearer token、hash 本身）。
#[derive(Debug, Error)]
pub enum StorageError {
    /// 参数非法（validate-on-construct / 调用方契约违反）。
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// 引用对象不存在。
    #[error("not found: {0}")]
    NotFound(String),

    /// 唯一性冲突（用户重名、会话 digest 重复等）。
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// §19.4 / §18.3 供应链冲突：同一 `ComponentId + ComponentVersion` 已绑定
    /// 一个已接受 digest，收到不同 digest 必须显式阻断，绝不静默覆盖。
    #[error(
        "digest conflict: {component} {version} is bound to digest {existing}, refusing to bind {incoming}"
    )]
    DigestConflict {
        /// 逻辑产品/应用身份。
        component: ComponentId,
        /// 作者声明的发布版本。
        version: ComponentVersion,
        /// 注册表已绑定的 digest。
        existing: ContentDigest,
        /// 被拒绝的新 digest。
        incoming: ContentDigest,
    },

    /// 生命周期/状态机冲突（§12.2：非法转换显式拒绝，不静默忽略）。
    #[error("lifecycle conflict: {0}")]
    LifecycleConflict(String),

    /// §41.2/§41.3 state schema 版本冲突：请求的 schema 版本与 store 当前
    /// 版本不符（WIT `unsupported-schema-version`；migration 前阻止混合
    /// 版本写入的契约边界；空 store 不产生本错误——首次写入建立版本）。
    #[error(
        "state schema version mismatch: installation {installation} is at version {expected}, \
         requested {requested}"
    )]
    SchemaVersionMismatch {
        /// 安装实例。
        installation: InstallationId,
        /// store 当前持久化版本。
        expected: StateSchemaVersion,
        /// 请求的版本。
        requested: StateSchemaVersion,
    },

    /// §41.2 state 事务冲突（WIT `conflict`：并发修改冲突，或对已终止事务
    /// 继续操作；单连接 executor 的进行中事务窗口排他，§18.2）。
    #[error("state transaction conflict: {0}")]
    StateTransactionConflict(String),

    /// 有界请求队列已满（§15.2 / §18.2：请求 channel 必须有界）。
    #[error("storage request queue is full; retry later")]
    QueueFull,

    /// 存储 executor 已关闭（shutdown 已接纳 / 已结束）。
    #[error("storage executor is shutting down")]
    Shutdown,

    /// 请求在事务提交前被取消；本请求没有任何事务提交（§18.2 取消语义）。
    #[error("request was cancelled before commit; no transaction was committed")]
    Cancelled,

    /// 数据库 schema 版本高于本构建支持版本：降级被明确拒绝（§18.4 0.x
    /// downgrade 语义：fail closed，不尝试降级打开）。
    #[error(
        "database schema version {db} is newer than this build supports ({current}); 0.x downgrade is refused"
    )]
    SchemaTooNew {
        /// 数据库中的 schema 版本。
        db: u32,
        /// 本构建支持的当前版本。
        current: u32,
    },

    /// 数据库 schema 版本低于本 release 的最低可直接升级来源版本（§18.4）。
    #[error(
        "database schema version {db} is older than the minimum upgradeable source version ({minimum})"
    )]
    SchemaTooOld {
        /// 数据库中的 schema 版本。
        db: u32,
        /// 本 release 的最低可直接升级来源版本。
        minimum: u32,
    },

    /// Migration 失败：该 migration 的事务整体回滚，Core 不以半升级 schema
    /// 继续（§18.4：migration 必须事务化；失败时 fail closed）。
    #[error("schema migration failed at version {version} ({name}): {message}")]
    MigrationFailed {
        /// 失败的 migration 版本号。
        version: u32,
        /// 失败的 migration 名称。
        name: &'static str,
        /// 可诊断失败原因。
        message: String,
    },

    /// 持久化状态损坏（对账失败 / 读取到非法值 / 必须 fail closed 的歧义状态，
    /// §18.5：永远不存在两个版本都被误认为唯一 active）。
    #[error("persistent state is corrupt: {0}")]
    CorruptState(String),

    /// 单个制品超过硬大小上限（§19.1：oversized input 在写入前被拒绝）。
    #[error("artifact of {size:?} bytes exceeds the hard limit of {limit:?} bytes")]
    ArtifactTooLarge {
        /// 提交的字节数。
        size: operune_domain::ByteSize,
        /// 硬上限。
        limit: operune_domain::ByteSize,
    },

    /// 磁盘预算超限（§18.7：staging/quarantine/final 都有硬上限，禁止无限吃满磁盘）。
    #[error("artifact disk budget exceeded for {space}: {message}")]
    BudgetExceeded {
        /// 超限的存储空间。
        space: BudgetSpace,
        /// 可诊断原因。
        message: String,
    },

    /// 文件系统 I/O 失败（保留 source 供诊断，不泄漏机密）。
    #[error("io error: {message}")]
    Io {
        /// 可诊断上下文。
        message: String,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },

    /// SQLite 失败（保留 source 供诊断；SQLite error code 不进入公开契约，§18.1）。
    #[error("sqlite error: {message}")]
    Sqlite {
        /// 可诊断上下文。
        message: String,
        /// 底层 SQLite 错误。
        #[source]
        source: rusqlite::Error,
    },

    /// worker 线程 join 失败（panic 逃逸，§15.3 禁止 detached critical task）。
    #[error("storage worker thread failed: {0}")]
    WorkerJoin(#[source] tokio::task::JoinError),

    /// 领域层错误透传（domain 是项目第一方契约，§14.1 允许）。
    #[error(transparent)]
    Domain(#[from] DomainError),
}

impl StorageError {
    /// 包装 rusqlite 错误（适配层转换，§14.1）。
    pub(crate) fn sqlite(message: &str, source: rusqlite::Error) -> Self {
        Self::Sqlite {
            message: message.to_string(),
            source,
        }
    }

    /// 包装 IO 错误。
    pub(crate) fn io(message: &str, source: std::io::Error) -> Self {
        Self::Io {
            message: message.to_string(),
            source,
        }
    }
}
