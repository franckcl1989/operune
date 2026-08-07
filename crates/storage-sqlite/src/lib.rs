#![forbid(unsafe_code)]

//! Operune SQLite 持久化 adapter（规范 §24.2：storage-sqlite）。
//!
//! SQLite schema、migration、repository adapter、Storage Executor（§18）。
//! SQLite 与 Tokio 之间由项目专用、有界、typed Storage Executor 处理
//! （§22.4），本 crate 不引入通用 Actor Framework，也不反向成为 Core 状态的
//! 中央消息总线（§18.2）。
//!
//! # 依赖方向（§24.3）
//!
//! ```text
//! storage-sqlite ---> operune-domain
//! ```
//!
//! domain 是唯一逻辑依赖（类型契约，§13.3）；SQL 细节、rusqlite、SQLite
//! error code 与 schema 均不向调用方泄漏（§18.1）。
//!
//! # 模块地图
//!
//! - [`schema`]：0.1.0 Core schema DDL（§18.3 数据所有权）+ 打开校验；
//! - [`migration`]：版本化、事务化 migration（§18.4），0.x downgrade 明确
//!   拒绝（fail closed）；
//! - [`artifact`]：`data_root` 下 staging / quarantine / content-addressed
//!   空间、磁盘预算、GC/retention 与崩溃点协议（§18.7）；
//! - [`repository`]：typed repository adapter（§24.2），SQL 边界解析一次
//!   （§13.3），事务边界与安装/升级 crash consistency 协议（§18.5）；
//! - [`recovery`]：打开时确定性对账（§18.5 crash recovery 决策表）；
//! - [`executor`]：Storage Executor（§18.2）：专用线程 + 有界队列 +
//!   typed request/response + 提交前取消语义 + shutdown 等待；0.3.0
//!   state 事务（§41.2，migration v4）：跨命令边界、取消/crash → 回滚；
//! - [`ports`]：application port traits 的实现（§24.2：ComponentRegistry /
//!   GrantStore / Audit / Config / ProviderGraph），同步桥接到 executor 并做
//!   用例级类型与存储侧记录之间的转换（§13.3）；0.3.0 的
//!   StateStore / SecretStore / ComponentConfigStore port trait 由 application
//!   里程碑定义后接线（§41.2）。
//!
//! # 权威性边界（§18.1）
//!
//! 本 crate 是 0.1.0 单节点 Core 元数据的权威事实源，但 **SQLite 不是 Domain
//! 契约**：`operune-domain` 与未来的 `application` 只依赖本 crate 的 typed
//! storage ports（`StorageExecutor` 的 typed async 方法），不暴露 SQL /
//! `rusqlite::Connection` / SQLite error code / schema 细节。

#[cfg(test)]
pub(crate) mod testutil;

pub mod artifact;
pub mod error;
pub mod executor;
pub mod migration;
pub mod model;
pub mod ports;
mod recovery;
mod repository;
mod schema;

pub use artifact::{BudgetUsage, DataRoot, DiskBudget, GcPolicy, GcReport};
pub use error::{BudgetSpace, StorageError};
pub use executor::{ExecutorConfig, StorageExecutor};
pub use migration::{
    Migration, PRODUCTION_MIGRATIONS, current_schema_version, open_authoritative_db,
};
pub use model::{
    ActiveBinding, ArtifactRecord, ArtifactState, AuditActor, AuditCategory, AuditEvent,
    AuditOutcome, AuditRecord, CapabilityScope, ComponentConfigRecord, ConfigEntry, ConfigFormat,
    GrantRecord, InstallationRecord, InstallationVersionRecord, RollbackResult, SecretMetadata,
    SecretName, SecretRecord, SessionId, SessionRecord, StagedArtifact, StateKey,
    StateSchemaVersion, StateTransactionHandle, StateValueRecord, Timestamp, UpgradePhase,
    UpgradeTransactionId, UpgradeTransactionRecord, UserId, UserRecord, VersionState,
};
pub use ports::StoragePorts;
pub use recovery::RecoveryAction;
