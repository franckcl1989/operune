//! 0.3.0 Stateful Runtime（§41.2）——StateStore port（application 定义，
//! storage-sqlite 接线实现）。
//!
//! 语义（契约面 `operune:state@0.1.0` state.wit，已提交稳定；§41.2
//! transaction/atomic update semantics）：
//!
//! - State 是 Component 产生的权威持久业务状态（§41.2 三分离）；本 port
//!   只承载存储面（get/put/delete/事务/schema 版本），**值内容平台不解释**
//!   （P6），CAS get→compare→put 编排在 [`crate::state::StateService`]
//!   （executor 单连接串行 ⇒ 服务侧读-判-写天然无交错，无需存储层条件写
//!   原语）；
//! - 事务跨命令边界（§41.2 MUST all-or-nothing）：begin 携带请求版本，
//!   提交在**同一事务**内推进 store schema marker（§41.3：升级/crash/
//!   取消/磁盘失败均不得产生"代码版本已切换但状态 schema 不确定"）；
//! - `begin_migration_transaction` 是显式 state migration 的事务面
//!   （§20.5：版本化、原子、可失败、rollback policy；forward-only，
//!   空 store 不可迁移——存储层拒绝，migration 编排在
//!   [`crate::migration::StateMigrationService`]）。
//!
//! 全部签名使用 domain 类型（§24.2），不泄漏任何存储具体类型；存储侧
//! （storage-sqlite）接线实现见其 `ports.rs`（`submit_blocking` 同步桥接，
//! 下一里程碑）。

use operune_domain::{
    InstallationId, StateKey, StateSchemaVersion, StateTransactionId, StateValue,
};

use crate::error::ErrorSource;

/// state 存储错误（封闭 typed error，§14.1；storage 接线层映射）。
#[derive(Debug, thiserror::Error)]
pub enum StateStoreError {
    /// 安装实例或键不存在（§41.2 WIT not-found）。
    #[error("state not found: {0}")]
    NotFound(String),

    /// schema 版本不符（§41.3：Normal 必须等于存储版本；空 store 由首次
    /// 写入建立版本；Migration 必须大于存储版本，forward-only）。
    #[error(
        "state schema version mismatch for installation {installation}: store is at {current:?}, requested {requested}"
    )]
    SchemaVersionMismatch {
        /// 安装实例。
        installation: InstallationId,
        /// 存储当前版本（`None` = 空 store）。
        current: Option<StateSchemaVersion>,
        /// 请求的版本。
        requested: StateSchemaVersion,
    },

    /// 事务冲突（§41.2 WIT conflict）：对已终止事务的操作、重复 begin
    /// （单连接串行 ⇒ 同一时刻至多一个进行中事务）。
    #[error("state transaction conflict: {0}")]
    TransactionConflict(String),

    /// 参数非法（如空 store 不可迁移、值超存储侧硬上限）。
    #[error("invalid state argument: {0}")]
    InvalidArgument(String),

    /// 持久数据完整性 / schema 检查失败（WIT corrupt）。
    #[error("state data corrupt: {0}")]
    Corrupt(String),

    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("state store failure: {0}")]
    Storage(#[source] ErrorSource),
}

/// StateStore port（§24.2：trait 定义在本 crate，storage-sqlite 层实现）。
pub trait StateStorePort: Send + Sync {
    /// 快照点读（WIT `state.get`；`None` = 键不存在）。
    fn get(
        &self,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError>;

    /// 原子单键 upsert（§41.2 atomic update；CAS 的基础原语——executor
    /// 单连接串行 ⇒ 服务侧 get→compare→put 天然无交错）。`schema_version`
    /// 必须等于 store 当前版本（空 store 首次写入在同一事务内建立版本），
    /// 否则 [`StateStoreError::SchemaVersionMismatch`]。
    fn put(
        &self,
        installation: InstallationId,
        key: &StateKey,
        schema_version: StateSchemaVersion,
        value: &StateValue,
    ) -> Result<(), StateStoreError>;

    /// 删除单键（键不存在 → [`StateStoreError::NotFound`]，WIT not-found）。
    fn delete(&self, installation: InstallationId, key: &StateKey) -> Result<(), StateStoreError>;

    /// 读取安装实例 state store 的整体 schema 版本（§41.3 确定性；
    /// `None` = 空 store，版本由首次写入建立）。
    fn schema_version(
        &self,
        installation: InstallationId,
    ) -> Result<Option<StateSchemaVersion>, StateStoreError>;

    /// 开启常规 state 事务（§41.2）：请求版本必须等于存储当前版本
    /// （空 store 由首次写入建立），否则
    /// [`StateStoreError::SchemaVersionMismatch`]；已有进行中事务 →
    /// [`StateStoreError::TransactionConflict`]。返回 Core 侧事务身份。
    fn begin_transaction(
        &self,
        installation: InstallationId,
        schema_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError>;

    /// 开启显式 state **migration** 事务（§20.5）：请求版本必须大于存储
    /// 当前版本（forward-only，WIT 不定义降级）；空 store 不可迁移 →
    /// [`StateStoreError::InvalidArgument`]。提交时在**同一事务**内把
    /// store 版本推进到目标版本（§41.3）。
    fn begin_migration_transaction(
        &self,
        installation: InstallationId,
        to_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError>;

    /// 事务内读取（WIT：一致性快照，未写过的键读取到 store 当前值）。
    fn tx_get(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError>;

    /// 事务内写入（提交时原子生效；已终止事务 →
    /// [`StateStoreError::TransactionConflict`]）。
    fn tx_put(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
        value: &StateValue,
    ) -> Result<(), StateStoreError>;

    /// 事务内删除（键不存在 → [`StateStoreError::NotFound`]；已终止事务 →
    /// [`StateStoreError::TransactionConflict`]）。
    fn tx_delete(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<(), StateStoreError>;

    /// 原子提交（§41.2 MUST all-or-nothing）：事务内全部写入一次性生效，
    /// schema marker 与数据在同一事务内原子提交（§41.3）。对已终止事务
    /// 的 commit → [`StateStoreError::TransactionConflict`]（WIT conflict）。
    fn commit(&self, tx: StateTransactionId) -> Result<(), StateStoreError>;

    /// 放弃事务：全部暂存操作不生效。对已终止事务是 no-op（WIT abort）。
    fn abort(&self, tx: StateTransactionId) -> Result<(), StateStoreError>;
}
