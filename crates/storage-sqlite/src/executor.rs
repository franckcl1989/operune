//! Storage Executor（§18.2）：小而明确的第一方 executor。
//!
//! # 设计
//!
//! - **线程模型**：单独持有一个 rusqlite connection（§18.2），由**专用 OS 线程**
//!   独占（`blocking_recv` 循环）。SQLite blocking 调用绝不运行在 Tokio core
//!   worker 上（§18.2）。所有命令在 worker 线程上串行执行 → 无 SQLite 锁竞争、
//!   事务边界明确；
//! - **有界请求队列**（§15.2）：`tokio::sync::mpsc` 有界 channel
//!   （[`ExecutorConfig::queue_capacity`]）。队列满 → `send().await` 背压等待，
//!   或 `try_send` 返回 [`StorageError::QueueFull`]；不存在 unbounded queue；
//! - **typed request/response**：每个 storage command 用 typed
//!   [`Command`]/[`Response`] 对（§18.2），单答复用 `oneshot`（§15.2）；
//! - **事务边界**：在 `repository` 模块明确（§18.2）；本模块只做分发；
//! - **取消语义**（§18.2）：每个请求携带 `Arc<AtomicBool>` 取消探针；请求
//!   的 async future 被 drop（结构化取消 / caller 放弃）时，RAII guard 置位
//!   探针。worker 在**执行前**与**每个事务提交点之前**检查探针：
//!   请求在事务提交前被取消 ⇒ 该事务不提交（回滚），返回
//!   [`StorageError::Cancelled`]。绝不产生半事务状态；
//! - **shutdown**（§18.2）：`shutdown()` 关闭 channel 并**等待** worker 排空
//!   已接纳请求后退出（join，经 `spawn_blocking` 不在 Tokio worker 上等待），
//!   不 detached。已接纳的关键写事务要么完整执行、要么被确定取消
//!   （切换协议取消 = marker 确定性回滚，§18.5），绝不悬挂；
//! - **不是通用 Actor Framework**（§18.2）：只服务本 crate 的 SQLite
//!   权威存储，也不反向成为 Core 状态的中央消息总线。
//!
//! # State 事务（§41.2，migration v4）
//!
//! 0.3.0 Stateful Runtime 的 state 事务语义（transaction/atomic update
//! semantics，§41.2 MUST）由 SQLite 事务实现，**跨命令边界**存活：
//!
//! - **事务句柄在 executor 内管理**：worker 持有至多一个进行中事务
//!   （[`ActiveStateTx`]）。SQLite 事务在连接上，而 executor 单连接串行
//!   （§18.2）⇒ 事务命令被自然串行化，同一时刻至多一个进行中事务
//!   （重复 begin → [`StorageError::StateTransactionConflict`]）；
//! - **事务窗口排他**：进行中事务期间只允许 state 命令（§18.2 单连接：
//!   其它命令会落入未提交事务并被连带回滚，因此显式拒绝）；服务侧应把
//!   事务限制在一次 guest 调用窗口内（WIT 短生命周期契约，§41.2）；
//! - **取消/超时 → 回滚**：任何被取消的请求（含事务内操作与 commit）在
//!   提交前触发事务整体回滚（§18.2 提交前取消检查 + §41.2 取消 → 回滚，
//!   无半状态）；超时由服务侧 deadline 驱动取消探针；
//! - **crash → 自然回滚**：未提交事务在连接关闭/进程崩溃时由 SQLite
//!   回滚（§18.5：WAL 只重放已提交帧）——重启后绝无"半个事务"残留；
//!   worker 退出时显式 `ROLLBACK` 兜底；
//! - **schema 版本确定性**（§41.3）：每个安装实例的 state store 版本以
//!   保留 key 单行持久承载（model.rs [`STATE_SCHEMA_MARKER_KEY`]）；begin
//!   校验请求版本（Normal 必须等于存储版本；Migration 必须前进，forward-
//!   only），版本推进与数据在**同一事务**内原子提交——升级、crash、
//!   取消、磁盘失败均不得产生"代码版本已切换但状态 schema 不确定"。
//!
//! # 公开 API
//!
//! [`StorageExecutor`] 的 async 方法即 repository 能力的 transport 面：
//! 所有参数与返回值都是 typed 领域/存储类型（§13.3），SQL 细节不泄漏（§18.1）。
//!
//! # state/config/secret 端口接线（§41.2）
//!
//! 本模块提供 state/config/secret 的 **executor 层能力**（typed 命令 +
//! async 方法）。application 的 `StateStore` / `SecretStore` /
//! `ComponentConfigStore` port trait 由另一里程碑定义；trait 落定后按
//! [`crate::ports`] 的既有模式（`submit_blocking` 同步桥接 + §13.3 转换层）
//! 接线，本 executor 层不依赖、也不定义 application 层 trait。

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use operune_application::ports::GraphRecords;
use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleEvent, ComponentLifecycleState,
    ComponentVersion, ConsumerRecord, ContentDigest, InstallationId, ProviderRecord,
};
use tokio::sync::{mpsc, oneshot};

use crate::artifact::{ArtifactStore, BudgetUsage, DataRoot, DiskBudget, GcPolicy, GcReport};
use crate::error::StorageError;
use crate::migration::open_authoritative_db;
use crate::model::{
    ActiveBinding, ArtifactRecord, AuditEvent, AuditRecord, CapabilityScope, ComponentConfigRecord,
    ConfigEntry, ConfigFormat, GrantRecord, InstallationRecord, InstallationVersionRecord,
    RollbackResult, SecretMetadata, SecretName, SecretRecord, SessionId, SessionRecord,
    StagedArtifact, StateKey, StateSchemaVersion, StateTransactionHandle, StateValueRecord,
    Timestamp, UpgradeTransactionRecord, UserId, UserRecord,
};
use crate::recovery::{RecoveryAction, run_recovery};
use crate::repository::{Repository, check_cancel};

/// Executor 配置（BootstrapConfig 提供的宿主启动事实，§18.0）。
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// 数据根目录（§18.7 空间布局 / §18.0 BootstrapConfig.data_root）。
    pub data_root: DataRoot,
    /// 磁盘预算硬上限（§18.7）。
    pub budget: DiskBudget,
    /// 有界请求队列容量（§15.2 / §18.2）。
    pub queue_capacity: NonZeroUsize,
    /// 单个 artifact 的硬大小上限（§19.1，写入前拒绝）。
    pub artifact_hard_limit: ByteSize,
}

impl ExecutorConfig {
    /// 默认配置：预算默认值、队列容量 64、artifact 硬上限 512 MiB。
    pub fn new(data_root: DataRoot) -> Result<Self, StorageError> {
        let queue_capacity = NonZeroUsize::new(64).ok_or_else(|| {
            StorageError::InvalidArgument("queue capacity must be non-zero".into())
        })?;
        let artifact_hard_limit = ByteSize::mib(512)?;
        Ok(Self {
            data_root,
            budget: DiskBudget::default(),
            queue_capacity,
            artifact_hard_limit,
        })
    }
}

/// 取消探针（caller cancellation，§18.2；不使用 tokio-util，保持最小依赖）。
pub(crate) type CancelFlag = Arc<AtomicBool>;

/// RAII 取消 guard：无论 future 正常完成还是被 drop（结构化取消），
/// 离开作用域即置位探针。正常完成时置位无害（worker 已执行完毕，
/// 提交点检查已通过）。
struct CancelGuard(CancelFlag);

impl Drop for CancelGuard {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// state 事务的绑定模式（§41.2：常规 vs 显式 migration）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StateTxMode {
    /// 常规：请求版本必须等于 store 当前持久化版本（空 store 由首次写入
    /// 建立版本）。begin 校验失败 → [`StorageError::SchemaVersionMismatch`]。
    Normal,
    /// §41.2 显式 state migration：请求版本必须**大于**当前版本
    /// （forward-only；0.1.0 不定义已提交迁移后的降级，WIT operune:state）。
    Migration,
}

/// worker 持有的进行中 state 事务状态（§41.2：事务句柄在 executor 内管理，
/// 每事务一个进行中状态；跨命令边界存活——SQLite 事务在连接上，§18.2）。
#[derive(Debug, Clone)]
pub(crate) struct ActiveStateTx {
    /// 事务句柄（begin 时由 worker 单调计数签发）。
    handle: u64,
    /// 事务绑定的安装实例（§19.4：state 命名空间私有于安装实例）。
    installation_id: InstallationId,
    /// 事务绑定的 schema 版本（行写入使用该版本；commit 时推进 marker）。
    schema_version: StateSchemaVersion,
    /// 事务内是否有成功的写操作（commit 时决定是否写入/推进 marker）。
    dirty: bool,
}

/// Typed 请求（§18.2：每个 storage command 用 typed request/response）。
///
/// `Command` 是 wire 契约（crate 内部 transport）；公开 API 是
/// [`StorageExecutor`] 的 typed async 方法。
#[derive(Debug)]
pub(crate) enum Command {
    /// 打开后 recovery 报告。
    RecoveryReport,
    /// 暂存字节（staging，§19.2）。
    StageBytes {
        /// 原始字节（不可信输入，§19.1）。
        bytes: Vec<u8>,
        /// 硬大小上限。
        hard_limit: ByteSize,
    },
    /// quarantine 记录（字节事实阶段，§19.2）。
    RecordQuarantine {
        /// staging 结果。
        staged: StagedArtifact,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// candidate 提交（注册表绑定，§19.2）。
    CommitCandidate {
        /// 内容摘要。
        digest: ContentDigest,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 逻辑版本。
        version: ComponentVersion,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 创建安装实例（§19.4）。
    CreateInstallation {
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 绑定安装版本（§18.3）。
    BindInstallationVersion {
        /// 安装实例。
        installation_id: InstallationId,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 逻辑版本。
        version: ComponentVersion,
        /// 绑定 digest。
        digest: ContentDigest,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 生命周期事件（§12.2）。
    ApplyLifecycleEvent {
        /// 安装实例。
        installation_id: InstallationId,
        /// 领域生命周期事件。
        event: ComponentLifecycleEvent,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 唯一 active 切换（§18.5 两阶段协议）。
    SwitchActiveVersion {
        /// 安装实例。
        installation_id: InstallationId,
        /// 目标版本。
        version: ComponentVersion,
        /// 目标 digest。
        digest: ContentDigest,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 显式回滚（§20.1）。
    RollbackVersion {
        /// 安装实例。
        installation_id: InstallationId,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// enable/disable（§39.2）。
    SetInstallationEnabled {
        /// 安装实例。
        installation_id: InstallationId,
        /// 是否启用。
        enabled: bool,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 卸载安装实例（§39.2 remove / §42.4：卸载后 UI + backend 完整消失）。
    /// **单事务**删除该安装实例的全部 Core 元数据（grants / active_version /
    /// upgrade_transactions / graph 记录 / component_state/config/secret /
    /// installation_versions / installations 行）；**artifact 保留**
    /// （§18.7 rollback retention：digest 仍被 artifact/component_versions
    /// 引用，GC 规则不变）。audit 与删除同事务（§18.7 fail closed）。
    RemoveInstallation {
        /// 安装实例。
        installation_id: InstallationId,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 能力授权（§17.5）。
    GrantCapability {
        /// 安装实例。
        installation_id: InstallationId,
        /// 能力身份。
        capability_id: CapabilityId,
        /// 资源级 scope。
        scope: CapabilityScope,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 撤销授权（§17.5）。
    RevokeCapability {
        /// 安装实例。
        installation_id: InstallationId,
        /// 能力身份。
        capability_id: CapabilityId,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 当前生效授权列表。
    ListGrants {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 创建用户（§16.4 只存 Argon2id 哈希）。
    CreateUser {
        /// 用户名。
        username: String,
        /// Argon2id PHC 哈希（绝不接受明文，§16.4）。
        password_hash: String,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 按用户名查用户。
    GetUserByUsername {
        /// 用户名。
        username: String,
    },
    /// 按 ID 查用户。
    GetUser {
        /// 用户 ID。
        user_id: UserId,
    },
    /// 轮换密码哈希（§16.3）。
    UpdatePasswordHash {
        /// 用户 ID。
        user_id: UserId,
        /// 新 Argon2id PHC 哈希。
        new_hash: String,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 停用/启用用户。
    SetUserDisabled {
        /// 用户 ID。
        user_id: UserId,
        /// 是否停用。
        disabled: bool,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 创建 session（§16.5 只存 token 摘要）。
    CreateSession {
        /// 用户 ID。
        user_id: UserId,
        /// bearer token 的单向 SHA-256 摘要。
        token_digest: ContentDigest,
        /// 绝对过期时间。
        absolute_expires_at: Timestamp,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 按 token 摘要查找 session。
    LookupSession {
        /// token 摘要。
        token_digest: ContentDigest,
    },
    /// 刷新 last_used_at。
    TouchSession {
        /// session ID。
        session_id: SessionId,
    },
    /// 吊销 session。
    RevokeSession {
        /// session ID。
        session_id: SessionId,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 吊销用户全部 session（§16.5）。
    RevokeAllUserSessions {
        /// 用户 ID。
        user_id: UserId,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 独立追加 audit（§18.7）。
    AppendAudit {
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 写入 RuntimeConfig（§18.0）。
    SetConfig {
        /// 配置键。
        key: String,
        /// 配置值。
        value: String,
        /// audit 事件。
        audit: AuditEvent,
    },
    /// 读配置。
    GetConfig {
        /// 配置键。
        key: String,
    },
    /// 列出配置。
    ListConfig,
    /// GC / retention（§18.7）。
    Gc {
        /// GC 策略。
        policy: GcPolicy,
    },
    /// 预算占用。
    GetBudgetUsage,
    /// artifact 是否存在。
    ArtifactExists {
        /// 内容摘要。
        digest: ContentDigest,
    },
    /// 读 artifact。
    GetArtifact {
        /// 内容摘要。
        digest: ContentDigest,
    },
    /// 读安装实例。
    GetInstallation {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 列出安装实例。
    ListInstallations,
    /// 读唯一 active 绑定。
    GetActiveBinding {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 列出安装版本绑定。
    ListInstallationVersions {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 列出升级/回滚事务标记。
    ListUpgradeTransactions {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 最近审计事件。
    ListAuditRecent {
        /// 条数上限（≤ 1000）。
        limit: usize,
    },
    /// 写入 / 更新 digest 主键的 candidate 记录（§19.2 / §12.2；
    /// application 的 `ComponentRegistryPort` 面）。
    UpsertCandidate {
        /// 字节事实主键 + 领域生命周期 + 字节大小。
        record: operune_application::model::CandidateRecord,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 推进 candidate 的领域生命周期（§12.2）。
    UpdateCandidateState {
        /// 字节事实主键。
        digest: ContentDigest,
        /// 目标领域生命周期状态。
        state: ComponentLifecycleState,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 读取 candidate 记录。
    GetCandidate {
        /// 字节事实主键。
        digest: ContentDigest,
    },
    /// 查询 `ComponentId + ComponentVersion` 的既有绑定（§19.4）。
    ResolveVersion {
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 逻辑版本。
        version: ComponentVersion,
    },
    /// 以调用方给定的 InstallationId 创建安装实例（§19.4）。
    CreateInstallationWithId {
        /// 安装实例身份（用例层生成）。
        installation_id: InstallationId,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 幂等绑定安装版本（§18.3；application 激活路径按安装记录补绑定）。
    BindInstallationVersionOnce {
        /// 安装实例。
        installation_id: InstallationId,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 逻辑版本。
        version: ComponentVersion,
        /// 绑定 digest。
        digest: ContentDigest,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 按 digest 读取制品字节（§18.7 rollback retention）。
    ReadArtifactBytes {
        /// 内容摘要。
        digest: ContentDigest,
    },
    /// 整体替换安装实例的授权集（§17.5，原子替换）。
    ReplaceGrants {
        /// 安装实例。
        installation_id: InstallationId,
        /// 新授权集（能力 + 资源级 scope）。
        grants: Vec<(CapabilityId, CapabilityScope)>,
        /// audit 事件（同事务，§18.7）。
        audit: AuditEvent,
    },
    /// 原子替换某安装实例的全部 graph 记录（§40.2 graph
    /// persistence/recovery；application 的 `ProviderGraphPort` 面；
    /// 单事务语义见 repository 文档）。
    ReplaceGraphRecords {
        /// 安装实例（记录键，§17.5）。
        installation_id: InstallationId,
        /// 新的 provider 记录（`None` = 该安装不再提供任何 interface）。
        provider: Option<ProviderRecord>,
        /// 新的 consumer 记录（`None` = 该安装不再导入任何 interface）。
        consumer: Option<ConsumerRecord>,
    },
    /// 加载全部 graph 记录（§40.2 恢复输入）。
    LoadGraphRecords,
    // ------------------------------------------------------------------
    // 0.3.0 Stateful Runtime（§41.2，migration v4）：state/config/secret。
    // 语义与事务协议见模块文档与 repository.rs。
    // ------------------------------------------------------------------
    /// 读取单键 state（§41.2 快照点读；`tx = Some(handle)` 时在事务快照内
    /// 读取，须为进行中事务且安装匹配，否则
    /// [`StorageError::StateTransactionConflict`]）。
    GetState {
        /// 安装实例。
        installation_id: InstallationId,
        /// 状态键（WIT state-key 不变量已校验）。
        key: StateKey,
        /// 事务句柄（`None` = 事务外点读；进行中事务期间必须携带句柄）。
        tx: Option<StateTransactionHandle>,
    },
    /// 原子单键 upsert（§41.2 atomic update；CAS 基础，见 repository.rs）。
    /// `tx = Some(handle)` 时在事务内写入（`schema_version` 必须为 `None`，
    /// 版本绑定于事务）；`tx = None` 时 `schema_version` 必须为 `Some` 且
    /// 等于 store 当前版本（空 store 首次写入建立版本）。
    PutState {
        /// 安装实例。
        installation_id: InstallationId,
        /// 状态键。
        key: StateKey,
        /// schema 版本（`None` = 事务内写入，使用事务绑定版本）。
        schema_version: Option<StateSchemaVersion>,
        /// 平台不透明的序列化业务字节（§41.2 平台不解释内容）。
        value: Vec<u8>,
        /// 事务句柄。
        tx: Option<StateTransactionHandle>,
    },
    /// 删除单键（键不存在 → [`StorageError::NotFound`]，WIT not-found）。
    DeleteState {
        /// 安装实例。
        installation_id: InstallationId,
        /// 状态键。
        key: StateKey,
        /// 事务句柄（语义同 [`Command::GetState`]）。
        tx: Option<StateTransactionHandle>,
    },
    /// 读取安装实例 state store 的整体 schema 版本（§41.3 确定性；
    /// `None` = 空 store，版本由首次写入建立）。
    GetStateSchemaVersion {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 开启 state 事务（§41.2；SQLite 事务在连接上，executor 单连接串行
    /// ⇒ 至多一个进行中事务——重复 begin → StateTransactionConflict）。
    /// 版本语义（§41.3）：`Normal` 请求版本必须等于存储版本（空 store
    /// 由首次写入建立）；`Migration` 必须大于存储版本（forward-only），
    /// commit 时在**同一事务**内推进 marker——升级/crash/取消/磁盘失败
    /// 均不得产生"代码版本已切换但状态 schema 不确定"（§41.3 验收）。
    BeginStateTransaction {
        /// 安装实例。
        installation_id: InstallationId,
        /// 请求的 schema 版本。
        schema_version: StateSchemaVersion,
        /// 绑定模式（常规 / 显式 migration）。
        mode: StateTxMode,
    },
    /// 原子提交（§41.2 MUST all-or-nothing）：事务内全部写入一次性生效；
    /// 提交前取消检查 → 回滚（§18.2），绝无半事务状态。对已终止事务的
    /// commit → StateTransactionConflict（WIT conflict）。
    CommitStateTransaction {
        /// 事务句柄。
        handle: StateTransactionHandle,
    },
    /// 放弃事务：全部暂存操作不生效（WIT：abort 无返回值，对已终止事务
    /// 是 no-op——本命令对无进行中事务/未知句柄一律 no-op 成功）。
    AbortStateTransaction {
        /// 事务句柄。
        handle: StateTransactionHandle,
    },
    /// 读取安装实例的 component config 快照（§41.2；原子：revision 与
    /// value 同行同读）。
    GetComponentConfig {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 写入/更新 component config（revision +1 原子，§41.2；单语句 upsert
    /// 保证单调，设计注释见 repository.rs）。
    PutComponentConfig {
        /// 安装实例。
        installation_id: InstallationId,
        /// 声明格式（json/toml/raw，WIT）。
        format: ConfigFormat,
        /// 配置契约的 schema 版本（WIT 与 revision 相区别）。
        schema_version: StateSchemaVersion,
        /// 有界配置值（通过验证后才成为当前配置）。
        value: Vec<u8>,
    },
    /// 写入/轮换 secret 密文（insert or replace 版本递增；**storage 不解密
    /// 不解释内容**，§16.6 / ADR-0001）。
    PutSecret {
        /// 安装实例。
        installation_id: InstallationId,
        /// secret 名称（grant scope 的键，§17.3）。
        name: SecretName,
        /// 不透明密文 BLOB（服务侧加密后的 envelope）。
        ciphertext: Vec<u8>,
        /// 非敏感元数据（绝不含值/密钥材料，§16.6）。
        metadata: String,
    },
    /// 读取 secret 密文（不透明字节原样返回；`None` = 名称不存在）。
    GetSecretCiphertext {
        /// 安装实例。
        installation_id: InstallationId,
        /// secret 名称。
        name: SecretName,
    },
    /// 列出安装实例的全部 secret 名称与版本（**不含值**，§41.2 防泄漏）。
    ListSecretNames {
        /// 安装实例。
        installation_id: InstallationId,
    },
    /// 删除 secret（名称不存在 → [`StorageError::NotFound`]）。
    DeleteSecret {
        /// 安装实例。
        installation_id: InstallationId,
        /// secret 名称。
        name: SecretName,
    },
    /// 测试专用 gate（仅 cfg(test)：阻塞 worker 以验证有界队列 / 取消 /
    /// shutdown 排空语义，§29）。
    #[cfg(test)]
    TestGate {
        /// "worker 已进入等待"信号。
        entered: oneshot::Sender<()>,
        /// 释放信号。
        release: oneshot::Receiver<()>,
    },
}

/// Typed 响应（与 [`Command`] 一一对应）。
#[derive(Debug)]
pub(crate) enum Response {
    /// recovery 报告。
    RecoveryReport(Vec<RecoveryAction>),
    /// staging 结果。
    Staged(StagedArtifact),
    /// quarantine 已记录。
    Quarantined,
    /// candidate 已提交。
    CandidateCommitted,
    /// 安装实例已创建。
    InstallationCreated(InstallationId),
    /// 版本已绑定。
    VersionBound,
    /// 生命周期推进后的状态。
    LifecycleAdvanced(ComponentLifecycleState),
    /// 切换后的唯一 active 绑定。
    VersionSwitched(ActiveBinding),
    /// 回滚结果。
    RollbackPerformed(RollbackResult),
    /// enable/disable 已设置。
    Enabled,
    /// 卸载已执行（§39.2 remove；单事务）。
    Removed,
    /// 已授权。
    Granted,
    /// 已撤销。
    Revoked,
    /// 授权列表。
    Grants(Vec<GrantRecord>),
    /// 用户已创建。
    UserCreated(UserId),
    /// 用户记录。
    User(Option<UserRecord>),
    /// 密码已更新。
    PasswordUpdated,
    /// 用户停用状态已设置。
    UserDisabled,
    /// session 已创建。
    SessionCreated(SessionId),
    /// session 记录。
    Session(Option<SessionRecord>),
    /// last_used_at 已刷新。
    SessionTouched,
    /// session 已吊销。
    SessionRevoked,
    /// 吊销数量。
    SessionsRevoked(u64),
    /// audit 事件序号。
    AuditAppended(i64),
    /// 配置已写入。
    ConfigSet,
    /// 配置条目。
    Config(Option<ConfigEntry>),
    /// 配置列表。
    ConfigList(Vec<ConfigEntry>),
    /// GC 报告。
    GcPerformed(GcReport),
    /// 预算占用。
    BudgetUsage(BudgetUsage),
    /// artifact 存在性。
    ArtifactExists(bool),
    /// artifact 记录。
    Artifact(Option<ArtifactRecord>),
    /// 安装记录。
    Installation(Option<InstallationRecord>),
    /// 安装列表。
    Installations(Vec<InstallationRecord>),
    /// 唯一 active 绑定。
    ActiveBinding(Option<ActiveBinding>),
    /// 版本绑定列表。
    InstallationVersions(Vec<InstallationVersionRecord>),
    /// 升级/回滚事务列表。
    UpgradeTransactions(Vec<UpgradeTransactionRecord>),
    /// 审计列表。
    AuditRecent(Vec<AuditRecord>),
    /// candidate 记录已写入 / 更新。
    CandidateUpserted,
    /// candidate 领域生命周期已推进。
    CandidateStateUpdated,
    /// candidate 记录。
    Candidate(Option<operune_application::model::CandidateRecord>),
    /// 版本绑定。
    VersionBinding(Option<operune_application::model::DigestVersionBinding>),
    /// 安装实例已创建（调用方给定 ID 形态）。
    InstallationCreatedWithId,
    /// 版本已绑定（幂等）。
    VersionBoundOnce,
    /// 制品字节。
    ArtifactBytes(Option<Vec<u8>>),
    /// 授权集已整体替换。
    GrantsReplaced,
    /// graph 记录已整体替换（§40.2）。
    GraphRecordsReplaced,
    /// 全部 graph 记录（§40.2 恢复输入）。
    GraphRecords(GraphRecords),
    /// 单键 state 记录（§41.2）。
    StateValue(Option<StateValueRecord>),
    /// store 整体 schema 版本（§41.3）。
    StateSchemaVersion(Option<StateSchemaVersion>),
    /// state 事务已开启（携带句柄）。
    StateTransactionBegan(StateTransactionHandle),
    /// state 事务已原子提交（§41.2 all-or-nothing）。
    StateCommitted,
    /// state 事务已放弃（no-op 语义，WIT）。
    StateAborted,
    /// state 已写入（原子单键 upsert）。
    StatePut,
    /// state 键已删除。
    StateDeleted,
    /// component config 快照（§41.2）。
    ComponentConfig(Option<ComponentConfigRecord>),
    /// component config 已写入（revision +1）。
    ComponentConfigSet,
    /// secret 密文已写入/轮换（版本递增）。
    SecretPut,
    /// secret 密文记录（§16.6：不透明字节；值只在本响应出现一次）。
    Secret(Option<SecretRecord>),
    /// secret 名称与版本列表（不含值，§41.2）。
    SecretList(Vec<SecretMetadata>),
    /// secret 已删除。
    SecretDeleted,
}

/// 单个请求（命令 + 取消探针 + 单答复）。
pub(crate) struct Request {
    /// 命令。
    pub cmd: Command,
    /// 取消探针（§18.2）。
    pub cancel: CancelFlag,
    /// 单答复通道（§15.2）。
    pub reply: oneshot::Sender<Result<Response, StorageError>>,
}

/// Storage Executor handle（§18.2）。`Arc<StorageExecutor>` 可跨任务共享
/// （mpsc Sender 是 `Clone` + `Send + Sync`）。
pub struct StorageExecutor {
    /// `None` 表示已 shutdown（channel 已关闭）。
    sender: Option<mpsc::Sender<Request>>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl StorageExecutor {
    /// 打开存储：worker 线程内完成 open + migration + recovery（fail closed，
    /// §18.4 / §18.5），就绪后返回。
    ///
    /// 打开失败（schema 不匹配 / migration 失败 / recovery 判定损坏）⇒
    /// 返回错误，worker 线程已回收。
    pub async fn open(config: ExecutorConfig) -> Result<Self, StorageError> {
        let (sender, receiver) = mpsc::channel(config.queue_capacity.get());
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker = std::thread::Builder::new()
            .name("operune-storage-worker".into())
            .spawn(move || worker_main(receiver, config, ready_tx))
            .map_err(|e| StorageError::io("spawn storage worker thread", e))?;
        let ready = ready_rx.await.map_err(|_| {
            StorageError::CorruptState("storage worker exited before reporting readiness".into())
        })?;
        match ready {
            Ok(()) => Ok(Self {
                sender: Some(sender),
                worker: Some(worker),
            }),
            Err(error) => {
                // worker 已退出：回收线程后传播失败（fail closed）。
                let _ = tokio::task::spawn_blocking(move || worker.join()).await;
                Err(error)
            }
        }
    }

    /// 关闭 executor：关闭 channel，**等待** worker 排空已接纳请求后退出
    /// （§18.2 shutdown 不得 detached）。已接纳请求要么完整执行、要么被
    /// 确定取消（取消语义见模块文档）。
    pub async fn shutdown(mut self) -> Result<(), StorageError> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| StorageError::InvalidArgument("executor is already shut down".into()))?;
        // 关闭 channel（所有 sender 消失 → worker 排空后退出）。
        self.sender.take();
        let joined = tokio::task::spawn_blocking(move || worker.join())
            .await
            .map_err(StorageError::WorkerJoin)?;
        joined.map_err(|_| {
            StorageError::CorruptState("storage worker thread panicked during shutdown".into())
        })?;
        Ok(())
    }

    /// 提交一个 typed 命令并等待响应（有界背压：队列满时 `send().await`
    /// 等待容量，§15.2）。
    async fn submit(&self, cmd: Command) -> Result<Response, StorageError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        // RAII 取消 guard：本 future 被 drop（caller 放弃 / 结构化取消）即置位。
        let _cancel_guard = CancelGuard(cancel.clone());
        let sender = self.sender.as_ref().ok_or(StorageError::Shutdown)?;
        sender
            .send(Request {
                cmd,
                cancel,
                reply: reply_tx,
            })
            .await
            .map_err(|_| StorageError::Shutdown)?;
        reply_rx.await.map_err(|_| StorageError::Shutdown)?
    }

    /// 同步提交（application port 适配层专用，见 `crate::ports`）：
    /// `try_send` + 短等待重试（有界背压，§15.2）+ `try_recv` 轮询答复。
    ///
    /// 用途：application 的 port traits 是同步接口（§24.2），而本 executor
    /// 是 async facade（§18.2）——同步桥接在**调用线程**上等待通道，
    /// SQLite 执行仍全部发生在 worker 线程（§18.2：SQLite blocking 调用
    /// 不运行在 Tokio core worker 上）。
    ///
    /// 为什么不用 `blocking_send` / `blocking_recv`：tokio 的 blocking_*
    /// 经 `crate::future::block_on` 实现，在 async 上下文（如 axum worker、
    /// tokio 测试）内调用会 panic（"Cannot block the current thread from
    /// within a runtime"）——port 的调用方可能是 async 上下文。`try_send` /
    /// `try_recv` 无此限制；队列满 / 答复未就绪时短等待（1ms）重试——
    /// worker 快速排空（每个请求耗时都有界，§18.2），等待有界。与异步
    /// `submit` 的取消语义差异：同步调用方无法在等待中结构化取消（没有
    /// async future 可 drop），取消探针保持未置位，请求执行到完成。
    pub(crate) fn submit_blocking(&self, cmd: Command) -> Result<Response, StorageError> {
        let (reply_tx, mut reply_rx) = oneshot::channel();
        let sender = self.sender.as_ref().ok_or(StorageError::Shutdown)?;
        let mut request = Request {
            cmd,
            cancel: Arc::new(AtomicBool::new(false)),
            reply: reply_tx,
        };
        loop {
            match sender.try_send(request) {
                Ok(()) => break,
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    request = returned;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Err(StorageError::Shutdown),
            }
        }
        loop {
            match reply_rx.try_recv() {
                Ok(result) => return result,
                Err(oneshot::error::TryRecvError::Empty) => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(oneshot::error::TryRecvError::Closed) => return Err(StorageError::Shutdown),
            }
        }
    }

    /// try 提交（有界队列拒绝测试用；队列满 ⇒ [`StorageError::QueueFull`]）。
    /// 仅测试编译（§29 有界队列 / 取消测试的确定性 gate 机制）。
    #[cfg(test)]
    pub(crate) fn try_submit(
        &self,
        cmd: Command,
    ) -> Result<oneshot::Receiver<Result<Response, StorageError>>, StorageError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.try_submit_request(Request {
            cmd,
            cancel: Arc::new(AtomicBool::new(false)),
            reply: reply_tx,
        })?;
        Ok(reply_rx)
    }

    /// try 提交一个完整 Request（有界队列 / 取消测试用）。
    #[cfg(test)]
    pub(crate) fn try_submit_request(&self, request: Request) -> Result<(), StorageError> {
        let sender = self.sender.as_ref().ok_or(StorageError::Shutdown)?;
        match sender.try_send(request) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => Err(StorageError::QueueFull),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(StorageError::Shutdown),
        }
    }

    /// 打开时 recovery 报告（§18.5；recovery 动作已写入 durable audit）。
    pub async fn recovery_report(&self) -> Result<Vec<RecoveryAction>, StorageError> {
        let response = self.submit(Command::RecoveryReport).await?;
        match response {
            Response::RecoveryReport(report) => Ok(report),
            _ => Err(unexpected_response("RecoveryReport")),
        }
    }

    /// 暂存原始字节（§19.2 字节事实阶段）。
    pub async fn stage_bytes(
        &self,
        bytes: Vec<u8>,
        hard_limit: ByteSize,
    ) -> Result<StagedArtifact, StorageError> {
        let response = self
            .submit(Command::StageBytes { bytes, hard_limit })
            .await?;
        match response {
            Response::Staged(staged) => Ok(staged),
            _ => Err(unexpected_response("StageBytes")),
        }
    }

    /// 记录 quarantine（字节事实阶段，§19.2）。
    pub async fn record_quarantine(
        &self,
        staged: StagedArtifact,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::RecordQuarantine { staged, audit })
            .await?;
        match response {
            Response::Quarantined => Ok(()),
            _ => Err(unexpected_response("RecordQuarantine")),
        }
    }

    /// 提交 candidate（注册表绑定，§19.2；同版本不同 digest 显式阻断，§19.4）。
    pub async fn commit_candidate(
        &self,
        digest: ContentDigest,
        component_id: ComponentId,
        version: ComponentVersion,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::CommitCandidate {
                digest,
                component_id,
                version,
                audit,
            })
            .await?;
        match response {
            Response::CandidateCommitted => Ok(()),
            _ => Err(unexpected_response("CommitCandidate")),
        }
    }

    /// 创建安装实例（§19.4：Core 生成 InstallationId）。
    pub async fn create_installation(
        &self,
        component_id: ComponentId,
        audit: AuditEvent,
    ) -> Result<InstallationId, StorageError> {
        let response = self
            .submit(Command::CreateInstallation {
                component_id,
                audit,
            })
            .await?;
        match response {
            Response::InstallationCreated(id) => Ok(id),
            _ => Err(unexpected_response("CreateInstallation")),
        }
    }

    /// 绑定安装版本（§18.3）。
    pub async fn bind_installation_version(
        &self,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        digest: ContentDigest,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::BindInstallationVersion {
                installation_id,
                component_id,
                version,
                digest,
                audit,
            })
            .await?;
        match response {
            Response::VersionBound => Ok(()),
            _ => Err(unexpected_response("BindInstallationVersion")),
        }
    }

    /// 推进领域生命周期状态机（§12.2；非法转换返回 typed error）。
    pub async fn apply_lifecycle_event(
        &self,
        installation_id: InstallationId,
        event: ComponentLifecycleEvent,
        audit: AuditEvent,
    ) -> Result<ComponentLifecycleState, StorageError> {
        let response = self
            .submit(Command::ApplyLifecycleEvent {
                installation_id,
                event,
                audit,
            })
            .await?;
        match response {
            Response::LifecycleAdvanced(state) => Ok(state),
            _ => Err(unexpected_response("ApplyLifecycleEvent")),
        }
    }

    /// 唯一 active 切换（§18.5 两阶段协议；初次激活 / 热升级共用）。
    pub async fn switch_active_version(
        &self,
        installation_id: InstallationId,
        version: ComponentVersion,
        digest: ContentDigest,
        audit: AuditEvent,
    ) -> Result<ActiveBinding, StorageError> {
        let response = self
            .submit(Command::SwitchActiveVersion {
                installation_id,
                version,
                digest,
                audit,
            })
            .await?;
        match response {
            Response::VersionSwitched(binding) => Ok(binding),
            _ => Err(unexpected_response("SwitchActiveVersion")),
        }
    }

    /// 显式回滚到上一已知良好版本（§20.1 / §18.7 rollback retention）。
    pub async fn rollback_version(
        &self,
        installation_id: InstallationId,
        audit: AuditEvent,
    ) -> Result<RollbackResult, StorageError> {
        let response = self
            .submit(Command::RollbackVersion {
                installation_id,
                audit,
            })
            .await?;
        match response {
            Response::RollbackPerformed(result) => Ok(result),
            _ => Err(unexpected_response("RollbackVersion")),
        }
    }

    /// 卸载安装实例（§39.2 remove / §42.4）。不存在 →
    /// [`StorageError::NotFound`]；单事务删除（§18.5 crash consistency），
    /// artifact 保留（§18.7）。
    pub async fn remove_installation(
        &self,
        installation_id: InstallationId,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::RemoveInstallation {
                installation_id,
                audit,
            })
            .await?;
        match response {
            Response::Removed => Ok(()),
            _ => Err(unexpected_response("RemoveInstallation")),
        }
    }

    /// enable/disable（§39.2）。
    pub async fn set_installation_enabled(
        &self,
        installation_id: InstallationId,
        enabled: bool,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::SetInstallationEnabled {
                installation_id,
                enabled,
                audit,
            })
            .await?;
        match response {
            Response::Enabled => Ok(()),
            _ => Err(unexpected_response("SetInstallationEnabled")),
        }
    }

    /// 授权能力（§17.5：grant 绑定 InstallationId）。
    pub async fn grant_capability(
        &self,
        installation_id: InstallationId,
        capability_id: CapabilityId,
        scope: CapabilityScope,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::GrantCapability {
                installation_id,
                capability_id,
                scope,
                audit,
            })
            .await?;
        match response {
            Response::Granted => Ok(()),
            _ => Err(unexpected_response("GrantCapability")),
        }
    }

    /// 撤销授权（§17.5）。
    pub async fn revoke_capability(
        &self,
        installation_id: InstallationId,
        capability_id: CapabilityId,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::RevokeCapability {
                installation_id,
                capability_id,
                audit,
            })
            .await?;
        match response {
            Response::Revoked => Ok(()),
            _ => Err(unexpected_response("RevokeCapability")),
        }
    }

    /// 当前生效授权列表。
    pub async fn list_grants(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<GrantRecord>, StorageError> {
        let response = self.submit(Command::ListGrants { installation_id }).await?;
        match response {
            Response::Grants(grants) => Ok(grants),
            _ => Err(unexpected_response("ListGrants")),
        }
    }

    /// 创建用户（§16.4：只存 Argon2id PHC 哈希，绝不存明文）。
    pub async fn create_user(
        &self,
        username: String,
        password_hash: String,
        audit: AuditEvent,
    ) -> Result<UserId, StorageError> {
        let response = self
            .submit(Command::CreateUser {
                username,
                password_hash,
                audit,
            })
            .await?;
        match response {
            Response::UserCreated(user_id) => Ok(user_id),
            _ => Err(unexpected_response("CreateUser")),
        }
    }

    /// 按用户名查用户。
    pub async fn get_user_by_username(
        &self,
        username: String,
    ) -> Result<Option<UserRecord>, StorageError> {
        let response = self.submit(Command::GetUserByUsername { username }).await?;
        match response {
            Response::User(user) => Ok(user),
            _ => Err(unexpected_response("GetUserByUsername")),
        }
    }

    /// 按 ID 查用户。
    pub async fn get_user(&self, user_id: UserId) -> Result<Option<UserRecord>, StorageError> {
        let response = self.submit(Command::GetUser { user_id }).await?;
        match response {
            Response::User(user) => Ok(user),
            _ => Err(unexpected_response("GetUser")),
        }
    }

    /// 轮换密码哈希（§16.3；audit 不含哈希值，§16.6）。
    pub async fn update_password_hash(
        &self,
        user_id: UserId,
        new_hash: String,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::UpdatePasswordHash {
                user_id,
                new_hash,
                audit,
            })
            .await?;
        match response {
            Response::PasswordUpdated => Ok(()),
            _ => Err(unexpected_response("UpdatePasswordHash")),
        }
    }

    /// 停用/启用用户。
    pub async fn set_user_disabled(
        &self,
        user_id: UserId,
        disabled: bool,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::SetUserDisabled {
                user_id,
                disabled,
                audit,
            })
            .await?;
        match response {
            Response::UserDisabled => Ok(()),
            _ => Err(unexpected_response("SetUserDisabled")),
        }
    }

    /// 创建 session（§16.5：权威存储只保存 token 的单向 SHA-256 摘要；
    /// 本 API 不接受明文 token）。
    pub async fn create_session(
        &self,
        user_id: UserId,
        token_digest: ContentDigest,
        absolute_expires_at: Timestamp,
        audit: AuditEvent,
    ) -> Result<SessionId, StorageError> {
        let response = self
            .submit(Command::CreateSession {
                user_id,
                token_digest,
                absolute_expires_at,
                audit,
            })
            .await?;
        match response {
            Response::SessionCreated(session_id) => Ok(session_id),
            _ => Err(unexpected_response("CreateSession")),
        }
    }

    /// 按 token 摘要查找有效 session（§16.5 验证路径）。
    pub async fn lookup_session(
        &self,
        token_digest: ContentDigest,
    ) -> Result<Option<SessionRecord>, StorageError> {
        let response = self.submit(Command::LookupSession { token_digest }).await?;
        match response {
            Response::Session(session) => Ok(session),
            _ => Err(unexpected_response("LookupSession")),
        }
    }

    /// 刷新 session `last_used_at`（idle expiry，§16.5）。
    pub async fn touch_session(&self, session_id: SessionId) -> Result<(), StorageError> {
        let response = self.submit(Command::TouchSession { session_id }).await?;
        match response {
            Response::SessionTouched => Ok(()),
            _ => Err(unexpected_response("TouchSession")),
        }
    }

    /// 吊销 session（§16.5 logout / 吊销路径）。
    pub async fn revoke_session(
        &self,
        session_id: SessionId,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::RevokeSession { session_id, audit })
            .await?;
        match response {
            Response::SessionRevoked => Ok(()),
            _ => Err(unexpected_response("RevokeSession")),
        }
    }

    /// 吊销用户全部 session（§16.5）。返回吊销数量。
    pub async fn revoke_all_user_sessions(
        &self,
        user_id: UserId,
        audit: AuditEvent,
    ) -> Result<u64, StorageError> {
        let response = self
            .submit(Command::RevokeAllUserSessions { user_id, audit })
            .await?;
        match response {
            Response::SessionsRevoked(count) => Ok(count),
            _ => Err(unexpected_response("RevokeAllUserSessions")),
        }
    }

    /// 独立追加审计事件（§18.7）。返回事件序号。
    pub async fn append_audit(&self, audit: AuditEvent) -> Result<i64, StorageError> {
        let response = self.submit(Command::AppendAudit { audit }).await?;
        match response {
            Response::AuditAppended(id) => Ok(id),
            _ => Err(unexpected_response("AppendAudit")),
        }
    }

    /// 写入 RuntimeConfig（§18.0：事务化、版本化并审计）。
    pub async fn set_config(
        &self,
        key: String,
        value: String,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::SetConfig { key, value, audit })
            .await?;
        match response {
            Response::ConfigSet => Ok(()),
            _ => Err(unexpected_response("SetConfig")),
        }
    }

    /// 读 RuntimeConfig。
    pub async fn get_config(&self, key: String) -> Result<Option<ConfigEntry>, StorageError> {
        let response = self.submit(Command::GetConfig { key }).await?;
        match response {
            Response::Config(entry) => Ok(entry),
            _ => Err(unexpected_response("GetConfig")),
        }
    }

    /// 列出 RuntimeConfig。
    pub async fn list_config(&self) -> Result<Vec<ConfigEntry>, StorageError> {
        let response = self.submit(Command::ListConfig).await?;
        match response {
            Response::ConfigList(entries) => Ok(entries),
            _ => Err(unexpected_response("ListConfig")),
        }
    }

    /// GC / retention（§18.7）。
    pub async fn gc(&self, policy: GcPolicy) -> Result<GcReport, StorageError> {
        let response = self.submit(Command::Gc { policy }).await?;
        match response {
            Response::GcPerformed(report) => Ok(report),
            _ => Err(unexpected_response("Gc")),
        }
    }

    /// 各空间预算占用（§18.7）。
    pub async fn get_budget_usage(&self) -> Result<BudgetUsage, StorageError> {
        let response = self.submit(Command::GetBudgetUsage).await?;
        match response {
            Response::BudgetUsage(usage) => Ok(usage),
            _ => Err(unexpected_response("GetBudgetUsage")),
        }
    }

    /// artifact 是否存在。
    pub async fn artifact_exists(&self, digest: ContentDigest) -> Result<bool, StorageError> {
        let response = self.submit(Command::ArtifactExists { digest }).await?;
        match response {
            Response::ArtifactExists(exists) => Ok(exists),
            _ => Err(unexpected_response("ArtifactExists")),
        }
    }

    /// 读 artifact 记录。
    pub async fn get_artifact(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<ArtifactRecord>, StorageError> {
        let response = self.submit(Command::GetArtifact { digest }).await?;
        match response {
            Response::Artifact(artifact) => Ok(artifact),
            _ => Err(unexpected_response("GetArtifact")),
        }
    }

    /// 读安装实例。
    pub async fn get_installation(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<InstallationRecord>, StorageError> {
        let response = self
            .submit(Command::GetInstallation { installation_id })
            .await?;
        match response {
            Response::Installation(installation) => Ok(installation),
            _ => Err(unexpected_response("GetInstallation")),
        }
    }

    /// 列出安装实例。
    pub async fn list_installations(&self) -> Result<Vec<InstallationRecord>, StorageError> {
        let response = self.submit(Command::ListInstallations).await?;
        match response {
            Response::Installations(installations) => Ok(installations),
            _ => Err(unexpected_response("ListInstallations")),
        }
    }

    /// 读唯一 active 绑定。
    pub async fn get_active_binding(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<ActiveBinding>, StorageError> {
        let response = self
            .submit(Command::GetActiveBinding { installation_id })
            .await?;
        match response {
            Response::ActiveBinding(binding) => Ok(binding),
            _ => Err(unexpected_response("GetActiveBinding")),
        }
    }

    /// 列出安装版本绑定（含 rolled_back 历史，§18.7 retention 事实源）。
    pub async fn list_installation_versions(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<InstallationVersionRecord>, StorageError> {
        let response = self
            .submit(Command::ListInstallationVersions { installation_id })
            .await?;
        match response {
            Response::InstallationVersions(records) => Ok(records),
            _ => Err(unexpected_response("ListInstallationVersions")),
        }
    }

    /// 列出升级/回滚事务标记（§18.5 可观测性）。
    pub async fn list_upgrade_transactions(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<UpgradeTransactionRecord>, StorageError> {
        let response = self
            .submit(Command::ListUpgradeTransactions { installation_id })
            .await?;
        match response {
            Response::UpgradeTransactions(records) => Ok(records),
            _ => Err(unexpected_response("ListUpgradeTransactions")),
        }
    }

    /// 最近审计事件（新→旧；limit ≤ 1000）。
    pub async fn list_audit_recent(&self, limit: usize) -> Result<Vec<AuditRecord>, StorageError> {
        let response = self.submit(Command::ListAuditRecent { limit }).await?;
        match response {
            Response::AuditRecent(events) => Ok(events),
            _ => Err(unexpected_response("ListAuditRecent")),
        }
    }

    // ------------------------------------------------------------------
    // application port 面命令（§24.2：本 crate 实现 application 的
    // ComponentRegistryPort / GrantStorePort；命令语义见仓库方法文档）
    // ------------------------------------------------------------------

    /// 写入 / 更新 digest 主键的 candidate 记录（§19.2 / §12.2）。
    pub async fn upsert_candidate(
        &self,
        record: &operune_application::model::CandidateRecord,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::UpsertCandidate {
                record: record.clone(),
                audit,
            })
            .await?;
        match response {
            Response::CandidateUpserted => Ok(()),
            _ => Err(unexpected_response("UpsertCandidate")),
        }
    }

    /// 推进 candidate 的领域生命周期（§12.2）。
    pub async fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::UpdateCandidateState {
                digest,
                state,
                audit,
            })
            .await?;
        match response {
            Response::CandidateStateUpdated => Ok(()),
            _ => Err(unexpected_response("UpdateCandidateState")),
        }
    }

    /// 读取 digest 主键的 candidate 记录。
    pub async fn get_candidate(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<operune_application::model::CandidateRecord>, StorageError> {
        let response = self.submit(Command::GetCandidate { digest }).await?;
        match response {
            Response::Candidate(record) => Ok(record),
            _ => Err(unexpected_response("GetCandidate")),
        }
    }

    /// 查询 `ComponentId + ComponentVersion` 的既有绑定（§19.4）。
    pub async fn resolve_version(
        &self,
        component_id: ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<operune_application::model::DigestVersionBinding>, StorageError> {
        let response = self
            .submit(Command::ResolveVersion {
                component_id,
                version,
            })
            .await?;
        match response {
            Response::VersionBinding(binding) => Ok(binding),
            _ => Err(unexpected_response("ResolveVersion")),
        }
    }

    /// 以调用方给定的 InstallationId 创建安装实例（§19.4）。
    pub async fn create_installation_with_id(
        &self,
        installation_id: InstallationId,
        component_id: ComponentId,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::CreateInstallationWithId {
                installation_id,
                component_id,
                audit,
            })
            .await?;
        match response {
            Response::InstallationCreatedWithId => Ok(()),
            _ => Err(unexpected_response("CreateInstallationWithId")),
        }
    }

    /// 幂等绑定安装版本（§18.3）。
    pub async fn bind_installation_version_once(
        &self,
        installation_id: InstallationId,
        component_id: ComponentId,
        version: ComponentVersion,
        digest: ContentDigest,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::BindInstallationVersionOnce {
                installation_id,
                component_id,
                version,
                digest,
                audit,
            })
            .await?;
        match response {
            Response::VersionBoundOnce => Ok(()),
            _ => Err(unexpected_response("BindInstallationVersionOnce")),
        }
    }

    /// 按 digest 读取制品字节（§18.7 rollback retention）。
    pub async fn read_artifact_bytes(
        &self,
        digest: ContentDigest,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let response = self.submit(Command::ReadArtifactBytes { digest }).await?;
        match response {
            Response::ArtifactBytes(bytes) => Ok(bytes),
            _ => Err(unexpected_response("ReadArtifactBytes")),
        }
    }

    /// 整体替换安装实例的授权集（§17.5，原子替换）。
    pub async fn replace_grants(
        &self,
        installation_id: InstallationId,
        grants: Vec<(CapabilityId, CapabilityScope)>,
        audit: AuditEvent,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::ReplaceGrants {
                installation_id,
                grants,
                audit,
            })
            .await?;
        match response {
            Response::GrantsReplaced => Ok(()),
            _ => Err(unexpected_response("ReplaceGrants")),
        }
    }

    /// 原子替换某安装实例的全部 graph 记录（§40.2 graph
    /// persistence/recovery；单事务，§18.5：任何中间观不可观察）。
    pub async fn replace_graph_records(
        &self,
        installation_id: InstallationId,
        provider: Option<ProviderRecord>,
        consumer: Option<ConsumerRecord>,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::ReplaceGraphRecords {
                installation_id,
                provider,
                consumer,
            })
            .await?;
        match response {
            Response::GraphRecordsReplaced => Ok(()),
            _ => Err(unexpected_response("ReplaceGraphRecords")),
        }
    }

    /// 加载全部 graph 记录（§40.2 恢复输入；缺失 → 空集，损坏 → fail
    /// closed）。
    pub async fn load_graph_records(&self) -> Result<GraphRecords, StorageError> {
        let response = self.submit(Command::LoadGraphRecords).await?;
        match response {
            Response::GraphRecords(records) => Ok(records),
            _ => Err(unexpected_response("LoadGraphRecords")),
        }
    }

    // ------------------------------------------------------------------
    // 0.3.0 Stateful Runtime（§41.2，migration v4）：state / config / secret
    // 的 executor 层能力。事务协议与取消/crash 语义见模块文档；application
    // 的 port trait（StateStore / SecretStore / ComponentConfigStore）由另一
    // 里程碑定义，trait 落定后按 crate::ports 的既有模式接线。
    // ------------------------------------------------------------------

    /// 读取单键 state（§41.2 快照点读；`None` = 键不存在，WIT not-found）。
    pub async fn get_state(
        &self,
        installation_id: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValueRecord>, StorageError> {
        let response = self
            .submit(Command::GetState {
                installation_id,
                key: key.clone(),
                tx: None,
            })
            .await?;
        match response {
            Response::StateValue(record) => Ok(record),
            _ => Err(unexpected_response("GetState")),
        }
    }

    /// 原子单键 upsert（§41.2 atomic update；CAS 的基础原语——executor
    /// 单连接串行 ⇒ 服务侧 get→compare→put 天然无交错，无需存储层条件写
    /// 原语）。`schema_version` 必须等于 store 当前版本（空 store 首次写入
    /// 建立版本），否则 [`StorageError::SchemaVersionMismatch`]。
    pub async fn put_state(
        &self,
        installation_id: InstallationId,
        key: &StateKey,
        schema_version: StateSchemaVersion,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::PutState {
                installation_id,
                key: key.clone(),
                schema_version: Some(schema_version),
                value,
                tx: None,
            })
            .await?;
        match response {
            Response::StatePut => Ok(()),
            _ => Err(unexpected_response("PutState")),
        }
    }

    /// 删除单键（键不存在 → [`StorageError::NotFound`]，WIT not-found）。
    pub async fn delete_state(
        &self,
        installation_id: InstallationId,
        key: &StateKey,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::DeleteState {
                installation_id,
                key: key.clone(),
                tx: None,
            })
            .await?;
        match response {
            Response::StateDeleted => Ok(()),
            _ => Err(unexpected_response("DeleteState")),
        }
    }

    /// 读取安装实例 state store 的整体 schema 版本（§41.3 确定性；`None`
    /// = 空 store，版本由首次写入建立）。
    pub async fn get_state_schema_version(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<StateSchemaVersion>, StorageError> {
        let response = self
            .submit(Command::GetStateSchemaVersion { installation_id })
            .await?;
        match response {
            Response::StateSchemaVersion(version) => Ok(version),
            _ => Err(unexpected_response("GetStateSchemaVersion")),
        }
    }

    /// 开启 state 事务（§41.2 常规模式：请求版本必须等于 store 当前版本，
    /// 空 store 由首次写入建立）。事务句柄在 executor 内管理；单连接串行
    /// ⇒ 同一时刻至多一个进行中事务（重复 begin →
    /// [`StorageError::StateTransactionConflict`]）。
    pub async fn begin_state_transaction(
        &self,
        installation_id: InstallationId,
        schema_version: StateSchemaVersion,
    ) -> Result<StateTransactionHandle, StorageError> {
        let response = self
            .submit(Command::BeginStateTransaction {
                installation_id,
                schema_version,
                mode: StateTxMode::Normal,
            })
            .await?;
        match response {
            Response::StateTransactionBegan(handle) => Ok(handle),
            _ => Err(unexpected_response("BeginStateTransaction")),
        }
    }

    /// 开启 state **migration** 事务（§41.2 显式 state migration：
    /// 请求版本必须**大于**存储版本，forward-only——0.1.0 不定义已提交
    /// 迁移后的降级，WIT operune:state）。guest `migrate` 成功后 commit 在
    /// **同一事务**内把 store 版本推进到目标版本（§41.3：升级/crash/取消/
    /// 磁盘失败均不得产生"代码版本已切换但状态 schema 不确定"）。
    pub async fn begin_state_migration_transaction(
        &self,
        installation_id: InstallationId,
        to_version: StateSchemaVersion,
    ) -> Result<StateTransactionHandle, StorageError> {
        let response = self
            .submit(Command::BeginStateTransaction {
                installation_id,
                schema_version: to_version,
                mode: StateTxMode::Migration,
            })
            .await?;
        match response {
            Response::StateTransactionBegan(handle) => Ok(handle),
            _ => Err(unexpected_response("BeginStateTransaction")),
        }
    }

    /// 原子提交（§41.2 MUST all-or-nothing）：事务内全部写入一次性生效；
    /// 提交前被取消 ⇒ 事务整体回滚（§18.2，无半状态）。对已终止事务的
    /// commit → [`StorageError::StateTransactionConflict`]（WIT conflict）。
    pub async fn commit_state_transaction(
        &self,
        handle: StateTransactionHandle,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::CommitStateTransaction { handle })
            .await?;
        match response {
            Response::StateCommitted => Ok(()),
            _ => Err(unexpected_response("CommitStateTransaction")),
        }
    }

    /// 放弃事务（WIT：abort 无返回值，对已终止事务是 no-op）。
    pub async fn abort_state_transaction(
        &self,
        handle: StateTransactionHandle,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::AbortStateTransaction { handle })
            .await?;
        match response {
            Response::StateAborted => Ok(()),
            _ => Err(unexpected_response("AbortStateTransaction")),
        }
    }

    /// 事务内读取（快照语义，WIT：事务内读取看到一致性快照）。
    pub async fn state_tx_get(
        &self,
        handle: StateTransactionHandle,
        installation_id: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValueRecord>, StorageError> {
        let response = self
            .submit(Command::GetState {
                installation_id,
                key: key.clone(),
                tx: Some(handle),
            })
            .await?;
        match response {
            Response::StateValue(record) => Ok(record),
            _ => Err(unexpected_response("GetState")),
        }
    }

    /// 事务内写入（行 schema 版本 = 事务绑定版本，§41.2）。
    pub async fn state_tx_put(
        &self,
        handle: StateTransactionHandle,
        installation_id: InstallationId,
        key: &StateKey,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::PutState {
                installation_id,
                key: key.clone(),
                schema_version: None,
                value,
                tx: Some(handle),
            })
            .await?;
        match response {
            Response::StatePut => Ok(()),
            _ => Err(unexpected_response("PutState")),
        }
    }

    /// 事务内删除（键不存在 → [`StorageError::NotFound`]）。
    pub async fn state_tx_delete(
        &self,
        handle: StateTransactionHandle,
        installation_id: InstallationId,
        key: &StateKey,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::DeleteState {
                installation_id,
                key: key.clone(),
                tx: Some(handle),
            })
            .await?;
        match response {
            Response::StateDeleted => Ok(()),
            _ => Err(unexpected_response("DeleteState")),
        }
    }

    /// 读取安装实例的 component config 快照（§41.2；原子：revision 与
    /// value 同行同读，WIT config-snapshot；`None` = 尚无已校验配置）。
    pub async fn get_component_config(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<ComponentConfigRecord>, StorageError> {
        let response = self
            .submit(Command::GetComponentConfig { installation_id })
            .await?;
        match response {
            Response::ComponentConfig(record) => Ok(record),
            _ => Err(unexpected_response("GetComponentConfig")),
        }
    }

    /// 写入/更新 component config（revision +1 原子，§41.2；单调性设计注释
    /// 见 repository.rs）。config 是输入、无平台级 migration（与 state 的
    /// 本质区别）。
    pub async fn put_component_config(
        &self,
        installation_id: InstallationId,
        format: ConfigFormat,
        schema_version: StateSchemaVersion,
        value: Vec<u8>,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::PutComponentConfig {
                installation_id,
                format,
                schema_version,
                value,
            })
            .await?;
        match response {
            Response::ComponentConfigSet => Ok(()),
            _ => Err(unexpected_response("PutComponentConfig")),
        }
    }

    /// 写入/轮换 secret 密文（insert or replace 版本递增，§41.2）。
    ///
    /// **密文边界（§16.6 / ADR-0001，已裁决）**：`ciphertext` 是 SecretStore
    /// 服务侧加密后的**不透明密文 BLOB**——本方法不加密、不解密、不解释
    /// 内容，原样落库；明文与 KEK 绝不进本库；`metadata` 只承载非敏感
    /// 元数据。
    pub async fn put_secret(
        &self,
        installation_id: InstallationId,
        name: &SecretName,
        ciphertext: Vec<u8>,
        metadata: String,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::PutSecret {
                installation_id,
                name: name.clone(),
                ciphertext,
                metadata,
            })
            .await?;
        match response {
            Response::SecretPut => Ok(()),
            _ => Err(unexpected_response("PutSecret")),
        }
    }

    /// 读取 secret 密文（不透明字节原样返回，§16.6：值只在本返回值出现
    /// 一次，绝不进入日志/错误/审计；`None` = 名称不存在）。
    pub async fn get_secret_ciphertext(
        &self,
        installation_id: InstallationId,
        name: &SecretName,
    ) -> Result<Option<SecretRecord>, StorageError> {
        let response = self
            .submit(Command::GetSecretCiphertext {
                installation_id,
                name: name.clone(),
            })
            .await?;
        match response {
            Response::Secret(record) => Ok(record),
            _ => Err(unexpected_response("GetSecretCiphertext")),
        }
    }

    /// 列出安装实例的全部 secret 名称与版本（§41.2 list-granted-secrets
    /// 的存储输入；**不含值**——不读取 ciphertext 列，防泄漏）。
    pub async fn list_secret_names(
        &self,
        installation_id: InstallationId,
    ) -> Result<Vec<SecretMetadata>, StorageError> {
        let response = self
            .submit(Command::ListSecretNames { installation_id })
            .await?;
        match response {
            Response::SecretList(names) => Ok(names),
            _ => Err(unexpected_response("ListSecretNames")),
        }
    }

    /// 删除 secret（名称不存在 → [`StorageError::NotFound`]）。
    pub async fn delete_secret(
        &self,
        installation_id: InstallationId,
        name: &SecretName,
    ) -> Result<(), StorageError> {
        let response = self
            .submit(Command::DeleteSecret {
                installation_id,
                name: name.clone(),
            })
            .await?;
        match response {
            Response::SecretDeleted => Ok(()),
            _ => Err(unexpected_response("DeleteSecret")),
        }
    }
}

impl Drop for StorageExecutor {
    fn drop(&mut self) {
        // 未显式 shutdown 时的有界尽力等待（正式路径必须调用 `shutdown()`）。
        // 关闭 channel 后 worker 排空剩余请求即退出；每个请求耗时都有界
        // （SQLite 短事务 + 有界文件 I/O，§7.4），因此等待有界。
        if let Some(worker) = self.worker.take() {
            self.sender.take(); // 关闭 channel → worker 排空后退出
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !worker.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            // 尽力等待后仍未退出（理论上不可达：每个请求耗时都有界）：
            // 正式路径必须调用 shutdown()（§18.2 shutdown 不 detached）。
            let _still_running = !worker.is_finished();
        }
    }
}

/// worker 线程主体：打开 + migration + recovery，然后串行服务请求。
fn worker_main(
    mut receiver: mpsc::Receiver<Request>,
    config: ExecutorConfig,
    ready: oneshot::Sender<Result<(), StorageError>>,
) {
    // 初始化：打开数据库（fail closed，§18.4）→ recovery（§18.5）。
    let outcome =
        (|| -> Result<(rusqlite::Connection, ArtifactStore, Vec<RecoveryAction>), StorageError> {
            config.data_root.ensure_layout()?;
            let mut conn = open_authoritative_db(&config.data_root.db_path())?;
            let store = ArtifactStore::new(config.data_root.clone(), config.budget);
            let actions = run_recovery(&mut conn, &store)?;
            Ok((conn, store, actions))
        })();
    let (mut conn, store, recovery_report) = match outcome {
        Ok(state) => state,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let _ = ready.send(Ok(()));

    let report = recovery_report;
    // §41.2 state 事务：worker 持有至多一个进行中事务（模块文档；SQLite
    // 事务在连接上，单连接串行 => 事务命令被串行化，§18.2）。
    let mut state_tx: Option<ActiveStateTx> = None;
    let mut tx_counter: u64 = 0;
    while let Some(request) = receiver.blocking_recv() {
        // 执行前取消检查（§18.2：请求在事务提交前被取消则事务不提交）。
        // 进行中的 state 事务随取消请求一并回滚（取消 = caller 已放弃，
        // 事务无法继续；§41.2 取消 → 回滚，无半状态）。
        if request.cancel.load(Ordering::Relaxed) {
            rollback_state_tx(&conn, &mut state_tx);
            let _ = request.reply.send(Err(StorageError::Cancelled));
            continue;
        }
        // §41.2 事务窗口排他：state 事务进行中时只允许 state 命令
        //（其它命令会落入未提交事务并被连带回滚 → 显式拒绝，模块文档）。
        let result = match request.cmd {
            cmd @ (Command::GetState { .. }
            | Command::PutState { .. }
            | Command::DeleteState { .. }
            | Command::GetStateSchemaVersion { .. }
            | Command::BeginStateTransaction { .. }
            | Command::CommitStateTransaction { .. }
            | Command::AbortStateTransaction { .. }
            | Command::GetComponentConfig { .. }
            | Command::PutComponentConfig { .. }
            | Command::PutSecret { .. }
            | Command::GetSecretCiphertext { .. }
            | Command::ListSecretNames { .. }
            | Command::DeleteSecret { .. }) => dispatch_stateful(
                &mut conn,
                &store,
                &mut state_tx,
                &mut tx_counter,
                cmd,
                &request.cancel,
            ),
            _other if state_tx.is_some() => Err(StorageError::StateTransactionConflict(
                "a state transaction is in progress; only state transaction commands are \
                 allowed until commit or abort (single-connection executor, §18.2)"
                    .into(),
            )),
            other => match other {
                Command::RecoveryReport => Ok(Response::RecoveryReport(report.clone())),
                Command::StageBytes { bytes, hard_limit } => Repository::new(&mut conn, &store)
                    .stage_bytes(&bytes, hard_limit)
                    .map(Response::Staged),
                Command::RecordQuarantine { staged, audit } => Repository::new(&mut conn, &store)
                    .record_quarantine(&staged, &audit, &request.cancel)
                    .map(|()| Response::Quarantined),
                Command::CommitCandidate {
                    digest,
                    component_id,
                    version,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .commit_candidate(digest, component_id, version, &audit, &request.cancel)
                    .map(|()| Response::CandidateCommitted),
                Command::CreateInstallation {
                    component_id,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .create_installation(component_id, &audit, &request.cancel)
                    .map(Response::InstallationCreated),
                Command::BindInstallationVersion {
                    installation_id,
                    component_id,
                    version,
                    digest,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .bind_installation_version(
                        installation_id,
                        component_id,
                        version,
                        digest,
                        &audit,
                        &request.cancel,
                    )
                    .map(|()| Response::VersionBound),
                Command::ApplyLifecycleEvent {
                    installation_id,
                    event,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .apply_lifecycle_event(installation_id, event, &audit, &request.cancel)
                    .map(Response::LifecycleAdvanced),
                Command::SwitchActiveVersion {
                    installation_id,
                    version,
                    digest,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .switch_active_version(
                        installation_id,
                        version,
                        digest,
                        &audit,
                        &request.cancel,
                    )
                    .map(Response::VersionSwitched),
                Command::RollbackVersion {
                    installation_id,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .rollback_version(installation_id, &audit, &request.cancel)
                    .map(Response::RollbackPerformed),
                Command::SetInstallationEnabled {
                    installation_id,
                    enabled,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .set_installation_enabled(installation_id, enabled, &audit, &request.cancel)
                    .map(|()| Response::Enabled),
                Command::RemoveInstallation {
                    installation_id,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .remove_installation(installation_id, &audit, &request.cancel)
                    .map(|()| Response::Removed),
                Command::GrantCapability {
                    installation_id,
                    capability_id,
                    scope,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .grant_capability(
                        installation_id,
                        capability_id,
                        scope,
                        &audit,
                        &request.cancel,
                    )
                    .map(|()| Response::Granted),
                Command::RevokeCapability {
                    installation_id,
                    capability_id,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .revoke_capability(installation_id, capability_id, &audit, &request.cancel)
                    .map(|()| Response::Revoked),
                Command::ListGrants { installation_id } => Repository::new(&mut conn, &store)
                    .list_grants(installation_id)
                    .map(Response::Grants),
                Command::CreateUser {
                    username,
                    password_hash,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .create_user(&username, &password_hash, &audit, &request.cancel)
                    .map(Response::UserCreated),
                Command::GetUserByUsername { username } => Repository::new(&mut conn, &store)
                    .get_user_by_username(&username)
                    .map(Response::User),
                Command::GetUser { user_id } => Repository::new(&mut conn, &store)
                    .get_user(user_id)
                    .map(Response::User),
                Command::UpdatePasswordHash {
                    user_id,
                    new_hash,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .update_password_hash(user_id, &new_hash, &audit, &request.cancel)
                    .map(|()| Response::PasswordUpdated),
                Command::SetUserDisabled {
                    user_id,
                    disabled,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .set_user_disabled(user_id, disabled, &audit, &request.cancel)
                    .map(|()| Response::UserDisabled),
                Command::CreateSession {
                    user_id,
                    token_digest,
                    absolute_expires_at,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .create_session(
                        user_id,
                        token_digest,
                        absolute_expires_at,
                        &audit,
                        &request.cancel,
                    )
                    .map(Response::SessionCreated),
                Command::LookupSession { token_digest } => Repository::new(&mut conn, &store)
                    .lookup_session(token_digest)
                    .map(Response::Session),
                Command::TouchSession { session_id } => Repository::new(&mut conn, &store)
                    .touch_session(session_id)
                    .map(|()| Response::SessionTouched),
                Command::RevokeSession { session_id, audit } => Repository::new(&mut conn, &store)
                    .revoke_session(session_id, &audit, &request.cancel)
                    .map(|()| Response::SessionRevoked),
                Command::RevokeAllUserSessions { user_id, audit } => {
                    Repository::new(&mut conn, &store)
                        .revoke_all_user_sessions(user_id, &audit, &request.cancel)
                        .map(Response::SessionsRevoked)
                }
                Command::AppendAudit { audit } => Repository::new(&mut conn, &store)
                    .append_audit(&audit)
                    .map(Response::AuditAppended),
                Command::SetConfig { key, value, audit } => Repository::new(&mut conn, &store)
                    .set_config(&key, &value, &audit, &request.cancel)
                    .map(|()| Response::ConfigSet),
                Command::GetConfig { key } => Repository::new(&mut conn, &store)
                    .get_config(&key)
                    .map(Response::Config),
                Command::ListConfig => Repository::new(&mut conn, &store)
                    .list_config()
                    .map(Response::ConfigList),
                Command::Gc { policy } => Repository::new(&mut conn, &store)
                    .gc(policy)
                    .map(Response::GcPerformed),
                Command::GetBudgetUsage => Repository::new(&mut conn, &store)
                    .budget_usage()
                    .map(Response::BudgetUsage),
                Command::ArtifactExists { digest } => Repository::new(&mut conn, &store)
                    .artifact_exists(digest)
                    .map(Response::ArtifactExists),
                Command::GetArtifact { digest } => Repository::new(&mut conn, &store)
                    .get_artifact(digest)
                    .map(Response::Artifact),
                Command::GetInstallation { installation_id } => Repository::new(&mut conn, &store)
                    .get_installation(installation_id)
                    .map(Response::Installation),
                Command::ListInstallations => Repository::new(&mut conn, &store)
                    .list_installations()
                    .map(Response::Installations),
                Command::GetActiveBinding { installation_id } => Repository::new(&mut conn, &store)
                    .get_active_binding(installation_id)
                    .map(Response::ActiveBinding),
                Command::ListInstallationVersions { installation_id } => {
                    Repository::new(&mut conn, &store)
                        .list_installation_versions(installation_id)
                        .map(Response::InstallationVersions)
                }
                Command::ListUpgradeTransactions { installation_id } => {
                    Repository::new(&mut conn, &store)
                        .list_upgrade_transactions(installation_id)
                        .map(Response::UpgradeTransactions)
                }
                Command::ListAuditRecent { limit } => Repository::new(&mut conn, &store)
                    .list_audit_recent(limit)
                    .map(Response::AuditRecent),
                Command::UpsertCandidate { record, audit } => Repository::new(&mut conn, &store)
                    .upsert_candidate(&record, &audit, &request.cancel)
                    .map(|()| Response::CandidateUpserted),
                Command::UpdateCandidateState {
                    digest,
                    state,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .update_candidate_state(digest, state, &audit, &request.cancel)
                    .map(|()| Response::CandidateStateUpdated),
                Command::GetCandidate { digest } => Repository::new(&mut conn, &store)
                    .get_candidate(digest)
                    .map(Response::Candidate),
                Command::ResolveVersion {
                    component_id,
                    version,
                } => Repository::new(&mut conn, &store)
                    .resolve_version(&component_id, version)
                    .map(Response::VersionBinding),
                Command::CreateInstallationWithId {
                    installation_id,
                    component_id,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .create_installation_with_id(
                        installation_id,
                        component_id,
                        &audit,
                        &request.cancel,
                    )
                    .map(|()| Response::InstallationCreatedWithId),
                Command::BindInstallationVersionOnce {
                    installation_id,
                    component_id,
                    version,
                    digest,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .bind_installation_version_once(
                        installation_id,
                        component_id,
                        version,
                        digest,
                        &audit,
                        &request.cancel,
                    )
                    .map(|()| Response::VersionBoundOnce),
                Command::ReadArtifactBytes { digest } => Repository::new(&mut conn, &store)
                    .read_artifact_bytes(digest)
                    .map(Response::ArtifactBytes),
                Command::ReplaceGrants {
                    installation_id,
                    grants,
                    audit,
                } => Repository::new(&mut conn, &store)
                    .replace_grants(installation_id, &grants, &audit, &request.cancel)
                    .map(|()| Response::GrantsReplaced),
                Command::ReplaceGraphRecords {
                    installation_id,
                    provider,
                    consumer,
                } => Repository::new(&mut conn, &store)
                    .replace_graph_records(
                        installation_id,
                        provider.as_ref(),
                        consumer.as_ref(),
                        &request.cancel,
                    )
                    .map(|()| Response::GraphRecordsReplaced),
                Command::LoadGraphRecords => Repository::new(&mut conn, &store)
                    .load_graph_records()
                    .map(Response::GraphRecords),
                #[cfg(test)]
                Command::TestGate { entered, release } => {
                    let _ = entered.send(());
                    let _ = release.blocking_recv();
                    continue;
                }
                // 0.3.0 stateful 命令由外层 match 的 dispatch_stateful 分流
                //（§41.2）；本臂只为穷尽性存在——到达即内部不变量违反
                //（fail closed，§18.4）。
                _ => Err(unexpected_response(
                    "stateful command reached the main dispatch",
                )),
            },
        };
        let _ = request.reply.send(result);
    }
    // worker 退出：进行中的 state 事务显式回滚（§18.5：crash/关闭时未提交
    // 事务自然回滚——WAL 只重放已提交帧；此处显式化，连接关闭也兜底）。
    rollback_state_tx(&conn, &mut state_tx);
}

/// 尽力回滚进行中的 state 事务（§18.5：未提交事务回滚；失败保留连接状态，
/// 由连接关闭兜底——crash 时 SQLite 自然回滚）。
fn rollback_state_tx(conn: &rusqlite::Connection, state_tx: &mut Option<ActiveStateTx>) {
    if state_tx.is_some() {
        let _ = conn.execute_batch("ROLLBACK");
        *state_tx = None;
    }
}

/// 校验 state 命令的事务句柄/安装实例匹配进行中的事务（§41.2：对已终止
/// 事务的操作 = conflict，WIT operune:state）。
///
/// `Ok(Some(active))` = 在事务内执行（句柄与安装匹配）；`Ok(None)` = 事务外
/// 执行（`tx` 必须为 `None`）；任一不匹配 → [`StorageError::StateTransactionConflict`]。
fn require_active_tx(
    state_tx: &Option<ActiveStateTx>,
    tx: Option<StateTransactionHandle>,
    installation_id: InstallationId,
) -> Result<Option<ActiveStateTx>, StorageError> {
    match state_tx {
        Some(active) => {
            if tx.map(StateTransactionHandle::as_u64) != Some(active.handle)
                || active.installation_id != installation_id
            {
                return Err(StorageError::StateTransactionConflict(format!(
                    "operation on a state transaction that is not in progress for installation \
                     {installation_id} (terminated, aborted, or unknown handle)"
                )));
            }
            Ok(Some(active.clone()))
        }
        None => {
            if tx.is_some() {
                return Err(StorageError::StateTransactionConflict(
                    "operation on a state transaction that is not in progress (already \
                     committed or aborted, or unknown handle)"
                        .into(),
                ));
            }
            Ok(None)
        }
    }
}

/// 分发 state/config/secret 命令（§41.2，migration v4）。事务协议见模块
/// 文档：`state_tx` 为 worker 持有的至多一个进行中事务；事务命令在
/// `BEGIN IMMEDIATE` 与 `COMMIT`/`ROLLBACK` 之间直接执行于连接上
/// （repository 的 `tx_*` 方法，不套 `run_tx`——外层事务就是原子性边界）。
fn dispatch_stateful(
    conn: &mut rusqlite::Connection,
    store: &ArtifactStore,
    state_tx: &mut Option<ActiveStateTx>,
    tx_counter: &mut u64,
    cmd: Command,
    cancel: &AtomicBool,
) -> Result<Response, StorageError> {
    match cmd {
        Command::GetState {
            installation_id,
            key,
            tx,
        } => {
            let active = require_active_tx(state_tx, tx, installation_id)?;
            let record = match active {
                Some(_) => Repository::new(conn, store).tx_get_state(installation_id, &key)?,
                None => Repository::new(conn, store).get_state(installation_id, &key)?,
            };
            Ok(Response::StateValue(record))
        }
        Command::PutState {
            installation_id,
            key,
            schema_version,
            value,
            tx,
        } => {
            let active = require_active_tx(state_tx, tx, installation_id)?;
            match active {
                Some(active) => {
                    // 事务内写入：版本绑定于事务（单一事实源，§41.2）——
                    // 禁止另传版本（调用方契约违反，fail closed）。
                    if schema_version.is_some() {
                        return Err(StorageError::InvalidArgument(
                            "state puts inside a transaction bind the transaction's schema \
                             version; do not pass schema_version"
                                .into(),
                        ));
                    }
                    // 取消 → 事务整体回滚（§18.2 提交前取消检查；无半状态）。
                    if cancel.load(Ordering::Relaxed) {
                        rollback_state_tx(conn, state_tx);
                        return Err(StorageError::Cancelled);
                    }
                    let outcome = Repository::new(conn, store).tx_put_state(
                        installation_id,
                        &key,
                        active.schema_version,
                        &value,
                    );
                    // 标记 dirty：commit 时写入/推进 schema marker（§41.3）。
                    if outcome.is_ok()
                        && let Some(active) = state_tx.as_mut()
                    {
                        active.dirty = true;
                    }
                    outcome.map(|()| Response::StatePut)
                }
                None => {
                    let version = schema_version.ok_or_else(|| {
                        StorageError::InvalidArgument(
                            "schema_version is required for a standalone state put".into(),
                        )
                    })?;
                    Repository::new(conn, store)
                        .put_state(installation_id, &key, version, &value, cancel)
                        .map(|()| Response::StatePut)
                }
            }
        }
        Command::DeleteState {
            installation_id,
            key,
            tx,
        } => {
            let active = require_active_tx(state_tx, tx, installation_id)?;
            match active {
                Some(_) => {
                    if cancel.load(Ordering::Relaxed) {
                        rollback_state_tx(conn, state_tx);
                        return Err(StorageError::Cancelled);
                    }
                    let outcome =
                        Repository::new(conn, store).tx_delete_state(installation_id, &key);
                    if outcome.is_ok()
                        && let Some(active) = state_tx.as_mut()
                    {
                        active.dirty = true;
                    }
                    outcome.map(|()| Response::StateDeleted)
                }
                None => {
                    check_cancel(cancel)?;
                    Repository::new(conn, store)
                        .delete_state(installation_id, &key, cancel)
                        .map(|()| Response::StateDeleted)
                }
            }
        }
        Command::GetStateSchemaVersion { installation_id } => {
            let version = Repository::new(conn, store).get_state_schema_version(installation_id)?;
            Ok(Response::StateSchemaVersion(version))
        }
        Command::BeginStateTransaction {
            installation_id,
            schema_version,
            mode,
        } => {
            // 单连接串行（§18.2）：至多一个进行中事务（SQLite 事务在连接上）。
            if state_tx.is_some() {
                return Err(StorageError::StateTransactionConflict(
                    "a state transaction is already in progress; commit or abort it first \
                     (single-connection executor allows at most one, §18.2)"
                        .into(),
                ));
            }
            // 版本校验（§41.2/§41.3）：Normal 必须等于存储版本（空 store
            // 由首次写入建立）；Migration 必须前进（forward-only，WIT）。
            let current = Repository::new(conn, store).get_state_schema_version(installation_id)?;
            match mode {
                StateTxMode::Normal => {
                    if let Some(current) = current
                        && current != schema_version
                    {
                        return Err(StorageError::SchemaVersionMismatch {
                            installation: installation_id,
                            expected: current,
                            requested: schema_version,
                        });
                    }
                }
                StateTxMode::Migration => {
                    let current = current.ok_or_else(|| {
                        StorageError::InvalidArgument(
                            "cannot migrate an empty state store (no schema version \
                             established)"
                                .into(),
                        )
                    })?;
                    if schema_version <= current {
                        return Err(StorageError::SchemaVersionMismatch {
                            installation: installation_id,
                            expected: current,
                            requested: schema_version,
                        });
                    }
                }
            }
            // BEGIN IMMEDIATE：立即取写锁（WAL 下不阻塞并发读者；单连接串行
            // 无锁竞争，§18.2）。取消 → 不开启（BEGIN 前检查一次）。
            check_cancel(cancel)?;
            conn.execute_batch("BEGIN IMMEDIATE")
                .map_err(|e| StorageError::sqlite("begin state transaction", e))?;
            *tx_counter = tx_counter.saturating_add(1);
            let handle = StateTransactionHandle::new(*tx_counter);
            *state_tx = Some(ActiveStateTx {
                handle: *tx_counter,
                installation_id,
                schema_version,
                dirty: false,
            });
            Ok(Response::StateTransactionBegan(handle))
        }
        Command::CommitStateTransaction { handle } => {
            // 对已终止事务的 commit = conflict（WIT）。
            let active = state_tx
                .as_ref()
                .filter(|active| active.handle == handle.as_u64())
                .cloned()
                .ok_or_else(|| {
                    StorageError::StateTransactionConflict(
                        "commit on a state transaction that is not in progress (already \
                         committed or aborted, or unknown handle)"
                            .into(),
                    )
                })?;
            // 提交前取消检查（§18.2）：提交前被取消 ⇒ 事务不提交（整体回滚）。
            if cancel.load(Ordering::Relaxed) {
                rollback_state_tx(conn, state_tx);
                return Err(StorageError::Cancelled);
            }
            // 最终化 + 提交：schema marker 与数据在同一事务内原子提交
            //（§41.3：升级/crash/取消/磁盘失败不得产生"代码版本已切换但
            // 状态 schema 不确定"）。
            let mut outcome = if active.dirty {
                Repository::new(conn, store)
                    .tx_finalize(active.installation_id, active.schema_version)
            } else {
                Ok(())
            };
            if outcome.is_ok() {
                outcome = conn
                    .execute_batch("COMMIT")
                    .map_err(|e| StorageError::sqlite("commit state transaction", e));
            }
            if outcome.is_err() {
                // COMMIT 失败（磁盘/锁）：事务整体回滚（§18.5：已提交事务
                // 崩溃后仍然存在；未提交事务回滚）——绝不产生"部分提交"。
                rollback_state_tx(conn, state_tx);
                return outcome.map(|()| Response::StateCommitted);
            }
            *state_tx = None;
            Ok(Response::StateCommitted)
        }
        Command::AbortStateTransaction { handle } => {
            // WIT：abort 无返回值；对已终止事务是 no-op（含未知句柄）。
            let in_progress = state_tx
                .as_ref()
                .map(|active| active.handle == handle.as_u64())
                .unwrap_or(false);
            if !in_progress {
                return Ok(Response::StateAborted);
            }
            conn.execute_batch("ROLLBACK")
                .map_err(|e| StorageError::sqlite("abort state transaction", e))?;
            *state_tx = None;
            Ok(Response::StateAborted)
        }
        Command::GetComponentConfig { installation_id } => {
            let record = Repository::new(conn, store).get_component_config(installation_id)?;
            Ok(Response::ComponentConfig(record))
        }
        Command::PutComponentConfig {
            installation_id,
            format,
            schema_version,
            value,
        } => {
            check_cancel(cancel)?;
            Repository::new(conn, store)
                .put_component_config(installation_id, format, schema_version, &value, cancel)
                .map(|()| Response::ComponentConfigSet)
        }
        Command::PutSecret {
            installation_id,
            name,
            ciphertext,
            metadata,
        } => {
            check_cancel(cancel)?;
            Repository::new(conn, store)
                .put_secret(installation_id, &name, &ciphertext, &metadata, cancel)
                .map(|()| Response::SecretPut)
        }
        Command::GetSecretCiphertext {
            installation_id,
            name,
        } => {
            let record = Repository::new(conn, store).get_secret(installation_id, &name)?;
            Ok(Response::Secret(record))
        }
        Command::ListSecretNames { installation_id } => {
            let names = Repository::new(conn, store).list_secret_names(installation_id)?;
            Ok(Response::SecretList(names))
        }
        Command::DeleteSecret {
            installation_id,
            name,
        } => {
            check_cancel(cancel)?;
            Repository::new(conn, store)
                .delete_secret(installation_id, &name, cancel)
                .map(|()| Response::SecretDeleted)
        }
        // 其它命令不在本分发器（worker 主 match 已按命令族分流）。
        other => Err(unexpected_response(&format!(
            "dispatch_stateful received non-stateful command {:?}",
            std::mem::discriminant(&other)
        ))),
    }
}

/// 内部不变量违反（不可能发生的响应错配）。
fn unexpected_response(expected: &str) -> StorageError {
    StorageError::CorruptState(format!(
        "internal error: unexpected response type for command {expected}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::open_authoritative_db;
    use crate::model::{AuditEvent, UpgradePhase};
    use crate::model::{CapabilityScope, Timestamp};
    use crate::recovery::RecoveryAction;
    use crate::testutil::{
        audit, component_id, data_root, err, ok, some, some_ok, tempdir, unit_ok,
    };
    use operune_domain::{
        ByteSize, CapabilityId, ComponentLifecycleEvent, ComponentVersion, ContentDigest,
    };
    use rusqlite::OptionalExtension;

    fn config(dir: &std::path::Path) -> ExecutorConfig {
        ok(ExecutorConfig::new(data_root(dir)), "executor config")
    }

    async fn open_executor(dir: &std::path::Path) -> StorageExecutor {
        ok(StorageExecutor::open(config(dir)).await, "open executor")
    }

    fn version(v: &str) -> ComponentVersion {
        ok(v.parse::<ComponentVersion>(), "parse version")
    }

    fn future(offset_secs: u64) -> Timestamp {
        Timestamp::from_unix_seconds(
            ok(Timestamp::now(), "now")
                .as_unix_seconds()
                .saturating_add(offset_secs),
        )
    }

    /// 把 worker 阻塞在 gate 上（确定性验证有界队列 / 取消 / 排空语义）。
    /// 返回 release sender（worker 进入等待后立即返回）。
    async fn gate(ex: &StorageExecutor) -> tokio::sync::oneshot::Sender<()> {
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        ok(
            ex.try_submit(Command::TestGate {
                entered: entered_tx,
                release: release_rx,
            }),
            "submit gate",
        );
        ok(entered_rx.await, "gate entered");
        release_tx
    }

    #[tokio::test]
    async fn open_fresh_reports_clean_recovery_and_shutdown() {
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let report = ok(ex.recovery_report().await, "recovery report");
        assert!(report.is_empty(), "fresh open must need no recovery");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn open_fails_closed_when_data_root_is_not_a_directory() {
        let dir = tempdir();
        // data_root 本身是一个文件 → ensure_layout 失败（fail closed，§18.0）。
        let file_path = dir.path().join("not-a-dir");
        ok(std::fs::write(&file_path, b"x"), "write file");
        let root = ok(DataRoot::new(file_path), "data root");
        let cfg = ok(ExecutorConfig::new(root), "config");
        let error = err(StorageExecutor::open(cfg).await, "open over file");
        assert!(matches!(error, StorageError::Io { .. }));
    }

    /// Arc 形式的显式 shutdown（所有任务 join 后引用计数为 1）。
    async fn shutdown_arc(ex: std::sync::Arc<StorageExecutor>) -> Result<(), StorageError> {
        match std::sync::Arc::try_unwrap(ex) {
            Ok(inner) => inner.shutdown().await,
            Err(_) => Err(StorageError::InvalidArgument(
                "executor still shared; cannot shutdown".into(),
            )),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_requests_serialize_correctly() {
        // §18.2：多个并发请求串行化正确性（单连接 worker）。
        let dir = tempdir();
        let ex = std::sync::Arc::new(open_executor(dir.path()).await);
        let mut handles = Vec::new();
        for i in 0..32 {
            let ex = std::sync::Arc::clone(&ex);
            handles.push(tokio::spawn(async move {
                ex.set_config(
                    format!("key-{i}"),
                    format!("value-{i}"),
                    audit("config set"),
                )
                .await
            }));
        }
        for handle in handles {
            let result = ok(handle.await, "join task");
            ok(result, "set_config");
        }
        let entries = ok(ex.list_config().await, "list config");
        assert_eq!(
            entries.len(),
            32,
            "all 32 concurrent writes must be serialized and applied"
        );
        ok(shutdown_arc(ex).await, "shutdown");
    }

    #[tokio::test]
    async fn bounded_queue_rejects_when_full() {
        // §15.2 / §18.2：有界请求队列，满 → QueueFull（无 unbounded queue）。
        let dir = tempdir();
        let mut cfg = config(dir.path());
        cfg.queue_capacity = some(NonZeroUsize::new(2), "capacity");
        let ex = ok(StorageExecutor::open(cfg).await, "open executor");
        let release = gate(&ex).await;
        // worker 被 gate 阻塞 → 队列容量 2：前两个成功，第三个 QueueFull。
        ok(ex.try_submit(Command::GetBudgetUsage), "fill 1");
        ok(ex.try_submit(Command::GetBudgetUsage), "fill 2");
        let error = err(ex.try_submit(Command::GetBudgetUsage), "queue overflow");
        assert!(matches!(error, StorageError::QueueFull));
        // 释放 gate → 排空。
        unit_ok(release.send(()), "release gate");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn cancelled_request_before_commit_leaves_no_state() {
        // §18.2 取消语义：请求在事务提交前被取消 → 事务不提交。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let release = gate(&ex).await;
        // 排队一个 set_config，随后置位取消探针。
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        ok(
            ex.try_submit_request(Request {
                cmd: Command::SetConfig {
                    key: "cancelled.key".into(),
                    value: "must-not-exist".into(),
                    audit: audit("cancelled"),
                },
                cancel: cancel.clone(),
                reply: reply_tx,
            }),
            "submit queued request",
        );
        cancel.store(true, Ordering::Relaxed);
        unit_ok(release.send(()), "release gate");
        let result = ok(reply_rx.await, "reply");
        assert!(
            matches!(result, Err(StorageError::Cancelled)),
            "expected Cancelled, got {result:?}"
        );
        assert!(
            ok(ex.get_config("cancelled.key".into()).await, "get config").is_none(),
            "cancelled request must not commit"
        );
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn aborted_task_cancels_queued_request() {
        // 结构化取消：caller future 被 drop → RAII 探针置位 → 队列中请求被取消
        // （§18.2）。确定性驱动（§26.5，不用 sleep 猜测时序）：
        //   1. `sent` 信号 = 请求已入队（gate 阻塞 worker，请求停留在队列）；
        //   2. `task.await` = join 完成 ⇒ 运行时已 drop 任务 future ⇒
        //      CancelGuard 已置位探针。`task.abort()` 只标记任务，future 的
        //      drop 是异步的——若在 worker 的取消检查前尚未 drop，请求会带
        //      未置位探针执行（旧版间歇失败根因）。join 完成保证 guard 的
        //      drop 先于 gate 释放，任何交错下都断言同一不变量。
        let dir = tempdir();
        let ex = std::sync::Arc::new(open_executor(dir.path()).await);
        let release = gate(&ex).await;
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let task = {
            let ex = std::sync::Arc::clone(&ex);
            tokio::spawn(async move {
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let cancel = Arc::new(AtomicBool::new(false));
                // RAII 取消 guard：本 future 被 drop（abort）即置位探针。
                let _cancel_guard = CancelGuard(cancel.clone());
                ex.try_submit_request(Request {
                    cmd: Command::SetConfig {
                        key: "aborted.key".into(),
                        value: "x".into(),
                        audit: audit("aborted"),
                    },
                    cancel,
                    reply: reply_tx,
                })?;
                let _ = sent_tx.send(());
                let _ = reply_rx.await;
                Ok::<(), StorageError>(())
            })
        };
        // 同步点 1：请求已入队（worker 仍被 gate 阻塞，请求留在队列中）。
        ok(sent_rx.await, "request enqueued");
        task.abort();
        // 同步点 2：join 完成 ⇒ 任务 future 已被 drop ⇒ 探针已置位。
        let join = task.await;
        assert!(
            matches!(&join, Err(error) if error.is_cancelled()),
            "aborted task must report cancellation, got {join:?}"
        );
        unit_ok(release.send(()), "release gate");
        assert!(
            ok(ex.get_config("aborted.key".into()).await, "get config").is_none(),
            "aborted request must not commit"
        );
        ok(shutdown_arc(ex).await, "shutdown");
    }

    #[tokio::test]
    async fn shutdown_drains_queued_requests() {
        // §18.2：shutdown 必须等待已接纳请求完成，不 detached。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let release = gate(&ex).await;
        let r1 = ok(ex.try_submit(Command::GetBudgetUsage), "queued 1");
        let r2 = ok(ex.try_submit(Command::GetBudgetUsage), "queued 2");
        let shutdown = tokio::spawn(async move { ex.shutdown().await });
        // shutdown 等待 gate 释放后 worker 排空退出。
        unit_ok(release.send(()), "release gate");
        let result = ok(shutdown.await, "join shutdown task");
        ok(result, "shutdown");
        // 已接纳请求得到响应（drain 语义）。
        let _resp1 = ok(r1.await, "reply 1");
        let _resp2 = ok(r2.await, "reply 2");
    }

    #[tokio::test]
    async fn executor_full_lifecycle_smoke() {
        // 通过 executor 公开 API 走完整安装/激活/审计/会话路径。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let cid = component_id("smoke");
        let v1 = version("1.0.0");
        let limit = ok(ByteSize::mib(16), "limit");
        let staged = ok(
            ex.stage_bytes(b"smoke-component".to_vec(), limit).await,
            "stage",
        );
        ok(
            ex.record_quarantine(staged.clone(), audit("quarantine"))
                .await,
            "quarantine",
        );
        ok(
            ex.commit_candidate(staged.digest, cid.clone(), v1, audit("candidate"))
                .await,
            "candidate",
        );
        let inst = ok(
            ex.create_installation(cid.clone(), audit("install")).await,
            "install",
        );
        ok(
            ex.bind_installation_version(inst, cid.clone(), v1, staged.digest, audit("bind"))
                .await,
            "bind",
        );
        ok(
            ex.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ValidationSucceeded,
                audit("v"),
            )
            .await,
            "validate",
        );
        ok(
            ex.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ActivationRequested,
                audit("a"),
            )
            .await,
            "activate",
        );
        ok(
            ex.apply_lifecycle_event(
                inst,
                ComponentLifecycleEvent::ReadinessSucceeded,
                audit("r"),
            )
            .await,
            "readiness",
        );
        ok(
            ex.set_installation_enabled(inst, true, audit("enable"))
                .await,
            "enable",
        );
        let binding = ok(
            ex.switch_active_version(inst, v1, staged.digest, audit("switch"))
                .await,
            "switch",
        );
        assert_eq!(binding.component_version, v1);
        // 能力授权。
        ok(
            ex.grant_capability(
                inst,
                ok(CapabilityId::new("wasi:http/outgoing-handler"), "cap"),
                ok(CapabilityScope::new("https://example.test"), "scope"),
                audit("grant"),
            )
            .await,
            "grant",
        );
        // 用户 + session（digest 形式）。
        let user = ok(
            ex.create_user(
                "admin".into(),
                "argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                audit("create user"),
            )
            .await,
            "create user",
        );
        let token = ContentDigest::from_bytes(b"smoke-token");
        let session = ok(
            ex.create_session(user, token, future(3600), audit("session"))
                .await,
            "create session",
        );
        let record = some(
            ok(ex.lookup_session(token).await, "lookup session"),
            "session record",
        );
        assert_eq!(record.session_id, session);
        // 审计可读。
        let events = ok(ex.list_audit_recent(100).await, "audit");
        assert!(events.len() >= 12);
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn reopen_recovers_interrupted_switch() {
        // §18.5 端到端：崩溃（prepared marker）→ 重新打开 → recovery 恢复旧版。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let cid = component_id("crash-recover");
        let v1 = version("1.0.0");
        let v2 = version("2.0.0");
        let limit = ok(ByteSize::mib(16), "limit");
        let s1 = ok(
            ex.stage_bytes(b"v1-bytes".to_vec(), limit).await,
            "stage v1",
        );
        ok(
            ex.record_quarantine(s1.clone(), audit("q1")).await,
            "quarantine v1",
        );
        ok(
            ex.commit_candidate(s1.digest, cid.clone(), v1, audit("c1"))
                .await,
            "candidate v1",
        );
        let inst = ok(
            ex.create_installation(cid.clone(), audit("install")).await,
            "install",
        );
        ok(
            ex.bind_installation_version(inst, cid.clone(), v1, s1.digest, audit("b1"))
                .await,
            "bind v1",
        );
        for event in [
            ComponentLifecycleEvent::ValidationSucceeded,
            ComponentLifecycleEvent::ActivationRequested,
            ComponentLifecycleEvent::ReadinessSucceeded,
        ] {
            ok(
                ex.apply_lifecycle_event(inst, event, audit("lifecycle"))
                    .await,
                "lifecycle event",
            );
        }
        ok(
            ex.switch_active_version(inst, v1, s1.digest, audit("switch1"))
                .await,
            "switch v1",
        );
        let s2 = ok(
            ex.stage_bytes(b"v2-bytes".to_vec(), limit).await,
            "stage v2",
        );
        ok(
            ex.record_quarantine(s2.clone(), audit("q2")).await,
            "quarantine v2",
        );
        ok(
            ex.commit_candidate(s2.digest, cid.clone(), v2, audit("c2"))
                .await,
            "candidate v2",
        );
        ok(
            ex.bind_installation_version(inst, cid, v2, s2.digest, audit("b2"))
                .await,
            "bind v2",
        );
        // 崩溃模拟：正常关闭后手工插入 prepared marker（阶段 A 已提交）。
        ok(ex.shutdown().await, "shutdown");
        let root = data_root(dir.path());
        let conn = ok(open_authoritative_db(&root.db_path()), "raw reopen");
        let now = ok(ok(Timestamp::now(), "now").sql_value(), "sql value");
        ok(
            conn.execute(
                "INSERT INTO upgrade_transactions
                     (installation_id, from_component_version, from_content_digest,
                      to_component_version, to_content_digest, phase, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'prepared', ?6)",
                rusqlite::params![
                    inst.to_string(),
                    v1.to_string(),
                    s1.digest.to_string(),
                    v2.to_string(),
                    s2.digest.to_string(),
                    now
                ],
            ),
            "insert prepared marker (crash simulation)",
        );
        drop(conn);
        // 重新打开 → recovery 自动执行（§18.5）。
        let ex2 = open_executor(dir.path()).await;
        let report = ok(ex2.recovery_report().await, "recovery report");
        assert_eq!(report.len(), 1);
        assert!(matches!(
            &report[0],
            RecoveryAction::SwitchRolledBack { to_version, .. } if *to_version == v2
        ));
        let binding = some(
            ok(ex2.get_active_binding(inst).await, "active binding"),
            "binding",
        );
        assert_eq!(
            binding.component_version, v1,
            "old version must be restored"
        );
        let markers = ok(ex2.list_upgrade_transactions(inst).await, "markers");
        assert!(
            markers.iter().all(|m| m.phase != UpgradePhase::Prepared),
            "no prepared marker may survive"
        );
        ok(ex2.shutdown().await, "shutdown 2");
    }

    #[tokio::test]
    async fn executor_open_validates_schema_version() {
        // §18.4：打开时校验 schema version，不匹配 fail closed。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        ok(ex.shutdown().await, "shutdown");
        let root = data_root(dir.path());
        let conn = ok(open_authoritative_db(&root.db_path()), "raw open");
        ok(
            conn.execute("UPDATE schema_version SET version = 99 WHERE id = 1", []),
            "bump schema version",
        );
        drop(conn);
        let error = err(
            StorageExecutor::open(config(dir.path())).await,
            "reopen with newer schema",
        );
        assert!(
            matches!(error, StorageError::SchemaTooNew { db: 99, current: 4 }),
            "expected SchemaTooNew, got {error:?}"
        );
    }

    #[tokio::test]
    async fn dropped_executor_releases_database_lock() {
        // Drop 路径的有界等待：worker 退出后数据库不残留文件锁。
        let dir = tempdir();
        {
            let ex = open_executor(dir.path()).await;
            ok(
                ex.set_config("k".into(), "v".into(), audit("config set"))
                    .await,
                "set config",
            );
            drop(ex);
        }
        let ex2 = open_executor(dir.path()).await;
        let entry = some_ok(ex2.get_config("k".into()).await, "get config");
        assert_eq!(entry.value, "v");
        ok(ex2.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn audit_via_executor_is_durable_and_typed() {
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let event = ok(
            AuditEvent::new(
                crate::model::AuditActor::System,
                crate::model::AuditCategory::Auth,
                "login-failed",
                None,
                crate::model::AuditOutcome::Failure,
                None,
            ),
            "audit event",
        );
        let e1 = ok(ex.append_audit(event).await, "append audit");
        let events = ok(ex.list_audit_recent(10).await, "list audit");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, e1);
        assert_eq!(events[0].category, crate::model::AuditCategory::Auth);
        assert_eq!(events[0].outcome, crate::model::AuditOutcome::Failure);
        ok(ex.shutdown().await, "shutdown");
    }

    // ------------------------------------------------------------------
    // 0.3.0 Stateful Runtime（§41.2，migration v4）：state / config / secret
    // ------------------------------------------------------------------

    /// 注册组件并创建安装实例（§19.2 两阶段：字节事实 → 注册表绑定 →
    /// 安装实例；state/config/secret 都锚定安装实例，§19.4）。
    async fn create_installation(ex: &StorageExecutor, component: &str) -> InstallationId {
        let bytes = format!("{component} bytes").into_bytes();
        let limit = ok(ByteSize::mib(16), "limit");
        let staged = ok(ex.stage_bytes(bytes, limit).await, "stage");
        ok(
            ex.record_quarantine(staged.clone(), audit("quarantine"))
                .await,
            "quarantine",
        );
        let cid = component_id(component);
        let v = version("1.0.0");
        ok(
            ex.commit_candidate(staged.digest, cid.clone(), v, audit("candidate"))
                .await,
            "candidate",
        );
        let id = InstallationId::new();
        ok(
            ex.create_installation_with_id(id, cid, audit("install"))
                .await,
            "create installation",
        );
        id
    }

    fn state_key(value: &str) -> StateKey {
        ok(StateKey::new(value), "state key")
    }

    #[tokio::test]
    async fn state_standalone_put_get_delete_roundtrip_and_version() {
        // §41.2 快照点读 + 原子单键 upsert（CAS 基础）；§41.3 版本确定性：
        // 空 store 无版本，首次写入在同一事务内建立版本，混合版本写入被阻止。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-roundtrip").await;
        let key = state_key("counter");
        let v1 = StateSchemaVersion::new(1);
        // 空 store：无版本（§41.3 `None` = 空 store）。
        assert!(
            ok(ex.get_state_schema_version(inst).await, "schema version").is_none(),
            "empty store must have no schema version"
        );
        assert!(
            ok(ex.get_state(inst, &key).await, "get before put").is_none(),
            "missing key must read as None (WIT not-found)"
        );
        // 首次写入建立版本 v1（同一事务，§41.3）。
        ok(
            ex.put_state(inst, &key, v1, b"v1-value".to_vec()).await,
            "put v1",
        );
        let record = some(
            ok(ex.get_state(inst, &key).await, "get after put"),
            "state record",
        );
        assert_eq!(record.value, b"v1-value");
        assert_eq!(record.schema_version, v1);
        assert_eq!(
            some(
                ok(ex.get_state_schema_version(inst).await, "schema version"),
                "version"
            ),
            v1
        );
        // 版本不符 → SchemaVersionMismatch（§41.3 混合版本写入被阻止）。
        let error = err(
            ex.put_state(inst, &key, StateSchemaVersion::new(2), b"v2".to_vec())
                .await,
            "put with wrong version",
        );
        assert!(
            matches!(error, StorageError::SchemaVersionMismatch { .. }),
            "expected SchemaVersionMismatch, got {error:?}"
        );
        // 同版本原子覆盖（CAS 基础：get → compare → put 在单连接串行下无交错）。
        ok(
            ex.put_state(inst, &key, v1, b"v1-updated".to_vec()).await,
            "put update",
        );
        let record = some(
            ok(ex.get_state(inst, &key).await, "get updated"),
            "state record",
        );
        assert_eq!(record.value, b"v1-updated");
        // 删除 + 删除不存在的键 → NotFound（WIT not-found）。
        ok(ex.delete_state(inst, &key).await, "delete");
        assert!(
            ok(ex.get_state(inst, &key).await, "get after delete").is_none(),
            "deleted key must be gone"
        );
        let error = err(ex.delete_state(inst, &key).await, "delete missing key");
        assert!(
            matches!(error, StorageError::NotFound(_)),
            "expected NotFound, got {error:?}"
        );
        // 版本在删除后仍然确定（marker 不可被删除路径触碰，§41.3）。
        assert_eq!(
            some(
                ok(ex.get_state_schema_version(inst).await, "schema version"),
                "version"
            ),
            v1
        );
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_key_and_secret_name_validate_wit_invariants() {
        // WIT record wrapper 不变量（§41.2/§13.5）：非空、显式字符集
        //（state-key `[A-Za-z0-9._-/]`；secret-name `[A-Za-z0-9._-]`）、
        // 长度上限。保留字符（'!'，schema marker 前缀）不可构造。
        for key in ["", "a b", "a!b", "a\nb", "a\tb", "ümlaut"] {
            let error = err(StateKey::new(key), "invalid state key");
            assert!(
                matches!(error, StorageError::InvalidArgument(_)),
                "{key:?} must be rejected as a state key"
            );
        }
        ok(StateKey::new("a.z-_/9"), "valid state key");
        ok(
            StateKey::new("a/b/c"),
            "valid state key (slash is in the charset)",
        );
        for name in ["", "a b", "a!b", "a/b", "a\nb", "ümlaut"] {
            let error = err(SecretName::new(name), "invalid secret name");
            assert!(
                matches!(error, StorageError::InvalidArgument(_)),
                "{name:?} must be rejected as a secret name"
            );
        }
        ok(SecretName::new("a.z-_9"), "valid secret name");
        // 长度上限。
        let error = err(StateKey::new("x".repeat(256)), "too long state key");
        assert!(matches!(error, StorageError::InvalidArgument(_)));
        let error = err(SecretName::new("x".repeat(256)), "too long secret name");
        assert!(matches!(error, StorageError::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn state_transaction_commit_is_atomic() {
        // §41.2 MUST：begin → put×N → commit 一次性原子生效（all-or-nothing）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-commit").await;
        let v1 = StateSchemaVersion::new(1);
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        let keys = [state_key("a"), state_key("b"), state_key("c")];
        for (i, key) in keys.iter().enumerate() {
            ok(
                ex.state_tx_put(handle, inst, key, format!("value-{i}").into_bytes())
                    .await,
                "tx put",
            );
        }
        // 事务内快照读取（WIT：同版本一致性快照）。
        let snapshot = some(
            ok(ex.state_tx_get(handle, inst, &keys[1]).await, "tx get"),
            "tx record",
        );
        assert_eq!(snapshot.value, b"value-1");
        // 提交前事务外不可见（未提交，§41.2）；未携带句柄的操作在窗口内被拒绝。
        let error = err(
            ex.get_state(inst, &keys[0]).await,
            "standalone get during tx",
        );
        assert!(
            matches!(error, StorageError::StateTransactionConflict(_)),
            "standalone state ops must be rejected during a transaction window"
        );
        ok(ex.commit_state_transaction(handle).await, "commit");
        // 提交后全部可见；store 版本 v1 建立（§41.3：版本与数据原子提交）。
        for (i, key) in keys.iter().enumerate() {
            let record = some(
                ok(ex.get_state(inst, key).await, "get after commit"),
                "state record",
            );
            assert_eq!(record.value, format!("value-{i}").into_bytes());
            assert_eq!(record.schema_version, v1);
        }
        assert_eq!(
            some(
                ok(ex.get_state_schema_version(inst).await, "schema version"),
                "version"
            ),
            v1
        );
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_transaction_abort_rolls_back() {
        // §41.2：abort → 事务内全部写入不生效；WIT：abort 对已终止事务
        // 是 no-op。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-abort").await;
        let v1 = StateSchemaVersion::new(1);
        let key = state_key("k");
        let other = state_key("other");
        ok(
            ex.put_state(inst, &key, v1, b"before".to_vec()).await,
            "seed",
        );
        ok(
            ex.put_state(inst, &other, v1, b"other-before".to_vec())
                .await,
            "seed other",
        );
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        ok(
            ex.state_tx_put(handle, inst, &key, b"in-tx".to_vec()).await,
            "tx put",
        );
        ok(ex.state_tx_delete(handle, inst, &other).await, "tx delete");
        ok(ex.abort_state_transaction(handle).await, "abort");
        // 回滚：两个 seed 值都保持、事务内写入不存在（无半状态，§41.2）。
        let record = some(ok(ex.get_state(inst, &key).await, "get"), "state record");
        assert_eq!(record.value, b"before");
        let record = some(
            ok(ex.get_state(inst, &other).await, "get other"),
            "other record",
        );
        assert_eq!(
            record.value, b"other-before",
            "aborted tx delete must not survive"
        );
        // 对已终止事务的 abort = no-op；对已终止事务的操作 = conflict（WIT）。
        ok(
            ex.abort_state_transaction(handle).await,
            "abort again no-op",
        );
        let error = err(
            ex.state_tx_put(handle, inst, &key, b"x".to_vec()).await,
            "put on terminated tx",
        );
        assert!(
            matches!(error, StorageError::StateTransactionConflict(_)),
            "ops on terminated tx must conflict"
        );
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_transaction_window_is_exclusive() {
        // §18.2 单连接：事务窗口内只允许 state 命令（其它命令会落入未提交
        // 事务并被连带回滚 → 显式拒绝，模块文档）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-exclusive").await;
        let v1 = StateSchemaVersion::new(1);
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        // 非 state 命令（写与读）在窗口内被拒绝。
        let error = err(
            ex.set_config("k".into(), "v".into(), audit("config")).await,
            "set_config during tx",
        );
        assert!(
            matches!(error, StorageError::StateTransactionConflict(_)),
            "non-state writes must be rejected during a transaction window"
        );
        let error = err(ex.get_config("k".into()).await, "get_config during tx");
        assert!(
            matches!(error, StorageError::StateTransactionConflict(_)),
            "non-state reads must be rejected during a transaction window"
        );
        // 未携带句柄的 state 操作也被拒绝；重复 begin 被拒绝。
        let key = state_key("k");
        let error = err(
            ex.put_state(inst, &key, v1, b"x".to_vec()).await,
            "standalone put during tx",
        );
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        let error = err(ex.begin_state_transaction(inst, v1).await, "second begin");
        assert!(
            matches!(error, StorageError::StateTransactionConflict(_)),
            "at most one in-progress transaction (single connection, §18.2)"
        );
        // commit 后窗口关闭，非 state 命令恢复。
        ok(ex.commit_state_transaction(handle).await, "commit");
        ok(
            ex.set_config("k".into(), "v".into(), audit("config")).await,
            "set_config after commit",
        );
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn cancelled_state_tx_operation_rolls_back_entire_tx() {
        // §41.2 取消 → 回滚，无半状态：进行中事务的请求被取消 ⇒ 事务整体
        // 回滚（§18.2 提交前取消检查）。确定性驱动（§26.5）：gate 阻塞
        // worker 后排队 begin（不取消）→ tx_put（取消）；释放后 begin 先
        // 执行，tx_put 在取消检查处命中 → 回滚。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-cancel").await;
        let v1 = StateSchemaVersion::new(1);
        let key = state_key("k");
        let release = gate(&ex).await;
        let (begin_tx, begin_rx) = tokio::sync::oneshot::channel();
        ok(
            ex.try_submit_request(Request {
                cmd: Command::BeginStateTransaction {
                    installation_id: inst,
                    schema_version: v1,
                    mode: StateTxMode::Normal,
                },
                cancel: Arc::new(AtomicBool::new(false)),
                reply: begin_tx,
            }),
            "queue begin",
        );
        let (put_tx, put_rx) = tokio::sync::oneshot::channel();
        let put_cancel = Arc::new(AtomicBool::new(false));
        ok(
            ex.try_submit_request(Request {
                cmd: Command::PutState {
                    installation_id: inst,
                    key: key.clone(),
                    schema_version: None,
                    value: b"must-not-survive".to_vec(),
                    tx: Some(StateTransactionHandle::new(1)),
                },
                cancel: put_cancel.clone(),
                reply: put_tx,
            }),
            "queue tx put",
        );
        put_cancel.store(true, Ordering::Relaxed);
        unit_ok(release.send(()), "release gate");
        ok(ok(begin_rx.await, "begin reply"), "begin must succeed");
        let put_result = ok(put_rx.await, "put reply");
        assert!(
            matches!(put_result, Err(StorageError::Cancelled)),
            "cancelled in-tx put must report Cancelled, got {put_result:?}"
        );
        // 无半状态：值不存在、无版本建立、事务已回滚（可重新 begin）。
        assert!(
            ok(ex.get_state(inst, &key).await, "get").is_none(),
            "cancelled tx must not leave any state"
        );
        assert!(
            ok(ex.get_state_schema_version(inst).await, "schema version").is_none(),
            "cancelled tx must not establish a schema version"
        );
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin again");
        ok(ex.commit_state_transaction(handle).await, "commit empty");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn cancelled_state_commit_rolls_back() {
        // §18.2 提交前取消检查：commit 被取消 ⇒ 事务不提交（整体回滚）。
        // 确定性驱动：begin 与 tx_put 已 await 完成（worker 已处理）后，携带
        // **预先置位**取消探针的 commit 提交——FIFO 保证其在二者之后处理，
        // 取消检查确定性命中（TestGate 在事务窗口内被排他规则拒绝，故不用
        // gate；预先置位探针等价，§26.5 不用 sleep 猜测时序）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-cancel-commit").await;
        let v1 = StateSchemaVersion::new(1);
        let key = state_key("k");
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        ok(
            ex.state_tx_put(handle, inst, &key, b"x".to_vec()).await,
            "tx put",
        );
        let (commit_tx, commit_rx) = tokio::sync::oneshot::channel();
        let commit_cancel = Arc::new(AtomicBool::new(true));
        ok(
            ex.try_submit_request(Request {
                cmd: Command::CommitStateTransaction { handle },
                cancel: commit_cancel,
                reply: commit_tx,
            }),
            "queue commit",
        );
        let commit_result = ok(commit_rx.await, "commit reply");
        assert!(
            matches!(commit_result, Err(StorageError::Cancelled)),
            "cancelled commit must report Cancelled, got {commit_result:?}"
        );
        // 回滚：值不存在、无版本；旧句柄已终止（再 commit = conflict）。
        assert!(ok(ex.get_state(inst, &key).await, "get").is_none());
        assert!(
            ok(ex.get_state_schema_version(inst).await, "schema version").is_none(),
            "cancelled commit must not advance the schema version"
        );
        let error = err(ex.commit_state_transaction(handle).await, "commit again");
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn uncommitted_state_transaction_leaves_no_residue_after_reopen() {
        // §18.5：crash/关闭时未提交事务自然回滚（WAL 只重放已提交帧）——
        // 事务中 reopen 无残留（§41.3：绝不产生"代码版本已切换但状态
        // schema 不确定"）。
        let dir = tempdir();
        let inst = {
            let ex = open_executor(dir.path()).await;
            let inst = create_installation(&ex, "state-tx-crash").await;
            let v1 = StateSchemaVersion::new(1);
            let key = state_key("k");
            let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
            ok(
                ex.state_tx_put(handle, inst, &key, b"uncommitted".to_vec())
                    .await,
                "tx put",
            );
            // 不 commit：shutdown（worker 退出时显式回滚；等价于进程 crash
            // ——SQLite 连接关闭时未提交事务必然回滚）。
            ok(ex.shutdown().await, "shutdown");
            inst
        };
        let ex = open_executor(dir.path()).await;
        let key = state_key("k");
        assert!(
            ok(ex.get_state(inst, &key).await, "get after reopen").is_none(),
            "uncommitted transaction must not survive reopen"
        );
        assert!(
            ok(ex.get_state_schema_version(inst).await, "schema version").is_none(),
            "no schema version may survive an uncommitted transaction"
        );
        // 重开后无悬挂锁/残留状态：可立即重新建立事务。
        let handle = ok(
            ex.begin_state_transaction(inst, StateSchemaVersion::new(1))
                .await,
            "begin after reopen",
        );
        ok(ex.commit_state_transaction(handle).await, "commit empty");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_migration_transaction_advances_schema_version_atomically() {
        // §41.2 显式 state migration：migration begin（新版本）→ 写入新
        // 版本形态 → commit 在**同一事务**内推进 store 版本（§41.3：版本
        // 与数据原子提交，无"代码版本已切换但状态 schema 不确定"）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-migration").await;
        let v1 = StateSchemaVersion::new(1);
        let v2 = StateSchemaVersion::new(2);
        let key = state_key("k");
        ok(
            ex.put_state(inst, &key, v1, b"old-shape".to_vec()).await,
            "seed v1",
        );
        // 常规 begin 用新版本 = SchemaVersionMismatch（§41.3 混合版本写入
        // 被阻止——迁移前旧版本继续可运行）。
        let error = err(
            ex.begin_state_transaction(inst, v2).await,
            "normal begin with v2",
        );
        assert!(matches!(error, StorageError::SchemaVersionMismatch { .. }));
        // migration begin：forward-only。
        let handle = ok(
            ex.begin_state_migration_transaction(inst, v2).await,
            "migration begin",
        );
        ok(
            ex.state_tx_put(handle, inst, &key, b"new-shape".to_vec())
                .await,
            "migration write",
        );
        ok(
            ex.state_tx_put(handle, inst, &state_key("k2"), b"new-key".to_vec())
                .await,
            "migration write 2",
        );
        ok(
            ex.commit_state_transaction(handle).await,
            "commit migration",
        );
        // 提交后：版本 = v2、数据为新形态（原子切换）。
        assert_eq!(
            some(
                ok(ex.get_state_schema_version(inst).await, "schema version"),
                "version"
            ),
            v2
        );
        let record = some(ok(ex.get_state(inst, &key).await, "get"), "state record");
        assert_eq!(record.value, b"new-shape");
        assert_eq!(record.schema_version, v2);
        // 旧版本不再可写（正常 begin 必须用 v2）。
        let error = err(
            ex.begin_state_transaction(inst, v1).await,
            "begin with v1 after migration",
        );
        assert!(matches!(error, StorageError::SchemaVersionMismatch { .. }));
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_migration_is_forward_only_and_rejects_empty_store() {
        // §41.2/WIT：migration 必须 forward-only（0.1.0 不定义降级）；
        // 空 store 不能迁移（无既有版本可迁移）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-migration-guard").await;
        let v1 = StateSchemaVersion::new(1);
        let v2 = StateSchemaVersion::new(2);
        let key = state_key("k");
        let error = err(
            ex.begin_state_migration_transaction(inst, v1).await,
            "migrate empty store",
        );
        assert!(matches!(error, StorageError::InvalidArgument(_)));
        ok(ex.put_state(inst, &key, v1, b"x".to_vec()).await, "seed v1");
        // 非前进（<= 当前版本）→ SchemaVersionMismatch。
        let error = err(
            ex.begin_state_migration_transaction(inst, v1).await,
            "migrate to same version",
        );
        assert!(matches!(error, StorageError::SchemaVersionMismatch { .. }));
        let error = err(
            ex.begin_state_migration_transaction(inst, StateSchemaVersion::new(0))
                .await,
            "migrate backward",
        );
        assert!(matches!(error, StorageError::SchemaVersionMismatch { .. }));
        // 未提交的 migration abort → 版本与数据都不变（§41.3 回滚语义）。
        let handle = ok(
            ex.begin_state_migration_transaction(inst, v2).await,
            "migration begin",
        );
        ok(
            ex.state_tx_put(handle, inst, &key, b"v2-shape".to_vec())
                .await,
            "migration write",
        );
        ok(ex.abort_state_transaction(handle).await, "abort migration");
        assert_eq!(
            some(
                ok(ex.get_state_schema_version(inst).await, "schema version"),
                "version"
            ),
            v1,
            "aborted migration must not advance the schema version"
        );
        let record = some(ok(ex.get_state(inst, &key).await, "get"), "state record");
        assert_eq!(record.value, b"x");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_transaction_ops_on_terminated_or_unknown_handle_conflict() {
        // WIT conflict：对已终止事务继续操作、未知句柄、跨安装句柄。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-tx-terminated").await;
        // 第二个安装在 begin 之前创建（事务窗口排他：窗口内非 state 命令
        // 被拒绝，§18.2）。
        let other_inst = create_installation(&ex, "state-tx-other").await;
        let v1 = StateSchemaVersion::new(1);
        let key = state_key("k");
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        // 未知句柄（未 begin 过）。
        let ghost = StateTransactionHandle::new(999);
        let error = err(ex.state_tx_get(ghost, inst, &key).await, "ghost handle get");
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        // 句柄匹配但安装不匹配（§19.4 命名空间私有）。
        let error = err(
            ex.state_tx_put(handle, other_inst, &key, b"x".to_vec())
                .await,
            "wrong installation",
        );
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        ok(ex.commit_state_transaction(handle).await, "commit");
        // 已提交：对旧句柄操作 = conflict；重复 commit = conflict。
        let error = err(
            ex.state_tx_put(handle, inst, &key, b"x".to_vec()).await,
            "put on committed tx",
        );
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        let error = err(ex.commit_state_transaction(handle).await, "double commit");
        assert!(matches!(error, StorageError::StateTransactionConflict(_)));
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn state_value_size_bound_rejected_before_write() {
        // §41.2/WIT：单值体积受宿主侧硬上限约束（§7.4）——写入前拒绝
        //（§13.3；SQL CHECK 是硬后备）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "state-size").await;
        let v1 = StateSchemaVersion::new(1);
        let key = state_key("k");
        let oversized = vec![0u8; crate::model::STATE_VALUE_MAX_BYTES + 1];
        let error = err(
            ex.put_state(inst, &key, v1, oversized).await,
            "oversized put",
        );
        assert!(
            matches!(error, StorageError::InvalidArgument(_)),
            "oversized state value must be rejected before write"
        );
        // 事务内同样拒绝（写路径校验，§13.3）；普通失败不回滚事务
        //（仅取消回滚——事务可继续正常提交）。
        let handle = ok(ex.begin_state_transaction(inst, v1).await, "begin");
        let error = err(
            ex.state_tx_put(
                handle,
                inst,
                &key,
                vec![0u8; crate::model::STATE_VALUE_MAX_BYTES + 1],
            )
            .await,
            "oversized tx put",
        );
        assert!(matches!(error, StorageError::InvalidArgument(_)));
        ok(ex.abort_state_transaction(handle).await, "abort");
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn component_config_revision_monotonic_and_roundtrip() {
        // §41.2：revision 每次被接受的写入 +1（单调；变化检测），快照原子
        //（revision 与 value 同行同读，WIT config-snapshot）。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "config-demo").await;
        let v1 = StateSchemaVersion::new(1);
        assert!(
            ok(ex.get_component_config(inst).await, "get before").is_none(),
            "no config before first write"
        );
        for (i, bytes) in [b"cfg-1".as_slice(), b"cfg-2", b"cfg-3"].iter().enumerate() {
            ok(
                ex.put_component_config(inst, ConfigFormat::Json, v1, bytes.to_vec())
                    .await,
                "put config",
            );
            let record = some(
                ok(ex.get_component_config(inst).await, "get config"),
                "config record",
            );
            assert_eq!(
                record.revision,
                (i + 1) as u64,
                "revision must be monotonic +1"
            );
            assert_eq!(record.value, bytes.to_vec());
            assert_eq!(record.format, ConfigFormat::Json);
            assert_eq!(record.schema_version, v1);
        }
        // 未知安装 → NotFound（§19.4 命名空间私有于安装实例）。
        let ghost = InstallationId::new();
        let error = err(
            ex.put_component_config(ghost, ConfigFormat::Toml, v1, b"x".to_vec())
                .await,
            "put to unknown installation",
        );
        assert!(matches!(error, StorageError::NotFound(_)));
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn secret_ciphertext_opaque_roundtrip_and_version_increment() {
        // §16.6/§41.2：storage 只存不透明密文 BLOB——存任意字节（包括
        // 明文形态的字节）再取回必须逐字节相等（storage 不解密、不解释
        // 内容）；轮换版本递增；列表不含值。
        let dir = tempdir();
        let ex = open_executor(dir.path()).await;
        let inst = create_installation(&ex, "secret-demo").await;
        let name = ok(SecretName::new("db.password"), "secret name");
        let ciphertext: Vec<u8> = b"plaintext-looking-bytes-are-opaque-ciphertext".to_vec();
        let metadata = r#"{"kek-id":"file:///secretstore/kek","algo":"xchacha20poly1305"}"#;
        ok(
            ex.put_secret(inst, &name, ciphertext.clone(), metadata.to_owned())
                .await,
            "put secret",
        );
        let record = some(
            ok(ex.get_secret_ciphertext(inst, &name).await, "get secret"),
            "secret record",
        );
        assert_eq!(
            record.ciphertext, ciphertext,
            "ciphertext must round-trip byte-identical (opaque, §16.6)"
        );
        assert_eq!(record.version, 1);
        assert_eq!(record.metadata, metadata);
        // 轮换：版本递增、新密文替换（insert or replace，§41.2）。
        let rotated: Vec<u8> = b"rotated-ciphertext".to_vec();
        ok(
            ex.put_secret(inst, &name, rotated.clone(), metadata.to_owned())
                .await,
            "rotate secret",
        );
        let record = some(
            ok(ex.get_secret_ciphertext(inst, &name).await, "get rotated"),
            "secret record",
        );
        assert_eq!(record.version, 2, "rotation must increment the version");
        assert_eq!(record.ciphertext, rotated);
        // 列表（名称 + 版本；不含值，§41.2 防泄漏）。
        let names = ok(ex.list_secret_names(inst).await, "list secrets");
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, name);
        assert_eq!(names[0].version, 2);
        // 空密文拒绝（结构性 envelope 上界/下界，§16.6）。
        let error = err(
            ex.put_secret(inst, &name, Vec::new(), "{}".to_owned())
                .await,
            "empty ciphertext",
        );
        assert!(matches!(error, StorageError::InvalidArgument(_)));
        // 删除；再删 = NotFound。
        ok(ex.delete_secret(inst, &name).await, "delete secret");
        assert!(
            ok(ex.get_secret_ciphertext(inst, &name).await, "get deleted").is_none(),
            "deleted secret must be gone"
        );
        let error = err(ex.delete_secret(inst, &name).await, "delete missing secret");
        assert!(matches!(error, StorageError::NotFound(_)));
        ok(ex.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn secret_table_has_no_plaintext_column() {
        // §16.6/§41.3：普通 SQLite metadata dump 不得暴露 secret 明文——
        // 表结构断言：component_secret 只有 6 列，唯一值承载列是 ciphertext
        //（BLOB），**不存在任何可容纳明文的列**；明文形态字节只以密文
        //（不透明字节）形态存在。
        let dir = tempdir();
        let plaintext = b"super-secret-db-password".to_vec();
        {
            let ex = open_executor(dir.path()).await;
            let inst = create_installation(&ex, "secret-noplain").await;
            let name = ok(SecretName::new("db.password"), "secret name");
            ok(
                ex.put_secret(inst, &name, plaintext.clone(), "{}".to_owned())
                    .await,
                "put secret",
            );
            ok(ex.shutdown().await, "shutdown");
        }
        let root = data_root(dir.path());
        let conn = ok(open_authoritative_db(&root.db_path()), "raw open");
        // 列集合断言（无明文列）。
        let columns: Vec<(String, String)> = ok(
            conn.prepare("PRAGMA table_info(component_secret)")
                .and_then(|mut stmt| {
                    stmt.query_map([], |row| {
                        Ok((row.get::<_, String>(1)?, row.get::<_, String>(2)?))
                    })
                    .and_then(|rows| rows.collect())
                }),
            "table info",
        );
        assert_eq!(
            columns
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "installation_id",
                "secret_name",
                "secret_version",
                "ciphertext",
                "metadata",
                "updated_at"
            ],
            "component_secret must have exactly the 6 designed columns"
        );
        let ciphertext_type = columns
            .iter()
            .find(|(name, _)| name == "ciphertext")
            .map(|(_, type_name)| type_name.as_str());
        assert_eq!(ciphertext_type, Some("BLOB"), "ciphertext must be a BLOB");
        // 明文形态字节只出现在 ciphertext 列（其它列不含该内容）。
        let row: Option<(String, String, i64, Vec<u8>, String, i64)> = ok(
            conn.query_row(
                "SELECT installation_id, secret_name, secret_version, ciphertext, metadata, updated_at
                 FROM component_secret",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .optional(),
            "raw secret row",
        );
        let (_, secret_name, _, ciphertext, metadata, _) = some(row, "secret row");
        assert_eq!(
            ciphertext, plaintext,
            "stored bytes are the opaque ciphertext (service-side encrypted), stored verbatim"
        );
        assert!(
            !secret_name.contains("super-secret") && !metadata.contains("super-secret"),
            "plaintext must not appear in any non-ciphertext column"
        );
    }
}
