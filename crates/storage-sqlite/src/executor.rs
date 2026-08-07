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
//! # 公开 API
//!
//! [`StorageExecutor`] 的 async 方法即 repository 能力的 transport 面：
//! 所有参数与返回值都是 typed 领域/存储类型（§13.3），SQL 细节不泄漏（§18.1）。

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleEvent, ComponentLifecycleState,
    ComponentVersion, ContentDigest, InstallationId,
};
use tokio::sync::{mpsc, oneshot};

use crate::artifact::{ArtifactStore, BudgetUsage, DataRoot, DiskBudget, GcPolicy, GcReport};
use crate::error::StorageError;
use crate::migration::open_authoritative_db;
use crate::model::{
    ActiveBinding, ArtifactRecord, AuditEvent, AuditRecord, CapabilityScope, ConfigEntry,
    GrantRecord, InstallationRecord, InstallationVersionRecord, RollbackResult, SessionId,
    SessionRecord, StagedArtifact, Timestamp, UpgradeTransactionRecord, UserId, UserRecord,
};
use crate::recovery::{RecoveryAction, run_recovery};
use crate::repository::Repository;

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
    while let Some(request) = receiver.blocking_recv() {
        // 执行前取消检查（§18.2：请求在事务提交前被取消则事务不提交）。
        if request.cancel.load(Ordering::Relaxed) {
            let _ = request.reply.send(Err(StorageError::Cancelled));
            continue;
        }
        let result = match request.cmd {
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
                .switch_active_version(installation_id, version, digest, &audit, &request.cancel)
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
            Command::RevokeAllUserSessions { user_id, audit } => Repository::new(&mut conn, &store)
                .revoke_all_user_sessions(user_id, &audit, &request.cancel)
                .map(Response::SessionsRevoked),
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
                .create_installation_with_id(installation_id, component_id, &audit, &request.cancel)
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
            #[cfg(test)]
            Command::TestGate { entered, release } => {
                let _ = entered.send(());
                let _ = release.blocking_recv();
                continue;
            }
        };
        let _ = request.reply.send(result);
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
            matches!(error, StorageError::SchemaTooNew { db: 99, current: 2 }),
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
}
