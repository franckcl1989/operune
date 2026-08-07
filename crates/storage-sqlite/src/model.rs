//! 存储侧 typed 值类型与记录（§13.1 / §13.3）。
//!
//! 原则：
//! - 所有跨 SQL 边界出现的值在适配层立即 parse/validate 成领域类型或本模块的
//!   typed newtype（§13.3 边界解析一次），SQL 细节不泄漏到调用方（§18.1）；
//! - domain 已建模的身份/版本/digest/生命周期一律使用 `operune_domain` 类型：
//!   [`ComponentId`]、[`ComponentVersion`]、[`ContentDigest`]、[`InstallationId`]、
//!   [`CapabilityId`]、[`ComponentLifecycleState`]（四种身份永久分离，§19.4）；
//! - domain 尚未建模的存储内部身份（user / session / upgrade transaction）用
//!   本模块的 typed newtype，杜绝 primitive obsession（§13.1）。它们以 SQLite
//!   AUTOINCREMENT 行 ID 为底层表示：0.1.0 是节点本地权威（§18.1）；0.6+ 多节点
//!   下按 §18.6 的 node-local / cluster-authoritative 分类演进，不构成锁定；
//! - 时间用 UTC unix 秒数（u64）的 [`Timestamp`] newtype；domain 的
//!   `Deadline` 是单调时钟瞬态类型（§13.2），不用于持久化。

use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use operune_domain::{
    CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest,
    InstallationId,
};

use crate::error::StorageError;

/// 文本长度上界（供审计字段等诊断文本使用）。
pub(crate) const MAX_TEXT_LEN: usize = 65536;

/// 通用文本校验：非空 + 长度上界 + 无控制字符（与 domain 的标识符校验同一
/// 原则，§19.1 输入不可信 / 防日志注入）。
pub(crate) fn validate_text(value: &str, kind: &str, max_len: usize) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::InvalidArgument(format!(
            "{kind} must not be empty"
        )));
    }
    if value.len() > max_len {
        return Err(StorageError::InvalidArgument(format!(
            "{kind} must not exceed {max_len} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(StorageError::InvalidArgument(format!(
            "{kind} must not contain control characters"
        )));
    }
    Ok(())
}

/// 用户身份（`users.user_id`，SQLite AUTOINCREMENT 行 ID）。
///
/// 0.1.0 节点本地权威身份（§18.1）；不承载 Component 身份语义（§19.4 四种
/// 身份永久分离）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(i64);

impl UserId {
    /// 从 SQLite 行 ID 构造（validate-on-construct：AUTOINCREMENT 从 1 开始）。
    pub fn from_rowid(rowid: i64) -> Result<Self, StorageError> {
        if rowid <= 0 {
            return Err(StorageError::CorruptState(format!(
                "invalid user rowid {rowid}"
            )));
        }
        Ok(Self(rowid))
    }

    /// 底层行 ID。
    pub fn as_rowid(self) -> i64 {
        self.0
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "user-{}", self.0)
    }
}

/// Session 身份（`sessions.session_id`，SQLite AUTOINCREMENT 行 ID）。
///
/// 注意：session 的浏览器端秘密是 bearer token，其单向 SHA-256 摘要
/// （[`ContentDigest`]）才是权威存储内容（§16.5）；本 ID 只是服务端内部键。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(i64);

impl SessionId {
    /// 从 SQLite 行 ID 构造（validate-on-construct）。
    pub fn from_rowid(rowid: i64) -> Result<Self, StorageError> {
        if rowid <= 0 {
            return Err(StorageError::CorruptState(format!(
                "invalid session rowid {rowid}"
            )));
        }
        Ok(Self(rowid))
    }

    /// 底层行 ID。
    pub fn as_rowid(self) -> i64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session-{}", self.0)
    }
}

/// Upgrade/rollback 事务标记身份（`upgrade_transactions.transaction_id`，
/// SQLite AUTOINCREMENT 行 ID）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UpgradeTransactionId(i64);

impl UpgradeTransactionId {
    /// 从 SQLite 行 ID 构造（validate-on-construct）。
    pub fn from_rowid(rowid: i64) -> Result<Self, StorageError> {
        if rowid <= 0 {
            return Err(StorageError::CorruptState(format!(
                "invalid upgrade transaction rowid {rowid}"
            )));
        }
        Ok(Self(rowid))
    }

    /// 底层行 ID。
    pub fn as_rowid(self) -> i64 {
        self.0
    }
}

impl fmt::Display for UpgradeTransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tx-{}", self.0)
    }
}

/// 能力授权 scope（§17.3 资源级 scope，如 network host/port/scheme、文件系统
/// path + mode、secret names）。domain 尚未建模 scope 语义类型（0.1.0 最小面），
/// 本模块提供结构性校验的 newtype；语义解析属于 security/application 的
/// resolution 职责（§17.5）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityScope(String);

impl CapabilityScope {
    /// 构造并校验（validate-on-construct，§13.3）。
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_text(&value, "capability scope", 4096)?;
        Ok(Self(value))
    }

    /// 原始字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// UTC unix 秒数时间戳（持久化 wall-clock 时间，§13.2 UTC 时间语义）。
///
/// 构造不可失败（任意非负 u64 都是合法 unix 秒数）；`now()` 在病理时钟
/// （早于 1970-01-01，任何真实宿主不可达）下失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    /// 从 unix 秒数构造（不可失败）。
    pub const fn from_unix_seconds(secs: u64) -> Self {
        Self(secs)
    }

    /// 当前时间（UTC unix 秒）。
    pub fn now() -> Result<Self, StorageError> {
        let duration = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| {
            StorageError::InvalidArgument("system clock is before the unix epoch".into())
        })?;
        Ok(Self(duration.as_secs()))
    }

    /// 原始 unix 秒数。
    pub const fn as_unix_seconds(self) -> u64 {
        self.0
    }

    /// SQLite 参数表示（INTEGER 为 i64；超出范围视为持久化损坏——真实时钟
    /// 秒数远小于 i64::MAX，§14.4 无回绕）。
    pub(crate) fn sql_value(self) -> Result<i64, StorageError> {
        i64::try_from(self.0).map_err(|_| {
            StorageError::CorruptState(format!("timestamp {} out of i64 range", self.0))
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Artifact 字节事实的记录状态（§19.2 字节事实阶段 → 应用身份阶段 → 激活）。
///
/// 这是存储侧记录种类，不是 domain 的 [`ComponentLifecycleState`]
/// （§19.2：quarantine/candidate 是持久化记录种类，不是生命周期状态）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ArtifactState {
    /// 字节已接收并持久化，尚未通过验证（§19.2 首段）。
    Quarantine,
    /// 已通过验证、已与逻辑版本绑定，等待激活（§19.2）。
    Candidate,
    /// 已激活（被至少一个安装的 active 绑定引用，§18.7 不可变内容寻址）。
    Installed,
}

impl fmt::Display for ArtifactState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Quarantine => "quarantine",
            Self::Candidate => "candidate",
            Self::Installed => "installed",
        };
        f.write_str(s)
    }
}

impl FromStr for ArtifactState {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "quarantine" => Ok(Self::Quarantine),
            "candidate" => Ok(Self::Candidate),
            "installed" => Ok(Self::Installed),
            other => Err(StorageError::CorruptState(format!(
                "invalid artifact state {other:?}"
            ))),
        }
    }
}

/// 单个安装实例与某逻辑版本的绑定状态（§18.3 installation 表语义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VersionState {
    /// 候选：已绑定，尚未成为 active（或可重试激活）。
    Candidate,
    /// 已安装：曾为或当前为 active（历史保留 → 回滚 retention，§18.7）。
    Installed,
    /// 已回滚：曾为 active，后被显式回滚（digest 仍被本行引用，GC 不删，§18.7）。
    RolledBack,
}

impl fmt::Display for VersionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Candidate => "candidate",
            Self::Installed => "installed",
            Self::RolledBack => "rolled_back",
        };
        f.write_str(s)
    }
}

impl FromStr for VersionState {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "candidate" => Ok(Self::Candidate),
            "installed" => Ok(Self::Installed),
            "rolled_back" => Ok(Self::RolledBack),
            other => Err(StorageError::CorruptState(format!(
                "invalid installation version state {other:?}"
            ))),
        }
    }
}

/// Upgrade/rollback 事务标记阶段（§18.3 / §18.5 lifecycle journal / transaction
/// marker）。唯一歧义消除手段见 [`crate::recovery`] 与 `upgrade_transactions`
/// 协议文档：`prepared` 与 active 切换在不同事务中，切换事务原子提交。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UpgradePhase {
    /// 已写入 durable marker（switch 意图已落库），active 尚未切换。
    Prepared,
    /// 切换事务已提交：active 已指向新版。
    Committed,
    /// 已确定性恢复/回滚（recovery 或取消收尾）。
    RolledBack,
}

impl fmt::Display for UpgradePhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Prepared => "prepared",
            Self::Committed => "committed",
            Self::RolledBack => "rolled_back",
        };
        f.write_str(s)
    }
}

impl FromStr for UpgradePhase {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "prepared" => Ok(Self::Prepared),
            "committed" => Ok(Self::Committed),
            "rolled_back" => Ok(Self::RolledBack),
            other => Err(StorageError::CorruptState(format!(
                "invalid upgrade transaction phase {other:?}"
            ))),
        }
    }
}

/// 审计事件主体（§18.7 durable audit）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuditActor {
    /// 已认证用户。
    User(UserId),
    /// 系统进程（Core 自身动作）。
    System,
    /// 恢复流程（crash recovery / 确定性收尾，§18.5）。
    Recovery,
}

impl fmt::Display for AuditActor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(id) => write!(f, "user:{id}"),
            Self::System => f.write_str("system"),
            Self::Recovery => f.write_str("recovery"),
        }
    }
}

impl FromStr for AuditActor {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "system" => Ok(Self::System),
            "recovery" => Ok(Self::Recovery),
            other => {
                let id = other
                    .strip_prefix("user:")
                    .ok_or_else(|| {
                        StorageError::CorruptState(format!("invalid audit actor {other:?}"))
                    })?
                    .parse::<i64>()
                    .map_err(|_| {
                        StorageError::CorruptState(format!("invalid audit actor {other:?}"))
                    })?;
                Ok(Self::User(UserId::from_rowid(id)?))
            }
        }
    }
}

/// 审计事件类别（闭集，§12.2 闭集 enum；存储侧记录分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    /// 认证（§16）。
    Auth,
    /// Session 生命周期（§16.5）。
    Session,
    /// 用户管理。
    User,
    /// Component 安装/激活/升级/回滚生命周期（§19 / §20）。
    ComponentLifecycle,
    /// 能力授权（§17.5 grant）。
    Grant,
    /// Runtime config（§18.0）。
    Config,
    /// 崩溃恢复动作（§18.5）。
    Recovery,
    /// Artifact 存储动作（§18.7）。
    Artifact,
}

impl fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Auth => "auth",
            Self::Session => "session",
            Self::User => "user",
            Self::ComponentLifecycle => "component-lifecycle",
            Self::Grant => "grant",
            Self::Config => "config",
            Self::Recovery => "recovery",
            Self::Artifact => "artifact",
        };
        f.write_str(s)
    }
}

impl FromStr for AuditCategory {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auth" => Ok(Self::Auth),
            "session" => Ok(Self::Session),
            "user" => Ok(Self::User),
            "component-lifecycle" => Ok(Self::ComponentLifecycle),
            "grant" => Ok(Self::Grant),
            "config" => Ok(Self::Config),
            "recovery" => Ok(Self::Recovery),
            "artifact" => Ok(Self::Artifact),
            other => Err(StorageError::CorruptState(format!(
                "invalid audit category {other:?}"
            ))),
        }
    }
}

/// 审计结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// 成功。
    Success,
    /// 失败。
    Failure,
}

impl fmt::Display for AuditOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Success => "success",
            Self::Failure => "failure",
        };
        f.write_str(s)
    }
}

impl FromStr for AuditOutcome {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            other => Err(StorageError::CorruptState(format!(
                "invalid audit outcome {other:?}"
            ))),
        }
    }
}

/// 审计事件（§18.7）。`occurred_at` 由存储层落库时统一打标（本类型不含时间）。
///
/// 安全契约（§16.6）：`action` / `target` / `detail` 不得包含密码、bearer token、
/// CSRF secret、private key 或 Component secret 的值；存储层只做长度/控制字符
/// 校验，不检查内容语义。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditEvent {
    /// 事件主体。
    actor: AuditActor,
    /// 事件类别。
    category: AuditCategory,
    /// 动作名（≤ 255 字节，可诊断）。
    action: String,
    /// 目标（可选，≤ 255 字节）。
    target: Option<String>,
    /// 结果。
    outcome: AuditOutcome,
    /// 细节（可选，≤ 64 KiB）。
    detail: Option<String>,
}

impl AuditEvent {
    /// 构造并校验（validate-on-construct，§13.3）。
    pub fn new(
        actor: AuditActor,
        category: AuditCategory,
        action: impl Into<String>,
        target: Option<String>,
        outcome: AuditOutcome,
        detail: Option<String>,
    ) -> Result<Self, StorageError> {
        let action = action.into();
        validate_text(&action, "audit action", 255)?;
        if let Some(target) = &target {
            validate_text(target, "audit target", 255)?;
        }
        if let Some(detail) = &detail {
            validate_text(detail, "audit detail", MAX_TEXT_LEN)?;
        }
        Ok(Self {
            actor,
            category,
            action,
            target,
            outcome,
            detail,
        })
    }

    /// 事件主体。
    pub fn actor(&self) -> &AuditActor {
        &self.actor
    }

    /// 事件类别。
    pub fn category(&self) -> AuditCategory {
        self.category
    }

    /// 动作名。
    pub fn action(&self) -> &str {
        &self.action
    }

    /// 目标。
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    /// 结果。
    pub fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    /// 细节。
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

/// `stage_bytes` 的结果：staging 暂存文件 + 字节事实（digest/size）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedArtifact {
    /// 内容摘要（不可变字节事实，§6.7）。
    pub digest: ContentDigest,
    /// 字节数。
    pub byte_size: operune_domain::ByteSize,
    /// staging 目录内的临时文件名（内部细节；由本 crate 生成，调用方原样传回）。
    pub(crate) staging_name: String,
}

/// `artifacts` 表记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    /// 内容摘要。
    pub digest: ContentDigest,
    /// 字节数。
    pub byte_size: operune_domain::ByteSize,
    /// 记录状态。
    pub state: ArtifactState,
    /// 首次落库时间（UTC unix 秒）。
    pub created_at: Timestamp,
}

/// `installations` 表记录（§18.3 InstallationId 及其关系）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationRecord {
    /// 安装实例身份（Core 创建并持久化，§19.4）。
    pub installation_id: InstallationId,
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// enable/disable 事实（是否接受请求）。
    pub enabled: bool,
    /// 当前候选/激活阶段的领域生命周期状态（§12.2 / §19）。
    pub lifecycle_state: ComponentLifecycleState,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 最后更新时间。
    pub updated_at: Timestamp,
}

/// `installation_versions` 表记录（安装实例 × 逻辑版本的绑定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationVersionRecord {
    /// 安装实例身份。
    pub installation_id: InstallationId,
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// 逻辑版本。
    pub component_version: ComponentVersion,
    /// 绑定 digest。
    pub content_digest: ContentDigest,
    /// 绑定状态。
    pub state: VersionState,
    /// 绑定时间。
    pub created_at: Timestamp,
}

/// `active_version` 表记录：**唯一 active 事实**（每安装至多一行，§18.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveBinding {
    /// 安装实例身份。
    pub installation_id: InstallationId,
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// 当前 active 的逻辑版本。
    pub component_version: ComponentVersion,
    /// 当前 active 的 digest。
    pub content_digest: ContentDigest,
}

/// `grants` 表记录（§17.5：grant 的 durable owner 是 InstallationId）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    /// 安装实例身份。
    pub installation_id: InstallationId,
    /// 能力身份（WIT import 语义解析在 application/runtime，§17.5 Resolution）。
    pub capability_id: CapabilityId,
    /// 资源级 scope（§17.3）。
    pub scope: CapabilityScope,
    /// 授权时间。
    pub granted_at: Timestamp,
    /// 撤销时间（未撤销为 `None`）。
    pub revoked_at: Option<Timestamp>,
}

/// `users` 表记录（§16.4：只存 Argon2id password hash，绝不存明文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// 用户身份。
    pub user_id: UserId,
    /// 用户名（唯一）。
    pub username: String,
    /// Argon2id PHC 哈希字符串（不透明；安全 crate 生成/验证，§16.4）。
    pub password_hash: String,
    /// 是否停用。
    pub disabled: bool,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 最后更新时间。
    pub updated_at: Timestamp,
}

/// `sessions` 表记录（§16.5：权威存储只保存 token 的单向摘要）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// 服务端 session 身份。
    pub session_id: SessionId,
    /// 所属用户。
    pub user_id: UserId,
    /// bearer token 的单向 SHA-256 摘要（**绝不存明文**，§16.5）。
    pub token_digest: ContentDigest,
    /// 创建时间。
    pub created_at: Timestamp,
    /// 最后使用时间（idle expiry 依据）。
    pub last_used_at: Timestamp,
    /// 绝对过期时间。
    pub absolute_expires_at: Timestamp,
    /// 是否已吊销。
    pub revoked: bool,
}

/// `audit_events` 表记录（§18.7 append-only）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// 自增序号（追加顺序）。
    pub id: i64,
    /// 事件时间。
    pub occurred_at: Timestamp,
    /// 事件主体。
    pub actor: AuditActor,
    /// 事件类别。
    pub category: AuditCategory,
    /// 动作名。
    pub action: String,
    /// 目标。
    pub target: Option<String>,
    /// 结果。
    pub outcome: AuditOutcome,
    /// 细节。
    pub detail: Option<String>,
}

/// `upgrade_transactions` 表记录（§18.3 upgrade/rollback 事务元数据 +
/// §18.5 lifecycle journal / transaction marker）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeTransactionRecord {
    /// 事务标记身份。
    pub transaction_id: UpgradeTransactionId,
    /// 安装实例。
    pub installation_id: InstallationId,
    /// 切换前版本（初次安装为 `None`）。
    pub from_version: Option<ComponentVersion>,
    /// 切换前 digest。
    pub from_digest: Option<ContentDigest>,
    /// 切换目标版本。
    pub to_version: ComponentVersion,
    /// 切换目标 digest。
    pub to_digest: ContentDigest,
    /// 标记阶段。
    pub phase: UpgradePhase,
    /// 标记创建时间。
    pub created_at: Timestamp,
    /// 完成时间（committed / rolled_back）。
    pub completed_at: Option<Timestamp>,
}

/// `runtime_config` 表记录（§18.0：事务化、版本化并审计）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigEntry {
    /// 配置键。
    pub key: String,
    /// 配置值。
    pub value: String,
    /// 版本（每次变更 +1，§18.0 版本化）。
    pub version: u64,
    /// 最后更新时间。
    pub updated_at: Timestamp,
    /// 最后更新主体（审计 actor 字符串）。
    pub updated_by: String,
}

// ---------------------------------------------------------------------------
// 0.3.0 Stateful Runtime（§41.2）：state / config / secret 三分离的存储侧
// typed 值类型（migration v4 表，§41）。
//
// 依赖注记：domain crate 的 stateful 新类型（`StateKey` / `SecretName` /
// state schema version 等）由另一里程碑并行添加，**尚未提交**。本模块按
// WIT 契约（wit/operune/state、wit/operune/secret）自行建模存储侧 typed
// newtype（与 `UserId` / `SessionId` 同模式：domain 未建模的存储内部身份用
// 本模块 newtype）；domain 类型就绪后按 §13.3 在 SQL 边界切换到 domain
// 类型（本 crate 的公开签名跟随 domain，不构成锁定）。
// ---------------------------------------------------------------------------

/// state key 最大长度（WIT operune:state `state-key` 的宿主侧上限，§41.2）。
pub(crate) const STATE_KEY_MAX_LEN: usize = 255;

/// state 单值硬上限（1 MiB；WIT "体积受 Core 宿主侧单值上限与安装实例总
/// 预算约束（§7.4）"——单值上限由本常量定义，SQL CHECK 是其硬后备）。
pub(crate) const STATE_VALUE_MAX_BYTES: usize = 1024 * 1024;

/// config 单值硬上限（1 MiB；WIT operune:config `config-value` "体积受 Core
/// 宿主侧硬上限约束（§7.4 / §7.5）"）。
pub(crate) const CONFIG_VALUE_MAX_BYTES: usize = 1024 * 1024;

/// secret 名称最大长度（WIT operune:secret `secret-name` 的宿主侧上限，
/// §41.2）。
pub(crate) const SECRET_NAME_MAX_LEN: usize = 255;

/// secret 密文 BLOB 硬上限（256 KiB；密文 envelope = 算法标识 + 版本 +
/// nonce + 密文 + tag，见 ADR-0001——storage 不解释内容，只做结构性上界）。
pub(crate) const SECRET_CIPHERTEXT_MAX_BYTES: usize = 256 * 1024;

/// secret 非敏感 metadata 上限（§41.2：metadata 只承载非敏感元数据，绝不
/// 含值或密钥材料，§16.6；存储侧只做结构性校验，语义由 SecretStore 服务
/// 侧定义）。
pub(crate) const SECRET_METADATA_MAX_LEN: usize = 4096;

/// state store 整体 schema 版本的保留 marker key（§41.2 "每个安装实例的
/// state store 有一个整体 `state-schema-version`"；§41.3：schema 版本必须
/// 持久确定，migration 提交原子推进）。
///
/// 选择 `'!'` 开头：WIT `state-key` 不变量只允许 `[A-Za-z0-9._-/]`
/// （§41.2），`'!'` 不在字符集内 ⇒ 任何 guest key 都不可能与本 marker
/// 冲突（storage 侧 [`StateKey`] 校验同时保证该不变式，marker 不可伪造）。
pub(crate) const STATE_SCHEMA_MARKER_KEY: &str = "!schema-version";

/// 校验 WIT record wrapper 键（§13.5：非裸 string；validate-on-construct，
/// §13.3）。只允许 ASCII 字母数字 + 显式白名单标点（无控制字符/空白）；
/// 长度上界。
fn validate_key(
    value: &str,
    kind: &str,
    allowed_punct: &[u8],
    max_len: usize,
) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::InvalidArgument(format!(
            "{kind} must not be empty"
        )));
    }
    if value.len() > max_len {
        return Err(StorageError::InvalidArgument(format!(
            "{kind} must not exceed {max_len} bytes"
        )));
    }
    for byte in value.bytes() {
        if !byte.is_ascii_alphanumeric() && !allowed_punct.contains(&byte) {
            return Err(StorageError::InvalidArgument(format!(
                "{kind} contains a character outside the allowed set \
                 (ASCII alphanumeric + {})",
                String::from_utf8_lossy(allowed_punct)
            )));
        }
    }
    Ok(())
}

/// 状态键（`component_state.state_key`；WIT operune:state `state-key`，
/// §41.2）。字符集 `[A-Za-z0-9._-/]`（非空、无控制字符/空白、≤ 255 字节）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateKey(String);

impl StateKey {
    /// 构造并校验（validate-on-construct，§13.3；违反 WIT 不变量 →
    /// [`StorageError::InvalidArgument`]）。
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_key(&value, "state key", b"._-/", STATE_KEY_MAX_LEN)?;
        Ok(Self(value))
    }

    /// 原始字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 安装实例 state store 的 schema 版本（WIT operune:state
/// `state-schema-version`，§41.2 契约层版本表达；u32 无非法取值，
/// 构造不可失败）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StateSchemaVersion(u32);

impl StateSchemaVersion {
    /// 构造（u32 全取值合法，不可失败）。
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// 原始值。
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// SQLite 参数表示（u32 → i64 恒可表示，§14.4 无回绕）。
    pub(crate) fn sql_value(self) -> i64 {
        i64::from(self.0)
    }
}

impl fmt::Display for StateSchemaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// 进行中的 state 事务句柄（§41.2 事务资源；由 executor 在 begin 时签发，
/// 跨命令边界引用同一进行中事务；单连接串行 ⇒ 同一时刻至多一个，§18.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StateTransactionHandle(u64);

impl StateTransactionHandle {
    /// 从 executor 单调计数构造。
    pub(crate) fn new(counter: u64) -> Self {
        Self(counter)
    }

    /// 底层计数。
    pub(crate) fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for StateTransactionHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "state-tx-{}", self.0)
    }
}

/// `component_state` 表记录（§41.2：state 是 Component 产生的权威持久业务
/// 状态；value 是平台不透明的序列化业务字节——**平台不解析、不解释 value
/// 内容**，结构化形态由 Component 与自身 schema 之间的事实保证，WIT）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateValueRecord {
    /// 安装实例（state 命名空间私有于安装实例，§19.4）。
    pub installation_id: InstallationId,
    /// 状态键。
    pub key: StateKey,
    /// 本行的 schema 版本（写入时绑定，§41.2 版本化 state）。
    pub schema_version: StateSchemaVersion,
    /// 平台不透明的序列化业务字节。
    pub value: Vec<u8>,
    /// 最后更新时间。
    pub updated_at: Timestamp,
}

/// Component config 的声明格式（WIT operune:config："契约层表达格式
/// （json/toml/raw）"，§41.2；闭集，CHECK 与 domain 枚举字符串一致）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFormat {
    /// JSON。
    Json,
    /// TOML。
    Toml,
    /// 原始字节（无格式声明）。
    Raw,
}

impl fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Raw => "raw",
        };
        f.write_str(s)
    }
}

impl std::str::FromStr for ConfigFormat {
    type Err = StorageError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "raw" => Ok(Self::Raw),
            other => Err(StorageError::CorruptState(format!(
                "invalid component config format {other:?}"
            ))),
        }
    }
}

/// `component_config` 表记录（§41.2：config 是管理员/系统提供的输入，具有
/// validation 与版本语义；guest 只读，写侧不在 Component 契约内）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentConfigRecord {
    /// 安装实例。
    pub installation_id: InstallationId,
    /// 声明格式（json/toml/raw）。
    pub format: ConfigFormat,
    /// 配置契约的 schema 版本（WIT：与 config-version/revision 相区别）。
    pub schema_version: StateSchemaVersion,
    /// 快照修订号（每次被接受的写入 +1，§41.2 变化检测）。
    pub revision: u64,
    /// 有界配置值（通过验证后才成为当前配置）。
    pub value: Vec<u8>,
    /// 最后更新时间。
    pub updated_at: Timestamp,
}

/// secret 名称（`component_secret.secret_name`；WIT operune:secret
/// `secret-name`，§41.2）。字符集 `[A-Za-z0-9._-]`（非空、无控制字符/空白、
/// ≤ 255 字节）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretName(String);

impl SecretName {
    /// 构造并校验（validate-on-construct，§13.3）。
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_key(&value, "secret name", b"._-", SECRET_NAME_MAX_LEN)?;
        Ok(Self(value))
    }

    /// 原始字符串视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SecretName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `component_secret` 表记录（§41.2：secret 是受专门访问控制与防泄漏规则
/// 保护的敏感值）。
///
/// **密文边界（§16.6 / ADR-0001，已裁决）**：`ciphertext` 是**不透明密文
///   BLOB**——加密在 SecretStore 服务侧完成（AEAD envelope：算法标识 +
///   版本 + nonce + 密文 + tag），本存储层不解密、不解释、不回显内容；
///   明文绝不落库（本表没有也不会有可容纳明文的列）；KEK 绝不进入本
///   数据库（§16.6：KEK 不得与密文同库同保护级）。`metadata` 只承载
///   非敏感元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRecord {
    /// secret 名称（grant scope 的键，§17.3）。
    pub name: SecretName,
    /// 轮换版本（每次轮换 +1，WIT `secret-version`）。
    pub version: u64,
    /// 不透明密文 BLOB（storage 不解密，原样存取）。
    pub ciphertext: Vec<u8>,
    /// 非敏感元数据（绝不含值/密钥材料，§16.6）。
    pub metadata: String,
    /// 最后更新时间。
    pub updated_at: Timestamp,
}

/// secret 列表项元数据（WIT `list-granted-secrets` 的 `secret-metadata`：
/// 名称 + 版本；**不含值**，§41.2 防泄漏）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    /// secret 名称。
    pub name: SecretName,
    /// 轮换版本。
    pub version: u64,
}

/// 显式回滚结果（§20.1 热升级/回滚）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackResult {
    /// 回滚到的版本。
    pub to_version: ComponentVersion,
    /// 回滚到的 digest。
    pub to_digest: ContentDigest,
}
