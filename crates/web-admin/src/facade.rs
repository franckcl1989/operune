//! Root Admin 用例 facade（§21.1 / §24.2）。
//!
//! web-admin 只**消费** application 的用例 API（InstallService / UpgradeService /
//! WebBridge）与 ports（ComponentRegistryPort / GrantStorePort / ConfigPort /
//! AuditPort），不实现它们（那是 storage 的职责）。
//!
//! application 在 0.1.0 没有覆盖以下管理操作，本模块以 **adapter 级 port**
//! 表达并给出内存实现（这些是 web-admin 自己的边界，不属于 application 的
//! ports 实现面）：
//!
//! - [`AdminUserStore`]：Root Admin 用户（登录主体 + 密码哈希 + enabled）。
//!   §16.3 bootstrap CLI 是首次管理员创建路径；本 port 供 composition root
//!   注入持久化实现（0.1：内存实现）。
//! - [`AuditLogView`]：审计读取（application 的 AuditPort 只有 append，
//!   无读取面）。0.1：内存环形实现；durable 实现由 storage-sqlite 提供。
//! - [`SafeModeState`]：safe mode 标志（§21.1；语义接线在 composition root）。
//!
//! [`RealAdminApi`] 是生产实现；HTTP 层注入 `Arc<dyn AdminApi>` 使测试可以
//! 用假用例（§32 测试的注入缝）。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use operune_application::ports::{
    AuditError as AppAuditError, ComponentRegistryPort, ConfigError, ConfigPort, GrantError,
    GrantStorePort, RegistryError,
};
use operune_application::{
    ActiveRuntimeRegistry, ApplicationError, GrantApproval, GrantScope, InstallOutcome,
    InstallRequest, InstallService, InstallationGrant, RollbackRequest, RuntimeConfig,
    UninstallService, UpgradeOutcome, UpgradeRequest, UpgradeService,
};
use operune_domain::{
    ByteSize, ComponentLifecycleEvent, ComponentLifecycleState, DomainError, InstallationId,
};
use operune_observability::{
    AuditAction, AuditCategory, AuditEvent, AuditOutcome, AuditSeverity, AuditSink, LogAuditSink,
};
use operune_security::password::{
    PasswordError, PasswordHashString, PasswordHasher, PasswordParams,
};
use operune_security::session::SessionManager;
use secrecy::{ExposeSecret, SecretString};

/// Admin 密码最小字节数（0.1 管理面决策；bootstrap CLI 仍应使用 TTY 输入，
/// §16.3）。低于该长度拒绝创建。
const MIN_PASSWORD_LEN: usize = 8;
/// Admin 密码最大字节数（§19.1 输入不可信：防超大表单与哈希放大）。
const MAX_PASSWORD_LEN: usize = 1024;
/// 用户主体名最大长度（§13.3 结构性上界；对齐 domain 255 字节）。
const MAX_SUBJECT_LEN: usize = 255;

/// 内存审计环形缓冲默认容量。
const DEFAULT_AUDIT_CAP: usize = 1024;

// ---------------------------------------------------------------------------
// AdminApi trait（HTTP 层消费的用例面）
// ---------------------------------------------------------------------------

/// Root Admin 用例面（§21.1 功能面）。全部同步（application 用例为同步）。
pub trait AdminApi: Send + Sync {
    /// Runtime 状态页数据（§21.1）。
    fn status(&self) -> Result<StatusView, AdminError>;

    /// Component 列表（安装记录 + 激活信息 + grants，§21.1）。
    fn list_components(&self) -> Result<Vec<ComponentView>, AdminError>;

    /// Component 详情（§21.1）。
    fn component(&self, id: InstallationId) -> Result<ComponentView, AdminError>;

    /// 安装（§19.2 两阶段管线；grants 必须显式批准，§17.1）。
    fn install(
        &self,
        bytes: Vec<u8>,
        grants: Vec<InstallationGrant>,
    ) -> Result<InstallOutcome, AdminError>;

    /// 热升级（§20.1）。`grants = Some` 表示显式重新批准，`None` = 复用既有
    /// （§17.5：扩大能力时管线返回 [`UpgradeOutcome::RequiresApproval`]）。
    fn upgrade(
        &self,
        id: InstallationId,
        bytes: Vec<u8>,
        grants: Option<Vec<InstallationGrant>>,
    ) -> Result<UpgradeOutcome, AdminError>;

    /// 回滚到上一已知良好版本（§20）。
    fn rollback(&self, id: InstallationId) -> Result<UpgradeOutcome, AdminError>;

    /// 管理性停用（Active → Draining → Disabled；有界 drain，§20.4）。
    fn disable(&self, id: InstallationId) -> Result<(), AdminError>;

    /// 重新启用（§39.2 enable：Disabled → readiness 重验证 → 原子激活；
    /// 经 [`InstallService::enable`] 复用完整激活管线）。
    fn enable(&self, id: InstallationId) -> Result<(), AdminError>;

    /// 卸载（§39.2 remove / §42.4：卸载后组件从 UI 与 backend 完整消失）。
    /// provider 仍有 active consumer 依赖时拒绝
    /// （[`ApplicationError::ProviderHasConsumers`]）。
    fn remove(&self, id: InstallationId) -> Result<(), AdminError>;

    /// 安装实例的 grants（§17.5）。
    fn grants_for(&self, id: InstallationId) -> Result<Vec<InstallationGrant>, AdminError>;

    /// 整体替换 grants（§17.5 显式重新批准）。
    fn replace_grants(
        &self,
        id: InstallationId,
        grants: Vec<InstallationGrant>,
    ) -> Result<(), AdminError>;

    /// 用户列表（§21.1 最小用户管理）。
    fn list_users(&self) -> Result<Vec<AdminUserView>, AdminError>;

    /// 创建用户（密码经 PasswordHasher 哈希；§16.4）。
    fn create_user(&self, subject: String, password: SecretString) -> Result<(), AdminError>;

    /// 启用 / 禁用用户；禁用时作废该主体全部 session（§16.5）。
    fn set_user_enabled(&self, subject: String, enabled: bool) -> Result<(), AdminError>;

    /// Core config 快照（§21.1 / §18.0）。
    fn config(&self) -> Result<RuntimeConfig, AdminError>;

    /// 最近审计事件（§21.1 / §18.7）。
    fn audit_recent(&self, limit: usize) -> Result<Vec<AuditEvent>, AdminError>;

    /// safe mode 状态（§21.1）。
    fn safe_mode_status(&self) -> bool;

    /// 进入 / 退出 safe mode（全部审计，§16.3 精神）。
    fn set_safe_mode(&self, enabled: bool) -> Result<(), AdminError>;
}

// ---------------------------------------------------------------------------
// 视图类型（模板数据；含预格式化，domain 类型无 Display 的边界在此处理）
// ---------------------------------------------------------------------------

/// 状态页视图（§21.1）。
#[derive(Debug, Clone)]
pub struct StatusView {
    /// 全部安装记录。
    pub installations: Vec<operune_application::InstallationRecord>,
    /// 当前 Active 安装。
    pub active: Vec<operune_application::active::ActiveInstallation>,
    /// Core config（格式化视图）。
    pub config: ConfigView,
    /// safe mode 状态。
    pub safe_mode: bool,
}

/// Core config 的展示视图（预格式化；引擎预算类字段属内部细节，不展示）。
#[derive(Debug, Clone)]
pub struct ConfigView {
    /// 安装输入硬上限。
    pub max_component_bytes: String,
    /// descriptor deadline（毫秒）。
    pub descriptor_deadline_ms: u64,
    /// readiness deadline（毫秒）。
    pub readiness_deadline_ms: u64,
    /// drain deadline（毫秒）。
    pub drain_deadline_ms: u64,
    /// 资产缓存条目上限。
    pub max_web_assets: usize,
    /// 单资产体积上限。
    pub max_asset_bytes: String,
    /// action 请求体上限。
    pub max_action_body_bytes: String,
    /// action 响应体积上限。
    pub max_action_response_bytes: String,
    /// 每安装每分钟 action 上限。
    pub max_actions_per_minute: u32,
}

impl ConfigView {
    /// 从快照构造（格式化边界）。
    pub fn from_config(config: &RuntimeConfig) -> Self {
        Self {
            max_component_bytes: format_bytes(config.max_component_bytes),
            descriptor_deadline_ms: millis(config.descriptor_deadline),
            readiness_deadline_ms: millis(config.readiness_deadline),
            drain_deadline_ms: millis(config.drain_deadline),
            max_web_assets: config.max_web_assets,
            max_asset_bytes: format_bytes(config.max_asset_bytes),
            max_action_body_bytes: format_bytes(config.max_action_body_bytes),
            max_action_response_bytes: format_bytes(config.max_action_response_bytes),
            max_actions_per_minute: config.max_actions_per_minute,
        }
    }
}

/// Component 列表 / 详情视图（§21.1）。
#[derive(Debug, Clone)]
pub struct ComponentView {
    /// 安装记录（digest 主键关系、状态、rollback 目标）。
    pub record: operune_application::InstallationRecord,
    /// 当前 Active 条目（无则 `None`）。
    pub active: Option<operune_application::active::ActiveInstallation>,
    /// 该安装的 grants（§17.5）。
    pub grants: Vec<InstallationGrant>,
}

/// 用户视图（不含密码哈希，§16.6）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUserView {
    /// 登录主体名。
    pub subject: String,
    /// 是否启用。
    pub enabled: bool,
}

/// 字节数展示（KiB/MiB；domain ByteSize 无 Display，边界在此格式化）。
pub fn format_bytes(bytes: ByteSize) -> String {
    let value = bytes.as_u64();
    if value >= 1024 * 1024 {
        format!(
            "{:.1} MiB ({value} bytes)",
            value as f64 / (1024.0 * 1024.0)
        )
    } else if value >= 1024 {
        format!("{:.1} KiB ({value} bytes)", value as f64 / 1024.0)
    } else {
        format!("{value} bytes")
    }
}

fn millis(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u64::MAX as u128) as u64
}

/// grant scope 的展示摘要（§16.6：环境变量值一律遮蔽，不进入页面/审计）。
pub fn grant_scope_summary(scope: &GrantScope) -> String {
    match scope {
        GrantScope::Unscoped => "unscoped".to_owned(),
        GrantScope::WasiPreopen {
            guest_path,
            host_path,
            read,
            write,
        } => format!("preopen:{guest_path} -> {host_path} ({read}+{write})"),
        GrantScope::WasiEnv { key, .. } => format!("env:{key}=[REDACTED]"),
        GrantScope::Action { name } => format!("action:{name}"),
    }
}

// ---------------------------------------------------------------------------
// AdminError（HTTP 层映射为确定响应；§14.1 封闭 typed）
// ---------------------------------------------------------------------------

/// Admin 用例错误（封闭 typed，§14.1；不携带 secret，§16.6）。
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// 安装实例不存在。
    #[error("installation {0} not found")]
    NotFound(InstallationId),
    /// application 用例层错误。
    #[error("application error: {0}")]
    Application(#[from] ApplicationError),
    /// 注册表失败。
    #[error("registry failure: {0}")]
    Registry(#[from] RegistryError),
    /// grant store 失败。
    #[error("grant store failure: {0}")]
    Grants(#[from] GrantError),
    /// config 读取失败。
    #[error("config failure: {0}")]
    ConfigSource(#[from] ConfigError),
    /// durable audit 写入失败（§18.7 fail closed：依赖 audit 的变更不得提交）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[from] AppAuditError),
    /// 管理审计 sink 写入失败（admin 操作同样 fail closed）。
    #[error("admin audit failure (fail closed): {0}")]
    AdminAudit(#[from] operune_observability::AuditError),
    /// 用户 store 失败。
    #[error("user store failure: {0}")]
    Users(#[from] AdminUserError),
    /// 密码哈希失败。
    #[error("password hashing failure: {0}")]
    Password(#[from] PasswordError),
    /// session 生命周期失败（登录/旋转/发放）。
    #[error("session failure: {0}")]
    Session(#[from] operune_security::session::SessionError),
    /// 登录 cookie 装配失败。
    #[error("session cookie failure: {0}")]
    Cookie(#[from] crate::auth::CookieBuildError),
    /// 非法输入（表单/参数校验失败）。
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// 0.1.0 明确不支持的操作（application 用例 API 缺口）。
    #[error("unsupported in 0.1.0: {0}")]
    Unsupported(&'static str),
    /// domain 层错误（生命周期转换等）。
    #[error("domain error: {0}")]
    Domain(#[from] DomainError),
    /// 内部不变量破坏（fail-stop 语义，§14.3）。
    #[error("admin internal invariant violated: {0}")]
    Internal(&'static str),
}

impl AdminError {
    /// 是否可映射为 404（HTTP 层）。
    pub const fn is_not_found(&self) -> bool {
        matches!(self, AdminError::NotFound(_))
    }
}

// ---------------------------------------------------------------------------
// AdminUserStore port + 内存实现
// ---------------------------------------------------------------------------

/// Root Admin 用户 store（web-admin 的 adapter 级 port；§21.1 用户/RBAC
/// 最小管理。首次管理员创建走 bootstrap CLI，§16.3）。
pub trait AdminUserStore: Send + Sync {
    /// 校验主体 + 密码（§16.4：存储 hash 的参数验证，constant-time 比较）。
    /// 主体不存在返回 `Ok(false)`（等时性见实现说明）。
    fn verify_credentials(
        &self,
        subject: &str,
        password: &SecretString,
    ) -> Result<bool, AdminUserError>;

    /// 主体是否存在且启用（Auth 中间件的 RBAC 检查点）。
    fn is_enabled(&self, subject: &str) -> Result<bool, AdminUserError>;

    /// 全部用户。
    fn list(&self) -> Result<Vec<AdminUser>, AdminUserError>;

    /// 创建用户（哈希由调用方经 [`PasswordHasher`] 生成，§16.4）。
    fn create(&self, user: AdminUser) -> Result<(), AdminUserError>;

    /// 启用 / 禁用。
    fn set_enabled(&self, subject: &str, enabled: bool) -> Result<(), AdminUserError>;
}

/// 用���记录（哈希是权威值；页面视图用 [`AdminUserView`]，不含哈希）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminUser {
    /// 登录主体名。
    pub subject: String,
    /// 是否启用。
    pub enabled: bool,
    /// PHC 密码哈希（§16.4；非秘密——它就是权威存储值）。
    pub password_hash: PasswordHashString,
}

/// 用户 store 错误（封闭 typed，§14.1）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AdminUserError {
    /// 主体已存在。
    #[error("user {0} already exists")]
    AlreadyExists(String),
    /// 主体不存在。
    #[error("user {0} not found")]
    NotFound(String),
    /// 实现层故障。
    #[error("user store failure: {0}")]
    Storage(String),
}

/// 内存用户 store（0.1 开发/测试；持久化实现由 storage-sqlite 提供）。
///
/// 等时性：未知主体仍执行一次 dummy Argon2id 验证（固定随机哈希），避免
/// "主体不存在" 与 "密码错误" 的可观测时间差（§16.4 纵深防御）。
#[derive(Debug)]
pub struct InMemoryAdminUserStore {
    users: Mutex<HashMap<String, AdminUser>>,
    hasher: PasswordHasher,
    dummy_hash: Mutex<Option<PasswordHashString>>,
}

impl InMemoryAdminUserStore {
    /// 构造（注入哈希器）。
    pub fn new(hasher: PasswordHasher) -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            hasher,
            dummy_hash: Mutex::new(None),
        }
    }

    fn dummy_hash(&self) -> Result<PasswordHashString, AdminUserError> {
        // 惰性计算一次（首次未知主体验证时）；`OnceLock::get_or_try_init`
        // 在 1.97 仍不稳定，用 Mutex 表达同一语义。
        let mut slot = self
            .dummy_hash
            .lock()
            .map_err(|_| AdminUserError::Storage("dummy hash lock poisoned".to_owned()))?;
        match slot.as_ref() {
            Some(hash) => Ok(hash.clone()),
            None => {
                let hash = self
                    .hasher
                    .hash(&SecretString::from(DUMMY_PASSWORD))
                    .map_err(|error| {
                        AdminUserError::Storage(format!("dummy credential hash failed: {error}"))
                    })?;
                *slot = Some(hash.clone());
                Ok(hash)
            }
        }
    }
}

/// dummy 验证用固定口令（非真实凭据；只用于等时性）。
const DUMMY_PASSWORD: &str = "operune-admin-dummy-credential-0000";

impl AdminUserStore for InMemoryAdminUserStore {
    fn verify_credentials(
        &self,
        subject: &str,
        password: &SecretString,
    ) -> Result<bool, AdminUserError> {
        let users = self
            .users
            .lock()
            .map_err(|_| AdminUserError::Storage("user store lock poisoned".to_owned()))?;
        match users.get(subject) {
            Some(user) => {
                let matched = self
                    .hasher
                    .verify(password, user.password_hash.as_str())
                    .is_ok();
                Ok(matched)
            }
            None => {
                // 等时性：同样执行一次 Argon2id 验证（§16.4 纵深防御）。
                let dummy = self.dummy_hash()?;
                let _ = self.hasher.verify(password, dummy.as_str());
                Ok(false)
            }
        }
    }

    fn is_enabled(&self, subject: &str) -> Result<bool, AdminUserError> {
        let users = self
            .users
            .lock()
            .map_err(|_| AdminUserError::Storage("user store lock poisoned".to_owned()))?;
        match users.get(subject) {
            Some(user) => Ok(user.enabled),
            None => Ok(false),
        }
    }

    fn list(&self) -> Result<Vec<AdminUser>, AdminUserError> {
        let users = self
            .users
            .lock()
            .map_err(|_| AdminUserError::Storage("user store lock poisoned".to_owned()))?;
        let mut all: Vec<AdminUser> = users.values().cloned().collect();
        all.sort_by(|a, b| a.subject.cmp(&b.subject));
        Ok(all)
    }

    fn create(&self, user: AdminUser) -> Result<(), AdminUserError> {
        let mut users = self
            .users
            .lock()
            .map_err(|_| AdminUserError::Storage("user store lock poisoned".to_owned()))?;
        if users.contains_key(&user.subject) {
            return Err(AdminUserError::AlreadyExists(user.subject));
        }
        users.insert(user.subject.clone(), user);
        Ok(())
    }

    fn set_enabled(&self, subject: &str, enabled: bool) -> Result<(), AdminUserError> {
        let mut users = self
            .users
            .lock()
            .map_err(|_| AdminUserError::Storage("user store lock poisoned".to_owned()))?;
        match users.get_mut(subject) {
            Some(user) => {
                user.enabled = enabled;
                Ok(())
            }
            None => Err(AdminUserError::NotFound(subject.to_owned())),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditLogView port + 内存实现
// ---------------------------------------------------------------------------

/// 审计读取 port（web-admin 的 adapter 级 port；§21.1 audit 页。
/// application 的 AuditPort 只有 append 面——读取面缺口见 crate 文档）。
pub trait AuditLogView: Send + Sync {
    /// 最近 `limit` 条事件（新→旧；容量不足时返回全部）。
    fn recent(&self, limit: usize) -> Vec<AuditEvent>;
}

/// 内存审计日志（0.1 开发/测试；同时实现写入 [`AuditSink`] 与读取
/// [`AuditLogView`]）。durable 实现由 storage-sqlite 提供。
#[derive(Debug)]
pub struct InMemoryAuditLog {
    events: Mutex<Vec<AuditEvent>>,
    cap: usize,
}

impl InMemoryAuditLog {
    /// 构造（默认容量 [`DEFAULT_AUDIT_CAP`]）。
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_AUDIT_CAP)
    }

    /// 构造（指定容量；至少 1）。
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            cap: cap.max(1),
        }
    }

    /// 当前事件数（测试/诊断）。
    pub fn len(&self) -> usize {
        match self.events.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryAuditLog {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for InMemoryAuditLog {
    fn write(&self, event: AuditEvent) -> Result<(), operune_observability::AuditError> {
        let mut events =
            self.events
                .lock()
                .map_err(|_| operune_observability::AuditError::WriteFailed {
                    detail: "audit log lock poisoned".to_owned(),
                })?;
        events.push(event);
        while events.len() > self.cap {
            events.remove(0);
        }
        Ok(())
    }
}

impl AuditLogView for InMemoryAuditLog {
    fn recent(&self, limit: usize) -> Vec<AuditEvent> {
        let events = match self.events.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let take = limit.min(events.len());
        events[events.len() - take..]
            .iter()
            .rev()
            .cloned()
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SafeModeState
// ---------------------------------------------------------------------------

/// safe mode 状态（§21.1；"safe mode 不自动激活有问题 Component"的语义
/// 接线由 composition root 消费本状态——0.1 只提供标志 + 审计）。
#[derive(Debug, Default)]
pub struct SafeModeState {
    enabled: AtomicBool,
}

impl SafeModeState {
    /// 新建（初始关闭）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 当前是否 safe mode。
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::SeqCst)
    }

    /// 设置状态；返回旧值。
    pub fn set_enabled(&self, enabled: bool) -> bool {
        self.enabled.swap(enabled, Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// RealAdminApi（生产实现）
// ---------------------------------------------------------------------------

/// 生产 AdminApi 实现（composition root 装配；§24.2 server 只做 wiring）。
pub struct RealAdminApi {
    install: InstallService,
    upgrade: UpgradeService,
    uninstall: UninstallService,
    active: Arc<ActiveRuntimeRegistry>,
    registry: Arc<dyn ComponentRegistryPort>,
    grants: Arc<dyn GrantStorePort>,
    config: Arc<dyn ConfigPort>,
    admin_audit: Arc<dyn AuditSink>,
    users: Arc<dyn AdminUserStore>,
    audit_view: Arc<dyn AuditLogView>,
    sessions: Arc<dyn crate::compat::SendableSessionStore>,
    session_manager: SessionManager,
    safe_mode: Arc<SafeModeState>,
    hasher: PasswordHasher,
}

impl RealAdminApi {
    /// 构造（注入全部依赖；与 InstallService / UpgradeService / WebBridge
    /// 共享同一组 Arc）。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        install: InstallService,
        upgrade: UpgradeService,
        uninstall: UninstallService,
        active: Arc<ActiveRuntimeRegistry>,
        registry: Arc<dyn ComponentRegistryPort>,
        grants: Arc<dyn GrantStorePort>,
        config: Arc<dyn ConfigPort>,
        admin_audit: Arc<dyn AuditSink>,
        users: Arc<dyn AdminUserStore>,
        audit_view: Arc<dyn AuditLogView>,
        sessions: Arc<dyn crate::compat::SendableSessionStore>,
        session_manager: SessionManager,
        safe_mode: Arc<SafeModeState>,
        hasher: PasswordHasher,
    ) -> Self {
        Self {
            install,
            upgrade,
            uninstall,
            active,
            registry,
            grants,
            config,
            admin_audit,
            users,
            audit_view,
            sessions,
            session_manager,
            safe_mode,
            hasher,
        }
    }

    fn write_admin_audit(
        &self,
        action: &str,
        message: impl Into<String>,
    ) -> Result<(), AdminError> {
        let action = AuditAction::new(action).map_err(AdminError::AdminAudit)?;
        let event = AuditEvent::new(
            AuditCategory::Security,
            AuditSeverity::Info,
            AuditOutcome::Success,
            action,
            message,
        );
        self.admin_audit
            .write(event)
            .map_err(AdminError::AdminAudit)
    }

    fn grants_view(&self, id: InstallationId) -> Result<Vec<InstallationGrant>, AdminError> {
        self.grants.grants_for(id).map_err(AdminError::Grants)
    }

    /// 主体名校验（URL 路径段安全 + §13.3 结构性校验）。
    fn validate_subject(subject: &str) -> Result<(), AdminError> {
        if subject.is_empty() {
            return Err(AdminError::InvalidInput("user subject must not be empty"));
        }
        if subject.len() > MAX_SUBJECT_LEN {
            return Err(AdminError::InvalidInput("user subject too long"));
        }
        let valid = subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if !valid {
            return Err(AdminError::InvalidInput(
                "user subject may only contain ascii alphanumeric, '-', '_' or '.'",
            ));
        }
        Ok(())
    }
}

impl AdminApi for RealAdminApi {
    fn status(&self) -> Result<StatusView, AdminError> {
        let config = self.config.snapshot().map_err(AdminError::ConfigSource)?;
        Ok(StatusView {
            installations: self
                .registry
                .list_installations()
                .map_err(AdminError::Registry)?,
            active: self.active.list(),
            config: ConfigView::from_config(&config),
            safe_mode: self.safe_mode.is_enabled(),
        })
    }

    fn list_components(&self) -> Result<Vec<ComponentView>, AdminError> {
        let records = self
            .registry
            .list_installations()
            .map_err(AdminError::Registry)?;
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            let active = self
                .active
                .get(record.installation_id)
                .map(|entry| entry.installation.clone());
            let grants = self
                .grants
                .grants_for(record.installation_id)
                .map_err(AdminError::Grants)?;
            views.push(ComponentView {
                active,
                grants,
                record,
            });
        }
        views.sort_by_key(|view| view.record.installation_id);
        Ok(views)
    }

    fn component(&self, id: InstallationId) -> Result<ComponentView, AdminError> {
        let record = self
            .registry
            .installation(id)
            .map_err(AdminError::Registry)?
            .ok_or(AdminError::NotFound(id))?;
        Ok(ComponentView {
            active: self.active.get(id).map(|entry| entry.installation.clone()),
            grants: self.grants_view(id)?,
            record,
        })
    }

    fn install(
        &self,
        bytes: Vec<u8>,
        grants: Vec<InstallationGrant>,
    ) -> Result<InstallOutcome, AdminError> {
        let config = self.config.snapshot().map_err(AdminError::ConfigSource)?;
        let size = ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if size.exceeds(config.max_component_bytes) {
            return Err(ApplicationError::OversizedComponent {
                limit: config.max_component_bytes,
                actual: size,
            }
            .into());
        }
        self.install
            .install(InstallRequest {
                bytes,
                grants: GrantApproval::Explicit(grants),
            })
            .map_err(AdminError::Application)
    }

    fn upgrade(
        &self,
        id: InstallationId,
        bytes: Vec<u8>,
        grants: Option<Vec<InstallationGrant>>,
    ) -> Result<UpgradeOutcome, AdminError> {
        let config = self.config.snapshot().map_err(AdminError::ConfigSource)?;
        let size = ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        if size.exceeds(config.max_component_bytes) {
            return Err(ApplicationError::OversizedComponent {
                limit: config.max_component_bytes,
                actual: size,
            }
            .into());
        }
        let approval = match grants {
            Some(grants) => GrantApproval::Explicit(grants),
            None => GrantApproval::ReuseExisting,
        };
        self.upgrade
            .upgrade(UpgradeRequest {
                installation: id,
                bytes,
                grants: approval,
            })
            .map_err(AdminError::Application)
    }

    fn rollback(&self, id: InstallationId) -> Result<UpgradeOutcome, AdminError> {
        self.upgrade
            .rollback(RollbackRequest { installation: id })
            .map_err(AdminError::Application)
    }

    fn disable(&self, id: InstallationId) -> Result<(), AdminError> {
        let record = self
            .registry
            .installation(id)
            .map_err(AdminError::Registry)?
            .ok_or(AdminError::NotFound(id))?;
        let draining_state = record
            .state
            .transition(ComponentLifecycleEvent::DrainStarted)
            .map_err(AdminError::Domain)?;
        let mut draining = record.clone();
        draining.state = draining_state;
        self.registry
            .update_installation(&draining)
            .map_err(AdminError::Registry)?;

        // 有界 drain（§20.4）。drain 失败时记录保持 Draining（应用层缺口：
        // 0.1 无管线级 drain 恢复路径；见 crate 文档）。
        let deadline = self
            .config
            .snapshot()
            .map_err(AdminError::ConfigSource)?
            .drain_deadline;
        if let Some(entry) = self.active.get(id) {
            Arc::clone(&entry.runtime)
                .drain(deadline)
                .map_err(ApplicationError::Runtime)?;
        }

        let mut disabled = draining;
        disabled.state = ComponentLifecycleState::Disabled;
        self.registry
            .update_installation(&disabled)
            .map_err(AdminError::Registry)?;
        self.active.remove(id);
        self.write_admin_audit(
            "component.disable",
            format!("installation {id} disabled (admin)"),
        )?;
        Ok(())
    }

    fn enable(&self, id: InstallationId) -> Result<(), AdminError> {
        // §39.2 enable：readiness 重验证 → 原子激活（复用完整激活管线，
        // §19.3）。前置状态非法 / grants 被撤销 / artifact 缺失都以
        // typed ApplicationError 拒绝（错误映射见 error.rs）。
        self.install.enable(id).map_err(AdminError::Application)
    }

    fn remove(&self, id: InstallationId) -> Result<(), AdminError> {
        // §39.2 remove / §42.4：卸载编排（drain → 停后台任务 → 清 graph
        // records → 单事务删除全部 Core 元数据；artifact 保留，§18.7）。
        // provider 仍有 active consumer 依赖 → ProviderHasConsumers 拒绝。
        // 卸载成功后才写管理面审计（与 disable 同模式；application 侧
        // 的组件生命周期审计已由 UninstallService 写入，§18.7）。
        self.uninstall
            .uninstall(id)
            .map_err(AdminError::Application)?;
        self.write_admin_audit(
            "component.remove",
            format!("installation {id} removed (admin)"),
        )
    }

    fn grants_for(&self, id: InstallationId) -> Result<Vec<InstallationGrant>, AdminError> {
        self.grants_view(id)
    }

    fn replace_grants(
        &self,
        id: InstallationId,
        grants: Vec<InstallationGrant>,
    ) -> Result<(), AdminError> {
        // §18.7 fail closed：先写 audit（durable 由实现保证），失败即中止。
        let summary: Vec<String> = grants
            .iter()
            .map(|grant| {
                format!(
                    "{} {}",
                    grant.capability.as_str(),
                    grant_scope_summary(&grant.scope)
                )
            })
            .collect();
        self.write_admin_audit(
            "grant.replace",
            format!("installation {id}: {}", summary.join("; ")),
        )?;
        self.grants
            .replace_grants(id, &grants)
            .map_err(AdminError::Grants)
    }

    fn list_users(&self) -> Result<Vec<AdminUserView>, AdminError> {
        let users = self.users.list().map_err(AdminError::Users)?;
        Ok(users
            .into_iter()
            .map(|user| AdminUserView {
                subject: user.subject,
                enabled: user.enabled,
            })
            .collect())
    }

    fn create_user(&self, subject: String, password: SecretString) -> Result<(), AdminError> {
        Self::validate_subject(&subject)?;
        let len = password.expose_secret().len();
        if !(MIN_PASSWORD_LEN..=MAX_PASSWORD_LEN).contains(&len) {
            return Err(AdminError::InvalidInput(
                "password must be between 8 and 1024 bytes",
            ));
        }
        let hash = self.hasher.hash(&password).map_err(AdminError::Password)?;
        self.users
            .create(AdminUser {
                subject: subject.clone(),
                enabled: true,
                password_hash: hash,
            })
            .map_err(AdminError::Users)?;
        self.write_admin_audit("user.create", format!("user {subject} created"))?;
        Ok(())
    }

    fn set_user_enabled(&self, subject: String, enabled: bool) -> Result<(), AdminError> {
        Self::validate_subject(&subject)?;
        self.users
            .set_enabled(&subject, enabled)
            .map_err(AdminError::Users)?;
        if !enabled {
            // §16.5：管理员禁用必须作废该主体全部 server-side session。
            let revoked = self.session_manager.revoke_all_for_subject(
                &crate::compat::SessionStoreRef::new(Arc::clone(&self.sessions)),
                &subject,
            );
            self.write_admin_audit(
                "user.disable",
                format!("user {subject} disabled, {revoked} session(s) revoked"),
            )?;
        } else {
            self.write_admin_audit("user.enable", format!("user {subject} enabled"))?;
        }
        Ok(())
    }

    fn config(&self) -> Result<RuntimeConfig, AdminError> {
        self.config.snapshot().map_err(AdminError::ConfigSource)
    }

    fn audit_recent(&self, limit: usize) -> Result<Vec<AuditEvent>, AdminError> {
        Ok(self.audit_view.recent(limit))
    }

    fn safe_mode_status(&self) -> bool {
        self.safe_mode.is_enabled()
    }

    fn set_safe_mode(&self, enabled: bool) -> Result<(), AdminError> {
        let previous = self.safe_mode.set_enabled(enabled);
        if previous != enabled {
            self.write_admin_audit(
                "safe-mode",
                if enabled {
                    "safe mode entered".to_owned()
                } else {
                    "safe mode exited".to_owned()
                },
            )?;
        }
        Ok(())
    }
}

/// 默认管理审计 sink（结构化日志通道，§5.1；durable 实现由 storage-sqlite
/// 提供并替换）。
pub fn default_admin_audit_sink() -> Arc<dyn AuditSink> {
    Arc::new(LogAuditSink)
}

/// 构造 §16.4 基线参数的 AdminPasswordHasher 便捷函数。
pub fn default_password_hasher() -> PasswordHasher {
    PasswordHasher::new(PasswordParams::DEFAULT)
}
