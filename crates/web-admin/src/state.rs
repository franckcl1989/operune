//! Root Admin 的 axum 共享状态（§21.2：依赖注入的单一来源）。
//!
//! - [`facade`]：用例面（`Arc<dyn AdminApi>`——HTTP 层只消费用例 API，
//!   不实现 application 的 ports，§24.2）；
//! - [`users`]：用户 store（登录验证 + RBAC 最小检查点，§21.1）；
//! - [`sessions`] / [`session_manager`]：session 生命周期（§16.5）；
//! - [`audit`]：管理审计 sink（登录/登出/CSRF 拒绝等安全事件，§16.6）；
//! - [`insecure_dev`]：§16.1 开发模式标记（cookie 契约 + Origin scheme 规则）；
//! - [`max_body_bytes`]：CSRF 中间件缓冲 form body 的上限（§19.1 输入
//!   不可信；外层另有 DefaultBodyLimit 纵深防御）。

use std::sync::Arc;

use operune_observability::AuditSink;
use operune_security::session::SessionManager;

use crate::auth::{ANONYMOUS_SUBJECT, DEV_SESSION_COOKIE_NAME};
use crate::compat::{SendableSessionStore, SessionStoreRef};
use crate::facade::{AdminApi, AdminUserStore};

/// Root Admin 共享状态。
pub struct AdminState {
    /// 用例面（§21.1 功能面）。
    pub facade: Arc<dyn AdminApi>,
    /// 用户 store（§21.1 users/RBAC 最小管理；登录验证 + 启用检查）。
    pub users: Arc<dyn AdminUserStore>,
    /// 权威 session store（§16.5：只存 digest）。
    pub sessions: Arc<dyn SendableSessionStore>,
    /// session 生命周期管理器（§16.5）。
    pub session_manager: SessionManager,
    /// 管理审计 sink（§16.6：不记 secret）。
    pub audit: Arc<dyn AuditSink>,
    /// §16.1 insecure dev 模式标记（影响 cookie 契约与 Origin scheme 规则）。
    pub insecure_dev: bool,
    /// CSRF 中间件缓冲 form body 的上限（字节；§19.1 输入不可信）。
    pub max_body_bytes: usize,
    /// 上传端点（install/upgrade）的 DefaultBodyLimit（字节；§19.2
    /// 输入不可信——前端限制 + 服务端限制双重强制）。
    pub upload_limit_bytes: usize,
}

impl AdminState {
    /// 构造（composition root 注入）。
    ///
    /// `upload_limit_bytes` 来自 config 快照的 `max_component_bytes`。
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        facade: Arc<dyn AdminApi>,
        users: Arc<dyn AdminUserStore>,
        sessions: Arc<dyn SendableSessionStore>,
        session_manager: SessionManager,
        audit: Arc<dyn AuditSink>,
        insecure_dev: bool,
        max_body_bytes: usize,
        upload_limit_bytes: usize,
    ) -> Self {
        Self {
            facade,
            users,
            sessions,
            session_manager,
            audit,
            insecure_dev,
            max_body_bytes: max_body_bytes.max(1),
            upload_limit_bytes: upload_limit_bytes.max(1),
        }
    }

    /// 匿名预登录主体标记（登录页 CSRF 承载，§16.5）。
    pub const fn anonymous_subject() -> &'static str {
        ANONYMOUS_SUBJECT
    }

    /// 开发模式 cookie 名（§16.1 契约）。
    pub const fn dev_cookie_name() -> &'static str {
        DEV_SESSION_COOKIE_NAME
    }

    /// `Sized` 的 session store 视图（security `SessionManager` 的
    /// `&impl SessionStore` 参数需要 Sized，见 compat 模块文档）。
    pub fn session_store(&self) -> SessionStoreRef {
        SessionStoreRef::new(Arc::clone(&self.sessions))
    }
}
