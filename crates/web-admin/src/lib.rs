#![forbid(unsafe_code)]

//! Operune Root Admin Web adapter（规范 §24.2：web-admin）。
//!
//! Root Admin Axum / Askama server-side rendering adapter（§21.1 / §21.2）：
//! Runtime Recovery/Administration Plane。**只消费** application 的用例 API
//! 与 security crate，不实现 application 的 ports（那是 storage 的职责）。
//!
//! # 安全基线（第 16 章，全部实现）
//!
//! - **暴露面**（§16.1）：默认只绑定 loopback；非 loopback 必须显式生产
//!   TLS 配置（[`config::AdminListenConfig::validate`] 装配期强制）；
//! - **TLS**（§16.2 / §22.3）：rustls 安全默认集；crypto provider 由本
//!   crate（装配层）显式选择 **ring**（理由见 [`tls`] 模块文档）；TLS
//!   身份来自 [`operune_security::tls::TlsIdentity`]；无 TLS 身份时只有
//!   明确标记的 insecure loopback 开发模式（独立 cookie 契约），production
//!   不自动退化明文 HTTP；
//! - **Session**（§16.5）：server-side session，bearer token → digest →
//!   store（security crate）；登录成功旋转；idle + absolute expiry；logout
//!   作废；production cookie `__Host-operune-session`（`Secure`/`HttpOnly`/
//!   `SameSite=Strict`/`Path=/`/无 `Domain`）；
//! - **CSRF**（§16.5）：所有 state-changing 请求走统一
//!   Auth/RBAC/CSRF 中间件（[`routes`] 文档的中间件栈图）；独立 CSRF
//!   token + Origin/Referer 校验；SameSite=Strict 仅作纵深防御；
//! - **密码**（§16.6）：登录表单走 HTTPS POST，值立即包装
//!   [`secrecy::SecretString`]；日志/审计/错误路径不记录密码（测试证明）。
//!
//! # 功能面（§21.1）
//!
//! Login/Logout、Runtime status、Component install/list/detail/enable/
//! disable/upgrade/rollback、grants、users/RBAC 最小管理、Core config
//! （0.1 只读）、audit、safe mode / recovery。卸载所有 Component 后本平面
//! 仍可用；无业务 Dashboard。
//!
//! # 与 application 的 API 缺口（0.1.0，需主 agent 排期）
//!
//! 1. **安装/升级/回滚管线不可在适配层测试驱动**：application 的
//!    `GuestComponentDescriptor` 字段为 `pub(crate)`，无公开构造器；
//!    `test_support` 仅 `#[cfg(test)]`（非 feature）。web-admin 的 HTTP
//!    测试用 [`test_support::FakeAdminApi`]（假用例）注入，facade 单元测试
//!    用 [`test_support::NeverRuntime`] 桩（安装管线路径无法端到端覆盖）。
//!    建议：application 提供 `test-support` feature 或公开 descriptor 构造。
//! 2. **enable（重新激活）无用例 API**：`ActiveRuntimeRegistry::swap` 为
//!    `pub(crate)`，重新激活需要管线支持；0.1 返回
//!    [`facade::AdminError::Unsupported`]（页面明确提示）。
//! 3. **grants 管理、用户管理、safe mode、audit 读取无 application 用例**：
//!    web-admin 以 adapter 级 port（[`facade::AdminUserStore`] /
//!    [`facade::AuditLogView`] / [`facade::SafeModeState`]）表达，内存实现
//!    供 0.1 开发；durable 实现由 storage-sqlite 提供。
//! 4. **两套审计模型**：管线事件走 application 的 `AuditPort`（只有
//!    append，无读取面）；管理安全事件走 observability 的 `AuditSink`。
//!    统一 durable 读取模型待 storage 接线。
//!
//! # 模块
//!
//! - [`config`]：监听 / TLS 模式配置（§16.1）；
//! - [`tls`]：rustls `ServerConfig` 装配（§16.2 / §22.3，ring provider）；
//! - [`state`]：axum 共享状态（依赖注入单一来源）；
//! - [`facade`]：用例 facade + adapter 级 ports（users/audit/safe-mode）；
//! - [`auth`]：session 认证中间件与 cookie 装配（§16.5）；
//! - [`csrf`]：CSRF 中间件（§16.5）；
//! - [`headers`]：Core-owned 安全头（§21.2）；
//! - [`routes`]：路由表与 handler（§21.1）；
//! - [`templates`]：Askama 模板结构（`templates/*.html`，无前端构建链）。

pub mod auth;
pub mod compat;
pub mod config;
pub mod csrf;
pub mod error;
pub mod facade;
pub mod headers;
pub mod routes;
pub mod state;
pub mod templates;
pub mod tls;

#[cfg(test)]
mod facade_tests;
#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod test_support;

pub use auth::{Authenticated, build_login_cookie, build_removal_cookie, session_cookie_name};
pub use config::{AdminListenConfig, ListenConfigError, TlsMode};
pub use error::{admin_error_response, error_page};
pub use facade::{
    AdminApi, AdminError, AdminUser, AdminUserError, AdminUserStore, AdminUserView, AuditLogView,
    ComponentView, ConfigView, InMemoryAdminUserStore, InMemoryAuditLog, RealAdminApi,
    SafeModeState, StatusView, default_admin_audit_sink, default_password_hasher, format_bytes,
    grant_scope_summary,
};
pub use routes::admin_router;
pub use state::AdminState;
pub use tls::{TlsAssemblyError, build_server_config, install_ring_provider};

/// Root Admin 的共享状态别名（server 装配签名简化）。
pub type SharedAdminState = std::sync::Arc<AdminState>;
