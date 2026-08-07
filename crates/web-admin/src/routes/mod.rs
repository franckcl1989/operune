//! Root Admin 路由（§21.1 / §21.2）。
//!
//! 中间件栈（`Router::layer` 后添加者在外层）：
//!
//! ```text
//! security_headers (最外层：全部响应统一 Core-owned 安全头)
//!   └─ require_session（Auth：§16.5 session 校验 + RBAC 最小启用检查）
//!        └─ csrf_guard（§16.5：state-changing 的 Origin/Referer + CSRF
//!             token 校验；无绕过路径）
//!             └─ 路由 / handlers（install/upgrade 另有 DefaultBodyLimit）
//! ```
//!
//! `/login` 是唯一不要求 session 的路径（GET 签发匿名会话承载登录表单的
//! CSRF，§16.5）；登录成功时旋转 session（§16.5）。上传端点以原始字节
//! body 接收 `.wasm`（§19.2 输入不可信：前端 + 服务端双重大小限制）。

pub mod components;
pub mod grants;
pub mod login;
pub mod pages;
pub mod users;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, middleware};

use crate::state::AdminState;

/// 上传端点的默认 body 上限（composition root 用 config 快照覆盖；
/// 0.1 默认 64 MiB 与 `RuntimeConfig::default().max_component_bytes` 对齐）。
pub const DEFAULT_UPLOAD_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// 装配 Root Admin 路由（§21.2：统一 Auth/RBAC/CSRF 中间件，handler 无
/// 绕过路径）。
pub fn admin_router(state: Arc<AdminState>) -> Router {
    // 上传端点单独挂 DefaultBodyLimit（§19.2 输入不可信：前端限制 +
    // 服务端 DefaultBodyLimit + facade 预检 + 管线硬限制，四重防御）。
    // 不能做全局 layer：登录等表单路由会误受上传上限影响。
    let upload_limit = state.upload_limit_bytes;
    Router::new()
        .route("/login", get(login::login_page).post(login::login_post))
        .route("/logout", post(login::logout))
        .route("/", get(pages::status_page))
        .route("/components", get(components::components_list))
        .route("/components/{id}", get(components::component_detail))
        .route("/components/{id}/enable", post(components::enable_post))
        .route("/components/{id}/disable", post(components::disable_post))
        .route(
            "/components/install",
            get(components::install_form)
                .post(components::install_post)
                .layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route(
            "/components/{id}/upgrade",
            get(components::upgrade_form)
                .post(components::upgrade_post)
                .layer(DefaultBodyLimit::max(upload_limit)),
        )
        .route("/components/{id}/rollback", post(components::rollback_post))
        .route(
            "/components/{id}/remove",
            get(components::remove_form).post(components::remove_post),
        )
        .route("/grants", get(grants::grants_list))
        .route(
            "/grants/{id}",
            get(grants::grants_form).post(grants::grants_replace),
        )
        .route("/users", get(users::users_list).post(users::users_create))
        .route("/users/{subject}/disable", post(users::user_disable))
        .route("/users/{subject}/enable", post(users::user_enable))
        .route("/config", get(pages::config_page))
        .route("/audit", get(pages::audit_page))
        .route(
            "/safe-mode",
            get(pages::safe_mode_page).post(pages::safe_mode_post),
        )
        .route("/static/admin.js", get(admin_js))
        .with_state(state.clone())
        // 中间件栈（后添加者在外层）：csrf（内）→ auth（外）→ 安全头（最外）。
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::csrf::csrf_guard,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::auth::require_session,
        ))
        .layer(middleware::from_fn(crate::headers::security_headers))
        .fallback(crate::error::not_found)
}

/// 最小原生 JS（§21.2：无前端构建链；`script-src 'self'` 允许）。
pub async fn admin_js() -> Response {
    let body = include_str!("../../static/admin.js");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        body,
    )
        .into_response()
}
