//! 用户 / RBAC 最小管理路由（§21.1 users；首次管理员由 bootstrap CLI
//! 创建，§16.3）。密码只经 HTTPS POST 表单进入（§16.1/§16.5），不记录
//! （§16.6）；哈希由 facade 经 Argon2id 生成（§16.4）。

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use secrecy::SecretString;

use crate::auth::Authenticated;
use crate::error::{admin_error_response, render_template};
use crate::routes::login::page_ctx;
use crate::state::AdminState;
use crate::templates::UsersTemplate;

/// 创建用户表单（`_csrf` 由中间件校验）。
#[derive(Deserialize)]
pub struct CreateUserForm {
    /// 主体名。
    pub subject: String,
    /// 密码（HTTPS 传输；立即包装 SecretString，§16.6）。
    pub password: String,
}

/// GET /users（列表 + 创建表单）。
pub async fn users_list(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    match state.facade.list_users() {
        Ok(users) => render_template(
            UsersTemplate {
                ctx: page_ctx(&auth),
                users,
                error: None,
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /users（创建）。
pub async fn users_create(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let password = SecretString::from(form.password);
    match state.facade.create_user(form.subject, password) {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => {
            // 重新渲染列表（错误提示；不记录密码，§16.6）。
            match state.facade.list_users() {
                Ok(users) => render_template(
                    UsersTemplate {
                        ctx: page_ctx(&auth),
                        users,
                        error: Some(error.to_string()),
                    },
                    StatusCode::BAD_REQUEST,
                ),
                Err(list_error) => admin_error_response(&list_error),
            }
        }
    }
}

/// POST /users/{subject}/disable（禁用 + 作废其全部 session，§16.5）。
pub async fn user_disable(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(subject): Path<String>,
) -> Response {
    match state.facade.set_user_enabled(subject, false) {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /users/{subject}/enable。
pub async fn user_enable(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(subject): Path<String>,
) -> Response {
    match state.facade.set_user_enabled(subject, true) {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => admin_error_response(&error),
    }
}
