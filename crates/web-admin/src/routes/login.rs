//! Login / Logout（§21.1；§16.5 session 生命周期接线）。
//!
//! - GET `/login`：无 session 时签发**匿名会话**（独立随机值，承载登录表单
//!   的 CSRF token，§16.5）并设置 cookie；已登录用户重定向到 `/`；
//! - POST `/login`：Auth/CSRF 由统一中间件完成；密码经
//!   [`AdminUserStore::verify_credentials`]（Argon2id，§16.4）验证；**登录
//!   成功旋转 session**（§16.5）；失败不旋转（防攻击者利用失败登录作废
//!   他人会话）；
//! - POST `/logout`：作废 server-side session + 删除 cookie（§16.5）。
//!
//! 密码处理（§16.6）：表单值立即包装为 `SecretString`，任何日志/审计/错误
//! 路径都不记录密码（测试证明见 `tests` 模块）。

use std::sync::Arc;

use axum::extract::{Form, FromRequest, State};
use axum::http::Request;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use cookie::Cookie;
use serde::Deserialize;
use time::OffsetDateTime;

use crate::auth::{ANONYMOUS_SUBJECT, Authenticated, build_login_cookie, redirect_to_login};
use crate::csrf::set_cookie_header;
use crate::error::{admin_error_response, render_template};
use crate::facade::AdminError;
use crate::state::AdminState;
use crate::templates::{LoginTemplate, PageContext};
use secrecy::SecretString;

/// 登录表单（`_csrf` 字段由 CSRF 中间件从 body 校验；此处忽略其值）。
#[derive(Deserialize)]
pub struct LoginForm {
    /// 用户主体名。
    pub username: String,
    /// 密码（立即包装为 `SecretString`，§16.6）。
    pub password: String,
}

/// GET /login（§16.5：匿名会话承载登录表单 CSRF）。
pub async fn login_page(
    State(state): State<Arc<AdminState>>,
    request: Request<axum::body::Body>,
) -> Response {
    let now = OffsetDateTime::now_utc();
    let existing = request.extensions().get::<Authenticated>().cloned();
    match existing {
        Some(auth) if auth.subject != ANONYMOUS_SUBJECT => Redirect::to("/").into_response(),
        Some(auth) => {
            let csrf = auth.record.csrf_secret().to_url_safe_string();
            render_template(
                LoginTemplate { csrf, error: None },
                axum::http::StatusCode::OK,
            )
        }
        None => {
            let issued = match state.session_manager.create(
                &state.session_store(),
                ANONYMOUS_SUBJECT.to_owned(),
                now,
            ) {
                Ok(issued) => issued,
                Err(error) => return admin_error_response(&AdminError::Session(error)),
            };
            let cookie = match build_login_cookie(issued.token(), now, state.insecure_dev) {
                Ok(cookie) => cookie,
                Err(error) => return admin_error_response(&AdminError::Cookie(error)),
            };
            let csrf = issued.record().csrf_secret().to_url_safe_string();
            let mut response = render_template(
                LoginTemplate { csrf, error: None },
                axum::http::StatusCode::OK,
            );
            set_session_cookie(&mut response, &cookie);
            response
        }
    }
}

/// POST /login（§16.5：登录成功旋转 session）。
pub async fn login_post(
    State(state): State<Arc<AdminState>>,
    request: Request<axum::body::Body>,
) -> Response {
    // 先取 session 上下文（Form 提取器消费 body；axum 0.8 的
    // `FromRequest::from_request` 按值取 Request）。
    let previous = request
        .extensions()
        .get::<Authenticated>()
        .map(|auth| auth.token.clone());
    let failure_csrf = request
        .extensions()
        .get::<Authenticated>()
        .map(|auth| auth.record.csrf_secret().to_url_safe_string());
    let form = match Form::<LoginForm>::from_request(request, &state).await {
        Ok(form) => form.0,
        Err(rejection) => return rejection.into_response(),
    };
    // §16.6：密码立即进入 SecretString，任何后续路径都不落日志。
    let password = SecretString::from(form.password);
    let verified = match state.users.verify_credentials(&form.username, &password) {
        Ok(verified) => verified,
        Err(error) => return admin_error_response(&AdminError::Users(error)),
    };

    if !verified {
        record_login_audit(&state, &form.username, false);
        // 失败不旋转（§16.5）；保留匿名会话供重试。不记录密码（§16.6）。
        // 正常浏览器流程总有匿名会话（GET /login 签发）；无会话的极端
        // 情形（中间件已拒绝过 CSRF，不可达）签发新匿名会话。
        let now = OffsetDateTime::now_utc();
        let (csrf, issued_cookie) = match failure_csrf {
            Some(csrf) => (csrf, None),
            None => match state.session_manager.create(
                &state.session_store(),
                ANONYMOUS_SUBJECT.to_owned(),
                now,
            ) {
                Ok(issued) => {
                    let cookie = build_login_cookie(issued.token(), now, state.insecure_dev).ok();
                    (issued.record().csrf_secret().to_url_safe_string(), cookie)
                }
                Err(error) => {
                    return admin_error_response(&AdminError::Session(error));
                }
            },
        };
        let mut response = render_template(
            LoginTemplate {
                csrf,
                error: Some("Invalid user name or password.".to_owned()),
            },
            axum::http::StatusCode::UNAUTHORIZED,
        );
        if let Some(cookie) = issued_cookie {
            set_session_cookie(&mut response, &cookie);
        }
        return response;
    }

    // 登录成功：旋转 session（§16.5：登录时旋转；旧匿名会话作废）。
    let now = OffsetDateTime::now_utc();
    let issued = match state.session_manager.rotate(
        &state.session_store(),
        previous.as_ref(),
        form.username.clone(),
        now,
    ) {
        Ok(issued) => issued,
        Err(error) => return admin_error_response(&AdminError::Session(error)),
    };
    let cookie = match build_login_cookie(issued.token(), now, state.insecure_dev) {
        Ok(cookie) => cookie,
        Err(error) => return admin_error_response(&AdminError::Cookie(error)),
    };
    record_login_audit(&state, &form.username, true);
    let mut response = Redirect::to("/").into_response();
    set_session_cookie(&mut response, &cookie);
    response
}

/// POST /logout（§16.5：作废 server-side session + 删除 cookie）。
pub async fn logout(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    let revoked = state
        .session_manager
        .revoke(&state.session_store(), &auth.token);
    let _ = state.audit.write(operune_observability::AuditEvent::new(
        operune_observability::AuditCategory::Security,
        operune_observability::AuditSeverity::Info,
        operune_observability::AuditOutcome::Success,
        // action 标识合法（此处手工构造，失败则跳过审计）。
        match operune_observability::AuditAction::new("session.logout") {
            Ok(action) => action,
            Err(_) => return redirect_to_login(state.insecure_dev),
        },
        format!("logout: session revoked = {revoked}"),
    ));
    redirect_to_login(state.insecure_dev)
}

/// 记录登录成功/失败审计（§16.6：只记主体名与结果，不记密码）。
fn record_login_audit(state: &AdminState, subject: &str, success: bool) {
    let event = operune_observability::AuditEvent::new(
        operune_observability::AuditCategory::Security,
        if success {
            operune_observability::AuditSeverity::Info
        } else {
            operune_observability::AuditSeverity::Warning
        },
        if success {
            operune_observability::AuditOutcome::Success
        } else {
            operune_observability::AuditOutcome::Denied
        },
        match operune_observability::AuditAction::new(if success {
            "session.login"
        } else {
            "session.login-failed"
        }) {
            Ok(action) => action,
            Err(_) => return,
        },
        if success {
            format!("login succeeded for subject {subject}")
        } else {
            format!("login failed for subject {subject}")
        },
    );
    let _ = state.audit.write(event);
}

/// 把 Set-Cookie 头写入响应（§16.5 cookie 契约由构造函数保证）。
pub fn set_session_cookie(response: &mut Response, cookie: &Cookie<'static>) {
    if let Some(value) = set_cookie_header(cookie) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
}

/// PageContext 构造（供其他路由模块复用）。
pub fn page_ctx(auth: &Authenticated) -> PageContext {
    PageContext {
        subject: auth.subject.clone(),
        csrf: auth.record.csrf_secret().to_url_safe_string(),
    }
}
