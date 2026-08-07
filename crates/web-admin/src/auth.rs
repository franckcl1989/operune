//! Session 认证接线（§16.5）与 cookie 装配（§16.1 开发模式契约）。
//!
//! - bearer token 从 `__Host-operune-session`（production）/ 开发模式独立
//!   cookie 读取，经 [`operune_security::session::SessionManager`] 校验
//!   （digest → store，idle + absolute expiry，§16.5）；
//! - production cookie 构造完全复用 security crate（§16.5 属性全部固定）；
//!   开发模式（§16.1：明确标记的 insecure loopback）使用独立 cookie 名
//!   `operune-dev-session`（**不复用生产 Session Cookie 契约**）；
//! - 校验成功后把 [`Authenticated`]（subject + 权威记录 + bearer）注入
//!   request extension，供 handler 与 CSRF 中间件消费；
//! - 禁用用户的 session 在校验时作废（§16.5：管理员禁用必须使相关
//!   server-side session 失效）。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{self, HeaderMap};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use cookie::{Cookie, SameSite};
use operune_security::session::{SessionManager, SessionPolicy, SessionRecord};
use operune_security::session_cookie::{
    SESSION_COOKIE_NAME, build_session_cookie, build_session_cookie_removal,
};
use operune_security::token::SessionToken;
use time::OffsetDateTime;

use crate::state::AdminState;

/// 开发模式独立 cookie 名（§16.1：insecure dev 不复用生产 Session Cookie
/// 契约——不满足 `__Host-` / `Secure`）。
pub const DEV_SESSION_COOKIE_NAME: &str = "operune-dev-session";

/// 匿名预登录 session 的主体标记（§16.5：登录表单的 CSRF 需要一次
/// 有记录的匿名会话承载）。
pub const ANONYMOUS_SUBJECT: &str = "anonymous";

/// 认证上下文（auth 中间件注入 extension；handler 与 CSRF 中间件消费）。
#[derive(Clone)]
pub struct Authenticated {
    /// 会话主体。
    pub subject: String,
    /// 权威 session 记录（含 CSRF secret，§16.5）。
    pub record: SessionRecord,
    /// bearer token（logout 时作废用；只存在于请求生命周期）。
    pub token: SessionToken,
}

/// production / dev cookie 名（§16.1 契约分离）。
pub const fn session_cookie_name(insecure_dev: bool) -> &'static str {
    if insecure_dev {
        DEV_SESSION_COOKIE_NAME
    } else {
        SESSION_COOKIE_NAME
    }
}

/// 从请求 Cookie 头解析指定 cookie 的 bearer token。
///
/// 解析用 cookie crate（§22.6：不自写解析器）；解析失败/非法值一律视为
/// 无 session（不因恶意 cookie 值产生错误响应）。
pub fn session_token_from_headers(headers: &HeaderMap, name: &str) -> Option<SessionToken> {
    let value = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in value.split(';') {
        let part = part.trim();
        let parsed = Cookie::parse(part).ok()?;
        if parsed.name() == name {
            return SessionToken::from_url_safe(parsed.value()).ok();
        }
    }
    None
}

/// 构造登录成功后的 session cookie（§16.5：expires = now + absolute
/// lifetime；Max-Age 同值）。production 复用 security crate 构造并自检；
/// dev 模式手工构造（独立契约，§16.1）。
pub fn build_login_cookie(
    token: &SessionToken,
    now: OffsetDateTime,
    insecure_dev: bool,
) -> Result<Cookie<'static>, CookieBuildError> {
    let policy = SessionManager::new(SessionPolicy::DEFAULT).policy();
    let expires = now
        .checked_add(policy.absolute_lifetime())
        .ok_or(CookieBuildError::TimeOverflow)?;
    if insecure_dev {
        let mut cookie = Cookie::build((DEV_SESSION_COOKIE_NAME, token.to_url_safe_string()))
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/")
            .expires(expires)
            .max_age(policy.absolute_lifetime())
            .build();
        cookie.set_secure(false);
        Ok(cookie)
    } else {
        let cookie = build_session_cookie(token, expires, policy.absolute_lifetime());
        operune_security::session_cookie::validate_production_cookie(&cookie)
            .map_err(CookieBuildError::ProductionContract)?;
        Ok(cookie)
    }
}

/// 构造 logout / 失效用的删除 cookie（§16.5）。
pub fn build_removal_cookie(insecure_dev: bool) -> Cookie<'static> {
    if insecure_dev {
        let mut cookie = Cookie::build((DEV_SESSION_COOKIE_NAME, ""))
            .http_only(true)
            .same_site(SameSite::Strict)
            .path("/")
            .expires(OffsetDateTime::UNIX_EPOCH)
            .max_age(time::Duration::ZERO)
            .build();
        cookie.set_secure(false);
        cookie
    } else {
        build_session_cookie_removal()
    }
}

/// cookie 装配错误（封闭 typed，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum CookieBuildError {
    /// 时间计算溢出（§14.4 checked 运算）。
    #[error("cookie expiry time overflow")]
    TimeOverflow,
    /// production cookie 契约偏离（§16.5 自检失败）。
    #[error("production cookie contract deviation: {0}")]
    ProductionContract(operune_security::session_cookie::SessionCookieError),
}

/// Auth 中间件（§16.5 / §21.2：统一 Auth 检查点，无绕过路径）。
///
/// - `/login`：不要求 session（GET 签发匿名会话、POST 走 CSRF 检查）；
///   已认证 session 存在时同样注入 extension（供 handler 使用）。
/// - 其他路由：无有效 session → 303 重定向 /login（附带删除 cookie）。
/// - 被禁用主体：作废其全部 session 并重定向（§16.5）。
pub async fn require_session(
    State(state): State<Arc<AdminState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let is_login = request.uri().path() == "/login";
    let cookie_name = session_cookie_name(state.insecure_dev);
    let token = session_token_from_headers(request.headers(), cookie_name);
    let validated = match &token {
        Some(token) => state
            .session_manager
            .validate(&state.session_store(), token, OffsetDateTime::now_utc())
            .ok(),
        None => None,
    };

    let usable = match &validated {
        Some(record) => {
            // RBAC 最小检查点：主体必须存在且启用（§21.1 users/RBAC）。
            // 匿名预登录会话（§16.5：登录表单的 CSRF 承载）不是真实用户，
            // 豁免启用检查（只允许出现在 /login，见下）。
            let enabled = record.subject() == ANONYMOUS_SUBJECT
                || state.users.is_enabled(record.subject()).unwrap_or(false);
            if enabled {
                Some(record.clone())
            } else {
                // §16.5：禁用主体的 session 立即作废。
                state
                    .session_manager
                    .revoke_all_for_subject(&state.session_store(), record.subject());
                None
            }
        }
        None => None,
    };

    let Some(record) = usable else {
        if is_login {
            // 登录页不要求 session（匿名会话由 GET 处理器签发）。
            return next.run(request).await;
        }
        return redirect_to_login(state.insecure_dev);
    };

    if let Some(token) = token {
        request.extensions_mut().insert(Authenticated {
            subject: record.subject().to_owned(),
            record,
            token,
        });
    }
    next.run(request).await
}

/// 303 重定向到 /login 并附加删除 cookie（未认证 / session 失效）。
pub fn redirect_to_login(insecure_dev: bool) -> Response {
    let mut response = Redirect::to("/login").into_response();
    let removal = build_removal_cookie(insecure_dev).to_string();
    if let Ok(value) = HeaderValue::from_str(&removal) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

/// `Authenticated` 提取器（handler 使用；auth 中间件保证存在）。
impl axum::extract::FromRequestParts<Arc<AdminState>> for Authenticated {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &Arc<AdminState>,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Authenticated>()
            .cloned()
            .ok_or_else(|| axum::http::StatusCode::UNAUTHORIZED.into_response())
    }
}
