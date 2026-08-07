//! CSRF 防护中间件（§16.5：所有 state-changing request 使用独立 CSRF
//! token 并执行 Origin/Referer 校验；SameSite=Strict 只是 defense-in-depth）。
//!
//! # 检查链（统一中间件，无绕过路径，§21.2）
//!
//! 对非 `GET`/`HEAD`/`OPTIONS` 请求：
//!
//! 1. **Origin/Referer 校验**：`Origin` 头（或 `Referer`）的主机必须与
//!    `Host` 头一致，且 scheme 为 `https`（insecure dev 模式允许
//!    `http`/`https`，§16.1 开发契约）。缺失或不匹配 → 403。
//! 2. **CSRF token 校验**：`X-CSRF-Token` 头，或（form-urlencoded 请求）
//!    表单字段 `_csrf`；与当前 session 记录的 CSRF secret 做 constant-time
//!    比较（security crate，§16.5）。缺失/不匹配 → 403。
//!
//! token 与 session bearer 是**不同随机值、不同生命周期**（§16.5：每个
//! session 记录内保存独立 [`CsrfSecret`]，session 旋转时一并更换）。
//!
//! # body 处理
//!
//! form-urlencoded 请求的 body 由中间件缓冲（上限 [`AdminState::max_body_bytes`]，
//! 外层另有 DefaultBodyLimit 纵深防御），提取 `_csrf` 后重建 request 原样
//! 放行给 handler 的 `Form` 提取器。提取不做 percent-decode：我们生成的
//! CSRF 值是 base64url（`[A-Za-z0-9_-]`），攻击者注入的 `%xx` 只会导致
//! constant-time 比较失败（拒绝），不存在解码歧义面。
//!
//! 二进制上传（octet-stream）不缓冲 body：token 必须经 `X-CSRF-Token` 头
//! 携带（页面内最小原生 JS 从表单隐藏字段读取，§21.2）。

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::{self, HeaderValue};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::auth::Authenticated;
use crate::state::AdminState;

/// CSRF token 的请求头名（浏览器侧最小 JS 使用）。
pub const CSRF_HEADER: &str = "x-csrf-token";
/// CSRF token 的表单字段名（HTML 表单隐藏字段）。
pub const CSRF_FIELD: &str = "_csrf";

/// CSRF 拒绝响应（403；不重定向——CSRF 攻击不应获得可跟随的响应）。
fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        "403: CSRF check failed (missing or invalid CSRF token / origin)",
    )
        .into_response()
}

/// CSRF 中间件（§16.5 / §21.2 统一检查点）。
pub async fn csrf_guard(
    State(state): State<Arc<AdminState>>,
    request: Request,
    next: Next,
) -> Response {
    if request.method().is_safe() {
        return next.run(request).await;
    }

    // 1. Origin/Referer 校验（§16.5：独立于 token 的通道校验）。
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if !origin_or_referer_allowed(request.headers(), host, state.insecure_dev) {
        record_denial(&state, "origin/referer");
        return forbidden();
    }

    // 2. CSRF token（头或表单字段；§16.5 constant-time 校验）。
    let header_token = request
        .headers()
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);

    let is_form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/x-www-form-urlencoded"));

    let (form_token, request) = if header_token.is_none() && is_form {
        let (parts, body) = request.into_parts();
        match axum::body::to_bytes(body, state.max_body_bytes).await {
            Ok(bytes) => {
                let token = extract_form_field(&bytes, CSRF_FIELD);
                (token, Request::from_parts(parts, Body::from(bytes)))
            }
            Err(_) => {
                record_denial(&state, "body over limit");
                return StatusCode::PAYLOAD_TOO_LARGE.into_response();
            }
        }
    } else {
        (None, request)
    };

    let token = header_token.or(form_token);

    let Some(auth) = request.extensions().get::<Authenticated>().cloned() else {
        // auth 中间件先于 csrf 运行；无认证上下文 = 无 session（含
        // /login POST 无匿名会话的情形）→ 拒绝（§16.5 无绕过路径）。
        record_denial(&state, "no session");
        return forbidden();
    };

    match token {
        Some(presented) => {
            if auth.record.csrf_secret().verify(&presented).is_ok() {
                next.run(request).await
            } else {
                record_denial(&state, "token mismatch");
                forbidden()
            }
        }
        None => {
            record_denial(&state, "missing token");
            forbidden()
        }
    }
}

/// Origin（或 Referer）与 Host 的通道校验（§16.5）。
///
/// - 必须存在 Origin 或 Referer 之一（缺失即拒绝——不允许"无源"的
///   state-changing 请求通过）；
/// - authority（host[:port]）必须与 Host 头**完全一致**；
/// - scheme：production 必须 `https`；insecure dev 允许 `http`/`https`
///   （§16.1：开发模式明确标记且不复用生产契约）。
fn origin_or_referer_allowed(
    headers: &axum::http::HeaderMap,
    host: Option<&str>,
    insecure_dev: bool,
) -> bool {
    let Some(host) = host else {
        return false;
    };
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return origin_matches(origin, host, insecure_dev);
    }
    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        return origin_matches(referer, host, insecure_dev);
    }
    false
}

/// 解析 `scheme://authority[/path]` 并校验 scheme + authority 一致。
fn origin_matches(value: &str, host: &str, insecure_dev: bool) -> bool {
    let Some((scheme, authority)) = split_origin(value) else {
        return false;
    };
    let scheme_ok = if insecure_dev {
        matches!(scheme, "http" | "https")
    } else {
        scheme == "https"
    };
    scheme_ok && authority == host
}

/// `scheme://authority[/…]` 的极简解析（不引入 url crate 依赖：
/// workspace 依赖池不含 url，§23.1）。
fn split_origin(value: &str) -> Option<(&str, &str)> {
    let (scheme, rest) = value.split_once("://")?;
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let authority = rest.split('/').next()?;
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some((scheme, authority))
}

/// 从 form-urlencoded body 提取字段值（不做 percent-decode；见模块文档）。
fn extract_form_field(body: &[u8], field: &str) -> Option<String> {
    for pair in body.split(|byte| *byte == b'&') {
        let Some((key, value)) = split_pair(pair, b'=') else {
            continue;
        };
        if key == field.as_bytes() {
            return String::from_utf8(value.to_vec()).ok();
        }
    }
    None
}

/// 在切片中按分隔字节找 `key=value` 对。
fn split_pair(bytes: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let position = bytes.iter().position(|byte| *byte == sep)?;
    Some((&bytes[..position], &bytes[position + 1..]))
}

/// 记录 CSRF 拒绝（§16.6：只记类别与路径，不记 token / body 内容）。
fn record_denial(state: &AdminState, reason: &str) {
    let event = operune_observability::AuditEvent::new(
        operune_observability::AuditCategory::Security,
        operune_observability::AuditSeverity::Warning,
        operune_observability::AuditOutcome::Denied,
        // action 标识合法（audit crate 校验通过后才会被使用）。
        match operune_observability::AuditAction::new("csrf.deny") {
            Ok(action) => action,
            Err(_) => return,
        },
        format!("state-changing request denied by CSRF guard: {reason}"),
    );
    let _ = state.audit.write(event);
}

/// Set-Cookie 头构造辅助（handlers 共用）。
pub fn set_cookie_header(cookie: &cookie::Cookie<'static>) -> Option<HeaderValue> {
    HeaderValue::from_str(&cookie.to_string()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_parsing_and_matching() {
        // 同源 https 一致。
        assert!(origin_matches(
            "https://127.0.0.1:8443",
            "127.0.0.1:8443",
            false
        ));
        // production 拒绝 http。
        assert!(!origin_matches(
            "http://127.0.0.1:8443",
            "127.0.0.1:8443",
            false
        ));
        // 开发模式允许 http。
        assert!(origin_matches(
            "http://127.0.0.1:8443",
            "127.0.0.1:8443",
            true
        ));
        // 异源拒绝。
        assert!(!origin_matches(
            "https://evil.example",
            "127.0.0.1:8443",
            false
        ));
        // 端口不同拒绝。
        assert!(!origin_matches(
            "https://127.0.0.1:9999",
            "127.0.0.1:8443",
            false
        ));
        // Referer 带路径。
        assert!(origin_matches(
            "https://127.0.0.1:8443/login",
            "127.0.0.1:8443",
            false
        ));
        // 畸形输入。
        assert!(!origin_matches("not-a-url", "127.0.0.1:8443", false));
        assert!(!origin_matches(
            "ftp://127.0.0.1:8443",
            "127.0.0.1:8443",
            false
        ));
        assert!(!origin_matches("", "127.0.0.1:8443", false));
        // authority 含 @（userinfo）拒绝。
        assert!(!origin_matches(
            "https://evil@127.0.0.1:8443",
            "127.0.0.1:8443",
            false
        ));
    }

    #[test]
    fn form_field_extraction() {
        assert_eq!(
            extract_form_field(b"username=alice&_csrf=abc123&x=1", "_csrf"),
            Some("abc123".to_owned())
        );
        assert_eq!(extract_form_field(b"username=alice", "_csrf"), None);
        assert_eq!(extract_form_field(b"", "_csrf"), None);
        // 不做 percent-decode：值原样返回（校验方 constant-time 比较拒绝
        // 任何非 base64url 输入，§16.5）。
        assert_eq!(
            extract_form_field(b"_csrf=a%2Fb", "_csrf"),
            Some("a%2Fb".to_owned())
        );
    }

    #[test]
    fn safe_methods_skip_csrf() {
        // `is_safe` 覆盖 GET/HEAD/OPTIONS（中间件入口判定）。
        assert!(axum::http::Method::GET.is_safe());
        assert!(axum::http::Method::HEAD.is_safe());
        assert!(axum::http::Method::OPTIONS.is_safe());
        assert!(!axum::http::Method::POST.is_safe());
        assert!(!axum::http::Method::PUT.is_safe());
        assert!(!axum::http::Method::DELETE.is_safe());
    }
}
