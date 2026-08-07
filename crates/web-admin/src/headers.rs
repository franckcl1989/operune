//! Core-owned 安全头中间件（§21.2 / §21.3 精神：Core 最后写安全头，
//! Root Admin 页面统一由 Core 设置）。
//!
//! 对全部 Root Admin 响应设置：
//! - `X-Content-Type-Options: nosniff`
//! - `X-Frame-Options: DENY`（§21.3：Component-controlled HTML 不得嵌入
//!   Root Admin DOM；同时防点击劫持）
//! - `Referrer-Policy: no-referrer`（登录表单 POST 密码——不泄漏 Referer）
//! - `Content-Security-Policy`（Root Admin 页面自身：默认 `'self'`，无内联
//!   脚本、无外部源、`form-action 'self'`、`frame-ancestors 'none'`）
//!
//! 头值全部为静态常量（无用户数据进入 HeaderValue，无注入面）。

use axum::extract::Request;
use axum::http::header::{self, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

/// Root Admin 页面的 CSP（§21.2：最小原生 HTML/CSS/JS；脚本只允许 'self'
/// 文件——页面内联逻辑放在 `/static/admin.js`，无内联脚本）。
pub const ADMIN_CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// 安全头中间件（§16.6 / §21.3：Core-owned，组件响应不得覆盖）。
pub async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    // http 1.5 的 from_static 不可失败（常量均为合法 ASCII）。
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(ADMIN_CSP),
    );
    response
}
