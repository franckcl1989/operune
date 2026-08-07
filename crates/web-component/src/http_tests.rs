#![cfg(test)]

//! Component Web bridge 的 HTTP 黑盒测试（§32 对应项）：
//!
//! - 静态资产 path traversal 拒绝（§32：web asset path 无 traversal）；
//! - 资产 URL 绑定激活 digest（§21.5：升级后旧 URL 立即失效）；
//! - action 未授权拒绝（§17.2 deny-by-default / §21.3 Core-mediated）；
//! - action body 超限提前拒绝（§21.3 / §32 oversized）；
//! - 响应体积超限拒绝（§21.3 宿主侧硬上限）；
//! - 响应无 Set-Cookie（§16.6 / §21.3 凭据边界）；
//! - Core-owned security headers 存在（CSP / X-Content-Type-Options；
//!   §21.3：Component 响应不得覆盖）。
//!
//! 用 [`FakeWebPort`]（假用例）注入 + `tower::ServiceExt::oneshot` 驱动。

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{Method, Request, StatusCode};
use operune_application::WebAssetPath;
use operune_domain::{ContentDigest, InstallationId};
use tower::ServiceExt;

use crate::csp::COMPONENT_CSP;
use crate::error::BridgeError;
use crate::router::{BridgeLimits, component_router};
use crate::test_support::{FakeWebPort, ok};

/// 测试装配。
struct TestApp {
    router: Router,
    port: Arc<FakeWebPort>,
}

fn app(limits: BridgeLimits) -> TestApp {
    let port = Arc::new(FakeWebPort::new());
    TestApp {
        router: component_router(
            Arc::clone(&port) as Arc<dyn crate::bridge::ComponentWebPort>,
            limits,
        ),
        port,
    }
}

fn default_limits() -> BridgeLimits {
    BridgeLimits {
        max_action_body_bytes: 1024,
        max_action_response_bytes: 4096,
    }
}

/// 请求辅助。
async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = ok(builder.body(Body::from(body)), "build request");
    ok(router.clone().oneshot(request).await, "oneshot")
}

/// 响应 body 字节。
async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    ok(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read body",
    )
    .to_vec()
}

/// 断言响应不含 Set-Cookie（§21.3 凭据边界）。
fn assert_no_set_cookie(response: &axum::response::Response) {
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "§21.3：Component bridge 响应不得携带 Set-Cookie"
    );
}

/// 断言 Core-owned 安全头存在（§21.3：Core 最后写，Component 不能覆盖）。
fn assert_core_headers(response: &axum::response::Response) {
    let csp = response
        .headers()
        .get(header::CONTENT_SECURITY_POLICY)
        .and_then(|value| value.to_str().ok());
    assert_eq!(csp, Some(COMPONENT_CSP), "Core 生成的 restrictive CSP");
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_no_set_cookie(response);
}

/// 装配一个带激活安装的测试场景。
fn installed(port: &FakeWebPort) -> (InstallationId, ContentDigest) {
    let installation = InstallationId::new();
    let digest = ContentDigest::from_bytes(b"v1 bytes");
    port.with_digest(installation, digest);
    port.with_entry(installation, ok(WebAssetPath::new("/index.html"), "entry"));
    port.with_asset(
        installation,
        ok(WebAssetPath::new("/index.html"), "asset"),
        b"<html>hello</html>".to_vec(),
    );
    port.with_action_result(installation, Ok(vec![1, 2, 3]));
    (installation, digest)
}

// ---------------------------------------------------------------------------
// 静态资产（§21.3 / §32）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn asset_served_with_core_headers_and_no_cookie() {
    let app = app(default_limits());
    let (installation, digest) = installed(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/assets/{digest}/index.html"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "asset 应 200；body: {}",
        String::from_utf8_lossy(&body_bytes(response).await)
    );
    // Core-owned headers（CSP、nosniff）+ 无 Set-Cookie（先于 body 消费）。
    assert_core_headers(&response);
    let bytes = body_bytes(response).await;
    assert_eq!(bytes, b"<html>hello</html>");
}

#[tokio::test]
async fn asset_path_traversal_rejected() {
    // §32：web asset path 无 traversal（../、空段、反斜杠）。
    let app = app(default_limits());
    let (installation, digest) = installed(&app.port);
    for bad in ["../etc/passwd", "a/../../b", "/a/./b", "/a//b", "/a%5Cb"] {
        let response = send(
            &app.router,
            Method::GET,
            &format!("/component/{installation}/assets/{digest}/{bad}"),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "path {bad:?}");
        assert_no_set_cookie(&response);
    }
}

#[tokio::test]
async fn asset_with_stale_digest_rejected() {
    // §21.5：URL 绑定激活 digest——升级后旧 URL 立即失效。
    let app = app(default_limits());
    let (installation, digest) = installed(&app.port);
    let stale = ContentDigest::from_bytes(b"old v1 bytes");
    assert_ne!(stale, digest);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/assets/{stale}/index.html"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_no_set_cookie(&response);
}

#[tokio::test]
async fn asset_unknown_installation_rejected() {
    let app = app(default_limits());
    let (_, digest) = installed(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!(
            "/component/{}/assets/{digest}/index.html",
            InstallationId::new()
        ),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn entry_redirect_points_to_digest_asset() {
    let app = app(default_limits());
    let (installation, digest) = installed(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .ok_or_fail("location");
    assert_eq!(
        location,
        format!("/component/{installation}/assets/{digest}/index.html")
    );
}

// ---------------------------------------------------------------------------
// bounded action（§21.3）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn action_success_bounded_and_header_clean() {
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        b"payload-bytes".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_core_headers(&response);
    assert_eq!(body_bytes(response).await, vec![1, 2, 3]);
    assert_eq!(app.port.action_calls(), 1, "Core-mediated 只调用一次");
}

#[tokio::test]
async fn action_json_payload_accepted() {
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/json")],
        br#"{"payload":"{\"a\":1}"}"#.to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_no_set_cookie(&response);
}

#[tokio::test]
async fn action_malformed_json_rejected() {
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/json")],
        b"{not json".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.port.action_calls(), 0, "guest 不被调用");
}

#[tokio::test]
async fn action_denied_without_grant() {
    // §17.2 deny-by-default / §21.3：服务端重做检查拒绝。
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    app.port.with_action_result(
        installation,
        Err(BridgeError::Denied(
            operune_application::ActionDenied::NotGranted,
        )),
    );
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_no_set_cookie(&response);
    assert_core_headers(&response);
}

#[tokio::test]
async fn action_rate_limited_maps_to_429() {
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    app.port.with_action_result(
        installation,
        Err(BridgeError::Denied(
            operune_application::ActionDenied::RateLimited,
        )),
    );
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn action_body_over_limit_rejected_early() {
    // §21.3 / §32 oversized：DefaultBodyLimit（64 字节）→ 413；
    // 且不进入 guest（action_calls == 0）。
    let app = app(BridgeLimits {
        max_action_body_bytes: 64,
        max_action_response_bytes: 4096,
    });
    let (installation, _) = installed(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        vec![0u8; 128],
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.port.action_calls(), 0, "oversized 不进入 guest");
}

#[tokio::test]
async fn action_response_over_limit_rejected() {
    // §21.3：响应体积宿主侧硬上限 → 502。
    let app = app(BridgeLimits {
        max_action_body_bytes: 1024,
        max_action_response_bytes: 8,
    });
    let (installation, _) = installed(&app.port);
    app.port.with_action_result(installation, Ok(vec![0u8; 64]));
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    assert_no_set_cookie(&response);
}

#[tokio::test]
async fn action_unknown_installation_rejected() {
    let app = app(default_limits());
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{}/actions/run-check", InstallationId::new()),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn action_invalid_name_rejected() {
    let app = app(default_limits());
    let (installation, _) = installed(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/{}", "bad%0Aname"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.port.action_calls(), 0);
}

// ---------------------------------------------------------------------------
// 辅助断言
// ---------------------------------------------------------------------------

trait OkOrFail<T> {
    fn ok_or_fail(self, what: &str) -> T;
}

impl<T, E: std::fmt::Debug> OkOrFail<T> for Result<T, E> {
    fn ok_or_fail(self, what: &str) -> T {
        ok(self, what)
    }
}

impl<T> OkOrFail<T> for Option<T> {
    fn ok_or_fail(self, what: &str) -> T {
        match self {
            Some(value) => value,
            None => unreachable!("{what} 应为 Some"),
        }
    }
}
