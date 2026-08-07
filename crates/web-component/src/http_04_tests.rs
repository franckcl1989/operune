#![cfg(test)]

//! 0.4.0 Web Application Runtime HTTP 面的黑盒测试（§42.2 / §32 对应项）：
//!
//! - 导航服务：页面列表（navigation 索引）、默认页（根路径解析）、
//!   页面导航（页面入口 = 资产）、未知页面 404；
//! - typed route 分发：方法 + 路径模板匹配、参数按声明解析、类型不符
//!   400、未命中 404、未授权 403、配额 429、取消 408、body / 响应
//!   超限、per-Component 配额门（速率 429 / 并发 503）；
//! - SRI / integrity：资产响应 Content-Digest + immutable 缓存语义；
//!   页面响应 no-cache + Content-Digest；
//! - cancellation：令牌经完整 HTTP 路径传递（调用期间新鲜、handler
//!   完成后取消）；
//! - 0.1 回退回归：无 0.4 声明的旧组件 entry / assets / actions 路径
//!   不变，0.4 面确定性 404。
//!
//! 用 [`FakeWebPort`]（假用例）注入 + `tower::ServiceExt::oneshot` 驱动。

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{Method, Request, StatusCode};
use operune_application::WebAssetPath;
use operune_domain::{
    AppDeclaration, AppFeatures, AssetPath, ContentDigest, HttpMethod, InstallationId,
    PageDeclaration, PageId, PagePath, ParamType, PathTemplate, PermissionDeclaration,
    PermissionName, RouteDeclaration, RouteId, RouteParam,
};
use tower::ServiceExt;

use crate::csp::{COMPONENT_CSP, IMMUTABLE_CACHE, NO_CACHE};
use crate::error::BridgeError;
use crate::integrity::content_digest_value;
use crate::router::{BridgeLimits, component_router};
use crate::test_support::{FakeWebPort, PageAccessOutcome, ok};

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
    BridgeLimits::default()
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

/// 响应 body 文本。
async fn body_text(response: axum::response::Response) -> String {
    String::from_utf8_lossy(&body_bytes(response).await).into_owned()
}

// ---------------------------------------------------------------------------
// 声明构建（§42.2 app descriptor 的测试夹具）
// ---------------------------------------------------------------------------

fn permission_name(value: &str) -> PermissionName {
    ok(PermissionName::new(value), "permission-name")
}

fn page_id(value: &str) -> PageId {
    ok(PageId::new(value), "page-id")
}

fn page_path(value: &str) -> PagePath {
    ok(PagePath::new(value), "page-path")
}

fn route_id(value: &str) -> RouteId {
    ok(RouteId::new(value), "route-id")
}

fn param(name: &str, ty: ParamType) -> RouteParam {
    ok(RouteParam::new(name, ty), "route-param")
}

fn template(value: &str) -> PathTemplate {
    ok(PathTemplate::new(value), "path-template")
}

/// 0.4 测试声明：两个页面（home 公开 / about 需 "view" 权限）+ 三条
/// route（GET 带参数、POST 需权限、DELETE 同路径不同方法）+ 默认页 home。
fn declaration() -> AppDeclaration {
    ok(
        AppDeclaration::new(
            ok(AssetPath::new("/index.html"), "entry"),
            AppFeatures::new(true, true, true, true, true),
            None,
            vec![PermissionDeclaration::new(permission_name("view"), None)],
            vec![
                PageDeclaration::new(
                    page_id("home"),
                    page_path("/home"),
                    Some("Home".to_owned()),
                    None,
                ),
                PageDeclaration::new(
                    page_id("about"),
                    page_path("/about"),
                    None,
                    Some(permission_name("view")),
                ),
            ],
            vec![
                ok(
                    RouteDeclaration::new(
                        route_id("get-item"),
                        HttpMethod::Get,
                        template("/api/{id}/item"),
                        vec![param("id", ParamType::Integer)],
                        None,
                    ),
                    "route-declaration",
                ),
                ok(
                    RouteDeclaration::new(
                        route_id("echo"),
                        HttpMethod::Post,
                        template("/echo"),
                        vec![],
                        Some(permission_name("view")),
                    ),
                    "route-declaration",
                ),
                ok(
                    RouteDeclaration::new(
                        route_id("delete-item"),
                        HttpMethod::Delete,
                        template("/api/{id}"),
                        vec![param("id", ParamType::Integer)],
                        None,
                    ),
                    "route-declaration",
                ),
            ],
            Some(page_id("home")),
        ),
        "app-declaration",
    )
}

/// 装配一个带 0.4 声明的激活安装（0.4 场景）。
fn installed04(port: &FakeWebPort) -> (InstallationId, ContentDigest) {
    let installation = InstallationId::new();
    let digest = ContentDigest::from_bytes(b"v1 bytes");
    port.with_digest(installation, digest);
    port.with_entry(installation, ok(WebAssetPath::new("/index.html"), "entry"));
    port.with_asset(
        installation,
        ok(WebAssetPath::new("/index.html"), "asset"),
        b"<html>index</html>".to_vec(),
    );
    port.with_asset(
        installation,
        ok(WebAssetPath::new("/home"), "asset"),
        b"<h1>home page</h1>".to_vec(),
    );
    port.with_asset(
        installation,
        ok(WebAssetPath::new("/about"), "asset"),
        b"<h1>about page</h1>".to_vec(),
    );
    port.with_declaration(installation, declaration());
    port.with_route_result(installation, Ok(b"route-ok".to_vec()));
    port.with_page_access(installation, PageAccessOutcome::Allowed);
    (installation, digest)
}

/// 装配一个 0.1 组件（无 0.4 声明；0.1 回退回归场景）。
fn installed01(port: &FakeWebPort) -> (InstallationId, ContentDigest) {
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

/// 断言 Core-owned 安全头存在（§21.3：Core 最后写）。
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
    assert!(
        response.headers().get(header::SET_COOKIE).is_none(),
        "§21.3：Component bridge 响应不得携带 Set-Cookie"
    );
}

fn header_str(response: &axum::response::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// 导航服务（§42.2）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn navigation_index_lists_pages_and_default_page() {
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/navigation"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_core_headers(&response);
    assert_eq!(
        header_str(&response, "content-type").as_deref(),
        Some("application/json"),
        "导航索引是 JSON 文档"
    );
    assert_eq!(
        header_str(&response, "cache-control").as_deref(),
        Some(NO_CACHE),
        "版本无关 URL：每次重验证（§21.5）"
    );
    let text = body_text(response).await;
    assert!(text.contains("\"page_id\":\"home\""), "{text}");
    assert!(text.contains("\"path\":\"/home\""), "{text}");
    assert!(text.contains("\"display_name\":\"Home\""), "{text}");
    assert!(text.contains("\"path\":\"/about\""), "{text}");
    assert!(text.contains("\"default_page\":\"home\""), "{text}");
    // 权限名不进入导航文档（Core 内部强制执行点，§42.2）。
    assert!(!text.contains("view"), "{text}");
}

#[tokio::test]
async fn navigation_unknown_installation_is_404() {
    let app = app(default_limits());
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{}/navigation", InstallationId::new()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn navigation_for_01_component_is_404() {
    // §6.7 / §42.2：无 0.4 声明的旧组件没有导航面（0.1 回退）。
    let app = app(default_limits());
    let (installation, _) = installed01(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/navigation"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn root_resolves_to_default_page() {
    // §42.2：挂载点根路径解析到默认页（home → /pages/home）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = header_str(&response, "location");
    assert_eq!(
        location.as_deref(),
        Some(format!("/component/{installation}/pages/home").as_str())
    );
}

#[tokio::test]
async fn root_for_01_component_still_redirects_to_entry_asset() {
    // 0.1 回退回归（§21.3 / §8.4）：无导航声明的旧组件根路径 → 入口资产。
    let app = app(default_limits());
    let (installation, digest) = installed01(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        header_str(&response, "location").as_deref(),
        Some(format!("/component/{installation}/assets/{digest}/index.html").as_str())
    );
}

#[tokio::test]
async fn page_navigation_serves_page_asset() {
    // 页面入口 = 资产（§42.2 衔接 0.1 asset 服务）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/home"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_core_headers(&response);
    let bytes = body_bytes(response).await;
    assert_eq!(bytes, b"<h1>home page</h1>");
}

#[tokio::test]
async fn page_navigation_unknown_page_is_404() {
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    for bad in ["missing", "a/../../etc", "home/extra"] {
        let response = send(
            &app.router,
            Method::GET,
            &format!("/component/{installation}/pages/{bad}"),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "path {bad:?}");
    }
}

#[tokio::test]
async fn page_navigation_with_permission_allowed() {
    // §42.2：required-permission 页面经 Core 检查通过 → 200。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/about"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_bytes(response).await, b"<h1>about page</h1>");
}

#[tokio::test]
async fn page_navigation_with_permission_denied_is_403() {
    // §42.2 page permission 强制执行点：未授权 → 403。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    app.port
        .with_page_access(installation, PageAccessOutcome::Denied);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/about"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_core_headers(&response);
}

#[tokio::test]
async fn page_navigation_for_01_component_is_404() {
    // 0.1 回退：旧组件无页面面。
    let app = app(default_limits());
    let (installation, _) = installed01(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/home"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// typed route 分发（§42.2）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatch_success_with_typed_params() {
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/42/item"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_core_headers(&response);
    assert_eq!(body_bytes(response).await, b"route-ok");
    assert_eq!(app.port.route_calls(), 1, "Core-mediated 只调用一次");
    // 参数按声明解析并构造（§42.2 typed 参数）。
    let params = crate::test_support::some(app.port.last_route_params(), "recorded params");
    assert_eq!(params.len(), 1);
    assert_eq!(params[0].name(), "id");
    assert_eq!(
        params[0].value(),
        &operune_domain::ParamValue::integer(42),
        "路径模板参数按声明类型解析"
    );
    // 令牌经完整路径传递：调用期间新鲜（未取消）。
    assert_eq!(
        app.port.last_route_token_was_fresh(),
        Some(true),
        "调用期间取消令牌必须未取消"
    );
}

#[tokio::test]
async fn dispatch_param_type_mismatch_is_400() {
    // §42.2：类型不符 → 400，不进 guest 错误空间。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/abc/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.port.route_calls(), 0, "参数错误不进入 guest");
}

#[tokio::test]
async fn dispatch_route_not_matched_is_404() {
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    // 未命中：路径不存在 / 方法不符（GET 请求不命中 DELETE route）。
    for (method, path) in [
        (Method::GET, "/nope/42"),
        (Method::POST, "/api/42/item"),
        (Method::GET, "/api/42"),
        (Method::GET, "/api/42/item/extra"),
    ] {
        let response = send(
            &app.router,
            method.clone(),
            &format!("/component/{installation}/routes{path}"),
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{method} {path}");
        assert_eq!(app.port.route_calls(), 0, "{method} {path}");
    }
}

#[tokio::test]
async fn dispatch_delete_route_is_method_discriminated() {
    // 同路径不同方法不冲突（§42.2）：DELETE /api/{id} 命中 delete-item。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::DELETE,
        &format!("/component/{installation}/routes/api/7"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(app.port.route_calls(), 1);
}

#[tokio::test]
async fn dispatch_unknown_installation_is_404() {
    let app = app(default_limits());
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{}/routes/api/1/item", InstallationId::new()),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dispatch_for_01_component_is_404() {
    // 0.1 回退：旧组件无 typed route 面（§6.7 / §42.2）。
    let app = app(default_limits());
    let (installation, _) = installed01(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn dispatch_unauthorized_is_403() {
    // §42.2：route permission 强制执行（Core 侧；fake 注入拒绝）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    app.port
        .with_route_result(installation, Err(BridgeError::RouteDenied));
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/routes/echo"),
        &[("content-type", "application/octet-stream")],
        b"x".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_core_headers(&response);
}

#[tokio::test]
async fn dispatch_quota_exceeded_is_429() {
    // §42.2 per-Component HTTP quotas：Core 层执行，429。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    app.port
        .with_route_result(installation, Err(BridgeError::QuotaExceeded));
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn dispatch_cancelled_maps_to_408() {
    // §42.2 cancellation：调用被取消（deadline / 服务端中断）→ 确定
    // HTTP 语义（客户端已断开时响应不交付，此处为确定性映射）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    app.port
        .with_route_result(installation, Err(BridgeError::Cancelled));
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
}

#[tokio::test]
async fn dispatch_body_over_limit_rejected_early() {
    // §32 oversized：DefaultBodyLimit → 413；不进入 guest。
    let app = app(BridgeLimits {
        max_route_body_bytes: 64,
        ..Default::default()
    });
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/routes/echo"),
        &[("content-type", "application/octet-stream")],
        vec![0u8; 128],
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(app.port.route_calls(), 0, "oversized 不进入 guest");
}

#[tokio::test]
async fn dispatch_response_over_limit_rejected() {
    // §42.2 响应体积宿主侧硬上限 → 502。
    let app = app(BridgeLimits {
        max_route_response_bytes: 4,
        ..Default::default()
    });
    let (installation, _) = installed04(&app.port);
    app.port.with_route_result(installation, Ok(vec![0u8; 64]));
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn dispatch_malformed_json_payload_is_400() {
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/routes/echo"),
        &[("content-type", "application/json")],
        b"{not json".to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(app.port.route_calls(), 0);
}

#[tokio::test]
async fn dispatch_json_payload_accepted() {
    // payload 是 route-request 的可选辅助载荷（§42.2）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/routes/echo"),
        &[("content-type", "application/json")],
        br#"{"payload":"{\"a\":1}"}"#.to_vec(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn dispatch_head_has_no_body() {
    // §42.2：HEAD 按 GET 语义（去响应体）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::HEAD,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(app.port.route_calls(), 1, "HEAD 走 GET 语义匹配");
    assert_eq!(body_bytes(response).await.len(), 0, "HEAD 响应无 body");
}

// ---------------------------------------------------------------------------
// per-Component HTTP quotas / backpressure（§42.2，HTTP 层配额门）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dispatch_rate_limit_by_http_gate_is_429() {
    // HTTP 层每安装实例速率配额：窗口内第二次 → 429。
    let app = app(BridgeLimits {
        max_requests_per_minute: 1,
        ..Default::default()
    });
    let (installation, _) = installed04(&app.port);
    let first = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/2/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(app.port.route_calls(), 1, "配额拒绝不进入 guest");
    assert_core_headers(&second);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dispatch_concurrency_limit_by_http_gate_is_503() {
    // HTTP 层每安装实例并发配额：第一个调用 in-flight 时第二个 → 503
    // （§42.2 backpressure）。
    let app = app(BridgeLimits {
        max_in_flight_per_installation: 1,
        ..Default::default()
    });
    let (installation, _) = installed04(&app.port);
    app.port.with_blocking_route(installation);
    // 第一个调用进入 invoke_route（阻塞式 fake，最多自旋 1s）。
    let first = tokio::spawn({
        let router = app.router.clone();
        async move {
            send(
                &router,
                Method::GET,
                &format!("/component/{installation}/routes/api/1/item"),
                &[],
                Vec::new(),
            )
            .await
        }
    });
    // 等待第一个调用进入端口（并发槽已占用）。
    for _ in 0..10_000 {
        if app.port.route_calls() >= 1 {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(app.port.route_calls() >= 1, "第一个调用必须已进入端口");
    let second = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/2/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(
        second.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "并发超限 → 503"
    );
    let first_response = match first.await {
        Ok(response) => response,
        Err(_) => unreachable!("first request task 应完成（JoinHandle 仅在被 abort 时 Err）"),
    };
    assert_eq!(first_response.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// SRI / integrity（§42.2 Web asset caching / integrity）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn asset_carries_content_digest_and_immutable_cache() {
    // §42.2：资产响应携带 RFC 9530 Content-Digest（资源字节级完整性，
    // SRI 形态）+ immutable 长缓存语义（digest 绑定 URL，§21.5）。
    let app = app(default_limits());
    let (installation, digest) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/assets/{digest}/index.html"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_str(&response, "cache-control").as_deref(),
        Some(IMMUTABLE_CACHE),
        "digest 绑定 URL 是 immutable 内容"
    );
    assert_eq!(
        header_str(&response, "content-digest").as_deref(),
        Some(content_digest_value(b"<html>index</html>").as_str()),
        "Content-Digest 必须是资源字节的 SHA-256 完整性声明"
    );
    assert_core_headers(&response);
}

#[tokio::test]
async fn page_carries_content_digest_and_no_cache() {
    // §42.2：页面响应同样携带完整性声明；版本无关 URL → no-cache
    // （§21.5：升级后同一 URL 解析到新的 active version）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/home"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        header_str(&response, "cache-control").as_deref(),
        Some(NO_CACHE),
        "页面 URL 不携带 digest，必须每次重验证"
    );
    assert_eq!(
        header_str(&response, "content-digest").as_deref(),
        Some(content_digest_value(b"<h1>home page</h1>").as_str())
    );
}

// ---------------------------------------------------------------------------
// cancellation 令牌（§42.2）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancellation_token_flows_through_full_http_path() {
    // 每次 route 调用绑定取消令牌：调用期间新鲜（未取消）；handler 完成
    // 后由 CancelOnDrop 取消（幂等无害；客户端断开 → handler future 被
    // hyper 丢弃 → 同一 drop 机制取消令牌 → application 侧经令牌执行
    // epoch interruption 中止 in-flight guest 调用，§42.2）。
    let app = app(default_limits());
    let (installation, _) = installed04(&app.port);
    let response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/5/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        app.port.last_route_token_was_fresh(),
        Some(true),
        "调用期间令牌必须未取消"
    );
    // oneshot 已返回 ⇒ handler 已完整结束 ⇒ CancelOnDrop 已执行。
    let token = crate::test_support::some(app.port.last_cancel_token(), "recorded cancel token");
    assert!(
        token.is_cancelled(),
        "handler 完成后 CancelOnDrop 已取消令牌"
    );
}

// ---------------------------------------------------------------------------
// 0.1 回退回归（§8.4 无 flag-day；§42.2 不推翻 0.1）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn legacy_component_keeps_01_asset_and_action_paths() {
    // 旧组件（无 0.4 声明）：asset / action / entry 路径逐项不变。
    let app = app(default_limits());
    let (installation, digest) = installed01(&app.port);

    // 资产照常服务（并带 0.4 完整性头——叠加不破坏 0.1 语义）。
    let asset_response = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/assets/{digest}/index.html"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(asset_response.status(), StatusCode::OK);
    assert_eq!(body_bytes(asset_response).await, b"<html>hello</html>");

    // action 照常服务（0.1 路径不变）。
    let action_response = send(
        &app.router,
        Method::POST,
        &format!("/component/{installation}/actions/run-check"),
        &[("content-type", "application/octet-stream")],
        b"payload-bytes".to_vec(),
    )
    .await;
    assert_eq!(action_response.status(), StatusCode::OK);
    assert_eq!(body_bytes(action_response).await, vec![1, 2, 3]);
    assert_eq!(app.port.action_calls(), 1);

    // 0.4 面确定性 404（导航 / 页面 / typed route）。
    let navigation = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/navigation"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(navigation.status(), StatusCode::NOT_FOUND);
    let pages = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/pages/home"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(pages.status(), StatusCode::NOT_FOUND);
    let routes = send(
        &app.router,
        Method::GET,
        &format!("/component/{installation}/routes/api/1/item"),
        &[],
        Vec::new(),
    )
    .await;
    assert_eq!(routes.status(), StatusCode::NOT_FOUND);
}
