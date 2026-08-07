#![cfg(test)]

//! HTTP 黑盒测试（§32 对应项：路由不能绕过 Auth/RBAC、CSRF 有效、session
//! rotation 有效、secret 不落日志、oversized 提前拒绝、上传限制）。
//!
//! 用 [`FakeAdminApi`]（假用例）注入 + `tower::ServiceExt::oneshot` 驱动；
//! TLS 装配测试见 `tests/tls.rs`（fixture 驱动）。

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{Method, Request, StatusCode};
use cookie::Cookie;
use operune_security::session::{
    InMemorySessionStore, SessionManager, SessionPolicy, SessionStore,
};
use secrecy::SecretString;
use time::OffsetDateTime;
use tower::ServiceExt;

use crate::auth::session_cookie_name;
use crate::facade::{
    AdminUser, AdminUserStore, AuditLogView, InMemoryAdminUserStore, InMemoryAuditLog,
    default_password_hasher,
};
use crate::routes::admin_router;
use crate::state::AdminState;
use crate::test_support::{FakeAdminApi, ok_or_fail, some_or_fail};

/// 测试固定 host（与 Origin 一致，§16.5 Origin 校验）。
const HOST: &str = "127.0.0.1:8443";
/// production 模式的 Origin（https，§16.5）。
const ORIGIN: &str = "https://127.0.0.1:8443";
/// 种子用户密码。
const PASSWORD: &str = "correct-horse-battery-123";

/// 测试装配。
struct TestApp {
    router: Router,
    facade: Arc<FakeAdminApi>,
    users: Arc<InMemoryAdminUserStore>,
    sessions: Arc<InMemorySessionStore>,
    manager: SessionManager,
    audit: Arc<InMemoryAuditLog>,
}

fn app(insecure_dev: bool, upload_limit: usize) -> TestApp {
    let facade = Arc::new(FakeAdminApi::new());
    let users = Arc::new(InMemoryAdminUserStore::new(default_password_hasher()));
    let sessions = Arc::new(InMemorySessionStore::new());
    let manager = SessionManager::new(SessionPolicy::DEFAULT);
    let audit = Arc::new(InMemoryAuditLog::new());
    let state = Arc::new(AdminState::new(
        Arc::clone(&facade) as Arc<dyn crate::facade::AdminApi>,
        Arc::clone(&users) as Arc<dyn crate::facade::AdminUserStore>,
        Arc::clone(&sessions) as Arc<dyn crate::compat::SendableSessionStore>,
        manager,
        Arc::clone(&audit) as Arc<dyn operune_observability::AuditSink>,
        insecure_dev,
        1024 * 1024,
        upload_limit,
    ));
    TestApp {
        router: admin_router(state),
        facade,
        users,
        sessions,
        manager,
        audit,
    }
}

/// 生产模式默认 app（上传上限 64 MiB）。
fn prod_app() -> TestApp {
    app(false, 64 * 1024 * 1024)
}

/// 种子用户（启用）。
fn seed_user(app: &TestApp, subject: &str) {
    let hash = ok_or_fail(
        default_password_hasher().hash(&SecretString::from(PASSWORD)),
        "hash",
    );
    ok_or_fail(
        app.users.create(AdminUser {
            subject: subject.to_owned(),
            enabled: true,
            password_hash: hash,
        }),
        "seed user",
    );
}

/// 请求辅助。
async fn send(
    router: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", HOST);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = ok_or_fail(builder.body(Body::from(body)), "build request");
    ok_or_fail(router.clone().oneshot(request).await, "oneshot")
}

/// 响应 body 文本。
async fn body_text(response: axum::response::Response) -> String {
    let bytes = ok_or_fail(
        axum::body::to_bytes(response.into_body(), usize::MAX).await,
        "read body",
    );
    String::from_utf8_lossy(&bytes).into_owned()
}

/// 提取 Set-Cookie 头的 cookie 属性检查。
fn response_cookie<'a>(response: &'a axum::response::Response, name: &str) -> Option<Cookie<'a>> {
    let value = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    let parsed = ok_or_fail(Cookie::parse(value), "parse set-cookie");
    if parsed.name() == name {
        Some(parsed)
    } else {
        None
    }
}

/// 提取 cookie 值（owned）。
fn response_cookie_value(response: &axum::response::Response, name: &str) -> Option<String> {
    let value = response.headers().get(header::SET_COOKIE)?.to_str().ok()?;
    let parsed = ok_or_fail(Cookie::parse(value), "parse set-cookie");
    if parsed.name() == name {
        Some(parsed.value().to_owned())
    } else {
        None
    }
}

/// 提取登录页隐藏 CSRF 字段值。
fn extract_csrf(body: &str) -> String {
    let marker = r#"name="_csrf" value=""#;
    let start = some_or_fail(body.find(marker), "csrf marker in login page");
    let rest = &body[start + marker.len()..];
    let end = some_or_fail(rest.find('"'), "csrf value end");
    rest[..end].to_owned()
}

/// 登录流程：GET /login（匿名会话 + csrf）→ POST /login（正确凭据）。
/// 返回真实 session 的 cookie 值；断言 303 → `/` 且 Set-Cookie 有效。
async fn login(app: &TestApp, subject: &str) -> String {
    seed_user(app, subject);
    let anon = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
    assert_eq!(anon.status(), StatusCode::OK);
    let anon_cookie = some_or_fail(
        response_cookie_value(&anon, session_cookie_name(false)),
        "anon cookie",
    );
    let anon_body = body_text(anon).await;
    let csrf = extract_csrf(&anon_body);

    let form = format!("username={subject}&password={PASSWORD}&_csrf={csrf}");
    let response = send(
        &app.router,
        Method::POST,
        "/login",
        &[
            ("cookie", &format!("__Host-operune-session={anon_cookie}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        form.into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/")
    );
    let session_cookie = some_or_fail(
        response_cookie_value(&response, session_cookie_name(false)),
        "session cookie",
    );
    // §16.5：登录成功旋转——新值 != 匿名会话值。
    assert_ne!(session_cookie, anon_cookie);
    session_cookie
}

/// 从会话记录的 CSRF secret 生成请求 token（测试直接读 store）。
fn csrf_for(app: &TestApp, session: &str) -> String {
    let token = ok_or_fail(
        operune_security::token::SessionToken::from_url_safe(session),
        "parse session token",
    );
    let record = some_or_fail(app.sessions.get(&token.digest()), "session record exists");
    record.csrf_secret().to_url_safe_string()
}

// ---------------------------------------------------------------------------
// Auth / 未登录（§32：HTTP route 不能绕过 Auth/RBAC）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unauthenticated_routes_redirect_to_login() {
    let app = prod_app();
    for path in [
        "/",
        "/components",
        "/components/install",
        "/grants",
        "/users",
        "/config",
        "/audit",
        "/safe-mode",
    ] {
        let response = send(&app.router, Method::GET, path, &[], Vec::new()).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "GET {path}");
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/login"),
            "GET {path}"
        );
    }
}

#[tokio::test]
async fn unauthenticated_state_changing_redirects() {
    // POST /logout 无 session：Auth 先于 CSRF 拒绝（303 → /login）。
    let app = prod_app();
    let response = send(&app.router, Method::POST, "/logout", &[], Vec::new()).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::GET,
        "/no-such-path",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// 登录 / session（§16.5）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn login_page_issues_anonymous_session_with_production_cookie() {
    let app = prod_app();
    let response = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    // §16.5：production cookie 契约（__Host-、Secure、HttpOnly、Strict、
    // Path=/、无 Domain）。
    let cookie = some_or_fail(
        response_cookie(&response, "__Host-operune-session"),
        "cookie",
    );
    ok_or_fail(
        operune_security::session_cookie::validate_production_cookie(&cookie),
        "production cookie contract",
    );
    // 页面包含 CSRF 隐藏字段（匿名会话承载，§16.5）。
    let body = body_text(response).await;
    assert!(body.contains(r#"name="_csrf""#));
}

#[tokio::test]
async fn login_success_rotates_session_and_old_anon_is_dead() {
    let app = prod_app();
    seed_user(&app, "alice");
    let anon = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
    let anon_cookie = some_or_fail(
        response_cookie_value(&anon, "__Host-operune-session"),
        "anon cookie",
    );
    let anon_body = body_text(anon).await;
    let csrf = extract_csrf(&anon_body);

    let response = send(
        &app.router,
        Method::POST,
        "/login",
        &[
            ("cookie", &format!("__Host-operune-session={anon_cookie}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!("username=alice&password={PASSWORD}&_csrf={csrf}").into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let session_cookie = some_or_fail(
        response_cookie_value(&response, "__Host-operune-session"),
        "session cookie",
    );
    assert_ne!(session_cookie, anon_cookie, "§16.5 登录必须旋转");

    // 旧匿名 token 已作废；新 token 有效（GET / → 200）。
    let old_token = ok_or_fail(
        operune_security::token::SessionToken::from_url_safe(&anon_cookie),
        "parse anon",
    );
    assert!(matches!(
        app.manager.validate(
            &crate::compat::SessionStoreRef::new(
                Arc::clone(&app.sessions) as Arc<dyn crate::compat::SendableSessionStore>
            ),
            &old_token,
            OffsetDateTime::now_utc(),
        ),
        Err(operune_security::session::SessionError::Unknown)
    ));
    let home = send(
        &app.router,
        Method::GET,
        "/",
        &[(
            "cookie",
            &format!("__Host-operune-session={session_cookie}"),
        )],
        Vec::new(),
    )
    .await;
    assert_eq!(home.status(), StatusCode::OK);
}

#[tokio::test]
async fn login_failure_does_not_rotate_and_password_not_echoed() {
    let app = prod_app();
    seed_user(&app, "alice");
    let anon = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
    let anon_cookie = some_or_fail(
        response_cookie_value(&anon, "__Host-operune-session"),
        "anon cookie",
    );
    let csrf = extract_csrf(&body_text(anon).await);

    let response = send(
        &app.router,
        Method::POST,
        "/login",
        &[
            ("cookie", &format!("__Host-operune-session={anon_cookie}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!("username=alice&password=wrong-password-xyz&_csrf={csrf}").into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let body = body_text(response).await;
    // §16.6：错误页不回显密码。
    assert!(!body.contains("wrong-password-xyz"));
    // §16.5：失败不旋转——匿名会话仍然有效（未作废）。
    let anon_token = ok_or_fail(
        operune_security::token::SessionToken::from_url_safe(&anon_cookie),
        "parse anon",
    );
    assert!(
        app.manager
            .validate(
                &crate::compat::SessionStoreRef::new(
                    Arc::clone(&app.sessions) as Arc<dyn crate::compat::SendableSessionStore>
                ),
                &anon_token,
                OffsetDateTime::now_utc(),
            )
            .is_ok()
    );
    // 审计记录了失败（只记主体，不记密码，§16.6）。
    assert!(
        app.audit
            .recent(10)
            .iter()
            .any(|event| { event.action.as_str() == "session.login-failed" })
    );
}

#[tokio::test]
async fn logged_in_user_visiting_login_redirects_home() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::GET,
        "/login",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/")
    );
}

#[tokio::test]
async fn dev_mode_uses_separate_cookie_contract() {
    // §16.1：insecure dev 不复用生产 Session Cookie 契约。
    let app = app(true, 1024);
    let response = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let cookie = some_or_fail(
        response_cookie(&response, "operune-dev-session"),
        "dev cookie",
    );
    assert_eq!(cookie.name(), "operune-dev-session");
    assert_ne!(cookie.name(), "__Host-operune-session");
    assert_ne!(cookie.secure(), Some(true), "dev cookie 不得有 Secure");
    // Origin 规则放宽：dev 模式允许 http origin。
    seed_user(&app, "alice");
    let session = {
        // 走 dev cookie 的登录流程。
        let anon = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
        let anon_cookie = some_or_fail(
            response_cookie_value(&anon, "operune-dev-session"),
            "anon dev cookie",
        );
        let csrf = extract_csrf(&body_text(anon).await);
        let response = send(
            &app.router,
            Method::POST,
            "/login",
            &[
                ("cookie", &format!("operune-dev-session={anon_cookie}")),
                ("origin", "http://127.0.0.1:8443"),
                ("content-type", "application/x-www-form-urlencoded"),
            ],
            format!("username=alice&password={PASSWORD}&_csrf={csrf}").into_bytes(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        some_or_fail(
            response_cookie_value(&response, "operune-dev-session"),
            "dev session cookie",
        )
    };
    let home = send(
        &app.router,
        Method::GET,
        "/",
        &[("cookie", &format!("operune-dev-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(home.status(), StatusCode::OK);
}

// ---------------------------------------------------------------------------
// CSRF（§16.5 / §32：CSRF 防护有效；state-changing 无 CSRF 拒绝）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn state_changing_without_csrf_token_rejected() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::POST,
        "/logout",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    // session 未被作废（拒绝发生在中间件）。
    assert!(
        app.sessions
            .get(
                &ok_or_fail(
                    operune_security::token::SessionToken::from_url_safe(&session),
                    "parse",
                )
                .digest()
            )
            .is_some()
    );
}

#[tokio::test]
async fn state_changing_with_wrong_csrf_token_rejected() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::POST,
        "/logout",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
            (
                "x-csrf-token",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn state_changing_with_wrong_origin_rejected() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    // 异源 Origin（§16.5 Origin 校验）。
    let response = send(
        &app.router,
        Method::POST,
        "/logout",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", "https://evil.example"),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-csrf-token", &csrf),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn state_changing_without_origin_rejected() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    // 无 Origin 且无 Referer（§16.5：不允许"无源"的 state-changing）。
    let response = send(
        &app.router,
        Method::POST,
        "/logout",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-csrf-token", &csrf),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn csrf_token_in_form_body_accepted() {
    // 表单路径（`_csrf` 字段，中间件从 body 提取，§16.5）。
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let response = send(
        &app.router,
        Method::POST,
        "/logout",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!("_csrf={csrf}").into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );
    // 已作废：再次使用该 session 请求受保护页 → 303。
    let after = send(
        &app.router,
        Method::GET,
        "/",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(after.status(), StatusCode::SEE_OTHER);
}

// ---------------------------------------------------------------------------
// 页面路由（§21.1）与安全头
// ---------------------------------------------------------------------------

#[tokio::test]
async fn authenticated_pages_render() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    for path in [
        "/",
        "/components",
        "/grants",
        "/users",
        "/config",
        "/audit",
        "/safe-mode",
    ] {
        let response = send(
            &app.router,
            Method::GET,
            path,
            &[("cookie", &format!("__Host-operune-session={session}"))],
            Vec::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "GET {path}");
        let body = body_text(response).await;
        // 布局导航（base.html 继承）与登录主体渲染。
        assert!(body.contains("Log out"), "GET {path} renders admin nav");
        assert!(
            body.contains("logged in as alice"),
            "GET {path} renders subject"
        );
    }
}

#[tokio::test]
async fn core_owned_security_headers_present() {
    // §21.2 / §21.3 精神：Core 统一写安全头。
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::GET,
        "/",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(
        response
            .headers()
            .get(header::X_CONTENT_TYPE_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get(header::X_FRAME_OPTIONS)
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get(header::REFERRER_POLICY)
            .and_then(|v| v.to_str().ok()),
        Some("no-referrer")
    );
    let csp = some_or_fail(
        response
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|v| v.to_str().ok()),
        "csp header",
    );
    assert!(csp.contains("frame-ancestors 'none'"));
    assert!(csp.contains("form-action 'self'"));
}

#[tokio::test]
async fn admin_js_served_with_script_content_type() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::GET,
        "/static/admin.js",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|value| value.contains("javascript"))
    );
}

// ---------------------------------------------------------------------------
// 假用例调用面（state-changing 经统一中间件到达用例层）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn install_with_csrf_reaches_facade() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    app.facade
        .with_install(operune_application::InstallOutcome::Activated {
            installation: operune_domain::InstallationId::new(),
            version: operune_domain::ComponentVersion::from_parts(1, 0, 0),
            digest: operune_domain::ContentDigest::from_bytes(b"wasm"),
        });
    let response = send(
        &app.router,
        Method::POST,
        "/components/install?grant=operune%3Aweb%2Factions",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/octet-stream"),
            ("x-csrf-token", &csrf),
        ],
        vec![0u8; 32],
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::SEE_OTHER,
        "install 应 303；实际 body: {}",
        body_text(response).await
    );
    // 假用例收到 bytes + 解析后的 grant（§17.1 显式批准）。
    assert!(app.facade.calls().iter().any(|call| matches!(
        call,
        crate::test_support::RecordedCall::Install {
            byte_len: 32,
            grants: 1
        }
    )));
}

#[tokio::test]
async fn install_without_csrf_rejected_before_facade() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::POST,
        "/components/install",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/octet-stream"),
        ],
        vec![0u8; 8],
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(app.facade.calls().is_empty(), "facade 不得被调用");
}

#[tokio::test]
async fn install_oversized_body_rejected_early() {
    // §32 oversized 输入提前拒绝：DefaultBodyLimit（服务端硬上限）。
    let app = app(false, 64); // 上传上限 64 字节。
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let response = send(
        &app.router,
        Method::POST,
        "/components/install",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/octet-stream"),
            ("x-csrf-token", &csrf),
        ],
        vec![0u8; 128],
    )
    .await;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(app.facade.calls().is_empty(), "oversized 不进入用例层");
}

#[tokio::test]
async fn upgrade_requires_approval_renders_missing_capabilities() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let installation = operune_domain::InstallationId::new();
    app.facade
        .with_upgrade(operune_application::UpgradeOutcome::RequiresApproval {
            installation,
            missing: vec![ok_or_fail(
                operune_domain::CapabilityId::new("operune:web/actions"),
                "capability",
            )],
        });
    let response = send(
        &app.router,
        Method::POST,
        &format!("/components/{installation}/upgrade"),
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/octet-stream"),
            ("x-csrf-token", &csrf),
        ],
        vec![1u8; 16],
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_text(response).await;
    // §17.5：RequiresApproval 提示列出缺失能力。
    assert!(body.contains("operune:web/actions"));
}

#[tokio::test]
async fn grants_replace_form_with_csrf() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let installation = operune_domain::InstallationId::new();
    let response = send(
        &app.router,
        Method::POST,
        &format!("/grants/{installation}"),
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!(
            "_csrf={csrf}&capabilities={}",
            "operune%3Aweb%2Factions%0Aoperune%3Aweb%2Factions%3Daction%3Arun-check"
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(app.facade.calls().iter().any(|call| matches!(
        call,
        crate::test_support::RecordedCall::ReplaceGrants { grants: 2, .. }
    )));
}

#[tokio::test]
async fn grants_replace_invalid_line_rejected() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let installation = operune_domain::InstallationId::new();
    let response = send(
        &app.router,
        Method::POST,
        &format!("/grants/{installation}"),
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!(
            "_csrf={csrf}&capabilities={}",
            "operune%3Aweb%2Factions%3Daction%3A"
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(app.facade.calls().is_empty(), "非法行不进入用例层");
}

#[tokio::test]
async fn component_unknown_id_returns_404() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let response = send(
        &app.router,
        Method::GET,
        &format!("/components/{}", operune_domain::InstallationId::new()),
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn user_create_with_csrf_reaches_facade_and_password_not_in_responses() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let password = "brand-new-password-987";
    let response = send(
        &app.router,
        Method::POST,
        "/users",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
        ],
        format!("_csrf={csrf}&subject=bob&password={password}").into_bytes(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert!(app.facade.calls().iter().any(|call| matches!(
        call,
        crate::test_support::RecordedCall::CreateUser {
            subject,
            password_len,
        } if subject == "bob" && *password_len == password.len()
    )));
    // 密码不出现在任何响应体（§16.6）。
    let users_page = send(
        &app.router,
        Method::GET,
        "/users",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert!(!body_text(users_page).await.contains(password));
}

#[tokio::test]
async fn disabled_user_session_revoked_at_request_time() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    // 登录后禁用用户（§16.5：管理员禁用 → session 失效）。
    ok_or_fail(app.users.set_enabled("alice", false), "disable user");
    let response = send(
        &app.router,
        Method::GET,
        "/",
        &[("cookie", &format!("__Host-operune-session={session}"))],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok()),
        Some("/login")
    );
    // session 记录已作废。
    let token = ok_or_fail(
        operune_security::token::SessionToken::from_url_safe(&session),
        "parse",
    );
    assert!(app.sessions.get(&token.digest()).is_none());
}

#[tokio::test]
async fn safe_mode_toggle_with_csrf() {
    let app = prod_app();
    let session = login(&app, "alice").await;
    let csrf = csrf_for(&app, &session);
    let response = send(
        &app.router,
        Method::POST,
        "/safe-mode",
        &[
            ("cookie", &format!("__Host-operune-session={session}")),
            ("origin", ORIGIN),
            ("content-type", "application/x-www-form-urlencoded"),
            ("x-csrf-token", &csrf),
        ],
        Vec::new(),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        app.facade
            .calls()
            .iter()
            .any(|call| matches!(call, crate::test_support::RecordedCall::SetSafeMode(true)))
    );
}

// ---------------------------------------------------------------------------
// §16.6：密码不落日志（tracing 捕获证明）
// ---------------------------------------------------------------------------

#[test]
fn failed_login_password_never_logged() {
    use std::sync::Mutex;
    use tracing::level_filters::LevelFilter;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct Capture(std::sync::Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .ok()
                .map(|mut data| {
                    data.extend_from_slice(buf);
                    buf.len()
                })
                .ok_or_else(|| std::io::Error::other("poisoned"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Capture;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    let capture = Capture(std::sync::Arc::new(Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(LevelFilter::TRACE)
        .with_ansi(false)
        .with_writer(capture.clone())
        .finish();

    // 审计 sink 用 LogAuditSink（登录事件流入 tracing，证明不记录密码）。
    let facade = Arc::new(FakeAdminApi::new());
    let users = Arc::new(InMemoryAdminUserStore::new(default_password_hasher()));
    let sessions = Arc::new(InMemorySessionStore::new());
    let manager = SessionManager::new(SessionPolicy::DEFAULT);
    let state = Arc::new(AdminState::new(
        Arc::clone(&facade) as Arc<dyn crate::facade::AdminApi>,
        Arc::clone(&users) as Arc<dyn crate::facade::AdminUserStore>,
        Arc::clone(&sessions) as Arc<dyn crate::compat::SendableSessionStore>,
        manager,
        Arc::new(operune_observability::LogAuditSink) as Arc<dyn operune_observability::AuditSink>,
        false,
        1024 * 1024,
        64 * 1024 * 1024,
    ));
    let app = TestApp {
        router: admin_router(state),
        facade,
        users,
        sessions,
        manager,
        audit: Arc::new(InMemoryAuditLog::new()),
    };
    let secret_password = "super-secret-pw-42-x9";
    seed_user(&app, "alice");

    let handle = ok_or_fail(
        tokio::runtime::Builder::new_current_thread().build(),
        "runtime",
    );
    let outcome = tracing::subscriber::with_default(subscriber, || {
        // 在默认 subscriber 下执行一次失败的登录（含 GET 匿名会话）。
        handle.block_on(async {
            let anon = send(&app.router, Method::GET, "/login", &[], Vec::new()).await;
            let anon_cookie = some_or_fail(
                response_cookie_value(&anon, "__Host-operune-session"),
                "anon cookie",
            );
            let csrf = extract_csrf(&body_text(anon).await);
            let response = send(
                &app.router,
                Method::POST,
                "/login",
                &[
                    ("cookie", &format!("__Host-operune-session={anon_cookie}")),
                    ("origin", ORIGIN),
                    ("content-type", "application/x-www-form-urlencoded"),
                ],
                format!("username=alice&password={secret_password}&_csrf={csrf}").into_bytes(),
            )
            .await;
            response.status()
        })
    });
    assert_eq!(outcome, StatusCode::UNAUTHORIZED);

    let guard = match capture.0.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let logs = String::from_utf8_lossy(&guard);
    // §16.6：密码不出现在任何日志输出（包括审计事件与错误路径）。
    assert!(!logs.contains(secret_password), "日志泄漏密码");
    // 审计事件本身存在（结构化的 login-failed），但不含密码值。
    assert!(logs.contains("session.login-failed"));
}
