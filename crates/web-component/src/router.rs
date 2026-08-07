//! Component Web bridge 的 HTTP 层（§21.3 0.1 窄闭环 + §42.2 0.4 Web
//! Application Runtime 面）。
//!
//! # 路由
//!
//! ```text
//! GET  /component/{installation}/assets/{digest}/{*path}  静态资产（0.1）
//! POST /component/{installation}/actions/{action}         bounded action（0.1）
//! GET  /component/{installation}/                         入口重定向 / 默认页（0.4）
//! GET  /component/{installation}/navigation               页面列表 + 默认页（0.4）
//! GET  /component/{installation}/pages/{*path}            页面导航（0.4；页面入口 = 资产）
//! {GET|POST|PUT|PATCH|DELETE|HEAD}
//!      /component/{installation}/routes/{*path}           typed route 分发（0.4）
//! ```
//!
//! # 强制点（§21.3 + §42.2）
//!
//! - **mount namespace**：Core 分配（`InstallationId` 派生），天然不可冲突；
//! - **原子版本**（§21.5）：资产 URL 绑定激活 digest——升级后旧 URL 立即
//!   404；页面 / 导航 URL 不携带 digest，每次解析到同一 active version
//!   （no-cache 交付），不存在"前端 v2 + 后端 v1"拼接；
//! - **path traversal**（§32）：`{*path}` 经 `PagePath` / `WebAssetPath`
//!   校验（拒绝 `..`、空段、反斜杠）后才进入缓存/运行时；
//! - **typed route 分发**（§42.2）：HTTP 请求 → 声明路由表匹配（方法 +
//!   规范化路径模板）→ 参数按声明解析（闭集；类型不符 → 400，不进 guest
//!   错误空间）→ Core-mediated 调用（授权链 / 配额 / 速率 / 并发在
//!   application 内重做，403 / 429 / 503 确定拒绝）；
//! - **bounded**：body 上限（DefaultBodyLimit + handler 重检）、响应体积
//!   上限（宿主侧硬上限）、每安装实例并发 / 速率配额门
//!   （[`crate::quota::QuotaGate`]，§42.2 per-Component HTTP quotas /
//!   backpressure）；无流 / 长连接（§21.3 / §42.3：p2 同步形态）；
//! - **cancellation / disconnect**（§42.2）：每次 route 调用绑定取消令牌
//!   （[`CancelOnDrop`]）——客户端断开（handler future 被 hyper 丢弃）时
//!   令牌取消，application 侧接入运行时 epoch interruption 中止 in-flight
//!   guest 调用并丢弃结果；
//! - **Web asset caching / integrity**（§42.2）：资产响应 immutable 长缓存
//!   （digest 绑定 URL）+ RFC 9530 `Content-Digest`（资源字节级完整性，
//!   SRI 形态）；页面响应 no-cache + `Content-Digest`；
//! - **Core-owned headers**（§21.3）：所有响应由本层构造（Component 只
//!   提供字节 + 建议 MIME），CSP / X-Content-Type-Options 由 Core 最后写；
//!   响应绝不携带 `Set-Cookie`（无凭据边界，§16.6）；
//! - **凭据边界**：本 bridge 不读取 Root Admin session cookie / CSRF 值
//!   （§21.3）；授权 = 安装实例的 grant（deny-by-default，§17.2）。

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{self, HeaderValue};
use axum::http::{Method, Request, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{MethodFilter, get, on, post};
use axum::{Router, body::Body};

use operune_application::cancel::CancellationToken;
use operune_application::contract::GuestActionPayload;
use operune_application::{ActionName, ApplicationError, WebAssetPath};
use operune_domain::{ContentDigest, HttpMethod, InstallationId, PagePath};

use crate::bridge::ComponentWebPort;
use crate::csp::{COMPONENT_CSP, IMMUTABLE_CACHE, NO_CACHE};
use crate::dispatch::{build_typed_params, match_route, normalize_mount_path};
use crate::error::BridgeError;
use crate::integrity::content_digest_value;
use crate::mount::ComponentMount;
use crate::navigation::NavigationIndex;
use crate::quota::QuotaGate;

/// 挂载路由前缀（§21.3 命名空间）。
pub const ROUTE_ASSETS: &str = "/component/{installation}/assets/{digest}/{*path}";
pub const ROUTE_ACTIONS: &str = "/component/{installation}/actions/{action}";
pub const ROUTE_ENTRY: &str = "/component/{installation}";
/// 0.4 导航索引（§42.2 页面列表 + 默认页）。
pub const ROUTE_NAVIGATION: &str = "/component/{installation}/navigation";
/// 0.4 页面导航（挂载命名空间下的静态页面路径；页面入口 = 资产）。
pub const ROUTE_PAGES: &str = "/component/{installation}/pages/{*path}";
/// 0.4 typed route 分发（route namespace 的 HTTP 面）。
pub const ROUTE_DISPATCH: &str = "/component/{installation}/routes/{*path}";

/// bridge 的宿主侧限制（§21.3 0.1 基线 + §42.2 per-Component HTTP
/// quotas；装配期从 config 快照取值）。
#[derive(Debug, Clone, Copy)]
pub struct BridgeLimits {
    /// 单次 action 请求体上限（字节，0.1）。
    pub max_action_body_bytes: usize,
    /// 单次 action 响应体积上限（字节，0.1）。
    pub max_action_response_bytes: usize,
    /// 单次 typed route 请求体上限（字节，§42.2）。
    pub max_route_body_bytes: usize,
    /// 单次 typed route 响应体积上限（字节，§42.2）。
    pub max_route_response_bytes: usize,
    /// 每安装实例的并发 in-flight 调用上限（§42.2 quotas/backpressure；
    /// 超限 → 503）。
    pub max_in_flight_per_installation: usize,
    /// 每安装实例的速率上限（次/分钟，固定窗口；§42.2；超限 → 429）。
    pub max_requests_per_minute: u32,
}

impl Default for BridgeLimits {
    /// 保守默认值（装配方应显式配置；测试以默认值运行时保持宽松）。
    fn default() -> Self {
        Self {
            max_action_body_bytes: 1024,
            max_action_response_bytes: 4096,
            max_route_body_bytes: 1024,
            max_route_response_bytes: 4096,
            max_in_flight_per_installation: 16,
            max_requests_per_minute: 120,
        }
    }
}

/// 装配 Component Web bridge 路由（§21.3 + §42.2）。
///
/// `bridge`：Component Web 用例 port（production 用
/// [`crate::bridge::AppWebBridge`] 包装 application 的 `WebBridge`）。
pub fn component_router(bridge: Arc<dyn ComponentWebPort>, limits: BridgeLimits) -> Router {
    let quota = Arc::new(QuotaGate::new(
        limits.max_in_flight_per_installation,
        limits.max_requests_per_minute,
    ));
    Router::new()
        .route(ROUTE_ENTRY, get(entry_redirect))
        .route(ROUTE_ASSETS, get(asset))
        .route(ROUTE_NAVIGATION, get(navigation_index))
        .route(ROUTE_PAGES, get(page))
        .route(
            ROUTE_ACTIONS,
            post(action).layer(DefaultBodyLimit::max(limits.max_action_body_bytes)),
        )
        .route(
            ROUTE_DISPATCH,
            on(dispatch_methods(), route_dispatch)
                .layer(DefaultBodyLimit::max(limits.max_route_body_bytes)),
        )
        .with_state(Arc::new(RouterState {
            bridge,
            limits,
            quota,
        }))
}

/// 共享状态。
pub struct RouterState {
    bridge: Arc<dyn ComponentWebPort>,
    limits: BridgeLimits,
    quota: Arc<QuotaGate>,
}

/// GET /component/{installation}/ → 默认页 / 入口资产（§21.3 / §42.2）。
pub async fn entry_redirect(
    State(state): State<Arc<RouterState>>,
    Path(installation): Path<InstallationId>,
) -> Response {
    let mount = ComponentMount::new(installation);
    // §42.2：0.4 组件声明 default-page 时，挂载点根路径解析到默认页。
    if let Some(declaration) = state.bridge.app_declaration(installation)
        && let Some(default) = declaration.default_page()
    {
        let path = declaration
            .pages()
            .iter()
            .find(|page| page.page_id() == default)
            .map(|page| page.path());
        if let Some(path) = path {
            return Redirect::to(&mount.page_url(path)).into_response();
        }
    }
    // 0.1 行为（§21.3）：入口资产重定向（manifest.entry）。
    let Some(path) = state.bridge.entry_asset(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    let Some(digest) = state.bridge.active_digest(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    Redirect::to(&mount.asset_url(digest, &path)).into_response()
}

/// GET /component/{installation}/navigation（§42.2 页面列表 + 默认页）。
pub async fn navigation_index(
    State(state): State<Arc<RouterState>>,
    Path(installation): Path<InstallationId>,
) -> Response {
    let Some(declaration) = state.bridge.app_declaration(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    let document = NavigationIndex::from_declaration(&declaration);
    let body = match serde_json::to_vec(&document) {
        Ok(body) => body,
        Err(_) => {
            return bridge_error_response(&BridgeError::Application(ApplicationError::Internal(
                "navigation index serialization failed",
            )));
        }
    };
    let mut response = build_response(StatusCode::OK, "application/json", body);
    // 版本无关 URL：每次重验证（§21.5 原子版本切换）。
    insert_cache_header(&mut response, NO_CACHE);
    apply_core_headers(&mut response);
    response
}

/// GET /component/{installation}/pages/{*path}（§42.2 页面导航）。
///
/// 页面入口 = 资产：页面路径即其资产路径，经 0.1 asset 服务衔接读取
/// （同一 Core-owned 响应头与缓存事实）。
pub async fn page(
    State(state): State<Arc<RouterState>>,
    Path((installation, raw_path)): Path<(InstallationId, String)>,
) -> Response {
    // §32：页面路径无 traversal / 模板段（PagePath 段级校验，fail
    // closed）。`{*path}` 捕获不带前导 `/`（0.1 资产路由同语义）。
    let path = normalize_mount_path(&raw_path);
    let Ok(page_path) = PagePath::new(path) else {
        return bridge_error_response(&BridgeError::PageNotFound);
    };
    let Some(declaration) = state.bridge.app_declaration(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    let Some(page_declaration) = declaration
        .pages()
        .iter()
        .find(|decl| decl.path() == &page_path)
    else {
        return bridge_error_response(&BridgeError::PageNotFound);
    };
    // §42.2 page permission 强制执行点（Core-mediated）：声明了
    // required-permission 的页面经 port 重新检查授权链（grant / 权限
    // 求值在 application；未授权 403，不进 guest 错误空间）。
    if page_declaration.required_permission().is_some()
        && let Err(error) = state
            .bridge
            .check_page_access(installation, page_declaration.page_id())
    {
        return bridge_error_response(&error);
    }
    // 页面入口 = 资产（衔接 0.1 asset 服务；read_asset 内部按激活版本
    // 解析，此处只需确认安装处于 Active 快照，§21.5）。
    if state.bridge.active_digest(installation).is_none() {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    }
    // PagePath 不变量保证其值必是合法 WebAssetPath（资产路径允许模板段
    // 字符、页面路径禁止——子集关系）；构造失败属防御性路径（§14.1）。
    let Ok(asset_path) = WebAssetPath::new(page_path.as_str()) else {
        return bridge_error_response(&BridgeError::InvalidAssetPath(
            "page path is not a valid asset path",
        ));
    };
    let bytes = match state.bridge.read_asset(installation, &asset_path) {
        Ok(bytes) => bytes,
        Err(error) => return bridge_error_response(&error),
    };
    let mut response = build_response(
        StatusCode::OK,
        asset_content_type(&asset_path).unwrap_or("application/octet-stream"),
        bytes.as_ref().clone(),
    );
    // §42.2 完整性 + 版本无关 URL 的缓存语义（§21.5）。
    insert_integrity_headers(&mut response, NO_CACHE, bytes.as_ref());
    apply_core_headers(&mut response);
    response
}

/// GET /component/{installation}/assets/{digest}/{*path}（§21.3 静态资产）。
pub async fn asset(
    State(state): State<Arc<RouterState>>,
    Path((installation, digest, raw_path)): Path<(InstallationId, ContentDigest, String)>,
) -> Response {
    // §32：asset path 无 traversal（WebAssetPath 段级校验）。
    // axum 0.8 的 `{*path}` 通配捕获不带前导 `/`（WIT 契约要求规范形态
    // 带前导 `/`，§21.3），此处归一化后校验。
    let raw_path = if raw_path.starts_with('/') {
        raw_path
    } else {
        format!("/{raw_path}")
    };
    let path = match WebAssetPath::new(raw_path) {
        Ok(path) => path,
        Err(_) => return bridge_error_response(&BridgeError::InvalidAssetPath("malformed path")),
    };
    // §21.5：URL 携带的 digest 必须等于当前激活 digest——升级后旧 URL
    // 立即失效（不存在 v1 前端 + v2 后端拼接）。
    if state.bridge.active_digest(installation) != Some(digest) {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    }
    let bytes = match state.bridge.read_asset(installation, &path) {
        Ok(bytes) => bytes,
        Err(error) => return bridge_error_response(&error),
    };
    let mut response = build_response(
        StatusCode::OK,
        asset_content_type(&path).unwrap_or("application/octet-stream"),
        bytes.as_ref().clone(),
    );
    // §42.2 Web asset caching / integrity：digest 绑定 URL 是 immutable
    // 内容（升级后旧 URL 404，§21.5）→ 浏览器长缓存；响应携带 RFC 9530
    // Content-Digest（资源字节级完整性声明，SRI 形态）。
    insert_integrity_headers(&mut response, IMMUTABLE_CACHE, bytes.as_ref());
    apply_core_headers(&mut response);
    response
}

/// POST /component/{installation}/actions/{action}（§21.3 bounded action）。
pub async fn action(
    State(state): State<Arc<RouterState>>,
    Path((installation, raw_action)): Path<(InstallationId, String)>,
    request: Request<Body>,
) -> Response {
    // action 名称边界校验（§13.3：边界解析一次）。
    let action = match ActionName::new(raw_action) {
        Ok(action) => action,
        Err(_) => return bridge_error_response(&BridgeError::InvalidActionName("malformed name")),
    };

    // body（有界：DefaultBodyLimit + 此处重检，§32 oversized 提前拒绝）。
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(_) => return bridge_error_response(&BridgeError::BodyRead),
    };
    if body.len() > state.limits.max_action_body_bytes {
        return bridge_error_response(&BridgeError::BodyTooLarge);
    }

    // payload 边界解析（§13.3）：JSON content-type 必须是
    // `{"payload": "…"}` 形状；其他 content-type 按原始字节。
    let payload = match parse_payload(&body, content_type.as_deref()) {
        Ok(payload) => payload,
        Err(error) => return bridge_error_response(&error),
    };

    // §42.2 per-Component HTTP quotas（HTTP 层：速率 + 并发；超限确定
    // 拒绝，不进 guest）。
    let _guard = match state.quota.enter(installation) {
        Ok(guard) => guard,
        Err(denied) => return bridge_error_response(&BridgeError::QuotaDenied(denied)),
    };

    let response_bytes = match state.bridge.invoke_action(installation, action, payload) {
        Ok(bytes) => bytes,
        Err(error) => return bridge_error_response(&error),
    };
    // §21.3 响应体积硬上限（宿主侧）。
    if response_bytes.len() > state.limits.max_action_response_bytes {
        return bridge_error_response(&BridgeError::ResponseTooLarge);
    }

    let mut response = build_response(StatusCode::OK, "application/octet-stream", response_bytes);
    apply_core_headers(&mut response);
    response
}

/// 可声明的 HTTP 方法闭集 + HEAD（§42.2：HEAD 与 OPTIONS 不可声明，Core
/// 在 bridge 层自动处理——HEAD 按 GET 语义；OPTIONS 是 CORS 预检语义，由
/// 上层 CORS 中间件处理，不进入本面；CONNECT / TRACE 等不支持）。
fn dispatch_methods() -> MethodFilter {
    MethodFilter::GET
        .or(MethodFilter::HEAD)
        .or(MethodFilter::POST)
        .or(MethodFilter::PUT)
        .or(MethodFilter::PATCH)
        .or(MethodFilter::DELETE)
}

/// {get|head|post|put|patch|delete}
/// /component/{installation}/routes/{*path}（§42.2 typed route 分发）。
///
/// 分发顺序（全部确定语义，不进 guest 错误空间）：
/// 1. 方法归一化（HEAD → GET 语义）；
/// 2. app declaration（无 0.4 surface → 404）；
/// 3. 声明路由表匹配（方法 + 规范化路径模板；未命中 → 404）；
/// 4. 参数按声明解析（闭集；类型不符 → 400）；
/// 5. body（有界；超限 → 413；形态不符 → 400）；
/// 6. 每安装实例配额门（速率 → 429；并发 → 503）；
/// 7. Core-mediated 调用（授权链 / 配额在 application 内重做；未授权
///    → 403；配额 → 429；调用取消 → 408）；响应体积硬上限 → 502。
pub async fn route_dispatch(
    State(state): State<Arc<RouterState>>,
    Path((installation, raw_path)): Path<(InstallationId, String)>,
    request: Request<Body>,
) -> Response {
    // §42.2：HEAD 按 GET 语义处理（响应体在交付时去除，见下）。方法
    // 映射到声明闭集（HTTP 方法名是大写，`from_str_checked` 是 WIT 变体
    // 名小写——闭集映射显式完成；过滤器已保证在闭集内，其余为防御性）。
    let method = match *request.method() {
        Method::HEAD => HttpMethod::Get,
        Method::GET => HttpMethod::Get,
        Method::POST => HttpMethod::Post,
        Method::PUT => HttpMethod::Put,
        Method::PATCH => HttpMethod::Patch,
        Method::DELETE => HttpMethod::Delete,
        _ => {
            return bridge_error_response(&BridgeError::InvalidRoutePath(
                "unsupported http method",
            ));
        }
    };
    let is_head = request.method() == Method::HEAD;

    // 声明事实（§42.2 app descriptor；无 0.4 surface → 404）。
    let Some(declaration) = state.bridge.app_declaration(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    // 方法 + 路径模板匹配（route namespace；§42.2 路由表）。
    let path = normalize_mount_path(&raw_path);
    let Some((route, extracted)) = match_route(declaration.routes(), method, &path) else {
        return bridge_error_response(&BridgeError::RouteNotFound);
    };
    // 参数按声明构造（§42.2：类型不符 → 400，不进 guest 错误空间）。
    let Some(params) = build_typed_params(route, &extracted) else {
        return bridge_error_response(&BridgeError::RouteInvalidParams);
    };
    // body（有界：DefaultBodyLimit + 重检，§32）。
    let content_type = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let body = match axum::body::to_bytes(request.into_body(), usize::MAX).await {
        Ok(body) => body,
        Err(_) => return bridge_error_response(&BridgeError::BodyRead),
    };
    if body.len() > state.limits.max_route_body_bytes {
        return bridge_error_response(&BridgeError::BodyTooLarge);
    }
    let payload = match parse_payload(&body, content_type.as_deref()) {
        Ok(payload) => Some(payload),
        Err(error) => return bridge_error_response(&error),
    };
    // §42.2 per-Component HTTP quotas（HTTP 层：速率 + 并发）。
    let _guard = match state.quota.enter(installation) {
        Ok(guard) => guard,
        Err(denied) => return bridge_error_response(&BridgeError::QuotaDenied(denied)),
    };
    // §42.2 cancellation / disconnect：令牌绑定本次调用——handler future
    // 被 hyper 丢弃（客户端断开）时 CancelOnDrop 取消令牌，application 侧
    // 经该令牌执行 epoch interruption 中止 in-flight guest 调用并丢弃
    // 结果（已提交副作用不回滚，§42.2；原子写路径用 operune:state 事务）。
    let cancel = CancellationToken::new();
    let _cancel_on_drop = CancelOnDrop::new(cancel.clone());
    let response_bytes = match state.bridge.invoke_route(
        installation,
        route.route_id().clone(),
        params,
        payload,
        &cancel,
    ) {
        Ok(bytes) => bytes,
        Err(error) => return bridge_error_response(&error),
    };
    // §42.2 响应体积硬上限（宿主侧）。
    if response_bytes.len() > state.limits.max_route_response_bytes {
        return bridge_error_response(&BridgeError::ResponseTooLarge);
    }
    let mut response = build_response(StatusCode::OK, "application/octet-stream", response_bytes);
    apply_core_headers(&mut response);
    if is_head {
        // HEAD 按 GET 语义去掉响应体（§42.2 Core bridge 自动处理）。
        *response.body_mut() = Body::empty();
    }
    response
}

/// 取消-on-drop 守卫（§42.2 request cancellation / disconnect）：
/// handler future 被 hyper 丢弃（客户端断开）时取消令牌；正常完成后的
/// 取消幂等无害（调用已返回）。
struct CancelOnDrop(CancellationToken);

impl CancelOnDrop {
    fn new(token: CancellationToken) -> Self {
        Self(token)
    }
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// payload 边界解析（§13.3）。JSON content-type 的 `{"payload": string}`
/// 解析失败按 400 拒绝。
fn parse_payload(
    body: &[u8],
    content_type: Option<&str>,
) -> Result<GuestActionPayload, BridgeError> {
    let is_json = content_type.is_some_and(|value| value.contains("application/json"));
    if is_json {
        let value = serde_json::from_slice::<serde_json::Value>(body)
            .map_err(|_| BridgeError::InvalidPayload("malformed json payload"))?;
        let payload = value
            .get("payload")
            .and_then(|payload| payload.as_str())
            .ok_or(BridgeError::InvalidPayload(
                "json payload must be a string field `payload`",
            ))?;
        Ok(GuestActionPayload::Json(payload.to_owned()))
    } else {
        Ok(GuestActionPayload::Raw(body.to_vec()))
    }
}

/// 构造响应（§21.3：Core 构造响应，Component 只提供字节）。
fn build_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    response
}

/// §42.2 Web asset caching / integrity：写入缓存语义头 + RFC 9530
/// `Content-Digest`（资源字节级完整性声明；SRI 形态的最小等价实现——
/// 注释见 [`crate::integrity`]）。
fn insert_integrity_headers(response: &mut Response, cache: &'static str, bytes: &[u8]) {
    insert_cache_header(response, cache);
    // http 1.5 无 CONTENT_DIGEST 常量；from_static 对合法 ASCII 不可失败。
    if let Ok(value) = HeaderValue::from_str(&content_digest_value(bytes)) {
        response
            .headers_mut()
            .insert(header::HeaderName::from_static("content-digest"), value);
    }
}

/// 写入缓存语义头（Core-owned；Component 不可改写）。
fn insert_cache_header(response: &mut Response, cache: &'static str) {
    if let Ok(value) = HeaderValue::from_str(cache) {
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }
}

/// 资产 Content-Type（按扩展名的保守映射；§21.3 Core 保留最终校验权——
/// 作者建议 MIME 不直接进入响应头）。
fn asset_content_type(path: &WebAssetPath) -> Option<&'static str> {
    let lower = path.as_str().to_ascii_lowercase();
    if lower.ends_with(".html") || lower.ends_with(".htm") {
        Some("text/html; charset=utf-8")
    } else if lower.ends_with(".js") {
        Some("text/javascript; charset=utf-8")
    } else if lower.ends_with(".css") {
        Some("text/css; charset=utf-8")
    } else if lower.ends_with(".json") {
        Some("application/json")
    } else if lower.ends_with(".wasm") {
        Some("application/wasm")
    } else if lower.ends_with(".png") {
        Some("image/png")
    } else if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        Some("image/jpeg")
    } else if lower.ends_with(".svg") {
        // SVG 是主动内容（可含脚本）——仍由 Core 的 CSP 约束。
        Some("image/svg+xml")
    } else {
        None
    }
}

/// Core-owned 安全头（§21.3：Core 最后写；Component 响应不得覆盖）。
fn apply_core_headers(response: &mut Response) {
    // http 1.5 的 from_static 不可失败（常量均为合法 ASCII）。
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(COMPONENT_CSP),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
}

/// BridgeError → 确定 HTTP 响应（§32：错误路径不产生绕过面）。
pub fn bridge_error_response(error: &BridgeError) -> Response {
    let mut response = (error.status_code(), error.to_string()).into_response();
    apply_core_headers(&mut response);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_on_drop_cancels_token() {
        // §42.2 cancellation 机制单元级验证：守卫 drop（handler future
        // 被丢弃 / 正常完成）即取消令牌。
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
        {
            let _guard = CancelOnDrop::new(token.clone());
            assert!(!token.is_cancelled(), "调用期间令牌必须保持活跃");
        }
        assert!(token.is_cancelled(), "守卫 drop 后令牌取消（幂等无害）");
    }

    #[test]
    fn bridge_limits_defaults_are_available() {
        let limits = BridgeLimits::default();
        assert!(limits.max_in_flight_per_installation > 0);
        assert!(limits.max_requests_per_minute > 0);
        assert!(limits.max_route_body_bytes > 0);
        assert!(limits.max_route_response_bytes > 0);
    }
}
