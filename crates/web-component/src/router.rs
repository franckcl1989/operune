//! Component Web bridge 的 HTTP 层（§21.3：窄而完整的 Core 侧闭环）。
//!
//! # 路由
//!
//! ```text
//! GET  /component/{installation}/assets/{digest}/{*path}  静态资产
//! POST /component/{installation}/actions/{action}         bounded action
//! GET  /component/{installation}/                         入口重定向（manifest.entry）
//! ```
//!
//! # 强制点（§21.3）
//!
//! - **mount namespace**：Core 分配（`InstallationId` 派生），天然不可冲突；
//! - **原子版本**（§21.5）：资产 URL 绑定激活 digest——升级后旧 URL 立即
//!   404，不存在"前端 v2 + 后端 v1"拼接；
//! - **path traversal**（§32）：`{*path}` 经 `WebAssetPath` 校验（拒绝
//!   `..`、空段、反斜杠）后才进入缓存/运行时；
//! - **bounded action**：body 上限（DefaultBodyLimit + handler 重检）、
//!   action 名称校验、服务端重做 grant/body/rate（application 的
//!   ActionPolicyPort 在 WebBridge 内）、deadline/concurrency（运行时）；
//!   响应体积上限（宿主侧硬上限）；无流 / 长连接（§21.3 只有
//!   bounded request/response）；
//! - **Core-owned headers**（§21.3）：所有响应由本层构造（Component 只
//!   提供字节 + 建议 MIME），CSP / X-Content-Type-Options 由 Core 最后写；
//!   响应绝不携带 `Set-Cookie`（无凭据边界，§16.6）；
//! - **凭据边界**：本 bridge 不读取 Root Admin session cookie / CSRF
//!   值（§21.3：浏览器内 Component 代码不接触它们）；授权 = 安装实例的
//!   grant（deny-by-default，§17.2）。

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{self, HeaderValue};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Router, body::Body};

use operune_application::contract::GuestActionPayload;
use operune_application::{ActionName, WebAssetPath};
use operune_domain::{ContentDigest, InstallationId};

use crate::bridge::ComponentWebPort;
use crate::csp::COMPONENT_CSP;
use crate::error::BridgeError;
use crate::mount::ComponentMount;

/// 挂载路由前缀（§21.3 命名空间）。
pub const ROUTE_ASSETS: &str = "/component/{installation}/assets/{digest}/{*path}";
pub const ROUTE_ACTIONS: &str = "/component/{installation}/actions/{action}";
pub const ROUTE_ENTRY: &str = "/component/{installation}";

/// bridge 的宿主侧限制（§21.3：装配期从 config 快照取值）。
#[derive(Debug, Clone, Copy)]
pub struct BridgeLimits {
    /// 单次 action 请求体上限（字节）。
    pub max_action_body_bytes: usize,
    /// 单次 action 响应体积上限（字节）。
    pub max_action_response_bytes: usize,
}

/// 装配 Component Web bridge 路由（§21.3）。
///
/// `bridge`：Component Web 用例 port（production 用
/// [`crate::bridge::AppWebBridge`] 包装 application 的 `WebBridge`）。
pub fn component_router(bridge: Arc<dyn ComponentWebPort>, limits: BridgeLimits) -> Router {
    Router::new()
        .route(ROUTE_ENTRY, get(entry_redirect))
        .route(ROUTE_ASSETS, get(asset))
        .route(
            ROUTE_ACTIONS,
            post(action).layer(DefaultBodyLimit::max(limits.max_action_body_bytes)),
        )
        .with_state(Arc::new(RouterState { bridge, limits }))
}

/// 共享状态。
pub struct RouterState {
    bridge: Arc<dyn ComponentWebPort>,
    limits: BridgeLimits,
}

/// GET /component/{installation}/ → 入口资产（§21.3 manifest.entry）。
pub async fn entry_redirect(
    State(state): State<Arc<RouterState>>,
    Path(installation): Path<InstallationId>,
) -> Response {
    let mount = ComponentMount::new(installation);
    let Some(path) = state.bridge.entry_asset(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    let Some(digest) = state.bridge.active_digest(installation) else {
        return bridge_error_response(&BridgeError::NotActiveForWeb(installation));
    };
    Redirect::to(&mount.asset_url(digest, &path)).into_response()
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

/// payload 边界解析（§13.3）。JSON content-type 的 `{"payload": string}`
/// 解析失败按 400 拒绝。
fn parse_payload(
    body: &[u8],
    content_type: Option<&str>,
) -> Result<GuestActionPayload, BridgeError> {
    let is_json = content_type.is_some_and(|value| value.contains("application/json"));
    if is_json {
        let value = serde_json::from_slice::<serde_json::Value>(body)
            .map_err(|_| BridgeError::InvalidActionName("malformed json payload"))?;
        let payload = value
            .get("payload")
            .and_then(|payload| payload.as_str())
            .ok_or(BridgeError::InvalidActionName(
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
