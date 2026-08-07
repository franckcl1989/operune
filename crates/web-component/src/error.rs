//! Component Web bridge 错误（封闭 typed，§14.1；映射为确定 HTTP 响应）。

use operune_application::{ActionDenied, ApplicationError};
use operune_domain::InstallationId;

use crate::quota::QuotaDenied;

/// bridge 错误（§21.3 + §42.2：Core 侧确定语义拒绝，不进 guest 错误空间）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BridgeError {
    /// 安装实例未激活（§21.3：资产/action 绑定 Active 快照）。
    #[error("installation {0} is not active for web")]
    NotActiveForWeb(InstallationId),
    /// 资产路径非法（§32：web asset path 无 traversal）。
    #[error("invalid web asset path: {0}")]
    InvalidAssetPath(&'static str),
    /// action 名称非法。
    #[error("invalid action name: {0}")]
    InvalidActionName(&'static str),
    /// action 被 Core 侧拒绝（§21.3 服务端重做检查）。
    #[error("action denied: {0}")]
    Denied(ActionDenied),
    /// 请求体超限（§21.3 / §42.2 body 上限）。
    #[error("request body exceeds the host-side limit")]
    BodyTooLarge,
    /// 响应体积超限（§21.3 / §42.2：Core 宿主侧硬上限）。
    #[error("response exceeds the host-side limit")]
    ResponseTooLarge,
    /// 请求体读取失败。
    #[error("failed to read request body")]
    BodyRead,
    /// 请求载荷非法（§13.3 边界解析失败；JSON / 原始字节形态不符）。
    #[error("invalid payload: {0}")]
    InvalidPayload(&'static str),
    /// application 用例层错误（运行期失败等）。
    #[error("application error: {0}")]
    Application(#[source] ApplicationError),

    // ------------------------------------------------------------------
    // 0.4.0（§42.2 Web Application Runtime）
    // ------------------------------------------------------------------
    /// 0.4 面未接线（接线点：[`crate::bridge::AppWebBridge`] 委托
    /// application 的 [`operune_application::WebAppService`]；0.4.0 起生产
    /// 接线已落地，本变体保留在封闭集合中以表达未注入服务的组合状态——
    /// 当前无生产构造点，防御性保留）。
    #[error("0.4 web application surface is not wired (application WebAppService adapter pending)")]
    WebAppNotWired,
    /// 页面不存在（导航；§42.2 pages——挂载命名空间下的静态页面路径）。
    #[error("page not found")]
    PageNotFound,
    /// 页面被 Core 侧拒绝（§42.2 page permission 强制执行点；授权链在
    /// application 内求值）。
    #[error("page access denied")]
    PageDenied,
    /// route 未声明（防御性闭集：HTTP 层分发前已按声明路由表匹配，未命中
    /// 即 404；该变体是 port 侧的防御路径）。
    #[error("route not found")]
    RouteNotFound,
    /// 参数与声明不一致（防御性闭集：HTTP 层分发前已按声明校验并构造；
    /// 该变体是 port 侧的防御路径）。
    #[error("invalid route params")]
    RouteInvalidParams,
    /// route 被 Core 侧拒绝（§42.2：授权链 / route permission 求值在
    /// application 内执行）。
    #[error("route denied")]
    RouteDenied,
    /// 配额超限（§42.2 per-Component HTTP quotas；Core 层执行，429）。
    #[error("component quota exceeded")]
    QuotaExceeded,
    /// route 调用被取消（§42.2 request cancellation / disconnect；客户端
    /// 断开或 deadline 后 Core 中止调用并丢弃结果）。
    #[error("request cancelled")]
    Cancelled,
    /// route 调用 deadline 到期（§42.2：运行时 epoch 强制；504 语义）。
    #[error("route call deadline exceeded")]
    DeadlineExceeded,
    /// route 路径非法（防御性；正常请求路径不产生）。
    #[error("invalid route path: {0}")]
    InvalidRoutePath(&'static str),
    /// 每安装实例配额拒绝（§42.2 quotas / backpressure；HTTP 层执行）。
    #[error("quota denied: {0}")]
    QuotaDenied(QuotaDenied),
}

impl BridgeError {
    /// 对应 HTTP 状态码（§32 测试断言用）。
    pub const fn status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            BridgeError::NotActiveForWeb(_) => StatusCode::NOT_FOUND,
            BridgeError::InvalidAssetPath(_)
            | BridgeError::InvalidActionName(_)
            | BridgeError::InvalidPayload(_)
            | BridgeError::InvalidRoutePath(_)
            | BridgeError::RouteInvalidParams => StatusCode::BAD_REQUEST,
            BridgeError::Denied(ActionDenied::NotGranted)
            | BridgeError::Denied(ActionDenied::Unknown) => StatusCode::FORBIDDEN,
            BridgeError::Denied(ActionDenied::RateLimited) => StatusCode::TOO_MANY_REQUESTS,
            BridgeError::Denied(ActionDenied::BodyTooLarge) | BridgeError::BodyTooLarge => {
                StatusCode::PAYLOAD_TOO_LARGE
            }
            BridgeError::Denied(ActionDenied::Busy) => StatusCode::SERVICE_UNAVAILABLE,
            BridgeError::ResponseTooLarge | BridgeError::BodyRead | BridgeError::Application(_) => {
                StatusCode::BAD_GATEWAY
            }
            // 0.4（§42.2）。
            BridgeError::WebAppNotWired => StatusCode::NOT_IMPLEMENTED,
            BridgeError::PageNotFound | BridgeError::RouteNotFound => StatusCode::NOT_FOUND,
            BridgeError::PageDenied | BridgeError::RouteDenied => StatusCode::FORBIDDEN,
            BridgeError::QuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            BridgeError::Cancelled => StatusCode::REQUEST_TIMEOUT,
            BridgeError::DeadlineExceeded => StatusCode::GATEWAY_TIMEOUT,
            BridgeError::QuotaDenied(QuotaDenied::RateLimited) => StatusCode::TOO_MANY_REQUESTS,
            BridgeError::QuotaDenied(QuotaDenied::Busy) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}
