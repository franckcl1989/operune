//! Component Web bridge 错误（封闭 typed，§14.1；映射为确定 HTTP 响应）。

use operune_application::{ActionDenied, ApplicationError};
use operune_domain::InstallationId;

/// bridge 错误（§21.3：Core 侧确定语义拒绝）。
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
    /// 请求体超限（§21.3 body 上限）。
    #[error("action body exceeds the host-side limit")]
    BodyTooLarge,
    /// 响应体积超限（§21.3：Core 宿主侧硬上限）。
    #[error("action response exceeds the host-side limit")]
    ResponseTooLarge,
    /// 请求体读取失败。
    #[error("failed to read request body")]
    BodyRead,
    /// application 用例层错误（运行期失败等）。
    #[error("application error: {0}")]
    Application(#[source] ApplicationError),
}

impl BridgeError {
    /// 对应 HTTP 状态码（§32 测试断言用）。
    pub const fn status_code(&self) -> axum::http::StatusCode {
        use axum::http::StatusCode;
        match self {
            BridgeError::NotActiveForWeb(_) => StatusCode::NOT_FOUND,
            BridgeError::InvalidAssetPath(_) | BridgeError::InvalidActionName(_) => {
                StatusCode::BAD_REQUEST
            }
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
        }
    }
}
