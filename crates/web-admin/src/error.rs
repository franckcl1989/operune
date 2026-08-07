//! 错误 → 确定 HTTP 响应（§14.1 封闭 typed 错误；§32 路由不能绕过
//! Auth/RBAC——错误映射不产生绕过面）。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::facade::AdminError;

/// 渲染错误页（模板；消息经 askama HTML 自动转义）。
pub fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    use askama::Template;
    let template = crate::templates::ErrorTemplate {
        title: title.to_owned(),
        message: message.to_owned(),
    };
    match template.render() {
        Ok(body) => (status, axum::response::Html(body)).into_response(),
        Err(_) => (status, "internal error page rendering failed").into_response(),
    }
}

/// 404 兜底（未知路径；§32：无隐式放行路径）。
pub async fn not_found() -> Response {
    error_page(
        StatusCode::NOT_FOUND,
        "Not found",
        "The requested path does not exist on the Root Admin plane.",
    )
}

/// `AdminError` → 确定 HTTP 响应（§32：HTTP route 不能绕过 Auth/RBAC——
/// 错误路径同样受统一中间件管辖）。
pub fn admin_error_response(error: &AdminError) -> Response {
    let (status, message) = match error {
        AdminError::NotFound(_) => (StatusCode::NOT_FOUND, error.to_string()),
        AdminError::InvalidInput(_) => (StatusCode::BAD_REQUEST, error.to_string()),
        AdminError::Unsupported(_) => (StatusCode::NOT_IMPLEMENTED, error.to_string()),
        AdminError::Application(app) => match app {
            operune_application::ApplicationError::OversizedComponent { .. } => {
                (StatusCode::PAYLOAD_TOO_LARGE, app.to_string())
            }
            operune_application::ApplicationError::NotActive(_)
            | operune_application::ApplicationError::NotActiveForWeb(_)
            | operune_application::ApplicationError::InstallationNotFound(_)
            | operune_application::ApplicationError::NoRollbackTarget(_)
            | operune_application::ApplicationError::RollbackUnavailable(_)
            | operune_application::ApplicationError::ProviderHasConsumers { .. }
            | operune_application::ApplicationError::EnableInvalidState { .. }
            | operune_application::ApplicationError::EnableRequiresApproval { .. }
            | operune_application::ApplicationError::ArtifactUnavailable(_) => {
                (StatusCode::CONFLICT, app.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, app.to_string()),
        },
        AdminError::Registry(_)
        | AdminError::Grants(_)
        | AdminError::ConfigSource(_)
        | AdminError::Audit(_)
        | AdminError::AdminAudit(_)
        | AdminError::Users(_)
        | AdminError::Password(_)
        | AdminError::Session(_)
        | AdminError::Cookie(_)
        | AdminError::Domain(_)
        | AdminError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()),
    };
    error_page(status, "Root Admin error", &message)
}

/// 渲染 askama 模板的便捷辅助（返回 Response）。
pub fn render_template(template: impl askama::Template, status: StatusCode) -> Response {
    match template.render() {
        Ok(body) => (status, axum::response::Html(body)).into_response(),
        Err(_) => error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rendering error",
            "The page template failed to render.",
        ),
    }
}
