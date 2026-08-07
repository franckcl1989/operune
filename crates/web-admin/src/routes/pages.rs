//! 页面路由：Runtime status（/）、Core config（/config）、audit（/audit）、
//! safe mode / recovery（/safe-mode）（§21.1）。

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;

use operune_observability::{AuditCategory, AuditOutcome, AuditSeverity};

use crate::auth::Authenticated;
use crate::error::{admin_error_response, render_template};
use crate::routes::login::page_ctx;
use crate::state::AdminState;
use crate::templates::{AuditRow, AuditTemplate, ConfigTemplate, SafeModeTemplate, StatusTemplate};

/// 审计页展示上限（§18.7 有界展示）。
const AUDIT_PAGE_LIMIT: usize = 200;

/// GET /（Runtime status，§21.1）。
pub async fn status_page(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    match state.facade.status() {
        Ok(view) => render_template(
            StatusTemplate {
                ctx: page_ctx(&auth),
                view,
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// GET /config（Core config，§21.1；0.1 只读，见模板说明）。
pub async fn config_page(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    match state.facade.config() {
        Ok(config) => render_template(
            ConfigTemplate {
                ctx: page_ctx(&auth),
                view: crate::facade::ConfigView::from_config(&config),
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// GET /audit（§21.1 audit；§16.6 事件内容不含 secret）。
pub async fn audit_page(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    match state.facade.audit_recent(AUDIT_PAGE_LIMIT) {
        Ok(events) => {
            let rows = events
                .into_iter()
                .map(|event| AuditRow {
                    occurred_at: event.occurred_at.to_string(),
                    category: category_label(&event.category),
                    severity: severity_label(&event.severity),
                    outcome: outcome_label(&event.outcome),
                    action: event.action.to_string(),
                    message: event.message,
                })
                .collect();
            render_template(
                AuditTemplate {
                    ctx: page_ctx(&auth),
                    events: rows,
                },
                StatusCode::OK,
            )
        }
        Err(error) => admin_error_response(&error),
    }
}

/// GET /safe-mode（§21.1 safe mode / recovery）。
pub async fn safe_mode_page(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    render_template(
        SafeModeTemplate {
            ctx: page_ctx(&auth),
            enabled: state.facade.safe_mode_status(),
            message: None,
        },
        StatusCode::OK,
    )
}

/// POST /safe-mode（切换；§16.3 精神：recovery 操作全部审计）。
pub async fn safe_mode_post(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
) -> Response {
    let target = !state.facade.safe_mode_status();
    match state.facade.set_safe_mode(target) {
        Ok(()) => render_template(
            SafeModeTemplate {
                ctx: page_ctx(&_auth),
                enabled: target,
                message: Some(if target {
                    "Safe mode entered.".to_owned()
                } else {
                    "Safe mode exited.".to_owned()
                }),
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

fn category_label(category: &AuditCategory) -> String {
    let label = match category {
        AuditCategory::Security => "security",
        AuditCategory::Component => "component",
        AuditCategory::Grant => "grant",
        AuditCategory::Config => "config",
        AuditCategory::Recovery => "recovery",
        AuditCategory::System => "system",
    };
    label.to_owned()
}

fn severity_label(severity: &AuditSeverity) -> String {
    let label = match severity {
        AuditSeverity::Info => "info",
        AuditSeverity::Warning => "warning",
        AuditSeverity::Error => "error",
        AuditSeverity::Critical => "critical",
    };
    label.to_owned()
}

fn outcome_label(outcome: &AuditOutcome) -> String {
    let label = match outcome {
        AuditOutcome::Success => "success",
        AuditOutcome::Denied => "denied",
        AuditOutcome::Failed => "failed",
    };
    label.to_owned()
}
