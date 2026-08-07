//! Grants 路由（§21.1 grants；§17.5 显式重新批准，绑定 InstallationId）。

use std::sync::Arc;

use axum::extract::{Form, Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use operune_application::GrantScope;
use operune_domain::{CapabilityId, InstallationId};

use crate::auth::Authenticated;
use crate::error::{admin_error_response, render_template};
use crate::facade::AdminError;
use crate::routes::components::grant_lines;
use crate::routes::login::page_ctx;
use crate::state::AdminState;
use crate::templates::component_row;
use crate::templates::{GrantsFormTemplate, GrantsTemplate};
use operune_application::InstallationGrant;

/// grants 替换表单（`_csrf` 由中间件校验；此处忽略）。
#[derive(Deserialize)]
pub struct GrantsForm {
    /// 每行一条：`capability` 或 `capability=action:name`。
    pub capabilities: String,
}

/// 解析一行 grant 规格（§17.3：unscoped 或 action scope）。
pub fn parse_grant_line(line: &str) -> Result<InstallationGrant, AdminError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(AdminError::InvalidInput("grant line must not be empty"));
    }
    let (capability, scope) = match line.split_once('=') {
        Some((capability, spec)) => {
            let spec = spec.trim();
            if let Some(action) = spec.strip_prefix("action:") {
                let action = action.trim();
                if action.is_empty() {
                    return Err(AdminError::InvalidInput("action scope must not be empty"));
                }
                (
                    capability.trim(),
                    GrantScope::Action {
                        name: action.to_owned(),
                    },
                )
            } else {
                return Err(AdminError::InvalidInput(
                    "unsupported grant scope spec (expected `capability` or `capability=action:name`)",
                ));
            }
        }
        None => (line, GrantScope::Unscoped),
    };
    let capability = CapabilityId::new(capability)
        .map_err(|_| AdminError::InvalidInput("invalid capability id in grant line"))?;
    Ok(InstallationGrant { capability, scope })
}

/// GET /grants（§21.1：全部安装的 grants 总览）。
pub async fn grants_list(State(state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    match state.facade.list_components() {
        Ok(views) => {
            let rows = views.iter().map(component_row).collect();
            render_template(
                GrantsTemplate {
                    ctx: page_ctx(&auth),
                    components: rows,
                },
                StatusCode::OK,
            )
        }
        Err(error) => admin_error_response(&error),
    }
}

/// GET /grants/{id}（编辑表单）。
pub async fn grants_form(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    match state.facade.component(id) {
        Ok(view) => render_template(
            GrantsFormTemplate {
                ctx: page_ctx(&auth),
                id,
                current: grant_lines(&view.grants),
                error: None,
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /grants/{id}（整体替换，§17.5）。
pub async fn grants_replace(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(id): Path<InstallationId>,
    Form(form): Form<GrantsForm>,
) -> Response {
    let mut grants = Vec::new();
    for line in form.capabilities.split('\n') {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_grant_line(line) {
            Ok(grant) => grants.push(grant),
            Err(error) => {
                return render_template(
                    GrantsFormTemplate {
                        ctx: page_ctx_from_state(&state, &_auth),
                        id,
                        current: form.capabilities.clone(),
                        error: Some(error.to_string()),
                    },
                    StatusCode::BAD_REQUEST,
                );
            }
        }
    }
    match state.facade.replace_grants(id, grants) {
        Ok(()) => Redirect::to("/grants").into_response(),
        Err(error) => admin_error_response(&error),
    }
}

/// 错误重渲染时的 ctx 构造（auth 已由中间件保证）。
fn page_ctx_from_state(_state: &AdminState, auth: &Authenticated) -> crate::templates::PageContext {
    page_ctx(auth)
}
