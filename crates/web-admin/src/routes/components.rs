//! Component 管理路由（§21.1：install / list / detail / enable / disable /
//! upgrade / rollback）。
//!
//! 上传以原始字节 body 接收 `.wasm`（§19.2 输入不可信）；大小限制在前端
//! （表单/JS）+ 服务端（DefaultBodyLimit + facade 预检 + 管线硬限制）多重
//! 强制（§32 oversized 输入提前拒绝）。grants 以 `grant=` query 参数传递
//! （全新安装必须显式批准，§17.1）。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::Request;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use operune_application::{InstallOutcome, UpgradeOutcome};
use operune_domain::{CapabilityId, InstallationId};

use crate::auth::Authenticated;
use crate::error::{admin_error_response, error_page, render_template};
use crate::facade::AdminError;
use crate::routes::login::page_ctx;
use crate::state::AdminState;
use crate::templates::{
    ComponentDetailTemplate, ComponentsTemplate, InstallTemplate, UpgradeTemplate, component_row,
};
use operune_application::InstallationGrant;

/// 上传 query：`grant=` 可重复（§17.1 显式批准）。
#[derive(Deserialize, Default)]
pub struct UploadQuery {
    /// 能力 id 列表（scoped 未指定 = Unscoped）。单个 `grant=a` 与重复
    /// `grant=a&grant=b` 都接受（serde_urlencoded 对单值产出 string）。
    #[serde(default, deserialize_with = "string_or_vec")]
    pub grant: Vec<String>,
}

/// `grant=` 参数的单值/多值兼容（§13.3 边界解析）。
fn string_or_vec<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrVec;
    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string or a sequence of strings")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            let mut out = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                out.push(value);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_any(StringOrVec)
}

/// 解析 `grant=` 参数为 InstallationGrant（§17.3：0.1 管理面只接受
/// Unscoped；action scope 走 grants 页）。
pub fn parse_grant_params(raw: &[String]) -> Result<Vec<InstallationGrant>, AdminError> {
    let mut grants = Vec::with_capacity(raw.len());
    for value in raw {
        let value = value.trim();
        if value.is_empty() {
            return Err(AdminError::InvalidInput(
                "grant capability id must not be empty",
            ));
        }
        let capability = CapabilityId::new(value)
            .map_err(|_| AdminError::InvalidInput("invalid capability id in grant parameter"))?;
        grants.push(InstallationGrant {
            capability,
            scope: operune_application::GrantScope::Unscoped,
        });
    }
    Ok(grants)
}

/// GET /components（§21.1 list）。
pub async fn components_list(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
) -> Response {
    match state.facade.list_components() {
        Ok(views) => {
            let rows = views.iter().map(component_row).collect();
            render_template(
                ComponentsTemplate {
                    ctx: page_ctx(&auth),
                    components: rows,
                },
                StatusCode::OK,
            )
        }
        Err(error) => admin_error_response(&error),
    }
}

/// GET /components/{id}（§21.1 detail）。
pub async fn component_detail(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    match state.facade.component(id) {
        Ok(view) => render_template(
            ComponentDetailTemplate {
                ctx: page_ctx(&auth),
                record: view.record,
                active: view.active,
                grants: crate::templates::grant_rows(&view.grants),
                requires_approval: None,
                message: None,
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// GET /components/install（表单页，§21.1）。
pub async fn install_form(State(_state): State<Arc<AdminState>>, auth: Authenticated) -> Response {
    render_template(
        InstallTemplate {
            ctx: page_ctx(&auth),
            error: None,
        },
        StatusCode::OK,
    )
}

/// POST /components/install（上传 .wasm，§19.2 / §32）。
pub async fn install_post(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Query(query): Query<UploadQuery>,
    request: Request<axum::body::Body>,
) -> Response {
    // §19.2 / §32：服务端大小重检（DefaultBodyLimit 只约束提取器路径；
    // 本 handler 手动读 body，必须显式限长并映射 413）。
    let bytes = match axum::body::to_bytes(request.into_body(), state.upload_limit_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_page(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "Upload exceeds the host-side component size limit.",
            );
        }
    };
    let grants = match parse_grant_params(&query.grant) {
        Ok(grants) => grants,
        Err(error) => return admin_error_response(&error),
    };
    match state.facade.install(bytes.to_vec(), grants) {
        Ok(InstallOutcome::Activated { installation, .. }) => {
            Redirect::to(&format!("/components/{installation}")).into_response()
        }
        Err(error) => admin_error_response(&error),
    }
}

/// GET /components/{id}/upgrade（表单页，§21.1）。
pub async fn upgrade_form(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    // 校验安装存在（表单引用有效目标）。
    match state.facade.component(id) {
        Ok(_) => render_template(
            UpgradeTemplate {
                ctx: page_ctx(&auth),
                id,
                missing: String::new(),
                error: None,
            },
            StatusCode::OK,
        ),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /components/{id}/upgrade（§20.1 热升级；RequiresApproval 重试路径）。
pub async fn upgrade_post(
    State(state): State<Arc<AdminState>>,
    auth: Authenticated,
    Path(id): Path<InstallationId>,
    Query(query): Query<UploadQuery>,
    request: Request<axum::body::Body>,
) -> Response {
    // §19.2 / §32：服务端大小重检（同 install）。
    let bytes = match axum::body::to_bytes(request.into_body(), state.upload_limit_bytes).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return error_page(
                axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                "Payload too large",
                "Upload exceeds the host-side component size limit.",
            );
        }
    };
    let grants = match parse_grant_params(&query.grant) {
        Ok(grants) => grants,
        Err(error) => return admin_error_response(&error),
    };
    // 显式 grants 非空 → Explicit 重新批准；空 → 复用既有（§17.5）。
    let explicit = if grants.is_empty() {
        None
    } else {
        Some(grants)
    };
    match state.facade.upgrade(id, bytes.to_vec(), explicit) {
        Ok(UpgradeOutcome::Swapped { installation, .. }) => {
            Redirect::to(&format!("/components/{installation}")).into_response()
        }
        Ok(UpgradeOutcome::NoOp { installation }) => {
            Redirect::to(&format!("/components/{installation}")).into_response()
        }
        Ok(UpgradeOutcome::RequiresApproval {
            installation,
            missing,
        }) => {
            let missing_str = missing
                .iter()
                .map(|capability| capability.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            render_template(
                UpgradeTemplate {
                    ctx: page_ctx(&auth),
                    id: installation,
                    missing: missing_str,
                    error: None,
                },
                StatusCode::OK,
            )
        }
        Err(error) => admin_error_response(&error),
    }
}

/// POST /components/{id}/rollback（§20：回滚到上一已知良好版本）。
pub async fn rollback_post(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    match state.facade.rollback(id) {
        Ok(_) => Redirect::to(&format!("/components/{id}")).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /components/{id}/disable（管理性停用；§39.2）。
pub async fn disable_post(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    match state.facade.disable(id) {
        Ok(()) => Redirect::to(&format!("/components/{id}")).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

/// POST /components/{id}/enable（0.1.0 明确不支持，见 facade 文档）。
pub async fn enable_post(
    State(state): State<Arc<AdminState>>,
    _auth: Authenticated,
    Path(id): Path<InstallationId>,
) -> Response {
    match state.facade.enable(id) {
        Ok(()) => Redirect::to(&format!("/components/{id}")).into_response(),
        Err(error) => admin_error_response(&error),
    }
}

// grants 表单预填复用（由 grants 路由模块导入）。
pub(crate) use crate::templates::grant_lines;
