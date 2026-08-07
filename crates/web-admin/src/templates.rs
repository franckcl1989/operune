//! Askama SSR 模板结构（§21.2：Axum + Askama server-side rendering + 最小
//! 原生 HTML/CSS/JS；模板文件随 crate 提交，编译期渲染，无前端构建链）。
//!
//! 模板位于 `templates/*.html`（askama 默认目录，相对 crate 根）。
//! askama 0.16 对 HTML 模板默认自动转义（`|safe` 显式关闭）；本 crate 所有
//! 展示值都来自不可信边界（Component 元数据、action 名、用户输入），一律
//! 保持默认转义，不引入任何 `|safe`。

use askama::Template;

use operune_application::active::ActiveInstallation;
use operune_application::{InstallationGrant, InstallationRecord};
use operune_domain::InstallationId;

use crate::facade::{AdminUserView, ComponentView, ConfigView, StatusView, grant_scope_summary};

/// 页面公共上下文（布局导航 + CSRF 隐藏字段）。
#[derive(Debug, Clone)]
pub struct PageContext {
    /// 当前登录主体。
    pub subject: String,
    /// 当前 session 的 CSRF token（§16.5；表单隐藏字段 `_csrf`）。
    pub csrf: String,
}

/// grant 的展示行（scope 摘要已在 Rust 侧格式化——环境变量值遮蔽，
/// §16.6）。
#[derive(Debug, Clone)]
pub struct GrantRow {
    /// 能力 id。
    pub capability: String,
    /// scope 摘要（值已遮蔽）。
    pub scope: String,
}

/// 把 grants 转换为展示行（§16.6 边界在此执行）。
pub fn grant_rows(grants: &[InstallationGrant]) -> Vec<GrantRow> {
    grants
        .iter()
        .map(|grant| GrantRow {
            capability: grant.capability.as_str().to_owned(),
            scope: grant_scope_summary(&grant.scope),
        })
        .collect()
}

/// grants 表单的预填文本（每行一条：`capability` 或 `capability=action:name`）。
pub fn grant_lines(grants: &[InstallationGrant]) -> String {
    let mut lines: Vec<String> = grants
        .iter()
        .map(|grant| match &grant.scope {
            operune_application::GrantScope::Action { name } => {
                format!("{}=action:{name}", grant.capability.as_str())
            }
            _ => grant.capability.as_str().to_owned(),
        })
        .collect();
    lines.sort();
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// 模板结构
// ---------------------------------------------------------------------------

/// 登录页（独立布局；§16.5 匿名会话承载 CSRF）。
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    /// 匿名会话的 CSRF token。
    pub csrf: String,
    /// 登录失败信息（展示用；不记录密码，§16.6）。
    pub error: Option<String>,
}

/// 状态页（§21.1 Runtime status）。
#[derive(Template)]
#[template(path = "status.html")]
pub struct StatusTemplate {
    pub ctx: PageContext,
    pub view: StatusView,
}

/// Component 列表（§21.1）。
#[derive(Template)]
#[template(path = "components.html")]
pub struct ComponentsTemplate {
    pub ctx: PageContext,
    /// 组件视图（含 grants 行）。
    pub components: Vec<ComponentRow>,
}

/// Component 详情（§21.1：install/list/detail/enable/disable/upgrade/
/// rollback 的操作面）。
#[derive(Template)]
#[template(path = "component.html")]
pub struct ComponentDetailTemplate {
    pub ctx: PageContext,
    pub record: InstallationRecord,
    pub active: Option<ActiveInstallation>,
    pub grants: Vec<GrantRow>,
    /// RequiresApproval 提示（升级需要显式批准的能力，§17.5）。
    pub requires_approval: Option<String>,
    /// 操作结果消息（success 提示）。
    pub message: Option<String>,
}

/// 安装表单页（§21.1 install；.wasm 原始字节上传，§19.2 输入不可信）。
#[derive(Template)]
#[template(path = "install.html")]
pub struct InstallTemplate {
    pub ctx: PageContext,
    pub error: Option<String>,
}

/// 升级表单页（§21.1 upgrade；RequiresApproval 重试路径）。
#[derive(Template)]
#[template(path = "upgrade.html")]
pub struct UpgradeTemplate {
    pub ctx: PageContext,
    /// 目标安装。
    pub id: InstallationId,
    /// 需要显式批准的能力（RequiresApproval 提示；已在 Rust 侧 join）。
    pub missing: String,
    pub error: Option<String>,
}

/// 卸载确认页（§39.2 remove / §42.4：破坏性操作必须显式确认；卸载后
/// 组件从 UI 与 backend 完整消失，artifact 保留，§18.7）。
#[derive(Template)]
#[template(path = "remove.html")]
pub struct RemoveTemplate {
    pub ctx: PageContext,
    pub record: InstallationRecord,
    pub error: Option<String>,
}

/// Grants 页（§21.1 grants）。
#[derive(Template)]
#[template(path = "grants.html")]
pub struct GrantsTemplate {
    pub ctx: PageContext,
    pub components: Vec<ComponentRow>,
}

/// 单安装 grants 编辑表单页。
#[derive(Template)]
#[template(path = "grants_form.html")]
pub struct GrantsFormTemplate {
    pub ctx: PageContext,
    pub id: InstallationId,
    /// 预填文本（`grant_lines` 格式）。
    pub current: String,
    pub error: Option<String>,
}

/// 用户管理页（§21.1 users/RBAC 最小管理）。
#[derive(Template)]
#[template(path = "users.html")]
pub struct UsersTemplate {
    pub ctx: PageContext,
    pub users: Vec<AdminUserView>,
    pub error: Option<String>,
}

/// Core config 页（§21.1）。
#[derive(Template)]
#[template(path = "config.html")]
pub struct ConfigTemplate {
    pub ctx: PageContext,
    pub view: ConfigView,
}

/// 审计展示行（时间/类别/严重级/结果/动作/消息——§16.6 无 secret）。
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub occurred_at: String,
    pub category: String,
    pub severity: String,
    pub outcome: String,
    pub action: String,
    pub message: String,
}

/// 审计页（§21.1 audit）。
#[derive(Template)]
#[template(path = "audit.html")]
pub struct AuditTemplate {
    pub ctx: PageContext,
    pub events: Vec<AuditRow>,
}

/// safe mode / recovery 页（§21.1）。
#[derive(Template)]
#[template(path = "safe_mode.html")]
pub struct SafeModeTemplate {
    pub ctx: PageContext,
    pub enabled: bool,
    pub message: Option<String>,
}

/// 错误页（通用）。
#[derive(Template)]
#[template(path = "error.html")]
pub struct ErrorTemplate {
    pub title: String,
    pub message: String,
}

/// 列表页的组件行（记录 + 激活信息 + grants 展示行）。
#[derive(Debug, Clone)]
pub struct ComponentRow {
    /// 安装记录。
    pub record: InstallationRecord,
    /// 当前 Active 条目。
    pub active: Option<ActiveInstallation>,
    /// grants 展示行。
    pub grants: Vec<GrantRow>,
}

/// 从 [`ComponentView`] 构造展示行。
pub fn component_row(view: &ComponentView) -> ComponentRow {
    ComponentRow {
        record: view.record.clone(),
        active: view.active.clone(),
        grants: grant_rows(&view.grants),
    }
}
