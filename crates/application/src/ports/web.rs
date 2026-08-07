//! 0.4.0 Web Application Runtime（§42.2）——page/action permission 检查点。
//!
//! §42.2 page/action permission declarations：页面 / 路由的
//! `required-permission` 以声明形态出现在 app descriptor（permissions
//! interface），enforcement 在 Core——请求经 Core-mediated bridge 时，Core
//! 在服务端重新执行 authentication → RBAC → grant → page/action permission
//! 检查（§17.5 四层授权链 / §21.3），未授权以确定 HTTP 语义拒绝（403），
//! 不进 guest 错误空间。
//!
//! 本 port 是**第四层（Grant）**的检查点形状：permission-name 是组件作用域
//! 的命名引用；到 grant scope 的映射与求值策略是 Core 政策（permissions.wit
//! 明文：0.4.0 声明面 + Core 强制执行点）。默认实现
//! [`InProcessWebPermissionPolicy`] 采用的映射政策：
//!
//! - 能力 id `operune:web/permissions`（[`WEB_PERMISSIONS_CAPABILITY`]）
//!   表达"该安装实例持有 web permission 声明面的授权"；
//! - [`GrantScope::Unscoped`] 放行全部 permission-name（纯布尔能力，§17.3）；
//! - [`GrantScope::Action`] `{ name }` 放行同名的 permission-name（命名
//!   scope 复用 0.1 action 级授权形态——permission-name 与 action-name
//!   一样是 Core 只做等价比较的命名引用，§13.5）；
//! - WASI preopen / env scope 不是 permission 授权。
//!
//! 认证 / RBAC 层由 HTTP 层（web-admin / web-component）经同一 port 的
//! 前置阶段实现完整链（§24.2：与 0.1 `ActionPolicyPort` 同模式）。
//!
//! 凭据边界（继承 0.1，不得放宽，§21.3）：检查上下文只有命名引用
//! （permission-name 字符串等价比较）与安装身份，不含任何凭据 / 会话 /
//! 角色字段（permissions.wit 明文）。

use std::sync::Arc;

use operune_domain::{ComponentVersion, InstallationId};

use crate::model::GrantScope;
use crate::ports::GrantStorePort;

/// web permission 声明的规范化能力 id（§17：grant 以该能力表达
/// "该安装持有 web permission 授权"）。
pub const WEB_PERMISSIONS_CAPABILITY: &str = "operune:web/permissions";

/// page / route permission 检查的上下文（§17.5 第四层 Grant 检查点）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebPermissionContext {
    /// 绑定安装实例。
    pub installation_id: InstallationId,
    /// 绑定当前版本（§21.5：UI 与 backend 随同一 ComponentVersion 原子
    /// 切换）。
    pub version: ComponentVersion,
    /// 被检查的 permission-name（组件作用域命名引用，§13.5）。
    pub permission: operune_domain::PermissionName,
}

/// permission 检查的拒绝类别（§42.2：未授权以确定 HTTP 语义拒绝 403；
/// HTTP 层负责映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PermissionDenied {
    /// 安装实例的 grant 集不包含该 permission-name 的授权（§17.5 第四层）。
    NotGranted,
    /// 检查无法完成（grant 存储失败 / 安装不存在等）。
    Unknown,
}

impl std::fmt::Display for PermissionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotGranted => "permission not granted for this installation",
            Self::Unknown => "permission check failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for PermissionDenied {}

/// Web permission 检查点 port（§24.2 端口注入；HTTP 层在权限链前置
/// auth/RBAC 阶段后调用）。
pub trait WebPermissionPolicyPort: Send + Sync {
    /// 服务端重做检查（§17.5 第四层）。拒绝返回 [`PermissionDenied`]。
    fn check_permission(&self, context: &WebPermissionContext) -> Result<(), PermissionDenied>;
}

/// 默认进程内 permission policy（Grant 层；§17.5 / §42.2）。
///
/// grant 检查：安装实例必须拥有 `operune:web/permissions` 能力，且 scope
/// 为 [`GrantScope::Unscoped`] 或 [`GrantScope::Action`] `{ name }` 与
/// permission-name 同名（映射政策见模块文档）。
pub struct InProcessWebPermissionPolicy {
    grants: Arc<dyn GrantStorePort>,
}

impl InProcessWebPermissionPolicy {
    /// 构造（注入 grant store）。
    pub fn new(grants: Arc<dyn GrantStorePort>) -> Self {
        Self { grants }
    }
}

impl WebPermissionPolicyPort for InProcessWebPermissionPolicy {
    fn check_permission(&self, context: &WebPermissionContext) -> Result<(), PermissionDenied> {
        let grants = self
            .grants
            .grants_for(context.installation_id)
            .map_err(|_| PermissionDenied::Unknown)?;
        let permitted = grants.iter().any(|grant| {
            grant.capability.as_str() == WEB_PERMISSIONS_CAPABILITY
                && match &grant.scope {
                    GrantScope::Unscoped => true,
                    GrantScope::Action { name } => name == context.permission.as_str(),
                    // preopen / env 不是 permission 授权。
                    GrantScope::WasiPreopen { .. } | GrantScope::WasiEnv { .. } => false,
                }
        });
        if permitted {
            Ok(())
        } else {
            Err(PermissionDenied::NotGranted)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeGrants, grant, ok};
    use operune_domain::CapabilityId;

    fn permission(name: &str) -> operune_domain::PermissionName {
        ok(operune_domain::PermissionName::new(name), "permission-name")
    }

    fn context(installation: InstallationId, name: &str) -> WebPermissionContext {
        WebPermissionContext {
            installation_id: installation,
            version: operune_domain::ComponentVersion::from_parts(1, 0, 0),
            permission: permission(name),
        }
    }

    #[test]
    fn unscoped_grant_allows_any_permission() {
        let grants = Arc::new(FakeGrants::new());
        let installation = InstallationId::new();
        ok(
            grants.replace_grants(installation, &[grant(WEB_PERMISSIONS_CAPABILITY)]),
            "replace grants",
        );
        let policy = InProcessWebPermissionPolicy::new(grants);
        assert!(
            policy
                .check_permission(&context(installation, "view"))
                .is_ok()
        );
        assert!(
            policy
                .check_permission(&context(installation, "admin"))
                .is_ok()
        );
    }

    #[test]
    fn named_scope_matches_permission_name() {
        let grants = Arc::new(FakeGrants::new());
        let installation = InstallationId::new();
        ok(
            grants.replace_grants(
                installation,
                &[crate::model::InstallationGrant {
                    capability: ok(CapabilityId::new(WEB_PERMISSIONS_CAPABILITY), "capability"),
                    scope: GrantScope::Action {
                        name: "view".to_owned(),
                    },
                }],
            ),
            "replace grants",
        );
        let policy = InProcessWebPermissionPolicy::new(grants);
        assert!(
            policy
                .check_permission(&context(installation, "view"))
                .is_ok()
        );
        assert_eq!(
            policy.check_permission(&context(installation, "admin")),
            Err(PermissionDenied::NotGranted)
        );
    }

    #[test]
    fn no_grant_is_denied_by_default() {
        // §17.2 / §42.2：deny-by-default——无 `operune:web/permissions` grant
        // 的安装实例拒绝全部 permission。
        let grants = Arc::new(FakeGrants::new());
        let policy = InProcessWebPermissionPolicy::new(grants);
        let installation = InstallationId::new();
        assert_eq!(
            policy.check_permission(&context(installation, "view")),
            Err(PermissionDenied::NotGranted)
        );
    }

    #[test]
    fn wasi_scopes_are_not_permission_grants() {
        let grants = Arc::new(FakeGrants::new());
        let installation = InstallationId::new();
        ok(
            grants.replace_grants(
                installation,
                &[crate::model::InstallationGrant {
                    capability: ok(CapabilityId::new(WEB_PERMISSIONS_CAPABILITY), "capability"),
                    scope: GrantScope::WasiEnv {
                        key: "OPERUNE_X".to_owned(),
                        value: "1".to_owned(),
                    },
                }],
            ),
            "replace grants",
        );
        let policy = InProcessWebPermissionPolicy::new(grants);
        assert_eq!(
            policy.check_permission(&context(installation, "view")),
            Err(PermissionDenied::NotGranted),
            "wasi env scope must not authorize a web permission"
        );
    }

    #[test]
    fn different_capability_does_not_authorize() {
        // 0.1 的 actions 能力不授权 0.4 的 permission 检查（命名空间分离）。
        let grants = Arc::new(FakeGrants::new());
        let installation = InstallationId::new();
        ok(
            grants.replace_grants(installation, &[grant("operune:web/actions")]),
            "replace grants",
        );
        let policy = InProcessWebPermissionPolicy::new(grants);
        assert_eq!(
            policy.check_permission(&context(installation, "view")),
            Err(PermissionDenied::NotGranted)
        );
    }
}
