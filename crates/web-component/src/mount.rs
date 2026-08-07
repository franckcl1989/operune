//! Component mount namespace（§21.3：Core 分配、不可冲突）。
//!
//! 每个安装实例的 Web 面挂在 `/component/{installation_id}/` 命名空间下；
//! `InstallationId` 是 Core 创建并持久化的随机 UUID v4 身份（§19.4），
//! 命名空间由构造派生、天然不可冲突。资产 URL 携带激活 digest
//! （§21.5：UI 与 backend 随同一 ComponentVersion 原子切换；旧 digest
//! 的 URL 在升级后立即 404）。

use operune_application::{ActionName, WebAssetPath};
use operune_domain::{ContentDigest, InstallationId};

/// 命名空间的第一段（固定）。
pub const MOUNT_PREFIX: &str = "component";

/// 资产 URL 的第二段（固定）。
pub const ASSETS_SEGMENT: &str = "assets";

/// 动作 URL 的第二段（固定）。
pub const ACTIONS_SEGMENT: &str = "actions";

/// 路由路径前缀（axum 路由写法：`/component/{installation}/…`）。
pub const ROUTE_PREFIX: &str = "/component/{installation}";

/// Component Web 挂载命名空间（§21.3：Core 分配、不可冲突）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ComponentMount {
    installation: InstallationId,
}

impl ComponentMount {
    /// 构造命名空间（安装身份即命名空间事实源，§6.7：文件/路径永不成为
    /// 逻辑身份事实源）。
    pub fn new(installation: InstallationId) -> Self {
        Self { installation }
    }

    /// 绑定的安装实例。
    pub const fn installation(&self) -> InstallationId {
        self.installation
    }

    /// 命名空间 URL 前缀（`/component/{uuid}`）。
    pub fn prefix(&self) -> String {
        format!("/{MOUNT_PREFIX}/{}", self.installation)
    }

    /// 资产 URL（`/component/{uuid}/assets/{digest}/{path}`；digest 保证
    /// §21.5 原子版本切换——升级后旧 URL 立即失效）。
    pub fn asset_url(&self, digest: ContentDigest, path: &WebAssetPath) -> String {
        format!(
            "/{MOUNT_PREFIX}/{}/{ASSETS_SEGMENT}/{digest}{}",
            self.installation,
            path.as_str()
        )
    }

    /// 动作 URL（`/component/{uuid}/actions/{action}`）。
    pub fn action_url(&self, action: &ActionName) -> String {
        format!(
            "/{MOUNT_PREFIX}/{}/{ACTIONS_SEGMENT}/{}",
            self.installation,
            action.as_str()
        )
    }
}

impl std::fmt::Display for ComponentMount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/{MOUNT_PREFIX}/{}", self.installation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn namespaces_are_disjoint_by_installation() {
        // §21.3：命名空间由安装身份派生，天然不可冲突。
        let a = ComponentMount::new(InstallationId::new());
        let b = ComponentMount::new(InstallationId::new());
        assert_ne!(a.prefix(), b.prefix());
        assert!(a.prefix().starts_with("/component/"));
    }

    #[test]
    fn asset_url_includes_digest_for_atomic_versioning() {
        // §21.5：资产 URL 绑定激活 digest——升级后旧 URL 不再解析到新内容。
        let mount = ComponentMount::new(InstallationId::new());
        let path = ok(WebAssetPath::new("/index.html"), "path");
        let digest = ContentDigest::from_bytes(b"v1");
        let url = mount.asset_url(digest, &path);
        assert_eq!(
            url,
            format!(
                "/component/{}/assets/{digest}/index.html",
                mount.installation()
            )
        );
        let other = ContentDigest::from_bytes(b"v2");
        assert_ne!(url, mount.asset_url(other, &path));
    }

    #[test]
    fn action_url_shape() {
        let mount = ComponentMount::new(InstallationId::new());
        let action = ok(ActionName::new("run-check"), "action");
        assert_eq!(
            mount.action_url(&action),
            format!("/component/{}/actions/run-check", mount.installation())
        );
    }
}
