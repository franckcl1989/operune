//! Grant store port（§17.1 / §17.5：Grant 的 durable owner 是 InstallationId）。

use operune_domain::InstallationId;

use crate::model::InstallationGrant;

/// grant 持久化错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// 安装实例不存在。
    #[error("installation {0} not found")]
    NotFound(InstallationId),
    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("grant store storage failure: {0}")]
    Storage(#[source] crate::error::ErrorSource),
}

/// Grant store port（storage-sqlite 层实现）。
///
/// 语义（§17.1 / §17.5）：
/// - grant 只绑定 [`InstallationId`]，不绑定可复用的 `ComponentId`——
///   同一逻辑 Component 的另一安装实例不会意外继承权限；
/// - 升级到新版本时，只有新版本实际 imports 没有扩大能力种类或 scope
///   需求、且 policy 重新验证通过时旧 grant 才可继续适用；新增/扩大权限
///   必须显式重新批准（由用例层决定何时调用 replace_grants）。
pub trait GrantStorePort: Send + Sync {
    /// 读取安装实例的全部 grant。
    fn grants_for(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<InstallationGrant>, GrantError>;

    /// 整体替换安装实例的 grant 集（显式重新批准的落盘，§17.5）。
    fn replace_grants(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
    ) -> Result<(), GrantError>;
}
