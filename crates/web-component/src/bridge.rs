//! Component Web bridge 的 Core 侧 port（§21.3）。
//!
//! HTTP 层（本 crate 的 router）只依赖 [`ComponentWebPort`]；生产实现
//! [`AppWebBridge`] 包装 application 的 [`WebBridge`] 用例（§24.2：
//! web-component 消费用例 API，不实现 application 的 ports）。
//!
//! port 方法签名以 domain/application 强类型表达（§13.1）：无凭据参数、
//! 无 header 集合——§21.3 的凭据/header 边界在类型层面成立。

use std::sync::Arc;

use operune_application::contract::GuestActionPayload;
use operune_application::{
    ActionName, ActiveRuntimeRegistry, ApplicationError, WebAssetPath, WebBridge,
};
use operune_domain::{ContentDigest, InstallationId};

use crate::error::BridgeError;

/// Component Web 用例 port（HTTP 层消费）。
pub trait ComponentWebPort: Send + Sync {
    /// 当前激活 digest（§21.5：资产 URL 绑定激活 digest；无激活安装返回
    /// `None`）。
    fn active_digest(&self, installation: InstallationId) -> Option<ContentDigest>;

    /// 入口资产路径（manifest.entry，§21.3；无 Web UI 返回 `None`）。
    fn entry_asset(&self, installation: InstallationId) -> Option<WebAssetPath>;

    /// 读取资产字节（缓存事实 = ContentDigest + asset path，§6.2 / §21.3）。
    fn read_asset(
        &self,
        installation: InstallationId,
        path: &WebAssetPath,
    ) -> Result<Arc<Vec<u8>>, BridgeError>;

    /// 一次 bounded backend action（§21.3：Core-mediated；服务端重做
    /// grant/body/rate 检查在 application 的 policy 内，deadline/concurrency
    /// 在运行时强制；响应只有字节）。
    fn invoke_action(
        &self,
        installation: InstallationId,
        action: ActionName,
        payload: GuestActionPayload,
    ) -> Result<Vec<u8>, BridgeError>;
}

/// application [`WebBridge`] 的适配实现（§24.3：adapter → application）。
///
/// `WebBridge` 不公开 Active 快照的 digest / manifest 读取（API 缺口：
/// `ActiveRuntimeRegistry` 由 composition root 同时注入 `WebBridge` 与本
/// 适配器——同一实例），本适配器持有所需的 registry 句柄完成绑定。
pub struct AppWebBridge {
    inner: WebBridge,
    active: Arc<ActiveRuntimeRegistry>,
}

impl AppWebBridge {
    /// 构造（注入 application 用例 + 同一 Active 快照句柄）。
    pub fn new(inner: WebBridge, active: Arc<ActiveRuntimeRegistry>) -> Self {
        Self { inner, active }
    }
}

impl ComponentWebPort for AppWebBridge {
    fn active_digest(&self, installation: InstallationId) -> Option<ContentDigest> {
        self.active
            .get(installation)
            .map(|entry| entry.installation.digest)
    }

    fn entry_asset(&self, installation: InstallationId) -> Option<WebAssetPath> {
        let entry = self.active.get(installation)?;
        entry
            .manifest
            .as_ref()
            .map(|manifest| manifest.entry.clone())
    }

    fn read_asset(
        &self,
        installation: InstallationId,
        path: &WebAssetPath,
    ) -> Result<Arc<Vec<u8>>, BridgeError> {
        self.inner
            .read_asset(installation, path)
            .map(|response| response.bytes)
            .map_err(BridgeError::from)
    }

    fn invoke_action(
        &self,
        installation: InstallationId,
        action: ActionName,
        payload: GuestActionPayload,
    ) -> Result<Vec<u8>, BridgeError> {
        self.inner
            .invoke_action(installation, action, payload)
            .map_err(BridgeError::from)
    }
}

impl From<ApplicationError> for BridgeError {
    fn from(error: ApplicationError) -> Self {
        match error {
            ApplicationError::NotActiveForWeb(installation) => {
                BridgeError::NotActiveForWeb(installation)
            }
            ApplicationError::ActionDenied(denied) => BridgeError::Denied(denied),
            other => BridgeError::Application(other),
        }
    }
}
