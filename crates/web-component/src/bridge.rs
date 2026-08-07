//! Component Web bridge 的 Core 侧 port（§21.3 / §42.2）。
//!
//! HTTP 层（本 crate 的 router）只依赖 [`ComponentWebPort`]；生产实现
//! [`AppWebBridge`] 包装 application 的 [`WebBridge`] 用例（§24.2：
//! web-component 消费用例 API，不实现 application 的 ports）。
//!
//! port 方法签名以 domain/application 强类型表达（§13.1）：无凭据参数、
//! 无 header 集合——§21.3 的凭据/header 边界在类型层面成立。
//!
//! # 0.1 → 0.2 surface 分发（§6.7 / §42.2；与 application 的分发一致）
//!
//! surface 判定（组件二进制可观察 exports：0.2 surface 优先、0.1 回退）
//! 由 **application** 负责（`ContractSurface`，§6.7）；本层只按 port
//! 语义消费：`app_declaration` 返回 `Some` ⇔ 组件是 0.2 surface（0.4
//! 面可用）；仅导出 0.1 surface 的组件该值为 `None`，其 entry / assets /
//! actions 路径按 0.1 语义继续服务（§8.4 无 flag-day）。版本分发不是
//! 第二套 bridge（§42.2 明文）：同一 bridge 实现，按声明面分流。

use std::sync::Arc;

use operune_application::cancel::CancellationToken;
use operune_application::contract::GuestActionPayload;
use operune_application::{
    ActionName, ActiveRuntimeRegistry, ApplicationError, WebAssetPath, WebBridge,
};
use operune_domain::{AppDeclaration, ContentDigest, InstallationId, PageId, RouteId, TypedParam};

use crate::error::BridgeError;

/// Component Web 用例 port（HTTP 层消费）。
pub trait ComponentWebPort: Send + Sync {
    // ---- 0.1 基线（§21.3）----

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

    // ---- 0.4 扩展（§42.2 Web Application Runtime；application 的
    // WebAppService 接线点——本 trait 的方法形状即衔接契约，应用侧代理
    // 按其 WebAppService 实现）----

    /// 当前 0.4 app declaration（§42.2 app descriptor；无 0.2 surface 的
    /// 组件 / 无激活安装 → `None`）。
    ///
    /// application 按 §6.7 可观察 contract surface 判定分发（0.2 优先、
    /// 0.1 回退）；本层只按返回值消费：`None` 时导航 / typed route 面
    /// 确定性 404，entry / assets / actions 走 0.1 语义。
    fn app_declaration(&self, installation: InstallationId) -> Option<AppDeclaration>;

    /// 页面访问检查（§42.2 page permission 强制执行点）。
    ///
    /// Core 在服务端重新执行授权链（§17.5 / §21.3）：auth / RBAC 由上层
    /// 完整链覆盖（web-admin），grant / page-permission 求值在 application
    /// 的 WebAppService 内；拒绝 → [`BridgeError::PageDenied`]（403）。
    /// 仅 `required-permission` 已声明的页面触发本调用。
    fn check_page_access(
        &self,
        installation: InstallationId,
        page_id: &PageId,
    ) -> Result<(), BridgeError>;

    /// 一次 typed route 调用（§42.2 `route-dispatch.handle-route`）。
    ///
    /// - `route_id` / `params` 已经 HTTP 层按声明校验并构造（
    ///   [`crate::dispatch`]；WIT：Core 分发前校验，guest 不应见到不一致）；
    /// - Core 侧检查（授权链 / 配额 / 速率 / 并发）在 application 内
    ///   执行，拒绝经 [`BridgeError`] 以确定 HTTP 语义表达（403 / 429 /
    ///   503），不进 guest 错误空间；
    /// - `cancel`：请求断开 / deadline 的取消探针（§42.2 cancellation
    ///   / disconnect）——HTTP 层在 handler future 被丢弃（客户端断开）
    ///   时取消令牌，application 将令牌接入运行时 epoch interruption，
    ///   中止 in-flight guest 调用并丢弃结果。
    fn invoke_route(
        &self,
        installation: InstallationId,
        route_id: RouteId,
        params: Vec<TypedParam>,
        payload: Option<GuestActionPayload>,
        cancel: &CancellationToken,
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

    // ---- 0.4 接线点（§42.2；application 的 WebAppService 并行实现中）
    // ----
    //
    // 当前占位语义（确定性、fail-closed）：
    // - `app_declaration` → `None`：0.4 面（导航 / typed route）确定性
    //   404，0.1 面（entry / assets / actions）不受影响；
    // - `check_page_access` / `invoke_route` → [`BridgeError::WebAppNotWired`]
    //   （501）：应用侧端口未接线时的确定性拒绝。
    //
    // WebAppService 落地后的接线：`app_declaration` 经 Active 快照读取
    // 并校验 0.4 app descriptor（解析 / 冲突诊断 / surface 分发在
    // application，§6.7）；`invoke_route` 委托
    // `WebAppService::handle_route`（授权链 / 配额 / 速率 / 并发检查在
    // 应用侧执行，`cancel` 接入运行时 epoch interruption）。

    fn app_declaration(&self, _installation: InstallationId) -> Option<AppDeclaration> {
        None
    }

    fn check_page_access(
        &self,
        _installation: InstallationId,
        _page_id: &PageId,
    ) -> Result<(), BridgeError> {
        Err(BridgeError::WebAppNotWired)
    }

    fn invoke_route(
        &self,
        _installation: InstallationId,
        _route_id: RouteId,
        _params: Vec<TypedParam>,
        _payload: Option<GuestActionPayload>,
        _cancel: &CancellationToken,
    ) -> Result<Vec<u8>, BridgeError> {
        Err(BridgeError::WebAppNotWired)
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
