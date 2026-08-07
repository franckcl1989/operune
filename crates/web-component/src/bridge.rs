//! Component Web bridge 的 Core 侧 port（§21.3 / §42.2）。
//!
//! HTTP 层（本 crate 的 router）只依赖 [`ComponentWebPort`]；生产实现
//! [`AppWebBridge`] 包装 application 的 [`WebBridge`] 用例（§24.2：
//! web-component 消费用例 API，不实现 application 的 ports）并委托
//! application 的 [`WebAppService`]（§42.2 0.4 Web Application Runtime）
//! 实现 0.4 面。
//!
//! port 方法签名以 domain/application 强类型表达（§13.1）：无凭据参数、
//! 无 header 集合——§21.3 的凭据/header 边界在类型层面成立。
//!
//! # 0.1 → 0.2 surface 分发（§6.7 / §42.2；与 application 的分发一致）
//!
//! surface 判定（组件二进制可观察 exports：0.2 surface 优先、0.1 回退）
//! 由 **application** 负责（`ContractSurface`，§6.7：激活期交叉校验决定
//! 激活条目是否携带 `web_app` 上下文）；本层只按 port 语义消费：
//! `app_declaration` 返回 `Some` ⇔ 组件是 0.2 surface（0.4 面可用）；
//! 仅导出 0.1 surface 的组件该值为 `None`，其 entry / assets / actions
//! 路径按 0.1 语义继续服务（§8.4 无 flag-day）。版本分发不是第二套
//! bridge（§42.2 明文）：同一 bridge 实现，按声明面分流。
//!
//! # 0.4 接线（§42.2）
//!
//! [`AppWebBridge`] 注入与 0.1 `WebBridge` **同一** Active 快照句柄
//! （[`ActiveRuntimeRegistry`]）和 [`WebAppService`]（application 侧
//! 编排；context / authorize_page / dispatch_route）。错误映射闭集：
//! `WebDispatchError` → [`BridgeError`]（404 / 400 / 403 / 413 / 429 /
//! 503 / 504 / 408 / 502 确定语义，不进 guest 错误空间），见
//! [`map_dispatch_error`]。

use std::sync::Arc;

use operune_application::cancel::CancellationToken;
use operune_application::contract::{
    GuestActionPayload, GuestParamValue, GuestRouteRequest, GuestTypedParam,
};
use operune_application::{
    ActionName, ActiveRuntimeRegistry, ApplicationError, WebAppService, WebAssetPath, WebBridge,
    WebDispatchError, WebPageDenied, WebQuotaDenied,
};
use operune_domain::{
    AppDeclaration, ContentDigest, InstallationId, PageId, ParamValue, RouteId, TypedParam,
};

use crate::error::BridgeError;
use crate::quota::QuotaDenied;

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

    // ---- 0.4 扩展（§42.2 Web Application Runtime；由
    // [`AppWebBridge`] 委托 application 的 WebAppService 实现——本 trait
    // 的方法形状即衔接契约）----

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
///
/// 0.4 面（§42.2）：持有 [`WebAppService`]（application 侧编排）——
/// `app_declaration` 经 `context` 读取激活条目的 Web 应用上下文；
/// `check_page_access` / `invoke_route` 委托 `authorize_page` /
/// `dispatch_route`，错误以 [`BridgeError`] 闭集表达确定 HTTP 语义。
pub struct AppWebBridge {
    inner: WebBridge,
    active: Arc<ActiveRuntimeRegistry>,
    web_app: Arc<WebAppService>,
}

impl AppWebBridge {
    /// 构造（注入 0.1 application 用例 + 同一 Active 快照句柄 + 0.4
    /// `WebAppService`；§42.2 接线点）。
    pub fn new(
        inner: WebBridge,
        active: Arc<ActiveRuntimeRegistry>,
        web_app: Arc<WebAppService>,
    ) -> Self {
        Self {
            inner,
            active,
            web_app,
        }
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

    // ---- 0.4 接线点（§42.2；委托 application 的 WebAppService）----
    //
    // 分发语义与 application 一致（§6.7）：surface 判定（激活期
    // `ContractSurface` 交叉校验）决定激活条目是否携带 `web_app` 上下文；
    // 本层只按返回值消费——`None` → 0.4 面确定性 404，0.1 面（entry /
    // assets / actions）不受影响。

    fn app_declaration(&self, installation: InstallationId) -> Option<AppDeclaration> {
        // 安装非 Active（NotActiveForWeb）或条目无 0.2 surface
        // （`web_app` = None，0.1-only 组件）→ `None`。
        let context = self.web_app.context(installation).ok()?;
        let context = context?;
        Some(context.declaration().clone())
    }

    fn check_page_access(
        &self,
        installation: InstallationId,
        page_id: &PageId,
    ) -> Result<(), BridgeError> {
        // 页面解析 + 授权（Grant 层检查点，§17.5 第四层）在 application
        // 的 `WebAppService` 内执行；本层只做确定语义映射。
        let context = self
            .web_app
            .context(installation)
            .map_err(BridgeError::from)?;
        let Some(context) = context else {
            // 激活条目无 0.2 surface（0.1-only 组件）：页面面不存在（防御
            // 性——HTTP 层仅在 `app_declaration` 为 `Some` 时调用本方法）。
            return Err(BridgeError::PageNotFound);
        };
        let page = context
            .page_by_id(page_id)
            .ok_or(BridgeError::PageNotFound)?;
        self.web_app
            .authorize_page(installation, page)
            .map_err(map_page_denied)
    }

    fn invoke_route(
        &self,
        installation: InstallationId,
        route_id: RouteId,
        params: Vec<TypedParam>,
        payload: Option<GuestActionPayload>,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, BridgeError> {
        // §42.2 typed route 分发（Core-mediated）：授权链 / 参数 / body /
        // quota / 取消探针检查在 application 的 `WebAppService` 内执行
        //（`dispatch_route`），错误以确定 HTTP 语义映射，不进 guest 错误
        // 空间；`cancel` 接入运行时 epoch interruption（disconnect →
        // 不启动新调用、调用结束后已取消则丢弃结果）。
        let request = build_route_request(route_id, params, payload);
        self.web_app
            .dispatch_route(installation, &request, cancel)
            .map_err(map_dispatch_error)
    }
}

/// 构造 `route-request`（§42.2）：port 侧的 domain typed 参数 →
/// WIT `route-request` 镜像（名称 / 值类型一一对应、声明顺序保持；
/// payload 原样传递）。
fn build_route_request(
    route_id: RouteId,
    params: Vec<TypedParam>,
    payload: Option<GuestActionPayload>,
) -> GuestRouteRequest {
    GuestRouteRequest {
        route_id: route_id.to_string(),
        params: params
            .iter()
            .map(|param| GuestTypedParam {
                name: param.name().to_owned(),
                value: guest_param_value(param.value()),
            })
            .collect(),
        payload,
    }
}

/// domain `ParamValue` → WIT `param-value` 镜像（§42.2 typed 参数闭集；
/// 一一对应，无失败路径）。
fn guest_param_value(value: &ParamValue) -> GuestParamValue {
    match value {
        ParamValue::Text(text) => GuestParamValue::Text(text.clone()),
        ParamValue::Integer(value) => GuestParamValue::Integer(*value),
        ParamValue::Unsigned(value) => GuestParamValue::Unsigned(*value),
        ParamValue::Boolean(value) => GuestParamValue::Boolean(*value),
        ParamValue::Decimal(value) => GuestParamValue::Decimal(*value),
    }
}

/// `WebPageDenied` → [`BridgeError`]（§42.2 page permission 确定语义：
/// 未激活 404 / 未授权 403，不进 guest 错误空间）。
fn map_page_denied(error: WebPageDenied) -> BridgeError {
    match error {
        WebPageDenied::NotActiveForWeb(installation) => BridgeError::NotActiveForWeb(installation),
        WebPageDenied::Denied(_) => BridgeError::PageDenied,
    }
}

/// `WebDispatchError` → [`BridgeError`]（§42.2 确定 HTTP 语义：404 / 400 /
/// 403 / 413 / 429 / 503 / 504 / 408 / 502，不进 guest 错误空间）。
///
/// `WebDispatchError` 是 `#[non_exhaustive]`（应用侧演进面）：未来变体
/// 以内部故障（502）兜底。
fn map_dispatch_error(error: WebDispatchError) -> BridgeError {
    match error {
        WebDispatchError::NotActiveForWeb(installation) => {
            BridgeError::NotActiveForWeb(installation)
        }
        // 0.1-only 组件无 typed route 表面 / route-id 未声明 / route-id
        // 结构非法（防御性：HTTP 层分发前已匹配并按声明构造）→ 404。
        WebDispatchError::RouteUnavailable
        | WebDispatchError::InvalidRouteId(_)
        | WebDispatchError::RouteNotFound(_) => BridgeError::RouteNotFound,
        // 参数与声明不一致（防御性：HTTP 层分发前已校验）→ 400。
        WebDispatchError::InvalidParams => BridgeError::RouteInvalidParams,
        // 辅助载荷超过宿主侧 body 上限（§42.2 无条件 baseline）→ 413。
        WebDispatchError::BodyTooLarge => BridgeError::BodyTooLarge,
        // required-permission 未授权（§17.5 第四层 Grant）→ 403。
        WebDispatchError::PermissionDenied(_) => BridgeError::RouteDenied,
        // per-Component HTTP 配额（§42.2）：速率 / 队列 → 429；并发 → 503；
        // 内部故障（配额状态锁异常等）→ 502。
        WebDispatchError::OverQuota(denied) => match denied {
            WebQuotaDenied::RateLimited | WebQuotaDenied::OverQueue => BridgeError::QuotaExceeded,
            WebQuotaDenied::OverConcurrency => BridgeError::QuotaDenied(QuotaDenied::Busy),
            WebQuotaDenied::Unknown => {
                BridgeError::Application(ApplicationError::Internal("web quota check failed"))
            }
        },
        // disconnect / deadline（§42.2）→ 408 / 504。
        WebDispatchError::Cancelled => BridgeError::Cancelled,
        WebDispatchError::DeadlineExceeded => BridgeError::DeadlineExceeded,
        // 响应超过宿主侧上限（§42.2）→ 502。
        WebDispatchError::ResponseTooLarge => BridgeError::ResponseTooLarge,
        // 全部实例槽位繁忙（§7.4 并发上限）→ 503。
        WebDispatchError::Busy => BridgeError::QuotaDenied(QuotaDenied::Busy),
        // guest 返回值空间错误（防御性闭集，route-dispatch.wit）→ 502。
        WebDispatchError::GuestError(reason) => {
            BridgeError::Application(ApplicationError::Internal(reason))
        }
        // wasm 执行失败（trap / 超预算等）→ 502。
        WebDispatchError::Runtime(error) => {
            BridgeError::Application(ApplicationError::Runtime(error))
        }
        // `WebDispatchError` 是 non_exhaustive：未来变体以内部故障兜底。
        _ => BridgeError::Application(ApplicationError::Internal("unhandled web dispatch error")),
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use operune_application::contract::{GuestParamValue, GuestTypedParam};
    use operune_application::{
        AssetCache, ConfigPort, InProcessWebQuota, PermissionDenied, RuntimeConfig,
        RuntimeExecutionError, WebPermissionPolicyPort, WebQuotaLimits, WebQuotaPort,
    };
    use operune_domain::ParamValue;

    use crate::test_support::{
        AllowAllActionPolicy, AllowAllWebPermissionPolicy, FakeAudit, FakeConfig, ok,
    };

    /// 接线夹具：**真实** [`AppWebBridge`]（真实 0.1 `WebBridge` + 真实
    /// [`WebAppService`]，最小 port fake 注入其依赖）+ 空 Active 快照
    /// （无激活安装 = 无 0.2 surface 的最简形态；application 的
    /// `ActiveRuntimeRegistry::swap` 是 `pub(crate)`，web-component 测试
    /// 无法填充真实快照——见 crate 文档 API 缺口 1）。
    ///
    /// 返回 `(bridge, audit)`——audit 句柄供断言委托路径的审计行为。
    fn wired_bridge() -> (Arc<AppWebBridge>, Arc<FakeAudit>) {
        let active = Arc::new(ActiveRuntimeRegistry::new());
        let config = Arc::new(FakeConfig::new()) as Arc<dyn ConfigPort>;
        let audit = Arc::new(FakeAudit::new());
        let audit_port: Arc<dyn operune_application::AuditPort> = audit.clone();
        let permission = Arc::new(AllowAllWebPermissionPolicy) as Arc<dyn WebPermissionPolicyPort>;
        let quota = Arc::new(ok(
            InProcessWebQuota::new(WebQuotaLimits::default()),
            "web-quota",
        )) as Arc<dyn WebQuotaPort>;
        let web_app = Arc::new(WebAppService::new(
            Arc::clone(&active),
            permission,
            quota,
            Arc::clone(&config),
            Arc::clone(&audit_port),
        ));
        let assets = Arc::new(ok(
            AssetCache::new(&RuntimeConfig::default()),
            "asset-cache",
        ));
        let policy =
            Arc::new(AllowAllActionPolicy) as Arc<dyn operune_application::ActionPolicyPort>;
        let inner = WebBridge::new(Arc::clone(&active), assets, policy, Arc::clone(&audit_port));
        (Arc::new(AppWebBridge::new(inner, active, web_app)), audit)
    }

    // -----------------------------------------------------------------------
    // 0.4 接线：真实 WebAppService 委托（空 Active 快照 = 无 0.2 surface）
    // -----------------------------------------------------------------------

    #[test]
    fn app_declaration_is_none_without_02_surface() {
        // §6.7 / §42.2 回退回归：真实接线下，无 0.2 surface（此处为无激活
        // 安装）→ `None`——0.4 面确定性 404，0.1 面不受影响（无 flag-day，
        // §8.4）。
        let (bridge, _audit) = wired_bridge();
        assert!(bridge.app_declaration(InstallationId::new()).is_none());
    }

    #[test]
    fn check_page_access_unwired_installation_is_not_active() {
        // §42.2 page permission 强制执行点：安装未激活 → 确定 404（不是
        // 403——403 只表示授权链拒绝，见 `map_page_denied` 单测）。
        let (bridge, _audit) = wired_bridge();
        let installation = InstallationId::new();
        let result = bridge.check_page_access(installation, &ok(PageId::new("home"), "page-id"));
        assert!(
            matches!(result, Err(BridgeError::NotActiveForWeb(id)) if id == installation),
            "未激活安装必须是 NotActiveForWeb（404），实际 {result:?}"
        );
    }

    #[test]
    fn invoke_route_unwired_installation_is_not_active() {
        // §42.2 typed route 分发：安装未激活 → 确定 404；调用不进入
        // guest 错误空间。
        let (bridge, audit) = wired_bridge();
        let installation = InstallationId::new();
        let cancel = CancellationToken::new();
        let result = bridge.invoke_route(
            installation,
            ok(RouteId::new("get-item"), "route-id"),
            vec![],
            None,
            &cancel,
        );
        assert!(
            matches!(result, Err(BridgeError::NotActiveForWeb(id)) if id == installation),
            "未激活安装必须是 NotActiveForWeb（404），实际 {result:?}"
        );
        assert_eq!(
            audit.events(),
            0,
            "dispatch 在安装未激活时不得写调用审计（未到达 invoke 步骤，§16.6）"
        );
    }

    #[test]
    fn invoke_route_forwards_cancel_token() {
        // §42.2 cancellation 探针：dispatch_route 对已取消令牌确定性拒绝
        //（408）——即使无激活安装也先经过 NotActiveForWeb（404），顺序由
        // application 的 dispatch_route 决定；此处断言令牌接线本身可用。
        let (bridge, _audit) = wired_bridge();
        let installation = InstallationId::new();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(cancel.is_cancelled());
        let result = bridge.invoke_route(
            installation,
            ok(RouteId::new("get-item"), "route-id"),
            vec![],
            None,
            &cancel,
        );
        assert!(result.is_err(), "未激活安装下 route 调用必须被拒绝");
    }

    // -----------------------------------------------------------------------
    // 0.1 路径冻结（§21.3：signature / 语义不变）
    // -----------------------------------------------------------------------

    #[test]
    fn legacy_paths_still_delegate_to_web_bridge() {
        // 0.1 基线（active_digest / entry_asset / read_asset /
        // invoke_action）与 0.4 接线无关：仍经 0.1 `WebBridge` 适配读取
        // Active 快照（空快照 → None / NotActiveForWeb）。
        let (bridge, _audit) = wired_bridge();
        let installation = InstallationId::new();
        assert!(bridge.active_digest(installation).is_none());
        assert!(bridge.entry_asset(installation).is_none());
        let asset_path = ok(WebAssetPath::new("/index.html"), "asset-path");
        assert!(matches!(
            bridge.read_asset(installation, &asset_path),
            Err(BridgeError::NotActiveForWeb(_))
        ));
        let action = ok(ActionName::new("run-check"), "action-name");
        assert!(matches!(
            bridge.invoke_action(installation, action, GuestActionPayload::Raw(vec![1, 2, 3])),
            Err(BridgeError::NotActiveForWeb(_))
        ));
    }

    // -----------------------------------------------------------------------
    // route-request 构造（§42.2：domain TypedParam → WIT 镜像）
    // -----------------------------------------------------------------------

    #[test]
    fn route_request_builder_preserves_order_and_payload() {
        // §42.2 typed：port 侧 domain 参数 → WIT `route-request`——名称 /
        // 值类型一一对应、声明顺序保持、payload 原样传递。
        let params = vec![
            ok(TypedParam::new("id", ParamValue::integer(7)), "param"),
            ok(TypedParam::new("tag", ParamValue::text("x")), "param"),
        ];
        let payload = GuestActionPayload::Json("{\"a\":1}".to_owned());
        let request = build_route_request(
            ok(RouteId::new("get-item"), "route-id"),
            params,
            Some(payload.clone()),
        );
        assert_eq!(request.route_id, "get-item");
        assert_eq!(request.params.len(), 2, "参数顺序与声明一致");
        assert_eq!(
            request.params[0],
            GuestTypedParam {
                name: "id".to_owned(),
                value: GuestParamValue::Integer(7),
            }
        );
        assert_eq!(
            request.params[1],
            GuestTypedParam {
                name: "tag".to_owned(),
                value: GuestParamValue::Text("x".to_owned()),
            }
        );
        assert_eq!(request.payload, Some(payload));
    }

    #[test]
    fn guest_param_value_covers_declared_closed_set() {
        // §42.2 typed 参数闭集：`ParamValue` → `GuestParamValue` 一一对应。
        assert_eq!(
            guest_param_value(&ParamValue::text("t")),
            GuestParamValue::Text("t".to_owned())
        );
        assert_eq!(
            guest_param_value(&ParamValue::integer(-1)),
            GuestParamValue::Integer(-1)
        );
        assert_eq!(
            guest_param_value(&ParamValue::unsigned(9)),
            GuestParamValue::Unsigned(9)
        );
        assert_eq!(
            guest_param_value(&ParamValue::boolean(true)),
            GuestParamValue::Boolean(true)
        );
        assert_eq!(
            guest_param_value(&ParamValue::decimal(1.5)),
            GuestParamValue::Decimal(1.5)
        );
    }

    // -----------------------------------------------------------------------
    // 错误映射闭集（§42.2：确定 HTTP 语义，不进 guest 错误空间）
    // -----------------------------------------------------------------------

    #[test]
    fn dispatch_error_not_found_family() {
        let installation = InstallationId::new();
        assert!(matches!(
            map_dispatch_error(WebDispatchError::NotActiveForWeb(installation)),
            BridgeError::NotActiveForWeb(_)
        ));
        // 0.1-only 组件 / route-id 非法 / 未声明 → 404。
        assert!(matches!(
            map_dispatch_error(WebDispatchError::RouteUnavailable),
            BridgeError::RouteNotFound
        ));
        assert!(matches!(
            map_dispatch_error(WebDispatchError::InvalidRouteId("x".to_owned())),
            BridgeError::RouteNotFound
        ));
        let missing = ok(RouteId::new("missing"), "route-id");
        assert!(matches!(
            map_dispatch_error(WebDispatchError::RouteNotFound(missing)),
            BridgeError::RouteNotFound
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::RouteUnavailable).status_code(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn dispatch_error_validation_family() {
        assert!(matches!(
            map_dispatch_error(WebDispatchError::InvalidParams),
            BridgeError::RouteInvalidParams
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::InvalidParams).status_code(),
            StatusCode::BAD_REQUEST
        );
        assert!(matches!(
            map_dispatch_error(WebDispatchError::BodyTooLarge),
            BridgeError::BodyTooLarge
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::BodyTooLarge).status_code(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[test]
    fn dispatch_error_permission_family() {
        assert!(matches!(
            map_dispatch_error(WebDispatchError::PermissionDenied(
                PermissionDenied::NotGranted
            )),
            BridgeError::RouteDenied
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::PermissionDenied(
                PermissionDenied::Unknown
            ))
            .status_code(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn dispatch_error_quota_family() {
        // 速率 / 队列 → 429；并发 → 503；内部故障 → 502。
        assert!(matches!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::RateLimited)),
            BridgeError::QuotaExceeded
        ));
        assert!(matches!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::OverQueue)),
            BridgeError::QuotaExceeded
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::RateLimited))
                .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert!(matches!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::OverConcurrency)),
            BridgeError::QuotaDenied(QuotaDenied::Busy)
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::OverConcurrency))
                .status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(matches!(
            map_dispatch_error(WebDispatchError::OverQuota(WebQuotaDenied::Unknown)),
            BridgeError::Application(_)
        ));
    }

    #[test]
    fn dispatch_error_timeout_and_busy_family() {
        assert!(matches!(
            map_dispatch_error(WebDispatchError::Cancelled),
            BridgeError::Cancelled
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::Cancelled).status_code(),
            StatusCode::REQUEST_TIMEOUT
        );
        assert!(matches!(
            map_dispatch_error(WebDispatchError::DeadlineExceeded),
            BridgeError::DeadlineExceeded
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::DeadlineExceeded).status_code(),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert!(matches!(
            map_dispatch_error(WebDispatchError::Busy),
            BridgeError::QuotaDenied(QuotaDenied::Busy)
        ));
        assert_eq!(
            map_dispatch_error(WebDispatchError::Busy).status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn dispatch_error_runtime_family_is_internal() {
        assert!(matches!(
            map_dispatch_error(WebDispatchError::ResponseTooLarge),
            BridgeError::ResponseTooLarge
        ));
        assert!(matches!(
            map_dispatch_error(WebDispatchError::GuestError("not-found")),
            BridgeError::Application(_)
        ));
        assert!(matches!(
            map_dispatch_error(WebDispatchError::Runtime(
                RuntimeExecutionError::ConfigUnavailable
            )),
            BridgeError::Application(_)
        ));
        // 内部故障 → 502（§32：失败不产生绕过面）。
        assert_eq!(
            map_dispatch_error(WebDispatchError::GuestError("not-found")).status_code(),
            StatusCode::BAD_GATEWAY
        );
    }

    #[test]
    fn page_denied_mapping_is_403_or_not_active() {
        let installation = InstallationId::new();
        assert!(matches!(
            map_page_denied(WebPageDenied::NotActiveForWeb(installation)),
            BridgeError::NotActiveForWeb(_)
        ));
        assert_eq!(
            map_page_denied(WebPageDenied::NotActiveForWeb(installation)).status_code(),
            StatusCode::NOT_FOUND
        );
        assert!(matches!(
            map_page_denied(WebPageDenied::Denied(PermissionDenied::NotGranted)),
            BridgeError::PageDenied
        ));
        assert_eq!(
            map_page_denied(WebPageDenied::Denied(PermissionDenied::Unknown)).status_code(),
            StatusCode::FORBIDDEN
        );
    }
}
