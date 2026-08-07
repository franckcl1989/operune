//! 0.4.0 Web Application Runtime（§42）——`operune:web@0.2.0` 的用例编排
//! （app descriptor 激活期校验、typed route registry / dispatch、page
//! permission 检查点、bounded + cancellation baseline、per-Component
//! quotas）。
//!
//! # 闭环（§42.2 / §42.3 / §21.5）
//!
//! - **激活期**：`get-app-descriptor`（descriptor-only Store，§19.3 精神）
//!   → [`WebAppService::build_app_declaration`]（domain 转换 + WIT features
//!   交叉校验）→ [`AppDeclaration::new`]（声明期冲突诊断闭集：
//!   RouteIdConflict / PageIdConflict / PathConflict / InvalidDefaultPage
//!   / InvalidPathTemplate / ParamMismatch / InvalidPermission）→
//!   [`WebAppService::validate_contract_surface`]（features flag 与二进制
//!   exports 交叉校验）。**失败 = candidate 保持 Failed（quarantine）**，
//!   当前 Active 不受污染（§19.2）；管线接线见 [`crate::install`]。
//! - **route registry**（typed）：激活期由 [`AppDeclaration`] 构建
//!   （[`WebAppContext`] / [`RouteRegistry`]）。route-id 在 mount namespace
//!   下由 Core 登记（Core 分配、不可冲突，§21.3 0.1 mount 语义扩展）；
//!   同方法路径模板无冲突由声明期诊断保证，因此运行期匹配至多命中一条
//!   路由（确定性）。
//! - **typed route dispatch**：path/method → 路由匹配（模板解析 →
//!   [`ParamValue`] 构造，溢出 / 类型不符以确定语义拒绝 400）→ guest
//!   `handle-route` 动态调用（经 instance lease，0.3 delivery 模式复用，
//!   [`crate::runtime`] 的 `ActiveRuntime::invoke_route`）。
//! - **page 权限检查点**（§17.5 第四层 Grant）：page required-permission
//!   → grant 集校验（[`crate::ports::WebPermissionPolicyPort`]）；未授权以
//!   确定 HTTP 语义拒绝（403），不进 guest 错误空间。
//! - **bounded + cancellation 无条件 baseline**（§42.2）：调用 deadline
//!   （运行时 epoch 强制）、body / 响应上限（宿主侧）、取消探针（
//!   [`crate::cancel::CancellationToken`]：disconnect → 不启动新调用、
//!   调用结束后已取消则丢弃结果——响应交付不保证，已提交副作用不回滚）。
//!   本版本**没有** stream / future / async 面（§42.3：WASI 0.3 production
//!   Gate 未通过，本机/当前保持 bounded 语义）。
//! - **per-Component HTTP quotas / backpressure**（§42.2）：
//!   [`crate::ports::WebQuotaPort`]（速率 / 并发 / 队列上限，§15.2 有界），
//!   超限确定拒绝 429 语义。
//!
//! # 凭据边界（继承 0.1，不得放宽，§21.3）
//!
//! 本模块任何请求结构不含会话 / cookie / CSRF / 认证凭据字段；认证信息
//! 永远不会被转发进 route-request / action-request。
//!
//! # Safe Rust（§11）
//!
//! 全部 Safe Rust；无 panic / unwrap / expect / todo / unimplemented；
//! 队列有界（§15.2）。

use std::collections::HashMap;
use std::sync::Arc;

use operune_domain::{
    AppDeclaration, AppFeatures, AssetPath, HttpMethod, InstallationId, PageDeclaration, PageId,
    PagePath, ParamType, ParamValue, PathSegment, PathTemplate, PermissionDeclaration,
    PermissionName, RouteDeclaration, RouteId, RouteParam, TypedParam, WebDeclarationError,
};

use crate::active::ActiveRuntimeRegistry;
use crate::cancel::CancellationToken;
use crate::contract::{
    GuestActionPayload, GuestAppDescriptor, GuestAppDescriptorError, GuestRouteRequest,
    GuestTypedParam,
};
use crate::error::{ApplicationError, RuntimeExecutionError};
use crate::model::{ActionDenied, ContractSurface};
use crate::ports::{
    AuditEvent, AuditPort, ConfigPort, PermissionDenied, WebPermissionContext,
    WebPermissionPolicyPort, WebQuotaContext, WebQuotaDenied, WebQuotaPort,
};

// ---------------------------------------------------------------------------
// 声明期失败（§42.2 app descriptor 校验 / conflict diagnostics）
// ---------------------------------------------------------------------------

/// app descriptor 激活期校验的失败（§42.2 声明期诊断闭集）。
///
/// - [`AppDescriptorFailure::Malformed`]：结构非法 / WIT features 交叉
///   不变量违反（app-descriptor.wit：pages / default-page 必须同时声明
///   navigation；routes 必须同时声明 typed-routes；permissions 或任何
///   required-permission 引用必须同时声明 permissions；空 entry 等）；
/// - [`AppDescriptorFailure::Declaration`]：domain 冲突诊断
///   （[`WebDeclarationError`] 闭集，对齐 WIT `app-descriptor-error` 的
///   route-id-conflict / page-id-conflict / path-conflict /
///   invalid-path-template / param-mismatch / invalid-permission /
///   invalid-default-page）；
/// - [`AppDescriptorFailure::Guest`]：guest 侧返回 app-descriptor-error
///   （malformed / unsupported-contract-version / internal 等）；
/// - [`AppDescriptorFailure::ContractViolation`]：features flag 与二进制
///   exports 不一致（§6.7 精神：声明与二进制可观察 exports 不一致视为
///   contract violation）。
///
/// 全部失败 → candidate 保持 Failed（quarantine），当前 Active 不受污染
///（§19.2）。
#[derive(Debug, thiserror::Error)]
pub enum AppDescriptorFailure {
    /// 返回的 metadata 无法解析或违反契约不变量（WIT `malformed`）。
    #[error("web app descriptor is malformed: {0}")]
    Malformed(String),
    /// 声明期冲突诊断（[`WebDeclarationError`] 闭集）。
    #[error("web app declaration conflict: {source}")]
    Declaration {
        /// 冲突诊断。
        #[source]
        source: WebDeclarationError,
    },
    /// guest 侧返回 app-descriptor-error（防御性闭集；guest 声明自身失败）。
    #[error("guest returned an app-descriptor error: {0:?}")]
    Guest(GuestAppDescriptorError),
    /// features flag 与二进制可观察 exports 不一致（§6.7 contract
    /// violation）。
    #[error("web app declaration violates the binary contract surface: {0}")]
    ContractViolation(&'static str),
}

impl From<WebDeclarationError> for AppDescriptorFailure {
    fn from(source: WebDeclarationError) -> Self {
        Self::Declaration { source }
    }
}

// ---------------------------------------------------------------------------
// route registry（§42.2 typed route / action 注册表）
// ---------------------------------------------------------------------------

/// 一次路由匹配的结果（HTTP 层据此构建 `route-request`，§42.2）。
#[derive(Debug, Clone, PartialEq)]
pub struct RouteResolution {
    /// 命中的 route-id（分发键）。
    pub route_id: RouteId,
    /// 按声明顺序构造的 typed 参数（与 `route-declaration.params` 一一
    /// 对应，§42.2 typed 语义）。
    pub params: Vec<TypedParam>,
}

/// 路由匹配的失败（Core 侧确定语义：HTTP 层映射 400 / 404，不进 guest
/// 错误空间，route-dispatch.wit）。
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum RouteMatchError {
    /// 请求路径不是合法的挂载命名空间路径（未以 "/" 开头、含 ".." 段、
    /// 空段、反斜杠等，fail closed，§32）。
    #[error("path {0:?} is not a valid mount-namespace path")]
    InvalidPath(String),
    /// 没有路由匹配（method + path → 404 语义）。
    #[error("no route matches {method} {path}")]
    NotMatched {
        /// 请求的 HTTP 方法。
        method: HttpMethod,
        /// 请求的路径。
        path: String,
    },
    /// 参数值不符合声明的类型（类型不符 / 溢出 / 非法形态 → 400 语义，
    /// route-dispatch.wit：类型不符的请求以确定 HTTP 语义拒绝）。
    #[error("parameter {name} value is invalid: {detail}")]
    InvalidParamValue {
        /// 出错的参数名。
        name: String,
        /// 可诊断原因。
        detail: String,
    },
}

/// typed route 注册表（§42.2 route namespace：Core 分配的 mount namespace
/// 下的登记面，激活期构建、运行期只读、确定性）。
///
/// 由 [`AppDeclaration`] 构建；声明期诊断已保证：route-id 唯一、同方法
/// 路径模板互不冲突（[`WebDeclarationError::RouteIdConflict`] /
/// [`WebDeclarationError::PathConflict`]），因此同一 method + 路径至多
/// 命中一条路由。
#[derive(Debug, Clone, PartialEq)]
pub struct RouteRegistry {
    /// route 声明（保持声明顺序，确定性遍历）。
    routes: Vec<Arc<RouteDeclaration>>,
    /// route-id → 索引（route namespace 唯一，声明期保证）。
    by_id: HashMap<RouteId, usize>,
    /// method → 索引列表（同方法模板互不冲突，声明期保证）。
    by_method: HashMap<HttpMethod, Vec<usize>>,
}

impl RouteRegistry {
    /// 从 [`AppDeclaration`] 构建（声明期冲突诊断已执行，映射无歧义）。
    pub fn new(declaration: &AppDeclaration) -> Self {
        let mut routes = Vec::with_capacity(declaration.routes().len());
        let mut by_id = HashMap::new();
        let mut by_method: HashMap<HttpMethod, Vec<usize>> = HashMap::new();
        for route in declaration.routes() {
            let index = routes.len();
            routes.push(Arc::new(route.clone()));
            by_id.insert(route.route_id().clone(), index);
            by_method.entry(route.method()).or_default().push(index);
        }
        Self {
            routes,
            by_id,
            by_method,
        }
    }

    /// 全部 route 声明（声明顺序；审计 / 管理面）。
    pub fn routes(&self) -> &[Arc<RouteDeclaration>] {
        &self.routes
    }

    /// 按 route-id 查找（分发键；未声明 → `None` → 404 语义）。
    pub fn route_by_id(&self, route_id: &RouteId) -> Option<&Arc<RouteDeclaration>> {
        self.by_id.get(route_id).map(|index| &self.routes[*index])
    }

    /// method + 路径 → 路由匹配（模板解析 → typed 参数构造，§42.2）。
    ///
    /// 参数值按声明类型解析：text 原样；integer / unsigned 宽边界解析 +
    /// 溢出拒绝（[`ParamValue::try_from`]）；boolean 闭集 {true, false}；
    /// decimal 拒绝非有限值（JSON 数字常规形态，routes.wit）。参数按
    /// **声明顺序**输出（route-dispatch.wit：顺序与声明一致）。
    pub fn resolve(
        &self,
        method: HttpMethod,
        path: &str,
    ) -> Result<RouteResolution, RouteMatchError> {
        let segments = normalize_request_path(path)?;
        let candidates = match self.by_method.get(&method) {
            Some(candidates) => candidates,
            None => {
                return Err(RouteMatchError::NotMatched {
                    method,
                    path: path.to_owned(),
                });
            }
        };
        for index in candidates {
            let route = &self.routes[*index];
            let Some(captured) = match_template(route.path(), &segments) else {
                continue;
            };
            let params = build_typed_params(route, &captured)?;
            return Ok(RouteResolution {
                route_id: route.route_id().clone(),
                params,
            });
        }
        Err(RouteMatchError::NotMatched {
            method,
            path: path.to_owned(),
        })
    }
}

/// 挂载命名空间请求路径的规范化校验（§32 fail closed：拒绝而不是归一化
/// 输入）。
///
/// 不变量：以 "/" 开头、无控制字符 / 反斜杠、无空段、无 "." / ".." 段。
/// 返回段序列（不含前导空段）。
fn normalize_request_path(path: &str) -> Result<Vec<String>, RouteMatchError> {
    if path.is_empty() {
        return Err(RouteMatchError::InvalidPath(path.to_owned()));
    }
    if path.len() > 4096 {
        return Err(RouteMatchError::InvalidPath(path.to_owned()));
    }
    if !path.starts_with('/') {
        return Err(RouteMatchError::InvalidPath(path.to_owned()));
    }
    if path.chars().any(char::is_control) {
        return Err(RouteMatchError::InvalidPath(path.to_owned()));
    }
    if path.contains('\\') {
        return Err(RouteMatchError::InvalidPath(path.to_owned()));
    }
    let mut segments = Vec::new();
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(RouteMatchError::InvalidPath(path.to_owned()));
        }
        segments.push(segment.to_owned());
    }
    Ok(segments)
}

/// 模板匹配：段数相同 + 字面段相等 + 参数段捕获。
///
/// 返回参数名 → 原始段值（模板内参数名唯一，PathTemplate 构造保证）。
fn match_template(template: &PathTemplate, segments: &[String]) -> Option<HashMap<String, String>> {
    let template_segments = template.segments();
    if template_segments.len() != segments.len() {
        return None;
    }
    let mut captured = HashMap::new();
    for (template_segment, path_segment) in template_segments.iter().zip(segments) {
        match template_segment {
            PathSegment::Literal(literal) => {
                if literal != path_segment {
                    return None;
                }
            }
            PathSegment::Param(name) => {
                captured.insert(name.clone(), path_segment.clone());
            }
        }
    }
    Some(captured)
}

/// 按声明类型把捕获的原始段值解析为 typed 参数（声明顺序；溢出 /
/// 类型不符 → [`RouteMatchError::InvalidParamValue`]，400 语义）。
fn build_typed_params(
    route: &RouteDeclaration,
    captured: &HashMap<String, String>,
) -> Result<Vec<TypedParam>, RouteMatchError> {
    let mut params = Vec::with_capacity(route.params().len());
    for declared in route.params() {
        let raw = match captured.get(declared.name()) {
            Some(raw) => raw,
            // 防御性：声明期已保证模板参数与声明一一对应（§13.3）。
            None => {
                return Err(RouteMatchError::InvalidParamValue {
                    name: declared.name().to_owned(),
                    detail: "not captured from the path template".to_owned(),
                });
            }
        };
        let value = parse_param_value(declared, raw)?;
        let param = TypedParam::new(declared.name(), value).map_err(|_| {
            RouteMatchError::InvalidParamValue {
                name: declared.name().to_owned(),
                detail: "parameter name is invalid".to_owned(),
            }
        })?;
        params.push(param);
    }
    Ok(params)
}

/// 单个参数值的类型化解析（§13.3 边界解析一次；溢出拒绝见
/// [`ParamValue::try_from`]）。
fn parse_param_value(declared: &RouteParam, raw: &str) -> Result<ParamValue, RouteMatchError> {
    let invalid = |detail: String| RouteMatchError::InvalidParamValue {
        name: declared.name().to_owned(),
        detail,
    };
    match declared.value_type() {
        ParamType::Text => Ok(ParamValue::Text(raw.to_owned())),
        ParamType::Integer => {
            let wide = raw
                .parse::<i128>()
                .map_err(|_| invalid(format!("{raw:?} is not an integer")))?;
            // 宽边界 → Integer：超出 i64 范围溢出拒绝（§13.3 边界解析）。
            ParamValue::try_from(wide)
                .map_err(|_| invalid(format!("integer value {raw:?} overflows the i64 range")))
        }
        ParamType::Unsigned => {
            let wide = raw
                .parse::<u128>()
                .map_err(|_| invalid(format!("{raw:?} is not an unsigned integer")))?;
            ParamValue::try_from(wide)
                .map_err(|_| invalid(format!("unsigned value {raw:?} overflows the u64 range")))
        }
        ParamType::Boolean => match raw {
            "true" => Ok(ParamValue::Boolean(true)),
            "false" => Ok(ParamValue::Boolean(false)),
            _ => Err(invalid(format!(
                "{raw:?} is not a boolean (expected \"true\" or \"false\")"
            ))),
        },
        ParamType::Decimal => {
            let value = raw
                .parse::<f64>()
                .map_err(|_| invalid(format!("{raw:?} is not a decimal number")))?;
            // JSON 数字常规形态（routes.wit：64 位浮点是 JSON 数字的常规
            // 形态）：非有限值（NaN / inf）拒绝。
            if value.is_finite() {
                Ok(ParamValue::Decimal(value))
            } else {
                Err(invalid(format!("decimal value {raw:?} is not finite")))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WebAppContext（激活期快照条目；§21.5 原子版本切换随 ActiveEntry 交换）
// ---------------------------------------------------------------------------

/// 激活期构建的 0.4.0 Web 应用上下文（随 [`crate::active::ActiveEntry`]
/// 原子切换，§21.5：descriptor / assets / backend exports 属于同一
/// ComponentVersion）。
#[derive(Debug, Clone, PartialEq)]
pub struct WebAppContext {
    declaration: AppDeclaration,
    registry: RouteRegistry,
}

impl WebAppContext {
    /// 从已通过声明期冲突诊断的 [`AppDeclaration`] 构建（激活期一次）。
    pub fn new(declaration: AppDeclaration) -> Self {
        let registry = RouteRegistry::new(&declaration);
        Self {
            declaration,
            registry,
        }
    }

    /// 完整 app declaration（导航 / 权限 / 路由声明面）。
    pub fn declaration(&self) -> &AppDeclaration {
        &self.declaration
    }

    /// 页面声明列表（导航语义：Core 据此构建页面列表）。
    pub fn pages(&self) -> &[PageDeclaration] {
        self.declaration.pages()
    }

    /// 默认页（Core 对挂载点根路径解析到该页）。
    pub fn default_page(&self) -> Option<&PageId> {
        self.declaration.default_page()
    }

    /// 按 page-id 查找页面。
    pub fn page_by_id(&self, page_id: &PageId) -> Option<&PageDeclaration> {
        self.declaration
            .pages()
            .iter()
            .find(|page| page.page_id() == page_id)
    }

    /// 按静态路径解析页面（页面路径是挂载命名空间下的静态路径，无模板段，
    /// navigation.wit；请求路径规范化失败 → `None`）。
    pub fn resolve_page(&self, path: &str) -> Option<&PageDeclaration> {
        let segments = normalize_request_path(path).ok()?;
        let normalized = format!("/{}", segments.join("/"));
        self.declaration
            .pages()
            .iter()
            .find(|page| page.path().as_str() == normalized)
    }

    /// typed route 注册表（method + path → 路由，§42.2）。
    pub fn registry(&self) -> &RouteRegistry {
        &self.registry
    }

    /// 按 route-id 查找声明（分发键）。
    pub fn route_by_id(&self, route_id: &RouteId) -> Option<&Arc<RouteDeclaration>> {
        self.registry.route_by_id(route_id)
    }
}

// ---------------------------------------------------------------------------
// WebAppService（0.4 编排）
// ---------------------------------------------------------------------------

/// 0.4.0 Web Application Runtime 用例服务（§42.2 编排面）。
///
/// - 激活期：app descriptor 读取 → 组装 → 冲突诊断 → 二进制表面交叉
///   校验（管线接线，[`crate::install`]；失败 = candidate Failed）；
/// - 运行期：page 权限检查点、typed route dispatch（route-id → 声明 →
///   参数校验 → 权限 → body → quota → cancellation 探针 → guest
///   handle-route，经 instance lease，0.3 delivery 模式复用）、路由匹配
///   （HTTP 层 Core 导航）。
pub struct WebAppService {
    active: Arc<ActiveRuntimeRegistry>,
    permission: Arc<dyn WebPermissionPolicyPort>,
    quota: Arc<dyn WebQuotaPort>,
    config: Arc<dyn ConfigPort>,
    audit: Arc<dyn AuditPort>,
}

impl WebAppService {
    /// 构造（注入 Active 快照、permission 检查点、quota 与 config / audit）。
    pub fn new(
        active: Arc<ActiveRuntimeRegistry>,
        permission: Arc<dyn WebPermissionPolicyPort>,
        quota: Arc<dyn WebQuotaPort>,
        config: Arc<dyn ConfigPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            active,
            permission,
            quota,
            config,
            audit,
        }
    }

    /// 读取安装实例的 0.4.0 Web 应用上下文（无 0.2.0 表面 → `None`；
    /// 安装不是 Active → [`ApplicationError::NotActiveForWeb`]）。
    pub fn context(
        &self,
        installation_id: InstallationId,
    ) -> Result<Option<Arc<WebAppContext>>, ApplicationError> {
        let entry = self
            .active
            .get(installation_id)
            .ok_or(ApplicationError::NotActiveForWeb(installation_id))?;
        Ok(entry.web_app.clone())
    }

    /// 激活期组装：guest app descriptor → domain [`AppDeclaration`]
    ///（§13.3 边界解析一次 + 声明期冲突诊断，§42.2）。
    ///
    /// 转换顺序固定（确定性 first-error-wins，§19.3 精神）：entry →
    /// permissions → pages → routes → default-page → features 交叉校验 →
    /// [`AppDeclaration::new`]（冲突诊断闭集）。
    pub fn build_app_declaration(
        &self,
        guest: &GuestAppDescriptor,
    ) -> Result<AppDeclaration, AppDescriptorFailure> {
        // entry（WIT：空 entry / 非法路径 → malformed）。
        let entry = AssetPath::new(&guest.entry).map_err(|_| {
            AppDescriptorFailure::Malformed(
                "entry is not a valid mount-namespace asset path".to_owned(),
            )
        })?;
        // permissions。
        let mut permissions = Vec::with_capacity(guest.permissions.len());
        for declared in &guest.permissions {
            let name = PermissionName::new(&declared.name).map_err(|_| {
                AppDescriptorFailure::Malformed(format!(
                    "permission-name {:?} is invalid",
                    declared.name
                ))
            })?;
            permissions.push(PermissionDeclaration::new(
                name,
                declared.description.clone(),
            ));
        }
        // pages。
        let mut pages = Vec::with_capacity(guest.pages.len());
        for declared in &guest.pages {
            let page_id = PageId::new(&declared.page_id).map_err(|_| {
                AppDescriptorFailure::Malformed(format!(
                    "page-id {:?} is invalid",
                    declared.page_id
                ))
            })?;
            let path = PagePath::new(&declared.path).map_err(|_| {
                AppDescriptorFailure::Malformed(format!(
                    "page path {:?} is not a valid static path",
                    declared.path
                ))
            })?;
            let required_permission = declared
                .required_permission
                .as_ref()
                .map(PermissionName::new)
                .transpose()
                .map_err(|_| {
                    AppDescriptorFailure::Malformed(
                        "page required-permission is invalid".to_owned(),
                    )
                })?;
            pages.push(PageDeclaration::new(
                page_id,
                path,
                declared.display_name.clone(),
                required_permission,
            ));
        }
        // routes（模板语法错误 → InvalidPathTemplate；参数不一致 →
        // ParamMismatch，声明期诊断闭集）。
        let mut routes = Vec::with_capacity(guest.routes.len());
        for declared in &guest.routes {
            let route_id = RouteId::new(&declared.route_id).map_err(|_| {
                AppDescriptorFailure::Malformed(format!(
                    "route-id {:?} is invalid",
                    declared.route_id
                ))
            })?;
            let method = HttpMethod::from_str_checked(&declared.method).map_err(|_| {
                AppDescriptorFailure::Malformed(format!(
                    "http method {:?} is not in the declared closed set",
                    declared.method
                ))
            })?;
            let path = PathTemplate::new(&declared.path)?;
            let mut params = Vec::with_capacity(declared.params.len());
            for param in &declared.params {
                let value_type = ParamType::from_str_checked(&param.value_type).map_err(|_| {
                    AppDescriptorFailure::Malformed(format!(
                        "param-type {:?} is not in the declared closed set",
                        param.value_type
                    ))
                })?;
                params.push(RouteParam::new(&param.name, value_type).map_err(|_| {
                    AppDescriptorFailure::Malformed(format!(
                        "route-param name {:?} is invalid",
                        param.name
                    ))
                })?);
            }
            let required_permission = declared
                .required_permission
                .as_ref()
                .map(PermissionName::new)
                .transpose()
                .map_err(|_| {
                    AppDescriptorFailure::Malformed(
                        "route required-permission is invalid".to_owned(),
                    )
                })?;
            routes.push(RouteDeclaration::new(
                route_id,
                method,
                path,
                params,
                required_permission,
            )?);
        }
        let default_page = guest
            .default_page
            .as_ref()
            .map(PageId::new)
            .transpose()
            .map_err(|_| AppDescriptorFailure::Malformed("default-page is invalid".to_owned()))?;
        // WIT features 交叉不变量（app-descriptor.wit：声明与 flag 不一致
        // → malformed）。
        let features = AppFeatures::new(
            guest.features.static_assets,
            guest.features.backend_actions,
            guest.features.navigation,
            guest.features.typed_routes,
            guest.features.permissions,
        );
        if !features.navigation() && (!guest.pages.is_empty() || guest.default_page.is_some()) {
            return Err(AppDescriptorFailure::Malformed(
                "pages / default-page declared without the navigation feature flag".to_owned(),
            ));
        }
        if !features.typed_routes() && !guest.routes.is_empty() {
            return Err(AppDescriptorFailure::Malformed(
                "routes declared without the typed-routes feature flag".to_owned(),
            ));
        }
        let references_permission = guest
            .pages
            .iter()
            .any(|page| page.required_permission.is_some())
            || guest
                .routes
                .iter()
                .any(|route| route.required_permission.is_some());
        if !features.permissions() && (!guest.permissions.is_empty() || references_permission) {
            return Err(AppDescriptorFailure::Malformed(
                "permissions or required-permission references declared without the permissions feature flag".to_owned(),
            ));
        }
        // 组装 + 声明期冲突诊断（§42.2 conflict diagnostics）。
        AppDeclaration::new(
            entry,
            features,
            guest.display_name.clone(),
            permissions,
            pages,
            routes,
            default_page,
        )
        .map_err(AppDescriptorFailure::from)
    }

    /// 二进制 contract surface 交叉校验（§6.7 精神：声明与二进制可观察
    /// exports 不一致视为 contract violation）。
    ///
    /// - `navigation` flag → 组件必须导出 navigation 接口；
    /// - `typed-routes` flag → 组件必须导出 route-dispatch 接口（运行期
    ///   分发入口；routes 接口本身无函数面）；
    /// - `permissions` flag → 组件必须导出 permissions 接口。
    pub fn validate_contract_surface(
        &self,
        declaration: &AppDeclaration,
        surface: &ContractSurface,
    ) -> Result<(), AppDescriptorFailure> {
        let features = declaration.features();
        if features.navigation() && !surface.exports_web_navigation() {
            return Err(AppDescriptorFailure::ContractViolation(
                "navigation feature requires the navigation interface export",
            ));
        }
        if features.typed_routes() && !surface.exports_web_route_dispatch() {
            return Err(AppDescriptorFailure::ContractViolation(
                "typed-routes feature requires the route-dispatch interface export",
            ));
        }
        if features.permissions() && !surface.exports_web_permissions() {
            return Err(AppDescriptorFailure::ContractViolation(
                "permissions feature requires the permissions interface export",
            ));
        }
        Ok(())
    }

    /// 页面权限检查点（§17.5 四层授权链的 Grant 层；§42.2 page
    /// permission declarations）。
    ///
    /// 页面无 required-permission → 放行；有 → grant 集校验（
    /// [`WebPermissionPolicyPort`]）；未授权以确定 HTTP 语义拒绝（403），
    /// 不进 guest 错误空间。拒绝写审计（元数据 only，§16.6）。
    pub fn authorize_page(
        &self,
        installation_id: InstallationId,
        page: &PageDeclaration,
    ) -> Result<(), WebPageDenied> {
        let Some(required) = page.required_permission() else {
            return Ok(());
        };
        let entry = self
            .active
            .get(installation_id)
            .ok_or(WebPageDenied::NotActiveForWeb(installation_id))?;
        let result = self.permission.check_permission(&WebPermissionContext {
            installation_id,
            version: entry.installation.version,
            permission: required.clone(),
        });
        if let Err(denied) = &result {
            let _ = self.audit.append(AuditEvent::ActionDenied {
                installation: installation_id,
                action: format!("page:{}", page.page_id()),
                reason: map_permission_denied(*denied),
            });
        }
        result.map_err(WebPageDenied::Denied)
    }

    /// typed route dispatch（§42.2；Core-mediated）。
    ///
    /// 顺序（全部 Core 侧检查通过才调用 guest，route-dispatch.wit）：
    /// 1. route-id → 声明（route namespace；未声明 → 404 语义）；
    /// 2. required-permission → grant 集校验（§17.5 第四层；未授权 403）；
    /// 3. 参数按声明校验（数量 / 名称 / 类型；不符 → 400 语义）；
    /// 4. body 上限（§42.2 无条件 baseline）；
    /// 5. per-Component HTTP quota（速率 / 并发 / 队列；超限 429 语义）；
    /// 6. cancellation 探针（disconnect → 不启动新的 in-flight 调用）；
    /// 7. guest `handle-route` 动态调用（经 instance lease，0.3 delivery
    ///    模式复用；deadline / 响应上限在运行时强制）；
    /// 8. 调用结束后的取消探针：已取消 → 丢弃结果（响应交付不保证，
    ///    §42.2；已提交副作用不回滚）。
    pub fn dispatch_route(
        &self,
        installation_id: InstallationId,
        request: &GuestRouteRequest,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, WebDispatchError> {
        let entry = self
            .active
            .get(installation_id)
            .ok_or(WebDispatchError::NotActiveForWeb(installation_id))?;
        // 0.2.0 表面缺失（0.1-only 组件 / 未接线）：typed route 不存在。
        let context = entry
            .web_app
            .as_ref()
            .ok_or(WebDispatchError::RouteUnavailable)?;
        let route_id = RouteId::new(&request.route_id)
            .map_err(|_| WebDispatchError::InvalidRouteId(request.route_id.clone()))?;
        let route = context
            .route_by_id(&route_id)
            .ok_or(WebDispatchError::RouteNotFound(route_id.clone()))?;
        // 2. route required-permission（§17.5 第四层）。
        if let Some(required) = route.required_permission() {
            let result = self.permission.check_permission(&WebPermissionContext {
                installation_id,
                version: entry.installation.version,
                permission: required.clone(),
            });
            if let Err(denied) = result {
                let _ = self.audit.append(AuditEvent::ActionDenied {
                    installation: installation_id,
                    action: route_id.to_string(),
                    reason: map_permission_denied(denied),
                });
                return Err(WebDispatchError::PermissionDenied(denied));
            }
        }
        // 3. 参数按声明校验（§42.2 typed：数量 / 顺序 / 名称 / 类型；
        //    guest 收到的 params 与声明一致是契约）。
        if !validate_request_params(route, &request.params) {
            return Err(WebDispatchError::InvalidParams);
        }
        // 4. body 上限（§42.2 无条件 baseline；宿主侧硬上限）。
        let config = self
            .config
            .snapshot()
            .map_err(|_| WebDispatchError::Runtime(RuntimeExecutionError::ConfigUnavailable))?;
        let body_size = request_payload_size(&request.payload);
        if body_size > config.max_action_body_bytes.as_u64() {
            return Err(WebDispatchError::BodyTooLarge);
        }
        // 5. per-Component HTTP quota（§42.2：超限确定拒绝 429 语义）。
        let guard = self
            .quota
            .admit(&WebQuotaContext {
                installation_id,
                version: entry.installation.version,
            })
            .map_err(WebDispatchError::OverQuota)?;
        // 6. cancellation 探针（§42.2：disconnect → 不启动新的调用）。
        if cancel.is_cancelled() {
            return Err(WebDispatchError::Cancelled);
        }
        // 7. guest handle-route 动态调用（经 instance lease；调用 deadline
        //    与响应体积上限在运行时强制）。
        guard.begin();
        let response = entry
            .runtime
            .invoke_route(request)
            .map_err(map_route_runtime_error)?;
        // 调用已发生：审计记录调用（§16.6 元数据 only；已提交副作用不
        // 回滚，§42.2）。
        let _ = self.audit.append(AuditEvent::ActionInvoked {
            installation: installation_id,
            version: entry.installation.version,
            action: route_id.to_string(),
        });
        // 8. 调用结束后的取消探针：已取消 → 丢弃结果（§42.2 响应交付不
        //    保证）。
        if cancel.is_cancelled() {
            return Err(WebDispatchError::Cancelled);
        }
        Ok(response)
    }
}

/// 把 `PermissionDenied` 映射为 0.1 审计事件可承载的拒绝类别（§16.6
/// 元数据 only；PermissionDenied::NotGranted 与
/// `ActionDenied::NotGranted` 同属 §17.5 第四层 Grant 拒绝）。
fn map_permission_denied(denied: PermissionDenied) -> ActionDenied {
    match denied {
        PermissionDenied::NotGranted => ActionDenied::NotGranted,
        PermissionDenied::Unknown => ActionDenied::Unknown,
    }
}

/// 参数按声明校验（数量 / 顺序 / 名称 / 类型逐项一致；宿主侧请求参数
/// 列表上限，§7.4 host-buffer 纪律）。
fn validate_request_params(route: &RouteDeclaration, params: &[GuestTypedParam]) -> bool {
    if params.len() > crate::contract::MAX_APP_REQUEST_PARAMS_LEN {
        return false;
    }
    let declared = route.params();
    if params.len() != declared.len() {
        return false;
    }
    for (param, declared) in params.iter().zip(declared) {
        if param.name != declared.name() {
            return false;
        }
        if param.value.param_type() != declared.value_type() {
            return false;
        }
    }
    true
}

/// 辅助载荷的宿主侧体积（§42.2 body 上限检查）。
fn request_payload_size(payload: &Option<GuestActionPayload>) -> u64 {
    match payload {
        Some(GuestActionPayload::Json(value)) => u64::try_from(value.len()).unwrap_or(u64::MAX),
        Some(GuestActionPayload::Raw(bytes)) => u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        None => 0,
    }
}

/// 运行时调用错误的宿主侧映射（§14.1 封闭 typed）。
fn map_route_runtime_error(error: RuntimeExecutionError) -> WebDispatchError {
    match error {
        RuntimeExecutionError::DeadlineExceeded => WebDispatchError::DeadlineExceeded,
        RuntimeExecutionError::ResponseTooLarge => WebDispatchError::ResponseTooLarge,
        RuntimeExecutionError::Busy => WebDispatchError::Busy,
        RuntimeExecutionError::MissingOperuneExport(_) => WebDispatchError::RouteUnavailable,
        other => WebDispatchError::Runtime(other),
    }
}

// ---------------------------------------------------------------------------
// 运行期拒绝（§42.2 Core 侧确定语义；HTTP 层映射为确定状态码，不进
// guest 错误空间）
// ---------------------------------------------------------------------------

/// typed route dispatch 的 Core 侧拒绝（§42.2；HTTP 层映射：404 / 400 /
/// 403 / 413 / 429 / 503 / 504）。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WebDispatchError {
    /// 安装实例不是 Active（§21.3 绑定要求）。
    #[error("installation {0} is not active for web")]
    NotActiveForWeb(InstallationId),
    /// 组件没有 typed route 表面（0.1-only / 未接线；route-dispatch.wit
    /// not-found 语义的 Core 侧形态）。
    #[error("component does not support typed route dispatch")]
    RouteUnavailable,
    /// route-id 结构非法（§13.3 边界校验）。
    #[error("route-id {0:?} is invalid")]
    InvalidRouteId(String),
    /// 请求的 route-id 未声明（route namespace；404 语义）。
    #[error("route {0} is not declared")]
    RouteNotFound(RouteId),
    /// 参数与声明不一致（数量 / 顺序 / 名称 / 类型；400 语义，
    /// route-dispatch.wit）。
    #[error("route params do not match the declaration")]
    InvalidParams,
    /// 辅助载荷超过宿主侧 body 上限（§42.2 无条件 baseline）。
    #[error("route request body exceeds the host-side limit")]
    BodyTooLarge,
    /// required-permission 未授权（§17.5 第四层；403 语义）。
    #[error("route access denied: {0}")]
    PermissionDenied(PermissionDenied),
    /// per-Component HTTP quota 超限（§42.2；429 / 503 语义）。
    #[error("route quota exceeded: {0}")]
    OverQuota(WebQuotaDenied),
    /// 调用被取消（disconnect；响应交付不保证，§42.2）。
    #[error("route call cancelled")]
    Cancelled,
    /// 调用 deadline 到期（§7.5 / §42.2；504 语义）。
    #[error("route call deadline exceeded")]
    DeadlineExceeded,
    /// 响应体积超过宿主侧上限（§42.2）。
    #[error("route response exceeds the host-side limit")]
    ResponseTooLarge,
    /// 全部实例槽位繁忙（§7.4 并发上限；503 语义）。
    #[error("all instance slots are busy")]
    Busy,
    /// guest 返回值空间错误（防御性闭集，route-dispatch.wit）。
    #[error("guest returned a route error: {0}")]
    GuestError(&'static str),
    /// wasm 执行失败（trap / 超预算等）。
    #[error("wasm execution failed: {0}")]
    Runtime(#[source] RuntimeExecutionError),
}

/// 页面访问的 Core 侧拒绝（§42.2 page permission；403 语义）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebPageDenied {
    /// 安装实例不是 Active。
    #[error("installation {0} is not active for web")]
    NotActiveForWeb(InstallationId),
    /// 页面 required-permission 未授权（§17.5 第四层）。
    #[error("page access denied: {0}")]
    Denied(PermissionDenied),
}
