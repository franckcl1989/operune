//! 0.4.0 Web Application Runtime（§42）——`operune:web@0.2.0` 的领域类型。
//!
//! 契约面：`operune:web@0.2.0`（app-descriptor / navigation / routes /
//! permissions / route-dispatch，已提交稳定；§42.2）。语义边界（各 .wit
//! 文件顶部注释）：
//!
//! - **声明面**：pages / routes / permissions 全部是安装期声明事实，注册
//!   发生在声明期（descriptor 校验阶段），不是运行期动态注册；Core 是
//!   导航与分发的唯一执行者，guest 没有运行时导航 / 注册 API；
//! - **route namespace**（Core 分配、不可冲突）：route-id / page-id 在同一
//!   ComponentVersion 内必须唯一；路径模板（方法 + 规范化模板）必须唯一；
//!   冲突在声明期以确定性诊断拒绝（[`WebDeclarationError`] 闭集，对齐 WIT
//!   `app-descriptor-error`）；
//! - **typed 参数**（§42.2）：`routes.param-type` 闭集与
//!   `route-dispatch.param-value` 闭集一一对应（[`ParamValue::param_type`]）；
//!   Core 在分发前按声明校验并构造参数值；
//! - **页面路径是静态路径**（无模板段、无参数；动态路径属于
//!   `path-template`）；全部路径都是挂载命名空间下的规范化路径（以 "/"
//!   开头，拒绝 ".." 段、空段、反斜杠与目录穿越，fail closed，§32）；
//! - **凭据边界**（继承 0.1）：本模块任何类型不含会话 / cookie / CSRF /
//!   认证凭据字段（§21.3）；Core 的认证信息永不进入请求结构。
//!
//! 错误空间划分（本模块的设计选择，与 crate 全局 validate-on-construct
//! 约定一致，§13.3）：
//! - 值对象结构性校验（标识符 / 路径 / 参数名 / 参数值域）失败 →
//!   [`DomainError::InvalidValue`]；
//! - 模板语法与声明期冲突诊断（WIT `app-descriptor-error` 的 domain 闭集）
//!   → [`WebDeclarationError`]：非法模板（`invalid-path-template`）、参数
//!   不一致（`param-mismatch`）、重复 route-id / page-id、路径冲突、非法
//!   权限引用、非法默认页。`malformed`（其余情形）/
//!   `unsupported-contract-version` / `internal` 三个 WIT 变体是宿主侧
//!   （Core）语义，不由 Domain 产生（见 [`WebDeclarationError`] 文档）。

use std::collections::HashSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::id::{MAX_IDENTIFIER_LEN, validate_identifier};
use crate::path::MAX_PATH_LEN;

// ---------------------------------------------------------------------------
// navigation（operune:web@0.2.0 `navigation` interface）：页面类型
// ---------------------------------------------------------------------------

/// 页面标识符（§13.5 record wrapper；与 WIT `navigation.page-id` record
/// 严格对齐）。
///
/// 语义（navigation.wit 明文）：Component 定义的开放页面标识符；Core 只做
/// 等价比较、审计与导航解析，不解析语义；同一 app descriptor 内不得重复
/// （重复 → [`WebDeclarationError::PageIdConflict`]，由
/// [`AppDeclaration::new`] 检出）。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制
/// 字符。WIT 未声明字符集，采用与 [`ComponentId`](crate::ComponentId) 相同
/// 的结构性校验（§19.1 输入不可信、§19.3 宿主侧体积上限）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PageId(String);

impl PageId {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::PageId)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PageId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for PageId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 页面路径（与 WIT `navigation.page-path` record 严格对齐）。
///
/// 语义（navigation.wit 明文）：挂载命名空间下的**静态路径**（无模板段、
/// 无参数；动态路径属于 `routes.path-template`）。Core 对挂载点根路径解析
/// 到默认页；页面路径不得与任何 route 路径模板冲突（声明期 path-conflict
/// 诊断，见 [`AppDeclaration::new`]）。
///
/// 与 [`ArtifactPath`](crate::ArtifactPath) 的关系：两者都拒绝 traversal、
/// 反斜杠、控制字符（§32 安全测试）；本类型是**挂载命名空间绝对形态**——
/// 以 "/" 开头，且必须是**已规范化**的路径（拒绝空段 / "." 段，拒绝而不
/// 是归一化输入，fail closed）；并额外拒绝模板段（"{...}"）。
///
/// 不变量（validate-on-construct，§13.3）：
/// - 非空，以 "/" 开头；
/// - 不含空段（"a//b"、尾部 "/" 拒绝）、"." / ".." 段（目录穿越直接拒绝）；
/// - 不含反斜杠（路径是跨平台持久语义，不因宿主 OS 而异，§9.4）与控制
///   字符；
/// - 不含模板段（任何段内出现 '{' 或 '}' 均拒绝）；
/// - 长度 ≤ 4096 字节。
///
/// "/" 本身被拒绝：根路径是 Core 默认页解析的语义空间，不属于页面路径。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PagePath(String);

impl PagePath {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_mount_path(&value, true, ValueKind::PagePath)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；已规范化、以 "/" 开头、无模板段）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 字面段序列（不含前导 "/"；由不变量保证非空段、无模板段）。
    ///
    /// 仅供同一 crate 内把页面路径视为纯字面路径模板使用（
    /// [`PathTemplate::from_literal_segments`]；page 路径与 route 模板的
    /// 冲突判定，见 [`AppDeclaration::new`]）。
    pub(crate) fn literal_segments(&self) -> Vec<String> {
        self.0.split('/').skip(1).map(str::to_string).collect()
    }
}

impl fmt::Display for PagePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PagePath {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for PagePath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PagePath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 页面声明（与 WIT `navigation.page-declaration` record 严格对齐）。
///
/// 语义（navigation.wit 明文）：一个可导航页面；`display-name` 是可选项
/// （导航 UI 使用；Core 不解析）；`required_permission` 引用 permissions
/// 声明的权限名（Core 强制执行；引用未声明的权限名 → 声明期
/// [`WebDeclarationError::InvalidPermission`]，由 [`AppDeclaration::new`]
/// 检出）。
///
/// 构造不可失败（各字段在自身构造时已校验，§13.3）；页面集合级的冲突
/// 诊断（page-id 重复、页面路径与 route 模板冲突、default-page 引用）在
/// [`AppDeclaration::new`] 执行。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PageDeclaration {
    page_id: PageId,
    path: PagePath,
    display_name: Option<String>,
    required_permission: Option<PermissionName>,
}

impl PageDeclaration {
    /// 构造页面声明（§13.3 边界解析一次；字段均已校验）。
    pub fn new(
        page_id: PageId,
        path: PagePath,
        display_name: Option<String>,
        required_permission: Option<PermissionName>,
    ) -> Self {
        Self {
            page_id,
            path,
            display_name,
            required_permission,
        }
    }

    /// 页面标识符（导航与权限引用的键）。
    pub fn page_id(&self) -> &PageId {
        &self.page_id
    }

    /// 页面路径（静态路径，无参数）。
    pub fn path(&self) -> &PagePath {
        &self.path
    }

    /// 可选展示名（导航 UI 使用；Core 不解析）。
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// 访问该页面所需的权限声明引用（可选；Core 强制执行）。
    pub fn required_permission(&self) -> Option<&PermissionName> {
        self.required_permission.as_ref()
    }
}

// ---------------------------------------------------------------------------
// permissions（operune:web@0.2.0 `permissions` interface）：权限类型
// ---------------------------------------------------------------------------

/// 权限名（§13.5 record wrapper；与 WIT `permissions.permission-name` record
/// 严格对齐）。
///
/// 语义（permissions.wit 明文）：Component 声明的、页面 / 路由可引用的权限
/// 标识符；Core 只做等价比较、声明校验与审计，不解析语义；引用了未声明的
/// permission-name 的声明视为非法（→ [`WebDeclarationError::InvalidPermission`]，
/// 由 [`AppDeclaration::new`] 检出）。permission-name 是组件作用域的命名
/// 引用；到 grant scope 的映射与求值策略是 Core 政策。本类型只有命名引用，
/// 不含任何凭据 / 会话 / 角色字段。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制
/// 字符（WIT 未声明字符集，与 [`PageId`] 相同的结构性校验）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PermissionName(String);

impl PermissionName {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::PermissionName)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PermissionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PermissionName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for PermissionName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PermissionName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 权限声明（与 WIT `permissions.permission-declaration` record 严格对齐）。
///
/// 语义（permissions.wit 明文）：可被页面 / 路由引用的命名权限；
/// `description` 是可选人类可读描述（审计与 UI 展示；Core 不解析）。
///
/// 构造不可失败（各字段在自身构造时已校验）；同一 app descriptor 内权限
/// 名必须唯一（违反 → [`WebDeclarationError::InvalidPermission`]，由
/// [`AppDeclaration::new`] 检出）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PermissionDeclaration {
    name: PermissionName,
    description: Option<String>,
}

impl PermissionDeclaration {
    /// 构造权限声明（§13.3 边界解析一次）。
    pub fn new(name: PermissionName, description: Option<String>) -> Self {
        Self { name, description }
    }

    /// 权限名（同一 app descriptor 内唯一）。
    pub fn name(&self) -> &PermissionName {
        &self.name
    }

    /// 可选人类可读描述（审计与 UI 展示；Core 不解析）。
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

// ---------------------------------------------------------------------------
// routes（operune:web@0.2.0 `routes` interface）：typed route / action
// ---------------------------------------------------------------------------

/// route 标识符（§13.5 record wrapper；与 WIT `routes.route-id` record
/// 严格对齐）。
///
/// 语义（routes.wit 明文）：Component 定义的开放路由 / typed action 标识符，
/// 0.1.0 `action-name` 的 typed 演进；0.4.0 的 typed action 以 route-id 为
/// 分发键。Core 只做等价比较与审计记录，不解析语义；同一 ComponentVersion
/// 内 route-id 必须唯一（重复 → [`WebDeclarationError::RouteIdConflict`]，
/// 由 [`AppDeclaration::new`] 检出）。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制
/// 字符（WIT 未声明字符集，与 [`PageId`] 相同的结构性校验）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteId(String);

impl RouteId {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::RouteId)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RouteId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for RouteId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RouteId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 可声明的 HTTP 方法闭集（与 WIT `routes.http-method` enum 严格对齐，§6.3
/// enum 表达闭集）。
///
/// 语义（routes.wit 明文）：HEAD 与 OPTIONS 不可声明（Core 在 bridge 层
/// 自动处理：HEAD 按 GET 语义去掉响应体、OPTIONS 按 CORS 预检语义）；
/// CONNECT / TRACE 等一律不支持（浏览器安全政策与 §21.3 隔离底线）。
///
/// 冲突判定的方法维度：同一路径模板在不同方法下不冲突（方法不同语义不
/// 同）；冲突只在同方法下判定（[`PathConflict::detect`] 的方法分组由
/// [`AppDeclaration::new`] 实现）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HttpMethod {
    /// `get`
    Get,
    /// `post`
    Post,
    /// `put`
    Put,
    /// `patch`
    Patch,
    /// `delete`
    Delete,
}

impl HttpMethod {
    /// 与 WIT `http-method` 变体名一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }

    /// 从 WIT 变体名解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集
    /// 之外的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "get" => Ok(Self::Get),
            "post" => Ok(Self::Post),
            "put" => Ok(Self::Put),
            "patch" => Ok(Self::Patch),
            "delete" => Ok(Self::Delete),
            _ => Err(DomainError::invalid_value(
                ValueKind::HttpMethod,
                format!("{s:?} is not an http-method variant (get | post | put | patch | delete)"),
            )),
        }
    }
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for HttpMethod {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for HttpMethod {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HttpMethod {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 路径模板段（`path-template` 的解析结果；§13.3 构造时解析一次）。
///
/// - [`PathSegment::Literal`]：字面段（如 "a"）；
/// - [`PathSegment::Param`]：模板参数段（"{name}"，name 是 `[a-z0-9-]+`
///   标识符）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PathSegment {
    /// 字面段（不含 '{' / '}'）。
    Literal(String),
    /// 模板参数段（"{name}"）。
    Param(String),
}

impl PathSegment {
    /// 是否为字面段。
    pub fn is_literal(&self) -> bool {
        matches!(self, Self::Literal(_))
    }

    /// 字面段内容。
    pub fn as_literal(&self) -> Option<&str> {
        match self {
            Self::Literal(segment) => Some(segment),
            Self::Param(_) => None,
        }
    }

    /// 模板参数名（"{name}" 的 name）。
    pub fn as_param(&self) -> Option<&str> {
        match self {
            Self::Param(name) => Some(name),
            Self::Literal(_) => None,
        }
    }
}

/// 路径模板（与 WIT `routes.path-template` record 严格对齐）。
///
/// 语法（routes.wit 明文）：以 "/" 开头的规范化相对路径；段可为字面段或
/// 模板段 "{name}"，name 为小写字母 / 数字 / "-" 组成的标识符
/// （`[a-z0-9-]+`）；同一路径内模板段不得重复。不变量：不含 ".." 段、
/// 空段、反斜杠；不得解析到挂载命名空间之外。
///
/// 解析在构造时完成一次（§13.3 边界解析一次）：段分类（字面 / 参数）、
/// 参数名唯一性与字符集校验全部在 [`PathTemplate::new`] 完成；任何语法
/// 错误返回 [`WebDeclarationError::InvalidPathTemplate`]（对齐 WIT
/// `invalid-path-template`）。
///
/// 模板参数到声明类型的映射（模板段名 ↔ `route-param`）由
/// [`RouteDeclaration::new`] 校验（不一致 → `param-mismatch`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathTemplate {
    value: String,
    segments: Vec<PathSegment>,
}

impl PathTemplate {
    /// 解析并校验路径模板（§13.3 边界解析一次；语法错误 →
    /// [`WebDeclarationError::InvalidPathTemplate`]）。
    pub fn new(value: impl Into<String>) -> Result<PathTemplate, WebDeclarationError> {
        let value = value.into();
        let segments = parse_template(&value)?;
        Ok(PathTemplate { value, segments })
    }

    /// 模板原始字符串视图（只读；未归一化，非法形态在构造时已拒绝）。
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// 解析后的段序列（字面 / 参数，保持声明顺序）。
    pub fn segments(&self) -> &[PathSegment] {
        &self.segments
    }

    /// 模板参数名（按出现顺序；[`PathTemplate::new`] 已保证唯一）。
    pub fn param_names(&self) -> Vec<&str> {
        self.segments
            .iter()
            .filter_map(PathSegment::as_param)
            .collect()
    }

    /// 从已校验的纯字面段构造（内部；[`PagePath`] → [`PathTemplate`] 的
    /// 不变量保证转换不可失败——页面路径是合法纯字面模板的子集）。
    pub(crate) fn from_literal_segments(segments: Vec<String>) -> Self {
        let value = format!("/{}", segments.join("/"));
        let segments = segments.into_iter().map(PathSegment::Literal).collect();
        Self { value, segments }
    }
}

/// 解析路径模板并做段分类（见 [`PathTemplate::new`]）。
fn parse_template(value: &str) -> Result<Vec<PathSegment>, WebDeclarationError> {
    if value.is_empty() {
        return Err(WebDeclarationError::invalid_template("must not be empty"));
    }
    if value.len() > MAX_PATH_LEN {
        return Err(WebDeclarationError::invalid_template(format!(
            "must not exceed {MAX_PATH_LEN} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(WebDeclarationError::invalid_template(
            "must not contain control characters",
        ));
    }
    if value.contains('\\') {
        return Err(WebDeclarationError::invalid_template(
            "backslash is not a valid path separator; use '/'",
        ));
    }
    if !value.starts_with('/') {
        return Err(WebDeclarationError::invalid_template(
            "must start with '/' (mount-namespace path)",
        ));
    }
    let mut segments = Vec::new();
    let mut seen = HashSet::new();
    for segment in value.split('/').skip(1) {
        if segment.is_empty() {
            return Err(WebDeclarationError::invalid_template(
                "must not contain empty segments (e.g. '//' or trailing '/')",
            ));
        }
        if segment == "." || segment == ".." {
            return Err(WebDeclarationError::invalid_template(format!(
                "path segment {segment:?} is not allowed (directory traversal)"
            )));
        }
        if let Some(rest) = segment.strip_prefix('{') {
            let Some(name) = rest.strip_suffix('}') else {
                return Err(WebDeclarationError::invalid_template(format!(
                    "template segment {segment:?} must be of the form '{{name}}'"
                )));
            };
            if let Some(detail) = param_name_error(name) {
                return Err(WebDeclarationError::invalid_template(format!(
                    "template segment {segment:?}: {detail}"
                )));
            }
            if !seen.insert(name) {
                return Err(WebDeclarationError::invalid_template(format!(
                    "template parameter {name:?} appears more than once"
                )));
            }
            segments.push(PathSegment::Param(name.to_string()));
        } else if segment.contains('{') || segment.contains('}') {
            return Err(WebDeclarationError::invalid_template(format!(
                "segment {segment:?} contains '{{' or '}}' but is not a template segment"
            )));
        } else {
            segments.push(PathSegment::Literal(segment.to_string()));
        }
    }
    Ok(segments)
}

impl fmt::Display for PathTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

impl FromStr for PathTemplate {
    type Err = WebDeclarationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for PathTemplate {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PathTemplate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl From<&PagePath> for PathTemplate {
    /// 页面路径 → 纯字面路径模板。
    ///
    /// [`PagePath`] 的不变量保证其值已是合法的纯字面路径模板（以 "/"
    /// 开头、无空段 / "." / ".." / 反斜杠 / 模板段），转换不可失败；用于
    /// page 路径与 route 模板的冲突判定（[`AppDeclaration::new`]）。
    fn from(page: &PagePath) -> Self {
        PathTemplate::from_literal_segments(page.literal_segments())
    }
}

/// 结构化参数类型闭集（与 WIT `routes.param-type` enum 严格对齐，§6.3
/// enum 表达闭集；§42.2 typed action 的参数声明形态）。
///
/// 语义（routes.wit 明文）：闭集在 WIT 中固定，不随组件声明扩展（§22.4
/// 精神：禁止把任意动态值当作万能 payload）；与 `route-dispatch.param-value`
/// 一一对应（[`ParamValue::param_type`]）。本版本 typed 参数全部为必填；
/// 可选数据走 route-request 的 payload。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ParamType {
    /// 文本（UTF-8 字符串）。
    Text,
    /// 有符号 64 位整数。
    Integer,
    /// 无符号 64 位整数。
    Unsigned,
    /// 布尔值。
    Boolean,
    /// 64 位浮点（JSON 数字的常规形态）。
    Decimal,
}

impl ParamType {
    /// 与 WIT `param-type` 变体名一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Integer => "integer",
            Self::Unsigned => "unsigned",
            Self::Boolean => "boolean",
            Self::Decimal => "decimal",
        }
    }

    /// 从 WIT 变体名解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集
    /// 之外的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "text" => Ok(Self::Text),
            "integer" => Ok(Self::Integer),
            "unsigned" => Ok(Self::Unsigned),
            "boolean" => Ok(Self::Boolean),
            "decimal" => Ok(Self::Decimal),
            _ => Err(DomainError::invalid_value(
                ValueKind::ParamType,
                format!(
                    "{s:?} is not a param-type variant (text | integer | unsigned | boolean | decimal)"
                ),
            )),
        }
    }
}

impl fmt::Display for ParamType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ParamType {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for ParamType {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ParamType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 单个声明参数：名称 + 类型（与 WIT `routes.route-param` record 严格
/// 对齐）。
///
/// 语义（routes.wit 明文）：名称必须与路径模板段一致（或作为查询参数名），
/// 不一致 → `param-mismatch`（[`RouteDeclaration::new`] 校验；本版本模板
/// 语法没有查询部分，因此名称集合必须与模板参数集合**一一对应**——模板
/// 引用未声明参数、声明了模板中不存在的参数都是 param-mismatch，见
/// app-descriptor.wit）。
///
/// 不变量（validate-on-construct，§13.3）：名称与 `path-template` 的
/// "{name}" 语法逐字一致——非空、≤ 255 字节、仅含小写 ASCII 字母 / 数字 /
/// "-"（`[a-z0-9-]+`）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct RouteParam {
    name: String,
    value_type: ParamType,
}

impl RouteParam {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(name: impl Into<String>, value_type: ParamType) -> Result<Self, DomainError> {
        let name = name.into();
        if let Some(detail) = param_name_error(&name) {
            return Err(DomainError::invalid_value(ValueKind::RouteParam, detail));
        }
        Ok(Self { name, value_type })
    }

    /// 参数名（路径模板段名或查询参数名）。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 声明类型（Core 按此校验分发时的 param-value）。
    pub const fn value_type(&self) -> ParamType {
        self.value_type
    }
}

impl<'de> Deserialize<'de> for RouteParam {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            name: String,
            value_type: ParamType,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.name, wire.value_type).map_err(serde::de::Error::custom)
    }
}

/// 路由声明（与 WIT `routes.route-declaration` record 严格对齐）。
///
/// 语义（routes.wit 明文）：一个 typed backend route / action；`route_id`
/// 是分发键（route namespace 内唯一）；`required_permission` 是调用该
/// route 所需的权限声明引用（可选；Core 强制执行）。
///
/// 构造校验（§42.2 声明期冲突诊断的基础）：
/// - 模板与参数一致性（`param-mismatch`）：模板段名必须全部在 params 中
///   声明（模板引用未声明参数）；params 中不得出现模板中不存在的名字
///   （声明了模板中不存在的参数）；参数名不得重复。即模板参数集合与声明
///   参数集合必须一一对应——模板段名 ↔ 声明类型（参数类型映射）在构造时
///   建立；
/// - route-id 重复、同方法路径冲突等**集合级**诊断在
///   [`AppDeclaration::new`] 执行。
///
/// 错误：构造失败返回 [`WebDeclarationError::ParamMismatch`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct RouteDeclaration {
    route_id: RouteId,
    method: HttpMethod,
    path: PathTemplate,
    params: Vec<RouteParam>,
    required_permission: Option<PermissionName>,
}

impl RouteDeclaration {
    /// 构造路由声明并校验模板与参数一致性（§13.3 边界解析一次）。
    pub fn new(
        route_id: RouteId,
        method: HttpMethod,
        path: PathTemplate,
        params: Vec<RouteParam>,
        required_permission: Option<PermissionName>,
    ) -> Result<RouteDeclaration, WebDeclarationError> {
        let template_names = path.param_names();
        // 模板引用未声明参数 → param-mismatch。
        for name in &template_names {
            if !params.iter().any(|param| param.name() == *name) {
                return Err(WebDeclarationError::ParamMismatch {
                    route_id: route_id.clone(),
                    detail: format!("template parameter {name:?} is not declared in params"),
                });
            }
        }
        // 声明了模板中不存在的参数 / 参数名重复 → param-mismatch。
        let mut seen = HashSet::new();
        for param in &params {
            if !template_names.iter().any(|name| *name == param.name()) {
                return Err(WebDeclarationError::ParamMismatch {
                    route_id: route_id.clone(),
                    detail: format!(
                        "declared parameter {:?} does not appear in the path template",
                        param.name()
                    ),
                });
            }
            if !seen.insert(param.name()) {
                return Err(WebDeclarationError::ParamMismatch {
                    route_id: route_id.clone(),
                    detail: format!("parameter {:?} is declared more than once", param.name()),
                });
            }
        }
        Ok(RouteDeclaration {
            route_id,
            method,
            path,
            params,
            required_permission,
        })
    }

    /// route 标识符（分发键；route namespace 内唯一）。
    pub fn route_id(&self) -> &RouteId {
        &self.route_id
    }

    /// HTTP 方法。
    pub const fn method(&self) -> HttpMethod {
        self.method
    }

    /// 路径模板。
    pub fn path(&self) -> &PathTemplate {
        &self.path
    }

    /// 参数声明（与路径模板一致；不一致 → param-mismatch）。
    pub fn params(&self) -> &[RouteParam] {
        &self.params
    }

    /// 调用该 route 所需的权限声明引用（可选；Core 强制执行）。
    pub fn required_permission(&self) -> Option<&PermissionName> {
        self.required_permission.as_ref()
    }
}

impl<'de> Deserialize<'de> for RouteDeclaration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            route_id: RouteId,
            method: HttpMethod,
            path: PathTemplate,
            params: Vec<RouteParam>,
            required_permission: Option<PermissionName>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.route_id,
            wire.method,
            wire.path,
            wire.params,
            wire.required_permission,
        )
        .map_err(serde::de::Error::custom)
    }
}

/// 同 method 下两条路径模板的冲突判定（§42.2 声明期冲突诊断；WIT
/// `path-conflict` 的纯逻辑）。
///
/// 判定语义（歧义路由）：两条模板在同一 HTTP 方法下冲突，当且仅当存在
/// 一条具体的规范化路径同时匹配两者——段数相同，且每一段位置不出现
/// "两侧都是**不同的**字面段"（参数段匹配任意值）：
/// - **字面段冲突**：同一位置两侧都是相同的字面段（"/a/b" 与 "/a/b"）；
/// - **参数位置冲突**：同一位置至少一侧是参数段（"/a/{x}" 与 "/a/b"、
///   "/a/{x}" 与 "/a/{y}"、"/a/{x}" 与 "/{y}/b"、"/{x}" 与 "/a"）。
///
/// 方法无关：判定只看模板形态；"同 path 不同方法不冲突"由
/// [`AppDeclaration::new`] 按方法分组实现。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathConflict {
    first: PathTemplate,
    second: PathTemplate,
}

impl PathConflict {
    /// 纯逻辑判定：两条模板在**同一方法**下是否冲突。
    ///
    /// 公式：冲突 ⟺ 段数相同 ∧ 每一段位置满足 ¬（两侧都是字面段且不同）。
    /// 无分配 / 无错误路径，application 可在注册期直接使用。
    pub fn detect(first: &PathTemplate, second: &PathTemplate) -> bool {
        let a = first.segments();
        let b = second.segments();
        if a.len() != b.len() {
            return false;
        }
        a.iter()
            .zip(b.iter())
            .all(|(sa, sb)| !(sa.is_literal() && sb.is_literal()) || sa == sb)
    }

    /// 冲突的第一条模板。
    pub fn first(&self) -> &PathTemplate {
        &self.first
    }

    /// 冲突的第二条模板。
    pub fn second(&self) -> &PathTemplate {
        &self.second
    }
}

/// 路径冲突的当事方（[`WebDeclarationError::PathConflict`] 诊断用）。
///
/// - [`PathConflictParty::Route`]：route-route 冲突的一方（route-id）；
/// - [`PathConflictParty::Page`]：page 路径与 route 路径模板冲突的页面
///   （page-id）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathConflictParty {
    /// 冲突的一方是一条 route（route-id）。
    Route(RouteId),
    /// 冲突的一方是一个页面（page-id）。
    Page(PageId),
}

impl fmt::Display for PathConflictParty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Route(id) => write!(f, "route {id}"),
            Self::Page(id) => write!(f, "page {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// route-dispatch（operune:web@0.2.0 `route-dispatch` interface）：运行期
// 参数类型
// ---------------------------------------------------------------------------

/// 结构化参数值（与 WIT `route-dispatch.param-value` variant 严格对齐；
/// 闭集，与 `routes.param-type` 一一对应）。
///
/// 语义（route-dispatch.wit 明文）：Core 按声明类型构造并校验；guest 不
/// 应假设出现声明类型之外的变体（出现即 contract violation）。本类型提供：
/// - 闭集构造器（[`ParamValue::text`] / [`ParamValue::integer`] /
///   [`ParamValue::unsigned`] / [`ParamValue::boolean`] /
///   [`ParamValue::decimal`]）；
/// - 值域校验的宽边界转换：[`TryFrom<i128>`]（→ Integer，超出 i64 范围
///   溢出拒绝）与 [`TryFrom<u128>`]（→ Unsigned，超出 u64 范围溢出拒绝），
///   适配层解析字符串 / 宽整数边界输入时使用（§13.3 边界解析一次）；
///   boolean 是 Rust `bool`，天然闭集 {true, false}；
/// - 与 [`ParamType`] 的一一对应（[`ParamValue::param_type`]）。
///
/// 错误：宽边界转换失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq)]
pub enum ParamValue {
    /// UTF-8 文本（`param-type.text`）。
    Text(String),
    /// 有符号 64 位整数（`param-type.integer`）。
    Integer(i64),
    /// 无符号 64 位整数（`param-type.unsigned`）。
    Unsigned(u64),
    /// 布尔值（`param-type.boolean`；闭集 {true, false}）。
    Boolean(bool),
    /// 64 位浮点（`param-type.decimal`）。
    Decimal(f64),
}

impl ParamValue {
    /// 文本值（UTF-8 字符串）。
    pub fn text(value: impl Into<String>) -> Self {
        Self::Text(value.into())
    }

    /// 有符号 64 位整数（i64 已是该值域，构造不可失败）。
    pub fn integer(value: i64) -> Self {
        Self::Integer(value)
    }

    /// 无符号 64 位整数（u64 已是该值域，构造不可失败）。
    pub fn unsigned(value: u64) -> Self {
        Self::Unsigned(value)
    }

    /// 布尔值（闭集 {true, false}）。
    pub fn boolean(value: bool) -> Self {
        Self::Boolean(value)
    }

    /// 64 位浮点。
    pub fn decimal(value: f64) -> Self {
        Self::Decimal(value)
    }

    /// 与 WIT `param-type` 一一对应（分发前按声明校验值类型的映射面）。
    pub fn param_type(&self) -> ParamType {
        match self {
            Self::Text(_) => ParamType::Text,
            Self::Integer(_) => ParamType::Integer,
            Self::Unsigned(_) => ParamType::Unsigned,
            Self::Boolean(_) => ParamType::Boolean,
            Self::Decimal(_) => ParamType::Decimal,
        }
    }

    /// 文本值视图（变体不符为 `None`）。
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(value) => Some(value),
            _ => None,
        }
    }

    /// 有符号 64 位整数视图（变体不符为 `None`）。
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }

    /// 无符号 64 位整数视图（变体不符为 `None`）。
    pub fn as_unsigned(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            _ => None,
        }
    }

    /// 布尔视图（变体不符为 `None`）。
    pub fn as_boolean(&self) -> Option<bool> {
        match self {
            Self::Boolean(value) => Some(*value),
            _ => None,
        }
    }

    /// 64 位浮点视图（变体不符为 `None`）。
    pub fn as_decimal(&self) -> Option<f64> {
        match self {
            Self::Decimal(value) => Some(*value),
            _ => None,
        }
    }
}

impl Serialize for ParamValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Text(value) => {
                serializer.serialize_newtype_variant("ParamValue", 0, "text", value)
            }
            Self::Integer(value) => {
                serializer.serialize_newtype_variant("ParamValue", 1, "integer", value)
            }
            Self::Unsigned(value) => {
                serializer.serialize_newtype_variant("ParamValue", 2, "unsigned", value)
            }
            Self::Boolean(value) => {
                serializer.serialize_newtype_variant("ParamValue", 3, "boolean", value)
            }
            Self::Decimal(value) => {
                serializer.serialize_newtype_variant("ParamValue", 4, "decimal", value)
            }
        }
    }
}

impl<'de> Deserialize<'de> for ParamValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "lowercase")]
        enum Wire {
            Text(String),
            Integer(i64),
            Unsigned(u64),
            Boolean(bool),
            Decimal(f64),
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(match wire {
            Wire::Text(value) => Self::Text(value),
            Wire::Integer(value) => Self::Integer(value),
            Wire::Unsigned(value) => Self::Unsigned(value),
            Wire::Boolean(value) => Self::Boolean(value),
            Wire::Decimal(value) => Self::Decimal(value),
        })
    }
}

impl TryFrom<i128> for ParamValue {
    type Error = DomainError;

    /// 宽边界有符号整数 → Integer（超出 i64 范围 → 溢出拒绝）。
    fn try_from(value: i128) -> Result<Self, Self::Error> {
        i64::try_from(value).map(Self::Integer).map_err(|_| {
            DomainError::invalid_value(
                ValueKind::ParamValue,
                format!("integer value {value} overflows the i64 range"),
            )
        })
    }
}

impl TryFrom<u128> for ParamValue {
    type Error = DomainError;

    /// 宽边界无符号整数 → Unsigned（超出 u64 范围 → 溢出拒绝）。
    fn try_from(value: u128) -> Result<Self, Self::Error> {
        u64::try_from(value).map(Self::Unsigned).map_err(|_| {
            DomainError::invalid_value(
                ValueKind::ParamValue,
                format!("unsigned value {value} overflows the u64 range"),
            )
        })
    }
}

/// 单个命名参数：名称 + 值（与 WIT `route-dispatch.typed-param` record
/// 严格对齐；`handle-route` 请求参数）。
///
/// 语义（route-dispatch.wit 明文）：名称与值由 Core 按声明校验（名称与
/// `route-param` 同名、值类型与声明一致）；类型不符的请求以确定 HTTP
/// 语义拒绝（400），不进 guest 错误空间。
///
/// 名称不变量与 [`RouteParam`] 相同（`[a-z0-9-]+`，≤ 255 字节，
/// validate-on-construct，§13.3）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TypedParam {
    name: String,
    value: ParamValue,
}

impl TypedParam {
    /// 从 WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(name: impl Into<String>, value: ParamValue) -> Result<Self, DomainError> {
        let name = name.into();
        if let Some(detail) = param_name_error(&name) {
            return Err(DomainError::invalid_value(ValueKind::TypedParam, detail));
        }
        Ok(Self { name, value })
    }

    /// 参数名（与声明一致）。
    pub fn name(&self) -> &str {
        &self.name
    }

    /// 参数值（类型与声明一致）。
    pub fn value(&self) -> &ParamValue {
        &self.value
    }
}

impl<'de> Deserialize<'de> for TypedParam {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            name: String,
            value: ParamValue,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.name, wire.value).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// app-descriptor（operune:web@0.2.0 `app-descriptor` interface）：app 声明
// ---------------------------------------------------------------------------

/// Component 内嵌资产的逻辑路径（§13.5 record wrapper；与 WIT
/// `app-descriptor.asset-path` record 严格对齐；语义继承 0.1.0
/// `descriptor.asset-path`，§21.3）。
///
/// 语义（app-descriptor.wit 明文）：非宿主文件路径；值必须是**规范化**相对
/// 路径，以 "/" 开头，不含 ".." 段、空段或反斜杠；不得解析到挂载命名空间
/// 之外。Core 对每个路径执行规范化与越界校验（防 path traversal，§32
/// security test 覆盖）。
///
/// 与 [`PagePath`] 的关系：共享挂载命名空间路径结构（以 "/" 开头、无空段 /
/// "." / ".." / 反斜杠 / 控制字符、长度 ≤ 4096 字节）；区别是本类型**允许**
/// 模板段字符（"{...}"，资产路径无路由歧义语义）。
///
/// "/" 本身被拒绝（入口资产必须是一个具体的规范化路径）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AssetPath(String);

impl AssetPath {
    /// 从组件声明 / WIT 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_mount_path(&value, false, ValueKind::AssetPath)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；已规范化、以 "/" 开头）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AssetPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for AssetPath {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for AssetPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AssetPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 0.4.0 的可组合 Web 能力声明（flags 表达可组合特征，§6.3；与 WIT
/// `app-descriptor.app-features` flags 严格对齐）。
///
/// 语义（app-descriptor.wit 明文）：`static-assets` 与 `backend-actions`
/// 语义与 0.1.0 完全一致；新增 `navigation`（页面声明）、`typed-routes`
/// （typed route / action 注册）、`permissions`（权限声明）。本版本**没有**
/// realtime / stream flag（§42.3 条件未满足，不进本版本 production scope）。
///
/// 闭集 flags 以五个 bool 字段表达（默认全 false）。features 与 pages /
/// routes / permissions 声明之间的交叉不变量（WIT 明文：声明了 pages /
/// default-page 必须同时声明 navigation；声明了 routes 必须同时声明
/// typed-routes；声明了 permissions 或任何 required-permission 引用必须
/// 同时声明 permissions）属于 Core 侧 contract violation 检查（WIT
/// `malformed`），不在本模块 [`WebDeclarationError`] 闭集内。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct AppFeatures {
    static_assets: bool,
    backend_actions: bool,
    navigation: bool,
    typed_routes: bool,
    permissions: bool,
}

impl AppFeatures {
    /// 从五个闭集 flag 构造（§13.3 边界解析一次；与 WIT
    /// `app-features` flags 一一对应）。
    pub const fn new(
        static_assets: bool,
        backend_actions: bool,
        navigation: bool,
        typed_routes: bool,
        permissions: bool,
    ) -> Self {
        Self {
            static_assets,
            backend_actions,
            navigation,
            typed_routes,
            permissions,
        }
    }

    /// 内嵌静态资产（`assets` interface）。
    pub const fn static_assets(self) -> bool {
        self.static_assets
    }

    /// 有界 backend action（`actions` / `route-dispatch`）。
    pub const fn backend_actions(self) -> bool {
        self.backend_actions
    }

    /// 页面声明与导航（`navigation` interface）。
    pub const fn navigation(self) -> bool {
        self.navigation
    }

    /// typed route / action 注册（`routes` interface）。
    pub const fn typed_routes(self) -> bool {
        self.typed_routes
    }

    /// 页面 / action 权限声明（`permissions` interface）。
    pub const fn permissions(self) -> bool {
        self.permissions
    }
}

/// 0.4.0 的 app descriptor（与 WIT `app-descriptor.app-descriptor` record
/// 严格对齐）。
///
/// 语义（app-descriptor.wit 明文）：`entry` / `display-name` 语义继承 0.1
/// （入口资产路径、展示名）；`permissions` / `pages` / `routes` 是新增声明
/// 面；`default-page` 是导航语义（Core 对挂载点根路径解析到该页），必须
/// 引用已声明的 page-id，否则视为非法（malformed）。
///
/// 组装期冲突诊断（§42.2 conflict diagnostics；确定性：同一 ContentDigest
/// + 同一 contract version 得到同一诊断，§19.3 精神；first-error-wins，
///   检查顺序固定如下）：
///
/// 1. 权限名重复（WIT permissions.wit：同一 app descriptor 内唯一）→
///    [`WebDeclarationError::InvalidPermission`]；
/// 2. 页面 / 路由的 required-permission 引用未声明的 permission-name →
///    [`WebDeclarationError::InvalidPermission`]；
/// 3. page-id 重复 → [`WebDeclarationError::PageIdConflict`]；
/// 4. route-id 重复（route namespace 冲突）→
///    [`WebDeclarationError::RouteIdConflict`]；
/// 5. 同方法 route 路径模板冲突（[`PathConflict::detect`]；**同 path 不同
///    方法不冲突**）→ [`WebDeclarationError::PathConflict`]；
/// 6. page 路径与 **GET** route 路径模板冲突（歧义路由；页面经 GET 导航，
///    与非 GET route 同路径不冲突）→ [`WebDeclarationError::PathConflict`]；
/// 7. default-page 引用未声明的 page-id →
///    [`WebDeclarationError::InvalidDefaultPage`]。
///
/// 反序列化边界同样执行组装校验（§13.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppDeclaration {
    entry: AssetPath,
    features: AppFeatures,
    display_name: Option<String>,
    permissions: Vec<PermissionDeclaration>,
    pages: Vec<PageDeclaration>,
    routes: Vec<RouteDeclaration>,
    default_page: Option<PageId>,
}

impl AppDeclaration {
    /// 组装 app descriptor 并执行声明期冲突诊断（§13.3 边界解析一次）。
    pub fn new(
        entry: AssetPath,
        features: AppFeatures,
        display_name: Option<String>,
        permissions: Vec<PermissionDeclaration>,
        pages: Vec<PageDeclaration>,
        routes: Vec<RouteDeclaration>,
        default_page: Option<PageId>,
    ) -> Result<AppDeclaration, WebDeclarationError> {
        // 1. 权限名唯一。
        let mut permission_names = HashSet::new();
        for permission in &permissions {
            if !permission_names.insert(permission.name().clone()) {
                return Err(WebDeclarationError::InvalidPermission {
                    detail: format!(
                        "permission-name {} is declared more than once",
                        permission.name()
                    ),
                });
            }
        }
        // 2. required-permission 必须引用已声明的 permission-name
        //    （invalid-permission）。
        for page in &pages {
            if let Some(required) = page.required_permission()
                && !permission_names.contains(required)
            {
                return Err(WebDeclarationError::InvalidPermission {
                    detail: format!(
                        "page {} references undeclared permission-name {required}",
                        page.page_id()
                    ),
                });
            }
        }
        for route in &routes {
            if let Some(required) = route.required_permission()
                && !permission_names.contains(required)
            {
                return Err(WebDeclarationError::InvalidPermission {
                    detail: format!(
                        "route {} references undeclared permission-name {required}",
                        route.route_id()
                    ),
                });
            }
        }
        // 3. page-id 唯一。
        let mut page_ids = HashSet::new();
        for page in &pages {
            if !page_ids.insert(page.page_id().clone()) {
                return Err(WebDeclarationError::PageIdConflict {
                    page_id: page.page_id().clone(),
                });
            }
        }
        // 4. route-id 唯一（route namespace 冲突）。
        let mut route_ids = HashSet::new();
        for route in &routes {
            if !route_ids.insert(route.route_id().clone()) {
                return Err(WebDeclarationError::RouteIdConflict {
                    route_id: route.route_id().clone(),
                });
            }
        }
        // 5. 同方法 route 路径模板冲突（同 path 不同方法不冲突）。
        for (index, first) in routes.iter().enumerate() {
            for second in routes.iter().skip(index + 1) {
                if first.method() == second.method()
                    && PathConflict::detect(first.path(), second.path())
                {
                    return Err(WebDeclarationError::PathConflict {
                        method: first.method(),
                        template: first.path().clone(),
                        first: PathConflictParty::Route(first.route_id().clone()),
                        second: PathConflictParty::Route(second.route_id().clone()),
                    });
                }
            }
        }
        // 6. page 路径与 GET route 路径模板冲突（歧义路由；页面经 GET
        //    导航，与非 GET route 同路径不冲突）。
        for page in &pages {
            let page_template = PathTemplate::from(page.path());
            for route in &routes {
                if route.method() == HttpMethod::Get
                    && PathConflict::detect(&page_template, route.path())
                {
                    return Err(WebDeclarationError::PathConflict {
                        method: HttpMethod::Get,
                        template: page_template.clone(),
                        first: PathConflictParty::Page(page.page_id().clone()),
                        second: PathConflictParty::Route(route.route_id().clone()),
                    });
                }
            }
        }
        // 7. default-page 必须引用已声明的 page-id（WIT malformed 的该
        //    子情形 → InvalidDefaultPage）。
        if let Some(default) = &default_page
            && !pages.iter().any(|page| page.page_id() == default)
        {
            return Err(WebDeclarationError::InvalidDefaultPage {
                detail: format!("default-page {default} is not declared in pages"),
            });
        }
        Ok(AppDeclaration {
            entry,
            features,
            display_name,
            permissions,
            pages,
            routes,
            default_page,
        })
    }

    /// 入口资产路径（语义继承 0.1.0 web-descriptor.entry）。
    pub fn entry(&self) -> &AssetPath {
        &self.entry
    }

    /// 本 Component 声明的 Web 能力集合。
    pub const fn features(&self) -> AppFeatures {
        self.features
    }

    /// 挂载命名空间下的展示名（可选，作者声明；语义继承 0.1）。
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// 权限声明集合（页面 / route 的 required-permission 引用点）。
    pub fn permissions(&self) -> &[PermissionDeclaration] {
        &self.permissions
    }

    /// 页面声明（导航语义：Core 据此构建页面列表与导航）。
    pub fn pages(&self) -> &[PageDeclaration] {
        &self.pages
    }

    /// typed route / action 声明（route namespace 注册面）。
    pub fn routes(&self) -> &[RouteDeclaration] {
        &self.routes
    }

    /// 默认页（导航语义：Core 对挂载点根路径解析到该页）。
    pub fn default_page(&self) -> Option<&PageId> {
        self.default_page.as_ref()
    }
}

impl<'de> Deserialize<'de> for AppDeclaration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            entry: AssetPath,
            features: AppFeatures,
            display_name: Option<String>,
            permissions: Vec<PermissionDeclaration>,
            pages: Vec<PageDeclaration>,
            routes: Vec<RouteDeclaration>,
            default_page: Option<PageId>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.entry,
            wire.features,
            wire.display_name,
            wire.permissions,
            wire.pages,
            wire.routes,
            wire.default_page,
        )
        .map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// 声明期冲突诊断（WIT `app-descriptor-error` 的 domain 闭集）
// ---------------------------------------------------------------------------

/// 声明期冲突诊断（WIT `app-descriptor-error` enum 的 domain 闭集，§42.2
/// conflict diagnostics）。
///
/// 对齐说明：本闭集覆盖 WIT 九变体中 Domain 可产生的七个——
/// - `route-id-conflict` → [`WebDeclarationError::RouteIdConflict`]；
/// - `page-id-conflict` → [`WebDeclarationError::PageIdConflict`]；
/// - `path-conflict` → [`WebDeclarationError::PathConflict`]（同方法 route
///   模板冲突与 page 路径 / GET route 模板冲突，歧义路由）；
/// - `invalid-path-template` → [`WebDeclarationError::InvalidPathTemplate`]；
/// - `param-mismatch` → [`WebDeclarationError::ParamMismatch`]；
/// - `invalid-permission` → [`WebDeclarationError::InvalidPermission`]；
/// - `malformed` 的 "default-page 未声明" 子情形 →
///   [`WebDeclarationError::InvalidDefaultPage`]（domain 对 WIT `malformed`
///   该子情形的细化）。
///
/// 其余两个 WIT 变体是宿主侧语义，不由 Domain 产生：`malformed`（其余
/// 情形，如空 entry、features flag 与声明不一致）与
/// `unsupported-contract-version` 是 Core 侧 contract violation /
/// 平台演进检查；`internal` 是 guest 侧不可恢复错误的防御性变体。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WebDeclarationError {
    /// 同一 route-id 被重复声明（route namespace 冲突）。
    #[error("route-id conflict: route-id {route_id} is declared more than once")]
    RouteIdConflict {
        /// 重复声明的 route-id。
        route_id: RouteId,
    },

    /// 同一 page-id 被重复声明。
    #[error("page-id conflict: page-id {page_id} is declared more than once")]
    PageIdConflict {
        /// 重复声明的 page-id。
        page_id: PageId,
    },

    /// 路径冲突：同方法下两条 route 的规范化路径模板冲突，或 page 路径与
    /// route 路径模板冲突（歧义路由）。
    #[error("path conflict for {method} {template}: {first} conflicts with {second}")]
    PathConflict {
        /// 冲突的 HTTP 方法（page-route 冲突固定为 get）。
        method: HttpMethod,
        /// 冲突的路径模板（规范化）。
        template: PathTemplate,
        /// 冲突第一方（route / page）。
        first: PathConflictParty,
        /// 冲突第二方（route）。
        second: PathConflictParty,
    },

    /// 路径模板非法（未以 "/" 开头、含 ".." 段、模板段语法错误等）。
    #[error("invalid path template: {detail}")]
    InvalidPathTemplate {
        /// 可诊断原因。
        detail: String,
    },

    /// 声明参数与路径模板不一致（模板引用未声明参数，或声明了模板中不
    /// 存在的参数）。
    #[error("param mismatch in route {route_id}: {detail}")]
    ParamMismatch {
        /// 声明不一致的 route-id。
        route_id: RouteId,
        /// 可诊断原因。
        detail: String,
    },

    /// required-permission 引用了未声明的 permission-name（或权限名重复
    /// 声明——WIT "同一 app descriptor 内唯一" 不变量的 domain 表达）。
    #[error("invalid permission: {detail}")]
    InvalidPermission {
        /// 可诊断原因。
        detail: String,
    },

    /// default-page 引用未声明的 page-id（WIT `malformed` 的该子情形）。
    #[error("invalid default page: {detail}")]
    InvalidDefaultPage {
        /// 可诊断原因。
        detail: String,
    },
}

impl WebDeclarationError {
    /// 便捷构造 [`WebDeclarationError::InvalidPathTemplate`]（模块内部）。
    fn invalid_template(detail: impl Into<String>) -> Self {
        Self::InvalidPathTemplate {
            detail: detail.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 共用校验
// ---------------------------------------------------------------------------

/// 挂载命名空间路径共用的结构性校验（[`PagePath`] / [`AssetPath`] / 0.5.0
/// [`FileSystemPath`](crate::FileSystemPath)）：
/// 非空、以 "/" 开头、已规范化（无空段 / "." / ".." 段；拒绝而不是归一化
/// 输入，fail closed，§32）、无反斜杠 / 控制字符、长度 ≤ `MAX_PATH_LEN`
/// 字节。
///
/// `forbid_templates` 为 true 时额外拒绝任何含 '{' / '}' 的段（页面路径是
/// 静态路径，无模板段）。
pub(crate) fn validate_mount_path(
    value: &str,
    forbid_templates: bool,
    kind: ValueKind,
) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::invalid_value(kind, "must not be empty"));
    }
    if value.len() > MAX_PATH_LEN {
        return Err(DomainError::invalid_value(
            kind,
            format!("must not exceed {MAX_PATH_LEN} bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(DomainError::invalid_value(
            kind,
            "must not contain control characters",
        ));
    }
    if value.contains('\\') {
        return Err(DomainError::invalid_value(
            kind,
            "backslash is not a valid path separator; use '/'",
        ));
    }
    if !value.starts_with('/') {
        return Err(DomainError::invalid_value(
            kind,
            "must start with '/' (mount-namespace path)",
        ));
    }
    // 段级检查：首个空段来自前导 '/'，其后不允许任何空段、'.' / '..' 段
    // 与（可选）模板段。
    for segment in value.split('/').skip(1) {
        if segment.is_empty() {
            return Err(DomainError::invalid_value(
                kind,
                "must not contain empty segments (e.g. '//' or trailing '/')",
            ));
        }
        if segment == "." || segment == ".." {
            return Err(DomainError::invalid_value(
                kind,
                format!("path segment {segment:?} is not allowed (directory traversal)"),
            ));
        }
        if forbid_templates && (segment.contains('{') || segment.contains('}')) {
            return Err(DomainError::invalid_value(
                kind,
                format!("path segment {segment:?} must not be a template segment ('{{...}}')"),
            ));
        }
    }
    Ok(())
}

/// 参数名共用的结构性校验（`[a-z0-9-]+`，≤ `MAX_IDENTIFIER_LEN` 字节）。
///
/// 与 WIT `path-template` 的 "{name}" 语法逐字一致（routes.wit 明文：
/// name 为小写字母 / 数字 / "-" 组成的标识符），`route-param.name` 与
/// `typed-param.name` 共用。返回 `None` 表示合法；否则返回可诊断原因。
fn param_name_error(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("parameter name must not be empty".to_string());
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Some(format!(
            "parameter name must not exceed {MAX_IDENTIFIER_LEN} bytes"
        ));
    }
    let all_allowed = value
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'));
    if !all_allowed {
        return Some(format!(
            "parameter name {value:?} must only contain lowercase ASCII letters, digits, or '-' ([a-z0-9-])"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    // ---- 测试助手 ----

    fn page_id(value: &str) -> PageId {
        ok(PageId::new(value), "page-id")
    }

    fn route_id(value: &str) -> RouteId {
        ok(RouteId::new(value), "route-id")
    }

    fn perm_name(value: &str) -> PermissionName {
        ok(PermissionName::new(value), "permission-name")
    }

    fn page_path(value: &str) -> PagePath {
        ok(PagePath::new(value), "page-path")
    }

    fn template(value: &str) -> PathTemplate {
        ok(PathTemplate::new(value), "path-template")
    }

    fn asset(value: &str) -> AssetPath {
        ok(AssetPath::new(value), "asset-path")
    }

    fn param(name: &str, value_type: ParamType) -> RouteParam {
        ok(RouteParam::new(name, value_type), "route-param")
    }

    fn permission(name: &str) -> PermissionDeclaration {
        PermissionDeclaration::new(perm_name(name), None)
    }

    fn page(id: &str, path: &str) -> PageDeclaration {
        PageDeclaration::new(page_id(id), page_path(path), None, None)
    }

    fn page_with_permission(id: &str, path: &str, permission: &str) -> PageDeclaration {
        PageDeclaration::new(
            page_id(id),
            page_path(path),
            None,
            Some(perm_name(permission)),
        )
    }

    fn route(
        id: &str,
        method: HttpMethod,
        path: &str,
        params: Vec<RouteParam>,
    ) -> RouteDeclaration {
        ok(
            RouteDeclaration::new(route_id(id), method, template(path), params, None),
            "route-declaration",
        )
    }

    fn route_with_permission(
        id: &str,
        method: HttpMethod,
        path: &str,
        params: Vec<RouteParam>,
        permission: &str,
    ) -> RouteDeclaration {
        ok(
            RouteDeclaration::new(
                route_id(id),
                method,
                template(path),
                params,
                Some(perm_name(permission)),
            ),
            "route-declaration",
        )
    }

    fn app(
        permissions: Vec<PermissionDeclaration>,
        pages: Vec<PageDeclaration>,
        routes: Vec<RouteDeclaration>,
        default_page: Option<&str>,
    ) -> Result<AppDeclaration, WebDeclarationError> {
        AppDeclaration::new(
            asset("/index.html"),
            AppFeatures::new(true, true, true, true, true),
            None,
            permissions,
            pages,
            routes,
            default_page.map(page_id),
        )
    }

    // ---- PageId ----

    #[test]
    fn page_id_accepts_valid() {
        for id in ["home", "checkout-page", "组件-页", "a", "A", "0"] {
            assert!(PageId::new(id).is_ok(), "{id:?} must be accepted");
        }
        // 恰好 255 字节：边界内合法。
        let max_len = "x".repeat(MAX_IDENTIFIER_LEN);
        assert_eq!(
            PageId::new(max_len.clone()).map(|id| id.as_str().len()),
            Ok(MAX_IDENTIFIER_LEN)
        );
    }

    #[test]
    fn page_id_rejects_invalid() {
        for bad in [
            "",
            &"x".repeat(MAX_IDENTIFIER_LEN + 1),
            "a\nb",
            "a\tb",
            "a\u{0}b",
        ] {
            assert!(
                matches!(
                    PageId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PageId,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn page_id_display_fromstr_serde_roundtrip() {
        let id = page_id("home");
        assert_eq!(id.to_string(), "home");
        assert_eq!("home".parse::<PageId>(), Ok(id.clone()));
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "\"home\"");
        assert_eq!(ok(serde_json::from_str::<PageId>(&json), "deserialize"), id);
        assert!(serde_json::from_str::<PageId>("\"\"").is_err());
    }

    // ---- PagePath ----

    #[test]
    fn page_path_accepts_valid_paths() {
        for path in [
            "/a",
            "/a/b",
            "/a/b-c",
            "/数据/表",
            "/dir/with space",
            "/a/0",
        ] {
            let parsed = ok(PagePath::new(path), path);
            assert_eq!(parsed.as_str(), path, "{path:?} must be accepted unchanged");
        }
        let max_len = format!("/{}", "a".repeat(MAX_PATH_LEN - 2));
        assert!(PagePath::new(max_len).is_ok());
    }

    #[test]
    fn page_path_rejects_invalid_paths() {
        for path in [
            "", "a", "a/b", "/", "/a/", "/a//b", "/a/../b", "/../a", "/a/./b", "/..", "/a\\b",
            "/a\nb", "/a\u{0}b", "/a/{id}", "/{id}", "/a{x}", "/a/b}",
        ] {
            assert!(
                matches!(
                    PagePath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PagePath,
                        ..
                    })
                ),
                "{path:?} must be rejected"
            );
        }
        let too_long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(PagePath::new(too_long).is_err());
    }

    #[test]
    fn page_path_serde_roundtrip() {
        let path = page_path("/a/b");
        let json = ok(serde_json::to_string(&path), "serialize");
        assert_eq!(json, "\"/a/b\"");
        assert_eq!(
            ok(serde_json::from_str::<PagePath>(&json), "deserialize"),
            path
        );
        // 反序列化边界同样执行校验（§13.3）。
        assert!(serde_json::from_str::<PagePath>("\"/a/../b\"").is_err());
    }

    // ---- AssetPath ----

    #[test]
    fn asset_path_accepts_valid_paths() {
        for path in ["/index.html", "/assets/icon.svg", "/a/b", "/a/{x}"] {
            assert!(
                AssetPath::new(path).is_ok(),
                "{path:?} must be accepted (assets allow template segment characters)"
            );
        }
        // 模板段字符允许（与 PagePath 的区别）："/a/{x}" 是合法资产路径。
        assert_eq!(asset("/a/{x}").as_str(), "/a/{x}");
    }

    #[test]
    fn asset_path_rejects_invalid_paths() {
        for path in [
            "", "a", "/", "/a/", "/a//b", "/a/../b", "/../a", "/a/./b", "/a\\b", "/a\nb",
        ] {
            assert!(
                matches!(
                    AssetPath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::AssetPath,
                        ..
                    })
                ),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn asset_path_serde_roundtrip() {
        let path = asset("/index.html");
        let json = ok(serde_json::to_string(&path), "serialize");
        assert_eq!(json, "\"/index.html\"");
        assert_eq!(
            ok(serde_json::from_str::<AssetPath>(&json), "deserialize"),
            path
        );
    }

    // ---- PageDeclaration ----

    #[test]
    fn page_declaration_fields_and_serde() {
        let plain = PageDeclaration::new(page_id("home"), page_path("/home"), None, None);
        assert_eq!(plain.page_id(), &page_id("home"));
        assert_eq!(plain.path(), &page_path("/home"));
        assert_eq!(plain.display_name(), None);
        assert_eq!(plain.required_permission(), None);

        let with_options = PageDeclaration::new(
            page_id("home"),
            page_path("/home"),
            Some("Home".to_string()),
            Some(perm_name("view")),
        );
        assert_eq!(with_options.display_name(), Some("Home"));
        assert_eq!(with_options.required_permission(), Some(&perm_name("view")));

        let json = ok(serde_json::to_string(&with_options), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<PageDeclaration>(&json),
                "deserialize"
            ),
            with_options
        );
    }

    // ---- PermissionName / PermissionDeclaration ----

    #[test]
    fn permission_name_valid_and_rejects() {
        for name in ["view", "admin", "can-approve", "组件-权限", "A", "0", "."] {
            assert!(
                PermissionName::new(name).is_ok(),
                "{name:?} must be accepted"
            );
        }
        for bad in ["", &"x".repeat(MAX_IDENTIFIER_LEN + 1), "a\nb", "a\u{0}b"] {
            assert!(
                matches!(
                    PermissionName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PermissionName,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn permission_name_serde_roundtrip() {
        let name = perm_name("view");
        let json = ok(serde_json::to_string(&name), "serialize");
        assert_eq!(json, "\"view\"");
        assert_eq!(
            ok(serde_json::from_str::<PermissionName>(&json), "deserialize"),
            name
        );
        assert_eq!("view".parse::<PermissionName>(), Ok(name.clone()));
    }

    #[test]
    fn permission_declaration_fields_and_serde() {
        let declared =
            PermissionDeclaration::new(perm_name("view"), Some("可以查看该页面".to_string()));
        assert_eq!(declared.name(), &perm_name("view"));
        assert_eq!(declared.description(), Some("可以查看该页面"));
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<PermissionDeclaration>(&json),
                "deserialize"
            ),
            declared
        );
    }

    // ---- RouteId ----

    #[test]
    fn route_id_valid_and_rejects() {
        for id in ["run-check", "api/items", "组件-route", "A", "0"] {
            assert!(RouteId::new(id).is_ok(), "{id:?} must be accepted");
        }
        for bad in ["", &"x".repeat(MAX_IDENTIFIER_LEN + 1), "a\nb", "a\u{0}b"] {
            assert!(
                matches!(
                    RouteId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::RouteId,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
        let id = route_id("run-check");
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<RouteId>(&json), "deserialize"),
            id
        );
    }

    // ---- HttpMethod ----

    #[test]
    fn http_method_closed_set() {
        for (method, name) in [
            (HttpMethod::Get, "get"),
            (HttpMethod::Post, "post"),
            (HttpMethod::Put, "put"),
            (HttpMethod::Patch, "patch"),
            (HttpMethod::Delete, "delete"),
        ] {
            assert_eq!(name.parse::<HttpMethod>(), Ok(method));
            assert_eq!(method.to_string(), name);
            let json = ok(serde_json::to_string(&method), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<HttpMethod>(&json), "deserialize"),
                method
            );
        }
    }

    #[test]
    fn http_method_rejects_non_closed() {
        // HEAD / OPTIONS 不可声明（Core bridge 自动处理）；CONNECT / TRACE
        // 一律不支持（routes.wit 明文）。
        for bad in [
            "head", "options", "GET", "Post", "", "connect", "trace", "get ",
        ] {
            assert!(
                matches!(
                    bad.parse::<HttpMethod>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::HttpMethod,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
        assert!(serde_json::from_str::<HttpMethod>("\"head\"").is_err());
    }

    // ---- ParamType ----

    #[test]
    fn param_type_closed_set() {
        for (value_type, name) in [
            (ParamType::Text, "text"),
            (ParamType::Integer, "integer"),
            (ParamType::Unsigned, "unsigned"),
            (ParamType::Boolean, "boolean"),
            (ParamType::Decimal, "decimal"),
        ] {
            assert_eq!(name.parse::<ParamType>(), Ok(value_type));
            assert_eq!(value_type.to_string(), name);
            let json = ok(serde_json::to_string(&value_type), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<ParamType>(&json), "deserialize"),
                value_type
            );
        }
    }

    #[test]
    fn param_type_rejects_non_closed() {
        for bad in ["string", "float", "", "TEXT", "integer ", "int"] {
            assert!(
                matches!(
                    bad.parse::<ParamType>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ParamType,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
        assert!(serde_json::from_str::<ParamType>("\"string\"").is_err());
    }

    // ---- PathTemplate ----

    #[test]
    fn path_template_accepts_valid_templates() {
        for path in [
            "/a",
            "/a/b",
            "/{id}",
            "/a/{id}/b",
            "/{a-b}",
            "/{0}",
            "/{-}",
            "/a/{x}/c",
            "/a/b-2",
        ] {
            assert!(
                PathTemplate::new(path).is_ok(),
                "{path:?} must be accepted (literal segments and [a-z0-9-] parameter names)"
            );
        }
        let max_len = format!("/{}", "a".repeat(MAX_PATH_LEN - 2));
        assert!(PathTemplate::new(max_len).is_ok());
    }

    #[test]
    fn path_template_segment_classification() {
        let parsed = template("/a/{id}/b/{x-y}");
        assert_eq!(
            parsed.segments(),
            &[
                PathSegment::Literal("a".to_string()),
                PathSegment::Param("id".to_string()),
                PathSegment::Literal("b".to_string()),
                PathSegment::Param("x-y".to_string()),
            ]
        );
        assert_eq!(parsed.param_names(), vec!["id", "x-y"]);
        // 纯字面模板：无参数。
        assert!(template("/a/b").param_names().is_empty());
    }

    #[test]
    fn path_template_rejects_structural_errors() {
        for path in [
            "", "a", "a/b", "/", "/a/", "/a//b", "/a/../b", "/../a", "/a/./b", "/a\\b", "/a\nb",
            "/a\u{0}b",
        ] {
            assert!(
                matches!(
                    PathTemplate::new(path),
                    Err(WebDeclarationError::InvalidPathTemplate { .. })
                ),
                "{path:?} must be rejected (structural)"
            );
        }
        let too_long = format!("/{}", "a".repeat(MAX_PATH_LEN));
        assert!(matches!(
            PathTemplate::new(too_long),
            Err(WebDeclarationError::InvalidPathTemplate { .. })
        ));
    }

    #[test]
    fn path_template_rejects_malformed_template_segments() {
        for path in [
            "/{id}/{id}", // 同一路径内模板段重复
            "/{ID}",      // 大写不在 [a-z0-9-]
            "/{id_x}",    // 下划线不在 [a-z0-9-]
            "/{x y}",     // 空白不在 [a-z0-9-]
            "/{id",       // 未闭合
            "/id}",       // 游离 '}'
            "/a{x}",      // 字面段含 '{'
            "/{x}y",      // 模板段后跟内容
            "/{}",        // 空参数名
            "/{{x}}",     // 嵌套花括号
            "/{x}{y}",    // 两个模板段粘连
        ] {
            assert!(
                matches!(
                    PathTemplate::new(path),
                    Err(WebDeclarationError::InvalidPathTemplate { .. })
                ),
                "{path:?} must be rejected (template syntax)"
            );
        }
    }

    #[test]
    fn path_template_serde_roundtrip() {
        let parsed = template("/a/{id}/b");
        let json = ok(serde_json::to_string(&parsed), "serialize");
        assert_eq!(json, "\"/a/{id}/b\"");
        assert_eq!(
            ok(serde_json::from_str::<PathTemplate>(&json), "deserialize"),
            parsed
        );
        // 反序列化边界同样执行模板语法校验（§13.3）。
        assert!(serde_json::from_str::<PathTemplate>("\"/{ID}\"").is_err());
    }

    #[test]
    fn page_path_converts_to_literal_template() {
        // 页面路径 → 纯字面模板（page 路径与 route 模板冲突判定的输入）。
        let page = page_path("/a/b");
        let converted = PathTemplate::from(&page);
        assert_eq!(converted.as_str(), "/a/b");
        assert!(PathConflict::detect(&converted, &template("/a/{x}")));
        assert!(!PathConflict::detect(&converted, &template("/a/b/c")));
    }

    // ---- PathConflict ----

    #[test]
    fn path_conflict_detect_pairs() {
        let pairs: &[(&str, &str, bool)] = &[
            // 字面段冲突：同位置相同字面段。
            ("/a/b", "/a/b", true),
            ("/a/b", "/a/c", false),
            ("/a/b", "/c/d", false),
            // 参数位置冲突：同位置至少一侧是参数段。
            ("/a/{x}", "/a/b", true),
            ("/a/{x}", "/a/{y}", true),
            ("/a/{x}", "/{y}/b", true),
            ("/{x}", "/a", true),
            ("/a/{x}/c", "/a/{y}/c", true),
            // 段数不同：永不冲突。
            ("/a/{x}", "/a/b/c", false),
            // 参数位置对应不同字面段：段数相同但该位置两侧都是不同字面段
            // → 不冲突。
            ("/a/{x}/c", "/a/b/d", false),
            // 参数 + 字面混合。
            ("/a/{x}/c", "/a/b/c", true),
            ("/a/b/c", "/a/{x}/c", true),
        ];
        for (first, second, expected) in pairs {
            let a = template(first);
            let b = template(second);
            assert_eq!(
                PathConflict::detect(&a, &b),
                *expected,
                "detect({first}, {second})"
            );
        }
    }

    #[test]
    fn path_conflict_is_reflexive() {
        // 任意模板与自身冲突（歧义路由：任何匹配自身的请求都同时匹配
        // 两者）。
        for path in ["/a/b", "/{x}/c", "/a/{y}/b"] {
            let parsed = template(path);
            assert!(
                PathConflict::detect(&parsed, &parsed),
                "{path} must conflict with itself"
            );
        }
    }

    // ---- RouteParam ----

    #[test]
    fn route_param_valid_and_rejects() {
        let declared = ok(RouteParam::new("id", ParamType::Integer), "route-param");
        assert_eq!(declared.name(), "id");
        assert_eq!(declared.value_type(), ParamType::Integer);
        for name in ["id", "a-b", "0", "user-id"] {
            assert!(RouteParam::new(name, ParamType::Text).is_ok(), "{name:?}");
        }
        for bad in [
            "",
            "Id",
            "id_x",
            "id name",
            &"x".repeat(MAX_IDENTIFIER_LEN + 1),
        ] {
            assert!(
                matches!(
                    RouteParam::new(bad, ParamType::Text),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::RouteParam,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn route_param_serde_roundtrip() {
        let declared = param("id", ParamType::Unsigned);
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<RouteParam>(&json), "deserialize"),
            declared
        );
        // 反序列化边界同样校验名称字符集。
        assert!(
            serde_json::from_str::<RouteParam>(r#"{"name": "Id", "value_type": "text"}"#).is_err()
        );
    }

    // ---- RouteDeclaration ----

    #[test]
    fn route_declaration_accepts_consistent() {
        let declared = ok(
            RouteDeclaration::new(
                route_id("get-item"),
                HttpMethod::Get,
                template("/api/{id}"),
                vec![param("id", ParamType::Integer)],
                Some(perm_name("view")),
            ),
            "route-declaration",
        );
        assert_eq!(declared.route_id(), &route_id("get-item"));
        assert_eq!(declared.method(), HttpMethod::Get);
        assert_eq!(declared.path().as_str(), "/api/{id}");
        assert_eq!(declared.params().len(), 1);
        assert_eq!(declared.required_permission(), Some(&perm_name("view")));

        // 纯字面模板 + 无参数：一致。
        assert!(
            RouteDeclaration::new(
                route_id("about"),
                HttpMethod::Get,
                template("/about"),
                vec![],
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn route_declaration_param_mismatch() {
        // 模板引用未声明参数。
        let missing = RouteDeclaration::new(
            route_id("r1"),
            HttpMethod::Get,
            template("/a/{id}"),
            vec![],
            None,
        );
        assert!(matches!(
            missing,
            Err(WebDeclarationError::ParamMismatch {
                route_id: id,
                detail
            }) if id == route_id("r1") && detail.contains("template parameter \"id\"")
        ));

        // 声明了模板中不存在的参数。
        let extra = RouteDeclaration::new(
            route_id("r2"),
            HttpMethod::Get,
            template("/a"),
            vec![param("extra", ParamType::Text)],
            None,
        );
        assert!(matches!(
            extra,
            Err(WebDeclarationError::ParamMismatch { route_id: id, .. }) if id == route_id("r2")
        ));

        // 参数名重复。
        let duplicate = RouteDeclaration::new(
            route_id("r3"),
            HttpMethod::Get,
            template("/a/{id}"),
            vec![
                param("id", ParamType::Integer),
                param("id", ParamType::Text),
            ],
            None,
        );
        assert!(matches!(
            duplicate,
            Err(WebDeclarationError::ParamMismatch { route_id: id, .. }) if id == route_id("r3")
        ));
    }

    #[test]
    fn route_declaration_serde_roundtrip() {
        let declared = route(
            "get-item",
            HttpMethod::Get,
            "/api/{id}",
            vec![param("id", ParamType::Integer)],
        );
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<RouteDeclaration>(&json),
                "deserialize"
            ),
            declared
        );
        // 反序列化边界同样执行模板/参数一致性校验（§13.3）。
        let mismatched = r#"{
            "route_id": "r1",
            "method": "get",
            "path": "/a/{id}",
            "params": [],
            "required_permission": null
        }"#;
        let err = serde_json::from_str::<RouteDeclaration>(mismatched);
        assert!(
            err.is_err(),
            "params missing template parameter must be rejected"
        );
    }

    // ---- ParamValue / TypedParam ----

    #[test]
    fn param_value_variants_and_type_mapping() {
        let values = [
            ParamValue::text("hello"),
            ParamValue::integer(-42),
            ParamValue::unsigned(42),
            ParamValue::boolean(true),
            ParamValue::decimal(1.5),
        ];
        let expected_types = [
            ParamType::Text,
            ParamType::Integer,
            ParamType::Unsigned,
            ParamType::Boolean,
            ParamType::Decimal,
        ];
        for (value, expected) in values.iter().zip(expected_types) {
            assert_eq!(
                value.param_type(),
                expected,
                "one-to-one param-type mapping"
            );
        }
        assert_eq!(ParamValue::text("hello").as_text(), Some("hello"));
        assert_eq!(ParamValue::integer(-42).as_integer(), Some(-42));
        assert_eq!(ParamValue::unsigned(42).as_unsigned(), Some(42));
        assert_eq!(ParamValue::boolean(true).as_boolean(), Some(true));
        assert_eq!(ParamValue::decimal(1.5).as_decimal(), Some(1.5));
        // 变体不符 → None。
        assert_eq!(ParamValue::text("x").as_integer(), None);
        assert_eq!(ParamValue::integer(1).as_boolean(), None);
    }

    #[test]
    fn param_value_overflow_rejected() {
        // i128 → Integer：i64 范围内合法，超出溢出拒绝。
        assert_eq!(
            ok(ParamValue::try_from(i64::MIN as i128), "integer min"),
            ParamValue::Integer(i64::MIN)
        );
        assert_eq!(
            ok(ParamValue::try_from(i64::MAX as i128), "integer max"),
            ParamValue::Integer(i64::MAX)
        );
        let overflow = i64::MAX as i128 + 1;
        assert!(
            matches!(
                ParamValue::try_from(overflow),
                Err(DomainError::InvalidValue {
                    kind: ValueKind::ParamValue,
                    ..
                })
            ),
            "integer value beyond i64 must be rejected (overflow)"
        );
        // u128 → Unsigned：u64 范围内合法，超出溢出拒绝。
        assert_eq!(
            ok(ParamValue::try_from(u64::MAX as u128), "unsigned max"),
            ParamValue::Unsigned(u64::MAX)
        );
        let overflow_unsigned = u64::MAX as u128 + 1;
        assert!(
            matches!(
                ParamValue::try_from(overflow_unsigned),
                Err(DomainError::InvalidValue {
                    kind: ValueKind::ParamValue,
                    ..
                })
            ),
            "unsigned value beyond u64 must be rejected (overflow)"
        );
        // boolean 是闭集 {true, false}。
        assert_eq!(ParamValue::boolean(false), ParamValue::Boolean(false));
        assert_eq!(ParamValue::boolean(true), ParamValue::Boolean(true));
    }

    #[test]
    fn param_value_serde_roundtrip() {
        for (value, json) in [
            (ParamValue::text("x"), r#"{"text":"x"}"#),
            (ParamValue::integer(-5), r#"{"integer":-5}"#),
            (ParamValue::unsigned(5), r#"{"unsigned":5}"#),
            (ParamValue::boolean(true), r#"{"boolean":true}"#),
            (ParamValue::decimal(1.5), r#"{"decimal":1.5}"#),
        ] {
            let serialized = ok(serde_json::to_string(&value), "serialize");
            assert_eq!(serialized, json);
            assert_eq!(
                ok(serde_json::from_str::<ParamValue>(json), "deserialize"),
                value
            );
        }
    }

    #[test]
    fn typed_param_valid_and_rejects() {
        let declared = ok(TypedParam::new("id", ParamValue::integer(7)), "typed-param");
        assert_eq!(declared.name(), "id");
        assert_eq!(declared.value(), &ParamValue::integer(7));
        for bad in ["", "Id", "id_x", "id name"] {
            assert!(
                matches!(
                    TypedParam::new(bad, ParamValue::text("x")),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::TypedParam,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<TypedParam>(&json), "deserialize"),
            declared
        );
        // 反序列化边界同样校验名称字符集。
        assert!(
            serde_json::from_str::<TypedParam>(r#"{"name": "Id", "value": {"integer": 1}}"#)
                .is_err()
        );
    }

    // ---- AppFeatures ----

    #[test]
    fn app_features_flags() {
        let all = AppFeatures::new(true, true, true, true, true);
        assert!(all.static_assets());
        assert!(all.backend_actions());
        assert!(all.navigation());
        assert!(all.typed_routes());
        assert!(all.permissions());

        let none = AppFeatures::default();
        assert!(!none.static_assets());
        assert!(!none.backend_actions());
        assert!(!none.navigation());
        assert!(!none.typed_routes());
        assert!(!none.permissions());

        // 兼容路径：仅 static-assets / backend-actions 的 0.2.0 组件与
        // 0.1 组件行为等价（app-descriptor.wit 明文）。
        let legacy = AppFeatures::new(true, true, false, false, false);
        assert!(legacy.static_assets() && legacy.backend_actions());
        assert!(!legacy.navigation() && !legacy.typed_routes() && !legacy.permissions());

        let json = ok(serde_json::to_string(&all), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<AppFeatures>(&json), "deserialize"),
            all
        );
    }

    // ---- AppDeclaration ----

    #[test]
    fn app_declaration_accepts_valid_descriptor() {
        let declared = ok(
            app(
                vec![permission("view")],
                vec![
                    page("home", "/home"),
                    page_with_permission("about", "/about", "view"),
                ],
                vec![
                    route(
                        "get-item",
                        HttpMethod::Get,
                        "/api/{id}",
                        vec![param("id", ParamType::Integer)],
                    ),
                    route(
                        "create-item",
                        HttpMethod::Post,
                        "/api/{id}",
                        vec![param("id", ParamType::Integer)],
                    ),
                ],
                Some("home"),
            ),
            "app-declaration",
        );
        assert_eq!(declared.entry().as_str(), "/index.html");
        assert_eq!(
            declared.features(),
            AppFeatures::new(true, true, true, true, true)
        );
        assert_eq!(declared.display_name(), None);
        assert_eq!(declared.permissions().len(), 1);
        assert_eq!(declared.pages().len(), 2);
        assert_eq!(declared.routes().len(), 2);
        assert_eq!(declared.default_page(), Some(&page_id("home")));
    }

    #[test]
    fn app_declaration_duplicate_route_id() {
        let result = app(
            vec![],
            vec![],
            vec![
                route("dup", HttpMethod::Get, "/a", vec![]),
                route("dup", HttpMethod::Post, "/b", vec![]),
            ],
            None,
        );
        assert!(matches!(
            result,
            Err(WebDeclarationError::RouteIdConflict { route_id: id }) if id == route_id("dup")
        ));
    }

    #[test]
    fn app_declaration_duplicate_page_id() {
        let result = app(
            vec![],
            vec![page("home", "/home"), page("home", "/other")],
            vec![],
            None,
        );
        assert!(matches!(
            result,
            Err(WebDeclarationError::PageIdConflict { page_id: id }) if id == page_id("home")
        ));
    }

    #[test]
    fn app_declaration_default_page_not_declared() {
        let result = app(vec![], vec![page("home", "/home")], vec![], Some("missing"));
        assert!(matches!(
            result,
            Err(WebDeclarationError::InvalidDefaultPage { detail }) if detail.contains("missing")
        ));
        // default-page 引用已声明 page：合法。
        assert!(app(vec![], vec![page("home", "/home")], vec![], Some("home")).is_ok());
    }

    #[test]
    fn app_declaration_path_conflicts() {
        // 同方法字面段冲突。
        let literal = app(
            vec![],
            vec![],
            vec![
                route("r1", HttpMethod::Get, "/a/b", vec![]),
                route("r2", HttpMethod::Get, "/a/b", vec![]),
            ],
            None,
        );
        assert!(matches!(
            literal,
            Err(WebDeclarationError::PathConflict {
                method: HttpMethod::Get,
                first: PathConflictParty::Route(first),
                second: PathConflictParty::Route(second),
                ..
            }) if first == route_id("r1") && second == route_id("r2")
        ));

        // 同方法参数位置冲突。
        let param_position = app(
            vec![],
            vec![],
            vec![
                route(
                    "r1",
                    HttpMethod::Get,
                    "/a/{x}",
                    vec![param("x", ParamType::Text)],
                ),
                route("r2", HttpMethod::Get, "/a/b", vec![]),
            ],
            None,
        );
        assert!(matches!(
            param_position,
            Err(WebDeclarationError::PathConflict { .. })
        ));

        // page 路径与 GET route 模板冲突（歧义路由）。
        let page_vs_route = app(
            vec![],
            vec![page("home", "/home")],
            vec![route(
                "r1",
                HttpMethod::Get,
                "/{x}",
                vec![param("x", ParamType::Text)],
            )],
            None,
        );
        assert!(matches!(
            page_vs_route,
            Err(WebDeclarationError::PathConflict {
                method: HttpMethod::Get,
                first: PathConflictParty::Page(page),
                second: PathConflictParty::Route(route),
                ..
            }) if page == page_id("home") && route == route_id("r1")
        ));

        // page 路径与 GET route 规范化路径相同也冲突。
        let same_path = app(
            vec![],
            vec![page("home", "/home")],
            vec![route("r1", HttpMethod::Get, "/home", vec![])],
            None,
        );
        assert!(matches!(
            same_path,
            Err(WebDeclarationError::PathConflict { .. })
        ));
    }

    #[test]
    fn app_declaration_same_path_different_method_ok() {
        // 同 path 不同方法不冲突。
        let result = app(
            vec![],
            vec![],
            vec![
                route(
                    "r1",
                    HttpMethod::Get,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                ),
                route(
                    "r2",
                    HttpMethod::Post,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                ),
                route(
                    "r3",
                    HttpMethod::Delete,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                ),
                route(
                    "r4",
                    HttpMethod::Put,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                ),
                route(
                    "r5",
                    HttpMethod::Patch,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                ),
            ],
            None,
        );
        assert!(
            result.is_ok(),
            "same path template under different methods must not conflict"
        );

        // page 路径与 POST route 同路径不冲突（页面经 GET 导航）。
        let page_vs_post = app(
            vec![],
            vec![page("home", "/home")],
            vec![route("r1", HttpMethod::Post, "/home", vec![])],
            Some("home"),
        );
        assert!(page_vs_post.is_ok());
    }

    #[test]
    fn app_declaration_invalid_permission() {
        // required-permission 引用未声明的 permission-name。
        let page_ref = app(
            vec![],
            vec![page_with_permission("home", "/home", "view")],
            vec![],
            None,
        );
        assert!(matches!(
            page_ref,
            Err(WebDeclarationError::InvalidPermission { detail }) if detail.contains("view")
        ));

        let route_ref = app(
            vec![],
            vec![],
            vec![route_with_permission(
                "r1",
                HttpMethod::Get,
                "/a",
                vec![],
                "admin",
            )],
            None,
        );
        assert!(matches!(
            route_ref,
            Err(WebDeclarationError::InvalidPermission { .. })
        ));

        // 权限名重复声明（WIT：同一 app descriptor 内唯一）。
        let duplicate = app(
            vec![permission("view"), permission("view")],
            vec![],
            vec![],
            None,
        );
        assert!(matches!(
            duplicate,
            Err(WebDeclarationError::InvalidPermission { detail }) if detail.contains("view")
        ));

        // 声明的权限名被引用：合法。
        assert!(
            app(
                vec![permission("view")],
                vec![page_with_permission("home", "/home", "view")],
                vec![],
                Some("home"),
            )
            .is_ok()
        );
    }

    #[test]
    fn app_declaration_serde_roundtrip() {
        let declared = ok(
            app(
                vec![permission("view")],
                vec![
                    page("home", "/home"),
                    page_with_permission("about", "/about", "view"),
                ],
                vec![route(
                    "get-item",
                    HttpMethod::Get,
                    "/api/{id}",
                    vec![param("id", ParamType::Integer)],
                )],
                Some("home"),
            ),
            "app-declaration",
        );
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<AppDeclaration>(&json), "deserialize"),
            declared
        );
        // 反序列化边界同样执行组装期冲突诊断（§13.3）：重复 route-id 拒绝。
        let conflicting = r#"{
            "entry": "/index.html",
            "features": {
                "static_assets": true,
                "backend_actions": true,
                "navigation": true,
                "typed_routes": true,
                "permissions": true
            },
            "display_name": null,
            "permissions": [],
            "pages": [],
            "routes": [
                {
                    "route_id": "r1",
                    "method": "get",
                    "path": "/a",
                    "params": [],
                    "required_permission": null
                },
                {
                    "route_id": "r1",
                    "method": "post",
                    "path": "/b",
                    "params": [],
                    "required_permission": null
                }
            ],
            "default_page": null
        }"#;
        let err = serde_json::from_str::<AppDeclaration>(conflicting);
        assert!(
            err.is_err(),
            "descriptor with duplicate route-id must be rejected on deserialize"
        );
        let message = format!("{err:?}");
        assert!(message.contains("route-id conflict"), "{message}");
    }

    // ---- 性质测试 ----

    proptest! {
        #[test]
        fn path_template_parse_is_idempotent(s in ".*") {
            // 解析成功的模板再解析得到同一结果（§13.3 边界解析一次）。
            if let Ok(parsed) = PathTemplate::new(&s) {
                prop_assert_eq!(PathTemplate::new(parsed.as_str()), Ok(parsed.clone()));
            }
        }

        #[test]
        fn path_conflict_detect_is_symmetric(a in ".*", b in ".*") {
            // 冲突判定是对称关系。
            if let (Ok(first), Ok(second)) = (PathTemplate::new(&a), PathTemplate::new(&b)) {
                prop_assert_eq!(
                    PathConflict::detect(&first, &second),
                    PathConflict::detect(&second, &first)
                );
            }
        }
    }
}
