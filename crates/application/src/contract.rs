//! `operune:*@0.1.0` WIT 契约的镜像用例类型与 `wasmtime::component::Val`
//! 编解码（§13.3：边界解析一次；§19.3：guest 返回值有宿主侧体积上限）。
//!
//! 本模块是 [`crate::runtime`]（Safe Wasmtime Component API 调用面）与
//! 编排层之间的类型边界：guest 侧的 `Val` 在 wasm 边界被解析为这里的强类型
//! 值对象，编排层只消费强类型（见 [`crate::wit_bindings`] 的 §25 裁决说明：
//! bindgen 全量代码生成被 `forbid(unsafe_code)` 阻挡，typed 边界在此手工
//! 建模并与 WIT 契约逐字段对齐）。
//!
//! 契约对齐目标（WIT 权威版本）：
//! - `operune:component/descriptor`（`component-descriptor` /
//!   `descriptor-error`）；
//! - `operune:web/descriptor`（`web-descriptor` / `web-descriptor-error`）；
//! - `operune:web/assets`（`asset-metadata` / `assets-error`）；
//! - `operune:web/actions`（`action-request` / `action-payload` /
//!   `action-error`）。
//!
//! 全部解析按 **record 字段顺序**（canonical ABI 编码的是顺序而非名字），
//! 字段名同时校验（与 WIT 契约不一致视为 contract violation）。

use std::fmt;

use wasmtime::component::Val;

/// 解析边界上的宿主体积上限（§19.3 / §21.3：guest 返回值有宿主侧硬上限）。
pub(crate) const MAX_COMPONENT_ID_LEN: usize = 255;
/// 展示性字符串（display-name / author / description）上限。
pub(crate) const MAX_DISPLAY_TEXT_LEN: usize = 2048;
/// web asset 路径上限（对齐 WIT `asset-path` 契约长度约束）。
pub(crate) const MAX_WEB_ASSET_PATH_LEN: usize = 4096;
/// 单次 `list-assets` 清单的资产条目上限（§21.3 有界清单）。
pub(crate) const MAX_ASSET_LIST_LEN: usize = 1024;

/// guest 返回值的解析 / 形状错误（contract violation，§19.3 语义）。
///
/// 封闭 typed 错误（§14.1）：变体只表达契约违反类别，不携带 guest 数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractValueError {
    /// record 缺少契约字段（位置或名字不符）。
    MissingField(&'static str),
    /// 值形状与契约不符（字段 + 期望形状）。
    ShapeMismatch {
        /// 出错字段。
        field: &'static str,
        /// 期望形状描述。
        expected: &'static str,
    },
    /// guest 返回了契约外的 variant / enum 名字。
    InvalidVariant(String),
    /// 返回值超过宿主侧体积上限。
    ValueTooLarge {
        /// 超限字段。
        field: &'static str,
        /// 上限。
        limit: usize,
    },
}

impl fmt::Display for ContractValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "record is missing field `{field}`"),
            Self::ShapeMismatch { field, expected } => {
                write!(
                    f,
                    "field `{field}` has unexpected shape (expected {expected})"
                )
            }
            Self::InvalidVariant(name) => write!(f, "unknown variant or enum case `{name}`"),
            Self::ValueTooLarge { field, limit } => {
                write!(
                    f,
                    "field `{field}` exceeds the host-side limit of {limit} bytes"
                )
            }
        }
    }
}

impl std::error::Error for ContractValueError {}

// ---------------------------------------------------------------------------
// operune:component/descriptor 镜像类型
// ---------------------------------------------------------------------------

/// `component-descriptor` 镜像（§19.3：作者声明的逻辑身份与平台 metadata）。
///
/// 字段与 WIT `component-descriptor` record 一一对应；解析边界执行体积上限。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestComponentDescriptor {
    /// `component-id.value`（原始字符串；身份校验在编排层做）。
    pub(crate) component_id: String,
    /// `version.major`。
    pub(crate) major: u32,
    /// `version.minor`。
    pub(crate) minor: u32,
    /// `version.patch`。
    pub(crate) patch: u32,
    /// `display-name`。
    pub(crate) display_name: String,
    /// `author`（option）。
    pub(crate) author: Option<GuestAuthorInfo>,
}

/// `author-info` 镜像。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAuthorInfo {
    /// `display-name`。
    pub(crate) display_name: String,
    /// `homepage`（option；Core 只展示不解析不访问）。
    pub(crate) homepage: Option<String>,
    /// `description`（option）。
    pub(crate) description: Option<String>,
}

/// `descriptor-error` 镜像（guest 返回值空间的预期失败，§6.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestDescriptorError {
    /// `malformed`。
    Malformed,
    /// `unsupported-contract-version`。
    UnsupportedContractVersion,
    /// `internal`。
    Internal,
}

/// 把 `component-descriptor` 编成 guest 调用面的 `Val`（record 顺序对齐 WIT）。
#[cfg(test)]
pub(crate) fn build_component_descriptor_val(descriptor: &GuestComponentDescriptor) -> Val {
    let author = match &descriptor.author {
        Some(author) => Val::Option(Some(Box::new(Val::Record(vec![
            (
                "display-name".to_owned(),
                Val::String(author.display_name.clone()),
            ),
            ("homepage".to_owned(), opt_string(&author.homepage)),
            ("description".to_owned(), opt_string(&author.description)),
        ])))),
        None => Val::Option(None),
    };
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        (
            "component-id".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(descriptor.component_id.clone()),
            )]),
        ),
        (
            "version".to_owned(),
            Val::Record(vec![
                ("major".to_owned(), Val::U32(descriptor.major)),
                ("minor".to_owned(), Val::U32(descriptor.minor)),
                ("patch".to_owned(), Val::U32(descriptor.patch)),
            ]),
        ),
        (
            "display-name".to_owned(),
            Val::String(descriptor.display_name.clone()),
        ),
        ("author".to_owned(), author),
    ])))))
}

/// 把 `descriptor-error` 编成 guest 返回值空间的 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_descriptor_error_val(error: GuestDescriptorError) -> Val {
    let name = match error {
        GuestDescriptorError::Malformed => "malformed",
        GuestDescriptorError::UnsupportedContractVersion => "unsupported-contract-version",
        GuestDescriptorError::Internal => "internal",
    };
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

/// 解析 `get-descriptor` 的返回 `Val` 为镜像类型（§13.3 边界解析一次）。
pub(crate) fn parse_component_descriptor_val(
    val: &Val,
) -> Result<GuestComponentDescriptor, ContractValueError> {
    let inner = as_result_ok(val, "get-descriptor")?;
    let fields = as_record(inner, "component-descriptor")?;
    // `component-id` 是 record 包装（WIT §13.5：避免 string alias 误传）。
    let component_id_record = as_record(field(fields, 0, "component-id")?, "component-id")?;
    let component_id = string_field(component_id_record, 0, "value", MAX_COMPONENT_ID_LEN)?;
    let version = as_record(field(fields, 1, "version")?, "component-version")?;
    let major = u32_field(version, 0, "major")?;
    let minor = u32_field(version, 1, "minor")?;
    let patch = u32_field(version, 2, "patch")?;
    let display_name = string_field(fields, 2, "display-name", MAX_DISPLAY_TEXT_LEN)?;
    let author = option_field(fields, 3, "author")?;
    let author = match author {
        None => None,
        Some(record) => {
            let fields = as_record(&record, "author-info")?;
            let display_name = string_field(fields, 0, "display-name", MAX_DISPLAY_TEXT_LEN)?;
            let homepage = option_field(fields, 1, "homepage")?;
            let homepage = match homepage {
                None => None,
                Some(value) => Some(as_string(&value, "author-info.homepage")?.to_owned()),
            };
            let description = option_field(fields, 2, "description")?;
            let description = match description {
                None => None,
                Some(value) => Some(as_string(&value, "author-info.description")?.to_owned()),
            };
            Some(GuestAuthorInfo {
                display_name,
                homepage,
                description,
            })
        }
    };
    Ok(GuestComponentDescriptor {
        component_id,
        major,
        minor,
        patch,
        display_name,
        author,
    })
}

/// 解析 `descriptor-error` 载荷（result 的 Err 侧）。
#[cfg(test)]
pub(crate) fn parse_descriptor_error_val(
    val: &Val,
) -> Result<GuestDescriptorError, ContractValueError> {
    let payload = as_result_err(val, "get-descriptor")?;
    let name = as_enum(payload, "descriptor-error")?;
    match name {
        "malformed" => Ok(GuestDescriptorError::Malformed),
        "unsupported-contract-version" => Ok(GuestDescriptorError::UnsupportedContractVersion),
        "internal" => Ok(GuestDescriptorError::Internal),
        other => Err(ContractValueError::InvalidVariant(other.to_owned())),
    }
}

// ---------------------------------------------------------------------------
// operune:state/declaration 镜像类型（§41.2 声明面 / §20.5 迁移触发事实）
// ---------------------------------------------------------------------------

/// `state-declaration` 镜像（§41.2 声明面：Component 激活前向 Core 声明的
/// state 契约；upgrade 管线以 `schema-version` 与 store 当前版本比较，
/// 决定是否触发显式迁移，§20.5）。
///
/// 字段与 WIT `state-declaration` record 一一对应（name、schema-version）；
/// 解析边界执行体积上限（§19.3 精神，declaration.wit 明文）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestStateDeclaration {
    /// `name`（option；展示性名称，非身份事实，不参与兼容判断，§19.4）。
    pub(crate) name: Option<String>,
    /// `schema-version.value`（本 ComponentVersion 激活后读取/写入的
    /// state schema 版本；迁移触发事实，§20.5）。
    pub(crate) schema_version: u32,
}

/// `state-declaration-error` 镜像（guest 返回值空间的预期失败，§6.3）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestStateDeclarationError {
    /// `malformed`。
    Malformed,
    /// `unsupported-contract-version`。
    UnsupportedContractVersion,
    /// `internal`。
    Internal,
}

/// 解析 `get-state-declaration` 的返回 `Val` 为镜像类型（§13.3 边界解析
/// 一次；record 字段顺序对齐 WIT：name、schema-version）。
pub(crate) fn parse_state_declaration_val(
    val: &Val,
) -> Result<GuestStateDeclaration, ContractValueError> {
    let inner = as_result_ok(val, "get-state-declaration")?;
    let fields = as_record(inner, "state-declaration")?;
    let name = match option_field(fields, 0, "name")? {
        None => None,
        Some(value) => {
            let text = as_string(&value, "state-declaration.name")?;
            if text.len() > MAX_DISPLAY_TEXT_LEN {
                return Err(ContractValueError::ValueTooLarge {
                    field: "name",
                    limit: MAX_DISPLAY_TEXT_LEN,
                });
            }
            Some(text.to_owned())
        }
    };
    let schema_version = as_record(field(fields, 1, "schema-version")?, "state-schema-version")?;
    let value = u32_field(schema_version, 0, "value")?;
    Ok(GuestStateDeclaration {
        name,
        schema_version: value,
    })
}

/// 把 `state-declaration` 编成 guest 返回值空间的 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_state_declaration_val(declaration: &GuestStateDeclaration) -> Val {
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        ("name".to_owned(), opt_string(&declaration.name)),
        (
            "schema-version".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::U32(declaration.schema_version),
            )]),
        ),
    ])))))
}

/// 把 `state-declaration-error` 编成 guest 返回值空间的 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_state_declaration_error_val(error: GuestStateDeclarationError) -> Val {
    let name = match error {
        GuestStateDeclarationError::Malformed => "malformed",
        GuestStateDeclarationError::UnsupportedContractVersion => "unsupported-contract-version",
        GuestStateDeclarationError::Internal => "internal",
    };
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

/// 解析 `state-declaration-error` 载荷（result 的 Err 侧）。
#[cfg(test)]
pub(crate) fn parse_state_declaration_error_val(
    val: &Val,
) -> Result<GuestStateDeclarationError, ContractValueError> {
    let payload = as_result_err(val, "get-state-declaration")?;
    let name = as_enum(payload, "state-declaration-error")?;
    match name {
        "malformed" => Ok(GuestStateDeclarationError::Malformed),
        "unsupported-contract-version" => {
            Ok(GuestStateDeclarationError::UnsupportedContractVersion)
        }
        "internal" => Ok(GuestStateDeclarationError::Internal),
        other => Err(ContractValueError::InvalidVariant(other.to_owned())),
    }
}

// ---------------------------------------------------------------------------
// operune:web/descriptor 镜像类型
// ---------------------------------------------------------------------------

/// `web-descriptor` 镜像（§21.3：Web UI 能力声明）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestWebDescriptor {
    /// `entry.value`（WIT 契约：以 `/` 开头的规范化相对路径）。
    pub(crate) entry: String,
    /// `features`。
    pub(crate) features: GuestWebFeatures,
    /// `display-name`（option）。
    pub(crate) display_name: Option<String>,
}

/// `web-features` flags 镜像。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuestWebFeatures {
    /// `static-assets`。
    pub(crate) static_assets: bool,
    /// `backend-actions`。
    pub(crate) backend_actions: bool,
}

/// 把 `web-descriptor` 编成 guest 返回值空间的 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_web_descriptor_val(descriptor: &GuestWebDescriptor) -> Val {
    let mut flags = Vec::new();
    if descriptor.features.static_assets {
        flags.push("static-assets".to_owned());
    }
    if descriptor.features.backend_actions {
        flags.push("backend-actions".to_owned());
    }
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        (
            "entry".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(descriptor.entry.clone()),
            )]),
        ),
        ("features".to_owned(), Val::Flags(flags)),
        (
            "display-name".to_owned(),
            opt_string(&descriptor.display_name),
        ),
    ])))))
}

/// 解析 `get-web-descriptor` 的返回 `Val`。
pub(crate) fn parse_web_descriptor_val(
    val: &Val,
) -> Result<GuestWebDescriptor, ContractValueError> {
    let inner = as_result_ok(val, "get-web-descriptor")?;
    let fields = as_record(inner, "web-descriptor")?;
    let entry_record = as_record(field(fields, 0, "entry")?, "asset-path")?;
    let entry = string_field(entry_record, 0, "value", MAX_WEB_ASSET_PATH_LEN)?;
    let features = as_flags(field(fields, 1, "features")?, "web-features")?;
    let static_assets = features.iter().any(|name| name == "static-assets");
    let backend_actions = features.iter().any(|name| name == "backend-actions");
    let display_name = match option_field(fields, 2, "display-name")? {
        None => None,
        Some(value) => Some(as_string(&value, "web-descriptor.display-name")?.to_owned()),
    };
    Ok(GuestWebDescriptor {
        entry,
        features: GuestWebFeatures {
            static_assets,
            backend_actions,
        },
        display_name,
    })
}

// ---------------------------------------------------------------------------
// operune:web/assets 镜像类型
// ---------------------------------------------------------------------------

/// `asset-metadata` 镜像（§21.3：资产缓存键为 ContentDigest + asset path）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GuestAssetMetadata {
    /// `path.value`（WIT 契约规范化路径）。
    pub(crate) path: String,
    /// `size`（字节）。
    pub(crate) size: u64,
    /// `content-type`（option；Core 保留最终校验权，§21.3）。
    pub(crate) content_type: Option<String>,
}

/// 把 `asset-metadata` 清单编成 `list-assets` 返回 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_asset_list_val(assets: &[GuestAssetMetadata]) -> Val {
    let items = assets
        .iter()
        .map(|asset| {
            Val::Record(vec![
                (
                    "path".to_owned(),
                    Val::Record(vec![("value".to_owned(), Val::String(asset.path.clone()))]),
                ),
                ("size".to_owned(), Val::U64(asset.size)),
                ("content-type".to_owned(), opt_string(&asset.content_type)),
            ])
        })
        .collect();
    Val::Result(Ok(Some(Box::new(Val::List(items)))))
}

/// 解析 `list-assets` 的返回 `Val`（清单条目有上限 [`MAX_ASSET_LIST_LEN`]）。
pub(crate) fn parse_asset_list_val(
    val: &Val,
) -> Result<Vec<GuestAssetMetadata>, ContractValueError> {
    let inner = as_result_ok(val, "list-assets")?;
    let list = as_list(inner, "asset-metadata list")?;
    if list.len() > MAX_ASSET_LIST_LEN {
        return Err(ContractValueError::ValueTooLarge {
            field: "assets",
            limit: MAX_ASSET_LIST_LEN,
        });
    }
    let mut assets = Vec::with_capacity(list.len());
    for item in list {
        let fields = as_record(item, "asset-metadata")?;
        let path_record = as_record(field(fields, 0, "path")?, "asset-path")?;
        let path = string_field(path_record, 0, "value", MAX_WEB_ASSET_PATH_LEN)?;
        let size = u64_field(fields, 1, "size")?;
        let content_type = match option_field(fields, 2, "content-type")? {
            None => None,
            Some(value) => Some(as_string(&value, "asset-metadata.content-type")?.to_owned()),
        };
        assets.push(GuestAssetMetadata {
            path,
            size,
            content_type,
        });
    }
    Ok(assets)
}

// ---------------------------------------------------------------------------
// operune:web/actions 镜像类型
// ---------------------------------------------------------------------------

/// `action-payload` 镜像（variant：互斥形态，§6.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestActionPayload {
    /// `json(string)`。
    Json(String),
    /// `raw(list<u8>)`。
    Raw(Vec<u8>),
}

/// `action-request` 镜像（§21.3：无凭据字段——结构中没有会话 / cookie / CSRF）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestActionRequest {
    /// `action.value`。
    pub(crate) action: String,
    /// `payload`。
    pub(crate) payload: GuestActionPayload,
}

/// `action-error` 镜像（guest 返回值空间；Core 侧拒绝不进入该空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuestActionError {
    /// `not-found`。
    NotFound,
    /// `invalid-payload`。
    InvalidPayload,
    /// `internal`。
    Internal,
}

/// 把 `action-request` 编成调用 guest 的 `Val`。
pub(crate) fn build_action_request_val(request: &GuestActionRequest) -> Val {
    let payload = match &request.payload {
        GuestActionPayload::Json(value) => Val::Variant(
            "json".to_owned(),
            Some(Box::new(Val::String(value.clone()))),
        ),
        GuestActionPayload::Raw(bytes) => Val::Variant(
            "raw".to_owned(),
            Some(Box::new(Val::List(
                bytes.iter().map(|b| Val::U8(*b)).collect(),
            ))),
        ),
    };
    Val::Record(vec![
        (
            "action".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(request.action.clone()),
            )]),
        ),
        ("payload".to_owned(), payload),
    ])
}

/// 解析 `handle-action` 的返回 `Val`（`result<list<u8>, action-error>`）。
pub(crate) fn parse_action_result_val(val: &Val) -> Result<Vec<u8>, GuestActionError> {
    match val {
        Val::Result(Ok(Some(inner))) => {
            let items = match inner.as_ref() {
                Val::List(items) => items,
                _ => return Err(GuestActionError::InvalidPayload),
            };
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Val::U8(byte) => bytes.push(*byte),
                    _ => return Err(GuestActionError::InvalidPayload),
                }
            }
            Ok(bytes)
        }
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Enum(name) => match name.as_str() {
                "not-found" => Err(GuestActionError::NotFound),
                "invalid-payload" => Err(GuestActionError::InvalidPayload),
                "internal" => Err(GuestActionError::Internal),
                _ => Err(GuestActionError::Internal),
            },
            _ => Err(GuestActionError::InvalidPayload),
        },
        _ => Err(GuestActionError::InvalidPayload),
    }
}

// ---------------------------------------------------------------------------
// operune:web@0.2.0 镜像类型（§42.2 0.4.0 Web Application Runtime）
// ---------------------------------------------------------------------------
//
// 契约对齐目标（WIT 权威版本 = wit/operune/web@0.2.0/，已提交稳定）：
// - `app-descriptor`（`app-descriptor` / `app-features` / `app-descriptor-error`；
//   permissions / pages / routes 声明面）；
// - `routes`（`route-declaration` / `route-param` / `param-type` /
//   `http-method`）；
// - `route-dispatch`（`route-request` / `typed-param` / `param-value` /
//   `route-error`）。
//
// 解析全部按 **record 字段顺序**（canonical ABI 编码的是顺序而非名字），
// 字段名同时校验；声明面列表（permissions/pages/routes）与请求参数列表
// 都有宿主侧体积上限（§7.4 host-buffer 纪律）。

/// 声明面 permissions 列表上限（§7.4 有界清单）。
pub(crate) const MAX_APP_PERMISSIONS_LEN: usize = 256;
/// 声明面 pages 列表上限。
pub(crate) const MAX_APP_PAGES_LEN: usize = 512;
/// 声明面 routes 列表上限。
pub(crate) const MAX_APP_ROUTES_LEN: usize = 1024;
/// 单条 route 的 params 声明上限。
pub(crate) const MAX_APP_ROUTE_PARAMS_LEN: usize = 64;
/// 单次 route-request 的 typed params 上限（对齐声明面上限）。
pub(crate) const MAX_APP_REQUEST_PARAMS_LEN: usize = 64;

/// `app-features` flags 镜像（0.4.0 可组合 Web 能力声明；§42.2）。
///
/// 五个 flag 与 WIT `app-features` 一一对应；`static-assets` /
/// `backend-actions` 语义继承 0.1；`navigation` / `typed-routes` /
/// `permissions` 是 0.4 新增声明面。本版本**没有** realtime/stream flag
/// （§42.3 条件未满足，不进本版本 production scope）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestAppFeatures {
    /// `static-assets`（语义继承 0.1）。
    pub static_assets: bool,
    /// `backend-actions`（语义继承 0.1）。
    pub backend_actions: bool,
    /// `navigation`（页面声明）。
    pub navigation: bool,
    /// `typed-routes`（typed route / action 注册）。
    pub typed_routes: bool,
    /// `permissions`（权限声明）。
    pub permissions: bool,
}

/// `permission-declaration` 镜像。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPermissionDeclaration {
    /// `name.value`。
    pub name: String,
    /// `description`（option；Core 不解析）。
    pub description: Option<String>,
}

/// `page-declaration` 镜像。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestPageDeclaration {
    /// `page-id.value`。
    pub page_id: String,
    /// `path.value`（静态路径，无模板段）。
    pub path: String,
    /// `display-name`（option）。
    pub display_name: Option<String>,
    /// `required-permission`（option；引用 permissions 声明）。
    pub required_permission: Option<String>,
}

/// `route-param` 镜像（声明侧：名称 + `param-type` 变体名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRouteParamDecl {
    /// `name`。
    pub name: String,
    /// `value-type`（WIT `param-type` 变体名：text/integer/unsigned/
    /// boolean/decimal）。
    pub value_type: String,
}

/// `route-declaration` 镜像。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestRouteDeclaration {
    /// `route-id.value`。
    pub route_id: String,
    /// `method`（WIT `http-method` 变体名：get/post/put/patch/delete）。
    pub method: String,
    /// `path.value`（路径模板）。
    pub path: String,
    /// `params`（参数声明，与路径模板一致）。
    pub params: Vec<GuestRouteParamDecl>,
    /// `required-permission`（option）。
    pub required_permission: Option<String>,
}

/// `app-descriptor` 镜像（§42.2 app descriptor 声明契约）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestAppDescriptor {
    /// `entry.value`（入口资产路径）。
    pub entry: String,
    /// `features`。
    pub features: GuestAppFeatures,
    /// `display-name`（option）。
    pub display_name: Option<String>,
    /// `permissions`（权限声明集合）。
    pub permissions: Vec<GuestPermissionDeclaration>,
    /// `pages`（页面声明集合）。
    pub pages: Vec<GuestPageDeclaration>,
    /// `routes`（typed route / action 声明集合）。
    pub routes: Vec<GuestRouteDeclaration>,
    /// `default-page`（option；导航语义）。
    pub default_page: Option<String>,
}

/// `app-descriptor-error` 镜像（guest 返回值空间的预期失败，§42.2
/// conflict diagnostics 闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestAppDescriptorError {
    /// `malformed`。
    Malformed,
    /// `unsupported-contract-version`。
    UnsupportedContractVersion,
    /// `route-id-conflict`。
    RouteIdConflict,
    /// `page-id-conflict`。
    PageIdConflict,
    /// `path-conflict`。
    PathConflict,
    /// `invalid-path-template`。
    InvalidPathTemplate,
    /// `param-mismatch`。
    ParamMismatch,
    /// `invalid-permission`。
    InvalidPermission,
    /// `internal`。
    Internal,
}

/// 把 `app-descriptor` 编成 guest 返回值空间的 `Val`（测试用；record
/// 字段顺序对齐 WIT：entry、features、display-name、permissions、pages、
/// routes、default-page）。
#[cfg(test)]
pub(crate) fn build_app_descriptor_val(descriptor: &GuestAppDescriptor) -> Val {
    let mut flags = Vec::new();
    if descriptor.features.static_assets {
        flags.push("static-assets".to_owned());
    }
    if descriptor.features.backend_actions {
        flags.push("backend-actions".to_owned());
    }
    if descriptor.features.navigation {
        flags.push("navigation".to_owned());
    }
    if descriptor.features.typed_routes {
        flags.push("typed-routes".to_owned());
    }
    if descriptor.features.permissions {
        flags.push("permissions".to_owned());
    }
    let permissions = descriptor
        .permissions
        .iter()
        .map(|permission| {
            Val::Record(vec![
                (
                    "name".to_owned(),
                    Val::Record(vec![(
                        "value".to_owned(),
                        Val::String(permission.name.clone()),
                    )]),
                ),
                (
                    "description".to_owned(),
                    opt_string(&permission.description),
                ),
            ])
        })
        .collect();
    let pages = descriptor
        .pages
        .iter()
        .map(|page| {
            Val::Record(vec![
                (
                    "page-id".to_owned(),
                    Val::Record(vec![(
                        "value".to_owned(),
                        Val::String(page.page_id.clone()),
                    )]),
                ),
                (
                    "path".to_owned(),
                    Val::Record(vec![("value".to_owned(), Val::String(page.path.clone()))]),
                ),
                ("display-name".to_owned(), opt_string(&page.display_name)),
                (
                    "required-permission".to_owned(),
                    opt_permission_name(&page.required_permission),
                ),
            ])
        })
        .collect();
    let routes = descriptor
        .routes
        .iter()
        .map(|route| {
            let params = route
                .params
                .iter()
                .map(|param| {
                    Val::Record(vec![
                        ("name".to_owned(), Val::String(param.name.clone())),
                        ("value-type".to_owned(), Val::Enum(param.value_type.clone())),
                    ])
                })
                .collect();
            Val::Record(vec![
                (
                    "route-id".to_owned(),
                    Val::Record(vec![(
                        "value".to_owned(),
                        Val::String(route.route_id.clone()),
                    )]),
                ),
                ("method".to_owned(), Val::Enum(route.method.clone())),
                (
                    "path".to_owned(),
                    Val::Record(vec![("value".to_owned(), Val::String(route.path.clone()))]),
                ),
                ("params".to_owned(), Val::List(params)),
                (
                    "required-permission".to_owned(),
                    opt_permission_name(&route.required_permission),
                ),
            ])
        })
        .collect();
    Val::Result(Ok(Some(Box::new(Val::Record(vec![
        (
            "entry".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(descriptor.entry.clone()),
            )]),
        ),
        ("features".to_owned(), Val::Flags(flags)),
        (
            "display-name".to_owned(),
            opt_string(&descriptor.display_name),
        ),
        ("permissions".to_owned(), Val::List(permissions)),
        ("pages".to_owned(), Val::List(pages)),
        ("routes".to_owned(), Val::List(routes)),
        (
            "default-page".to_owned(),
            opt_permission_name(&descriptor.default_page),
        ),
    ])))))
}

/// 把 `app-descriptor-error` 编成 guest 返回值空间的 `Val`（测试用）。
#[cfg(test)]
pub(crate) fn build_app_descriptor_error_val(error: GuestAppDescriptorError) -> Val {
    let name = match error {
        GuestAppDescriptorError::Malformed => "malformed",
        GuestAppDescriptorError::UnsupportedContractVersion => "unsupported-contract-version",
        GuestAppDescriptorError::RouteIdConflict => "route-id-conflict",
        GuestAppDescriptorError::PageIdConflict => "page-id-conflict",
        GuestAppDescriptorError::PathConflict => "path-conflict",
        GuestAppDescriptorError::InvalidPathTemplate => "invalid-path-template",
        GuestAppDescriptorError::ParamMismatch => "param-mismatch",
        GuestAppDescriptorError::InvalidPermission => "invalid-permission",
        GuestAppDescriptorError::Internal => "internal",
    };
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

/// 解析 `get-app-descriptor` 的返回 `Val`（§13.3 边界解析一次；声明面
/// 列表与字符串都有宿主侧体积上限）。
pub(crate) fn parse_app_descriptor_val(
    val: &Val,
) -> Result<GuestAppDescriptor, ContractValueError> {
    let inner = as_result_ok(val, "get-app-descriptor")?;
    let fields = as_record(inner, "app-descriptor")?;
    let entry_record = as_record(field(fields, 0, "entry")?, "asset-path")?;
    let entry = string_field(entry_record, 0, "value", MAX_WEB_ASSET_PATH_LEN)?;
    let features = as_flags(field(fields, 1, "features")?, "app-features")?;
    let features = GuestAppFeatures {
        static_assets: features.iter().any(|name| name == "static-assets"),
        backend_actions: features.iter().any(|name| name == "backend-actions"),
        navigation: features.iter().any(|name| name == "navigation"),
        typed_routes: features.iter().any(|name| name == "typed-routes"),
        permissions: features.iter().any(|name| name == "permissions"),
    };
    let display_name = match option_field(fields, 2, "display-name")? {
        None => None,
        Some(value) => {
            let text = as_string(&value, "app-descriptor.display-name")?;
            if text.len() > MAX_DISPLAY_TEXT_LEN {
                return Err(ContractValueError::ValueTooLarge {
                    field: "display-name",
                    limit: MAX_DISPLAY_TEXT_LEN,
                });
            }
            Some(text.to_owned())
        }
    };
    let permissions = parse_permission_list(field(fields, 3, "permissions")?)?;
    let pages = parse_page_list(field(fields, 4, "pages")?)?;
    let routes = parse_route_list(field(fields, 5, "routes")?)?;
    let default_page = match option_field(fields, 6, "default-page")? {
        None => None,
        Some(value) => {
            let record = as_record(&value, "page-id")?;
            Some(string_field(record, 0, "value", MAX_COMPONENT_ID_LEN)?)
        }
    };
    Ok(GuestAppDescriptor {
        entry,
        features,
        display_name,
        permissions,
        pages,
        routes,
        default_page,
    })
}

/// 解析 `permissions` 列表（`list<permission-declaration>`）。
fn parse_permission_list(val: &Val) -> Result<Vec<GuestPermissionDeclaration>, ContractValueError> {
    let list = as_list(val, "permission-declaration list")?;
    if list.len() > MAX_APP_PERMISSIONS_LEN {
        return Err(ContractValueError::ValueTooLarge {
            field: "permissions",
            limit: MAX_APP_PERMISSIONS_LEN,
        });
    }
    let mut permissions = Vec::with_capacity(list.len());
    for item in list {
        let fields = as_record(item, "permission-declaration")?;
        let name_record = as_record(field(fields, 0, "name")?, "permission-name")?;
        let name = string_field(name_record, 0, "value", MAX_COMPONENT_ID_LEN)?;
        let description = match option_field(fields, 1, "description")? {
            None => None,
            Some(value) => {
                let text = as_string(&value, "permission-declaration.description")?;
                if text.len() > MAX_DISPLAY_TEXT_LEN {
                    return Err(ContractValueError::ValueTooLarge {
                        field: "description",
                        limit: MAX_DISPLAY_TEXT_LEN,
                    });
                }
                Some(text.to_owned())
            }
        };
        permissions.push(GuestPermissionDeclaration { name, description });
    }
    Ok(permissions)
}

/// 解析 `pages` 列表（`list<page-declaration>`）。
fn parse_page_list(val: &Val) -> Result<Vec<GuestPageDeclaration>, ContractValueError> {
    let list = as_list(val, "page-declaration list")?;
    if list.len() > MAX_APP_PAGES_LEN {
        return Err(ContractValueError::ValueTooLarge {
            field: "pages",
            limit: MAX_APP_PAGES_LEN,
        });
    }
    let mut pages = Vec::with_capacity(list.len());
    for item in list {
        let fields = as_record(item, "page-declaration")?;
        let page_id_record = as_record(field(fields, 0, "page-id")?, "page-id")?;
        let page_id = string_field(page_id_record, 0, "value", MAX_COMPONENT_ID_LEN)?;
        let path_record = as_record(field(fields, 1, "path")?, "page-path")?;
        let path = string_field(path_record, 0, "value", MAX_WEB_ASSET_PATH_LEN)?;
        let display_name = match option_field(fields, 2, "display-name")? {
            None => None,
            Some(value) => {
                let text = as_string(&value, "page-declaration.display-name")?;
                if text.len() > MAX_DISPLAY_TEXT_LEN {
                    return Err(ContractValueError::ValueTooLarge {
                        field: "display-name",
                        limit: MAX_DISPLAY_TEXT_LEN,
                    });
                }
                Some(text.to_owned())
            }
        };
        let required_permission = match option_field(fields, 3, "required-permission")? {
            None => None,
            Some(value) => {
                let record = as_record(&value, "permission-name")?;
                Some(string_field(record, 0, "value", MAX_COMPONENT_ID_LEN)?)
            }
        };
        pages.push(GuestPageDeclaration {
            page_id,
            path,
            display_name,
            required_permission,
        });
    }
    Ok(pages)
}

/// 解析 `routes` 列表（`list<route-declaration>`）。
fn parse_route_list(val: &Val) -> Result<Vec<GuestRouteDeclaration>, ContractValueError> {
    let list = as_list(val, "route-declaration list")?;
    if list.len() > MAX_APP_ROUTES_LEN {
        return Err(ContractValueError::ValueTooLarge {
            field: "routes",
            limit: MAX_APP_ROUTES_LEN,
        });
    }
    let mut routes = Vec::with_capacity(list.len());
    for item in list {
        let fields = as_record(item, "route-declaration")?;
        let route_id_record = as_record(field(fields, 0, "route-id")?, "route-id")?;
        let route_id = string_field(route_id_record, 0, "value", MAX_COMPONENT_ID_LEN)?;
        let method = match field(fields, 1, "method")? {
            Val::Enum(name) => name.clone(),
            _ => {
                return Err(ContractValueError::ShapeMismatch {
                    field: "method",
                    expected: "enum",
                });
            }
        };
        // http-method 是闭集（routes.wit：get/post/put/patch/delete）；
        // 闭集外变体在组装期以 malformed 拒绝（web_app 层）。
        let path_record = as_record(field(fields, 2, "path")?, "path-template")?;
        let path = string_field(path_record, 0, "value", MAX_WEB_ASSET_PATH_LEN)?;
        let params = match field(fields, 3, "params")? {
            Val::List(items) => {
                if items.len() > MAX_APP_ROUTE_PARAMS_LEN {
                    return Err(ContractValueError::ValueTooLarge {
                        field: "params",
                        limit: MAX_APP_ROUTE_PARAMS_LEN,
                    });
                }
                let mut params = Vec::with_capacity(items.len());
                for item in items {
                    let param_fields = as_record(item, "route-param")?;
                    let name = string_field(param_fields, 0, "name", MAX_COMPONENT_ID_LEN)?;
                    let value_type = match field(param_fields, 1, "value-type")? {
                        Val::Enum(name) => name.clone(),
                        _ => {
                            return Err(ContractValueError::ShapeMismatch {
                                field: "value-type",
                                expected: "enum",
                            });
                        }
                    };
                    params.push(GuestRouteParamDecl { name, value_type });
                }
                params
            }
            _ => {
                return Err(ContractValueError::ShapeMismatch {
                    field: "params",
                    expected: "list",
                });
            }
        };
        let required_permission = match option_field(fields, 4, "required-permission")? {
            None => None,
            Some(value) => {
                let record = as_record(&value, "permission-name")?;
                Some(string_field(record, 0, "value", MAX_COMPONENT_ID_LEN)?)
            }
        };
        routes.push(GuestRouteDeclaration {
            route_id,
            method,
            path,
            params,
            required_permission,
        });
    }
    Ok(routes)
}

/// 解析 `app-descriptor-error` 载荷（result 的 Err 侧）。
pub(crate) fn parse_app_descriptor_error_val(
    val: &Val,
) -> Result<GuestAppDescriptorError, ContractValueError> {
    let payload = as_result_err(val, "get-app-descriptor")?;
    let name = as_enum(payload, "app-descriptor-error")?;
    match name {
        "malformed" => Ok(GuestAppDescriptorError::Malformed),
        "unsupported-contract-version" => Ok(GuestAppDescriptorError::UnsupportedContractVersion),
        "route-id-conflict" => Ok(GuestAppDescriptorError::RouteIdConflict),
        "page-id-conflict" => Ok(GuestAppDescriptorError::PageIdConflict),
        "path-conflict" => Ok(GuestAppDescriptorError::PathConflict),
        "invalid-path-template" => Ok(GuestAppDescriptorError::InvalidPathTemplate),
        "param-mismatch" => Ok(GuestAppDescriptorError::ParamMismatch),
        "invalid-permission" => Ok(GuestAppDescriptorError::InvalidPermission),
        "internal" => Ok(GuestAppDescriptorError::Internal),
        other => Err(ContractValueError::InvalidVariant(other.to_owned())),
    }
}

// ---------------------------------------------------------------------------
// operune:web@0.2.0 route-dispatch 镜像类型（§42.2 typed route dispatch）
// ---------------------------------------------------------------------------

/// `param-value` 镜像（闭集 variant，与 `routes.param-type` 一一对应；
/// §42.2 typed 参数运行期形态）。
#[derive(Debug, Clone, PartialEq)]
pub enum GuestParamValue {
    /// `text(string)`。
    Text(String),
    /// `integer(s64)`。
    Integer(i64),
    /// `unsigned(u64)`。
    Unsigned(u64),
    /// `boolean(bool)`。
    Boolean(bool),
    /// `decimal(f64)`。
    Decimal(f64),
}

impl GuestParamValue {
    /// 与 WIT `param-type` 一一对应（分发前按声明校验值类型的映射面）。
    pub(crate) fn param_type(&self) -> operune_domain::ParamType {
        match self {
            Self::Text(_) => operune_domain::ParamType::Text,
            Self::Integer(_) => operune_domain::ParamType::Integer,
            Self::Unsigned(_) => operune_domain::ParamType::Unsigned,
            Self::Boolean(_) => operune_domain::ParamType::Boolean,
            Self::Decimal(_) => operune_domain::ParamType::Decimal,
        }
    }
}

/// `typed-param` 镜像（名称 + 值；名称与值由 Core 按声明校验，§42.2）。
#[derive(Debug, Clone, PartialEq)]
pub struct GuestTypedParam {
    /// `name`。
    pub name: String,
    /// `value`。
    pub value: GuestParamValue,
}

/// `route-request` 镜像（§42.2 typed route 请求；无凭据字段，§21.3
/// 凭据边界）。
#[derive(Debug, Clone, PartialEq)]
pub struct GuestRouteRequest {
    /// `route-id.value`（分发键）。
    pub route_id: String,
    /// `params`（结构化参数，顺序与声明一致）。
    pub params: Vec<GuestTypedParam>,
    /// `payload`（可选辅助载荷）。
    pub payload: Option<GuestActionPayload>,
}

/// `route-error` 镜像（guest 返回值空间；Core 侧拒绝不进入该空间）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRouteError {
    /// `not-found`（防御性闭集：Core 分发前已按声明路由表检查）。
    NotFound,
    /// `invalid-params`（防御性闭集：Core 分发前已校验）。
    InvalidParams,
    /// `invalid-payload`。
    InvalidPayload,
    /// `internal`。
    Internal,
}

/// 把 `route-request` 编成调用 guest 的 `Val`（record 顺序对齐 WIT：
/// route-id、params、payload）。
pub(crate) fn build_route_request_val(request: &GuestRouteRequest) -> Val {
    let params = request
        .params
        .iter()
        .map(|param| {
            Val::Record(vec![
                ("name".to_owned(), Val::String(param.name.clone())),
                ("value".to_owned(), build_param_value_val(&param.value)),
            ])
        })
        .collect();
    let payload = match &request.payload {
        Some(payload) => Val::Option(Some(Box::new(build_action_payload_val(payload)))),
        None => Val::Option(None),
    };
    Val::Record(vec![
        (
            "route-id".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(request.route_id.clone()),
            )]),
        ),
        ("params".to_owned(), Val::List(params)),
        ("payload".to_owned(), payload),
    ])
}

/// 把 `param-value` 编成 `Val`（WIT variant 形态）。
fn build_param_value_val(value: &GuestParamValue) -> Val {
    match value {
        GuestParamValue::Text(text) => {
            Val::Variant("text".to_owned(), Some(Box::new(Val::String(text.clone()))))
        }
        GuestParamValue::Integer(value) => {
            Val::Variant("integer".to_owned(), Some(Box::new(Val::S64(*value))))
        }
        GuestParamValue::Unsigned(value) => {
            Val::Variant("unsigned".to_owned(), Some(Box::new(Val::U64(*value))))
        }
        GuestParamValue::Boolean(value) => {
            Val::Variant("boolean".to_owned(), Some(Box::new(Val::Bool(*value))))
        }
        GuestParamValue::Decimal(value) => {
            Val::Variant("decimal".to_owned(), Some(Box::new(Val::Float64(*value))))
        }
    }
}

/// 把 `action-payload` 编成 `Val`（route-request 的辅助载荷复用 0.1 形态）。
fn build_action_payload_val(payload: &GuestActionPayload) -> Val {
    match payload {
        GuestActionPayload::Json(value) => Val::Variant(
            "json".to_owned(),
            Some(Box::new(Val::String(value.clone()))),
        ),
        GuestActionPayload::Raw(bytes) => Val::Variant(
            "raw".to_owned(),
            Some(Box::new(Val::List(
                bytes.iter().map(|byte| Val::U8(*byte)).collect(),
            ))),
        ),
    }
}

/// 解析 `handle-route` 的返回 `Val`（`result<list<u8>, route-error>`）。
pub(crate) fn parse_route_result_val(val: &Val) -> Result<Vec<u8>, GuestRouteError> {
    match val {
        Val::Result(Ok(Some(inner))) => {
            let items = match inner.as_ref() {
                Val::List(items) => items,
                _ => return Err(GuestRouteError::InvalidPayload),
            };
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Val::U8(byte) => bytes.push(*byte),
                    _ => return Err(GuestRouteError::InvalidPayload),
                }
            }
            Ok(bytes)
        }
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Enum(name) => match name.as_str() {
                "not-found" => Err(GuestRouteError::NotFound),
                "invalid-params" => Err(GuestRouteError::InvalidParams),
                "invalid-payload" => Err(GuestRouteError::InvalidPayload),
                "internal" => Err(GuestRouteError::Internal),
                _ => Err(GuestRouteError::Internal),
            },
            _ => Err(GuestRouteError::InvalidPayload),
        },
        _ => Err(GuestRouteError::InvalidPayload),
    }
}

// ---------------------------------------------------------------------------
// 基础 Val 访问器（全部只读匹配，失败返回封闭 typed 错误）
// ---------------------------------------------------------------------------

#[cfg(test)]
fn opt_string(value: &Option<String>) -> Val {
    match value {
        Some(value) => Val::Option(Some(Box::new(Val::String(value.clone())))),
        None => Val::Option(None),
    }
}

/// `option<record { value: string }>` 的测试编码（permission-name /
/// page-id / 一般命名 record wrapper 形态，§13.5）。
#[cfg(test)]
fn opt_permission_name(value: &Option<String>) -> Val {
    match value {
        Some(value) => Val::Option(Some(Box::new(Val::Record(vec![(
            "value".to_owned(),
            Val::String(value.clone()),
        )])))),
        None => Val::Option(None),
    }
}

/// `result<T, _>` 的 Ok 载荷。
fn as_result_ok<'a>(val: &'a Val, what: &'static str) -> Result<&'a Val, ContractValueError> {
    match val {
        Val::Result(Ok(Some(inner))) => Ok(inner),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "result with Ok payload",
        }),
    }
}

/// `result<_, E>` 的 Err 载荷。
fn as_result_err<'a>(val: &'a Val, what: &'static str) -> Result<&'a Val, ContractValueError> {
    match val {
        Val::Result(Err(Some(inner))) => Ok(inner),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "result with Err payload",
        }),
    }
}

fn as_record<'a>(
    val: &'a Val,
    what: &'static str,
) -> Result<&'a [(String, Val)], ContractValueError> {
    match val {
        Val::Record(fields) => Ok(fields),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "record",
        }),
    }
}

/// 按位置 + 名字取 record 字段（canonical ABI 编码顺序；名字同时校验）。
fn field<'a>(
    fields: &'a [(String, Val)],
    index: usize,
    expected_name: &'static str,
) -> Result<&'a Val, ContractValueError> {
    let (name, value) = fields
        .get(index)
        .ok_or(ContractValueError::MissingField(expected_name))?;
    if name != expected_name {
        return Err(ContractValueError::MissingField(expected_name));
    }
    Ok(value)
}

fn string_field(
    fields: &[(String, Val)],
    index: usize,
    name: &'static str,
    limit: usize,
) -> Result<String, ContractValueError> {
    let value = as_string(field(fields, index, name)?, name)?;
    if value.len() > limit {
        return Err(ContractValueError::ValueTooLarge { field: name, limit });
    }
    Ok(value.to_owned())
}

fn u32_field(
    fields: &[(String, Val)],
    index: usize,
    name: &'static str,
) -> Result<u32, ContractValueError> {
    match field(fields, index, name)? {
        Val::U32(value) => Ok(*value),
        _ => Err(ContractValueError::ShapeMismatch {
            field: name,
            expected: "u32",
        }),
    }
}

fn u64_field(
    fields: &[(String, Val)],
    index: usize,
    name: &'static str,
) -> Result<u64, ContractValueError> {
    match field(fields, index, name)? {
        Val::U64(value) => Ok(*value),
        _ => Err(ContractValueError::ShapeMismatch {
            field: name,
            expected: "u64",
        }),
    }
}

fn as_string<'a>(val: &'a Val, what: &'static str) -> Result<&'a str, ContractValueError> {
    match val {
        Val::String(value) => Ok(value),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "string",
        }),
    }
}

fn as_enum<'a>(val: &'a Val, what: &'static str) -> Result<&'a str, ContractValueError> {
    match val {
        Val::Enum(name) => Ok(name),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "enum",
        }),
    }
}

fn as_flags<'a>(val: &'a Val, what: &'static str) -> Result<&'a [String], ContractValueError> {
    match val {
        Val::Flags(names) => Ok(names),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "flags",
        }),
    }
}

fn as_list<'a>(val: &'a Val, what: &'static str) -> Result<&'a [Val], ContractValueError> {
    match val {
        Val::List(items) => Ok(items),
        _ => Err(ContractValueError::ShapeMismatch {
            field: what,
            expected: "list",
        }),
    }
}

fn option_field(
    fields: &[(String, Val)],
    index: usize,
    name: &'static str,
) -> Result<Option<Val>, ContractValueError> {
    match field(fields, index, name)? {
        Val::Option(None) => Ok(None),
        Val::Option(Some(inner)) => Ok(Some(*inner.clone())),
        _ => Err(ContractValueError::ShapeMismatch {
            field: name,
            expected: "option",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor(component_id: &str) -> GuestComponentDescriptor {
        GuestComponentDescriptor {
            component_id: component_id.to_owned(),
            major: 1,
            minor: 2,
            patch: 3,
            display_name: "Example".to_owned(),
            author: Some(GuestAuthorInfo {
                display_name: "Author".to_owned(),
                homepage: Some("https://example.invalid".to_owned()),
                description: None,
            }),
        }
    }

    #[test]
    fn component_descriptor_val_roundtrip() {
        let original = descriptor("my-component");
        let val = build_component_descriptor_val(&original);
        let parsed = match parse_component_descriptor_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn component_descriptor_rejects_missing_field() {
        // 位置 1（version）缺失 → contract violation。
        let val = Val::Result(Ok(Some(Box::new(Val::Record(vec![(
            "component-id".to_owned(),
            Val::Record(vec![("value".to_owned(), Val::String("x".to_owned()))]),
        )])))));
        assert!(parse_component_descriptor_val(&val).is_err());
    }

    #[test]
    fn component_descriptor_rejects_oversized_id() {
        let val =
            build_component_descriptor_val(&descriptor(&"x".repeat(MAX_COMPONENT_ID_LEN + 1)));
        let result = parse_component_descriptor_val(&val);
        assert!(
            matches!(
                result,
                Err(ContractValueError::ValueTooLarge { field: "value", .. })
            ),
            "oversized component-id must be rejected"
        );
    }

    #[test]
    fn descriptor_error_val_parses() {
        let val = build_descriptor_error_val(GuestDescriptorError::Malformed);
        match parse_descriptor_error_val(&val) {
            Ok(GuestDescriptorError::Malformed) => {}
            Ok(other) => test_failure(format_args!("unexpected error: {other:?}")),
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        }
    }

    #[test]
    fn state_declaration_val_roundtrip() {
        let original = GuestStateDeclaration {
            name: Some("Demo State".to_owned()),
            schema_version: 2,
        };
        let val = build_state_declaration_val(&original);
        let parsed = match parse_state_declaration_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_declaration_unnamed_roundtrip() {
        // `name` 是 option：None 形态（无展示名的声明合法，declaration.wit）。
        let original = GuestStateDeclaration {
            name: None,
            schema_version: 0,
        };
        let val = build_state_declaration_val(&original);
        let parsed = match parse_state_declaration_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn state_declaration_rejects_missing_schema_version() {
        // 位置 1（schema-version）缺失 → contract violation。
        let val = Val::Result(Ok(Some(Box::new(Val::Record(vec![(
            "name".to_owned(),
            Val::Option(None),
        )])))));
        assert!(parse_state_declaration_val(&val).is_err());
    }

    #[test]
    fn state_declaration_rejects_oversized_name() {
        let val = build_state_declaration_val(&GuestStateDeclaration {
            name: Some("x".repeat(MAX_DISPLAY_TEXT_LEN + 1)),
            schema_version: 1,
        });
        let result = parse_state_declaration_val(&val);
        assert!(
            matches!(
                result,
                Err(ContractValueError::ValueTooLarge { field: "name", .. })
            ),
            "oversized declaration name must be rejected"
        );
    }

    #[test]
    fn state_declaration_error_val_parses() {
        let val = build_state_declaration_error_val(
            GuestStateDeclarationError::UnsupportedContractVersion,
        );
        match parse_state_declaration_error_val(&val) {
            Ok(GuestStateDeclarationError::UnsupportedContractVersion) => {}
            Ok(other) => test_failure(format_args!("unexpected error: {other:?}")),
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        }
    }

    #[test]
    fn web_descriptor_val_roundtrip() {
        let original = GuestWebDescriptor {
            entry: "/index.html".to_owned(),
            features: GuestWebFeatures {
                static_assets: true,
                backend_actions: true,
            },
            display_name: Some("Example UI".to_owned()),
        };
        let val = build_web_descriptor_val(&original);
        let parsed = match parse_web_descriptor_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn web_descriptor_flags_missing_means_false() {
        let val = Val::Result(Ok(Some(Box::new(Val::Record(vec![
            (
                "entry".to_owned(),
                Val::Record(vec![("value".to_owned(), Val::String("/a".to_owned()))]),
            ),
            ("features".to_owned(), Val::Flags(vec![])),
            ("display-name".to_owned(), Val::Option(None)),
        ])))));
        let parsed = match parse_web_descriptor_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert!(!parsed.features.static_assets);
        assert!(!parsed.features.backend_actions);
    }

    #[test]
    fn asset_list_val_roundtrip() {
        let original = vec![
            GuestAssetMetadata {
                path: "/index.html".to_owned(),
                size: 42,
                content_type: Some("text/html".to_owned()),
            },
            GuestAssetMetadata {
                path: "/app.js".to_owned(),
                size: 0,
                content_type: None,
            },
        ];
        let val = build_asset_list_val(&original);
        let parsed = match parse_asset_list_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn asset_list_rejects_oversized_manifest() {
        // 超过清单条目上限 → contract violation（宿主侧有界，§21.3）。
        let assets: Vec<GuestAssetMetadata> = (0..MAX_ASSET_LIST_LEN + 1)
            .map(|i| GuestAssetMetadata {
                path: format!("/a{i}"),
                size: 1,
                content_type: None,
            })
            .collect();
        let val = build_asset_list_val(&assets);
        assert!(parse_asset_list_val(&val).is_err());
    }

    #[test]
    fn action_request_val_roundtrip() {
        let original = GuestActionRequest {
            action: "run-check".to_owned(),
            payload: GuestActionPayload::Json("{\"a\":1}".to_owned()),
        };
        let val = build_action_request_val(&original);
        // 结构断言：请求记录只有 action + payload 两个字段，无任何凭据字段
        //（§21.3 凭据边界：浏览器内 Component 代码不接触 session/CSRF）。
        match &val {
            Val::Record(fields) => {
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "action");
                assert_eq!(fields[1].0, "payload");
            }
            other => test_failure(format_args!("unexpected val shape: {other:?}")),
        }
    }

    #[test]
    fn action_result_val_parses() {
        let ok_val = Val::Result(Ok(Some(Box::new(Val::List(
            vec![1u8, 2, 3].into_iter().map(Val::U8).collect(),
        )))));
        assert_eq!(
            match parse_action_result_val(&ok_val) {
                Ok(bytes) => bytes,
                Err(e) => test_failure(format_args!("parse failed: {e:?}")),
            },
            vec![1u8, 2, 3]
        );

        let err_val = Val::Result(Err(Some(Box::new(Val::Enum("not-found".to_owned())))));
        assert_eq!(
            parse_action_result_val(&err_val),
            Err(GuestActionError::NotFound)
        );
    }

    #[test]
    fn action_result_rejects_non_byte_list() {
        // 返回的 list 元素不是 u8（契约外的形状）→ invalid-payload。
        let val = Val::Result(Ok(Some(Box::new(Val::List(vec![Val::U32(1)])))));
        assert_eq!(
            parse_action_result_val(&val),
            Err(GuestActionError::InvalidPayload)
        );
    }

    // ------------------------------------------------------------------
    // 0.4.0（§42.2）：operune:web@0.2.0 app-descriptor / route-dispatch
    // ------------------------------------------------------------------

    /// 一个覆盖全部声明面形态的 app-descriptor 夹具。
    fn sample_app_descriptor() -> GuestAppDescriptor {
        GuestAppDescriptor {
            entry: "/index.html".to_owned(),
            features: GuestAppFeatures {
                static_assets: true,
                backend_actions: true,
                navigation: true,
                typed_routes: true,
                permissions: true,
            },
            display_name: Some("Example UI".to_owned()),
            permissions: vec![
                GuestPermissionDeclaration {
                    name: "view".to_owned(),
                    description: Some("可以查看".to_owned()),
                },
                GuestPermissionDeclaration {
                    name: "admin".to_owned(),
                    description: None,
                },
            ],
            pages: vec![
                GuestPageDeclaration {
                    page_id: "home".to_owned(),
                    path: "/home".to_owned(),
                    display_name: Some("Home".to_owned()),
                    required_permission: None,
                },
                GuestPageDeclaration {
                    page_id: "admin".to_owned(),
                    path: "/admin".to_owned(),
                    display_name: None,
                    required_permission: Some("admin".to_owned()),
                },
            ],
            routes: vec![
                GuestRouteDeclaration {
                    route_id: "get-item".to_owned(),
                    method: "get".to_owned(),
                    path: "/api/{id}".to_owned(),
                    params: vec![GuestRouteParamDecl {
                        name: "id".to_owned(),
                        value_type: "integer".to_owned(),
                    }],
                    required_permission: None,
                },
                GuestRouteDeclaration {
                    route_id: "create-item".to_owned(),
                    method: "post".to_owned(),
                    path: "/api/items".to_owned(),
                    params: vec![GuestRouteParamDecl {
                        name: "label".to_owned(),
                        value_type: "text".to_owned(),
                    }],
                    required_permission: Some("admin".to_owned()),
                },
            ],
            default_page: Some("home".to_owned()),
        }
    }

    #[test]
    fn app_descriptor_val_roundtrip() {
        let original = sample_app_descriptor();
        let val = build_app_descriptor_val(&original);
        let parsed = match parse_app_descriptor_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert_eq!(parsed, original);
    }

    #[test]
    fn app_descriptor_flags_missing_means_false() {
        // 0.2.0 组件只声明 static-assets / backend-actions 时与 0.1 组件
        // 行为等价（app-descriptor.wit 兼容路径）。
        let original = GuestAppDescriptor {
            features: GuestAppFeatures {
                static_assets: true,
                backend_actions: true,
                navigation: false,
                typed_routes: false,
                permissions: false,
            },
            ..sample_app_descriptor()
        };
        let val = build_app_descriptor_val(&original);
        let parsed = match parse_app_descriptor_val(&val) {
            Ok(parsed) => parsed,
            Err(e) => test_failure(format_args!("parse failed: {e}")),
        };
        assert!(!parsed.features.navigation);
        assert!(!parsed.features.typed_routes);
        assert!(!parsed.features.permissions);
    }

    #[test]
    fn app_descriptor_rejects_oversized_declaration_lists() {
        // §7.4 host-buffer 纪律：声明面列表超宿主侧上限 → contract
        // violation。
        let mut oversized = sample_app_descriptor();
        oversized.routes = (0..(MAX_APP_ROUTES_LEN + 1))
            .map(|index| GuestRouteDeclaration {
                route_id: format!("r{index}"),
                method: "get".to_owned(),
                path: format!("/r/{index}"),
                params: Vec::new(),
                required_permission: None,
            })
            .collect();
        let val = build_app_descriptor_val(&oversized);
        let result = parse_app_descriptor_val(&val);
        assert!(
            matches!(
                result,
                Err(ContractValueError::ValueTooLarge {
                    field: "routes",
                    ..
                })
            ),
            "oversized routes list must be rejected: {result:?}"
        );
    }

    #[test]
    fn app_descriptor_rejects_oversized_identifier() {
        let mut oversized = sample_app_descriptor();
        oversized.pages[0].page_id = "x".repeat(MAX_COMPONENT_ID_LEN + 1);
        let val = build_app_descriptor_val(&oversized);
        let result = parse_app_descriptor_val(&val);
        assert!(
            matches!(
                result,
                Err(ContractValueError::ValueTooLarge { field: "value", .. })
            ),
            "oversized page-id must be rejected: {result:?}"
        );
    }

    #[test]
    fn app_descriptor_error_val_parses() {
        for (error, name) in [
            (GuestAppDescriptorError::Malformed, "malformed"),
            (
                GuestAppDescriptorError::UnsupportedContractVersion,
                "unsupported-contract-version",
            ),
            (
                GuestAppDescriptorError::RouteIdConflict,
                "route-id-conflict",
            ),
            (GuestAppDescriptorError::PageIdConflict, "page-id-conflict"),
            (GuestAppDescriptorError::PathConflict, "path-conflict"),
            (
                GuestAppDescriptorError::InvalidPathTemplate,
                "invalid-path-template",
            ),
            (GuestAppDescriptorError::ParamMismatch, "param-mismatch"),
            (
                GuestAppDescriptorError::InvalidPermission,
                "invalid-permission",
            ),
            (GuestAppDescriptorError::Internal, "internal"),
        ] {
            let val = build_app_descriptor_error_val(error);
            match parse_app_descriptor_error_val(&val) {
                Ok(parsed) if parsed == error => {}
                Ok(parsed) => test_failure(format_args!("expected {name}, got {parsed:?}")),
                Err(e) => test_failure(format_args!("parse {name} failed: {e}")),
            }
        }
        // 闭集外变体 → contract violation。
        let unknown = Val::Result(Err(Some(Box::new(Val::Enum("bogus".to_owned())))));
        assert!(parse_app_descriptor_error_val(&unknown).is_err());
    }

    #[test]
    fn route_request_val_roundtrip() {
        let original = GuestRouteRequest {
            route_id: "get-item".to_owned(),
            params: vec![
                GuestTypedParam {
                    name: "id".to_owned(),
                    value: GuestParamValue::Integer(42),
                },
                GuestTypedParam {
                    name: "active".to_owned(),
                    value: GuestParamValue::Boolean(true),
                },
                GuestTypedParam {
                    name: "ratio".to_owned(),
                    value: GuestParamValue::Decimal(1.5),
                },
            ],
            payload: Some(GuestActionPayload::Json("{}".to_owned())),
        };
        let val = build_route_request_val(&original);
        // 结构断言（§21.3 凭据边界）：route-id + params + payload，无凭据
        // 字段。
        match &val {
            Val::Record(fields) => {
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].0, "route-id");
                assert_eq!(fields[1].0, "params");
                assert_eq!(fields[2].0, "payload");
            }
            other => test_failure(format_args!("unexpected val shape: {other:?}")),
        }
    }

    #[test]
    fn route_result_val_parses() {
        let ok_val = Val::Result(Ok(Some(Box::new(Val::List(
            vec![9u8, 8, 7].into_iter().map(Val::U8).collect(),
        )))));
        assert_eq!(
            match parse_route_result_val(&ok_val) {
                Ok(bytes) => bytes,
                Err(e) => test_failure(format_args!("parse failed: {e:?}")),
            },
            vec![9u8, 8, 7]
        );
        for (name, error) in [
            ("not-found", GuestRouteError::NotFound),
            ("invalid-params", GuestRouteError::InvalidParams),
            ("invalid-payload", GuestRouteError::InvalidPayload),
            ("internal", GuestRouteError::Internal),
        ] {
            let err_val = Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))));
            assert_eq!(parse_route_result_val(&err_val), Err(error), "{name}");
        }
        // 闭集外变体 → Internal（防御性闭集）。
        let unknown = Val::Result(Err(Some(Box::new(Val::Enum("bogus".to_owned())))));
        assert_eq!(
            parse_route_result_val(&unknown),
            Err(GuestRouteError::Internal)
        );
        // 非字节列表 → InvalidPayload。
        let bad_list = Val::Result(Ok(Some(Box::new(Val::List(vec![Val::U32(1)])))));
        assert_eq!(
            parse_route_result_val(&bad_list),
            Err(GuestRouteError::InvalidPayload)
        );
    }

    #[test]
    fn guest_param_value_maps_to_param_type() {
        // §42.2：param-value 与 param-type 一一对应。
        assert_eq!(
            GuestParamValue::Text("x".to_owned()).param_type(),
            operune_domain::ParamType::Text
        );
        assert_eq!(
            GuestParamValue::Integer(-1).param_type(),
            operune_domain::ParamType::Integer
        );
        assert_eq!(
            GuestParamValue::Unsigned(1).param_type(),
            operune_domain::ParamType::Unsigned
        );
        assert_eq!(
            GuestParamValue::Boolean(true).param_type(),
            operune_domain::ParamType::Boolean
        );
        assert_eq!(
            GuestParamValue::Decimal(1.0).param_type(),
            operune_domain::ParamType::Decimal
        );
    }

    #[allow(clippy::assertions_on_constants)]
    fn test_failure(message: impl std::fmt::Display) -> ! {
        assert!(false, "{message}");
        std::process::abort();
    }
}
