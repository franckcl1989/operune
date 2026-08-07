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
// 基础 Val 访问器（全部只读匹配，失败返回封闭 typed 错误）
// ---------------------------------------------------------------------------

#[cfg(test)]
fn opt_string(value: &Option<String>) -> Val {
    match value {
        Some(value) => Val::Option(Some(Box::new(Val::String(value.clone())))),
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
#[cfg(test)]
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

#[cfg(test)]
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

    #[allow(clippy::assertions_on_constants)]
    fn test_failure(message: impl std::fmt::Display) -> ! {
        assert!(false, "{message}");
        std::process::abort();
    }
}
