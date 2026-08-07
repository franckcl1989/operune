//! 0.2.0 Component-to-Component 链接（§40.2）：[`LinkedComponentSet`]。
//!
//! # wasmtime 36.0.13 组件依赖链接机制（研究结论，2026-08-08，源码核实）
//!
//! **结论：wasmtime 36.0.13 不存在“把已实例化组件实例的 exports 注册进
//! Linker 供另一组件 imports 解析”的宿主侧 API。** 逐项核实（registry
//! 源码 `wasmtime-36.0.13/src/runtime/component/`）：
//!
//! 1. [`wasmtime::component::Linker`]（linker.rs）的 public API 只有
//!    `new` / `engine` / `allow_shadowing` / `root` / `instance(name) ->
//!    Result<LinkerInstance>` / `substituted_component_type` / `instantiate_pre` /
//!    `instantiate` / `instantiate_async` / `define_unknown_imports_as_traps`——
//!    **没有**两参 `Linker::instance(name, &Instance)`（历史版本也不存在
//!    component 形态；旧版两参 `instance` 属于 core module 的
//!    `wasmtime::Linker`）。
//! 2. [`wasmtime::component::LinkerInstance`]（linker.rs 94-890）只提供
//!    `func_wrap*` / `func_new*` / `module` / `resource*` / `instance(name)` /
//!    `into_instance(name)`：全部是**手工逐项构建定义**，没有任何方法接受
//!    一个已实例化的 `Instance`。
//! 3. Linker 内部 `Definition` 枚举（linker.rs 104-110）只有
//!    `Instance(NameMap)` / `Func` / `Module` / `Resource`——不存在承载运行时
//!    组件实例的变体。
//! 4. 类型检查器（matching.rs 36-90）对 `TypeDef::Component(_)` 导入一律
//!    `bail!("component implementation is missing")`（组件二进制可以声明
//!    component 类型导入，但宿主 Linker 无法满足）；`TypeDef::ComponentInstance`
//!    导入只接受 `Definition::Instance`（手工构建的名字映射）。
//! 5. 组件模型的官方组合机制是**二进制级组合**：composed 组件内
//!    `(instance $c (instantiate $consumer (with "import" (instance $p))))`
//!    ——即 `wasm-tools compose` 在构建期完成接线；宿主侧只有“实例化一个
//!    已组合的组件”这一条路。组件模型规范不把已实例化组件作为可链接值。
//!
//! ## 本类型的机制：宿主侧桥接（host-mediated bridge）
//!
//! 因此 0.2.0 的 runtime-wasm 侧支持采用**桥接**：provider 成员按拓扑序
//! 先实例化（宿主 linker 定义）；consumer 成员的 Linker 为每条链接边建
//! 一个 named instance namespace，其中每个 func 导出被注册为**动态宿主
//! 函数**（`LinkerInstance::func_new`，`Val` 数组参数），闭包内部转发到
//! provider 实例的对应导出（`component::Func::call`，同步 Store）。可行使性
//! 证据（源码核实）：
//!
//! - `func_new` 的动态宿主函数跳过前置类型检查（func/host.rs
//!   `typecheck: Box::new(|_, _| Ok(()))`），签名一致性由本模块在构建期
//!   做结构校验（见 [`FuncSignature`]），调用期由 canonical ABI 动态检查；
//! - `StoreContextMut<'_, T>` 实现 `AsContextMut`（store/context.rs 137），
//!   宿主函数内可再入同一 Store 的其他组件实例（`may_leave` 仅在 canonical
//!   realloc 回调期间被清除，func/host.rs 251/294-299；func.rs 898-903）；
//! - `component::Func::call` 断言 `async_support` 关闭（func.rs 253-255）——
//!   本 crate 的 [`crate::engine::EngineConfig`] 0.1.0 不启用 async Store，
//!   契约一致；未来启用 async Store 时桥接须改走 `call_async`（文档化限制）。
//!
//! # 语义
//!
//! - **成员按激活顺序（拓扑序）**：调用方（application）把 domain 的
//!   [`ProviderGraph`](https://docs.rs/operune-domain) 快照映射为本类型的
//!   规格——`members` 数组即 `topological_order`（provider 先于 consumer），
//!   `links` 即已解析边（consumer 的 import 名 → provider 成员下标）。
//!   本类型不重新解析依赖图（§40.2 解析规则属 domain；§40.3 事实源是
//!   WIT imports/exports + Runtime Policy，两者都在 runtime-wasm 之外）。
//! - **单一执行上下文**：整个链接集合实例化进**一个** [`StoreHandle`]
//!   （桥接的 `Func` 句柄绑定该 Store；跨 Store 转发不可能）。因此集合
//!   同时只执行一个调用（§7.3 单一执行），`store_mut()` 是执行入口；
//!   每个成员实例化仍是独立执行（§7.5：实例化含 start 代码执行）。
//! - **资源治理保持（§7.3/§7.4）**：Store 经 [`crate::store::StoreFactory`]
//!   按 [`ResourceBudget`] 构建（limiter 覆盖 memory/table/instance 上限），
//!   epoch interruption 按 budget 的 `call_deadline` 在每个成员实例化前
//!   设置 deadline；调用前调用方必须 `begin_execution` + `set_deadline`
//!   （与 0.1 [`crate::store::StoreHandle`] 同一契约）。
//! - **0.1 stateless contract 保持**：本类型不承诺跨调用 instance affinity。
//!
//! # 0.2.0 里程碑边界（明确不支持，错误为 typed）
//!
//! - 链接端口只支持 **标量 primitive 类型**（bool/s8..u64/float32/float64/
//!   char）——string 与 list/record/variant/enum/option/result/flags/resource/
//!   future/stream 参数或结果在构建期以 [`LinkError::UnsupportedPortType`]
//!   拒绝（string 的跨实例 canonical ABI 传输走 realloc 路径，留待后续
//!   里程碑专门测试）；
//! - 链接项只支持 **instance（含 func 导出）与根级 func** 两种形状——
//!   resource / type / module / component / 嵌套 instance 导入以
//!   [`LinkError::UnsupportedItem`] 拒绝（宿主 Linker 无法为这些形状提供
//!   定义）；instance 内的**类型导出不需要桥接**（matching.rs 对
//!   `TypeDef::Interface` 导出跳过检查，已核实）；
//! - **根级 type 导入**同样拒绝（wasmtime 宿主 Linker 无定义 API，任何
//!   情况下都会失败——本类型给出更精确的 typed 错误）；
//! - 不支持 async Store（`Func::call` 的 sync 断言）；
//! - 每个集合一个执行上下文：0.2.0 不做“整个图的实例池化”（未来里程碑：
//!   按 budget.max_concurrent 复制整个图到 N 个 Store）。
//!
//! # 分层（§8.2）
//!
//! runtime-wasm **不依赖 domain**：本类型不 import `ProviderGraph` 等
//! domain 类型；`ProviderGraphError`（Missing/Ambiguous/IncompatibleVersion/
//! Cycle）→ 链接规格的转换在 application 层完成（§40.2 解析规则属
//! domain+policy）。runtime 侧只给出 runtime 错误（[`LinkError`]）。
//! WASI 世界 / host 函数经 [`HostLinkHook`] 由 application 注入
//!（runtime-wasi-p2 的 `add_to_linker` 即典型实现——本 crate 不 import
//! runtime-wasi-p2，§8.2/§24.2）。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use wasmtime::component::types::{ComponentFunc, ComponentItem, Type};

use crate::budget::ResourceBudget;
use crate::component::ComponentHandle;
use crate::engine::EngineHandle;
use crate::error::{ErrorSource, RuntimeError};
use crate::store::{StoreFactory, StoreHandle, StoreHostState};
use crate::wasi::{WasiAdapter, WasiPolicy};

/// 链接的 import 名（如 `test:calc/calc@1.0.0`；WIT 世界的 import instance
/// 名 = `namespace:package/interface@version`，与 domain 的
/// [`InterfaceId`](crate) 显示形态一致，application 据此映射）。
///
/// 不变量：非空（构造即校验）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LinkName(String);

impl LinkName {
    /// 构造；空名以 [`LinkError::EmptyLinkName`] 拒绝。
    pub fn new(name: impl Into<String>) -> Result<Self, LinkError> {
        let name = name.into();
        if name.is_empty() {
            return Err(LinkError::EmptyLinkName);
        }
        Ok(Self(name))
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LinkName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 一条链接边：consumer 成员的 import `import` 由 `provider` 成员（下标，
/// 激活顺序中的位置）的实例导出满足。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkSpec {
    /// consumer 声明的 import 名（其组件二进制的 WIT import 面，§40.3 事实源）。
    pub import: LinkName,
    /// provider 成员下标（必须小于 consumer 成员下标；拓扑序由调用方保证，
    /// 本类型校验）。
    pub provider: usize,
}

/// 一个成员的规格：组件 + 该成员（作为 consumer）的链接边。
pub struct MemberSpec<'a> {
    /// 已验证并编译的组件（[`ComponentHandle`]；实例化顺序 = 数组顺序）。
    pub component: &'a ComponentHandle,
    /// 该成员的导入链接边（provider 必须已排在本成员之前）。
    pub links: &'a [LinkSpec],
}

/// 宿主侧链接 hook：为**每个成员**的 Linker 追加宿主定义（§8.2 分层——
/// WASI 0.2 世界组装属 runtime-wasi-p2，host 能力按 grants 注入属
/// application；本 crate 不 import 两者）。
///
/// 受控泄漏点（同 [`crate::store::StoreHandle::store_mut`] 裁决，§8.2 的
/// MUST NOT 列表不含 runtime-wasm）：签名必须使用
/// `wasmtime::component::Linker<StoreHostState>`——WIT bindgen 生成的接口
/// 与 `Linker::instantiate` 以该类型为参数，不存在经项目自有类型间接的
/// 等价面。调用方不得把该 Linker 泄漏到 domain 公共 API。
///
/// hook 对每个成员各自调用一次（每个成员使用全新 Linker，定义互不冲突）；
/// hook 定义的名称与链接 namespace 重名时以
/// [`LinkError::LinkerDefinition`] 拒绝（deny-by-default，不静默覆盖）。
pub trait HostLinkHook: Send + Sync {
    /// 向成员 Linker 追加宿主定义（如 `runtime-wasi-p2::linker::add_to_linker`）。
    fn apply(
        &self,
        linker: &mut wasmtime::component::Linker<StoreHostState>,
    ) -> Result<(), RuntimeError>;
}

/// 链接集合规格：成员按激活顺序（拓扑序，provider 先于 consumer）。
///
/// 调用方（application）把 domain `ProviderGraph` 快照映射为
/// `members`（= `topological_order`）+ `links`（= 已解析边）。
pub struct LinkedSetSpec<'a> {
    /// 成员（激活顺序；下标被 [`LinkSpec::provider`] 引用）。
    pub members: &'a [MemberSpec<'a>],
    /// 宿主侧定义 hook（`None` = 纯 c2c：consumer 的全部导入必须被链接边
    /// 覆盖，否则 [`LinkError::UnlinkedImport`]）。
    pub host: Option<&'a dyn HostLinkHook>,
}

/// 0.2.0 组件间链接错误（§14.1：封闭、可匹配的 typed error）。
///
/// 与 domain [`ProviderGraphError`](crate) 的衔接：provider 缺失/歧义/版本
/// 不兼容在 **application 层**（graph 构建）拒绝；本类型是 runtime 侧错误——
/// 规格错误（provider 下标、未声明导入、未链接导入）、二进制面不匹配
/// （缺导出、形状不符、签名不匹配）与实例化失败（含资源超限，映射为
/// [`RuntimeError::ResourceLimit`]）。
///
/// 所有错误携带可诊断上下文（哪个 consumer、哪个 import、哪个 provider），
/// 不含机密（§16.6）；wasmtime 具体错误只装箱为 [`ErrorSource`]。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LinkError {
    /// 链接集合没有成员。
    #[error("linked component set must contain at least one member")]
    EmptySet,
    /// 链接边引用的 provider 下标越界或未排在 consumer 之前（拓扑序违反）。
    #[error(
        "link for import {import} of member {consumer} references provider member {provider} which is not ordered before its consumer"
    )]
    InvalidProvider {
        /// consumer 成员下标。
        consumer: usize,
        /// 被引用的 provider 成员下标。
        provider: usize,
        /// 该链接的 import 名。
        import: LinkName,
    },
    /// 同一 consumer 对同一 import 声明了多条链接边（拒绝歧义，§40.4 精神）。
    #[error("duplicate link for import {import} of member {consumer}")]
    DuplicateLink {
        /// consumer 成员下标。
        consumer: usize,
        /// 重复链接的 import 名。
        import: LinkName,
    },
    /// 链接边命名的 import 在 consumer 组件二进制中不存在（§40.3 事实源
    /// 不一致：规格与二进制不符）。
    #[error("member {consumer} declares no import named {import}")]
    NoSuchImport {
        /// consumer 成员下标。
        consumer: usize,
        /// 规格命名的 import。
        import: LinkName,
    },
    /// consumer 存在未被任何链接边覆盖、宿主 hook 也未提供的导入
    /// （“缺失 provider”的 runtime 侧形态；host hook 在场时由 wasmtime
    /// 判定，映射为 [`LinkError::Instantiate`]）。
    #[error(
        "member {consumer} imports {import} which is neither linked to a provider nor provided by the host"
    )]
    UnlinkedImport {
        /// consumer 成员下标。
        consumer: usize,
        /// 未链接的 import。
        import: LinkName,
    },
    /// provider 组件二进制不导出该 import 名，或导出形状与 consumer 期望不符。
    #[error(
        "provider member {provider} does not export {import} as a {expected} (found {actual}) for member {consumer}"
    )]
    MissingProviderExport {
        /// consumer 成员下标。
        consumer: usize,
        /// provider 成员下标。
        provider: usize,
        /// 缺失/形状不符的导出。
        import: LinkName,
        /// 期望的形状（"instance" / "func"）。
        expected: &'static str,
        /// 实际形状（"none" = 未导出）。
        actual: &'static str,
    },
    /// instance 形状链接中，provider 实例缺 consumer 导入的 func 导出。
    #[error(
        "provider member {provider} does not export function {export} inside {import} for member {consumer}"
    )]
    MissingFunctionExport {
        /// consumer 成员下标。
        consumer: usize,
        /// provider 成员下标。
        provider: usize,
        /// instance 形状的 import 名。
        import: LinkName,
        /// 缺失的 func 导出名。
        export: String,
    },
    /// consumer 导入 func 与 provider 导出 func 的结构签名不匹配。
    #[error(
        "interface mismatch for import {import} of member {consumer}: provider member {provider} export {export} has incompatible signature ({detail})"
    )]
    InterfaceMismatch {
        /// consumer 成员下标。
        consumer: usize,
        /// provider 成员下标。
        provider: usize,
        /// 该链接的 import 名。
        import: LinkName,
        /// 不匹配的 func 导出名。
        export: String,
        /// 诊断细节（期望 vs 实际签名）。
        detail: String,
    },
    /// 链接项形状不在 0.2.0 里程碑支持集内（resource/type/module/component/
    /// 嵌套 instance 等；宿主 Linker 无法提供定义）。
    #[error("unsupported link item for import {import} of member {consumer}: {detail}")]
    UnsupportedItem {
        /// consumer 成员下标。
        consumer: usize,
        /// 该链接的 import 名。
        import: LinkName,
        /// 诊断细节。
        detail: String,
    },
    /// 链接端口类型不在 0.2.0 里程碑支持集内（非 primitive）。
    #[error(
        "unsupported port type in import {import} of member {consumer} (export {export}): {detail}"
    )]
    UnsupportedPortType {
        /// consumer 成员下标。
        consumer: usize,
        /// 该链接的 import 名。
        import: LinkName,
        /// 含非 primitive 类型的 func 导出名。
        export: String,
        /// 诊断细节（类型描述）。
        detail: String,
    },
    /// 成员实例化失败（含 epoch deadline 到期与 wasmtime typecheck 失败；
    /// source 保留完整诊断链）。资源超限单独映射为
    /// [`RuntimeError::ResourceLimit`]（见模块文档）。
    #[error("member {member} instantiation failed: {source}")]
    Instantiate {
        /// 失败的成员下标。
        member: usize,
        /// 可诊断 source。
        #[source]
        source: ErrorSource,
    },
    /// Linker 定义冲突（通常为宿主 hook 定义了与链接 namespace 相同的名称）。
    #[error("linker definition conflict for member {member}: {source}")]
    LinkerDefinition {
        /// 冲突的成员下标。
        member: usize,
        /// 可诊断 source。
        #[source]
        source: ErrorSource,
    },
    /// 规格内部不一致（本类型防御性校验；正常调用不可达）。
    #[error("invalid linked set specification: {0}")]
    InvalidSpec(&'static str),
    /// 链接名称为空。
    #[error("link name must not be empty")]
    EmptyLinkName,
}

/// 组件 func 的“形状”描述（诊断用）。
fn item_desc(item: &ComponentItem) -> &'static str {
    match item {
        ComponentItem::ComponentFunc(_) => "func",
        ComponentItem::CoreFunc(_) => "core-func",
        ComponentItem::Module(_) => "module",
        ComponentItem::Component(_) => "component",
        ComponentItem::ComponentInstance(_) => "instance",
        ComponentItem::Type(_) => "type",
        ComponentItem::Resource(_) => "resource",
    }
}

/// 链接端口的 primitive 类型（0.2.0 里程碑支持集；§8.2：项目自有类型，
/// wasmtime 类型不泄漏）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PortType {
    Bool,
    S8,
    U8,
    S16,
    U16,
    S32,
    U32,
    S64,
    U64,
    Float32,
    Float64,
    Char,
}

impl PortType {
    /// 规范化映射；不支持的类型返回其描述（诊断用）。
    fn from_wasmtime(ty: &Type) -> Result<Self, &'static str> {
        Ok(match ty {
            Type::Bool => Self::Bool,
            Type::S8 => Self::S8,
            Type::U8 => Self::U8,
            Type::S16 => Self::S16,
            Type::U16 => Self::U16,
            Type::S32 => Self::S32,
            Type::U32 => Self::U32,
            Type::S64 => Self::S64,
            Type::U64 => Self::U64,
            Type::Float32 => Self::Float32,
            Type::Float64 => Self::Float64,
            Type::Char => Self::Char,
            // string 明确不在 0.2.0 里程碑支持集：Val::String 的跨实例
            // canonical ABI 传输会走 realloc 路径（may_leave 限制与内存
            // 生命周期细节需专门测试），留待后续里程碑。
            Type::String => return Err("string"),
            Type::List(_) => return Err("list"),
            Type::Record(_) => return Err("record"),
            Type::Tuple(_) => return Err("tuple"),
            Type::Variant(_) => return Err("variant"),
            Type::Enum(_) => return Err("enum"),
            Type::Option(_) => return Err("option"),
            Type::Result(_) => return Err("result"),
            Type::Flags(_) => return Err("flags"),
            Type::Own(_) => return Err("own-resource"),
            Type::Borrow(_) => return Err("borrow-resource"),
            Type::Future(_) => return Err("future"),
            Type::Stream(_) => return Err("stream"),
            Type::ErrorContext => return Err("error-context"),
        })
    }
}

/// 链接 func 的结构签名（参数/结果类型序列；名称是 WIT 元数据，不参与
/// canonical ABI，比较只按类型序列，§22.2 canonical ABI）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct FuncSignature {
    params: Vec<PortType>,
    results: Vec<PortType>,
}

impl fmt::Display for FuncSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(")?;
        for (i, param) in self.params.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{param:?}")?;
        }
        write!(f, ") -> (")?;
        for (i, result) in self.results.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{result:?}")?;
        }
        write!(f, ")")
    }
}

impl FuncSignature {
    /// 从组件类型面的 ComponentFunc 规范化（参数/结果逐个映射；不支持类型
    /// 返回其描述）。
    fn from_component_func(func: &ComponentFunc) -> Result<Self, &'static str> {
        let mut params = Vec::new();
        for (_, ty) in func.params() {
            params.push(PortType::from_wasmtime(&ty)?);
        }
        let mut results = Vec::new();
        for ty in func.results() {
            results.push(PortType::from_wasmtime(&ty)?);
        }
        Ok(Self { params, results })
    }
}

/// 链接项的导出形状。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemShape {
    /// 根级 func 导入（`(import "name" (func ...))`）。
    RootFunc,
    /// instance 导入（`(import "name" (instance ...))`）。
    Instance,
}

impl ItemShape {
    fn expected_desc(self) -> &'static str {
        match self {
            Self::RootFunc => "func",
            Self::Instance => "instance",
        }
    }
}

/// 一条已校验链接边的桥接计划。
#[derive(Debug)]
struct PlannedLink {
    import: LinkName,
    /// provider 成员下标（实例化期取运行时句柄）。
    provider: usize,
    shape: ItemShape,
    /// 需要桥接的 func 导出（RootFunc 形状恰一项，export == import 名）。
    funcs: Vec<PlannedFunc>,
}

/// 一个 func 导出的桥接计划（名称；结构签名在构建期校验，运行时
/// `func_new` 为动态分派，无需再携带）。
#[derive(Debug)]
struct PlannedFunc {
    export: String,
}

/// 一个成员的桥接计划（构建期校验完成；桥接句柄在实例化期取得）。
#[derive(Debug)]
struct MemberPlan {
    links: Vec<PlannedLink>,
}

/// 0.2.0 组件链接集合（§40.2/§7.3）：provider 成员 + consumer 成员按拓扑序
/// 实例化，consumer 的 imports 由 provider 实例的 exports 经宿主桥接满足。
///
/// 机制与 wasmtime 36.0.13 的能力边界见模块文档。语义：
/// - **单一执行上下文**：整个集合在一个 Store 内实例化与执行（§7.3 单一
///   执行）；[`LinkedComponentSet::store_mut`] 是执行入口；
/// - **资源治理（§7.3/§7.4）**：Store 按预算构建（limiter），实例化期
///   按 `budget.call_deadline` 设置 epoch deadline（start 代码执行受控）；
/// - **确定性（§40.4）**：校验与报错按成员数组顺序（调用方从 domain 的
///   确定性 graph 映射而来），同一规格得到同一结果；
/// - 构建失败即整体拒绝：部分实例化随本类型丢弃（Store 不泄漏，同
///   [`crate::instance::InstanceSet`] 语义）。
pub struct LinkedComponentSet {
    store: StoreHandle,
    instances: Vec<wasmtime::component::Instance>,
}

impl LinkedComponentSet {
    /// 构建链接集合：成员按激活顺序实例化（provider 先于 consumer），
    /// consumer 导入由 provider 实例导出桥接满足。Store 无任何 WASI/宿主
    /// 能力（§7.6 deny-by-default；宿主定义经 [`LinkedSetSpec::host`] 注入）。
    ///
    /// 错误：规格/二进制面校验失败 → [`LinkError`]；Store 构建失败 →
    /// [`RuntimeError::Store`]；成员实例化超限 → [`RuntimeError::ResourceLimit`]；
    /// 其余实例化失败 → [`LinkError::Instantiate`]。
    pub fn new(
        engine: &EngineHandle,
        budget: &ResourceBudget,
        spec: &LinkedSetSpec<'_>,
    ) -> Result<Self, RuntimeError> {
        Self::build(engine, budget, spec, None)
    }

    /// 构建链接集合，并按 policy 显式附加 WASI 能力（§7.6/§17.2；WASI
    /// 0.2 上下文经 [`crate::wasi::WasiAdapter`] 安装）。WASI 世界的
    /// linker 组装仍由调用方经 [`LinkedSetSpec::host`] 提供（§8.2/§24.2：
    /// 本 crate 不 import runtime-wasi-p2）。
    ///
    /// 错误：同 [`LinkedComponentSet::new`]；WASI 版本不一致或 attach 失败
    /// → [`RuntimeError::Wasi`]（fail closed）。
    pub fn new_with_wasi(
        engine: &EngineHandle,
        budget: &ResourceBudget,
        adapter: &dyn WasiAdapter,
        policy: &WasiPolicy,
        spec: &LinkedSetSpec<'_>,
    ) -> Result<Self, RuntimeError> {
        let factory =
            StoreFactory::with_wasi(engine, adapter, policy).map_err(RuntimeError::Wasi)?;
        Self::build(engine, budget, spec, Some(factory))
    }

    fn build(
        engine: &EngineHandle,
        budget: &ResourceBudget,
        spec: &LinkedSetSpec<'_>,
        factory: Option<StoreFactory<'_>>,
    ) -> Result<Self, RuntimeError> {
        if spec.members.is_empty() {
            return Err(RuntimeError::Link(LinkError::EmptySet));
        }
        let store = match factory {
            Some(factory) => factory.new_store(budget)?,
            None => StoreFactory::new(engine).new_store(budget)?,
        };
        let mut set = Self {
            store,
            instances: Vec::new(),
        };
        for member in 0..spec.members.len() {
            let plan = plan_member(engine, spec, member, spec.host.is_some())?;
            let instance = set.instantiate_member(engine, budget, spec, &plan, member)?;
            set.instances.push(instance);
        }
        Ok(set)
    }

    /// 成员数量（= 激活顺序长度）。
    pub fn member_count(&self) -> usize {
        self.instances.len()
    }

    /// 成员实例的只读句柄（受控泄漏点：`wasmtime::component::Instance`
    /// 绑定本集合的 Store；用于 typed invoke 扩展缝，同
    /// [`crate::store::StoreHandle::store_mut`] 的裁决——调用方不得把
    /// 返回句柄再暴露到领域层公共 API）。
    ///
    /// 下标越界返回 `None`（调用方以 [`LinkedComponentSet::member_count`]
    /// 判定范围）。
    pub fn instance(&self, member: usize) -> Option<&wasmtime::component::Instance> {
        self.instances.get(member)
    }

    /// 执行入口（受控泄漏点，同
    /// [`crate::store::StoreHandle::store_mut`]）：每次不可信执行前调用方
    /// 必须 `begin_execution` + `set_deadline`（§7.5；epoch 启用时默认
    /// deadline 为 0 立即 trap）。实例/typed func 的查找与调用经
    /// [`LinkedComponentSet::instance`] + 本入口进行。
    pub fn store_mut(&mut self) -> &mut StoreHandle {
        &mut self.store
    }

    /// 实例化一个成员（计划校验已由 [`plan_member`] 完成）：
    /// 宿主 hook → 链接桥接 → deadline → 实例化。
    fn instantiate_member(
        &mut self,
        engine: &EngineHandle,
        budget: &ResourceBudget,
        spec: &LinkedSetSpec<'_>,
        plan: &MemberPlan,
        member: usize,
    ) -> Result<wasmtime::component::Instance, RuntimeError> {
        let mut linker = wasmtime::component::Linker::<StoreHostState>::new(engine.engine());
        if let Some(hook) = spec.host {
            hook.apply(&mut linker)?;
        }
        for link in &plan.links {
            let provider_instance = self.instances.get(link.provider).ok_or_else(|| {
                RuntimeError::Link(LinkError::InvalidSpec("provider not instantiated"))
            })?;
            match link.shape {
                ItemShape::RootFunc => {
                    if link.funcs.is_empty() {
                        return Err(RuntimeError::Link(LinkError::InvalidSpec(
                            "root func link without func",
                        )));
                    }
                    let func = provider_instance
                        .get_func(self.store.store_mut(), link.import.as_str())
                        .ok_or_else(|| {
                            RuntimeError::Link(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::RootFunc.expected_desc(),
                                actual: "none",
                            })
                        })?;
                    linker
                        .root()
                        .func_new(link.import.as_str(), bridge_closure(func))
                        .map_err(|source| {
                            RuntimeError::Link(LinkError::LinkerDefinition {
                                member,
                                source: ErrorSource::from(source),
                            })
                        })?;
                }
                ItemShape::Instance => {
                    let (_, instance_index) = provider_instance
                        .get_export(self.store.store_mut(), None, link.import.as_str())
                        .ok_or_else(|| {
                            RuntimeError::Link(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::Instance.expected_desc(),
                                actual: "none",
                            })
                        })?;
                    let mut namespace =
                        linker.instance(link.import.as_str()).map_err(|source| {
                            RuntimeError::Link(LinkError::LinkerDefinition {
                                member,
                                source: ErrorSource::from(source),
                            })
                        })?;
                    for planned in &link.funcs {
                        let (_, func_index) = provider_instance
                            .get_export(
                                self.store.store_mut(),
                                Some(&instance_index),
                                &planned.export,
                            )
                            .ok_or_else(|| {
                                RuntimeError::Link(LinkError::MissingFunctionExport {
                                    consumer: member,
                                    provider: link.provider,
                                    import: link.import.clone(),
                                    export: planned.export.clone(),
                                })
                            })?;
                        let func = provider_instance
                            .get_func(self.store.store_mut(), func_index)
                            .ok_or_else(|| {
                                RuntimeError::Link(LinkError::MissingFunctionExport {
                                    consumer: member,
                                    provider: link.provider,
                                    import: link.import.clone(),
                                    export: planned.export.clone(),
                                })
                            })?;
                        namespace
                            .func_new(&planned.export, bridge_closure(func))
                            .map_err(|source| {
                                RuntimeError::Link(LinkError::LinkerDefinition {
                                    member,
                                    source: ErrorSource::from(source),
                                })
                            })?;
                    }
                }
            }
        }
        // §7.5：实例化会执行 guest start 代码——按预算设置 epoch deadline
        //（call_deadline 为 None = 显式无期限，与 0.1 执行期语义一致）。
        if engine.config().epoch_interruption {
            match budget.call_deadline {
                Some(deadline) => self.store.set_deadline(deadline)?,
                None => self.store.reset_deadline()?,
            }
        }
        self.store.begin_execution();
        let component = spec
            .members
            .get(member)
            .ok_or_else(|| RuntimeError::Link(LinkError::InvalidSpec("member out of range")))?
            .component;
        match linker.instantiate(self.store.store_mut(), component.component()) {
            Ok(instance) => Ok(instance),
            Err(error) => {
                let source: ErrorSource = error.into();
                if let Some(kind) = self.store.take_rejection() {
                    return Err(RuntimeError::ResourceLimit { kind, source });
                }
                Err(RuntimeError::Link(LinkError::Instantiate {
                    member,
                    source,
                }))
            }
        }
    }
}

/// 桥接宿主函数：把对 consumer import 的调用转发到 provider 实例的导出
///（`Val` 数组直通；同步 Store 的 `Func::call`——模块文档已核实
/// `async_support` 关闭的前置条件）。
///
/// **post-return 契约**（源码核实，func/typed.rs 文档 + func.rs
/// `with_lower_context`）：每次成功调用后必须调用 `Func::post_return` 才能
/// 重置目标实例的 `may_enter` 锁——否则该实例在本 Store 内永远不可再进入
///（`Trap::CannotEnterComponent`，func.rs 875-915：`may_enter` 在进入时清零、
/// 只在 post-return 成功后恢复；调用失败时实例保持锁定，post_return 不调用）。
/// 调用失败（含 guest trap / epoch 中断）返回错误后不再调用 post_return，
/// provider 实例按 wasmtime 语义保持锁定——调用方（application）须以
/// “trap 后该集合内的实例不可复用”处理（同 0.1 的直接调用语义）。
fn bridge_closure(
    func: wasmtime::component::Func,
) -> impl Fn(
    wasmtime::StoreContextMut<'_, StoreHostState>,
    &[wasmtime::component::Val],
    &mut [wasmtime::component::Val],
) -> wasmtime::Result<()>
+ Send
+ Sync
+ 'static {
    move |mut store, params, results| {
        func.call(&mut store, params, results)?;
        func.post_return(store)
    }
}

/// 构建期校验一个成员的链接计划（纯类型面，无 Store 依赖）：
/// 规格一致性（provider 顺序/范围、import 存在性、无重复边、无未链接
/// 导入）+ 二进制面匹配（provider 导出形状、每个 func 的结构签名）。
///
/// 错误顺序：按 `members[member].links` 的顺序 fail-fast（调用方从 domain
/// 的确定性 graph 映射规格，§40.4 确定性保持）。
fn plan_member(
    engine: &EngineHandle,
    spec: &LinkedSetSpec<'_>,
    member: usize,
    host_present: bool,
) -> Result<MemberPlan, LinkError> {
    let member_spec = spec
        .members
        .get(member)
        .ok_or(LinkError::InvalidSpec("member index out of range"))?;

    // §40.3：consumer 的导入面来自组件二进制（WIT imports）。
    let mut imports: BTreeMap<String, ComponentItem> = BTreeMap::new();
    for (name, item) in member_spec
        .component
        .component()
        .component_type()
        .imports(engine.engine())
    {
        imports.insert(name.to_owned(), item);
    }

    let mut links = Vec::new();
    let mut covered: BTreeSet<String> = BTreeSet::new();
    for link in member_spec.links {
        if !covered.insert(link.import.as_str().to_owned()) {
            return Err(LinkError::DuplicateLink {
                consumer: member,
                import: link.import.clone(),
            });
        }
        if link.provider >= member {
            return Err(LinkError::InvalidProvider {
                consumer: member,
                provider: link.provider,
                import: link.import.clone(),
            });
        }
        let expected =
            imports
                .get(link.import.as_str())
                .ok_or_else(|| LinkError::NoSuchImport {
                    consumer: member,
                    import: link.import.clone(),
                })?;
        let provider_ty = spec
            .members
            .get(link.provider)
            .ok_or(LinkError::InvalidSpec("provider index out of range"))?;
        let provider_export = provider_ty
            .component
            .component()
            .component_type()
            .get_export(engine.engine(), link.import.as_str());
        let planned =
            match expected {
                ComponentItem::ComponentInstance(expected_instance) => {
                    let provider_instance_ty = match provider_export {
                        Some(ComponentItem::ComponentInstance(instance_ty)) => instance_ty,
                        Some(other) => {
                            return Err(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::Instance.expected_desc(),
                                actual: item_desc(&other),
                            });
                        }
                        None => {
                            return Err(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::Instance.expected_desc(),
                                actual: "none",
                            });
                        }
                    };
                    let mut funcs = Vec::new();
                    for (export_name, export_item) in expected_instance.exports(engine.engine()) {
                        let expected_func = match export_item {
                            ComponentItem::ComponentFunc(func) => func,
                            // 类型导出不需要桥接（matching.rs 对 TypeDef::Interface
                            // 跳过检查；已核实）。
                            ComponentItem::Type(_) => continue,
                            other => {
                                return Err(LinkError::UnsupportedItem {
                                    consumer: member,
                                    import: link.import.clone(),
                                    detail: format!(
                                        "linked instance export `{export_name}` is a {}",
                                        item_desc(&other)
                                    ),
                                });
                            }
                        };
                        let expected_sig = FuncSignature::from_component_func(&expected_func)
                            .map_err(|desc| LinkError::UnsupportedPortType {
                                consumer: member,
                                import: link.import.clone(),
                                export: export_name.to_owned(),
                                detail: desc.to_owned(),
                            })?;
                        let provider_func =
                            match provider_instance_ty.get_export(engine.engine(), export_name) {
                                Some(ComponentItem::ComponentFunc(func)) => func,
                                Some(other) => {
                                    return Err(LinkError::InterfaceMismatch {
                                        consumer: member,
                                        provider: link.provider,
                                        import: link.import.clone(),
                                        export: export_name.to_owned(),
                                        detail: format!(
                                            "provider instance export is a {}",
                                            item_desc(&other)
                                        ),
                                    });
                                }
                                None => {
                                    return Err(LinkError::MissingFunctionExport {
                                        consumer: member,
                                        provider: link.provider,
                                        import: link.import.clone(),
                                        export: export_name.to_owned(),
                                    });
                                }
                            };
                        let provider_sig = FuncSignature::from_component_func(&provider_func)
                            .map_err(|desc| LinkError::UnsupportedPortType {
                                consumer: member,
                                import: link.import.clone(),
                                export: export_name.to_owned(),
                                detail: desc.to_owned(),
                            })?;
                        if provider_sig != expected_sig {
                            return Err(LinkError::InterfaceMismatch {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                export: export_name.to_owned(),
                                detail: format!(
                                    "expected {expected_sig}, provider exports {provider_sig}"
                                ),
                            });
                        }
                        funcs.push(PlannedFunc {
                            export: export_name.to_owned(),
                        });
                    }
                    PlannedLink {
                        import: link.import.clone(),
                        provider: link.provider,
                        shape: ItemShape::Instance,
                        funcs,
                    }
                }
                ComponentItem::ComponentFunc(expected_func) => {
                    let expected_sig =
                        FuncSignature::from_component_func(expected_func).map_err(|desc| {
                            LinkError::UnsupportedPortType {
                                consumer: member,
                                import: link.import.clone(),
                                export: link.import.as_str().to_owned(),
                                detail: desc.to_owned(),
                            }
                        })?;
                    let provider_func = match provider_export {
                        Some(ComponentItem::ComponentFunc(func)) => func,
                        Some(other) => {
                            return Err(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::RootFunc.expected_desc(),
                                actual: item_desc(&other),
                            });
                        }
                        None => {
                            return Err(LinkError::MissingProviderExport {
                                consumer: member,
                                provider: link.provider,
                                import: link.import.clone(),
                                expected: ItemShape::RootFunc.expected_desc(),
                                actual: "none",
                            });
                        }
                    };
                    let provider_sig =
                        FuncSignature::from_component_func(&provider_func).map_err(|desc| {
                            LinkError::UnsupportedPortType {
                                consumer: member,
                                import: link.import.clone(),
                                export: link.import.as_str().to_owned(),
                                detail: desc.to_owned(),
                            }
                        })?;
                    if provider_sig != expected_sig {
                        return Err(LinkError::InterfaceMismatch {
                            consumer: member,
                            provider: link.provider,
                            import: link.import.clone(),
                            export: link.import.as_str().to_owned(),
                            detail: format!(
                                "expected {expected_sig}, provider exports {provider_sig}"
                            ),
                        });
                    }
                    PlannedLink {
                        import: link.import.clone(),
                        provider: link.provider,
                        shape: ItemShape::RootFunc,
                        funcs: vec![PlannedFunc {
                            export: link.import.as_str().to_owned(),
                        }],
                    }
                }
                other => {
                    return Err(LinkError::UnsupportedItem {
                        consumer: member,
                        import: link.import.clone(),
                        detail: format!("import is a {}", item_desc(other)),
                    });
                }
            };
        links.push(planned);
    }

    // 未链接的导入（“缺失 provider”）：宿主 hook 在场时交由 wasmtime 判定。
    if !host_present {
        for name in imports.keys() {
            if !covered.contains(name) {
                return Err(LinkError::UnlinkedImport {
                    consumer: member,
                    import: LinkName(name.clone()),
                });
            }
        }
    }
    Ok(MemberPlan { links })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WasmFailure;
    use crate::budget::{ByteSize, CallDeadline, LinearMemoryLimit};
    use crate::error::classify_wasm_error;
    use crate::test_support::{self, engine, expect_ok, expect_some, test_failure};
    use std::time::Duration;

    /// provider：导出 `test:calc/calc@1.0.0` instance（add/sub，primitive）。
    ///
    /// 语法注（探针验证）：组件级 `(export ...)` 的导出值必须是 index/identifier
    /// 引用（内联 `(instance (export ...))` 不被 wasmtime 36 的 wat 解析器接受），
    /// 因此先定义命名 instance 再导出。
    const PROVIDER_ADD_WAT: &str = r#"(component
        (core module $m
            (memory (export "memory") 1)
            (func (export "add") (param i32 i32) (result i32)
                (i32.add (local.get 0) (local.get 1)))
            (func (export "sub") (param i32 i32) (result i32)
                (i32.sub (local.get 0) (local.get 1))))
        (core instance $i (instantiate $m))
        (func $add (param "a" s32) (param "b" s32) (result s32)
            (canon lift (core func $i "add")))
        (func $sub (param "a" s32) (param "b" s32) (result s32)
            (canon lift (core func $i "sub")))
        (instance $calc
            (export "add" (func $add))
            (export "sub" (func $sub)))
        (export "test:calc/calc@1.0.0" (instance $calc))
    )"#;

    /// consumer：导入 `test:calc/calc@1.0.0` 的 add，导出 run = add(20, 22)。
    const CONSUMER_ADD_CALLER_WAT: &str = r#"(component
        (import "test:calc/calc@1.0.0" (instance $calc
            (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
        (core func $calc_add (canon lower (func $calc "add")))
        (core module $m
            (import "calc" "add" (func $add (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                (call $add (i32.const 20) (i32.const 22))))
        (core instance $i (instantiate $m
            (with "calc" (instance (export "add" (func $calc_add))))))
        (func (export "run") (result s32) (canon lift (core func $i "run")))
    )"#;

    /// 接口不匹配的 consumer：期望 add 只有一个参数。
    const CONSUMER_ADD_MISMATCH_WAT: &str = r#"(component
        (import "test:calc/calc@1.0.0" (instance $calc
            (export "add" (func (param "a" s32) (result s32)))))
    )"#;

    /// 形状不符的 provider：把 interface 名导出为根级 func。
    const PROVIDER_WRONG_SHAPE_WAT: &str = r#"(component
        (core module $m (func (export "f") (result i32) (i32.const 1)))
        (core instance $i (instantiate $m))
        (func $f (result s32) (canon lift (core func $i "f")))
        (export "test:calc/calc@1.0.0" (func $f))
    )"#;

    /// 未链接导入的 consumer：导入一个没有任何链接边覆盖的 interface。
    const CONSUMER_UNLINKED_WAT: &str = r#"(component
        (import "other:calc/calc@1.0.0" (instance $calc
            (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
    )"#;

    /// 非 primitive 端口的 consumer（string 参数 → UnsupportedPortType）。
    const CONSUMER_STRING_WAT: &str = r#"(component
        (import "test:calc/calc@1.0.0" (instance $calc
            (export "greet" (func (param "name" string) (result s32)))))
    )"#;

    /// provider：导出 `test:calc/spin@1.0.0` instance（spin = 无限循环）。
    const PROVIDER_SPIN_WAT: &str = r#"(component
        (core module $m
            (memory (export "memory") 1)
            (func (export "spin") (loop $l (br $l))))
        (core instance $i (instantiate $m))
        (func $spin (canon lift (core func $i "spin")))
        (instance $spin_iface (export "spin" (func $spin)))
        (export "test:calc/spin@1.0.0" (instance $spin_iface))
    )"#;

    /// consumer：导入 spin 并导出 run（调用一次 spin）。
    const CONSUMER_SPIN_CALLER_WAT: &str = r#"(component
        (import "test:calc/spin@1.0.0" (instance $spin
            (export "spin" (func))))
        (core func $cspin (canon lower (func $spin "spin")))
        (core module $m
            (import "spin" "spin" (func $spin))
            (memory (export "memory") 1)
            (func (export "run") (call $spin)))
        (core instance $i (instantiate $m
            (with "spin" (instance (export "spin" (func $cspin))))))
        (func (export "run") (canon lift (core func $i "run")))
    )"#;

    /// provider A：导出 `test:calc/calc@1.0.0` instance（add）。
    const PROVIDER_A_ADD_WAT: &str = r#"(component
        (core module $m
            (memory (export "memory") 1)
            (func (export "add") (param i32 i32) (result i32)
                (i32.add (local.get 0) (local.get 1))))
        (core instance $i (instantiate $m))
        (func $add (param "a" s32) (param "b" s32) (result s32)
            (canon lift (core func $i "add")))
        (instance $calc (export "add" (func $add)))
        (export "test:calc/calc@1.0.0" (instance $calc))
    )"#;

    /// provider B：导入 add，导出 `test:calc/mul@1.0.0` instance（mul = add(a,b)+b）。
    const PROVIDER_B_MUL_WAT: &str = r#"(component
        (import "test:calc/calc@1.0.0" (instance $calc
            (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
        (core func $calc_add (canon lower (func $calc "add")))
        (core module $m
            (import "calc" "add" (func $add (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "mul") (param i32 i32) (result i32)
                (i32.add (call $add (local.get 0) (local.get 1)) (local.get 1))))
        (core instance $i (instantiate $m
            (with "calc" (instance (export "add" (func $calc_add))))))
        (func $mul (export "mul") (param "a" s32) (param "b" s32) (result s32)
            (canon lift (core func $i "mul")))
        (instance $mul_iface (export "mul" (func $mul)))
        (export "test:calc/mul@1.0.0" (instance $mul_iface))
    )"#;

    /// consumer C：导入 mul，导出 run = mul(3, 4)（= add(3,4)+4 = 11）。
    const CONSUMER_C_MUL_WAT: &str = r#"(component
        (import "test:calc/mul@1.0.0" (instance $mul
            (export "mul" (func (param "a" s32) (param "b" s32) (result s32)))))
        (core func $cmul (canon lower (func $mul "mul")))
        (core module $m
            (import "mul" "mul" (func $mul (param i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                (call $mul (i32.const 3) (i32.const 4))))
        (core instance $i (instantiate $m
            (with "mul" (instance (export "mul" (func $cmul))))))
        (func (export "run") (result s32) (canon lift (core func $i "run")))
    )"#;

    /// 依赖宿主 hook 的 consumer：导入根级 func `host-echo`。
    const CONSUMER_HOST_ECHO_WAT: &str = r#"(component
        (import "host-echo" (func $echo (param "x" s32) (result s32)))
        (core func $cecho (canon lower (func $echo)))
        (core module $m
            (import "" "echo" (func $echo (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (result i32)
                (call $echo (i32.const 41))))
        (core instance $i (instantiate $m
            (with "" (instance (export "echo" (func $cecho))))))
        (func (export "run") (result s32) (canon lift (core func $i "run")))
    )"#;

    /// 大内存 consumer（core module 2 pages；预算测试用）。
    const CONSUMER_BIG_MEMORY_WAT: &str = r#"(component
        (core module $m (memory 2))
        (core instance $i (instantiate $m))
    )"#;

    /// 用与集合相同的 Engine 编译夹具（§7.2：Component 与 Engine 绑定，
    /// 跨 Engine 实例化不支持）。
    fn compile(engine: &EngineHandle, wat: &str) -> ComponentHandle {
        expect_ok(
            ComponentHandle::new(engine, wat.as_bytes()),
            "fixture compile",
        )
    }

    fn name(import: &str) -> LinkName {
        expect_ok(LinkName::new(import), "link name")
    }

    #[test]
    fn linked_set_bridges_provider_exports_to_consumer_imports() {
        // §40.2 闭环：consumer 的 import 由 provider 实例导出满足，调用透传
        // 正确（add(20, 22) = 42）；provider 实例自身的导出也可直接调用。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_CALLER_WAT);
        let links = [LinkSpec {
            import: name("test:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let mut set = expect_ok(
            LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec),
            "linked set build",
        );
        assert_eq!(set.member_count(), 2);

        // 调用前契约（§7.5/§7.3）：deadline + 清拒绝记录。
        expect_ok(
            set.store_mut()
                .set_deadline(CallDeadline::new(Duration::from_secs(1))),
            "set deadline",
        );
        set.store_mut().begin_execution();

        // provider 实例自身的导出（嵌套 instance 内的 add）。
        // Instance 是 Copy 句柄：复制出来，避免与 store_mut 的借用冲突。
        let provider_instance = *expect_some(set.instance(0), "provider instance");
        {
            let store = set.store_mut().store_mut();
            let (_, instance_index) = expect_some(
                provider_instance.get_export(&mut *store, None, "test:calc/calc@1.0.0"),
                "provider instance export",
            );
            let (_, add_index) = expect_some(
                provider_instance.get_export(&mut *store, Some(&instance_index), "add"),
                "provider add export",
            );
            let add = expect_some(
                provider_instance.get_func(&mut *store, add_index),
                "provider add func",
            );
            let typed = expect_ok(add.typed::<(i32, i32), (i32,)>(&*store), "add typed");
            match typed.call(&mut *store, (1, 2)) {
                Ok((sum,)) => {
                    assert_eq!(sum, 3, "provider add must return 1 + 2");
                    // post-return 契约：每次成功调用后必须 post_return 重置
                    // 实例的 may_enter 锁，否则后续调用 CannotEnterComponent。
                    expect_ok(typed.post_return(&mut *store), "provider add post_return");
                }
                Err(e) => test_failure(format_args!("provider add call failed: {e}")),
            }
        }

        // consumer 的 run 经桥接调用 provider 的 add。
        let consumer_instance = *expect_some(set.instance(1), "consumer instance");
        {
            let run = expect_ok(
                consumer_instance.get_typed_func::<(), (i32,)>(set.store_mut().store_mut(), "run"),
                "run lookup",
            );
            match run.call(set.store_mut().store_mut(), ()) {
                Ok((sum,)) => {
                    assert_eq!(sum, 42, "run must return add(20, 22) = 42");
                    // post-return 契约（见 bridge_closure 文档）。
                    let _ = run.post_return(set.store_mut().store_mut());
                }
                Err(e) => test_failure(format_args!("run call failed: {e}")),
            }
        }
    }

    #[test]
    fn linked_set_supports_chain_in_topological_order() {
        // §40.2 激活顺序：A（provider）→ B（provider+consumer）→ C（consumer）；
        // 中间节点既消费上游又提供给下游。
        let engine = engine();
        let a = compile(&engine, PROVIDER_A_ADD_WAT);
        let b = compile(&engine, PROVIDER_B_MUL_WAT);
        let c = compile(&engine, CONSUMER_C_MUL_WAT);
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &a,
                    links: &[],
                },
                MemberSpec {
                    component: &b,
                    links: &[LinkSpec {
                        import: name("test:calc/calc@1.0.0"),
                        provider: 0,
                    }],
                },
                MemberSpec {
                    component: &c,
                    links: &[LinkSpec {
                        import: name("test:calc/mul@1.0.0"),
                        provider: 1,
                    }],
                },
            ],
            host: None,
        };
        let mut set = expect_ok(
            LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec),
            "linked chain build",
        );
        expect_ok(
            set.store_mut()
                .set_deadline(CallDeadline::new(Duration::from_secs(1))),
            "set deadline",
        );
        set.store_mut().begin_execution();
        let consumer = *expect_some(set.instance(2), "consumer instance");
        let run = expect_ok(
            consumer.get_typed_func::<(), (i32,)>(set.store_mut().store_mut(), "run"),
            "run lookup",
        );
        // mul(3, 4) = add(3, 4) + 4 = 11。
        match run.call(set.store_mut().store_mut(), ()) {
            Ok((product,)) => {
                assert_eq!(product, 11);
                let _ = run.post_return(set.store_mut().store_mut());
            }
            Err(e) => test_failure(format_args!("chain run call failed: {e}")),
        }
    }

    #[test]
    fn linked_set_rejects_missing_provider_export() {
        // 接口在 consumer 声明、链接边存在，但 provider 二进制不导出该
        // interface（或形状不符）→ 构建期 typed 拒绝。
        let engine = engine();
        // 形状不符：provider 把 interface 名导出为根级 func。
        let provider = compile(&engine, PROVIDER_WRONG_SHAPE_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_CALLER_WAT);
        let links = [LinkSpec {
            import: name("test:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("wrong-shape provider must be rejected"),
            Err(RuntimeError::Link(LinkError::MissingProviderExport {
                consumer: 1,
                provider: 0,
                expected: "instance",
                actual: "func",
                ..
            })) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }

        // 未导出：provider 根本不提供该 interface 名（链接 consumer 真实声明的
        // import 名）。
        let provider = compile(&engine, PROVIDER_A_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_UNLINKED_WAT);
        let links = [LinkSpec {
            import: name("other:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("missing provider export must be rejected"),
            Err(RuntimeError::Link(LinkError::MissingProviderExport { .. })) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_unlinked_import_without_host_hook() {
        // consumer 导入未被任何链接边覆盖、也无宿主 hook → UnlinkedImport
        //（“缺失 provider”的 runtime 侧形态）。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_UNLINKED_WAT);
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                // 不链接任何导入：consumer 的 other:calc/calc@1.0.0 无 provider、
                // 无宿主 hook → UnlinkedImport。
                component: &consumer,
                links: &[],
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("unlinked import must be rejected"),
            Err(RuntimeError::Link(LinkError::UnlinkedImport {
                consumer: 1,
                import,
            })) => {
                assert_eq!(import, name("other:calc/calc@1.0.0"));
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_interface_mismatch() {
        // consumer 期望 add(param s32) -> s32，provider 提供 add(param s32 s32)
        // -> s32 → InterfaceMismatch（结构签名比较，构建期拒绝）。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_MISMATCH_WAT);
        let links = [LinkSpec {
            import: name("test:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("interface mismatch must be rejected"),
            Err(RuntimeError::Link(LinkError::InterfaceMismatch {
                consumer: 1,
                provider: 0,
                export,
                detail,
                ..
            })) => {
                assert_eq!(export, "add");
                assert!(detail.contains("provider exports"), "detail: {detail}");
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_unsupported_port_type() {
        // string 端口超出 0.2.0 primitive 里程碑 → UnsupportedPortType。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_STRING_WAT);
        let links = [LinkSpec {
            import: name("test:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("unsupported port type must be rejected"),
            Err(RuntimeError::Link(LinkError::UnsupportedPortType { export, detail, .. })) => {
                assert_eq!(export, "greet");
                assert_eq!(detail, "string");
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_invalid_provider_order() {
        // 拓扑序违反：provider 下标 >= consumer 下标 → InvalidProvider。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_CALLER_WAT);
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &consumer,
                    links: &[LinkSpec {
                        import: name("test:calc/calc@1.0.0"),
                        provider: 1,
                    }],
                },
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
            ],
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("out-of-order provider must be rejected"),
            Err(RuntimeError::Link(LinkError::InvalidProvider {
                consumer: 0,
                provider: 1,
                ..
            })) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_no_such_import_and_duplicate_link() {
        // 链接边命名的 import 不存在于 consumer 二进制 → NoSuchImport。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_CALLER_WAT);
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
                MemberSpec {
                    component: &consumer,
                    links: &[LinkSpec {
                        import: name("test:calc/nope@9.9.9"),
                        provider: 0,
                    }],
                },
            ],
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("no-such-import link must be rejected"),
            Err(RuntimeError::Link(LinkError::NoSuchImport {
                consumer: 1,
                import,
            })) => {
                assert_eq!(import, name("test:calc/nope@9.9.9"));
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }

        // 同一 import 两条链接边 → DuplicateLink。
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
                MemberSpec {
                    component: &consumer,
                    links: &[
                        LinkSpec {
                            import: name("test:calc/calc@1.0.0"),
                            provider: 0,
                        },
                        LinkSpec {
                            import: name("test:calc/calc@1.0.0"),
                            provider: 0,
                        },
                    ],
                },
            ],
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("duplicate link must be rejected"),
            Err(RuntimeError::Link(LinkError::DuplicateLink {
                consumer: 1,
                import,
            })) => {
                assert_eq!(import, name("test:calc/calc@1.0.0"));
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_rejects_empty_members_and_empty_link_name() {
        // 空集合 → EmptySet。
        let engine = engine();
        let spec = LinkedSetSpec {
            members: &[],
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("empty linked set must be rejected"),
            Err(RuntimeError::Link(LinkError::EmptySet)) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
        // 空链接名 → EmptyLinkName。
        match LinkName::new("") {
            Ok(_) => test_failure("empty link name must be rejected"),
            Err(LinkError::EmptyLinkName) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn linked_set_host_hook_supplies_host_definitions() {
        // §8.2 分层：宿主定义（WASI 世界 / host funcs）经 HostLinkHook 注入；
        // 有 hook → 未链接导入可用；无 hook → UnlinkedImport。
        struct EchoHook;

        impl HostLinkHook for EchoHook {
            fn apply(
                &self,
                linker: &mut wasmtime::component::Linker<StoreHostState>,
            ) -> Result<(), RuntimeError> {
                linker
                    .root()
                    .func_wrap(
                        "host-echo",
                        |_store, x: (i32,)| -> wasmtime::Result<(i32,)> { Ok((x.0 + 1,)) },
                    )
                    .map_err(|source| {
                        RuntimeError::Link(LinkError::LinkerDefinition {
                            member: 0,
                            source: ErrorSource::from(source),
                        })
                    })
            }
        }

        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_HOST_ECHO_WAT);
        // 无 hook：host-echo 未链接 → UnlinkedImport。
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
                MemberSpec {
                    component: &consumer,
                    links: &[],
                },
            ],
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec);
        match result {
            Ok(_) => test_failure("host import without hook must be rejected"),
            Err(RuntimeError::Link(LinkError::UnlinkedImport {
                consumer: 1,
                import,
            })) => {
                assert_eq!(import, name("host-echo"));
            }
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
        // 有 hook：host-echo 由宿主提供 → 成功且调用正确（41 + 1 = 42）。
        let hook = EchoHook;
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
                MemberSpec {
                    component: &consumer,
                    links: &[],
                },
            ],
            host: Some(&hook),
        };
        let mut set = expect_ok(
            LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec),
            "linked set with host hook",
        );
        expect_ok(
            set.store_mut()
                .set_deadline(CallDeadline::new(Duration::from_secs(1))),
            "set deadline",
        );
        set.store_mut().begin_execution();
        let consumer_instance = *expect_some(set.instance(1), "consumer instance");
        let run = expect_ok(
            consumer_instance.get_typed_func::<(), (i32,)>(set.store_mut().store_mut(), "run"),
            "run lookup",
        );
        match run.call(set.store_mut().store_mut(), ()) {
            Ok((echoed,)) => {
                assert_eq!(echoed, 42, "host echo must return 41 + 1");
                let _ = run.post_return(set.store_mut().store_mut());
            }
            Err(e) => test_failure(format_args!("host echo call failed: {e}")),
        }
    }

    #[test]
    fn linked_set_budget_applies_across_members() {
        // §7.4：预算对整个集合的 Store 生效——成员内存超限 → 构建期确定
        // 拒绝（ResourceLimit::LinearMemory）。
        let engine = engine();
        let budget = ResourceBudget {
            linear_memory: Some(LinearMemoryLimit::new(ByteSize::kib(64))),
            ..ResourceBudget::default()
        };
        let provider = compile(&engine, PROVIDER_ADD_WAT); // 1 page = 64 KiB（恰好上限）
        let consumer = compile(&engine, CONSUMER_BIG_MEMORY_WAT); // 2 pages = 128 KiB（超限）
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                // 该 consumer 无任何导入（纯大内存成员）。
                component: &consumer,
                links: &[],
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let result = LinkedComponentSet::new(&engine, &budget, &spec);
        match result {
            Ok(_) => test_failure("memory over budget must be rejected"),
            Err(RuntimeError::ResourceLimit {
                kind: crate::ResourceLimitKind::LinearMemory,
                ..
            }) => {}
            Err(other) => test_failure(format_args!("unexpected error: {other}")),
        }
    }

    #[test]
    fn epoch_deadline_applies_across_link() {
        // §7.5：epoch deadline 跨链接生效——consumer 经桥接调用 provider 的
        // 无限循环 spin，必须按 deadline 中断（EpochDeadlineExceeded）。
        let engine = engine();
        let provider = compile(&engine, PROVIDER_SPIN_WAT);
        let consumer = compile(&engine, CONSUMER_SPIN_CALLER_WAT);
        let spec = LinkedSetSpec {
            members: &[
                MemberSpec {
                    component: &provider,
                    links: &[],
                },
                MemberSpec {
                    component: &consumer,
                    links: &[LinkSpec {
                        import: name("test:calc/spin@1.0.0"),
                        provider: 0,
                    }],
                },
            ],
            host: None,
        };
        let mut set = expect_ok(
            LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec),
            "linked set build",
        );
        let ticker = test_support::ticker(&engine);
        expect_ok(
            set.store_mut()
                .set_deadline(CallDeadline::new(Duration::from_millis(25))),
            "set deadline",
        );
        set.store_mut().begin_execution();
        let consumer_instance = *expect_some(set.instance(1), "consumer instance");
        let run = expect_ok(
            consumer_instance.get_typed_func::<(), ()>(set.store_mut().store_mut(), "run"),
            "run lookup",
        );
        let result = run.call(set.store_mut().store_mut(), ());
        match result {
            Ok(()) => test_failure("infinite spin across link must be interrupted"),
            Err(e) => {
                let mapped = classify_wasm_error(set.store_mut(), e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::Execution {
                            kind: WasmFailure::EpochDeadlineExceeded,
                            ..
                        }
                    ),
                    "epoch trap must map to EpochDeadlineExceeded: {mapped:?}"
                );
            }
        }
        drop(ticker);
    }

    #[test]
    fn instance_access_out_of_range_returns_none() {
        let engine = engine();
        let provider = compile(&engine, PROVIDER_ADD_WAT);
        let consumer = compile(&engine, CONSUMER_ADD_CALLER_WAT);
        let links = [LinkSpec {
            import: name("test:calc/calc@1.0.0"),
            provider: 0,
        }];
        let members = [
            MemberSpec {
                component: &provider,
                links: &[],
            },
            MemberSpec {
                component: &consumer,
                links: &links,
            },
        ];
        let spec = LinkedSetSpec {
            members: &members,
            host: None,
        };
        let set = expect_ok(
            LinkedComponentSet::new(&engine, &ResourceBudget::default(), &spec),
            "linked set build",
        );
        assert!(set.instance(2).is_none());
        assert!(set.instance(usize::MAX).is_none());
        assert!(set.instance(0).is_some());
    }
}
