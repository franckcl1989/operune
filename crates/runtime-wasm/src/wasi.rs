//! WASI 集成边界（§8.2 分层 / §7.6 无 ambient authority）。
//!
//! 本模块定义 runtime-wasm ↔ runtime-wasi-p2 的 port 契约：
//! - [`WasiVersion`] / [`WasiPolicy`]：能力策略的 typed 数据形状（deny-by-default）；
//! - [`WasiAdapter`]：adapter crate（runtime-wasi-p2）实现的 trait；
//! - [`WasiError`]：集成错误（fail closed 语义）。
//!
//! 边界规则（§8.2）：runtime-wasm 不 import runtime-wasi-p2 的任何具体类型；
//! WASI 0.2 具体 linker/binding 只存在于 adapter crate。adapter 经
//! [`crate::store::StoreHostState::set_wasi_state`] 安装 WASI 上下文、
//! 经 [`crate::store::StoreHostState::replace_adapter_state`] 保存自有
//! 附加状态。
//!
//! 受控 glue 例外（0020e24 审计裁决，见 git 历史）：[`WasiP2HostState`] 是
//! [`StoreHostState`](crate::store::StoreHostState) 的 `wasmtime_wasi::WasiView`
//! 接线的状态载体（存于 StoreHostState 专用字段，构造时预置零权限空
//! context，见 [`crate::store::StoreHostState::set_wasi_state`]），因 orphan
//! rule 必须定义在持有 Store 类型的 crate（runtime-wasm）；其公开签名因此
//! 包含 `wasmtime_wasi::WasiCtx`（§8.2 的 MUST NOT 列表不含 runtime-wasm）。
//! 该例外只覆盖 WasiView 接线本身，不扩展到 WASI 具体 binding/linker
//!（仍只存在于 runtime-wasi-p2，§24.2）。

use std::error::Error as StdError;

use crate::store::StoreHostState;

/// WASI 主版本（§4.2：0.1.0 production 只启用 WASI 0.2；p3 未达到成熟度 Gate）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WasiVersion {
    /// WASI 0.2（production line，§4.2/§22.2）。
    P2,
}

/// WASI 能力策略（§7.6/§17.2：deny-by-default——空策略 = 无任何 WASI 能力）。
///
/// 本阶段固定版本维度；具体能力字段（preopened 路径、出站网络、环境变量、
/// 时钟等）随 runtime-wasi-p2 adapter 里程碑以 typed 字段扩展。在能力字段
/// 落地前，[`WasiAdapter::attach`] 的实现方必须拒绝授予任何能力（或保持
/// 空策略直通，由 adapter 自身的 deny-by-default 保证）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasiPolicy {
    version: WasiVersion,
}

impl WasiPolicy {
    /// WASI 0.2 策略（无能力授予）。
    pub const fn p2() -> Self {
        Self {
            version: WasiVersion::P2,
        }
    }

    /// 策略要求的 WASI 版本。
    pub const fn version(&self) -> WasiVersion {
        self.version
    }
}

impl Default for WasiPolicy {
    fn default() -> Self {
        Self::p2()
    }
}

/// WASI 集成错误。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WasiError {
    /// adapter 不支持 policy 要求的 WASI 版本（Store 构建被拒绝，fail closed）。
    #[error("WASI adapter ({adapter:?}) does not support requested version ({requested:?})")]
    VersionMismatch {
        /// adapter 支持的版本。
        adapter: WasiVersion,
        /// policy 要求的版本。
        requested: WasiVersion,
    },
    /// adapter 附加能力失败（fail closed：整个 Store 构建被拒绝，§7.6）。
    #[error("WASI capability attach failed: {0}")]
    Attach(#[source] Box<dyn StdError + Send + Sync>),
}

/// WASI 0.2 host 状态持有器——`wasmtime_wasi::WasiView` 接线的状态载体
///（§8.2 受控 glue 例外，0020e24 审计裁决，见 git 历史；模块文档）。
///
/// 内部持有 `wasmtime_wasi::WasiCtx`（WASI 0.2 的 Host 状态）与
/// `wasmtime::component::ResourceTable`（guest 资源表）。[`StoreHostState`]
/// 的 `wasmtime_wasi::WasiView` 实现从专用字段（[`StoreHostState::set_wasi_state`]
/// 的安装点）直接接线，无 downcast。
///
/// 分层（§8.2）：本类型定义在 runtime-wasm（orphan rule 强制），由
/// runtime-wasi-p2 的 [`WasiAdapter::attach`] 在附加时经 [`WasiP2HostState::new`]
/// 构建并经 [`crate::store::StoreHostState::set_wasi_state`] 安装（Store
/// 构建时预置的是 [`WasiP2HostState::empty`]，§7.6 deny-by-default）。
/// WASI 具体 linker/binding 仍只存在于 runtime-wasi-p2（§24.2）。
///
/// 并发保证：随 [`StoreHostState`] 的单一执行模型（§7.3）使用，不跨线程共享。
pub struct WasiP2HostState {
    // 字段为 pub(crate)：WasiView 实现（store.rs）需按字段拆分可变借用
    //（ctx 与 table 同时借出，无法经方法完成——见 wasmtime_wasi::WasiView 文档）。
    pub(crate) ctx: wasmtime_wasi::WasiCtx,
    pub(crate) table: wasmtime::component::ResourceTable,
}

impl WasiP2HostState {
    /// 用 adapter 构建的 WASI 0.2 context 创建持有器（附带新的 guest
    /// resource table）。
    pub fn new(ctx: wasmtime_wasi::WasiCtx) -> Self {
        Self {
            ctx,
            table: wasmtime::component::ResourceTable::new(),
        }
    }

    /// 零权限空 context（deny-by-default 预置，§7.6）。
    ///
    /// [`StoreFactory`](crate::store::StoreFactory) 在构建每个 Store 时预置
    /// 本构造（[`StoreHostState`] 的 WasiView 实现由此无失败路径——`ctx` 的
    /// 返回借用与 `&mut self` 同生命周期，回退分支无法在 Safe Rust 下表达，
    /// 见 store.rs 的 WasiView 实现文档），直到 attach 经
    /// [`crate::store::StoreHostState::set_wasi_state`] 显式替换。
    ///
    /// 逐项配置镜像 runtime-wasi-p2 的 `WasiContextBuilder` 零权限默认
    ///（无 preopen、无环境变量/参数、网络结构性关闭、随机源零熵）——本
    /// crate 不 import runtime-wasi-p2（§8.2），故按 §7.6 直接以
    /// wasmtime-wasi 表达同一默认（两处注释互相引用；§7.6 默认 Store 不
    /// 获得文件系统/网络/环境变量/随机资源）。
    pub(crate) fn empty() -> Self {
        let mut builder = wasmtime_wasi::WasiCtxBuilder::new();
        builder.allow_ip_name_lookup(false);
        builder.allow_tcp(false);
        builder.allow_udp(false);
        builder.insecure_random_seed(0);
        builder.secure_random(wasmtime_wasi::Deterministic::new(vec![0; 64]));
        builder.insecure_random(wasmtime_wasi::Deterministic::new(vec![0; 64]));
        Self {
            ctx: builder.build(),
            table: wasmtime::component::ResourceTable::new(),
        }
    }
}

/// WASI adapter 契约（§8.2：由 runtime-wasi-p2 实现；runtime-wasm 不 import
/// 其具体类型）。
///
/// 语义：
/// - [`WasiAdapter::attach`] 只在 Store 构建时调用一次；失败即拒绝整个 Store
///   构建（fail closed，§7.6）；
/// - 实现方只能授予 `policy` 中显式声明的能力（§7.6：无 ambient authority；
///   默认 Store 不获得文件系统/网络/环境变量/进程环境/随机资源）；
/// - 实现方经 [`StoreHostState::set_wasi_state`] 安装其 WASI 0.2 上下文
///   （[`WasiP2HostState`] 实例；Store 构建时已预置零权限空 context，
///   attach 以 policy 构建的上下文整体替换）；opaque 状态槽
///   （[`StoreHostState::replace_adapter_state`]）保留给 adapter 自有附加
///   状态；
/// - [`StoreHostState::budget`] 提供资源预算快照（如 §7.4 HTTP body 上限），
///   实现方可据此配置 wasi-http 等适配层强制项；
/// - 0.1.0 的 adapter 版本维度仅 P2；未来 p3 进入 production 时经 §8.3 Gate
///   后在此扩展新版本（side-by-side，§8.4）。
pub trait WasiAdapter: Send + Sync + 'static {
    /// 该 adapter 支持的 WASI 主版本。
    fn version(&self) -> WasiVersion;

    /// 将 policy 授予的能力附加到 Store 宿主状态。
    fn attach(&self, policy: &WasiPolicy, host_state: &mut StoreHostState)
    -> Result<(), WasiError>;
}
