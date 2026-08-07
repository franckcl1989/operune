//! WASI 集成边界（§8.2 分层 / §7.6 无 ambient authority）。
//!
//! 本模块定义 runtime-wasm ↔ runtime-wasi-p2 的 port 契约：
//! - [`WasiVersion`] / [`WasiPolicy`]：能力策略的 typed 数据形状（deny-by-default）；
//! - [`WasiAdapter`]：adapter crate（runtime-wasi-p2）实现的 trait；
//! - [`WasiError`]：集成错误（fail closed 语义）。
//!
//! 边界规则（§8.2）：runtime-wasm 不 import runtime-wasi-p2 的任何具体类型；
//! WASI 0.2 具体 linker/binding 只存在于 adapter crate。本模块的公共签名
//! 不含任何 wasmtime 类型（adapter 通过 [`crate::store::StoreHostState`] 的
//! opaque 状态槽完成附加）。

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

/// WASI adapter 契约（§8.2：由 runtime-wasi-p2 实现；runtime-wasm 不 import
/// 其具体类型）。
///
/// 语义：
/// - [`WasiAdapter::attach`] 只在 Store 构建时调用一次；失败即拒绝整个 Store
///   构建（fail closed，§7.6）；
/// - 实现方只能授予 `policy` 中显式声明的能力（§7.6：无 ambient authority；
///   默认 Store 不获得文件系统/网络/环境变量/进程环境/随机资源）；
/// - 实现方通过 [`StoreHostState::replace_adapter_state`] 保存其 WASI 上下文，
///   并在实例化阶段的 linker 绑定闭包中 downcast 使用；
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
