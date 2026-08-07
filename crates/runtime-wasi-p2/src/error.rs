//! 本 crate 的 typed error（规范 §14.1）。
//!
//! 适配层把第三方错误转换为项目错误语义，并保存可诊断的 source/context，
//! 但**不在公开契约中命名第三方错误类型**：`anyhow` / `wasmtime` /
//! `wasmtime_wasi` 的错误一律擦除为 `Box<dyn std::error::Error + Send + Sync>`
//! 作为 `#[source]`，满足"不让第三方错误类型污染核心契约"同时保留诊断信息。
//!
//! 本错误集合是封闭的（无 `Other(String)` 兜底），便于上层精确匹配（§14.1）。

use std::error::Error;
use std::fmt;

/// 第三方错误擦除后的可诊断载体（§14.1）。
///
/// wasmtime 36 的 `wasmtime::Error`（`anyhow::Error` 的 re-export）出于设计
/// 不实现 `std::error::Error`（其内部错误不一定 `Send + Sync + 'static`），
/// 无法直接装箱为 `dyn Error`。本类型捕获其 Display 全文（anyhow 的 Display
/// 已含 context 链）作为 `#[source]`：第三方错误类型不进入公开契约，
/// 诊断信息不丢失。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AdapterSource(String);

impl AdapterSource {
    /// 捕获任何可 Display 错误的诊断文本。
    pub(crate) fn new(source: impl fmt::Display) -> Self {
        Self(source.to_string())
    }
}

impl fmt::Display for AdapterSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for AdapterSource {}

/// WASI 0.2 适配层的封闭 typed error。
///
/// 全部变体都是 Host 侧适配层错误（capability 规格校验、context 构建、
/// linker 组装）。guest 可见的 WASI 错误（如 `wasi:filesystem` 的 errno）
/// 由标准 WASI 接口自身的错误语义返回给 guest（P4：不建立平行错误面），
/// 不属于本类型。
#[derive(Debug, thiserror::Error)]
pub enum WasiP2Error {
    /// Guest 侧 preopen 路径为空字符串。
    #[error("guest path must not be empty")]
    EmptyGuestPath,
    /// Guest 侧 preopen 路径含 NUL 字节。
    #[error("guest path must not contain NUL bytes")]
    NulInGuestPath,
    /// Host 侧 preopen 目录路径为空（不表达"当前目录"这种隐式含义，必须显式）。
    #[error("host path must not be empty")]
    EmptyHostPath,
    /// 同一能力集合中出现重复的 guest 路径，会造成 guest 侧解析歧义。
    #[error("duplicate guest path: {0:?}")]
    DuplicateGuestPath(String),
    /// 环境变量 key 为空。
    #[error("environment variable key must not be empty")]
    EmptyEnvKey,
    /// 环境变量 key 或 value 含 NUL 字节。
    #[error("environment variable key or value must not contain NUL bytes")]
    NulInEnvVar,
    /// 按 policy 打开 preopen 目录失败（如 host 路径不存在、无权限）。
    ///
    /// `source` 保留上游（cap-std / io）的可诊断错误，但不暴露第三方类型。
    #[error(
        "failed to open preopen directory (guest: {guest_path:?}, host: {host_path:?}): {source}"
    )]
    PreopenOpen {
        /// 声明时的 guest 路径。
        guest_path: String,
        /// 声明时的 host 路径。
        host_path: String,
        /// 上游打开目录时的错误（已擦除类型）。
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// 把 WASI 0.2 接口组装进 `wasmtime::component::Linker` 失败。
    ///
    /// 正常路径不会触发；例如在已定义同名实例的 linker 上重复组装会因
    /// shadowing 保护而失败。
    #[error("failed to link WASI 0.2 interfaces into the linker: {source}")]
    LinkerAssembly {
        /// 上游 linker 定义错误（已擦除类型）。
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
}
