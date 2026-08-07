//! Core config port（§18.0 RuntimeConfig 语义：Core 启动并打开 authoritative
//! store 后管理的可变运行策略；快照读取）。

use crate::model::RuntimeConfig;

/// config 读取错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 底层配置存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("config storage failure: {0}")]
    Storage(#[source] crate::error::ErrorSource),
}

/// Core config port（storage-sqlite 层实现）。
///
/// 语义（§18.0）：返回不可变 [`RuntimeConfig`] 快照；用例层在每次管线
/// 开始时读取并校验（validate-on-construct，§13.3）。BootstrapConfig
/// （宿主启动事实）不属于本 port。
pub trait ConfigPort: Send + Sync {
    /// 读取当前 RuntimeConfig 快照。
    fn snapshot(&self) -> Result<RuntimeConfig, ConfigError>;
}
