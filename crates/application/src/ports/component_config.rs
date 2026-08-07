//! 0.3.0 Stateful Runtime（§41.2）——Component config storage port
//! （application 定义，storage-sqlite 接线实现）。
//!
//! 语义（契约面 `operune:config@0.1.0` config.wit，已提交稳定；§41.2
//! Component config storage/validation）：
//!
//! - Config 是管理员/系统提供、具有 validation 和版本语义的**输入**
//!   （§41.2 三分离），不是 Component 产生的权威状态；guest 只读，写侧
//!   不在 Component 契约内（本 port 的管理侧写由 Root Admin / Core 系统面
//!   调用）；
//! - 写入时 revision 单调递增由存储保证（单语句 upsert，§41.2）；值通过
//!   Component 自身 `validator` export 校验后才成为当前配置（validation
//!   编排属于 runtime 接线面，不在本 port）；
//! - config 无平台级 migration（与 state 的本质区别，config.wit）；
//! - 敏感值**不得**放进 config（凭据/密钥属于 operune:secret，§16.6）——
//!   本 port 与 secret port 分离。
//!
//! 全部签名使用 domain 类型（§24.2），不泄漏任何存储具体类型。

use operune_domain::{
    ConfigFormat, ConfigRevision, ConfigSchemaVersion, ConfigSnapshot, ConfigValue, InstallationId,
};

use crate::error::ErrorSource;

/// component config 存储错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum ConfigStoreError {
    /// 安装实例不存在。
    #[error("component config not found: {0}")]
    NotFound(String),

    /// 参数非法（如值超存储侧硬上限）。
    #[error("invalid component config argument: {0}")]
    InvalidArgument(String),

    /// 存储的配置快照未通过完整性检查（损坏；需管理员重新提供配置）。
    #[error("component config data corrupt: {0}")]
    Corrupt(String),

    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("component config store failure: {0}")]
    Storage(#[source] ErrorSource),
}

/// Component config store port（§24.2：trait 定义在本 crate，storage-sqlite
/// 层实现）。
pub trait ComponentConfigStorePort: Send + Sync {
    /// 读取原子配置快照（§41.2：revision 与 value 同行同读，一次快照内
    /// 一致；`None` = 尚无已校验配置——激活门禁下运行时读取必有快照，
    /// `None` 即"未就绪"，config.wit 无 not-found）。
    fn snapshot(
        &self,
        installation: InstallationId,
    ) -> Result<Option<ConfigSnapshot>, ConfigStoreError>;

    /// 写入/更新配置（§41.2）：revision 单调 +1 由存储保证（单语句
    /// upsert，无交错）；返回**新修订号**（管理侧与审计关联需要）。
    /// `value` 必须是已通过 Component `validator` 校验的配置（validation
    /// 编排在 runtime 接线面）。
    fn put(
        &self,
        installation: InstallationId,
        format: ConfigFormat,
        schema_version: ConfigSchemaVersion,
        value: &ConfigValue,
    ) -> Result<ConfigRevision, ConfigStoreError>;
}
