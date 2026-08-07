//! application 的 port traits（§24.2：用例编排和 ports；trait 定义在本
//! crate，storage / web 层将来实现）。
//!
//! 全部签名使用 domain 类型与本 crate 的用例级类型（[`crate::model`]），
//! typed Result 错误（thiserror，§14.1）；不泄漏任何 rusqlite / wasmtime /
//! WASI 具体类型（§24.2 / §8.2）。
//!
//! - [`ComponentRegistryPort`]：digest 主键的 quarantine/candidate 记录、
//!   ComponentId+ComponentVersion→Digest 唯一绑定（重复 digest 显式冲突，
//!   §19.4 / §6.7）、InstallationId 记录（激活 digest、状态、rollback
//!   保留目标）；制品字节的 digest 寻址存取（§18.7）。
//! - [`ProviderGraphPort`]：0.2.0 provider graph records 的持久化（§40.2
//!   graph persistence/recovery；恢复 = 加载 records 后重新 `try_build`
//!   重校验不变量）。
//! - [`GrantStorePort`]：绑定 InstallationId 的 grants（§17.5）。
//! - [`AuditPort`]：audit 事件追加（不记 secret，§16.6）。
//! - [`ConfigPort`]：Core config 快照读取（§18.0 RuntimeConfig 语义）。
//! - [`ActionPolicyPort`]：Web bridge 的服务端重做检查点（§21.3：
//!   auth / RBAC / grant / body / rate / concurrency 检查点用 port 表达，
//!   HTTP 层在 web-admin 实现完整链；本 crate 提供默认实现
//!   [`InProcessActionPolicy`]）。

mod audit;
mod config;
mod grants;
mod graph;
mod policy;
mod registry;

pub use audit::{AuditError, AuditEvent, AuditPort, RejectReason};
pub use config::{ConfigError, ConfigPort};
pub use grants::{GrantError, GrantStorePort};
pub use graph::{GraphRecords, GraphStoreError, ProviderGraphPort};
pub use policy::{ActionContext, ActionPolicyPort, InProcessActionPolicy};
pub use registry::{ComponentRegistryPort, RegistryError};
