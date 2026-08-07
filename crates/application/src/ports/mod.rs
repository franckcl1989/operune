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
//!
//! # 0.3.0 Stateful Runtime（§41.2）——state/config/secret 端口
//!
//! - [`StateStorePort`]：typed state 存储面（快照点读、原子 upsert、事务
//!   begin/commit/abort、schema 版本查询、显式 migration 事务 begin）。
//!   CAS 的 get→compare→put 编排在 [`crate::state::StateService`]
//!   （executor 单连接串行 ⇒ 无交错）。
//! - [`ComponentConfigStorePort`]：管理员输入配置的存储面（原子快照读、
//!   带 revision 单调递增的写；guest 只读语义，config.wit）。
//! - [`SecretStorePort`]：**不含明文**的密文 BLOB 存储面（put/delete/
//!   list/ciphertext）；加解密永远经 security 层
//!   （[`crate::secret::SecretService`]），storage 不解密。
//! - [`SecretGrantPort`]：安装实例被授予的 secret 名称集（§17.3
//!   "secret names" scope 维度；§17.5 第三层 Grant）。与既有
//!   `GrantStorePort` 分开定义：既有 grant scope 变体集是跨 crate 闭集，
//!   名称级 scope 以独立 port 面演进。
//! - [`StatefulAuditPort`]：0.3 state/config/secret 审计（§41.2 audit
//!   MUST；metadata-only，值绝不进入审计，§16.6）。与 [`AuditPort`]
//!   分开定义：既有 [`AuditEvent`] 变体集被 storage-sqlite 穷尽映射。
//!
//! # 0.3.0 Stateful Runtime（§41.2）——scheduler/event/lifecycle 端口
//!
//! - [`SchedulerDeliveryPort`]：定时任务交付面（Core-mediated push 到
//!   guest `handler.on-trigger`，scheduler.wit；返回即已消费，trap 视为
//!   已消费）。
//! - [`SchedulerGrantPort`]：scheduler 能力的静态授权查询（§17.1/§17.5；
//!   `denied` 判定面），进程内实现 [`InProcessSchedulerGrant`]。
//! - [`EventPolicyPort`]：event 静态策略查询（§17.3 "event topics" scope：
//!   发布授权 + 订阅集合，订阅是 policy 事实，无运行时 subscribe），
//!   进程内实现 [`InProcessEventPolicy`]。
//! - [`EventDeliveryPort`]：事件投递面（Core-mediated push 到 guest
//!   `handler.on-event`，event.wit；trap 视为已消费）。
//! - [`CheckpointPort`]：checkpoint 编排的最小 flush 入口（§41.2
//!   checkpoint；StateService 无独立 flush 语义，见模块文档），进程内
//!   实现 [`InProcessCheckpoint`]。

mod audit;
mod component_config;
mod config;
mod event;
mod grants;
mod graph;
mod lifecycle;
mod policy;
mod registry;
mod scheduler;
mod secret;
mod state;

pub use audit::{
    AuditError, AuditEvent, AuditPort, RejectReason, StatefulAuditEvent, StatefulAuditPort,
};
pub use component_config::{ComponentConfigStorePort, ConfigStoreError};
pub use config::{ConfigError, ConfigPort};
pub use event::{EventDeliveryError, EventDeliveryPort, EventPolicyPort, InProcessEventPolicy};
pub use grants::{GrantError, GrantStorePort};
pub use graph::{GraphRecords, GraphStoreError, ProviderGraphPort};
pub use lifecycle::{CheckpointError, CheckpointPort, InProcessCheckpoint};
pub use policy::{ActionContext, ActionPolicyPort, InProcessActionPolicy};
pub use registry::{ComponentRegistryPort, RegistryError};
pub use scheduler::{
    InProcessSchedulerGrant, SchedulerDeliveryError, SchedulerDeliveryPort, SchedulerGrantPort,
};
pub use secret::{SecretCiphertextRecord, SecretGrantPort, SecretStoreError, SecretStorePort};
pub use state::{StateStoreError, StateStorePort};
