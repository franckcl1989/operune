#![forbid(unsafe_code)]

//! Operune Application 层（规范 §24.2：application）。
//!
//! 用例编排和 ports；依赖 domain；**不得知道 SQLite / Axum / WASI p2 具体类型**。
//! 本 crate 是 Core 的用例编排层：两阶段安装管线（§19.2）、descriptor 确定性
//! （§19.3）、热升级与回滚（§20）、最小 Component Web bridge 用例（§21.3）、
//! Capability 安全模型的四层授权链中的 Grant 层（§17.5）。
//!
//! # 分层
//!
//! - [`ports`]：application 自己的 port traits（ComponentRegistry /
//!   GrantStore / Audit / Config + ActionPolicy），由 storage / web 适配层
//!   将来实现（§24.2）。全部签名使用 domain 类型与本 crate 的用例级类型，
//!   不泄漏 rusqlite / wasmtime / WASI 具体类型。
//! - [`model`]：用例级记录（candidate / 版本绑定 / installation / grants /
//!   config 快照 / 请求与结果类型）。
//! - [`install`]：两阶段安装管线（§19.2 严格顺序，全程由
//!   `operune_domain::ComponentLifecycleState` 驱动，§12.2）。
//! - [`upgrade`]：热升级与回滚（§20：非 destructive-in-place、原子快照交换、
//!   有界 drain、旧 grant 不静默继承 §17.5）。
//! - [`web`]：最小 Component Web bridge 用例（§21.3：激活期 web descriptor +
//!   资产清单与缓存、Core-mediated bounded action、服务端重做检查）。
//! - [`runtime`]：wasm 执行边界（`WasmRuntime` / `CompiledWasm` /
//!   `ActiveRuntime` port + `WasmtimeRuntime` 生产实现）。生产实现通过
//!   runtime-wasm 的公开 API（`EngineHandle::engine()` /
//!   `StoreHandle::store_mut()` / `ComponentHandle::component()`）构造
//!   `wasmtime::component::Linker` 并在 Store 上 instantiate（§22.2）。
//! - [`active`]：[`ActiveRuntimeRegistry`]——§15.5 / §20.3 的不可变 Active
//!   快照 + arc-swap 原子切换。
//! - [`composition`]：0.2.0 Capability Composition（§40）——provider graph
//!   构建管线（§40.3 事实源：WIT imports/exports 观察 + Runtime Policy
//!   过滤）、确定性的 provider selection（§40.4 [`GraphPolicy`]）、
//!   activation/deactivation 编排（§40.2 activation ordering）、graph
//!   快照原子切换（§20.3 模式复用）、provider 升级前 consumer 兼容分析
//!   门控（§40.2）、records 持久化 port（[`ProviderGraphPort`]）。
//! - [`contract`]：`operune:*@0.1.0` WIT 契约的镜像用例类型与
//!   `wasmtime::component::Val` 编解码（§13.3 边界解析一次）。
//! - [`wit_bindings`]：`wasmtime::component::bindgen!` 的编译期 WIT 验证
//!   （§22.2；见该模块的 §25 裁决说明）。
//!
//! # 0.3.0 Stateful Runtime（§41.2）——scheduler/event/lifecycle
//!
//! - [`clock`]：墙上时钟抽象（scheduler 的 UTC 硬时刻语义；`Clock` /
//!   [`clock::SystemClock`]——生产时钟，测试注入受控时钟）。
//! - [`scheduler`]：[`SchedulerService`]——typed scheduler（注册/取消/状态
//!   查询；UTC 硬时刻 + tokio 定时器驱动；missed-fires 计数与 at-most-once
//!   交付；cancel 竞态；停机不补投；有界任务数与交付队列，§15.2）。
//! - [`event`]：[`EventService`]——typed event bus（静态 grant 策略下的
//!   发布/投递；发布侧同步背压 `over-budget`；投递侧 `dropped` 计数；
//!   有界入队/投递队列的扇出广播，§15.2）。
//! - [`lifecycle`]：[`LifecycleController`]——graceful lifecycle 编排
//!   （ready/drain/stop/checkpoint，§41.2；与 domain
//!   `ComponentLifecycleState` 衔接，§20.4 有界 drain + CancellationToken）。
//! - [`cancel`]：最小第一方 CancellationToken（§15.3 structured
//!   cancellation；与 server crate 同模式）。
//! - [`stateful_imports`]：0.3.0 operune:state/config/secret 三包
//!   Component import 的宿主注册（`StatefulHostServices` + Linker 动态
//!   注册，§41.2）；`runtime` 的 [`SchedulerRuntimeDelivery`] /
//!   [`EventRuntimeDelivery`] 是 scheduler/event 交付 port 的生产接线。
//!
//! # 时序契约（Wasm 执行，§7.5 / §19.3）
//!
//! 每次不可信执行遵循 runtime-wasm 的时序：`begin_execution` →
//! `set_deadline` → `store_mut()` 上的 instantiate / 调用 →
//! `classify_wasm_error`（错误分类）。descriptor 调用使用独立的
//! deadline / 预算（`RuntimeConfig::descriptor_deadline` /
//! `descriptor_budget`，§19.3），与正常运行预算相同或更严格。
//!
//! # Safe Rust（§11）
//!
//! 全部第一方代码为 Safe Rust（`#![forbid(unsafe_code)]`），production path
//! 无 `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`（workspace lints
//! deny，§14.2 / §26.1）。

pub mod active;
pub mod cancel;
pub mod clock;
pub mod composition;
pub mod config;
pub mod contract;
pub mod error;
pub mod event;
pub mod install;
pub mod lifecycle;
pub mod migration;
pub mod model;
pub mod ports;
pub mod runtime;
pub mod scheduler;
pub mod secret;
pub mod state;
pub mod stateful_imports;
pub mod upgrade;
pub mod web;
pub mod wit_bindings;

#[cfg(test)]
mod test_support;

pub use active::ActiveRuntimeRegistry;
// 注：0.3 component config 服务的 `ConfigService` 在根重导出，但其错误
// `crate::config::ConfigError` 只在模块路径可见（根 `ConfigError` 已被
// 0.1 Core config port 的错误占用——`operune_application::ConfigError`）。
pub use composition::{
    ActiveGraph, CompositionService, ContractRecords, GraphPolicy, GraphPolicyError, InterfaceKey,
    records_from_surface,
};
pub use config::ConfigService;
pub use error::{ApplicationError, RuntimeExecutionError};
pub use event::{DeliveredEvent, EventError, EventLimits, EventService};
pub use install::{InstallService, StateMigrationRunner, StateWiring};
pub use lifecycle::{LifecycleController, LifecycleError};
pub use migration::{MigrationError, MigrationGuestError, MigrationOutcome, StateMigrationService};
pub use model::{
    ActionDenied, ActionName, CandidateRecord, ContractSurface, DigestVersionBinding,
    GrantApproval, GrantScope, GrantSnapshot, ImportClass, InstallOutcome, InstallRequest,
    InstallationGrant, InstallationRecord, PipelineTargetKind, RollbackRequest, RuntimeConfig,
    UpgradeOutcome, UpgradeRequest, WebAssetEntry, WebAssetPath, WebManifestData,
};
pub use ports::{
    ActionContext, ActionPolicyPort, AuditError, AuditEvent, AuditPort, ComponentConfigStorePort,
    ComponentRegistryPort, ConfigError, ConfigPort, ConfigStoreError, GrantError, GrantStorePort,
    GraphRecords, GraphStoreError, InProcessActionPolicy, ProviderGraphPort, RegistryError,
    SecretCiphertextRecord, SecretGrantPort, SecretStoreError, SecretStorePort, StateStoreError,
    StateStorePort, StatefulAuditEvent, StatefulAuditPort,
};
pub use runtime::{
    ActiveRuntime, CompiledWasm, EventRuntimeDelivery, PreparedRuntime, RuntimePlan,
    SchedulerRuntimeDelivery, WasmRuntime, WasmtimeRuntime,
};
pub use scheduler::{SchedulerError, SchedulerLimits, SchedulerService};
pub use secret::{SecretError, SecretService};
pub use state::{CasOutcome, MigrationGate, StateError, StateService};
pub use stateful_imports::StatefulHostServices;
pub use upgrade::UpgradeService;
pub use web::{AssetCache, AssetResponse, WebBridge};
