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
//! - [`contract`]：`operune:*@0.1.0` WIT 契约的镜像用例类型与
//!   `wasmtime::component::Val` 编解码（§13.3 边界解析一次）。
//! - [`wit_bindings`]：`wasmtime::component::bindgen!` 的编译期 WIT 验证
//!   （§22.2；见该模块的 §25 裁决说明）。
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
pub mod contract;
pub mod error;
pub mod install;
pub mod model;
pub mod ports;
pub mod runtime;
pub mod upgrade;
pub mod web;
pub mod wit_bindings;

#[cfg(test)]
mod test_support;

pub use active::ActiveRuntimeRegistry;
pub use error::{ApplicationError, RuntimeExecutionError};
pub use install::InstallService;
pub use model::{
    ActionDenied, ActionName, CandidateRecord, ContractSurface, DigestVersionBinding,
    GrantApproval, GrantScope, GrantSnapshot, ImportClass, InstallOutcome, InstallRequest,
    InstallationGrant, InstallationRecord, PipelineTargetKind, RollbackRequest, RuntimeConfig,
    UpgradeOutcome, UpgradeRequest, WebAssetEntry, WebAssetPath, WebManifestData,
};
pub use ports::{
    ActionContext, ActionPolicyPort, AuditError, AuditEvent, AuditPort, ComponentRegistryPort,
    ConfigError, ConfigPort, GrantError, GrantStorePort, InProcessActionPolicy, RegistryError,
};
pub use runtime::{
    ActiveRuntime, CompiledWasm, PreparedRuntime, RuntimePlan, WasmRuntime, WasmtimeRuntime,
};
pub use upgrade::UpgradeService;
pub use web::{AssetCache, AssetResponse, WebBridge};
