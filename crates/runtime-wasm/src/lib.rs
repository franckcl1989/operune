#![forbid(unsafe_code)]

//! Operune Core Runtime 的 Wasm 运行适配层（规范 §24.2：runtime-wasm）。
//!
//! 本 crate 承担 §7（Wasmtime 运行模型）与 §22.2（Wasmtime 36.x LTS production
//! feature set）的宿主侧核心：
//!
//! - **Engine（§7.1）**：[`engine::EngineHandle`] 是长期共享、配置不可变的
//!   [`engine::EngineConfig`] + Wasmtime Engine；配置在启动后视为不可变基础设施，
//!   不为每个 Component 创建独立 Engine。实例化策略固定 OnDemand（§7.3/§22.9，
//!   0.1 不默认 pooling）；编译后端固定 Cranelift（§4.1）。
//! - **Component（§7.2）**：[`component::ComponentHandle`] 对不可信 `.wasm` 输入
//!   做同步验证（含全部 core modules）并编译；Wasmtime 私有序列化/AOT 格式
//!   不作为用户可见插件制品。
//! - **Store 与资源治理（§7.3/§7.4）**：[`store::StoreFactory`] 按
//!   [`budget::ResourceBudget`] 注入 [`limiter`]（Wasmtime `ResourceLimiter`）；
//!   预算覆盖 linear memory 大小/数量、table 数量/元素、实例数量、host buffer、
//!   最大并发、最大排队、单次调用截止时间、后台任务数量、HTTP body 上限。
//!   §7.4 边界：`ResourceLimiter` 只强制 Wasmtime 可见资源；host 分配的缓冲、
//!   数据库结果、缓存、HTTP body 等由 Core/适配层自己有界化（预算类型仅作
//!   策略载体向下传递）。
//! - **CPU 中断（§7.5）**：epoch interruption 默认启用（见
//!   [`engine::EngineConfig`]）；[`engine::EpochTicker`] 是统一 ticker；每次不可信
//!   执行通过 [`store::StoreHandle::set_deadline`] 设置 epoch deadline，超时 trap
//!   （分类为 [`error::WasmFailure::EpochDeadlineExceeded`]）。不默认启用 fuel
//!   （原因与启用条件见 [`engine::EngineConfig`] 文档）。
//! - **无 ambient authority（§7.6）**：默认 Store 不获得宿主文件系统、网络、
//!   环境变量、进程环境或随机资源；每一项 Host/WASI 能力必须经
//!   [`store::StoreFactory::with_wasi`] + [`wasi::WasiAdapter`] 显式构建。
//! - **实例模型（§7.3）**：[`instance::InstanceSet`] 是有界 Instance Set：
//!   单一 owner、任一时刻每个槽位只执行一个调用（[`instance::InstanceLease`]
//!   独占）、有界 dispatch（`try_dispatch` 非阻塞拒绝 / `dispatch` 有界排队）。
//!   0.1.0 stateless contract：不承诺跨调用 instance affinity，调用者不得把
//!   linear memory 或实例本地变量当作下一次调用仍存在的事实。
//!
//! # 分层（§8.2/§24.2）
//!
//! 本 crate 的公共 API 只暴露项目自己的 typed port/value 类型，不把 Wasmtime
//! 具体类型泄漏给上层：`domain` / `application` / `web-admin` / `security` /
//! `storage` 不得 import `wasmtime_wasi::p2`/`p3` 具体类型（§8.2）；本 crate
//! 是隔离层，[`wasi::WasiAdapter`] 是 runtime-wasm ↔ runtime-wasi-p2 的
//! adapter 契约（本 crate 不 import runtime-wasi-p2 的具体类型）。
//!
//! 受控 glue 例外（0020e24 审计裁决，见 git 历史）：`wasmtime_wasi::WasiView`
//! binding trait 因 orphan rule 只能由持有 Store 类型的 crate 实现，故
//! [`store::StoreHostState`] 的 WasiView 接线必须存在于此（§8.2 的 MUST NOT
//! 列表不含 runtime-wasm）。该例外只覆盖接线本身：公开面限于
//! [`wasi::WasiP2HostState`] 与其安装点 [`store::StoreHostState::set_wasi_state`]，
//! WASI 具体 linker/binding 仍只存在于 runtime-wasi-p2（§24.2）。
//! 错误模型（§14）：[`error::RuntimeError`] 为封闭 typed error，第三方错误
//! 装箱为可诊断 source（[`error::ErrorSource`]），不向公共边界返回 anyhow/
//! `Box<dyn Error>` 本身。
//!
//! # Safe Rust（§11）
//!
//! 全部第一方代码为 Safe Rust（`#![forbid(unsafe_code)]`），production path
//! 无 `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`（workspace lints deny）。

pub mod budget;
pub mod component;
pub mod engine;
pub mod error;
pub mod instance;
pub mod limiter;
pub mod store;
pub mod wasi;

#[cfg(test)]
pub(crate) mod test_support;

pub use budget::{
    BackgroundTaskLimit, ByteSize, CallDeadline, HostBufferLimit, HttpBodyLimit,
    InstanceCountLimit, LinearMemoryLimit, MaxConcurrent, MaxQueued, MemoryCountLimit,
    ResourceBudget, TableCountLimit, TableElementLimit,
};
pub use component::ComponentHandle;
pub use engine::{EngineConfig, EngineHandle, EpochTicker};
pub use error::{ResourceLimitKind, RuntimeError, TrapKind, WasmFailure, classify_wasm_error};
pub use instance::{DispatchError, InstanceLease, InstanceSet};
pub use store::{StoreFactory, StoreHandle, StoreHostState};
pub use wasi::{WasiAdapter, WasiError, WasiP2HostState, WasiPolicy, WasiVersion};
