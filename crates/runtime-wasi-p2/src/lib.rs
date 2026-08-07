#![forbid(unsafe_code)]

//! Operune WASI 0.2 adapter（规范 §24.2：runtime-wasi-p2）。
//!
//! 职责：所有 WASI 0.2 的 Host linker / context / binding 适配（wasmtime-wasi
//! 36 的 `wasmtime_wasi::p2` 模块及其 `WasiCtx` / `WasiCtxBuilder` / `WasiView`
//! 等 WASI-0.2 Host 类型）。本 crate 是未来标准版本替换点（§8.2 强制分层：
//! 位于 runtime-wasm 之下、WASI 版本适配层；§24.2："这里是未来标准版本替换点"）。
//!
//! # 标准版本隔离（§8）
//!
//! - 0.1.0 production 只启用 WASI 0.2（§4.2 / §22.2："production 仅 p2"）；
//! - p3 尚未通过 §8.3 成熟度 Gate（wasmtime_wasi::p3 官方仍标记 experimental/
//!   incomplete）。本 crate **不启用** wasmtime-wasi 的 `p3` feature（§4.2
//!   MUST NOT：p3 不得进入 production dependency closure），因此本 crate
//!   源码中不存在任何 `wasmtime_wasi::p3` 类型引用；
//! - p3 是未来双栈 lab 方向（§8.4 side-by-side 迁移：production 保留
//!   WASI 0.2 adapter 供既有 Component 继续运行，独立 p3 适配供新 Component
//!   opt-in；禁止 flag-day）。届时本 crate 仍是 p2 侧替换点。
//!
//! # 无 ambient authority（§7.6 / P7）
//!
//! 默认 context 不获得宿主文件系统、网络、环境变量、进程环境或随机任意资源。
//! 逐项表达见 [`context::WasiContextBuilder`] 模块文档；每个 WASI 能力按
//! Runtime Policy 显式构建（[`capability::WasiCapabilities`]），
//! 构建失败整体拒绝（§17.2 deny-by-default，不允许静默跳过已声明能力）。
//!
//! # P4：只适配标准 WASI 0.2
//!
//! 本 crate 不创建 `operune:http` / `operune:clock` / `operune:file` 等平行
//! 接口（§4.2 / P4 / §52）：公开的 capability 规格只是 Host 侧 policy 配置
//! （决定把哪些**标准** WASI 接口以什么范围构建进 context），不是平行 Host API。
//!
//! # 公开 API 不泄漏 p2 具体类型（§8.2）
//!
//! 对外只提供项目自己的 typed port/value 类型：capability 规格
//!（[`capability`]）、不透明 context 句柄（[`context`]）、typed error
//!（[`error`]）。`wasmtime_wasi` 的 p2 具体类型（`WasiCtx` / `WasiCtxBuilder` /
//! `WasiView` / `p2::add_to_linker_sync`）只出现在两个受控 glue 例外中：
//! [`context::WasiContext::into_p2_inner`]（context 所有权迁移给 runtime-wasm
//! 的 `WasiP2HostState::new`）与 [`linker::add_to_linker`] 的 trait bound
//!（由 runtime-wasm 的 `StoreHostState` 满足）。
//!
//! # 与 runtime-wasm / application 的衔接点
//!
//! - **adapter 契约**：[`adapter`] 实现 runtime-wasm 的
//!   [`operune_runtime_wasm::wasi::WasiAdapter`]（本 crate 依赖 runtime-wasm
//!   ——port 定义层，§24.3；runtime-wasm 不依赖本 crate，无环）；
//! - **上下文**：[`context::WasiContext`] 是集成层需要持有的 WASI 0.2
//!   状态句柄；经 [`context::WasiContext::into_p2_inner`] 迁移给
//!   [`adapter`] 的 attach 安装（§8.2 受控 glue 例外，见其文档）；
//! - **linker**：[`linker::add_to_linker`] 是 WASI 0.2 世界组装点。由于
//!   wasmtime-wasi 36 的 `WasiView` binding trait 受 orphan rule 约束，
//!   其实现只能在持有 Store 类型的 crate（runtime-wasm 的 `StoreHostState`，
//!   §8.2 的 MUST NOT 列表不含 runtime-wasm），本 crate 以泛型
//!   `T: WasiView` 公开组装入口并测试覆盖；
//! - **policy 形状**：[`capability::WasiCapabilities`] 是 application 层按
//!   §17 grant 语义产生的能力值（见 [`adapter`] 的 policy 映射说明；
//!   socket 许可、宿主熵随机源等接线留到后续里程碑，YAGNI §12.6）；
//! - **guest fixture 集成测试**：留到 §30 conformance 阶段（本机无
//!   cargo-component/wasm-tools guest 工具链，已确认不可用）；本阶段只做
//!   host 侧可测部分（linker 组装、context 默认无权限、capability 校验、
//!   adapter attach、错误映射）。
//!
//! # 错误契约（§14.1）
//!
//! 所有第三方错误（anyhow / wasmtime / wasmtime_wasi）在适配层转换为
//! [`error::WasiP2Error`]，并以 `Box<dyn Error + Send + Sync>` 保留
//! `#[source]` 供诊断，不把第三方错误类型泄漏到公开契约。
//!
//! # 依赖说明（§22.2）
//!
//! - `wasmtime` 36.x LTS（同 release line）：仅 `component-model` + `std`
//!   features，`cranelift` 只在 dev-dependencies（测试需要 Engine）；
//! - `wasmtime-wasi` 36.x LTS：`default-features = false`（关闭 preview1
//!   遗留路径），`p3` feature 永不启用（§4.2）；
//! - `thiserror` 2.x：typed error（§14.1）。

pub mod adapter;
pub mod capability;
pub mod context;
pub mod error;
pub mod linker;
