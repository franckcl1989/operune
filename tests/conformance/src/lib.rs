#![forbid(unsafe_code)]

//! Operune Component Conformance Suite（规范 §30、§27、§39.4）。
//!
//! 本 crate 是 Runtime 的产品测试套件：**测试 Component 是 Runtime 符合性
//! 夹具，不是产品插件**（§30）。Conformance Suite 是 Runtime 的产品测试，
//! 不依赖任何具体监控/日志插件（§30 末句）——全部夹具与断言只通过项目
//! 公开 typed API 消费：
//!
//! - **runtime-wasm**（§7 运行模型）：[`operune_runtime_wasm::EngineConfig`] /
//!   [`operune_runtime_wasm::EngineHandle`] / [`operune_runtime_wasm::StoreFactory`] /
//!   [`operune_runtime_wasm::StoreHandle`] / [`operune_runtime_wasm::InstanceSet`] /
//!   [`operune_runtime_wasm::ResourceBudget`]（limiter）/ epoch
//!   （[`operune_runtime_wasm::EpochTicker`] + [`operune_runtime_wasm::StoreHandle::set_deadline`]）/
//!   [`operune_runtime_wasm::classify_wasm_error`]；
//! - **application**（§19 两阶段安装 / §24.2 编排层）：[`operune_application::WasmtimeRuntime`] /
//!   [`operune_application::InstallService`] / [`operune_application::WasmRuntime`] /
//!   ports（[`operune_application::ComponentRegistryPort`] 等）；
//! - **runtime-wasi-p2**（§7.6 能力规格）：[`operune_runtime_wasi_p2::capability::WasiCapabilities`] /
//!   [`operune_runtime_wasi_p2::adapter::WasiContextAdapter`]；
//! - **domain**（§18.3 记录类型）：[`operune_domain`]。
//!
//! wasmtime 具体类型（[`wasmtime::component::Linker`] / `Instance` / `Func`）只在
//! 集成测试面出现（runtime-wasm engine.rs / store.rs 定义的"受控泄漏点"，
//! §8.2——与 application 的 [`operune_application::WasmtimeRuntime`] 同一位置）。
//!
//! # §30 清单覆盖矩阵（本机工具链可构建部分）
//!
//! 夹具实体见 [`fixtures`]（wat 内联常量）；每个夹具的 §30 条目、验证的
//! §39.4/§7.4/§7.5 验收项与测试断言见 [`runtime_suite`] 与 [`pipeline_suite`]。
//!
//! | §30 条目 | 夹具 | 验收项 |
//! |---|---|---|
//! | minimal valid Component | `MINIMAL_COMPONENT` | §39.4 基线：验证/编译/实例化闭环 |
//! | malformed bytes | `MALFORMED_BYTES` + `CORE_MODULE_NOT_COMPONENT` | §39.4 非法 Component 不能拖垮 Core；§19.2 阶段二拒绝 |
//! | unknown import | `UNKNOWN_IMPORT_COMPONENT` | §39.4 未授权/未知 import 不能成为 Active（link 期拒绝，§17.2/§19.5） |
//! | denied capability | `UNKNOWN_IMPORT_COMPONENT`（零能力 vs 显式 grant）+ 零权限 Store | §32 未授权 Component 无宿主能力；§7.6 无 ambient authority |
//! | memory grow attacker | `MEMORY_GROW_COMPONENT` / `HUGE_MEMORY_COMPONENT` | §39.4 memory over-limit 确定拒绝或 trap；§7.4 limiter |
//! | infinite loop | `SPIN_LOOP_COMPONENT` / `SPIN_ON_INIT_COMPONENT` | §39.4 infinite loop 能按 deadline 中断（epoch，§7.5） |
//! | trap on init | `TRAP_ON_INIT_COMPONENT` | §14.1 typed trap 分类；§39.4 恶意 Component 不可拖垮宿主 |
//! | slow/drain component | `SLOW_COMPONENT` | §20.4 drain：关闭后不接新工作、已发放租约运行到结束 |
//! | （两阶段安装拒绝路径） | `MALFORMED_BYTES` / `MINIMAL_COMPONENT` / oversized 输入 | §19.2 quarantine：非法/缺契约面字节不产生 candidate；§32 oversized 提前拒绝 |
//!
//! # 已知工具链缺口（本机不可构建，0.1.0 已知非阻塞）
//!
//! 完整清单与说明见 [`gaps`]。要点：descriptor 确定性、grant-expansion
//! upgrade、Web assets + sandbox escape、health check failure、incompatible
//! contract/interface version 等夹具需要导出 `operune:component@0.1.0` /
//! `operune:web@0.1.0` WIT 契约的 guest 组件（canonical ABI 必须由
//! cargo-component/wasm-tools 生成）；本机无该工具链（已多次确认），且
//! wasmtime 36 对手写 wat 的内联 record/variant/enum import/export 有
//! named-type 注册要求（见 application runtime.rs 测试注释），无法以 wat
//! 文本伪造。按用户原则"本机无法支持的暂时略过不阻塞整体进度"记录为
//! 0.1.0 已知非阻塞缺口，待工具链就绪后补充——**不写空测试**（缺口的
//! 存在由 [`gaps`] 的清单测试显式审计，防止静默遗忘）。
//!
//! # Safe Rust（§11 / §14.2）
//!
//! 本 crate 遵循 workspace 强制：`#![forbid(unsafe_code)]`；测试代码无
//! `unwrap`/`expect`/`panic!`/`todo!`/`unimplemented!`——断言式失败统一走
//! [`test_support::test_failure`]（runtime-wasm / application 的 test_support
//! 同模式，§26.1 允许测试断言语义）。

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod gaps;
#[cfg(test)]
mod pipeline_suite;
#[cfg(test)]
mod runtime_suite;
#[cfg(test)]
mod test_support;
