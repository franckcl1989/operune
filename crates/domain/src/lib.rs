#![forbid(unsafe_code)]

//! Operune Core Domain（规范 §24.2：domain）。
//!
//! 纯领域类型、状态机、不变量、兼容规则。
//! 禁止 Wasmtime / Tokio / Axum / rusqlite（§24.2、§24.3 依赖方向：
//! domain 永不反向依赖 adapter；Domain/Application 不得出现面向
//! `x86_64` / `aarch64` 或具体设备厂商的条件分支）。
//!
//! 骨架阶段：暂无公开 API，按 YAGNI（§12.6）随真实需求增加。

// 骨架阶段无公开项。
