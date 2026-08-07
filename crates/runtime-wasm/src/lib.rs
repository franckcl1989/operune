#![forbid(unsafe_code)]

//! Operune Wasm Runtime adapter（规范 §24.2：runtime-wasm）。
//!
//! Wasmtime Engine / Component / Store、资源治理、trap/error mapping、
//! instance model。对上暴露项目自己的 typed ports，不把 Wasmtime
//! 具体类型泄漏到 Domain/Application 契约（§24.3、§22.2）。
//!
//! 骨架阶段：暂无公开 API，按 YAGNI（§12.6）随真实需求增加。

// 骨架阶段无公开项。
