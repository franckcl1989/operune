#![forbid(unsafe_code)]

//! Operune Windows 平台 adapter（规范 §24.2：platform-windows）。
//!
//! §9.4：唯一允许承载 Windows 特定 `cfg` 和 safe wrapper integration 的
//! 地方；平台差异不得泄漏为 Domain 公共契约。
//!
//! 0.1.0 提供 §18.0 冻结的 Windows 默认数据根目录解析
//! （`%LOCALAPPDATA%\operune`，见 [`WindowsDataRootResolver`]）。
//! 实现为纯 Safe Rust：`std::env` 环境读取 + `std::path` 校验，当前无需
//! 任何 `#[cfg]` 条件分支。

mod data_root;

pub use data_root::WindowsDataRootResolver;
