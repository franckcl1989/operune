#![forbid(unsafe_code)]

//! Operune Core Domain（规范 §24.2：domain）。
//!
//! 纯领域类型、状态机、不变量、兼容规则。
//! 禁止 Wasmtime / Tokio / Axum / rusqlite（§24.2、§24.3 依赖方向：domain
//! 永不反向依赖 adapter；Domain/Application 不得出现面向 `x86_64` /
//! `aarch64` 或具体设备厂商的条件分支）。
//!
//! # 0.1.0 公开面（§39.2 MUST scope 中的 domain 部分）
//!
//! - 四种身份（§19.4，必须永久分离，彼此类型不同且不存在相互转换）：
//!   - [`ComponentId`]：作者声明的逻辑产品/应用身份（与 WIT
//!     `operune:component@0.1.0` 的 `component-id` 契约对齐）；
//!   - [`ComponentVersion`]：作者声明的发布版本（与 WIT `component-version`
//!     契约对齐：major/minor/patch 三段 u32）；
//!   - [`ContentDigest`]：实际收到的原始字节的不可变内容事实（固定长度
//!     SHA-256，不是任意 `Vec<u8>`，§13.2）；
//!   - [`InstallationId`]：Core 创建并持久化的安装实例身份（§19.4，承载
//!     grant / enable / active 状态与本机生命周期）。
//! - 平台能力身份（§17）：[`CapabilityId`]。
//! - 生命周期状态机（§12.2 / §19）：[`ComponentLifecycleState`] 与
//!   [`ComponentLifecycleEvent`]，闭集 enum + 显式转换校验，非法转换返回
//!   typed error，绝不静默忽略。
//! - 资源语义类型（§13.1 / §13.2）：[`ByteSize`]（字节数量）、[`Duration`]
//!   （非负时间间隔）、[`Deadline`]（单调时钟绝对截止时间）、[`ArtifactPath`]
//!   （受校验的制品相对路径，§18.7 / §21.3）。
//! - 封闭 typed error（§14.1）：[`DomainError`]，禁止 anyhow / eyre /
//!   `Box<dyn Error>` / String error。
//!
//! # 设计约束
//!
//! - 全部值类型 validate-on-construct（§13.3 边界解析一次，内部保持强类型，
//!   §13.1 / §13.2 禁止 primitive obsession）。
//! - 全部算术使用 checked / saturating / try-conversion（§14.4，禁止回绕）。
//! - 所有值对象均为不可变值类型（`Send` + `Sync` 自动成立），无全局可变状态
//!   （§12.4）。

#[cfg(test)]
mod test_support;

mod digest;
mod error;
mod id;
mod lifecycle;
mod path;
mod size;
mod time;
mod version;

pub use digest::ContentDigest;
pub use error::{DomainError, ValueKind};
pub use id::{CapabilityId, ComponentId, InstallationId};
pub use lifecycle::{ComponentLifecycleEvent, ComponentLifecycleState};
pub use path::ArtifactPath;
pub use size::ByteSize;
pub use time::{Deadline, Duration};
pub use version::ComponentVersion;
