#![forbid(unsafe_code)]

//! Operune 跨平台 port / value definitions（规范 §24.2：platform）。
//!
//! 本 crate 只定义**跨平台**的 port（trait / 函数签名）与 typed value，
//! **不含任何 OS 具体实现**（§9.4、§24.2）：
//!
//! - OS 特定实现只允许落在 `platform-*` adapter crates（platform-linux /
//!   platform-windows / platform-macos）；
//! - 本 crate 内禁止任何 `#[cfg(target_os)]` / `#[cfg(target_arch)]` 之类的
//!   平台条件分支（§9.4：平台与架构差异不得散落在非 adapter 层，也不得泄漏
//!   为 Domain 公共契约）；
//! - 平台差异若在含义上无法统一，只能通过 capability availability / variant
//!   表达（§9.4），本 crate 遵循该边界。
//!
//! # 0.1.0 公开面
//!
//! - [`DataRootResolver`]：平台默认数据根目录解析 port（§18.0：0.1.0 正式
//!   交付冻结一个平台默认路径；本 crate 只声明语义与解析规则）；
//! - [`DataRoot`]：受校验的宿主数据根目录（绝对路径，跨平台校验）；
//! - [`BootstrapConfigPath`]：`--config <path>` 的受校验输入类型（§18.0）；
//! - [`PlatformFamily`]：宿主 OS family 标识（§9.1）；
//! - [`Environment`] / [`RealEnvironment`]：平台解析规则的外部输入视图
//!   （可注入，供测试与 platform-* adapter 复用）；
//! - [`PlatformError`]：封闭 typed error（§14.1）。
//!
//! # Secret（§16.6）
//!
//! 路径与环境变量名不是 secret，可进入错误与日志；本 crate 的 API 不接收
//! 任何 secret 值。

mod bootstrap;
mod data_root;
mod environment;
mod error;
mod family;
#[cfg(test)]
mod test_support;

pub use bootstrap::BootstrapConfigPath;
pub use data_root::{DEFAULT_BOOTSTRAP_CONFIG_RELATIVE, DataRoot, DataRootResolver};
pub use environment::{Environment, RealEnvironment};
pub use error::PlatformError;
pub use family::PlatformFamily;

/// 校验路径值：有效 UTF-8、非空、不含 NUL（跨平台；§13.3 validate-on-construct）。
///
/// 平台特定检查（如 Windows 盘符）由 platform-* adapter 负责（§9.4）。
pub(crate) fn validate_path_value(path: &std::path::Path) -> Result<(), String> {
    let text = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    if text.is_empty() {
        return Err("path must not be empty".to_string());
    }
    if text.contains('\0') {
        return Err("path must not contain NUL".to_string());
    }
    Ok(())
}
