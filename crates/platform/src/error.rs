//! 平台层封闭错误（§14.1：thiserror 定义封闭、可匹配的 typed error；
//! 禁止 anyhow / eyre / `Box<dyn Error>` / String error）。
//!
//! 错误信息只包含可诊断信息（路径、环境变量名），不含任何 secret（§16.6）。

/// 平台层统一封闭错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PlatformError {
    /// 平台默认路径解析所需的宿主环境变量未设置（fail closed，§18.0）。
    #[error("required environment variable {variable} is not set")]
    MissingEnvironmentVariable {
        /// 缺失的环境变量名（静态字符串）。
        variable: &'static str,
    },

    /// 环境变量值必须是绝对路径（确定性 fail closed，§18.0）。
    #[error("environment variable {variable} must be an absolute path, got {value:?}")]
    NonAbsolutePath {
        /// 环境变量名（静态字符串）。
        variable: &'static str,
        /// 实际值（仅诊断；路径不是 secret，§16.6）。
        value: String,
    },

    /// 数据根目录值不合法（非绝对 / 空 / 含 NUL / 非 UTF-8）。
    #[error("invalid data root: {detail}")]
    InvalidDataRoot {
        /// 可诊断原因。
        detail: String,
    },

    /// BootstrapConfig 路径值不合法（空 / 含 NUL / 非 UTF-8）。
    #[error("invalid bootstrap config path: {detail}")]
    InvalidBootstrapConfigPath {
        /// 可诊断原因。
        detail: String,
    },
}
