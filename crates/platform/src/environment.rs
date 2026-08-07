//! 平台解析规则的外部输入视图（可注入；供测试与 platform-* adapter 复用）。
//!
//! §18.0：production 不支持环境变量覆盖 BootstrapConfig 字段——本 trait 只
//! 用于平台默认路径解析读取宿主启动事实（如 `LOCALAPPDATA` / `XDG_DATA_HOME` /
//! `HOME`），不构成任何配置覆盖机制。

use std::ffi::OsString;

/// 进程环境的只读视图（平台默认路径解析的输入类型，§18.0）。
///
/// 平台 adapter 通过本 trait 读取宿主环境事实；测试注入固定视图即可确定性
/// 验证解析规则，无需触碰真实进程环境。
pub trait Environment {
    /// 读取环境变量；未设置时返回 `None`。
    fn var(&self, name: &str) -> Option<OsString>;
}

/// 真实进程环境（`std::env::var_os` 的薄封装）。
///
/// 纯跨平台 Safe Rust（§11.1），不含任何 `#[cfg]`（§9.4：环境读取是标准库
/// 能力，不是 OS 特定实现）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RealEnvironment;

impl Environment for RealEnvironment {
    fn var(&self, name: &str) -> Option<OsString> {
        std::env::var_os(name)
    }
}
