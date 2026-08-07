//! 宿主 OS family（§9.1）。

use std::fmt;

/// 当前 Runtime Host Node 的 OS family（§9.1：一等宿主 OS 家族冻结为
/// Linux / Windows / macOS）。
///
/// 语义：仅描述 OS family 本身，不包含任何平台具体行为；本 crate 不做任何
/// target 推导（零 cfg，§9.4），本类型只作为平台 port 的标识值，供 adapter
/// 声明其实现的 family 与文档/诊断使用。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlatformFamily {
    /// Linux（§9.3：0.1.0 Production Supported）。
    Linux,
    /// Windows（§9.3：0.1.0 一等开发/CI + Production Candidate）。
    Windows,
    /// macOS（§9.3：0.1.0 一等开发/CI + Production Candidate）。
    MacOs,
}

impl fmt::Display for PlatformFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Linux => "linux",
            Self::Windows => "windows",
            Self::MacOs => "macos",
        };
        f.write_str(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_names() {
        assert_eq!(PlatformFamily::Linux.to_string(), "linux");
        assert_eq!(PlatformFamily::Windows.to_string(), "windows");
        assert_eq!(PlatformFamily::MacOs.to_string(), "macos");
    }
}
