//! BootstrapConfig 路径 port（§18.0）。
//!
//! §18.0：BootstrapConfig 是单个 TOML 文件，其路径解析必须**确定**：
//!
//! - 未指定 `--config` 时使用默认路径
//!   （默认 data root / `config/operune.toml`，见
//!   [`crate::DataRoot::default_bootstrap_config_path`]）；
//! - 指定 `--config <path>` 时，该路径**只选择整份 BootstrapConfig**，
//!   不是单项 override；
//! - production 不支持环境变量覆盖 BootstrapConfig 字段，不做当前目录搜索、
//!   多个 TOML merge 或 `CLI > env > file > DB` 式隐式优先级；
//! - 相对路径在启动时相对当前工作目录解析一次（确定性；由 server/CLI 层
//!   执行），之后不再重新解析。
//!
//! 本类型是 `--config <path>` 的受校验输入类型（§13.3：边界解析一次）。

use std::path::{Path, PathBuf};

use crate::error::PlatformError;

/// 受校验的 BootstrapConfig 文件路径（§18.0：`--config <path>` 输入类型）。
///
/// 不变量（validate-on-construct，§13.3）：非空、有效 UTF-8、不含 NUL。
/// 不做平台特定检查（本 crate 零 cfg，§9.4）；相对路径的确定性解析由
/// server/CLI 层执行并文档化为 §18.0 规则。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BootstrapConfigPath(PathBuf);

impl BootstrapConfigPath {
    /// 校验构造（§13.3：边界解析一次）。
    pub fn new(path: PathBuf) -> Result<BootstrapConfigPath, PlatformError> {
        crate::validate_path_value(&path)
            .map_err(|detail| PlatformError::InvalidBootstrapConfigPath { detail })?;
        Ok(BootstrapConfigPath(path))
    }

    /// 路径视图。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// 释放路径。
    pub fn into_path(self) -> PathBuf {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn accepts_config_paths() {
        assert!(BootstrapConfigPath::new(PathBuf::from("operune.toml")).is_ok());
        assert!(BootstrapConfigPath::new(std::env::temp_dir().join("config.toml")).is_ok());
    }

    #[test]
    fn rejects_empty_and_nul() {
        assert!(matches!(
            BootstrapConfigPath::new(PathBuf::from("")),
            Err(PlatformError::InvalidBootstrapConfigPath { .. })
        ));
        assert!(matches!(
            BootstrapConfigPath::new(PathBuf::from("a\0b.toml")),
            Err(PlatformError::InvalidBootstrapConfigPath { .. })
        ));
    }

    #[test]
    fn into_path_roundtrip() {
        let original = std::env::temp_dir().join("operune.toml");
        let path = ok(BootstrapConfigPath::new(original.clone()), "config path");
        assert_eq!(path.into_path(), original);
    }
}
