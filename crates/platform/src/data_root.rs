//! 平台默认数据根目录 port（§18.0）。
//!
//! # 0.1.0 冻结的平台默认路径语义
//!
//! 0.1.0 正式交付冻结一个平台默认路径（§18.0）：[`DataRootResolver::default_data_root`]
//! 解析的宿主默认数据根目录。本模块只**声明**语义与解析规则；实际解析
//! （读取环境变量、拼接路径）由各 `platform-*` adapter crate 实现
//! （§9.4、§24.2），冻结规则如下：
//!
//! | OS family | 冻结规则 | 失败行为 |
//! |---|---|---|
//! | Linux | `$XDG_DATA_HOME/operune`；`XDG_DATA_HOME` 未设置或为相对路径时回退 `$HOME/.local/share/operune` | 均不可得 → fail closed |
//! | Windows | `%LOCALAPPDATA%\operune` | 未设置或非绝对路径 → fail closed |
//! | macOS | `$HOME/Library/Application Support/operune` | `HOME` 未设置 → fail closed |
//!
//! 解析失败一律 fail closed（§18.0：配置缺失/解析失败必须 fail closed，并
//! 保留本机 recovery/bootstrap CLI 所需的最小恢复路径）。
//!
//! # Port 形状
//!
//! [`DataRootResolver`] 是解析 port（trait）；0.1.0 由 platform-windows
//! 提供 Windows 实现（`WindowsDataRootResolver`），Linux / macOS 实现随
//! 各自 adapter 落地（§9.4：实现只允许在 platform-* adapter）。

use std::path::{Path, PathBuf};

use operune_domain::ArtifactPath;

use crate::error::PlatformError;

/// 默认 BootstrapConfig 在 data root 下的相对位置（§18.0）。
///
/// 0.1.0 冻结的默认 BootstrapConfig 路径 = 默认 data root /
/// [`DEFAULT_BOOTSTRAP_CONFIG_RELATIVE`]（见
/// [`DataRoot::default_bootstrap_config_path`]）；CLI 的 `--config <path>`
/// 只选择整份 BootstrapConfig，不改变本默认值。该相对位置按
/// [`ArtifactPath`] 规则校验（跨平台、相对、无 `.`/`..`）。
pub const DEFAULT_BOOTSTRAP_CONFIG_RELATIVE: &str = "config/operune.toml";

/// 受校验的宿主数据根目录（§18.0 / §18.7）。
///
/// 不变量（validate-on-construct，§13.3）：
/// - 绝对路径（`Path::is_absolute`，跨平台语义）；
/// - 非空；
/// - 有效 UTF-8；
/// - 不含 NUL。
///
/// 校验只使用跨平台 `std::path` API，不含任何 `#[cfg]`（§9.4：平台差异
/// 只允许在 platform-* adapter）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataRoot(PathBuf);

impl DataRoot {
    /// 校验构造（§13.3：边界解析一次，内部保持强类型）。
    pub fn new(path: PathBuf) -> Result<DataRoot, PlatformError> {
        crate::validate_path_value(&path)
            .map_err(|detail| PlatformError::InvalidDataRoot { detail })?;
        if !path.is_absolute() {
            return Err(PlatformError::InvalidDataRoot {
                detail: format!("path must be absolute, got {path:?}"),
            });
        }
        Ok(DataRoot(path))
    }

    /// 绝对路径视图。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// 在 data root 下解析制品相对路径（§18.7 staging / quarantine /
    /// content-addressed artifact 空间）。
    ///
    /// `relative` 已由 [`ArtifactPath`] 校验（相对、无 `.`/`..` 段、无控制
    /// 字符、`/` 分隔），`Path::join` 不可失败。
    pub fn resolve(&self, relative: &ArtifactPath) -> PathBuf {
        self.0.join(relative.as_str())
    }

    /// 默认 BootstrapConfig 文件位置（§18.0 冻结默认路径）：
    /// `data_root` / [`DEFAULT_BOOTSTRAP_CONFIG_RELATIVE`]。
    pub fn default_bootstrap_config_path(&self) -> PathBuf {
        self.0.join(DEFAULT_BOOTSTRAP_CONFIG_RELATIVE)
    }
}

/// 平台默认数据根目录解析 port（§18.0）。
///
/// 语义：返回宿主默认数据根目录（绝对路径）。解析失败必须 fail closed
/// （返回 [`PlatformError`]），不得猜测或静默回退到未定义位置。
///
/// 实现位置：`platform-*` adapter crate（§9.4）；本 crate 只声明签名与语义。
/// 对象安全：server 可用 `Box<dyn DataRootResolver>` 注入。
pub trait DataRootResolver {
    /// 解析宿主默认数据根目录。
    fn default_data_root(&self) -> Result<DataRoot, PlatformError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use operune_domain::ArtifactPath;

    #[test]
    fn accepts_absolute_paths() {
        let root = ok(
            DataRoot::new(std::env::temp_dir().join("operune-test")),
            "absolute path",
        );
        assert!(root.as_path().is_absolute());
    }

    #[test]
    fn rejects_relative_paths() {
        assert!(matches!(
            DataRoot::new(PathBuf::from("relative/operune")),
            Err(PlatformError::InvalidDataRoot { .. })
        ));
    }

    #[test]
    fn rejects_empty_and_nul() {
        assert!(matches!(
            DataRoot::new(PathBuf::from("")),
            Err(PlatformError::InvalidDataRoot { .. })
        ));
        assert!(matches!(
            DataRoot::new(std::env::temp_dir().join("operune\0test")),
            Err(PlatformError::InvalidDataRoot { .. })
        ));
    }

    #[test]
    fn resolves_artifact_paths_under_root() {
        let root = ok(
            DataRoot::new(std::env::temp_dir().join("operune-test")),
            "data root",
        );
        let relative = ok(ArtifactPath::new("staging/a.wasm"), "artifact path");
        let resolved = root.resolve(&relative);
        assert_eq!(
            resolved,
            std::env::temp_dir()
                .join("operune-test")
                .join("staging/a.wasm")
        );
    }

    #[test]
    fn default_bootstrap_config_path_is_frozen() {
        let root = ok(
            DataRoot::new(std::env::temp_dir().join("operune-test")),
            "data root",
        );
        assert_eq!(
            root.default_bootstrap_config_path(),
            root.as_path().join(DEFAULT_BOOTSTRAP_CONFIG_RELATIVE)
        );
        // 冻结的相对位置必须本身是合法 ArtifactPath（跨平台相对路径语义）。
        assert!(ArtifactPath::new(DEFAULT_BOOTSTRAP_CONFIG_RELATIVE).is_ok());
    }
}
