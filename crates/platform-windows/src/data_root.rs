//! Windows 平台默认数据根目录解析（§18.0 冻结规则：`%LOCALAPPDATA%\operune`）。

use std::path::PathBuf;

use operune_platform::{DataRoot, DataRootResolver, Environment, PlatformError, RealEnvironment};

/// Windows 宿主默认数据根目录解析器（§18.0）。
///
/// 冻结规则：`%LOCALAPPDATA%\operune`。
///
/// - `LOCALAPPDATA` 未设置 → [`PlatformError::MissingEnvironmentVariable`]
///   （fail closed，§18.0）；
/// - `LOCALAPPDATA` 非绝对路径 → [`PlatformError::NonAbsolutePath`]
///   （fail closed，确定性）；
/// - 否则 `DataRoot::new(LOCALAPPDATA.join("operune"))`（内部校验：绝对、
///   非空、UTF-8、无 NUL）。
///
/// 环境视图可注入（[`Environment`]），测试无需触碰真实进程环境；
/// 真实环境用 [`WindowsDataRootResolver::real`]。
#[derive(Debug, Clone)]
pub struct WindowsDataRootResolver<E: Environment> {
    env: E,
}

impl WindowsDataRootResolver<RealEnvironment> {
    /// 使用真实进程环境的解析器。
    pub fn real() -> Self {
        Self::new(RealEnvironment)
    }
}

impl<E: Environment> WindowsDataRootResolver<E> {
    /// 使用给定环境视图的解析器（测试注入）。
    pub fn new(env: E) -> Self {
        Self { env }
    }
}

impl<E: Environment> DataRootResolver for WindowsDataRootResolver<E> {
    fn default_data_root(&self) -> Result<DataRoot, PlatformError> {
        const LOCAL_APPDATA: &str = "LOCALAPPDATA";
        let raw = self
            .env
            .var(LOCAL_APPDATA)
            .ok_or(PlatformError::MissingEnvironmentVariable {
                variable: LOCAL_APPDATA,
            })?;
        let base = PathBuf::from(raw);
        if !base.is_absolute() {
            return Err(PlatformError::NonAbsolutePath {
                variable: LOCAL_APPDATA,
                value: base.to_string_lossy().into_owned(),
            });
        }
        DataRoot::new(base.join("operune"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::Path;

    #[derive(Debug, Clone)]
    struct StaticEnvironment {
        pairs: Vec<(String, OsString)>,
    }

    impl Environment for StaticEnvironment {
        fn var(&self, name: &str) -> Option<OsString> {
            self.pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        }
    }

    fn environment(pairs: &[(&str, &str)]) -> StaticEnvironment {
        StaticEnvironment {
            pairs: pairs
                .iter()
                .map(|(key, value)| (key.to_string(), OsString::from(value)))
                .collect(),
        }
    }

    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    #[test]
    fn resolves_localappdata_operune() {
        let base = std::env::temp_dir();
        let resolver =
            WindowsDataRootResolver::new(environment(&[("LOCALAPPDATA", &base.to_string_lossy())]));
        let root = ok(resolver.default_data_root(), "resolve data root");
        assert_eq!(root.as_path(), base.join("operune"));
    }

    #[cfg(windows)]
    #[test]
    fn resolves_windows_literal_path() {
        let resolver = WindowsDataRootResolver::new(environment(&[(
            "LOCALAPPDATA",
            "C:\\Users\\dev\\AppData\\Local",
        )]));
        let root = ok(resolver.default_data_root(), "resolve data root");
        assert_eq!(
            root.as_path(),
            Path::new("C:\\Users\\dev\\AppData\\Local\\operune")
        );
    }

    #[test]
    fn missing_localappdata_fails_closed() {
        let resolver = WindowsDataRootResolver::new(environment(&[]));
        assert!(matches!(
            resolver.default_data_root(),
            Err(PlatformError::MissingEnvironmentVariable {
                variable: "LOCALAPPDATA"
            })
        ));
    }

    #[test]
    fn relative_localappdata_fails_closed() {
        let resolver =
            WindowsDataRootResolver::new(environment(&[("LOCALAPPDATA", "AppData\\Local")]));
        assert!(matches!(
            resolver.default_data_root(),
            Err(PlatformError::NonAbsolutePath {
                variable: "LOCALAPPDATA",
                ..
            })
        ));
    }

    #[test]
    fn real_environment_consistency() {
        // 仅当本机真实设置了 LOCALAPPDATA 时断言一致性（Windows 开发机必然
        // 命中；未设置时静默跳过，保证任何 CI 环境确定通过）。
        let Some(raw) = std::env::var_os("LOCALAPPDATA") else {
            return;
        };
        let base = PathBuf::from(raw);
        let resolver = WindowsDataRootResolver::real();
        if base.is_absolute() {
            let root = ok(
                resolver.default_data_root(),
                "absolute LOCALAPPDATA must resolve",
            );
            assert_eq!(root.as_path(), base.join("operune"));
        } else {
            // 相对值在 is_absolute 检查处确定性失败（在进入 DataRoot 校验之前）。
            assert!(matches!(
                resolver.default_data_root(),
                Err(PlatformError::NonAbsolutePath { .. })
            ));
        }
    }
}
