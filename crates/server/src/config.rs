//! BootstrapConfig → adapter 配置的**确定性**映射（§18.0 / §24.2 wiring）。
//!
//! - [`resolve_config_path`]：`--config <path>` 只选择整份 BootstrapConfig
//!   （§18.0）；缺省时用平台默认路径 = 默认 data root /
//!   `config/operune.toml`（§18.0 冻结，`operune_platform::DataRoot`）；
//! - [`executor_config`]：BootstrapConfig → StorageExecutor 配置；
//! - [`tracing_config`]：BootstrapConfig 日志 → observability 配置（audit
//!   target 强制至少 INFO：audit 通道不得被日志级别过滤掉，§18.7）。

use std::path::PathBuf;

use operune_observability::{AUDIT_LOG_TARGET, TracingConfig};
use operune_platform::{BootstrapConfigPath, DataRootResolver};
use tracing::level_filters::LevelFilter;

use crate::bootstrap::{BootstrapConfig, LogFormat, LogLevel};
use crate::error::ServerError;

/// 解析 BootstrapConfig 文件路径（§18.0：只选择整份文件；相对路径按 CLI
/// 提供的原样使用——不重新解析，确定性）。
///
/// - `Some(path)`：`--config <path>`，边界已由
///   [`BootstrapConfigPath`] 校验（§13.3：非空/UTF-8/无 NUL；此处再校验
///   一次，双保险）；
/// - `None`：平台默认 data root 的 `default_bootstrap_config_path()`
///   （解析失败 fail closed，§18.0）。
pub fn resolve_config_path(
    config_arg: Option<PathBuf>,
    resolver: &dyn DataRootResolver,
) -> Result<PathBuf, ServerError> {
    match config_arg {
        Some(path) => {
            let validated = BootstrapConfigPath::new(path).map_err(ServerError::ConfigPath)?;
            Ok(validated.into_path())
        }
        None => {
            let data_root = resolver
                .default_data_root()
                .map_err(ServerError::ConfigPath)?;
            Ok(data_root.default_bootstrap_config_path())
        }
    }
}

/// BootstrapConfig → [`operune_storage_sqlite::ExecutorConfig`]（§18.2）。
///
/// `data_root` 与 artifact 磁盘预算来自宿主启动事实（§18.0）；队列容量与
/// artifact 硬上限取 ExecutorConfig 的存储侧默认（§18.2 / §19.1）。
pub fn executor_config(
    bootstrap: &BootstrapConfig,
) -> Result<operune_storage_sqlite::ExecutorConfig, ServerError> {
    let data_root = operune_storage_sqlite::artifact::DataRoot::new(bootstrap.data_root.clone())?;
    let mut config = operune_storage_sqlite::ExecutorConfig::new(data_root)?;
    config.budget = bootstrap.storage.budget;
    Ok(config)
}

/// BootstrapConfig 日志 → [`TracingConfig`]（§22.7）。
///
/// audit target（`operune::audit`，§18.7 审计通道）强制至少 INFO，避免
/// 用户把默认级别调高后审计日志被过滤掉；其余 target 按配置过滤。
pub fn tracing_config(bootstrap: &BootstrapConfig) -> TracingConfig {
    TracingConfig {
        default_level: bootstrap.logging.level.to_level_filter(),
        target_overrides: Vec::new(),
        format: match bootstrap.logging.format {
            LogFormat::Compact => operune_observability::LogFormat::Compact,
            LogFormat::Json => operune_observability::LogFormat::Json,
        },
    }
    .with_target_override(AUDIT_LOG_TARGET, LevelFilter::INFO)
}

impl LogLevel {
    /// 映射到 tracing 过滤级别。
    pub fn to_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        AdminListener, BootstrapConfig, LoggingConfig, StorageConfig, TlsIdentityRef,
    };
    use operune_platform::{DataRoot, PlatformError};
    use std::net::IpAddr;
    use std::str::FromStr;

    /// 断言式取值助手（§14.2）。
    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    fn bootstrap_with(data_root: PathBuf) -> BootstrapConfig {
        BootstrapConfig {
            data_root,
            admin: AdminListener {
                address: ok(IpAddr::from_str("127.0.0.1"), "loopback address"),
                port: 8787,
            },
            tls: None,
            logging: LoggingConfig {
                level: crate::bootstrap::LogLevel::Info,
                format: LogFormat::Compact,
            },
            storage: StorageConfig {
                budget: operune_storage_sqlite::artifact::DiskBudget::default(),
            },
        }
    }

    fn tls_bootstrap(data_root: PathBuf) -> BootstrapConfig {
        let mut config = bootstrap_with(data_root);
        config.tls = Some(TlsIdentityRef {
            cert_chain: PathBuf::from("certs/chain.pem"),
            private_key: PathBuf::from("certs/key.pem"),
        });
        config
    }

    /// 固定视图 resolver（§18.0：平台默认路径解析规则由 platform-* 测试）。
    #[derive(Debug, Clone)]
    struct FixedResolver(PathBuf);

    impl DataRootResolver for FixedResolver {
        fn default_data_root(&self) -> Result<DataRoot, PlatformError> {
            DataRoot::new(self.0.clone())
        }
    }

    /// 失败视图 resolver（§18.0：解析失败 fail closed）。
    struct FailingResolver;

    impl DataRootResolver for FailingResolver {
        fn default_data_root(&self) -> Result<DataRoot, PlatformError> {
            Err(PlatformError::MissingEnvironmentVariable {
                variable: "LOCALAPPDATA",
            })
        }
    }

    #[test]
    fn explicit_config_path_wins_deterministically() {
        let explicit = PathBuf::from("my-config/operune.toml");
        let resolved = ok(
            resolve_config_path(
                Some(explicit.clone()),
                &FixedResolver(PathBuf::from("ignored")),
            ),
            "explicit path",
        );
        assert_eq!(resolved, explicit);
    }

    #[test]
    fn default_config_path_uses_data_root_relative() {
        let root = std::env::temp_dir().join("operune-config-test");
        let resolved = ok(
            resolve_config_path(None, &FixedResolver(root.clone())),
            "default",
        );
        assert_eq!(
            resolved,
            root.join(operune_platform::DEFAULT_BOOTSTRAP_CONFIG_RELATIVE)
        );
    }

    #[test]
    fn default_resolution_failure_fails_closed() {
        assert!(matches!(
            resolve_config_path(None, &FailingResolver),
            Err(ServerError::ConfigPath(
                PlatformError::MissingEnvironmentVariable {
                    variable: "LOCALAPPDATA"
                }
            ))
        ));
    }

    #[test]
    fn invalid_explicit_config_path_fails_closed() {
        assert!(matches!(
            resolve_config_path(
                Some(PathBuf::from("a\0b.toml")),
                &FixedResolver(PathBuf::from("x"))
            ),
            Err(ServerError::ConfigPath(
                PlatformError::InvalidBootstrapConfigPath { .. }
            ))
        ));
    }

    #[test]
    fn executor_config_carries_data_root_and_budget() {
        let root = ok(
            operune_storage_sqlite::artifact::DataRoot::new(
                std::env::temp_dir().join("op-exec-test"),
            ),
            "storage data root",
        );
        let config = ok(
            executor_config(&bootstrap_with(root.as_path().to_path_buf())),
            "executor config",
        );
        assert_eq!(config.data_root, root);
        assert_eq!(
            config.budget,
            operune_storage_sqlite::artifact::DiskBudget::default()
        );
    }

    #[test]
    fn executor_config_rejects_relative_data_root() {
        assert!(matches!(
            executor_config(&bootstrap_with(PathBuf::from("relative/operune"))),
            Err(ServerError::Storage(
                operune_storage_sqlite::StorageError::InvalidArgument(_)
            ))
        ));
    }

    #[test]
    fn tracing_config_maps_level_and_format() {
        let mut config = bootstrap_with(std::env::temp_dir().join("op-tracing-test"));
        config.logging = LoggingConfig {
            level: crate::bootstrap::LogLevel::Warn,
            format: LogFormat::Json,
        };
        let tracing = tracing_config(&config);
        assert_eq!(tracing.default_level, LevelFilter::WARN);
        assert_eq!(tracing.format, operune_observability::LogFormat::Json);
        // §18.7：audit target 强制至少 INFO（不受默认级别调高影响）。
        assert!(tracing.target_overrides.iter().any(|override_| {
            override_.target == AUDIT_LOG_TARGET && override_.level == LevelFilter::INFO
        }));
    }

    #[test]
    fn tracing_config_default_shape() {
        let config = tracing_config(&bootstrap_with(std::env::temp_dir().join("op-tracing2")));
        assert_eq!(config.default_level, LevelFilter::INFO);
        assert_eq!(config.format, operune_observability::LogFormat::Compact);
    }

    #[test]
    fn tls_reference_preserved_for_assembly() {
        let config = tls_bootstrap(std::env::temp_dir().join("op-tls-ref"));
        let tls = match config.tls {
            Some(tls) => tls,
            None => unreachable!("tls must be configured in this test"),
        };
        assert_eq!(tls.cert_chain, PathBuf::from("certs/chain.pem"));
    }
}
