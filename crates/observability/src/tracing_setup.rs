//! tracing-subscriber 初始化（§22.7；§24.2 observability）。
//!
//! 形状可配置：默认过滤级别、target 前缀覆盖与输出格式（§22.7
//! `logging/filter/format subscriber`）。过滤器是**确定性 typed 配置**，
//! 不读取环境变量（§18.0：production 不支持环境变量覆盖 BootstrapConfig
//! 字段；启动期日志级别等宿主事实由 BootstrapConfig 提供，经 server 装配
//! 注入本 crate）。
//!
//! # Secret（§16.6）
//!
//! 初始化不接收任何 secret 输入；事件字段中的 secret 必须经
//! [`crate::redact`] 掩码（见 crate 模块文档）。

use std::io;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::prelude::*;
use tracing_subscriber::registry::Registry;

/// 日志输出格式（§22.7 可配置形状）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogFormat {
    /// 人类可读紧凑格式（默认）。
    #[default]
    Compact,
    /// 每行一个 JSON 对象的结构化格式。
    Json,
}

/// 单条 target 前缀过滤覆盖（与 tracing directive 的 target 前缀匹配语义
/// 一致：`operune::component` 匹配 `operune::component::installer` 等）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetLevel {
    /// target 前缀（如 `operune::component`、`operune::audit`）。
    pub target: String,
    /// 该 target 前缀下允许的最低级别。
    pub level: LevelFilter,
}

/// tracing 初始化配置（§22.7：格式/过滤器可配置形状）。
///
/// 默认值：[`LevelFilter::INFO`]、无 target 覆盖、[`LogFormat::Compact`]。
/// 默认过滤级别应用于所有 target；[`TargetLevel`] 覆盖按 target 前缀匹配
/// 优先于默认值。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TracingConfig {
    /// 默认过滤级别。
    pub default_level: LevelFilter,
    /// target 前缀过滤覆盖（有序追加；同一 target 后写覆盖先写）。
    pub target_overrides: Vec<TargetLevel>,
    /// 输出格式。
    pub format: LogFormat,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            default_level: LevelFilter::INFO,
            target_overrides: Vec::new(),
            format: LogFormat::Compact,
        }
    }
}

impl TracingConfig {
    /// 追加一条 target 过滤覆盖。
    pub fn with_target_override(mut self, target: impl Into<String>, level: LevelFilter) -> Self {
        self.target_overrides.push(TargetLevel {
            target: target.into(),
            level,
        });
        self
    }
}

/// tracing 初始化错误（§14.1 thiserror）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TracingError {
    /// 全局默认 subscriber 已被设置（进程内只能成功初始化一次）。
    #[error("tracing global default already initialized")]
    AlreadyInitialized,
}

/// 初始化全局默认 tracing subscriber（进程内一次；重复调用返回
/// [`TracingError::AlreadyInitialized`]，确定性 fail，不 panic）。
pub fn init(config: TracingConfig) -> Result<(), TracingError> {
    let subscriber = build_subscriber(config, io::stdout);
    tracing::subscriber::set_global_default(subscriber)
        .map_err(|_| TracingError::AlreadyInitialized)
}

/// 构造 subscriber（生产输出到 stdout；测试注入内存 writer）。
///
/// `json()` 会改变 Layer 的类型（事件格式），因此按格式分支后统一装箱为
/// trait object（`fmt::Layer` 是 `dyn Layer` 的合法实现，§12.5：此处不是
/// 抽象仪式，而是两种格式的真实分派）。
fn build_subscriber<W>(
    config: TracingConfig,
    writer: W,
) -> impl tracing::Subscriber + Send + Sync + 'static
where
    W: for<'a> tracing_subscriber::fmt::MakeWriter<'a> + Send + Sync + 'static,
{
    let filter = config.target_overrides.iter().fold(
        Targets::new().with_default(config.default_level),
        |acc, target_level| acc.with_target(&target_level.target, target_level.level),
    );
    // 0.1.0 基线输出不含 ANSI 转义（日志面向文件与结构化消费，§18.7；
    // 彩色控制台输出如需可后续 ADR 增加配置项）。
    let layer: Box<dyn Layer<Registry> + Send + Sync> = match config.format {
        LogFormat::Compact => Box::new(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(writer),
        ),
        LogFormat::Json => Box::new(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .json()
                .with_writer(writer),
        ),
    };
    Registry::default().with(layer.with_filter(filter))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::{TestWriter, ok};

    #[test]
    fn default_config_shape() {
        let config = TracingConfig::default();
        assert_eq!(config.default_level, LevelFilter::INFO);
        assert!(config.target_overrides.is_empty());
        assert_eq!(config.format, LogFormat::Compact);
    }

    #[test]
    fn target_override_appends() {
        let config =
            TracingConfig::default().with_target_override("operune::component", LevelFilter::DEBUG);
        assert_eq!(config.target_overrides.len(), 1);
        assert_eq!(config.target_overrides[0].target, "operune::component");
        assert_eq!(config.target_overrides[0].level, LevelFilter::DEBUG);
    }

    #[test]
    fn default_level_filters_below_info() {
        let writer = TestWriter::new();
        let subscriber = build_subscriber(TracingConfig::default(), writer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("hidden by default level");
            tracing::info!("visible at info");
        });
        let contents = writer.contents();
        assert!(!contents.contains("hidden by default level"));
        assert!(contents.contains("visible at info"));
    }

    #[test]
    fn target_override_enables_debug_for_matching_target() {
        let writer = TestWriter::new();
        let config = TracingConfig {
            default_level: LevelFilter::WARN,
            target_overrides: vec![TargetLevel {
                target: "operune::component".to_string(),
                level: LevelFilter::DEBUG,
            }],
            format: LogFormat::Compact,
        };
        let subscriber = build_subscriber(config, writer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: "operune::component::installer", "component debug");
            tracing::debug!(target: "operune::other", "other debug");
            tracing::warn!("warn visible at default level");
        });
        let contents = writer.contents();
        assert!(contents.contains("component debug"));
        assert!(!contents.contains("other debug"));
        assert!(contents.contains("warn visible at default level"));
    }

    #[test]
    fn json_format_produces_structured_output() {
        let writer = TestWriter::new();
        let config = TracingConfig {
            format: LogFormat::Json,
            ..TracingConfig::default()
        };
        let subscriber = build_subscriber(config, writer.clone());
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(request_id = 42, "request handled");
        });
        let contents = writer.contents();
        let line = contents
            .lines()
            .find(|line| line.contains("request handled"));
        assert!(line.is_some(), "event line must be present in: {contents}");
        let line = line.unwrap_or_default();
        let value = ok(
            serde_json::from_str::<serde_json::Value>(line),
            "parse json event line",
        );
        assert_eq!(value["fields"]["message"], "request handled");
        assert_eq!(value["level"], "INFO");
        assert_eq!(value["fields"]["request_id"], 42);
    }

    #[test]
    fn init_twice_fails_deterministically() {
        // 全局默认 subscriber 是进程级状态：持锁串行执行，保证确定性。
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(init(TracingConfig::default()), Ok(()));
        assert_eq!(
            init(TracingConfig::default()),
            Err(TracingError::AlreadyInitialized)
        );
    }
}
