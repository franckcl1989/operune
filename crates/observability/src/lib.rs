#![forbid(unsafe_code)]

//! Operune 可观测性 plumbing（规范 §24.2：observability）。
//!
//! Core 自身 tracing / metrics / audit plumbing（§5.1、§22.7）。
//!
//! # 模块
//!
//! - [`tracing_setup`]：tracing-subscriber 初始化（§22.7：格式/过滤器可配置
//!   形状；结构化事件基础）；
//! - [`redaction`]：secret 掩码防护（§16.6：Core 日志/审计不得记录 secret）；
//! - [`audit`]：审计事件 typed 模型与写入 port（§5.1、§18.7）；
//! - [`metrics`]：0.1.0 最小 typed metrics（§5.1、§34.3；无外部 metrics
//!   crate，YAGNI §12.6）。
//!
//! # Secret 边界（§16.6）
//!
//! 日志、error context、panic report、metrics label、audit event 中禁止记录：
//! 密码、session bearer token、CSRF secret、private key 与 Component secret
//! 值。含 secret 的上下文必须通过 [`redact`] 包装后再进入日志/审计消息；
//! 本 crate 不提供接收原始 secret 值的日志 API（typed 约束见 [`redact`]）。
//!
//! # 依赖边界
//!
//! 不依赖 tokio / axum / wasmtime / rusqlite（§24.3）；不涉及 HTTP 与业务
//! 运维领域（§1/§5.2）。审计 port 为同步形状，异步持久化由 storage-sqlite /
//! server 装配层提供。

mod audit;
mod metrics;
mod redaction;
#[cfg(test)]
mod support;
mod tracing_setup;

pub use audit::{
    AUDIT_LOG_TARGET, AuditAction, AuditCategory, AuditError, AuditEvent, AuditOutcome,
    AuditSeverity, AuditSink, LogAuditSink,
};
pub use metrics::{
    Counter, CounterSample, HISTOGRAM_BUCKET_COUNT, HISTOGRAM_BUCKET_UPPER_BOUNDS, Histogram,
    HistogramSample, MetricKind, MetricName, MetricsError, MetricsRegistry, MetricsSnapshot,
};
pub use redaction::{REDACTED_MARKER, Redacted, redact};
pub use tracing_setup::{LogFormat, TargetLevel, TracingConfig, TracingError, init};

/// 标识符校验（metric name / audit action 共用，§13.1）：非空、长度 ≤ `max`
/// 字节、仅小写 ascii 字母数字与 `_` `.` `-` `:`。
///
/// 校验失败返回可诊断原因（不含任何值本身之外的敏感信息）。
pub(crate) fn validate_identifier(value: &str, max: usize) -> Result<(), String> {
    if value.is_empty() {
        return Err("must not be empty".to_string());
    }
    if value.len() > max {
        return Err(format!("must not exceed {max} bytes"));
    }
    let valid = value.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'.' | b'-' | b':')
    });
    if valid {
        Ok(())
    } else {
        Err("must contain only lowercase ascii alphanumeric, '_', '.', '-' or ':'".to_string())
    }
}
