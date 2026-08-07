//! Secret 防泄漏（§16.6）。
//!
//! Core 日志、error context、panic report、metrics label、audit event 中
//! **禁止记录**：密码、session bearer token、CSRF secret、private key 与
//! Component secret 值（§16.6）。
//!
//! 本模块提供 typed 防护：[`redact`] 包装任何值后，其 `Debug` / `Display` /
//! serde 序列化一律输出 [`REDACTED_MARKER`]，值本身永不参与输出。
//!
//! 使用约束（§16.6、§54）：凡构造含 secret 的日志/审计消息，必须通过
//! [`redact`] 包装；不得直接把 secret 值放入 `tracing::info!` 字段或
//! [`crate::audit::AuditEvent`] 消息。

use std::fmt;
use std::marker::PhantomData;

use serde::{Serialize, Serializer};

/// 掩码标记（`Debug` / `Display` / serde 输出统一使用）。
pub const REDACTED_MARKER: &str = "[REDACTED]";

/// 掩码视图类型（§16.6 防护）。
///
/// [`redact`] 返回本类型：其 `Debug` / `Display` / serde 序列化一律输出
/// [`REDACTED_MARKER`]，被包装的值从不参与任何输出。
///
/// 本类型**不存储值**（仅携带类型标记 `PhantomData`）：零运行时开销，也不
/// 在本类型中保留 secret 内存副本；它只作为编译期约束——调用方必须显式、
/// 有意识地包装 secret 值，才能把它放进日志/审计消息。
pub struct Redacted<T: ?Sized>(PhantomData<T>);

impl<T: ?Sized> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl<T: ?Sized> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl<T: ?Sized> Serialize for Redacted<T> {
    /// 序列化边界同样掩码（§16.6：不序列化 secret）。
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED_MARKER)
    }
}

/// 将任意值包装为掩码视图（§16.6 防护入口）。
///
/// 返回值的 `Debug` / `Display` / 序列化输出为 [`REDACTED_MARKER`]；
/// 原始值只在本函数参数中短暂可见，不进入返回类型。
///
/// ```rust
/// use operune_observability::{redact, REDACTED_MARKER};
/// let token = "bearer-secret";
/// let line = format!("login ok, token={}", redact(token));
/// assert!(line.contains(REDACTED_MARKER));
/// assert!(!line.contains(token));
/// ```
pub fn redact<T: ?Sized>(_value: &T) -> Redacted<&T> {
    Redacted(PhantomData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::support::ok;
    use tracing::level_filters::LevelFilter;

    #[test]
    fn display_and_debug_mask_value() {
        let secret = "s3cr3t-value";
        let redacted = redact(&secret);
        assert_eq!(format!("{redacted}"), REDACTED_MARKER);
        assert_eq!(format!("{redacted:?}"), REDACTED_MARKER);
        assert!(!format!("{redacted:?}").contains(secret));
        assert!(!format!("{redacted}").contains(secret));
    }

    #[test]
    fn serde_serializes_marker_only() {
        let secret = "another-secret";
        let json = ok(
            serde_json::to_string(&redact(&secret)),
            "serialize redacted",
        );
        assert_eq!(json, "\"[REDACTED]\"");
        assert!(!json.contains(secret));
    }

    #[test]
    fn log_output_masks_secret_values() {
        // 防护测试（§32：secret 不出现在 logs）：构造含 secret 值类型，
        // 断言格式化输出为掩码而非原文。
        let writer = crate::support::TestWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::INFO)
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();
        let secret = "password-hunter2";
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!("login failed; token={}", crate::redact(&secret));
        });
        let contents = writer.contents();
        assert!(!contents.contains(secret));
        assert!(contents.contains(REDACTED_MARKER));
    }
}
