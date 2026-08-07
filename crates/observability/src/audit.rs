//! 审计事件模型与写入 port（§5.1、§18.7、§16.6）。
//!
//! 0.1.0 基线：runtime 自身结构化日志、指标、审计（§5.1）。本模块定义审计
//! 事件的 typed 模型（类别 / 严重级别 / 结果 / 动作 / 时间戳 / 消息）与写入
//! port（[`AuditSink`]）；durable 持久化由 storage-sqlite 提供，本模块只
//! 定义事件模型与 port 形状（§24.2）。
//!
//! # Secret（§16.6）
//!
//! 审计事件禁止记录 secret 值。[`AuditEvent::message`] 是自由文本，调用方
//! MUST NOT 放入 secret；含 secret 的上下文必须用 [`crate::redact`] 包装
//! （输出为 [`crate::REDACTED_MARKER`] 掩码）。§16.6 禁止清单：密码、session
//! bearer token、CSRF secret、private key、Component secret。
//!
//! # Fail-closed（§18.7）
//!
//! 需要 durable audit 的安全 / 权限 / Component 生命周期变更，在
//! [`AuditSink::write`] 返回 `Err` 时必须在提交前 fail closed；audit 无法
//! 可靠落盘时不得先提交变更。

use std::fmt;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

/// 为审计闭集 enum 生成字符串序列化（snake_case 名称；反序列化同样校验）。
///
/// workspace 冻结的 serde 基线不含 derive feature（§22.4：serde 1.0.229 默认
/// features 仅 `std`），本 crate 与 domain 一致使用手写 impl（§13.3：反序列化
/// 边界同样执行校验）。
macro_rules! audit_enum_serde {
    ($ty:ident, $($variant:ident => $name:literal),+ $(,)?) => {
        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let name = match self {
                    $(Self::$variant => $name,)+
                };
                serializer.serialize_str(name)
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                match value.as_str() {
                    $($name => Ok(Self::$variant),)+
                    _ => Err(serde::de::Error::custom(format!(
                        "unknown variant {value:?}"
                    ))),
                }
            }
        }
    };
}

/// 审计事件类别（闭集；§5.1 Core 拥有清单）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditCategory {
    /// 认证 / 会话 / 密码等安全事件（§16.3、§16.5）。
    Security,
    /// Component 生命周期事件（§19、§20）。
    Component,
    /// Capability grant / 授权事件（§17）。
    Grant,
    /// RuntimeConfig 变更（§18.0）。
    Config,
    /// bootstrap / recovery CLI 操作（§16.3：其能力全部审计）。
    Recovery,
    /// Runtime 自身系统事件（启动 / 停止 / 安全模式等）。
    System,
}

audit_enum_serde!(
    AuditCategory,
    Security => "security",
    Component => "component",
    Grant => "grant",
    Config => "config",
    Recovery => "recovery",
    System => "system",
);

/// 审计严重级别。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditSeverity {
    /// 常规信息。
    Info,
    /// 需要注意但未失败。
    Warning,
    /// 操作失败。
    Error,
    /// 安全边界 / 完整性相关，必须立即关注。
    Critical,
}

audit_enum_serde!(
    AuditSeverity,
    Info => "info",
    Warning => "warning",
    Error => "error",
    Critical => "critical",
);

/// 审计结果（§18.7：audit 需能说明最后已提交状态；§16.3：recovery 操作
/// 全部审计并记录结果）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuditOutcome {
    /// 操作成功并已提交。
    Success,
    /// 因权限 / 策略被拒绝（deny-by-default，§17.2）。
    Denied,
    /// 操作尝试失败。
    Failed,
}

audit_enum_serde!(
    AuditOutcome,
    Success => "success",
    Denied => "denied",
    Failed => "failed",
);

/// 审计动作标识（如 `component.install`、`session.login`、`grant.revoke`）。
///
/// 受校验 newtype（§13.1）：非空、长度 ≤ [`AuditAction::MAX_LEN`] 字节、
/// 仅小写 ascii 字母数字与 `_` `.` `-` `:`。反序列化边界同样执行校验
/// （§13.3）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AuditAction(String);

impl AuditAction {
    /// 动作标识最大长度（字节）。
    pub const MAX_LEN: usize = 256;

    /// 校验构造（validate-on-construct，§13.3）。
    pub fn new(value: impl Into<String>) -> Result<AuditAction, AuditError> {
        let value = value.into();
        crate::validate_identifier(&value, Self::MAX_LEN).map_err(AuditError::InvalidAction)?;
        Ok(AuditAction(value))
    }

    /// 动作标识视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for AuditAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AuditAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 审计模块封闭错误（§14.1 thiserror）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    /// 动作标识校验失败。
    #[error("invalid audit action: {0}")]
    InvalidAction(String),

    /// 审计写入失败（调用方必须 fail closed，§18.7）。
    #[error("audit write failed: {detail}")]
    WriteFailed {
        /// 可诊断原因（不含 secret）。
        detail: String,
    },
}

/// 审计事件（§5.1、§18.7、§16.6）。
///
/// 序列化边界：serde（JSON 等）用于持久化与日志；事件内容禁止携带 secret
/// （见模块文档）。序列化为结构化对象；反序列化边界同样执行校验
/// （字段完整性、动作标识校验、消息截断，§13.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// 事件发生时刻（UTC 墙上时钟；RFC3339 序列化，`time` crate serde 默认格式）。
    pub occurred_at: OffsetDateTime,
    /// 事件类别。
    pub category: AuditCategory,
    /// 严重级别。
    pub severity: AuditSeverity,
    /// 结果（§18.7：audit 需能说明最后已提交状态）。
    pub outcome: AuditOutcome,
    /// 动作标识。
    pub action: AuditAction,
    /// 事件消息（§16.6：禁止 secret；超长按字节边界截断）。
    pub message: String,
}

impl Serialize for AuditEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("AuditEvent", 6)?;
        state.serialize_field("occurred_at", &self.occurred_at)?;
        state.serialize_field("category", &self.category)?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("outcome", &self.outcome)?;
        state.serialize_field("action", &self.action)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for AuditEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(
            "AuditEvent",
            &[
                "occurred_at",
                "category",
                "severity",
                "outcome",
                "action",
                "message",
            ],
            AuditEventVisitor,
        )
    }
}

struct AuditEventVisitor;

impl<'de> Visitor<'de> for AuditEventVisitor {
    type Value = AuditEvent;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "an audit event with occurred_at, category, severity, outcome, action and message",
        )
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut occurred_at: Option<OffsetDateTime> = None;
        let mut category: Option<AuditCategory> = None;
        let mut severity: Option<AuditSeverity> = None;
        let mut outcome: Option<AuditOutcome> = None;
        let mut action: Option<AuditAction> = None;
        let mut message: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "occurred_at" => occurred_at = Some(map.next_value()?),
                "category" => category = Some(map.next_value()?),
                "severity" => severity = Some(map.next_value()?),
                "outcome" => outcome = Some(map.next_value()?),
                "action" => action = Some(map.next_value()?),
                "message" => message = Some(map.next_value()?),
                // 未知字段忽略（向前兼容：未来版本可增加字段）。
                _ => {
                    let _ = map.next_value::<serde::de::IgnoredAny>()?;
                }
            }
        }
        Ok(AuditEvent {
            occurred_at: occurred_at
                .ok_or_else(|| serde::de::Error::missing_field("occurred_at"))?,
            category: category.ok_or_else(|| serde::de::Error::missing_field("category"))?,
            severity: severity.ok_or_else(|| serde::de::Error::missing_field("severity"))?,
            outcome: outcome.ok_or_else(|| serde::de::Error::missing_field("outcome"))?,
            action: action.ok_or_else(|| serde::de::Error::missing_field("action"))?,
            message: truncate_message(
                message.ok_or_else(|| serde::de::Error::missing_field("message"))?,
            ),
        })
    }
}

impl AuditEvent {
    /// 消息最大长度（字节）；超长在 [`AuditEvent::new`] 内按 UTF-8 字符边界
    /// 截断（有界消息，§18.7：audit 存储有硬上限）。
    pub const MAX_MESSAGE_LEN: usize = 4096;

    /// 构造审计事件。`occurred_at` 取当前 UTC 时间；`message` 超过
    /// [`AuditEvent::MAX_MESSAGE_LEN`] 字节时按 UTF-8 字符边界截断。
    ///
    /// # Secret（§16.6）
    /// `message` 不得包含 secret 值；需要展示 secret 时必须用
    /// [`crate::redact`] 包装（输出为掩码）。
    pub fn new(
        category: AuditCategory,
        severity: AuditSeverity,
        outcome: AuditOutcome,
        action: AuditAction,
        message: impl Into<String>,
    ) -> AuditEvent {
        AuditEvent {
            occurred_at: OffsetDateTime::now_utc(),
            category,
            severity,
            outcome,
            action,
            message: truncate_message(message.into()),
        }
    }
}

/// 按 UTF-8 字符边界截断消息（永不失败、不 panic、不拆字符）。
fn truncate_message(message: String) -> String {
    if message.len() <= AuditEvent::MAX_MESSAGE_LEN {
        return message;
    }
    let mut end = AuditEvent::MAX_MESSAGE_LEN;
    while !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_string()
}

/// 审计写入 port（§5.1、§18.7）。
///
/// 语义：`write` 返回 `Err` 表示事件未能持久化；需要 durable audit 的变更
/// （安全 / 权限 / Component 生命周期，§18.7）必须以该 `Err` 为 fail-closed
/// 信号，不得先提交变更。
///
/// 0.1.0 提供 [`LogAuditSink`]（结构化日志通道）；durable 实现由
/// storage-sqlite 提供并在 server 装配（§24.3）。
pub trait AuditSink: Send + Sync {
    /// 写入一条审计事件。
    fn write(&self, event: AuditEvent) -> Result<(), AuditError>;
}

/// 审计日志输出 target（过滤 / 检索用，§22.7）。
pub const AUDIT_LOG_TARGET: &str = "operune::audit";

/// 将审计事件写入 Core 结构化日志的 sink（0.1.0 基线通道；§5.1）。
///
/// 事件整体以 JSON 序列化后写入 tracing，保证日志面可完整检索；序列化边界
/// 与 secret 约束与 durable 持久化路径一致（§16.6）。写入失败仅可能来自
/// 序列化（本模型不可失败）；durable 失败由 storage-sqlite 实现承担。
#[derive(Debug, Clone, Copy, Default)]
pub struct LogAuditSink;

impl AuditSink for LogAuditSink {
    fn write(&self, event: AuditEvent) -> Result<(), AuditError> {
        let json = serde_json::to_string(&event).map_err(|err| AuditError::WriteFailed {
            detail: err.to_string(),
        })?;
        tracing::info!(target: AUDIT_LOG_TARGET, event = %json);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::REDACTED_MARKER;
    use crate::support::{TestWriter, ok};
    use tracing::level_filters::LevelFilter;

    fn action(value: &str) -> AuditAction {
        ok(AuditAction::new(value), "valid action")
    }

    #[test]
    fn action_validation() {
        assert!(AuditAction::new("component.install").is_ok());
        assert!(AuditAction::new("session_login").is_ok());
        assert!(AuditAction::new("grant:revoke").is_ok());
        assert!(matches!(
            AuditAction::new(""),
            Err(AuditError::InvalidAction(_))
        ));
        assert!(matches!(
            AuditAction::new("UPPER"),
            Err(AuditError::InvalidAction(_))
        ));
        assert!(matches!(
            AuditAction::new("has space"),
            Err(AuditError::InvalidAction(_))
        ));
        assert!(matches!(
            AuditAction::new("a".repeat(AuditAction::MAX_LEN + 1)),
            Err(AuditError::InvalidAction(_))
        ));
    }

    #[test]
    fn action_serde_roundtrip_and_revalidation() {
        let action = action("component.install");
        let json = ok(serde_json::to_string(&action), "serialize action");
        assert_eq!(json, "\"component.install\"");
        assert_eq!(
            ok(
                serde_json::from_str::<AuditAction>(&json),
                "deserialize action"
            ),
            action
        );
        // 反序列化边界同样执行校验（§13.3）。
        assert!(serde_json::from_str::<AuditAction>("\"Bad Action!\"").is_err());
    }

    #[test]
    fn audit_event_serde_roundtrip() {
        let occurred_at = ok(
            OffsetDateTime::from_unix_timestamp_nanos(1_752_000_000_123_456_789),
            "fixed timestamp",
        );
        let mut event = AuditEvent::new(
            AuditCategory::Security,
            AuditSeverity::Error,
            AuditOutcome::Failed,
            action("session.login"),
            "login failed: bad credentials",
        );
        event.occurred_at = occurred_at;
        let json = ok(serde_json::to_string(&event), "serialize event");
        let decoded: AuditEvent = ok(serde_json::from_str(&json), "deserialize event");
        assert_eq!(decoded, event);
    }

    #[test]
    fn message_truncated_to_max_len() {
        let event = AuditEvent::new(
            AuditCategory::System,
            AuditSeverity::Info,
            AuditOutcome::Success,
            action("runtime.start"),
            "a".repeat(AuditEvent::MAX_MESSAGE_LEN + 100),
        );
        assert_eq!(event.message.len(), AuditEvent::MAX_MESSAGE_LEN);
    }

    #[test]
    fn message_truncation_never_splits_utf8() {
        let base = "a".repeat(AuditEvent::MAX_MESSAGE_LEN - 1);
        let event = AuditEvent::new(
            AuditCategory::System,
            AuditSeverity::Info,
            AuditOutcome::Success,
            action("runtime.start"),
            format!("{base}€€"),
        );
        assert!(event.message.is_char_boundary(event.message.len()));
        assert_eq!(event.message, base);
    }

    #[test]
    fn audit_message_with_redacted_secret_is_masked() {
        // §16.6 防护：审计消息经 redact 包装后，序列化输出为掩码而非原文。
        let token = "session-bearer-token-value";
        let event = AuditEvent::new(
            AuditCategory::Security,
            AuditSeverity::Warning,
            AuditOutcome::Denied,
            action("session.deny"),
            format!("token={}", crate::redact(token)),
        );
        let json = ok(serde_json::to_string(&event), "serialize event");
        assert!(!json.contains(token));
        assert!(json.contains(REDACTED_MARKER));
    }

    #[test]
    fn log_audit_sink_writes_structured_event() {
        let writer = TestWriter::new();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(LevelFilter::INFO)
            .with_ansi(false)
            .with_writer(writer.clone())
            .finish();
        let event = AuditEvent::new(
            AuditCategory::Component,
            AuditSeverity::Info,
            AuditOutcome::Success,
            action("component.install"),
            "installed v1.0.0",
        );
        tracing::subscriber::with_default(subscriber, || {
            let sink = LogAuditSink;
            assert_eq!(sink.write(event.clone()), Ok(()));
        });
        let contents = writer.contents();
        assert!(contents.contains(AUDIT_LOG_TARGET));
        assert!(contents.contains("component.install"));
        assert!(contents.contains("installed v1.0.0"));
    }
}
