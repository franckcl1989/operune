//! 0.3.0 Stateful Runtime（§41）——event bus 与 scheduler/event backpressure
//! （§41.2 MUST）的领域类型。
//!
//! 契约面：`operune:event@0.1.0`（event.wit / handler.wit，已提交稳定）。
//! 语义边界（event.wit 顶部注释 / §17.3）：
//!
//! - 订阅是**静态策��（grant），不是运行时 API**（§17.1 两阶段含义）：
//!   "订阅哪些 topic"属于 Runtime Policy 的 grant scope（§17.3 "event
//!   topics"），本契约没有运行时 subscribe/unsubscribe；发布授权同样在
//!   grant scope；
//! - 交付为 **at-most-once**：无重试、无补投、无 ack 协议；投递到订阅
//!   实例的 handler（Core-mediated 同步调用，无 async，§8.3/§42.3 边界
//!   同 scheduler）；投递侧背压以 `dropped` 计数表达（§41.2 MUST）；
//! - 事件 id 由 Core 分配（发布时），用于审计关联（§41.2 audit）与跨
//!   系统排查，不做交付去重（at-most-once 下无需去重语义）；
//! - 事件载荷**不含**凭据/会话/CSRF 字段（§16.5 凭据边界：敏感值只能走
//!   operune:secret）。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::id::validate_name_key;

/// event topic 长度上界（字节）。结构性上界（§19.1 输入不可信；
/// event.wit：长度受 Core 宿主侧上限约束）。
pub(crate) const MAX_EVENT_TOPIC_LEN: usize = 255;

/// event payload 长度上界（字节）。结构性上界（§7.4 host buffer 上限；
/// event.wit：载荷有界，发布速率受策略限制）。
pub(crate) const MAX_EVENT_PAYLOAD_LEN: usize = 1024 * 1024;

/// 事件主题（§13.5 record wrapper，非裸 string；grant scope 的键，§17.3；
/// 与 WIT `topic` record 严格对齐）。
///
/// 不变量（validate-on-construct，§13.3；WIT topic 明文）：
/// - 非空；
/// - 仅含 `[A-Za-z0-9._-]`，`.` 为命名空间分隔符（不含 `/`）；
/// - 长度 ≤ [`MAX_EVENT_TOPIC_LEN`] 字节。
///
/// Core 保留前缀（系统 topic 命名空间）**不**由 Domain 强制——event.wit
/// 明文"策略细节"：保留前缀与 topic 级 grant scope 校验（§17.3/§17.5
/// 四层授权链）属于 policy / application 层。Core 按字符串等价匹配（§6.7）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventTopic(String);

impl EventTopic {
    /// 从 WIT `topic` 边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_name_key(&value, MAX_EVENT_TOPIC_LEN, false, ValueKind::EventTopic)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价，§6.7）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EventTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for EventTopic {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for EventTopic {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for EventTopic {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 事件 id（Core 发布时分配；审计关联句柄；与 WIT `event-id` record 严格
/// 对齐）。
///
/// 语义（event.wit 明文）：0.1.0 不做交付去重（at-most-once），id 服务于
/// 审计关联（§41.2 audit）与跨系统排查。
///
/// 任意 u64 都是合法事件 id，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(u64);

impl EventId {
    /// 从 u64 构造（与 WIT `event-id.value` 字段一一对应；不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 事件载荷的 JSON 文本形态（WIT `event-payload` 的 `json(string)` 变体；
/// 有界 UTF-8 文本）。
///
/// 有界性：字节长度 ≤ [`MAX_EVENT_PAYLOAD_LEN`]（超限即 `over-budget` 的
/// Domain 侧表达，§7.4）。UTF-8 由 `String` 类型保证（WIT `string` 亦为
/// UTF-8 契约，§13.3：Domain 不重复校验同一不变量）。
///
/// §22.4 边界：serde_json 不得作为 Domain 万能动态值——payload 对平台是
/// 不透明文本，平台不解析、不回显；结构化参数是 0.4.0 的演进方向
/// （§42.2 typed action/事件），本类型是 0.1.0 的过渡边界。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventPayloadText(String);

impl EventPayloadText {
    /// 从有界 UTF-8 文本构造（§13.3 边界解析一次；超限返回
    /// [`DomainError::InvalidValue`]）。
    pub fn new(text: impl Into<String>) -> Result<Self, DomainError> {
        let text = text.into();
        if text.len() > MAX_EVENT_PAYLOAD_LEN {
            return Err(DomainError::invalid_value(
                ValueKind::EventPayload,
                format!("must not exceed {MAX_EVENT_PAYLOAD_LEN} bytes"),
            ));
        }
        Ok(Self(text))
    }

    /// 原始文本视图（只读；UTF-8 由 `String` 保证）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 字节长度。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空文本（空 JSON 文本是合法载荷）。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for EventPayloadText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for EventPayloadText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for EventPayloadText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 事件载荷的原始字节形态（WIT `event-payload` 的 `raw(list<u8>)` 变体；
/// 有界字节）。
///
/// 平台不解析、不解释字节内容（P6）；任意字节（含非 UTF-8）都是合法载荷
/// ——与 json 形态的 UTF-8 保证不同，raw 是**平台不透明**字节。
///
/// 不变量（validate-on-construct，§13.3）：长度 ≤ [`MAX_EVENT_PAYLOAD_LEN`]。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EventPayloadBytes(Vec<u8>);

impl EventPayloadBytes {
    /// 从有界字节构造（§13.3 边界解析一次；超限返回
    /// [`DomainError::InvalidValue`]）。
    pub fn new(data: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        let data = data.into();
        if data.len() > MAX_EVENT_PAYLOAD_LEN {
            return Err(DomainError::invalid_value(
                ValueKind::EventPayload,
                format!("must not exceed {MAX_EVENT_PAYLOAD_LEN} bytes"),
            ));
        }
        Ok(Self(data))
    }

    /// 原始字节视图（只读）。
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// 字节数。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空字节载荷。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 取出底层字节（适配层边界输出，§13.3）。
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for EventPayloadBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for EventPayloadBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let data = Vec::<u8>::deserialize(deserializer)?;
        Self::new(data).map_err(serde::de::Error::custom)
    }
}

/// 事件载荷的互斥形态（闭集 variant；与 WIT `event-payload` variant 严格
/// 对齐，§6.3 variant 表达互斥形态）。
///
/// 仅两种形态：结构化文本载荷（json）或原始字节载荷（raw）。禁止把任意
/// 动态值当作万能 payload（§22.4：serde_json 不得作为 Domain 万能动态值）；
/// 0.4.0 的 typed action/事件将提供结构化参数（§42.2），本 variant 是
/// 0.1.0 的过渡边界，不得作为未来动态值的后门（event.wit 明文）。
///
/// 两种形态均有界（≤ [`MAX_EVENT_PAYLOAD_LEN`]），构造即校验
/// （validate-on-construct，§13.3）；§16.5 凭据边界：载荷不含
/// 凭据/会话/CSRF 字段（敏感值只能走 operune:secret）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EventPayload {
    /// JSON 文本载荷（结构化事件形态；UTF-8 保证）。
    Json(EventPayloadText),
    /// 原始字节载荷（平台不透明）。
    Raw(EventPayloadBytes),
}

impl EventPayload {
    /// 构造 JSON 文本载荷（§13.3 边界解析一次；UTF-8 与体积均校验）。
    pub fn json(text: impl Into<String>) -> Result<Self, DomainError> {
        Ok(Self::Json(EventPayloadText::new(text)?))
    }

    /// 构造原始字节载荷（体积校验；任意字节合法）。
    pub fn raw(data: impl Into<Vec<u8>>) -> Result<Self, DomainError> {
        Ok(Self::Raw(EventPayloadBytes::new(data)?))
    }

    /// JSON 文本形态视图（仅当载荷为 json 形态）。
    pub fn as_json(&self) -> Option<&EventPayloadText> {
        match self {
            Self::Json(text) => Some(text),
            Self::Raw(_) => None,
        }
    }

    /// 原始字节形态视图（仅当载荷为 raw 形态）。
    pub fn as_raw(&self) -> Option<&EventPayloadBytes> {
        match self {
            Self::Json(_) => None,
            Self::Raw(bytes) => Some(bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn event_topic_accepts_wit_charset() {
        for topic in [
            "order.created",
            "orders.v1.created",
            "a",
            "A0",
            "_",
            ".",
            "-",
        ] {
            assert!(
                EventTopic::new(topic).is_ok(),
                "{topic:?} is in the WIT topic charset [A-Za-z0-9._-] and must be accepted"
            );
        }
        let max_len = "x".repeat(MAX_EVENT_TOPIC_LEN);
        assert_eq!(
            EventTopic::new(max_len.clone()).map(|topic| topic.as_str().len()),
            Ok(MAX_EVENT_TOPIC_LEN)
        );
    }

    #[test]
    fn event_topic_rejects_invalid() {
        for bad in [
            "", "a/b", // '/' 不在 topic 字符集（与 state key 不同）
            "a\\b", "a b", "a\nb", "a\u{0}b", "a@b", "键",
        ] {
            assert!(
                matches!(
                    EventTopic::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::EventTopic,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
        assert!(matches!(
            EventTopic::new("x".repeat(MAX_EVENT_TOPIC_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::EventTopic,
                ..
            })
        ));
    }

    #[test]
    fn event_topic_display_fromstr_serde_roundtrip() {
        let topic = ok(EventTopic::new("order.created"), "topic");
        assert_eq!(topic.to_string(), "order.created");
        assert_eq!(topic.to_string().parse::<EventTopic>(), Ok(topic.clone()));
        let json = ok(serde_json::to_string(&topic), "serialize");
        assert_eq!(json, "\"order.created\"");
        assert_eq!(
            ok(serde_json::from_str::<EventTopic>(&json), "deserialize"),
            topic
        );
        assert!(serde_json::from_str::<EventTopic>("\"a/b\"").is_err());
    }

    #[test]
    fn event_id_roundtrip() {
        let id = EventId::from_u64(99);
        assert_eq!(id.as_u64(), 99);
        assert_eq!(id.to_string(), "99");
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "99");
        assert_eq!(
            ok(serde_json::from_str::<EventId>(&json), "deserialize"),
            id
        );
    }

    #[test]
    fn event_payload_text_bounds() {
        let text = ok(EventPayloadText::new("{\"ok\":true}"), "text");
        assert_eq!(text.as_str(), "{\"ok\":true}");
        assert_eq!(text.len(), 11);
        assert!(!text.is_empty());
        assert!(ok(EventPayloadText::new(String::new()), "empty").is_empty());
        let max = "x".repeat(MAX_EVENT_PAYLOAD_LEN);
        assert_eq!(
            ok(EventPayloadText::new(max.clone()), "max").len(),
            MAX_EVENT_PAYLOAD_LEN
        );
        assert!(matches!(
            EventPayloadText::new("x".repeat(MAX_EVENT_PAYLOAD_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::EventPayload,
                ..
            })
        ));
        // 非 ASCII 文本合法（UTF-8）。
        assert_eq!(ok(EventPayloadText::new("载荷"), "utf8").as_str(), "载荷");
    }

    #[test]
    fn event_payload_bytes_bounds() {
        let bytes = ok(EventPayloadBytes::new(vec![0u8, 255]), "bytes");
        assert_eq!(bytes.as_slice(), &[0u8, 255]);
        assert_eq!(bytes.len(), 2);
        assert!(ok(EventPayloadBytes::new(Vec::new()), "empty").is_empty());
        assert!(matches!(
            EventPayloadBytes::new(vec![0u8; MAX_EVENT_PAYLOAD_LEN + 1]),
            Err(DomainError::InvalidValue {
                kind: ValueKind::EventPayload,
                ..
            })
        ));
        let json = ok(serde_json::to_string(&bytes), "serialize");
        assert_eq!(json, "[0,255]");
        assert_eq!(
            ok(
                serde_json::from_str::<EventPayloadBytes>(&json),
                "deserialize"
            ),
            bytes
        );
    }

    #[test]
    fn event_payload_variants_and_accessors() {
        let json = ok(EventPayload::json("{\"ok\":true}"), "json");
        assert_eq!(json.as_json().map(|t| t.as_str()), Some("{\"ok\":true}"));
        assert_eq!(json.as_raw(), None);
        assert!(matches!(json, EventPayload::Json(_)));

        let raw = ok(EventPayload::raw(vec![0u8, 1, 2]), "raw");
        assert_eq!(raw.as_raw().map(|b| b.as_slice()), Some(&[0u8, 1, 2][..]));
        assert_eq!(raw.as_json(), None);
        assert!(matches!(raw, EventPayload::Raw(_)));

        // raw 形态可承载非 UTF-8 字节（平台不透明）。
        let binary = ok(EventPayload::raw(vec![0xff, 0x00, 0xfe]), "binary");
        assert_eq!(
            binary.as_raw().map(|b| b.as_slice()),
            Some(&[0xff, 0x00, 0xfe][..])
        );

        for payload in [json.clone(), raw.clone(), binary] {
            let serialized = ok(serde_json::to_string(&payload), "serialize");
            assert_eq!(
                ok(
                    serde_json::from_str::<EventPayload>(&serialized),
                    "deserialize"
                ),
                payload
            );
        }
        assert!(matches!(
            EventPayload::json("x".repeat(MAX_EVENT_PAYLOAD_LEN + 1)),
            Err(DomainError::InvalidValue {
                kind: ValueKind::EventPayload,
                ..
            })
        ));
        assert!(matches!(
            EventPayload::raw(vec![0u8; MAX_EVENT_PAYLOAD_LEN + 1]),
            Err(DomainError::InvalidValue {
                kind: ValueKind::EventPayload,
                ..
            })
        ));
    }
}
