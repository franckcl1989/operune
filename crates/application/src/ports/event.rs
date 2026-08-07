//! 0.3.0 Stateful Runtime（§41.2 / §17.3）——event bus 的策略与交付 port
//! （契约面 `operune:event@0.1.0` event.wit / handler.wit，已提交稳定）。
//!
//! # 策略 port（订阅是静态 grant 策略，§17.1 两阶段含义）
//!
//! event.wit 明文：**没有运行时 subscribe/unsubscribe**——"订阅哪些 topic"
//! 属于 Runtime Policy 的 grant scope（§17.3 "event topics"），由管理员在
//! 安装/授权时配置；发布授权同样在 grant scope。本 port 承载"策略事实"的
//! 查询面：发布授权判定 + 订阅集合（投递扇出目标）。
//!
//! Core 系统 topic 命名空间（保留前缀）与 topic 级 scope 校验属于**策略
//! 细节**（event.wit 明文"策略细节，不进契约"），由策略实现
//! （[`InProcessEventPolicy`]）裁决，不进服务层。
//!
//! # 交付 port
//!
//! 投递模型是 Core-mediated push（event.wit 明文）：投递到订阅实例的
//! handler（同步调用，无 async，§8.3/§42.3 边界同 scheduler）；at-most-once：
//! 无重试、无补投、无 ack；handler 调用 trap 视为已消费，不重投。本 port
//! 承载"宿主 → guest handler"的调用面，错误只用于宿主侧观测。

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use operune_domain::{EventTopic, InstallationId};

use crate::event::DeliveredEvent;

/// 事件投递错误（宿主侧观测；handler trap/失败 = 已消费，不重投，
/// handler.wit）。
#[derive(Debug, thiserror::Error)]
pub enum EventDeliveryError {
    /// guest handler trap / runtime 调用失败（已消费语义下的观测记录）。
    #[error("event delivery to guest handler failed: {0}")]
    Guest(&'static str),
}

/// 事件投递 port（§24.2：trait 定义在本 crate，runtime 接线层实现）。
///
/// 调用方：event 服务层的每订阅投递 consumer（有界队列的另一端）。
pub trait EventDeliveryPort: Send + Sync {
    /// Core-mediated push：调用 guest 的 `on-event`（同步；返回即已消费，
    /// trap 视为已消费，调用方不得重试/补投）。
    fn on_event(&self, event: DeliveredEvent) -> Result<(), EventDeliveryError>;
}

/// event 静态策略 port（§17.1/§17.3：策略事实的快照查询）。
pub trait EventPolicyPort: Send + Sync {
    /// 发布授权：安装实例是否被授予 topic 的发布权（event.wit `denied`）。
    fn publish_granted(&self, installation: InstallationId, topic: &EventTopic) -> bool;

    /// 订阅集合：policy 授予 topic 订阅权的全部安装实例（确定性排序；
    /// 投递扇出目标，§41.2 发布投递对象）。
    fn subscribers(&self, topic: &EventTopic) -> Vec<InstallationId>;
}

/// Core 保留系统 topic 命名空间（策略细节，event.wit 明文"guest topic
/// 不得使用保留前缀"）。`core.` 前缀下的 topic 是 Core 系统事件专用。
pub(crate) const RESERVED_TOPIC_PREFIX: &str = "core.";

/// 进程内默认实现（composition root 与测试共用）：每安装实例的发布/订阅
/// topic 集（§17.3 "event topics" scope 维度的确定性注入面）。
///
/// 策略裁决（event.wit "策略细节"）：
/// - `core.` 保留前缀的 topic 一律拒绝 guest 发布（Core 系统事件专用）；
/// - 订阅集合按安装实例身份确定性排序（BTreeMap 键序），投递顺序可复现。
#[derive(Debug, Default)]
pub struct InProcessEventPolicy {
    publish: Mutex<BTreeMap<InstallationId, BTreeSet<EventTopic>>>,
    subscribe: Mutex<BTreeMap<InstallationId, BTreeSet<EventTopic>>>,
}

impl InProcessEventPolicy {
    /// 新建空策略（deny-by-default，§17.2）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 显式授予安装实例 topic 的发布权（§17.3）。
    pub fn grant_publish(&self, installation: InstallationId, topic: EventTopic) {
        self.publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(installation)
            .or_default()
            .insert(topic);
    }

    /// 显式授予安装实例 topic 的订阅权（§17.3；投递扇出目标）。
    pub fn grant_subscribe(&self, installation: InstallationId, topic: EventTopic) {
        self.subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .entry(installation)
            .or_default()
            .insert(topic);
    }

    /// 撤销订阅授权（§17.5 快照语义：撤销后 Core 停止投递）。
    pub fn revoke_subscribe(&self, installation: InstallationId, topic: &EventTopic) {
        let mut subscribe = self
            .subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(topics) = subscribe.get_mut(&installation) {
            topics.remove(topic);
        }
    }

    /// 授予发布授权的 topic 数（测试/诊断）。
    pub fn publish_count(&self) -> usize {
        self.publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(BTreeSet::len)
            .sum()
    }

    /// 授予订阅授权的 topic 数（测试/诊断）。
    pub fn subscribe_count(&self) -> usize {
        self.subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .values()
            .map(BTreeSet::len)
            .sum()
    }
}

impl EventPolicyPort for InProcessEventPolicy {
    fn publish_granted(&self, installation: InstallationId, topic: &EventTopic) -> bool {
        // 策略细节（event.wit 明文）：Core 保留系统 topic 命名空间，guest
        // 不得发布；发布授权按 topic 字符串等价匹配（§6.7）。
        if topic.as_str().starts_with(RESERVED_TOPIC_PREFIX) {
            return false;
        }
        self.publish
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&installation)
            .map(|topics| topics.contains(topic))
            .unwrap_or(false)
    }

    fn subscribers(&self, topic: &EventTopic) -> Vec<InstallationId> {
        let subscribe = self
            .subscribe
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // 确定性排序（BTreeMap 键序；投递顺序可复现）。
        subscribe
            .iter()
            .filter(|(_, topics)| topics.contains(topic))
            .map(|(installation, _)| *installation)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{installation, ok};

    fn topic(name: &str) -> EventTopic {
        ok(EventTopic::new(name), "topic")
    }

    #[test]
    fn publish_granted_deny_by_default_and_matches_exact_topic() {
        let policy = InProcessEventPolicy::new();
        let publisher = installation(1);
        assert!(!policy.publish_granted(publisher, &topic("order.created")));
        policy.grant_publish(publisher, topic("order.created"));
        assert!(policy.publish_granted(publisher, &topic("order.created")));
        // 字符串等价匹配：相近 topic 不授权。
        assert!(!policy.publish_granted(publisher, &topic("order.creat")));
        assert!(!policy.publish_granted(installation(2), &topic("order.created")));
    }

    #[test]
    fn reserved_topic_prefix_denies_guest_publish() {
        let policy = InProcessEventPolicy::new();
        let publisher = installation(1);
        // 策略细节：core. 保留前缀即使显式授予也拒绝 guest 发布。
        policy.grant_publish(publisher, topic("core.system.heartbeat"));
        assert!(!policy.publish_granted(publisher, &topic("core.system.heartbeat")));
    }

    #[test]
    fn subscribers_are_deterministically_ordered() {
        let policy = InProcessEventPolicy::new();
        let created_topic = topic("order.created");
        // 乱序授予，期望按安装身份排序返回。
        let subscriber_c = installation(30);
        let subscriber_a = installation(10);
        let subscriber_b = installation(20);
        policy.grant_subscribe(subscriber_c, created_topic.clone());
        policy.grant_subscribe(subscriber_a, created_topic.clone());
        policy.grant_subscribe(subscriber_b, created_topic.clone());
        assert_eq!(
            policy.subscribers(&created_topic),
            vec![subscriber_a, subscriber_b, subscriber_c]
        );
        // 其他 topic 无订阅者。
        assert!(policy.subscribers(&topic("order.shipped")).is_empty());
    }

    #[test]
    fn revoke_subscribe_stops_fan_out() {
        let policy = InProcessEventPolicy::new();
        let created_topic = topic("order.created");
        let subscriber = installation(1);
        policy.grant_subscribe(subscriber, created_topic.clone());
        assert_eq!(policy.subscribers(&created_topic), vec![subscriber]);
        policy.revoke_subscribe(subscriber, &created_topic);
        assert!(policy.subscribers(&created_topic).is_empty());
    }
}
