//! 0.3.0 Stateful Runtime（§41.2 / §17.3）——typed event bus service
//! （guest 调用面；契约 `operune:event@0.1.0` event.wit / handler.wit，
//! 已提交稳定）。
//!
//! # 职责
//!
//! - **publish（同步背压）**：topic 由 domain 边界校验（[`EventTopic`]，
//!   §13.3 边界解析一次）；载荷有界（[`EventPayload`]，§7.4 host buffer
//!   上限）；发布授权按静态 grant 策略（[`crate::ports::EventPolicyPort`]，
//!   §17.3 "event topics" scope）→ `denied`；发布经**有界入队队列**
//!   （§15.2/§7.4 最大排队）接收——队列满 → `over-budget`（**发布侧背压
//!   以同步错误表达**，event.wit §41.2 MUST）；停机窗口 → `not-ready`；
//! - **事件 id 分配**（发布时，Core 侧；§41.2 audit 关联与跨系统排查，
//!   0.1.0 不做交付去重）；
//! - **订阅是静态 grant 策略**（§17.1 两阶段含义）：没有运行时
//!   subscribe/unsubscribe——服务层按 [`EventPolicyPort::subscribers`]
//!   的快照（§17.5 快照语义）**按 grant 集投递**；授权撤销后 Core 停止
//!   投递（撤销前已在途的事件仍可能到达——与 scheduler cancel 竞态同类，
//!   载荷的 `id` 供审计关联）；
//! - **投递侧背压（dropped 计数）**：每订阅有界投递队列（§7.4 最大排队；
//!   §15.2 broadcast 只用于允许 lag/drop 的广播语义——本服务是**每订阅
//!   有界队列的扇出广播**，lag/drop 由 `dropped` 计数显式表达）溢出 →
//!   事件被丢弃并计入 `dropped`，随下一次成功交付可见（event.wit）；
//!   交付为 **at-most-once**：无重试、无补投、无 ack；handler trap 视为
//!   已消费，不重投；
//! - **有界广播**：发布入队队列（每安装实例）与投递队列（每订阅）全部
//!   有界（§15.2）；pump 每轮批量处理以入队队列容量为界（确定性背压）。
//!
//! # 架构
//!
//! 每安装实例一条 **pump 任务**（`tokio::spawn`，`JoinHandle` 由共享状态
//! 持有——supervisor 语义，§15.3；受 CancellationToken 管理，§20.4）：
//!
//! - `publish`（同步）：授权 → 分配 id → 有界入队（满 → `over-budget`）；
//! - pump：从入队队列成批取出（有界）→ 按策略快照查订阅集 → 逐订阅
//!   `try_send` 到有界投递队列（溢出 → `dropped` 递增）；
//! - 每订阅一条 **consumer 任务**：`recv` → 同步调用
//!   [`crate::ports::EventDeliveryPort`]（Core-mediated push；trap = 已
//!   消费）；投递队列关闭（stop）后排空退出；
//! - `stop`：置停机标记、drop 入队 sender（pump 排空已接受工作后退出并
//!   关闭投递队列；consumer 排空后退出）——已接受工作完成，无新发布。

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use operune_domain::{EventId, EventPayload, EventTopic, InstallationId};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::cancel::CancellationToken;
use crate::ports::{EventDeliveryPort, EventPolicyPort};

/// event 策略上限（§7.4 / §15.2 有界性；WIT：载荷体积与发布速率受宿主侧
/// 策略约束，策略值不进入契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventLimits {
    /// 每安装实例的发布入队队列容量（§15.2 有界；满 → publish 同步
    /// `over-budget`——发布侧背压）。
    pub inbound_queue_capacity: usize,
    /// 每订阅的投递队列容量（§15.2 有界广播：lag/drop 语义；溢出 →
    /// 事件被丢弃并计入 `dropped`）。
    pub delivery_queue_capacity: usize,
}

impl Default for EventLimits {
    fn default() -> Self {
        Self {
            inbound_queue_capacity: 64,
            delivery_queue_capacity: 16,
        }
    }
}

/// event 用例层错误（对齐 WIT `event-error` 闭集，§6.3）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EventError {
    /// 未获该 topic 的发布授权（grant 解析/撤销，§17.1/§17.5；含 Core
    /// 保留前缀的策略拒绝）。
    #[error("event publish not granted for topic")]
    Denied,

    /// topic 违反本契约不变量（domain 边界已拦截；防御面）。
    #[error("invalid event topic: {0}")]
    InvalidTopic(&'static str),

    /// 总线未就绪（激活窗口/恢复中；停机窗口；无 tokio runtime 上下文）。
    #[error("event bus not ready (stopped or no runtime context)")]
    NotReady,

    /// 超出预算：发布入队队列满（发布速率超限，§7.4/§41.2 发布侧背压）。
    #[error("event publish over budget (inbound queue full)")]
    OverBudget,

    /// guest/host 内部不可恢复错误（§14.3 fail-stop 语义）。
    #[error("event bus internal invariant violated: {0}")]
    Internal(&'static str),
}

/// 一次发布入队的事件（publish 时分配 id；投递形态在扇出时按订阅补
/// `dropped`）。
#[derive(Debug, Clone)]
struct InboundEvent {
    event_id: EventId,
    topic: EventTopic,
    payload: EventPayload,
}

/// 每订阅的投递队列状态（dropped 计数：自上次成功交付以来被丢弃的事件
/// 数，随下一次成功交付可见，event.wit）。
#[derive(Debug)]
struct SubscriberState {
    /// 有界投递队列 sender（consumer 在另一端）。
    tx: mpsc::Sender<DeliveredEvent>,
    /// consumer 任务句柄（supervisor 持有，§15.3——句柄存续期间任务不被
    /// detach；生命周期结束由通道关闭 + 队列排空决定，无需读取句柄）。
    #[allow(dead_code)]
    consumer: Option<JoinHandle<()>>,
    /// 自上次成功交付以来被背压丢弃的事件数。
    dropped: u64,
}

/// 每安装实例的 bus 状态。
#[derive(Debug)]
struct InstallEventState {
    /// 发布入队队列 sender（`None` = 停机/未创建）。
    inbound: Option<mpsc::Sender<InboundEvent>>,
    /// 每订阅投递队列（惰性创建；stop 时整体关闭）。
    subscribers: HashMap<InstallationId, SubscriberState>,
    /// pump 任务句柄（supervisor 持有）。
    pump: Option<JoinHandle<()>>,
    /// 结构化取消令牌（§20.4）。
    token: CancellationToken,
    /// 停机标记。
    stopped: bool,
}

/// 共享状态（`Send + Sync`：同步调用方与 pump/consumer 任务共享）。
#[derive(Debug)]
struct SharedState {
    installs: BTreeMap<InstallationId, InstallEventState>,
}

/// 服务内部共享面。
struct Inner {
    state: Mutex<SharedState>,
    policy: Arc<dyn EventPolicyPort>,
    delivery: Arc<dyn EventDeliveryPort>,
    limits: EventLimits,
    next_event_id: AtomicU64,
}

/// 一次事件投递的载荷（WIT handler 的 `event` record 对齐：
/// id / topic / payload / dropped）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredEvent {
    id: EventId,
    topic: EventTopic,
    payload: EventPayload,
    dropped: u64,
}

impl DeliveredEvent {
    /// 构造投递载荷（§13.3 边界解析一次；`dropped` 由服务层按订阅计数
    /// 产生）。
    pub fn new(id: EventId, topic: EventTopic, payload: EventPayload, dropped: u64) -> Self {
        Self {
            id,
            topic,
            payload,
            dropped,
        }
    }

    /// 事件 id（Core 发布时分配；审计关联）。
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// 事件的 topic。
    pub fn topic(&self) -> &EventTopic {
        &self.topic
    }

    /// 事件载荷。
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    /// 自本订阅上次成功交付以来被背压丢弃的事件数（0 = 未丢弃）。
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// typed event bus service（guest 调用面，§41.2 / §17.3）。
///
/// 构造：`policy`/`delivery`/`limits` 由 composition root 注入（§24.2
/// 端口注入）。订阅与发布授权是静态策略（[`EventPolicyPort`]），无运行时
/// subscribe/unsubscribe。
pub struct EventService {
    inner: Arc<Inner>,
}

impl EventService {
    /// 构造（policy + delivery + limits；§24.2 端口注入）。
    pub fn new(
        policy: Arc<dyn EventPolicyPort>,
        delivery: Arc<dyn EventDeliveryPort>,
        limits: EventLimits,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(SharedState {
                    installs: BTreeMap::new(),
                }),
                policy,
                delivery,
                limits,
                next_event_id: AtomicU64::new(1),
            }),
        }
    }

    /// 向 topic 发布一个事件（WIT `publish`）。
    ///
    /// - 发布授权在 grant scope（§17.3 event topics）；未授权 → `denied`
    ///   （含 Core 保留前缀的策略拒绝）；
    /// - 载荷体积由 domain 边界校验（超限构造即失败，§13.3）；
    /// - 同步返回：`ok` 表示事件已被 Core 接收（**有界入队**，投递到各
    ///   订阅实例是异步的、at-most-once）；入队队列满 → `over-budget`
    ///   （发布侧同步背压，§41.2 MUST）；停机窗口 → `not-ready`。
    pub fn publish(
        &self,
        installation: InstallationId,
        topic: EventTopic,
        payload: EventPayload,
    ) -> Result<(), EventError> {
        // 发布授权（静态 grant 策略，§17.3）。
        if !self.inner.policy.publish_granted(installation, &topic) {
            return Err(EventError::Denied);
        }
        // 事件 id 由 Core 分配（发布时；审计关联，§41.2）。
        let event_id = EventId::from_u64(self.inner.next_event_id.fetch_add(1, Ordering::Relaxed));
        let inbound = InboundEvent {
            event_id,
            topic,
            payload,
        };
        let tx = self.ensure_install(installation)?;
        match tx.try_send(inbound) {
            Ok(()) => Ok(()),
            // 有界入队队列满：发布速率超限（§7.4）——同步背压。
            Err(TrySendError::Full(_)) => Err(EventError::OverBudget),
            // pump 已退出（停机窗口）。
            Err(TrySendError::Closed(_)) => Err(EventError::NotReady),
        }
    }

    /// 停机（§20.4/§41.2 stop）：不再接收新发布；已入队的在途事件由 pump
    /// 排空（已接受工作），随后投递队列关闭、consumer 排空退出。
    ///
    /// 幂等；从未使用过总线的安装实例也会记录停机（其后的 `publish`
    /// 返回 `not-ready`）。
    pub fn stop(&self, installation: InstallationId) -> Result<(), EventError> {
        let token = {
            let mut guard = self.state_lock();
            let install = guard
                .installs
                .entry(installation)
                .or_insert_with(|| InstallEventState {
                    inbound: None,
                    subscribers: HashMap::new(),
                    pump: None,
                    token: CancellationToken::new(),
                    stopped: false,
                });
            if install.stopped {
                return Ok(());
            }
            install.stopped = true;
            // 关闭发布入队（pump 排空后退出，退出路径关闭投递队列）。
            install.inbound = None;
            install.token.clone()
        };
        // 结构化取消 pump（§15.3/§20.4）；pump 退出时关闭投递队列 →
        // consumer 排空后退出。
        token.cancel();
        Ok(())
    }

    /// 安装实例当前是否处于停机状态（诊断）。
    pub fn is_stopped(&self, installation: InstallationId) -> bool {
        self.state_lock()
            .installs
            .get(&installation)
            .map(|install| install.stopped)
            .unwrap_or(false)
    }

    /// 安装实例累计被丢弃（投递侧背压）的事件数（诊断/测试；跨订阅求和）。
    pub fn dropped_total(&self, installation: InstallationId) -> u64 {
        self.state_lock()
            .installs
            .get(&installation)
            .map(|install| {
                install
                    .subscribers
                    .values()
                    .map(|subscriber| subscriber.dropped)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// 获取（或惰性创建）安装实例的发布入队队列并确保 pump 运行。
    fn ensure_install(
        &self,
        installation: InstallationId,
    ) -> Result<mpsc::Sender<InboundEvent>, EventError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| EventError::NotReady)?;
        let mut guard = self.state_lock();
        if let Some(install) = guard.installs.get(&installation) {
            if install.stopped {
                return Err(EventError::NotReady);
            }
            if let Some(tx) = &install.inbound {
                return Ok(tx.clone());
            }
            // 理论不可达（未停机必有 sender）；防御面。
            return Err(EventError::Internal("install state without inbound sender"));
        }
        // 惰性创建：channel + pump（同一临界区内完成；并发 publish 的
        // get-or-create 由首次插入者胜出）。
        let (tx, rx) = mpsc::channel(self.inner.limits.inbound_queue_capacity);
        let inner = Arc::clone(&self.inner);
        let token = CancellationToken::new();
        let pump_token = token.clone();
        let pump = handle.spawn(run_pump(inner, installation, rx, pump_token));
        guard.installs.insert(
            installation,
            InstallEventState {
                inbound: Some(tx.clone()),
                subscribers: HashMap::new(),
                pump: Some(pump),
                token,
                stopped: false,
            },
        );
        Ok(tx)
    }

    fn state_lock(&self) -> MutexGuard<'_, SharedState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// pump 循环（每安装实例一个）：成批取出入队事件（以入队队列容量为界，
/// §15.2）→ 按策略快照查订阅集 → 逐订阅投递（有界投递队列；溢出 →
/// `dropped` 递增）。
///
/// 停机语义（§20.4/§41.2 stop）：取消令牌或入队通道关闭（stop 两者都
/// 触发）→ **排空已接受工作**（在途入队事件仍扇出投递）后退出；随后关闭
/// 全部订阅投递队列（drop sender）→ 各 consumer 排空后退出；移除自身
/// pump 句柄。
async fn run_pump(
    inner: Arc<Inner>,
    installation: InstallationId,
    mut inbound: mpsc::Receiver<InboundEvent>,
    token: CancellationToken,
) {
    loop {
        let event = tokio::select! {
            _ = token.cancelled() => {
                // 停机：排空已接受工作（在途发布）后退出。
                while let Ok(more) = inbound.try_recv() {
                    fan_out(&inner, installation, &more);
                }
                break;
            }
            event = inbound.recv() => event,
        };
        let Some(first) = event else {
            break;
        };
        // 有界批量：同一订阅的连续发布在同一轮 pump 内看到一致的队列
        // 状态（确定性背压；批量大小以入队队列容量为界，§15.2）。
        let mut batch = vec![first];
        while let Ok(more) = inbound.try_recv() {
            batch.push(more);
        }
        for event in batch {
            fan_out(&inner, installation, &event);
        }
        // 批处理期间停机（token 已取消）：排空剩余在途后退出——本批仍
        // 完成（已接受工作），剩余事件同样按已接受工作排空。
        if token.is_cancelled() {
            while let Ok(more) = inbound.try_recv() {
                fan_out(&inner, installation, &more);
            }
            break;
        }
    }
    // 退出路径：关闭全部订阅投递队列（consumer 排空后退出）。
    let mut guard = inner
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(install) = guard.installs.get_mut(&installation) {
        install.subscribers.clear();
        install.pump = None;
    }
}

/// 单事件扇出：按策略快照（§17.5 快照语义）把事件投递到每个订阅安装
/// 实例的有界投递队列；队列溢出 → 事件被丢弃并计入 `dropped`（随下一次
/// 成功交付可见，event.wit）。
fn fan_out(inner: &Inner, installation: InstallationId, event: &InboundEvent) {
    // 策略快照（§17.5）：每次扇出读取当前订阅集——撤销后 Core 以快照
    // 停止投递（撤销前已入队投递队列的事件仍可能到达，event.wit）。
    let subscribers = inner.policy.subscribers(&event.topic);
    for subscriber in subscribers {
        let mut guard = inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(install) = guard.installs.get_mut(&installation) else {
            return;
        };
        let state = install
            .subscribers
            .entry(subscriber)
            .or_insert_with(|| spawn_subscriber(inner));
        // 载荷携带自上次成功交付以来被丢弃的计数（随本次交付可见）。
        let delivered = DeliveredEvent::new(
            event.event_id,
            event.topic.clone(),
            event.payload.clone(),
            state.dropped,
        );
        match state.tx.try_send(delivered) {
            Ok(()) => {
                // 交付成功：计数复位（本次载荷已携带此前丢弃数）。
                state.dropped = 0;
            }
            // 投递队列溢出：事件被丢弃并计入 dropped（§41.2 投递侧背压）。
            Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                state.dropped = state.dropped.saturating_add(1);
            }
        }
    }
}

/// 惰性派生订阅投递队列 + consumer（有界，§15.2；Core-mediated push）。
fn spawn_subscriber(inner: &Inner) -> SubscriberState {
    let handle = match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle,
        // 防御：pump 运行中必有 runtime 上下文；失败则返回空队列 sender
        // 会被立刻关闭（drop）——该订阅的投递按丢弃处理。
        Err(_) => {
            let (tx, _rx) = mpsc::channel(inner.limits.delivery_queue_capacity);
            return SubscriberState {
                tx,
                consumer: None,
                dropped: 0,
            };
        }
    };
    let (tx, rx) = mpsc::channel(inner.limits.delivery_queue_capacity);
    let delivery = Arc::clone(&inner.delivery);
    let consumer = handle.spawn(run_consumer(delivery, rx));
    SubscriberState {
        tx,
        consumer: Some(consumer),
        dropped: 0,
    }
}

/// 投递 consumer（有界队列的另一端）：Core-mediated push 同步调用 guest
/// handler；返回即已消费，trap 视为已消费，不重投（at-most-once）。
async fn run_consumer(
    delivery: Arc<dyn EventDeliveryPort>,
    mut rx: mpsc::Receiver<DeliveredEvent>,
) {
    while let Some(event) = rx.recv().await {
        // handler trap/运行时失败：已消费语义，不重投（handler.wit）；
        // 错误只用于宿主侧观测。
        let _ = delivery.on_event(event);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::ports::InProcessEventPolicy;
    use crate::test_support::{FakeEventDelivery, err, installation, ok};

    /// 测试装配：静态策略 + 记录投递。
    struct Harness {
        service: EventService,
        policy: Arc<InProcessEventPolicy>,
        delivery: Arc<FakeEventDelivery>,
    }

    fn harness(limits: EventLimits) -> Harness {
        let policy = Arc::new(InProcessEventPolicy::new());
        let delivery = Arc::new(FakeEventDelivery::new());
        let service = EventService::new(
            Arc::clone(&policy) as Arc<dyn EventPolicyPort>,
            Arc::clone(&delivery) as Arc<dyn EventDeliveryPort>,
            limits,
        );
        Harness {
            service,
            policy,
            delivery,
        }
    }

    fn default_limits() -> EventLimits {
        EventLimits {
            inbound_queue_capacity: 64,
            delivery_queue_capacity: 16,
        }
    }

    /// 投递队列容量 1 的测试形态（dropped 场景）。
    fn tight_limits() -> EventLimits {
        EventLimits {
            delivery_queue_capacity: 1,
            ..default_limits()
        }
    }

    fn topic(name: &str) -> EventTopic {
        ok(EventTopic::new(name), "topic")
    }

    fn payload(text: &str) -> EventPayload {
        ok(EventPayload::json(text), "payload")
    }

    /// 推进 paused-time 并让 pump/consumer 任务得到轮询。
    async fn advance(h: &Harness, millis: u64) {
        tokio::time::advance(StdDuration::from_millis(millis)).await;
        // paused-time 下任务只在被 poll 时推进；yield 让 pump（扇出）与
        // consumer（交付）完成处理。
        tokio::task::yield_now().await;
        let _ = h.delivery.delivered();
    }

    /// 等待投递队列被 consumer 排空（确定性：yield 让已唤醒的 consumer
    /// 任务逐项处理；投递队列有界，排空轮数有界）。
    async fn drain_pending(h: &Harness) {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let _ = h.delivery.delivered();
    }

    #[tokio::test(start_paused = true)]
    async fn publish_delivers_to_all_subscribers_with_unique_ids() {
        let h = harness(default_limits());
        let publisher = installation(1);
        let subscriber_a = installation(2);
        let subscriber_b = installation(3);
        h.policy.grant_publish(publisher, topic("order.created"));
        h.policy
            .grant_subscribe(subscriber_a, topic("order.created"));
        h.policy
            .grant_subscribe(subscriber_b, topic("order.created"));
        let payload = payload("{\"order\":1}");
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload.clone()),
            "publish",
        );
        advance(&h, 1).await;
        drain_pending(&h).await;
        let delivered = h.delivery.delivered();
        assert_eq!(delivered.len(), 2, "fan-out to every subscriber");
        // 同一事件投递到两个订阅：id 相同（发布时分配），载荷/topic 保留。
        assert_eq!(delivered[0].id(), delivered[1].id());
        assert_eq!(delivered[0].id().as_u64(), 1);
        assert_eq!(delivered[0].topic().as_str(), "order.created");
        assert_eq!(delivered[0].payload(), &payload);
        assert_eq!(delivered[0].dropped(), 0);
        assert_eq!(delivered[1].dropped(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn publish_without_grant_is_denied() {
        let h = harness(default_limits());
        let publisher = installation(1);
        let error = err(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish",
        );
        assert!(matches!(error, EventError::Denied));
    }

    #[tokio::test(start_paused = true)]
    async fn publish_to_reserved_prefix_is_denied() {
        let h = harness(default_limits());
        let publisher = installation(1);
        // 策略细节（InProcessEventPolicy）：core. 保留前缀即使显式授予也
        // 拒绝 guest 发布。
        h.policy
            .grant_publish(publisher, topic("core.system.heartbeat"));
        let error = err(
            h.service
                .publish(publisher, topic("core.system.heartbeat"), payload("{}")),
            "publish",
        );
        assert!(matches!(error, EventError::Denied));
    }

    #[tokio::test(start_paused = true)]
    async fn no_subscribers_still_accepts_publish() {
        let h = harness(default_limits());
        let publisher = installation(1);
        h.policy.grant_publish(publisher, topic("order.created"));
        // 无订阅者：发布成功（事件被 Core 接收），无投递。
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish",
        );
        advance(&h, 1).await;
        assert!(h.delivery.delivered().is_empty());
    }

    // ------------------------------------------------------------------
    // 投递侧背压：dropped 计数（随下一次成功交付可见，event.wit）
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn delivery_queue_overflow_counts_dropped() {
        // 投递队列容量 1：同一 pump 轮内的连续两次发布 → 第一次入队，
        // 第二次溢出 → 计入 dropped（确定性背压，无需慢 consumer）。
        let h = harness(tight_limits());
        let publisher = installation(1);
        let subscriber = installation(2);
        h.policy.grant_publish(publisher, topic("order.created"));
        h.policy.grant_subscribe(subscriber, topic("order.created"));
        // 连续发布两次（同步调用之间无任务轮询）：同一 pump 轮内扇出。
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":1}")),
            "publish 1",
        );
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":2}")),
            "publish 2",
        );
        advance(&h, 1).await;
        // 第二次发布被丢弃并计入 dropped（投递侧背压观测面）。
        assert_eq!(h.service.dropped_total(publisher), 1);
        // 下一次成功交付携带 dropped = 1。
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":3}")),
            "publish 3",
        );
        advance(&h, 1).await;
        drain_pending(&h).await;
        let delivered = h.delivery.delivered();
        assert_eq!(delivered.len(), 2, "two delivered: first and third event");
        assert_eq!(delivered[0].dropped(), 0);
        assert_eq!(
            delivered[1].dropped(),
            1,
            "dropped count visible on next delivery"
        );
        assert_eq!(delivered[1].id().as_u64(), 3);
        // 交付成功后计数复位。
        assert_eq!(h.service.dropped_total(publisher), 0);
    }

    // ------------------------------------------------------------------
    // 发布侧同步背压：入队队列满 → over-budget
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn publish_over_budget_when_inbound_queue_full() {
        let limits = EventLimits {
            inbound_queue_capacity: 2,
            delivery_queue_capacity: 16,
        };
        let h = harness(limits);
        let publisher = installation(1);
        h.policy.grant_publish(publisher, topic("order.created"));
        // 入队容量 2：pump 未轮询期间连续发布填满队列 → 第三次同步拒绝。
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish 1",
        );
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish 2",
        );
        let error = err(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish 3",
        );
        assert!(matches!(error, EventError::OverBudget));
        // pump 排空后恢复。
        advance(&h, 1).await;
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish after drain",
        );
    }

    // ------------------------------------------------------------------
    // 停机：不再接收新发布；已接受工作完成
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn stop_prevents_new_publishes_and_drains_in_flight() {
        let h = harness(default_limits());
        let publisher = installation(1);
        let subscriber = installation(2);
        h.policy.grant_publish(publisher, topic("order.created"));
        h.policy.grant_subscribe(subscriber, topic("order.created"));
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":1}")),
            "publish 1",
        );
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":2}")),
            "publish 2",
        );
        ok(h.service.stop(publisher), "stop");
        // 停机错过不补投：无新发布接收。
        let error = err(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":3}")),
            "publish after stop",
        );
        assert!(matches!(error, EventError::NotReady));
        // 已接受工作（在途事件）排空后投递。
        advance(&h, 1).await;
        drain_pending(&h).await;
        let delivered = h.delivery.delivered();
        assert_eq!(delivered.len(), 2, "in-flight events complete");
    }

    #[tokio::test(start_paused = true)]
    async fn stop_is_idempotent_and_noop_for_unused_installations() {
        let h = harness(default_limits());
        let unused = installation(1);
        // 授予发布权（publish 的授权检查先于就绪检查——未授权 topic 在
        // 任何总线状态下都是 denied）。
        h.policy.grant_publish(unused, topic("order.created"));
        ok(h.service.stop(unused), "stop unused");
        assert!(h.service.is_stopped(unused));
        ok(h.service.stop(unused), "stop again (idempotent)");
        // 停用后发布 → not-ready（总线未就绪）。
        let error = err(
            h.service
                .publish(unused, topic("order.created"), payload("{}")),
            "publish after stop",
        );
        assert!(matches!(error, EventError::NotReady));
    }

    // ------------------------------------------------------------------
    // 策略快照：撤销订阅后停止投递
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn revoked_subscription_stops_delivery() {
        let h = harness(default_limits());
        let publisher = installation(1);
        let subscriber = installation(2);
        h.policy.grant_publish(publisher, topic("order.created"));
        h.policy.grant_subscribe(subscriber, topic("order.created"));
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":1}")),
            "publish 1",
        );
        // 让第一个事件完成扇出（撤销前已在途，event.wit：仍可能到达）。
        advance(&h, 1).await;
        drain_pending(&h).await;
        assert_eq!(h.delivery.delivered().len(), 1);
        // 授权撤销（§17.5 快照语义）：Core 以策略快照停止投递。
        h.policy
            .revoke_subscribe(subscriber, &topic("order.created"));
        ok(
            h.service
                .publish(publisher, topic("order.created"), payload("{\"n\":2}")),
            "publish 2",
        );
        advance(&h, 1).await;
        drain_pending(&h).await;
        assert_eq!(
            h.delivery.delivered().len(),
            1,
            "no delivery after subscription revocation"
        );
    }

    #[test]
    fn publish_outside_runtime_context_is_not_ready() {
        // 无 tokio runtime 上下文：无法派生 pump → not-ready，且不产生
        // 任何状态变化。
        let h = harness(default_limits());
        let publisher = installation(1);
        h.policy.grant_publish(publisher, topic("order.created"));
        let error = err(
            h.service
                .publish(publisher, topic("order.created"), payload("{}")),
            "publish",
        );
        assert!(matches!(error, EventError::NotReady));
        assert_eq!(h.service.dropped_total(publisher), 0);
    }

    #[test]
    fn delivered_event_accessors() {
        let event = DeliveredEvent::new(
            EventId::from_u64(7),
            topic("order.created"),
            payload("{\"ok\":true}"),
            3,
        );
        assert_eq!(event.id(), EventId::from_u64(7));
        assert_eq!(event.topic().as_str(), "order.created");
        assert_eq!(event.payload(), &payload("{\"ok\":true}"));
        assert_eq!(event.dropped(), 3);
    }
}
