//! 0.3.0 Stateful Runtime（§41.2）——typed scheduler service（guest 调用面；
//! 契约 `operune:scheduler@0.1.0` scheduler.wit / handler.wit，已提交稳定）。
//!
//! # 职责
//!
//! - **注册/取消/状态查询**：typed [`ScheduleTrigger`]（domain 校验过的
//!   触发形态，§13.3 边界解析一次）；`schedule` 注册期校验（
//!   `invalid-trigger`：目标时刻已过去 / interval 低于策略下限，
//!   scheduler.wit 明文）；Core 分配 [`ScheduledTaskId`]；
//! - **UTC 硬时刻语义**：`fire-at` / `next-fire-at` 是 UTC 硬时刻；服务层
//!   以注入的 [`Clock`]（[`crate::clock`]）判定"目标时刻已过去"，用
//!   [`UtcInstant`] 计算下一次 fire 时刻，换算为单调延迟后由 **tokio
//!   定时器**驱动（§15.1）；
//! - **missed-fires 语义**（scheduler.wit 交付语义，§41.2 backpressure）：
//!   每次 fire 要么交付一次、要么计入错过——交付队列溢出（实例忙/实例集
//!   受限，§7.3）的 fire 计入错过，随下一次成功交付可见（handler 载荷
//!   `missed-fires`）；**at-most-once**：无重试、无补投、无 catch-up 回放；
//!   handler trap 视为已消费，不重投；
//! - **cancel 竞态**：`cancel` 返回 ok 后不再产生新 fire，但已在途的一次
//!   fire 仍可能先到（线性化点；guest 用 `sequence` 幂等，handler.wit）；
//!   一次性任务已触发/已错过、或任务未知 → `not-found`；
//! - **停机不补投**：停机（[`SchedulerService::stop`]）后不再调度新任务、
//!   不产生新 fire；已入队的在途 fire 由投递 consumer 排空（已接受工作，
//!   §20.4）；错过在停机后不重放（0.1.0 的任务本体持久化是 Core 实现
//!   细节，WIT 明文）；
//! - **有界（§15.2/§7.4）**：每安装实例任务数上限、全局任务数上限
//!   （`over-budget`）；每安装实例待交付队列有界（容量
//!   [`SchedulerLimits::delivery_queue_capacity`]，溢出 → 计入错过）；
//!   driver 唤醒信号用 watch 通道（无丢失唤醒，先例：server 的
//!   CancellationToken 模式）。
//!
//! # 架构
//!
//! 每安装实例一个 **driver 任务**（`tokio::spawn`，`JoinHandle` 由共享
//! 状态持有——supervisor 语义，§15.3；受 CancellationToken 管理，§20.4）：
//!
//! - 共享状态（`Mutex` 守卫）持有每安装的任务表（权威事实）与 wake 通道；
//! - driver 循环：计算最早下次 fire 时刻 → `select!`{ 取消令牌、wake
//!   （schedule/cancel 后重新扫描）、时钟 sleep } → 到期处理全部到期网格
//!   点（一次性 1 个；周期 k_max 个，队列溢出时 O(1) 批量计入错过）；
//! - 交付：driver 经**有界**投递队列（`tokio::sync::mpsc`）交给 consumer
//!   任务，consumer 同步调用 [`SchedulerDeliveryPort`]（Core-mediated push；
//!   trap = 已消费）；队列溢出 → fire 计入错过；
//! - driver 退出（取消令牌）时移除自身句柄并 drop 投递 sender → consumer
//!   排空后退出（停机错过不补投）。
//!
//! 时间推进的可测性：注入的 [`Clock`] 决定 `now()` 与 sleep——测试用
//! tokio paused-time + 锁步 UTC 时钟（`PausedClock`，test_support）即可
//! 确定性推进（无 sleep 掩盖竞态）。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use operune_domain::{
    Duration, InstallationId, ScheduleTrigger, ScheduledTaskId, TaskState, TaskStatus,
    TriggerPayload, UtcInstant,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::cancel::CancellationToken;
use crate::clock::Clock;
use crate::ports::{SchedulerDeliveryPort, SchedulerGrantPort};

/// scheduler 策略上限（§7.4 / §15.2 有界性；WIT：任务总数与队列上限受
/// 宿主侧策略约束，策略值不进入契约）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerLimits {
    /// 每安装实例的注册任务数上限（§7.4 "Component 生成的后台任务数量"）。
    pub max_tasks_per_installation: usize,
    /// 全局注册任务数上限（跨安装实例）。
    pub max_total_tasks: usize,
    /// 每安装实例待交付队列容量（有界，§15.2；溢出 → 计入错过）。
    pub delivery_queue_capacity: usize,
    /// 周期触发的最小间隔（策略下限；低于 → `invalid-trigger`）。
    pub min_periodic_interval: Duration,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            max_tasks_per_installation: 64,
            max_total_tasks: 1024,
            delivery_queue_capacity: 16,
            min_periodic_interval: Duration::from_millis(1),
        }
    }
}

/// scheduler 用例层错误（对齐 WIT `scheduler-error` 闭集，§6.3）。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// 未获 scheduler 能力授权（grant 解析/撤销，§17.1/§17.5）。
    #[error("scheduler capability not granted")]
    Denied,

    /// 触发形态违反契约不变量（目标时刻已过去、interval 低于策略下限）。
    #[error("invalid trigger: {0}")]
    InvalidTrigger(&'static str),

    /// 任务不存在（未知 / 已结束的一次性任务 / 已取消）。
    #[error("scheduled task not found")]
    NotFound,

    /// 调度器未就绪（停机窗口；无 tokio runtime 上下文）。
    #[error("scheduler not ready (stopped or no runtime context)")]
    NotReady,

    /// 超出预算：注册任务总数（§7.4 后台任务数量）、调度速率上限。
    #[error("scheduler operation over budget")]
    OverBudget,

    /// guest/host 内部不可恢复错误（§14.3 fail-stop 语义）。
    #[error("scheduler internal invariant violated: {0}")]
    Internal(&'static str),
}

/// 一次 fire 的调度记录（共享状态中的权威任务事实）。
#[derive(Debug, Clone)]
struct TaskEntry {
    trigger: ScheduleTrigger,
    state: TaskState,
    /// 下一个 fire 的序号（从 1 递增；每次 fire——交付或错过——消耗一个
    /// 序号，handler.wit 幂等面）。
    sequence: u64,
    /// 自上次成功交付以来错过的 fire 数（handler 载荷同源，scheduler.wit）。
    missed_fires: u64,
    /// 下一次计划触发时刻（已取消/已结束为 `None`）。
    next_fire_at: Option<UtcInstant>,
}

/// 每安装实例的调度器状态。
#[derive(Debug)]
struct InstallSchedulerState {
    /// 权威任务表（driver 与同步调用方共享）。
    tasks: BTreeMap<ScheduledTaskId, TaskEntry>,
    /// 停机标记：stop 后不再调度新任务、不产生新 fire。
    stopped: bool,
    /// driver 唤醒通道（generation；schedule/cancel 后 bump，无丢失唤醒）。
    wake: watch::Sender<u64>,
    /// 当前 driver 任务句柄（supervisor 持有，§15.3；driver 退出时自移除）。
    driver: Option<JoinHandle<()>>,
    /// 投递 consumer 任务句柄（supervisor 持有，§15.3——句柄存续期间
    /// 任务不被 detach；生命周期结束由通道关闭 + 队列排空决定）。
    #[allow(dead_code)]
    consumer: Option<JoinHandle<()>>,
    /// driver/consumer 的结构化取消令牌（§20.4）。
    token: CancellationToken,
}

impl InstallSchedulerState {
    fn new() -> Self {
        let (wake, _) = watch::channel(0u64);
        Self {
            tasks: BTreeMap::new(),
            stopped: false,
            wake,
            driver: None,
            consumer: None,
            token: CancellationToken::new(),
        }
    }
}

/// 共享状态（`Send + Sync`：同步调用方与 driver 任务共享）。
#[derive(Debug)]
struct SharedState {
    installs: BTreeMap<InstallationId, InstallSchedulerState>,
}

/// 服务内部共享面。
struct Inner {
    state: Mutex<SharedState>,
    grant: Arc<dyn SchedulerGrantPort>,
    delivery: Arc<dyn SchedulerDeliveryPort>,
    clock: Arc<dyn Clock>,
    limits: SchedulerLimits,
    next_task_id: AtomicU64,
}

/// typed scheduler service（guest 调用面，§41.2）。
///
/// 构造：`grant`/`delivery`/`clock`/`limits` 由 composition root 注入
/// （§24.2 端口注入）。时间推进依赖注入的 [`Clock`]——生产用
/// [`crate::clock::SystemClock`]，测试用受控时钟。
pub struct SchedulerService {
    inner: Arc<Inner>,
}

impl SchedulerService {
    /// 构造（grant + delivery + clock + limits；§24.2 端口注入）。
    pub fn new(
        grant: Arc<dyn SchedulerGrantPort>,
        delivery: Arc<dyn SchedulerDeliveryPort>,
        clock: Arc<dyn Clock>,
        limits: SchedulerLimits,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(SharedState {
                    installs: BTreeMap::new(),
                }),
                grant,
                delivery,
                clock,
                limits,
                next_task_id: AtomicU64::new(1),
            }),
        }
    }

    /// 注册一个定时任务（WIT `schedule`）。
    ///
    /// 注册期校验（scheduler.wit 明文）：目标时刻已过去（
    /// `invalid-trigger`）、interval 低于策略下限（`invalid-trigger`）、
    /// 任务数超上限（`over-budget`）、未获能力授权（`denied`）、停机窗口
    /// （`not-ready`）。返回 Core 分配的任务标识。
    pub fn schedule(
        &self,
        installation: InstallationId,
        trigger: ScheduleTrigger,
    ) -> Result<ScheduledTaskId, SchedulerError> {
        // 运行时上下文先行（driver 派生前提；失败不产生任何状态变化）。
        tokio::runtime::Handle::try_current().map_err(|_| SchedulerError::NotReady)?;
        if !self
            .inner
            .grant
            .scheduler_granted(installation)
            .map_err(|_| SchedulerError::Internal("grant query failed"))?
        {
            return Err(SchedulerError::Denied);
        }
        let now = self
            .inner
            .clock
            .now()
            .map_err(|_| SchedulerError::Internal("wall clock unavailable"))?;
        validate_trigger(trigger, now, self.inner.limits.min_periodic_interval)?;

        let task_id =
            ScheduledTaskId::from_u64(self.inner.next_task_id.fetch_add(1, Ordering::Relaxed));
        {
            let mut guard = self.state_lock();
            // 全局任务数（跨安装实例；只计 Scheduled——已取消任务不再是
            // 后台任务，§7.4；先于本安装条目借用计算）。
            let total: usize = guard
                .installs
                .values()
                .map(|install| scheduled_count(&install.tasks))
                .sum();
            if total >= self.inner.limits.max_total_tasks {
                return Err(SchedulerError::OverBudget);
            }
            let install = guard
                .installs
                .entry(installation)
                .or_insert_with(InstallSchedulerState::new);
            if install.stopped {
                return Err(SchedulerError::NotReady);
            }
            if scheduled_count(&install.tasks) >= self.inner.limits.max_tasks_per_installation {
                return Err(SchedulerError::OverBudget);
            }
            install.tasks.insert(
                task_id,
                TaskEntry {
                    trigger,
                    state: TaskState::Scheduled,
                    sequence: 1,
                    missed_fires: 0,
                    next_fire_at: Some(trigger.first_fire_at()),
                },
            );
            // 唤醒 driver 重新扫描（无丢失唤醒：watch 版本递增）。
            // 注意：先把 generation 拷出再 send_replace——`borrow()` 持有
            // 内部 RwLock 读锁，而 send_replace 需要写锁（send 同）；把
            // `Ref` 作为实参传给 send 会在同一语句内自死锁。
            let generation = install.wake.borrow().saturating_add(1);
            install.wake.send_replace(generation);
        }
        self.ensure_driver(installation)?;
        Ok(task_id)
    }

    /// 取消已注册任务（WIT `cancel`）。
    ///
    /// - 返回 ok：任务已移除，之后不再产生新 fire；已在途的一次 fire 仍
    ///   可能先到（线性化点；guest 用 `sequence` 幂等）；
    /// - 一次性任务已触发/已错过、或任务未知/已取消 → [`SchedulerError::NotFound`]。
    pub fn cancel(
        &self,
        installation: InstallationId,
        task: ScheduledTaskId,
    ) -> Result<(), SchedulerError> {
        let mut guard = self.state_lock();
        let install = guard
            .installs
            .get_mut(&installation)
            .ok_or(SchedulerError::NotFound)?;
        if install.stopped {
            return Err(SchedulerError::NotReady);
        }
        let entry = install
            .tasks
            .get_mut(&task)
            .ok_or(SchedulerError::NotFound)?;
        match entry.state {
            TaskState::Scheduled => {}
            // 已触发/已错过的一次性任务、已取消任务：视为不存在（WIT）。
            TaskState::Cancelled | TaskState::Completed => return Err(SchedulerError::NotFound),
        }
        entry.state = TaskState::Cancelled;
        entry.next_fire_at = None;
        // 取消后唤醒 driver（被取消任务可能正排队最早 fire）。
        // 注意：先把 generation 拷出再 send_replace（borrow 读锁 vs
        // send_replace 写锁的自死锁，见 schedule 注释）；send_replace 不
        // 等待接收者消费（`send` 会阻塞等待——driver 的 receiver 可能
        // 正停在不被 poll 的 `changed()` 上，同步调用方会死锁）。
        let generation = install.wake.borrow().saturating_add(1);
        install.wake.send_replace(generation);
        Ok(())
    }

    /// 查询任务状态（WIT `get-task-status`；side-effect-free）。
    ///
    /// 一次性任务被错过（missed-fires > 0 且状态 completed）时，guest 以
    /// 此可观测全错过的交付损失（scheduler.wit）。
    pub fn task_status(
        &self,
        installation: InstallationId,
        task: ScheduledTaskId,
    ) -> Result<TaskStatus, SchedulerError> {
        let guard = self.state_lock();
        let install = guard
            .installs
            .get(&installation)
            .ok_or(SchedulerError::NotFound)?;
        let entry = install.tasks.get(&task).ok_or(SchedulerError::NotFound)?;
        Ok(TaskStatus::new(
            entry.state,
            entry.missed_fires,
            entry.next_fire_at,
        ))
    }

    /// 停机（§20.4/§41.2 stop）：不再调度新任务、不产生新 fire；已入队的
    /// 在途 fire 由投递 consumer 排空（已接受工作）；**停机错过不补投**。
    ///
    /// 幂等；从未使用过 scheduler 的安装实例也会记录停机（其后的
    /// `schedule`/`cancel` 返回 `not-ready`）。0.1.0 的任务本体（fire 序列）
    /// 不持久化（WIT：持久化策略是 Core 实现细节）——重启后不恢复、不补投。
    pub fn stop(&self, installation: InstallationId) -> Result<(), SchedulerError> {
        let token = {
            let mut guard = self.state_lock();
            let install = guard
                .installs
                .entry(installation)
                .or_insert_with(InstallSchedulerState::new);
            if install.stopped {
                return Ok(());
            }
            install.stopped = true;
            install.token.clone()
        };
        // 结构化取消（§15.3/§20.4）：driver 退出 → drop 投递 sender →
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

    /// 安装实例当前注册任务数（诊断/测试）。
    pub fn task_count(&self, installation: InstallationId) -> usize {
        self.state_lock()
            .installs
            .get(&installation)
            .map(|install| install.tasks.len())
            .unwrap_or(0)
    }

    /// 确保 driver 任务在运行（首次 schedule 时惰性派生；supervisor 持有
    /// 句柄，§15.3）。
    fn ensure_driver(&self, installation: InstallationId) -> Result<(), SchedulerError> {
        let handle = tokio::runtime::Handle::try_current().map_err(|_| SchedulerError::NotReady)?;
        let mut guard = self.state_lock();
        let install = guard
            .installs
            .get_mut(&installation)
            .ok_or(SchedulerError::NotReady)?;
        if install.driver.is_some() {
            return Ok(());
        }
        let inner = Arc::clone(&self.inner);
        let wake_rx = install.wake.subscribe();
        let token = install.token.clone();
        // 投递 consumer 与 driver 同生（有界队列；Core-mediated push）。
        let (tx, rx) = mpsc::channel(self.inner.limits.delivery_queue_capacity);
        let delivery = Arc::clone(&self.inner.delivery);
        install.consumer = Some(handle.spawn(run_consumer(delivery, rx)));
        install.driver = Some(handle.spawn(run_driver(inner, installation, wake_rx, token, tx)));
        Ok(())
    }

    fn state_lock(&self) -> MutexGuard<'_, SharedState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// 注册期触发形态校验（scheduler.wit 明文）：目标时刻已过去 →
/// `invalid-trigger`；interval 低于策略下限 → `invalid-trigger`。
fn validate_trigger(
    trigger: ScheduleTrigger,
    now: UtcInstant,
    min_interval: Duration,
) -> Result<(), SchedulerError> {
    match trigger {
        ScheduleTrigger::OneShot { at } => {
            if at <= now {
                return Err(SchedulerError::InvalidTrigger(
                    "fire-at must be strictly in the future",
                ));
            }
        }
        ScheduleTrigger::Periodic {
            next_fire_at,
            interval,
        } => {
            if next_fire_at <= now {
                return Err(SchedulerError::InvalidTrigger(
                    "next-fire-at must be strictly in the future",
                ));
            }
            if interval < min_interval {
                return Err(SchedulerError::InvalidTrigger(
                    "interval below the policy minimum",
                ));
            }
        }
    }
    Ok(())
}

/// 周期网格的到期点数（`next + k*interval <= now` 的 k 个数，k ≥ 1）。
///
/// `now >= next` 时 k_max = floor((now - next) / interval) + 1；防御面：
/// interval 为 0（注册期已拦截）或差值为负（调用方保证）时回退 1。
fn due_grid_points(next: UtcInstant, now: UtcInstant, interval: Duration) -> u64 {
    let interval_nanos = interval.as_std().as_nanos();
    if interval_nanos == 0 {
        return 1;
    }
    let elapsed_nanos = u128::try_from(
        (now.as_offset_date_time() - next.as_offset_date_time()).whole_nanoseconds(),
    )
    .unwrap_or(0);
    let k = u64::try_from(elapsed_nanos / interval_nanos + 1).unwrap_or(u64::MAX);
    k.max(1)
}

/// 周期网格偏移（`interval * k`；饱和算术，§14.4 禁止回绕；k 超出 u32
/// 乘法范围时饱和——正常路径不可达，投递队列上限约束每轮处理量）。
fn grid_offset(interval: Duration, k: u64) -> Duration {
    let factor = u32::try_from(k).unwrap_or(u32::MAX);
    Duration::from_std(interval.as_std().saturating_mul(factor))
}

/// driver 循环（每安装实例一个）：计算最早下次 fire → select{取消令牌、
/// wake、时钟 sleep} → 处理到期网格点。
///
/// 退出路径（取消令牌）：移除自身 driver 句柄；drop 投递 sender →
/// consumer 排空后退出（已接受工作完成；停机不补投）。
async fn run_driver(
    inner: Arc<Inner>,
    installation: InstallationId,
    mut wake_rx: watch::Receiver<u64>,
    token: CancellationToken,
    delivery_tx: mpsc::Sender<TriggerPayload>,
) {
    loop {
        // 最早下次 fire 时刻（共享状态，短临界区）。
        let next_fire = {
            let guard = inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard
                .installs
                .get(&installation)
                .and_then(|install| earliest_next_fire(&install.tasks))
        };
        let Some(next_fire) = next_fire else {
            // 无任务：只等取消或唤醒（schedule 后重新扫描）。
            tokio::select! {
                _ = token.cancelled() => break,
                changed = wake_rx.changed() => { let _ = changed; }
            }
            continue;
        };
        let now = match inner.clock.now() {
            Ok(now) => now,
            // 时钟失败：无法判定 fire 时刻——防御性退出（不再产生 fire；
            // 任务保留在表中，后续 schedule 会重新派生 driver）。
            Err(_) => break,
        };
        if next_fire <= now {
            fire_due(&inner, installation, &delivery_tx);
            continue;
        }
        let delay = duration_between(now, next_fire);
        tokio::select! {
            _ = token.cancelled() => break,
            changed = wake_rx.changed() => { let _ = changed; }
            _ = inner.clock.sleep(delay) => {
                fire_due(&inner, installation, &delivery_tx);
            }
        }
    }
    // 退出路径。
    drop(delivery_tx);
    let mut guard = inner
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(install) = guard.installs.get_mut(&installation) {
        install.driver = None;
    }
}

/// 投递 consumer（有界队列的另一端）：Core-mediated push 同步调用 guest
/// handler；返回即已消费，trap 视为已消费，不重投（at-most-once）。
async fn run_consumer(
    delivery: Arc<dyn SchedulerDeliveryPort>,
    mut rx: mpsc::Receiver<TriggerPayload>,
) {
    while let Some(payload) = rx.recv().await {
        // handler trap/运行时失败：已消费语义，不重投（handler.wit）；
        // 错误只用于宿主侧观测（交付 port 的 typed 面）。
        let _ = delivery.on_trigger(payload);
    }
}

/// 处理当前时刻到期的全部网格点（锁内执行；try_send 非阻塞）。
///
/// 每个到期网格点（一次性 1 个；周期 k_max 个）要么交付一次、要么计入
/// 错过（scheduler.wit）：投递队列溢出 → `missed_fires` 递增，随下一次
/// 成功交付可见；交付成功 → 计数复位（载荷已携带）。
fn fire_due(
    inner: &Inner,
    installation: InstallationId,
    delivery_tx: &mpsc::Sender<TriggerPayload>,
) {
    let now = match inner.clock.now() {
        Ok(now) => now,
        Err(_) => return,
    };
    let mut guard = inner
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(install) = guard.installs.get_mut(&installation) else {
        return;
    };
    if install.stopped {
        return;
    }
    for (task_id, task) in install.tasks.iter_mut() {
        if task.state != TaskState::Scheduled {
            continue;
        }
        let Some(next) = task.next_fire_at else {
            continue;
        };
        if next > now {
            continue;
        }
        match task.trigger {
            ScheduleTrigger::OneShot { .. } => {
                let payload = TriggerPayload::new(*task_id, task.sequence, next, task.missed_fires);
                task.sequence = task.sequence.saturating_add(1);
                task.state = TaskState::Completed;
                task.next_fire_at = None;
                match delivery_tx.try_send(payload) {
                    Ok(()) => {
                        // 交付成功：计数复位（载荷已携带此前的错过数）。
                        task.missed_fires = 0;
                    }
                    // 队列溢出 / 通道关闭：本次 fire 计入错过（一次性全
                    // 错过 → missed-fires = 1，WIT）。
                    Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                        task.missed_fires = task.missed_fires.saturating_add(1);
                    }
                }
            }
            ScheduleTrigger::Periodic { interval, .. } => {
                let k_max = due_grid_points(next, now, interval);
                let mut k = 0u64;
                while k < k_max {
                    let scheduled_at = match next.checked_add(grid_offset(interval, k)) {
                        Ok(instant) => instant,
                        // 网格超出表示范围：防御性结束（正常路径不可达）。
                        Err(_) => break,
                    };
                    let payload = TriggerPayload::new(
                        *task_id,
                        task.sequence.saturating_add(k),
                        scheduled_at,
                        task.missed_fires,
                    );
                    match delivery_tx.try_send(payload) {
                        Ok(()) => {
                            // 交付成功：复位（本次载荷已携带此前错过数）。
                            task.missed_fires = 0;
                            k += 1;
                        }
                        // 队列溢出：剩余全部网格点都计为错过（队列已满，
                        // 后续 try_send 必失败）——O(1) 批量跳过。
                        Err(TrySendError::Full(_)) | Err(TrySendError::Closed(_)) => {
                            task.missed_fires =
                                task.missed_fires.saturating_add(k_max.saturating_sub(k));
                            k = k_max;
                        }
                    }
                }
                task.sequence = task.sequence.saturating_add(k_max);
                match next.checked_add(grid_offset(interval, k_max)) {
                    Ok(next_fire_at) => task.next_fire_at = Some(next_fire_at),
                    // 网格超出表示范围：结束任务（防御面；正常路径不可达）。
                    Err(_) => {
                        task.state = TaskState::Completed;
                        task.next_fire_at = None;
                    }
                }
            }
        }
    }
}

/// 任务表的最早下次 fire 时刻。
fn earliest_next_fire(tasks: &BTreeMap<ScheduledTaskId, TaskEntry>) -> Option<UtcInstant> {
    tasks
        .values()
        .filter(|task| task.state == TaskState::Scheduled)
        .filter_map(|task| task.next_fire_at)
        .min()
}

/// 任务表中处于 Scheduled 状态的任务数（§7.4 后台任务数量的计数口径：
/// 已取消/已结束任务不再占用调度资源）。
fn scheduled_count(tasks: &BTreeMap<ScheduledTaskId, TaskEntry>) -> usize {
    tasks
        .values()
        .filter(|task| task.state == TaskState::Scheduled)
        .count()
}

/// 两个 UTC 时刻之间的间隔（`to >= from`；防御性饱和为零）。
fn duration_between(from: UtcInstant, to: UtcInstant) -> Duration {
    let elapsed = to.as_offset_date_time() - from.as_offset_date_time();
    match std::time::Duration::try_from(elapsed) {
        Ok(duration) => Duration::from_std(duration),
        // 防御：负差值（调用方保证 to >= from）饱和为零——立即重试。
        Err(_) => Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::clock::ClockError;
    use crate::ports::InProcessSchedulerGrant;
    use crate::test_support::{FakeTriggerDelivery, PausedClock, err, installation, ok};

    /// 测试装配：确定性时钟（tokio paused-time 锁步）+ 记录交付。
    struct Harness {
        service: SchedulerService,
        grants: Arc<InProcessSchedulerGrant>,
        delivery: Arc<FakeTriggerDelivery>,
        limits: SchedulerLimits,
    }

    fn harness(limits: SchedulerLimits) -> Harness {
        harness_with_clock(limits, 1_752_000_000)
    }

    fn harness_with_clock(limits: SchedulerLimits, start_utc: u64) -> Harness {
        let grants = Arc::new(InProcessSchedulerGrant::new());
        let delivery = Arc::new(FakeTriggerDelivery::new());
        let clock = Arc::new(PausedClock::new(utc(start_utc)));
        let service = SchedulerService::new(
            Arc::clone(&grants) as Arc<dyn SchedulerGrantPort>,
            Arc::clone(&delivery) as Arc<dyn SchedulerDeliveryPort>,
            Arc::clone(&clock) as Arc<dyn Clock>,
            limits,
        );
        Harness {
            service,
            grants,
            delivery,
            limits,
        }
    }

    fn utc(seconds: u64) -> UtcInstant {
        ok(UtcInstant::from_unix_parts(seconds, 0), "utc instant")
    }

    fn install(h: &Harness, seed: u64) -> InstallationId {
        let installation = installation(seed);
        h.grants.grant(installation);
        installation
    }

    fn default_limits() -> SchedulerLimits {
        SchedulerLimits {
            max_tasks_per_installation: 4,
            max_total_tasks: 8,
            delivery_queue_capacity: 16,
            min_periodic_interval: Duration::from_millis(1),
        }
    }

    /// 队列容量 1 的测试形态（背压/错过场景）。
    fn tight_limits() -> SchedulerLimits {
        SchedulerLimits {
            delivery_queue_capacity: 1,
            ..default_limits()
        }
    }

    /// 向前推进 paused-time（毫秒）并让 driver/consumer 任务得到轮询。
    async fn advance_ms(millis: u64) {
        tokio::time::advance(StdDuration::from_millis(millis)).await;
        // paused-time 下任务只在被 poll 时推进；advance 已唤醒相关任务，
        // yield 一次保证 driver（fire_due）与 consumer（交付）完成处理。
        tokio::task::yield_now().await;
    }

    fn status(h: &Harness, inst: InstallationId, task: ScheduledTaskId) -> TaskStatus {
        ok(h.service.task_status(inst, task), "task status")
    }

    // ------------------------------------------------------------------
    // 一次性触发
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn one_shot_fires_once_at_target_moment() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service
                .schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_010))),
            "schedule",
        );
        assert_eq!(task.as_u64(), 1);

        advance_ms(9_000).await;
        assert!(h.delivery.delivered().is_empty());

        advance_ms(1_000).await;
        let delivered = h.delivery.delivered();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].task_id(), task);
        assert_eq!(delivered[0].sequence(), 1);
        assert_eq!(delivered[0].scheduled_at(), utc(1_752_000_010));
        assert_eq!(delivered[0].missed_fires(), 0);

        // 一次性：触发后状态为 completed，不再产生 fire。
        assert_eq!(
            status(&h, inst, task),
            TaskStatus::new(TaskState::Completed, 0, None)
        );
        advance_ms(60_000).await;
        assert_eq!(h.delivery.delivered().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn one_shot_in_the_past_is_invalid_trigger() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let error = err(
            h.service
                .schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_000))),
            "schedule",
        );
        assert!(matches!(error, SchedulerError::InvalidTrigger(_)));
        assert_eq!(h.service.task_count(inst), 0);
    }

    // ------------------------------------------------------------------
    // 周期触发
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn periodic_fires_on_grid_with_increasing_sequence() {
        // 队列容量 16（默认）≥ 单轮处理量：即使 driver 单轮批量处理多个
        // 到期网格点，全部 fire 也交付成功（错过只源于队列溢出）。
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(10)),
            ),
            "schedule",
        );
        advance_ms(10_000).await;
        advance_ms(10_000).await;
        advance_ms(10_000).await;
        let delivered = h.delivery.delivered();
        assert_eq!(delivered.len(), 3);
        assert_eq!(
            delivered.iter().map(|p| p.sequence()).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        assert_eq!(
            delivered
                .iter()
                .map(|p| p.scheduled_at())
                .collect::<Vec<_>>(),
            vec![utc(1_752_000_010), utc(1_752_000_020), utc(1_752_000_030),]
        );
        assert_eq!(
            delivered
                .iter()
                .map(|p| p.missed_fires())
                .collect::<Vec<_>>(),
            vec![0, 0, 0]
        );
        // 状态仍为 scheduled，下次 fire 继续推进。
        assert_eq!(
            status(&h, inst, task),
            TaskStatus::new(TaskState::Scheduled, 0, Some(utc(1_752_000_040)))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_interval_below_floor_is_invalid_trigger() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let error = err(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::ZERO),
            ),
            "schedule",
        );
        assert!(matches!(error, SchedulerError::InvalidTrigger(_)));
        let error = err(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(
                    utc(1_752_000_010),
                    h.limits
                        .min_periodic_interval
                        .saturating_sub(Duration::from_millis(1)),
                ),
            ),
            "schedule below floor",
        );
        assert!(matches!(error, SchedulerError::InvalidTrigger(_)));
        // 恰好等于下限合法。
        assert!(
            h.service
                .schedule(
                    inst,
                    ScheduleTrigger::periodic(utc(1_752_000_010), h.limits.min_periodic_interval,),
                )
                .is_ok()
        );
    }

    // ------------------------------------------------------------------
    // missed-fires（交付队列溢出 → 计入错过，随下一次成功交付可见）
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn queue_overflow_fires_are_counted_as_missed() {
        // 队列容量 1：两个任务同一时刻到期 → 同一处理轮内第一个入队
        // 成功，第二个溢出 → 计入错过（确定性背压，无需慢 consumer）。
        let h = harness(tight_limits());
        let inst = install(&h, 1);
        let task_a = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule a",
        );
        let task_b = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule b",
        );
        advance_ms(10_000).await;
        assert_eq!(
            status(&h, inst, task_a),
            TaskStatus::new(TaskState::Scheduled, 0, Some(utc(1_752_000_070)))
        );
        assert_eq!(
            status(&h, inst, task_b),
            TaskStatus::new(TaskState::Scheduled, 1, Some(utc(1_752_000_070)))
        );
        // 取消 A（其 fire 已交付，队列不再被占用）。
        ok(h.service.cancel(inst, task_a), "cancel a");
        // 下一次 fire（队列已空）：B 的载荷携带 missed-fires = 1，序号 2。
        advance_ms(60_000).await;
        let b_payloads: Vec<TriggerPayload> = h
            .delivery
            .delivered()
            .into_iter()
            .filter(|payload| payload.task_id() == task_b)
            .collect();
        assert_eq!(b_payloads.len(), 1);
        assert_eq!(b_payloads[0].sequence(), 2);
        assert_eq!(b_payloads[0].missed_fires(), 1);
        // 交付成功后计数复位。
        assert_eq!(
            status(&h, inst, task_b),
            TaskStatus::new(TaskState::Scheduled, 0, Some(utc(1_752_000_130)))
        );
    }

    // ------------------------------------------------------------------
    // cancel 竞态与 not-found
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn cancel_stops_new_fires_and_unknown_is_not_found() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(10)),
            ),
            "schedule",
        );
        ok(h.service.cancel(inst, task), "cancel");
        assert_eq!(
            status(&h, inst, task),
            TaskStatus::new(TaskState::Cancelled, 0, None)
        );
        // 取消后不再产生 fire（推进多个周期）。
        advance_ms(60_000).await;
        assert!(h.delivery.delivered().is_empty());
        // 重复 cancel：已取消 → not-found（WIT）。
        assert!(matches!(
            h.service.cancel(inst, task),
            Err(SchedulerError::NotFound)
        ));
        // 未知任务 → not-found。
        assert!(matches!(
            h.service.cancel(inst, ScheduledTaskId::from_u64(999)),
            Err(SchedulerError::NotFound)
        ));
        assert!(matches!(
            h.service.task_status(inst, ScheduledTaskId::from_u64(999)),
            Err(SchedulerError::NotFound)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_after_fire_returns_not_found_for_one_shot() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service
                .schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_010))),
            "schedule",
        );
        advance_ms(10_000).await;
        assert_eq!(h.delivery.delivered().len(), 1);
        // 已触发的一次性任务：cancel → not-found（WIT）。
        assert!(matches!(
            h.service.cancel(inst, task),
            Err(SchedulerError::NotFound)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_race_in_flight_fire_may_still_arrive() {
        // 竞态语义（scheduler.wit）：cancel 返回 ok 后不再产生新 fire，
        // 但已在途的一次 fire 仍可能先到（线性化点；guest 用 sequence
        // 幂等）。此处的确定性形态：fire 已入队（在途），cancel 返回 ok；
        // 断言：至多一次交付（在途 fire 到达），此后无新 fire。
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(10)),
            ),
            "schedule",
        );
        // fire 到期并入队（在途）。
        advance_ms(10_000).await;
        ok(h.service.cancel(inst, task), "cancel");
        // 推进更多周期：无新 fire（至多保留在途的一次）。
        advance_ms(60_000).await;
        let delivered = h.delivery.delivered();
        assert!(
            delivered.len() <= 1,
            "at most one in-flight fire may arrive"
        );
        assert!(
            delivered
                .iter()
                .all(|payload| payload.task_id() == task && payload.sequence() == 1),
            "guest dedup by sequence: no sequence re-delivery"
        );
    }

    // ------------------------------------------------------------------
    // 上限（有界，§7.4/§15.2）
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn per_installation_task_limit_rejects_over_budget() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        for _ in 0..4 {
            ok(
                h.service.schedule(
                    inst,
                    ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
                ),
                "schedule within limit",
            );
        }
        let error = err(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule over per-installation limit",
        );
        assert!(matches!(error, SchedulerError::OverBudget));
        assert_eq!(h.service.task_count(inst), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn global_task_limit_rejects_over_budget() {
        let limits = SchedulerLimits {
            max_tasks_per_installation: 8,
            max_total_tasks: 2,
            ..default_limits()
        };
        let h = harness(limits);
        let inst_a = install(&h, 1);
        let inst_b = install(&h, 2);
        ok(
            h.service.schedule(
                inst_a,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule a1",
        );
        ok(
            h.service.schedule(
                inst_a,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule a2",
        );
        let error = err(
            h.service.schedule(
                inst_b,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule over global limit",
        );
        assert!(matches!(error, SchedulerError::OverBudget));
        // cancel 释放名额。
        ok(
            h.service.cancel(inst_a, ScheduledTaskId::from_u64(1)),
            "cancel 1",
        );
        ok(
            h.service.schedule(
                inst_b,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule after cancel",
        );
    }

    // ------------------------------------------------------------------
    // 停机：不补投、不再调度
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn stop_prevents_new_fires_and_no_catch_up() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(10)),
            ),
            "schedule",
        );
        // 第一次 fire 已投递。
        advance_ms(10_000).await;
        assert_eq!(h.delivery.delivered().len(), 1);
        ok(h.service.stop(inst), "stop");
        // 停机错过不补投：推进多个周期，无新 fire、无 catch-up 回放。
        advance_ms(120_000).await;
        assert_eq!(h.delivery.delivered().len(), 1);
        assert!(h.service.is_stopped(inst));
        // 停机后不再调度新任务（not-ready）。
        let error = err(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_200), Duration::from_secs(60)),
            ),
            "schedule after stop",
        );
        assert!(matches!(error, SchedulerError::NotReady));
        let error = err(
            h.service.cancel(inst, ScheduledTaskId::from_u64(1)),
            "cancel after stop",
        );
        assert!(matches!(error, SchedulerError::NotReady));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_is_idempotent_and_noop_for_unused_installations() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        ok(h.service.stop(inst), "stop unused installation");
        assert!(h.service.is_stopped(inst));
        ok(h.service.stop(inst), "stop again (idempotent)");
    }

    // ------------------------------------------------------------------
    // 授权与运行时上下文
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn schedule_without_grant_is_denied() {
        let h = harness(default_limits());
        // 未授予 scheduler 能力（deny-by-default，§17.2）。
        let inst = installation(9);
        let error = err(
            h.service
                .schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_010))),
            "schedule",
        );
        assert!(matches!(error, SchedulerError::Denied));
        assert_eq!(h.service.task_count(inst), 0);
    }

    #[test]
    fn schedule_outside_runtime_context_is_not_ready() {
        // 无 tokio runtime 上下文：无法派生 driver → not-ready，且不产生
        // 任何状态变化。
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let error = err(
            h.service
                .schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_010))),
            "schedule",
        );
        assert!(matches!(error, SchedulerError::NotReady));
        assert_eq!(h.service.task_count(inst), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn clock_error_maps_to_internal() {
        struct BrokenClock;
        impl Clock for BrokenClock {
            fn now(&self) -> Result<UtcInstant, ClockError> {
                Err(ClockError::OutOfRange)
            }
            fn sleep(
                &self,
                _: Duration,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
                Box::pin(std::future::pending())
            }
        }
        let grants = Arc::new(InProcessSchedulerGrant::new());
        let delivery = Arc::new(FakeTriggerDelivery::new());
        let service = SchedulerService::new(
            Arc::clone(&grants) as Arc<dyn SchedulerGrantPort>,
            Arc::clone(&delivery) as Arc<dyn SchedulerDeliveryPort>,
            Arc::new(BrokenClock) as Arc<dyn Clock>,
            default_limits(),
        );
        let inst = installation(1);
        grants.grant(inst);
        let error = err(
            service.schedule(inst, ScheduleTrigger::one_shot(utc(1_752_000_010))),
            "schedule",
        );
        assert!(matches!(error, SchedulerError::Internal(_)));
    }

    // ------------------------------------------------------------------
    // 状态查询
    // ------------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn task_status_reflects_state_and_missed() {
        let h = harness(default_limits());
        let inst = install(&h, 1);
        let task = ok(
            h.service.schedule(
                inst,
                ScheduleTrigger::periodic(utc(1_752_000_010), Duration::from_secs(60)),
            ),
            "schedule",
        );
        assert_eq!(
            status(&h, inst, task),
            TaskStatus::new(TaskState::Scheduled, 0, Some(utc(1_752_000_010)))
        );
        // 未使用过 scheduler 的安装：not-found（无状态）。
        assert!(matches!(
            h.service.task_status(installation(42), task),
            Err(SchedulerError::NotFound)
        ));
    }

    // ------------------------------------------------------------------
    // 纯函数：到期网格点与时刻换算
    // ------------------------------------------------------------------

    #[test]
    fn due_grid_points_counts_due_grid_members() {
        let next = utc(100);
        assert_eq!(due_grid_points(next, utc(100), Duration::from_secs(10)), 1);
        assert_eq!(due_grid_points(next, utc(109), Duration::from_secs(10)), 1);
        assert_eq!(due_grid_points(next, utc(110), Duration::from_secs(10)), 2);
        assert_eq!(due_grid_points(next, utc(130), Duration::from_secs(10)), 4);
        // interval 0 防御面。
        assert_eq!(due_grid_points(next, utc(200), Duration::ZERO), 1);
        // now < next（调用方保证）防御面。
        assert_eq!(due_grid_points(next, utc(90), Duration::from_secs(10)), 1);
    }

    #[test]
    fn grid_offset_saturates() {
        assert_eq!(
            grid_offset(Duration::from_secs(10), 3),
            Duration::from_secs(30)
        );
        // k 超出 u32 乘法范围：饱和（防御面）。
        let _ = grid_offset(Duration::from_secs(10), u64::MAX);
    }

    #[test]
    fn duration_between_is_forward_and_saturates() {
        assert_eq!(
            duration_between(utc(100), utc(110)),
            Duration::from_secs(10)
        );
        // 反向（防御面）：饱和为零。
        assert_eq!(duration_between(utc(110), utc(100)), Duration::ZERO);
    }
}
