//! 有界 Instance Set（§7.3）。

use std::sync::{Condvar, Mutex, MutexGuard};

use crate::budget::ResourceBudget;
use crate::engine::EngineHandle;
use crate::error::RuntimeError;
use crate::store::{StoreFactory, StoreHandle};
use crate::wasi::{WasiAdapter, WasiPolicy};

/// 实例调度错误（§7.4：并发/排队超限 → 确定拒绝或等待被拒）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DispatchError {
    /// 全部槽位繁忙（达到最大并发）：`try_dispatch` 的非阻塞拒绝。
    #[error("all instance slots are busy (max concurrency reached)")]
    Busy,
    /// 等待队列已满（达到最大排队）：`dispatch` 拒绝入队。
    #[error("dispatch queue is full (max queued reached)")]
    QueueFull,
    /// Instance Set 已关闭（drain 语义：不再接收新工作，§20.4）。
    #[error("instance set is closed; new dispatch rejected")]
    Closed,
    /// 内部状态损坏（互斥锁中毒）：按系统故障处理（fail-stop 语义）。
    #[error("instance set internal state corrupted")]
    Corrupted,
}

struct SlotState {
    busy: bool,
}

struct SetState {
    slots: Vec<SlotState>,
    waiting: usize,
    closed: bool,
}

/// 有界 Instance Set（§7.3）：一个 Active ComponentVersion 的运行实例集合。
///
/// 语义（§7.3）：
/// - **单一 owner**：本类型不实现 `Clone`，集合整体被一个调用方持有；
/// - **任一时刻单执行**：每个槽位通过 [`InstanceLease`] 独占，同一槽位同时
///   只执行一个进入该实例的调用；`with_store` 期间只锁定本槽位，其他槽位
///   可并发执行；
/// - **有界 dispatch**：最大并发 = 槽位数 = `budget.max_concurrent`；
///   `try_dispatch` 非阻塞（繁忙即 [`DispatchError::Busy`]）；`dispatch`
///   阻塞排队（入队上限 `budget.max_queued`，满则 [`DispatchError::QueueFull`]）；
/// - **实例化策略 OnDemand**（§7.3/§22.9）：配置见 [`crate::engine::EngineHandle`]；
/// - **stateless contract（0.1.0）**：不承诺跨调用 instance affinity；调用者
///   不得把 linear memory 或实例本地变量当作下一次调用仍存在的事实（§7.3）；
/// - **close（drain，§20.4）**：不再接收新工作；已发放的租约运行到结束；
///   Drop 时释放全部 Store 与宿主资源。
///
/// 0.1.0 阶段槽位承载 [`StoreHandle`]；具体 wasmtime 实例的绑定与 typed
/// invoke 属 application/集成阶段（需要 WIT bindgen 与 WASI linker），
/// 经 [`InstanceLease::with_store`] 扩展（衔接点见 PR 报告）。
pub struct InstanceSet {
    stores: Vec<Mutex<StoreHandle>>,
    state: Mutex<SetState>,
    gate: Condvar,
    max_queued: usize,
}

impl InstanceSet {
    /// 创建有界 Instance Set。默认 Store 无任何 WASI 能力（§7.6 deny-by-default）。
    ///
    /// 错误：任一槽位 Store 创建失败 → [`RuntimeError`]（部分创建的 Store
    /// 随本类型丢弃，不泄漏）。
    pub fn new(engine: &EngineHandle, budget: &ResourceBudget) -> Result<Self, RuntimeError> {
        Self::build(engine, budget, None)
    }

    /// 创建有界 Instance Set，并按 policy 显式附加 WASI 能力（§7.6/§17.2）。
    ///
    /// 错误：[`RuntimeError::Wasi`]（版本不一致或能力附加失败，fail closed）
    /// 或 [`RuntimeError`]（Store 创建失败）。
    pub fn new_with_wasi(
        engine: &EngineHandle,
        budget: &ResourceBudget,
        adapter: &dyn WasiAdapter,
        policy: &WasiPolicy,
    ) -> Result<Self, RuntimeError> {
        let factory =
            StoreFactory::with_wasi(engine, adapter, policy).map_err(RuntimeError::Wasi)?;
        Self::build(engine, budget, Some(factory))
    }

    fn build(
        engine: &EngineHandle,
        budget: &ResourceBudget,
        factory: Option<StoreFactory<'_>>,
    ) -> Result<Self, RuntimeError> {
        let capacity = budget.max_concurrent.get().get();
        let factory = match factory {
            Some(factory) => factory,
            None => StoreFactory::new(engine),
        };
        let mut stores = Vec::with_capacity(capacity);
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            stores.push(Mutex::new(factory.new_store(budget)?));
            slots.push(SlotState { busy: false });
        }
        Ok(Self {
            stores,
            state: Mutex::new(SetState {
                slots,
                waiting: 0,
                closed: false,
            }),
            gate: Condvar::new(),
            max_queued: budget.max_queued.get().get(),
        })
    }

    /// 槽位数（= 最大并发，§7.4）。
    pub fn capacity(&self) -> usize {
        self.stores.len()
    }

    /// 非阻塞获取一个槽位（§7.4：并发超限 → 确定拒绝 [`DispatchError::Busy`]）。
    ///
    /// 返回的租约 Drop 时自动释放槽位。
    pub fn try_dispatch(&self) -> Result<InstanceLease<'_>, DispatchError> {
        let mut state = self.lock_state()?;
        if state.closed {
            return Err(DispatchError::Closed);
        }
        let index = first_free_index(&state.slots).ok_or(DispatchError::Busy)?;
        let slot = state.slots.get_mut(index).ok_or(DispatchError::Corrupted)?;
        slot.busy = true;
        Ok(InstanceLease {
            set: self,
            slot: index,
        })
    }

    /// 阻塞获取一个槽位：繁忙时排队等待（入队上限 `budget.max_queued`，
    /// 满则 [`DispatchError::QueueFull`]；§7.4 确定拒绝）。
    ///
    /// 等待期间不持有任何槽位锁；集合关闭（[`InstanceSet::close`]）时
    /// 等待者以 [`DispatchError::Closed`] 返回（drain，§20.4）。
    /// 注意：本调用阻塞调用线程；异步调用方应在未来里程碑改用
    /// tokio 有界信号量等价物（§15.2）驱动同一语义。
    pub fn dispatch(&self) -> Result<InstanceLease<'_>, DispatchError> {
        loop {
            let mut state = self.lock_state()?;
            if state.closed {
                return Err(DispatchError::Closed);
            }
            if let Some(index) = first_free_index(&state.slots) {
                let slot = state.slots.get_mut(index).ok_or(DispatchError::Corrupted)?;
                slot.busy = true;
                return Ok(InstanceLease {
                    set: self,
                    slot: index,
                });
            }
            if state.waiting >= self.max_queued {
                return Err(DispatchError::QueueFull);
            }
            state.waiting += 1;
            state = self
                .gate
                .wait(state)
                .map_err(|_| DispatchError::Corrupted)?;
            state.waiting -= 1;
        }
    }

    /// 当前排队等待的 dispatch 数（诊断/测试探针；0.1.0 由测试消费，
    /// lib-only 构建下允许 dead_code）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn waiting(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.waiting,
            Err(_) => 0,
        }
    }

    /// 关闭集合（drain，§20.4）：不再接收新工作；已发放租约继续运行到结束。
    /// 幂等；关闭后所有新 dispatch 以 [`DispatchError::Closed`] 拒绝。
    pub fn close(&self) -> Result<(), DispatchError> {
        let mut state = self.lock_state()?;
        state.closed = true;
        self.gate.notify_all();
        Ok(())
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, SetState>, DispatchError> {
        self.state.lock().map_err(|_| DispatchError::Corrupted)
    }

    fn release(&self, slot: usize) {
        // Drop 路径：互斥锁中毒时放弃更新（集合已不可用，fail-stop 语义）。
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some(slot_state) = state.slots.get_mut(slot) {
            slot_state.busy = false;
        }
        self.gate.notify_one();
    }
}

fn first_free_index(slots: &[SlotState]) -> Option<usize> {
    slots.iter().position(|slot| !slot.busy)
}

/// 独占槽位租约（§7.3：任一时刻单执行；RAII——Drop 释放槽位并唤醒等待者）。
///
/// 0.1.0 stateless contract（§7.3）：租约不承诺跨调用 instance affinity；
/// 调用者不得把 linear memory 或实例本地变量当作下一次调用仍存在的事实。
pub struct InstanceLease<'a> {
    set: &'a InstanceSet,
    slot: usize,
}

impl<'a> InstanceLease<'a> {
    /// 独占访问本槽位的 Store（执行窗口：期间只锁定本槽位，其他槽位可并发）。
    ///
    /// 错误：槽位无效或锁损坏 → [`RuntimeError::Internal`]（不变量破坏）。
    pub fn with_store<R>(
        &mut self,
        f: impl FnOnce(&mut StoreHandle) -> R,
    ) -> Result<R, RuntimeError> {
        let slot_mutex = self
            .set
            .stores
            .get(self.slot)
            .ok_or_else(|| RuntimeError::Internal("instance lease refers to invalid slot"))?;
        let mut store = slot_mutex
            .lock()
            .map_err(|_| RuntimeError::Internal("instance slot store mutex poisoned"))?;
        Ok(f(&mut store))
    }

    /// §7.5：为本次不可信执行设置 epoch deadline。
    ///
    /// 错误：见 [`StoreHandle::set_deadline`]。
    pub fn set_deadline(
        &mut self,
        deadline: crate::budget::CallDeadline,
    ) -> Result<(), RuntimeError> {
        match self.with_store(|store| store.set_deadline(deadline)) {
            Ok(inner) => inner,
            Err(outer) => Err(outer),
        }
    }

    /// 清除本次执行的 deadline（等效“无期限”；仅显式策略允许时使用）。
    pub fn reset_deadline(&mut self) -> Result<(), RuntimeError> {
        match self.with_store(|store| store.reset_deadline()) {
            Ok(inner) => inner,
            Err(outer) => Err(outer),
        }
    }

    /// 本租约占用的槽位下标（诊断用；0.1.0 不承诺 affinity）。
    pub fn slot(&self) -> usize {
        self.slot
    }
}

impl Drop for InstanceLease<'_> {
    fn drop(&mut self) {
        self.set.release(self.slot);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{MaxConcurrent, MaxQueued};
    use crate::test_support::{engine, expect_some, test_failure};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn budget_with(capacity: usize, queued: usize) -> ResourceBudget {
        ResourceBudget {
            max_concurrent: expect_some(MaxConcurrent::try_new(capacity), "max concurrent"),
            max_queued: expect_some(MaxQueued::try_new(queued), "max queued"),
            ..ResourceBudget::default()
        }
    }

    #[test]
    fn lease_is_exclusive_per_slot_and_released_on_drop() {
        // §7.3：同一槽位任一时刻单执行；Drop 后槽位可再次调度。
        let engine = engine();
        let set = match InstanceSet::new(&engine, &budget_with(1, 1)) {
            Ok(set) => set,
            Err(e) => test_failure(format_args!("instance set creation failed: {e}")),
        };
        assert_eq!(set.capacity(), 1);

        let lease = match set.try_dispatch() {
            Ok(lease) => lease,
            Err(e) => test_failure(format_args!("first dispatch failed: {e}")),
        };
        // 槽位被独占：第二次非阻塞调度必须被拒绝。
        match set.try_dispatch() {
            Ok(_) => test_failure("second dispatch must be rejected while slot is busy"),
            Err(e) => assert_eq!(e, DispatchError::Busy),
        }
        drop(lease);
        // Drop 释放后再次调度成功。
        match set.try_dispatch() {
            Ok(lease) => drop(lease),
            Err(e) => test_failure(format_args!("dispatch after release failed: {e}")),
        }
    }

    #[test]
    fn with_store_grants_exclusive_store_access() {
        // 租约提供对槽位 Store 的独占访问（§7.3 执行窗口）。
        let engine = engine();
        let set = match InstanceSet::new(&engine, &budget_with(1, 1)) {
            Ok(set) => set,
            Err(e) => test_failure(format_args!("instance set creation failed: {e}")),
        };
        let mut lease = match set.try_dispatch() {
            Ok(lease) => lease,
            Err(e) => test_failure(format_args!("dispatch failed: {e}")),
        };
        let deadline_ok =
            lease.set_deadline(crate::budget::CallDeadline::new(Duration::from_secs(1)));
        assert!(deadline_ok.is_ok());
        let reset_ok = lease.reset_deadline();
        assert!(reset_ok.is_ok());
        let slot = lease.slot();
        assert_eq!(slot, 0);
    }

    #[test]
    fn dispatch_queues_up_to_max_and_rejects_overflow() {
        // §7.4：排队有界——超过 max_queued 的等待者被确定拒绝（QueueFull）。
        let engine = engine();
        let set = match InstanceSet::new(&engine, &budget_with(1, 1)) {
            Ok(set) => set,
            Err(e) => test_failure(format_args!("instance set creation failed: {e}")),
        };
        let holder = match set.try_dispatch() {
            Ok(lease) => lease,
            Err(e) => test_failure(format_args!("first dispatch failed: {e}")),
        };

        // 线程 A：进入阻塞排队（等待槽位）。scoped thread 共享 set 借用。
        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(0);
            let (result_tx, result_rx) =
                mpsc::sync_channel::<Result<InstanceLease<'_>, DispatchError>>(0);
            let set_ref = &set;
            scope.spawn(move || {
                ready_tx.send(()).ok();
                let lease = set_ref.dispatch();
                result_tx.send(lease).ok();
            });

            // 等线程 A 开始；随后轮询等待其实际入队（waiting == 1），
            // 保证后续断言时序确定（避免“主线程先入队”竞态）。
            match ready_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(()) => {}
                Err(_) => test_failure("thread A did not start"),
            }
            let poll_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if set.waiting() == 1 {
                    break;
                }
                if Instant::now() >= poll_deadline {
                    test_failure("thread A did not queue within deadline");
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            // 排队上限已满（holder 占用 1 槽，A 排队 1）→ 新调度者被确定拒绝。
            match set.try_dispatch() {
                Ok(_) => test_failure("dispatch must be rejected when queue is full"),
                Err(e) => assert_eq!(e, DispatchError::Busy, "slot busy takes precedence"),
            }
            match set.dispatch() {
                Ok(_) => test_failure("third dispatch must be rejected when queue is full"),
                Err(e) => assert_eq!(e, DispatchError::QueueFull),
            }

            // 释放 holder → A 获得租约。
            drop(holder);
            let lease_result = match result_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(result) => result,
                Err(_) => test_failure("thread A did not acquire the slot"),
            };
            match lease_result {
                Ok(_) => {}
                Err(e) => test_failure(format_args!("queued dispatch failed: {e}")),
            }
        });
    }

    #[test]
    fn close_rejects_new_dispatch_and_wakes_waiters() {
        // §20.4 drain：关闭后不接新工作；等待者以 Closed 返回。
        let engine = engine();
        let set = match InstanceSet::new(&engine, &budget_with(1, 1)) {
            Ok(set) => set,
            Err(e) => test_failure(format_args!("instance set creation failed: {e}")),
        };
        let holder = match set.try_dispatch() {
            Ok(lease) => lease,
            Err(e) => test_failure(format_args!("first dispatch failed: {e}")),
        };

        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(0);
            let (result_tx, result_rx) =
                mpsc::sync_channel::<Result<InstanceLease<'_>, DispatchError>>(0);
            let set_ref = &set;
            scope.spawn(move || {
                ready_tx.send(()).ok();
                let lease = set_ref.dispatch();
                result_tx.send(lease).ok();
            });
            match ready_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(()) => {}
                Err(_) => test_failure("thread A did not start"),
            }

            // 关闭：新 dispatch 拒绝；等待者被唤醒并以 Closed 返回。
            match set.close() {
                Ok(()) => {}
                Err(e) => test_failure(format_args!("close failed: {e}")),
            }
            match set.try_dispatch() {
                Ok(_) => test_failure("dispatch after close must be rejected"),
                Err(e) => assert_eq!(e, DispatchError::Closed),
            }
            let lease_result = match result_rx.recv_timeout(Duration::from_secs(5)) {
                Ok(result) => result,
                Err(_) => test_failure("waiter was not woken by close"),
            };
            match lease_result {
                Ok(_) => test_failure("waiting dispatch after close must fail"),
                Err(e) => assert_eq!(e, DispatchError::Closed),
            }
            drop(holder);
        });
    }

    #[test]
    fn stateless_contract_means_lease_reuse_without_affinity() {
        // §7.3 0.1.0 stateless contract：同一 InstanceSet 多次调度租约，
        // 每次租约都是全新独占窗口（不承诺 affinity 是文档承诺，不是代码行为）。
        let engine = engine();
        let set = match InstanceSet::new(&engine, &budget_with(2, 2)) {
            Ok(set) => set,
            Err(e) => test_failure(format_args!("instance set creation failed: {e}")),
        };
        let mut seen_slots = std::collections::HashSet::new();
        for _ in 0..6 {
            let mut lease = match set.try_dispatch() {
                Ok(lease) => lease,
                Err(e) => test_failure(format_args!("dispatch failed: {e}")),
            };
            let deadline_ok =
                lease.set_deadline(crate::budget::CallDeadline::new(Duration::from_millis(50)));
            assert!(deadline_ok.is_ok());
            seen_slots.insert(lease.slot());
            drop(lease);
        }
        // 槽位可复用：总调度次数可以超过槽位数。
        assert!(seen_slots.len() <= 2);
    }
}
