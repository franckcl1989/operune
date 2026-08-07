//! 0.3.0 Stateful Runtime（§41.2）——graceful lifecycle 编排
//! （ready / drain / stop / checkpoint）。
//!
//! §41.2 MUST：graceful lifecycle (`ready/drain/stop/checkpoint`)。
//! 本服务在**服务层**编排这四个阶段，并与 domain 的
//! [`ComponentLifecycleState`]（§12.2 状态机：`Active → Draining →
//! Disabled`）衔接：
//!
//! - **ready**：安装实例已原子激活（§19.2 末步）、对外服务；编排状态
//!   以 registry（[`ActiveRuntimeRegistry`]）中的 Active 快照条目为事实源
//!   （服务层种子状态，无需扩展 domain 状态机——0.3 不需要新状态变体，
//!   drain 路径由既有 `DrainStarted`/`DrainCompleted` 事件表达）；
//! - **drain**（§20.4）：不接新工作——先停止 scheduler/event 后台任务
//!   （**所有 background task 受 CancellationToken 管理**，§20.4；停机关
//!   闭后不再产生新 fire/新发布），再以**有界 deadline** 排空运行句柄
//!   （[`ActiveRuntime::drain`] 的既有 `InstanceSet::close` 语义 + deadline
//!   到期取消/trap）；在途交付（已入队 fire/事件）作为已接受工作在此窗口
//!   完成；
//! - **stop**：终态（`Draining → Disabled`，§12.2 概念图终点；可经重新
//!   激活回到 `Activating`，§39.2）；
//! - **checkpoint**：stop 前把权威状态 flush 到持久面（§41.2 checkpoint；
//!   [`crate::state::StateService`] 无独立 flush 入口——本服务经
//!   [`crate::ports::CheckpointPort`] 编排，最小入口见该 port 模块文档）。
//!
//! 编排纪律：
//! - 阶段转换经 domain 状态机显式校验（非法转换 → `invalid-transition`，
//!   绝不静默忽略，§12.2）；
//! - **audit fail-closed**（§18.7）：durable audit 先行——`DrainStarted`
//!   /`DrainCompleted` 审计失败则中止编排，不产生任何副作用（复用既有
//!   [`AuditEvent`] 的 drain 事件，与升级管线同模式）；
//! - drain deadline 有界（§20.4）：deadline 来自注入配置（生产装配取
//!   [`RuntimeConfig::drain_deadline`]）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration as StdDuration;

use operune_domain::{
    ComponentLifecycleEvent, ComponentLifecycleState, ContentDigest, InstallationId,
};

use crate::active::ActiveRuntimeRegistry;
use crate::event::EventService;
use crate::ports::{AuditError, AuditEvent, AuditPort, CheckpointError, CheckpointPort};
use crate::scheduler::SchedulerService;

/// graceful lifecycle 编排错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum LifecycleError {
    /// 安装实例不存在（registry 与编排状态都无记录）。
    #[error("installation {0} not found")]
    NotFound(InstallationId),

    /// 实例未就绪（未激活/已停用）。
    #[error("installation {0} is not ready for {1}")]
    NotReady(InstallationId, &'static str),

    /// 阶段转换被状态机拒绝（§12.2 显式校验；如未 drain 直接 stop）。
    #[error("lifecycle transition rejected: {0}")]
    InvalidTransition(#[from] operune_domain::DomainError),

    /// 后台服务停机失败（scheduler/event 的 stop 失败）。
    #[error("background service stop failed: {0}")]
    BackgroundStop(String),

    /// 有界 drain 失败（§20.4；运行时错误）。
    #[error("drain failed: {0}")]
    Drain(#[source] crate::error::RuntimeExecutionError),

    /// checkpoint 失败（fail-stop：不得进入终态）。
    #[error("checkpoint failed: {0}")]
    Checkpoint(#[source] CheckpointError),

    /// audit 失败（§18.7 fail closed：需要 durable audit 的变更不得静默
    /// 继续）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] AuditError),

    /// 内部不变量破坏（视为系统故障，fail-stop 语义，§14.3）。
    #[error("application internal invariant violated: {0}")]
    Internal(&'static str),
}

/// 编排状态：阶段 + 关联 digest（audit 用；begin_drain 时从 registry 快照
/// 固化，避免 registry 交换后 digest 漂移）。
#[derive(Debug, Clone)]
struct InstallationState {
    phase: ComponentLifecycleState,
    digest: ContentDigest,
}

/// graceful lifecycle 编排服务（§41.2 ready/drain/stop/checkpoint）。
///
/// 构造：`registry`/`scheduler`/`event`/`checkpoint`/`audit`/`drain_deadline`
/// 由 composition root 注入（§24.2 端口注入）。
pub struct LifecycleController {
    registry: Arc<ActiveRuntimeRegistry>,
    scheduler: Arc<SchedulerService>,
    event: Arc<EventService>,
    checkpoint: Arc<dyn CheckpointPort>,
    audit: Arc<dyn AuditPort>,
    states: Mutex<BTreeMap<InstallationId, InstallationState>>,
    /// 有界 drain deadline（§20.4；生产装配取 RuntimeConfig.drain_deadline）。
    drain_deadline: StdDuration,
}

impl LifecycleController {
    /// 构造（registry + scheduler/event 后台服务 + checkpoint + audit +
    /// drain deadline；§24.2 端口注入）。
    pub fn new(
        registry: Arc<ActiveRuntimeRegistry>,
        scheduler: Arc<SchedulerService>,
        event: Arc<EventService>,
        checkpoint: Arc<dyn CheckpointPort>,
        audit: Arc<dyn AuditPort>,
        drain_deadline: StdDuration,
    ) -> Self {
        Self {
            registry,
            scheduler,
            event,
            checkpoint,
            audit,
            states: Mutex::new(BTreeMap::new()),
            drain_deadline,
        }
    }

    /// ready：安装实例已原子激活、对外服务（§41.2 ready；§19.2 末步）。
    ///
    /// 以 registry 的 Active 快照条目为事实源：条目存在 → 编排状态进入
    /// Ready（`Active`）；实例已处于 drain/stop 终态 → [`LifecycleError::NotReady`]。
    pub fn ready(&self, installation: InstallationId) -> Result<(), LifecycleError> {
        let entry = self
            .registry
            .get(installation)
            .ok_or(LifecycleError::NotFound(installation))?;
        let mut guard = self.states_lock();
        if let Some(state) = guard.get(&installation) {
            if state.phase != ComponentLifecycleState::Active {
                return Err(LifecycleError::NotReady(installation, "ready"));
            }
            return Ok(());
        }
        guard.insert(
            installation,
            InstallationState {
                phase: ComponentLifecycleState::Active,
                digest: entry.installation.digest,
            },
        );
        Ok(())
    }

    /// 编排状态查询（测试/诊断）。
    pub fn phase(&self, installation: InstallationId) -> Option<ComponentLifecycleState> {
        self.states_lock()
            .get(&installation)
            .map(|state| state.phase)
    }

    /// begin_drain（§20.4/§41.2 drain）：
    ///
    /// 1. audit `DrainStarted` 先行（§18.7 fail-closed）；
    /// 2. 状态机 `Active → Draining`（显式校验，§12.2；registry 有 Active
    ///    条目而编排状态缺失时视为已 ready，从 registry 种子）；
    /// 3. 停止 scheduler/event 后台任务（§20.4：所有 background task 受
    ///    CancellationToken 管理；停机关闭后不再产生新 fire/新发布）；
    /// 4. 以**有界 deadline** 排空运行句柄（[`ActiveRuntime::drain`]：
    ///    `InstanceSet::close` + deadline 到期取消/trap；在途交付作为已
    ///    接受工作在此窗口完成，随后释放 Store 与 Host 资源）。
    ///
    /// 成功后编排状态保持在 `Draining`；由 [`Self::stop`] 完成终态。
    pub fn begin_drain(&self, installation: InstallationId) -> Result<(), LifecycleError> {
        let state = self.ensure_ready_state(installation)?;
        // §18.7：durable audit 先行（fail closed）。
        self.audit_ok(AuditEvent::DrainStarted {
            installation,
            digest: state.digest,
            deadline_secs: self.drain_deadline.as_secs(),
        })?;
        // 状态机：Active → Draining（显式校验）。
        let mut guard = self.states_lock();
        let state = guard
            .get_mut(&installation)
            .ok_or(LifecycleError::Internal(
                "lifecycle state vanished between checks",
            ))?;
        let next = state
            .phase
            .transition(ComponentLifecycleEvent::DrainStarted)?;
        state.phase = next;
        drop(guard);

        // 后台任务停止（scheduler/event；幂等，未使用者为 no-op）。
        self.scheduler
            .stop(installation)
            .map_err(|error| LifecycleError::BackgroundStop(error.to_string()))?;
        self.event
            .stop(installation)
            .map_err(|error| LifecycleError::BackgroundStop(error.to_string()))?;

        // 有界 drain（§20.4）：InstanceSet::close + deadline；drop 释放
        // Store 与 Host 资源。
        let entry = self
            .registry
            .get(installation)
            .ok_or(LifecycleError::NotFound(installation))?;
        Arc::clone(&entry.runtime)
            .drain(self.drain_deadline)
            .map_err(LifecycleError::Drain)?;
        Ok(())
    }

    /// stop（§41.2 stop；§20.4 终态）：`Draining → Disabled`。
    ///
    /// 1. audit `DrainCompleted` 先行（§18.7 fail-closed；digest 取
    ///    begin_drain 时固化的快照）；
    /// 2. 状态机 `Draining → Disabled`（§12.2 概念图终点；可经重新激活
    ///    回到 `Activating`，§39.2）。
    ///
    /// 未先 drain 直接 stop → [`LifecycleError::InvalidTransition`]。
    pub fn stop(&self, installation: InstallationId) -> Result<(), LifecycleError> {
        let digest = self
            .states_lock()
            .get(&installation)
            .map(|state| state.digest)
            .ok_or(LifecycleError::NotFound(installation))?;
        // §18.7：durable audit 先行（fail closed）。
        self.audit_ok(AuditEvent::DrainCompleted {
            installation,
            digest,
        })?;
        let mut guard = self.states_lock();
        let state = guard
            .get_mut(&installation)
            .ok_or(LifecycleError::Internal(
                "lifecycle state vanished between checks",
            ))?;
        let next = state
            .phase
            .transition(ComponentLifecycleEvent::DrainCompleted)?;
        state.phase = next;
        Ok(())
    }

    /// checkpoint（§41.2 checkpoint）：把安装实例的权威状态 flush 到持久
    /// 面（stop 前的显式确认步骤；[`CheckpointPort`] 是 StateService 无
    /// 独立 flush 语义下的最小编排入口，见 port 模块文档）。
    ///
    /// 失败 → [`LifecycleError::Checkpoint`]（fail-stop：编排方不得进入
    /// 终态）。
    pub fn checkpoint(&self, installation: InstallationId) -> Result<(), LifecycleError> {
        self.checkpoint
            .checkpoint(installation)
            .map_err(LifecycleError::Checkpoint)
    }

    /// 编排状态存在性确认（registry 有 Active 条目而编排状态缺失时视为
    /// 已 ready，从 registry 种子状态）。
    fn ensure_ready_state(
        &self,
        installation: InstallationId,
    ) -> Result<InstallationState, LifecycleError> {
        let mut guard = self.states_lock();
        if let Some(state) = guard.get(&installation) {
            return Ok(state.clone());
        }
        let entry = self
            .registry
            .get(installation)
            .ok_or(LifecycleError::NotFound(installation))?;
        let state = InstallationState {
            phase: ComponentLifecycleState::Active,
            digest: entry.installation.digest,
        };
        guard.insert(installation, state.clone());
        Ok(state)
    }

    fn audit_ok(&self, event: AuditEvent) -> Result<(), LifecycleError> {
        self.audit.append(event).map_err(LifecycleError::Audit)
    }

    fn states_lock(&self) -> MutexGuard<'_, BTreeMap<InstallationId, InstallationState>> {
        self.states
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use super::*;
    use crate::clock::SystemClock;
    use crate::event::{EventLimits, EventService};
    use crate::ports::{
        InProcessCheckpoint, InProcessEventPolicy, InProcessSchedulerGrant, SchedulerDeliveryPort,
    };
    use crate::scheduler::{SchedulerLimits, SchedulerService};
    use crate::test_support::{
        FakeAudit, FakeEventDelivery, FakeTriggerDelivery, Harness, installation, ok,
        plain_install_request,
    };

    /// 断言式失败（workspace lints deny panic!/unwrap!，§26.1；与
    /// test_support 同模式）。
    #[allow(clippy::assertions_on_constants)]
    fn test_failure(message: impl std::fmt::Display) -> ! {
        assert!(false, "{message}");
        std::process::abort();
    }

    fn err<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> E {
        match result {
            Err(error) => error,
            Ok(_) => test_failure(format_args!("{what} succeeded unexpectedly")),
        }
    }

    /// 确定性未来时刻（2033-05-18；SystemClock.now() ≈ 2026 ≪ 该时刻）。
    fn future_instant(seconds_offset: u64) -> operune_domain::UtcInstant {
        ok(
            operune_domain::UtcInstant::from_unix_parts(2_000_000_000 + seconds_offset, 0),
            "future instant",
        )
    }

    /// lifecycle 测试装配：registry（FakeRuntime）+ scheduler/event 后台
    /// 服务 + InProcessCheckpoint + FakeAudit。
    struct LifecycleHarness {
        controller: LifecycleController,
        harness: Harness,
        scheduler: Arc<SchedulerService>,
        event: Arc<EventService>,
        checkpoint: Arc<InProcessCheckpoint>,
        audit: Arc<FakeAudit>,
        grants: Arc<InProcessSchedulerGrant>,
    }

    fn lifecycle_harness() -> LifecycleHarness {
        let harness = Harness::new(crate::model::RuntimeConfig::default());
        let audit = Arc::new(FakeAudit::new());
        let checkpoint = Arc::new(InProcessCheckpoint::new());
        let grants = Arc::new(InProcessSchedulerGrant::new());
        let delivery = Arc::new(FakeTriggerDelivery::new());
        let scheduler = Arc::new(SchedulerService::new(
            Arc::clone(&grants) as Arc<dyn crate::ports::SchedulerGrantPort>,
            Arc::clone(&delivery) as Arc<dyn SchedulerDeliveryPort>,
            Arc::new(SystemClock::new()) as Arc<dyn crate::clock::Clock>,
            SchedulerLimits::default(),
        ));
        let event = Arc::new(EventService::new(
            Arc::new(InProcessEventPolicy::new()) as Arc<dyn crate::ports::EventPolicyPort>,
            Arc::new(FakeEventDelivery::new()) as Arc<dyn crate::ports::EventDeliveryPort>,
            EventLimits::default(),
        ));
        let controller = LifecycleController::new(
            Arc::clone(&harness.active),
            Arc::clone(&scheduler),
            Arc::clone(&event),
            Arc::clone(&checkpoint) as Arc<dyn CheckpointPort>,
            Arc::clone(&audit) as Arc<dyn AuditPort>,
            StdDuration::from_secs(10),
        );
        LifecycleHarness {
            controller,
            harness,
            scheduler,
            event,
            checkpoint,
            audit,
            grants,
        }
    }

    /// 安装并激活一个组件（registry 获得 Active 条目）。
    fn activate(h: &LifecycleHarness) -> InstallationId {
        let outcome = ok(
            h.harness
                .install
                .install(plain_install_request(b"lifecycle v1 bytes".to_vec())),
            "install",
        );
        match outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn ready_drain_stop_orchestration() {
        let h = lifecycle_harness();
        let inst = activate(&h);
        // ready：registry 有 Active 条目。
        ok(h.controller.ready(inst), "ready");
        assert_eq!(
            h.controller.phase(inst),
            Some(ComponentLifecycleState::Active)
        );
        // begin_drain：Active → Draining；FakeRuntime 记录有界 deadline。
        ok(h.controller.begin_drain(inst), "begin drain");
        assert_eq!(
            h.controller.phase(inst),
            Some(ComponentLifecycleState::Draining)
        );
        let drains = h.harness.runtime.drains();
        assert_eq!(drains.len(), 1);
        assert_eq!(drains[0], StdDuration::from_secs(10));
        // audit 事件按序（DrainStarted 先行，§18.7）。
        assert!(h.audit.contains(|event| matches!(
            event,
            AuditEvent::DrainStarted { installation, deadline_secs, .. }
                if *installation == inst && *deadline_secs == 10
        )));
        // stop：Draining → Disabled（终态）。
        ok(h.controller.stop(inst), "stop");
        assert_eq!(
            h.controller.phase(inst),
            Some(ComponentLifecycleState::Disabled)
        );
        assert!(h.audit.contains(|event| matches!(
            event,
            AuditEvent::DrainCompleted { installation, .. } if *installation == inst
        )));
    }

    #[tokio::test(start_paused = true)]
    async fn drain_stops_scheduler_and_event_background_services() {
        let h = lifecycle_harness();
        let inst = activate(&h);
        h.grants.grant(inst);
        // 注册一个定时任务（后台 driver 派生）。
        let _task = ok(
            h.scheduler.schedule(
                inst,
                operune_domain::ScheduleTrigger::one_shot(future_instant(10)),
            ),
            "schedule",
        );
        ok(h.controller.begin_drain(inst), "begin drain");
        // §20.4：后台任务已停止——scheduler/event 不再接受新工作。
        assert!(h.scheduler.is_stopped(inst));
        assert!(h.event.is_stopped(inst));
        let error = err(
            h.scheduler.schedule(
                inst,
                operune_domain::ScheduleTrigger::one_shot(future_instant(100)),
            ),
            "schedule after drain",
        );
        assert!(matches!(error, crate::scheduler::SchedulerError::NotReady));
    }

    #[tokio::test(start_paused = true)]
    async fn stop_without_drain_is_invalid_transition() {
        let h = lifecycle_harness();
        let inst = activate(&h);
        ok(h.controller.ready(inst), "ready");
        let error = err(h.controller.stop(inst), "stop without drain");
        assert!(matches!(error, LifecycleError::InvalidTransition(_)));
        // 状态未被破坏（仍在 Active）。
        assert_eq!(
            h.controller.phase(inst),
            Some(ComponentLifecycleState::Active)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn double_drain_and_double_stop_are_rejected() {
        let h = lifecycle_harness();
        let inst = activate(&h);
        ok(h.controller.begin_drain(inst), "first drain");
        let error = err(h.controller.begin_drain(inst), "second drain");
        assert!(matches!(error, LifecycleError::InvalidTransition(_)));
        ok(h.controller.stop(inst), "stop");
        let error = err(h.controller.stop(inst), "second stop");
        assert!(matches!(error, LifecycleError::InvalidTransition(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn begin_drain_unknown_installation_is_not_found() {
        let h = lifecycle_harness();
        let error = err(h.controller.begin_drain(installation(99)), "drain unknown");
        assert!(matches!(error, LifecycleError::NotFound(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn checkpoint_is_orchestrated_before_terminal_state() {
        let h = lifecycle_harness();
        let inst = activate(&h);
        ok(h.controller.checkpoint(inst), "checkpoint");
        assert_eq!(h.checkpoint.checkpoint_calls(), 1);
        // checkpoint 可在 drain 中/终态前执行（§41.2 顺序）。
        ok(h.controller.begin_drain(inst), "begin drain");
        ok(h.controller.checkpoint(inst), "checkpoint during drain");
        assert_eq!(h.checkpoint.checkpoint_calls(), 2);
        ok(h.controller.stop(inst), "stop");
    }

    #[test]
    fn ready_requires_registry_entry() {
        let h = lifecycle_harness();
        let error = err(h.controller.ready(installation(7)), "ready unknown");
        assert!(matches!(error, LifecycleError::NotFound(_)));
    }
}
