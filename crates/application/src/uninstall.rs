//! 卸载用例（§39.2 remove / §42.4：卸载后组件从 UI 与 backend 完整消失）。
//!
//! # 编排顺序
//!
//! ```text
//! load record（不存在 → InstallationNotFound）
//!   -> provider 依赖检查（§40：有 active consumer 依赖时拒绝卸载）
//!   -> 有界 drain（§20.4：不接新工作；deadline 到期取消/trap；释放 Store）
//!   -> ActiveEntry 移除（§15.5 快照交换）→ web 路由/页面/资产/app
//!      context 全部 404（§42.4：卸载后完整消失）
//!   -> 停 scheduler/event 后台任务（§20.4：CancellationToken 管理）
//!   -> composition deactivate（清 graph records + 快照原子切换，§40.2）
//!   -> 单事务删除 Core 元数据（UninstallStorePort，§18.5 crash
//!      consistency；grants / 版本绑定 / active / graph 记录 /
//!      state/config/secret / installation 行）
//!   -> audit 与删除同事务落盘（§18.7 fail closed）
//! ```
//!
//! artifact **保留**（§18.7 rollback retention）：digest 仍被
//! artifact/component_versions 引用，GC 引用规则不变——卸载后同一 digest
//! 可全新安装（§19.4：InstallationId 由 Core 重新生成，不跨卸载复用）。
//!
//! # Provider 卸载裁决（§40 依赖图完整性）
//!
//! 选项 (a) 拒绝卸载（有依赖时）vs (b) 允许并标记受影响 consumer 为
//! failed/未激活（须重解析）。选 (a)：**有 active consumer 依赖时拒绝
//! 卸载（[`ApplicationError::ProviderHasConsumers`]），consumer 卸载直接
//! 允许**。理由：
//!
//! - 确定性：拒绝发生在任何状态变更之前，无部分图、无隐式重解析；
//! - 安全性：§19.5 禁止把缺失依赖的 Component 当作健康 active 服务，
//!   §40.4 要求同一 Component set 确定解析——(b) 会把 graph 留在
//!   "已提交但不可解析"的中间态；(a) 保持 graph 快照永远可解析；
//! - 操作语义与既有停用 / 升级门控一致（[`CompositionService::deactivate`]
//!   同样拒绝仍被依赖的 provider，§40.2 deactivation ordering）。
//!
//! 0.2.0 composition 未接线（0.1.0 语义）时无 provider 概念，跳过检查。

use std::sync::{Arc, OnceLock};

use operune_domain::{InstallationId, ProviderId};

use crate::active::ActiveRuntimeRegistry;
use crate::composition::CompositionService;
use crate::error::ApplicationError;
use crate::event::EventService;
use crate::ports::{AuditEvent, AuditPort, ComponentRegistryPort, ConfigPort, UninstallStorePort};
use crate::scheduler::SchedulerService;

/// 卸载用例服务（§39.2 remove / §42.4）。
///
/// scheduler / event / composition 是**可选接线**（composition root 装配期
/// 一次性注入，[`OnceLock`] 模式与 [`crate::install::InstallService`] 一致）；
/// 未接线时对应步骤跳过（0.1.0 语义：无 composition / 无 0.3.0 后台任务
/// 服务）。
pub struct UninstallService {
    registry: Arc<dyn ComponentRegistryPort>,
    store: Arc<dyn UninstallStorePort>,
    audit: Arc<dyn AuditPort>,
    config: Arc<dyn ConfigPort>,
    active: Arc<ActiveRuntimeRegistry>,
    /// 0.2.0 Capability Composition 接线（§40；`None` = 0.1.0 语义）。
    composition: OnceLock<Arc<CompositionService>>,
    /// 0.3.0 scheduler 服务接线（§41.2；`None` = 未接线）。
    scheduler: OnceLock<Arc<SchedulerService>>,
    /// 0.3.0 event 服务接线（§41.2；`None` = 未接线）。
    event: OnceLock<Arc<EventService>>,
}

impl UninstallService {
    /// 构造（注入全部端口与运行依赖；composition root 组装）。
    pub fn new(
        registry: Arc<dyn ComponentRegistryPort>,
        store: Arc<dyn UninstallStorePort>,
        audit: Arc<dyn AuditPort>,
        config: Arc<dyn ConfigPort>,
        active: Arc<ActiveRuntimeRegistry>,
    ) -> Self {
        Self {
            registry,
            store,
            audit,
            config,
            active,
            composition: OnceLock::new(),
            scheduler: OnceLock::new(),
            event: OnceLock::new(),
        }
    }

    /// 接线 0.2.0 Capability Composition（§40：卸载前检查 provider 依赖、
    /// 卸载时清 graph records 并原子切换快照）。composition root 在启动
    /// 装配期调用一次；重复接线 → typed 拒绝（§12.4）。
    pub fn set_composition(
        &self,
        composition: Arc<CompositionService>,
    ) -> Result<(), ApplicationError> {
        self.composition
            .set(composition)
            .map_err(|_| ApplicationError::Internal("composition is already wired"))
    }

    /// 接线 0.3.0 scheduler 服务（§20.4：卸载时停后台任务）。composition
    /// root 在启动装配期调用一次；重复接线 → typed 拒绝。
    pub fn set_scheduler(&self, scheduler: Arc<SchedulerService>) -> Result<(), ApplicationError> {
        self.scheduler
            .set(scheduler)
            .map_err(|_| ApplicationError::Internal("scheduler is already wired"))
    }

    /// 接线 0.3.0 event 服务（§20.4：卸载时停后台任务）。composition root
    /// 在启动装配期调用一次；重复接线 → typed 拒绝。
    pub fn set_event(&self, event: Arc<EventService>) -> Result<(), ApplicationError> {
        self.event
            .set(event)
            .map_err(|_| ApplicationError::Internal("event service is already wired"))
    }

    /// 卸载（§39.2 remove / §42.4）。顺序见模块文档；任何失败都以 typed
    /// error 中止，不留"半删除"状态（存储侧单事务，§18.5）。
    pub fn uninstall(&self, installation: InstallationId) -> Result<(), ApplicationError> {
        let record = self
            .registry
            .installation(installation)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::InstallationNotFound(installation))?;

        // 1. §40 依赖图完整性检查（任何状态变更之前，§19.5 / §40.4 裁决
        //    见模块文档）：安装是 provider 且仍有 active consumer 直接
        //    依赖 → 拒绝卸载。consumer 卸载直接允许。
        if let Some(composition) = self.composition.get() {
            let provider = ProviderId::from_installation(installation);
            let graph = composition.graph();
            let consumers = graph.direct_consumers(provider);
            if !consumers.is_empty() {
                let consumer_ids = consumers.iter().map(|edge| edge.consumer()).collect();
                return Err(ApplicationError::ProviderHasConsumers {
                    installation,
                    consumers: consumer_ids,
                });
            }
        }

        let config = self
            .config
            .snapshot()
            .map_err(ApplicationError::ConfigSource)?;

        // 2. §20.4 有界 drain（Active 时）：audit 先行（fail closed，
        //    §18.7）→ drain（deadline 到期取消/trap；结束后释放 Store 与
        //    Host 资源）。
        if let Some(entry) = self.active.get(installation) {
            self.audit
                .append(AuditEvent::DrainStarted {
                    installation,
                    digest: entry.installation.digest,
                    deadline_secs: config.drain_deadline.as_secs(),
                })
                .map_err(ApplicationError::Audit)?;
            Arc::clone(&entry.runtime)
                .drain(config.drain_deadline)
                .map_err(ApplicationError::Runtime)?;
            self.audit
                .append(AuditEvent::DrainCompleted {
                    installation,
                    digest: entry.installation.digest,
                })
                .map_err(ApplicationError::Audit)?;
        }
        // ActiveEntry 从快照移除（§15.5 单指针交换）→ web 路由 / 页面 /
        // 资产 / app context 全部 404（§42.4：卸载后完整消失；web_app /
        // web 都以 Active 快照为事实源）。
        self.active.remove(installation);

        // 3. §20.4：停 scheduler / event 后台任务（fail closed：停机失败
        //    = 已入队任务可能仍在投递/触发，卸载中止）。
        if let Some(scheduler) = self.scheduler.get() {
            scheduler
                .stop(installation)
                .map_err(|error| ApplicationError::BackgroundStop(Box::new(error)))?;
        }
        if let Some(event) = self.event.get() {
            event
                .stop(installation)
                .map_err(|error| ApplicationError::BackgroundStop(Box::new(error)))?;
        }

        // 4. §40.2：清 graph records（records 移除 + graph 快照原子切换；
        //    与停用共用 deactivate 路径——consumer 直接允许，provider 已
        //    由步骤 1 检查）。
        if let Some(composition) = self.composition.get() {
            composition.deactivate(installation)?;
        }

        // 5. 单事务删除（grants / 版本绑定 / active / graph 记录 /
        //    state/config/secret / installation 行）；artifact 保留
        //    （§18.7）。audit 事件与删除同事务落盘（fail closed）。
        let event = AuditEvent::UninstallCompleted {
            installation,
            component_id: record.component_id.clone(),
            version: record.version,
            digest: record.active_digest,
        };
        self.store
            .remove_installation(installation, event)
            .map_err(|error| match error {
                crate::ports::RegistryError::NotFound(_) => {
                    ApplicationError::InstallationNotFound(installation)
                }
                other => ApplicationError::Registry(other),
            })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SystemClock;
    use crate::event::EventLimits;
    use crate::model::{
        ContractSurface, GrantApproval, InstallRequest, RuntimeConfig, UpgradeRequest,
    };
    use crate::ports::{
        EventDeliveryError, EventDeliveryPort, InProcessEventPolicy, InProcessSchedulerGrant,
        SchedulerDeliveryError, SchedulerDeliveryPort, SchedulerGrantPort,
    };
    use crate::test_support::{
        Harness, default_descriptor, grant, ok, plain_install_request, some, test_failure,
    };
    use operune_domain::{
        ComponentLifecycleEvent, ComponentLifecycleState, ContentDigest, TriggerPayload,
    };
    use std::time::Duration;

    fn harness() -> Harness {
        Harness::new(RuntimeConfig::default())
    }

    /// 复刻 web-admin facade 的 disable 持久化语义（§39.2 disable：
    /// Active → Draining → Disabled + 有界 drain + ActiveEntry 移除；
    /// application 尚无 disable 用例服务，enable 测试需要先到 Disabled）。
    fn disable_via_admin(harness: &Harness, installation: InstallationId) {
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        let digest = some(record.active_digest, "active digest");
        let mut draining = record.clone();
        draining.state = ComponentLifecycleState::Draining;
        ok(
            harness.registry.update_installation(&draining),
            "mark draining",
        );
        if let Some(entry) = harness.active.get(installation) {
            ok(
                Arc::clone(&entry.runtime).drain(Duration::from_secs(1)),
                "drain",
            );
        }
        harness.active.remove(installation);
        let mut disabled = draining;
        disabled.state = ComponentLifecycleState::Disabled;
        ok(
            harness.registry.update_installation(&disabled),
            "mark disabled",
        );
        // 候选 digest：Active → DrainStarted → Draining → DrainCompleted →
        // Disabled（§20.4 drain 完成终态）。
        let candidate = some(
            ok(harness.registry.candidate(digest), "candidate record read"),
            "candidate record",
        );
        let drained = candidate
            .state
            .transition(ComponentLifecycleEvent::DrainStarted)
            .unwrap_or_else(|_| test_failure("drain start transition"));
        let disabled_state = drained
            .transition(ComponentLifecycleEvent::DrainCompleted)
            .unwrap_or_else(|_| test_failure("drain completion transition"));
        ok(
            harness
                .registry
                .update_candidate_state(digest, disabled_state),
            "candidate disabled",
        );
    }

    /// 安装并激活一个组件；返回 (installation, digest)。
    fn activate_v1(harness: &Harness) -> (InstallationId, ContentDigest) {
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"v1 bytes".to_vec())),
            "install v1",
        );
        match outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => {
                (installation, ContentDigest::from_bytes(b"v1 bytes"))
            }
        }
    }

    /// 安装并激活（携带 import 能力的组件）；返回 installation。
    fn activate_with_import(harness: &Harness, bytes: Vec<u8>, import: &str) -> InstallationId {
        harness.runtime.with_surface_for(
            &bytes,
            ContractSurface {
                imports: vec![import.to_owned()],
                exports: vec!["descriptor".to_owned()],
            },
        );
        let outcome = ok(
            harness.install.install(InstallRequest {
                bytes,
                grants: GrantApproval::Explicit(vec![grant(import)]),
            }),
            "install with import",
        );
        match outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        }
    }

    #[test]
    fn uninstall_removes_installation_completely() {
        // §39.2 remove / §42.4：卸载后组件从管理面列表与 Active 快照
        // 完整消失（路由/页面/资产/app context 以 Active 快照为事实源，
        // §42.4）；grants 与安装记录由存储单事务删除。
        let harness = harness();
        let (installation, digest) = activate_v1(&harness);
        // 安装带一个 grant（卸载应清空）。
        ok(
            crate::ports::GrantStorePort::replace_grants(
                &*harness.grants,
                installation,
                &[grant("wasi:cli/environment")],
            ),
            "grant install",
        );
        assert!(!harness.active.is_empty());
        assert!(harness.registry.installation(installation).is_some());

        ok(
            harness.uninstall.uninstall(installation),
            "uninstall installation",
        );

        // 列表 / 记录 / Active 快照全部消失。
        assert!(harness.registry.installation(installation).is_none());
        assert!(ok(harness.registry.list_installations(), "list installations").is_empty());
        assert!(harness.active.is_empty());
        // §42.4：卸载后路由 / 页面 / 资产 / app context 完整消失
        // （web_app 与 web bridge 都以 Active 快照为事实源 → 404）。
        assert!(matches!(
            harness.web_app.context(installation),
            Err(ApplicationError::NotActiveForWeb(_))
        ));
        assert!(matches!(
            harness.web.read_asset(
                installation,
                &crate::model::WebAssetPath::new("/index.html")
                    .unwrap_or_else(|_| { test_failure("invalid web asset path in test") })
            ),
            Err(ApplicationError::NotActiveForWeb(_))
        ));
        assert!(matches!(
            harness.web.invoke_action(
                installation,
                crate::model::ActionName::new("run")
                    .unwrap_or_else(|_| { test_failure("invalid action name in test") }),
                crate::contract::GuestActionPayload::Raw(vec![1, 2, 3]),
            ),
            Err(ApplicationError::NotActiveForWeb(_))
        ));
        assert_eq!(harness.uninstall_store.removed().len(), 1);
        let (removed_id, audit) = &harness.uninstall_store.removed()[0];
        assert_eq!(*removed_id, installation);
        assert!(matches!(
            audit,
            crate::ports::AuditEvent::UninstallCompleted {
                digest: Some(d),
                ..
            } if *d == digest
        ));
        // 审计：drain（§20.4）。卸载完成事件由存储侧与删除同事务落盘
        // （§18.7 fail closed）——fake 世界记录在 UninstallStorePort 调用
        // 载荷（已断言其形状）；durable 落盘由真实 executor 端到端测试
        // 验证。
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, crate::ports::AuditEvent::DrainStarted { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, crate::ports::AuditEvent::DrainCompleted { .. }))
        );
        // drain 以 config 的有界 deadline 调用（§20.4）。
        let drains = harness.runtime.drains();
        assert_eq!(drains.len(), 1);
        assert_eq!(drains[0], Duration::from_secs(10)); // default drain_deadline
    }

    #[test]
    fn uninstall_unknown_installation_is_not_found() {
        let harness = harness();
        let result = harness.uninstall.uninstall(InstallationId::new());
        assert!(matches!(
            result,
            Err(ApplicationError::InstallationNotFound(_))
        ));
        assert!(harness.uninstall_store.removed().is_empty());
    }

    #[test]
    fn uninstall_storage_failure_aborts_without_partial_state() {
        // 存储删除失败（单事务中止，§18.5）→ typed 错误；安装记录不受
        // 影响（应用层无半删除状态）。
        let harness = harness();
        let (installation, _digest) = activate_v1(&harness);
        harness.uninstall_store.with_storage_failure();
        let result = harness.uninstall.uninstall(installation);
        assert!(result.is_err(), "storage failure must abort uninstall");
        // Active 快照已移除（drain 先行）但记录仍在——重试可恢复。
        assert!(harness.registry.installation(installation).is_some());
    }

    #[test]
    fn uninstall_provider_with_consumers_is_rejected_but_consumer_allowed() {
        // §40 裁决（模块文档）：有 active consumer 依赖的 provider 拒绝
        // 卸载（ProviderHasConsumers）；consumer 卸载直接允许。
        let harness = Harness::with_composition(RuntimeConfig::default());
        // provider：exports 组件间接口（§40.3 事实源；descriptor 导出是
        // 契约面要求，§19.2）。
        let provider_bytes = b"provider bytes".to_vec();
        harness.runtime.with_surface_for(
            &provider_bytes,
            ContractSurface {
                imports: Vec::new(),
                exports: vec!["descriptor".to_owned(), "acme:svc/api@1.0.0".to_owned()],
            },
        );
        let provider_outcome = ok(
            harness
                .install
                .install(plain_install_request(provider_bytes)),
            "install provider",
        );
        let provider = match provider_outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        };
        // consumer：imports 组件间接口（依赖 provider）。
        let consumer_bytes = b"consumer bytes".to_vec();
        harness.runtime.with_surface_for(
            &consumer_bytes,
            ContractSurface {
                imports: vec!["acme:svc/api@1.0.0".to_owned()],
                exports: vec!["descriptor".to_owned()],
            },
        );
        harness.runtime.with_descriptor_for(&consumer_bytes, {
            let mut descriptor = default_descriptor();
            descriptor.component_id = "acme-consumer".to_owned();
            descriptor
        });
        let consumer_outcome = ok(
            harness
                .install
                .install(plain_install_request(consumer_bytes)),
            "install consumer",
        );
        let consumer = match consumer_outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        };
        // graph 已解析：consumer 依赖 provider。
        assert!(
            harness
                .composition
                .as_ref()
                .map(|composition| composition
                    .graph()
                    .direct_consumers(ProviderId::from_installation(provider))
                    .len())
                .unwrap_or(0)
                == 1,
            "consumer must be resolved against the provider"
        );

        // provider 卸载被拒绝（typed 错误携带受影响 consumer）。
        let error = match harness.uninstall.uninstall(provider) {
            Ok(()) => test_failure("provider uninstall with consumers must be rejected"),
            Err(error) => error,
        };
        match error {
            ApplicationError::ProviderHasConsumers {
                installation,
                consumers,
            } => {
                assert_eq!(installation, provider);
                assert_eq!(consumers, vec![consumer]);
            }
            other => test_failure(format_args!("unexpected error: {other:?}")),
        }
        // 拒绝发生在任何状态变更之前：无删除、无 drain、无审计。
        assert!(harness.uninstall_store.removed().is_empty());
        assert!(harness.registry.installation(provider).is_some());
        assert!(harness.runtime.drains().is_empty());

        // consumer 卸载直接允许；graph records 与快照更新。
        ok(harness.uninstall.uninstall(consumer), "uninstall consumer");
        assert!(harness.registry.installation(consumer).is_none());
        assert!(
            harness
                .composition
                .as_ref()
                .map(|composition| composition
                    .graph()
                    .direct_consumers(ProviderId::from_installation(provider))
                    .len())
                .unwrap_or(1)
                == 0,
            "consumer records must be removed from the graph"
        );
    }

    #[test]
    fn uninstall_stops_scheduler_and_event_background_tasks() {
        // §20.4：卸载编排必须停 scheduler/event 后台任务（CancellationToken
        // 管理）；停机失败 = 卸载中止（fail closed）。
        let harness = harness();
        let (installation, _digest) = activate_v1(&harness);
        // 真实 scheduler / event 服务接线（无 runtime 上下文的 stop 路径）。
        let scheduler = Arc::new(SchedulerService::new(
            Arc::new(InProcessSchedulerGrant::new()) as Arc<dyn SchedulerGrantPort>,
            Arc::new(NoopSchedulerDelivery) as Arc<dyn SchedulerDeliveryPort>,
            Arc::new(SystemClock),
            crate::scheduler::SchedulerLimits::default(),
        ));
        let event = Arc::new(EventService::new(
            Arc::new(InProcessEventPolicy::new()),
            Arc::new(NoopEventDelivery) as Arc<dyn EventDeliveryPort>,
            EventLimits::default(),
        ));
        ok(
            harness.uninstall.set_scheduler(Arc::clone(&scheduler)),
            "wire scheduler",
        );
        ok(
            harness.uninstall.set_event(Arc::clone(&event)),
            "wire event",
        );
        assert!(!scheduler.is_stopped(installation));
        assert!(!event.is_stopped(installation));

        ok(
            harness.uninstall.uninstall(installation),
            "uninstall installation",
        );
        assert!(scheduler.is_stopped(installation));
        assert!(event.is_stopped(installation));
        // 停机幂等（重复卸载前已停机）。
        assert!(scheduler.is_stopped(installation));
    }

    /// no-op scheduler 投递（停机测试只需 stop 语义）。
    struct NoopSchedulerDelivery;
    impl SchedulerDeliveryPort for NoopSchedulerDelivery {
        fn on_trigger(&self, _payload: TriggerPayload) -> Result<(), SchedulerDeliveryError> {
            Ok(())
        }
    }

    /// no-op event 投递（停机测试只需 stop 语义）。
    struct NoopEventDelivery;
    impl EventDeliveryPort for NoopEventDelivery {
        fn on_event(&self, _event: crate::event::DeliveredEvent) -> Result<(), EventDeliveryError> {
            Ok(())
        }
    }

    #[test]
    fn uninstall_without_composition_skips_graph() {
        // 0.1.0 语义（composition 未接线）：无 provider 概念，卸载直接
        // 允许（跳过 graph 检查与 records 清理）。
        let harness = harness();
        let (installation, _digest) = activate_v1(&harness);
        ok(
            harness.uninstall.uninstall(installation),
            "uninstall without composition",
        );
        assert!(harness.registry.installation(installation).is_none());
    }

    #[test]
    fn uninstalled_digest_reinstall_mints_fresh_installation_id() {
        // §19.4 / §18.7：卸载后 artifact 保留，同一 digest 全新安装获得
        // **新的** InstallationId（身份不跨卸载复用）。
        let harness = harness();
        let (first, digest) = activate_v1(&harness);
        ok(harness.uninstall.uninstall(first), "uninstall first");
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"v1 bytes".to_vec())),
            "reinstall same digest",
        );
        let second = match outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        };
        assert_ne!(first, second);
        let record = some(harness.registry.installation(second), "reinstalled record");
        assert_eq!(record.active_digest, Some(digest));
    }

    // ------------------------------------------------------------------
    // enable（§39.2 enable 重新激活：Disabled → 重新验证 → 激活）
    // ------------------------------------------------------------------

    #[test]
    fn enable_reactivates_disabled_installation() {
        // §39.2 enable：readiness 重验证后原子激活（§19.3 / §20.3）——
        // Active 快照重新包含该安装（web 路由/页面/资产恢复），记录回到
        // Active，候选 digest 回到 Active。
        let harness = harness();
        let (installation, digest) = activate_v1(&harness);
        disable_via_admin(&harness, installation);
        assert!(harness.active.is_empty());

        ok(harness.install.enable(installation), "enable installation");

        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, digest);
        assert_eq!(entry.installation.installation_id, installation);
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.state, ComponentLifecycleState::Active);
        assert_eq!(record.active_digest, Some(digest));
        assert_eq!(
            harness.registry.candidate_state(digest),
            Some(ComponentLifecycleState::Active)
        );
        // 审计：重新激活走完整激活路径（§18.7 组件生命周期类事件）。
        assert!(harness.audit.contains(|event| matches!(
            event,
            crate::ports::AuditEvent::ActivationSucceeded { .. }
        )));
        // 重新激活不产生新的 drain（停用时的运行句柄已释放，§20.4；
        // 仅 disable 辅助产生的一次 drain）。
        assert_eq!(harness.runtime.drains().len(), 1);
    }

    #[test]
    fn enable_requires_disabled_state() {
        // §12.2：仅 Disabled 终态可重新激活。
        let harness = harness();
        let (installation, _digest) = activate_v1(&harness);
        let result = harness.install.enable(installation);
        assert!(matches!(
            result,
            Err(ApplicationError::EnableInvalidState {
                state: ComponentLifecycleState::Active,
                ..
            })
        ));
        // 未知安装 → InstallationNotFound。
        let missing = harness.install.enable(InstallationId::new());
        assert!(matches!(
            missing,
            Err(ApplicationError::InstallationNotFound(_))
        ));
    }

    #[test]
    fn enable_artifact_unavailable_fails() {
        // §18.7：enable 需要重新验证字节事实；retention 被破坏（artifact
        // 缺失）→ 显式失败，不"跳过验证直接恢复"。
        let first_harness = harness();
        let (installation, digest) = activate_v1(&first_harness);
        disable_via_admin(&first_harness, installation);
        first_harness.registry.remove_artifact_bytes(digest);
        let result = first_harness.install.enable(installation);
        assert!(matches!(
            result,
            Err(ApplicationError::ArtifactUnavailable(_))
        ));
        // 存储读失败（非缺失）→ Registry 错误（typed，不吞掉）。
        let second_harness = harness();
        let (installation, _digest) = activate_v1(&second_harness);
        disable_via_admin(&second_harness, installation);
        second_harness.registry.fail_artifact_reads();
        let result = second_harness.install.enable(installation);
        assert!(matches!(result, Err(ApplicationError::Registry(_))));
    }

    #[test]
    fn enable_requires_approval_after_grants_removed() {
        // §17.5：既有 grant 被替换/撤销后 enable 不得静默放行——缺失能力
        // 必须显式重新批准。
        let harness = harness();
        let installation =
            activate_with_import(&harness, b"env component".to_vec(), "wasi:cli/environment");
        disable_via_admin(&harness, installation);
        // 管理员替换 grants 为空集（§17.5 显式重新批准路径）。
        ok(
            crate::ports::GrantStorePort::replace_grants(&*harness.grants, installation, &[]),
            "revoke all grants",
        );
        let result = harness.install.enable(installation);
        match result {
            Err(ApplicationError::EnableRequiresApproval { missing, .. }) => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].as_str(), "wasi:cli/environment");
            }
            other => test_failure(format_args!(
                "expected EnableRequiresApproval, got {other:?}"
            )),
        }
        // 未激活：记录仍 Disabled，Active 快照无该安装。
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.state, ComponentLifecycleState::Disabled);
        assert!(harness.active.is_empty());
    }

    #[test]
    fn enable_preserves_rollback_retention_target() {
        // §18.7 rollback retention：停用/重新启用不得丢失 last_known_good。
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        // 升级到 v2（v1 成为回滚保留目标）。
        let v2_bytes = b"v2 bytes".to_vec();
        harness.runtime.with_descriptor_for(&v2_bytes, {
            let mut descriptor = default_descriptor();
            descriptor.major = 2;
            descriptor
        });
        let v2_digest = ContentDigest::from_bytes(&v2_bytes);
        ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes,
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade to v2",
        );
        disable_via_admin(&harness, installation);
        ok(harness.install.enable(installation), "enable installation");
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.active_digest, Some(v2_digest));
        assert_eq!(
            record.last_known_good_digest,
            Some(v1_digest),
            "rollback retention target must survive disable/enable (§18.7)"
        );
    }
}
