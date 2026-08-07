//! 热升级与回滚用例（§20）。
//!
//! # 升级流程（§20.1 逐字实现）
//!
//! ```text
//! v1 active
//!   +--> load/validate v2（共用 §19.2 候选管线）
//!        -> resolve dependencies/grants（§17.5：旧 grant 不静默继承——
//!           新版本 imports 扩大能力则重新批准）
//!        -> instantiate v2
//!        -> readiness/health
//!        -> atomic active snapshot swap（§20.3 单指针交换）
//!        -> new requests -> v2
//!        -> drain v1（§20.4 有界 deadline）
//!        -> drop v1 Store
//! ```
//!
//! 不变量（§20.2 / §39.4 验收）：
//! - 非 destructive-in-place：v2 的任何验证 / 实例化 / readiness 失败时
//!   v1 保持可用（candidate 进入 Failed，Active 快照不变）；
//! - 旧 grant 不静默继承（§17.5）：`GrantApproval::ReuseExisting` 仅当
//!   v2 的 imports 未扩大能力需求时成立，否则返回
//!   [`UpgradeOutcome::RequiresApproval`]；扩大权限必须显式重新批准。
//!
//! # 回滚（§20）
//!
//! 回滚到上一已知良好版本（`InstallationRecord::last_known_good_digest`，
//! §18.7 rollback retention）：从 artifact store 读取目标字节（§18.7：
//! GC 不得删除仍被 rollback 使用的 digest），复用同一候选管线重新验证并
//! 原子切换。

use std::sync::Arc;

use operune_domain::{ComponentLifecycleState, ContentDigest, InstallationId};

use crate::active::ActiveRuntimeRegistry;
use crate::error::ApplicationError;
use crate::install::{InstallService, PipelineResult};
use crate::model::{
    GrantApproval, InstallRequest, RollbackRequest, UpgradeOutcome, UpgradeRequest,
};
use crate::ports::{AuditPort, ComponentRegistryPort, ConfigPort, GrantStorePort};
use crate::runtime::WasmRuntime;
use crate::web::AssetCache;

/// 热升级 / 回滚用例服务（§20）。
pub struct UpgradeService {
    install: InstallService,
    registry: Arc<dyn ComponentRegistryPort>,
}

impl UpgradeService {
    /// 构造（与 [`InstallService`] 共享同一组注入依赖）。
    pub fn new(
        registry: Arc<dyn ComponentRegistryPort>,
        grants: Arc<dyn GrantStorePort>,
        audit: Arc<dyn AuditPort>,
        config: Arc<dyn ConfigPort>,
        runtime: Arc<dyn WasmRuntime>,
        active: Arc<ActiveRuntimeRegistry>,
        assets: Arc<AssetCache>,
    ) -> Self {
        Self {
            install: InstallService::new(
                Arc::clone(&registry),
                grants,
                audit,
                config,
                runtime,
                active,
                assets,
            ),
            registry,
        }
    }

    /// 热升级（§20.1）：v1 保持可用直到 v2 验证通过并原子切换。
    pub fn upgrade(&self, request: UpgradeRequest) -> Result<UpgradeOutcome, ApplicationError> {
        let current = self.require_active(request.installation)?;
        let from = current.active_digest.ok_or(ApplicationError::Internal(
            "active installation lacks an active digest",
        ))?;
        // 幂等：目标 digest 与当前 Active 相同（§20 验收：不破坏现状）。
        let target_digest = ContentDigest::from_bytes(&request.bytes);
        if from == target_digest {
            return Ok(UpgradeOutcome::NoOp {
                installation: request.installation,
            });
        }
        let result = self.install.pipeline().run(
            InstallRequest {
                bytes: request.bytes,
                grants: request.grants,
            },
            crate::model::PipelineTarget::Upgrade { current },
        )?;
        match result {
            PipelineResult::Activated {
                installation,
                digest,
            } => Ok(UpgradeOutcome::Swapped {
                installation: installation.installation_id,
                from,
                to: digest,
            }),
            PipelineResult::RequiresApproval {
                installation,
                missing,
            } => Ok(UpgradeOutcome::RequiresApproval {
                installation: installation.installation_id,
                missing,
            }),
        }
    }

    /// 回滚到上一已知良好版本（§20 / §18.7 rollback retention）。
    pub fn rollback(&self, request: RollbackRequest) -> Result<UpgradeOutcome, ApplicationError> {
        let current = self.require_active(request.installation)?;
        let from = current.active_digest.ok_or(ApplicationError::Internal(
            "active installation lacks an active digest",
        ))?;
        let Some(target_digest) = current.last_known_good_digest else {
            return Err(ApplicationError::NoRollbackTarget(request.installation));
        };
        if from == target_digest {
            // 当前已是上一已知良好版本（幂等）。
            return Ok(UpgradeOutcome::NoOp {
                installation: request.installation,
            });
        }
        // §18.7：回滚目标字节必须可用（GC 不得删除仍被 rollback 使用的
        // digest）。
        let target_bytes = self
            .registry
            .artifact_bytes(target_digest)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::RollbackUnavailable(target_digest))?;
        let result = self.install.pipeline().run(
            InstallRequest {
                bytes: target_bytes,
                grants: GrantApproval::ReuseExisting,
            },
            crate::model::PipelineTarget::Rollback { current },
        )?;
        match result {
            PipelineResult::Activated {
                installation,
                digest,
            } => Ok(UpgradeOutcome::Swapped {
                installation: installation.installation_id,
                from,
                to: digest,
            }),
            PipelineResult::RequiresApproval {
                installation,
                missing,
            } => Ok(UpgradeOutcome::RequiresApproval {
                installation: installation.installation_id,
                missing,
            }),
        }
    }

    /// 当前安装必须存在且为 Active（§20.1 起点）。
    fn require_active(
        &self,
        installation: InstallationId,
    ) -> Result<crate::model::InstallationRecord, ApplicationError> {
        let record = self
            .registry
            .installation(installation)
            .map_err(ApplicationError::Registry)?
            .ok_or(ApplicationError::InstallationNotFound(installation))?;
        if record.state != ComponentLifecycleState::Active {
            return Err(ApplicationError::NotActive(installation));
        }
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ContractSurface, RuntimeConfig};
    use crate::ports::AuditEvent;
    use crate::test_support::{
        Harness, default_descriptor, grant, ok, plain_install_request, some, test_failure,
    };
    use operune_domain::ComponentVersion;
    use std::time::Duration;

    fn harness() -> Harness {
        Harness::new(RuntimeConfig::default())
    }

    /// v1（demo 1.0.0）安装并激活；返回 installation id 与 v1 digest。
    fn activate_v1(harness: &Harness) -> (InstallationId, ContentDigest) {
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"v1 bytes".to_vec())),
            "install v1",
        );
        let installation = match outcome {
            crate::model::InstallOutcome::Activated { installation, .. } => installation,
        };
        (installation, ContentDigest::from_bytes(b"v1 bytes"))
    }

    /// v2 descriptor：demo 2.0.0（同一逻辑产品的新版本，§20）。
    fn v2_descriptor() -> crate::contract::GuestComponentDescriptor {
        let mut descriptor = default_descriptor();
        descriptor.major = 2;
        descriptor.minor = 0;
        descriptor.patch = 0;
        descriptor
    }

    fn v2_bytes() -> Vec<u8> {
        b"v2 bytes".to_vec()
    }

    #[test]
    fn upgrade_swaps_and_drains_old_version() {
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade to v2",
        );
        let v2_digest = ContentDigest::from_bytes(&v2_bytes());
        match outcome {
            UpgradeOutcome::Swapped { from, to, .. } => {
                assert_eq!(from, v1_digest);
                assert_eq!(to, v2_digest);
            }
            other => test_failure(format_args!("expected swap, got {other:?}")),
        }
        // 新请求 → v2（§20.1：swap 后快照指向新版本）。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v2_digest);
        assert_eq!(
            entry.installation.version,
            ComponentVersion::from_parts(2, 0, 0)
        );
        // v1：Active → Draining → Disabled（§20.4 有界 drain）。
        assert_eq!(
            harness.registry.candidate_state(v1_digest),
            Some(ComponentLifecycleState::Disabled)
        );
        // v2 candidate → Active；installation 记录指向 v2。
        assert_eq!(
            harness.registry.candidate_state(v2_digest),
            Some(ComponentLifecycleState::Active)
        );
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.active_digest, Some(v2_digest));
        assert_eq!(record.last_known_good_digest, Some(v1_digest));
        // drain 以 config 的有界 deadline 调用（§20.4）。
        let drains = harness.runtime.drains();
        assert_eq!(drains.len(), 1);
        assert_eq!(
            drains[0],
            Duration::from_secs(10) // RuntimeConfig::default().drain_deadline
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::UpgradeSwapped { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::DrainStarted { .. }))
        );
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::DrainCompleted { .. }))
        );
    }

    #[test]
    fn upgrade_failure_keeps_v1_active() {
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        harness.runtime.with_instantiate_failure();
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation,
            bytes: v2_bytes(),
            grants: GrantApproval::ReuseExisting,
        });
        assert!(
            result.is_err(),
            "v2 instantiation failure must fail the upgrade: {result:?}"
        );
        // §39.4 验收 / §20.2：v2 失败时 v1 保持可用。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v1_digest);
        assert_eq!(
            harness
                .registry
                .installation(installation)
                .map(|record| record.state),
            Some(ComponentLifecycleState::Active)
        );
        // v2 candidate Failed（§19.3：readiness 类失败）。
        assert_eq!(
            harness
                .registry
                .candidate_state(ContentDigest::from_bytes(&v2_bytes())),
            Some(ComponentLifecycleState::Failed)
        );
        // v1 没有被 drain。
        assert!(harness.runtime.drains().is_empty());
    }

    #[test]
    fn upgrade_grant_expansion_requires_approval() {
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        // v2 需要新能力（wasi:http），既有 grant 未覆盖（§17.5：不静默继承）。
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["wasi:http/outgoing-handler@0.2.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade awaiting approval",
        );
        match outcome {
            UpgradeOutcome::RequiresApproval { missing, .. } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0].as_str(), "wasi:http/outgoing-handler");
            }
            other => test_failure(format_args!("expected RequiresApproval, got {other:?}")),
        }
        // 未发生交换：v1 仍 active；v2 candidate 保持 Validated（非 Failed）。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v1_digest);
        assert_eq!(
            harness
                .registry
                .candidate_state(ContentDigest::from_bytes(&v2_bytes())),
            Some(ComponentLifecycleState::Validated)
        );
        assert!(harness.runtime.drains().is_empty());
    }

    #[test]
    fn upgrade_grant_expansion_explicit_approval_swaps() {
        let harness = harness();
        let (installation, _v1_digest) = activate_v1(&harness);
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        harness.runtime.with_surface(ContractSurface {
            imports: vec!["wasi:http/outgoing-handler@0.2.0".to_owned()],
            exports: vec!["descriptor".to_owned()],
        });
        // §17.5：显式重新批准扩大后的权限 → 激活继续。
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes(),
                grants: GrantApproval::Explicit(vec![grant("wasi:http/outgoing-handler")]),
            }),
            "upgrade with explicit approval",
        );
        assert!(matches!(outcome, UpgradeOutcome::Swapped { .. }));
        // 新 grant 已落盘（§17.5：替换语义）。
        assert_eq!(harness.grants.stored(installation).len(), 1);
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::GrantsApproved { .. }))
        );
    }

    #[test]
    fn upgrade_to_other_component_id_rejected() {
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        let mut foreign = v2_descriptor();
        foreign.component_id = "other-product".to_owned();
        harness.runtime.with_descriptor_for(&v2_bytes(), foreign);
        let result = harness.upgrade.upgrade(UpgradeRequest {
            installation,
            bytes: v2_bytes(),
            grants: GrantApproval::ReuseExisting,
        });
        assert!(
            matches!(
                result,
                Err(ApplicationError::UpgradeComponentMismatch { .. })
            ),
            "upgrade to a different product must be rejected: {result:?}"
        );
        // v1 未受影响。
        assert_eq!(
            harness
                .active
                .get(installation)
                .map(|entry| entry.installation.digest),
            Some(v1_digest)
        );
    }

    #[test]
    fn upgrade_same_digest_is_noop() {
        let harness = harness();
        let (installation, _v1_digest) = activate_v1(&harness);
        let outcome = ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: b"v1 bytes".to_vec(),
                grants: GrantApproval::ReuseExisting,
            }),
            "noop upgrade",
        );
        assert_eq!(outcome, UpgradeOutcome::NoOp { installation });
        // 幂等：不重新验证、不 swap、不 drain。
        assert_eq!(
            harness.runtime.descriptor_calls(),
            2 // 仅 v1 安装时的两次（§19.3）
        );
    }

    #[test]
    fn rollback_to_last_good_version() {
        let harness = harness();
        let (installation, v1_digest) = activate_v1(&harness);
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade to v2",
        );
        // 回滚到上一已知良好版本（§20：v1 的 artifact 仍按 rollback
        // retention 保留，§18.7）。
        let outcome = ok(
            harness.upgrade.rollback(RollbackRequest { installation }),
            "rollback to v1",
        );
        match outcome {
            UpgradeOutcome::Swapped { from, to, .. } => {
                assert_eq!(from, ContentDigest::from_bytes(&v2_bytes()));
                assert_eq!(to, v1_digest);
            }
            other => test_failure(format_args!("expected swap, got {other:?}")),
        }
        // Active 快照回到 v1；installation 记录 active_digest = v1。
        let entry = some(harness.active.get(installation), "active entry");
        assert_eq!(entry.installation.digest, v1_digest);
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        assert_eq!(record.active_digest, Some(v1_digest));
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, AuditEvent::Rollback { .. }))
        );
    }

    #[test]
    fn rollback_without_target_fails() {
        let harness = harness();
        let (installation, _v1_digest) = activate_v1(&harness);
        // 清空 last_known_good：首个版本没有回滚目标（§20）。
        let record = some(
            harness.registry.installation(installation),
            "installation record",
        );
        let mut no_target = record.clone();
        no_target.last_known_good_digest = None;
        ok(
            harness.registry.update_installation(&no_target),
            "clear rollback target",
        );
        let result = harness.upgrade.rollback(RollbackRequest { installation });
        assert!(
            matches!(result, Err(ApplicationError::NoRollbackTarget(_))),
            "rollback without a target must fail: {result:?}"
        );
    }

    #[test]
    fn rollback_target_artifact_missing_fails() {
        let harness = harness();
        let (installation, _v1_digest) = activate_v1(&harness);
        harness
            .runtime
            .with_descriptor_for(&v2_bytes(), v2_descriptor());
        ok(
            harness.upgrade.upgrade(UpgradeRequest {
                installation,
                bytes: v2_bytes(),
                grants: GrantApproval::ReuseExisting,
            }),
            "upgrade to v2",
        );
        // §18.7：rollback retention 被破坏（artifact 缺失）→ 显式失败。
        harness.registry.fail_artifact_reads();
        let result = harness.upgrade.rollback(RollbackRequest { installation });
        assert!(result.is_err());
    }
}
