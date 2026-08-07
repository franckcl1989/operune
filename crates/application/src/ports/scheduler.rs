//! 0.3.0 Stateful Runtime（§41.2）——scheduler 的交付与授权 port
//! （契约面 `operune:scheduler@0.1.0` scheduler.wit / handler.wit，已提交
//! 稳定）。
//!
//! # 交付 port
//!
//! 交付模型是 **Core-mediated push**（scheduler.wit 明文）：定时器到期时
//! Core 同步调用 guest 导出的 `handler.on-trigger`，落在 bounded Instance
//! Set 的任一实例（§7.3）。本 port 承载"宿主 → guest handler"的调用面；
//! 服务层（[`crate::scheduler::SchedulerService`]）的 driver 经有界待交付
//! 队列把 fire 交给 consumer 任务，consumer 调用本 port。
//!
//! 语义（handler.wit 明文）：`on-trigger` 无返回值——调用返回即已消费，
//! **trap 也视为已消费**（不重投、不计入错过）；因此本 port 的错误只用于
//! 宿主侧观测，服务层不做重试/补投。
//!
//! # 授权 port
//!
//! `denied`（scheduler.wit）＝"未获 scheduler 能力授权（grant 解析/撤销，
//! §17.1/§17.5）"。0.3 的 scheduler 能力授权是**静态 grant 策略**：管理员
//! 在安装/授权时配置（§17.1 两阶段含义），运行时无 subscribe/approve 变体。
//! 本 port 承载"安装实例是否被授予 scheduler 能力"的查询面；storage 接线
//! 层（下一里程碑）从 grant 存储映射实现，本文件提供进程内默认实现
//! [`InProcessSchedulerGrant`]（composition root 与测试共用）。

use std::collections::BTreeSet;
use std::sync::Mutex;

use operune_domain::{InstallationId, TriggerPayload};

use super::GrantError;

/// scheduler 交付错误（宿主侧观测；handler trap/失败 = 已消费，不重投，
/// handler.wit）。
#[derive(Debug, thiserror::Error)]
pub enum SchedulerDeliveryError {
    /// guest handler trap / runtime 调用失败（已消费语义下的观测记录）。
    #[error("scheduler delivery to guest handler failed: {0}")]
    Guest(&'static str),
}

/// 定时任务交付 port（§24.2：trait 定义在本 crate，runtime 接线层实现）。
///
/// 调用方：scheduler 服务层的投递 consumer（有界队列的另一端）。
pub trait SchedulerDeliveryPort: Send + Sync {
    /// Core-mediated push：调用 guest 的 `on-trigger`（同步；返回即已消费，
    /// trap 视为已消费，调用方不得重试/补投）。
    fn on_trigger(&self, payload: TriggerPayload) -> Result<(), SchedulerDeliveryError>;
}

/// scheduler 能力授权的静态查询（§17.1/§17.5；scheduler.wit `denied`）。
pub trait SchedulerGrantPort: Send + Sync {
    /// 安装实例是否被授予 scheduler 能力（grant 解析失败按未授权处理——
    /// deny-by-default，§17.2）。
    fn scheduler_granted(&self, installation: InstallationId) -> Result<bool, GrantError>;
}

/// 进程内默认实现（composition root 与测试共用）：显式授予的安装实例集。
///
/// 0.1.0 的 grant 存储接线（storage-sqlite）尚未把 scheduler 能力映射进
/// 本 port；本实现提供确定性注入面（管理员面/测试直接配置）。
#[derive(Debug, Default)]
pub struct InProcessSchedulerGrant {
    granted: Mutex<BTreeSet<InstallationId>>,
}

impl InProcessSchedulerGrant {
    /// 新建空授权集（deny-by-default，§17.2）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 显式授予安装实例 scheduler 能力。
    pub fn grant(&self, installation: InstallationId) {
        self.lock().insert(installation);
    }

    /// 撤销授权（§17.5 撤销后不再接受新注册；已注册任务由编排方停止）。
    pub fn revoke(&self, installation: InstallationId) {
        self.lock().remove(&installation);
    }

    /// 已授权安装实例数（测试/诊断）。
    pub fn granted_count(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeSet<InstallationId>> {
        self.granted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl SchedulerGrantPort for InProcessSchedulerGrant {
    fn scheduler_granted(&self, installation: InstallationId) -> Result<bool, GrantError> {
        Ok(self.lock().contains(&installation))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::installation;

    #[test]
    fn in_process_grant_deny_by_default() {
        let grants = InProcessSchedulerGrant::new();
        let inst = installation(1);
        assert!(!ok_granted(&grants, inst));
        assert_eq!(grants.granted_count(), 0);
        grants.grant(inst);
        assert!(ok_granted(&grants, inst));
        assert_eq!(grants.granted_count(), 1);
        grants.revoke(inst);
        assert!(!ok_granted(&grants, inst));
    }

    fn ok_granted(grants: &InProcessSchedulerGrant, installation: InstallationId) -> bool {
        grants
            .scheduler_granted(installation)
            .unwrap_or_else(|_| crate::test_support::test_failure("grant query failed"))
    }
}
