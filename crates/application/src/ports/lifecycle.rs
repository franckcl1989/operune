//! 0.3.0 Stateful Runtime（§41.2）——graceful lifecycle 的 checkpoint port
//! （checkpoint 编排的最小入口）。
//!
//! §41.2 MUST：checkpoint + graceful lifecycle（ready/drain/stop/checkpoint）。
//! [`crate::state::StateService`] 的写路径（`cas`/事务 commit）是同步持久写
//! （经 [`crate::ports::StateStorePort`]，存储层原子提交），**没有独立的
//! flush/checkpoint 入口**——本 port 是"stop 前显式确认权威状态已 flush"
//! 的最小编排入口：storage 接线层（下一里程碑）可把 executor 的 checkpoint
//! 命令（WAL flush / 迁移日志确认）挂到这里；0.1.0 的 in-memory 事实
//! （scheduler fire 序列、event 计数）无持久化面（WIT：持久化策略是 Core
//! 实现细节），由 [`InProcessCheckpoint`] 以 no-op 承载。
//!
//! 编排语义（§20.4/§41.2）：checkpoint 在 drain/stop 序列中执行——drain
//! （已接受工作完成）之后、终态之前 flush 权威状态，确保停机不丢已确认
//! 状态。

use std::sync::atomic::{AtomicU64, Ordering};

use operune_domain::InstallationId;

/// checkpoint 错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum CheckpointError {
    /// 安装实例的权威状态无法确认 flush（fail-stop：编排方不得进入终态）。
    #[error("checkpoint failed for installation {0}: {1}")]
    Failed(InstallationId, &'static str),
}

/// checkpoint port（§24.2：trait 定义在本 crate，storage 接线层实现）。
pub trait CheckpointPort: Send + Sync {
    /// checkpoint：把安装实例的权威状态 flush 到持久面（§41.2
    /// checkpoint）。失败 → 编排方不得进入终态（fail-stop）。
    fn checkpoint(&self, installation: InstallationId) -> Result<(), CheckpointError>;
}

/// 进程内默认实现（composition root 与测试共用）：0.1.0 的 in-memory 事实
/// 无持久化面（WIT：定时任务持久化是 Core 实现细节；event 不承诺持久化），
/// checkpoint 为 no-op，并以调用计数供观测/测试断言编排顺序。
#[derive(Debug, Default)]
pub struct InProcessCheckpoint {
    calls: AtomicU64,
}

impl InProcessCheckpoint {
    /// 新建 no-op checkpoint 入口。
    pub fn new() -> Self {
        Self::default()
    }

    /// checkpoint 调用次数（观测/测试）。
    pub fn checkpoint_calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl CheckpointPort for InProcessCheckpoint {
    fn checkpoint(&self, _installation: InstallationId) -> Result<(), CheckpointError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::installation;

    #[test]
    fn in_process_checkpoint_is_noop_and_counts() {
        let checkpoint = InProcessCheckpoint::new();
        assert_eq!(checkpoint.checkpoint_calls(), 0);
        assert!(checkpoint.checkpoint(installation(1)).is_ok());
        assert!(checkpoint.checkpoint(installation(2)).is_ok());
        assert_eq!(checkpoint.checkpoint_calls(), 2);
    }
}
