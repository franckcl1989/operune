//! Active Component 快照（§15.5 / §20.3：read-mostly 不可变快照 +
//! arc-swap 原子切换）。

use std::collections::BTreeMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use operune_domain::{ComponentId, ComponentVersion, ContentDigest, InstallationId};

use crate::runtime::ActiveRuntime;

/// Active 安装实例条目（§19.2 末步原子激活后进入快照）。
///
/// 不变量：同一 [`InstallationId`] 在快照中至多一条（§18.5：永远不存在
/// 两个版本都被误认为同一逻辑 Component 唯一 active 的歧义）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveInstallation {
    /// 安装实例身份（§19.4）。
    pub installation_id: InstallationId,
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// 当前激活版本。
    pub version: ComponentVersion,
    /// 当前激活 digest。
    pub digest: ContentDigest,
}

/// Active 路由快照（§15.5 / §20.3）：安装实例 → 运行句柄的不可变快照，
/// 通过 arc-swap 原子交换完成热升级切换（单指针交换，不允许分步修改造成
/// 前端 v2 / 后端 v1 不一致，§20.3 / §21.5）。
pub struct ActiveRuntimeRegistry {
    current: ArcSwap<BTreeMap<InstallationId, Arc<ActiveEntry>>>,
}

/// 快照条目：身份事实 + 运行句柄 + 激活期 Web 清单（§21.5：UI assets 与
/// backend exports 随同一 ComponentVersion 原子切换——清单随快照一起交换）。
pub struct ActiveEntry {
    /// 身份事实（§19.4）。
    pub installation: ActiveInstallation,
    /// 运行句柄（有界 Instance Set，§7.3）。
    pub runtime: Arc<dyn ActiveRuntime>,
    /// 激活期 Web 清单（无 Web UI 为 `None`）。
    pub manifest: Option<crate::model::WebManifestData>,
    /// 0.4.0（§42.2）：激活期构建的 Web 应用上下文（app descriptor +
    /// typed route registry；组件无 `operune:web@0.2.0` 表面为 `None`，
    /// 0.1 语义保持）。随快照一起原子交换（§21.5）。
    pub web_app: Option<Arc<crate::web_app::WebAppContext>>,
}

impl ActiveRuntimeRegistry {
    /// 创建空快照（composition root 注入）。
    pub fn new() -> Self {
        Self {
            current: ArcSwap::from_pointee(BTreeMap::new()),
        }
    }

    /// 读快照（读多写少，§15.5：不可变快照 + 原子加载）。
    pub fn get(&self, installation: InstallationId) -> Option<Arc<ActiveEntry>> {
        self.current.load().get(&installation).cloned()
    }

    /// 当前全部 Active 安装（管理面列表，§21.1）。
    pub fn list(&self) -> Vec<ActiveInstallation> {
        self.current
            .load()
            .values()
            .map(|entry| entry.installation.clone())
            .collect()
    }

    /// 原子激活 / 原子交换（§19.2 末步 / §20.1 / §20.3）：整个快照一次
    /// 指针交换完成；同一安装的旧条目由调用方（管线）在交换后 drain。
    pub(crate) fn swap(
        &self,
        installation: InstallationId,
        entry: Arc<ActiveEntry>,
    ) -> Result<(), crate::error::ApplicationError> {
        let mut next = BTreeMap::clone(&self.current.load());
        next.insert(installation, entry);
        self.current.store(Arc::new(next));
        Ok(())
    }

    /// 移除条目（管理性停用 / 卸载后）。
    pub fn remove(&self, installation: InstallationId) {
        let mut next = BTreeMap::clone(&self.current.load());
        next.remove(&installation);
        self.current.store(Arc::new(next));
    }

    /// 取回旧条目（升级 / 回滚交换前读取旧运行句柄用于 drain）。
    pub(crate) fn take_previous(&self, installation: InstallationId) -> Option<Arc<ActiveEntry>> {
        self.get(installation)
    }

    /// 快照内条目数（测试 / 诊断）。
    pub fn len(&self) -> usize {
        self.current.load().len()
    }

    /// 是否为空（测试 / 诊断）。
    pub fn is_empty(&self) -> bool {
        self.current.load().is_empty()
    }
}

impl Default for ActiveRuntimeRegistry {
    fn default() -> Self {
        Self::new()
    }
}
