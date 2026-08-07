//! 0.2.0 provider graph 持久化 port（§40.2 graph persistence/recovery）。
//!
//! 持久化的是 **records**（[`ProviderRecord`] / [`ConsumerRecord`]，§40.3
//! 事实源 = WIT imports/exports + Runtime Policy 过滤后的输入形态），
//! **不是**图本身：[`ProviderGraph`](operune_domain::ProviderGraph) 的不变量
//! （无环、每条需求唯一解析、身份可追溯）无法在反序列化时重新校验（domain
//! 明确不实现 `Deserialize`），恢复路径永远是
//! `load_records` → `ProviderGraph::try_build` 重新校验全部不变量
//! （§40.2：graph persistence/recovery 的图重建语义）。
//!
//! 存储层（storage-sqlite）负责 §18.5 crash consistency（staging + durable
//! transaction）：本 port 的 [`replace_records`](ProviderGraphPort::replace_records)
//! 是"某安装实例的全部 graph 记录"的**单次原子替换边界**（激活 = upsert，
//! 停用 = 全删），不允许分步修改产生半条记录。

use operune_domain::{ConsumerRecord, InstallationId, ProviderRecord};

use crate::error::ErrorSource;

/// 全部已持久化的 graph 记录（恢复 / 重建输入，§40.2）。
///
/// 顺序无意义：`try_build` 与 policy 应用均按稳定键排序（§40.4），
/// 本类型只负责搬运。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GraphRecords {
    /// 全部 provider 记录。
    pub providers: Vec<ProviderRecord>,
    /// 全部 consumer 记录。
    pub consumers: Vec<ConsumerRecord>,
}

/// graph 记录存储错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum GraphStoreError {
    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("graph store storage failure: {0}")]
    Storage(#[source] ErrorSource),
}

/// Provider graph 记录 port（storage-sqlite 层实现，§24.2 依赖方向）。
///
/// 语义（§40.2 / §40.3 / §18.5）：
/// - 以 [`InstallationId`] 为记录键（§17.5：grant 的 durable owner 是
///   InstallationId，graph 记录同样锚定安装实例）；
/// - [`replace_records`](ProviderGraphPort::replace_records) 是单次原子替换
///   边界：`provider` / `consumer` 均为 `None` 即删除该安装的全部记录
///   （deactivation / 激活失败的记录清理）；
/// - 记录是不可变字节事实（同一安装的同一提供面/需求面），升级 = 以
///   新版本表面整组替换；
/// - 恢复时 application 层重新 `try_build` 重校验全部图不变量。
pub trait ProviderGraphPort: Send + Sync {
    /// 原子替换某安装实例的全部 graph 记录（upsert / 全删）。
    fn replace_records(
        &self,
        installation: InstallationId,
        provider: Option<&ProviderRecord>,
        consumer: Option<&ConsumerRecord>,
    ) -> Result<(), GraphStoreError>;

    /// 加载全部记录（恢复输入）。
    fn load_records(&self) -> Result<GraphRecords, GraphStoreError>;

    /// 移除某安装实例的全部记录（便捷形态 = `replace_records(None, None)`）。
    fn remove_installation(&self, installation: InstallationId) -> Result<(), GraphStoreError> {
        self.replace_records(installation, None, None)
    }
}
