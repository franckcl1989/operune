//! Component 注册表 port（§18.3 数据所有权 / §19.2 / §19.4 / §6.7）。

use operune_domain::{ComponentId, ComponentVersion, ContentDigest, InstallationId};

use crate::model::{CandidateRecord, DigestVersionBinding, InstallationRecord};

/// 注册表持久化错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    /// `ComponentId + ComponentVersion -> Digest` 绑定已存在且 digest 不同
    /// （§19.4：供应链/发布冲突必须显式阻断，不能静默覆盖）。
    #[error(
        "version binding conflict: {component_id} {version} is already bound to digest {existing}, refusing {incoming}"
    )]
    VersionBindingConflict {
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 作者声明版本。
        version: ComponentVersion,
        /// 已存在的绑定 digest。
        existing: ContentDigest,
        /// 试图写入的 digest。
        incoming: ContentDigest,
    },
    /// 记录不存在（查询类操作）。
    #[error("record not found: {0}")]
    NotFound(&'static str),
    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("registry storage failure: {0}")]
    Storage(#[source] crate::error::ErrorSource),
}

/// Component 注册表 port（storage-sqlite 层实现）。
///
/// 语义（§6.7 / §19.2 / §19.4）：
/// - quarantine/candidate 记录以 [`ContentDigest`] 为主键（"字节事实"
///   阶段完成即持久化）；
/// - `ComponentId + ComponentVersion -> Digest` 唯一绑定：重复 digest
///   显式冲突（[`RegistryError::VersionBindingConflict`]），不静默覆盖；
/// - [`InstallationId`] 记录承载激活 digest、生命周期状态与 rollback
///   保留目标（§18.3 / §18.7 rollback retention）；
/// - 制品字节以 ContentDigest 寻址并视为不可变（§18.7 final artifact）。
pub trait ComponentRegistryPort: Send + Sync {
    /// 持久化制品字节（content-addressed，§18.7）。实现方负责 staging /
    /// final 语义与原子 rename（§18.5 / §18.7 属存储层）。
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError>;

    /// 按 digest 读取制品字节（回滚保留目标，§18.7）。不可用返回 `None`。
    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError>;

    /// 写入 / 更新 digest 主键的 quarantine/candidate 记录（upsert）。
    fn upsert_candidate(&self, record: &CandidateRecord) -> Result<(), RegistryError>;

    /// 更新 candidate 的生命周期状态（§12.2：显式转换由用例层执行后落盘）。
    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: operune_domain::ComponentLifecycleState,
    ) -> Result<(), RegistryError>;

    /// 查询 candidate 记录（状态机转换的前置读取，§12.2）。
    fn candidate(&self, digest: ContentDigest) -> Result<Option<CandidateRecord>, RegistryError>;

    /// 查询 `ComponentId + ComponentVersion` 的既有绑定。
    fn resolve_version(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<DigestVersionBinding>, RegistryError>;

    /// 建立版本绑定（§19.4 唯一性；冲突 → [`RegistryError::VersionBindingConflict`]）。
    fn bind_version(&self, binding: &DigestVersionBinding) -> Result<(), RegistryError>;

    /// 创建安装实例记录。
    fn insert_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError>;

    /// 更新安装实例记录（激活 digest / 状态 / rollback 保留目标）。
    fn update_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError>;

    /// 按 InstallationId 查询安装实例记录。
    fn installation(&self, id: InstallationId)
    -> Result<Option<InstallationRecord>, RegistryError>;

    /// 全部安装实例记录（管理面列表，§21.1）。
    fn list_installations(&self) -> Result<Vec<InstallationRecord>, RegistryError>;
}
