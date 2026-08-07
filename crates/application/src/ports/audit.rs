//! Audit port（§16.6 / §18.7：不记 secret；安全/权限/生命周期变更必须在
//! 提交前写入 durable audit，无法落盘时 fail closed）。

use operune_domain::{CapabilityId, ComponentId, ComponentVersion, ContentDigest, InstallationId};
use serde::Serialize;

/// audit 持久化错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。用例层按
    /// §18.7 fail closed 语义把该错误向上传播，阻止变更提交。
    #[error("audit storage failure: {0}")]
    Storage(#[source] crate::error::ErrorSource),
}

/// 审计事件（§16.6：事件内容不含密码 / session / CSRF / secret 值——
/// 环境变量 grant 的 value 一律遮蔽，见 [`crate::model::GrantAuditShape`]）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum AuditEvent {
    /// 安装输入被拒绝（超大小 / 非法字节 / 契约面缺失）——未产生 candidate。
    InstallRejected {
        /// 字节事实。
        digest: ContentDigest,
        /// 拒绝原因。
        reason: RejectReason,
    },
    /// digest 主键的 quarantine/candidate 已持久化（§19.2 "字节事实"完成）。
    CandidatePersisted {
        /// 字节事实。
        digest: ContentDigest,
    },
    /// descriptor 读取失败（超时 / trap / 超预算 / 非法 metadata，§19.3）。
    DescriptorFailed {
        /// 字节事实。
        digest: ContentDigest,
        /// 失败原因。
        reason: &'static str,
    },
    /// 同一 digest 重复调用 descriptor 结果不一致（contract violation，
    /// §19.3：candidate 保持 quarantine/failed）。
    DescriptorMismatch {
        /// 字节事实。
        digest: ContentDigest,
    },
    /// 逻辑身份 / 版本关系已建立（§19.2 阶段二完成）。
    IdentityRegistered {
        /// 安装实例。
        installation: InstallationId,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 作者声明版本。
        version: ComponentVersion,
        /// 字节事实。
        digest: ContentDigest,
    },
    /// 供应链/发布冲突被显式阻断（§19.4：相同逻辑版本不同 digest）。
    VersionConflict {
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 作者声明版本。
        version: ComponentVersion,
        /// 已存在的绑定 digest。
        existing: ContentDigest,
        /// 试图安装的 digest。
        incoming: ContentDigest,
    },
    /// imports 解析 / grant policy 失败（§17.2 deny-by-default / §19.5）。
    ResolutionFailed {
        /// 安装实例。
        installation: InstallationId,
        /// 未被覆盖的能力。
        missing: Vec<CapabilityId>,
    },
    /// grant 显式批准已落盘（§17.5；环境变量值不进入审计，§16.6）。
    GrantsApproved {
        /// 安装实例。
        installation: InstallationId,
        /// grant 审计形态（值遮蔽）。
        grants: Vec<crate::model::GrantAuditShape>,
    },
    /// 激活开始（Activating，§19.3）。
    ActivationStarted {
        /// 安装实例。
        installation: InstallationId,
    },
    /// 激活失败（实例化 / readiness / web manifest，§19.3）——候选 Failed，
    /// 当前 Active 不受污染（§19.2）。
    ActivationFailed {
        /// 安装实例。
        installation: InstallationId,
        /// 失败阶段。
        stage: &'static str,
    },
    /// 原子激活完成（§19.2 末步）。
    ActivationSucceeded {
        /// 安装实例。
        installation: InstallationId,
        /// 逻辑产品身份。
        component_id: ComponentId,
        /// 激活版本。
        version: ComponentVersion,
        /// 激活 digest。
        digest: ContentDigest,
    },
    /// 热升级原子快照交换完成（§20.1：新请求 → 新版本，旧版本进入 drain）。
    UpgradeSwapped {
        /// 安装实例。
        installation: InstallationId,
        /// 旧 digest。
        from: ContentDigest,
        /// 新 digest。
        to: ContentDigest,
    },
    /// 旧版本开始排空（§20.4：不接新工作，有界 deadline 内完成）。
    DrainStarted {
        /// 安装实例。
        installation: InstallationId,
        /// 被排空版本的 digest。
        digest: ContentDigest,
        /// 有界 deadline（秒）。
        deadline_secs: u64,
    },
    /// 排空完成（§20.4：Store 与 Host 资源已释放）。
    DrainCompleted {
        /// 安装实例。
        installation: InstallationId,
        /// 被排空版本的 digest。
        digest: ContentDigest,
    },
    /// Web manifest 加载完成（§21.3：激活阶段读取 web descriptor + 资产
    /// 清单并按 ContentDigest + asset path 缓存）。
    WebManifestLoaded {
        /// 安装实例。
        installation: InstallationId,
        /// 清单资产条目数。
        assets: u64,
        /// 实际进入缓存（受上限约束）的条目数。
        cached: u64,
    },
    /// backend action 调用成功（§21.3；只记元数据，不记请求 / 响应体——
    /// 响应不得含凭据，§16.6 / §21.3）。
    ActionInvoked {
        /// 安装实例。
        installation: InstallationId,
        /// 当前版本。
        version: ComponentVersion,
        /// action 名称。
        action: String,
    },
    /// backend action 被 Core 侧拒绝（§21.3：未授权 / 限流 / 超限等以
    /// 确定语义拒绝，不进入 guest 错误空间）。
    ActionDenied {
        /// 安装实例。
        installation: InstallationId,
        /// action 名称。
        action: String,
        /// 拒绝类别。
        reason: crate::model::ActionDenied,
    },
    /// 回滚完成（§20：回滚到上一已知良好版本）。
    Rollback {
        /// 安装实例。
        installation: InstallationId,
        /// 回滚前的 digest。
        from: ContentDigest,
        /// 回滚目标 digest。
        to: ContentDigest,
    },
    /// 0.2.0 provider graph 门控拒绝（§40.2：缺失 provider / 歧义 / 环 /
    /// provider 升级不兼容——candidate 保持 Failed，当前 Active 不受污染）。
    ProviderGraphRejected {
        /// 安装实例。
        installation: InstallationId,
        /// 拒绝阶段（surface / resolution / upgrade-analysis / commit）。
        reason: &'static str,
    },
    /// 0.2.0 graph records 已提交（持久化 + 快照原子切换，§40.2 graph
    /// snapshot atomic switch / persistence）。
    GraphRecordsCommitted {
        /// 安装实例。
        installation: InstallationId,
    },
    /// 0.2.0 graph records 已移除（管理性停用，§40.2 deactivation）。
    GraphRecordsRemoved {
        /// 安装实例。
        installation: InstallationId,
    },
    /// 0.2.0 provider selection policy 已更新（§40.4：更新前先以当前
    /// records 在新 policy 下重建验证，失败则状态不变）。
    GraphPolicyUpdated {
        /// 绑定规则数。
        bindings: usize,
        /// 排除规则数。
        exclusions: usize,
    },
}

/// 安装输入拒绝原因（§19.1 / §19.2）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RejectReason {
    /// 超过硬字节大小限制。
    Oversized,
    /// WebAssembly Component validation 失败。
    InvalidBytes,
    /// 缺少 `operune:component/descriptor` 导出（契约面，§19.2）。
    MissingComponentDescriptor,
    /// 其他契约面检查失败。
    ContractSurface,
}

/// Audit port（storage-sqlite 层实现；§18.7：durable audit 写入失败时
/// 依赖 audit 的变更必须 fail closed——用例层在提交前调用 append 并把
/// [`AuditError`] 传播为中止）。
pub trait AuditPort: Send + Sync {
    /// 追加一条审计事件。
    fn append(&self, event: AuditEvent) -> Result<(), AuditError>;
}
