use std::fmt;

use crate::lifecycle::{ComponentLifecycleEvent, ComponentLifecycleState};

/// 领域层统一封闭错误（§14.1：使用 `thiserror` 定义封闭、可匹配的 typed error；
/// 禁止 anyhow / eyre / `Box<dyn Error>` / String 作为公开错误类型，§22.9）。
///
/// 所有 Domain 操作的失败都落在本枚举中，调用方可以穷尽匹配。错误信息只包含
/// 可诊断信息，不含任何机密（§16.6 secret 不进日志/错误）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    /// 值对象构造 / 边界解析失败（§13.3 边界解析一次、构造即校验）。
    ///
    /// `kind` 指明失败的值类别，`detail` 是原因描述。
    #[error("invalid {kind}: {detail}")]
    InvalidValue {
        /// 校验失败的值类别。
        kind: ValueKind,
        /// 可诊断原因。
        detail: String,
    },

    /// 非法生命周期转换（§12.2：非法转换返回 typed error，不能静默忽略）。
    #[error("invalid lifecycle transition: {state} does not accept event {event}")]
    InvalidTransition {
        /// 转换前状态。
        state: ComponentLifecycleState,
        /// 被拒绝的事件。
        event: ComponentLifecycleEvent,
    },

    /// checked / saturating 算术失败（§14.4：不得依赖整数回绕）。
    #[error("arithmetic overflow during {operation}")]
    Overflow {
        /// 发生溢出的运算（静态字符串，用于日志）。
        operation: &'static str,
    },
}

impl DomainError {
    /// 便捷构造 [`DomainError::InvalidValue`]（crate 内部使用）。
    pub(crate) fn invalid_value(kind: ValueKind, detail: impl Into<String>) -> Self {
        Self::InvalidValue {
            kind,
            detail: detail.into(),
        }
    }
}

/// 发生校验失败的值类别（§13.1 语义类型清单），用于匹配与日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// [`ComponentId`](crate::ComponentId)。
    ComponentId,
    /// [`InstallationId`](crate::InstallationId)。
    InstallationId,
    /// [`CapabilityId`](crate::CapabilityId)。
    CapabilityId,
    /// [`ComponentVersion`](crate::ComponentVersion)。
    ComponentVersion,
    /// [`ContentDigest`](crate::ContentDigest)。
    ContentDigest,
    /// [`ByteSize`](crate::ByteSize)。
    ByteSize,
    /// [`Duration`](crate::Duration)。
    Duration,
    /// [`Deadline`](crate::Deadline)。
    Deadline,
    /// [`ArtifactPath`](crate::ArtifactPath)。
    ArtifactPath,
    /// [`ComponentLifecycleState`](crate::ComponentLifecycleState) 字符串解析。
    LifecycleState,
    /// [`ComponentLifecycleEvent`](crate::ComponentLifecycleEvent) 字符串解析。
    LifecycleEvent,
    /// [`ProviderId`](crate::ProviderId)（0.2.0 provider graph，§40.2）。
    ProviderId,
    /// [`PackageName`](crate::PackageName)（0.2.0 契约面，§40.2）。
    PackageName,
    /// [`InterfaceName`](crate::InterfaceName)（0.2.0 契约面，§40.2）。
    InterfaceName,
    /// [`InterfaceId`](crate::InterfaceId)（0.2.0 契约面，§40.2）。
    InterfaceId,
    /// [`InterfaceRequirement`](crate::InterfaceRequirement)（0.2.0 契约面，§40.2）。
    InterfaceRequirement,
    /// [`StateKey`](crate::StateKey)（0.3.0 stateful runtime，§41.2）。
    StateKey,
    /// [`StateValue`](crate::StateValue)（0.3.0 stateful runtime，§41.2）。
    StateValue,
    /// [`ConfigFormat`](crate::ConfigFormat)（0.3.0 stateful runtime，§41.2）。
    ConfigFormat,
    /// [`ConfigValue`](crate::ConfigValue)（0.3.0 stateful runtime，§41.2）。
    ConfigValue,
    /// [`SecretName`](crate::SecretName)（0.3.0 stateful runtime，§41.2 / §16.6）。
    SecretName,
    /// [`UtcInstant`](crate::UtcInstant)（0.3.0 scheduler，§41.2；WIT `datetime`）。
    UtcInstant,
    /// [`TaskState`](crate::TaskState)（0.3.0 scheduler，§41.2）。
    TaskState,
    /// [`EventTopic`](crate::EventTopic)（0.3.0 event bus，§41.2 / §17.3）。
    EventTopic,
    /// [`EventPayload`](crate::EventPayload) 载荷（0.3.0 event bus，§41.2）。
    EventPayload,
    /// [`PageId`](crate::PageId)（0.4.0 web application runtime，§42.2）。
    PageId,
    /// [`PagePath`](crate::PagePath)（0.4.0 web application runtime，§42.2）。
    PagePath,
    /// [`AssetPath`](crate::AssetPath)（0.4.0 web application runtime，§42.2）。
    AssetPath,
    /// [`RouteId`](crate::RouteId)（0.4.0 web application runtime，§42.2）。
    RouteId,
    /// [`HttpMethod`](crate::HttpMethod) 字符串解析（0.4.0 web application runtime，§42.2）。
    HttpMethod,
    /// [`ParamType`](crate::ParamType) 字符串解析（0.4.0 web application runtime，§42.2）。
    ParamType,
    /// [`RouteParam`](crate::RouteParam)（0.4.0 web application runtime，§42.2）。
    RouteParam,
    /// [`ParamValue`](crate::ParamValue)（0.4.0 web application runtime，§42.2）。
    ParamValue,
    /// [`TypedParam`](crate::TypedParam)（0.4.0 web application runtime，§42.2）。
    TypedParam,
    /// [`PermissionName`](crate::PermissionName)（0.4.0 web application runtime，§42.2）。
    PermissionName,
    /// [`RoleId`](crate::RoleId)（0.5.0 RBAC，§43.2）。
    RoleId,
    /// [`RoleName`](crate::RoleName)（0.5.0 RBAC，§43.2）。
    RoleName,
    /// [`GroupId`](crate::GroupId)（0.5.0 RBAC，§43.2）。
    GroupId,
    /// [`UserId`](crate::UserId) 字符串解析（0.5.0 RBAC，§43.2）。
    UserId,
    /// [`PermissionAction`](crate::PermissionAction) 字符串解析（0.5.0 RBAC，§43.2）。
    PermissionAction,
    /// [`Role`](crate::Role) 权限集合校验（0.5.0 RBAC，§43.2）。
    Role,
    /// [`NetworkScheme`](crate::NetworkScheme) 字符串解析（0.5.0 scoped
    /// capability policies，§43.2 / §17.3）。
    NetworkScheme,
    /// [`HostName`](crate::HostName)（0.5.0 scoped capability policies，§43.2）。
    HostName,
    /// [`FileSystemPath`](crate::FileSystemPath)（0.5.0 scoped capability
    /// policies，§43.2）。
    FileSystemPath,
    /// [`PolicySnapshot`](crate::PolicySnapshot) 组装校验（0.5.0 policy
    /// snapshot/versioning，§43.2）。
    PolicySnapshot,
    /// [`PolicyDiff`](crate::PolicyDiff)（0.5.0 permission change impact
    /// analysis，§43.2）。
    PolicyDiff,
    /// [`PolicyChain`](crate::PolicyChain)（0.5.0 可审计 policy chain，§43.3）。
    PolicyChain,
    /// [`PolicyChainLayer`](crate::PolicyChainLayer) 字符串解析（0.5.0
    /// policy chain，§43.3 / §17.5）。
    PolicyChainLayer,
    /// [`PolicyDecision`](crate::PolicyDecision) 字符串解析（0.5.0 policy
    /// chain，§43.3）。
    PolicyDecision,
    /// [`QuotaHierarchy`](crate::QuotaHierarchy) 层级形状 / id 唯一性校验
    /// （0.5.0 resource quota hierarchy，§43.2）。
    QuotaHierarchy,
    /// [`QuotaBudget`](crate::QuotaBudget)（0.5.0 quota hierarchy，§43.2；
    /// 全局层必须全量预算）。
    QuotaBudget,
    /// [`QuotaLevel`](crate::QuotaLevel) 字符串解析（0.5.0 quota hierarchy，§43.2）。
    QuotaLevel,
    /// [`BudgetDimension`](crate::BudgetDimension) 字符串解析（0.5.0 quota
    /// hierarchy，§43.2）。
    BudgetDimension,
}

impl fmt::Display for ValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ComponentId => "component-id",
            Self::InstallationId => "installation-id",
            Self::CapabilityId => "capability-id",
            Self::ComponentVersion => "component-version",
            Self::ContentDigest => "content-digest",
            Self::ByteSize => "byte-size",
            Self::Duration => "duration",
            Self::Deadline => "deadline",
            Self::ArtifactPath => "artifact-path",
            Self::LifecycleState => "lifecycle-state",
            Self::LifecycleEvent => "lifecycle-event",
            Self::ProviderId => "provider-id",
            Self::PackageName => "package-name",
            Self::InterfaceName => "interface-name",
            Self::InterfaceId => "interface-id",
            Self::InterfaceRequirement => "interface-requirement",
            Self::StateKey => "state-key",
            Self::StateValue => "state-value",
            Self::ConfigFormat => "config-format",
            Self::ConfigValue => "config-value",
            Self::SecretName => "secret-name",
            Self::UtcInstant => "utc-instant",
            Self::TaskState => "task-state",
            Self::EventTopic => "event-topic",
            Self::EventPayload => "event-payload",
            Self::PageId => "page-id",
            Self::PagePath => "page-path",
            Self::AssetPath => "asset-path",
            Self::RouteId => "route-id",
            Self::HttpMethod => "http-method",
            Self::ParamType => "param-type",
            Self::RouteParam => "route-param",
            Self::ParamValue => "param-value",
            Self::TypedParam => "typed-param",
            Self::PermissionName => "permission-name",
            Self::RoleId => "role-id",
            Self::RoleName => "role-name",
            Self::GroupId => "group-id",
            Self::UserId => "user-id",
            Self::PermissionAction => "permission-action",
            Self::Role => "role",
            Self::NetworkScheme => "network-scheme",
            Self::HostName => "host-name",
            Self::FileSystemPath => "filesystem-path",
            Self::PolicySnapshot => "policy-snapshot",
            Self::PolicyDiff => "policy-diff",
            Self::PolicyChain => "policy-chain",
            Self::PolicyChainLayer => "policy-chain-layer",
            Self::PolicyDecision => "policy-decision",
            Self::QuotaHierarchy => "quota-hierarchy",
            Self::QuotaBudget => "quota-budget",
            Self::QuotaLevel => "quota-level",
            Self::BudgetDimension => "budget-dimension",
        };
        f.write_str(s)
    }
}
