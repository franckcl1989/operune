//! 0.5.0 Security & Governance（§43.2）——complete RBAC roles/groups 与
//! Root Admin/Operator separation。
//!
//! 契约语义（§5.1：身份认证、平台级 RBAC、Root Admin 属于 Core 必须拥有；
//! §43.2 complete RBAC roles/groups / Root Admin-Operator separation /
//! fine-grained Component administration permissions）：
//!
//! - [`Role`] = 稳定 id + 展示名 + 权限集合（[`PermissionGrant`] 列表）；
//!   [`PermissionGrant`] 是 **资源 + 动作 + scope** 三元组——scope 维度
//!   复用 [`PolicyScope`](crate::PolicyScope)（§17.3 资源级 scope 词汇表，
//!   非 boolean，见 `policy.rs`）；
//! - [`Group`] = 用户集合 + 角色引用集合（用户经组获得角色）；
//!   [`GroupId`] 同时是 quota hierarchy（`quota.rs`）组层节点的键；
//! - **Root Admin/Operator separation**（§43.2）：[`Role::root_admin`] 是
//!   不可移除、不可降权的平台内建角色（本模块注释即平台不变量声明，storage
//!   层必须拒绝删除/修改 `root-admin` 角色与 `Root Admin` 用户）；
//!   [`Role::operator`] 提供日常运维的非破坏性默认权限集（可裁剪，least
//!   privilege §17.4）；
//! - 权限判定（[`Role::permits`]）在**角色层面**求值：`All` 资源 / `All`
//!   scope 是显式通配形态；用户 → 组 → 角色 → 权限的聚合求值是
//!   application / security 层的职责（本模块只提供单一角色的确定性判定）。
//!
//! 全部身份类型 validate-on-construct（§13.3）；`Role` 的权限集合不变量
//! （非空、无重复）由构造保证（§13.4 不合法状态不可表示）。

use std::collections::BTreeSet;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::{DomainError, ValueKind};
use crate::id::validate_identifier;
use crate::policy::PolicyScope;
use crate::{CapabilityId, ComponentId, InstallationId};

/// 平台内建 Root Admin 角色的稳定 id（§43.2 Root Admin/Operator separation）。
///
/// 平台不变量：`root-admin` 角色不可被移除、不可被降权（包括其 id 与
/// 权限集合）；由 storage / application 层拒绝对应删除/修改操作。本常量
/// 是内建角色的权威 id（[`Role::root_admin`] 构造使用）。
pub const ROOT_ADMIN_ROLE_ID: &str = "root-admin";

/// 平台内建 Operator 角色的稳定 id（§43.2 Root Admin/Operator separation）。
///
/// Operator 是日常运维角色（非破坏性默认权限集，[`Role::operator`]）；
/// 与 Root Admin 分离：Operator 不拥有安装/卸载/授权/配额/角色管理动作。
pub const OPERATOR_ROLE_ID: &str = "operator";

/// 用户的平台身份（§43.2 RBAC 成员；§5.1 平台级身份认证属于 Core）。
///
/// 与 [`InstallationId`] / [`ProviderId`] / [`ComponentId`] 语义角色不同、
/// 类型不同（§19.4 身份分离精神）；由 Core 在用户管理流程中创建并持久化
/// （§18.3 数据所有权）。
///
/// 底层表示 `uuid::Uuid`（§13.2：持久 ID 用 `uuid::Uuid` 再包一层领域
/// newtype）。任意 `Uuid` 都是合法用户身份，故构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UserId(Uuid);

impl UserId {
    /// 创建新的用户身份（随机 UUID v4）。
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// 从已有 `Uuid` 包装（持久化恢复 / 适配层边界输入，§13.3）。
    pub fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// 底层 `Uuid` 视图（持久化 / 展示）。
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    /// 新用户身份（同 [`UserId::new`]）。
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for UserId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| DomainError::invalid_value(ValueKind::UserId, e.to_string()))
    }
}

impl Serialize for UserId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for UserId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// 标识符类
// ---------------------------------------------------------------------------

/// 组身份（§43.2 RBAC groups；同时是 quota hierarchy 组层节点的键，
/// `quota.rs`）。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制字符。
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GroupId(String);

impl GroupId {
    /// 从管理边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::GroupId)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；比较语义是字符串等价）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for GroupId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for GroupId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for GroupId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 角色身份（§43.2 RBAC roles 的稳定逻辑键；引用与持久化使用）。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制字符。
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleId(String);

impl RoleId {
    /// 从管理边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::RoleId)?;
        Ok(Self(value))
    }

    /// 从已验证的静态字符串构造（仅限平台内建角色常量，见
    /// [`ROOT_ADMIN_ROLE_ID`] / [`OPERATOR_ROLE_ID`]；公开构造路径
    /// [`RoleId::new`] 已保证不变量，本路径的常量由构造语义保证合法）。
    pub(crate) fn from_static(value: &'static str) -> Self {
        Self(value.to_string())
    }

    /// 原始字符串视图（只读；比较语义是字符串等价）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RoleId {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for RoleId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RoleId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 角色展示名（§43.2 RBAC roles；人类可读，非逻辑键——逻辑键是
/// [`RoleId`]）。
///
/// 不变量（validate-on-construct，§13.3）：非空、≤ 255 字节、不含控制字符。
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RoleName(String);

impl RoleName {
    /// 从管理边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_identifier(&value, ValueKind::RoleName)?;
        Ok(Self(value))
    }

    /// 从已验证的静态字符串构造（仅限平台内建角色展示名）。
    pub(crate) fn from_static(value: &'static str) -> Self {
        Self(value.to_string())
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RoleName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for RoleName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for RoleName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// 权限词汇表（§43.2 fine-grained Component administration permissions）
// ---------------------------------------------------------------------------

/// 权限的资源维度（作用对象，§43.2 fine-grained Component administration
/// permissions 的"资源"）。
///
/// - [`PermissionResource::All`]：全部资源（Root Admin 全量授权的显式形态）；
/// - [`PermissionResource::Platform`]：平台级资源（平台配置、用户/角色
///   管理、审计、配额等无组件归属的治理对象）；
/// - [`PermissionResource::Component`]：逻辑组件（§19.4 ComponentId——
///   该逻辑组件的**所有**安装实例）；
/// - [`PermissionResource::Installation`]：单个安装实例（§19.4
///   InstallationId）；
/// - [`PermissionResource::Capability`]：能力类别（§17 CapabilityId——
///   管理该能力的授权 / scope）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PermissionResource {
    /// 全部资源（仅 Root Admin 使用；显式全量形态）。
    All,
    /// 平台级资源（全局配置、用户/角色/组管理、审计、配额）。
    Platform,
    /// 一个逻辑组件（该逻辑组件的所有安装实例）。
    Component(ComponentId),
    /// 一个安装实例。
    Installation(InstallationId),
    /// 一类能力（§17）。
    Capability(CapabilityId),
}

impl fmt::Display for PermissionResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Platform => write!(f, "platform"),
            Self::Component(id) => write!(f, "component {id}"),
            Self::Installation(id) => write!(f, "installation {id}"),
            Self::Capability(id) => write!(f, "capability {id}"),
        }
    }
}

/// 权限动作闭集（§43.2 fine-grained Component administration permissions）。
///
/// 按治理面分组：
/// - **组件管理**：Install / Enable / Disable / Remove / Upgrade / Rollback；
/// - **能力治理**（§17.5 Grant 层）：Grant（授权/撤销能力 grant 与 scope）；
/// - **配置**：Config（管理组件配置，§41.2 config 是管理员写入的输入）；
/// - **审计**：AuditView（查看安全/审计记录，§43.2 audit query）；
/// - **资源治理**：Quota（管理资源配额，§43.2 quota hierarchy）；
/// - **RBAC 治理**：ManageUsers（用户与组）、ManageRoles（角色）。
///
/// 闭集之外的动作不存在（§6.3 enum 表达闭集）；每次扩展必须走版本演进，
/// 不得在适配层"借用"现有变体表达新语义。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionAction {
    /// 安装组件。
    Install,
    /// 启用安装实例。
    Enable,
    /// 停用安装实例。
    Disable,
    /// 卸载组件（移除安装实例）。
    Remove,
    /// 升级到新版本。
    Upgrade,
    /// 回滚到旧版本。
    Rollback,
    /// 管理能力授权（grant / 撤销 / 修改 scope）。
    Grant,
    /// 管理组件配置。
    Config,
    /// 查看安全 / 审计记录。
    AuditView,
    /// 管理资源配额。
    Quota,
    /// 管理用户与组。
    ManageUsers,
    /// 管理角色。
    ManageRoles,
}

impl PermissionAction {
    /// 与变体一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Enable => "enable",
            Self::Disable => "disable",
            Self::Remove => "remove",
            Self::Upgrade => "upgrade",
            Self::Rollback => "rollback",
            Self::Grant => "grant",
            Self::Config => "config",
            Self::AuditView => "audit-view",
            Self::Quota => "quota",
            Self::ManageUsers => "manage-users",
            Self::ManageRoles => "manage-roles",
        }
    }

    /// 从字符串解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集之外
    /// 的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "install" => Ok(Self::Install),
            "enable" => Ok(Self::Enable),
            "disable" => Ok(Self::Disable),
            "remove" => Ok(Self::Remove),
            "upgrade" => Ok(Self::Upgrade),
            "rollback" => Ok(Self::Rollback),
            "grant" => Ok(Self::Grant),
            "config" => Ok(Self::Config),
            "audit-view" => Ok(Self::AuditView),
            "quota" => Ok(Self::Quota),
            "manage-users" => Ok(Self::ManageUsers),
            "manage-roles" => Ok(Self::ManageRoles),
            _ => Err(DomainError::invalid_value(
                ValueKind::PermissionAction,
                format!(
                    "{s:?} is not a permission-action variant (install | enable | disable | remove | upgrade | rollback | grant | config | audit-view | quota | manage-users | manage-roles)"
                ),
            )),
        }
    }

    /// 全部动作变体（内建 Root Admin 全量授权的枚举面；顺序固定）。
    pub const fn all() -> [PermissionAction; 12] {
        [
            Self::Install,
            Self::Enable,
            Self::Disable,
            Self::Remove,
            Self::Upgrade,
            Self::Rollback,
            Self::Grant,
            Self::Config,
            Self::AuditView,
            Self::Quota,
            Self::ManageUsers,
            Self::ManageRoles,
        ]
    }
}

impl fmt::Display for PermissionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PermissionAction {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for PermissionAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for PermissionAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 单个权限条目：资源 + 动作 + scope（§43.2 fine-grained Component
/// administration permissions 的条目形态）。
///
/// scope 维度复用 [`PolicyScope`]（§17.3 资源级 scope 词汇表）——权限
/// 是资源级 scope 而非 boolean：例如
/// `Grant + Capability(operune:secret/read) + Secret("db-password")` 表示
/// "可以授予 `db-password` 这一 secret 名称的读取授权"；
/// `Enable + Component("my-app") + All` 表示"可以启用 my-app 的全部安装
/// 实例"。scope 与资源是否语义匹配（如对 Install 动作使用 Secret scope）
/// 由 application 层策略校验，本类型表达结构形态。
///
/// 构造不可失败（各字段在自身构造时已校验，§13.3）；集合级不变量（角色内
/// 无重复条目）由 [`Role::new`] 保证。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PermissionGrant {
    resource: PermissionResource,
    action: PermissionAction,
    scope: PolicyScope,
}

impl PermissionGrant {
    /// 构造权限条目（§13.3 边界解析一次）。
    pub fn new(resource: PermissionResource, action: PermissionAction, scope: PolicyScope) -> Self {
        Self {
            resource,
            action,
            scope,
        }
    }

    /// 权限的资源维度（作用对象）。
    pub fn resource(&self) -> &PermissionResource {
        &self.resource
    }

    /// 权限动作。
    pub const fn action(&self) -> PermissionAction {
        self.action
    }

    /// 权限的 scope 维度（§17.3 资源级 scope，非 boolean）。
    pub fn scope(&self) -> &PolicyScope {
        &self.scope
    }
}

impl fmt::Display for PermissionGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.action, self.resource, self.scope)
    }
}

// ---------------------------------------------------------------------------
// 角色 / 组
// ---------------------------------------------------------------------------

/// 平台角色（§43.2 complete RBAC roles）：稳定 id + 展示名 + 权限集合。
///
/// 不变量（构造保证，§13.4）：
/// - 权限集合**非空**（无权限的角色是不合法配置——角色必须授予至少一个
///   权限条目）；
/// - 权限集合**无重复条目**（同一 `(resource, action, scope)` 只出现一次；
///   重复授予是配置错误而非"增强授权"）。
///
/// 内建角色（§43.2 Root Admin/Operator separation）：
/// - [`Role::root_admin`]：全量权限（全部动作 × 全部资源 × All scope），
///   id 固定为 [`ROOT_ADMIN_ROLE_ID`]，**不可移除、不可降权**（平台不变量，
///   storage 层必须拒绝删除/修改）；
/// - [`Role::operator`]：日常运维的非破坏性默认权限集（Enable / Disable /
///   Config / AuditView），id 固定为 [`OPERATOR_ROLE_ID`]；Operator 默认集
///   可被管理员裁剪（least privilege，§17.4），但与 Root Admin 的分离是
///   平台语义（Operator 永不隐含安装/卸载/授权/角色管理）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Role {
    id: RoleId,
    name: RoleName,
    grants: Vec<PermissionGrant>,
}

impl Role {
    /// 构造角色并校验权限集合不变量（§13.3 边界解析一次）。
    pub fn new(
        id: RoleId,
        name: RoleName,
        grants: Vec<PermissionGrant>,
    ) -> Result<Self, DomainError> {
        if grants.is_empty() {
            return Err(DomainError::invalid_value(
                ValueKind::Role,
                format!("role {id} must grant at least one permission"),
            ));
        }
        let mut seen = BTreeSet::new();
        for grant in &grants {
            if !seen.insert(grant) {
                return Err(DomainError::invalid_value(
                    ValueKind::Role,
                    format!("role {id} grants {grant} more than once"),
                ));
            }
        }
        Ok(Self::from_validated(id, name, grants))
    }

    /// 从不变量已成立的字段构造（内部；公开路径 [`Role::new`] 已校验）。
    fn from_validated(id: RoleId, name: RoleName, grants: Vec<PermissionGrant>) -> Self {
        Self { id, name, grants }
    }

    /// 平台内建 Root Admin 角色（§43.2 Root Admin/Operator separation）。
    ///
    /// 全量权限：全部动作 × [`PermissionResource::All`] ×
    /// [`PolicyScope::All`]。平台不变量：**不可移除、不可降权**——本角色
    /// 与 `Root Admin` 用户一起构成 §16 Root Admin 安全基线的管理主体；
    /// storage 层必须拒绝删除 `root-admin` 角色或修改其权限集合。
    ///
    /// 构造不可失败（常量与闭集保证合法性，§13.3）。
    pub fn root_admin() -> Self {
        let grants = PermissionAction::all()
            .into_iter()
            .map(|action| PermissionGrant::new(PermissionResource::All, action, PolicyScope::All))
            .collect();
        // 内建常量经公开构造路径校验（"root-admin" 是合法标识符，闭集非空
        // 且无重复）；经 from_validated 直接构造避免把"不可能的错误"泄漏
        // 为 Result（§13.4 不变量；§14.2 无 panic 路径）。
        Self::from_validated(
            RoleId::from_static(ROOT_ADMIN_ROLE_ID),
            RoleName::from_static("Root Admin"),
            grants,
        )
    }

    /// 平台内建 Operator 角色（§43.2 Root Admin/Operator separation）。
    ///
    /// 默认权限集（日常运维、非破坏性，least privilege §17.4）：
    /// Enable / Disable / Config / AuditView × [`PermissionResource::All`]
    /// × [`PolicyScope::All`]。Operator **不**拥有 Install / Remove /
    /// Upgrade / Rollback / Grant / Quota / ManageUsers / ManageRoles——
    /// 破坏性与治理动作保留给 Root Admin（或管理员显式扩展的自定义角色）。
    ///
    /// 默认集可被管理员裁剪（自定义角色的 Operator 变体）；内建
    /// `operator` 角色本身与 Root Admin 的分离是平台语义。
    ///
    /// 构造不可失败（常量与闭集保证合法性，§13.3）。
    pub fn operator() -> Self {
        let grants = [
            PermissionAction::Enable,
            PermissionAction::Disable,
            PermissionAction::Config,
            PermissionAction::AuditView,
        ]
        .into_iter()
        .map(|action| PermissionGrant::new(PermissionResource::All, action, PolicyScope::All))
        .collect();
        // 同上：常量与闭集保证不变量，无错误路径（§14.2）。
        Self::from_validated(
            RoleId::from_static(OPERATOR_ROLE_ID),
            RoleName::from_static("Operator"),
            grants,
        )
    }

    /// 角色稳定 id（逻辑键）。
    pub fn id(&self) -> &RoleId {
        &self.id
    }

    /// 角色展示名（人类可读，非逻辑键）。
    pub fn name(&self) -> &RoleName {
        &self.name
    }

    /// 权限条目集合（只读，按声明顺序）。
    pub fn grants(&self) -> &[PermissionGrant] {
        &self.grants
    }

    /// 是否为平台内建 Root Admin（id == [`ROOT_ADMIN_ROLE_ID`]）。
    pub fn is_root_admin(&self) -> bool {
        self.id.as_str() == ROOT_ADMIN_ROLE_ID
    }

    /// 是否为平台内建 Operator（id == [`OPERATOR_ROLE_ID`]）。
    pub fn is_operator(&self) -> bool {
        self.id.as_str() == OPERATOR_ROLE_ID
    }

    /// 角色级权限判定（确定性）：存在任一权限条目匹配 `action`，且
    /// 资源匹配（条目资源为 `All` 或等于 `resource`），且 scope 匹配
    /// （条目 scope 为 `All` 或等于 `scope`）。
    ///
    /// 用户 → 组 → 角色 → 权限的聚合求值是 application / security 层职责
    /// （本方法只回答"该角色是否允许此请求"）。
    pub fn permits(
        &self,
        resource: &PermissionResource,
        action: PermissionAction,
        scope: &PolicyScope,
    ) -> bool {
        self.grants.iter().any(|grant| {
            grant.action() == action
                && (grant.resource() == &PermissionResource::All || grant.resource() == resource)
                && (grant.scope() == &PolicyScope::All || grant.scope() == scope)
        })
    }
}

impl<'de> Deserialize<'de> for Role {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            id: RoleId,
            name: RoleName,
            grants: Vec<PermissionGrant>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.id, wire.name, wire.grants).map_err(serde::de::Error::custom)
    }
}

/// 用户组（§43.2 complete RBAC groups）：组 = 用户集合 + 角色引用集合。
///
/// 语义：用户经组成员关系获得组的角色（角色 → 权限的解析由 application /
/// security 层执行）；组 id 同时是 quota hierarchy 组层节点的键
/// （`quota.rs`，同 §43.2 quota 与 RBAC 的"组"是同一治理实体）。
///
/// 成员 / 角色集合可以为空（空组是合法的惰性容器——管理员逐步添加成员 /
/// 角色；无成员或无角色的组不授予任何权限，deny-by-default §17.2）。
///
/// 构造不可失败（id 在自身构造时已校验，§13.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    id: GroupId,
    members: BTreeSet<UserId>,
    roles: BTreeSet<RoleId>,
}

impl Group {
    /// 构造用户组（§13.3 边界解析一次）。
    pub fn new(id: GroupId, members: BTreeSet<UserId>, roles: BTreeSet<RoleId>) -> Self {
        Self { id, members, roles }
    }

    /// 组身份（quota hierarchy 组层节点的键）。
    pub fn id(&self) -> &GroupId {
        &self.id
    }

    /// 成员用户集合（只读）。
    pub fn members(&self) -> &BTreeSet<UserId> {
        &self.members
    }

    /// 角色引用集合（只读；角色解析由 application / security 层执行）。
    pub fn roles(&self) -> &BTreeSet<RoleId> {
        &self.roles
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretName;
    use crate::test_support::ok;

    fn role_id(value: &str) -> RoleId {
        ok(RoleId::new(value), "role-id")
    }

    fn role_name(value: &str) -> RoleName {
        ok(RoleName::new(value), "role-name")
    }

    fn group_id(value: &str) -> GroupId {
        ok(GroupId::new(value), "group-id")
    }

    fn capability(value: &str) -> CapabilityId {
        ok(CapabilityId::new(value), "capability-id")
    }

    fn component(value: &str) -> ComponentId {
        ok(ComponentId::new(value), "component-id")
    }

    fn grant(
        resource: PermissionResource,
        action: PermissionAction,
        scope: PolicyScope,
    ) -> PermissionGrant {
        PermissionGrant::new(resource, action, scope)
    }

    // ---- UserId ----

    #[test]
    fn user_id_new_is_random_unique() {
        assert_ne!(UserId::new(), UserId::new());
    }

    #[test]
    fn user_id_parse_roundtrip() {
        let user = UserId::new();
        assert_eq!(user.to_string().parse::<UserId>(), Ok(user));
        assert!(matches!(
            "not-a-uuid".parse::<UserId>(),
            Err(DomainError::InvalidValue {
                kind: ValueKind::UserId,
                ..
            })
        ));
        let json = ok(serde_json::to_string(&user), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<UserId>(&json), "deserialize"),
            user
        );
    }

    // ---- 标识符 ----

    #[test]
    fn role_id_role_name_group_id_validate() {
        for value in ["ops", "component-admin", "组-1", "A", "0"] {
            assert!(RoleId::new(value).is_ok(), "role-id {value:?}");
            assert!(RoleName::new(value).is_ok(), "role-name {value:?}");
            assert!(GroupId::new(value).is_ok(), "group-id {value:?}");
        }
        for bad in ["", &"x".repeat(256), "a\nb", "a\u{0}b"] {
            assert!(
                matches!(
                    RoleId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::RoleId,
                        ..
                    })
                ),
                "role-id {bad:?} must be rejected"
            );
            assert!(
                matches!(
                    RoleName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::RoleName,
                        ..
                    })
                ),
                "role-name {bad:?} must be rejected"
            );
            assert!(
                matches!(
                    GroupId::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::GroupId,
                        ..
                    })
                ),
                "group-id {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn identifiers_roundtrip() {
        let id = role_id("ops");
        assert_eq!(id.to_string(), "ops");
        assert_eq!("ops".parse::<RoleId>(), Ok(id.clone()));
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "\"ops\"");
        assert_eq!(ok(serde_json::from_str::<RoleId>(&json), "deserialize"), id);

        let name = role_name("Operator");
        assert_eq!(name.as_str(), "Operator");
        let group = group_id("platform-ops");
        assert_eq!(group.as_str(), "platform-ops");
        assert_eq!(
            ok(
                serde_json::from_str::<GroupId>(&ok(serde_json::to_string(&group), "serialize")),
                "deserialize"
            ),
            group
        );
    }

    // ---- PermissionAction ----

    #[test]
    fn permission_action_closed_set() {
        for (action, name) in [
            (PermissionAction::Install, "install"),
            (PermissionAction::Enable, "enable"),
            (PermissionAction::Disable, "disable"),
            (PermissionAction::Remove, "remove"),
            (PermissionAction::Upgrade, "upgrade"),
            (PermissionAction::Rollback, "rollback"),
            (PermissionAction::Grant, "grant"),
            (PermissionAction::Config, "config"),
            (PermissionAction::AuditView, "audit-view"),
            (PermissionAction::Quota, "quota"),
            (PermissionAction::ManageUsers, "manage-users"),
            (PermissionAction::ManageRoles, "manage-roles"),
        ] {
            assert_eq!(name.parse::<PermissionAction>(), Ok(action));
            assert_eq!(action.to_string(), name);
            let json = ok(serde_json::to_string(&action), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(
                    serde_json::from_str::<PermissionAction>(&json),
                    "deserialize"
                ),
                action
            );
        }
        for bad in ["", "VIEW", "execute", "install ", "start"] {
            assert!(
                matches!(
                    bad.parse::<PermissionAction>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::PermissionAction,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
    }

    #[test]
    fn permission_action_all_covers_every_variant() {
        // `all()` 必须恰好覆盖全部 12 个变体（内建 Root Admin 授权面）。
        assert_eq!(PermissionAction::all().len(), 12);
        let mut covered = BTreeSet::new();
        for action in PermissionAction::all() {
            covered.insert(action);
        }
        assert_eq!(covered.len(), 12, "variants must be distinct");
    }

    // ---- PermissionGrant ----

    #[test]
    fn permission_grant_fields_and_serde() {
        let declared = grant(
            PermissionResource::Capability(capability("operune:secret/read")),
            PermissionAction::Grant,
            PolicyScope::Secret(ok(SecretName::new("db-password"), "secret-name")),
        );
        assert_eq!(
            declared.resource(),
            &PermissionResource::Capability(capability("operune:secret/read"))
        );
        assert_eq!(declared.action(), PermissionAction::Grant);
        assert_eq!(
            declared.scope(),
            &PolicyScope::Secret(ok(SecretName::new("db-password"), "secret-name"))
        );
        assert_eq!(
            declared.to_string(),
            "grant capability operune:secret/read secret db-password"
        );
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<PermissionGrant>(&json),
                "deserialize"
            ),
            declared
        );
    }

    // ---- Role ----

    #[test]
    fn role_accepts_non_empty_distinct_grants() {
        let role = ok(
            Role::new(
                role_id("component-admin"),
                role_name("Component Admin"),
                vec![
                    grant(
                        PermissionResource::All,
                        PermissionAction::Enable,
                        PolicyScope::All,
                    ),
                    grant(
                        PermissionResource::All,
                        PermissionAction::Config,
                        PolicyScope::All,
                    ),
                ],
            ),
            "role",
        );
        assert_eq!(role.id(), &role_id("component-admin"));
        assert_eq!(role.name(), &role_name("Component Admin"));
        assert_eq!(role.grants().len(), 2);
        assert!(!role.is_root_admin());
        assert!(!role.is_operator());
    }

    #[test]
    fn role_rejects_empty_grants() {
        assert!(matches!(
            Role::new(role_id("empty-role"), role_name("Empty"), vec![]),
            Err(DomainError::InvalidValue {
                kind: ValueKind::Role,
                ..
            })
        ));
    }

    #[test]
    fn role_rejects_duplicate_grants() {
        let duplicate = Role::new(
            role_id("dup-role"),
            role_name("Duplicate"),
            vec![
                grant(
                    PermissionResource::All,
                    PermissionAction::Enable,
                    PolicyScope::All,
                ),
                grant(
                    PermissionResource::All,
                    PermissionAction::Enable,
                    PolicyScope::All,
                ),
            ],
        );
        assert!(matches!(
            duplicate,
            Err(DomainError::InvalidValue {
                kind: ValueKind::Role,
                ..
            })
        ));
        // 相同动作不同 scope：不是重复条目。
        assert!(
            Role::new(
                role_id("scoped-role"),
                role_name("Scoped"),
                vec![
                    grant(
                        PermissionResource::All,
                        PermissionAction::Grant,
                        PolicyScope::Secret(ok(SecretName::new("a"), "a")),
                    ),
                    grant(
                        PermissionResource::All,
                        PermissionAction::Grant,
                        PolicyScope::Secret(ok(SecretName::new("b"), "b")),
                    ),
                ],
            )
            .is_ok()
        );
    }

    #[test]
    fn role_permits_matches_action_resource_scope() {
        let role = ok(
            Role::new(
                role_id("ops"),
                role_name("Ops"),
                vec![
                    // 指定组件：只对该组件生效。
                    grant(
                        PermissionResource::Component(component("my-app")),
                        PermissionAction::Disable,
                        PolicyScope::All,
                    ),
                    // All 资源 × 指定 scope：该 secret 的 grant 管理。
                    grant(
                        PermissionResource::All,
                        PermissionAction::Grant,
                        PolicyScope::Secret(ok(SecretName::new("db-password"), "db")),
                    ),
                ],
            ),
            "role",
        );
        assert!(role.permits(
            &PermissionResource::Component(component("my-app")),
            PermissionAction::Disable,
            &PolicyScope::All
        ));
        // 指定组件之外的组件：拒绝。
        assert!(!role.permits(
            &PermissionResource::Component(component("other-app")),
            PermissionAction::Disable,
            &PolicyScope::All
        ));
        // 动作不符：拒绝。
        assert!(!role.permits(
            &PermissionResource::Component(component("my-app")),
            PermissionAction::Remove,
            &PolicyScope::All
        ));
        // scope 匹配（All 资源通配）：允许。
        assert!(role.permits(
            &PermissionResource::Capability(capability("operune:secret/read")),
            PermissionAction::Grant,
            &PolicyScope::Secret(ok(SecretName::new("db-password"), "db")),
        ));
        // scope 不符：拒绝。
        assert!(!role.permits(
            &PermissionResource::Capability(capability("operune:secret/read")),
            PermissionAction::Grant,
            &PolicyScope::Secret(ok(SecretName::new("other"), "other")),
        ));
    }

    #[test]
    fn role_root_admin_is_omnipotent_and_immutable_semantics() {
        let root = Role::root_admin();
        assert!(root.is_root_admin());
        assert_eq!(root.id().as_str(), ROOT_ADMIN_ROLE_ID);
        assert_eq!(root.grants().len(), 12);
        // Root Admin 允许任意资源 × 任意动作 × 任意 scope。
        for action in PermissionAction::all() {
            assert!(
                root.permits(
                    &PermissionResource::Installation(InstallationId::new()),
                    action,
                    &PolicyScope::All,
                ),
                "root-admin must permit {action}"
            );
            assert!(
                root.permits(
                    &PermissionResource::Platform,
                    action,
                    &PolicyScope::Secret(ok(SecretName::new("any"), "any")),
                ),
                "root-admin must permit {action} with any scope"
            );
        }
        // 不可移除/降权语义：本模块声明的平台不变量（storage 层拒绝删除/
        // 修改 root-admin）；Root Admin 与 Operator 必须分离。
        assert_ne!(root.id(), Role::operator().id());
        assert!(!Role::operator().is_root_admin());
    }

    #[test]
    fn role_operator_has_non_destructive_default_set() {
        let operator = Role::operator();
        assert!(operator.is_operator());
        assert_eq!(operator.id().as_str(), OPERATOR_ROLE_ID);
        // 默认集：Enable / Disable / Config / AuditView。
        for action in [
            PermissionAction::Enable,
            PermissionAction::Disable,
            PermissionAction::Config,
            PermissionAction::AuditView,
        ] {
            assert!(
                operator.permits(
                    &PermissionResource::Component(component("any")),
                    action,
                    &PolicyScope::All,
                ),
                "operator default set must permit {action}"
            );
        }
        // 破坏性与治理动作不在 Operator 默认集（§43.2 separation）。
        for action in [
            PermissionAction::Install,
            PermissionAction::Remove,
            PermissionAction::Upgrade,
            PermissionAction::Rollback,
            PermissionAction::Grant,
            PermissionAction::Quota,
            PermissionAction::ManageUsers,
            PermissionAction::ManageRoles,
        ] {
            assert!(
                !operator.permits(&PermissionResource::All, action, &PolicyScope::All),
                "operator default set must NOT permit {action}"
            );
        }
    }

    #[test]
    fn role_serde_roundtrip() {
        let role = ok(
            Role::new(
                role_id("component-admin"),
                role_name("Component Admin"),
                vec![grant(
                    PermissionResource::All,
                    PermissionAction::Enable,
                    PolicyScope::All,
                )],
            ),
            "role",
        );
        let json = ok(serde_json::to_string(&role), "serialize");
        assert_eq!(ok(serde_json::from_str::<Role>(&json), "deserialize"), role);
        // 反序列化边界同样执行不变量校验（§13.3）：空权限集合拒绝。
        let empty = r#"{"id": "empty-role", "name": "Empty", "grants": []}"#;
        assert!(serde_json::from_str::<Role>(empty).is_err());
    }

    // ---- Group ----

    #[test]
    fn group_carries_members_and_roles() {
        let user_a = UserId::new();
        let user_b = UserId::new();
        let members: BTreeSet<UserId> = [user_a, user_b].into_iter().collect();
        let roles: BTreeSet<RoleId> = [role_id("ops"), role_id("component-admin")]
            .into_iter()
            .collect();
        let group = Group::new(group_id("platform-ops"), members, roles);
        assert_eq!(group.id(), &group_id("platform-ops"));
        assert_eq!(group.members().len(), 2);
        assert!(group.members().contains(&user_a));
        assert!(group.roles().contains(&role_id("ops")));
        // 空组是合法惰性容器（不授予任何权限，deny-by-default）。
        let empty = Group::new(group_id("empty"), BTreeSet::new(), BTreeSet::new());
        assert!(empty.members().is_empty() && empty.roles().is_empty());
        let json = ok(serde_json::to_string(&group), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<Group>(&json), "deserialize"),
            group
        );
    }
}
