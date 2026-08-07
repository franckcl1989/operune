//! 0.5.0 Security & Governance（§43.2）——scoped capability policies 与
//! policy snapshot/versioning。
//!
//! 契约语义（§43.2 scoped capability policies / policy snapshot/versioning；
//! §17 Capability 安全模型）：
//!
//! - **CapabilityPolicy 是平台级策略**（"能力 X 在哪些 scope 内可用"，§17.3
//!   资源级 scope，不是 boolean）；per-installation 的授权绑定（§17.1 /
//!   §17.5 Grant 的 durable owner 是 InstallationId）由 application /
//!   security 层依据本策略与 grant store 求值，Domain 不建模 grant store；
//! - **scope 词汇表**（[`PolicyScope`]）是 17.3 六维 scope 的领域闭集：
//!   network host/port/scheme、filesystem preopened path + 读写模式、
//!   secret names、event topics、provider identity/version，外加唯一的
//!   显式全量形态 [`PolicyScope::All`]（deny-by-default §17.2 下谨慎使用）；
//! - **快照不可变**（§15.5 read-mostly snapshot 精神）：[`PolicySnapshot`]
//!   无任何修改方法；新策略只能通过 `new_after` 生成**更高版本**的快照
//!   （§43.2 policy snapshot/versioning），版本号 u64 单调递增（§43.2；
//!   §14.4 溢出即错误，不回绕）；
//! - 授权撤销、scope 变化必须以确定的 snapshot/version 语义生效（§17.5：
//!   不得依赖 Component 自觉遵守），本类型的版本语义即该确定的生效面。

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::web::validate_mount_path;
use crate::{CapabilityId, EventTopic, InterfaceId, SecretName, UtcInstant};

/// host name 长度上界（字节）。结构性上界：DNS 全限定名最大 253 字节
/// （RFC 1035），策略 scope 的 host 字段沿用（§19.1 输入不可信）。
pub(crate) const MAX_HOST_NAME_LEN: usize = 253;

// ---------------------------------------------------------------------------
// §17.3 资源级 scope 词汇表
// ---------------------------------------------------------------------------

/// 网络 scheme 闭集（§17.3 "network host/port/scheme" 的 scheme 维度；
/// wasi 0.3 网络边界：tcp/udp socket + http 之上的应用层协议）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetworkScheme {
    /// `http`
    Http,
    /// `https`
    Https,
    /// `tcp`
    Tcp,
    /// `udp`
    Udp,
}

impl NetworkScheme {
    /// 与变体一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// 从字符串解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集之外
    /// 的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(DomainError::invalid_value(
                ValueKind::NetworkScheme,
                format!("{s:?} is not a network-scheme variant (http | https | tcp | udp)"),
            )),
        }
    }
}

impl fmt::Display for NetworkScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkScheme {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for NetworkScheme {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for NetworkScheme {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 策略 scope 中的 host 名（§17.3 "network host/port/scheme" 的 host 维度）。
///
/// 支持唯一的通配形态：前导 `*.`（如 `*.example.com`，匹配该域任意子域）；
/// 除此之外仅允许 ASCII 字母 / 数字 / `.` / `-`（RFC 1035 host name 字符集）。
///
/// 不变量（validate-on-construct，§13.3）：
/// - 非空，≤ [`MAX_HOST_NAME_LEN`] 字节；
/// - `*` 只允许作为前导 `*.` 通配前缀，且其后必须有非空 host 名；
/// - 不允许前导 / 尾随 `.` 与连续 `..`（无空标签）；
/// - 不含控制字符（字符集白名单即拒绝，§14.2 日志注入防护）。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// 从策略边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_host_name(&value)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 是否带 `*.` 通配前缀。
    pub fn is_wildcard(&self) -> bool {
        self.0.starts_with("*.")
    }
}

/// [`HostName`] 的结构性校验（见类型文档）。
fn validate_host_name(value: &str) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            "must not be empty",
        ));
    }
    if value.len() > MAX_HOST_NAME_LEN {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            format!("must not exceed {MAX_HOST_NAME_LEN} bytes"),
        ));
    }
    if value.contains('*') && !value.starts_with("*.") {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            "'*' is only allowed as a leading '*.' wildcard prefix",
        ));
    }
    let rest = value.strip_prefix("*.").unwrap_or(value);
    if rest.is_empty() {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            "wildcard prefix '*.' must be followed by a host name",
        ));
    }
    let all_allowed = rest
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-'));
    if !all_allowed {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            "must only contain ASCII letters, digits, '.', or '-' (RFC 1035)",
        ));
    }
    if rest.starts_with('.') || rest.ends_with('.') || rest.contains("..") {
        return Err(DomainError::invalid_value(
            ValueKind::HostName,
            "must not contain empty labels (leading/trailing '.' or '..')",
        ));
    }
    Ok(())
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for HostName {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for HostName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HostName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 策略 scope 中的文件系统 preopened 路径（§17.3 "filesystem preopened path
/// + read/write mode" 的 path 维度）。
///
/// 形态 = 挂载命名空间绝对路径（与 [`PagePath`](crate::PagePath) /
/// [`AssetPath`](crate::AssetPath) 共享 `validate_mount_path` 校验，见
/// `web.rs`）：以 "/" 开头、已规范化（拒绝空段 / "." / ".." 段、反斜杠、
/// 控制字符，fail closed，§32）、≤ 4096 字节。本类型**不限制**模板段字符
/// （"{}"）——文件系统路径没有路由语义。
///
/// 读写模式是 scope 的独立维度（[`PolicyScope::FileSystem`] 的 `read` /
/// `write` 字段），不在路径内编码。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileSystemPath(String);

impl FileSystemPath {
    /// 从策略边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        validate_mount_path(&value, false, ValueKind::FileSystemPath)?;
        Ok(Self(value))
    }

    /// 原始字符串视图（只读；已规范化、以 "/" 开头）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FileSystemPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FileSystemPath {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for FileSystemPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for FileSystemPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// 资源级授权 scope（§17.3 scope 的领域闭集；§43.2 "scoped capability
/// policies" 的 scope 词汇表）。
///
/// §17.3 明文：Capability policy 必须能表达资源级 scope，而不仅是 boolean。
/// 六维词汇 + 唯一显式全量形态：
///
/// - [`PolicyScope::All`]：显式全量（deny-by-default §17.2 下唯一的全量
///   授权形态；只有明确表达"任何 scope"时才使用）；
/// - [`PolicyScope::Secret`]：secret names（复用 [`SecretName`]）；
/// - [`PolicyScope::Event`]：event topics（复用 [`EventTopic`]）；
/// - [`PolicyScope::Network`]：network host/port/scheme；
/// - [`PolicyScope::FileSystem`]：filesystem preopened path + 读写模式；
/// - [`PolicyScope::Provider`]：Component-to-Component provider
///   identity/version 的 interface 维度（复用 [`InterfaceId`]；版本兼容
///   是 resolution 层职责，§17.5 第 2 层）。
///
/// 本类型是**策略条目**（静态声明）；实际请求与 scope 的匹配
/// （invocation-time enforcement，§17.5 第 4 层）由 application / security
/// 层执行。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum PolicyScope {
    /// 显式全量 scope（唯一全量形态；§17.2 deny-by-default 下谨慎使用）。
    All,
    /// 按 secret 名称限定（§17.3 secret names；复用 [`SecretName`]）。
    Secret(SecretName),
    /// 按 event topic 限定（§17.3 event topics；复用 [`EventTopic`]）。
    Event(EventTopic),
    /// 网络端点：scheme + host（支持 `*.` 通配）+ 可选端口（§17.3 network
    /// host/port/scheme）。
    Network {
        /// 协议（http/https/tcp/udp）。
        scheme: NetworkScheme,
        /// host 名（`*.` 通配形态见 [`HostName`]）。
        host: HostName,
        /// 可选端口（`None` = 不限定端口）。
        port: Option<u16>,
    },
    /// 文件系统：preopened 路径 + 读写模式（§17.3 filesystem preopened
    /// path + read/write mode）。
    FileSystem {
        /// preopened 虚拟路径。
        path: FileSystemPath,
        /// 是否允许读。
        read: bool,
        /// 是否允许写。
        write: bool,
    },
    /// 按 provider interface 限定（§17.3 Component-to-Component provider
    /// identity/version 的 interface 维度；复用 [`InterfaceId`]）。
    Provider(InterfaceId),
}

impl fmt::Display for PolicyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "all"),
            Self::Secret(name) => write!(f, "secret {name}"),
            Self::Event(topic) => write!(f, "event {topic}"),
            Self::Network { scheme, host, port } => match port {
                Some(port) => write!(f, "network {scheme}://{host}:{port}"),
                None => write!(f, "network {scheme}://{host}"),
            },
            Self::FileSystem { path, read, write } => {
                let mode = match (*read, *write) {
                    (true, true) => "read-write",
                    (true, false) => "read",
                    (false, true) => "write",
                    (false, false) => "no-access",
                };
                write!(f, "filesystem {path} ({mode})")
            }
            Self::Provider(interface) => write!(f, "provider {interface}"),
        }
    }
}

impl PolicyScope {
    /// 是否为显式全量 scope。
    pub fn is_all(&self) -> bool {
        matches!(self, Self::All)
    }
}

// ---------------------------------------------------------------------------
// scoped capability policy 与 snapshot/versioning
// ---------------------------------------------------------------------------

/// 平台级能力策略（§43.2 scoped capability policies）：能力 + 允许的 scope
/// 集合（§17.3 资源级 scope 形态）。
///
/// 语义：
/// - **平台级声明**（非 per-installation）：能力在哪些 scope 内允许使用；
///   per-installation 的授权绑定是 grant store（application / security）
///   的职责（§17.1：Runtime Grant 表示"这个 InstallationId 被授权在什么
///   范围使用这种能力"）；
/// - 空 `allowed_scopes` = **显式拒绝该能力**（deny-by-default §17.2 的
///   显式形态；与"无策略"（同样 deny）的区别是前者在快照中可见、可审计）；
/// - `allowed_scopes` 含 [`PolicyScope::All`] = 任何 scope 都允许（仅显式
///   配置时才成立）。
///
/// 构造不可失败（字段各自在构造时已校验，§13.3）；同一快照内一个能力至多
/// 一条策略（重复由 [`PolicySnapshot::new`] 拒绝）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityPolicy {
    capability: CapabilityId,
    allowed_scopes: BTreeSet<PolicyScope>,
}

impl CapabilityPolicy {
    /// 构造能力策略（§13.3 边界解析一次；空 scope 集合 = 显式拒绝）。
    pub fn new(capability: CapabilityId, allowed_scopes: BTreeSet<PolicyScope>) -> Self {
        Self {
            capability,
            allowed_scopes,
        }
    }

    /// 能力身份（快照内唯一键）。
    pub fn capability(&self) -> &CapabilityId {
        &self.capability
    }

    /// 允许的 scope 集合（只读；空集 = 显式拒绝）。
    pub fn allowed_scopes(&self) -> &BTreeSet<PolicyScope> {
        &self.allowed_scopes
    }

    /// 该策略是否允许 `scope`（显式包含，或策略含 [`PolicyScope::All`]）。
    pub fn allows(&self, scope: &PolicyScope) -> bool {
        self.allowed_scopes.contains(scope) || self.allowed_scopes.contains(&PolicyScope::All)
    }

    /// 是否显式拒绝（空 scope 集合）。
    pub fn is_explicit_deny(&self) -> bool {
        self.allowed_scopes.is_empty()
    }
}

/// 策略快照版本号（§43.2 policy snapshot/versioning；§17.5 "确定的
/// snapshot/version 语义"）。
///
/// 语义：平台策略快照的单调版本；每次策略变更生成更高版本（
/// [`PolicySnapshot::new_after`]），授权撤销 / scope 变化以版本切换生效。
///
/// 任意 u64 都是合法版本号（持久化恢复），构造不可失败；`next` 使用
/// checked 算术（§14.4，溢出即错误，绝不回绕）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyVersion(u64);

impl PolicyVersion {
    /// 首个策略快照的版本号（1；0 不产生——`from_u64` 仅用于持久化恢复）。
    pub const INITIAL: PolicyVersion = PolicyVersion(1);

    /// 从 u64 构造（持久化恢复 / 适配层边界输入，§13.3；不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// 下一个版本号（checked 递增，§14.4：`u64::MAX` 处溢出即错误）。
    pub fn next(self) -> Result<Self, DomainError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or(DomainError::Overflow {
                operation: "policy-version increment",
            })
    }
}

impl fmt::Display for PolicyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for PolicyVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for PolicyVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 平台能力策略的**不可变快照**（§43.2 policy snapshot/versioning；
/// §15.5 read-mostly snapshot）。
///
/// 不变量（构造保证）：
/// - 同一快照内每个能力至多一条策略（`capability` 键唯一，§13.4 不合法
///   状态不可表示）；
/// - 快照内部以 `BTreeMap` 按键排序存储（确定性迭代，§40.4 精神）；
/// - **无任何修改方法**（§15.5）：新策略只能生成更高版本的新快照
///   （[`PolicySnapshot::new_after`]），授权变更以版本切换生效（§17.5），
///   旧版本快照永久可审计（§43.3）。
///
/// [`PolicySnapshot::new`] 用于持久化恢复 / 边界反序列化（版本可显式
/// 指定）；[`PolicySnapshot::new_after`] 用于策略变更（版本自动 = 前序
/// 快照版本 + 1，**单调性由构造保证**，§43.2 versioning）。
///
/// 错误：重复能力返回 [`DomainError::InvalidValue`]；版本递增溢出返回
/// [`DomainError::Overflow`]。
///
/// 序列化形态：`policies` 以**数组**持久化（按键排序，确定性）——反序列化
/// 边界因此可以复用 [`PolicySnapshot::new`] 的重复能力校验（§13.3）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySnapshot {
    version: PolicyVersion,
    policies: BTreeMap<CapabilityId, CapabilityPolicy>,
    created_at: UtcInstant,
}

impl PolicySnapshot {
    /// 从已校验策略列表构造快照（§13.3 边界解析一次；重复能力拒绝）。
    pub fn new(
        version: PolicyVersion,
        policies: Vec<CapabilityPolicy>,
        created_at: UtcInstant,
    ) -> Result<Self, DomainError> {
        let mut map = BTreeMap::new();
        for policy in policies {
            let key = policy.capability().clone();
            if map.insert(key.clone(), policy).is_some() {
                return Err(DomainError::invalid_value(
                    ValueKind::PolicySnapshot,
                    format!("capability {key} appears in more than one policy of the snapshot"),
                ));
            }
        }
        Ok(Self {
            version,
            policies: map,
            created_at,
        })
    }

    /// 从**前序快照**生成下一版本快照（§43.2 versioning：版本单调）。
    ///
    /// 版本 = `previous.version().next()`——调用方无法指定版本，因此
    /// 版本回退 / 重复**由构造排除**（§13.4 不合法状态不可表示）；旧快照
    /// 保持原样（不可变），审计面保留完整历史。
    pub fn new_after(
        previous: &PolicySnapshot,
        policies: Vec<CapabilityPolicy>,
        created_at: UtcInstant,
    ) -> Result<Self, DomainError> {
        let version = previous.version().next()?;
        Self::new(version, policies, created_at)
    }

    /// 快照版本（版本化语义的生效面，§17.5）。
    pub const fn version(&self) -> PolicyVersion {
        self.version
    }

    /// 快照创建时刻（审计关联）。
    pub const fn created_at(&self) -> UtcInstant {
        self.created_at
    }

    /// 快照内全部策略（按键排序，只读）。
    pub fn policies(&self) -> &BTreeMap<CapabilityId, CapabilityPolicy> {
        &self.policies
    }

    /// 某能力的策略（无策略 = deny-by-default，§17.2）。
    pub fn policy_for(&self, capability: &CapabilityId) -> Option<&CapabilityPolicy> {
        self.policies.get(capability)
    }
}

impl Serialize for PolicySnapshot {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            version: PolicyVersion,
            policies: Vec<&'a CapabilityPolicy>,
            created_at: UtcInstant,
        }
        Wire {
            version: self.version,
            // 按键排序的数组形态（BTreeMap 迭代序即键序，确定性，§40.4）。
            policies: self.policies.values().collect(),
            created_at: self.created_at,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicySnapshot {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            version: PolicyVersion,
            policies: Vec<CapabilityPolicy>,
            created_at: UtcInstant,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.version, wire.policies, wire.created_at).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    fn capability(value: &str) -> CapabilityId {
        ok(CapabilityId::new(value), "capability-id")
    }

    fn instant(seconds: u64) -> UtcInstant {
        ok(UtcInstant::from_unix_parts(seconds, 0), "utc-instant")
    }

    fn secret_scope(name: &str) -> PolicyScope {
        PolicyScope::Secret(ok(SecretName::new(name), "secret-name"))
    }

    fn event_scope(topic: &str) -> PolicyScope {
        PolicyScope::Event(ok(EventTopic::new(topic), "event-topic"))
    }

    fn scopes(items: &[PolicyScope]) -> BTreeSet<PolicyScope> {
        items.iter().cloned().collect()
    }

    fn policy(cap: &str, allowed: BTreeSet<PolicyScope>) -> CapabilityPolicy {
        CapabilityPolicy::new(capability(cap), allowed)
    }

    fn interface_id(value: &str) -> InterfaceId {
        ok(value.parse::<InterfaceId>(), "interface-id")
    }

    fn host(value: &str) -> HostName {
        ok(HostName::new(value), "host-name")
    }

    fn fs_path(value: &str) -> FileSystemPath {
        ok(FileSystemPath::new(value), "filesystem-path")
    }

    // ---- NetworkScheme ----

    #[test]
    fn network_scheme_closed_set() {
        for (scheme, name) in [
            (NetworkScheme::Http, "http"),
            (NetworkScheme::Https, "https"),
            (NetworkScheme::Tcp, "tcp"),
            (NetworkScheme::Udp, "udp"),
        ] {
            assert_eq!(name.parse::<NetworkScheme>(), Ok(scheme));
            assert_eq!(scheme.to_string(), name);
            let json = ok(serde_json::to_string(&scheme), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<NetworkScheme>(&json), "deserialize"),
                scheme
            );
        }
        for bad in ["ftp", "wss", "HTTP", "", "http "] {
            assert!(
                matches!(
                    bad.parse::<NetworkScheme>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::NetworkScheme,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
    }

    // ---- HostName ----

    #[test]
    fn host_name_accepts_valid() {
        for name in [
            "example.com",
            "a",
            "A.b-c.example.com",
            "127.0.0.1",
            "0.0.0.0",
            "localhost",
            "*.example.com",
        ] {
            assert!(
                HostName::new(name).is_ok(),
                "{name:?} must be accepted as a host name"
            );
        }
        assert!(host("*.example.com").is_wildcard());
        assert!(!host("example.com").is_wildcard());
        let max_len = format!("{}.a", "a".repeat(MAX_HOST_NAME_LEN - 4));
        assert!(HostName::new(max_len).is_ok());
    }

    #[test]
    fn host_name_rejects_invalid() {
        for bad in [
            "",
            &"a".repeat(MAX_HOST_NAME_LEN + 1),
            "*",         // 裸通配符
            "*.",        // 通配符后无 host
            "*a.com",    // '*' 非前导 "*."
            "a*b.com",   // '*' 在中间
            "a..b",      // 连续空标签
            ".example",  // 前导 '.'
            "example.",  // 尾随 '.'
            "exa mple",  // 空白
            "exa\nmple", // 控制字符
            "exa@mple",  // 非法字符
            "exa_mple",  // 下划线不在 RFC 1035 host name 字符集
        ] {
            assert!(
                matches!(
                    HostName::new(bad),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::HostName,
                        ..
                    })
                ),
                "{bad:?} must be rejected as a host name"
            );
        }
    }

    #[test]
    fn host_name_roundtrip() {
        let host = ok(HostName::new("api.example.com"), "host");
        assert_eq!(host.to_string(), "api.example.com");
        assert_eq!("api.example.com".parse::<HostName>(), Ok(host.clone()));
        let json = ok(serde_json::to_string(&host), "serialize");
        assert_eq!(json, "\"api.example.com\"");
        assert_eq!(
            ok(serde_json::from_str::<HostName>(&json), "deserialize"),
            host
        );
        assert!(serde_json::from_str::<HostName>("\"a..b\"").is_err());
    }

    // ---- FileSystemPath ----

    #[test]
    fn filesystem_path_accepts_valid() {
        for path in ["/data", "/data/sub", "/var/lib/my-component", "/a/{x}"] {
            assert!(
                FileSystemPath::new(path).is_ok(),
                "{path:?} must be accepted (template characters allowed)"
            );
        }
    }

    #[test]
    fn filesystem_path_rejects_invalid() {
        for path in [
            "",
            "data",
            "/",
            "/data/",
            "/data//x",
            "/../x",
            "/data/..",
            "/data/./x",
            "/a\\b",
            "/a\nb",
        ] {
            assert!(
                matches!(
                    FileSystemPath::new(path),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::FileSystemPath,
                        ..
                    })
                ),
                "{path:?} must be rejected"
            );
        }
    }

    #[test]
    fn filesystem_path_roundtrip() {
        let path = ok(FileSystemPath::new("/data"), "path");
        assert_eq!(path.as_str(), "/data");
        let json = ok(serde_json::to_string(&path), "serialize");
        assert_eq!(json, "\"/data\"");
        assert_eq!(
            ok(serde_json::from_str::<FileSystemPath>(&json), "deserialize"),
            path
        );
    }

    // ---- PolicyScope ----

    #[test]
    fn policy_scope_variants_and_display() {
        let scopes = [
            PolicyScope::All,
            secret_scope("db-password"),
            event_scope("order.created"),
            PolicyScope::Network {
                scheme: NetworkScheme::Https,
                host: host("prometheus.internal"),
                port: Some(9090),
            },
            PolicyScope::Network {
                scheme: NetworkScheme::Http,
                host: host("*.internal"),
                port: None,
            },
            PolicyScope::FileSystem {
                path: fs_path("/data"),
                read: true,
                write: false,
            },
            PolicyScope::Provider(interface_id("wasi:http/outgoing-handler@0.2.0")),
        ];
        assert!(scopes[0].is_all());
        for scope in &scopes {
            let json = ok(serde_json::to_string(scope), "serialize");
            assert_eq!(
                ok(serde_json::from_str::<PolicyScope>(&json), "deserialize"),
                *scope
            );
        }
        assert_eq!(scopes[0].to_string(), "all");
        assert_eq!(scopes[1].to_string(), "secret db-password");
        assert_eq!(scopes[2].to_string(), "event order.created");
        assert_eq!(
            scopes[3].to_string(),
            "network https://prometheus.internal:9090"
        );
        assert_eq!(scopes[4].to_string(), "network http://*.internal");
        assert_eq!(scopes[5].to_string(), "filesystem /data (read)");
    }

    // ---- CapabilityPolicy ----

    #[test]
    fn capability_policy_allows_scopes() {
        let scoped = CapabilityPolicy::new(
            capability("wasi:http/outgoing-handler"),
            scopes(&[secret_scope("db-password"), event_scope("order.created")]),
        );
        assert!(scoped.allows(&secret_scope("db-password")));
        assert!(scoped.allows(&event_scope("order.created")));
        assert!(!scoped.allows(&event_scope("other.topic")));
        assert!(!scoped.is_explicit_deny());

        // All 形态：任何 scope 都允许。
        let all = CapabilityPolicy::new(
            capability("wasi:http/outgoing-handler"),
            scopes(&[PolicyScope::All]),
        );
        assert!(all.allows(&secret_scope("db-password")));
        assert!(all.allows(&event_scope("anything")));

        // 空集合 = 显式拒绝（deny-by-default 的显式形态）。
        let denied = CapabilityPolicy::new(capability("wasi:http/outgoing-handler"), scopes(&[]));
        assert!(denied.is_explicit_deny());
        assert!(!denied.allows(&PolicyScope::All));
        assert!(!denied.allows(&secret_scope("db-password")));
    }

    #[test]
    fn capability_policy_serde_roundtrip() {
        let declared = CapabilityPolicy::new(
            capability("wasi:http/outgoing-handler"),
            scopes(&[secret_scope("db-password")]),
        );
        let json = ok(serde_json::to_string(&declared), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<CapabilityPolicy>(&json),
                "deserialize"
            ),
            declared
        );
    }

    // ---- PolicyVersion ----

    #[test]
    fn policy_version_next_is_monotonic() {
        let v1 = PolicyVersion::INITIAL;
        assert_eq!(v1.as_u64(), 1);
        let v2 = ok(v1.next(), "next");
        assert_eq!(v2, PolicyVersion::from_u64(2));
        assert!(v1 < v2);
        assert_eq!(v2.next(), Ok(PolicyVersion::from_u64(3)));
        // 任意 u64 可恢复构造。
        assert_eq!(PolicyVersion::from_u64(0).as_u64(), 0);
        let json = ok(serde_json::to_string(&v1), "serialize");
        assert_eq!(json, "1");
        assert_eq!(
            ok(serde_json::from_str::<PolicyVersion>(&json), "deserialize"),
            v1
        );
    }

    #[test]
    fn policy_version_next_overflows_at_max() {
        let max = PolicyVersion::from_u64(u64::MAX);
        assert!(matches!(max.next(), Err(DomainError::Overflow { .. })));
    }

    // ---- PolicySnapshot ----

    #[test]
    fn policy_snapshot_new_accepts_distinct_capabilities() {
        let snapshot = ok(
            PolicySnapshot::new(
                PolicyVersion::INITIAL,
                vec![
                    policy("wasi:http/outgoing-handler", scopes(&[PolicyScope::All])),
                    policy(
                        "operune:secret/read",
                        scopes(&[secret_scope("db-password")]),
                    ),
                ],
                instant(1_752_000_000),
            ),
            "snapshot",
        );
        assert_eq!(snapshot.version(), PolicyVersion::INITIAL);
        assert_eq!(snapshot.created_at(), instant(1_752_000_000));
        assert_eq!(snapshot.policies().len(), 2);
        assert!(
            snapshot
                .policy_for(&capability("operune:secret/read"))
                .is_some()
        );
        assert!(
            snapshot
                .policy_for(&capability("wasi:filesystem/preopens"))
                .is_none()
        );
    }

    #[test]
    fn policy_snapshot_rejects_duplicate_capability() {
        let duplicate = PolicySnapshot::new(
            PolicyVersion::INITIAL,
            vec![
                policy("wasi:http/outgoing-handler", scopes(&[PolicyScope::All])),
                policy(
                    "wasi:http/outgoing-handler",
                    scopes(&[event_scope("other")]),
                ),
            ],
            instant(1_752_000_000),
        );
        assert!(matches!(
            duplicate,
            Err(DomainError::InvalidValue {
                kind: ValueKind::PolicySnapshot,
                ..
            })
        ));
    }

    #[test]
    fn policy_snapshot_new_after_is_monotonic() {
        let v1 = ok(
            PolicySnapshot::new(
                PolicyVersion::INITIAL,
                vec![policy(
                    "wasi:http/outgoing-handler",
                    scopes(&[PolicyScope::All]),
                )],
                instant(1_752_000_000),
            ),
            "snapshot v1",
        );
        let v2 = ok(
            PolicySnapshot::new_after(
                &v1,
                vec![policy(
                    "wasi:http/outgoing-handler",
                    scopes(&[secret_scope("db-password")]),
                )],
                instant(1_752_000_001),
            ),
            "snapshot v2",
        );
        // 版本自动 +1，单调（§43.2 versioning）。
        assert_eq!(v2.version(), PolicyVersion::from_u64(2));
        assert!(v1.version() < v2.version());
        // 前序快照不可变（v1 内容原样保留，审计可追溯）。
        match v1.policy_for(&capability("wasi:http/outgoing-handler")) {
            Some(policy) => assert!(policy.allowed_scopes().contains(&PolicyScope::All)),
            None => unreachable!("v1 policy exists by construction"),
        }
        // 新快照 scope 已收紧。
        match v2.policy_for(&capability("wasi:http/outgoing-handler")) {
            Some(policy) => {
                assert!(policy.allows(&secret_scope("db-password")));
                assert!(!policy.allows(&event_scope("order.created")));
            }
            None => unreachable!("v2 policy exists by construction"),
        }
    }

    #[test]
    fn policy_snapshot_serde_roundtrip() {
        let snapshot = ok(
            PolicySnapshot::new(
                PolicyVersion::from_u64(7),
                vec![policy(
                    "operune:secret/read",
                    scopes(&[secret_scope("db-password")]),
                )],
                instant(1_752_000_000),
            ),
            "snapshot",
        );
        let json = ok(serde_json::to_string(&snapshot), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<PolicySnapshot>(&json), "deserialize"),
            snapshot
        );
        // 反序列化边界同样执行键唯一校验（§13.3）。
        let duplicate = r#"{
            "version": 1,
            "created_at": {"seconds": 1752000000, "nanoseconds": 0},
            "policies": [
                {"capability": "wasi:http/outgoing-handler", "allowed_scopes": ["all"]},
                {"capability": "wasi:http/outgoing-handler", "allowed_scopes": [{"secret": "db-password"}]}
            ]
        }"#;
        assert!(
            serde_json::from_str::<PolicySnapshot>(duplicate).is_err(),
            "duplicate capability must be rejected on deserialize"
        );
    }
}
