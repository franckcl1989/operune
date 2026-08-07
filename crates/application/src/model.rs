//! 用例级记录类型（§24.2：application 的用例编排与 ports 使用的类型）。
//!
//! 这些类型是 application 的"用例级类型"（任务 A）：端口签名与用例 API
//! 只使用 domain 类型 + 本模块的类型，不泄漏 rusqlite / wasmtime / WASI
//! 具体类型（§24.2 / §8.2）。语义对齐 §6.7 / §17 / §18.3 / §19.4 / §20 / §21.3。

use std::time::Duration;

use operune_domain::{
    ByteSize, CapabilityId, ComponentId, ComponentLifecycleState, ComponentVersion, ContentDigest,
    InstallationId,
};
use operune_runtime_wasi_p2::capability::WasiCapabilities;
use serde::{Deserialize, Serialize};

use crate::contract::{MAX_COMPONENT_ID_LEN, MAX_WEB_ASSET_PATH_LEN};

/// 安装 / 升级 / 回滚请求携带的 grant 批准（§17.1：grant 绑定
/// InstallationId，不绑定可复用的 ComponentId）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantApproval {
    /// 显式批准的 grant 集（全新安装必须使用此形态；升级时即"重新显式批准"，
    /// §17.5：新增/扩大权限必须在 activation 前重新显式批准）。
    Explicit(Vec<InstallationGrant>),
    /// 升级 / 回滚时复用该安装既有 grant；仅当新版本实际 imports 没有扩大
    /// 能力种类或 scope 需求、且 policy 重新验证通过时才可继续适用
    /// （§17.5），否则用例返回 [`UpgradeOutcome::RequiresApproval`]。
    ReuseExisting,
}

/// 一条绑定 InstallationId 的 grant（§17.1 / §17.5：durable owner 是
/// InstallationId；同一逻辑 ComponentId 的另一安装实例不继承权限）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationGrant {
    /// 能力身份（WIT import 的规范化能力 id，见 [`ImportClass`] 说明）。
    pub capability: CapabilityId,
    /// 资源级 scope（§17.3：能表达资源级 scope 而非仅 boolean）。
    pub scope: GrantScope,
}

/// grant 的资源级 scope（§17.3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantScope {
    /// 无资源级 scope（纯布尔能力）。
    Unscoped,
    /// WASI preopen 目录（host 路径 → guest 路径 + 权限）。
    WasiPreopen {
        /// guest 侧目录名。
        guest_path: String,
        /// host 侧目录路径（平台适配层解析，§9.4）。
        host_path: String,
        /// 目录读取权限。
        read: bool,
        /// 目录写入权限。
        write: bool,
    },
    /// WASI 环境变量（值可能敏感，§16.6：审计只记录 key 不记录 value）。
    WasiEnv {
        /// 环境变量名。
        key: String,
        /// 环境变量值（不进入审计，§16.6）。
        value: String,
    },
    /// Web backend action 级授权（§21.3：action permission 检查）。
    Action {
        /// 被授权的 action 名称。
        name: String,
    },
}

impl InstallationGrant {
    /// 审计形态（§16.6：不记 secret——环境变量值一律遮蔽）。
    pub(crate) fn audit_shape(&self) -> GrantAuditShape {
        let (scope_kind, env_value_redacted) = match &self.scope {
            GrantScope::Unscoped => ("unscoped".to_owned(), false),
            GrantScope::WasiPreopen { guest_path, .. } => (format!("preopen:{guest_path}"), false),
            GrantScope::WasiEnv { key, .. } => (format!("env:{key}"), true),
            GrantScope::Action { name } => (format!("action:{name}"), false),
        };
        GrantAuditShape {
            capability: self.capability.clone(),
            scope_kind,
            env_value_redacted,
        }
    }
}

/// 审计记录中的 grant 形态（只含可诊断信息，§16.6：环境变量值一律遮蔽）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GrantAuditShape {
    /// 能力身份。
    pub capability: CapabilityId,
    /// scope 的展示形态（值已遮蔽）。
    pub scope_kind: String,
    /// 该 grant 是否包含被遮蔽的环境变量值。
    pub env_value_redacted: bool,
}

/// 安装实例的运行时能力快照（§19.3 / §20.1：在目标 grant / resource 快照
/// 下实例化 runtime candidate）。WASI 能力值按 §17 grant 语义由 application
/// 产生（runtime-wasi-p2 的 [`WasiCapabilities`] 形状，见其 crate 文档）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantSnapshot {
    /// 快照绑定的安装实例。
    pub installation: InstallationId,
    /// WASI 能力集合（deny-by-default：空集 = 零能力，§7.6 / §17.2）。
    pub wasi: WasiCapabilities,
    /// 目标资源预算（§7.4）。
    pub budget: operune_runtime_wasm::ResourceBudget,
}

/// 安装请求（§19.2 输入不可信：任何 `.wasm` 输入视为不可信字节，§19.1）。
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// 收到的原始 Component 字节。
    pub bytes: Vec<u8>,
    /// 本安装实例的 grant 批准（必须 [`GrantApproval::Explicit`]）。
    pub grants: GrantApproval,
}

/// 安装用例结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallOutcome {
    /// 两阶段安装完成并原子激活（§19.2 末步）。
    Activated {
        /// 新创建的安装实例。
        installation: InstallationId,
        /// 激活版本。
        version: ComponentVersion,
        /// 激活 digest。
        digest: ContentDigest,
    },
}

/// 升级请求（§20.1）。
#[derive(Debug, Clone)]
pub struct UpgradeRequest {
    /// 被升级的安装实例（当前必须 Active）。
    pub installation: InstallationId,
    /// 新版本字节（v2）。
    pub bytes: Vec<u8>,
    /// grant 批准（§17.5：显式批准或复用既有）。
    pub grants: GrantApproval,
}

/// 回滚请求（§20：回滚到上一已知良好版本）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackRequest {
    /// 被回滚的安装实例（当前必须 Active）。
    pub installation: InstallationId,
}

/// 升级 / 回滚用例结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpgradeOutcome {
    /// 原子快照交换完成（§20.1）：新请求解析到 `to`，旧版本进入 drain。
    Swapped {
        /// 安装实例。
        installation: InstallationId,
        /// 旧 digest（已进入 drain）。
        from: ContentDigest,
        /// 新 digest（新请求解析目标）。
        to: ContentDigest,
    },
    /// 需要显式重新批准（§17.5：新版本 imports 扩大能力种类或 scope）。
    ///
    /// candidate 保持 `Validated`（未被标记失败），等待携带
    /// [`GrantApproval::Explicit`] 的再次升级请求。
    RequiresApproval {
        /// 安装实例。
        installation: InstallationId,
        /// 尚未被既有 grant 覆盖的能力。
        missing: Vec<CapabilityId>,
    },
    /// 目标 digest 与当前 Active digest 相同（幂等 no-op）。
    NoOp {
        /// 安装实例。
        installation: InstallationId,
    },
}

/// 二进制 contract surface 事实（§6.7：从 Component binary type 实际可观察
/// 的 imports/exports；运行时兼容判断只依赖这些真实事实，不依赖 root
/// package / world 名）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractSurface {
    /// 全部 import 名（如 `wasi:cli/run@0.2.0`）。
    pub imports: Vec<String>,
    /// 全部 export 名（如 `descriptor`、`assets`、`actions`）。
    pub exports: Vec<String>,
}

impl ContractSurface {
    /// 是否导出 `operune:component/descriptor`（§19.2 必需契约）。
    ///
    /// 二进制中的实例名有两种合法形态（WIT world 写法不同）：
    /// `descriptor`（`operune-component` world 的本地 interface）或
    /// `operune:component/descriptor@0.1.0`（`operune-web-component` world
    /// 的全限定引用）。
    pub fn exports_component_descriptor(&self) -> bool {
        self.exports
            .iter()
            .any(|name| name == "descriptor" || name == "operune:component/descriptor@0.1.0")
    }

    /// 是否导出 `operune:web/assets`（§21.3 static assets）。
    pub fn exports_web_assets(&self) -> bool {
        self.exports.iter().any(|name| name == "assets")
    }

    /// 是否导出 `operune:web/actions`（§21.3 bounded backend action）。
    pub fn exports_web_actions(&self) -> bool {
        self.exports.iter().any(|name| name == "actions")
    }
}

/// import 名的规范化分类（§19.5 / §17.2 deny-by-default 的 Resolution 面）。
///
/// 0.1.0 的 Resolution 只覆盖 Host/WASI 与 Operune 平台能力（§17.5）；
/// 跨 Component import 属于 0.2 Provider Graph，0.1.0 明确判定为不支持并
/// 拒绝激活（§19.5）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportClass {
    /// WASI 标准接口（`wasi:` 前缀）——能力可解析，受 grant 门控。
    Wasi,
    /// Operune 平台接口（`operune:` 前缀）——能力可解析，受 grant 门控。
    Operune,
    /// 其他命名空间（Component-to-Component 或未知）——0.1.0 不支持（§19.5）。
    Unsupported,
}

impl ImportClass {
    /// 规范化 import 名（去掉 `@version` 后缀后的能力 id 形态）。
    ///
    /// 0.1.0 的 grant 能力 id 是版本无关的接口名（`wasi:cli/run` 形态）；
    /// WIT interface 版本兼容规则属于 0.2.0 Provider Graph 的正式模型
    /// （§17.5 版本兼容规则随 0.2 演进）。
    pub fn normalize(import: &str) -> ImportClass {
        let base = import.split('@').next().unwrap_or(import);
        if base.starts_with("wasi:") {
            ImportClass::Wasi
        } else if base.starts_with("operune:") {
            ImportClass::Operune
        } else {
            ImportClass::Unsupported
        }
    }

    /// 把 import 名转换为能力 id（仅可解析类别；调用方先检查类别）。
    pub fn capability_id(import: &str) -> Result<CapabilityId, crate::error::ApplicationError> {
        let base = import.split('@').next().unwrap_or(import);
        CapabilityId::new(base).map_err(crate::error::ApplicationError::Domain)
    }
}

/// digest 主键的 quarantine/candidate 记录（§19.2 / §18.3：安装早期的
/// candidate 以 digest 为主键；生命周期状态由 domain 状态机驱动，§12.2）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateRecord {
    /// 字节事实主键。
    pub digest: ContentDigest,
    /// 生命周期状态（`ComponentLifecycleState::initial()` 起步）。
    pub state: ComponentLifecycleState,
    /// 收到的原始字节数（§19.2 硬大小限制后的事实）。
    pub byte_len: ByteSize,
}

/// `ComponentId + ComponentVersion -> Digest` 的逻辑版本关系（§6.7 / §19.4：
/// 同一逻辑版本默认只能绑定一个已接受 digest；不同 digest 显式阻断）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestVersionBinding {
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// 作者声明版本。
    pub version: ComponentVersion,
    /// 已接受的字节事实。
    pub digest: ContentDigest,
}

/// InstallationId 记录（§19.4：承载 grant / enable/active 状态与本机
/// 生命周期；§18.3 至少持久化 InstallationId 及其与逻辑版本/当前 active
/// digest 的关系）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallationRecord {
    /// 安装实例身份。
    pub installation_id: InstallationId,
    /// 逻辑产品身份。
    pub component_id: ComponentId,
    /// 当前激活版本。
    pub version: ComponentVersion,
    /// 当前 active digest（无则 `None`）。
    pub active_digest: Option<ContentDigest>,
    /// 上一已知良好 digest（回滚目标，§20 / §18.7 rollback retention）。
    pub last_known_good_digest: Option<ContentDigest>,
    /// 生命周期状态。
    pub state: ComponentLifecycleState,
}

/// Core config 快照（§18.0 RuntimeConfig 语义：Core 启动并打开 authoritative
/// store 后管理的可变运行策略；本用例级快照由 [`crate::ports::ConfigPort`]
/// 提供）。
///
/// 全部字段是宿主侧硬上限 / 预算（§7.4 / §19.1 / §19.3 / §20.4 / §21.3）；
/// 构造后不可变。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    /// 安装输入的硬字节大小限制（§19.1 / §19.2）。
    pub max_component_bytes: ByteSize,
    /// descriptor 调用 deadline（§19.3：descriptor 有独立 deadline/预算）。
    pub descriptor_deadline: Duration,
    /// descriptor-only Store 预算（§19.3：与正常运行相同或更严格）。
    pub descriptor_budget: operune_runtime_wasm::ResourceBudget,
    /// runtime candidate 预算（§7.4）。
    pub candidate_budget: operune_runtime_wasm::ResourceBudget,
    /// readiness 验证 deadline（§19.3）。
    pub readiness_deadline: Duration,
    /// drain 有界 deadline（§20.4）。
    pub drain_deadline: Duration,
    /// web asset 缓存条目上限（§21.3 / §6.2；有界，§7.4 host-buffer 纪律）。
    pub max_web_assets: usize,
    /// 单资产体积上限（§21.3 / §7.4 host buffer 上限）。
    pub max_asset_bytes: ByteSize,
    /// 单次 backend action 请求体上限（§21.3）。
    pub max_action_body_bytes: ByteSize,
    /// 单次 backend action 响应体积上限（§21.3）。
    pub max_action_response_bytes: ByteSize,
    /// 每安装 action 速率上限（次/分钟；§21.3 rate 检查）。
    pub max_actions_per_minute: u32,
}

impl RuntimeConfig {
    /// 校验（validate-on-construct 精神，§13.3）：全部上限必须为正。
    pub fn validate(&self) -> Result<(), crate::error::ApplicationError> {
        if self.max_component_bytes.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "max_component_bytes must be non-zero",
            ));
        }
        if self.descriptor_deadline.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "descriptor_deadline must be non-zero",
            ));
        }
        if self.readiness_deadline.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "readiness_deadline must be non-zero",
            ));
        }
        if self.drain_deadline.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "drain_deadline must be non-zero",
            ));
        }
        if self.max_web_assets == 0 {
            return Err(crate::error::ApplicationError::Config(
                "max_web_assets must be non-zero",
            ));
        }
        if self.max_asset_bytes.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "max_asset_bytes must be non-zero",
            ));
        }
        if self.max_action_body_bytes.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "max_action_body_bytes must be non-zero",
            ));
        }
        if self.max_action_response_bytes.is_zero() {
            return Err(crate::error::ApplicationError::Config(
                "max_action_response_bytes must be non-zero",
            ));
        }
        if self.max_actions_per_minute == 0 {
            return Err(crate::error::ApplicationError::Config(
                "max_actions_per_minute must be non-zero",
            ));
        }
        Ok(())
    }
}

/// 测试 / 配置缺省的生产默认 config 快照（§7.4 默认值对齐 runtime-wasm）。
impl Default for RuntimeConfig {
    fn default() -> Self {
        let descriptor_budget = {
            // §19.3：descriptor Store 预算与正常运行相同或更严格——此处比
            // candidate 默认更紧（64 MiB → 16 MiB linear memory，并发 1）。
            operune_runtime_wasm::ResourceBudget {
                linear_memory: Some(operune_runtime_wasm::LinearMemoryLimit::new(
                    operune_runtime_wasm::ByteSize::mib(16),
                )),
                max_concurrent: operune_runtime_wasm::MaxConcurrent::try_new(1)
                    .unwrap_or(operune_runtime_wasm::MaxConcurrent::MIN),
                ..operune_runtime_wasm::ResourceBudget::default()
            }
        };
        Self {
            max_component_bytes: ByteSize::mib(64).unwrap_or(ByteSize::MAX),
            descriptor_deadline: Duration::from_secs(2),
            descriptor_budget,
            candidate_budget: operune_runtime_wasm::ResourceBudget::default(),
            readiness_deadline: Duration::from_secs(5),
            drain_deadline: Duration::from_secs(10),
            max_web_assets: 128,
            max_asset_bytes: ByteSize::mib(8).unwrap_or(ByteSize::MAX),
            max_action_body_bytes: ByteSize::kib(64).unwrap_or(ByteSize::MAX),
            max_action_response_bytes: ByteSize::kib(256).unwrap_or(ByteSize::MAX),
            max_actions_per_minute: 600,
        }
    }
}

/// 受校验的 Web 资产逻辑路径（§21.3 / `operune:web@0.1.0` `asset-path` 契约）。
///
/// WIT 契约不变量：规范化相对路径、以 `/` 开头、不含 `..` 段、空段或
/// 反斜杠；Core 对每个路径执行规范化与越界校验（§32 security test：
/// web asset path 无 traversal）。这与 domain 的 [`operune_domain::ArtifactPath`]
/// （制品相对路径，拒绝前导 `/`）语义不同——asset path 的规范形态带前导
/// `/`，故 application 定义本类型承载该契约。
///
/// 错误：构造失败返回 [`crate::error::ApplicationError::InvalidWebAssetPath`]。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct WebAssetPath(String);

impl WebAssetPath {
    /// 解析并校验（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, crate::error::ApplicationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "must not be empty",
            ));
        }
        if value.len() > MAX_WEB_ASSET_PATH_LEN {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "exceeds the maximum length",
            ));
        }
        if !value.starts_with('/') {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "must start with '/'",
            ));
        }
        if value.contains('\\') {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "backslash is not a valid separator",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "must not contain control characters",
            ));
        }
        // 段级校验：拒绝 `..`、`.` 与空段（目录穿越 fail closed，§32）。
        // 前导 `/` 产生的首空段是根标记（WIT 契约：路径以 `/` 开头）；
        // 其余位置的空段（`/a//b`、`/a/`）一律拒绝。
        let segments: Vec<&str> = value.split('/').collect();
        for (index, segment) in segments.iter().enumerate() {
            let is_root_leading = index == 0 && segment.is_empty();
            if is_root_leading {
                continue;
            }
            if *segment == "." || *segment == ".." || segment.is_empty() {
                return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                    "path contains an invalid segment",
                ));
            }
        }
        // 至少一个真实段（单独的 "/" 非法）。
        if segments.len() < 2 {
            return Err(crate::error::ApplicationError::InvalidWebAssetPath(
                "path must contain at least one segment",
            ));
        }
        Ok(Self(value))
    }

    /// 规范化路径视图（`/` 开头、无非法段）。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for WebAssetPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Web 清单（§21.3：激活阶段读取 web descriptor + 资产清单；UI assets 与
/// backend exports 随同一 ComponentVersion 原子切换，§21.5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebManifestData {
    /// 入口资产路径（`/index.html` 形态）。
    pub entry: WebAssetPath,
    /// 声明的能力（与二进制实际 exports 交叉校验，§web descriptor 契约）。
    pub features: WebManifestFeatures,
    /// 资产清单（激活阶段按 ContentDigest + asset path 缓存，§6.2 / §21.3）。
    pub assets: Vec<WebAssetEntry>,
}

/// Web 能力声明（§21.3；与二进制实际 exports 不一致视为 contract violation）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebManifestFeatures {
    /// static-assets。
    pub static_assets: bool,
    /// backend-actions。
    pub backend_actions: bool,
}

/// 资产清单条目。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAssetEntry {
    /// 资产逻辑路径。
    pub path: WebAssetPath,
    /// 资产字节大小（guest 声明；Core 另有宿主硬上限）。
    pub size: u64,
    /// 作者建议 MIME（Core 保留最终校验权，§21.3 Core-owned headers）。
    pub content_type: Option<String>,
}

/// backend action 名称（§21.3：Core 只做等价比较与审计，不解析语义）。
///
/// 不变量：非空、≤ 255 字节、不含控制字符（对齐 [`MAX_COMPONENT_ID_LEN`]）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionName(String);

impl ActionName {
    /// 从边界输入构造（§13.3 边界解析一次）。
    pub fn new(value: impl Into<String>) -> Result<Self, crate::error::ApplicationError> {
        let value = value.into();
        if value.is_empty() {
            return Err(crate::error::ApplicationError::InvalidActionName(
                "must not be empty",
            ));
        }
        if value.len() > MAX_COMPONENT_ID_LEN {
            return Err(crate::error::ApplicationError::InvalidActionName(
                "exceeds the maximum length",
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(crate::error::ApplicationError::InvalidActionName(
                "must not contain control characters",
            ));
        }
        Ok(Self(value))
    }

    /// 原始视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ActionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Web bridge 的拒绝类别（§21.3：Core 在服务端重做检查后以确定语义拒绝；
/// HTTP 层负责把这些映射为确定 HTTP 响应）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionDenied {
    /// 安装实例没有该 action 的 grant（§17.5 四层授权链的 Grant 层）。
    NotGranted,
    /// 超出速率上限（§21.3 rate 检查）。
    RateLimited,
    /// 请求体超限（§21.3 body 上限）。
    BodyTooLarge,
    /// 全部实例槽位繁忙 / 并发超限（§7.4 max_concurrent）。
    Busy,
    /// action 名称未知（guest `not-found` 之外的 Core 侧拒绝）。
    Unknown,
}

impl std::fmt::Display for ActionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NotGranted => "action not granted for this installation",
            Self::RateLimited => "action rate limit exceeded",
            Self::BodyTooLarge => "action body exceeds the host-side limit",
            Self::Busy => "action concurrency limit reached",
            Self::Unknown => "action denied",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ActionDenied {}

/// 管线目标（§19.2 安装 / §20.1 升级 / §20 回滚共用同一候选管线）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineTargetKind {
    /// 全新安装（§19.2 两阶段；结束 = 原子激活）。
    Install,
    /// 热升级（§20.1）。
    Upgrade,
    /// 回滚到上一已知良好版本（§20）。
    Rollback,
}

/// 管线前置条件（安装 / 升级 / 回滚的分支输入）。
#[derive(Debug, Clone)]
pub(crate) enum PipelineTarget {
    /// 全新安装。
    Install,
    /// 升级现有安装（携带当前记录）。
    Upgrade {
        /// 当前安装记录（必须 Active）。
        current: InstallationRecord,
    },
    /// 回滚到上一已知良好版本（携带当前记录；目标 digest =
    /// `current.last_known_good_digest`，字节由用例层从 artifact store
    /// 读取，§18.7）。
    Rollback {
        /// 当前安装记录（必须 Active）。
        current: InstallationRecord,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn web_asset_path_validation() {
        // §21.3 / WIT `asset-path` 契约：`/` 开头、无 `..` / 空段 /
        // 反斜杠；§32 security test：web asset path 无 traversal。
        for valid in ["/index.html", "/a/b.js", "/数据/表.json"] {
            assert!(
                WebAssetPath::new(valid).is_ok(),
                "{valid:?} must be accepted"
            );
        }
        for bad in [
            "index.html", // 必须以 "/" 开头（WIT 契约）
            "/../x",
            "/a/../../b",
            "/a/./b",
            "/a//b",
            "/a\\b",
            "/a\nb",
            "",
        ] {
            assert!(
                matches!(
                    WebAssetPath::new(bad),
                    Err(crate::error::ApplicationError::InvalidWebAssetPath(_))
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn runtime_config_validation() {
        // §13.3：宿主侧上限必须为正。
        assert!(RuntimeConfig::default().validate().is_ok());
        let zero_size = RuntimeConfig {
            max_component_bytes: ByteSize::ZERO,
            ..RuntimeConfig::default()
        };
        assert!(zero_size.validate().is_err());
        let zero_drain = RuntimeConfig {
            drain_deadline: Duration::ZERO,
            ..RuntimeConfig::default()
        };
        assert!(zero_drain.validate().is_err());
        let zero_assets = RuntimeConfig {
            max_web_assets: 0,
            ..RuntimeConfig::default()
        };
        assert!(zero_assets.validate().is_err());
    }

    #[test]
    fn action_name_validation() {
        assert!(ActionName::new("run-check").is_ok());
        for bad in ["", "bad\nname"] {
            assert!(
                matches!(
                    ActionName::new(bad),
                    Err(crate::error::ApplicationError::InvalidActionName(_))
                ),
                "{bad:?} must be rejected"
            );
        }
        // 超长 action 名。
        assert!(ActionName::new("x".repeat(256)).is_err());
    }

    #[test]
    fn contract_surface_descriptor_export_forms() {
        // §6.7：两种 world 写法的 descriptor 导出形态都接受。
        let simple = ContractSurface {
            imports: Vec::new(),
            exports: vec!["descriptor".to_owned()],
        };
        assert!(simple.exports_component_descriptor());
        let qualified = ContractSurface {
            imports: Vec::new(),
            exports: vec!["operune:component/descriptor@0.1.0".to_owned()],
        };
        assert!(qualified.exports_component_descriptor());
        let none = ContractSurface {
            imports: Vec::new(),
            exports: Vec::new(),
        };
        assert!(!none.exports_component_descriptor());
    }

    #[test]
    fn import_classification() {
        // §19.5：WASI / operune 可解析；其他命名空间 0.1.0 不支持。
        assert_eq!(
            ImportClass::normalize("wasi:cli/run@0.2.0"),
            ImportClass::Wasi
        );
        assert_eq!(
            ImportClass::normalize("operune:component/descriptor@0.1.0"),
            ImportClass::Operune
        );
        assert_eq!(
            ImportClass::normalize("acme:thing/x@1.0.0"),
            ImportClass::Unsupported
        );
        let capability = ok(
            ImportClass::capability_id("wasi:cli/run@0.2.0"),
            "capability id",
        );
        assert_eq!(capability.as_str(), "wasi:cli/run");
    }
}
