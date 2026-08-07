//! 最小 Component Web bridge 用例（§21.3）。
//!
//! # 闭环（§21.3 / §21.5）
//!
//! - 激活阶段读取 web descriptor + 资产清单（`list-assets`），资产以
//!   `ContentDigest + asset path` 为缓存事实（§6.2 / §21.3），静态资产
//!   请求不必每次重新执行 Wasm；
//! - bounded backend action 调用：Core-mediated（绑定 InstallationId +
//!   ComponentVersion），服务端重做 auth / RBAC / grant / body / deadline /
//!   rate / concurrency 检查（检查点经 [`crate::ports::ActionPolicyPort`]
//!   表达，HTTP 层在 web-admin 实现完整链）；
//! - 响应结构只有字节（`Vec<u8>`）——不得携带 / 设置凭据（§16.6 /
//!   §21.3：Core-owned security headers 不可覆盖）；
//! - 无流 / 长连接（§21.3：0.1 bridge 只有 bounded request/response）。
//!
//! # 有界性（§7.4 / §15.2）
//!
//! 资产缓存按条目数（`max_web_assets`）与单资产体积（`max_asset_bytes`）
//! 设硬上限（admission control，§18.7）；action 请求体 / 响应体有宿主侧
//! 硬上限；并发由 InstanceSet 槽位（max_concurrent）强制。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use operune_domain::{ByteSize, ContentDigest, InstallationId};

use crate::active::ActiveRuntimeRegistry;
use crate::contract::{GuestActionPayload, GuestActionRequest};
use crate::error::ApplicationError;
use crate::model::{ActionName, RuntimeConfig, WebAssetPath};
use crate::ports::{ActionContext, ActionPolicyPort, AuditEvent, AuditPort};

/// 资产缓存键（§6.2 / §21.3：ContentDigest + asset path 为缓存事实）。
type AssetCacheKey = (ContentDigest, WebAssetPath);

/// Web 资产缓存（§6.2 / §21.3：缓存键 = ContentDigest + asset path；
/// 宿主侧有界，§7.4 host-buffer 纪律 / §18.7 admission control）。
pub struct AssetCache {
    entries: Mutex<HashMap<AssetCacheKey, Arc<Vec<u8>>>>,
    entry_cap: usize,
    byte_cap: u64,
    bytes: Mutex<u64>,
}

impl AssetCache {
    /// 构造（上限来自 config 快照；上限非法时返回 config 错误）。
    pub fn new(config: &RuntimeConfig) -> Result<Self, ApplicationError> {
        config.validate()?;
        Ok(Self {
            entries: Mutex::new(HashMap::new()),
            entry_cap: config.max_web_assets,
            byte_cap: config.max_asset_bytes.as_u64(),
            bytes: Mutex::new(0),
        })
    }

    /// 注册资产（受上限约束的 admission control，§18.7）。超过条目数或
    /// 总字节上限时拒绝本次注册（返回 `false`），不驱逐既有条目。
    ///
    /// 返回值：`true` = 已缓存；`false` = 超出上限未缓存（调用方按
    /// 缓存截断处理并记录审计）。
    pub fn register(&self, digest: ContentDigest, path: &WebAssetPath, bytes: &[u8]) -> bool {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > self.byte_cap {
            return false;
        }
        let mut entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        let mut total = match self.bytes.lock() {
            Ok(guard) => guard,
            Err(_) => return false,
        };
        if entries.contains_key(&(digest, path.clone())) {
            return true;
        }
        if entries.len() >= self.entry_cap {
            return false;
        }
        let new_total = total.saturating_add(len);
        // 总字节保守上限 = 条目数 × 单资产上限（饱和运算，§14.4）。
        let byte_cap_total = u64::try_from(self.entry_cap)
            .unwrap_or(u64::MAX)
            .saturating_mul(self.byte_cap);
        if new_total > byte_cap_total {
            return false;
        }
        *total = new_total;
        entries.insert((digest, path.clone()), Arc::new(bytes.to_vec()));
        true
    }

    /// 命中查询（ContentDigest + asset path，§21.3 缓存事实）。
    pub fn get(&self, digest: ContentDigest, path: &WebAssetPath) -> Option<Arc<Vec<u8>>> {
        let entries = match self.entries.lock() {
            Ok(guard) => guard,
            Err(_) => return None,
        };
        entries.get(&(digest, path.clone())).cloned()
    }

    /// 当前条目数（诊断 / 测试）。
    pub fn len(&self) -> usize {
        match self.entries.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    /// 是否为空（诊断 / 测试）。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 资产响应（§21.3：只有字节与建议 MIME——不携带任何凭据 / header）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssetResponse {
    /// 资产字节。
    pub bytes: Arc<Vec<u8>>,
    /// 作者建议 MIME（Core 保留最终校验权，§21.3 Core-owned headers）。
    pub content_type: Option<String>,
}

/// Web bridge 用例（§21.3：最小闭环的 Core 侧）。
pub struct WebBridge {
    active: Arc<ActiveRuntimeRegistry>,
    assets: Arc<AssetCache>,
    policy: Arc<dyn ActionPolicyPort>,
    audit: Arc<dyn AuditPort>,
}

impl WebBridge {
    /// 构造（注入 Active 快照、资产缓存与 policy 检查点）。
    pub fn new(
        active: Arc<ActiveRuntimeRegistry>,
        assets: Arc<AssetCache>,
        policy: Arc<dyn ActionPolicyPort>,
        audit: Arc<dyn AuditPort>,
    ) -> Self {
        Self {
            active,
            assets,
            policy,
            audit,
        }
    }

    /// 读取资产（§21.3 / §6.2）：优先缓存命中（ContentDigest + asset
    /// path）；未命中时经运行时 bounded 读取并尝试入缓存。
    pub fn read_asset(
        &self,
        installation_id: InstallationId,
        path: &WebAssetPath,
    ) -> Result<AssetResponse, ApplicationError> {
        let entry = self
            .active
            .get(installation_id)
            .ok_or(ApplicationError::NotActiveForWeb(installation_id))?;
        let content_type = entry.manifest.as_ref().and_then(|manifest| {
            manifest
                .assets
                .iter()
                .find(|asset| asset.path == *path)
                .and_then(|asset| asset.content_type.clone())
        });
        if let Some(bytes) = self.assets.get(entry.installation.digest, path) {
            return Ok(AssetResponse {
                bytes,
                content_type,
            });
        }
        // 未命中：经 Active 运行时 bounded 读取（§21.3；宿主侧上限在
        // 运行时强制）。
        let bytes = entry
            .runtime
            .read_asset(path)
            .map_err(ApplicationError::Runtime)?;
        let response = AssetResponse {
            bytes: Arc::new(bytes.clone()),
            content_type,
        };
        // 尝试入缓存（admission control，§18.7：超限不缓存，不影响响应）。
        let _ = self
            .assets
            .register(entry.installation.digest, path, &bytes);
        Ok(response)
    }

    /// 处理一次 bounded backend action（§21.3）。
    ///
    /// Core-mediated：先把请求绑定到快照中的 InstallationId +
    /// ComponentVersion，再经 [`ActionPolicyPort`] 重做服务端检查
    /// （auth/RBAC 由 HTTP 层经同一 port 实现完整链；grant/body/rate 由
    /// 默认 policy 检查；deadline/concurrency 在运行时强制），全部通过后
    /// 才调用 guest。响应只有字节（`Vec<u8>`）——结构上不含凭据。
    pub fn invoke_action(
        &self,
        installation_id: InstallationId,
        action: ActionName,
        payload: GuestActionPayload,
    ) -> Result<Vec<u8>, ApplicationError> {
        let entry = self
            .active
            .get(installation_id)
            .ok_or(ApplicationError::NotActiveForWeb(installation_id))?;
        let body_size = match &payload {
            GuestActionPayload::Json(value) => {
                ByteSize::from_bytes(u64::try_from(value.len()).unwrap_or(u64::MAX))
            }
            GuestActionPayload::Raw(bytes) => {
                ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            }
        };
        // 服务端重做检查（§21.3：frame/channel 与 InstallationId +
        // ComponentVersion 绑定）。
        self.policy
            .check(&ActionContext {
                installation_id,
                version: entry.installation.version,
                action: action.clone(),
                body_size,
            })
            .map_err(|denied| {
                let _ = self.audit.append(AuditEvent::ActionDenied {
                    installation: installation_id,
                    action: action.to_string(),
                    reason: denied,
                });
                ApplicationError::ActionDenied(denied)
            })?;
        let request = GuestActionRequest {
            action: action.to_string(),
            payload,
        };
        // §21.3：deadline / concurrency 在运行时强制（epoch deadline +
        // 有界 InstanceSet dispatch）。
        let response = entry
            .runtime
            .invoke_action(&request)
            .map_err(ApplicationError::Runtime)?;
        let _ = self.audit.append(AuditEvent::ActionInvoked {
            installation: installation_id,
            version: entry.installation.version,
            action: action.to_string(),
        });
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract::GuestActionPayload;
    use crate::model::{
        ActionDenied, ContractSurface, GrantScope, InstallOutcome, InstallationGrant,
        RuntimeConfig, WebAssetEntry, WebManifestData, WebManifestFeatures,
    };
    use crate::ports::{ActionContext, ConfigPort, GrantStorePort, InProcessActionPolicy};
    use crate::test_support::{FakeConfig, FakeGrants, Harness, grant, ok, plain_install_request};
    use operune_domain::{ByteSize, CapabilityId, ComponentVersion, ContentDigest};

    fn harness() -> Harness {
        Harness::new(RuntimeConfig::default())
    }

    /// 安装一个带 Web UI 的组件并返回 installation id。
    fn install_web_component(harness: &Harness) -> InstallationId {
        harness.runtime.with_surface(ContractSurface {
            imports: Vec::new(),
            exports: vec![
                "descriptor".to_owned(),
                "assets".to_owned(),
                "actions".to_owned(),
            ],
        });
        harness.runtime.with_manifest(Some(WebManifestData {
            entry: ok(WebAssetPath::new("/index.html"), "entry"),
            features: WebManifestFeatures {
                static_assets: true,
                backend_actions: true,
            },
            assets: vec![WebAssetEntry {
                path: ok(WebAssetPath::new("/index.html"), "asset path"),
                size: 5,
                content_type: Some("text/html".to_owned()),
            }],
        }));
        harness.runtime.with_asset("/index.html", b"hello".to_vec());
        harness.runtime.with_action_result(Ok(vec![9, 8, 7]));
        let outcome = ok(
            harness
                .install
                .install(plain_install_request(b"web bytes".to_vec())),
            "install web component",
        );
        match outcome {
            InstallOutcome::Activated { installation, .. } => installation,
        }
    }

    fn action_request() -> (ActionName, GuestActionPayload) {
        (
            ok(ActionName::new("run-check"), "action name"),
            GuestActionPayload::Json("{}".to_owned()),
        )
    }

    #[test]
    fn web_asset_reads_through_when_not_cached() {
        let harness = harness();
        let installation = install_web_component(&harness);
        // 未在缓存中的路径：经运行时 bounded 读取（§21.3）。
        harness
            .runtime
            .with_asset("/other.js", b"console.log(1)".to_vec());
        let response = ok(
            harness
                .web
                .read_asset(installation, &ok(WebAssetPath::new("/other.js"), "path")),
            "read uncached asset",
        );
        assert_eq!(response.bytes.as_slice(), b"console.log(1)");
        // 读取后按 ContentDigest + asset path 入缓存（§6.2 / §21.3）。
        let digest = ContentDigest::from_bytes(b"web bytes");
        assert!(
            harness
                .assets
                .get(digest, &ok(WebAssetPath::new("/other.js"), "path"))
                .is_some()
        );
    }

    #[test]
    fn web_asset_path_traversal_rejected() {
        // §21.3 / §32：web asset path 无 traversal——边界构造即拒绝。
        for bad in [
            "../etc/passwd",
            "/../x",
            "a/../../b",
            "/a/./b",
            "\\a",
            "/a//b",
            "",
        ] {
            let result = WebAssetPath::new(bad);
            assert!(
                matches!(result, Err(ApplicationError::InvalidWebAssetPath(_))),
                "{bad:?} must be rejected"
            );
        }
        // 合法形态（WIT 契约：以 "/" 开头）。
        assert!(WebAssetPath::new("/index.html").is_ok());
    }

    #[test]
    fn web_action_invoke_binds_installation_and_version() {
        let harness = harness();
        let installation = install_web_component(&harness);
        // 授予 action 能力（§17.5：grant 绑定 InstallationId；§21.3
        // action permission 检查）。
        ok(
            harness
                .grants
                .replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        let (action, payload) = action_request();
        let response = ok(
            harness.web.invoke_action(installation, action, payload),
            "invoke action",
        );
        assert_eq!(response, vec![9, 8, 7]);
        assert_eq!(harness.runtime.action_calls(), 1);
        // 审计（§16.6：只记元数据，不记请求/响应体）。
        assert!(harness
            .audit
            .contains(|event| matches!(event, AuditEvent::ActionInvoked { action, .. } if action == "run-check")));
    }

    #[test]
    fn web_action_denied_without_grant() {
        let harness = harness();
        let installation = install_web_component(&harness);
        // 无 grant（deny-by-default，§17.2 / §21.3）→ 拒绝且 guest 不被调用。
        let (action, payload) = action_request();
        let result = harness.web.invoke_action(installation, action, payload);
        assert!(
            matches!(
                result,
                Err(ApplicationError::ActionDenied(ActionDenied::NotGranted))
            ),
            "ungranted action must be denied: {result:?}"
        );
        assert_eq!(harness.runtime.action_calls(), 0);
        assert!(harness.audit.contains(|event| matches!(
            event,
            AuditEvent::ActionDenied {
                reason: ActionDenied::NotGranted,
                ..
            }
        )));
    }

    #[test]
    fn web_action_scoped_grant_matches_action_name() {
        let harness = harness();
        let installation = install_web_component(&harness);
        // §17.3：资源级 scope——只授权 "run-check"，其他 action 被拒。
        ok(
            harness.grants.replace_grants(
                installation,
                &[InstallationGrant {
                    capability: ok(CapabilityId::new("operune:web/actions"), "capability"),
                    scope: GrantScope::Action {
                        name: "run-check".to_owned(),
                    },
                }],
            ),
            "scoped grant",
        );
        let (action, payload) = action_request();
        ok(
            harness.web.invoke_action(installation, action, payload),
            "invoke granted action",
        );
        let denied = harness.web.invoke_action(
            installation,
            ok(ActionName::new("other-action"), "action name"),
            GuestActionPayload::Json("{}".to_owned()),
        );
        assert!(
            matches!(
                denied,
                Err(ApplicationError::ActionDenied(ActionDenied::NotGranted))
            ),
            "scoped grant must deny other actions: {denied:?}"
        );
    }

    #[test]
    fn web_action_body_over_limit_denied() {
        // §21.3 body 检查点：超过宿主侧硬上限 → 确定拒绝。
        let config = RuntimeConfig {
            max_action_body_bytes: ByteSize::from_bytes(4),
            ..RuntimeConfig::default()
        };
        let grants: Arc<dyn GrantStorePort> = Arc::new(FakeGrants::new());
        let config_port: Arc<dyn ConfigPort> = Arc::new(FakeConfig::new(config));
        let policy = InProcessActionPolicy::new(Arc::clone(&grants), Arc::clone(&config_port));
        let installation = InstallationId::new();
        ok(
            grants.replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        let context = ActionContext {
            installation_id: installation,
            version: ComponentVersion::from_parts(1, 0, 0),
            action: ok(ActionName::new("run-check"), "action name"),
            body_size: ByteSize::from_bytes(10),
        };
        assert!(
            matches!(policy.check(&context), Err(ActionDenied::BodyTooLarge)),
            "oversized body must be denied"
        );
        let small = ActionContext {
            body_size: ByteSize::from_bytes(2),
            ..context.clone()
        };
        assert!(policy.check(&small).is_ok());
    }

    #[test]
    fn web_action_not_active_installation_denied() {
        // §21.3 绑定要求：action 只能调用 Active 快照中的安装。
        let harness = harness();
        let installation = install_web_component(&harness);
        ok(
            harness
                .grants
                .replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        let other = InstallationId::new();
        let result = harness.web.invoke_action(
            other,
            ok(ActionName::new("run-check"), "action name"),
            GuestActionPayload::Json("{}".to_owned()),
        );
        assert!(
            matches!(result, Err(ApplicationError::NotActiveForWeb(_))),
            "actions bind to active installations only: {result:?}"
        );
        // 快照中的安装正常调用不受影响。
        let (action, payload) = action_request();
        ok(
            harness.web.invoke_action(installation, action, payload),
            "invoke on active installation",
        );
    }

    #[test]
    fn web_action_response_contains_no_credentials() {
        // §21.3 凭据边界：响应类型只有字节（Vec<u8>）——结构上不可能
        // 携带 session bearer / CSRF / Set-Cookie（§16.5 / §21.3）。
        let harness = harness();
        let installation = install_web_component(&harness);
        ok(
            harness
                .grants
                .replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        let (action, payload) = action_request();
        let response = ok(
            harness.web.invoke_action(installation, action, payload),
            "invoke action",
        );
        // 响应为纯字节：无 header 集合、无 cookie、无凭据字段可设置。
        let bytes: &[u8] = &response;
        assert!(!bytes.is_empty());
    }

    /// 拒绝 policy（测试注入：模拟 auth/RBAC 层的拒绝，§21.3）。
    struct DenyAllPolicy;

    impl ActionPolicyPort for DenyAllPolicy {
        fn check(&self, _context: &ActionContext) -> Result<(), ActionDenied> {
            Err(ActionDenied::NotGranted)
        }
    }

    #[test]
    fn web_action_policy_port_is_invoked_before_guest() {
        // 服务端重做检查点（§21.3）：policy 拒绝 → guest 不被调用。
        let harness = harness();
        let installation = install_web_component(&harness);
        ok(
            harness
                .grants
                .replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        let audit = Arc::clone(&harness.audit) as Arc<dyn AuditPort>;
        let web = WebBridge::new(
            Arc::clone(&harness.active),
            Arc::clone(&harness.assets),
            Arc::new(DenyAllPolicy),
            audit,
        );
        let (action, payload) = action_request();
        let result = web.invoke_action(installation, action, payload);
        assert!(
            matches!(
                result,
                Err(ApplicationError::ActionDenied(ActionDenied::NotGranted))
            ),
            "policy denial must reach the caller: {result:?}"
        );
        assert_eq!(harness.runtime.action_calls(), 0);
    }

    #[test]
    fn rate_limit_denies_burst() {
        // §21.3 rate 检查：固定窗口限流（§15.2 有界语义）。
        let config = RuntimeConfig {
            max_actions_per_minute: 2,
            ..RuntimeConfig::default()
        };
        let harness = Harness::new(config);
        let installation = install_web_component(&harness);
        ok(
            harness
                .grants
                .replace_grants(installation, &[grant("operune:web/actions")]),
            "grant web actions",
        );
        for _ in 0..2 {
            ok(
                harness.web.invoke_action(
                    installation,
                    ok(ActionName::new("run-check"), "action name"),
                    GuestActionPayload::Json("{}".to_owned()),
                ),
                "action within limit",
            );
        }
        let result = harness.web.invoke_action(
            installation,
            ok(ActionName::new("run-check"), "action name"),
            GuestActionPayload::Json("{}".to_owned()),
        );
        assert!(
            matches!(
                result,
                Err(ApplicationError::ActionDenied(ActionDenied::RateLimited))
            ),
            "rate limit must deny the third action: {result:?}"
        );
    }

    /// 结构断言辅助：`GuestActionRequest` 无凭据字段（§21.3 凭据边界）。
    #[test]
    fn action_request_shape_has_no_credentials() {
        // 结构层面：请求类型只有 action + payload 两个字段，无
        // session/cookie/CSRF 字段（§21.3：浏览器内 Component 代码不接触
        // Root Admin session bearer 或 CSRF secret）。
        let request = crate::contract::GuestActionRequest {
            action: "run-check".to_owned(),
            payload: GuestActionPayload::Json("{}".to_owned()),
        };
        assert_eq!(request.action, "run-check");
        // WebBridge::invoke_action 的签名没有凭据参数（§16.5）。
        let _ = ok(ActionName::new(&request.action), "action name");
    }
}
