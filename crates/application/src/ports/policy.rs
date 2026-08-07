//! Web bridge 的服务端重做检查点（§21.3）。
//!
//! §21.3 要求 Core 在服务端重新执行 authentication、RBAC、grant、action
//! permission、body/deadline/rate/concurrency 检查；HTTP 层（web-admin）
//! 负责把检查点实现为完整链（auth/RBAC/session 是 web-admin 的职责，
//! §24.2）。本 crate 提供该检查点的 port 形状与默认实现
//! [`InProcessActionPolicy`]（grant / body / rate 的进程内检查；
//! concurrency 由运行时 InstanceSet 强制，§7.4）。

use std::sync::Mutex;
use std::time::{Duration, Instant};

use operune_domain::{ByteSize, ComponentVersion, InstallationId};

use crate::model::{ActionDenied, ActionName, GrantScope, RuntimeConfig};
use crate::ports::GrantStorePort;

/// 服务端重做检查的上下文（§21.3：frame/channel 与 InstallationId +
/// ComponentVersion 绑定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionContext {
    /// 绑定安装实例。
    pub installation_id: InstallationId,
    /// 绑定当前版本（§21.5：UI 与 backend 随同一 ComponentVersion 原子切换）。
    pub version: ComponentVersion,
    /// action 名称。
    pub action: ActionName,
    /// 请求体大小（body 上限检查，§21.3）。
    pub body_size: ByteSize,
}

/// Action policy port（web-admin 等适配层实现完整 auth/RBAC 链）。
pub trait ActionPolicyPort: Send + Sync {
    /// 服务端重做检查（§21.3）。拒绝返回 [`ActionDenied`]。
    fn check(&self, context: &ActionContext) -> Result<(), ActionDenied>;
}

/// 默认进程内 policy（grant + body + rate；§17.5 Grant 层 / §21.3）。
///
/// - grant：安装实例必须拥有 `operune:web/actions` 能力，且 scope 为
///   [`GrantScope::Unscoped`] 或匹配 [`GrantScope::Action`]（§17.3 资源级
///   scope）；
/// - body：≤ `RuntimeConfig::max_action_body_bytes`（§21.3）；
/// - rate：固定窗口限流（`max_actions_per_minute`，每安装独立窗口，§15.2
///   有界语义）；窗口表按安装实例惰性创建并在窗口过期时回收。
///
/// concurrency 检查由运行时实例集强制（[`crate::runtime`] 的
/// dispatch Busy 语义，§7.4），不在本 policy 内重复计数。
pub struct InProcessActionPolicy {
    grants: std::sync::Arc<dyn GrantStorePort>,
    config: std::sync::Arc<dyn crate::ports::ConfigPort>,
    windows: Mutex<std::collections::HashMap<InstallationId, RateWindow>>,
}

/// 固定窗口计数（§21.3 rate 检查）。
struct RateWindow {
    /// 窗口起点。
    start: Instant,
    /// 窗口内计数。
    count: u32,
}

/// 每安装 action 权限能力的规范化能力 id（§17：grant 以该能力表达
/// "web backend action" 授权）。
pub const WEB_ACTIONS_CAPABILITY: &str = "operune:web/actions";

impl InProcessActionPolicy {
    /// 构造（注入 grant store 与 config）。
    pub fn new(
        grants: std::sync::Arc<dyn GrantStorePort>,
        config: std::sync::Arc<dyn crate::ports::ConfigPort>,
    ) -> Self {
        Self {
            grants,
            config,
            windows: Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl ActionPolicyPort for InProcessActionPolicy {
    fn check(&self, context: &ActionContext) -> Result<(), ActionDenied> {
        let config = match self.config.snapshot() {
            Ok(config) => config,
            Err(_) => return Err(ActionDenied::Unknown),
        };
        self.check_grants(context)?;
        self.check_body(context, &config)?;
        self.check_rate(context, &config)
    }
}

impl InProcessActionPolicy {
    fn check_grants(&self, context: &ActionContext) -> Result<(), ActionDenied> {
        let grants = self
            .grants
            .grants_for(context.installation_id)
            .map_err(|_| ActionDenied::Unknown)?;
        let permitted = grants.iter().any(|grant| {
            grant.capability.as_str() == WEB_ACTIONS_CAPABILITY
                && match &grant.scope {
                    GrantScope::Unscoped => true,
                    GrantScope::Action { name } => name == context.action.as_str(),
                    // preopen / env 不是 action 授权。
                    GrantScope::WasiPreopen { .. } | GrantScope::WasiEnv { .. } => false,
                }
        });
        if permitted {
            Ok(())
        } else {
            Err(ActionDenied::NotGranted)
        }
    }

    fn check_body(
        &self,
        context: &ActionContext,
        config: &RuntimeConfig,
    ) -> Result<(), ActionDenied> {
        if context.body_size.exceeds(config.max_action_body_bytes) {
            Err(ActionDenied::BodyTooLarge)
        } else {
            Ok(())
        }
    }

    fn check_rate(
        &self,
        context: &ActionContext,
        config: &RuntimeConfig,
    ) -> Result<(), ActionDenied> {
        let window_secs = 60u64;
        let limit = config.max_actions_per_minute;
        let mut windows = self.windows.lock().map_err(|_| ActionDenied::Unknown)?;
        let now = Instant::now();
        let window = windows
            .entry(context.installation_id)
            .or_insert_with(|| RateWindow {
                start: now,
                count: 0,
            });
        // 窗口过期 → 重置（回收旧窗口状态，保持有界）。
        if now.duration_since(window.start) >= Duration::from_secs(window_secs) {
            window.start = now;
            window.count = 0;
        }
        if window.count >= limit {
            return Err(ActionDenied::RateLimited);
        }
        window.count = window.count.saturating_add(1);
        Ok(())
    }
}
