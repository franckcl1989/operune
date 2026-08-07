#![cfg(test)]

//! 测试支持：fake Component Web 用例 port（§32 注入缝）。
//!
//! application 的 `ActiveRuntimeRegistry::swap` 是 `pub(crate)`，测试无法
//! 填充真实 Active 快照（API 缺口，见 crate 文档）；HTTP 层测试注入
//! [`FakeWebPort`]。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use operune_application::cancel::CancellationToken;
use operune_application::contract::GuestActionPayload;
use operune_application::{ActionName, WebAssetPath};
use operune_domain::{AppDeclaration, ContentDigest, InstallationId, PageId, RouteId, TypedParam};

use crate::bridge::ComponentWebPort;
use crate::error::BridgeError;

/// 断言 `Result` 为 `Ok` 并取出值（workspace lints 禁止 unwrap/expect，
/// §26.1；测试断言语义）。
pub(crate) fn ok<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    assert!(
        result.is_ok(),
        "{what} 应成功，实际 Err: {:?}",
        result.as_ref().err()
    );
    match result {
        Ok(value) => value,
        Err(_) => unreachable!("上面的断言已保证 is_ok"),
    }
}

/// 断言 `Option` 为 `Some` 并取出值（测试断言语义，§26.1）。
pub(crate) fn some<T>(value: Option<T>, what: &str) -> T {
    assert!(value.is_some(), "{what} 应为 Some");
    match value {
        Some(value) => value,
        None => unreachable!("上面的断言已保证 is_some"),
    }
}

/// 页面访问检查的 fake 注入结果（§42.2 page permission 强制执行点）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PageAccessOutcome {
    /// 授权链通过。
    Allowed,
    /// 授权链拒绝（→ 403）。
    Denied,
}

/// 脚本化 fake（每安装一份行为；0.1 + 0.4 面）。
pub(crate) struct FakeWebPort {
    state: Mutex<FakeState>,
}

#[derive(Default)]
struct FakeState {
    /// 安装 → 激活 digest。
    digests: HashMap<InstallationId, ContentDigest>,
    /// 安装 → 入口资产。
    entries: HashMap<InstallationId, WebAssetPath>,
    /// 安装 → (路径 → 资产字节)。
    assets: HashMap<(InstallationId, WebAssetPath), Vec<u8>>,
    /// 安装 → action 结果（Err = 注入拒绝）。
    action_results: HashMap<InstallationId, Result<Vec<u8>, BridgeError>>,
    /// action 调用计数（断言 Core-mediated 只调用一次）。
    action_calls: usize,
    /// 安装 → 0.4 app declaration（None 状态 = 无 0.2 surface / 0.1 组件）。
    declarations: HashMap<InstallationId, AppDeclaration>,
    /// 安装 → route 调用结果（Err = 注入拒绝）。
    route_results: HashMap<InstallationId, Result<Vec<u8>, BridgeError>>,
    /// 安装 → 页面访问检查结果（未配置 → 拒绝，deny-by-default §17.2）。
    page_access: HashMap<InstallationId, PageAccessOutcome>,
    /// route 调用计数。
    route_calls: usize,
    /// 最近一次 route 调用的参数（断言 typed 参数解析）。
    last_route_params: Option<Vec<TypedParam>>,
    /// 最近一次 route 调用收到令牌时令牌是否已取消（断言取消探针
    /// 新鲜性——调用期间必须未取消）。
    last_route_token_cancelled: Option<bool>,
    /// 最近一次 route 调用收到的令牌（handler 完成后由 CancelOnDrop
    /// 取消——测试在 oneshot 返回后断言 `is_cancelled`）。
    last_cancel: Option<CancellationToken>,
    /// 阻塞式 route 行为（§42.2 backpressure / 并发测试）：invoke_route
    /// 同步自旋直到令牌取消或 1s 上限（hold 住并发槽）。
    block_route: bool,
}

impl FakeWebPort {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(FakeState::default()),
        }
    }

    pub(crate) fn with_digest(&self, installation: InstallationId, digest: ContentDigest) {
        if let Ok(mut state) = self.state.lock() {
            state.digests.insert(installation, digest);
        }
    }

    pub(crate) fn with_entry(&self, installation: InstallationId, path: WebAssetPath) {
        if let Ok(mut state) = self.state.lock() {
            state.entries.insert(installation, path);
        }
    }

    pub(crate) fn with_asset(
        &self,
        installation: InstallationId,
        path: WebAssetPath,
        bytes: Vec<u8>,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.assets.insert((installation, path), bytes);
        }
    }

    pub(crate) fn with_action_result(
        &self,
        installation: InstallationId,
        result: Result<Vec<u8>, BridgeError>,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.action_results.insert(installation, result);
        }
    }

    pub(crate) fn action_calls(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.action_calls,
            Err(_) => 0,
        }
    }

    pub(crate) fn with_declaration(
        &self,
        installation: InstallationId,
        declaration: AppDeclaration,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.declarations.insert(installation, declaration);
        }
    }

    pub(crate) fn with_route_result(
        &self,
        installation: InstallationId,
        result: Result<Vec<u8>, BridgeError>,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.route_results.insert(installation, result);
        }
    }

    pub(crate) fn with_page_access(
        &self,
        installation: InstallationId,
        outcome: PageAccessOutcome,
    ) {
        if let Ok(mut state) = self.state.lock() {
            state.page_access.insert(installation, outcome);
        }
    }

    /// 开启阻塞式 route 行为（并发 / backpressure 测试用）：invoke_route
    /// 同步自旋直到令牌取消或 1s 上限（hold 住并发槽）。
    pub(crate) fn with_blocking_route(&self, _installation: InstallationId) {
        if let Ok(mut state) = self.state.lock() {
            state.block_route = true;
        }
    }

    pub(crate) fn route_calls(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.route_calls,
            Err(_) => 0,
        }
    }

    pub(crate) fn last_route_params(&self) -> Option<Vec<TypedParam>> {
        match self.state.lock() {
            Ok(state) => state.last_route_params.clone(),
            Err(_) => None,
        }
    }

    pub(crate) fn last_route_token_was_fresh(&self) -> Option<bool> {
        match self.state.lock() {
            Ok(state) => state.last_route_token_cancelled,
            Err(_) => None,
        }
    }

    pub(crate) fn last_cancel_token(&self) -> Option<CancellationToken> {
        match self.state.lock() {
            Ok(state) => state.last_cancel.clone(),
            Err(_) => None,
        }
    }
}

impl ComponentWebPort for FakeWebPort {
    fn active_digest(&self, installation: InstallationId) -> Option<ContentDigest> {
        match self.state.lock() {
            Ok(state) => state.digests.get(&installation).copied(),
            Err(_) => None,
        }
    }

    fn entry_asset(&self, installation: InstallationId) -> Option<WebAssetPath> {
        match self.state.lock() {
            Ok(state) => state.entries.get(&installation).cloned(),
            Err(_) => None,
        }
    }

    fn read_asset(
        &self,
        installation: InstallationId,
        path: &WebAssetPath,
    ) -> Result<Arc<Vec<u8>>, BridgeError> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err(BridgeError::Application(
                    operune_application::ApplicationError::Internal("fake state poisoned"),
                ));
            }
        };
        match state.assets.get(&(installation, path.clone())) {
            Some(bytes) => Ok(Arc::new(bytes.clone())),
            None => Err(BridgeError::NotActiveForWeb(installation)),
        }
    }

    fn invoke_action(
        &self,
        installation: InstallationId,
        _action: ActionName,
        _payload: GuestActionPayload,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err(BridgeError::Application(
                    operune_application::ApplicationError::Internal("fake state poisoned"),
                ));
            }
        };
        state.action_calls = state.action_calls.saturating_add(1);
        match state.action_results.remove(&installation) {
            Some(result) => result,
            // 未配置结果 = 安装未激活（deny-by-default，§17.2）。
            None => Err(BridgeError::NotActiveForWeb(installation)),
        }
    }

    fn app_declaration(&self, installation: InstallationId) -> Option<AppDeclaration> {
        match self.state.lock() {
            Ok(state) => state.declarations.get(&installation).cloned(),
            Err(_) => None,
        }
    }

    fn check_page_access(
        &self,
        installation: InstallationId,
        _page_id: &PageId,
    ) -> Result<(), BridgeError> {
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(BridgeError::PageDenied),
        };
        match state.page_access.get(&installation) {
            Some(PageAccessOutcome::Allowed) => Ok(()),
            Some(PageAccessOutcome::Denied) | None => Err(BridgeError::PageDenied),
        }
    }

    fn invoke_route(
        &self,
        installation: InstallationId,
        _route_id: RouteId,
        params: Vec<TypedParam>,
        _payload: Option<GuestActionPayload>,
        cancel: &CancellationToken,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return Err(BridgeError::Application(
                    operune_application::ApplicationError::Internal("fake state poisoned"),
                ));
            }
        };
        state.route_calls = state.route_calls.saturating_add(1);
        state.last_route_params = Some(params);
        let fresh = !cancel.is_cancelled();
        state.last_route_token_cancelled = Some(fresh);
        state.last_cancel = Some(cancel.clone());
        if state.block_route {
            drop(state);
            // 阻塞式：同步自旋直到令牌取消或 1s 上限（§42.2 并发 /
            // backpressure 的 fake 观察点；hold 住并发槽）。
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            while !cancel.is_cancelled() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            if cancel.is_cancelled() {
                return Err(BridgeError::Cancelled);
            }
            return Ok(vec![]);
        }
        match state.route_results.remove(&installation) {
            Some(result) => result,
            // 未配置结果 = 安装未激活（deny-by-default，§17.2）。
            None => Err(BridgeError::NotActiveForWeb(installation)),
        }
    }
}
