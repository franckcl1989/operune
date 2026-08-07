#![cfg(test)]

//! 测试支持：fake Component Web 用例 port（§32 注入缝）。
//!
//! application 的 `ActiveRuntimeRegistry::swap` 是 `pub(crate)`，测试无法
//! 填充真实 Active 快照（API 缺口，见 crate 文档）；HTTP 层测试注入
//! [`FakeWebPort`]。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use operune_application::contract::GuestActionPayload;
use operune_application::{ActionName, WebAssetPath};
use operune_domain::{ContentDigest, InstallationId};

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

/// 脚本化 fake（每安装一份行为）。
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
}
