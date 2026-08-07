//! `WasiAdapter` port 实现（§8.2：adapter crate 实现 runtime-wasm 定义的
//! adapter 契约）。
//!
//! [`WasiContextAdapter`] 实现 [`operune_runtime_wasm::wasi::WasiAdapter`]：
//! [`WasiAdapter::attach`] 把按能力规格构建的 WASI 0.2 context 安装进
//! Store 宿主状态（[`StoreHostState::set_wasi_state`]），即 §8.2 分层图中
//! runtime-wasm ↔ runtime-wasi-p2 的真实接线点。
//!
//! # 为什么 adapter 不是 `WasiContextBuilder` 本身
//!
//! wasmtime-wasi 36 的 `WasiCtxBuilder` 内含 `Box<dyn RngCore + Send>`
//! 随机源（`WasiRandomCtx`），不满足 `WasiAdapter: Send + Sync` 约束；
//! 因此 adapter 类型只持有能力规格（[`WasiCapabilities`]，`Send + Sync`），
//! attach 时现场经 [`WasiContextBuilder`] 构建 context（§13.4：不持有
//! 不可共享的中间状态）。
//!
//! # policy → capabilities 的语义映射（§7.6 / §17.2）
//!
//! 0.1.0 的 [`WasiPolicy`] 只有版本维度、无能力字段（见 runtime-wasm
//! wasi.rs 文档：能力字段随 adapter 里程碑扩展）。因此 attach 的能力值
//! 来自 adapter 自身的 [`WasiContextAdapter::with_capabilities`]（由
//! application 按 §17 grant 快照逐计划构建，deny-by-default：未显式
//! 构建任何能力 = 零权限 context）；policy 只做版本门控。两者共同满足
//! §7.6：attach 绝不授予 policy/adapter 未声明的能力。
//!
//! # fail closed（§17.2 / §7.6）
//!
//! - 版本不匹配（policy 要求非 P2）→ [`WasiError::VersionMismatch`]，Store
//!   构建整体拒绝；
//! - context 构建失败（如声明的 preopen host 路径不可打开）→
//!   [`WasiError::Attach`]，Store 构建整体拒绝——绝不静默跳过已声明能力。
//!
//! # 分层（§8.2）
//!
//! 本 crate 依赖 runtime-wasm（port 定义层，§24.3：adapter → port 定义层）；
//! runtime-wasm 不依赖本 crate，无依赖环。

use operune_runtime_wasm::StoreHostState;
use operune_runtime_wasm::wasi::{
    WasiAdapter, WasiError, WasiP2HostState, WasiPolicy, WasiVersion,
};

use crate::capability::WasiCapabilities;
use crate::context::WasiContextBuilder;

/// WASI adapter 实例（§8.2：adapter crate 实现的 `WasiAdapter` port 类型）。
///
/// 持有能力规格（`Send + Sync`）；`attach` 时现场构建 context（见模块
/// 文档的"为什么不是 WasiContextBuilder"说明）。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WasiContextAdapter {
    capabilities: WasiCapabilities,
}

impl WasiContextAdapter {
    /// 零权限 adapter（deny-by-default，§7.6：attach 不授予任何能力）。
    pub fn new() -> Self {
        Self::default()
    }

    /// 用一份能力集合整体替换当前集合（replace 语义，可预期）。
    ///
    /// 消费并返回自身，支持链式
    /// `WasiContextAdapter::new().with_capabilities(caps)`；
    /// 传入 [`WasiCapabilities::empty`] 等价于保持零权限默认。
    pub fn with_capabilities(mut self, capabilities: WasiCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
}

impl WasiAdapter for WasiContextAdapter {
    /// 该 adapter 支持的 WASI 主版本（0.1.0 production 只启用 WASI 0.2，
    /// §4.2 / §22.2）。
    fn version(&self) -> WasiVersion {
        WasiVersion::P2
    }

    /// 按 policy 构建 WASI context 并安装进 Store 宿主状态（§8.2 接线点）。
    ///
    /// 流程：版本门控（fail closed）→ 构建 context（能力值来自本 adapter
    /// 的 `with_capabilities`，见模块文档的 policy 映射说明）→
    /// [`WasiContext::into_p2_inner`] 迁移内层 ctx → `WasiP2HostState::new`
    /// → [`StoreHostState::set_wasi_state`] 整体替换（Store 构建时预置的是
    /// 零权限空 context，§7.6 deny-by-default）。
    ///
    /// # Errors
    ///
    /// - [`WasiError::VersionMismatch`]：policy 要求的版本不是 P2；
    /// - [`WasiError::Attach`]：context 构建失败（已声明能力无法满足，
    ///   §17.2 不静默跳过）。
    fn attach(
        &self,
        policy: &WasiPolicy,
        host_state: &mut StoreHostState,
    ) -> Result<(), WasiError> {
        // §17.2 fail closed：版本不匹配拒绝整个 Store 构建（StoreFactory
        // 已在 with_wasi 校验一次，此处为 adapter 侧防御性复检）。
        if policy.version() != WasiVersion::P2 {
            return Err(WasiError::VersionMismatch {
                adapter: WasiVersion::P2,
                requested: policy.version(),
            });
        }
        // 构建失败 = 能力无法满足 → 整体拒绝（绝不静默跳过，§17.2）。
        let context = WasiContextBuilder::new()
            .with_capabilities(self.capabilities.clone())
            .build()
            .map_err(|error| WasiError::Attach(Box::new(error)))?;
        host_state.set_wasi_state(WasiP2HostState::new(context.into_p2_inner()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use operune_runtime_wasm::wasi::{WasiAdapter, WasiPolicy, WasiVersion};
    use operune_runtime_wasm::{EngineConfig, EngineHandle, ResourceBudget, StoreFactory};
    use wasmtime_wasi::WasiView;

    use crate::capability::{EnvVarSpec, FsPerms, GuestPath, PreopenDirSpec, WasiCapabilities};
    use crate::error::WasiP2Error;

    /// 断言式失败（测试代码的断言语义，§26.1 允许）。
    #[allow(clippy::assertions_on_constants)]
    fn test_failure(message: impl std::fmt::Display) -> ! {
        assert!(false, "{message}");
        std::process::abort();
    }

    fn expect_ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => test_failure(format_args!("{what} failed: {error}")),
        }
    }

    /// 共享测试 Engine（§7.1：Engine 长期共享、配置不可变）。
    fn engine() -> EngineHandle {
        expect_ok(
            EngineHandle::new(EngineConfig::default()),
            "engine creation",
        )
    }

    /// 默认（零权限）adapter attach 后：Store 的 WasiView ctx 为零权限
    /// 默认（§7.6 deny-by-default——attach 不授予任何未声明能力）。
    #[test]
    fn attach_with_default_adapter_installs_zero_capability_context() {
        let engine = engine();
        let adapter = WasiContextAdapter::new();
        assert_eq!(WasiAdapter::version(&adapter), WasiVersion::P2);
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &adapter, &WasiPolicy::p2()),
            "store factory with default wasi adapter",
        );
        let mut store = expect_ok(
            factory.new_store(&ResourceBudget::default()),
            "store creation with wasi attach",
        );
        let view = WasiView::ctx(store.store_mut().data_mut());
        assert!(view.ctx.cli().environment.is_empty());
        assert!(view.ctx.cli().arguments.is_empty());
        assert!(!view.ctx.sockets().allowed_network_uses.tcp);
        assert!(!view.ctx.sockets().allowed_network_uses.udp);
        assert!(!view.ctx.sockets().allowed_network_uses.ip_name_lookup);
        assert_eq!(view.ctx.random().insecure_random_seed, 0);
    }

    /// attach 经 `with_capabilities` 显式构建的能力生效（§7.6：能力只经
    /// 显式构建进入 context）。
    #[test]
    fn attach_applies_explicitly_built_capabilities() {
        let engine = engine();
        let mut caps = WasiCapabilities::empty();
        let spec = match EnvVarSpec::new("OPERUNE_ADAPTER_TEST", "attached") {
            Ok(spec) => spec,
            Err(_) => test_failure("env spec construction failed"),
        };
        caps.add_env(spec);
        let adapter = WasiContextAdapter::new().with_capabilities(caps);
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &adapter, &WasiPolicy::p2()),
            "store factory with capability adapter",
        );
        let mut store = expect_ok(
            factory.new_store(&ResourceBudget::default()),
            "store creation with wasi attach",
        );
        let view = WasiView::ctx(store.store_mut().data_mut());
        assert_eq!(
            view.ctx.cli().environment,
            vec![("OPERUNE_ADAPTER_TEST".to_owned(), "attached".to_owned())]
        );
        // 其他维度仍为零权限默认。
        assert!(!view.ctx.sockets().allowed_network_uses.tcp);
        assert_eq!(view.ctx.random().insecure_random_seed, 0);
    }

    /// preopen 能力以真实目录构建成功（attach 正常路径）。
    #[test]
    fn attach_with_preopen_capability_succeeds() {
        let engine = engine();
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(_) => test_failure("tempdir creation failed"),
        };
        let mut caps = WasiCapabilities::empty();
        let guest = match GuestPath::new("data") {
            Ok(path) => path,
            Err(_) => test_failure("guest path construction failed"),
        };
        let spec = match PreopenDirSpec::new(
            guest,
            dir.path().to_path_buf(),
            FsPerms::READ_ONLY,
            FsPerms::READ_ONLY,
        ) {
            Ok(spec) => spec,
            Err(_) => test_failure("preopen spec construction failed"),
        };
        match caps.add_preopen(spec) {
            Ok(()) => {}
            Err(_) => test_failure("add preopen failed"),
        }
        let adapter = WasiContextAdapter::new().with_capabilities(caps);
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &adapter, &WasiPolicy::p2()),
            "store factory with preopen adapter",
        );
        // attach 成功即证明 host 目录被打开并经标准 preopened_dir 注册。
        let store = expect_ok(
            factory.new_store(&ResourceBudget::default()),
            "store creation with preopen attach",
        );
        drop(store);
    }

    /// fail closed（§17.2）：已声明能力无法满足（preopen host 路径不存在）
    /// → 整个 Store 构建被拒绝，不静默跳过。
    #[test]
    fn attach_failure_rejects_whole_store() {
        let engine = engine();
        let mut caps = WasiCapabilities::empty();
        let missing_host = match tempfile::tempdir() {
            Ok(dir) => dir.path().join("does-not-exist"),
            Err(_) => test_failure("tempdir creation failed"),
        };
        let guest = match GuestPath::new("data") {
            Ok(path) => path,
            Err(_) => test_failure("guest path construction failed"),
        };
        let spec = match PreopenDirSpec::new(
            guest,
            missing_host,
            FsPerms::READ_ONLY,
            FsPerms::READ_ONLY,
        ) {
            Ok(spec) => spec,
            Err(_) => test_failure("preopen spec construction failed"),
        };
        match caps.add_preopen(spec) {
            Ok(()) => {}
            Err(_) => test_failure("add preopen failed"),
        }
        let adapter = WasiContextAdapter::new().with_capabilities(caps);
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &adapter, &WasiPolicy::p2()),
            "store factory with failing preopen adapter",
        );
        let result = factory.new_store(&ResourceBudget::default());
        match result {
            Ok(_) => test_failure("store must be rejected when WASI attach fails"),
            Err(error) => {
                let source = match error {
                    operune_runtime_wasm::RuntimeError::Wasi(
                        operune_runtime_wasm::WasiError::Attach(source),
                    ) => source,
                    other => {
                        test_failure(format_args!("expected Wasi attach error, got {other:?}"))
                    }
                };
                // 底层是 preopen 打开失败（typed WasiP2Error，§14.1）。
                let downcast = source.downcast_ref::<WasiP2Error>();
                match downcast {
                    Some(WasiP2Error::PreopenOpen { .. }) => {}
                    _ => test_failure(format_args!("expected PreopenOpen source, got {source:?}")),
                }
            }
        }
    }

    /// adapter 版本面：固定 P2（0.1.0 production 只启用 WASI 0.2，§4.2）。
    #[test]
    fn adapter_version_is_p2() {
        let adapter = WasiContextAdapter::new();
        assert_eq!(WasiAdapter::version(&adapter), WasiVersion::P2);
    }
}
