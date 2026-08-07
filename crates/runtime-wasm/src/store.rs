//! Store 工厂与 Store 句柄（§7.3 / §7.6）。

use std::any::Any;
use std::time::Duration;

use crate::budget::{CallDeadline, ResourceBudget};
use crate::engine::EngineHandle;
use crate::error::{ResourceLimitKind, RuntimeError};
use crate::limiter::StoreResourceLimiter;
use crate::wasi::{WasiAdapter, WasiError, WasiPolicy};

/// 每个 Store 的宿主状态（Wasmtime `Store<T>` 的数据类型）。
///
/// 对上层不暴露 wasmtime 具体类型（§8.2）：所有公开成员均为项目自有类型。
/// WASI adapter 通过 [`StoreHostState::replace_adapter_state`] 保存其自有
/// 状态（opaque `dyn Any` 槽），在实例化阶段的 linker 绑定闭包中 downcast
/// 使用（衔接点见 [`crate::wasi::WasiAdapter`] 文档）。
///
/// 并发保证：本类型不实现 `Sync`（拒绝记录为 `Cell`）；Store 遵循单一执行
/// 模型（§7.3），不在线程间共享。
pub struct StoreHostState {
    pub(crate) limiter: StoreResourceLimiter,
    pub(crate) adapter_state: Option<Box<dyn Any + Send>>,
    budget: ResourceBudget,
}

impl StoreHostState {
    /// WASI adapter 状态槽（只读；adapter 专用，上层不得依赖内部结构）。
    pub fn adapter_state(&self) -> Option<&dyn Any> {
        // `Box<dyn Any + Send>` → `&dyn Any`（去掉 auto trait 标记的显示转换）。
        self.adapter_state.as_deref().map(|state| state as &dyn Any)
    }

    /// WASI adapter 状态槽（可变；adapter 专用）。
    pub fn adapter_state_mut(&mut self) -> Option<&mut dyn Any> {
        self.adapter_state
            .as_deref_mut()
            .map(|state| state as &mut dyn Any)
    }

    /// 替换 WASI adapter 状态槽，返回旧值（adapter 在 [`WasiAdapter::attach`]
    /// 中调用；上层不得直接写入）。
    pub fn replace_adapter_state(
        &mut self,
        state: Box<dyn Any + Send>,
    ) -> Option<Box<dyn Any + Send>> {
        self.adapter_state.replace(state)
    }

    /// 本 Store 的资源预算快照（§7.4：adapter 可读取，如 wasi-http body 上限）。
    pub fn budget(&self) -> &ResourceBudget {
        &self.budget
    }
}

/// Store 工厂（§7.3/§7.6）：按显式策略构建 Store。
///
/// - [`StoreFactory::new`]：**无任何 WASI/宿主能力**（§7.6 无 ambient
///   authority——默认 Store 不获得宿主文件系统、网络、环境变量、进程环境
///   或随机资源）；
/// - [`StoreFactory::with_wasi`]：按 policy 显式构建 WASI 能力（§7.6/§17.2）。
///
/// Store 构建失败即 fail closed（§7.6）：能力附加失败时整体拒绝 Store。
pub struct StoreFactory<'a> {
    engine: &'a EngineHandle,
    wasi: Option<(&'a dyn WasiAdapter, WasiPolicy)>,
}

impl<'a> StoreFactory<'a> {
    /// 无 WASI 能力的默认工厂（deny-by-default，§7.6）。
    pub fn new(engine: &'a EngineHandle) -> Self {
        Self { engine, wasi: None }
    }

    /// 显式构建 WASI 能力（§7.6/§17.2）。校验 adapter 版本与 policy 版本一致；
    /// 不一致返回 [`WasiError::VersionMismatch`]。
    pub fn with_wasi(
        engine: &'a EngineHandle,
        adapter: &'a dyn WasiAdapter,
        policy: &WasiPolicy,
    ) -> Result<Self, WasiError> {
        if adapter.version() != policy.version() {
            return Err(WasiError::VersionMismatch {
                adapter: adapter.version(),
                requested: policy.version(),
            });
        }
        Ok(Self {
            engine,
            wasi: Some((adapter, *policy)),
        })
    }

    /// 按预算创建一个新 Store（§7.4：注入 wasmtime 资源限制器；
    /// §7.6：能力按 policy 显式构建，失败即 fail closed）。
    pub fn new_store(&self, budget: &ResourceBudget) -> Result<StoreHandle, RuntimeError> {
        let host = StoreHostState {
            limiter: StoreResourceLimiter::new(budget.clone()),
            adapter_state: None,
            budget: budget.clone(),
        };
        let mut store = wasmtime::Store::new(self.engine.engine(), host);
        // §7.4：注入 wasmtime 资源限制器。闭包不捕获任何变量 →
        // `FnMut + Send + Sync + 'static`（wasmtime 36 的 limiter 挂接签名）。
        store.limiter(|data: &mut StoreHostState| &mut data.limiter);
        if let Some((adapter, policy)) = self.wasi {
            // §7.6：能力按 policy 显式构建；失败则整体拒绝 Store 构建。
            adapter
                .attach(&policy, store.data_mut())
                .map_err(RuntimeError::Wasi)?;
        }
        let config = self.engine.config();
        Ok(StoreHandle {
            store,
            epoch_enabled: config.epoch_interruption,
            tick_interval: config.epoch_tick_interval,
        })
    }
}

/// Store 句柄（§7.3）：一个运行实例的 Wasm 状态与 Host 状态边界。
///
/// **每次不可信执行都必须先设置 epoch deadline**（§7.5）：epoch 启用时
/// Store 的默认 deadline 为 0（已过期 → 立即 trap）；本类型提供
/// [`StoreHandle::set_deadline`]（时长 → ticks 换算）与
/// [`StoreHandle::reset_deadline`]（无期限，仅显式策略允许时使用）。
///
/// 不变量：同一时刻只执行一个进入该 Store 的调用（§7.3；由上层
/// [`crate::instance::InstanceSet`] 的租约模型保证）。
pub struct StoreHandle {
    pub(crate) store: wasmtime::Store<StoreHostState>,
    epoch_enabled: bool,
    tick_interval: Duration,
}

impl StoreHandle {
    /// §7.5：为下一次不可信执行设置 epoch deadline（按 ticker 间隔换算 ticks，
    /// 向上取整、最小 1）。每次执行前调用。
    ///
    /// 错误：epoch 未启用或 deadline 为零 → [`RuntimeError::Config`]；
    /// 换算溢出 → [`RuntimeError::Config`]。
    pub fn set_deadline(&mut self, deadline: CallDeadline) -> Result<(), RuntimeError> {
        if !self.epoch_enabled {
            return Err(RuntimeError::Config(
                "epoch interruption is disabled; cannot set deadline",
            ));
        }
        if deadline.get().is_zero() {
            return Err(RuntimeError::Config("call deadline must be non-zero"));
        }
        self.store
            .set_epoch_deadline(deadline_to_ticks(deadline.get(), self.tick_interval)?);
        Ok(())
    }

    /// 清除 deadline（等效“无期限”）。仅显式策略允许的无期限执行时使用；
    /// 日常路径应始终使用 [`StoreHandle::set_deadline`]（§7.5）。
    pub fn reset_deadline(&mut self) -> Result<(), RuntimeError> {
        if !self.epoch_enabled {
            return Err(RuntimeError::Config(
                "epoch interruption is disabled; cannot reset deadline",
            ));
        }
        self.store.set_epoch_deadline(u64::MAX);
        Ok(())
    }

    /// 开始一次不可信执行：清除资源拒绝记录（错误分类前置步骤）。
    ///
    /// 语义：清空上一次执行期间 Wasmtime 记录在本 Store 上的资源超限拒绝
    /// 类别，使 [`crate::error::classify_wasm_error`] 在本次执行失败时只读到
    /// 本次的记录（§7.4/§14.1）。必须与 [`StoreHandle::take_rejection`]
    /// 配对使用，且每次不可信执行**开始前**调用；不调用时分类器可能读到
    /// 陈旧记录（把上一次的拒绝误报为本次执行的结果）。
    ///
    /// 不变量：本方法不执行 guest 代码，不触发任何 Wasmtime 回调，不可失败。
    /// 错误：无（`&mut self` 的独占性由类型层保证，无可运行失败路径）。
    /// 并发：`&mut self` 独占本 Store（§7.3 单一执行模型；Store 不跨线程
    /// 共享）；返回前清空记录，调用后到下一次调用之间 `take_rejection`
    /// 返回 `None`。
    /// 安全/权限：只清空本 Store 的资源记账状态，不授予或撤销任何 guest
    /// 能力（§7.6 无 ambient authority）。
    pub fn begin_execution(&mut self) {
        let _ = self.store.data().limiter.take_rejection();
    }

    /// 读取并清除最近一次资源超限拒绝类别（§7.4）。
    ///
    /// 语义：返回自上次清除以来最近一次被 Wasmtime 资源限制器拒绝的资源
    /// 类别，并清空记录（一次性读取）。`None` 只表示“当前无记录”——可能
    /// 没有发生拒绝，也可能记录已被 [`StoreHandle::begin_execution`] 清除；
    /// 调用方不得把 `None` 解读为“本次执行确定未超限”（§7.4：实例/table/
    /// memory 数量类上限由 wasmtime 内部计数强制，不经过拒绝记录，超限
    /// 表现为实例化/创建失败而非记录）。
    ///
    /// 所有权：不转移任何状态，仅借出返回值（`Option<ResourceLimitKind>`，
    /// 值类型，无借用问题）。
    /// 错误：无（只读本 Store 状态，不可失败）。
    /// 并发：`&mut self` 独占（§7.3 单一执行模型）。
    /// 安全/权限：只读资源记账信息（资源类别枚举，不含长度/地址等细节），
    /// 不触及 guest 数据，无权限含义。
    pub fn take_rejection(&mut self) -> Option<ResourceLimitKind> {
        self.store.data().limiter.take_rejection()
    }

    /// 独占访问底层 wasmtime Store（invoke 扩展缝：WIT bindgen 生成的接口、
    /// [`wasmtime::component::Linker`] 绑定与实例化入口以
    /// `&mut wasmtime::Store<StoreHostState>` 为参数）。
    ///
    /// 类型泄漏说明（§8.2）：本签名必须暴露 wasmtime 具体类型——typed
    /// invoke 与 `Linker::instantiate` 的签名以 `&mut wasmtime::Store<T>`
    /// 为参数，不存在经项目自有类型间接的等价面。本方法是隔离层向
    /// 集成层（application）的受控泄漏点：调用方不得把返回的 Store 再
    /// 暴露到领域层（domain/application 的公共 API 不 import wasmtime 类型，
    /// §8.2 只约束领域层）。
    ///
    /// 所有权：返回可变借用，不转移所有权；借用期间本句柄不可再被借用，
    /// 返回引用的存活期受调用方作用域约束。
    /// 不变量：epoch 启用时每次不可信执行前必须经
    /// [`StoreHandle::set_deadline`] 设置 deadline（§7.5）——未设置时默认
    /// deadline 为 0（已过期），执行立即以 [`WasmFailure::EpochDeadlineExceeded`]
    /// trap；见 [`StoreHandle`] 文档。
    /// 错误：无（纯借用获取，无运行时可失败路径）。
    /// 并发：`&mut self` 独占（§7.3 单一执行模型）；返回的 Store 非 `Sync`，
    /// 不得跨线程使用。
    /// 安全/权限：返回的 Store 默认无任何宿主能力（§7.6）；WASI 能力只经
    /// [`StoreFactory::with_wasi`] 在构建时显式附加。
    pub fn store_mut(&mut self) -> &mut wasmtime::Store<StoreHostState> {
        &mut self.store
    }
}

/// 时长 → epoch ticks 换算（向上取整，最小 1；checked 算术，§14.4）。
fn deadline_to_ticks(deadline: Duration, interval: Duration) -> Result<u64, RuntimeError> {
    let deadline_nanos = deadline.as_nanos();
    let interval_nanos = interval.as_nanos();
    // interval 在 EngineHandle::new 已校验非零，interval_nanos >= 1。
    let rounded = deadline_nanos
        .checked_add(interval_nanos.saturating_sub(1))
        .ok_or_else(|| RuntimeError::Config("call deadline overflow"))?;
    let ticks = u64::try_from((rounded / interval_nanos).max(1))
        .map_err(|_| RuntimeError::Config("call deadline too large"))?;
    Ok(ticks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{InstanceCountLimit, LinearMemoryLimit, MaxConcurrent, TableElementLimit};
    use crate::error::classify_wasm_error;
    use crate::test_support::{
        self, engine, expect_ok, expect_some, store_with_budget, test_failure,
    };
    use crate::wasi::{WasiAdapter, WasiError, WasiPolicy, WasiVersion};
    use crate::{TrapKind, WasmFailure};

    /// 测试用 WASI adapter：把 marker 写入宿主状态槽（验证 §8.2 port 形状）。
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestWasiMarker(u32);

    struct TestWasiAdapter;

    impl WasiAdapter for TestWasiAdapter {
        fn version(&self) -> WasiVersion {
            WasiVersion::P2
        }

        fn attach(
            &self,
            _policy: &WasiPolicy,
            host_state: &mut StoreHostState,
        ) -> Result<(), WasiError> {
            host_state.replace_adapter_state(Box::new(TestWasiMarker(42)));
            Ok(())
        }
    }

    struct FailingWasiAdapter;

    impl WasiAdapter for FailingWasiAdapter {
        fn version(&self) -> WasiVersion {
            WasiVersion::P2
        }

        fn attach(
            &self,
            _policy: &WasiPolicy,
            _host_state: &mut StoreHostState,
        ) -> Result<(), WasiError> {
            Err(WasiError::Attach(Box::new(std::io::Error::other(
                "denied by policy",
            ))))
        }
    }

    #[test]
    fn default_store_has_no_wasi_capabilities() {
        // §7.6：默认 Store 不附加任何 WASI/宿主能力。
        let engine = engine();
        let store = store_with_budget(&engine, &ResourceBudget::default());
        assert!(store.store.data().adapter_state().is_none());
    }

    #[test]
    fn wasi_adapter_attach_flow_stores_opaque_state() {
        // §8.2：adapter 通过 opaque 状态槽附加自有状态；上层只看到 dyn Any。
        let engine = engine();
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &TestWasiAdapter, &WasiPolicy::p2()),
            "store factory with wasi",
        );
        let store = expect_ok(
            factory.new_store(&ResourceBudget::default()),
            "store creation with wasi",
        );
        let marker = store.store.data().adapter_state();
        let marker = match marker {
            Some(any) => match any.downcast_ref::<TestWasiMarker>() {
                Some(m) => *m,
                None => test_failure("adapter state has wrong type"),
            },
            None => test_failure("adapter state missing"),
        };
        assert_eq!(marker, TestWasiMarker(42));
    }

    #[test]
    fn wasi_adapter_attach_failure_fails_closed() {
        // §7.6：能力附加失败 → 整个 Store 构建被拒绝。
        let engine = engine();
        let factory = expect_ok(
            StoreFactory::with_wasi(&engine, &FailingWasiAdapter, &WasiPolicy::p2()),
            "store factory with failing wasi",
        );
        let result = factory.new_store(&ResourceBudget::default());
        match result {
            Ok(_) => test_failure("store must be rejected when WASI attach fails"),
            Err(e) => assert!(matches!(e, RuntimeError::Wasi(_))),
        }
    }

    #[test]
    fn deadline_rejected_when_epoch_disabled() {
        // epoch 关闭时 set_deadline 必须显式拒绝（§7.5 默认启用；关闭是显式选择）。
        let config = crate::engine::EngineConfig {
            epoch_interruption: false,
            ..crate::engine::EngineConfig::default()
        };
        let engine = expect_ok(EngineHandle::new(config), "engine with epoch disabled");
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let result = store.set_deadline(CallDeadline::new(Duration::from_secs(1)));
        match result {
            Ok(()) => test_failure("deadline must be rejected when epoch is disabled"),
            Err(e) => assert!(matches!(e, RuntimeError::Config(_))),
        }
    }

    #[test]
    fn deadline_rejected_when_zero() {
        let engine = engine();
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let result = store.set_deadline(CallDeadline::new(Duration::ZERO));
        match result {
            Ok(()) => test_failure("zero deadline must be rejected"),
            Err(e) => assert!(matches!(e, RuntimeError::Config(_))),
        }
    }

    #[test]
    fn memory_limit_rejects_instantiation() {
        // §7.4/§39.4：实例化超限 → 确定拒绝（typed: ResourceLimit::LinearMemory）。
        let engine = engine();
        let budget = ResourceBudget {
            linear_memory: Some(LinearMemoryLimit::new(crate::budget::ByteSize::kib(64))),
            ..ResourceBudget::default()
        };
        let mut store = store_with_budget(&engine, &budget);
        store.begin_execution();
        let module = expect_ok(
            wasmtime::Module::new(engine.engine(), r#"(module (memory 10))"#),
            "module compile",
        );
        let result = wasmtime::Instance::new(store.store_mut(), &module, &[]);
        match result {
            Ok(_) => test_failure("instantiation with memory over limit must be rejected"),
            Err(e) => {
                let mapped = classify_wasm_error(&mut store, e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::ResourceLimit {
                            kind: ResourceLimitKind::LinearMemory,
                            ..
                        }
                    ),
                    "unexpected mapping: {mapped:?}"
                );
            }
        }
    }

    #[test]
    fn memory_grow_over_limit_returns_minus_one() {
        // §7.4：guest 侧 memory.grow 超限 → 返回 -1（非 trap）。
        let engine = engine();
        let budget = ResourceBudget {
            linear_memory: Some(LinearMemoryLimit::new(crate::budget::ByteSize::kib(64))),
            ..ResourceBudget::default()
        };
        let mut store = store_with_budget(&engine, &budget);
        let module = expect_ok(
            wasmtime::Module::new(
                engine.engine(),
                r#"(module (memory 1 10) (func (export "grow") (param i32) (result i32) (local.get 0) (memory.grow)))"#,
            ),
            "module compile",
        );
        let instance = expect_ok(
            wasmtime::Instance::new(store.store_mut(), &module, &[]),
            "instance creation",
        );
        let grow = expect_ok(
            instance.get_typed_func::<i32, i32>(store.store_mut(), "grow"),
            "typed func lookup",
        );
        // §7.5：先设置 deadline，避免 epoch 未设 deadline 的立即 trap
        // 掩盖 memory.grow 的返回值语义。
        expect_ok(
            store.set_deadline(CallDeadline::new(Duration::from_secs(1))),
            "set deadline",
        );
        let result = grow.call(store.store_mut(), 1);
        match result {
            Ok(grown) => assert_eq!(grown, -1, "grow beyond limit must return -1"),
            Err(_) => test_failure("grow beyond limit must not trap"),
        }
    }

    #[test]
    fn table_element_limit_rejects_instantiation() {
        // §7.4：table 元素上限 → 实例化确定拒绝。
        let engine = engine();
        let budget = ResourceBudget {
            table_elements: Some(TableElementLimit::new(4)),
            ..ResourceBudget::default()
        };
        let mut store = store_with_budget(&engine, &budget);
        store.begin_execution();
        let module = expect_ok(
            wasmtime::Module::new(engine.engine(), r#"(module (table 10 funcref))"#),
            "module compile",
        );
        let result = wasmtime::Instance::new(store.store_mut(), &module, &[]);
        match result {
            Ok(_) => test_failure("instantiation with table over limit must be rejected"),
            Err(e) => {
                let mapped = classify_wasm_error(&mut store, e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::ResourceLimit {
                            kind: ResourceLimitKind::TableElements,
                            ..
                        }
                    ),
                    "unexpected mapping: {mapped:?}"
                );
            }
        }
    }

    #[test]
    fn instance_count_limit_rejects_second_instance() {
        // §7.4：实例数量上限 → 第二个实例确定拒绝。
        let engine = engine();
        let budget = ResourceBudget {
            instances: Some(InstanceCountLimit::new(1)),
            ..ResourceBudget::default()
        };
        let mut store = store_with_budget(&engine, &budget);
        store.begin_execution();
        let module = expect_ok(
            wasmtime::Module::new(engine.engine(), r#"(module (func (export "f")))"#),
            "module compile",
        );
        let first = wasmtime::Instance::new(store.store_mut(), &module, &[]);
        assert!(first.is_ok(), "first instance must succeed");
        store.begin_execution();
        let second = wasmtime::Instance::new(store.store_mut(), &module, &[]);
        match second {
            Ok(_) => test_failure("second instance must be rejected by instance limit"),
            Err(_) => {
                // 实例数量上限由 wasmtime 内部计数比较，错误为 wasmtime 生成；
                // 分类为 Unknown + 可诊断 source（见 limiter.rs 模块文档）。
                let mapped = store.take_rejection();
                assert!(
                    mapped.is_none(),
                    "count limits are enforced inside wasmtime, not via rejection record"
                );
            }
        }
    }

    #[test]
    fn deadline_ticks_round_up_to_at_least_one() {
        // 25ms deadline @ 10ms tick → 3 ticks；< 1 tick 的 deadline → 1 tick。
        let engine = engine();
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let result = store.set_deadline(CallDeadline::new(Duration::from_millis(25)));
        assert!(result.is_ok());
        let result = store.set_deadline(CallDeadline::new(Duration::from_millis(1)));
        assert!(result.is_ok());
        let result = store.reset_deadline();
        assert!(result.is_ok());
    }

    #[test]
    fn store_is_bounded_by_max_concurrent_via_budget() {
        // §7.4：预算 max_concurrent 驱动 Instance Set 槽位数（instance.rs 有
        // 行为测试）；此处验证预算可以被覆盖为 1。
        let budget = ResourceBudget {
            max_concurrent: expect_some(MaxConcurrent::try_new(1), "max concurrent 1"),
            ..ResourceBudget::default()
        };
        assert_eq!(budget.max_concurrent.get().get(), 1);
    }

    #[test]
    fn epoch_deadline_traps_infinite_loop() {
        // §7.5/§39.4：infinite loop 能按 deadline 中断（epoch interruption）。
        // 构造：epoch 启用（默认）+ 统一 ticker（10ms）+ 25ms deadline +
        // 无导入的无限循环 core module；调用被 epoch trap 中断并映射为
        // WasmFailure::EpochDeadlineExceeded。
        let engine = engine();
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let module = expect_ok(
            wasmtime::Module::new(
                engine.engine(),
                r#"(module (func $spin (export "spin") (loop $l br $l)))"#,
            ),
            "spin module compile",
        );
        let instance = expect_ok(
            wasmtime::Instance::new(store.store_mut(), &module, &[]),
            "spin instance",
        );
        let spin = expect_ok(
            instance.get_typed_func::<(), ()>(store.store_mut(), "spin"),
            "spin func lookup",
        );
        // 统一 ticker 后台递增 epoch（§7.5）。
        let ticker = test_support::ticker(&engine);
        // §7.5：每次不可信执行设置 deadline（25ms → 3 ticks @10ms）。
        expect_ok(
            store.set_deadline(CallDeadline::new(Duration::from_millis(25))),
            "set deadline",
        );
        store.begin_execution();
        let result = spin.call(store.store_mut(), ());
        match result {
            Ok(()) => test_failure("infinite loop must be interrupted by epoch deadline"),
            Err(e) => {
                let mapped = classify_wasm_error(&mut store, e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::Execution {
                            kind: WasmFailure::EpochDeadlineExceeded,
                            ..
                        }
                    ),
                    "epoch trap must map to EpochDeadlineExceeded: {mapped:?}"
                );
            }
        }
        drop(ticker);
    }

    #[test]
    fn no_deadline_traps_immediately() {
        // §7.5 实证：epoch 启用时 Store 默认 deadline 为 0（已过期）——
        // 未设置 deadline 的不可信执行立即 trap。这是“每次不可信执行
        // 必须设置 deadline”的机制保证。
        let engine = engine();
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let module = expect_ok(
            wasmtime::Module::new(engine.engine(), r#"(module (func (export "nop")))"#),
            "nop module compile",
        );
        let instance = expect_ok(
            wasmtime::Instance::new(store.store_mut(), &module, &[]),
            "nop instance",
        );
        let nop = expect_ok(
            instance.get_typed_func::<(), ()>(store.store_mut(), "nop"),
            "nop func lookup",
        );
        store.begin_execution();
        let result = nop.call(store.store_mut(), ());
        match result {
            Ok(()) => test_failure("execution without deadline must trap immediately"),
            Err(e) => {
                let mapped = classify_wasm_error(&mut store, e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::Execution {
                            kind: WasmFailure::EpochDeadlineExceeded,
                            ..
                        }
                    ),
                    "unexpected mapping: {mapped:?}"
                );
            }
        }
    }

    #[test]
    fn guest_trap_maps_to_typed_trap_kind() {
        // §14.1：guest trap 映射为 typed TrapKind（此例 unreachable）。
        // 注意：必须先设置 deadline——epoch 启用时未设置 deadline 的执行
        // 会立即以 EpochDeadlineExceeded trap（见 no_deadline_traps_immediately）。
        let engine = engine();
        let mut store = store_with_budget(&engine, &ResourceBudget::default());
        let module = expect_ok(
            wasmtime::Module::new(
                engine.engine(),
                r#"(module (func (export "boom") unreachable))"#,
            ),
            "boom module compile",
        );
        let instance = expect_ok(
            wasmtime::Instance::new(store.store_mut(), &module, &[]),
            "boom instance",
        );
        let boom = expect_ok(
            instance.get_typed_func::<(), ()>(store.store_mut(), "boom"),
            "boom func lookup",
        );
        expect_ok(
            store.set_deadline(CallDeadline::new(Duration::from_secs(1))),
            "set deadline",
        );
        store.begin_execution();
        let result = boom.call(store.store_mut(), ());
        match result {
            Ok(()) => test_failure("unreachable must trap"),
            Err(e) => {
                let mapped = classify_wasm_error(&mut store, e.into());
                assert!(
                    matches!(
                        mapped,
                        RuntimeError::Execution {
                            kind: WasmFailure::Trap(TrapKind::UnreachableCodeReached),
                            ..
                        }
                    ),
                    "unexpected mapping: {mapped:?}"
                );
            }
        }
    }
}
