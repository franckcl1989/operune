//! 测试支持（仅 `#[cfg(test)]` 编译）：断言式失败辅助与 conformance 专用
//! 加载/执行辅助。
//!
//! workspace lints 对测试代码同样 deny `panic!`/`unwrap`/`expect`
//!（§26.1 / §14.2："测试代码可以使用断言表达测试失败"）。本模块提供
//! 与 runtime-wasm / application 的 test_support 同模式的断言辅助：
//! [`test_failure`]（不可达路径上以 resume_unwind 语义中止当前测试，
//! 等价断言失败，不使用被禁止的 panic!/unwrap/expect）。
//!
//! §7.5 时序契约（每次不可信执行）：`set_deadline` → `begin_execution` →
//! 执行 → `classify_wasm_error`。本模块的
//! [`instantiate_with_empty_linker`] / [`call_lifted_func`] 封装该时序，
//! 与 application runtime.rs 的 `prepare_store_call` 语义一致（§19.3
//! descriptor-only Store = 空 Linker，deny-by-default，§17.2）。

use std::time::Duration;

use operune_runtime_wasm::{
    CallDeadline, EngineConfig, EngineHandle, EpochTicker, RuntimeError, StoreFactory, StoreHandle,
    StoreHostState, classify_wasm_error,
};

/// 断言式失败：以测试失败语义中止当前测试（返回类型 `!`）。
/// 与 runtime-wasm 的 test_support 同模式（§26.1 允许测试断言语义）。
#[allow(clippy::assertions_on_constants)]
pub(crate) fn test_failure(message: impl std::fmt::Display) -> ! {
    assert!(false, "{message}");
    std::process::abort();
}

/// 断言 `Result` 为 `Ok` 并取出值；否则中止测试。
pub(crate) fn expect_ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => test_failure(format_args!("{what} failed: {error}")),
    }
}

/// 断言 `Option` 为 `Some` 并取出值；否则中止测试。
pub(crate) fn expect_some<T>(option: Option<T>, what: &str) -> T {
    match option {
        Some(value) => value,
        None => test_failure(format_args!("{what} is None")),
    }
}

/// 测试用 Engine（§7.5 默认：epoch 启用，tick 10ms）。
pub(crate) fn engine() -> EngineHandle {
    expect_ok(
        EngineHandle::new(EngineConfig::default()),
        "conformance test engine creation",
    )
}

/// 测试用 Store（指定预算；§7.6 默认无任何 WASI/宿主能力）。
pub(crate) fn store_with_budget(
    engine: &EngineHandle,
    budget: &operune_runtime_wasm::ResourceBudget,
) -> StoreHandle {
    expect_ok(
        StoreFactory::new(engine).new_store(budget),
        "conformance test store creation",
    )
}

/// 测试用 epoch ticker（10ms 间隔，§7.5 统一 ticker）。
pub(crate) fn ticker(engine: &EngineHandle) -> EpochTicker {
    expect_ok(
        EpochTicker::start(engine, Duration::from_millis(10)),
        "conformance test epoch ticker start",
    )
}

/// 在 Store 中以**空 Linker**（deny-by-default，§19.3 descriptor-only
/// 语义）实例化组件并分类失败。
///
/// §7.5 时序：先设置 deadline（`deadline == None` 时保持 Store 默认
/// deadline 0——已过期，用于验证"未设置 deadline 的执行立即 trap"的
/// 机制保证），再 `begin_execution`；失败经 [`classify_wasm_error`] 映射
/// 为 typed [`RuntimeError`]。
pub(crate) fn instantiate_with_empty_linker(
    engine: &EngineHandle,
    store: &mut StoreHandle,
    component: &wasmtime::component::Component,
    deadline: Option<Duration>,
) -> Result<wasmtime::component::Instance, RuntimeError> {
    if let Some(deadline) = deadline {
        store.set_deadline(CallDeadline::new(deadline))?;
    }
    store.begin_execution();
    let linker = wasmtime::component::Linker::<StoreHostState>::new(engine.engine());
    linker
        .instantiate(store.store_mut(), component)
        .map_err(|error| classify_wasm_error(store, Box::from(error)))
}

/// 调用组件的扁平签名导出（`(i32) -> (i32)` 形态）并分类失败。
///
/// wasmtime 36 的 component typed func 签名要求 `ComponentNamedList`
///（元组形态：`(i32,)` / `()`），单值不实现该 trait——组件导出调用
/// 统一以元组表达（探针验证，见 wasmtime typed.rs 的 named-list 实现）。
///
/// §7.5 时序：每次不可信执行先设置 deadline 再 `begin_execution`（与
/// application runtime.rs 的 `prepare_store_call` 一致）。导出查找失败属
/// 夹具不变量破坏（中止测试）；**调用**失败经 [`classify_wasm_error`]
/// 映射为 typed [`RuntimeError`]。
pub(crate) fn call_i32_export(
    store: &mut StoreHandle,
    instance: &wasmtime::component::Instance,
    export: &str,
    arg: i32,
    deadline: Duration,
) -> Result<i32, RuntimeError> {
    let func = expect_ok(
        instance.get_typed_func::<(i32,), (i32,)>(store.store_mut(), export),
        "lifted i32 export lookup",
    );
    store.set_deadline(CallDeadline::new(deadline))?;
    store.begin_execution();
    func.call(store.store_mut(), (arg,))
        .map(|(result,)| result)
        .map_err(|error| classify_wasm_error(store, Box::from(error)))
}

/// 调用组件的空参数空结果导出（`() -> ()` 形态）并分类失败。语义同
/// [`call_i32_export`]。
pub(crate) fn call_unit_export(
    store: &mut StoreHandle,
    instance: &wasmtime::component::Instance,
    export: &str,
    deadline: Duration,
) -> Result<(), RuntimeError> {
    let func = expect_ok(
        instance.get_typed_func::<(), ()>(store.store_mut(), export),
        "lifted unit export lookup",
    );
    store.set_deadline(CallDeadline::new(deadline))?;
    store.begin_execution();
    func.call(store.store_mut(), ())
        .map_err(|error| classify_wasm_error(store, Box::from(error)))
}

/// 调用组件的 `() -> i32` 导出（slow fixture）并分类失败。语义同
/// [`call_i32_export`]。
pub(crate) fn call_unit_to_i32_export(
    store: &mut StoreHandle,
    instance: &wasmtime::component::Instance,
    export: &str,
    deadline: Duration,
) -> Result<i32, RuntimeError> {
    let func = expect_ok(
        instance.get_typed_func::<(), (i32,)>(store.store_mut(), export),
        "lifted unit->i32 export lookup",
    );
    store.set_deadline(CallDeadline::new(deadline))?;
    store.begin_execution();
    func.call(store.store_mut(), ())
        .map(|(result,)| result)
        .map_err(|error| classify_wasm_error(store, Box::from(error)))
}
