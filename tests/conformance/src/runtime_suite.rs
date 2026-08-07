//! runtime-wasm 层 conformance 测试（§7 运行模型 / §7.4 资源治理 /
//! §7.5 epoch interruption / §7.6 无 ambient authority / §14.1 typed error）。
//!
//! 全部夹具经 runtime-wasm 的公开 API 运行：`EngineHandle` / `StoreFactory` /
//! `StoreHandle` / `InstanceSet` / `ResourceBudget`（limiter）/ `EpochTicker` /
//! `classify_wasm_error`。wasmtime 具体类型只出现在受控泄漏点
//!（`Linker<StoreHostState>` / `Instance` / `Func`，与 application 的
//! `WasmtimeRuntime` 同位置，§8.2）。
//!
//! 时序契约（§7.5）：每次不可信执行 `set_deadline` → `begin_execution` →
//! 执行 → `classify_wasm_error`（封装见 [`super::test_support`]）。

use std::time::{Duration, Instant};

use operune_runtime_wasm::{
    ByteSize, CallDeadline, DispatchError, InstanceSet, LinearMemoryLimit, MaxConcurrent,
    MaxQueued, ResourceBudget, ResourceLimitKind, RuntimeError, WasmFailure,
};

use super::fixtures::{
    CORE_MODULE_NOT_COMPONENT_WAT, HUGE_MEMORY_COMPONENT_WAT, MALFORMED_BYTES,
    MEMORY_GROW_COMPONENT_WAT, MINIMAL_COMPONENT_WAT, SLOW_COMPONENT_WAT, SPIN_LOOP_COMPONENT_WAT,
    SPIN_ON_INIT_COMPONENT_WAT, TRAP_ON_INIT_COMPONENT_WAT, UNKNOWN_IMPORT_COMPONENT_WAT,
};
use super::test_support::{
    call_i32_export, call_unit_export, call_unit_to_i32_export, engine, expect_ok, expect_some,
    instantiate_with_empty_linker, store_with_budget, test_failure, ticker,
};

// ---------------------------------------------------------------------------
// minimal valid Component / malformed bytes（§30；§39.4 非法输入）
// ---------------------------------------------------------------------------

#[test]
fn minimal_component_compiles_and_instantiates() {
    // §30 minimal valid Component：验证/编译（§7.2）→ 实例化（§7.3）
    // 的闭环在默认 Engine/Store 下成功。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, MINIMAL_COMPONENT_WAT.as_bytes()),
        "minimal component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let instance = expect_ok(
        instantiate_with_empty_linker(
            &engine,
            &mut store,
            handle.component(),
            Some(Duration::from_secs(1)),
        ),
        "minimal component instantiate",
    );
    // 实例句柄保持存活到测试结束（显式保活，防 drop 时序误解）。
    let _ = instance;
}

#[test]
fn malformed_bytes_rejected_as_component() {
    // §30 malformed bytes / §39.4：非法字节在验证期以 typed 错误拒绝
    //（RuntimeError::Component），不 panic、不拖垮宿主。
    let engine = engine();
    let result = operune_runtime_wasm::ComponentHandle::new(&engine, MALFORMED_BYTES);
    match result {
        Ok(_) => test_failure("malformed bytes must be rejected"),
        Err(error) => {
            assert!(
                matches!(error, RuntimeError::Component(_)),
                "malformed bytes must map to Component validation failure: {error:?}"
            );
        }
    }
}

#[test]
fn core_module_bytes_rejected_by_component_gate() {
    // §30 malformed bytes 变体（合法 wasm 非组件）/ §7.2：core module
    // 二进制不得冒充 Component——Component::new 必须拒绝。
    let engine = engine();
    let result = operune_runtime_wasm::ComponentHandle::new(
        &engine,
        CORE_MODULE_NOT_COMPONENT_WAT.as_bytes(),
    );
    match result {
        Ok(_) => test_failure("core module bytes must be rejected by the component gate"),
        Err(error) => {
            assert!(
                matches!(error, RuntimeError::Component(_)),
                "core module bytes must map to Component validation failure: {error:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// infinite loop / epoch interruption（§30；§39.4；§7.5）
// ---------------------------------------------------------------------------

#[test]
fn infinite_loop_interrupted_by_epoch_deadline() {
    // §39.4 "infinite loop 能按 deadline 中断"：统一 ticker（§7.5）
    // 递增 epoch；25ms deadline（→3 ticks @10ms）到期后调用被中断并
    // 分类为 WasmFailure::EpochDeadlineExceeded。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, SPIN_LOOP_COMPONENT_WAT.as_bytes()),
        "spin component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let instance = expect_ok(
        instantiate_with_empty_linker(
            &engine,
            &mut store,
            handle.component(),
            Some(Duration::from_secs(1)),
        ),
        "spin component instantiate",
    );
    let ticker = ticker(&engine);
    let result = call_unit_export(&mut store, &instance, "spin", Duration::from_millis(25));
    match result {
        Ok(()) => test_failure("infinite loop must be interrupted by the epoch deadline"),
        Err(error) => {
            assert!(
                matches!(
                    error,
                    RuntimeError::Execution {
                        kind: WasmFailure::EpochDeadlineExceeded,
                        ..
                    }
                ),
                "epoch interrupt must classify as EpochDeadlineExceeded: {error:?}"
            );
        }
    }
    drop(ticker);
}

#[test]
fn infinite_loop_on_init_interrupted_by_deadline() {
    // §39.4 的实例化面：start 函数无限循环——实例化本身执行 guest 代码，
    // epoch deadline 必须在实例化期间中断（§7.5 对每次不可信执行生效）。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, SPIN_ON_INIT_COMPONENT_WAT.as_bytes()),
        "spin-on-init component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let ticker = ticker(&engine);
    let started = Instant::now();
    let result = instantiate_with_empty_linker(
        &engine,
        &mut store,
        handle.component(),
        Some(Duration::from_millis(50)),
    );
    match result {
        Ok(_) => test_failure("spin-on-init must be interrupted by the epoch deadline"),
        Err(error) => {
            assert!(
                matches!(
                    error,
                    RuntimeError::Execution {
                        kind: WasmFailure::EpochDeadlineExceeded,
                        ..
                    }
                ),
                "spin-on-init interrupt must classify as EpochDeadlineExceeded: {error:?}"
            );
        }
    }
    // 中断必须有界（50ms deadline + tick 粒度余量），不悬挂。
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "spin-on-init must be interrupted within a bounded time"
    );
    drop(ticker);
}

#[test]
fn execution_without_deadline_traps_immediately() {
    // §7.5 机制保证：epoch 启用时 Store 默认 deadline 为 0（已过期）——
    // 未设置 deadline 的不可信执行立即 trap。这是"每次不可信执行必须
    // 设置 deadline"的强制面（调用期与实例化期都成立）。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, SPIN_LOOP_COMPONENT_WAT.as_bytes()),
        "spin component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    // 实例化**不设置任何 deadline**（deadline=None → Store 保持默认 0）：
    // SPIN_LOOP 的 core instance 无 start 函数（实例化不执行 guest 代码，
    // 不受 epoch 检查影响）；随后调用期的 deadline 仍是默认 0 → 立即 trap。
    // 注意：不能先设正常 deadline 再调用——epoch 不递增时 deadline 会残留
    // 到调用期，把"未设 deadline"语义掩盖成"无限执行"。
    let instance = expect_ok(
        instantiate_with_empty_linker(&engine, &mut store, handle.component(), None),
        "spin component instantiate",
    );
    let func = expect_ok(
        instance.get_typed_func::<(), ()>(store.store_mut(), "spin"),
        "spin export lookup",
    );
    store.begin_execution();
    let result = func.call(store.store_mut(), ());
    match result {
        Ok(()) => test_failure("execution without deadline must trap immediately"),
        Err(error) => {
            let classified =
                operune_runtime_wasm::classify_wasm_error(&mut store, Box::from(error));
            assert!(
                matches!(
                    classified,
                    RuntimeError::Execution {
                        kind: WasmFailure::EpochDeadlineExceeded,
                        ..
                    }
                ),
                "unexpected mapping: {classified:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// trap on init（§30；§14.1 typed 分类）
// ---------------------------------------------------------------------------

#[test]
fn trap_on_init_classified_as_typed_failure() {
    // §30 trap on init：start 函数 unreachable → 实例化即失败；失败必须
    // 是 typed `RuntimeError::Execution` 分类（宿主不崩溃、可诊断）。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, TRAP_ON_INIT_COMPONENT_WAT.as_bytes()),
        "trap-on-init component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let result = instantiate_with_empty_linker(
        &engine,
        &mut store,
        handle.component(),
        Some(Duration::from_secs(1)),
    );
    match result {
        Ok(_) => test_failure("trap-on-init must fail at instantiation"),
        Err(error) => {
            // wasmtime 36 的实例化错误链：start trap 经 anyhow 包装，
            // 分类器可经 error chain 定位 Trap（UnreachableCodeReached）；
            // 无法定位时归入 WasmFailure::Unknown——两种形态都必须是
            // typed Execution 失败且不崩溃宿主（§14.1）。
            assert!(
                matches!(error, RuntimeError::Execution { .. }),
                "trap-on-init must classify as a typed execution failure: {error:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// memory grow attacker（§30；§7.4 limiter；§39.4）
// ---------------------------------------------------------------------------

/// memory grow attacker 的预算：64 KiB linear memory 上限（默认 64 MiB
/// 的缩小版，覆盖 §7.4 清单的 linear memory 维度）。
fn memory_attacker_budget() -> ResourceBudget {
    ResourceBudget {
        linear_memory: Some(LinearMemoryLimit::new(ByteSize::kib(64))),
        ..ResourceBudget::default()
    }
}

#[test]
fn memory_grow_attacker_denied_with_minus_one() {
    // §39.4 "memory over-limit 有确定拒绝或 trap"：guest 侧 memory.grow
    // 超限 → 返回 -1（wasm 语义拒绝，非 trap）；limiter 记录
    // ResourceLimitKind::LinearMemory（§7.4 拒绝记录）。
    let engine = engine();
    let budget = memory_attacker_budget();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, MEMORY_GROW_COMPONENT_WAT.as_bytes()),
        "memory grow component compile",
    );
    let mut store = store_with_budget(&engine, &budget);
    let instance = expect_ok(
        instantiate_with_empty_linker(
            &engine,
            &mut store,
            handle.component(),
            Some(Duration::from_secs(1)),
        ),
        "memory grow component instantiate",
    );
    // 预算内：初始 1 page（64 KiB）在限内 → 实例化成功；grow(1) →
    // 128 KiB 超限 → -1。
    let result = call_i32_export(&mut store, &instance, "grow", 1, Duration::from_secs(1));
    match result {
        Ok(grown) => {
            assert_eq!(
                grown, -1,
                "grow beyond limit must return -1 (deny, not trap)"
            );
        }
        Err(error) => test_failure(format_args!(
            "grow beyond limit must not trap; classified: {error:?}"
        )),
    }
    // limiter 拒绝记录（§7.4）：最近一次执行期间的超限类别可被读取。
    let rejection = store.take_rejection();
    assert!(
        matches!(rejection, Some(ResourceLimitKind::LinearMemory)),
        "limiter must record LinearMemory rejection: {rejection:?}"
    );
}

#[test]
fn memory_grow_attacker_instantiation_rejected_by_limiter() {
    // §39.4 实例化面：初始分配超限 → 实例化被分类为
    // RuntimeError::ResourceLimit（LinearMemory）——确定拒绝，不 panic。
    let engine = engine();
    let budget = memory_attacker_budget();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, HUGE_MEMORY_COMPONENT_WAT.as_bytes()),
        "huge memory component compile",
    );
    let mut store = store_with_budget(&engine, &budget);
    let result = instantiate_with_empty_linker(
        &engine,
        &mut store,
        handle.component(),
        Some(Duration::from_secs(1)),
    );
    match result {
        Ok(_) => test_failure("4 GiB initial memory must be rejected by the limiter"),
        Err(error) => {
            assert!(
                matches!(
                    error,
                    RuntimeError::ResourceLimit {
                        kind: ResourceLimitKind::LinearMemory,
                        ..
                    }
                ),
                "huge initial memory must classify as LinearMemory resource limit: {error:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// unknown import / denied capability（§30；§17.2/§19.5 link 期拒绝）
// ---------------------------------------------------------------------------

#[test]
fn unknown_import_rejected_at_link_time() {
    // §39.4 "未授权/未知 import 不能成为 Active"：带 WASI import 的组件
    // 在空 Linker（零 grant，§17.2 deny-by-default）下以**确定性 link 错误**
    // 失败——不得"先运行，失败时 trap"（§19.5）。
    let engine = engine();
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(
            &engine,
            UNKNOWN_IMPORT_COMPONENT_WAT.as_bytes(),
        ),
        "unknown import component compile",
    );
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let result = instantiate_with_empty_linker(
        &engine,
        &mut store,
        handle.component(),
        Some(Duration::from_secs(1)),
    );
    match result {
        Ok(_) => test_failure("ungranted import must fail at link time"),
        Err(error) => {
            // link 错误非 trap、无资源拒绝记录 → 分类为 Execution/Unknown
            //（source 保留可诊断上下文，§14.1）。关键断言是"确定性拒绝"：
            // 组件不能进入可执行状态。
            assert!(
                matches!(error, RuntimeError::Execution { .. }),
                "link failure must surface as typed execution failure: {error:?}"
            );
        }
    }
}

#[test]
fn default_store_has_no_ambient_authority() {
    // §30 denied capability / §7.6：默认 Store 不获得任何 WASI/宿主能力
    //（无文件系统、网络、环境变量、随机资源）；WASI 能力只经显式
    // StoreFactory::with_wasi + adapter attach 进入（deny-by-default）。
    let engine = engine();
    let mut store = store_with_budget(&engine, &ResourceBudget::default());
    let adapter_state = store.store_mut().data().adapter_state();
    assert!(
        adapter_state.is_none(),
        "default store must carry no WASI adapter state (§7.6)"
    );
}

// ---------------------------------------------------------------------------
// slow/drain component（§30；§20.4 drain 语义）
// ---------------------------------------------------------------------------

#[test]
fn slow_component_drain_closes_over_inflight_work() {
    // §20.4 drain：InstanceSet 关闭后不接收新工作（try_dispatch → Closed）；
    // **已发放**的租约（in-flight 调用）运行到结束；调用完成后集合保持
    // 关闭。全部通过公开 API：InstanceSet::try_dispatch / close / dispatch。
    let engine = engine();
    let budget = ResourceBudget {
        max_concurrent: expect_some(MaxConcurrent::try_new(1), "max concurrent 1"),
        max_queued: expect_some(MaxQueued::try_new(1), "max queued 1"),
        ..ResourceBudget::default()
    };
    let set = expect_ok(InstanceSet::new(&engine, &budget), "instance set creation");
    assert_eq!(set.capacity(), 1);

    // 先编译 + 实例化 slow 组件（真实 component 夹具）。
    let handle = expect_ok(
        operune_runtime_wasm::ComponentHandle::new(&engine, SLOW_COMPONENT_WAT.as_bytes()),
        "slow component compile",
    );

    // 主线程持有唯一租约（in-flight 调用窗口）。
    let mut lease = match set.try_dispatch() {
        Ok(lease) => lease,
        Err(error) => test_failure(format_args!("first dispatch failed: {error}")),
    };

    // 并发线程：槽位繁忙 → Busy；随后 close（drain 开始）→ 新工作
    // 以 Closed 拒绝（§20.4：不接新工作）。
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let set_ref = &set;
        let done_tx = &done_tx;
        scope.spawn(move || {
            match set_ref.try_dispatch() {
                Ok(_) => {}
                Err(error) => assert_eq!(error, DispatchError::Busy),
            }
            match set_ref.close() {
                Ok(()) => {}
                Err(error) => test_failure(format_args!("close failed: {error}")),
            }
            match set_ref.try_dispatch() {
                Ok(_) => test_failure("dispatch after close must be rejected"),
                Err(error) => assert_eq!(error, DispatchError::Closed),
            }
            done_tx.send(()).ok();
        });
        // 等 drain 线程完成（关闭已生效）。
        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(()) => {}
            Err(_) => test_failure("drain thread did not finish in time"),
        }

        // in-flight 调用：已发放租约运行到结束（§20.4 的"已接受工作允许
        // 在有界 deadline 内完成"）。slow 调用有界（计数循环 + 1s deadline）。
        let result = lease.with_store(|store| {
            // 槽位 Store 上以空 Linker 实例化 slow 组件（组件无 import；
            // §19.3 descriptor-only 语义的空 Linker 复用）。
            let linker = wasmtime::component::Linker::<operune_runtime_wasm::StoreHostState>::new(
                engine.engine(),
            );
            expect_ok(
                store.set_deadline(CallDeadline::new(Duration::from_secs(1))),
                "set deadline in lease",
            );
            store.begin_execution();
            let instance = expect_ok(
                linker
                    .instantiate(store.store_mut(), handle.component())
                    .map_err(|error| {
                        operune_runtime_wasm::classify_wasm_error(store, Box::from(error))
                    }),
                "slow component instantiate in lease",
            );
            call_unit_to_i32_export(store, &instance, "slow", Duration::from_secs(1))
        });
        // with_store 的外层错误（槽位/锁，RuntimeError::Internal）与执行
        // 层错误同面：展平为单一 Result 再断言（in-flight 调用必须成功）。
        let result: Result<i32, RuntimeError> = match result {
            Ok(inner) => inner,
            Err(error) => Err(error),
        };
        match result {
            Ok(iterations) => {
                assert!(
                    iterations > 0,
                    "slow fixture must complete its bounded loop"
                );
            }
            Err(error) => test_failure(format_args!("in-flight call failed: {error:?}")),
        }

        // 租约释放后集合仍关闭（drain 终态不可逆）。
        drop(lease);
        match set.try_dispatch() {
            Ok(_) => test_failure("dispatch after drain must be rejected"),
            Err(error) => assert_eq!(error, DispatchError::Closed),
        }
    });
}
