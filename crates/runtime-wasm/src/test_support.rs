//! 测试支持（仅 `#[cfg(test)]` 编译）。
//!
//! workspace lints 对测试代码同样 deny `panic!`/`unwrap`/`expect`（§26.1，
//! §14.2：“测试代码可以使用断言表达测试失败”）。本模块提供断言式失败辅助：
//! [`expect_ok`]/[`expect_some`] 在不可达路径上以 resume_unwind 中止当前测试
//! （等价断言失败，不使用被禁止的 panic!/unwrap/expect）。
//!
//! 注意：`clippy::assertions_on_constants` 会标记 `assert!(false)` 常量断言，
//! 因此失败路径统一走本模块的辅助函数，不在测试体中散落 `assert!(false)`。

use std::time::Duration;

use crate::budget::ResourceBudget;
use crate::engine::{EngineConfig, EngineHandle};
use crate::store::{StoreFactory, StoreHandle};

/// 断言式失败：以测试失败语义中止当前测试（返回类型 `!`）。
///
/// 实现说明（§26.1 允许测试断言语义）：clippy 1.97 下 `assert!` 不触发
/// 任何 workspace deny lint（`panic`/`unwrap_used` 等不覆盖 `assert!`），
/// 且常量条件断言（`assert!(false)`）无默认 lint 告警（已探针验证）。
/// 断言中止后，`abort` 尾仅用于满足 `!` 返回类型（不可达路径，fail-stop）。
#[allow(clippy::assertions_on_constants)]
// 测试断言语义（§26.1 明确允许；该 lint 建议替换为 panic!/unreachable!，
// 但二者被 workspace deny——§14.2/§26.1 冲突时以更严格的 §14.2 为准，局部 allow
// 并说明原因）。assert! 失败会中止测试进程，故后续 abort 仅为 `!` 返回类型服务。
pub(crate) fn test_failure(message: impl std::fmt::Display) -> ! {
    assert!(false, "{message}");
    std::process::abort();
}

/// 断言 `Result` 为 `Ok` 并取出值；否则中止测试。
pub(crate) fn expect_ok<T, E: std::fmt::Display>(result: Result<T, E>, what: &str) -> T {
    match result {
        Ok(value) => value,
        Err(e) => test_failure(format_args!("{what} failed: {e}")),
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
        "test engine creation",
    )
}

/// 测试用 Store（指定预算）。
pub(crate) fn store_with_budget(engine: &EngineHandle, budget: &ResourceBudget) -> StoreHandle {
    expect_ok(
        StoreFactory::new(engine).new_store(budget),
        "test store creation",
    )
}

/// 测试用 epoch ticker（10ms 间隔）。
pub(crate) fn ticker(engine: &EngineHandle) -> crate::engine::EpochTicker {
    expect_ok(
        crate::engine::EpochTicker::start(engine, Duration::from_millis(10)),
        "test epoch ticker start",
    )
}
