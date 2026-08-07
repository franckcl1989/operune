//! 测试支持（仅 `cfg(test)` 编译，不进 production）。
//!
//! §14.2：测试代码使用断言表达测试失败。workspace lints 已机械禁止
//! `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!`（§26.1），
//! 本模块提供断言式取值助手（与 domain 的 `test_support` 同一模式）。

use std::fmt;

use operune_domain::ComponentId;

use crate::artifact::DataRoot;
use crate::model::{AuditActor, AuditCategory, AuditEvent, AuditOutcome};

/// 断言 `Result` 必须为 `Ok` 并取出值；否则触发测试失败。
pub(crate) fn ok<T, E: fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => unreachable!("{context}: expected Ok, got {error}"),
    }
}

/// 断言 `Result` 必须为 `Err` 并取出错误；否则触发测试失败。
pub(crate) fn err<T, E: fmt::Display>(result: Result<T, E>, context: &str) -> E {
    match result {
        Ok(_) => unreachable!("{context}: expected Err"),
        Err(error) => error,
    }
}

/// 断言 `Result<(), T>` 必须为 `Ok`（错误侧 `T` 未必实现 `Display`，
/// 如 oneshot `SendError<()>`）。
pub(crate) fn unit_ok<T>(result: Result<(), T>, context: &str) {
    match result {
        Ok(()) => {}
        Err(_) => unreachable!("{context}: expected Ok(())"),
    }
}

/// 断言 `Option` 必须为 `Some` 并取出值。
pub(crate) fn some<T>(option: Option<T>, context: &str) -> T {
    match option {
        Some(value) => value,
        None => unreachable!("{context}: expected Some"),
    }
}

/// `Result<Option<T>, _>` 组合断言：先 Ok 后 Some。
pub(crate) fn some_ok<T, E: fmt::Display>(result: Result<Option<T>, E>, context: &str) -> T {
    some(ok(result, context), context)
}

/// 隔离的临时目录（§22.8 tempfile）。
pub(crate) fn tempdir() -> tempfile::TempDir {
    ok(tempfile::tempdir(), "create tempdir")
}

/// 从临时目录构造 DataRoot（绝对路径，validate-on-construct 通过）。
pub(crate) fn data_root(dir: &std::path::Path) -> DataRoot {
    ok(DataRoot::new(dir.to_path_buf()), "data root")
}

/// 断言式组件 ID。
pub(crate) fn component_id(name: &str) -> ComponentId {
    ok(ComponentId::new(name), "component id")
}

/// 测试用 audit 事件（actor = System）。
pub(crate) fn audit(action: &str) -> AuditEvent {
    ok(
        AuditEvent::new(
            AuditActor::System,
            AuditCategory::ComponentLifecycle,
            action,
            None,
            AuditOutcome::Success,
            None,
        ),
        "audit event",
    )
}

// （executor 测试自带 open 助手；本模块不再重复提供。）
