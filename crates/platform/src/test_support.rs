//! 测试支持（仅 `cfg(test)` 编译，不进 production）。
//!
//! §14.2：测试代码使用断言表达测试失败。workspace lints 已机械禁止
//! `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!`（§26.1），
//! 本模块提供断言式取值助手。

use std::fmt;

/// 断言 `Result` 必须为 `Ok` 并取出值；否则触发测试失败。
///
/// 只允许在测试中使用。`unreachable!` 语义即"该分支按不变量不可达"，
/// 失败时携带上下文与错误信息。
pub(crate) fn ok<T, E: fmt::Display>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => unreachable!("{context}: expected Ok, got {error}"),
    }
}
