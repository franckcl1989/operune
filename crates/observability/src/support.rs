//! 测试支持（仅 `cfg(test)` 编译，不进 production）。
//!
//! §14.2：测试代码使用断言表达测试失败。workspace lints 已机械禁止
//! `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!`（§26.1），
//! 本模块提供断言式取值助手与可捕获 writer（确定性断言 tracing 输出）。

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

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

/// 收集 tracing 输出的内存 writer（测试用；确定性断言，不触碰真实 stdout）。
#[derive(Clone)]
pub(crate) struct TestWriter {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl TestWriter {
    pub(crate) fn new() -> TestWriter {
        TestWriter {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// 已捕获内容的 UTF-8 字符串视图。
    pub(crate) fn contents(&self) -> String {
        let bytes = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[derive(Clone)]
pub(crate) struct TestWriterGuard {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl io::Write for TestWriterGuard {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for TestWriter {
    type Writer = TestWriterGuard;

    fn make_writer(&'a self) -> Self::Writer {
        TestWriterGuard {
            inner: self.inner.clone(),
        }
    }
}
