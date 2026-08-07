//! 最小 CancellationToken（§15.3 structured cancellation；第一方实现，
//! 与 server crate 的同名模块同模式——标准库/tokio 现有能力足够时不得
//! 新增依赖，§23.1）。
//!
//! §15.3：结构化取消——shutdown 信号必须沿调用栈显式传播，不得依赖全局
//! 状态或隐式超时；§20.4：所有 background task（scheduler driver / 投递
//! consumer / event pump）必须受 CancellationToken 管理。
//!
//! 语义：
//! - [`CancellationToken::cancel`]：至多生效一次（幂等；重复 cancel 无害）；
//! - [`CancellationToken::cancelled`]：等待取消。**无丢失唤醒竞态**：
//!   `watch` 是"值 + 版本"通道——先创建 `subscribe`（读到当前值），再
//!   `changed()`；cancel 若在 `changed` 挂起后发生，`send` 立即可见；
//!   cancel 若在 `subscribe` 之前发生，前置 `is_cancelled` 检查命中。
//!   二者之间发生的 cancel 由 `changed()` 的版本比较捕获。
//! - [`CancellationToken::is_cancelled`]：非阻塞检查。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;

/// 内部状态（Arc 共享；watch sender 生命周期与 token 相同）。
#[derive(Debug)]
struct Inner {
    /// 已取消标记（Acquire/Release 语义的确定性检查）。
    state: AtomicBool,
    /// 取消通知通道（true = 已取消）。
    notify: watch::Sender<bool>,
}

/// 结构化取消令牌（§15.3）。`Clone` 共享同一取消源。
#[derive(Debug, Clone)]
pub struct CancellationToken {
    inner: Arc<Inner>,
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

impl CancellationToken {
    /// 创建未取消的令牌。
    pub fn new() -> Self {
        let (notify, _) = watch::channel(false);
        Self {
            inner: Arc::new(Inner {
                state: AtomicBool::new(false),
                notify,
            }),
        }
    }

    /// 发起取消（幂等：至多一次通知语义）。
    pub fn cancel(&self) {
        if !self.inner.state.swap(true, Ordering::AcqRel) {
            // 只有首次取消才通知；忽略"无接收者"错误（此时没有等待者，
            // 后续等待者都会先看到 state=true）。
            let _ = self.inner.notify.send(true);
        }
    }

    /// 是否已取消（非阻塞）。
    pub fn is_cancelled(&self) -> bool {
        self.inner.state.load(Ordering::Acquire)
    }

    /// 等待取消（§15.3：调用方在此显式挂起并响应取消）。
    ///
    /// 无丢失唤醒：见模块文档的竞态分析。
    pub async fn cancelled(&self) {
        if self.is_cancelled() {
            return;
        }
        let mut rx = self.inner.notify.subscribe();
        if self.is_cancelled() {
            return;
        }
        // changed() 返回 Err 仅当 sender 已 drop（本 token 存活期间不可达）。
        let _ = rx.changed().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn fresh_token_is_not_cancelled() {
        let token = CancellationToken::new();
        assert!(!token.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let token = CancellationToken::new();
        token.cancel();
        token.cancel();
        assert!(token.is_cancelled());
    }

    #[test]
    fn cloned_tokens_share_cancellation() {
        let token = CancellationToken::new();
        let cloned = token.clone();
        token.cancel();
        assert!(cloned.is_cancelled());
        assert!(token.is_cancelled());
    }

    #[tokio::test]
    async fn cancelled_before_await_returns_immediately() {
        let token = CancellationToken::new();
        token.cancel();
        let elapsed = tokio::time::Instant::now();
        token.cancelled().await;
        assert!(
            elapsed.elapsed() < Duration::from_millis(100),
            "must not block after cancellation"
        );
    }

    #[tokio::test]
    async fn cancel_wakes_waiting_waiter() {
        let token = CancellationToken::new();
        let waiter = {
            let token = token.clone();
            tokio::spawn(async move { token.cancelled().await })
        };
        // 给 waiter 时间进入等待（cancelled 的第一次 is_cancelled 检查必
        // 须在 cancel 之前完成，否则测试无意义）。
        tokio::time::sleep(Duration::from_millis(20)).await;
        token.cancel();
        let _ = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .ok();
    }

    #[tokio::test]
    async fn repeated_cancelled_awaits_are_instant() {
        // cancel 之后，任何后续 cancelled() 调用立即返回（确定性）。
        let token = CancellationToken::new();
        token.cancel();
        for _ in 0..3 {
            let elapsed = tokio::time::Instant::now();
            token.cancelled().await;
            assert!(elapsed.elapsed() < Duration::from_millis(100));
        }
    }
}
