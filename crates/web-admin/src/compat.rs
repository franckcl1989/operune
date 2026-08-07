//! 本地兼容层（application/security 的 API 缺口适配，见 crate 文档）。
//!
//! # 缺口 1：`SessionStore` 无 `Send + Sync` 边界
//!
//! [`operune_security::session::SessionStore`] port 未声明 `Send + Sync`，
//! `Arc<dyn SessionStore>` 不能跨线程传递，axum `Router` 需要 `Send` 服务。
//! 本模块定义本地超集 trait [`SendableSessionStore`] 并以 blanket impl
//! 覆盖全部实现（`InMemorySessionStore`、storage-sqlite 的持久化实现均
//! 满足 `Send + Sync`）。
//!
//! # 缺口 2：`SessionManager` 的方法参数是 `&impl SessionStore`（隐式
//! `Sized`）——trait object 无法直接传入
//!
//! [`SessionStoreRef`] 是 `Sized` 的转发包装（内部持有
//! `Arc<dyn SendableSessionStore>`），实现 [`SessionStore`] 委托给内部
//! store；AdminState 经 [`crate::state::AdminState::session_store`] 构造，
//! 调用点以具体类型传给 `SessionManager`。
//!
//! 建议：security 的 `SessionStore` 声明 `Send + Sync` 超边界，且
//! `SessionManager` 方法改为接受 `&dyn SessionStore`（API 缺口）。

use std::sync::Arc;

use operune_security::session::{SessionRecord, SessionStore};
use operune_security::token::TokenDigest;

/// 可跨线程的 [`SessionStore`]（本地超集；blanket impl）。
pub trait SendableSessionStore: SessionStore + Send + Sync {}

impl<T: SessionStore + Send + Sync> SendableSessionStore for T {}

/// `Sized` 的 [`SessionStore`] 转发包装（缺口 2 的适配点）。
#[derive(Clone)]
pub struct SessionStoreRef(pub(crate) Arc<dyn SendableSessionStore>);

impl SessionStoreRef {
    /// 包装一个共享 store。
    pub fn new(store: Arc<dyn SendableSessionStore>) -> Self {
        Self(store)
    }
}

impl SessionStore for SessionStoreRef {
    fn get(&self, digest: &TokenDigest) -> Option<SessionRecord> {
        self.0.get(digest)
    }

    fn insert(&self, record: SessionRecord) {
        self.0.insert(record);
    }

    fn remove(&self, digest: &TokenDigest) -> bool {
        self.0.remove(digest)
    }

    fn remove_all_for_subject(&self, subject: &str) -> usize {
        self.0.remove_all_for_subject(subject)
    }
}
