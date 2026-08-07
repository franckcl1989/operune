//! 服务端 session 生命周期（§16.5）。
//!
//! - authoritative store（[`SessionStore`] port）只保存 bearer token 的**单向
//!   digest**（[`TokenDigest`]），bearer 明文类型层面不进入 store：store 的键
//!   只有 digest，[`SessionRecord`] 没有 token 字段；
//! - idle expiry 与 absolute expiry 同时存在（[`SessionPolicy`]）；
//! - 登录、权限提升、敏感身份变化时旋转 session（[`SessionManager::rotate`]）；
//! - logout / 管理员禁用 / 密码重置 / 高风险权限撤销可作废相关 server-side
//!   session（[`SessionManager::revoke`] / [`SessionManager::revoke_all_for_subject`]）；
//! - 每次请求的 CSRF 校验使用记录内的 [`CsrfSecret`]（与 bearer token 独立）。
//!
//! 存储实现（0.1：storage-sqlite）实现 [`SessionStore`] port；本 crate 提供
//! [`InMemorySessionStore`] 供测试与开发使用。

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard};

use time::{Duration, OffsetDateTime};

use crate::csrf::{CsrfError, CsrfSecret};
use crate::token::{SessionToken, TokenDigest, TokenError};

/// session 生命周期策略（§16.5：idle expiry + absolute expiry 同时存在）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPolicy {
    absolute_lifetime: Duration,
    idle_timeout: Duration,
}

impl SessionPolicy {
    /// 0.1 默认策略：absolute 12 小时、idle 30 分钟。
    ///
    /// §16.5 未固定数值；Root Admin 是管理平面，0.1 取保守默认，
    /// web-admin 可用 [`SessionPolicy::new`] 配置覆盖。
    pub const DEFAULT: Self = Self {
        absolute_lifetime: Duration::hours(12),
        idle_timeout: Duration::minutes(30),
    };

    /// 校验并构造：两个期限都必须为正（§13.4 不合法状态不可表示）。
    pub fn new(absolute_lifetime: Duration, idle_timeout: Duration) -> Result<Self, SessionError> {
        if absolute_lifetime <= Duration::ZERO || idle_timeout <= Duration::ZERO {
            return Err(SessionError::InvalidPolicy {
                absolute_lifetime,
                idle_timeout,
            });
        }
        Ok(Self {
            absolute_lifetime,
            idle_timeout,
        })
    }

    /// absolute expiry 期限。
    pub const fn absolute_lifetime(&self) -> Duration {
        self.absolute_lifetime
    }

    /// idle expiry 期限。
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// 权威 session 记录（§16.5）。
///
/// **只保存 bearer token 的单向 digest**；bearer 明文（[`SessionToken`]）只存在
/// 于发放瞬间与客户端，类型层面不进入本结构、不进入 store。
#[derive(Clone, Debug)]
pub struct SessionRecord {
    digest: TokenDigest,
    subject: String,
    csrf_secret: CsrfSecret,
    created_at: OffsetDateTime,
    last_used_at: OffsetDateTime,
}

impl SessionRecord {
    /// 构造记录。由 [`SessionManager`] 发放，或由存储层从持久化字段重建时使用。
    pub fn new(
        digest: TokenDigest,
        subject: String,
        csrf_secret: CsrfSecret,
        created_at: OffsetDateTime,
        last_used_at: OffsetDateTime,
    ) -> Self {
        Self {
            digest,
            subject,
            csrf_secret,
            created_at,
            last_used_at,
        }
    }

    /// 记录键：bearer token 的 SHA-256 单向 digest。
    pub fn digest(&self) -> &TokenDigest {
        &self.digest
    }

    /// 会话主体（身份绑定；不含业务权限，§24.2）。
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// 会话绑定的 CSRF secret（与 bearer token 独立，§16.5）。
    pub fn csrf_secret(&self) -> &CsrfSecret {
        &self.csrf_secret
    }

    /// 创建时间（absolute expiry 的基准）。
    pub fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// 最近活动时间（idle expiry 的基准）。
    pub fn last_used_at(&self) -> OffsetDateTime {
        self.last_used_at
    }

    /// 更新最近活动时间（validate 时 touch）。
    fn touch(&mut self, now: OffsetDateTime) {
        self.last_used_at = now;
    }
}

/// authoritative session store port（§16.5）。
///
/// - 键必须是 [`TokenDigest`]（单向 digest），实现方**不得**保存 bearer 明文；
/// - 并发语义由实现方保证（0.1 的 SQLite 实现走 storage-sqlite 的 executor）。
pub trait SessionStore {
    /// 读取记录；不存在返回 `None`。
    fn get(&self, digest: &TokenDigest) -> Option<SessionRecord>;

    /// 写入或覆盖（upsert；记录的键 digest 不可变）。
    fn insert(&self, record: SessionRecord);

    /// 删除记录；返回是否存在。
    fn remove(&self, digest: &TokenDigest) -> bool;

    /// 作废该 subject 的全部 session（管理员禁用 / 密码重置 / 高权限撤销，
    /// §16.5）；返回删除数量。
    fn remove_all_for_subject(&self, subject: &str) -> usize;
}

/// 进程内 session store（测试/开发用）。
///
/// 真实持久化由 storage-sqlite 实现 [`SessionStore`] port。
/// 线程安全：内部 `Mutex` 串行化（session 操作低频，§15.2 有界并发）。
/// `Debug` 只输出 digest 与记录元数据，不含 bearer token（§16.5）。
#[derive(Debug, Default)]
pub struct InMemorySessionStore {
    inner: Mutex<HashMap<TokenDigest, SessionRecord>>,
}

impl InMemorySessionStore {
    /// 新建空 store。
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<TokenDigest, SessionRecord>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            // 本 crate 无 panic 路径；poison 只能来自外部持有者异常终止。
            // 为满足"不可恢复不变量 fail-stop"以外的容忍语义，取回数据继续。
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

impl SessionStore for InMemorySessionStore {
    fn get(&self, digest: &TokenDigest) -> Option<SessionRecord> {
        self.lock().get(digest).cloned()
    }

    fn insert(&self, record: SessionRecord) {
        self.lock().insert(*record.digest(), record);
    }

    fn remove(&self, digest: &TokenDigest) -> bool {
        self.lock().remove(digest).is_some()
    }

    fn remove_all_for_subject(&self, subject: &str) -> usize {
        let mut guard = self.lock();
        let before = guard.len();
        guard.retain(|_, record| record.subject() != subject);
        before - guard.len()
    }
}

/// session 生命周期管理器（§16.5）。无内部状态：策略 + store port。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionManager {
    policy: SessionPolicy,
}

impl SessionManager {
    /// 以指定策略构造。
    pub fn new(policy: SessionPolicy) -> Self {
        Self { policy }
    }

    /// 当前策略。
    pub const fn policy(&self) -> SessionPolicy {
        self.policy
    }

    /// 发放新 session（登录）。bearer token 仅此一次可见（§16.5）。
    pub fn create(
        &self,
        store: &impl SessionStore,
        subject: String,
        now: OffsetDateTime,
    ) -> Result<IssuedSession, SessionError> {
        let token = SessionToken::generate()?;
        let csrf_secret = CsrfSecret::generate()?;
        let record = SessionRecord::new(token.digest(), subject, csrf_secret, now, now);
        store.insert(record.clone());
        Ok(IssuedSession { token, record })
    }

    /// 校验 session 并 touch 活动时间。
    ///
    /// - 未知/已作废 digest：[`SessionError::Unknown`]；
    /// - 过期（absolute 或 idle）：从 store 作废记录并返回
    ///   [`SessionError::Expired`]（§16.5 失效机制）。
    pub fn validate(
        &self,
        store: &impl SessionStore,
        token: &SessionToken,
        now: OffsetDateTime,
    ) -> Result<SessionRecord, SessionError> {
        let digest = token.digest();
        let Some(mut record) = store.get(&digest) else {
            return Err(SessionError::Unknown);
        };

        // absolute expiry：创建时刻 + 绝对期限（checked 运算，§14.4）。
        let absolute_expiry = record
            .created_at()
            .checked_add(self.policy.absolute_lifetime())
            .ok_or(SessionError::TimeOverflow)?;
        if now >= absolute_expiry {
            store.remove(&digest);
            return Err(SessionError::Expired {
                reason: ExpiryReason::Absolute,
            });
        }

        // idle expiry：最近活动时刻 + 空闲期限。
        let idle_cutoff = record
            .last_used_at()
            .checked_add(self.policy.idle_timeout())
            .ok_or(SessionError::TimeOverflow)?;
        if now >= idle_cutoff {
            store.remove(&digest);
            return Err(SessionError::Expired {
                reason: ExpiryReason::Idle,
            });
        }

        record.touch(now);
        store.insert(record.clone());
        Ok(record)
    }

    /// 旋转 session（登录/权限提升/敏感身份变化，§16.5）：发放新 bearer token 与
    /// 新 CSRF secret（独立随机值，§16.5），同时作废旧 session。
    ///
    /// `previous` 为 `None`（如首次登录）时等价于 [`SessionManager::create`]。
    /// 旧 session 已不存在时仍成功（幂等，不泄漏旧 session 是否有效）。
    pub fn rotate(
        &self,
        store: &impl SessionStore,
        previous: Option<&SessionToken>,
        subject: String,
        now: OffsetDateTime,
    ) -> Result<IssuedSession, SessionError> {
        if let Some(previous) = previous {
            store.remove(&previous.digest());
        }
        self.create(store, subject, now)
    }

    /// 作废指定 session（logout，§16.5）。返回是否实际删除。
    pub fn revoke(&self, store: &impl SessionStore, token: &SessionToken) -> bool {
        store.remove(&token.digest())
    }

    /// 作废某 subject 的全部 session（管理员禁用 / 密码重置 / 高权限撤销，
    /// §16.5）。返回删除数量。
    pub fn revoke_all_for_subject(&self, store: &impl SessionStore, subject: &str) -> usize {
        store.remove_all_for_subject(subject)
    }
}

/// 一次 session 发放结果：bearer token 只在此时可见（§16.5），
/// 调用方应立即交给客户端并只保留记录。
#[derive(Clone, Debug)]
pub struct IssuedSession {
    token: SessionToken,
    record: SessionRecord,
}

impl IssuedSession {
    /// bearer token（交给客户端一次后丢弃）。
    pub fn token(&self) -> &SessionToken {
        &self.token
    }

    /// 权威记录（存入 store 的那份副本）。
    pub fn record(&self) -> &SessionRecord {
        &self.record
    }
}

/// 过期原因（§16.5：absolute 与 idle 同时存在）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryReason {
    /// 超过 absolute expiry。
    Absolute,
    /// 超过 idle expiry。
    Idle,
}

impl fmt::Display for ExpiryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExpiryReason::Absolute => f.write_str("absolute expiry"),
            ExpiryReason::Idle => f.write_str("idle expiry"),
        }
    }
}

/// session 错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// 策略期限非正。
    #[error(
        "session 策略无效：absolute_lifetime={absolute_lifetime}, idle_timeout={idle_timeout}（必须为正）"
    )]
    InvalidPolicy {
        absolute_lifetime: Duration,
        idle_timeout: Duration,
    },
    /// 未知或已作废的 session。
    #[error("session 不存在或已被作废")]
    Unknown,
    /// session 已过期（记录已从 store 作废）。
    #[error("session 已过期：{reason}")]
    Expired { reason: ExpiryReason },
    /// 时间计算溢出（checked 运算，§14.4）。
    #[error("session 时间计算溢出")]
    TimeOverflow,
    /// bearer token 生成失败。
    #[error("bearer token 生成失败")]
    Token(#[from] TokenError),
    /// CSRF secret 生成失败。
    #[error("CSRF secret 生成失败")]
    Csrf(#[from] CsrfError),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_or_fail<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        assert!(
            result.is_ok(),
            "{what} 应成功，实际 Err: {:?}",
            result.as_ref().err()
        );
        match result {
            Ok(value) => value,
            Err(_) => unreachable!("上面的断言已保证 is_ok"),
        }
    }

    fn some_or_fail<T>(option: Option<T>, what: &str) -> T {
        assert!(option.is_some(), "{what} 应存在");
        match option {
            Some(value) => value,
            None => unreachable!("上面的断言已保证 is_some"),
        }
    }

    /// 测试基准时刻（远离 UNIX_EPOCH 的可表示时刻）。
    fn base_time() -> OffsetDateTime {
        some_or_fail(
            OffsetDateTime::UNIX_EPOCH.checked_add(Duration::days(400)),
            "base time",
        )
    }

    fn policy(absolute: i64, idle: i64) -> SessionPolicy {
        ok_or_fail(
            SessionPolicy::new(Duration::minutes(absolute), Duration::minutes(idle)),
            "policy",
        )
    }

    #[test]
    fn create_then_validate() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        assert_eq!(issued.record().subject(), "alice");
        assert_eq!(issued.record().created_at(), now);
        assert_eq!(issued.record().last_used_at(), now);

        // validate 后返回记录并 touch。
        let validated = ok_or_fail(
            manager.validate(&store, issued.token(), now + Duration::minutes(1)),
            "validate",
        );
        assert_eq!(validated.subject(), "alice");
        assert_eq!(validated.last_used_at(), now + Duration::minutes(1));
        assert_eq!(validated.digest(), &issued.token().digest());
    }

    #[test]
    fn validate_unknown_session_rejected() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let stranger = ok_or_fail(SessionToken::generate(), "generate");
        assert!(matches!(
            manager.validate(&store, &stranger, now),
            Err(SessionError::Unknown)
        ));
    }

    #[test]
    fn absolute_expiry_invalidates_session() {
        let manager = SessionManager::new(policy(10, 5));
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        // 11 分钟后：超过 absolute（10 分钟），未超过 idle（5 分钟）——仍判 absolute。
        assert!(matches!(
            manager.validate(&store, issued.token(), now + Duration::minutes(11)),
            Err(SessionError::Expired {
                reason: ExpiryReason::Absolute
            })
        ));
        // 过期后记录已从 store 作废。
        assert!(store.get(&issued.token().digest()).is_none());
    }

    #[test]
    fn idle_expiry_invalidates_session() {
        let manager = SessionManager::new(policy(120, 5));
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        // 3 分钟后仍有效（idle 5 分钟），touch 使 last_used 前移。
        ok_or_fail(
            manager.validate(&store, issued.token(), now + Duration::minutes(3)),
            "validate at +3min",
        );
        // 再过 6 分钟：距最近活动 6 分钟 > idle 5 分钟。
        assert!(matches!(
            manager.validate(&store, issued.token(), now + Duration::minutes(9)),
            Err(SessionError::Expired {
                reason: ExpiryReason::Idle
            })
        ));
        assert!(store.get(&issued.token().digest()).is_none());
    }

    #[test]
    fn activity_within_idle_window_keeps_session_alive() {
        let manager = SessionManager::new(policy(120, 5));
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        // 每 4 分钟活动一次：永远在 idle 窗口内。
        for step in 1..=10 {
            let at = now + Duration::minutes(4 * step);
            let record = ok_or_fail(manager.validate(&store, issued.token(), at), "validate");
            assert_eq!(record.last_used_at(), at);
        }
    }

    #[test]
    fn rotation_invalidates_old_and_issues_fresh_values() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let first = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        let rotated = ok_or_fail(
            manager.rotate(
                &store,
                Some(first.token()),
                "alice".into(),
                now + Duration::minutes(1),
            ),
            "rotate",
        );

        // 旧 token 失效；新 token 有效。
        assert!(matches!(
            manager.validate(&store, first.token(), now + Duration::minutes(2)),
            Err(SessionError::Unknown)
        ));
        ok_or_fail(
            manager.validate(&store, rotated.token(), now + Duration::minutes(2)),
            "validate new",
        );

        // 新随机值与旧值不同（§16.5：session token 与 CSRF token 都独立）。
        assert_ne!(
            first.token().to_url_safe_string(),
            rotated.token().to_url_safe_string()
        );
        assert_ne!(
            first.record().csrf_secret().to_url_safe_string(),
            rotated.record().csrf_secret().to_url_safe_string()
        );
        // 同一 session 内 CSRF secret 与 bearer token 也是不同随机值。
        assert_ne!(
            rotated.token().to_url_safe_string(),
            rotated.record().csrf_secret().to_url_safe_string()
        );
    }

    #[test]
    fn rotation_without_previous_is_login() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(
            manager.rotate(&store, None, "bob".into(), now),
            "rotate without previous",
        );
        assert_eq!(issued.record().subject(), "bob");
    }

    #[test]
    fn revoke_removes_session() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        assert!(manager.revoke(&store, issued.token()));
        assert!(
            !manager.revoke(&store, issued.token()),
            "再次 revoke 返回 false"
        );
        assert!(store.get(&issued.token().digest()).is_none());
    }

    #[test]
    fn revoke_all_for_subject_invalidates_related_sessions_only() {
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let alice_one = ok_or_fail(manager.create(&store, "alice".into(), now), "alice 1");
        let alice_two = ok_or_fail(manager.create(&store, "alice".into(), now), "alice 2");
        let bob = ok_or_fail(manager.create(&store, "bob".into(), now), "bob");

        // 密码重置/禁用：作废 alice 的全部 session（§16.5）。
        assert_eq!(manager.revoke_all_for_subject(&store, "alice"), 2);
        assert!(matches!(
            manager.validate(&store, alice_one.token(), now),
            Err(SessionError::Unknown)
        ));
        assert!(matches!(
            manager.validate(&store, alice_two.token(), now),
            Err(SessionError::Unknown)
        ));
        // bob 不受影响。
        ok_or_fail(
            manager.validate(&store, bob.token(), now),
            "bob still valid",
        );

        // 不存在的 subject：删除 0 个。
        assert_eq!(manager.revoke_all_for_subject(&store, "nobody"), 0);
    }

    #[test]
    fn policy_rejects_non_positive_durations() {
        assert!(matches!(
            SessionPolicy::new(Duration::ZERO, Duration::minutes(5)),
            Err(SessionError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            SessionPolicy::new(Duration::minutes(5), Duration::ZERO),
            Err(SessionError::InvalidPolicy { .. })
        ));
        assert!(matches!(
            SessionPolicy::new(Duration::minutes(-1), Duration::minutes(5)),
            Err(SessionError::InvalidPolicy { .. })
        ));
        assert!(SessionPolicy::new(Duration::minutes(5), Duration::minutes(1)).is_ok());
    }

    #[test]
    fn default_policy_is_sane() {
        let policy = SessionPolicy::DEFAULT;
        assert!(policy.absolute_lifetime() > policy.idle_timeout());
        assert!(policy.absolute_lifetime() > Duration::ZERO);
        assert!(policy.idle_timeout() > Duration::ZERO);
    }

    #[test]
    fn store_never_contains_bearer_token() {
        // §32 对应项：authoritative store 只存 digest——明文 token 不出现于存储输出。
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let issued = ok_or_fail(manager.create(&store, "alice".into(), now), "create");
        let token_string = issued.token().to_url_safe_string();

        let record = some_or_fail(store.get(&issued.token().digest()), "get record");
        // 结构保证：记录只有 digest。
        assert_eq!(record.digest(), &issued.token().digest());
        let record_debug = format!("{record:?}");
        assert!(
            !record_debug.contains(&token_string),
            "记录 Debug 输出泄漏 bearer token: {record_debug}"
        );

        let store_debug = format!("{store:?}");
        assert!(
            !store_debug.contains(&token_string),
            "store Debug 输出泄漏 bearer token: {store_debug}"
        );
        // digest 是 SHA-256 单向值，可出现在存储输出中。
        assert!(store_debug.contains(&issued.token().digest().to_hex()));
    }

    #[test]
    fn csrf_secret_validation_binds_to_session() {
        // web-admin 模式：validate 拿到记录 → 用记录内 CSRF secret 校验请求值。
        let manager = SessionManager::new(SessionPolicy::DEFAULT);
        let store = InMemorySessionStore::new();
        let now = base_time();

        let alice = ok_or_fail(manager.create(&store, "alice".into(), now), "alice");
        let bob = ok_or_fail(manager.create(&store, "bob".into(), now), "bob");

        let validated = ok_or_fail(manager.validate(&store, alice.token(), now), "validate");
        let alice_form_value = validated.csrf_secret().to_url_safe_string();
        let bob_form_value = bob.record().csrf_secret().to_url_safe_string();

        // alice 的 session 拒绝 bob 的 CSRF 值（跨 session 不互通）。
        assert!(validated.csrf_secret().verify(&alice_form_value).is_ok());
        assert!(matches!(
            validated.csrf_secret().verify(&bob_form_value),
            Err(crate::csrf::CsrfError::Mismatch)
        ));
    }
}
