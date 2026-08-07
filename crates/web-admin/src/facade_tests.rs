#![cfg(test)]

//! [`RealAdminApi`] 与 adapter 级 port 的单元测试（§32 对应项）。
//!
//! 安装/升级管线不能在 web-admin 测试中端到端执行（application 的
//! `GuestComponentDescriptor` 字段 pub(crate)，见 crate 文档 API 缺口）；
//! HTTP 层测试用 [`FakeAdminApi`] 注入（见 `tests` 模块）。

use operune_observability::{AuditAction, AuditCategory, AuditEvent, AuditOutcome, AuditSeverity};
use operune_security::session::SessionError;
use secrecy::SecretString;
use time::OffsetDateTime;

use crate::facade::{
    AdminApi, AdminError, AdminUser, AdminUserError, AdminUserStore, AuditLogView,
    InMemoryAdminUserStore, InMemoryAuditLog, SafeModeState, format_bytes, grant_scope_summary,
};
use crate::test_support::{action_grant, grant, harness, ok_or_fail, some_or_fail};
use operune_application::{ApplicationError, GrantScope, RuntimeConfig};
use operune_domain::{ByteSize, InstallationId};
use operune_observability::AuditSink;
use operune_security::password::{PasswordHashString, PasswordHasher};

fn hash_of(password: &str) -> PasswordHashString {
    ok_or_fail(
        PasswordHasher::default().hash(&SecretString::from(password)),
        "hash",
    )
}

#[test]
fn user_credentials_verify_and_unknown_is_false() {
    let store = InMemoryAdminUserStore::new(PasswordHasher::default());
    ok_or_fail(
        store.create(AdminUser {
            subject: "alice".to_owned(),
            enabled: true,
            password_hash: hash_of("correct-horse-battery"),
        }),
        "create",
    );
    let matched = ok_or_fail(
        store.verify_credentials("alice", &SecretString::from("correct-horse-battery")),
        "verify",
    );
    assert!(matched);
    let wrong = ok_or_fail(
        store.verify_credentials("alice", &SecretString::from("wrong-password")),
        "verify wrong",
    );
    assert!(!wrong);
    // 未知主体：Ok(false)（不泄漏主体是否存在，§16.4 等时性纵深）。
    let unknown = ok_or_fail(
        store.verify_credentials("nobody", &SecretString::from("correct-horse-battery")),
        "verify unknown",
    );
    assert!(!unknown);
}

#[test]
fn user_store_rejects_duplicate_and_missing() {
    let store = InMemoryAdminUserStore::new(PasswordHasher::default());
    ok_or_fail(
        store.create(AdminUser {
            subject: "alice".to_owned(),
            enabled: true,
            password_hash: hash_of("correct-horse-battery"),
        }),
        "create",
    );
    assert!(matches!(
        store.create(AdminUser {
            subject: "alice".to_owned(),
            enabled: true,
            password_hash: hash_of("correct-horse-battery"),
        }),
        Err(AdminUserError::AlreadyExists(_))
    ));
    assert!(matches!(
        store.set_enabled("nobody", true),
        Err(AdminUserError::NotFound(_))
    ));
    assert_eq!(ok_or_fail(store.list(), "list").len(), 1);
    assert!(ok_or_fail(store.is_enabled("alice"), "is_enabled"));
}

#[test]
fn audit_log_ring_buffer_caps_and_orders() {
    let log = InMemoryAuditLog::with_capacity(3);
    for i in 0..5u32 {
        ok_or_fail(
            log.write(AuditEvent::new(
                AuditCategory::System,
                AuditSeverity::Info,
                AuditOutcome::Success,
                ok_or_fail(AuditAction::new("test.event"), "action"),
                format!("event {i}"),
            )),
            "write",
        );
    }
    let recent = log.recent(10);
    assert_eq!(recent.len(), 3);
    assert!(recent[0].message.contains("event 4"));
    assert!(recent[2].message.contains("event 2"));
    assert_eq!(log.recent(2).len(), 2);
}

#[test]
fn safe_mode_toggle_audited() {
    let harness = harness();
    assert!(!harness.api.safe_mode_status());
    ok_or_fail(harness.api.set_safe_mode(true), "enter");
    assert!(harness.api.safe_mode_status());
    // 幂等：状态未变化时不重复审计（写入仍成功）。
    ok_or_fail(harness.api.set_safe_mode(true), "re-enter");
    ok_or_fail(harness.api.set_safe_mode(false), "exit");
    assert!(!harness.api.safe_mode_status());
    assert!(harness.admin_audit.len() >= 2);
}

#[test]
fn status_and_config_views() {
    let harness = harness();
    let status = ok_or_fail(harness.api.status(), "status");
    assert!(status.installations.is_empty());
    assert!(status.active.is_empty());
    assert!(status.config.max_web_assets > 0);
    assert!(!format_bytes(ByteSize::ZERO).is_empty());
    // KiB/MiB 格式化边界。
    assert!(format_bytes(ByteSize::from_bytes(2048)).contains("KiB"));
    assert!(format_bytes(ByteSize::from_bytes(2 * 1024 * 1024)).contains("MiB"));
}

#[test]
fn grant_scope_summary_redacts_env_values() {
    // §16.6：环境变量 grant 的值不得进入页面/审计。
    let scope = GrantScope::WasiEnv {
        key: "API_TOKEN".to_owned(),
        value: "super-secret-value".to_owned(),
    };
    let summary = grant_scope_summary(&scope);
    assert!(!summary.contains("super-secret-value"));
    assert!(summary.contains("API_TOKEN"));
    assert!(summary.contains("REDACTED"));
}

#[test]
fn users_crud_and_disable_revokes_sessions() {
    let harness = harness();
    harness.seed_user("alice", "correct-horse-battery");
    let issued = ok_or_fail(
        harness.session_manager.create(
            &*harness.sessions,
            "alice".to_owned(),
            OffsetDateTime::now_utc(),
        ),
        "create session",
    );

    let views = ok_or_fail(harness.api.list_users(), "list");
    assert_eq!(views.len(), 1);
    assert!(views[0].enabled);

    // 禁用 → session 作废（§16.5）。
    ok_or_fail(
        harness.api.set_user_enabled("alice".to_owned(), false),
        "disable",
    );
    assert!(matches!(
        harness.session_manager.validate(
            &*harness.sessions,
            issued.token(),
            OffsetDateTime::now_utc()
        ),
        Err(SessionError::Unknown)
    ));
    let views = ok_or_fail(harness.api.list_users(), "list");
    assert!(!views[0].enabled);
    // 不存在的用户。
    assert!(matches!(
        harness.api.set_user_enabled("nobody".to_owned(), true),
        Err(AdminError::Users(AdminUserError::NotFound(_)))
    ));
}

#[test]
fn create_user_rejects_weak_passwords_and_bad_subjects() {
    let harness = harness();
    assert!(matches!(
        harness
            .api
            .create_user("alice".to_owned(), SecretString::from("short")),
        Err(AdminError::InvalidInput(_))
    ));
    assert!(matches!(
        harness.api.create_user(
            "bad/name".to_owned(),
            SecretString::from("long-enough-password-123")
        ),
        Err(AdminError::InvalidInput(_))
    ));
    ok_or_fail(
        harness.api.create_user(
            "alice".to_owned(),
            SecretString::from("valid-password-12345"),
        ),
        "create",
    );
    assert!(matches!(
        harness.api.create_user(
            "alice".to_owned(),
            SecretString::from("valid-password-12345")
        ),
        Err(AdminError::Users(AdminUserError::AlreadyExists(_)))
    ));
    // 新用户可用存储中的哈希验证登录。
    let verified = ok_or_fail(
        harness
            .users
            .verify_credentials("alice", &SecretString::from("valid-password-12345")),
        "verify created user",
    );
    assert!(verified);
}

#[test]
fn grants_replace_roundtrip() {
    let harness = harness();
    let installation = InstallationId::new();
    ok_or_fail(
        harness
            .api
            .replace_grants(installation, vec![grant("operune:web/actions")]),
        "replace",
    );
    let grants = ok_or_fail(harness.api.grants_for(installation), "grants");
    assert_eq!(grants, vec![grant("operune:web/actions")]);
    // action-scoped grant 保留 scope。
    ok_or_fail(
        harness.api.replace_grants(
            installation,
            vec![action_grant("operune:web/actions", "run-check")],
        ),
        "replace scoped",
    );
    let grants = ok_or_fail(harness.api.grants_for(installation), "grants");
    assert!(matches!(grants[0].scope, GrantScope::Action { ref name } if name == "run-check"));
}

#[test]
fn disable_transitions_active_to_disabled() {
    let harness = harness();
    let installation = harness.insert_active_record();
    ok_or_fail(harness.api.disable(installation), "disable");
    let record = some_or_fail(harness.registry.installation(installation), "record");
    assert_eq!(
        record.state,
        operune_domain::ComponentLifecycleState::Disabled
    );

    // 未知安装 → NotFound。
    assert!(matches!(
        harness.api.disable(InstallationId::new()),
        Err(AdminError::NotFound(_))
    ));
    // 非 Active（Disabled）→ 非法转换。
    assert!(matches!(
        harness.api.disable(installation),
        Err(AdminError::Domain(_))
    ));
    // enable：0.1 明确不支持（application 用例 API 缺口）。
    assert!(matches!(
        harness.api.enable(installation),
        Err(AdminError::Unsupported(_))
    ));
}

#[test]
fn install_oversized_rejected_before_pipeline() {
    // §19.1 / §32：oversized 输入提前拒绝（facade 预检 + 管线二次检查）。
    let harness = crate::test_support::TestHarness::new(RuntimeConfig {
        max_component_bytes: ByteSize::from_bytes(16),
        ..RuntimeConfig::default()
    });
    let result = harness.api.install(vec![0u8; 17], Vec::new());
    assert!(matches!(
        result,
        Err(AdminError::Application(
            ApplicationError::OversizedComponent { .. }
        ))
    ));
}

#[test]
fn safe_mode_state_public_accessors() {
    let state = SafeModeState::new();
    assert!(!state.is_enabled());
    assert!(!state.set_enabled(true));
    assert!(state.is_enabled());
    assert!(state.set_enabled(true));
    // 最后调用 set(false) 返回旧值 true（前面已是 true）。
    assert!(state.set_enabled(false));
    assert!(!state.is_enabled());
}
