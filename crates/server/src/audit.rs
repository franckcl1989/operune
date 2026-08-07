//! CLI 操作的 durable audit（§16.3：bootstrap/recovery CLI 的能力全部审计；
//! §18.7：audit 写入失败 ⇒ fail closed，先写 audit 再提交变更）。
//!
//! 事件模型使用 storage-sqlite 的 typed audit 记录（`users`/`audit` 同事务
//! 写入，见 storage 的 repository：变更命令自带 audit 事件，读命令用
//! `append_audit`）。事件内容不含 secret（§16.6：无密码/私钥/token 值）。

use operune_storage_sqlite::StorageError;
use operune_storage_sqlite::StorageExecutor;
use operune_storage_sqlite::model::{AuditActor, AuditCategory, AuditEvent, AuditOutcome};

/// bootstrap-admin 动作标识。
pub const ACTION_BOOTSTRAP_ADMIN_CREATE: &str = "bootstrap.admin.create";

/// recover safe mode 动作标识。
pub const ACTION_RECOVER_SAFE_MODE_ENTER: &str = "recover.safe-mode.enter";

/// recover safe mode 退出动作标识。
pub const ACTION_RECOVER_SAFE_MODE_EXIT: &str = "recover.safe-mode.exit";

/// recover component 列表动作标识。
pub const ACTION_RECOVER_COMPONENT_LIST: &str = "recover.component.list";

/// recover component 禁用动作标识。
pub const ACTION_RECOVER_COMPONENT_DISABLE: &str = "recover.component.disable";

/// recover component 启用动作标识。
pub const ACTION_RECOVER_COMPONENT_ENABLE: &str = "recover.component.enable";

/// status 动作标识。
pub const ACTION_STATUS: &str = "cli.status";

/// 本机 CLI 操作主体：System（本地显式操作，非已认证 Web 会话；
/// 无用户 ID 可引用，§16.3）。
const CLI_ACTOR: AuditActor = AuditActor::System;

/// 构造 recovery 类别审计事件（validate-on-construct，§13.3）。
pub fn recovery_event(
    action: &str,
    target: Option<String>,
    outcome: AuditOutcome,
    detail: Option<String>,
) -> Result<AuditEvent, StorageError> {
    AuditEvent::new(
        CLI_ACTOR,
        AuditCategory::Recovery,
        action,
        target,
        outcome,
        detail,
    )
}

/// 构造用户管理类别审计事件（bootstrap-admin 用）。
pub fn user_event(
    action: &str,
    target: Option<String>,
    outcome: AuditOutcome,
    detail: Option<String>,
) -> Result<AuditEvent, StorageError> {
    AuditEvent::new(
        CLI_ACTOR,
        AuditCategory::User,
        action,
        target,
        outcome,
        detail,
    )
}

/// 记录一次失败（§16.3 全部审计：失败同样落 audit，outcome=Failure）。
///
/// best effort 语义：主操作已失败，本记录尽力而为；调用方以主错误为准，
/// 本函数返回 audit 自身的失败（供报告，不掩盖主错误）。
pub async fn record_failure(
    executor: &StorageExecutor,
    action: &str,
    target: Option<String>,
    detail: String,
) -> Result<(), StorageError> {
    let event = recovery_event(action, target, AuditOutcome::Failure, Some(detail))?;
    executor.append_audit(event).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    #[test]
    fn recovery_event_roundtrip_fields() {
        let event = ok(
            recovery_event(
                ACTION_RECOVER_COMPONENT_DISABLE,
                Some("inst-1".into()),
                AuditOutcome::Success,
                Some("disabled".into()),
            ),
            "event",
        );
        assert_eq!(event.actor(), &AuditActor::System);
        assert_eq!(event.category(), AuditCategory::Recovery);
        assert_eq!(event.action(), ACTION_RECOVER_COMPONENT_DISABLE);
        assert_eq!(event.target(), Some("inst-1"));
        assert_eq!(event.outcome(), AuditOutcome::Success);
        assert_eq!(event.detail(), Some("disabled"));
    }

    #[test]
    fn user_event_uses_user_category() {
        let event = ok(
            user_event(
                ACTION_BOOTSTRAP_ADMIN_CREATE,
                Some("admin".into()),
                AuditOutcome::Success,
                None,
            ),
            "event",
        );
        assert_eq!(event.category(), AuditCategory::User);
        assert_eq!(event.action(), ACTION_BOOTSTRAP_ADMIN_CREATE);
    }

    #[test]
    fn invalid_action_rejected() {
        // storage 侧 validate-on-construct（§13.3）：action 拒绝空串/超长/
        // 控制字符；空格不是控制字符，改用 NUL 表达"非法 action 拒绝"。
        assert!(recovery_event("has\u{0}null", None, AuditOutcome::Success, None).is_err());
        assert!(recovery_event("", None, AuditOutcome::Success, None).is_err());
    }
}
