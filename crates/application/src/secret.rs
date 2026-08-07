//! 0.3.0 Stateful Runtime（§41.2 / §16.6）——Secret service 用例层
//! （契约 `operune:secret@0.1.0` secret.wit，已提交稳定；加密层
//! [`operune_security::secret_store::SecretCipher`]，ADR-0001）。
//!
//! # 读取协议（§41.2 grant/read semantics + §17.5 四层授权链）
//!
//! ```text
//! 1. 名称必须在安装实例的 grant 集内（§17.3 "secret names" scope 维度；
//!    §17.5 第三层 Grant——durable owner 是 InstallationId，本服务只消费
//!    名称集；第四层 invocation-time enforcement 在本服务执行）；
//! 2. 未授权 → denied（与"名称不存在"合并，防止存在性预言机，secret.wit）;
//! 3. 已授权 → 存储读取**不透明密文 BLOB**（SecretStore port 不含明文）;
//! 4. security 层解密（SecretCipher，ADR-0001 envelope）→ `SecretBytes`;
//! 5. 审计只记 metadata（名称、版本、结果、安装实例——**不含值**，§16.6）;
//! 6. **明文值只存在于返回值**：错误、审计、日志、Debug 均不含值。
//! ```
//!
//! # 管理侧（Root Admin / Core 系统面）
//!
//! `rotate`（加密 → 存储密文，版本递增）与 `delete` 是轮换/撤销路径
//! （§16.6：轮换是管理员/密钥提供方职责，不在 guest 契约内）；`list_granted`
//! 是 guest 面枚举（只返回 grant 集内名称，不构成存在性查询）。
//!
//! # 防泄漏边界（§16.6）
//!
//! - 明文 `SecretBytes` 只在 `read_secret` 返回值出现一次；本服务内部不
//!   复制、不格式化、不序列化明文；
//! - 全部错误变体与审计事件不含值（`SecretError` 无值字段；
//!   `StatefulAuditEvent::Secret*` 只含名称/版本/结果）；
//! - 无缓存保证：每次读取返回当前值（轮换后下次读取即新值，secret.wit）。

use std::sync::Arc;

use operune_domain::{InstallationId, SecretMetadata, SecretName, SecretVersion};
use operune_security::secret_store::SecretCipher;

use crate::ports::{
    AuditError, GrantError, SecretGrantPort, SecretStoreError, SecretStorePort, StatefulAuditEvent,
    StatefulAuditPort,
};

/// secret 用例层错误（对齐 WIT `secret-error` 闭集，§6.3；**错误文本不含
/// 值**，§16.6；invalid-name 由 domain 边界拦截，不在本层）。
#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    /// 无权限或名称不存在——有意合并，不泄露 secret 存在性（secret.wit
    /// 防泄漏契约：denied 同时覆盖）。
    #[error("secret denied (no grant or name does not exist)")]
    Denied,

    /// 密钥提供方/存储不可用（重试性，WIT unavailable）。
    #[error("secret store or key provider unavailable")]
    Unavailable,

    /// 存储的 secret 未通过完整性检查（损坏；需管理员介入轮换，WIT
    /// corrupt——平台不会返回损坏值）。
    #[error("secret data corrupt")]
    Corrupt,

    /// 超出预算：读取速率/体积/次数（WIT over-budget）。
    #[error("secret operation over budget")]
    OverBudget,

    /// grant 集读取失败（§17.5 第三层）。
    #[error("secret grant set failure: {0}")]
    Grant(#[source] GrantError),

    /// 存储失败（WIT internal 面；source 保留可诊断上下文）。
    #[error("secret store failure: {0}")]
    Store(#[source] SecretStoreError),

    /// 审计失败（§18.7 fail closed）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] AuditError),

    /// host 内部不可恢复错误。
    #[error("application internal invariant violated: {0}")]
    Internal(&'static str),
}

impl SecretError {
    /// 审计 reason 标签（kebab-case 静态文本；不含值）。
    pub(crate) fn audit_label(&self) -> &'static str {
        match self {
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Corrupt => "corrupt",
            Self::OverBudget => "over-budget",
            Self::Grant(_) => "grant-set-failure",
            Self::Store(_) => "store-failure",
            Self::Audit(_) => "audit-failure",
            Self::Internal(_) => "internal",
        }
    }
}

/// 存储错误 → 用例错误映射（§14.1 封闭 typed）。
fn map_store_error(error: SecretStoreError) -> SecretError {
    match error {
        // 名称不存在（管理侧删除/轮换路径；读取路径的"不存在"在服务层
        // 已合并进 denied，不进入此映射）。
        SecretStoreError::NotFound(_) => SecretError::Store(error),
        SecretStoreError::InvalidArgument(_) => SecretError::OverBudget,
        SecretStoreError::Corrupt(_) => SecretError::Corrupt,
        SecretStoreError::Storage(_) => SecretError::Store(error),
    }
}

/// 加密层错误 → 用例错误映射（ADR-0001 fail closed：任何失败都不回退
/// 明文/静默成功；错误文本不含明文与密钥材料）。
fn map_cipher_error(error: operune_security::secret_store::SecretStoreError) -> SecretError {
    use operune_security::secret_store::SecretStoreError as CipherError;
    match error {
        CipherError::Decryption => SecretError::Corrupt,
        CipherError::OverBudget => SecretError::OverBudget,
        CipherError::Encryption => SecretError::Internal("secret encryption failed"),
        CipherError::KeyUnavailable(_) => SecretError::Unavailable,
        CipherError::CorruptKey => SecretError::Corrupt,
    }
}

/// Secret service（guest 读取按 grant + 管理侧轮换/删除；§41.2 / §16.6）。
///
/// 构造：`store`（密文存储，不含明文）、`grants`（§17.3 名称集）、
/// `cipher`（security 层，ADR-0001；KEK 由 key provider 在 composition
/// root 装配）、`audit`（metadata-only）——§24.2 端口注入。
pub struct SecretService {
    store: Arc<dyn SecretStorePort>,
    grants: Arc<dyn SecretGrantPort>,
    cipher: SecretCipher,
    audit: Arc<dyn StatefulAuditPort>,
}

impl SecretService {
    /// 构造（store + grant 集 + security 层密码器 + audit）。
    pub fn new(
        store: Arc<dyn SecretStorePort>,
        grants: Arc<dyn SecretGrantPort>,
        cipher: SecretCipher,
        audit: Arc<dyn StatefulAuditPort>,
    ) -> Self {
        Self {
            store,
            grants,
            cipher,
            audit,
        }
    }

    /// 读取被授予名称的 secret 当前值（WIT `read-secret`）。
    ///
    /// 协议（模块文档）：grant 检查（§17.5 第四层 invocation-time
    /// enforcement）→ 密文读取 → security 解密 → 审计（无值）。明文只
    /// 在本返回值出现一次；错误路径（denied/corrupt/unavailable/...）不
    /// 携带值。
    pub fn read_secret(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<operune_security::secret::SecretBytes, SecretError> {
        // 第四层 enforcement：名称必须在 grant 集内（§17.5：授权撤销、
        // scope 变化以确定语义生效，不依赖 Component 自觉）。
        let granted = self
            .grants
            .granted_names(installation)
            .map_err(SecretError::Grant)?;
        if !granted.iter().any(|granted| granted == name) {
            // denied 合并"无权限"与"名称不存在"（防存在性预言机）。
            self.audit(StatefulAuditEvent::SecretDenied {
                installation,
                name: name.clone(),
            })?;
            return Err(SecretError::Denied);
        }
        let record = match self.store.ciphertext(installation, name) {
            Ok(record) => record,
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, Some(name), &mapped)?;
                return Err(mapped);
            }
        };
        let Some(record) = record else {
            // 已授予但存储中不存在：与 denied 合并（不泄露存在性）。
            self.audit(StatefulAuditEvent::SecretDenied {
                installation,
                name: name.clone(),
            })?;
            return Err(SecretError::Denied);
        };
        // security 层解密（ADR-0001 envelope 校验；失败 fail closed）。
        let plaintext = match self.cipher.decrypt(&record.ciphertext) {
            Ok(plaintext) => plaintext,
            Err(error) => {
                let mapped = map_cipher_error(error);
                self.audit_failed(installation, Some(name), &mapped)?;
                return Err(mapped);
            }
        };
        // 审计只记 metadata（名称、版本、结果、安装实例；无值，§16.6）。
        self.audit(StatefulAuditEvent::SecretRead {
            installation,
            name: name.clone(),
            version: record.version,
        })?;
        Ok(plaintext)
    }

    /// 列举安装实例被授予的全部 secret 名称与版本（WIT
    /// `list-granted-secrets`；不含值）。
    ///
    /// 只返回 grant 集内的名称（grant 之外的名字不可见——不构成存在性
    /// 查询，secret.wit）。
    pub fn list_granted_secrets(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<SecretMetadata>, SecretError> {
        let granted = self
            .grants
            .granted_names(installation)
            .map_err(SecretError::Grant)?;
        let all = match self.store.list(installation) {
            Ok(all) => all,
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, None, &mapped)?;
                return Err(mapped);
            }
        };
        let filtered: Vec<SecretMetadata> = all
            .into_iter()
            .filter(|metadata| granted.contains(metadata.name()))
            .collect();
        self.audit(StatefulAuditEvent::SecretListed {
            installation,
            names: filtered.len(),
        })?;
        Ok(filtered)
    }

    /// 管理侧写入/轮换（§16.6：轮换是管理员/密钥提供方职责，不在 guest
    /// 契约内）。加密在 security 层完成（ADR-0001 envelope），本服务只把
    /// **不透明密文**交给存储 port（§41.2：SecretStore port 不含明文）。
    /// 返回新版本（审计关联）。
    pub fn rotate(
        &self,
        installation: InstallationId,
        name: &SecretName,
        plaintext: &operune_security::secret::SecretBytes,
        metadata: &str,
    ) -> Result<SecretVersion, SecretError> {
        let ciphertext = match self.cipher.encrypt(plaintext) {
            Ok(ciphertext) => ciphertext,
            Err(error) => {
                let mapped = map_cipher_error(error);
                self.audit_failed(installation, Some(name), &mapped)?;
                return Err(mapped);
            }
        };
        let version = match self.store.put(installation, name, ciphertext, metadata) {
            Ok(version) => version,
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, Some(name), &mapped)?;
                return Err(mapped);
            }
        };
        self.audit(StatefulAuditEvent::SecretRotated {
            installation,
            name: name.clone(),
            version,
        })?;
        Ok(version)
    }

    /// 管理侧删除（撤销；名称不存在 → 存储 NotFound 透传，管理员侧可见
    /// 存在性——管理员是存储的 owner，无存在性预言机风险）。
    pub fn delete(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<(), SecretError> {
        match self.store.delete(installation, name) {
            Ok(()) => {
                self.audit(StatefulAuditEvent::SecretDeleted {
                    installation,
                    name: name.clone(),
                })?;
                Ok(())
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, Some(name), &mapped)?;
                Err(mapped)
            }
        }
    }

    fn audit(&self, event: StatefulAuditEvent) -> Result<(), SecretError> {
        self.audit.append(event).map_err(SecretError::Audit)
    }

    fn audit_failed(
        &self,
        installation: InstallationId,
        name: Option<&SecretName>,
        error: &SecretError,
    ) -> Result<(), SecretError> {
        self.audit
            .append(StatefulAuditEvent::SecretFailed {
                installation,
                name: name.cloned(),
                reason: error.audit_label(),
            })
            .map_err(SecretError::Audit)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use operune_domain::{SecretName, SecretVersion};
    use operune_security::secret::SecretBytes;
    use operune_security::secret_store::{KEK_SIZE, SecretCipher};
    use secrecy::ExposeSecret;

    use crate::ports::StatefulAuditEvent;
    use crate::test_support::{
        FakeSecretGrants, FakeSecretStore, FakeStatefulAudit, err, installation, ok,
    };

    use super::*;

    fn name(value: &str) -> SecretName {
        ok(SecretName::new(value), "secret name")
    }

    fn cipher() -> SecretCipher {
        ok(
            SecretCipher::new(&SecretBytes::from_slice(&[0x42; KEK_SIZE])),
            "cipher",
        )
    }

    struct Harness {
        service: SecretService,
        store: Arc<FakeSecretStore>,
        grants: Arc<FakeSecretGrants>,
        audit: Arc<FakeStatefulAudit>,
    }

    fn harness() -> Harness {
        let store = Arc::new(FakeSecretStore::new());
        let grants = Arc::new(FakeSecretGrants::new());
        let audit = Arc::new(FakeStatefulAudit::new());
        let service = SecretService::new(store.clone(), grants.clone(), cipher(), audit.clone());
        Harness {
            service,
            store,
            grants,
            audit,
        }
    }

    #[test]
    fn read_secret_returns_plaintext_for_granted_name() {
        let harness = harness();
        let inst = installation(1);
        harness.grants.set_granted(inst, vec![name("db-password")]);
        ok(
            harness.service.rotate(
                inst,
                &name("db-password"),
                &SecretBytes::from_slice(b"top-secret"),
                "database credential",
            ),
            "rotate",
        );
        let plaintext = ok(
            harness.service.read_secret(inst, &name("db-password")),
            "read",
        );
        assert_eq!(plaintext.expose_secret(), b"top-secret");
        // 审计：名称 + 版本，无值。
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::SecretRead { name: n, version, .. }
                if n.as_str() == "db-password" && version.as_u64() == 1
        )));
    }

    #[test]
    fn read_secret_denied_without_grant_even_if_stored() {
        let harness = harness();
        let inst = installation(1);
        // 存储中存在（管理侧轮换），但安装实例无 grant。
        ok(
            harness.service.rotate(
                inst,
                &name("db-password"),
                &SecretBytes::from_slice(b"value"),
                "d",
            ),
            "rotate",
        );
        let error = err(
            harness.service.read_secret(inst, &name("db-password")),
            "read",
        );
        assert!(matches!(error, SecretError::Denied));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::SecretDenied { name: n, .. } if n.as_str() == "db-password"
        )));
    }

    #[test]
    fn read_secret_denied_when_name_missing_even_if_granted() {
        let harness = harness();
        let inst = installation(1);
        // 已授予但存储中不存在：与 denied 合并（不泄露存在性，secret.wit）。
        harness.grants.set_granted(inst, vec![name("ghost")]);
        let error = err(harness.service.read_secret(inst, &name("ghost")), "read");
        assert!(matches!(error, SecretError::Denied));
        assert!(
            harness
                .audit
                .contains(|event| matches!(event, StatefulAuditEvent::SecretDenied { .. }))
        );
    }

    #[test]
    fn read_secret_corrupt_ciphertext_is_corrupt() {
        let harness = harness();
        let inst = installation(1);
        harness.grants.set_granted(inst, vec![name("db-password")]);
        // 直接经存储 port 写入损坏密文（绕过加密层，模拟存储损坏）。
        ok(
            harness
                .store
                .put(inst, &name("db-password"), vec![0x00, 0x01, 0x02], "d"),
            "store put",
        );
        let error = err(
            harness.service.read_secret(inst, &name("db-password")),
            "read",
        );
        assert!(matches!(error, SecretError::Corrupt));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::SecretFailed { reason, .. } if *reason == "corrupt"
        )));
    }

    #[test]
    fn list_granted_secrets_filters_by_grant_scope() {
        let harness = harness();
        let inst = installation(1);
        harness.grants.set_granted(inst, vec![name("a"), name("b")]);
        for n in ["a", "b", "c"] {
            ok(
                harness
                    .service
                    .rotate(inst, &name(n), &SecretBytes::from_slice(b"v"), "d"),
                "rotate",
            );
        }
        let listed = ok(harness.service.list_granted_secrets(inst), "list");
        let names: Vec<String> = listed
            .iter()
            .map(|metadata| metadata.name().as_str().to_owned())
            .collect();
        // 只返回 grant 集内的名称（grant 之外不可见，不构成存在性查询）。
        assert_eq!(names, vec!["a".to_owned(), "b".to_owned()]);
        assert!(
            harness.audit.contains(|event| matches!(
                event,
                StatefulAuditEvent::SecretListed { names: 2, .. }
            ))
        );
    }

    #[test]
    fn rotate_increments_secret_version_and_read_returns_latest() {
        let harness = harness();
        let inst = installation(1);
        let v1 = ok(
            harness
                .service
                .rotate(inst, &name("api-key"), &SecretBytes::from_slice(b"v1"), "d"),
            "rotate",
        );
        assert_eq!(v1, SecretVersion::from_u64(1));
        let v2 = ok(
            harness
                .service
                .rotate(inst, &name("api-key"), &SecretBytes::from_slice(b"v2"), "d"),
            "rotate",
        );
        assert_eq!(v2, SecretVersion::from_u64(2));
        // 无缓存保证：每次读取返回当前值（轮换后下次读取即新值）。
        harness.grants.set_granted(inst, vec![name("api-key")]);
        let plaintext = ok(harness.service.read_secret(inst, &name("api-key")), "read");
        assert_eq!(plaintext.expose_secret(), b"v2");
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::SecretRotated { version, .. } if version.as_u64() == 2
        )));
    }

    #[test]
    fn delete_secret_removes_and_subsequent_read_is_denied() {
        let harness = harness();
        let inst = installation(1);
        harness.grants.set_granted(inst, vec![name("db-password")]);
        ok(
            harness.service.rotate(
                inst,
                &name("db-password"),
                &SecretBytes::from_slice(b"v"),
                "d",
            ),
            "rotate",
        );
        ok(harness.service.delete(inst, &name("db-password")), "delete");
        // 删除后读取：grant 仍在但名称不存在 → denied（合并语义）。
        assert!(matches!(
            harness.service.read_secret(inst, &name("db-password")),
            Err(SecretError::Denied)
        ));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::SecretDeleted { name: n, .. } if n.as_str() == "db-password"
        )));
    }

    #[test]
    fn audit_and_errors_never_contain_secret_value() {
        let harness = harness();
        let inst = installation(1);
        harness.grants.set_granted(inst, vec![name("db-password")]);
        let secret_value = b"super-secret-db-password-value";
        ok(
            harness.service.rotate(
                inst,
                &name("db-password"),
                &SecretBytes::from_slice(secret_value),
                "d",
            ),
            "rotate",
        );
        let _ = harness.service.read_secret(inst, &name("db-password"));
        // 拒绝路径（未授予的名称）。
        let denied_error = err(harness.service.read_secret(inst, &name("other")), "read");
        // 全部审计事件的序列化与 Debug 不含值（§16.6）。
        for event in harness.audit.events() {
            let json = ok(serde_json::to_string(&event), "serialize audit");
            assert!(
                !json.contains("super-secret-db-password-value"),
                "audit leaked secret value: {json}"
            );
            let debug = format!("{event:?}");
            assert!(
                !debug.contains("super-secret-db-password-value"),
                "audit Debug leaked secret value"
            );
        }
        // 错误 Display/Debug 不含值。
        assert!(!format!("{denied_error}").contains("super-secret-db-password-value"));
        assert!(!format!("{denied_error:?}").contains("super-secret-db-password-value"));
    }
}
