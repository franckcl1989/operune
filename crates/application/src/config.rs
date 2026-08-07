//! 0.3.0 Stateful Runtime（§41.2）——Component config service 用例层
//! （契约 `operune:config@0.1.0` config.wit，已提交稳定）。
//!
//! # 职责
//!
//! - **guest 只读**（config.wit 明文：写侧不在 Component 契约内——Config
//!   是管理员/系统提供的输入，本契约不存在任何 guest 写配置的入口）：
//!   `snapshot`（原子快照：版本 + 值同一次读取内一致）与 `version`
//!   （轻量变化检测，`get-config-version`）；
//! - **管理侧写**：`put` 写入已通过 Component `validator` export 校验的
//!   配置（validation 编排属于 runtime 接线面，本服务不做格式解析——
//!   P6），revision 单调递增由存储保证（单语句 upsert，§41.2）；
//! - 激活门禁（§19.2）保证存在 config 契约的 Component 必须先有已校验
//!   配置才能 active，因此运行时读取必有快照——存储 `None`（尚无已校验
//!   配置）即"未就绪"（config.wit `not-ready`，激活/重校验窗口），
//!   **无 not-found**；
//! - config 无平台级 migration（与 state 的本质区别，config.wit）；
//! - **审计**（§41.2 config audit MUST）：metadata-only（revision、格式、
//!   结果、安装实例；配置值不进入审计）。
//!
//! 错误闭集对齐 WIT `config-error`（not-ready / corrupt / internal）。
//! 敏感值不得放进 config（凭据/密钥属于 operune:secret，§16.6）——本
//! 服务与 [`crate::secret::SecretService`] 分离。

use std::sync::Arc;

use operune_domain::{
    ConfigFormat, ConfigRevision, ConfigSchemaVersion, ConfigSnapshot, ConfigValue, InstallationId,
};

use crate::ports::{
    AuditError, ComponentConfigStorePort, ConfigStoreError, StatefulAuditEvent, StatefulAuditPort,
};

/// component config 用例层错误（对齐 WIT `config-error` 闭集，§6.3）。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// 配置存储未就绪（激活窗口 / 升级重校验窗口；尚无已校验快照）。
    /// guest 应稍后重试。
    #[error("component config not ready (no validated snapshot yet)")]
    NotReady,

    /// 存储的配置快照未通过完整性检查（损坏；需管理员重新提供配置）。
    #[error("component config data corrupt")]
    Corrupt,

    /// 存储失败（WIT internal 面；source 保留可诊断上下文）。
    #[error("component config store failure: {0}")]
    Store(#[source] ConfigStoreError),

    /// 审计失败（§18.7 fail closed）。
    #[error("audit failure (fail closed): {0}")]
    Audit(#[source] AuditError),
}

impl ConfigError {
    /// 审计 reason 标签（kebab-case 静态文本；不含配置值）。
    pub(crate) fn audit_label(&self) -> &'static str {
        match self {
            Self::NotReady => "not-ready",
            Self::Corrupt => "corrupt",
            Self::Store(_) => "store-failure",
            Self::Audit(_) => "audit-failure",
        }
    }
}

/// 存储错误 → 用例错误映射（§14.1 封闭 typed）。
fn map_store_error(error: ConfigStoreError) -> ConfigError {
    match error {
        ConfigStoreError::Corrupt(_) => ConfigError::Corrupt,
        // NotFound（安装不存在）/ InvalidArgument / Storage 保留可诊断
        // source（WIT internal 面）。
        other => ConfigError::Store(other),
    }
}

/// Component config service（guest 只读 + 管理侧写，§41.2）。
pub struct ConfigService {
    store: Arc<dyn ComponentConfigStorePort>,
    audit: Arc<dyn StatefulAuditPort>,
}

impl ConfigService {
    /// 构造（store + audit；§24.2 端口注入）。
    pub fn new(
        store: Arc<dyn ComponentConfigStorePort>,
        audit: Arc<dyn StatefulAuditPort>,
    ) -> Self {
        Self { store, audit }
    }

    /// 读取当前配置快照（WIT `get-config`；原子：版本 + 值来自同一次
    /// 快照）。激活门禁保证必有已校验快照——存储 `None` 即 not-ready
    /// （激活/升级重校验窗口），无 not-found。
    pub fn snapshot(&self, installation: InstallationId) -> Result<ConfigSnapshot, ConfigError> {
        match self.store.snapshot(installation) {
            Ok(Some(snapshot)) => {
                self.audit(StatefulAuditEvent::ConfigRead {
                    installation,
                    revision: snapshot.revision(),
                })?;
                Ok(snapshot)
            }
            Ok(None) => {
                let error = ConfigError::NotReady;
                self.audit_failed(installation, "snapshot", &error)?;
                Err(error)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "snapshot", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 轻量读取当前配置版本（WIT `get-config-version`；side-effect-free
    /// 变化检测——值大时用本调用代替 `get-config` 轮询）。
    pub fn version(&self, installation: InstallationId) -> Result<ConfigRevision, ConfigError> {
        match self.store.snapshot(installation) {
            Ok(Some(snapshot)) => {
                let revision = snapshot.revision();
                self.audit(StatefulAuditEvent::ConfigRead {
                    installation,
                    revision,
                })?;
                Ok(revision)
            }
            Ok(None) => {
                let error = ConfigError::NotReady;
                self.audit_failed(installation, "version", &error)?;
                Err(error)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "version", &mapped)?;
                Err(mapped)
            }
        }
    }

    /// 管理侧写入已校验配置（§41.2：管理员/系统提供；`value` 必须已通过
    /// 激活中 ComponentVersion 的 `validator` export——validation 编排在
    /// runtime 接线面）。revision 单调递增由存储保证；返回**新修订号**。
    pub fn put(
        &self,
        installation: InstallationId,
        format: ConfigFormat,
        schema_version: ConfigSchemaVersion,
        value: &ConfigValue,
    ) -> Result<ConfigRevision, ConfigError> {
        match self.store.put(installation, format, schema_version, value) {
            Ok(revision) => {
                self.audit(StatefulAuditEvent::ConfigWritten {
                    installation,
                    revision,
                    format,
                })?;
                Ok(revision)
            }
            Err(error) => {
                let mapped = map_store_error(error);
                self.audit_failed(installation, "put", &mapped)?;
                Err(mapped)
            }
        }
    }

    fn audit(&self, event: StatefulAuditEvent) -> Result<(), ConfigError> {
        self.audit.append(event).map_err(ConfigError::Audit)
    }

    fn audit_failed(
        &self,
        installation: InstallationId,
        operation: &'static str,
        error: &ConfigError,
    ) -> Result<(), ConfigError> {
        self.audit
            .append(StatefulAuditEvent::ConfigFailed {
                installation,
                operation,
                reason: error.audit_label(),
            })
            .map_err(ConfigError::Audit)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use operune_domain::{ConfigFormat, ConfigRevision, ConfigSchemaVersion, ConfigValue};

    use crate::ports::StatefulAuditEvent;
    use crate::test_support::{FakeConfigStore, FakeStatefulAudit, installation, ok};

    use super::*;

    fn value(bytes: &[u8]) -> ConfigValue {
        ok(ConfigValue::new(bytes.to_vec()), "config value")
    }

    struct Harness {
        service: ConfigService,
        audit: Arc<FakeStatefulAudit>,
    }

    fn harness() -> Harness {
        let store = Arc::new(FakeConfigStore::new());
        let audit = Arc::new(FakeStatefulAudit::new());
        let service = ConfigService::new(store.clone(), audit.clone());
        Harness { service, audit }
    }

    #[test]
    fn snapshot_returns_atomic_revision_and_value() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.service.put(
                inst,
                ConfigFormat::Json,
                ConfigSchemaVersion::from_u32(1),
                &value(b"{\"a\":1}"),
            ),
            "put",
        );
        let snapshot = ok(harness.service.snapshot(inst), "snapshot");
        assert_eq!(snapshot.revision(), ConfigRevision::from_u64(1));
        assert_eq!(snapshot.value().as_slice(), b"{\"a\":1}");
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::ConfigRead { revision, .. } if revision.as_u64() == 1
        )));
    }

    #[test]
    fn snapshot_is_not_ready_without_validated_config() {
        let harness = harness();
        let inst = installation(1);
        // 激活门禁前（尚无已校验配置）→ not-ready（config.wit 无 not-found）。
        assert!(matches!(
            harness.service.snapshot(inst),
            Err(ConfigError::NotReady)
        ));
        assert!(matches!(
            harness.service.version(inst),
            Err(ConfigError::NotReady)
        ));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::ConfigFailed { operation, .. }
                if *operation == "snapshot" || *operation == "version"
        )));
    }

    #[test]
    fn version_returns_current_revision() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.service.put(
                inst,
                ConfigFormat::Raw,
                ConfigSchemaVersion::from_u32(1),
                &value(b"v"),
            ),
            "put",
        );
        let revision = ok(harness.service.version(inst), "version");
        assert_eq!(revision, ConfigRevision::from_u64(1));
    }

    #[test]
    fn put_increments_revision_monotonically() {
        let harness = harness();
        let inst = installation(1);
        let r1 = ok(
            harness.service.put(
                inst,
                ConfigFormat::Raw,
                ConfigSchemaVersion::from_u32(1),
                &value(b"v1"),
            ),
            "put",
        );
        let r2 = ok(
            harness.service.put(
                inst,
                ConfigFormat::Raw,
                ConfigSchemaVersion::from_u32(1),
                &value(b"v2"),
            ),
            "put",
        );
        assert_eq!(r1, ConfigRevision::from_u64(1));
        assert_eq!(r2, ConfigRevision::from_u64(2));
        assert!(harness.audit.contains(|event| matches!(
            event,
            StatefulAuditEvent::ConfigWritten { revision, .. } if revision.as_u64() == 2
        )));
        // 写入即成为当前快照（通过验证后才接受，revision 与值一致）。
        let snapshot = ok(harness.service.snapshot(inst), "snapshot");
        assert_eq!(snapshot.revision(), ConfigRevision::from_u64(2));
        assert_eq!(snapshot.value().as_slice(), b"v2");
    }

    #[test]
    fn config_audit_never_contains_config_bytes() {
        let harness = harness();
        let inst = installation(1);
        ok(
            harness.service.put(
                inst,
                ConfigFormat::Json,
                ConfigSchemaVersion::from_u32(1),
                &value(b"config-payload-that-must-not-audit"),
            ),
            "put",
        );
        let _ = harness.service.snapshot(inst);
        for event in harness.audit.events() {
            let json = ok(serde_json::to_string(&event), "serialize audit");
            assert!(
                !json.contains("config-payload-that-must-not-audit"),
                "config audit leaked payload: {json}"
            );
        }
    }
}
