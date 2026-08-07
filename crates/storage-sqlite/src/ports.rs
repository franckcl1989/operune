//! application port traits 的实现（§24.2：storage-sqlite 是 application 的
//! 持久化适配层）。
//!
//! 本模块实现 [`operune_application::ports`] 的五个 port：
//! [`ComponentRegistryPort`]、[`GrantStorePort`]、[`AuditPort`]、
//! [`ConfigPort`]、[`ProviderGraphPort`]（0.2.0，§40.2 graph
//! persistence/recovery）。全部方法把 application 的用例级类型经 Storage
//! Executor 的 typed 命令持久化（§18.2 / §18.1：SQL 细节不泄漏）。
//!
//! # 同步桥接（§18.2）
//!
//! application 的 port traits 是同步接口；Storage Executor 是 async
//! facade。桥接经 [`StorageExecutor::submit_blocking`]：`blocking_send`
//!（有界背压）+ `blocking_recv`，在调用线程等待通道——SQLite 执行仍全部
//! 在 executor 的专用 worker 线程（§18.2 的约束针对 SQLite blocking 调用，
//! 不针对通道等待）。不引入嵌套 tokio runtime（`Runtime::block_on` 在
//! async 上下文内会 panic，且调用方可能是 axum worker）。
//!
//! # 转换层（§13.3 边界解析一次，不放宽校验）
//!
//! - **grant scope**：application 的 [`GrantScope`]（typed enum）↔ 存储侧的
//!   [`CapabilityScope`]（字符串 newtype）。存储侧 0.1.0 的最小面只有字符串
//!   scope；转换经 serde_json 规范化（构造时序列化、读取时解析），解析
//!   失败 = 存储损坏 fail closed（[`StorageError::CorruptState`]），不静默
//!   跳过、不丢失字段。这是 port 定义与 storage 语义的形状差异，见
//!   模块文档与主 agent 报告。
//! - **审计事件**：application 的 [`AuditEvent`]（rich enum，§16.6 不记
//!   secret）→ 存储侧的 [`crate::model::AuditEvent`]（actor/category/
//!   action/target/outcome/detail 平面形态）。逐变体显式映射（见
//!   [`to_storage_audit`]）：类别闭集对齐、环境变量值不进入任何字段
//!   （application 事件本身已遮蔽，§16.6）。
//! - **安装记录**：application 的 [`InstallationRecord`]（单行语义：
//!   当前版本 + active digest + 上一已知良好 digest）↔ 存储侧规范化模型
//!   （`installations` + `active_version` + `installation_versions` 三表，
//!   §18.3）。组合 / 派生逻辑见 [`StoragePorts::compose_installation`]。
//! - **config 快照**：application 的 [`RuntimeConfig`]（typed 结构，非
//!   Serialize）↔ 存储侧 `runtime_config` 表（key/value 字符串，§18.0）。
//!   本模块以单 key + 显式 JSON 文档承载（键名见 [`RUNTIME_CONFIG_KEY`]；
//!   逐字段解析，缺失 / 非法 = fail closed）。
//! - **graph 记录**（0.2.0，§40.2）：application 的 [`ProviderRecord`] /
//!   [`ConsumerRecord`]（domain typed）直接作为命令载荷（无存储侧中间
//!   模型——记录形状与 port 契约一致）；repository 在 SQL 边界把 interface
//!   集合序列化为 **JSON 规范化数组**（单 TEXT 列；schema.rs 的 `DDL_V3`
//!   文档记录设计理由：记录 = 不可变字节事实、单行即整条记录、domain
//!   `Serialize` 即规范形态），读取解析失败一律
//!   [`StorageError::CorruptState`] fail closed（与 grant scope 的 JSON
//!   规范化同模式）。
//!
//! # 0.3.0 state/config/secret 端口接线（§41.2）
//!
//! 本 crate 的 executor 层提供 0.3.0 Stateful Runtime 的**存储能力**
//!（migration v4 三表 + typed 命令，见 executor.rs 模块文档）：state 事务
//!（begin/put/delete/commit/abort，跨命令边界、取消/crash → 回滚、schema
//! 版本确定性）、component config（revision 单调）、secret 密文 BLOB
//!（不透明，§16.6 / ADR-0001）。本模块实现 application 的五个 0.3 port
//! trait（[`StateStorePort`] / [`ComponentConfigStorePort`] / [`SecretStorePort`]
//! / [`SecretGrantPort`] / [`StatefulAuditPort`]），与既有 port 同模式：
//! `submit_blocking` 同步桥接 + §13.3 转换层（边界解析一次，不放宽校验）。
//!
//! 接线要点（与 application/tests/stateful_e2e.rs 验证的模式一致）：
//! - **事务句柄映射**：domain [`StateTransactionId`] ↔ 存储侧
//!   [`StateTransactionHandle`]（构造器 `pub(crate)`，本层在 begin 时建立
//!   `id → handle` 映射；executor 单连接串行 ⇒ 映射一致，无并发交错）；
//! - **类型转换**：storage 自有 newtype（[`crate::model::StateKey`] /
//!   [`crate::model::SecretName`]）与 domain 类型字符集一致，转换失败 =
//!   契约违反 fail closed；`ConfigSchemaVersion` 与存储侧
//!   [`crate::model::StateSchemaVersion`] 同为 u32 形态，一一对应；
//! - **返回值读回**：config put 后读回 revision、secret put 后读回版本
//!   （单语句 upsert 的单调性由存储保证，串行 executor 下 put 后读一致；
//!   读回缺失 = 不变量违反 fail closed）；
//! - **secret grant**：从 grants 表按 `operune:secret/secret` 能力面筛选，
//!   名称范围经 scope 承载（JSON 规范化名称集，§13.3 同模式）；
//! - **audit**：0.3 事件映射为 component-lifecycle 审计行，metadata-only
//!   （值绝不进入审计，§16.6/§41.2）。

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use operune_application::model::{
    CandidateRecord, DigestVersionBinding, GrantScope, InstallationGrant, InstallationRecord,
    RuntimeConfig,
};
use operune_application::ports::{
    AuditError, AuditEvent, AuditPort, ComponentConfigStorePort, ComponentRegistryPort,
    ConfigError, ConfigPort, ConfigStoreError, GrantError, GrantStorePort, GraphRecords,
    GraphStoreError, ProviderGraphPort, RegistryError, SecretCiphertextRecord, SecretGrantPort,
    SecretStoreError, SecretStorePort, StateStoreError, StateStorePort, StatefulAuditEvent,
    StatefulAuditPort, UninstallStorePort,
};
use operune_domain::{
    ByteSize, ComponentId, ComponentLifecycleState, ComponentVersion, ConfigFormat, ConfigRevision,
    ConfigSchemaVersion, ConfigSnapshot, ConfigValue, ConsumerRecord, ContentDigest,
    InstallationId, ProviderRecord, SecretMetadata, SecretName, SecretVersion, StateKey,
    StateSchemaVersion, StateTransactionId, StateValue,
};
use operune_runtime_wasm::{
    BackgroundTaskLimit, CallDeadline, HostBufferLimit, HttpBodyLimit, InstanceCountLimit,
    LinearMemoryLimit, MaxConcurrent, MaxQueued, MemoryCountLimit, ResourceBudget, TableCountLimit,
    TableElementLimit,
};

use crate::error::StorageError;
use crate::executor::{Command, Response, StorageExecutor};
use crate::model::{
    ActiveBinding, AuditActor, AuditCategory, AuditOutcome, CapabilityScope, ComponentConfigRecord,
    ConfigFormat as StorageConfigFormat, InstallationVersionRecord,
    SecretName as StorageSecretName, SecretRecord, StateKey as StorageStateKey,
    StateSchemaVersion as StorageStateSchemaVersion, StateTransactionHandle, StateValueRecord,
    VersionState,
};

/// RuntimeConfig 快照在 `runtime_config` 表中的 key（§18.0：单键 + 显式
/// JSON 文档；BootstrapConfig 不进本表）。
const RUNTIME_CONFIG_KEY: &str = "runtime-config";

/// application port 适配层（全部 port trait 的单一实现类型）。
///
/// 构造：`StorageExecutor` 必须已打开（fail closed 语义见其 `open`）；
/// `artifact_hard_limit` 是制品字节写入的存储侧硬上限（§19.1；通常取
/// [`crate::ExecutorConfig::artifact_hard_limit`]）。
pub struct StoragePorts {
    executor: Arc<StorageExecutor>,
    artifact_hard_limit: ByteSize,
    /// §41.2 事务句柄映射：domain [`StateTransactionId`] → 存储侧
    /// [`StateTransactionHandle`]。存储句柄构造器 `pub(crate)`（executor 内
    /// 管理），接线层在 begin 时建立映射、commit/abort 时移除；executor
    /// 单连接串行（§18.2）⇒ 同一时刻至多一个进行中事务，映射一致、无
    /// 并发交错（模式见 application/tests/stateful_e2e.rs）。
    tx_map: Mutex<HashMap<StateTransactionId, StateTransactionHandle>>,
    /// domain 事务身份的单调分配器（Core 侧事务标识，§41.2；与 executor
    /// 内部句柄计数独立）。
    next_tx: Mutex<u64>,
}

impl StoragePorts {
    /// 构造（executor 与硬上限由 composition root 注入，§24.2 端口注入）。
    pub fn new(executor: Arc<StorageExecutor>, artifact_hard_limit: ByteSize) -> Self {
        Self {
            executor,
            artifact_hard_limit,
            tx_map: Mutex::new(HashMap::new()),
            next_tx: Mutex::new(0),
        }
    }

    /// 同步提交（见模块文档的同步桥接说明）。
    fn submit(&self, cmd: Command) -> Result<Response, StorageError> {
        self.executor.submit_blocking(cmd)
    }

    // ------------------------------------------------------------------
    // §41.2 事务句柄映射（StateTransactionId → StateTransactionHandle；
    // 见模块文档与 stateful_e2e.rs 验证模式）
    // ------------------------------------------------------------------

    /// begin 时建立映射并分配 domain 事务身份（Core 侧事务标识，§41.2）。
    fn remember_tx(&self, handle: StateTransactionHandle) -> StateTransactionId {
        let mut counter = self
            .next_tx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *counter = counter.saturating_add(1);
        let id = StateTransactionId::from_u64(*counter);
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(id, handle);
        id
    }

    /// 取出并移除事务句柄（commit 用；对已终止事务 → TransactionConflict，
    /// WIT conflict）。
    fn take_tx(&self, tx: StateTransactionId) -> Result<StateTransactionHandle, StateStoreError> {
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&tx)
            .ok_or_else(|| {
                StateStoreError::TransactionConflict(
                    "operation on a state transaction that is not in progress".into(),
                )
            })
    }

    /// 引用事务句柄（事务内操作用；对已终止事务 → TransactionConflict）。
    fn handle_of(&self, tx: StateTransactionId) -> Result<StateTransactionHandle, StateStoreError> {
        self.tx_map
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&tx)
            .copied()
            .ok_or_else(|| {
                StateStoreError::TransactionConflict(
                    "operation on a state transaction that is not in progress".into(),
                )
            })
    }

    // ------------------------------------------------------------------
    // 错误映射（§14.1：封闭 typed 错误；storage 错误 → port 错误）
    // ------------------------------------------------------------------

    fn registry_error(error: StorageError) -> RegistryError {
        match error {
            // §19.4 供应链/发布冲突（typed 变体，调用方精确匹配）。
            StorageError::DigestConflict {
                component,
                version,
                existing,
                incoming,
            } => RegistryError::VersionBindingConflict {
                component_id: component,
                version,
                existing,
                incoming,
            },
            // 其余（NotFound / 队列 / IO / SQLite / 损坏）装箱为可诊断 source。
            other => RegistryError::Storage(Box::new(other)),
        }
    }

    fn grant_error(error: StorageError, installation: InstallationId) -> GrantError {
        match error {
            StorageError::NotFound(_) => GrantError::NotFound(installation),
            other => GrantError::Storage(Box::new(other)),
        }
    }

    fn audit_error(error: StorageError) -> AuditError {
        AuditError::Storage(Box::new(error))
    }

    fn config_error(error: StorageError) -> ConfigError {
        ConfigError::Storage(Box::new(error))
    }

    /// state 存储错误映射（§14.1：typed 变体精确匹配，其余装箱为可诊断
    /// source；与 application/tests/stateful_e2e.rs 的映射一致）。
    fn state_error(error: StorageError) -> StateStoreError {
        match error {
            StorageError::NotFound(message) => StateStoreError::NotFound(message),
            StorageError::SchemaVersionMismatch {
                installation,
                expected,
                requested,
            } => StateStoreError::SchemaVersionMismatch {
                installation,
                // 存储侧空 store 不产生本错误（首次写入建立版本，§41.3）——
                // 因此此处恒有当前版本，`None` 分支由存储层保证不可达。
                current: Some(StateSchemaVersion::from_u32(expected.as_u32())),
                requested: StateSchemaVersion::from_u32(requested.as_u32()),
            },
            StorageError::StateTransactionConflict(message) => {
                StateStoreError::TransactionConflict(message)
            }
            StorageError::InvalidArgument(message) => StateStoreError::InvalidArgument(message),
            StorageError::CorruptState(message) => StateStoreError::Corrupt(message),
            other => StateStoreError::Storage(Box::new(other)),
        }
    }

    fn secret_error(error: StorageError) -> SecretStoreError {
        match error {
            StorageError::NotFound(message) => SecretStoreError::NotFound(message),
            StorageError::InvalidArgument(message) => SecretStoreError::InvalidArgument(message),
            StorageError::CorruptState(message) => SecretStoreError::Corrupt(message),
            other => SecretStoreError::Storage(Box::new(other)),
        }
    }

    fn component_config_error(error: StorageError) -> ConfigStoreError {
        match error {
            StorageError::NotFound(message) => ConfigStoreError::NotFound(message),
            StorageError::InvalidArgument(message) => ConfigStoreError::InvalidArgument(message),
            StorageError::CorruptState(message) => ConfigStoreError::Corrupt(message),
            other => ConfigStoreError::Storage(Box::new(other)),
        }
    }

    // ------------------------------------------------------------------
    // 存储侧内部 audit 事件（本适配层自身变更的审计轨迹，§18.7）
    // ------------------------------------------------------------------

    fn internal_audit(
        category: AuditCategory,
        action: &'static str,
        target: Option<String>,
        outcome: AuditOutcome,
        detail: Option<String>,
    ) -> Result<crate::model::AuditEvent, StorageError> {
        crate::model::AuditEvent::new(
            AuditActor::System,
            category,
            action,
            target,
            outcome,
            detail,
        )
    }

    // ------------------------------------------------------------------
    // 安装记录组合（§18.3 三表模型 → application 单行记录）
    // ------------------------------------------------------------------

    /// 把存储侧三表模型组合为 application 的安装记录（§13.3 边界解析一次）。
    ///
    /// - `version` / `active_digest`：来自 `active_version`（唯一 active 事实，
    ///   §18.5）；未激活（fresh Validated）时取唯一 `candidate` 状态绑定
    ///   的版本（激活前版本绑定由 [`StoragePorts::insert_installation`] 补做，
    ///   见其文档）；
    /// - `last_known_good_digest`：上一已知良好 = 最近一个非 active 的
    ///   `installed` / `rolled_back` 绑定（§18.7 rollback retention 事实源）；
    ///   无则 = active 自身（全新安装语义，§20）；
    /// - `state`：`installations.lifecycle_state`（§12.2）。
    fn compose_installation(
        &self,
        record: &crate::model::InstallationRecord,
    ) -> Result<InstallationRecord, StorageError> {
        let installation_id = record.installation_id;
        let active = match self.submit(Command::GetActiveBinding { installation_id })? {
            Response::ActiveBinding(binding) => binding,
            _ => return Err(unexpected("GetActiveBinding")),
        };
        let versions = match self.submit(Command::ListInstallationVersions { installation_id })? {
            Response::InstallationVersions(versions) => versions,
            _ => return Err(unexpected("ListInstallationVersions")),
        };
        let (version, active_digest) = match &active {
            Some(binding) => (binding.component_version, Some(binding.content_digest)),
            None => {
                // 未激活：唯一候选绑定承载版本（insert_installation 补绑定）。
                let candidate = versions
                    .iter()
                    .filter(|version| version.state == VersionState::Candidate)
                    .max_by_key(|version| version.component_version)
                    .ok_or_else(|| {
                        StorageError::CorruptState(format!(
                            "installation {installation_id} has no bound version"
                        ))
                    })?;
                (candidate.component_version, None)
            }
        };
        let last_known_good = Self::derive_last_known_good(active.as_ref(), &versions);
        Ok(InstallationRecord {
            installation_id,
            component_id: record.component_id.clone(),
            version,
            active_digest,
            last_known_good_digest: last_known_good,
            state: record.lifecycle_state,
        })
    }

    /// 上一已知良好 digest 的派生（§18.7 rollback retention / §20）。
    fn derive_last_known_good(
        active: Option<&ActiveBinding>,
        versions: &[InstallationVersionRecord],
    ) -> Option<ContentDigest> {
        // 最近一个非 active 的 installed / rolled_back 绑定（回滚后旧 active
        // 为 rolled_back，仍是 retention 目标，§18.7）。
        let non_active = versions
            .iter()
            .filter(|version| {
                matches!(
                    version.state,
                    VersionState::Installed | VersionState::RolledBack
                )
            })
            .filter(|version| {
                active
                    .map(|binding| binding.content_digest != version.content_digest)
                    .unwrap_or(true)
            })
            .max_by_key(|version| version.created_at);
        match non_active {
            Some(version) => Some(version.content_digest),
            None => active.map(|binding| binding.content_digest),
        }
    }

    /// 安装实例的领域生命周期推进（§12.2）：按 domain 状态机的规范事件
    /// 序列小步推进到目标状态；非法转换跳过（该路径不适用），到达目标
    /// 即停止。目标与当前状态一致 = no-op；无法推进到目标 = LifecycleConflict
    /// fail closed。
    fn advance_lifecycle_to(
        &self,
        installation_id: InstallationId,
        target: ComponentLifecycleState,
    ) -> Result<(), StorageError> {
        let current: ComponentLifecycleState =
            match self.submit(Command::GetInstallation { installation_id })? {
                Response::Installation(Some(record)) => record.lifecycle_state,
                Response::Installation(None) => {
                    return Err(StorageError::NotFound(format!(
                        "installation {installation_id}"
                    )));
                }
                _ => return Err(unexpected("GetInstallation")),
            };
        if current == target {
            return Ok(());
        }
        let mut state = current;
        for event in [
            operune_domain::ComponentLifecycleEvent::ValidationSucceeded,
            operune_domain::ComponentLifecycleEvent::ActivationRequested,
            operune_domain::ComponentLifecycleEvent::ReadinessSucceeded,
        ] {
            if state == target {
                break;
            }
            if let Ok(next) = state.transition(event) {
                // 转换合法性已由 domain 预检（§12.2）；executor 内的
                // 同转换确定性产生同一状态（单一事实源），以其响应
                // 确认落盘后采用预检结果推进。
                let audit = Self::internal_audit(
                    AuditCategory::ComponentLifecycle,
                    "lifecycle",
                    Some(installation_id.to_string()),
                    AuditOutcome::Success,
                    Some(format!("advance to {target}")),
                )?;
                match self.submit(Command::ApplyLifecycleEvent {
                    installation_id,
                    event,
                    audit,
                })? {
                    Response::LifecycleAdvanced(_) => {}
                    _ => return Err(unexpected("ApplyLifecycleEvent")),
                }
                state = next;
            }
            // 该事件在当前状态下不适用：跳过（确定性小步搜索，非静默
            // 忽略失败——转换合法性由 domain 判定，§12.2）。
        }
        if state != target {
            return Err(StorageError::LifecycleConflict(format!(
                "cannot advance installation {installation_id} from {current} to {target}"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ComponentRegistryPort（§18.3 / §19.2 / §19.4 / §6.7）
// ---------------------------------------------------------------------------

impl ComponentRegistryPort for StoragePorts {
    fn persist_artifact(&self, digest: ContentDigest, bytes: &[u8]) -> Result<(), RegistryError> {
        // §6.7：digest 是不可变字节事实——调用方声明的 digest 必须与字节
        // 内容一致（边界校验一次，fail closed；不放宽校验）。
        if digest != ContentDigest::from_bytes(bytes) {
            return Err(RegistryError::Storage(Box::new(
                StorageError::InvalidArgument(
                    "digest does not match the artifact bytes (content-addressing contract)".into(),
                ),
            )));
        }
        let staged = match self.submit(Command::StageBytes {
            bytes: bytes.to_vec(),
            hard_limit: self.artifact_hard_limit,
        }) {
            Ok(Response::Staged(staged)) => staged,
            Ok(_) => return Err(RegistryError::Storage(Box::new(unexpected("StageBytes")))),
            Err(error) => return Err(Self::registry_error(error)),
        };
        // §19.2 字节事实阶段完成：staging → quarantine（原子 rename + DB 事务；
        // 重复 digest 幂等，§18.7）。
        let audit = match Self::internal_audit(
            AuditCategory::Artifact,
            "persist-artifact",
            Some(staged.digest.to_string()),
            AuditOutcome::Success,
            None,
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::registry_error(error)),
        };
        match self.submit(Command::RecordQuarantine { staged, audit }) {
            Ok(Response::Quarantined) => Ok(()),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "RecordQuarantine",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn artifact_bytes(&self, digest: ContentDigest) -> Result<Option<Vec<u8>>, RegistryError> {
        match self.submit(Command::ReadArtifactBytes { digest }) {
            Ok(Response::ArtifactBytes(bytes)) => Ok(bytes),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "ReadArtifactBytes",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn upsert_candidate(&self, record: &CandidateRecord) -> Result<(), RegistryError> {
        let audit = match Self::internal_audit(
            AuditCategory::Artifact,
            "upsert-candidate",
            Some(record.digest.to_string()),
            AuditOutcome::Success,
            Some(format!("lifecycle {}", record.state)),
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::registry_error(error)),
        };
        match self.submit(Command::UpsertCandidate {
            record: record.clone(),
            audit,
        }) {
            Ok(Response::CandidateUpserted) => Ok(()),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "UpsertCandidate",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn update_candidate_state(
        &self,
        digest: ContentDigest,
        state: ComponentLifecycleState,
    ) -> Result<(), RegistryError> {
        let audit = match Self::internal_audit(
            AuditCategory::ComponentLifecycle,
            "candidate-state",
            Some(digest.to_string()),
            AuditOutcome::Success,
            Some(state.to_string()),
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::registry_error(error)),
        };
        match self.submit(Command::UpdateCandidateState {
            digest,
            state,
            audit,
        }) {
            Ok(Response::CandidateStateUpdated) => Ok(()),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "UpdateCandidateState",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn candidate(&self, digest: ContentDigest) -> Result<Option<CandidateRecord>, RegistryError> {
        match self.submit(Command::GetCandidate { digest }) {
            Ok(Response::Candidate(record)) => Ok(record),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected("GetCandidate")))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn resolve_version(
        &self,
        component_id: &ComponentId,
        version: ComponentVersion,
    ) -> Result<Option<DigestVersionBinding>, RegistryError> {
        match self.submit(Command::ResolveVersion {
            component_id: component_id.clone(),
            version,
        }) {
            Ok(Response::VersionBinding(binding)) => Ok(binding),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "ResolveVersion",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn bind_version(&self, binding: &DigestVersionBinding) -> Result<(), RegistryError> {
        // §19.4 幂等重入（管线 crash 后重新进入）：既有绑定同一 digest →
        // no-op；不同 digest → 显式冲突。存储侧的 commit_candidate 是
        // quarantine → candidate 的一次性推进（§19.2 应用身份阶段），而
        // component_versions 绑定与其在**同一事务**提交（§18.5）——既有
        // 绑定存在 ⟹ 该推进已完整生效，重入跳过正确（单 worker 串行，
        // 读-判-写无交错）。
        if let Some(existing) = self.resolve_version(&binding.component_id, binding.version)? {
            if existing.digest == binding.digest {
                return Ok(());
            }
            return Err(RegistryError::VersionBindingConflict {
                component_id: binding.component_id.clone(),
                version: binding.version,
                existing: existing.digest,
                incoming: binding.digest,
            });
        }
        let audit = match Self::internal_audit(
            AuditCategory::ComponentLifecycle,
            "bind-version",
            Some(binding.digest.to_string()),
            AuditOutcome::Success,
            Some(format!("{} {}", binding.component_id, binding.version)),
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::registry_error(error)),
        };
        // storage 侧对应：commit_candidate（注册表绑定 + quarantine → final，
        // §19.2 应用身份阶段；§19.4 同版本不同 digest 显式阻断）。
        match self.submit(Command::CommitCandidate {
            digest: binding.digest,
            component_id: binding.component_id.clone(),
            version: binding.version,
            audit,
        }) {
            Ok(Response::CandidateCommitted) => Ok(()),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "CommitCandidate",
            )))),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn insert_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        // §19.4：以用例层生成的 InstallationId 持久化（create_installation_with_id）。
        let audit = match Self::internal_audit(
            AuditCategory::ComponentLifecycle,
            "create-installation",
            Some(record.installation_id.to_string()),
            AuditOutcome::Success,
            Some(record.component_id.to_string()),
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::registry_error(error)),
        };
        match self.submit(Command::CreateInstallationWithId {
            installation_id: record.installation_id,
            component_id: record.component_id.clone(),
            audit,
        }) {
            Ok(Response::InstallationCreatedWithId) => {}
            Ok(_) => {
                return Err(RegistryError::Storage(Box::new(unexpected(
                    "CreateInstallationWithId",
                ))));
            }
            Err(error) => return Err(Self::registry_error(error)),
        }
        // §18.3：绑定"当前版本"到安装（application 记录无 digest，经全局
        // 绑定反查——管线在 insert 前已 bind_version，§19.2 顺序）。这使
        // 未激活安装的版本在列表/读取中可回读。
        let version_binding = self.resolve_version(&record.component_id, record.version)?;
        if let Some(binding) = version_binding {
            let audit = match Self::internal_audit(
                AuditCategory::ComponentLifecycle,
                "bind-installation-version",
                Some(record.installation_id.to_string()),
                AuditOutcome::Success,
                Some(format!("{} {}", record.component_id, record.version)),
            ) {
                Ok(audit) => audit,
                Err(error) => return Err(Self::registry_error(error)),
            };
            match self.submit(Command::BindInstallationVersionOnce {
                installation_id: record.installation_id,
                component_id: record.component_id.clone(),
                version: record.version,
                digest: binding.digest,
                audit,
            }) {
                Ok(Response::VersionBoundOnce) => {}
                Ok(_) => {
                    return Err(RegistryError::Storage(Box::new(unexpected(
                        "BindInstallationVersionOnce",
                    ))));
                }
                Err(error) => return Err(Self::registry_error(error)),
            }
        }
        // §12.2：应用身份阶段完成 → Validated（create 初始为 Installed）。
        if record.state == ComponentLifecycleState::Validated {
            match self
                .advance_lifecycle_to(record.installation_id, ComponentLifecycleState::Validated)
            {
                Ok(()) => {}
                Err(error) => return Err(Self::registry_error(error)),
            }
        }
        Ok(())
    }

    fn update_installation(&self, record: &InstallationRecord) -> Result<(), RegistryError> {
        // §19.2 末步 / §20：激活语义——绑定版本（幂等）+ 唯一 active 切换
        //（§18.5 两阶段协议）+ 生命周期推进。active_digest 为 None 时不
        // 触碰 active 绑定（仅状态更新场景）。
        if let Some(digest) = record.active_digest {
            let audit = match Self::internal_audit(
                AuditCategory::ComponentLifecycle,
                "bind-installation-version",
                Some(record.installation_id.to_string()),
                AuditOutcome::Success,
                Some(format!("{} {}", record.component_id, record.version)),
            ) {
                Ok(audit) => audit,
                Err(error) => return Err(Self::registry_error(error)),
            };
            match self.submit(Command::BindInstallationVersionOnce {
                installation_id: record.installation_id,
                component_id: record.component_id.clone(),
                version: record.version,
                digest,
                audit,
            }) {
                Ok(Response::VersionBoundOnce) => {}
                Ok(_) => {
                    return Err(RegistryError::Storage(Box::new(unexpected(
                        "BindInstallationVersionOnce",
                    ))));
                }
                Err(error) => return Err(Self::registry_error(error)),
            }
            let audit = match Self::internal_audit(
                AuditCategory::ComponentLifecycle,
                "activate-version",
                Some(record.installation_id.to_string()),
                AuditOutcome::Success,
                Some(format!("{} {}", record.version, digest)),
            ) {
                Ok(audit) => audit,
                Err(error) => return Err(Self::registry_error(error)),
            };
            match self.submit(Command::SwitchActiveVersion {
                installation_id: record.installation_id,
                version: record.version,
                digest,
                audit,
            }) {
                Ok(Response::VersionSwitched(_)) => {}
                Ok(_) => {
                    return Err(RegistryError::Storage(Box::new(unexpected(
                        "SwitchActiveVersion",
                    ))));
                }
                Err(error) => return Err(Self::registry_error(error)),
            }
        }
        // 生命周期推进到记录声明的状态（Active：Activating → Active；
        // 升级时已是 Active = no-op）。
        match self.advance_lifecycle_to(record.installation_id, record.state) {
            Ok(()) => Ok(()),
            Err(error) => Err(Self::registry_error(error)),
        }
    }

    fn installation(
        &self,
        id: InstallationId,
    ) -> Result<Option<InstallationRecord>, RegistryError> {
        let record = match self.submit(Command::GetInstallation {
            installation_id: id,
        }) {
            Ok(Response::Installation(record)) => record,
            Ok(_) => {
                return Err(RegistryError::Storage(Box::new(unexpected(
                    "GetInstallation",
                ))));
            }
            Err(error) => return Err(Self::registry_error(error)),
        };
        match record {
            Some(record) => {
                let composed = match self.compose_installation(&record) {
                    Ok(composed) => composed,
                    Err(error) => return Err(Self::registry_error(error)),
                };
                Ok(Some(composed))
            }
            None => Ok(None),
        }
    }

    fn list_installations(&self) -> Result<Vec<InstallationRecord>, RegistryError> {
        let records = match self.submit(Command::ListInstallations) {
            Ok(Response::Installations(records)) => records,
            Ok(_) => {
                return Err(RegistryError::Storage(Box::new(unexpected(
                    "ListInstallations",
                ))));
            }
            Err(error) => return Err(Self::registry_error(error)),
        };
        let mut composed = Vec::with_capacity(records.len());
        for record in records {
            match self.compose_installation(&record) {
                Ok(record) => composed.push(record),
                Err(error) => return Err(Self::registry_error(error)),
            }
        }
        Ok(composed)
    }
}

// ---------------------------------------------------------------------------
// UninstallStorePort（§39.2 remove / §42.4：卸载后 UI + backend 完整消失）
// ---------------------------------------------------------------------------

impl UninstallStorePort for StoragePorts {
    fn remove_installation(
        &self,
        installation: InstallationId,
        audit: AuditEvent,
    ) -> Result<(), RegistryError> {
        // §18.7 fail closed：audit 事件映射失败即中止（不提交删除）。
        let storage_audit = match to_storage_audit(&audit) {
            Ok(event) => event,
            Err(error) => {
                let message = match error {
                    AuditError::Storage(source) => {
                        format!("audit event mapping failed: {source}")
                    }
                };
                return Err(Self::registry_error(StorageError::InvalidArgument(message)));
            }
        };
        match self.submit(Command::RemoveInstallation {
            installation_id: installation,
            audit: storage_audit,
        }) {
            Ok(Response::Removed) => Ok(()),
            Ok(_) => Err(RegistryError::Storage(Box::new(unexpected(
                "RemoveInstallation",
            )))),
            // §39.2 remove 契约：安装不存在 → [`RegistryError::NotFound`]
            //（与 grant_error 的 NotFound 映射同模式——其余错误装箱为
            // 可诊断 source）。
            Err(StorageError::NotFound(_)) => Err(RegistryError::NotFound("installation")),
            Err(error) => Err(Self::registry_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// GrantStorePort（§17.1 / §17.5：grant 的 durable owner 是 InstallationId）
// ---------------------------------------------------------------------------

impl GrantStorePort for StoragePorts {
    fn grants_for(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<InstallationGrant>, GrantError> {
        let records = match self.submit(Command::ListGrants {
            installation_id: installation,
        }) {
            Ok(Response::Grants(records)) => records,
            Ok(_) => return Err(GrantError::Storage(Box::new(unexpected("ListGrants")))),
            Err(error) => return Err(Self::grant_error(error, installation)),
        };
        let mut grants = Vec::with_capacity(records.len());
        for record in records {
            let scope = match scope_from_storage(&record.scope) {
                Ok(scope) => scope,
                Err(error) => return Err(Self::grant_error(error, installation)),
            };
            grants.push(InstallationGrant {
                capability: record.capability_id,
                scope,
            });
        }
        Ok(grants)
    }

    fn replace_grants(
        &self,
        installation: InstallationId,
        grants: &[InstallationGrant],
    ) -> Result<(), GrantError> {
        // §17.5 整体替换（原子，见 repository::replace_grants）。
        let mut storage_grants = Vec::with_capacity(grants.len());
        for grant in grants {
            let scope = match scope_to_storage(&grant.scope) {
                Ok(scope) => scope,
                Err(error) => return Err(Self::grant_error(error, installation)),
            };
            storage_grants.push((grant.capability.clone(), scope));
        }
        let audit = match Self::internal_audit(
            AuditCategory::Grant,
            "replace-grants",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{} grants", storage_grants.len())),
        ) {
            Ok(audit) => audit,
            Err(error) => return Err(Self::grant_error(error, installation)),
        };
        match self.submit(Command::ReplaceGrants {
            installation_id: installation,
            grants: storage_grants,
            audit,
        }) {
            Ok(Response::GrantsReplaced) => Ok(()),
            Ok(_) => Err(GrantError::Storage(Box::new(unexpected("ReplaceGrants")))),
            Err(error) => Err(Self::grant_error(error, installation)),
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderGraphPort（§40.2 graph persistence/recovery；§18.6：0.2 graph
// 是节点本地权威状态——记录与其余 Core 元数据同库同事务语义）
// ---------------------------------------------------------------------------

impl ProviderGraphPort for StoragePorts {
    fn replace_records(
        &self,
        installation: InstallationId,
        provider: Option<&ProviderRecord>,
        consumer: Option<&ConsumerRecord>,
    ) -> Result<(), GraphStoreError> {
        // 单次原子替换边界（§40.2）：provider/consumer 均为 None = 全删；
        // 原子性与损坏 fail-closed 语义在 repository（单事务）承担。
        match self.submit(Command::ReplaceGraphRecords {
            installation_id: installation,
            provider: provider.cloned(),
            consumer: consumer.cloned(),
        }) {
            Ok(Response::GraphRecordsReplaced) => Ok(()),
            Ok(_) => Err(graph_error(unexpected("ReplaceGraphRecords"))),
            Err(error) => Err(graph_error(error)),
        }
    }

    fn load_records(&self) -> Result<GraphRecords, GraphStoreError> {
        match self.submit(Command::LoadGraphRecords) {
            Ok(Response::GraphRecords(records)) => Ok(records),
            Ok(_) => Err(graph_error(unexpected("LoadGraphRecords"))),
            Err(error) => Err(graph_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// AuditPort（§16.6 / §18.7：durable audit，写入失败 fail closed）
// ---------------------------------------------------------------------------

impl AuditPort for StoragePorts {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        let storage_event = to_storage_audit(&event)?;
        match self.submit(Command::AppendAudit {
            audit: storage_event,
        }) {
            Ok(Response::AuditAppended(_)) => Ok(()),
            Ok(_) => Err(AuditError::Storage(Box::new(unexpected("AppendAudit")))),
            Err(error) => Err(Self::audit_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// ConfigPort（§18.0 RuntimeConfig 语义：快照读取）
// ---------------------------------------------------------------------------

impl ConfigPort for StoragePorts {
    fn snapshot(&self) -> Result<RuntimeConfig, ConfigError> {
        let entry = match self.submit(Command::GetConfig {
            key: RUNTIME_CONFIG_KEY.to_owned(),
        }) {
            Ok(Response::Config(entry)) => entry,
            Ok(_) => return Err(ConfigError::Storage(Box::new(unexpected("GetConfig")))),
            Err(error) => return Err(Self::config_error(error)),
        };
        let value = match entry {
            Some(entry) => entry.value,
            None => {
                return Err(Self::config_error(StorageError::NotFound(
                    "runtime config is not initialized".into(),
                )));
            }
        };
        let parsed: serde_json::Value = match serde_json::from_str(&value) {
            Ok(parsed) => parsed,
            Err(error) => {
                return Err(Self::config_error(StorageError::CorruptState(format!(
                    "runtime config is not valid JSON: {error}"
                ))));
            }
        };
        runtime_config_from_json(&parsed)
    }
}

// ---------------------------------------------------------------------------
// StateStorePort（§41.2：state 是 Component 产生的权威持久业务状态；
// CAS 的 get→compare→put 编排在 application 的 StateService，本 port 只
// 承载存储面。executor 单连接串行 ⇒ 服务侧读-判-写无交错）
// ---------------------------------------------------------------------------

impl StateStorePort for StoragePorts {
    fn get(
        &self,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::GetState {
            installation_id: installation,
            key: storage_key,
            tx: None,
        }) {
            Ok(Response::StateValue(record)) => record.map(to_domain_state_value).transpose(),
            Ok(_) => Err(Self::state_error(unexpected("GetState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn put(
        &self,
        installation: InstallationId,
        key: &StateKey,
        schema_version: StateSchemaVersion,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::PutState {
            installation_id: installation,
            key: storage_key,
            schema_version: Some(to_storage_schema_version(schema_version)),
            value: value.as_slice().to_vec(),
            tx: None,
        }) {
            Ok(Response::StatePut) => Ok(()),
            Ok(_) => Err(Self::state_error(unexpected("PutState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn delete(&self, installation: InstallationId, key: &StateKey) -> Result<(), StateStoreError> {
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::DeleteState {
            installation_id: installation,
            key: storage_key,
            tx: None,
        }) {
            Ok(Response::StateDeleted) => Ok(()),
            Ok(_) => Err(Self::state_error(unexpected("DeleteState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn schema_version(
        &self,
        installation: InstallationId,
    ) -> Result<Option<StateSchemaVersion>, StateStoreError> {
        match self.submit(Command::GetStateSchemaVersion {
            installation_id: installation,
        }) {
            Ok(Response::StateSchemaVersion(version)) => {
                Ok(version.map(|version| StateSchemaVersion::from_u32(version.as_u32())))
            }
            Ok(_) => Err(Self::state_error(unexpected("GetStateSchemaVersion"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn begin_transaction(
        &self,
        installation: InstallationId,
        schema_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let handle = match self.submit(Command::BeginStateTransaction {
            installation_id: installation,
            schema_version: to_storage_schema_version(schema_version),
            mode: crate::executor::StateTxMode::Normal,
        }) {
            Ok(Response::StateTransactionBegan(handle)) => handle,
            Ok(_) => return Err(Self::state_error(unexpected("BeginStateTransaction"))),
            Err(error) => return Err(Self::state_error(error)),
        };
        Ok(self.remember_tx(handle))
    }

    fn begin_migration_transaction(
        &self,
        installation: InstallationId,
        to_version: StateSchemaVersion,
    ) -> Result<StateTransactionId, StateStoreError> {
        let handle = match self.submit(Command::BeginStateTransaction {
            installation_id: installation,
            schema_version: to_storage_schema_version(to_version),
            mode: crate::executor::StateTxMode::Migration,
        }) {
            Ok(Response::StateTransactionBegan(handle)) => handle,
            Ok(_) => return Err(Self::state_error(unexpected("BeginStateTransaction"))),
            Err(error) => return Err(Self::state_error(error)),
        };
        Ok(self.remember_tx(handle))
    }

    fn tx_get(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<Option<StateValue>, StateStoreError> {
        let handle = self.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::GetState {
            installation_id: installation,
            key: storage_key,
            tx: Some(handle),
        }) {
            Ok(Response::StateValue(record)) => record.map(to_domain_state_value).transpose(),
            Ok(_) => Err(Self::state_error(unexpected("GetState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn tx_put(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
        value: &StateValue,
    ) -> Result<(), StateStoreError> {
        let handle = self.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::PutState {
            installation_id: installation,
            key: storage_key,
            schema_version: None,
            value: value.as_slice().to_vec(),
            tx: Some(handle),
        }) {
            Ok(Response::StatePut) => Ok(()),
            Ok(_) => Err(Self::state_error(unexpected("PutState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn tx_delete(
        &self,
        tx: StateTransactionId,
        installation: InstallationId,
        key: &StateKey,
    ) -> Result<(), StateStoreError> {
        let handle = self.handle_of(tx)?;
        let storage_key = to_storage_state_key(key)?;
        match self.submit(Command::DeleteState {
            installation_id: installation,
            key: storage_key,
            tx: Some(handle),
        }) {
            Ok(Response::StateDeleted) => Ok(()),
            Ok(_) => Err(Self::state_error(unexpected("DeleteState"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn commit(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        let handle = self.take_tx(tx)?;
        match self.submit(Command::CommitStateTransaction { handle }) {
            Ok(Response::StateCommitted) => Ok(()),
            Ok(_) => Err(Self::state_error(unexpected("CommitStateTransaction"))),
            Err(error) => Err(Self::state_error(error)),
        }
    }

    fn abort(&self, tx: StateTransactionId) -> Result<(), StateStoreError> {
        // WIT：abort 对已终止事务是 no-op——句柄可能已不存在，按 no-op
        // 语义直接调用存储（存储侧对未知句柄 no-op 成功，§41.2）。
        if let Ok(handle) = self.handle_of(tx) {
            match self.submit(Command::AbortStateTransaction { handle }) {
                Ok(Response::StateAborted) => {}
                Ok(_) => return Err(Self::state_error(unexpected("AbortStateTransaction"))),
                Err(error) => return Err(Self::state_error(error)),
            }
            self.take_tx(tx)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ComponentConfigStorePort（§41.2：config 是管理员/系统提供的输入；写入时
// revision 单调 +1 由存储保证；无平台级 migration——与 state 的本质区别）
// ---------------------------------------------------------------------------

impl ComponentConfigStorePort for StoragePorts {
    fn snapshot(
        &self,
        installation: InstallationId,
    ) -> Result<Option<ConfigSnapshot>, ConfigStoreError> {
        match self.submit(Command::GetComponentConfig {
            installation_id: installation,
        }) {
            Ok(Response::ComponentConfig(record)) => {
                record.map(to_domain_config_snapshot).transpose()
            }
            Ok(_) => Err(Self::component_config_error(unexpected(
                "GetComponentConfig",
            ))),
            Err(error) => Err(Self::component_config_error(error)),
        }
    }

    fn put(
        &self,
        installation: InstallationId,
        format: ConfigFormat,
        schema_version: ConfigSchemaVersion,
        value: &ConfigValue,
    ) -> Result<ConfigRevision, ConfigStoreError> {
        // §13.3 边界转换：domain ConfigSchemaVersion（u32）↔ 存储侧
        // StateSchemaVersion（u32）一一对应，不可失败。
        match self.submit(Command::PutComponentConfig {
            installation_id: installation,
            format: to_storage_config_format(format),
            schema_version: StorageStateSchemaVersion::new(schema_version.as_u32()),
            value: value.as_slice().to_vec(),
        }) {
            Ok(Response::ComponentConfigSet) => {}
            Ok(_) => {
                return Err(Self::component_config_error(unexpected(
                    "PutComponentConfig",
                )));
            }
            Err(error) => return Err(Self::component_config_error(error)),
        }
        // §41.2 返回值读回：revision 由存储单语句 upsert 保证单调（§41.2），
        // executor 单连接串行 ⇒ put 后读一致，无交错。
        match self.submit(Command::GetComponentConfig {
            installation_id: installation,
        }) {
            Ok(Response::ComponentConfig(Some(record))) => {
                Ok(ConfigRevision::from_u64(record.revision))
            }
            Ok(Response::ComponentConfig(None)) => {
                Err(Self::component_config_error(StorageError::CorruptState(
                    "config disappeared after write (invariant violation)".into(),
                )))
            }
            Ok(_) => Err(Self::component_config_error(unexpected(
                "GetComponentConfig",
            ))),
            Err(error) => Err(Self::component_config_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// SecretStorePort（§41.2 / §16.6：本 port 只承载**不透明密文 BLOB**与
// 非敏感元数据，**明文绝不出现在本层**——加解密永远在 security 层
// SecretService；storage 不解密、不解释、不回显内容）
// ---------------------------------------------------------------------------

impl SecretStorePort for StoragePorts {
    fn put(
        &self,
        installation: InstallationId,
        name: &SecretName,
        ciphertext: Vec<u8>,
        metadata: &str,
    ) -> Result<SecretVersion, SecretStoreError> {
        let storage_name = to_storage_secret_name(name)?;
        match self.submit(Command::PutSecret {
            installation_id: installation,
            name: storage_name.clone(),
            ciphertext,
            metadata: metadata.to_owned(),
        }) {
            Ok(Response::SecretPut) => {}
            Ok(_) => return Err(Self::secret_error(unexpected("PutSecret"))),
            Err(error) => return Err(Self::secret_error(error)),
        }
        // §41.2 返回值读回：新版本（insert or replace 版本递增，存储保证）；
        // 串行 executor 下 put 后读一致，无交错。
        match self.submit(Command::GetSecretCiphertext {
            installation_id: installation,
            name: storage_name,
        }) {
            Ok(Response::Secret(Some(record))) => Ok(SecretVersion::from_u64(record.version)),
            Ok(Response::Secret(None)) => Err(Self::secret_error(StorageError::CorruptState(
                "secret disappeared after write (invariant violation)".into(),
            ))),
            Ok(_) => Err(Self::secret_error(unexpected("GetSecretCiphertext"))),
            Err(error) => Err(Self::secret_error(error)),
        }
    }

    fn ciphertext(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<Option<SecretCiphertextRecord>, SecretStoreError> {
        let storage_name = to_storage_secret_name(name)?;
        match self.submit(Command::GetSecretCiphertext {
            installation_id: installation,
            name: storage_name,
        }) {
            Ok(Response::Secret(record)) => record.map(to_domain_secret_record).transpose(),
            Ok(_) => Err(Self::secret_error(unexpected("GetSecretCiphertext"))),
            Err(error) => Err(Self::secret_error(error)),
        }
    }

    fn list(&self, installation: InstallationId) -> Result<Vec<SecretMetadata>, SecretStoreError> {
        match self.submit(Command::ListSecretNames {
            installation_id: installation,
        }) {
            Ok(Response::SecretList(records)) => {
                let mut metadata: Vec<SecretMetadata> = Vec::with_capacity(records.len());
                for record in records {
                    let name = SecretName::new(record.name.as_str()).map_err(|_| {
                        Self::secret_error(StorageError::CorruptState(
                            "invalid secret name in store".into(),
                        ))
                    })?;
                    metadata.push(SecretMetadata::new(
                        name,
                        SecretVersion::from_u64(record.version),
                    ));
                }
                Ok(metadata)
            }
            Ok(_) => Err(Self::secret_error(unexpected("ListSecretNames"))),
            Err(error) => Err(Self::secret_error(error)),
        }
    }

    fn delete(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<(), SecretStoreError> {
        let storage_name = to_storage_secret_name(name)?;
        match self.submit(Command::DeleteSecret {
            installation_id: installation,
            name: storage_name,
        }) {
            Ok(Response::SecretDeleted) => Ok(()),
            Ok(_) => Err(Self::secret_error(unexpected("DeleteSecret"))),
            Err(error) => Err(Self::secret_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// SecretGrantPort（§17.3 "secret names" 是 scope 维度之一；§17.5 第三层
// Grant：durable owner 是 InstallationId。本层从 grants 表按
// `operune:secret/secret` 能力面筛选名称范围——能力面之外不构成名称
// grant（deny-by-default，§17.2）；名称范围经 scope 承载，解析失败 =
// 存储损坏 fail closed（与 scope_from_storage 同模式，§13.3））
// ---------------------------------------------------------------------------

/// secret 能力面的能力 id（§19.5 `ImportClass::capability_id` 规范化形态：
/// import `operune:secret/secret@0.1.0` → 能力 id `operune:secret/secret`）。
const SECRET_CAPABILITY_ID: &str = "operune:secret/secret";

impl SecretGrantPort for StoragePorts {
    fn granted_names(&self, installation: InstallationId) -> Result<Vec<SecretName>, GrantError> {
        let records = match self.submit(Command::ListGrants {
            installation_id: installation,
        }) {
            Ok(Response::Grants(records)) => records,
            Ok(_) => return Err(GrantError::Storage(Box::new(unexpected("ListGrants")))),
            Err(error) => return Err(Self::grant_error(error, installation)),
        };
        // BTreeSet：去重 + 确定性顺序（SecretService 只做成员判定，§17.5
        // 第四层 invocation-time enforcement）。
        let mut names: BTreeSet<SecretName> = BTreeSet::new();
        for record in records {
            if record.capability_id.to_string() != SECRET_CAPABILITY_ID {
                continue;
            }
            // 名称范围 = scope 中的 JSON 规范化名称集（§13.3 与 grant scope /
            // graph 记录同模式；存储侧只做字符串结构性校验，语义解析在本层）。
            let raw: Vec<String> =
                serde_json::from_str(record.scope.as_str()).map_err(|error| {
                    GrantError::Storage(Box::new(StorageError::CorruptState(format!(
                        "invalid secret grant scope in database: {error}"
                    ))))
                })?;
            for raw_name in raw {
                let name = SecretName::new(raw_name).map_err(|_| {
                    GrantError::Storage(Box::new(StorageError::CorruptState(
                        "invalid secret name in database grant scope".into(),
                    )))
                })?;
                names.insert(name);
            }
        }
        Ok(names.into_iter().collect())
    }
}

// ---------------------------------------------------------------------------
// StatefulAuditPort（§41.2 state/config/secret audit MUST；映射为
// component-lifecycle 审计行，与 to_storage_audit 同模式；metadata-only，
// 值绝不进入审计，§16.6/§41.2）
// ---------------------------------------------------------------------------

impl StatefulAuditPort for StoragePorts {
    fn append(&self, event: StatefulAuditEvent) -> Result<(), AuditError> {
        let storage_event = to_storage_stateful_audit(&event)?;
        match self.submit(Command::AppendAudit {
            audit: storage_event,
        }) {
            Ok(Response::AuditAppended(_)) => Ok(()),
            Ok(_) => Err(AuditError::Storage(Box::new(unexpected("AppendAudit")))),
            Err(error) => Err(Self::audit_error(error)),
        }
    }
}

// ---------------------------------------------------------------------------
// 转换层（§13.3 边界解析一次；不放宽校验）
// ---------------------------------------------------------------------------

/// application [`GrantScope`] → 存储侧 [`CapabilityScope`]（JSON 规范化）。
fn scope_to_storage(scope: &GrantScope) -> Result<CapabilityScope, StorageError> {
    let json = serde_json::to_string(scope).map_err(|error| {
        StorageError::InvalidArgument(format!("grant scope serialization failed: {error}"))
    })?;
    // CapabilityScope::new 结构性校验（非空 / ≤4096 / 无控制字符）。
    CapabilityScope::new(json)
}

/// 存储侧 [`CapabilityScope`] → application [`GrantScope`]（解析失败 =
/// 存储损坏，fail closed，不静默跳过）。
fn scope_from_storage(scope: &CapabilityScope) -> Result<GrantScope, StorageError> {
    serde_json::from_str(scope.as_str()).map_err(|error| {
        StorageError::CorruptState(format!("invalid grant scope in database: {error}"))
    })
}

// ---------------------------------------------------------------------------
// 0.3.0 Stateful Runtime（§41.2）：state/config/secret 边界转换
// ---------------------------------------------------------------------------

/// domain `StateKey` → storage `StateKey`（§13.3 边界解析一次；两侧字符集
/// 一致（`[A-Za-z0-9._-/]`），失败 = 调用方契约违反 fail closed）。
fn to_storage_state_key(key: &StateKey) -> Result<StorageStateKey, StateStoreError> {
    StorageStateKey::new(key.as_str()).map_err(StoragePorts::state_error)
}

/// domain `StateSchemaVersion` → storage `StateSchemaVersion`（u32 一一对应，
/// 不可失败）。
fn to_storage_schema_version(version: StateSchemaVersion) -> StorageStateSchemaVersion {
    StorageStateSchemaVersion::new(version.as_u32())
}

/// storage `StateValueRecord` → domain `StateValue`（§13.3 边界解析一次；
/// 超限 = 存储损坏 fail closed）。
fn to_domain_state_value(record: StateValueRecord) -> Result<StateValue, StateStoreError> {
    StateValue::new(record.value).map_err(|_| {
        StoragePorts::state_error(StorageError::CorruptState(
            "state value exceeds the domain bound in store".into(),
        ))
    })
}

/// domain `ConfigFormat` → storage `ConfigFormat`（闭集一一对应，不可失败）。
fn to_storage_config_format(format: ConfigFormat) -> StorageConfigFormat {
    match format {
        ConfigFormat::Json => StorageConfigFormat::Json,
        ConfigFormat::Toml => StorageConfigFormat::Toml,
        ConfigFormat::Raw => StorageConfigFormat::Raw,
    }
}

/// storage `ComponentConfigRecord` → domain `ConfigSnapshot`（§13.3 边界
/// 解析一次；value 超限 = 存储损坏 fail closed）。
fn to_domain_config_snapshot(
    record: ComponentConfigRecord,
) -> Result<ConfigSnapshot, ConfigStoreError> {
    let value = ConfigValue::new(record.value).map_err(|_| {
        StoragePorts::component_config_error(StorageError::CorruptState(
            "config value exceeds the domain bound in store".into(),
        ))
    })?;
    Ok(ConfigSnapshot::new(
        ConfigRevision::from_u64(record.revision),
        value,
    ))
}

/// domain `SecretName` → storage `SecretName`（§13.3 边界解析一次；两侧
/// 字符集一致（`[A-Za-z0-9._-]`），失败 = 调用方契约违反 fail closed）。
fn to_storage_secret_name(name: &SecretName) -> Result<StorageSecretName, SecretStoreError> {
    StorageSecretName::new(name.as_str()).map_err(StoragePorts::secret_error)
}

/// storage `SecretRecord` → domain `SecretCiphertextRecord`（§16.6：只承载
/// 密文 BLOB 与元数据，**不含明文**；名称解析失败 = 存储损坏 fail closed）。
fn to_domain_secret_record(
    record: SecretRecord,
) -> Result<SecretCiphertextRecord, SecretStoreError> {
    let name = SecretName::new(record.name.as_str()).map_err(|_| {
        StoragePorts::secret_error(StorageError::CorruptState(
            "invalid secret name in store".into(),
        ))
    })?;
    Ok(SecretCiphertextRecord {
        name,
        version: SecretVersion::from_u64(record.version),
        ciphertext: record.ciphertext,
    })
}

/// application [`AuditEvent`] → 存储侧 [`crate::model::AuditEvent`]。
///
/// 逐变体显式映射（闭集对齐，§12.2）；`action` / `target` / `detail` 只含
/// 可诊断信息（§16.6：application 事件本身不携带 secret——环境变量 grant
/// 值在 [`operune_application::model::GrantAuditShape`] 已遮蔽）。
fn to_storage_audit(event: &AuditEvent) -> Result<crate::model::AuditEvent, AuditError> {
    let (category, action, target, outcome, detail) = match event {
        AuditEvent::InstallRejected { digest, reason } => (
            AuditCategory::ComponentLifecycle,
            "install-rejected",
            Some(digest.to_string()),
            AuditOutcome::Failure,
            Some(format!("reason: {reason:?}")),
        ),
        AuditEvent::CandidatePersisted { digest } => (
            AuditCategory::Artifact,
            "candidate-persisted",
            Some(digest.to_string()),
            AuditOutcome::Success,
            None,
        ),
        AuditEvent::DescriptorFailed { digest, reason } => (
            AuditCategory::ComponentLifecycle,
            "descriptor-failed",
            Some(digest.to_string()),
            AuditOutcome::Failure,
            Some((*reason).to_owned()),
        ),
        AuditEvent::DescriptorMismatch { digest } => (
            AuditCategory::ComponentLifecycle,
            "descriptor-mismatch",
            Some(digest.to_string()),
            AuditOutcome::Failure,
            None,
        ),
        AuditEvent::IdentityRegistered {
            installation,
            component_id,
            version,
            digest,
        } => (
            AuditCategory::ComponentLifecycle,
            "identity-registered",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{component_id} {version} {digest}")),
        ),
        AuditEvent::VersionConflict {
            component_id,
            version,
            existing,
            incoming,
        } => (
            AuditCategory::ComponentLifecycle,
            "version-conflict",
            Some(component_id.to_string()),
            AuditOutcome::Failure,
            Some(format!(
                "{version}: existing {existing}, incoming {incoming}"
            )),
        ),
        AuditEvent::ResolutionFailed {
            installation,
            missing,
        } => (
            AuditCategory::ComponentLifecycle,
            "resolution-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("missing: {:?}", missing)),
        ),
        AuditEvent::GrantsApproved {
            installation,
            grants,
        } => (
            AuditCategory::Grant,
            "grants-approved",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{} grants", grants.len())),
        ),
        AuditEvent::ActivationStarted { installation } => (
            AuditCategory::ComponentLifecycle,
            "activation-started",
            Some(installation.to_string()),
            AuditOutcome::Success,
            None,
        ),
        AuditEvent::ActivationFailed {
            installation,
            stage,
        } => (
            AuditCategory::ComponentLifecycle,
            "activation-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some((*stage).to_owned()),
        ),
        AuditEvent::ActivationSucceeded {
            installation,
            component_id,
            version,
            digest,
        } => (
            AuditCategory::ComponentLifecycle,
            "activation-succeeded",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{component_id} {version} {digest}")),
        ),
        AuditEvent::UpgradeSwapped {
            installation,
            from,
            to,
        } => (
            AuditCategory::ComponentLifecycle,
            "upgrade-swapped",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("from {from} to {to}")),
        ),
        AuditEvent::DrainStarted {
            installation,
            digest,
            deadline_secs,
        } => (
            AuditCategory::ComponentLifecycle,
            "drain-started",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("digest {digest} deadline {deadline_secs}s")),
        ),
        AuditEvent::DrainCompleted {
            installation,
            digest,
        } => (
            AuditCategory::ComponentLifecycle,
            "drain-completed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(digest.to_string()),
        ),
        AuditEvent::WebManifestLoaded {
            installation,
            assets,
            cached,
        } => (
            AuditCategory::ComponentLifecycle,
            "web-manifest-loaded",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("assets {assets} cached {cached}")),
        ),
        AuditEvent::ActionInvoked {
            installation,
            version,
            action,
        } => (
            AuditCategory::ComponentLifecycle,
            "action-invoked",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{version} {action}")),
        ),
        AuditEvent::ActionDenied {
            installation,
            action,
            reason,
        } => (
            AuditCategory::ComponentLifecycle,
            "action-denied",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("{action} {reason}")),
        ),
        AuditEvent::Rollback {
            installation,
            from,
            to,
        } => (
            AuditCategory::ComponentLifecycle,
            "rollback",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("from {from} to {to}")),
        ),
        // 0.2.0 provider graph（§40.2 / §40.4）：沿用 ComponentLifecycle 类别
        //（graph 门控属于安装 / 激活 / 升级编排）；action 前缀 graph- 区分。
        AuditEvent::ProviderGraphRejected {
            installation,
            reason,
        } => (
            AuditCategory::ComponentLifecycle,
            "provider-graph-rejected",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some((*reason).to_owned()),
        ),
        AuditEvent::GraphRecordsCommitted { installation } => (
            AuditCategory::ComponentLifecycle,
            "graph-records-committed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            None,
        ),
        AuditEvent::GraphRecordsRemoved { installation } => (
            AuditCategory::ComponentLifecycle,
            "graph-records-removed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            None,
        ),
        AuditEvent::GraphPolicyUpdated {
            bindings,
            exclusions,
        } => (
            AuditCategory::ComponentLifecycle,
            "graph-policy-updated",
            None,
            AuditOutcome::Success,
            Some(format!("{bindings} bindings, {exclusions} exclusions")),
        ),
        // §39.2 remove / §42.4：卸载完成（事件与元数据删除同事务，
        // §18.7 fail closed）。component-lifecycle 类别 + uninstall 前缀。
        AuditEvent::UninstallCompleted {
            installation,
            component_id,
            version,
            digest,
        } => (
            AuditCategory::ComponentLifecycle,
            "uninstall-completed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(match digest {
                Some(digest) => format!("{component_id} {version} {digest}"),
                None => format!("{component_id} {version} (never activated)"),
            }),
        ),
    };
    crate::model::AuditEvent::new(
        AuditActor::System,
        category,
        action,
        target,
        outcome,
        detail,
    )
    .map_err(|error| AuditError::Storage(Box::new(error)))
}

/// application [`StatefulAuditEvent`]（§41.2 state/config/secret 审计）→
/// 存储侧 [`crate::model::AuditEvent`]。
///
/// 逐变体显式映射（与 [`to_storage_audit`] 同模式）：类别沿用
/// component-lifecycle（audit.rs 文档：接线层映射为 component-lifecycle
/// 审计行）；`action` / `target` / `detail` 只含可诊断元数据（名称、版本、
/// 键、静态 reason 标签——**值绝不进入审计**，§16.6 / §41.2）。
fn to_storage_stateful_audit(
    event: &StatefulAuditEvent,
) -> Result<crate::model::AuditEvent, AuditError> {
    let (action, target, outcome, detail) = match event {
        StatefulAuditEvent::StateRead { installation, key } => (
            "state-read",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(key.to_string()),
        ),
        StatefulAuditEvent::StateCasApplied { installation, key } => (
            "state-cas-applied",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(key.to_string()),
        ),
        StatefulAuditEvent::StateCasRejected { installation, key } => (
            "state-cas-rejected",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(key.to_string()),
        ),
        StatefulAuditEvent::StateTxBegan {
            installation,
            schema_version,
        } => (
            "state-tx-began",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("schema-version {schema_version}")),
        ),
        StatefulAuditEvent::StateTxCommitted {
            installation,
            schema_version,
        } => (
            "state-tx-committed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("schema-version {schema_version}")),
        ),
        StatefulAuditEvent::StateTxAborted {
            installation,
            schema_version,
        } => (
            "state-tx-aborted",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("schema-version {schema_version}")),
        ),
        StatefulAuditEvent::StateTxPut { installation, key } => (
            "state-tx-put",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(key.to_string()),
        ),
        StatefulAuditEvent::StateTxDeleted { installation, key } => (
            "state-tx-deleted",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(key.to_string()),
        ),
        StatefulAuditEvent::StateFailed {
            installation,
            operation,
            reason,
        } => (
            "state-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("operation {operation}: {reason}")),
        ),
        StatefulAuditEvent::MigrationStarted {
            installation,
            from,
            to,
        } => (
            "state-migration-started",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("from {from} to {to}")),
        ),
        StatefulAuditEvent::MigrationCommitted {
            installation,
            from,
            to,
        } => (
            "state-migration-committed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("from {from} to {to}")),
        ),
        StatefulAuditEvent::MigrationRolledBack {
            installation,
            from,
            to,
            reason,
        } => (
            "state-migration-rolled-back",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("from {from} to {to}: {reason}")),
        ),
        StatefulAuditEvent::MigrationFailed {
            installation,
            from,
            to,
            reason,
        } => (
            "state-migration-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("from {from} to {to}: {reason}")),
        ),
        StatefulAuditEvent::ConfigRead {
            installation,
            revision,
        } => (
            "config-read",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("revision {revision}")),
        ),
        StatefulAuditEvent::ConfigWritten {
            installation,
            revision,
            format,
        } => (
            "config-written",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("revision {revision} format {format}")),
        ),
        StatefulAuditEvent::ConfigFailed {
            installation,
            operation,
            reason,
        } => (
            "config-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(format!("operation {operation}: {reason}")),
        ),
        StatefulAuditEvent::SecretRead {
            installation,
            name,
            version,
        } => (
            "secret-read",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{name} version {version}")),
        ),
        StatefulAuditEvent::SecretDenied { installation, name } => (
            "secret-denied",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(name.to_string()),
        ),
        StatefulAuditEvent::SecretRotated {
            installation,
            name,
            version,
        } => (
            "secret-rotated",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{name} version {version}")),
        ),
        StatefulAuditEvent::SecretDeleted { installation, name } => (
            "secret-deleted",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(name.to_string()),
        ),
        StatefulAuditEvent::SecretListed {
            installation,
            names,
        } => (
            "secret-listed",
            Some(installation.to_string()),
            AuditOutcome::Success,
            Some(format!("{names} names")),
        ),
        StatefulAuditEvent::SecretFailed {
            installation,
            name,
            reason,
        } => (
            "secret-failed",
            Some(installation.to_string()),
            AuditOutcome::Failure,
            Some(match name {
                Some(name) => format!("{name}: {reason}"),
                None => reason.to_string(),
            }),
        ),
    };
    crate::model::AuditEvent::new(
        AuditActor::System,
        AuditCategory::ComponentLifecycle,
        action,
        target,
        outcome,
        detail,
    )
    .map_err(|error| AuditError::Storage(Box::new(error)))
}

// ---------------------------------------------------------------------------
// RuntimeConfig 快照序列化 / 解析（§18.0 / §13.3）
// ---------------------------------------------------------------------------

/// 时长 → u64 毫秒（饱和语义不允许：溢出 = 序列化失败，fail closed）。
#[cfg_attr(not(test), allow(dead_code))] // 配置写入侧：RuntimeConfig 管理面（server/web-admin）与测试写入路径使用
fn millis_u64(duration: Duration) -> Result<u64, ConfigError> {
    u64::try_from(duration.as_millis()).map_err(|_| {
        ConfigError::Storage(Box::new(StorageError::InvalidArgument(
            "duration out of u64 millis range".into(),
        )))
    })
}

/// 预算 → JSON（ConfigPort 快照写入侧的规范化编码；`ConfigPort` 本身只读，
/// 写入由 RuntimeConfig 管理面经 executor 的 `set_config` 完成）。
#[cfg_attr(not(test), allow(dead_code))] // 同上：配置写入侧
fn budget_to_json(budget: &ResourceBudget) -> Result<serde_json::Value, ConfigError> {
    let call_deadline = match budget.call_deadline {
        Some(deadline) => Some(millis_u64(deadline.get())?),
        None => None,
    };
    Ok(serde_json::json!({
        "linear-memory-bytes": budget.linear_memory.map(|limit| limit.as_bytes().as_bytes()),
        "memories": budget.memories.map(|limit| limit.as_u64()),
        "tables": budget.tables.map(|limit| limit.as_u64()),
        "table-elements": budget.table_elements.map(|limit| limit.as_u64()),
        "instances": budget.instances.map(|limit| limit.as_u64()),
        "host-buffers-bytes": budget.host_buffers.map(|limit| limit.as_bytes().as_bytes()),
        "max-concurrent": budget.max_concurrent.get().get(),
        "max-queued": budget.max_queued.get().get(),
        "call-deadline-millis": call_deadline,
        "background-tasks": budget.background_tasks.get().get(),
        "http-body-bytes": budget.http_body.map(|limit| limit.as_bytes().as_bytes()),
    }))
}

/// RuntimeConfig → JSON 文档（配置写入侧的规范化编码；`ConfigPort` 本身
/// 只读，写入由 RuntimeConfig 管理面经 executor 的 `set_config` 完成）。
#[cfg_attr(not(test), allow(dead_code))] // 同上：配置写入侧
fn runtime_config_to_json(config: &RuntimeConfig) -> Result<serde_json::Value, ConfigError> {
    Ok(serde_json::json!({
        "max-component-bytes": config.max_component_bytes.as_u64(),
        "descriptor-deadline-millis": millis_u64(config.descriptor_deadline)?,
        "descriptor-budget": budget_to_json(&config.descriptor_budget)?,
        "candidate-budget": budget_to_json(&config.candidate_budget)?,
        "readiness-deadline-millis": millis_u64(config.readiness_deadline)?,
        "drain-deadline-millis": millis_u64(config.drain_deadline)?,
        "max-web-assets": config.max_web_assets,
        "max-asset-bytes": config.max_asset_bytes.as_u64(),
        "max-action-body-bytes": config.max_action_body_bytes.as_u64(),
        "max-action-response-bytes": config.max_action_response_bytes.as_u64(),
        "max-actions-per-minute": config.max_actions_per_minute,
    }))
}

/// JSON 对象中读取 u64 字段：缺失 = 损坏；`null` = `None`；非数字 = 损坏。
fn json_opt_u64(value: &serde_json::Value, key: &str) -> Result<Option<u64>, ConfigError> {
    match value.get(key) {
        None => Err(ConfigError::Storage(Box::new(StorageError::CorruptState(
            format!("runtime config key {key:?} is missing"),
        )))),
        Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(number)) => number.as_u64().map(Some).ok_or_else(|| {
            ConfigError::Storage(Box::new(StorageError::CorruptState(format!(
                "runtime config key {key:?} is not a non-negative integer"
            ))))
        }),
        Some(_) => Err(ConfigError::Storage(Box::new(StorageError::CorruptState(
            format!("runtime config key {key:?} is not a number"),
        )))),
    }
}

fn json_u64(value: &serde_json::Value, key: &str) -> Result<u64, ConfigError> {
    json_opt_u64(value, key)?.ok_or_else(|| {
        ConfigError::Storage(Box::new(StorageError::CorruptState(format!(
            "runtime config key {key:?} must be non-null"
        ))))
    })
}

fn budget_from_json(value: &serde_json::Value) -> Result<ResourceBudget, ConfigError> {
    let corrupt = |message: &str| {
        ConfigError::Storage(Box::new(StorageError::CorruptState(message.to_owned())))
    };
    // 预算字节量使用 runtime-wasm 的 ByteSize（domain ByteSize 是另一类型，
    // §7.4 预算类型语义）。
    let bytes = |key: &str| -> Result<Option<operune_runtime_wasm::ByteSize>, ConfigError> {
        Ok(json_opt_u64(value, key)?.map(operune_runtime_wasm::ByteSize::new))
    };
    let count = |key: &str| -> Result<Option<u64>, ConfigError> { json_opt_u64(value, key) };
    let max_concurrent_value = usize::try_from(json_u64(value, "max-concurrent")?)
        .map_err(|_| corrupt("max-concurrent exceeds usize"))?;
    let max_concurrent = MaxConcurrent::try_new(max_concurrent_value)
        .ok_or_else(|| corrupt("max-concurrent must be non-zero"))?;
    let max_queued_value = usize::try_from(json_u64(value, "max-queued")?)
        .map_err(|_| corrupt("max-queued exceeds usize"))?;
    let max_queued = MaxQueued::try_new(max_queued_value)
        .ok_or_else(|| corrupt("max-queued must be non-zero"))?;
    let background_value = usize::try_from(json_u64(value, "background-tasks")?)
        .map_err(|_| corrupt("background-tasks exceeds usize"))?;
    let background_tasks = BackgroundTaskLimit::try_new(background_value)
        .ok_or_else(|| corrupt("background-tasks must be non-zero"))?;
    let call_deadline = json_opt_u64(value, "call-deadline-millis")?
        .map(|millis| CallDeadline::new(Duration::from_millis(millis)));
    Ok(ResourceBudget {
        linear_memory: bytes("linear-memory-bytes")?.map(LinearMemoryLimit::new),
        memories: count("memories")?.map(MemoryCountLimit::new),
        tables: count("tables")?.map(TableCountLimit::new),
        table_elements: count("table-elements")?.map(TableElementLimit::new),
        instances: count("instances")?.map(InstanceCountLimit::new),
        host_buffers: bytes("host-buffers-bytes")?.map(HostBufferLimit::new),
        max_concurrent,
        max_queued,
        call_deadline,
        background_tasks,
        http_body: bytes("http-body-bytes")?.map(HttpBodyLimit::new),
    })
}

fn runtime_config_from_json(value: &serde_json::Value) -> Result<RuntimeConfig, ConfigError> {
    let budget = |key: &str| -> Result<ResourceBudget, ConfigError> {
        match value.get(key) {
            Some(budget) => budget_from_json(budget),
            None => Err(ConfigError::Storage(Box::new(StorageError::CorruptState(
                format!("runtime config key {key:?} is missing"),
            )))),
        }
    };
    let bytes = |key: &str| -> Result<ByteSize, ConfigError> {
        Ok(ByteSize::from_bytes(json_u64(value, key)?))
    };
    let millis = |key: &str| -> Result<Duration, ConfigError> {
        Ok(Duration::from_millis(json_u64(value, key)?))
    };
    let web_assets = usize::try_from(json_u64(value, "max-web-assets")?).map_err(|_| {
        ConfigError::Storage(Box::new(StorageError::CorruptState(
            "max-web-assets exceeds usize".into(),
        )))
    })?;
    let actions_per_minute =
        u32::try_from(json_u64(value, "max-actions-per-minute")?).map_err(|_| {
            ConfigError::Storage(Box::new(StorageError::CorruptState(
                "max-actions-per-minute exceeds u32".into(),
            )))
        })?;
    Ok(RuntimeConfig {
        max_component_bytes: bytes("max-component-bytes")?,
        descriptor_deadline: millis("descriptor-deadline-millis")?,
        descriptor_budget: budget("descriptor-budget")?,
        candidate_budget: budget("candidate-budget")?,
        readiness_deadline: millis("readiness-deadline-millis")?,
        drain_deadline: millis("drain-deadline-millis")?,
        max_web_assets: web_assets,
        max_asset_bytes: bytes("max-asset-bytes")?,
        max_action_body_bytes: bytes("max-action-body-bytes")?,
        max_action_response_bytes: bytes("max-action-response-bytes")?,
        max_actions_per_minute: actions_per_minute,
    })
}

/// 内部不变量违反（不可能发生的响应错配）。
fn unexpected(expected: &str) -> StorageError {
    StorageError::CorruptState(format!(
        "internal error: unexpected response type for command {expected}"
    ))
}

/// graph 存储错误映射（§14.1：类型擦除的可诊断 source，封闭 typed 错误
/// 由 application 的 [`GraphStoreError`] 承载）。
fn graph_error(error: StorageError) -> GraphStoreError {
    GraphStoreError::Storage(Box::new(error))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::testutil::{audit, component_id, data_root, err, ok, some, tempdir};
    use operune_domain::{
        CapabilityId, ComponentId, ComponentLifecycleEvent, ComponentVersion, InterfaceId,
        InterfaceName, InterfaceRequirement, PackageName,
    };

    fn config(dir: &std::path::Path) -> crate::executor::ExecutorConfig {
        ok(
            crate::executor::ExecutorConfig::new(data_root(dir)),
            "executor config",
        )
    }

    fn version(value: &str) -> ComponentVersion {
        ok(value.parse::<ComponentVersion>(), "parse version")
    }

    async fn open_ports(dir: &std::path::Path) -> StoragePorts {
        let executor = ok(StorageExecutor::open(config(dir)).await, "open executor");
        let hard_limit = ok(ByteSize::mib(16), "hard limit");
        StoragePorts::new(std::sync::Arc::new(executor), hard_limit)
    }

    async fn shutdown_ports(ports: StoragePorts) {
        let executor = match std::sync::Arc::try_unwrap(ports.executor) {
            Ok(executor) => executor,
            Err(_) => unreachable!("executor still shared at test shutdown"),
        };
        ok(executor.shutdown().await, "shutdown");
    }

    /// 断言式领域生命周期推进（测试语义：转换必须合法，§12.2）。
    fn transition_ok(
        state: ComponentLifecycleState,
        event: ComponentLifecycleEvent,
    ) -> ComponentLifecycleState {
        match state.transition(event) {
            Ok(next) => next,
            Err(error) => unreachable!("lifecycle transition failed: {error}"),
        }
    }

    /// 通过 registry port 完成一次全新安装的持久化路径
    ///（quarantine → candidate → active，§19.2 / §19.3）。
    async fn install_v1(
        ports: &StoragePorts,
        component_id: &ComponentId,
        version: ComponentVersion,
        bytes: Vec<u8>,
    ) -> (ContentDigest, InstallationId) {
        let digest = ContentDigest::from_bytes(&bytes);
        ok(ports.persist_artifact(digest, &bytes), "persist artifact");
        ok(
            ports.upsert_candidate(&CandidateRecord {
                digest,
                state: ComponentLifecycleState::initial(),
                byte_len: ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            }),
            "upsert candidate",
        );
        ok(
            ports.bind_version(&DigestVersionBinding {
                component_id: component_id.clone(),
                version,
                digest,
            }),
            "bind version",
        );
        let installation_id = InstallationId::new();
        ok(
            ports.insert_installation(&InstallationRecord {
                installation_id,
                component_id: component_id.clone(),
                version,
                active_digest: None,
                last_known_good_digest: None,
                state: ComponentLifecycleState::Validated,
            }),
            "insert installation",
        );
        // 领域生命周期：Installed → Validated → Activating → Active（§12.2）。
        for (state, event) in [
            (
                ComponentLifecycleState::Installed,
                ComponentLifecycleEvent::ValidationSucceeded,
            ),
            (
                ComponentLifecycleState::Validated,
                ComponentLifecycleEvent::ActivationRequested,
            ),
            (
                ComponentLifecycleState::Activating,
                ComponentLifecycleEvent::ReadinessSucceeded,
            ),
        ] {
            let record = some(
                ok(ports.candidate(digest), "candidate read"),
                "candidate record",
            );
            assert_eq!(record.state, state);
            ok(
                ports.update_candidate_state(digest, transition_ok(record.state, event)),
                "update candidate state",
            );
        }
        ok(
            ports.update_installation(&InstallationRecord {
                installation_id,
                component_id: component_id.clone(),
                version,
                active_digest: Some(digest),
                last_known_good_digest: Some(digest),
                state: ComponentLifecycleState::Active,
            }),
            "activate installation",
        );
        (digest, installation_id)
    }

    #[tokio::test]
    async fn registry_full_install_lifecycle_persists() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component_id = component_id("demo");
        let version = version("1.0.0");
        let bytes = b"v1 component bytes".to_vec();
        let (digest, installation_id) =
            install_v1(&ports, &component_id, version, bytes.clone()).await;

        // 字节事实可回读（§18.7 rollback retention）。
        let read_back = some(
            ok(ports.artifact_bytes(digest), "artifact bytes"),
            "artifact bytes",
        );
        assert_eq!(read_back, bytes);

        // candidate 生命周期精确回读（§12.2）。
        let record = some(ok(ports.candidate(digest), "candidate"), "candidate");
        assert_eq!(record.state, ComponentLifecycleState::Active);
        assert_eq!(
            record.byte_len,
            ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
        );

        // 版本绑定（§19.4）。
        let binding = some(
            ok(
                ports.resolve_version(&component_id, version),
                "resolve version",
            ),
            "binding",
        );
        assert_eq!(binding.digest, digest);

        // 安装记录组合回读（§18.3）。
        let record = some(
            ok(ports.installation(installation_id), "installation"),
            "installation",
        );
        assert_eq!(record.component_id, component_id);
        assert_eq!(record.version, version);
        assert_eq!(record.active_digest, Some(digest));
        assert_eq!(record.last_known_good_digest, Some(digest));
        assert_eq!(record.state, ComponentLifecycleState::Active);

        let listed = ok(ports.list_installations(), "list installations");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].installation_id, installation_id);

        // 幂等性：重入（同 digest 重新 persist + upsert + bind）。
        ok(
            ports.persist_artifact(digest, &bytes),
            "re-persist idempotent",
        );
        ok(
            ports.upsert_candidate(&CandidateRecord {
                digest,
                state: ComponentLifecycleState::initial(),
                byte_len: ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            }),
            "re-upsert idempotent",
        );
        ok(
            ports.bind_version(&DigestVersionBinding {
                component_id: component_id.clone(),
                version,
                digest,
            }),
            "re-bind idempotent",
        );
        // §19.4：同逻辑版本不同 digest 显式阻断。
        let other = ContentDigest::from_bytes(b"other bytes");
        let conflict = ports.bind_version(&DigestVersionBinding {
            component_id: component_id.clone(),
            version,
            digest: other,
        });
        assert!(
            matches!(conflict, Err(RegistryError::VersionBindingConflict { .. })),
            "version binding conflict must be explicit: {conflict:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn registry_upgrade_and_rollback_retention() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component_id = component_id("demo");
        let v1 = version("1.0.0");
        let v2 = version("2.0.0");
        let bytes_v1 = b"v1 bytes".to_vec();
        let bytes_v2 = b"v2 bytes".to_vec();
        let (digest_v1, installation_id) =
            install_v1(&ports, &component_id, v1, bytes_v1.clone()).await;

        // 升级 v2（§20.1：原子快照交换 + 旧版本进入 history）。
        let digest_v2 = ContentDigest::from_bytes(&bytes_v2);
        ok(ports.persist_artifact(digest_v2, &bytes_v2), "persist v2");
        ok(
            ports.upsert_candidate(&CandidateRecord {
                digest: digest_v2,
                state: ComponentLifecycleState::initial(),
                byte_len: ByteSize::from_bytes(bytes_v2.len() as u64),
            }),
            "upsert v2",
        );
        ok(
            ports.bind_version(&DigestVersionBinding {
                component_id: component_id.clone(),
                version: v2,
                digest: digest_v2,
            }),
            "bind v2",
        );
        let record = some(
            ok(ports.installation(installation_id), "installation"),
            "installation",
        );
        assert_eq!(record.state, ComponentLifecycleState::Active);
        ok(
            ports.update_installation(&InstallationRecord {
                installation_id,
                component_id: component_id.clone(),
                version: v2,
                active_digest: Some(digest_v2),
                last_known_good_digest: Some(digest_v1),
                state: ComponentLifecycleState::Active,
            }),
            "activate v2",
        );
        let record = some(
            ok(ports.installation(installation_id), "installation"),
            "installation",
        );
        assert_eq!(record.version, v2);
        assert_eq!(record.active_digest, Some(digest_v2));
        // §18.7 rollback retention：上一已知良好 = v1 digest。
        assert_eq!(record.last_known_good_digest, Some(digest_v1));
        // 回滚目标字节可用（§18.7）。
        let rollback_bytes = some(
            ok(ports.artifact_bytes(digest_v1), "rollback bytes"),
            "rollback target",
        );
        assert_eq!(rollback_bytes, bytes_v1);
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn grants_replace_is_atomic_and_roundtrips() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component_id = component_id("demo");
        let version = version("1.0.0");
        let (_, installation_id) =
            install_v1(&ports, &component_id, version, b"bytes".to_vec()).await;

        let env_scope = GrantScope::WasiEnv {
            key: "OPERUNE_PORT_TEST".to_owned(),
            value: "visible".to_owned(),
        };
        let preopen_scope = GrantScope::WasiPreopen {
            guest_path: "data".to_owned(),
            host_path: "/tmp/operune-test".to_owned(),
            read: true,
            write: false,
        };
        let grants = vec![
            InstallationGrant {
                capability: ok(CapabilityId::new("wasi:cli/run"), "capability"),
                scope: env_scope.clone(),
            },
            InstallationGrant {
                capability: ok(CapabilityId::new("wasi:filesystem"), "capability"),
                scope: preopen_scope.clone(),
            },
        ];
        ok(
            ports.replace_grants(installation_id, &grants),
            "replace grants",
        );
        // §17.5：round-trip 精确（scope 全字段保留，不丢校验）。
        let read_back = ok(ports.grants_for(installation_id), "grants for");
        assert_eq!(read_back, grants);

        // 整体替换：旧 grant 全部撤销，新集合生效（§17.5）。
        let replacement = vec![InstallationGrant {
            capability: ok(CapabilityId::new("wasi:http"), "capability"),
            scope: GrantScope::Unscoped,
        }];
        ok(
            ports.replace_grants(installation_id, &replacement),
            "replace grants again",
        );
        let read_back = ok(ports.grants_for(installation_id), "grants after replace");
        assert_eq!(read_back, replacement);
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn audit_append_is_durable_and_typed() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let digest = ContentDigest::from_bytes(b"audited bytes");
        ok(
            AuditPort::append(&ports, AuditEvent::CandidatePersisted { digest }),
            "append candidate-persisted",
        );
        ok(
            AuditPort::append(
                &ports,
                AuditEvent::InstallRejected {
                    digest,
                    reason: operune_application::ports::RejectReason::Oversized,
                },
            ),
            "append install-rejected",
        );
        // 存储侧 audit 可回读（§18.7 durable）。
        let events = ok(ports.executor.list_audit_recent(10).await, "list audit");
        assert!(
            events
                .iter()
                .any(|event| event.action == "candidate-persisted")
        );
        assert!(events.iter().any(|event| {
            event.action == "install-rejected" && event.outcome == AuditOutcome::Failure
        }));
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn config_snapshot_roundtrips_all_fields() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let config = RuntimeConfig::default();
        let json = ok(
            serde_json::to_string(&ok(runtime_config_to_json(&config), "config json")),
            "serialize config",
        );
        ok(
            ports
                .executor
                .set_config(RUNTIME_CONFIG_KEY.to_owned(), json, audit("config write"))
                .await,
            "write config",
        );
        let snapshot = ok(ConfigPort::snapshot(&ports), "config snapshot");
        assert_eq!(snapshot, config);
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn config_snapshot_fails_closed_when_missing() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let result = ConfigPort::snapshot(&ports);
        assert!(
            matches!(result, Err(ConfigError::Storage(_))),
            "missing config must fail closed: {result:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn candidate_lifecycle_survives_reopen() {
        // §18.3 / §19.2：digest 主键的 candidate 生命周期是持久化事实——
        // 重启后（重新打开 executor）仍精确可读。
        let dir = tempdir();
        let component_id = component_id("durable");
        let version = version("1.0.0");
        {
            let ports = open_ports(dir.path()).await;
            let (digest, _) =
                install_v1(&ports, &component_id, version, b"durable bytes".to_vec()).await;
            let record = some(ok(ports.candidate(digest), "candidate"), "candidate record");
            assert_eq!(record.state, ComponentLifecycleState::Active);
            shutdown_ports(ports).await;
        }
        let ports = open_ports(dir.path()).await;
        let record = some(
            ok(
                ports.candidate(ContentDigest::from_bytes(b"durable bytes")),
                "candidate after reopen",
            ),
            "candidate record",
        );
        assert_eq!(record.state, ComponentLifecycleState::Active);
        let listed = ok(ports.list_installations(), "list after reopen");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].state, ComponentLifecycleState::Active);
        shutdown_ports(ports).await;
    }

    // ------------------------------------------------------------------
    // ProviderGraphPort（§40.2 graph persistence/recovery）
    // ------------------------------------------------------------------

    fn iface(package: &str, interface: &str, major: u32, minor: u32, patch: u32) -> InterfaceId {
        InterfaceId::new(
            ok(PackageName::new(package), "package"),
            ok(InterfaceName::new(interface), "interface"),
            ComponentVersion::from_parts(major, minor, patch),
        )
    }

    fn requirement(package: &str, interface: &str, req: &str) -> InterfaceRequirement {
        ok(
            format!("{package}/{interface}@{req}").parse::<InterfaceRequirement>(),
            "requirement",
        )
    }

    fn provider_record(installation: InstallationId, provided: &[InterfaceId]) -> ProviderRecord {
        ok(
            ProviderRecord::new(installation, provided.iter().cloned().collect()),
            "provider record",
        )
    }

    fn consumer_record(
        installation: InstallationId,
        required: &[InterfaceRequirement],
    ) -> ConsumerRecord {
        ConsumerRecord::new(installation, required.iter().cloned().collect())
    }

    /// 注册组件（§19.2 两阶段安装前置：component 必须先有 committed
    /// candidate 才能创建安装实例；幂等，重复调用同 digest 合法）。
    async fn register_component(ports: &StoragePorts, component: &ComponentId) {
        let bytes = b"graph component bytes".to_vec();
        let digest = ContentDigest::from_bytes(&bytes);
        ok(ports.persist_artifact(digest, &bytes), "persist artifact");
        ok(
            ports.upsert_candidate(&CandidateRecord {
                digest,
                state: ComponentLifecycleState::initial(),
                byte_len: ByteSize::from_bytes(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
            }),
            "upsert candidate",
        );
        ok(
            ports.bind_version(&DigestVersionBinding {
                component_id: component.clone(),
                version: ComponentVersion::from_parts(1, 0, 0),
                digest,
            }),
            "bind version",
        );
    }

    /// 经 executor 创建安装实例（graph 记录锚定安装实例，§17.5）。
    async fn create_installation(ports: &StoragePorts, component: &ComponentId) -> InstallationId {
        register_component(ports, component).await;
        let id = InstallationId::new();
        ok(
            ports
                .executor
                .create_installation_with_id(id, component.clone(), audit("create installation"))
                .await,
            "create installation",
        );
        id
    }

    #[tokio::test]
    async fn graph_records_replace_and_load_roundtrip() {
        // 多 provider + 多 consumer + provider/consumer 同安装（依赖链中间
        // 节点，§40.3）：replace 后 load 精确回读（typed records，§40.2
        // 恢复输入）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-demo");
        let a = create_installation(&ports, &component).await;
        let b = create_installation(&ports, &component).await;
        let c = create_installation(&ports, &component).await;

        let provider_a = provider_record(
            a,
            &[
                iface("acme:svc", "checkout", 1, 0, 0),
                iface("acme:svc", "analytics", 0, 2, 0),
            ],
        );
        let provider_b = provider_record(b, &[iface("acme:svc", "analytics", 0, 3, 0)]);
        let consumer_b = consumer_record(
            b,
            &[
                requirement("acme:svc", "checkout", "^1.0.0"),
                requirement("acme:svc", "payments", "*"),
            ],
        );
        let consumer_c = consumer_record(c, &[requirement("acme:svc", "analytics", "^0.2.0")]);
        ok(
            ports.replace_records(a, Some(&provider_a), None),
            "replace a (provider only)",
        );
        ok(
            ports.replace_records(b, Some(&provider_b), Some(&consumer_b)),
            "replace b (provider + consumer)",
        );
        ok(
            ports.replace_records(c, None, Some(&consumer_c)),
            "replace c (consumer only)",
        );

        let stored = ok(ports.load_records(), "load records");
        assert_eq!(stored.providers.len(), 2);
        assert_eq!(stored.consumers.len(), 2);
        let stored_a = some(
            stored.providers.iter().find(|r| r.installation() == a),
            "provider a",
        );
        assert_eq!(stored_a.provided(), provider_a.provided());
        let stored_b = some(
            stored.providers.iter().find(|r| r.installation() == b),
            "provider b",
        );
        assert_eq!(stored_b.provided(), provider_b.provided());
        let stored_b_consumer = some(
            stored.consumers.iter().find(|r| r.installation() == b),
            "consumer b",
        );
        assert_eq!(stored_b_consumer.required(), consumer_b.required());
        let stored_c = some(
            stored.consumers.iter().find(|r| r.installation() == c),
            "consumer c",
        );
        assert_eq!(stored_c.required(), consumer_c.required());

        // 升级 = 整组替换（§40.2：不得与新面叠加）——b 的提供面替换后
        // 只含新 interface，consumer 记录保持不变。
        let upgraded_b = provider_record(b, &[iface("acme:svc", "checkout", 1, 2, 0)]);
        ok(
            ports.replace_records(b, Some(&upgraded_b), Some(&consumer_b)),
            "replace b surface",
        );
        let stored = ok(ports.load_records(), "load after upgrade");
        assert_eq!(stored.providers.len(), 2, "replace must not merge surfaces");
        let stored_b = some(
            stored.providers.iter().find(|r| r.installation() == b),
            "provider b after upgrade",
        );
        assert_eq!(
            stored_b.provided(),
            &BTreeSet::from([iface("acme:svc", "checkout", 1, 2, 0)])
        );
        assert_eq!(stored.consumers.len(), 2);
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_replace_with_empty_records_removes_installation() {
        // §40.2：provider/consumer 均为 None = 全删（deactivation /
        // 激活失败清理）；空集替换不影响其它安装的记录。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-empty");
        let a = create_installation(&ports, &component).await;
        let b = create_installation(&ports, &component).await;
        ok(
            ports.replace_records(
                a,
                Some(&provider_record(
                    a,
                    &[iface("acme:svc", "checkout", 1, 0, 0)],
                )),
                None,
            ),
            "replace a",
        );
        ok(
            ports.replace_records(
                b,
                None,
                Some(&consumer_record(
                    b,
                    &[requirement("acme:svc", "checkout", "^1.0.0")],
                )),
            ),
            "replace b",
        );
        ok(ports.replace_records(a, None, None), "clear a");
        let stored = ok(ports.load_records(), "load after clearing a");
        assert!(stored.providers.is_empty());
        assert_eq!(stored.consumers.len(), 1);
        assert_eq!(stored.consumers[0].installation(), b);
        ok(ports.replace_records(b, None, None), "clear b");
        let stored = ok(ports.load_records(), "load after clearing b");
        assert!(stored.providers.is_empty());
        assert!(stored.consumers.is_empty());
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_load_returns_empty_on_fresh_database() {
        // §40.2 恢复输入：缺失（无记录）→ 空集，不报错。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let stored = ok(ports.load_records(), "load on fresh db");
        assert!(stored.providers.is_empty());
        assert!(stored.consumers.is_empty());
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_replace_is_atomic_when_mid_transaction_fails() {
        // §18.5 fault-injection：触发器确定性构造 replace 事务**中途**失败
        //（DELETE 已执行、INSERT 被 RAISE(ABORT) 打断）——事务整体回滚，
        // 不存在"半条记录 / 新旧并存"的中间观。
        let dir = tempdir();
        let db_path = data_root(dir.path()).db_path();
        {
            let conn = ok(
                crate::migration::open_authoritative_db(&db_path),
                "raw open (test setup)",
            );
            ok(
                conn.execute_batch(
                    "CREATE TRIGGER graph_fail_inject
                     BEFORE INSERT ON graph_provider_records
                     WHEN NEW.provided LIKE '%graph-fail%'
                     BEGIN
                         SELECT RAISE(ABORT, 'injected graph failure');
                     END;",
                ),
                "create fault injection trigger",
            );
        }
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-atomic");
        let a = create_installation(&ports, &component).await;
        let original = provider_record(a, &[iface("acme:svc", "checkout", 1, 0, 0)]);
        let consumer = consumer_record(a, &[requirement("acme:svc", "checkout", "^1.0.0")]);
        ok(
            ports.replace_records(a, Some(&original), Some(&consumer)),
            "seed records",
        );
        // 触发失败：provider 面含 marker interface（触发器命中）。
        let failing = provider_record(a, &[iface("acme:svc", "graph-fail", 9, 0, 0)]);
        let result = ports.replace_records(a, Some(&failing), None);
        assert!(
            matches!(result, Err(GraphStoreError::Storage(_))),
            "injected mid-transaction failure must surface: {result:?}"
        );
        // 无半状态：provider 仍是 original、consumer 仍在（整体回滚）。
        let stored = ok(ports.load_records(), "load after failed replace");
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(stored.providers[0].provided(), original.provided());
        assert_eq!(stored.consumers.len(), 1);
        assert_eq!(stored.consumers[0].required(), consumer.required());
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_load_fails_closed_on_corrupt_provider_json() {
        // 损坏（非法 JSON）→ CorruptState fail closed，绝不静默跳过
        //（与 scope_from_storage 同模式）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-corrupt");
        let a = create_installation(&ports, &component).await;
        ok(
            ports.replace_records(
                a,
                Some(&provider_record(
                    a,
                    &[iface("acme:svc", "checkout", 1, 0, 0)],
                )),
                None,
            ),
            "seed provider",
        );
        {
            let conn = ok(
                crate::migration::open_authoritative_db(&data_root(dir.path()).db_path()),
                "raw open (test setup)",
            );
            ok(
                conn.execute(
                    "UPDATE graph_provider_records SET provided = '{not-json'
                     WHERE installation_id = ?1",
                    [a.to_string()],
                ),
                "corrupt provided",
            );
        }
        let error = match ports.load_records() {
            Ok(_) => unreachable!("corrupt provider JSON must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, GraphStoreError::Storage(ref source)
                if source.to_string().contains("corrupt")),
            "corruption must surface as GraphStoreError::Storage(CorruptState): {error:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_load_fails_closed_on_empty_provider_set() {
        // provider 的定义是至少提供一个 interface（§13.4 不合法状态不可
        // 表示）：数据库中出现空提供面 = 损坏。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-corrupt");
        let a = create_installation(&ports, &component).await;
        ok(
            ports.replace_records(
                a,
                Some(&provider_record(
                    a,
                    &[iface("acme:svc", "checkout", 1, 0, 0)],
                )),
                None,
            ),
            "seed provider",
        );
        {
            let conn = ok(
                crate::migration::open_authoritative_db(&data_root(dir.path()).db_path()),
                "raw open (test setup)",
            );
            ok(
                conn.execute(
                    "UPDATE graph_provider_records SET provided = '[]'
                     WHERE installation_id = ?1",
                    [a.to_string()],
                ),
                "corrupt provided to empty set",
            );
        }
        let error = match ports.load_records() {
            Ok(_) => unreachable!("empty provider set must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, GraphStoreError::Storage(ref source)
                if source.to_string().contains("corrupt")),
            "empty provider set must surface as CorruptState: {error:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_load_fails_closed_on_unparseable_interface_identifier() {
        // 合法 JSON 但条目无法解析为 InterfaceId（domain 边界解析，
        // §13.3）→ 损坏 fail closed。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-corrupt");
        let a = create_installation(&ports, &component).await;
        ok(
            ports.replace_records(
                a,
                Some(&provider_record(
                    a,
                    &[iface("acme:svc", "checkout", 1, 0, 0)],
                )),
                None,
            ),
            "seed provider",
        );
        {
            let conn = ok(
                crate::migration::open_authoritative_db(&data_root(dir.path()).db_path()),
                "raw open (test setup)",
            );
            ok(
                conn.execute(
                    "UPDATE graph_provider_records SET provided = '[\"bogus\"]'
                     WHERE installation_id = ?1",
                    [a.to_string()],
                ),
                "corrupt provided with unparseable identifier",
            );
        }
        let error = match ports.load_records() {
            Ok(_) => unreachable!("unparseable interface identifier must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, GraphStoreError::Storage(ref source)
                if source.to_string().contains("corrupt")),
            "unparseable identifier must surface as CorruptState: {error:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_records_survive_reopen() {
        // §18.5：已提交事务崩溃后仍然存在（WAL + synchronous FULL）——
        // 关闭后重新打开，记录精确回读（恢复输入，§40.2）。
        let dir = tempdir();
        let component = component_id("graph-durable");
        let (a, b) = {
            let ports = open_ports(dir.path()).await;
            let a = create_installation(&ports, &component).await;
            let b = create_installation(&ports, &component).await;
            ok(
                ports.replace_records(
                    a,
                    Some(&provider_record(
                        a,
                        &[iface("acme:svc", "checkout", 1, 0, 0)],
                    )),
                    None,
                ),
                "replace a",
            );
            ok(
                ports.replace_records(
                    b,
                    None,
                    Some(&consumer_record(
                        b,
                        &[requirement("acme:svc", "checkout", "^1.0.0")],
                    )),
                ),
                "replace b",
            );
            shutdown_ports(ports).await;
            (a, b)
        };
        let ports = open_ports(dir.path()).await;
        let stored = ok(ports.load_records(), "load after reopen");
        assert_eq!(stored.providers.len(), 1);
        assert_eq!(stored.providers[0].installation(), a);
        assert_eq!(
            stored.providers[0].provided(),
            &BTreeSet::from([iface("acme:svc", "checkout", 1, 0, 0)])
        );
        assert_eq!(stored.consumers.len(), 1);
        assert_eq!(stored.consumers[0].installation(), b);
        assert_eq!(
            stored.consumers[0].required(),
            &BTreeSet::from([requirement("acme:svc", "checkout", "^1.0.0")])
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_replace_rejects_unknown_installation() {
        // §17.5：graph 记录锚定安装实例（与 grants 同约束）——安装不存在
        // → typed NotFound，且不产生任何写入。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let ghost = InstallationId::new();
        let record = provider_record(ghost, &[iface("acme:svc", "checkout", 1, 0, 0)]);
        let error = match ports.replace_records(ghost, Some(&record), None) {
            Ok(_) => unreachable!("unknown installation must be rejected"),
            Err(error) => error,
        };
        match error {
            GraphStoreError::Storage(source) => {
                assert!(source.to_string().contains("not found"));
            }
        }
        let stored = ok(ports.load_records(), "load");
        assert!(stored.providers.is_empty());
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn graph_replace_rejects_record_installation_mismatch() {
        // §40.2 身份可追溯：传入记录的 installation 与替换键不一致 =
        // 调用方契约违反（InvalidArgument，fail closed）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("graph-mismatch");
        let a = create_installation(&ports, &component).await;
        let other = InstallationId::new();
        let record = provider_record(other, &[iface("acme:svc", "checkout", 1, 0, 0)]);
        let error = match ports.replace_records(a, Some(&record), None) {
            Ok(_) => unreachable!("mismatched record must be rejected"),
            Err(error) => error,
        };
        match error {
            GraphStoreError::Storage(source) => {
                assert!(
                    source
                        .to_string()
                        .contains("does not match replacement key")
                );
            }
        }
        let stored = ok(ports.load_records(), "load");
        assert!(stored.providers.is_empty());
        shutdown_ports(ports).await;
    }

    // ------------------------------------------------------------------
    // 0.3.0 Stateful Runtime（§41.2）：state/config/secret 端口接线测试
    //（真实 executor + tempdir；与 application/tests/stateful_e2e.rs 同模式）
    // ------------------------------------------------------------------

    fn state_key(name: &str) -> StateKey {
        ok(StateKey::new(name), "state key")
    }

    fn state_value(bytes: &[u8]) -> StateValue {
        ok(StateValue::new(bytes.to_vec()), "state value")
    }

    #[tokio::test]
    async fn state_cas_roundtrip_establishes_schema_version() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("state-demo")).await;
        let key = state_key("counter");
        let v1 = StateSchemaVersion::from_u32(1);

        // 空 store：点读 None + schema 版本 None（§41.3）。
        assert_eq!(ok(ports.get(installation, &key), "get empty"), None);
        assert_eq!(
            ok(ports.schema_version(installation), "schema version empty"),
            None
        );

        // 首次写入建立版本（§41.2 atomic update）。
        ok(
            StateStorePort::put(&ports, installation, &key, v1, &state_value(b"1")),
            "put",
        );
        assert_eq!(
            ok(ports.get(installation, &key), "get"),
            Some(state_value(b"1"))
        );
        assert_eq!(
            ok(ports.schema_version(installation), "schema version"),
            Some(v1)
        );

        // 版本不符 → typed mismatch（§41.3），不写入。
        let mismatch = err(
            StateStorePort::put(
                &ports,
                installation,
                &key,
                StateSchemaVersion::from_u32(2),
                &state_value(b"2"),
            ),
            "put mismatch",
        );
        assert!(
            matches!(
                mismatch,
                StateStoreError::SchemaVersionMismatch {
                    current: Some(current),
                    requested,
                    ..
                } if current.as_u32() == 1 && requested.as_u32() == 2
            ),
            "version mismatch must be typed"
        );

        // 删除：键不存在 → NotFound（WIT not-found）。
        ok(StateStorePort::delete(&ports, installation, &key), "delete");
        assert_eq!(ok(ports.get(installation, &key), "get after delete"), None);
        let missing = err(
            StateStorePort::delete(&ports, installation, &key),
            "delete again",
        );
        assert!(
            matches!(missing, StateStoreError::NotFound(_)),
            "delete of absent key must be NotFound"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn state_transaction_begin_put_commit_is_atomic() {
        // §41.2 MUST all-or-nothing：begin → tx_put → tx_get（一致性快照
        // 含自身未提交写入）→ commit 后事务外读回；提交前事务外不可见。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("state-tx")).await;
        let v1 = StateSchemaVersion::from_u32(1);
        ok(
            StateStorePort::put(
                &ports,
                installation,
                &state_key("seed"),
                v1,
                &state_value(b"0"),
            ),
            "seed put",
        );

        let tx = ok(ports.begin_transaction(installation, v1), "begin");
        ok(
            ports.tx_put(
                tx,
                installation,
                &state_key("jobs/1"),
                &state_value(b"queued"),
            ),
            "tx put",
        );
        assert_eq!(
            ok(
                ports.tx_get(tx, installation, &state_key("jobs/1")),
                "tx get"
            ),
            Some(state_value(b"queued"))
        );
        // 事务窗口排他（§18.2 单连接）：进行中事务期间点读（事务外命令）
        // 被拒绝——一致性快照经 tx_get 观察，事务外观察在 commit 后。
        let conflict = err(
            ports.get(installation, &state_key("jobs/1")),
            "point read during transaction window",
        );
        assert!(
            matches!(conflict, StateStoreError::TransactionConflict(_)),
            "point reads are excluded during an open transaction"
        );
        ok(ports.commit(tx), "commit");
        assert_eq!(
            ok(
                ports.get(installation, &state_key("jobs/1")),
                "get after commit"
            ),
            Some(state_value(b"queued"))
        );

        // 已终止事务继续操作 → TransactionConflict（WIT conflict）。
        let conflict = err(
            ports.tx_put(tx, installation, &state_key("after"), &state_value(b"x")),
            "tx put after commit",
        );
        assert!(
            matches!(conflict, StateStoreError::TransactionConflict(_)),
            "operation on terminated transaction must conflict"
        );
        let conflict = err(ports.commit(tx), "double commit");
        assert!(matches!(conflict, StateStoreError::TransactionConflict(_)));
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn state_transaction_abort_discards_staged_writes() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("state-abort")).await;
        let v1 = StateSchemaVersion::from_u32(1);
        ok(
            StateStorePort::put(
                &ports,
                installation,
                &state_key("seed"),
                v1,
                &state_value(b"0"),
            ),
            "seed put",
        );

        let tx = ok(ports.begin_transaction(installation, v1), "begin");
        ok(
            ports.tx_put(tx, installation, &state_key("staged"), &state_value(b"x")),
            "tx put",
        );
        ok(ports.abort(tx), "abort");
        // 暂存写入不生效（WIT abort）；已终止事务的 abort 是 no-op。
        assert_eq!(
            ok(
                ports.get(installation, &state_key("staged")),
                "get after abort"
            ),
            None
        );
        ok(ports.abort(tx), "abort again is no-op");
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn state_migration_transaction_advances_marker_atomically() {
        // §20.5 / §41.3：显式 migration 事务 forward-only；commit 时
        // store schema 版本与数据在同一事务内推进。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("state-migrate")).await;
        let v1 = StateSchemaVersion::from_u32(1);
        let v2 = StateSchemaVersion::from_u32(2);

        // 空 store 不可迁移（§20.5：InvalidArgument）。
        let invalid = err(
            ports.begin_migration_transaction(installation, v2),
            "migrate empty store",
        );
        assert!(
            matches!(invalid, StateStoreError::InvalidArgument(_)),
            "empty store migration must be rejected"
        );

        // 建立 v1（常规事务路径）。
        let tx = ok(ports.begin_transaction(installation, v1), "begin");
        ok(
            ports.tx_put(tx, installation, &state_key("v1-key"), &state_value(b"old")),
            "tx put",
        );
        ok(ports.commit(tx), "commit");

        // 非前进（<= 当前）→ SchemaVersionMismatch（forward-only，WIT）。
        let backwards = err(
            ports.begin_migration_transaction(installation, v1),
            "migrate to same version",
        );
        assert!(
            matches!(backwards, StateStoreError::SchemaVersionMismatch { .. }),
            "non-forward migration must be rejected"
        );

        // 显式 migration 到 v2：guest 写新形态 → 原子提交。
        let tx = ok(
            ports.begin_migration_transaction(installation, v2),
            "begin migration",
        );
        ok(
            ports.tx_put(
                tx,
                installation,
                &state_key("schema-v2"),
                &state_value(b"new-shape"),
            ),
            "guest write",
        );
        ok(ports.commit(tx), "commit migration");
        // §41.3：版本与数据同事务推进。
        assert_eq!(
            ok(ports.schema_version(installation), "schema version"),
            Some(v2)
        );
        assert_eq!(
            ok(
                ports.get(installation, &state_key("schema-v2")),
                "migrated value"
            ),
            Some(state_value(b"new-shape"))
        );
        assert_eq!(
            ok(
                ports.get(installation, &state_key("v1-key")),
                "old value intact"
            ),
            Some(state_value(b"old"))
        );
        // 迁移后常规写必须绑定 v2。
        let mismatch = err(
            StateStorePort::put(
                &ports,
                installation,
                &state_key("late"),
                v1,
                &state_value(b"x"),
            ),
            "put at stale version",
        );
        assert!(matches!(
            mismatch,
            StateStoreError::SchemaVersionMismatch { .. }
        ));
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn component_config_put_reads_back_monotonic_revision() {
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("config-demo")).await;
        let value = |bytes: &[u8]| ok(ConfigValue::new(bytes.to_vec()), "config value");

        // 未就绪：尚无已校验配置 → None（config.wit 无 not-found）。
        assert_eq!(
            ok(
                ComponentConfigStorePort::snapshot(&ports, installation),
                "snapshot empty"
            ),
            None
        );

        let r1 = ok(
            ComponentConfigStorePort::put(
                &ports,
                installation,
                ConfigFormat::Json,
                ConfigSchemaVersion::from_u32(1),
                &value(b"{\"worker\":1}"),
            ),
            "config put 1",
        );
        assert_eq!(r1, ConfigRevision::from_u64(1));
        let r2 = ok(
            ComponentConfigStorePort::put(
                &ports,
                installation,
                ConfigFormat::Toml,
                ConfigSchemaVersion::from_u32(2),
                &value(b"worker = 1"),
            ),
            "config put 2",
        );
        assert_eq!(r2, ConfigRevision::from_u64(2));
        let snapshot = ok(
            ComponentConfigStorePort::snapshot(&ports, installation),
            "snapshot",
        );
        let snapshot = ok(snapshot.ok_or("missing snapshot"), "snapshot record");
        assert_eq!(snapshot.revision(), ConfigRevision::from_u64(2));
        assert_eq!(snapshot.value().as_slice(), b"worker = 1");
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn secret_store_put_get_roundtrip_ciphertext_is_opaque() {
        // §16.6：密文 BLOB 原样落库（storage 不解密、不解释、不回显内容）；
        // 明文绝不进入本层——本测试全程只接触密文与元数据。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("secret-demo")).await;
        let name = || ok(SecretName::new("db-password"), "secret name");

        let ciphertext = vec![0x13, 0x37, 0xAB, 0xFF, 0x00];
        let v1 = ok(
            SecretStorePort::put(
                &ports,
                installation,
                &name(),
                ciphertext,
                "database credential",
            ),
            "secret put",
        );
        assert_eq!(v1, SecretVersion::from_u64(1));
        // 轮换：版本递增（insert or replace，§41.2）。
        let rotated = vec![0x42; 16];
        let v2 = ok(
            SecretStorePort::put(
                &ports,
                installation,
                &name(),
                rotated.clone(),
                "database credential",
            ),
            "secret rotate",
        );
        assert_eq!(v2, SecretVersion::from_u64(2));

        let record = ok(ports.ciphertext(installation, &name()), "ciphertext");
        let record = ok(record.ok_or("missing secret record"), "record");
        assert_eq!(record.name, name());
        assert_eq!(record.version, SecretVersion::from_u64(2));
        assert_eq!(record.ciphertext, rotated);

        // list：名称 + 版本，不含值（§41.2 防泄漏）。
        let listed = ok(ports.list(installation), "list");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name(), &name());
        assert_eq!(listed[0].version(), SecretVersion::from_u64(2));

        // 空密文 → InvalidArgument（结构性校验：存储侧硬上限，§41.2）。
        let invalid = err(
            SecretStorePort::put(&ports, installation, &name(), Vec::new(), "d"),
            "empty ciphertext",
        );
        assert!(
            matches!(invalid, SecretStoreError::InvalidArgument(_)),
            "empty ciphertext must be rejected"
        );

        ok(
            SecretStorePort::delete(&ports, installation, &name()),
            "delete",
        );
        assert_eq!(
            ok(ports.ciphertext(installation, &name()), "after delete"),
            None
        );
        let missing = err(
            SecretStorePort::delete(&ports, installation, &name()),
            "delete again",
        );
        assert!(
            matches!(missing, SecretStoreError::NotFound(_)),
            "delete of absent secret must be NotFound"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn secret_grant_names_filter_grants_table_by_capability_face() {
        // §17.3 "secret names" scope 维度：名称范围经 grants 表 scope 承载
        //（JSON 规范化名称集，§13.3 与 grant scope / graph 记录同模式）；
        // 能力面之外不构成名称 grant（deny-by-default，§17.2）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("grant-demo")).await;
        let secret_scope = || {
            ok(
                CapabilityScope::new(ok(
                    serde_json::to_string(&["db-password".to_owned(), "api-key".to_owned()]),
                    "serialize scope",
                )),
                "capability scope",
            )
        };
        ok(
            ports
                .executor
                .replace_grants(
                    installation,
                    vec![
                        (
                            ok(CapabilityId::new("operune:secret/secret"), "capability"),
                            secret_scope(),
                        ),
                        (
                            ok(CapabilityId::new("wasi:cli/run"), "capability"),
                            ok(CapabilityScope::new("run"), "scope"),
                        ),
                    ],
                    audit("grant secret names"),
                )
                .await,
            "replace grants",
        );

        let granted = ok(ports.granted_names(installation), "granted names");
        let names: Vec<&str> = granted.iter().map(|name| name.as_str()).collect();
        assert_eq!(names, vec!["api-key", "db-password"]);

        // 整体替换撤销后 → 空集（deny-by-default，§17.2）。
        ok(
            ports
                .executor
                .replace_grants(installation, Vec::new(), audit("revoke grants"))
                .await,
            "revoke grants",
        );
        let granted = ok(ports.granted_names(installation), "granted after revoke");
        assert!(granted.is_empty());
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn secret_grant_names_fail_closed_on_corrupt_scope() {
        // 损坏（非法 JSON）→ 存储损坏 fail closed，绝不静默跳过（与
        // scope_from_storage / graph 记录同模式，§13.3）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("grant-corrupt")).await;
        ok(
            ports
                .executor
                .replace_grants(
                    installation,
                    vec![(
                        ok(CapabilityId::new("operune:secret/secret"), "capability"),
                        ok(CapabilityScope::new("[\"ok-name\"]"), "scope"),
                    )],
                    audit("seed secret grant"),
                )
                .await,
            "seed grant",
        );
        {
            let conn = ok(
                crate::migration::open_authoritative_db(&data_root(dir.path()).db_path()),
                "raw open (test setup)",
            );
            ok(
                conn.execute(
                    "UPDATE grants SET scope = '{not-json' WHERE installation_id = ?1",
                    [installation.to_string()],
                ),
                "corrupt scope",
            );
        }
        let error = err(ports.granted_names(installation), "granted names");
        assert!(
            matches!(error, GrantError::Storage(ref source)
                if source.to_string().contains("corrupt")),
            "corrupt secret grant scope must fail closed: {error:?}"
        );
        shutdown_ports(ports).await;
    }

    #[tokio::test]
    async fn stateful_audit_events_map_to_component_lifecycle_rows() {
        // §41.2 audit MUST：0.3 事件落库为 component-lifecycle 审计行
        //（audit.rs 文档：与 to_storage_audit 同模式）；metadata-only，
        // 值绝不进入审计（§16.6）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let installation = create_installation(&ports, &component_id("audit-demo")).await;
        let key = state_key("k");
        ok(
            StatefulAuditPort::append(
                &ports,
                StatefulAuditEvent::StateRead {
                    installation,
                    key: key.clone(),
                },
            ),
            "append state read",
        );
        ok(
            StatefulAuditPort::append(
                &ports,
                StatefulAuditEvent::StateCasApplied {
                    installation,
                    key: key.clone(),
                },
            ),
            "append cas applied",
        );
        ok(
            StatefulAuditPort::append(
                &ports,
                StatefulAuditEvent::StateTxCommitted {
                    installation,
                    schema_version: StateSchemaVersion::from_u32(1),
                },
            ),
            "append tx committed",
        );
        ok(
            StatefulAuditPort::append(
                &ports,
                StatefulAuditEvent::SecretRotated {
                    installation,
                    name: ok(SecretName::new("db-password"), "secret name"),
                    version: SecretVersion::from_u64(1),
                },
            ),
            "append secret rotated",
        );
        ok(
            StatefulAuditPort::append(
                &ports,
                StatefulAuditEvent::ConfigFailed {
                    installation,
                    operation: "put",
                    reason: "corrupt",
                },
            ),
            "append config failed",
        );

        let events = ok(ports.executor.list_audit_recent(10).await, "list audit");
        let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
        for expected in [
            "state-read",
            "state-cas-applied",
            "state-tx-committed",
            "secret-rotated",
            "config-failed",
        ] {
            assert!(
                actions.contains(&expected),
                "audit row for {expected} missing"
            );
            // 0.3 事件全部映射为 component-lifecycle 类别（audit.rs 文档；
            // 安装辅助调用还写入 Artifact 类别的行，故只检查本次追加的
            // 事件行）。
            let row = some(
                events.iter().find(|event| event.action == expected),
                "audit row",
            );
            assert_eq!(
                row.category,
                AuditCategory::ComponentLifecycle,
                "stateful audit row {expected} must use the component-lifecycle category"
            );
        }
        // 失败类事件 outcome=failure。
        assert!(
            events.iter().any(|event| {
                event.action == "config-failed" && event.outcome == AuditOutcome::Failure
            }),
            "config-failed row must have failure outcome"
        );
        shutdown_ports(ports).await;
    }

    // ------------------------------------------------------------------
    // 卸载（§39.2 remove / §42.4）——真实 executor 端到端
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn uninstall_store_removes_everything_on_real_executor() {
        // §39.2 remove / §42.4 端到端（真实 executor）：安装实例的全部
        // Core 元数据（grants / active / 版本绑定 / graph 记录 /
        // state/config/secret / installation 行）在单事务中删除；artifact
        // 保留（§18.7）；audit 与删除同事务落盘（§18.7 fail closed）；
        // 重复卸载 → NotFound；同一 digest 全新安装 → 新的 InstallationId
        //（§19.4）。
        let dir = tempdir();
        let ports = open_ports(dir.path()).await;
        let component = component_id("uninstall-demo");
        let version = version("1.0.0");
        let bytes = b"uninstall component bytes".to_vec();
        let (digest, installation) = install_v1(&ports, &component, version, bytes).await;

        // 铺满关联元数据。
        // grants（§17.5）。
        let grant = InstallationGrant {
            capability: ok(CapabilityId::new("wasi:cli/environment"), "capability"),
            scope: GrantScope::Unscoped,
        };
        ok(
            GrantStorePort::replace_grants(&ports, installation, &[grant]),
            "replace grants",
        );
        // graph records（§40.2：provider + consumer 同一安装）。
        ok(
            ports.replace_records(
                installation,
                Some(&provider_record(
                    installation,
                    &[iface("acme:svc", "checkout", 1, 0, 0)],
                )),
                Some(&consumer_record(
                    installation,
                    &[requirement("acme:svc", "checkout", "^1.0.0")],
                )),
            ),
            "replace graph records",
        );
        // state / config / secret（§41.2）。
        let schema_v1 = StateSchemaVersion::from_u32(1);
        ok(
            StateStorePort::put(
                &ports,
                installation,
                &state_key("k"),
                schema_v1,
                &state_value(b"v"),
            ),
            "put state",
        );
        ok(
            ComponentConfigStorePort::put(
                &ports,
                installation,
                ConfigFormat::Json,
                ConfigSchemaVersion::from_u32(1),
                &ok(ConfigValue::new(b"{}".to_vec()), "config value"),
            ),
            "put config",
        );
        ok(
            SecretStorePort::put(
                &ports,
                installation,
                &ok(SecretName::new("db-password"), "secret name"),
                vec![1, 2, 3],
                "metadata",
            ),
            "put secret",
        );

        // 预检：关联数据全部存在。
        assert!(!ok(GrantStorePort::grants_for(&ports, installation), "grants").is_empty());
        let graph = ok(ports.load_records(), "graph records");
        assert!(!graph.providers.is_empty() || !graph.consumers.is_empty());
        assert!(ok(ports.get(installation, &state_key("k")), "state").is_some());
        assert!(
            ok(
                ComponentConfigStorePort::snapshot(&ports, installation),
                "config"
            )
            .is_some()
        );
        assert!(!ok(SecretStorePort::list(&ports, installation), "secret list").is_empty());

        // 卸载（服务侧 audit 事件同事务落盘，§18.7 fail closed）。
        let app_audit = operune_application::ports::AuditEvent::UninstallCompleted {
            installation,
            component_id: component.clone(),
            version,
            digest: Some(digest),
        };
        ok(
            UninstallStorePort::remove_installation(&ports, installation, app_audit.clone()),
            "remove installation",
        );

        // 卸载后：全部相关表无残留（§42.4）。
        assert!(ok(ports.installation(installation), "installation").is_none());
        assert!(ok(ports.list_installations(), "list").is_empty());
        assert!(
            ok(GrantStorePort::grants_for(&ports, installation), "grants").is_empty(),
            "grants gone"
        );
        let graph = ok(ports.load_records(), "graph records");
        assert!(
            graph.providers.is_empty() && graph.consumers.is_empty(),
            "graph records gone"
        );
        assert!(
            ok(ports.get(installation, &state_key("k")), "state").is_none(),
            "state gone"
        );
        assert!(
            ok(
                ComponentConfigStorePort::snapshot(&ports, installation),
                "config"
            )
            .is_none(),
            "config gone"
        );
        assert!(
            ok(SecretStorePort::list(&ports, installation), "secret list").is_empty(),
            "secret gone"
        );
        // artifact 保留（§18.7）：candidate 记录 + 字节 + 版本绑定都在。
        assert!(ok(ports.candidate(digest), "candidate").is_some());
        assert!(ok(ports.artifact_bytes(digest), "artifact bytes").is_some());
        assert!(
            ok(
                ports.resolve_version(&component, version),
                "version binding"
            )
            .is_some()
        );
        // audit 同事务落盘（§18.7）。
        let events = ok(ports.executor.list_audit_recent(1000).await, "audit recent");
        assert!(
            events
                .iter()
                .any(|event| event.action == "uninstall-completed"),
            "uninstall-completed audit row must be durable"
        );

        // 重复卸载 → RegistryError::NotFound（显式错误，不静默）。
        let error = err(
            UninstallStorePort::remove_installation(&ports, installation, app_audit),
            "repeat remove",
        );
        assert!(
            matches!(error, RegistryError::NotFound(_)),
            "repeat uninstall must be NotFound, got {error:?}"
        );

        // 同一 digest 全新安装 → 新的 InstallationId（§19.4：身份不跨
        // 卸载复用；§18.7：artifact 仍可用）。
        let (_, second) = install_v1(
            &ports,
            &component,
            version,
            b"uninstall component bytes".to_vec(),
        )
        .await;
        assert_ne!(installation, second);

        shutdown_ports(ports).await;
    }
}
