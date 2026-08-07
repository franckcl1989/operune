//! 0.3.0 Stateful Runtime（§41.2）——`operune:state/config/secret` 三包
//! Component import 的宿主注册（runtime 接线层；§24.2 端口注入的 guest
//! 可见面）。
//!
//! # 机制（wasmtime 36.0.13 源码核实，2026-08-08）
//!
//! bindgen 全量代码生成被 `#![forbid(unsafe_code)]` 阻挡（[`crate::wit_bindings`]
//! §25 裁决一），本模块以 **`LinkerInstance::func_new` 动态注册**实现宿主
//! import：宿主函数签名是 `Fn(StoreContextMut, &[Val], &mut [Val])`，参数/
//! 结果的 canonical ABI 编解码由 wasmtime 动态路径完成——
//! `func/host.rs` 的 `dynamic_params_load`（lift 参数）与 `values.rs` 的
//! `Val::lower`（lower 结果）支持全部 WIT 形状：string 参数经 guest 内存
//! ptr/len 读取，list/record 返回值经 guest `realloc` 写入（0.2.0
//! linked.rs 的"仅 primitive"里程碑边界是桥接侧的保守结论，不适用于本
//! 注册面）。`func_new` 跳过前置类型检查（typecheck 恒 Ok），import 形状
//! 由组件二进制声明，调用期由 canonical ABI 动态校验。
//!
//! # 接线范围（0.3.0 最小闭环，§41.2）
//!
//! - `operune:state/state@0.1.0`：`get`（快照点读）与 `cas`（单键原子
//!   比较-交换）；
//! - `operune:config/config@0.1.0`：`get-config`（原子快照）与
//!   `get-config-version`（轻量变化检测）；
//! - `operune:secret/secret@0.1.0`：`read-secret`（按 grant 读取；明文
//!   只在返回值出现一次，§16.6）与 `list-granted-secrets`（不含值）。
//!
//! # 明确未闭环（工具链/API 限制，如实记录）
//!
//! - **state 事务面**（`begin-transaction` / `state-transaction.*`）未注册：
//!   resource 形态的 import 需要宿主侧 typed resource 注册（
//!   `LinkerInstance::resource*` 的 `ResourceType` + dtor 生命周期），bindgen
//!   被 §25 裁决一阻挡；动态 `func_new` 无法安全表达 resource handle 的
//!   宿主 table/dtor。带此类 import 的组件以确定性 link 错误失败
//!   （deny-by-default，§17.2/§19.5）；
//! - **schema version 绑定**（state get/cas）：以 store 当前版本为绑定
//!   （[`crate::state::StateService::schema_binding_version`]），guest
//!   `declaration` 驱动的绑定在 migration 里程碑接线（见该方法文档）；
//! - **grant 快照过滤**：本层按"composition root 是否注入 services"整体
//!   注册（未注入 = 全部拒绝）；grant scope 对 operune import 的逐能力
//!   过滤属 composition/策略里程碑（§17.3）。
//!
//! # 防泄漏边界（§16.6）
//!
//! secret 明文只在 `read-secret` 的返回值出现一次（Val 编码即 canonical
//! ABI 写入 guest 内存的边界拷贝）；错误枚举、审计、日志均不含值。

use std::sync::Arc;

use operune_domain::{
    ConfigRevision, ConfigSnapshot, InstallationId, SecretName, StateKey, StateValue,
};
use secrecy::ExposeSecret;
use wasmtime::component::{Linker, Val};

use crate::config::ConfigService;
use crate::error::RuntimeExecutionError;
use crate::secret::SecretService;
use crate::state::{CasOutcome, StateError, StateService};

/// 0.3.0 stateful 宿主服务集合（§41.2）：`operune:state/config/secret` 三包
/// Component import 的宿主实现所依赖的用例服务（§24.2 composition root
/// 注入 [`crate::runtime::WasmtimeRuntime::with_stateful_services`]）。
///
/// 三服务共享同一审计/存储注入链（composition root 组装）；本类型只做
/// 聚合，不持有任何 wasmtime 类型（§24.2 分层）。
pub struct StatefulHostServices {
    state: Arc<StateService>,
    config: Arc<ConfigService>,
    secret: Arc<SecretService>,
}

impl StatefulHostServices {
    /// 构造（state + config + secret 用例服务；§24.2 端口注入）。
    pub fn new(
        state: Arc<StateService>,
        config: Arc<ConfigService>,
        secret: Arc<SecretService>,
    ) -> Self {
        Self {
            state,
            config,
            secret,
        }
    }
}

/// 注册三包 import 的宿主定义（`prepare` 期调用；services 未注入时本函数
/// 不被调用——带 operune import 的组件以确定性 link 错误失败，
/// deny-by-default，§17.2/§19.5）。
pub(crate) fn register_stateful_imports(
    linker: &mut Linker<operune_runtime_wasm::StoreHostState>,
    services: &Arc<StatefulHostServices>,
    installation: InstallationId,
) -> Result<(), RuntimeExecutionError> {
    register_config_imports(linker, services, installation)?;
    register_secret_imports(linker, services, installation)?;
    register_state_imports(linker, services, installation)?;
    Ok(())
}

/// linker 定义错误映射（§14.1 封闭 typed；wasmtime 错误经
/// `into_boxed_dyn_error` 装箱为可诊断 source——wasmtime 36 的 anyhow
/// 以 no_std 形态解析（default-features = false），其 `Error` 不实现
/// `std::error::Error`，标准 Box 强转不可用，§19.5 的确定性 link 失败面）。
fn map_link_error(error: wasmtime::Error) -> RuntimeExecutionError {
    RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Execution {
        kind: operune_runtime_wasm::WasmFailure::Unknown,
        source: error.into_boxed_dyn_error(),
    })
}

// ---------------------------------------------------------------------------
// operune:config/config@0.1.0（config.wit：guest 只读；写侧不在契约内）
// ---------------------------------------------------------------------------

/// `operune:config/config@0.1.0` import 的宿主定义：`get-config`（原子
/// 快照）与 `get-config-version`（轻量变化检测，side-effect-free）。
fn register_config_imports(
    linker: &mut Linker<operune_runtime_wasm::StoreHostState>,
    services: &Arc<StatefulHostServices>,
    installation: InstallationId,
) -> Result<(), RuntimeExecutionError> {
    let mut iface = linker
        .instance("operune:config/config@0.1.0")
        .map_err(map_link_error)?;
    iface
        .func_new("get-config", {
            let services = Arc::clone(services);
            move |_store, _params, results| {
                if let Some(result) = results.first_mut() {
                    *result = config_get_config(&services, installation);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    iface
        .func_new("get-config-version", {
            let services = Arc::clone(services);
            move |_store, _params, results| {
                if let Some(result) = results.first_mut() {
                    *result = config_get_config_version(&services, installation);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    Ok(())
}

/// `get-config` 的宿主实现：`result<config-snapshot, config-error>`（原子
/// 快照：revision + 值来自同一次读取，config.wit）。
fn config_get_config(services: &StatefulHostServices, installation: InstallationId) -> Val {
    match services.config.snapshot(installation) {
        Ok(snapshot) => Val::Result(Ok(Some(Box::new(config_snapshot_val(&snapshot))))),
        Err(error) => config_error_val(config_error_name(&error)),
    }
}

/// `get-config-version` 的宿主实现：`result<config-version, config-error>`
///（轻量变化检测，side-effect-free）。
fn config_get_config_version(services: &StatefulHostServices, installation: InstallationId) -> Val {
    match services.config.version(installation) {
        Ok(revision) => Val::Result(Ok(Some(Box::new(config_version_val(revision))))),
        Err(error) => config_error_val(config_error_name(&error)),
    }
}

/// WIT `config-snapshot` record（version: config-version + value:
/// config-value）。
fn config_snapshot_val(snapshot: &ConfigSnapshot) -> Val {
    Val::Record(vec![
        (
            "version".to_owned(),
            config_version_val(snapshot.revision()),
        ),
        (
            "value".to_owned(),
            Val::Record(vec![(
                "data".to_owned(),
                u8_list_val(snapshot.value().as_slice()),
            )]),
        ),
    ])
}

/// WIT `config-version` record（revision: u64）。
fn config_version_val(revision: ConfigRevision) -> Val {
    Val::Record(vec![("revision".to_owned(), Val::U64(revision.as_u64()))])
}

/// `config-error` 枚举名映射（闭集，config.wit；Store/Audit 透传为
/// internal——WIT 的 guest 可见面只有 not-ready/corrupt/internal）。
fn config_error_name(error: &crate::config::ConfigError) -> &'static str {
    match error {
        crate::config::ConfigError::NotReady => "not-ready",
        crate::config::ConfigError::Corrupt => "corrupt",
        crate::config::ConfigError::Store(_) | crate::config::ConfigError::Audit(_) => "internal",
    }
}

fn config_error_val(name: &'static str) -> Val {
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

// ---------------------------------------------------------------------------
// operune:secret/secret@0.1.0（secret.wit：按 grant 读取；防泄漏 §16.6）
// ---------------------------------------------------------------------------

/// `operune:secret/secret@0.1.0` import 的宿主定义：`read-secret`（明文只
/// 在返回值出现一次）与 `list-granted-secrets`（不含值）。
fn register_secret_imports(
    linker: &mut Linker<operune_runtime_wasm::StoreHostState>,
    services: &Arc<StatefulHostServices>,
    installation: InstallationId,
) -> Result<(), RuntimeExecutionError> {
    let mut iface = linker
        .instance("operune:secret/secret@0.1.0")
        .map_err(map_link_error)?;
    iface
        .func_new("read-secret", {
            let services = Arc::clone(services);
            move |_store, params, results| {
                if let Some(result) = results.first_mut() {
                    *result = secret_read_secret(&services, installation, params);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    iface
        .func_new("list-granted-secrets", {
            let services = Arc::clone(services);
            move |_store, _params, results| {
                if let Some(result) = results.first_mut() {
                    *result = secret_list_granted_secrets(&services, installation);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    Ok(())
}

/// `read-secret` 的宿主实现：`result<secret-value, secret-error>`。
///
/// 防泄漏契约（§16.6 / secret.wit）：明文经 `SecretBytes::expose_secret`
/// 只在本返回值出现一次（Val 编码即 canonical ABI 写入 guest 内存的边界
/// 拷贝）；错误枚举与审计不含值。`denied` 合并"无权限/名称不存在"。
fn secret_read_secret(
    services: &StatefulHostServices,
    installation: InstallationId,
    params: &[Val],
) -> Val {
    let Some(name_text) = record_string_field(params.first(), "value") else {
        return secret_error_val("internal");
    };
    let Ok(name) = SecretName::new(name_text) else {
        return secret_error_val("invalid-name");
    };
    match services.secret.read_secret(installation, &name) {
        Ok(plaintext) => Val::Result(Ok(Some(Box::new(Val::Record(vec![(
            "data".to_owned(),
            u8_list_val(plaintext.expose_secret()),
        )]))))),
        Err(error) => secret_error_val(secret_error_name(&error)),
    }
}

/// `list-granted-secrets` 的宿主实现：`result<list<secret-metadata>,
/// secret-error>`（只返回 grant scope 内的名称，不含值；不构成存在性
/// 查询，secret.wit）。
fn secret_list_granted_secrets(
    services: &StatefulHostServices,
    installation: InstallationId,
) -> Val {
    match services.secret.list_granted_secrets(installation) {
        Ok(metadata) => Val::Result(Ok(Some(Box::new(Val::List(
            metadata
                .iter()
                .map(|item| {
                    Val::Record(vec![
                        (
                            "name".to_owned(),
                            Val::Record(vec![(
                                "value".to_owned(),
                                Val::String(item.name().as_str().to_owned()),
                            )]),
                        ),
                        (
                            "version".to_owned(),
                            Val::Record(vec![(
                                "value".to_owned(),
                                Val::U64(item.version().as_u64()),
                            )]),
                        ),
                    ])
                })
                .collect(),
        ))))),
        Err(error) => secret_error_val(secret_error_name(&error)),
    }
}

/// `secret-error` 枚举名映射（闭集，secret.wit；Grant/Store/Audit/Internal
/// 透传为 internal——grant 读取失败属于 host 内部面）。
fn secret_error_name(error: &crate::secret::SecretError) -> &'static str {
    match error {
        crate::secret::SecretError::Denied => "denied",
        crate::secret::SecretError::Unavailable => "unavailable",
        crate::secret::SecretError::Corrupt => "corrupt",
        crate::secret::SecretError::OverBudget => "over-budget",
        crate::secret::SecretError::Grant(_)
        | crate::secret::SecretError::Store(_)
        | crate::secret::SecretError::Audit(_)
        | crate::secret::SecretError::Internal(_) => "internal",
    }
}

fn secret_error_val(name: &'static str) -> Val {
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

// ---------------------------------------------------------------------------
// operune:state/state@0.1.0（state.wit：快照点读 + 单键 CAS；事务面未闭环）
// ---------------------------------------------------------------------------

/// `operune:state/state@0.1.0` import 的宿主定义：`get`（快照点读）与
/// `cas`（单键原子比较-交换）。事务面（`begin-transaction` /
/// `state-transaction.*`）未注册——resource 形态需要 typed resource 注册
///（bindgen 被 §25 裁决一阻挡），见模块文档。
fn register_state_imports(
    linker: &mut Linker<operune_runtime_wasm::StoreHostState>,
    services: &Arc<StatefulHostServices>,
    installation: InstallationId,
) -> Result<(), RuntimeExecutionError> {
    let mut iface = linker
        .instance("operune:state/state@0.1.0")
        .map_err(map_link_error)?;
    iface
        .func_new("get", {
            let services = Arc::clone(services);
            move |_store, params, results| {
                if let Some(result) = results.first_mut() {
                    *result = state_get(&services, installation, params);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    iface
        .func_new("cas", {
            let services = Arc::clone(services);
            move |_store, params, results| {
                if let Some(result) = results.first_mut() {
                    *result = state_cas(&services, installation, params);
                }
                Ok(())
            }
        })
        .map_err(map_link_error)?;
    Ok(())
}

/// `get` 的宿主实现：`result<option<state-value>, state-error>`（快照点读；
/// 绑定 store 当前 schema version，见 [`StateService::schema_binding_version`]）。
fn state_get(services: &StatefulHostServices, installation: InstallationId, params: &[Val]) -> Val {
    let Some(key_text) = record_string_field(params.first(), "value") else {
        return state_error_val("internal");
    };
    let Ok(key) = StateKey::new(key_text) else {
        // invalid-key 在 domain 边界拦截（§13.3 边界解析一次，state.wit）。
        return state_error_val("invalid-key");
    };
    let declared = match services.state.schema_binding_version(installation) {
        Ok(version) => version,
        Err(_) => return state_error_val("internal"),
    };
    match services.state.get(installation, declared, &key) {
        Ok(value) => Val::Result(Ok(Some(Box::new(match value {
            Some(value) => Val::Option(Some(Box::new(state_value_val(&value)))),
            None => Val::Option(None),
        })))),
        Err(error) => state_error_val(state_error_name(&error)),
    }
}

/// `cas` 的宿主实现：`result<cas-outcome, state-error>`（期望值按字节等价
/// 比较；四种组合均可表达，state.wit）。
fn state_cas(services: &StatefulHostServices, installation: InstallationId, params: &[Val]) -> Val {
    let Some(key_text) = record_string_field(params.first(), "value") else {
        return state_error_val("internal");
    };
    let Ok(key) = StateKey::new(key_text) else {
        return state_error_val("invalid-key");
    };
    let expected = match option_state_value(params.get(1)) {
        Ok(value) => value,
        Err(val) => return val,
    };
    let new_value = match option_state_value(params.get(2)) {
        Ok(value) => value,
        Err(val) => return val,
    };
    let declared = match services.state.schema_binding_version(installation) {
        Ok(version) => version,
        Err(_) => return state_error_val("internal"),
    };
    match services.state.cas(
        installation,
        declared,
        &key,
        expected.as_ref(),
        new_value.as_ref(),
    ) {
        Ok(CasOutcome::Applied) => Val::Result(Ok(Some(Box::new(Val::Enum("applied".to_owned()))))),
        Ok(CasOutcome::Rejected) => {
            Val::Result(Ok(Some(Box::new(Val::Enum("rejected".to_owned())))))
        }
        Err(error) => state_error_val(state_error_name(&error)),
    }
}

/// WIT `state-value` record（data: list<u8>）。
fn state_value_val(value: &StateValue) -> Val {
    Val::Record(vec![("data".to_owned(), u8_list_val(value.as_slice()))])
}

/// 解析 `option<state-value>` 参数（None / Some(record{data: list<u8>})）。
///
/// 形状错误（guest 契约违规）→ internal；值体积超限（`StateValue::new`
/// 拒绝）→ over-budget（state.wit）。
fn option_state_value(val: Option<&Val>) -> Result<Option<StateValue>, Val> {
    match val {
        None => Err(state_error_val("internal")),
        Some(Val::Option(None)) => Ok(None),
        Some(Val::Option(Some(inner))) => match state_value_from_val(inner.as_ref()) {
            Ok(value) => Ok(Some(value)),
            Err(ParseError::Shape) => Err(state_error_val("internal")),
            Err(ParseError::Size) => Err(state_error_val("over-budget")),
        },
        Some(_) => Err(state_error_val("internal")),
    }
}

/// 从 `Val` 解析 `state-value` record（形状校验 + 有界字节构造）。
enum ParseError {
    /// 形状与契约不符（guest 契约违规）。
    Shape,
    /// 字节数超出宿主侧上限（over-budget）。
    Size,
}

fn state_value_from_val(val: &Val) -> Result<StateValue, ParseError> {
    let Val::Record(fields) = val else {
        return Err(ParseError::Shape);
    };
    let Some((_, Val::List(items))) = fields.iter().find(|(name, _)| name == "data") else {
        return Err(ParseError::Shape);
    };
    let mut bytes = Vec::with_capacity(items.len());
    for item in items {
        let Val::U8(byte) = item else {
            return Err(ParseError::Shape);
        };
        bytes.push(*byte);
    }
    StateValue::new(bytes).map_err(|_| ParseError::Size)
}

/// `state-error` 枚举名映射（闭集，state.wit；Store/Audit/Internal 透传为
/// internal；invalid-key 在 domain 边界拦截，服务层不产生）。
fn state_error_name(error: &StateError) -> &'static str {
    match error {
        StateError::NotReady => "not-ready",
        StateError::NotFound => "not-found",
        StateError::Conflict => "conflict",
        StateError::Corrupt => "corrupt",
        StateError::OverBudget => "over-budget",
        StateError::UnsupportedSchemaVersion => "unsupported-schema-version",
        StateError::Store(_) | StateError::Audit(_) | StateError::Internal(_) => "internal",
    }
}

fn state_error_val(name: &'static str) -> Val {
    Val::Result(Err(Some(Box::new(Val::Enum(name.to_owned())))))
}

// ---------------------------------------------------------------------------
// 通用 Val 编解码辅助
// ---------------------------------------------------------------------------

/// `list<u8>` 的 Val 编码（WIT bytes 形态）。
pub(crate) fn u8_list_val(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|byte| Val::U8(*byte)).collect())
}

/// 从单个 record 参数提取 string 字段（§13.3 边界解析一次；形状不符 →
/// `None`，调用方按 guest 契约违规处理）。
fn record_string_field(param: Option<&Val>, field: &str) -> Option<String> {
    let Val::Record(fields) = param? else {
        return None;
    };
    let (_, value) = fields.iter().find(|(name, _)| name == field)?;
    match value {
        Val::String(text) => Some(text.clone()),
        _ => None,
    }
}
