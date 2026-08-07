//! wasm 执行边界（§24.2 / §22.2）：application 编排层的注入缝与 Wasmtime
//! 生产实现。
//!
//! # 分层
//!
//! 编排层（install / upgrade / web）只依赖本模块的 typed port
//! （[`WasmRuntime`] / [`CompiledWasm`] / [`PreparedRuntime`] /
//! [`ActiveRuntime`]），不接触任何 wasmtime 类型；`WasmtimeRuntime` 是
//! 生产实现，通过 runtime-wasm 的公开 API（`EngineHandle::engine()` /
//! `StoreHandle::store_mut()` / `ComponentHandle::component()`）构造
//! `wasmtime::component::Linker` 并在 Store 上 instantiate（§22.2；
//! runtime-wasm 文档定义的"集成阶段受控泄漏点"）。
//!
//! # 时序契约（§7.5 / §19.3）
//!
//! 每次不可信执行严格遵循 runtime-wasm 时序：
//! `set_deadline` → `begin_execution` → `store_mut()` 上的
//! instantiate / `Func::call` → `Func::post_return` →
//! `classify_wasm_error`（经 [`crate::error::RuntimeExecutionError`]
//! 的映射）。descriptor 调用使用独立 deadline / 预算
//! （`RuntimeConfig::descriptor_deadline` / `descriptor_budget`，§19.3）。
//!
//! # WASI 集成边界（§19.3 / §7.6 / §17.2）
//!
//! - descriptor-only Store 使用空 Linker（§19.3 零 operational grant）：
//!   任何带 import 的组件在 descriptor 阶段以确定性 link 错误失败
//!   （deny-by-default，§17.2 / §19.5）。descriptor 阶段**绝不 attach WASI**
//!   （§19.3：读取 descriptor 只为目的元数据，不给 guest 正常运行权限）；
//! - runtime candidate 在目标 grant/resource 快照下实例化（§19.3）：
//!   grant 快照中的非空 WASI 能力经 runtime-wasi-p2 的 adapter
//!   （[`operune_runtime_wasi_p2::adapter::WasiContextAdapter`]，实现
//!   [`operune_runtime_wasm::wasi::WasiAdapter`] port）按 grant 构建 WASI
//!   0.2 context 并 attach（零 grant = 零权限 context，§7.6）；attach 失败
//!   即整个 candidate 失败（fail closed，§17.2）。WASI 0.2 世界组装经
//!   [`operune_runtime_wasi_p2::linker::add_to_linker`]（标准
//!   `wasi:cli/imports` 接口，P4：不建立平行接口）。
//!
//! # 0.3.0 Stateful Runtime 接线（§41.2）
//!
//! - **scheduler/event 交付**（本模块）：[`SchedulerRuntimeDelivery`] /
//!   [`EventRuntimeDelivery`] 把运行中的 candidate（[`ActiveRuntime`]）绑定
//!   为 [`crate::ports::SchedulerDeliveryPort`] / [`crate::ports::EventDeliveryPort`]
//!   ——fire/投递时经 Instance Set 有界 lease（§7.3/§7.4）调用 guest 导出的
//!   `operune:scheduler/handler.on-trigger` / `operune:event/handler.on-event`
//!   （动态 `Func::call`，载荷按 handler.wit record 逐字段编码；trap/失败 =
//!   已消费，at-most-once，错误只用于宿主侧观测）；
//! - **state/config/secret import**（[`crate::stateful_imports`]）：Core 提供
//!   的宿主实现经 `LinkerInstance::func_new` 动态注册（bindgen 全量生成被
//!   §25 裁决一阻挡），接入 [`StatefulHostServices`]（StateService /
//!   ConfigService / SecretService；composition root 注入，未注入时带此类
//!   import 的组件以确定性 link 错误失败，deny-by-default §19.5）。
//!
//! # Safe Rust（§11）
//!
//! 全部调用为 Safe Wasmtime API（`Linker` / `Instance::get_export_index` /
//! `Instance::get_func` / `Func::call` / `Func::post_return` / `Val`），
//! 无 unsafe / FFI（bindgen 全量代码生成被 `forbid(unsafe_code)` 阻挡的
//! §25 裁决见 [`crate::wit_bindings`]）。

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use operune_domain::{EventPayload, InstallationId, TriggerPayload};
use operune_runtime_wasi_p2::adapter::WasiContextAdapter;
use operune_runtime_wasi_p2::linker::add_to_linker;
use operune_runtime_wasm::{
    CallDeadline, ComponentHandle, EngineHandle, InstanceSet, ResourceBudget, StoreFactory,
    StoreHandle, WasiPolicy,
};
use wasmtime::component::{ComponentExportIndex, Func, Instance, InstancePre, Linker, Val};

use crate::contract::{
    ContractValueError, GuestActionError, GuestActionRequest, GuestAssetMetadata,
    GuestComponentDescriptor, GuestDescriptorError, GuestStateDeclaration,
    GuestStateDeclarationError, GuestWebDescriptor, build_action_request_val,
    parse_action_result_val, parse_asset_list_val, parse_component_descriptor_val,
    parse_state_declaration_val, parse_web_descriptor_val,
};
use crate::error::{ErrorSource, RuntimeExecutionError};
use crate::event::DeliveredEvent;
use crate::model::{
    ContractSurface, GrantSnapshot, RuntimeConfig, WebAssetEntry, WebAssetPath, WebManifestData,
    WebManifestFeatures,
};
use crate::ports::{
    ConfigPort, EventDeliveryError, EventDeliveryPort, SchedulerDeliveryError,
    SchedulerDeliveryPort,
};
use crate::stateful_imports::StatefulHostServices;

/// 已编译的 Component（§7.2）的 opaque 句柄（编排层不接触 wasmtime 类型）。
pub trait CompiledWasm: Send + Sync {
    /// 生产实现内部访问（`WasmtimeRuntime` 专用）。
    fn as_any(&self) -> &dyn std::any::Any;
    /// 原始字节长度（日志 / 审计用，§19.1 大小事实）。
    fn byte_len(&self) -> u64;
}

/// 已解析 import 图（link 检查通过，§17.2 / §19.5 deny-by-default 的
/// 二进制级强制点）的 opaque 句柄。
pub trait PreparedRuntime: Send + Sync {
    /// 快照绑定的安装实例。
    fn installation(&self) -> InstallationId;
    /// 快照的 grant / resource 视图。
    fn grants(&self) -> &GrantSnapshot;
    /// 生产实现内部访问（`WasmtimeRuntime` 专用）。
    fn as_any(&self) -> &dyn std::any::Any;
}

/// 运行中的 runtime candidate / active 版本（§7.3 有界 Instance Set）的
/// opaque 句柄。
pub trait ActiveRuntime: Send + Sync {
    /// 生产实现内部访问（`WasmtimeRuntime` 专用；与 [`CompiledWasm`] /
    /// [`PreparedRuntime`] 同模式，§24.2 受控泄漏——跨 trait 对象 downcast
    /// 由生产实现的接线面使用）。
    fn as_any(&self) -> &dyn std::any::Any;

    /// readiness / health 验证（§19.3：在真实 grant/resource 环境执行；
    /// 0.1.0 stateless contract——readiness 由实例化完整性 + web manifest
    /// 校验覆盖，本调用验证 Instance Set 可调度；0.3 起扩展为真实健康检查）。
    fn check_readiness(&self) -> Result<(), RuntimeExecutionError>;

    /// 读取 web descriptor + 资产清单（§21.3 激活阶段）。无 Web UI 返回
    /// `None`（§web descriptor：只有携带 Web UI 的 Component 导出）。
    fn read_web_manifest(&self) -> Result<Option<WebManifestData>, RuntimeExecutionError>;

    /// 读取单个资产字节（bounded，§21.3；宿主侧上限在实现内强制）。
    fn read_asset(&self, path: &WebAssetPath) -> Result<Vec<u8>, RuntimeExecutionError>;

    /// 处理一次 bounded backend action（§21.3：同步一次调用，无流 / 长连接）。
    fn invoke_action(&self, request: &GuestActionRequest)
    -> Result<Vec<u8>, RuntimeExecutionError>;

    /// drain（§20.4）：不接新工作；已接受工作允许在有界 deadline 内完成；
    /// deadline 到期后释放 Store 与 Host 资源。`self` 按值消费（drop 即释放）。
    fn drain(self: Arc<Self>, deadline: Duration) -> Result<(), RuntimeExecutionError>;
}

/// 运行时候选的实例化计划（§19.3：在目标 grant / resource 快照下实例化）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    /// 计划绑定的安装实例。
    pub installation: InstallationId,
    /// 目标 grant / resource 快照。
    pub grants: GrantSnapshot,
}

/// wasm 执行 port（编排层注入缝）。
pub trait WasmRuntime: Send + Sync {
    /// 同步验证并编译不可信字节（§7.2 / §19.2 阶段二）。
    fn compile(&self, bytes: &[u8]) -> Result<Arc<dyn CompiledWasm>, RuntimeExecutionError>;

    /// 二进制 contract surface（imports/exports，§6.7：不执行 guest 代码）。
    fn contract_surface(
        &self,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<ContractSurface, RuntimeExecutionError>;

    /// 在 descriptor-only Store（§19.3：零 operational grant、独立
    /// deadline/预算）中读取一次 `operune:component` descriptor。
    ///
    /// 调用方（编排层）按 §19.3 对同一 digest 重复调用并比对 canonical
    /// 结果（不一致 = contract violation，candidate 保持 quarantine/failed）。
    fn read_descriptor(
        &self,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<GuestComponentDescriptor, RuntimeExecutionError>;

    /// 0.3.0（§41.2 / §20.5）：在 descriptor-only Store（declaration.wit
    /// 明文：调用时机与约束遵循 §19.3 descriptor 阶段精神）中读取一次
    /// `operune:state/declaration` 的 `get-state-declaration`。
    ///
    /// 组件不导出声明接口 = 无状态组件（`Ok(None)`，0.1 语义保持）。
    /// 编排层按 §19.3 惯例对同一 digest 重复调用并比对 canonical 结果
    ///（不一致 = contract violation，candidate 保持 quarantine/failed）。
    ///
    /// 默认实现返回 `Ok(None)`（组件视为不导出声明接口）——沿用该默认的
    /// 实现（如 web-admin / server 的不可用 runtime 桩）在编译必然失败的
    /// 组件上运行，声明读取不可达；生产与 fake 实现按语义覆写。
    fn read_state_declaration(
        &self,
        _component: &Arc<dyn CompiledWasm>,
    ) -> Result<Option<GuestStateDeclaration>, RuntimeExecutionError> {
        Ok(None)
    }

    /// 解析 import 图（deny-by-default，§17.2 / §19.5）：在目标
    /// grant/resource 快照下检查该组件能否被实例化。失败 = resolution
    /// 类失败（候选保持 Failed，当前 Active 不受污染，§19.2）。
    fn prepare(
        &self,
        component: &Arc<dyn CompiledWasm>,
        plan: &RuntimePlan,
    ) -> Result<Arc<dyn PreparedRuntime>, RuntimeExecutionError>;

    /// 在目标 grant/resource 快照下实例化 runtime candidate（§19.3 /
    /// §20.1）：有界 Instance Set 的每个槽位在同一快照下实例化。
    /// 失败 = readiness 类失败（候选 Failed，§19.3）。
    fn instantiate(
        &self,
        prepared: &Arc<dyn PreparedRuntime>,
    ) -> Result<Arc<dyn ActiveRuntime>, RuntimeExecutionError>;
}

/// 生产实现（§22.2：Safe Wasmtime Component API）。
pub struct WasmtimeRuntime {
    engine: Arc<EngineHandle>,
    config: Arc<dyn ConfigPort>,
    /// 0.3.0（§41.2）：stateful 宿主服务（operune:state/config/secret 三包
    /// import 的宿主实现；`None` = 不注册任何 operune import——带此类
    /// import 的组件以确定性 link 错误失败，deny-by-default §19.5）。
    stateful: Option<Arc<StatefulHostServices>>,
}

/// 生产实现的已编译组件（包装 runtime-wasm 的 [`ComponentHandle`]）。
struct WasmtimeCompiledWasm {
    inner: Arc<ComponentHandle>,
    byte_len: u64,
}

impl CompiledWasm for WasmtimeCompiledWasm {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn byte_len(&self) -> u64 {
        self.byte_len
    }
}

/// 生产实现：编译组件 + link 检查产物。
struct WasmtimePreparedRuntime {
    installation: InstallationId,
    grants: GrantSnapshot,
    pre: InstancePre<operune_runtime_wasm::StoreHostState>,
}

impl PreparedRuntime for WasmtimePreparedRuntime {
    fn installation(&self) -> InstallationId {
        self.installation
    }

    fn grants(&self) -> &GrantSnapshot {
        &self.grants
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// 生产实现：运行中的实例集合（§7.3 有界 Instance Set + 每槽位绑定）。
struct WasmtimeActiveRuntime {
    set: InstanceSet,
    bindings: Vec<std::sync::Mutex<Option<SlotBindings>>>,
    budget: ResourceBudget,
    config: Arc<dyn ConfigPort>,
    in_flight: AtomicUsize,
}

/// 每槽位已解析的导出函数（绑定与槽位 Store 同生命周期；`Func` 自身
/// 携带其所属 Instance 的索引，无需单独保存 Instance 句柄）。
#[derive(Clone)]
struct SlotBindings {
    web_descriptor: Option<Func>,
    assets: Option<Func>,
    actions: Option<Func>,
    /// 0.3.0（§41.2）：scheduler handler 导出（`operune:scheduler/handler`
    /// 的 `on-trigger`，guest export——Core 在 fire 时刻同步调用）。
    scheduler_handler: Option<Func>,
    /// 0.3.0（§41.2）：event handler 导出（`operune:event/handler` 的
    /// `on-event`，guest export——Core 在投递时刻同步调用）。
    event_handler: Option<Func>,
}

/// in-flight 调用计数守卫（drain 等待的观测点，§20.4）。
struct InFlightGuard<'a> {
    counter: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::Relaxed);
    }
}

impl WasmtimeRuntime {
    /// 构造（注入共享 Engine 与 config 快照来源；Engine 由 composition
    /// root 创建一次，§7.1）。
    pub fn new(engine: Arc<EngineHandle>, config: Arc<dyn ConfigPort>) -> Self {
        Self {
            engine,
            config,
            stateful: None,
        }
    }

    /// 0.3.0：附加 stateful 宿主服务（§41.2）——operune:state/config/secret
    /// 三包 Component import 的宿主实现（StateService / ConfigService /
    /// SecretService，[`StatefulHostServices`]；§24.2 composition root
    /// 注入）。未附加时（默认）本 runtime 不注册任何 operune import——
    /// 带此类 import 的组件以确定性 link 错误失败（deny-by-default，
    /// §17.2/§19.5）。
    pub fn with_stateful_services(mut self, services: Arc<StatefulHostServices>) -> Self {
        self.stateful = Some(services);
        self
    }

    /// 生产实现的内部组件访问（跨 trait 对象 downcast，类型不符 = 内部
    /// 不变量破坏，fail-stop 语义，§14.3）。
    fn real_component<'a>(
        &self,
        component: &'a dyn CompiledWasm,
    ) -> Result<&'a WasmtimeCompiledWasm, RuntimeExecutionError> {
        component
            .as_any()
            .downcast_ref::<WasmtimeCompiledWasm>()
            .ok_or(RuntimeExecutionError::Internal(
                "compiled component is not a WasmtimeCompiledWasm",
            ))
    }

    fn real_prepared<'a>(
        &self,
        prepared: &'a dyn PreparedRuntime,
    ) -> Result<&'a WasmtimePreparedRuntime, RuntimeExecutionError> {
        prepared
            .as_any()
            .downcast_ref::<WasmtimePreparedRuntime>()
            .ok_or(RuntimeExecutionError::Internal(
                "prepared runtime is not a WasmtimePreparedRuntime",
            ))
    }

    fn config_snapshot(&self) -> Result<RuntimeConfig, RuntimeExecutionError> {
        self.config
            .snapshot()
            .map_err(|_| RuntimeExecutionError::ConfigUnavailable)
    }

    /// descriptor-only Store 的实例化（§19.3）：零 operational grant——
    /// 空 Linker；带 import 的组件在此以确定性 link 错误失败
    /// （deny-by-default，§17.2）。WASI 零权限 context 接线是 0.1.0
    /// 集成缺口（见模块文档），闭合后在此构造零权限 Linker。
    fn instantiate_descriptor_store(
        &self,
        component: &wasmtime::component::Component,
        store: &mut StoreHandle,
        deadline: Duration,
    ) -> Result<Instance, RuntimeExecutionError> {
        store
            .set_deadline(CallDeadline::new(deadline))
            .map_err(RuntimeExecutionError::Runtime)?;
        store.begin_execution();
        let linker = Linker::<operune_runtime_wasm::StoreHostState>::new(self.engine.engine());
        let instance = linker
            .instantiate(store.store_mut(), component)
            .map_err(|error| {
                RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
            })?;
        Ok(instance)
    }

    /// 在已实例化的 Store 中查找接口导出并取出其函数。
    fn call_exported_func(
        store: &mut StoreHandle,
        instance: &Instance,
        interface_names: &[&str],
        func_name: &'static str,
    ) -> Result<Func, RuntimeExecutionError> {
        let iface = Self::find_interface(store, instance, interface_names, func_name)?;
        let func_index = instance
            .get_export_index(store.store_mut(), Some(&iface), func_name)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(func_name))?;
        instance
            .get_func(store.store_mut(), func_index)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(func_name))
    }

    /// 按候选实例名查找顶层接口导出（§6.7：实例名不是身份事实源——两种
    /// world 写法都接受）。
    fn find_interface(
        store: &mut StoreHandle,
        instance: &Instance,
        names: &[&str],
        what: &'static str,
    ) -> Result<ComponentExportIndex, RuntimeExecutionError> {
        for name in names {
            if let Some(index) = instance.get_export_index(store.store_mut(), None, name) {
                return Ok(index);
            }
        }
        Err(RuntimeExecutionError::MissingOperuneExport(what))
    }

    /// 可选接口导出查找（无该接口 → `None`，如无 Web UI 的组件）。
    fn optional_interface_func(
        store: &mut StoreHandle,
        instance: &Instance,
        interface_names: &[&str],
        func_name: &'static str,
    ) -> Result<Option<Func>, RuntimeExecutionError> {
        let iface = match Self::find_interface(store, instance, interface_names, func_name) {
            Ok(index) => index,
            Err(_) => return Ok(None),
        };
        let func_index = instance
            .get_export_index(store.store_mut(), Some(&iface), func_name)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(func_name))?;
        instance
            .get_func(store.store_mut(), func_index)
            .map(Some)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(func_name))
    }
}

impl WasmRuntime for WasmtimeRuntime {
    fn compile(&self, bytes: &[u8]) -> Result<Arc<dyn CompiledWasm>, RuntimeExecutionError> {
        let handle = ComponentHandle::new(&self.engine, bytes)?;
        Ok(Arc::new(WasmtimeCompiledWasm {
            inner: Arc::new(handle),
            byte_len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }))
    }

    fn contract_surface(
        &self,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<ContractSurface, RuntimeExecutionError> {
        let real = self.real_component(component.as_ref())?;
        let ty = real.inner.component().component_type();
        let engine = self.engine.engine();
        let imports = ty
            .imports(engine)
            .map(|(name, _)| name.to_owned())
            .collect::<Vec<_>>();
        let exports = ty
            .exports(engine)
            .map(|(name, _)| name.to_owned())
            .collect::<Vec<_>>();
        Ok(ContractSurface { imports, exports })
    }

    fn read_descriptor(
        &self,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<GuestComponentDescriptor, RuntimeExecutionError> {
        let real = self.real_component(component.as_ref())?;
        let config = self.config_snapshot()?;
        // §19.3：descriptor-only Store 使用独立（更严格）预算。
        let mut store = StoreFactory::new(&self.engine)
            .new_store(&config.descriptor_budget)
            .map_err(RuntimeExecutionError::Runtime)?;
        let instance = self.instantiate_descriptor_store(
            real.inner.component(),
            &mut store,
            config.descriptor_deadline,
        )?;
        let func = Self::call_exported_func(
            &mut store,
            &instance,
            &["descriptor", "operune:component/descriptor@0.1.0"],
            "get-descriptor",
        )?;
        prepare_store_call(&mut store, config.descriptor_deadline)?;
        let mut results = [Val::Result(Ok(None))];
        func.call(store.store_mut(), &[], &mut results)
            .map_err(|error| {
                RuntimeExecutionError::from_classified(&mut store, ErrorSource::from(error))
            })?;
        func.post_return(store.store_mut()).map_err(|error| {
            RuntimeExecutionError::from_classified(&mut store, ErrorSource::from(error))
        })?;
        match &results[0] {
            Val::Result(Ok(_)) => parse_component_descriptor_val(&results[0])
                .map_err(RuntimeExecutionError::MalformedGuestData),
            Val::Result(Err(_)) => {
                let guest_error = parse_descriptor_error(&results[0])?;
                Err(RuntimeExecutionError::GuestDescriptorError(guest_error))
            }
            _ => Err(RuntimeExecutionError::MalformedGuestData(
                ContractValueError::ShapeMismatch {
                    field: "get-descriptor",
                    expected: "result",
                },
            )),
        }
    }

    fn read_state_declaration(
        &self,
        component: &Arc<dyn CompiledWasm>,
    ) -> Result<Option<GuestStateDeclaration>, RuntimeExecutionError> {
        let real = self.real_component(component.as_ref())?;
        let config = self.config_snapshot()?;
        // §19.3 精神（declaration.wit 明文）：descriptor-only Store +
        // 独立 deadline / 预算读取声明。
        let mut store = StoreFactory::new(&self.engine)
            .new_store(&config.descriptor_budget)
            .map_err(RuntimeExecutionError::Runtime)?;
        let instance = self.instantiate_descriptor_store(
            real.inner.component(),
            &mut store,
            config.descriptor_deadline,
        )?;
        let Some(func) = Self::optional_interface_func(
            &mut store,
            &instance,
            &["declaration", "operune:state/declaration@0.1.0"],
            "get-state-declaration",
        )?
        else {
            // 无 declaration 导出 = 无状态组件（0.1 语义保持）。
            return Ok(None);
        };
        prepare_store_call(&mut store, config.descriptor_deadline)?;
        let mut results = [Val::Result(Ok(None))];
        func.call(store.store_mut(), &[], &mut results)
            .map_err(|error| {
                RuntimeExecutionError::from_classified(&mut store, ErrorSource::from(error))
            })?;
        func.post_return(store.store_mut()).map_err(|error| {
            RuntimeExecutionError::from_classified(&mut store, ErrorSource::from(error))
        })?;
        match &results[0] {
            Val::Result(Ok(_)) => parse_state_declaration_val(&results[0])
                .map(Some)
                .map_err(RuntimeExecutionError::MalformedGuestData),
            Val::Result(Err(_)) => {
                let guest_error = parse_state_declaration_error(&results[0])?;
                Err(RuntimeExecutionError::GuestStateDeclarationError(
                    guest_error,
                ))
            }
            _ => Err(RuntimeExecutionError::MalformedGuestData(
                ContractValueError::ShapeMismatch {
                    field: "get-state-declaration",
                    expected: "result",
                },
            )),
        }
    }

    fn prepare(
        &self,
        component: &Arc<dyn CompiledWasm>,
        plan: &RuntimePlan,
    ) -> Result<Arc<dyn PreparedRuntime>, RuntimeExecutionError> {
        let real = self.real_component(component.as_ref())?;
        let mut linker = Linker::<operune_runtime_wasm::StoreHostState>::new(self.engine.engine());
        // §7.6 / §17.2 deny-by-default：只有 grant 快照携带 WASI 能力值时
        // 才组装标准 WASI 0.2 世界（runtime-wasi-p2 的 adapter 侧 linker，
        // P4：标准接口）。空能力时保持空 Linker——带 WASI import 的组件以
        // 确定性 link 错误失败（§19.5：不"先运行，失败时 trap"）。
        if !plan.grants.wasi.is_empty() {
            add_to_linker(&mut linker).map_err(|error| {
                RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Execution {
                    kind: operune_runtime_wasm::WasmFailure::Unknown,
                    source: Box::new(error),
                })
            })?;
        }
        // 0.3.0（§41.2）：operune:state/config/secret 三包 import 的宿主
        // 注册——composition root 注入 services 时注册（关闭期按安装实例
        // 绑定）；未注入 = deny-by-default：带此类 import 的组件以确定性
        // link 错误失败（§19.5）。
        if let Some(stateful) = &self.stateful {
            crate::stateful_imports::register_stateful_imports(
                &mut linker,
                stateful,
                plan.installation,
            )?;
        }
        let pre = linker
            .instantiate_pre(real.inner.component())
            .map_err(|error| {
                RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Execution {
                    kind: operune_runtime_wasm::WasmFailure::Unknown,
                    source: ErrorSource::from(error),
                })
            })?;
        Ok(Arc::new(WasmtimePreparedRuntime {
            installation: plan.installation,
            grants: plan.grants.clone(),
            pre,
        }))
    }

    fn instantiate(
        &self,
        prepared: &Arc<dyn PreparedRuntime>,
    ) -> Result<Arc<dyn ActiveRuntime>, RuntimeExecutionError> {
        let real = self.real_prepared(prepared.as_ref())?;
        let config = self.config_snapshot()?;
        let budget = real.grants.budget.clone();
        // §19.3：runtime candidate 在目标 grant/resource 快照下实例化——
        // 非空 WASI 能力经 runtime-wasi-p2 的 adapter（WasiAdapter port，
        // §8.2）执行 attach：per-plan context builder 携带 grant 构建的
        // 能力（§7.6：能力只经显式构建进入 context；零 grant = 零权限）。
        // attach 失败（政策不匹配 / 能力无法满足）→ 整个 candidate 拒绝，
        // fail closed（§17.2），当前 Active 不受污染（§19.2）。
        let set = if real.grants.wasi.is_empty() {
            InstanceSet::new(&self.engine, &budget).map_err(RuntimeExecutionError::Runtime)?
        } else {
            let adapter = WasiContextAdapter::new().with_capabilities(real.grants.wasi.clone());
            InstanceSet::new_with_wasi(&self.engine, &budget, &adapter, &WasiPolicy::p2())
                .map_err(RuntimeExecutionError::Runtime)?
        };
        let capacity = set.capacity();
        let mut bindings: Vec<std::sync::Mutex<Option<SlotBindings>>> =
            (0..capacity).map(|_| std::sync::Mutex::new(None)).collect();

        // 独占全部槽位后逐槽实例化（§7.3 单一执行模型；任一槽位失败 =
        // 整个 candidate 失败，部分创建的 Store 随 InstanceSet 释放）。
        let mut leases = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            leases.push(set.try_dispatch().map_err(map_dispatch_error)?);
        }
        for lease in &mut leases {
            let slot = lease.slot();
            let inner = lease.with_store(|store| {
                prepare_store_call(store, config.readiness_deadline)?;
                let instance = real.pre.instantiate(store.store_mut()).map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
                let web_descriptor = Self::optional_interface_func(
                    store,
                    &instance,
                    &["descriptor"],
                    "get-web-descriptor",
                )?;
                let assets =
                    Self::optional_interface_func(store, &instance, &["assets"], "list-assets")?;
                let actions =
                    Self::optional_interface_func(store, &instance, &["actions"], "handle-action")?;
                // 0.3.0（§41.2）：scheduler/event handler 导出（可选接口——
                // 无 handler 导出的组件在交付时以观测错误表达，不阻碍激活）。
                // 接口名接受两种 world 写法（§6.7 实例名不是身份事实源）：
                // 短名 "handler" 与完整 WIT 名（同 descriptor 查找惯例）。
                let scheduler_handler = Self::optional_interface_func(
                    store,
                    &instance,
                    &["handler", "operune:scheduler/handler@0.1.0"],
                    "on-trigger",
                )?;
                let event_handler = Self::optional_interface_func(
                    store,
                    &instance,
                    &["handler", "operune:event/handler@0.1.0"],
                    "on-event",
                )?;
                let binding = bindings
                    .get_mut(slot)
                    .ok_or(RuntimeExecutionError::Internal("invalid instance slot"))?;
                *binding.get_mut().map_err(|_| {
                    RuntimeExecutionError::Internal("instance slot mutex poisoned")
                })? = Some(SlotBindings {
                    web_descriptor,
                    assets,
                    actions,
                    scheduler_handler,
                    event_handler,
                });
                Ok::<(), RuntimeExecutionError>(())
            })?;
            inner?;
        }
        drop(leases);

        Ok(Arc::new(WasmtimeActiveRuntime {
            set,
            bindings,
            budget,
            config: Arc::clone(&self.config),
            in_flight: AtomicUsize::new(0),
        }))
    }
}

impl WasmtimeActiveRuntime {
    /// 通过槽位租约执行一次调用（有界 dispatch：繁忙 → Busy，§7.4）。
    fn with_lease<R>(
        &self,
        f: impl FnOnce(usize, &mut StoreHandle) -> Result<R, RuntimeExecutionError>,
    ) -> Result<R, RuntimeExecutionError> {
        let mut lease = self.set.try_dispatch().map_err(map_dispatch_error)?;
        let slot = lease.slot();
        lease
            .with_store(|store| f(slot, store))
            .map_err(RuntimeExecutionError::Runtime)?
    }

    /// 当前 call deadline（§7.4 预算；None = 不自动设置，调用方决定）。
    fn call_deadline(&self) -> Option<Duration> {
        self.budget.call_deadline.map(|deadline| deadline.get())
    }

    /// 读取一个槽位的绑定（生产实现专用）。
    fn slot_bindings(&self, slot: usize) -> Result<SlotBindings, RuntimeExecutionError> {
        let binding = self
            .bindings
            .get(slot)
            .ok_or(RuntimeExecutionError::Internal("invalid instance slot"))?;
        let guard = binding
            .lock()
            .map_err(|_| RuntimeExecutionError::Internal("instance slot mutex poisoned"))?;
        guard
            .clone()
            .ok_or(RuntimeExecutionError::Internal("instance slot not bound"))
    }

    fn config_snapshot(&self) -> Result<RuntimeConfig, RuntimeExecutionError> {
        self.config
            .snapshot()
            .map_err(|_| RuntimeExecutionError::ConfigUnavailable)
    }
}

/// 0.3.0（§41.2）——scheduler/event 交付的 guest handler 调用面。
///
/// Core-mediated push（handler.wit 明文）：调用返回即已消费，trap 也视为
/// 已消费（不重投、不计入错过）；错误只用于宿主侧观测。调用时序遵循
/// §7.5：deadline → begin_execution → `Func::call` → post_return →
/// classify（错误映射）。
impl WasmtimeActiveRuntime {
    /// 调用 guest 的 `operune:scheduler/handler.on-trigger`（一次 fire 的
    /// 交付；payload 按 handler.wit `trigger-payload` record 编码）。
    fn invoke_scheduler_handler(
        &self,
        payload: TriggerPayload,
    ) -> Result<(), SchedulerDeliveryError> {
        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        self.with_lease(|slot, store| {
            let bindings = self.slot_bindings(slot)?;
            let Some(handler) = bindings.scheduler_handler else {
                return Err(RuntimeExecutionError::MissingOperuneExport(
                    "scheduler handler",
                ));
            };
            let deadline = self.call_deadline().ok_or(RuntimeExecutionError::Internal(
                "call deadline is required for scheduler delivery",
            ))?;
            prepare_store_call(store, deadline)?;
            let param = build_trigger_payload_val(&payload);
            let mut results: [Val; 0] = [];
            handler
                .call(store.store_mut(), &[param], &mut results)
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            handler.post_return(store.store_mut()).map_err(|error| {
                RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
            })?;
            Ok(())
        })
        .map_err(map_scheduler_delivery_error)
    }

    /// 调用 guest 的 `operune:event/handler.on-event`（一次事件的投递；
    /// payload 按 handler.wit `event` record 编码，dropped 计数透传）。
    fn invoke_event_handler(&self, event: DeliveredEvent) -> Result<(), EventDeliveryError> {
        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        self.with_lease(|slot, store| {
            let bindings = self.slot_bindings(slot)?;
            let Some(handler) = bindings.event_handler else {
                return Err(RuntimeExecutionError::MissingOperuneExport("event handler"));
            };
            let deadline = self.call_deadline().ok_or(RuntimeExecutionError::Internal(
                "call deadline is required for event delivery",
            ))?;
            prepare_store_call(store, deadline)?;
            let param = build_event_val(&event);
            let mut results: [Val; 0] = [];
            handler
                .call(store.store_mut(), &[param], &mut results)
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            handler.post_return(store.store_mut()).map_err(|error| {
                RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
            })?;
            Ok(())
        })
        .map_err(map_event_delivery_error)
    }
}

/// `SchedulerDeliveryPort` 的 wasmtime 生产接线（§41.2 Core-mediated push）：
/// 把运行中的 runtime candidate（[`ActiveRuntime`]）绑定为 scheduler 交付
/// port——fire 时经有界 Instance Set lease 调用 guest 的
/// `operune:scheduler/handler.on-trigger`（§24.2 composition root 注入
/// [`crate::scheduler::SchedulerService`]）。
///
/// 安装实例绑定：适配器绑定创建时传入的 ActiveRuntime——端口签名不带
/// 安装实例（已提交稳定，scheduler.wit 交付对象是安装实例），接线方按
/// "每安装实例一个适配器"装配（0.3.0 composition 接线面）。
pub struct SchedulerRuntimeDelivery {
    active: Arc<dyn ActiveRuntime>,
}

impl SchedulerRuntimeDelivery {
    /// 绑定运行中的 candidate。须为 [`WasmtimeRuntime`] 实例化的 runtime
    /// （绑定类型不符 = 内部接线错误，fail-fast，§14.3）。
    pub fn new(active: Arc<dyn ActiveRuntime>) -> Result<Self, RuntimeExecutionError> {
        Self::real_active(active.as_ref())?;
        Ok(Self { active })
    }

    /// 跨 trait 对象 downcast（`as_any` 模式，同 [`Self::new`] 的文档）。
    fn real_active(
        active: &dyn ActiveRuntime,
    ) -> Result<&WasmtimeActiveRuntime, RuntimeExecutionError> {
        active
            .as_any()
            .downcast_ref::<WasmtimeActiveRuntime>()
            .ok_or(RuntimeExecutionError::Internal(
                "active runtime is not a WasmtimeActiveRuntime",
            ))
    }
}

impl SchedulerDeliveryPort for SchedulerRuntimeDelivery {
    fn on_trigger(&self, payload: TriggerPayload) -> Result<(), SchedulerDeliveryError> {
        let real = Self::real_active(self.active.as_ref()).map_err(map_scheduler_delivery_error)?;
        real.invoke_scheduler_handler(payload)
    }
}

/// `EventDeliveryPort` 的 wasmtime 生产接线（§41.2 Core-mediated push）：
/// 把运行中的 runtime candidate（[`ActiveRuntime`]）绑定为 event 交付
/// port——投递时经有界 Instance Set lease 调用 guest 的
/// `operune:event/handler.on-event`（§24.2 composition root 注入
/// [`crate::event::EventService`]）。
///
/// 安装实例绑定：同 [`SchedulerRuntimeDelivery`]（端口签名不带安装实例，
/// 接线方按每安装实例一个适配器装配）。
pub struct EventRuntimeDelivery {
    active: Arc<dyn ActiveRuntime>,
}

impl EventRuntimeDelivery {
    /// 绑定运行中的 candidate（类型不符 = 内部接线错误，fail-fast，§14.3）。
    pub fn new(active: Arc<dyn ActiveRuntime>) -> Result<Self, RuntimeExecutionError> {
        SchedulerRuntimeDelivery::real_active(active.as_ref())?;
        Ok(Self { active })
    }
}

impl EventDeliveryPort for EventRuntimeDelivery {
    fn on_event(&self, event: DeliveredEvent) -> Result<(), EventDeliveryError> {
        let real = SchedulerRuntimeDelivery::real_active(self.active.as_ref())
            .map_err(map_event_delivery_error)?;
        real.invoke_event_handler(event)
    }
}

impl ActiveRuntime for WasmtimeActiveRuntime {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn check_readiness(&self) -> Result<(), RuntimeExecutionError> {
        // 0.1.0 stateless contract：readiness = 实例化完整性 + web manifest
        // 校验（管线已执行）；此处验证 Instance Set 可调度（§7.3）。
        let lease = self.set.try_dispatch().map_err(map_dispatch_error)?;
        drop(lease);
        Ok(())
    }

    fn read_web_manifest(&self) -> Result<Option<WebManifestData>, RuntimeExecutionError> {
        let config = self.config_snapshot()?;
        self.with_lease(|slot, store| {
            let bindings = self.slot_bindings(slot)?;
            let Some(web_descriptor) = bindings.web_descriptor else {
                // 无 web descriptor 导出 = 无 Web UI（§web descriptor）。
                return Ok(None);
            };
            prepare_store_call(store, config.descriptor_deadline)?;
            let mut results = [Val::Result(Ok(None))];
            web_descriptor
                .call(store.store_mut(), &[], &mut results)
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            web_descriptor
                .post_return(store.store_mut())
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            let guest = match &results[0] {
                Val::Result(Ok(_)) => parse_web_descriptor_val(&results[0])
                    .map_err(RuntimeExecutionError::MalformedGuestData)?,
                Val::Result(Err(_)) => {
                    return Err(RuntimeExecutionError::GuestWebError(
                        "get-web-descriptor returned an error",
                    ));
                }
                _ => {
                    return Err(RuntimeExecutionError::MalformedGuestData(
                        ContractValueError::ShapeMismatch {
                            field: "get-web-descriptor",
                            expected: "result",
                        },
                    ));
                }
            };
            let assets = if let Some(assets_func) = bindings.assets {
                prepare_store_call(store, config.descriptor_deadline)?;
                let mut results = [Val::Result(Ok(None))];
                assets_func
                    .call(store.store_mut(), &[], &mut results)
                    .map_err(|error| {
                        RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                    })?;
                assets_func
                    .post_return(store.store_mut())
                    .map_err(|error| {
                        RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                    })?;
                match &results[0] {
                    Val::Result(Ok(_)) => parse_asset_list_val(&results[0])
                        .map_err(RuntimeExecutionError::MalformedGuestData)?,
                    Val::Result(Err(_)) => {
                        return Err(RuntimeExecutionError::GuestWebError(
                            "list-assets returned an error",
                        ));
                    }
                    _ => {
                        return Err(RuntimeExecutionError::MalformedGuestData(
                            ContractValueError::ShapeMismatch {
                                field: "list-assets",
                                expected: "result",
                            },
                        ));
                    }
                }
            } else {
                Vec::new()
            };
            to_web_manifest(guest, assets).map(Some)
        })
    }

    fn read_asset(&self, path: &WebAssetPath) -> Result<Vec<u8>, RuntimeExecutionError> {
        let config = self.config_snapshot()?;
        self.with_lease(|slot, store| {
            let bindings = self.slot_bindings(slot)?;
            let Some(assets_func) = bindings.assets else {
                return Err(RuntimeExecutionError::MissingOperuneExport("assets"));
            };
            let deadline = self.call_deadline().ok_or(RuntimeExecutionError::Internal(
                "call deadline is required for asset reads",
            ))?;
            prepare_store_call(store, deadline)?;
            let param = Val::Record(vec![(
                "value".to_owned(),
                Val::String(path.as_str().to_owned()),
            )]);
            let mut results = [Val::Result(Ok(None))];
            assets_func
                .call(store.store_mut(), &[param], &mut results)
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            assets_func
                .post_return(store.store_mut())
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            let bytes = match &results[0] {
                Val::Result(Ok(_)) => parse_asset_bytes_val(&results[0])
                    .map_err(RuntimeExecutionError::MalformedGuestData)?,
                Val::Result(Err(_)) => {
                    return Err(RuntimeExecutionError::GuestWebError(
                        "read-asset returned an error",
                    ));
                }
                _ => {
                    return Err(RuntimeExecutionError::MalformedGuestData(
                        ContractValueError::ShapeMismatch {
                            field: "read-asset",
                            expected: "result",
                        },
                    ));
                }
            };
            // §21.3：宿主侧单资产硬上限。
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > config.max_asset_bytes.as_u64() {
                return Err(RuntimeExecutionError::ResponseTooLarge);
            }
            Ok(bytes)
        })
    }

    fn invoke_action(
        &self,
        request: &GuestActionRequest,
    ) -> Result<Vec<u8>, RuntimeExecutionError> {
        let config = self.config_snapshot()?;
        let _guard = InFlightGuard {
            counter: &self.in_flight,
        };
        self.with_lease(|slot, store| {
            let bindings = self.slot_bindings(slot)?;
            let Some(actions_func) = bindings.actions else {
                return Err(RuntimeExecutionError::MissingOperuneExport("actions"));
            };
            let deadline = self.call_deadline().ok_or(RuntimeExecutionError::Internal(
                "call deadline is required for actions",
            ))?;
            prepare_store_call(store, deadline)?;
            let param = build_action_request_val(request);
            let mut results = [Val::Result(Ok(None))];
            actions_func
                .call(store.store_mut(), &[param], &mut results)
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            actions_func
                .post_return(store.store_mut())
                .map_err(|error| {
                    RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
                })?;
            let bytes = match &results[0] {
                Val::Result(_) => {
                    parse_action_result_val(&results[0]).map_err(|error| match error {
                        GuestActionError::NotFound => {
                            RuntimeExecutionError::GuestWebError("action not found")
                        }
                        GuestActionError::InvalidPayload => {
                            RuntimeExecutionError::GuestWebError("invalid action payload")
                        }
                        GuestActionError::Internal => {
                            RuntimeExecutionError::GuestWebError("guest action internal error")
                        }
                    })?
                }
                _ => {
                    return Err(RuntimeExecutionError::MalformedGuestData(
                        ContractValueError::ShapeMismatch {
                            field: "handle-action",
                            expected: "result",
                        },
                    ));
                }
            };
            // §21.3：宿主侧响应硬上限。
            if u64::try_from(bytes.len()).unwrap_or(u64::MAX)
                > config.max_action_response_bytes.as_u64()
            {
                return Err(RuntimeExecutionError::ResponseTooLarge);
            }
            Ok(bytes)
        })
    }

    fn drain(self: Arc<Self>, deadline: Duration) -> Result<(), RuntimeExecutionError> {
        // §20.4：不接新工作。
        self.set.close().map_err(map_dispatch_error)?;
        // 已接受工作允许在有界 deadline 内完成；到期后不再等待（调用自身
        // 有 call deadline 约束，同步模型下至多一个调用时长），随后释放
        // Store 与 Host 资源。
        let wait_start = Instant::now();
        while self.in_flight.load(Ordering::Relaxed) > 0 {
            if wait_start.elapsed() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // `self` 按值消费：drop 释放 InstanceSet 与全部 Store。
        drop(self);
        Ok(())
    }
}

/// 把 guest web descriptor + 资产清单转为用例级 [`WebManifestData`]
///（§13.3 边界解析：路径校验一次；非法路径 = contract violation）。
fn to_web_manifest(
    guest: GuestWebDescriptor,
    assets: Vec<GuestAssetMetadata>,
) -> Result<WebManifestData, RuntimeExecutionError> {
    let entry = WebAssetPath::new(&guest.entry).map_err(|_| {
        RuntimeExecutionError::MalformedGuestData(ContractValueError::ShapeMismatch {
            field: "web-descriptor.entry",
            expected: "valid asset path",
        })
    })?;
    let mut manifest_assets = Vec::with_capacity(assets.len());
    for asset in assets {
        let path = WebAssetPath::new(&asset.path).map_err(|_| {
            RuntimeExecutionError::MalformedGuestData(ContractValueError::ShapeMismatch {
                field: "asset-metadata.path",
                expected: "valid asset path",
            })
        })?;
        manifest_assets.push(WebAssetEntry {
            path,
            size: asset.size,
            content_type: asset.content_type,
        });
    }
    Ok(WebManifestData {
        entry,
        features: WebManifestFeatures {
            static_assets: guest.features.static_assets,
            backend_actions: guest.features.backend_actions,
        },
        assets: manifest_assets,
    })
}

/// 解析 `read-asset` 的返回 `Val`（`result<list<u8>, assets-error>`）。
fn parse_asset_bytes_val(val: &Val) -> Result<Vec<u8>, ContractValueError> {
    match val {
        Val::Result(Ok(Some(inner))) => {
            let items = match inner.as_ref() {
                Val::List(items) => items,
                _ => {
                    return Err(ContractValueError::ShapeMismatch {
                        field: "read-asset",
                        expected: "list<u8>",
                    });
                }
            };
            let mut bytes = Vec::with_capacity(items.len());
            for item in items {
                match item {
                    Val::U8(byte) => bytes.push(*byte),
                    _ => {
                        return Err(ContractValueError::ShapeMismatch {
                            field: "read-asset",
                            expected: "list<u8>",
                        });
                    }
                }
            }
            Ok(bytes)
        }
        _ => Err(ContractValueError::ShapeMismatch {
            field: "read-asset",
            expected: "result with list<u8>",
        }),
    }
}

/// 解析 `state-declaration-error` 载荷（result 的 Err 侧）。
fn parse_state_declaration_error(
    val: &Val,
) -> Result<GuestStateDeclarationError, RuntimeExecutionError> {
    match val {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Enum(name) => match name.as_str() {
                "malformed" => Ok(GuestStateDeclarationError::Malformed),
                "unsupported-contract-version" => {
                    Ok(GuestStateDeclarationError::UnsupportedContractVersion)
                }
                "internal" => Ok(GuestStateDeclarationError::Internal),
                other => Err(RuntimeExecutionError::MalformedGuestData(
                    ContractValueError::InvalidVariant(other.to_owned()),
                )),
            },
            _ => Err(RuntimeExecutionError::MalformedGuestData(
                ContractValueError::ShapeMismatch {
                    field: "state-declaration-error",
                    expected: "enum payload",
                },
            )),
        },
        _ => Err(RuntimeExecutionError::MalformedGuestData(
            ContractValueError::ShapeMismatch {
                field: "state-declaration-error",
                expected: "result Err payload",
            },
        )),
    }
}

/// 解析 `descriptor-error` 载荷（result 的 Err 侧）。
fn parse_descriptor_error(val: &Val) -> Result<GuestDescriptorError, RuntimeExecutionError> {
    match val {
        Val::Result(Err(Some(inner))) => match inner.as_ref() {
            Val::Enum(name) => match name.as_str() {
                "malformed" => Ok(GuestDescriptorError::Malformed),
                "unsupported-contract-version" => {
                    Ok(GuestDescriptorError::UnsupportedContractVersion)
                }
                "internal" => Ok(GuestDescriptorError::Internal),
                other => Err(RuntimeExecutionError::MalformedGuestData(
                    ContractValueError::InvalidVariant(other.to_owned()),
                )),
            },
            _ => Err(RuntimeExecutionError::MalformedGuestData(
                ContractValueError::ShapeMismatch {
                    field: "descriptor-error",
                    expected: "enum payload",
                },
            )),
        },
        _ => Err(RuntimeExecutionError::MalformedGuestData(
            ContractValueError::ShapeMismatch {
                field: "descriptor-error",
                expected: "result Err payload",
            },
        )),
    }
}

/// 调用前设置本轮 deadline 并清除资源拒绝记录（§7.5 时序：每次不可信
/// 执行先设置 epoch deadline，再 begin_execution）。
fn prepare_store_call(
    store: &mut StoreHandle,
    deadline: Duration,
) -> Result<(), RuntimeExecutionError> {
    store
        .set_deadline(CallDeadline::new(deadline))
        .map_err(RuntimeExecutionError::Runtime)?;
    store.begin_execution();
    Ok(())
}

/// 把 InstanceSet 调度错误映射为用例级错误（§7.4 / §21.3 concurrency）。
/// `DispatchError` 为 `#[non_exhaustive]`，保留通配分支（未来变体按
/// 内部不变量破坏处理，fail-stop，§14.3）。
fn map_dispatch_error(error: operune_runtime_wasm::DispatchError) -> RuntimeExecutionError {
    match error {
        operune_runtime_wasm::DispatchError::Busy
        | operune_runtime_wasm::DispatchError::QueueFull
        | operune_runtime_wasm::DispatchError::Closed => RuntimeExecutionError::Busy,
        operune_runtime_wasm::DispatchError::Corrupted | _ => {
            RuntimeExecutionError::Internal("instance set dispatch failure")
        }
    }
}

// ---------------------------------------------------------------------------
// 0.3.0（§41.2）——交付载荷的 Val 编码与交付错误映射
// ---------------------------------------------------------------------------

/// 把一次 fire 的交付载荷编成 guest 调用面的 `Val`（handler.wit
/// `trigger-payload` record 对齐：task-id / sequence / scheduled-at /
/// missed-fires；`scheduled-at` 按 WIT `datetime` 的 seconds/nanoseconds
/// wire 形态编码，`UtcInstant::as_unix_parts` 即该逆操作）。
fn build_trigger_payload_val(payload: &TriggerPayload) -> Val {
    let (seconds, nanoseconds) = payload.scheduled_at().as_unix_parts();
    Val::Record(vec![
        (
            "task-id".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::U64(payload.task_id().as_u64()),
            )]),
        ),
        ("sequence".to_owned(), Val::U64(payload.sequence())),
        (
            "scheduled-at".to_owned(),
            Val::Record(vec![
                ("seconds".to_owned(), Val::U64(seconds)),
                ("nanoseconds".to_owned(), Val::U32(nanoseconds)),
            ]),
        ),
        ("missed-fires".to_owned(), Val::U64(payload.missed_fires())),
    ])
}

/// 把一次投递的事件编成 guest 调用面的 `Val`（handler.wit `event` record
/// 对齐：id / topic / payload / dropped；`event-payload` 按 WIT variant
/// 的 json/raw 两种形态编码）。
fn build_event_val(event: &DeliveredEvent) -> Val {
    let payload = match event.payload() {
        EventPayload::Json(text) => Val::Variant(
            "json".to_owned(),
            Some(Box::new(Val::String(text.as_str().to_owned()))),
        ),
        EventPayload::Raw(bytes) => Val::Variant(
            "raw".to_owned(),
            Some(Box::new(u8_list_val(bytes.as_slice()))),
        ),
    };
    Val::Record(vec![
        (
            "id".to_owned(),
            Val::Record(vec![("value".to_owned(), Val::U64(event.id().as_u64()))]),
        ),
        (
            "topic".to_owned(),
            Val::Record(vec![(
                "value".to_owned(),
                Val::String(event.topic().as_str().to_owned()),
            )]),
        ),
        ("payload".to_owned(), payload),
        ("dropped".to_owned(), Val::U64(event.dropped())),
    ])
}

/// `list<u8>` 的 Val 编码（WIT bytes 形态；交付载荷与 state/config/secret
/// import 共用）。
fn u8_list_val(bytes: &[u8]) -> Val {
    Val::List(bytes.iter().map(|byte| Val::U8(*byte)).collect())
}

/// scheduler 交付错误的宿主侧映射（§14.1 封闭 typed）。trap/超时/超预算
/// = 已消费（handler.wit）：调用方（服务层 consumer）不重试、不补投，
/// 错误只用于宿主侧观测。
fn map_scheduler_delivery_error(error: RuntimeExecutionError) -> SchedulerDeliveryError {
    SchedulerDeliveryError::Guest(match error {
        RuntimeExecutionError::DeadlineExceeded => "guest scheduler handler deadline exceeded",
        RuntimeExecutionError::Busy => "instance set busy",
        RuntimeExecutionError::MissingOperuneExport(_) => {
            "component does not export the scheduler handler"
        }
        _ => "guest scheduler handler trap",
    })
}

/// event 交付错误的宿主侧映射（同 scheduler；trap = 已消费，不重投）。
fn map_event_delivery_error(error: RuntimeExecutionError) -> EventDeliveryError {
    EventDeliveryError::Guest(match error {
        RuntimeExecutionError::DeadlineExceeded => "guest event handler deadline exceeded",
        RuntimeExecutionError::Busy => "instance set busy",
        RuntimeExecutionError::MissingOperuneExport(_) => {
            "component does not export the event handler"
        }
        _ => "guest event handler trap",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ConfigService;
    use crate::secret::SecretService;
    use crate::state::{CasOutcome, MigrationGate, StateService};
    use crate::stateful_imports::StatefulHostServices;
    use crate::test_support::{
        FakeConfig, FakeConfigStore, FakeSecretGrants, FakeSecretStore, FakeStateStore,
        FakeStatefulAudit, ok, test_failure,
    };
    use operune_domain::{
        ConfigFormat, ConfigSchemaVersion, ConfigValue, EventId, EventTopic, ScheduledTaskId,
        SecretName, StateKey, StateSchemaVersion, StateValue, UtcInstant,
    };
    use operune_runtime_wasi_p2::capability::{EnvVarSpec, WasiCapabilities};
    use operune_runtime_wasm::{EngineConfig, EngineHandle};
    use operune_security::secret::SecretBytes;
    use operune_security::secret_store::{KEK_SIZE, SecretCipher};

    /// 真实 wasmtime 测试环境：共享 Engine + 默认 config + WasmtimeRuntime
    ///（拥有形态；stateful 测试经 `with_stateful_services` 链式装配）。
    fn real_runtime() -> WasmtimeRuntime {
        let engine = Arc::new(ok(
            EngineHandle::new(EngineConfig::default()),
            "engine creation",
        ));
        let config = Arc::new(FakeConfig::new(RuntimeConfig::default()));
        WasmtimeRuntime::new(engine, config)
    }

    /// 最小合法 Component（无 import、无 operune 导出）。
    fn minimal_component_wat() -> &'static str {
        r#"(component
            (core module $m
                (memory (export "memory") 1)
            )
            (core instance $i (instantiate $m))
        )"#
    }

    /// 带 WASI import 的 Component（deny-by-default 的 link 测试夹具）。
    fn importing_component_wat() -> &'static str {
        r#"(component
            (import "wasi:cli/run@0.2.0" (instance $wasi
                (export "run" (func (result string)))
            ))
        )"#
    }

    /// 带**真实签名**的 WASI import 的 Component（WASI 世界组装后的
    /// link + 实例化测试夹具）：`wasi:random/random@0.2.0` 的
    /// `get-random-u64: func() -> u64` 是纯 primitive 签名——wasmtime 36
    /// 对 import 实例内的内联 variant/record/enum 有 named-type 注册
    /// 要求（手写 WAT 无法表达 `wasi:cli/run` 的 `result<(), error-code>`
    /// 变体），而 primitive 形状可直接表达且与宿主 linker 类型精确匹配
    /// （探针已验证：add_to_linker + instantiate_pre + instantiate 全链路
    /// 成功）。复杂 WIT 形状的 guest fixture 属于 §30 conformance（本机无
    /// cargo-component 工具链）。
    fn wasi_importing_component_wat() -> &'static str {
        r#"(component
            (import "wasi:random/random@0.2.0" (instance $random
                (export "get-random-u64" (func (result u64)))
            ))
        )"#
    }

    #[test]
    fn real_compile_rejects_garbage_bytes() {
        let runtime = real_runtime();
        let result = runtime.compile(b"this is not a wasm component");
        assert!(
            matches!(
                result,
                Err(RuntimeExecutionError::Runtime(
                    operune_runtime_wasm::RuntimeError::Component(_)
                ))
            ),
            "garbage bytes must fail validation"
        );
    }

    #[test]
    fn real_compile_accepts_valid_component() {
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        assert_eq!(component.byte_len(), minimal_component_wat().len() as u64);
    }

    #[test]
    fn real_contract_surface_reflects_binary_facts() {
        // §6.7：contract surface 是二进制真实可观察事实。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let surface = ok(runtime.contract_surface(&component), "contract surface");
        assert!(surface.imports.is_empty());
        assert!(surface.exports.is_empty());
        assert!(!surface.exports_component_descriptor());
    }

    #[test]
    fn real_descriptor_phase_rejects_component_without_operune_exports() {
        // §19.3：descriptor-only Store 实例化成功，但组件缺少
        // operune:component/descriptor 导出 → 确定性 typed 失败。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let result = runtime.read_descriptor(&component);
        assert!(
            matches!(result, Err(RuntimeExecutionError::MissingOperuneExport(_))),
            "missing descriptor export must fail deterministically: {result:?}"
        );
    }

    #[test]
    fn real_prepare_rejects_component_with_imports() {
        // §17.2 / §19.5 deny-by-default 的二进制级强制：带 import 的组件
        // 在空 Linker 下以确定性 link 错误失败（不"先运行，失败时 trap"）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(importing_component_wat().as_bytes()),
            "component compile",
        );
        let plan = RuntimePlan {
            installation: InstallationId::new(),
            grants: GrantSnapshot {
                installation: InstallationId::new(),
                wasi: WasiCapabilities::empty(),
                budget: ResourceBudget::default(),
            },
        };
        let result = runtime.prepare(&component, &plan);
        assert!(
            matches!(result, Err(RuntimeExecutionError::Runtime(_))),
            "unknown import must fail at prepare (link) time"
        );
    }

    #[test]
    fn real_prepare_and_instantiate_with_wasi_env_grant() {
        // §7.6 / §17.2：grant 快照中的 WASI 能力值经 adapter 真实 attach——
        // prepare（link 解析）+ instantiate（Instance Set 在 WASI context
        // 下实例化）+ readiness 全链路成功（0.1.0 集成缺口已闭合）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let mut caps = WasiCapabilities::empty();
        caps.add_env(match EnvVarSpec::new("OPERUNE_PIPELINE_TEST", "attached") {
            Ok(spec) => spec,
            Err(_) => test_failure("env spec construction failed"),
        });
        let plan = RuntimePlan {
            installation: InstallationId::new(),
            grants: GrantSnapshot {
                installation: InstallationId::new(),
                wasi: caps,
                budget: ResourceBudget::default(),
            },
        };
        let prepared = ok(
            runtime.prepare(&component, &plan),
            "prepare with wasi grants",
        );
        let active = ok(
            runtime.instantiate(&prepared),
            "instantiate with wasi grants",
        );
        ok(active.check_readiness(), "readiness");
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_prepare_and_instantiate_with_wasi_imports() {
        // §19.5 / §17.2：带标准 WASI import 的组件在非空 WASI 能力下经
        // 标准 wasi:cli/imports 世界组装通过 link 解析并成功实例化——
        // import 名与宿主 linker 类型精确匹配（§19.5 的 deny-by-default
        // 强制点：空能力时同一组件以确定性 link 错误失败，见
        // real_prepare_rejects_component_with_imports；能力在场时解析 +
        // 实例化成功，0.1.0 集成缺口已闭合）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(wasi_importing_component_wat().as_bytes()),
            "component compile",
        );
        let mut caps = WasiCapabilities::empty();
        caps.add_env(match EnvVarSpec::new("OPERUNE_LINK_TEST", "visible") {
            Ok(spec) => spec,
            Err(_) => test_failure("env spec construction failed"),
        });
        let plan = RuntimePlan {
            installation: InstallationId::new(),
            grants: GrantSnapshot {
                installation: InstallationId::new(),
                wasi: caps,
                budget: ResourceBudget::default(),
            },
        };
        let prepared = ok(
            runtime.prepare(&component, &plan),
            "prepare wasi importing component",
        );
        let active = ok(
            runtime.instantiate(&prepared),
            "instantiate wasi importing component",
        );
        ok(active.check_readiness(), "readiness");
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_instantiate_fails_closed_when_wasi_attach_fails() {
        // §17.2 fail closed：attach 失败（grant 声明的 preopen host 路径
        // 无法打开）→ 整个 runtime candidate 拒绝，不静默跳过能力。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let mut caps = WasiCapabilities::empty();
        let guest = match operune_runtime_wasi_p2::capability::GuestPath::new("data") {
            Ok(path) => path,
            Err(_) => test_failure("guest path construction failed"),
        };
        let spec = match operune_runtime_wasi_p2::capability::PreopenDirSpec::new(
            guest,
            std::path::PathBuf::from("definitely-missing-host-path"),
            operune_runtime_wasi_p2::capability::FsPerms::READ_ONLY,
            operune_runtime_wasi_p2::capability::FsPerms::READ_ONLY,
        ) {
            Ok(spec) => spec,
            Err(_) => test_failure("preopen spec construction failed"),
        };
        match caps.add_preopen(spec) {
            Ok(()) => {}
            Err(_) => test_failure("add preopen failed"),
        }
        let plan = RuntimePlan {
            installation: InstallationId::new(),
            grants: GrantSnapshot {
                installation: InstallationId::new(),
                wasi: caps,
                budget: ResourceBudget::default(),
            },
        };
        let prepared = ok(runtime.prepare(&component, &plan), "prepare");
        let result = runtime.instantiate(&prepared);
        match result {
            Ok(_) => test_failure("instantiate must fail closed when WASI attach fails"),
            Err(error) => {
                assert!(
                    matches!(
                        error,
                        RuntimeExecutionError::Runtime(operune_runtime_wasm::RuntimeError::Wasi(_))
                    ),
                    "attach failure must surface as RuntimeError::Wasi: {error:?}"
                );
            }
        }
    }

    #[test]
    fn real_instantiate_creates_bounded_instance_set() {
        // §7.3：runtime candidate 实例化为有界 Instance Set；每槽位在同一
        // 快照下实例化；无 Web UI 的组件 manifest = None（§web descriptor）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let plan = RuntimePlan {
            installation,
            grants: GrantSnapshot {
                installation,
                wasi: WasiCapabilities::empty(),
                budget: ResourceBudget::default(),
            },
        };
        let prepared = ok(runtime.prepare(&component, &plan), "prepare");
        assert_eq!(prepared.installation(), installation);
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        // readiness（0.1.0 stateless：Instance Set 可调度）。
        ok(active.check_readiness(), "readiness");
        // 无 Web UI：manifest 为 None。
        match active.read_web_manifest() {
            Ok(None) => {}
            Ok(Some(_)) => test_failure("non-web component must have no manifest"),
            Err(e) => test_failure(format_args!("manifest read failed: {e}")),
        }
        // 无 assets/actions 导出 → 确定性 typed 错误（§21.3 契约面）。
        let path = match WebAssetPath::new("/index.html") {
            Ok(path) => path,
            Err(_) => test_failure("asset path construction failed"),
        };
        assert!(
            matches!(
                active.read_asset(&path),
                Err(RuntimeExecutionError::MissingOperuneExport("assets"))
            ),
            "asset read on a non-web component must fail"
        );
        let request = GuestActionRequest {
            action: "run-check".to_owned(),
            payload: crate::contract::GuestActionPayload::Json("{}".to_owned()),
        };
        assert!(
            matches!(
                active.invoke_action(&request),
                Err(RuntimeExecutionError::MissingOperuneExport("actions"))
            ),
            "action invoke on a non-web component must fail"
        );
        // drain（§20.4）：close + 释放。
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    // ------------------------------------------------------------------
    // 0.3.0（§41.2）——scheduler/event 交付的 guest handler 调用面
    // ------------------------------------------------------------------

    /// 夹具：导出 `operune:scheduler/handler@0.1.0`（on-trigger，WIT
    /// `trigger-payload` record 参数——全部数值形态；core 函数空实现——
    /// 调用成功 + post_return 契约可观测）。
    /// 夹具：导出 `operune:scheduler/handler@0.1.0`（on-trigger，WIT
    /// `trigger-payload` record 参数——全部数值形态；core 函数空实现——
    /// 调用成功 + post_return 契约可观测）。
    ///
    /// WAT 结构注（wasmparser 0.236.1 源码核实）：导出 func/instance 所
    /// 引用的一切 record/enum 类型必须是**命名且导出**的类型（
    /// `all_valtypes_named_in_*`，类型导出先于 func 导出）；`list<u8>` /
    /// `option` 可匿名（其元素须已命名）。
    fn scheduler_handler_component_wat() -> &'static str {
        r#"(component
            (core module $m
                (func (export "on-trigger") (param i64 i64 i64 i32 i64))
            )
            (core instance $i (instantiate $m))
            (type $task-id (record (field "value" u64)))
            (type $scheduled-at (record (field "seconds" u64) (field "nanoseconds" u32)))
            (type $trigger-payload (record
                (field "task-id" $task-id)
                (field "sequence" u64)
                (field "scheduled-at" $scheduled-at)
                (field "missed-fires" u64)))
            (func $on-trigger (param "payload" $trigger-payload)
                (canon lift (core func $i "on-trigger")))
            (instance $handler
                (export "task-id" (type $task-id))
                (export "scheduled-at" (type $scheduled-at))
                (export "trigger-payload" (type $trigger-payload))
                (export "on-trigger" (func $on-trigger)))
            (export "operune:scheduler/handler@0.1.0" (instance $handler))
        )"#
    }

    /// 夹具：on-trigger 立即 trap（unreachable）——已消费语义的观测面。
    fn scheduler_handler_trap_wat() -> &'static str {
        r#"(component
            (core module $m
                (func (export "on-trigger") (param i64 i64 i64 i32 i64)
                    (unreachable))
            )
            (core instance $i (instantiate $m))
            (type $task-id (record (field "value" u64)))
            (type $scheduled-at (record (field "seconds" u64) (field "nanoseconds" u32)))
            (type $trigger-payload (record
                (field "task-id" $task-id)
                (field "sequence" u64)
                (field "scheduled-at" $scheduled-at)
                (field "missed-fires" u64)))
            (func $on-trigger (param "payload" $trigger-payload)
                (canon lift (core func $i "on-trigger")))
            (instance $handler
                (export "task-id" (type $task-id))
                (export "scheduled-at" (type $scheduled-at))
                (export "trigger-payload" (type $trigger-payload))
                (export "on-trigger" (func $on-trigger)))
            (export "operune:scheduler/handler@0.1.0" (instance $handler))
        )"#
    }

    /// 夹具：导出 `operune:event/handler@0.1.0`（on-event，WIT `event`
    /// record 参数——含 string/list 的完整 payload；guest 经自身 memory +
    /// realloc 接收 lowered 参数）。
    fn event_handler_component_wat() -> &'static str {
        r#"(component
            (core module $m
                (memory (export "memory") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (i32.load (i32.const 4)))
                    (i32.store (i32.const 4) (i32.add (local.get $ptr) (i32.const 64)))
                    (local.get $ptr))
                (func (export "on-event") (param i64 i32 i32 i32 i32 i32 i64))
                (data (i32.const 4) "\10\00\00\00"))
            (core instance $i (instantiate $m))
            (type $event-id (record (field "value" u64)))
            (type $topic (record (field "value" string)))
            (type $event-payload (variant
                (case "json" string)
                (case "raw" (list u8))))
            (type $event (record
                (field "id" $event-id)
                (field "topic" $topic)
                (field "payload" $event-payload)
                (field "dropped" u64)))
            (func $on-event (param "event" $event)
                (canon lift (core func $i "on-event") (memory $i "memory") (realloc (func $i "realloc"))))
            (instance $handler
                (export "event-id" (type $event-id))
                (export "topic" (type $topic))
                (export "event-payload" (type $event-payload))
                (export "event" (type $event))
                (export "on-event" (func $on-event)))
            (export "operune:event/handler@0.1.0" (instance $handler))
        )"#
    }

    #[test]
    fn real_scheduler_delivery_calls_guest_handler() {
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(scheduler_handler_component_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let prepared = ok(
            runtime.prepare(&component, &delivery_plan(installation)),
            "prepare",
        );
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        let delivery: Arc<dyn SchedulerDeliveryPort> = Arc::new(ok(
            SchedulerRuntimeDelivery::new(Arc::clone(&active)),
            "scheduler delivery binding",
        ));
        let payload = TriggerPayload::new(
            ScheduledTaskId::from_u64(7),
            3,
            ok(
                UtcInstant::from_unix_parts(1_752_000_000, 123_456_789),
                "utc instant",
            ),
            2,
        );
        ok(delivery.on_trigger(payload), "first delivery");
        // 第二次调用：post_return 契约成立（实例锁已复位，无
        // CannotEnterComponent）。
        ok(
            delivery.on_trigger(TriggerPayload::new(
                ScheduledTaskId::from_u64(8),
                1,
                ok(UtcInstant::from_unix_parts(1_752_000_010, 0), "utc instant"),
                0,
            )),
            "second delivery",
        );
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_event_delivery_calls_guest_handler() {
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(event_handler_component_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let prepared = ok(
            runtime.prepare(&component, &delivery_plan(installation)),
            "prepare",
        );
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        let delivery: Arc<dyn EventDeliveryPort> = Arc::new(ok(
            EventRuntimeDelivery::new(Arc::clone(&active)),
            "event delivery binding",
        ));
        // json 形态载荷（string 参数经 guest realloc 传输）。
        let event = DeliveredEvent::new(
            EventId::from_u64(9),
            ok(EventTopic::new("order.created"), "topic"),
            ok(EventPayload::json("{\"order\":1}"), "payload"),
            1,
        );
        ok(delivery.on_event(event), "json delivery");
        // raw 形态载荷（list<u8>）。
        let raw_event = DeliveredEvent::new(
            EventId::from_u64(10),
            ok(EventTopic::new("ops.log"), "topic"),
            ok(EventPayload::raw(vec![0, 1, 2, 255]), "payload"),
            0,
        );
        ok(delivery.on_event(raw_event), "raw delivery");
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_delivery_missing_handler_is_guest_observation() {
        // 无 handler 导出的组件：交付以观测错误返回（handler.wit：已消费
        // 语义，调用方不重试/补投）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let prepared = ok(
            runtime.prepare(&component, &delivery_plan(installation)),
            "prepare",
        );
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        let scheduler: Arc<dyn SchedulerDeliveryPort> = Arc::new(ok(
            SchedulerRuntimeDelivery::new(Arc::clone(&active)),
            "scheduler delivery binding",
        ));
        let event: Arc<dyn EventDeliveryPort> = Arc::new(ok(
            EventRuntimeDelivery::new(Arc::clone(&active)),
            "event delivery binding",
        ));
        let payload = TriggerPayload::new(
            ScheduledTaskId::from_u64(1),
            1,
            ok(UtcInstant::from_unix_parts(1_752_000_000, 0), "utc instant"),
            0,
        );
        assert!(
            matches!(
                scheduler.on_trigger(payload),
                Err(SchedulerDeliveryError::Guest(_))
            ),
            "missing scheduler handler must be a guest observation error"
        );
        let event_payload = DeliveredEvent::new(
            EventId::from_u64(1),
            ok(EventTopic::new("order.created"), "topic"),
            ok(EventPayload::json("{}"), "payload"),
            0,
        );
        assert!(
            matches!(
                event.on_event(event_payload),
                Err(EventDeliveryError::Guest(_))
            ),
            "missing event handler must be a guest observation error"
        );
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_delivery_handler_trap_is_consumed_observation() {
        // handler trap = 已消费（handler.wit：不重投、不计入错过）；错误
        // 只用于宿主侧观测。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(scheduler_handler_trap_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let prepared = ok(
            runtime.prepare(&component, &delivery_plan(installation)),
            "prepare",
        );
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        let delivery: Arc<dyn SchedulerDeliveryPort> = Arc::new(ok(
            SchedulerRuntimeDelivery::new(Arc::clone(&active)),
            "scheduler delivery binding",
        ));
        let payload = TriggerPayload::new(
            ScheduledTaskId::from_u64(2),
            1,
            ok(UtcInstant::from_unix_parts(1_752_000_000, 0), "utc instant"),
            0,
        );
        assert!(
            matches!(
                delivery.on_trigger(payload),
                Err(SchedulerDeliveryError::Guest(_))
            ),
            "handler trap must surface as a guest observation error"
        );
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    // ------------------------------------------------------------------
    // 0.3.0（§41.2）——operune:state/config/secret import 的宿主注册
    // ------------------------------------------------------------------

    /// 空 grant 的 RuntimePlan（delivery/import 测试的快照形状，§19.3）。
    fn delivery_plan(installation: InstallationId) -> RuntimePlan {
        RuntimePlan {
            installation,
            grants: GrantSnapshot {
                installation,
                wasi: WasiCapabilities::empty(),
                budget: ResourceBudget::default(),
            },
        }
    }

    /// 0.3.0 stateful 宿主服务装配（fakes；import 注册的测试面）。
    struct StatefulHarness {
        services: Arc<StatefulHostServices>,
        state: Arc<StateService>,
        config: Arc<ConfigService>,
        secret: Arc<SecretService>,
        secret_grants: Arc<FakeSecretGrants>,
    }

    fn stateful_harness() -> StatefulHarness {
        let state = Arc::new(StateService::new(
            Arc::new(FakeStateStore::new()),
            Arc::new(FakeStatefulAudit::new()),
            Arc::new(MigrationGate::new()),
        ));
        let config = Arc::new(ConfigService::new(
            Arc::new(FakeConfigStore::new()),
            Arc::new(FakeStatefulAudit::new()),
        ));
        let secret_grants = Arc::new(FakeSecretGrants::new());
        let secret_grants_port: Arc<dyn crate::ports::SecretGrantPort> = secret_grants.clone();
        let secret = Arc::new(SecretService::new(
            Arc::new(FakeSecretStore::new()),
            secret_grants_port,
            ok(
                SecretCipher::new(&SecretBytes::from_slice(&[0x42; KEK_SIZE])),
                "secret cipher",
            ),
            Arc::new(FakeStatefulAudit::new()),
        ));
        let services = Arc::new(StatefulHostServices::new(
            Arc::clone(&state),
            Arc::clone(&config),
            Arc::clone(&secret),
        ));
        StatefulHarness {
            services,
            state,
            config,
            secret,
            secret_grants,
        }
    }

    /// 直接实例化带 operune import 的组件（绕过 Instance Set——import
    /// 注册面的聚焦测试；`WasmtimeRuntime::prepare`/`instantiate` 的集成
    /// 面由 real_prepare_and_instantiate_with_stateful_imports 覆盖）。
    fn instantiate_import_fixture(
        runtime: &WasmtimeRuntime,
        component: &Arc<dyn CompiledWasm>,
        installation: InstallationId,
    ) -> Result<(Instance, StoreHandle), RuntimeExecutionError> {
        let real = runtime.real_component(component.as_ref())?;
        let mut linker =
            Linker::<operune_runtime_wasm::StoreHostState>::new(runtime.engine.engine());
        if let Some(stateful) = &runtime.stateful {
            crate::stateful_imports::register_stateful_imports(
                &mut linker,
                stateful,
                installation,
            )?;
        }
        let config = runtime.config_snapshot()?;
        let mut store = StoreFactory::new(&runtime.engine)
            .new_store(&config.descriptor_budget)
            .map_err(RuntimeExecutionError::Runtime)?;
        prepare_store_call(&mut store, config.descriptor_deadline)?;
        let instance = linker
            .instantiate(store.store_mut(), real.inner.component())
            .map_err(|error| {
                RuntimeExecutionError::from_classified(&mut store, ErrorSource::from(error))
            })?;
        Ok((instance, store))
    }

    /// 调用夹具的根级导出（单结果；u32/u64 判别式或值形态）。
    fn call_fixture_export(
        instance: &Instance,
        store: &mut StoreHandle,
        name: &'static str,
    ) -> Result<Val, RuntimeExecutionError> {
        let index = instance
            .get_export_index(store.store_mut(), None, name)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(name))?;
        let func = instance
            .get_func(store.store_mut(), index)
            .ok_or(RuntimeExecutionError::MissingOperuneExport(name))?;
        prepare_store_call(store, Duration::from_secs(5))?;
        let mut results = [Val::Bool(false)];
        func.call(store.store_mut(), &[], &mut results)
            .map_err(|error| {
                RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
            })?;
        func.post_return(store.store_mut()).map_err(|error| {
            RuntimeExecutionError::from_classified(store, ErrorSource::from(error))
        })?;
        Ok(results[0].clone())
    }

    /// 夹具：导入 `operune:config/config@0.1.0` 的 get-config，导出 run
    ///（result 判别式：ok = 0 / err = 1）。
    ///
    /// WAT 结构注：canon lower 的 memory/realloc 选项引用**已实例化**的
    /// core instance（wast 255 解析器：core 导出引用在 CoreInstance 命名
    /// 空间解析）——libc 模块（提供 memory/realloc）先实例化，lowered
    /// func 绑定其内存；consumer 模块经 `with` 接线 lowered func。
    fn config_import_component_wat() -> &'static str {
        r#"(component
            (import "operune:config/config@0.1.0" (instance $config
                (type $config-version (record (field "revision" u64)))
                (type $config-value (record (field "data" (list u8))))
                (export "config-version" (type $config-version' (eq $config-version)))
                (export "config-value" (type $config-value' (eq $config-value)))
                (type $config-snapshot (record
                    (field "version" $config-version')
                    (field "value" $config-value')))
                (type $config-error (enum "not-ready" "corrupt" "internal"))
                (export "config-snapshot" (type $config-snapshot' (eq $config-snapshot)))
                (export "config-error" (type $config-error' (eq $config-error)))
                (export "get-config" (func (result (result $config-snapshot' (error $config-error')))))))
            (core module $libc
                (memory (export "memory") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (i32.load (i32.const 4)))
                    (i32.store (i32.const 4) (i32.add (local.get $ptr) (i32.const 64)))
                    (local.get $ptr))
                (func (export "discriminant") (result i32)
                    (i32.load (i32.const 4096)))
                (data (i32.const 4) "\00\20\00\00"))
            (core instance $libc (instantiate $libc))
            (core func $cfg (canon lower (func $config "get-config") (memory $libc "memory") (realloc (func $libc "realloc"))))
            (core module $m
                (import "config" "get-config" (func $get-config (param i32)))
                (import "libc" "discriminant" (func $discriminant (result i32)))
                (func (export "run") (result i32)
                    (call $get-config (i32.const 4096))
                    (call $discriminant)))
            (core instance $i (instantiate $m
                (with "config" (instance (export "get-config" (func $cfg))))
                (with "libc" (instance (export "discriminant" (func $libc "discriminant"))))))
            (func (export "run") (result u32) (canon lift (core func $i "run")))
        )"#
    }

    /// 夹具：导入 `operune:secret/secret@0.1.0` 的 read-secret，导出 run
    ///（result 判别式）；名称 `db-password` 经 libc data 段驻留 canonical
    /// memory（lowered func 从该内存读取 string 参数）。
    fn secret_import_component_wat() -> &'static str {
        r#"(component
            (import "operune:secret/secret@0.1.0" (instance $secret
                (type $secret-name (record (field "value" string)))
                (type $secret-value (record (field "data" (list u8))))
                (type $secret-error (enum "denied" "invalid-name" "unavailable" "corrupt" "over-budget" "internal"))
                (export "secret-name" (type $secret-name' (eq $secret-name)))
                (export "secret-value" (type $secret-value' (eq $secret-value)))
                (export "secret-error" (type $secret-error' (eq $secret-error)))
                (export "read-secret" (func (param "name" $secret-name')
                    (result (result $secret-value' (error $secret-error')))))))
            (core module $libc
                (memory (export "memory") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (i32.load (i32.const 4)))
                    (i32.store (i32.const 4) (i32.add (local.get $ptr) (i32.const 64)))
                    (local.get $ptr))
                (func (export "discriminant") (result i32)
                    (i32.load (i32.const 4096)))
                (data (i32.const 4) "\00\20\00\00")
                (data (i32.const 2000) "db-password"))
            (core instance $libc (instantiate $libc))
            (core func $secret_read (canon lower (func $secret "read-secret") (memory $libc "memory") (realloc (func $libc "realloc"))))
            (core module $m
                (import "secret" "read-secret" (func $read-secret (param i32 i32 i32)))
                (import "libc" "discriminant" (func $discriminant (result i32)))
                (func (export "run") (result i32)
                    (call $read-secret (i32.const 2000) (i32.const 11) (i32.const 4096))
                    (call $discriminant)))
            (core instance $i (instantiate $m
                (with "secret" (instance (export "read-secret" (func $secret_read))))
                (with "libc" (instance (export "discriminant" (func $libc "discriminant"))))))
            (func (export "run") (result u32) (canon lift (core func $i "run")))
        )"#
    }

    /// 夹具：导入 `operune:state/state@0.1.0` 的 get，导出 run（result
    /// 判别式）；键 `alpha` 经 libc data 段驻留 canonical memory。
    fn state_get_component_wat() -> &'static str {
        r#"(component
            (import "operune:state/state@0.1.0" (instance $state
                (type $state-key (record (field "value" string)))
                (type $state-value (record (field "data" (list u8))))
                (type $state-error (enum "not-ready" "not-found" "conflict" "corrupt" "over-budget" "invalid-key" "unsupported-schema-version" "internal"))
                (export "state-key" (type $state-key' (eq $state-key)))
                (export "state-value" (type $state-value' (eq $state-value)))
                (export "state-error" (type $state-error' (eq $state-error)))
                (export "get" (func (param "key" $state-key')
                    (result (result (option $state-value') (error $state-error')))))))
            (core module $libc
                (memory (export "memory") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    (local $ptr i32)
                    (local.set $ptr (i32.load (i32.const 4)))
                    (i32.store (i32.const 4) (i32.add (local.get $ptr) (i32.const 64)))
                    (local.get $ptr))
                (func (export "discriminant") (result i32)
                    (i32.load (i32.const 4096)))
                (data (i32.const 4) "\00\20\00\00")
                (data (i32.const 2000) "alpha"))
            (core instance $libc (instantiate $libc))
            (core func $state_get (canon lower (func $state "get") (memory $libc "memory") (realloc (func $libc "realloc"))))
            (core module $m
                (import "state" "get" (func $get (param i32 i32 i32)))
                (import "libc" "discriminant" (func $discriminant (result i32)))
                (func (export "run") (result i32)
                    (call $get (i32.const 2000) (i32.const 5) (i32.const 4096))
                    (call $discriminant)))
            (core instance $i (instantiate $m
                (with "state" (instance (export "get" (func $state_get))))
                (with "libc" (instance (export "discriminant" (func $libc "discriminant"))))))
            (func (export "run") (result u32) (canon lift (core func $i "run")))
        )"#
    }

    #[test]
    fn real_prepare_rejects_operune_imports_without_stateful_services() {
        // §19.5 deny-by-default：未注入 stateful services 时，带 operune
        // import 的组件以确定性 link 错误失败（不"先运行，失败时 trap"）。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(config_import_component_wat().as_bytes()),
            "component compile",
        );
        let result = runtime.prepare(&component, &delivery_plan(InstallationId::new()));
        assert!(
            matches!(result, Err(RuntimeExecutionError::Runtime(_))),
            "operune import without stateful services must fail at link time"
        );
    }

    #[test]
    fn real_prepare_and_instantiate_with_stateful_imports() {
        // §41.2：注入 stateful services 后，带 operune import 的组件通过
        // prepare（link 解析）+ instantiate（Instance Set 实例化）+
        // readiness 全链路。
        let harness = stateful_harness();
        let runtime = real_runtime().with_stateful_services(Arc::clone(&harness.services));
        let component = ok(
            runtime.compile(config_import_component_wat().as_bytes()),
            "component compile",
        );
        let installation = InstallationId::new();
        let prepared = ok(
            runtime.prepare(&component, &delivery_plan(installation)),
            "prepare",
        );
        let active = ok(runtime.instantiate(&prepared), "instantiate");
        ok(active.check_readiness(), "readiness");
        ok(Arc::clone(&active).drain(Duration::from_secs(1)), "drain");
    }

    #[test]
    fn real_stateful_config_import_round_trip() {
        // get-config 的完整 canonical ABI 往返：guest 调用 → 宿主闭包 →
        // ConfigService → result 判别式与快照 revision 落回 guest 内存。
        let harness = stateful_harness();
        let runtime = real_runtime().with_stateful_services(Arc::clone(&harness.services));
        let installation = InstallationId::new();
        let component = ok(
            runtime.compile(config_import_component_wat().as_bytes()),
            "component compile",
        );
        let (instance, mut store) = ok(
            instantiate_import_fixture(&runtime, &component, installation),
            "fixture instantiation",
        );
        // 无已校验配置：get-config → not-ready（err 判别式 = 1）。
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(1),
            "no validated config must surface the err discriminant"
        );
        // 管理侧写入已校验配置（revision 单调递增）。
        ok(
            harness.config.put(
                installation,
                ConfigFormat::Json,
                ConfigSchemaVersion::from_u32(1),
                &ok(ConfigValue::new(b"{\"a\":1}".to_vec()), "config value"),
            ),
            "config put",
        );
        // 再次调用：ok（判别式 0）——快照 record（含 list<u8>）经 canonical
        // ABI 完整往返 lowered 进 libc memory（ok 判别式即编码成功的证明）。
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(0),
            "validated config must surface the ok discriminant"
        );
    }

    #[test]
    fn real_stateful_secret_import_round_trip() {
        // read-secret 的完整 canonical ABI 往返（string 参数经 guest 内存
        // 读取）：无 grant → denied（err 判别式）；grant + rotate 后 →
        // ok（判别式 0）。
        let harness = stateful_harness();
        let runtime = real_runtime().with_stateful_services(Arc::clone(&harness.services));
        let installation = InstallationId::new();
        let component = ok(
            runtime.compile(secret_import_component_wat().as_bytes()),
            "component compile",
        );
        let (instance, mut store) = ok(
            instantiate_import_fixture(&runtime, &component, installation),
            "fixture instantiation",
        );
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(1),
            "ungranted secret must surface the err discriminant"
        );
        let name = ok(SecretName::new("db-password"), "secret name");
        harness
            .secret_grants
            .set_granted(installation, vec![name.clone()]);
        ok(
            harness.secret.rotate(
                installation,
                &name,
                &SecretBytes::from_slice(b"top-secret"),
                "database credential",
            ),
            "rotate",
        );
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(0),
            "granted secret must surface the ok discriminant"
        );
    }

    #[test]
    fn real_stateful_state_import_round_trip() {
        // state get 的完整 canonical ABI 往返：键不存在 → ok(None)；seed
        // 后 → ok（判别式 0）。
        let harness = stateful_harness();
        let runtime = real_runtime().with_stateful_services(Arc::clone(&harness.services));
        let installation = InstallationId::new();
        let component = ok(
            runtime.compile(state_get_component_wat().as_bytes()),
            "component compile",
        );
        let (instance, mut store) = ok(
            instantiate_import_fixture(&runtime, &component, installation),
            "fixture instantiation",
        );
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(0),
            "missing key must surface the ok (None) discriminant"
        );
        let key = ok(StateKey::new("alpha"), "state key");
        let value = ok(StateValue::new(b"v1".to_vec()), "state value");
        assert_eq!(
            ok(
                harness.state.cas(
                    installation,
                    StateSchemaVersion::from_u32(0),
                    &key,
                    None,
                    Some(&value),
                ),
                "cas seed"
            ),
            CasOutcome::Applied
        );
        assert_eq!(
            ok(call_fixture_export(&instance, &mut store, "run"), "run"),
            Val::U32(0),
            "seeded state must surface the ok discriminant"
        );
    }
}
