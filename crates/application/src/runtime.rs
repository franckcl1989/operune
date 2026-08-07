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
//! # 0.1.0 集成边界说明
//!
//! - descriptor-only Store 使用空 Linker（§19.3 零 operational grant）：
//!   任何带 import 的组件在 descriptor 阶段以确定性 link 错误失败
//!   （deny-by-default，§17.2 / §19.5）。WASI 默认 context（runtime-wasi-p2
//!   的零权限上下文）的接线需要 runtime-wasm 为 `StoreHostState` 实现
//!   `wasmtime_wasi::WasiView`（orphan rule，见 runtime-wasi-p2 crate 文档）——
//!   该缺口已作为 API gap 报告，闭合后 descriptor 阶段可在零权限 WASI
//!   context 下实例化带标准 WASI import 的组件；
//! - runtime candidate 的 grant 快照中非空 WASI 能力 →
//!   [`RuntimeExecutionError::WasiIntegrationUnavailable`]（同一缺口）。
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

use operune_domain::InstallationId;
use operune_runtime_wasm::{
    CallDeadline, ComponentHandle, EngineHandle, InstanceSet, ResourceBudget, StoreFactory,
    StoreHandle,
};
use wasmtime::component::{ComponentExportIndex, Func, Instance, InstancePre, Linker, Val};

use crate::contract::{
    ContractValueError, GuestActionError, GuestActionRequest, GuestAssetMetadata,
    GuestComponentDescriptor, GuestDescriptorError, GuestWebDescriptor, build_action_request_val,
    parse_action_result_val, parse_asset_list_val, parse_component_descriptor_val,
    parse_web_descriptor_val,
};
use crate::error::{ErrorSource, RuntimeExecutionError};
use crate::model::{
    ContractSurface, GrantSnapshot, RuntimeConfig, WebAssetEntry, WebAssetPath, WebManifestData,
    WebManifestFeatures,
};
use crate::ports::ConfigPort;

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
        Self { engine, config }
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

    fn prepare(
        &self,
        component: &Arc<dyn CompiledWasm>,
        plan: &RuntimePlan,
    ) -> Result<Arc<dyn PreparedRuntime>, RuntimeExecutionError> {
        let real = self.real_component(component.as_ref())?;
        // §7.6 / §17.2：非空 WASI 能力需要宿主集成（0.1.0 缺口，见模块文档）。
        if !plan.grants.wasi.is_empty() {
            return Err(RuntimeExecutionError::WasiIntegrationUnavailable);
        }
        let linker = Linker::<operune_runtime_wasm::StoreHostState>::new(self.engine.engine());
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
        let set =
            InstanceSet::new(&self.engine, &budget).map_err(RuntimeExecutionError::Runtime)?;
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
                let binding = bindings
                    .get_mut(slot)
                    .ok_or(RuntimeExecutionError::Internal("invalid instance slot"))?;
                *binding.get_mut().map_err(|_| {
                    RuntimeExecutionError::Internal("instance slot mutex poisoned")
                })? = Some(SlotBindings {
                    web_descriptor,
                    assets,
                    actions,
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

impl ActiveRuntime for WasmtimeActiveRuntime {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{FakeConfig, ok, test_failure};
    use operune_runtime_wasi_p2::capability::{EnvVarSpec, WasiCapabilities};
    use operune_runtime_wasm::{EngineConfig, EngineHandle};

    /// 真实 wasmtime 测试环境：共享 Engine + 默认 config + WasmtimeRuntime。
    fn real_runtime() -> Arc<WasmtimeRuntime> {
        let engine = Arc::new(ok(
            EngineHandle::new(EngineConfig::default()),
            "engine creation",
        ));
        let config = Arc::new(FakeConfig::new(RuntimeConfig::default()));
        Arc::new(WasmtimeRuntime::new(engine, config))
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
    fn real_prepare_rejects_nonempty_wasi_grants() {
        // 0.1.0 集成缺口（见模块文档）：非空 WASI 能力 → 显式 typed 错误，
        // 不静默降级。
        let runtime = real_runtime();
        let component = ok(
            runtime.compile(minimal_component_wat().as_bytes()),
            "component compile",
        );
        let mut caps = WasiCapabilities::empty();
        caps.add_env(match EnvVarSpec::new("K", "V") {
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
        let result = runtime.prepare(&component, &plan);
        assert!(
            matches!(
                result,
                Err(RuntimeExecutionError::WasiIntegrationUnavailable)
            ),
            "non-empty WASI grants must fail explicitly"
        );
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
}
