//! Component 验证与编译（§7.2 / §19.2 阶段二）。

use crate::engine::EngineHandle;
use crate::error::{ErrorSource, RuntimeError};

/// 已验证并编译的 WebAssembly Component（§7.2）。
///
/// 语义：
/// - 输入视为不可信字节（§19.1）；[`ComponentHandle::new`] 同步验证整个
///   component（含全部 core modules）并编译；
/// - 编译产物仅在本进程内复用；Wasmtime 私有序列化/AOT 格式不得升级为
///   用户可见插件制品（§7.2）；
/// - 安装管线的硬字节大小限制（§19.1/§19.2）由调用方（application 阶段）
///   在调用本类型之前执行，本类型不复制该策略。
///
/// 所有权：单一 owner（不实现 `Clone`）；共享经 `Arc<ComponentHandle>`。
///
/// 错误：验证/编译失败 → [`RuntimeError::Component`]（source 保留可诊断上下文）。
pub struct ComponentHandle {
    component: wasmtime::component::Component,
}

impl ComponentHandle {
    /// 验证并编译不可信 `.wasm` 字节（Component Model 输入；§19.2 阶段二）。
    pub fn new(engine: &EngineHandle, bytes: &[u8]) -> Result<Self, RuntimeError> {
        let component = wasmtime::component::Component::new(engine.engine(), bytes)
            .map_err(|e| RuntimeError::Component(ErrorSource::from(e)))?;
        Ok(Self { component })
    }

    /// 访问已编译的 Wasmtime Component（实例化扩展缝：`Linker::instantiate`
    /// 与 WIT bindgen 生成的接口以 `&wasmtime::component::Component` 为参数）。
    ///
    /// 类型泄漏说明（§8.2）：本签名必须暴露 wasmtime 具体类型——
    /// `wasmtime::component::Linker::instantiate` 与 bindgen 生成代码的签名
    /// 直接使用 `&Component`，typed invoke 必须持有编译产物；runtime-wasm
    /// 自身不提供 Component Model 的 invoke（属 application/集成阶段，需要
    /// WIT bindgen 与 WASI linker）。本方法是隔离层向集成层的受控泄漏点，
    /// 调用方不得把返回引用再暴露到领域层公共 API（§8.2 只约束领域层）。
    ///
    /// 所有权：只读借用，不转移所有权；返回引用的存活期受 `&self` 借用期
    /// 约束（编译产物生命周期与 `self` 相同）。
    /// 不变量：返回的 Component 只与创建它的 Engine（[`ComponentHandle::new`]
    /// 的 engine 参数所对应的 EngineHandle）兼容——跨 Engine 实例化会失败；
    /// 每次实例化必须使用同一 Engine 下创建的 Store。
    /// 错误：无（只读访问，无运行时可失败路径）。
    /// 并发：`&self` 只读借用，可被多线程共享只读访问（wasmtime Component
    /// 编译产物只读线程安全）；实例化本身仍须经 Store 的单一执行模型（§7.3）。
    /// 安全/权限：编译产物本身不携带任何能力（§7.6）；能力只经 Store 构建
    /// 时的 WASI policy 显式授予（[`crate::store::StoreFactory::with_wasi`]）。
    pub fn component(&self) -> &wasmtime::component::Component {
        &self.component
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{engine, expect_ok, test_failure};

    #[test]
    fn component_handle_rejects_garbage_bytes() {
        // §19.1/§19.2：不可信输入必须被验证拒绝（确定错误，不 panic）。
        let engine = engine();
        let result = ComponentHandle::new(&engine, b"this is not a wasm component");
        match result {
            Ok(_) => test_failure("garbage bytes must be rejected"),
            Err(e) => assert!(matches!(e, RuntimeError::Component(_))),
        }
    }

    #[test]
    fn component_handle_accepts_valid_component() {
        // 测试构建（wat feature 仅 dev 启用）：最小合法 Component。
        let engine = engine();
        let wat = r#"(component
            (core module $m
                (memory (export "memory") 1)
            )
            (core instance $i (instantiate $m))
        )"#;
        let handle = expect_ok(
            ComponentHandle::new(&engine, wat.as_bytes()),
            "component compile",
        );
        // 编译产物存在且属于该 engine（内部访问，仅测试面）。
        let _ = handle.component();
    }
}
