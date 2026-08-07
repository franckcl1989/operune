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

    /// 内部编译产物访问（0.1.0 由测试与实例化扩展缝消费；lib-only 构建下
    /// 允许 dead_code）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn component(&self) -> &wasmtime::component::Component {
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
