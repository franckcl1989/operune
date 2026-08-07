//! WASI 0.2 linker 组装（本 crate 内部；对外衔接在集成阶段）。
//!
//! 所有 `wasmtime_wasi::p2` 的 linker 相关绑定只存在于本 crate
//! （§8.2 / §24.2："WASI 版本具体 linker/binding 只存在于明确的 adapter
//! crate"）。
//!
//! # 为什么 0.1.0 不公开 linker 入口（集成阶段的衔接点）
//!
//! wasmtime-wasi 36 的 `p2::add_to_linker_sync` 要求 Store 的宿主状态类型
//! `T` 实现其 `WasiView` binding trait。由于 orphan rule，`WasiView` 的实现
//! 只能写在**拥有 Store 类型**的 crate（runtime-wasm 或集成层），本 adapter
//! crate 无法为外部 Store 类型提供该实现。
//!
//! 因此 0.1.0 的公开 API 保持全项目类型（§8.2：不把 wasmtime_wasi 的 p2
//! 具体类型泄漏到公开 API），此处提供被单元测试覆盖的组装函数作为接线点，
//! 并在 [`crate::context::WasiContext`] 文档中记录衔接形状。待 runtime-wasm
//! 的 Store 类型定型后，由主 agent 决定公开形态（可能涉及 ADR：§8.2 的
//! "binding 只存在于 adapter" 与 orphan rule 的张力，详见 crate 根文档）。
//!
//! # p3 隔离（§4.2 / §8.4）
//!
//! 本模块只组装 WASI 0.2（`wasi:cli/imports` 世界）。p3 是未来双栈 lab
//! 方向（§8.4 side-by-side 迁移：`runtime-wasi-p3-lab` 与 production 并存，
//! 禁止 flag-day），本 crate 是 p2 侧替换点；wasmtime-wasi 的 `p3` feature
//! 未启用，本 crate 不存在任何 p3 类型引用。

use crate::error::WasiP2Error;

/// 把全部 WASI 0.2 接口（`wasi:cli/imports` 世界）加入 linker。
///
/// 内部仅调用 `wasmtime_wasi::p2::add_to_linker_sync`（标准接口组装，P4：
/// 不建立平行接口），错误映射为本 crate 的 typed error（§14.1）。
///
/// `T` 是 Store 的宿主状态类型，必须实现 `wasmtime_wasi::WasiView`
///（见模块文档的 orphan rule 说明）。context 由 [`crate::context::WasiContext`]
/// 持有。
///
/// 说明：该函数组装的是标准 `wasi:cli/imports` 全集（含 `wasi:random/*`
/// 与 `wasi:sockets/*`）；"无 ambient authority"（§7.6）由
/// [`crate::context::WasiContextBuilder`] 的零权限 context 默认表达——
/// 接口在场但能力为空（无熵、无地址许可、无 preopen）。
///
/// # Errors
///
/// - `WasiP2Error::LinkerAssembly`：linker 定义冲突（如未开启 shadowing 时
///   重复组装同名实例）。
#[cfg_attr(not(test), allow(dead_code))] // 0.1.0 集成接线点：等 runtime-wasm Store 类型定型（见模块文档）
pub(crate) fn add_to_linker<T>(
    linker: &mut wasmtime::component::Linker<T>,
) -> Result<(), WasiP2Error>
where
    T: wasmtime_wasi::WasiView,
{
    wasmtime_wasi::p2::add_to_linker_sync(linker).map_err(|source| WasiP2Error::LinkerAssembly {
        source: Box::new(crate::error::AdapterSource::new(source)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试用 Store 状态：项目 context 句柄 + WASI resource table。
    /// 本类型定义在本 crate 内，因此可以合法实现 `wasmtime_wasi::WasiView`
    ///（orphan rule：trait 外来、类型本地）。
    struct TestStore {
        wasi: crate::context::WasiContext,
        table: wasmtime::component::ResourceTable,
    }

    impl TestStore {
        fn new() -> Result<Self, WasiP2Error> {
            Ok(Self {
                wasi: crate::context::WasiContextBuilder::new().build()?,
                table: wasmtime::component::ResourceTable::new(),
            })
        }
    }

    impl wasmtime_wasi::WasiView for TestStore {
        fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
            wasmtime_wasi::WasiCtxView {
                ctx: self.wasi.as_p2_mut(),
                table: &mut self.table,
            }
        }
    }

    /// 标准 WASI 0.2 世界（wasi:cli/imports 全集）可以成功组装进 linker；
    /// 且零权限 context 句柄可以装载进 wasmtime `Store`（Send 边界验证）。
    #[test]
    fn linker_assembly_succeeds() -> Result<(), Box<dyn std::error::Error>> {
        let engine = wasmtime::Engine::default();
        let mut linker = wasmtime::component::Linker::<TestStore>::new(&engine);
        add_to_linker(&mut linker)?;
        let store = wasmtime::Store::new(&engine, TestStore::new()?);
        drop(store);
        Ok(())
    }

    /// 未开启 shadowing 时重复组装同一世界被显式拒绝（deny-by-default，
    /// §17.2：不静默覆盖；映射为本 crate typed error）。
    #[test]
    fn duplicate_link_assembly_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let engine = wasmtime::Engine::default();
        let mut linker = wasmtime::component::Linker::<TestStore>::new(&engine);
        add_to_linker(&mut linker)?;
        let second = add_to_linker(&mut linker);
        assert!(
            second.is_err(),
            "second assembly of the same world must fail without shadowing"
        );
        Ok(())
    }
}
