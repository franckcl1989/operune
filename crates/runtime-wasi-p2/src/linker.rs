//! WASI 0.2 linker 组装（§8.2 / §24.2：WASI 版本具体 linker/binding 只存在
//! 于本 adapter crate）。
//!
//! 所有 `wasmtime_wasi::p2` 的 linker 相关绑定只存在于本 crate。
//!
//! # 公开形态（集成接线点）
//!
//! wasmtime-wasi 36 的 `p2::add_to_linker_sync` 要求 Store 的宿主状态类型
//! `T` 实现其 `WasiView` binding trait。由于 orphan rule，`WasiView` 的实现
//! 只能写在**拥有 Store 类型**的 crate（runtime-wasm，受控 glue 例外
//! 0020e24 审计裁决，见 git 历史）。因此本 crate 的 linker 入口以泛型
//! `T: wasmtime_wasi::WasiView` 公开：调用方（集成层 application）以
//! `Linker<StoreHostState>` 调用——runtime-wasm 已为 `StoreHostState`
//! 实现 `WasiView`（§8.2 的 MUST NOT 列表不含 runtime-wasm）。
//!
//! 分层说明：本签名把 wasmtime 的 `Linker<T>` 暴露为参数类型（wasmtime
//! 类型本身不在 §8.2 禁止名单，[`domain`/`application` 的 Cargo.toml 依赖
//! 面已含 wasmtime）；`wasmtime_wasi` 具体类型只出现在 trait bound 中，
//! 由调用方的 Store 状态类型满足，调用方无需 import wasmtime_wasi。
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
///（见模块文档的 orphan rule 说明：runtime-wasm 的 `StoreHostState` 已
/// 实现）。context 由 [`crate::context::WasiContext`] 持有，能力经
/// [`crate::adapter`] 的 attach 安装。
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
pub fn add_to_linker<T>(linker: &mut wasmtime::component::Linker<T>) -> Result<(), WasiP2Error>
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
