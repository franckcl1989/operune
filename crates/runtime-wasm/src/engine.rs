//! Engine 配置与生命周期（§7.1 / §22.2 / §7.5）。

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::budget::ByteSize;
use crate::error::{ErrorSource, RuntimeError};

/// 引擎配置（§7.1：Engine 配置在启动后视为不可变基础设施；本类型为不可变快照）。
///
/// 生产默认值说明：
/// - epoch interruption **默认启用**（§7.5）；统一 ticker 间隔默认 10ms；
/// - **fuel 默认不启用**（§7.5）：fuel 的确定性更强但执行开销更高；只有产品
///   出现“确定的 Wasm 指令预算”这一明确需求时，才经 benchmark + ADR 启用
///   （本 crate 不提供 fuel 配置开关，启用需要新开 ADR 后在此扩展）；
/// - 实例化策略固定 OnDemand（§7.3/§22.9：0.1 不默认 pooling）；
/// - 编译后端固定 Cranelift（§4.1/§22.2）；
/// - 0.1.0 不启用 Wasmtime 磁盘编译缓存（`cache` feature 未启用；compiled
///   module 缓存属于后续运维策略决策，且 §7.2 禁止把私有 AOT 格式当作插件制品）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// 是否启用 epoch interruption（§7.5，默认 `true`）。
    pub epoch_interruption: bool,
    /// 统一 epoch ticker 的滴答间隔（§7.5，默认 10ms；必须非零）。
    pub epoch_tick_interval: Duration,
    /// wasm 栈空间上限（默认 512 KiB，与 wasmtime 默认一致；必须非零）。
    pub max_wasm_stack: ByteSize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            epoch_interruption: true,
            epoch_tick_interval: Duration::from_millis(10),
            max_wasm_stack: ByteSize::kib(512),
        }
    }
}

/// 长期共享的 Wasmtime Engine（§7.1：每个 Core Runtime 进程默认创建一个；
/// 不为每个 Component 创建独立 Engine）。
///
/// 不变量：
/// - 创建后配置不可变（§7.1），可通过 [`EngineHandle::config`] 读取快照；
/// - 单一 owner：本类型不实现 `Clone`；进程级共享经 `Arc<EngineHandle>` 表达
///   （composition root 创建一次后以引用传递）。
///
/// 错误：配置无效 → [`RuntimeError::Config`]；Wasmtime 创建失败 →
/// [`RuntimeError::Engine`]（source 保留可诊断上下文）。
pub struct EngineHandle {
    engine: wasmtime::Engine,
    config: EngineConfig,
}

impl EngineHandle {
    /// 以给定配置创建 Engine（§7.1）。
    pub fn new(config: EngineConfig) -> Result<Self, RuntimeError> {
        if config.epoch_tick_interval.is_zero() {
            return Err(RuntimeError::Config("epoch_tick_interval must be non-zero"));
        }
        if config.max_wasm_stack.as_bytes() == 0 {
            return Err(RuntimeError::Config("max_wasm_stack must be non-zero"));
        }
        let mut wasmtime_config = wasmtime::Config::new();
        // §7.5：epoch interruption 默认启用。
        wasmtime_config.epoch_interruption(config.epoch_interruption);
        // §7.3/§22.9：实例化策略 OnDemand（0.1 不默认 pooling；pooling feature 未启用）。
        wasmtime_config.allocation_strategy(wasmtime::InstanceAllocationStrategy::OnDemand);
        // §4.1/§22.2：Cranelift 生产编译后端。
        wasmtime_config.strategy(wasmtime::Strategy::Cranelift);
        wasmtime_config.max_wasm_stack(config.max_wasm_stack.as_usize());
        // §4.1：Component Model（component-model feature 已启用）。
        wasmtime_config.wasm_component_model(true);
        // 不调用 consume_fuel（§7.5：不默认 fuel；见本模块文档）。
        // 不调用 async_support（本 0.1.0 runtime-wasm 阶段使用同步 Store；
        // 未来启用 async Store 时经 EngineConfig 显式打开——衔接点见 PR 报告）。
        let engine = wasmtime::Engine::new(&wasmtime_config)
            .map_err(|e| RuntimeError::Engine(ErrorSource::from(e)))?;
        Ok(Self { engine, config })
    }

    /// 配置快照（不可变，§7.1）。
    pub fn config(&self) -> &EngineConfig {
        &self.config
    }

    pub(crate) fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }

    /// 内部共享：ticker 等后台线程持有 Engine 强引用（§7.1 进程级共享 Engine）。
    pub(crate) fn clone_engine(&self) -> wasmtime::Engine {
        self.engine.clone()
    }
}

/// 统一 epoch ticker（§7.5：Core 维护统一 ticker；每次不可信执行设置 deadline）。
///
/// 实现：独立线程按固定间隔调用 `Engine::increment_epoch`（原子自增，信号安全）。
///
/// 所有权/生命周期：
/// - RAII：`Drop` 停止线程（至多等待一个滴答间隔）；[`EpochTicker::stop`] 可显式停止；
/// - 线程持有 Engine 的强引用（进程生命周期内 Engine 是共享的；若未来需要
///   “ticker 不保活 Engine”，可用 `EngineWeak` + 每 tick upgrade 演进）；
/// - 每个 Engine 只应有一个 ticker（统一 ticker，§7.5）——由 composition root
///   保证；本类型不强制全局单例。
///
/// 错误：[`RuntimeError::Config`]（间隔为零）；线程 spawn 失败 → [`RuntimeError::Ticker`]。
pub struct EpochTicker {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl EpochTicker {
    /// 启动 ticker：按 `interval` 周期递增 Engine 的 epoch。
    pub fn start(engine: &EngineHandle, interval: Duration) -> Result<Self, RuntimeError> {
        if interval.is_zero() {
            return Err(RuntimeError::Config("ticker interval must be non-zero"));
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        let engine_thread = engine.clone_engine();
        let thread = std::thread::Builder::new()
            .name("operune-epoch-ticker".to_owned())
            .spawn(move || {
                while !stop_thread.load(Ordering::Relaxed) {
                    std::thread::sleep(interval);
                    // increment_epoch 为原子自增，不可失败（信号安全）。
                    engine_thread.increment_epoch();
                }
            })
            .map_err(|e| RuntimeError::Ticker(Box::new(e)))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// 停止 ticker 并回收线程（幂等；至多等待一个滴答间隔）。
    pub fn stop(&mut self) -> Result<(), RuntimeError> {
        if let Some(thread) = self.thread.take() {
            self.stop.store(true, Ordering::Relaxed);
            // 循环体不存在 panic 路径；join 的 Err 仅当线程意外 panic
            // （不可能路径）——按内部不变量破坏处理。
            thread
                .join()
                .map_err(|_| RuntimeError::Internal("epoch ticker thread panicked"))?;
        }
        Ok(())
    }
}

impl Drop for EpochTicker {
    fn drop(&mut self) {
        // Drop 中无法返回错误；stop 的错误路径为内部不变量破坏，忽略并继续。
        let _ = self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{self, expect_ok, test_failure};
    use std::time::Instant;

    #[test]
    fn default_config_builds_engine_and_snapshot_is_immutable() {
        let engine = expect_ok(
            EngineHandle::new(EngineConfig::default()),
            "engine creation",
        );
        // §7.1：配置快照与输入一致，且之后不可变（快照读取是唯一的读取面）。
        assert_eq!(engine.config(), &EngineConfig::default());
        assert!(engine.config().epoch_interruption);
    }

    #[test]
    fn config_rejects_zero_tick_interval() {
        let config = EngineConfig {
            epoch_tick_interval: Duration::ZERO,
            ..EngineConfig::default()
        };
        let result = EngineHandle::new(config);
        match result {
            Ok(_) => test_failure("zero tick interval must be rejected"),
            Err(e) => assert!(matches!(e, RuntimeError::Config(_))),
        }
    }

    #[test]
    fn config_rejects_zero_wasm_stack() {
        let config = EngineConfig {
            max_wasm_stack: ByteSize::new(0),
            ..EngineConfig::default()
        };
        let result = EngineHandle::new(config);
        match result {
            Ok(_) => test_failure("zero wasm stack must be rejected"),
            Err(e) => assert!(matches!(e, RuntimeError::Config(_))),
        }
    }

    #[test]
    fn config_rejects_zero_ticker_interval() {
        let result = EpochTicker::start(&test_support::engine(), Duration::ZERO);
        match result {
            Ok(_) => test_failure("zero ticker interval must be rejected"),
            Err(e) => assert!(matches!(e, RuntimeError::Config(_))),
        }
    }

    #[test]
    fn epoch_ticker_runs_and_stops() {
        // §7.5：统一 ticker 运行与 RAII 停止路径。
        let engine = test_support::engine();
        let mut ticker = expect_ok(
            EpochTicker::start(&engine, Duration::from_millis(10)),
            "ticker start",
        );
        // 等待若干周期，确认 ticker 无故障运行。
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(60) {
            std::thread::sleep(Duration::from_millis(5));
        }
        let stop_result = ticker.stop();
        assert!(stop_result.is_ok());
        // 显式 stop 后 Drop 应为幂等 no-op。
        drop(ticker);
    }
}
