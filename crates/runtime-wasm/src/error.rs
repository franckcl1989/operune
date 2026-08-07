//! 错误模型（§14）：typed error + 可诊断 source；公共 API 不泄漏 wasmtime 类型。
//!
//! §14.1：生产边界使用 thiserror 定义的封闭 typed error；适配层把第三方错误
//! 转换为项目错误语义，同时保存可诊断 source/context（本模块的
//! [`ErrorSource`]）。禁止在公共边界返回 anyhow::Error / `Box<dyn Error>` /
//! String error 本身（§14.1、§22.9）。

use std::error::Error as StdError;

/// 可诊断错误源：第三方错误装箱（§14.1：保存 source/context 但不让第三方类型
/// 污染核心契约；§16.6 精神：错误路径不得携带 secret/敏感值）。
pub type ErrorSource = Box<dyn StdError + Send + Sync>;

/// Wasmtime 可见资源类别（§7.4）。用于超限拒绝的 typed 分类。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceLimitKind {
    /// linear memory 总大小（字节）超限。
    LinearMemory,
    /// linear memory 数量超限。
    Memories,
    /// table 数量超限。
    Tables,
    /// table 元素总数超限。
    TableElements,
    /// 实例数量超限。
    Instances,
}

/// WebAssembly 执行失败语义分类（§7.5/§14.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WasmFailure {
    /// epoch deadline 到期（§7.5：每次不可信执行设置 deadline；超时后 trap/取消）。
    /// 0.1.0 中 epoch 是 `Interrupt` trap 的唯一启用来源（wasm-interrupt 未启用）。
    EpochDeadlineExceeded,
    /// guest 触发普通 trap（见 [`TrapKind`]）。
    Trap(TrapKind),
    /// 其他/未知宿主侧失败（source 保留可诊断上下文）。
    Unknown,
}

/// guest trap 类别（映射 wasmtime::Trap；未知/未来变体归入 [`TrapKind::Other`]）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrapKind {
    /// 当前栈空间耗尽。
    StackOverflow,
    /// 越界内存访问。
    MemoryOutOfBounds,
    /// 越界 table 访问。
    TableOutOfBounds,
    /// 对 null 的间接调用。
    IndirectCallToNull,
    /// 间接调用签名不匹配。
    BadSignature,
    /// 整数算术溢出。
    IntegerOverflow,
    /// 整数除以零。
    IntegerDivisionByZero,
    /// 非法整数到浮点转换。
    BadConversionToInteger,
    /// 执行到不可达代码。
    UnreachableCodeReached,
    /// 燃料耗尽（本版本默认不启用 fuel，§7.5；保留以应对未来启用）。
    OutOfFuel,
    /// 其他/未知 trap 类别。
    Other,
}

impl From<&wasmtime::Trap> for TrapKind {
    fn from(trap: &wasmtime::Trap) -> Self {
        match trap {
            wasmtime::Trap::StackOverflow => Self::StackOverflow,
            wasmtime::Trap::MemoryOutOfBounds => Self::MemoryOutOfBounds,
            wasmtime::Trap::TableOutOfBounds => Self::TableOutOfBounds,
            wasmtime::Trap::IndirectCallToNull => Self::IndirectCallToNull,
            wasmtime::Trap::BadSignature => Self::BadSignature,
            wasmtime::Trap::IntegerOverflow => Self::IntegerOverflow,
            wasmtime::Trap::IntegerDivisionByZero => Self::IntegerDivisionByZero,
            wasmtime::Trap::BadConversionToInteger => Self::BadConversionToInteger,
            wasmtime::Trap::UnreachableCodeReached => Self::UnreachableCodeReached,
            wasmtime::Trap::OutOfFuel => Self::OutOfFuel,
            _ => Self::Other,
        }
    }
}

/// runtime-wasm 统一 typed error（§14.1）。
///
/// 不变量：错误 Display/错误链不携带机密（§16.6）；所有 wasmtime 具体错误
/// 只作为 [`ErrorSource`] 出现在 `source` 中，公共 API 不命名 wasmtime 类型。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RuntimeError {
    /// 引擎/预算配置无效（`&'static str` 为固定原因说明）。
    #[error("engine configuration invalid: {0}")]
    Config(&'static str),
    /// Engine 创建失败。
    #[error("engine creation failed: {0}")]
    Engine(#[source] ErrorSource),
    /// Component 验证或编译失败（§7.2/§19.2 阶段二）。
    #[error("component validation or compilation failed: {0}")]
    Component(#[source] ErrorSource),
    /// Store 创建失败（含 WASI 附加失败之外的 wasmtime 侧错误）。
    #[error("store creation failed: {0}")]
    Store(#[source] ErrorSource),
    /// Wasm 执行失败（trap / epoch 超时 / 未知宿主错误）。
    #[error("wasm execution failed: {kind:?}")]
    Execution {
        /// 失败语义分类。
        kind: WasmFailure,
        /// 可诊断 source。
        #[source]
        source: ErrorSource,
    },
    /// Wasmtime 可见资源上限拒绝（§7.4；分类见 [`ResourceLimitKind`]）。
    #[error("wasmtime resource limit exceeded: {kind:?}")]
    ResourceLimit {
        /// 超限资源类别。
        kind: ResourceLimitKind,
        /// 可诊断 source。
        #[source]
        source: ErrorSource,
    },
    /// epoch ticker 线程故障。
    #[error("epoch ticker failed: {0}")]
    Ticker(#[source] ErrorSource),
    /// WASI adapter 拒绝 Store 构建（fail closed，§7.6）。
    #[error("WASI adapter rejected store setup: {0}")]
    Wasi(#[from] crate::wasi::WasiError),
    /// 0.2.0 组件间链接失败（§40.2 c2c linking；见 [`crate::linked::LinkError`]）。
    #[error("component-to-component link failed: {0}")]
    Link(#[from] crate::linked::LinkError),
    /// runtime-wasm 内部不变量被破坏（视为系统故障，fail-stop 语义）。
    #[error("runtime-wasm internal invariant violated: {0}")]
    Internal(&'static str),
}

enum Outcome {
    Resource(ResourceLimitKind),
    Epoch,
    Trap(TrapKind),
    Unknown,
}

/// 把一次执行/实例化失败映射为 typed [`RuntimeError`]（§14.1）。
///
/// 分类顺序：
/// 1. Store 的资源拒绝记录（调用方必须在每次执行前调用
///    [`crate::store::StoreHandle::begin_execution`] 清除，否则可能读到陈旧记录）；
/// 2. wasmtime trap（epoch 超时 → [`WasmFailure::EpochDeadlineExceeded`]）；
/// 3. 未知宿主错误（source 保留可诊断上下文）。
///
/// 不变量：任何路径都不泄漏 wasmtime 具体类型到公共错误类型之外（仅装箱为
/// [`ErrorSource`]）；错误内容不携带 secret（§16.6）。
///
/// 调用方（invoke 扩展缝/测试）先把第三方错误经 `ErrorSource::from(e)` 装箱
/// （anyhow 提供 `From<Error> for Box<dyn Error + Send + Sync>`，因为
/// anyhow::Error 包装类型本身不实现 `std::error::Error`，只 Deref 到它），
/// 再传入本函数。
///
/// 所有权：不转移 Store 所有权，仅按 `&mut` 借用（读取并清除拒绝记录）；
/// `err` 按值装箱为本错误结果的 source（错误链持有 `err` 的可诊断上下文）。
/// 错误：本函数无失败返回路径（始终返回 `RuntimeError`，映射本身不可失败）。
/// 并发：`&mut` 独占借用（§7.3 单一执行模型；不得跨线程共享 Store）。
/// 安全/权限：只做错误分类，不执行 guest 代码，不授予或撤销任何能力（§7.6）。
pub fn classify_wasm_error(
    store: &mut crate::store::StoreHandle,
    err: ErrorSource,
) -> RuntimeError {
    let outcome = {
        if let Some(kind) = store.take_rejection() {
            Outcome::Resource(kind)
        } else if let Some(trap) = find_trap(err.as_ref()) {
            match trap {
                // 0.1.0 中 `Interrupt` 只可能来自 epoch interruption（§7.5；
                // wasm-interrupt proposal 未启用）。
                wasmtime::Trap::Interrupt => Outcome::Epoch,
                other => Outcome::Trap(TrapKind::from(other)),
            }
        } else {
            Outcome::Unknown
        }
    };
    match outcome {
        Outcome::Resource(kind) => RuntimeError::ResourceLimit { kind, source: err },
        Outcome::Epoch => RuntimeError::Execution {
            kind: WasmFailure::EpochDeadlineExceeded,
            source: err,
        },
        Outcome::Trap(trap) => RuntimeError::Execution {
            kind: WasmFailure::Trap(trap),
            source: err,
        },
        Outcome::Unknown => RuntimeError::Execution {
            kind: WasmFailure::Unknown,
            source: err,
        },
    }
}

/// 在错误链中查找 wasmtime trap（`downcast_ref` 走 error chain）。
fn find_trap<'a>(err: &'a (dyn StdError + 'static)) -> Option<&'a wasmtime::Trap> {
    let mut next: Option<&'a (dyn StdError + 'static)> = Some(err);
    while let Some(current) = next {
        if let Some(trap) = current.downcast_ref::<wasmtime::Trap>() {
            return Some(trap);
        }
        next = current.source();
    }
    None
}
