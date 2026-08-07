//! 资源治理预算类型（§7.4 / §13.1：禁止 primitive obsession）。
//!
//! §7.4 边界说明：`ResourceLimiter` 只解决 Wasmtime 可见资源（linear memory
//! 大小/数量、table 数量/元素、实例数量）。`host_buffers`、`background_tasks`、
//! `http_body` 不进入 wasmtime 强制路径，必须由 Core/适配层自己有界化
//! （Host 分配的缓冲、数据库结果、缓存、HTTP request/response body 等）；
//! 本预算类型对它们仅作策略载体，向下传递给各强制点。
//!
//! 所有构造/边界转换使用 checked/saturating 语义（§14.4）。

use std::num::NonZeroUsize;
use std::time::Duration;

/// 字节大小语义类型（§13.2）。
///
/// 构造即值对象；与 `usize` 的边界转换见 [`ByteSize::as_usize`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(u64);

impl ByteSize {
    /// 以字节为单位构造。
    pub const fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    /// 以 KiB 为单位构造（saturating 乘法，§14.4）。
    pub const fn kib(kib: u64) -> Self {
        Self(kib.saturating_mul(1024))
    }

    /// 以 MiB 为单位构造（saturating 乘法，§14.4）。
    pub const fn mib(mib: u64) -> Self {
        Self(mib.saturating_mul(1024 * 1024))
    }

    /// 原始字节数。
    pub const fn as_bytes(self) -> u64 {
        self.0
    }

    /// 到 `usize` 的饱和转换（仅在 32 位宿主上可能截断；0.1.0 不支持 32 位，§9.3）。
    pub fn as_usize(self) -> usize {
        usize::try_from(self.0).unwrap_or(usize::MAX)
    }
}

/// linear memory 总大小上限（§7.4；Wasmtime 强制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LinearMemoryLimit(ByteSize);

impl LinearMemoryLimit {
    /// 构造。
    pub const fn new(bytes: ByteSize) -> Self {
        Self(bytes)
    }

    /// 上限字节数。
    pub const fn as_bytes(self) -> ByteSize {
        self.0
    }
}

/// linear memory 数量上限（§7.4；Wasmtime 强制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemoryCountLimit(u64);

impl MemoryCountLimit {
    /// 构造。
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// 上限值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// table 数量上限（§7.4；Wasmtime 强制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableCountLimit(u64);

impl TableCountLimit {
    /// 构造。
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// 上限值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// table 元素总数上限（§7.4；每个元素一个指针宽；Wasmtime 强制）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableElementLimit(u64);

impl TableElementLimit {
    /// 构造。
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// 上限值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// 实例数量上限（§7.4；Wasmtime 强制；Component 实例化含其 core 实例）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct InstanceCountLimit(u64);

impl InstanceCountLimit {
    /// 构造。
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// 上限值。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// Host 缓冲上限（§7.4 注释：StoreLimits/ResourceLimiter 不覆盖；由 Core
/// 自己有界化。本类型仅作策略载体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HostBufferLimit(ByteSize);

impl HostBufferLimit {
    /// 构造。
    pub const fn new(bytes: ByteSize) -> Self {
        Self(bytes)
    }

    /// 上限字节数。
    pub const fn as_bytes(self) -> ByteSize {
        self.0
    }
}

/// HTTP request/response body 上限（§7.4；Web/wasi-http 适配层强制；本类型
/// 仅作策略载体，强制点在适配层）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HttpBodyLimit(ByteSize);

impl HttpBodyLimit {
    /// 构造。
    pub const fn new(bytes: ByteSize) -> Self {
        Self(bytes)
    }

    /// 上限字节数。
    pub const fn as_bytes(self) -> ByteSize {
        self.0
    }
}

/// 最大并发执行数（= Instance Set 槽位数，§7.4）。
///
/// 类型保证非零（§13.4：NonZero limit 使用 NonZeroUsize）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxConcurrent(NonZeroUsize);

impl MaxConcurrent {
    /// 最小合法值（1）。
    pub const MIN: Self = Self(NonZeroUsize::MIN);

    /// 构造；`value == 0` 返回 `None`。
    pub const fn try_new(value: usize) -> Option<Self> {
        match NonZeroUsize::new(value) {
            Some(inner) => Some(Self(inner)),
            None => None,
        }
    }

    /// 上限值。
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for MaxConcurrent {
    /// 生产默认：8。
    fn default() -> Self {
        // 8 恒非零；防御式回退到 MIN（1）不改变语义（§14.2：无 unwrap）。
        Self::try_new(8).unwrap_or(Self::MIN)
    }
}

/// 最大排队等待数（dispatch 阻塞等待的上限，§7.4）。
///
/// 类型保证非零（§13.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaxQueued(NonZeroUsize);

impl MaxQueued {
    /// 最小合法值（1）。
    pub const MIN: Self = Self(NonZeroUsize::MIN);

    /// 构造；`value == 0` 返回 `None`。
    pub const fn try_new(value: usize) -> Option<Self> {
        match NonZeroUsize::new(value) {
            Some(inner) => Some(Self(inner)),
            None => None,
        }
    }

    /// 上限值。
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for MaxQueued {
    /// 生产默认：64。
    fn default() -> Self {
        Self::try_new(64).unwrap_or(Self::MIN)
    }
}

/// Component 生成的后台任务数量上限（§7.4；由 Core/适配层记账，
/// 本类型仅作策略载体）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackgroundTaskLimit(NonZeroUsize);

impl BackgroundTaskLimit {
    /// 最小合法值（1）。
    pub const MIN: Self = Self(NonZeroUsize::MIN);

    /// 构造；`value == 0` 返回 `None`。
    pub const fn try_new(value: usize) -> Option<Self> {
        match NonZeroUsize::new(value) {
            Some(inner) => Some(Self(inner)),
            None => None,
        }
    }

    /// 上限值。
    pub const fn get(self) -> NonZeroUsize {
        self.0
    }
}

impl Default for BackgroundTaskLimit {
    /// 生产默认：8。
    fn default() -> Self {
        Self::try_new(8).unwrap_or(Self::MIN)
    }
}

/// 单次调用截止时间（§7.5：每次不可信执行设置的 epoch deadline；§13.1）。
///
/// `Duration::ZERO` 在类型层允许，但在 [`crate::store::StoreHandle::set_deadline`]
/// 处被拒绝（零时长 deadline 无意义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallDeadline(Duration);

impl CallDeadline {
    /// 构造。
    pub const fn new(deadline: Duration) -> Self {
        Self(deadline)
    }

    /// 截止时长。
    pub const fn get(self) -> Duration {
        self.0
    }
}

/// 单个 Component 实例的资源预算（§7.4）。
///
/// 覆盖（§7.4 清单）：linear memory 上限、table/instance 等 Wasmtime 资源上限、
/// host buffer 上限、最大并发、最大排队、单次调用截止时间、后台任务数量、
/// HTTP body 上限。`None` 表示显式“不设上限”（不推荐，生产策略应显式设值）。
///
/// 默认值为生产默认；具体 Component 的 policy 以 struct update 覆盖单个维度：
/// `ResourceBudget { linear_memory: Some(...), ..ResourceBudget::default() }`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceBudget {
    /// linear memory 总大小上限（Wasmtime 强制；默认 64 MiB）。
    pub linear_memory: Option<LinearMemoryLimit>,
    /// linear memory 数量上限（Wasmtime 强制；默认 8）。
    pub memories: Option<MemoryCountLimit>,
    /// table 数量上限（Wasmtime 强制；默认 16）。
    pub tables: Option<TableCountLimit>,
    /// table 元素总数上限（Wasmtime 强制；默认 1 Mi 个元素）。
    pub table_elements: Option<TableElementLimit>,
    /// 实例数量上限（Wasmtime 强制；默认 32。注意 Component 实例化会创建其
    /// 内部 core 实例，计数为整个 Store 累计）。
    pub instances: Option<InstanceCountLimit>,
    /// Host 缓冲上限（§7.4 注释：由 Core 自己有界化，非 wasmtime 强制；默认 16 MiB）。
    pub host_buffers: Option<HostBufferLimit>,
    /// 最大并发执行数 = Instance Set 槽位数（默认 8）。
    pub max_concurrent: MaxConcurrent,
    /// 最大排队等待数（默认 64）。
    pub max_queued: MaxQueued,
    /// 单次调用截止时间（§7.5；默认 5s）。`None` = 不自动设置 deadline，
    /// 调用方必须显式设置或 reset，否则 epoch 启用时 deadline 为 0 立即 trap。
    pub call_deadline: Option<CallDeadline>,
    /// Component 后台任务数量上限（§7.4；Core/适配层记账；默认 8）。
    pub background_tasks: BackgroundTaskLimit,
    /// HTTP request/response body 上限（§7.4；Web/wasi-http 适配层强制；默认 4 MiB）。
    pub http_body: Option<HttpBodyLimit>,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            linear_memory: Some(LinearMemoryLimit::new(ByteSize::mib(64))),
            memories: Some(MemoryCountLimit::new(8)),
            tables: Some(TableCountLimit::new(16)),
            table_elements: Some(TableElementLimit::new(1024 * 1024)),
            instances: Some(InstanceCountLimit::new(32)),
            host_buffers: Some(HostBufferLimit::new(ByteSize::mib(16))),
            max_concurrent: MaxConcurrent::default(),
            max_queued: MaxQueued::default(),
            call_deadline: Some(CallDeadline::new(Duration::from_secs(5))),
            background_tasks: BackgroundTaskLimit::default(),
            http_body: Some(HttpBodyLimit::new(ByteSize::mib(4))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_size_conversions_and_order() {
        assert_eq!(ByteSize::new(1024), ByteSize::kib(1));
        assert_eq!(ByteSize::new(1024 * 1024), ByteSize::mib(1));
        assert_eq!(ByteSize::kib(1).as_usize(), 1024);
        assert!(ByteSize::kib(2) > ByteSize::kib(1));
    }

    #[test]
    fn byte_size_checked_conversion_never_underflows() {
        // 饱和语义：超大值转换为 usize 时取 usize::MAX，不 panic。
        let huge = ByteSize::new(u64::MAX);
        let _ = huge.as_usize();
    }

    #[test]
    fn nonzero_limits_reject_zero() {
        let none = MaxConcurrent::try_new(0);
        assert!(none.is_none());
        let some = MaxConcurrent::try_new(1);
        assert!(some.is_some());
    }

    #[test]
    fn default_budget_covers_all_mandated_dimensions() {
        // §7.4：预算必须覆盖清单中的全部维度。
        let budget = ResourceBudget::default();
        assert!(budget.linear_memory.is_some());
        assert!(budget.memories.is_some());
        assert!(budget.tables.is_some());
        assert!(budget.table_elements.is_some());
        assert!(budget.instances.is_some());
        assert!(budget.host_buffers.is_some());
        assert!(budget.max_concurrent.get().get() > 0);
        assert!(budget.max_queued.get().get() > 0);
        assert!(budget.call_deadline.is_some());
        assert!(budget.background_tasks.get().get() > 0);
        assert!(budget.http_body.is_some());
    }
}
