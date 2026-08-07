//! Wasmtime 资源限制器实现（§7.4）。
//!
//! §7.4 边界：`ResourceLimiter` 只解决 Wasmtime 可见资源（linear memory
//! 大小/数量、table 数量/元素、实例数量）；host 分配的缓冲、数据库结果、
//! 缓存、HTTP body 等必须由 Core/适配层自己有界化，不由本模块强制。
//!
//! wasmtime 36 的 `ResourceLimiter` 语义：`memory_growing`/`table_growing`
//! 返回 `Ok(false)` 时增长失败（guest 的 `memory.grow` 返回 -1，实例化时
//! 的初始分配/表分配失败）；`instances()`/`tables()`/`memories()` 返回
//! Store 内的创建上限（wasmtime 内部计数比较）。超限拒绝被记录到
//! 拒绝记录（Cell），供 [`crate::error::classify_wasm_error`] 读取——
//! 调用方必须在每次执行前清除记录（见 [`crate::store::StoreHandle::begin_execution`]）。

use std::cell::Cell;

use crate::budget::ResourceBudget;
use crate::error::ResourceLimitKind;

/// 每个 Store 的 wasmtime 资源限制器。
///
/// 通过 [`wasmtime::Store::limiter`] 以闭包方式挂接（闭包指向 Store 宿主数据
/// 中的本限制器，不额外分配）。
///
/// 并发保证：Store 单一执行模型（§7.3），拒绝记录使用 `Cell`（无锁、同线程
/// 访问；`StoreHostState` 因此不实现 `Sync`，Store 不在线程间共享）。
pub(crate) struct StoreResourceLimiter {
    budget: ResourceBudget,
    rejections: Cell<Option<ResourceLimitKind>>,
}

impl StoreResourceLimiter {
    pub(crate) fn new(budget: ResourceBudget) -> Self {
        Self {
            budget,
            rejections: Cell::new(None),
        }
    }

    /// 读取并清除最近一次拒绝类别。
    pub(crate) fn take_rejection(&self) -> Option<ResourceLimitKind> {
        self.rejections.take()
    }

    fn record_rejection(&self, kind: ResourceLimitKind) -> bool {
        self.rejections.set(Some(kind));
        false
    }
}

impl wasmtime::ResourceLimiter for StoreResourceLimiter {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        match self.budget.linear_memory {
            Some(limit) if desired > limit.as_bytes().as_usize() => {
                Ok(self.record_rejection(ResourceLimitKind::LinearMemory))
            }
            _ => Ok(true),
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        match self.budget.table_elements {
            Some(limit) if usize::try_from(limit.as_u64()).unwrap_or(usize::MAX) < desired => {
                Ok(self.record_rejection(ResourceLimitKind::TableElements))
            }
            _ => Ok(true),
        }
    }

    fn instances(&self) -> usize {
        self.budget.instances.map_or(usize::MAX, |limit| {
            usize::try_from(limit.as_u64()).unwrap_or(usize::MAX)
        })
    }

    fn tables(&self) -> usize {
        self.budget.tables.map_or(usize::MAX, |limit| {
            usize::try_from(limit.as_u64()).unwrap_or(usize::MAX)
        })
    }

    fn memories(&self) -> usize {
        self.budget.memories.map_or(usize::MAX, |limit| {
            usize::try_from(limit.as_u64()).unwrap_or(usize::MAX)
        })
    }
}
