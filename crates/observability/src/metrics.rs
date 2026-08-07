//! 0.1.0 最小 typed metrics（§5.1：runtime 自身指标；§34.3：性能基线数据
//! 来源）。
//!
//! 不引入外部 metrics crate（YAGNI，§12.6）：[`Counter`]（单调计数器，饱和
//! 加法）与 [`Histogram`]（固定桶边界直方图）均为 typed 类型，由
//! [`MetricsRegistry`] 显式注册（唯一 owner，§12.4：composition root 创建
//! 并通过 `Arc`/`Clone` 注入）。0.1.0 的指标数据通过
//! [`MetricsRegistry::snapshot`] 输出（日志 / 审计 / 状态），后续按需替换
//! 输出通道（§5.3：不进入 Core 的具体监控集成由 Component 承担）。
//!
//! # Secret（§16.6）
//!
//! metric name 为受校验标识符，样本为无符号数：本模块不接收任何 secret 值，
//! metrics label 中也不存在可携带 secret 的自由文本。

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// 直方图桶上界（最后一个上界之后为溢出桶）。
///
/// 0.1.0 基线：2 的幂（1 至 2^20），覆盖毫秒级时长 / 字节级大小样本的常用
/// 范围；桶选择可在获得真实数据后经 ADR 调整（§34.3：阈值由实测数据设定）。
pub const HISTOGRAM_BUCKET_UPPER_BOUNDS: [u64; 21] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
    262144, 524288, 1048576,
];

/// 桶总数（含溢出桶）。
pub const HISTOGRAM_BUCKET_COUNT: usize = HISTOGRAM_BUCKET_UPPER_BOUNDS.len() + 1;

/// metric 名称（§13.1 受校验 newtype）。
///
/// 不变量（validate-on-construct，§13.3）：非空、长度 ≤ [`MetricName::MAX_LEN`]
/// 字节、仅小写 ascii 字母数字与 `_` `.` `-` `:`。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MetricName(String);

impl MetricName {
    /// 名称最大长度（字节）。
    pub const MAX_LEN: usize = 128;

    /// 校验构造。
    pub fn new(value: impl Into<String>) -> Result<MetricName, MetricsError> {
        let value = value.into();
        crate::validate_identifier(&value, Self::MAX_LEN).map_err(MetricsError::InvalidName)?;
        Ok(MetricName(value))
    }

    /// 名称视图。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MetricName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// metric 类型（注册冲突检测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// 单调计数器。
    Counter,
    /// 固定桶直方图。
    Histogram,
}

/// metrics 封闭错误（§14.1 thiserror）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MetricsError {
    /// 名称校验失败。
    #[error("invalid metric name: {0}")]
    InvalidName(String),

    /// 同一名称以不同类型注册（确定性拒绝，不静默覆盖）。
    #[error("metric {name} already registered as {existing:?}")]
    KindMismatch {
        /// 冲突的名称。
        name: MetricName,
        /// 已注册的类型。
        existing: MetricKind,
    },
}

/// 单调计数器（§34.3）。
///
/// 饱和加法（§14.4：不依赖整数回绕）；内部 `AtomicU64`，无锁、无全局状态。
#[derive(Clone)]
pub struct Counter {
    inner: Arc<CounterInner>,
}

struct CounterInner {
    value: AtomicU64,
}

impl Counter {
    fn new() -> Counter {
        Counter {
            inner: Arc::new(CounterInner {
                value: AtomicU64::new(0),
            }),
        }
    }

    /// 累加 `delta`（饱和到 `u64::MAX`），返回累加后的新值。
    pub fn increment(&self, delta: u64) -> u64 {
        let old =
            match self
                .inner
                .value
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(delta))
                }) {
                Ok(old) | Err(old) => old,
            };
        old.saturating_add(delta)
    }

    /// 当前值。
    pub fn value(&self) -> u64 {
        self.inner.value.load(Ordering::Relaxed)
    }
}

/// 固定桶直方图（0.1.0 最小实现；桶边界见 [`HISTOGRAM_BUCKET_UPPER_BOUNDS`]）。
///
/// 归桶规则：样本 `sample` 归入满足 `bound < sample` 的最后一个桶上界所在
/// 桶；`sample = 0` 归入第 0 桶；超过最大上界的样本归入溢出桶（最后一桶）。
/// sum / count 饱和累加（§14.4）；样本单位由调用方定义并在 metric 命名上
/// 注明。
#[derive(Clone)]
pub struct Histogram {
    inner: Arc<HistogramInner>,
}

struct HistogramInner {
    buckets: [AtomicU64; HISTOGRAM_BUCKET_COUNT],
    sum: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new() -> Histogram {
        Histogram {
            inner: Arc::new(HistogramInner {
                buckets: [const { AtomicU64::new(0) }; HISTOGRAM_BUCKET_COUNT],
                sum: AtomicU64::new(0),
                count: AtomicU64::new(0),
            }),
        }
    }

    /// 记录一个样本（饱和累加，不失败、不 panic）。
    pub fn record(&self, sample: u64) {
        let index = HISTOGRAM_BUCKET_UPPER_BOUNDS.partition_point(|&bound| bound < sample);
        let bucket = if index < HISTOGRAM_BUCKET_UPPER_BOUNDS.len() {
            index
        } else {
            HISTOGRAM_BUCKET_UPPER_BOUNDS.len()
        };
        let _ = self.inner.buckets[bucket].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(1)),
        );
        let _ = self
            .inner
            .sum
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(sample))
            });
        let _ = self
            .inner
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
    }

    /// 样本数。
    pub fn count(&self) -> u64 {
        self.inner.count.load(Ordering::Relaxed)
    }

    /// 样本总和。
    pub fn sum(&self) -> u64 {
        self.inner.sum.load(Ordering::Relaxed)
    }

    /// 各桶计数（长度 [`HISTOGRAM_BUCKET_COUNT`]，最后一项为溢出桶）。
    pub fn bucket_counts(&self) -> Vec<u64> {
        self.inner
            .buckets
            .iter()
            .map(|bucket| bucket.load(Ordering::Relaxed))
            .collect()
    }
}

/// 指标注册表（§12.4：唯一 owner；composition root 创建并通过 `Clone` 注入）。
///
/// 名称一旦以某类型注册，同类型注册返回同一句柄（`Arc` 共享），不同类型
/// 注册返回 [`MetricsError::KindMismatch`]（持锁检查 + 插入，无竞态、无
/// 静默覆盖）。
#[derive(Clone)]
pub struct MetricsRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    metrics: Mutex<HashMap<MetricName, MetricEntry>>,
}

enum MetricEntry {
    Counter(Counter),
    Histogram(Histogram),
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsRegistry {
    /// 创建空注册表。
    pub fn new() -> MetricsRegistry {
        MetricsRegistry {
            inner: Arc::new(RegistryInner {
                metrics: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// 注册或获取计数器句柄（§13.3：名称在边界校验一次）。
    pub fn counter(&self, name: MetricName) -> Result<Counter, MetricsError> {
        let mut metrics = lock(&self.inner.metrics);
        if let Some(entry) = metrics.get(&name) {
            return match entry {
                MetricEntry::Counter(counter) => Ok(counter.clone()),
                MetricEntry::Histogram(_) => Err(MetricsError::KindMismatch {
                    name,
                    existing: MetricKind::Histogram,
                }),
            };
        }
        let counter = Counter::new();
        metrics.insert(name, MetricEntry::Counter(counter.clone()));
        Ok(counter)
    }

    /// 注册或获取直方图句柄。
    pub fn histogram(&self, name: MetricName) -> Result<Histogram, MetricsError> {
        let mut metrics = lock(&self.inner.metrics);
        if let Some(entry) = metrics.get(&name) {
            return match entry {
                MetricEntry::Histogram(histogram) => Ok(histogram.clone()),
                MetricEntry::Counter(_) => Err(MetricsError::KindMismatch {
                    name,
                    existing: MetricKind::Counter,
                }),
            };
        }
        let histogram = Histogram::new();
        metrics.insert(name, MetricEntry::Histogram(histogram.clone()));
        Ok(histogram)
    }

    /// 注册表快照（确定性：按名称排序；§34.3 数据来源）。
    pub fn snapshot(&self) -> MetricsSnapshot {
        let metrics = lock(&self.inner.metrics);
        let mut counters = Vec::new();
        let mut histograms = Vec::new();
        for (name, entry) in metrics.iter() {
            match entry {
                MetricEntry::Counter(counter) => counters.push(CounterSample {
                    name: name.clone(),
                    value: counter.value(),
                }),
                MetricEntry::Histogram(histogram) => histograms.push(HistogramSample {
                    name: name.clone(),
                    count: histogram.count(),
                    sum: histogram.sum(),
                    buckets: histogram.bucket_counts(),
                }),
            }
        }
        counters.sort_by(|a, b| a.name.cmp(&b.name));
        histograms.sort_by(|a, b| a.name.cmp(&b.name));
        MetricsSnapshot {
            counters,
            histograms,
        }
    }
}

/// 计数器快照样本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterSample {
    /// 名称。
    pub name: MetricName,
    /// 当前值。
    pub value: u64,
}

/// 直方图快照样本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistogramSample {
    /// 名称。
    pub name: MetricName,
    /// 样本数。
    pub count: u64,
    /// 样本总和。
    pub sum: u64,
    /// 各桶计数（长度 [`HISTOGRAM_BUCKET_COUNT`]，最后一项为溢出桶）。
    pub buckets: Vec<u64>,
}

/// 注册表快照（§34.3；确定性排序输出）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MetricsSnapshot {
    /// 计数器样本（按名称升序）。
    pub counters: Vec<CounterSample>,
    /// 直方图样本（按名称升序）。
    pub histograms: Vec<HistogramSample>,
}

/// 锁助手：poison 恢复（§14.2：不 panic；poison 仅表示其他线程 panic，
/// 数据本身仍是 Safe Rust 状态）。
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(value: &str) -> MetricName {
        ok(MetricName::new(value), "valid metric name")
    }

    fn ok<T, E: fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    #[test]
    fn name_validation() {
        assert!(MetricName::new("runtime.invoke.count").is_ok());
        assert!(MetricName::new("component-requests").is_ok());
        assert!(MetricName::new("mem_used_bytes:total").is_ok());
        assert!(matches!(
            MetricName::new(""),
            Err(MetricsError::InvalidName(_))
        ));
        assert!(matches!(
            MetricName::new("HasUpper"),
            Err(MetricsError::InvalidName(_))
        ));
        assert!(matches!(
            MetricName::new("has space"),
            Err(MetricsError::InvalidName(_))
        ));
        assert!(matches!(
            MetricName::new("a".repeat(MetricName::MAX_LEN + 1)),
            Err(MetricsError::InvalidName(_))
        ));
    }

    #[test]
    fn counter_increments_saturating() {
        let registry = MetricsRegistry::new();
        let counter = ok(registry.counter(name("c.increments")), "register counter");
        assert_eq!(counter.increment(5), 5);
        assert_eq!(counter.increment(0), 5);
        assert_eq!(counter.value(), 5);
        counter.increment(u64::MAX);
        counter.increment(u64::MAX);
        assert_eq!(counter.value(), u64::MAX);
    }

    #[test]
    fn registry_returns_same_handle() {
        let registry = MetricsRegistry::new();
        let first = ok(registry.counter(name("c.shared")), "first handle");
        let second = ok(registry.counter(name("c.shared")), "second handle");
        first.increment(3);
        assert_eq!(second.value(), 3);
    }

    #[test]
    fn kind_mismatch_rejected() {
        let registry = MetricsRegistry::new();
        let counter_name = name("m.counter");
        ok(registry.counter(counter_name.clone()), "register counter");
        assert!(matches!(
            registry.histogram(counter_name),
            Err(MetricsError::KindMismatch {
                existing: MetricKind::Counter,
                ..
            })
        ));
        let histogram_name = name("m.histogram");
        ok(
            registry.histogram(histogram_name.clone()),
            "register histogram",
        );
        assert!(matches!(
            registry.counter(histogram_name),
            Err(MetricsError::KindMismatch {
                existing: MetricKind::Histogram,
                ..
            })
        ));
    }

    #[test]
    fn histogram_bucket_placement() {
        let registry = MetricsRegistry::new();
        let histogram = ok(
            registry.histogram(name("h.latency_ms")),
            "register histogram",
        );
        // 0, 1 → 第 0 桶；2 → 第 1 桶；1024 → 第 10 桶（上界 1024）；
        // 2^30 → 溢出桶（最后一桶）。
        histogram.record(0);
        histogram.record(1);
        histogram.record(2);
        histogram.record(1024);
        histogram.record(1 << 30);
        let buckets = histogram.bucket_counts();
        assert_eq!(buckets.len(), HISTOGRAM_BUCKET_COUNT);
        assert_eq!(buckets[0], 2);
        assert_eq!(buckets[1], 1);
        assert_eq!(buckets[10], 1);
        assert_eq!(buckets[HISTOGRAM_BUCKET_COUNT - 1], 1);
        assert_eq!(histogram.count(), 5);
        assert_eq!(histogram.sum(), 1 + 2 + 1024 + (1 << 30));
    }

    #[test]
    fn snapshot_is_deterministic() {
        let registry = MetricsRegistry::new();
        let counter_a = ok(registry.counter(name("a.count")), "counter a");
        let counter_z = ok(registry.counter(name("z.count")), "counter z");
        counter_a.increment(1);
        counter_z.increment(2);
        ok(registry.histogram(name("m.latency")), "histogram").record(7);
        let first = registry.snapshot();
        let second = registry.snapshot();
        assert_eq!(first, second);
        assert_eq!(first.counters.len(), 2);
        assert_eq!(first.counters[0].name.as_str(), "a.count");
        assert_eq!(first.counters[1].name.as_str(), "z.count");
        assert_eq!(first.counters[0].value, 1);
        assert_eq!(first.counters[1].value, 2);
        assert_eq!(first.histograms.len(), 1);
        assert_eq!(first.histograms[0].name.as_str(), "m.latency");
        assert_eq!(first.histograms[0].count, 1);
        assert_eq!(first.histograms[0].sum, 7);
    }

    #[test]
    fn counter_concurrent_increments_are_exact() {
        const THREADS: u64 = 4;
        const PER_THREAD: u64 = 1000;
        let counter = Counter::new();
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let counter = counter.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..PER_THREAD {
                    counter.increment(1);
                }
            }));
        }
        for handle in handles {
            assert!(handle.join().is_ok(), "worker thread must not panic");
        }
        assert_eq!(counter.value(), THREADS * PER_THREAD);
    }
}
