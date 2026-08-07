//! 0.3.0 Stateful Runtime（§41）——scheduler 与 scheduler/event backpressure
//! （§41.2 MUST）的领域类型。
//!
//! 契约面：`operune:scheduler@0.1.0`（scheduler.wit / handler.wit，已提交
//! 稳定）。语义边界（scheduler.wit 顶部注释）：
//!
//! - 交付模型：**Core-mediated push**（guest 导出 `handler`，Core 在 fire
//!   时刻同步调用），不需要 async func（§8.3 WASI 0.3 Gate 通过前不引入）；
//!   交付落在 bounded Instance Set 的任一实例（§7.3），guest 不得假设
//!   实例亲和；
//! - `fire-at` / `next-fire-at` 是 **UTC 硬时刻**（[`UtcInstant`]，自 Unix
//!   epoch 起），不是相对延迟；本契约不含时间读取（时间读取用
//!   wasi:clocks），"目标时刻已过去 → invalid-trigger" 是 application 层
//!   判定；
//! - 交付为 **at-most-once**：无重试、无 catch-up 回放；每次 fire 要么交付
//!   一次、要么计入错过（`missed-fires`）；cancel 竞态下已在途的一次 fire
//!   仍可能先到（guest 用 `sequence` 幂等）；
//! - 定时任务本体（fire 序列）是 Core 侧事实：跨实例、跨重启存活（持久化
//!   策略是 Core 实现细节）；0.1.0 契约只携带触发形态。

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::time::{Duration, UtcInstant};

/// 任务触发形态（闭集 variant；与 WIT `schedule-trigger` variant 严格对齐，
/// §6.3 variant 表达互斥形态）。
///
/// - `OneShot`：在 `at`（`fire-at`）时刻触发一次；
/// - `Periodic`：`next_fire_at` 时刻首次触发，此后每 `interval` 触发；
///   错过不补投（scheduler.wit 交付语义）；恢复后从当前时刻继续。
///
/// 0.1.0 契约**没有** `end`/结束时刻字段（scheduler.wit 明文：periodic 只
/// 携带 `next-fire-at` 与 `interval`；任务结束由 cancel 表达）。
///
/// 注册期校验（目标时刻已过去、interval 低于策略下限 → `invalid-trigger`）
/// 属于 application 层（本契约不含时间读取，wasi:clocks 在 guest 侧）；
/// 本类型自身无额外不变量，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScheduleTrigger {
    /// 一次性：在 `at` 时刻触发一次（WIT `one-shot(datetime)`）。
    OneShot {
        /// 触发时刻（UTC 硬时刻）。
        at: UtcInstant,
    },
    /// 周期：`next_fire_at` 时刻首次触发，此后每 `interval` 触发。
    Periodic {
        /// 首次触发时刻（UTC 硬时刻；WIT `next-fire-at`）。
        next_fire_at: UtcInstant,
        /// 触发间隔（WIT `interval`：毫秒精度 `duration` record；
        /// Domain 以 [`Duration`] 表达，毫秒值精确无损）。
        interval: Duration,
    },
}

impl ScheduleTrigger {
    /// 一次性触发（§13.3 边界解析一次；`at` 已校验）。
    pub fn one_shot(at: UtcInstant) -> Self {
        Self::OneShot { at }
    }

    /// 周期触发（`next_fire_at` 首次触发，此后每 `interval`）。
    pub fn periodic(next_fire_at: UtcInstant, interval: Duration) -> Self {
        Self::Periodic {
            next_fire_at,
            interval,
        }
    }

    /// 触发时刻视图：一次性为 `at`，周期为首发时刻。
    pub fn first_fire_at(self) -> UtcInstant {
        match self {
            Self::OneShot { at } => at,
            Self::Periodic { next_fire_at, .. } => next_fire_at,
        }
    }
}

/// Core 分配的任务标识（§13.5 record wrapper；与 WIT `scheduled-task-id`
/// record 严格对齐）。
///
/// 任意 u64 都是合法任务标识，构造不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScheduledTaskId(u64);

impl ScheduledTaskId {
    /// 从 u64 构造（与 WIT `scheduled-task-id.value` 字段一一对应；
    /// 不可失败）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ScheduledTaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for ScheduledTaskId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ScheduledTaskId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 任务生命周期状态（闭集 enum；与 WIT `task-state` enum 严格对齐，§6.3
/// enum 表达闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskState {
    /// 已注册，等待未来触发。
    Scheduled,
    /// 已取消（`cancel` 成功；不再触发）。
    Cancelled,
    /// 已结束：one-shot 已触发/已错过，或周期性任务在取消前的终态以外
    /// 情形（见 `Cancelled`；scheduler.wit 原文注释）。
    Completed,
}

impl TaskState {
    /// 与 WIT `task-state` 变体名一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Scheduled => "scheduled",
            Self::Cancelled => "cancelled",
            Self::Completed => "completed",
        }
    }

    /// 从 WIT 变体名解析（适配层 / 持久化边界，§13.3 边界解析一次）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "scheduled" => Ok(Self::Scheduled),
            "cancelled" => Ok(Self::Cancelled),
            "completed" => Ok(Self::Completed),
            _ => Err(DomainError::invalid_value(
                ValueKind::TaskState,
                format!("{s:?} is not a task-state variant (scheduled | cancelled | completed)"),
            )),
        }
    }
}

impl fmt::Display for TaskState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for TaskState {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for TaskState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for TaskState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 任务状态查询结果（供错过观测与诊断；与 WIT `task-status` record 严格
/// 对齐，`get-task-status` 返回）。
///
/// 语义（scheduler.wit 明文）：one-shot 全错过（`missed_fires > 0` 且
/// `state == Completed`）时 guest 以此可观测全错过的交付损失；周期性任务
/// 恢复后从当前时刻继续，不补投。
///
/// 构造不可失败（字段各自在构造时已验证）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskStatus {
    state: TaskState,
    /// 自上次成功交付以来被背压/停机错过的 fire 数
    /// （与 handler 载荷的 `missed_fires` 同源，scheduler.wit）。
    missed_fires: u64,
    /// 下一次计划触发时刻（一次性已触发或已取消时为 none）。
    next_fire_at: Option<UtcInstant>,
}

impl TaskStatus {
    /// 构造任务状态查询结果（§13.3 边界解析一次）。
    pub fn new(state: TaskState, missed_fires: u64, next_fire_at: Option<UtcInstant>) -> Self {
        Self {
            state,
            missed_fires,
            next_fire_at,
        }
    }

    /// 生命周期状态。
    pub const fn state(&self) -> TaskState {
        self.state
    }

    /// 错过的 fire 数（背压/停机观测面）。
    pub const fn missed_fires(&self) -> u64 {
        self.missed_fires
    }

    /// 下一次计划触发时刻（无后续触发时为 `None`）。
    pub const fn next_fire_at(&self) -> Option<UtcInstant> {
        self.next_fire_at
    }
}

/// 一次 fire 的交付载荷（与 WIT `trigger-payload` record 严格对齐，
/// handler 的 `on-trigger` 参数）。
///
/// 语义（handler.wit 明文）：`sequence` 从 1 递增（周期性任务持续递增），
/// guest 用它做幂等（cancel 竞态下已投递序号不重投）；`scheduled_at` 是
/// 本次 fire 的**名义计划时刻**（UTC），实际交付可能晚于该时刻（0.1.0 不
/// 承诺交付延迟上界，backpressure 窗口的延迟属正常现象）；`missed_fires`
/// 自上次成功交付以来因背压/停机错过的 fire 数（one-shot 该字段只可能
/// 是 0 或 1）。
///
/// 构造不可失败（字段各自在构造时已验证；`sequence`/`missed_fires` 由
/// Core 产生，非边界解析输入）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TriggerPayload {
    task_id: ScheduledTaskId,
    sequence: u64,
    scheduled_at: UtcInstant,
    missed_fires: u64,
}

impl TriggerPayload {
    /// 构造一次 fire 的交付载荷（§13.3 边界解析一次）。
    pub fn new(
        task_id: ScheduledTaskId,
        sequence: u64,
        scheduled_at: UtcInstant,
        missed_fires: u64,
    ) -> Self {
        Self {
            task_id,
            sequence,
            scheduled_at,
            missed_fires,
        }
    }

    /// 触发来源的任务标识。
    pub const fn task_id(&self) -> ScheduledTaskId {
        self.task_id
    }

    /// 本任务的第 N 次 fire（从 1 递增；幂等序号）。
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// 本次 fire 的名义计划时刻（UTC 硬时刻）。
    pub const fn scheduled_at(&self) -> UtcInstant {
        self.scheduled_at
    }

    /// 自上次成功交付以来错过的 fire 数。
    pub const fn missed_fires(&self) -> u64 {
        self.missed_fires
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    fn instant(seconds: u64) -> UtcInstant {
        ok(UtcInstant::from_unix_parts(seconds, 0), "instant")
    }

    #[test]
    fn schedule_trigger_constructors() {
        let one_shot = ScheduleTrigger::one_shot(instant(1_752_000_000));
        assert_eq!(
            one_shot,
            ScheduleTrigger::OneShot {
                at: instant(1_752_000_000)
            }
        );
        assert_eq!(one_shot.first_fire_at(), instant(1_752_000_000));

        let periodic = ScheduleTrigger::periodic(instant(1_752_000_000), Duration::from_secs(60));
        assert_eq!(
            periodic,
            ScheduleTrigger::Periodic {
                next_fire_at: instant(1_752_000_000),
                interval: Duration::from_secs(60)
            }
        );
        assert_eq!(periodic.first_fire_at(), instant(1_752_000_000));
    }

    #[test]
    fn schedule_trigger_serde_roundtrip() {
        for trigger in [
            ScheduleTrigger::one_shot(instant(1_752_000_000)),
            ScheduleTrigger::periodic(instant(1_752_000_000), Duration::from_secs(60)),
        ] {
            let json = ok(serde_json::to_string(&trigger), "serialize");
            assert_eq!(
                ok(
                    serde_json::from_str::<ScheduleTrigger>(&json),
                    "deserialize"
                ),
                trigger
            );
        }
        // 周期间隔为毫秒精度契约：1200ms 往返无损。
        let trigger = ScheduleTrigger::periodic(instant(0), Duration::from_millis(1200));
        let json = ok(serde_json::to_string(&trigger), "serialize");
        assert_eq!(
            ok(
                serde_json::from_str::<ScheduleTrigger>(&json),
                "deserialize"
            ),
            trigger
        );
    }

    #[test]
    fn scheduled_task_id_roundtrip() {
        let id = ScheduledTaskId::from_u64(7);
        assert_eq!(id.as_u64(), 7);
        assert_eq!(id.to_string(), "7");
        let json = ok(serde_json::to_string(&id), "serialize");
        assert_eq!(json, "7");
        assert_eq!(
            ok(
                serde_json::from_str::<ScheduledTaskId>(&json),
                "deserialize"
            ),
            id
        );
    }

    #[test]
    fn task_state_parse_display_serde() {
        for (state, name) in [
            (TaskState::Scheduled, "scheduled"),
            (TaskState::Cancelled, "cancelled"),
            (TaskState::Completed, "completed"),
        ] {
            assert_eq!(name.parse::<TaskState>(), Ok(state));
            assert_eq!(state.to_string(), name);
            let json = ok(serde_json::to_string(&state), "serialize");
            assert_eq!(json, format!("\"{name}\""));
            assert_eq!(
                ok(serde_json::from_str::<TaskState>(&json), "deserialize"),
                state
            );
        }
        for bad in ["running", "SCHEDULED", "", "paused"] {
            assert!(
                matches!(
                    bad.parse::<TaskState>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::TaskState,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
        assert!(serde_json::from_str::<TaskState>("\"running\"").is_err());
    }

    #[test]
    fn task_status_carries_state_and_missed() {
        let status = TaskStatus::new(TaskState::Completed, 3, Some(instant(1_752_000_000)));
        assert_eq!(status.state(), TaskState::Completed);
        assert_eq!(status.missed_fires(), 3);
        assert_eq!(status.next_fire_at(), Some(instant(1_752_000_000)));

        // 一次性已触发或已取消：next_fire_at 为 none。
        let done = TaskStatus::new(TaskState::Completed, 1, None);
        assert_eq!(done.next_fire_at(), None);

        let json = ok(serde_json::to_string(&status), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<TaskStatus>(&json), "deserialize"),
            status
        );
    }

    #[test]
    fn trigger_payload_carries_delivery_fields() {
        let payload =
            TriggerPayload::new(ScheduledTaskId::from_u64(7), 4, instant(1_752_000_000), 2);
        assert_eq!(payload.task_id(), ScheduledTaskId::from_u64(7));
        assert_eq!(payload.sequence(), 4);
        assert_eq!(payload.scheduled_at(), instant(1_752_000_000));
        assert_eq!(payload.missed_fires(), 2);

        // 未错过：missed_fires = 0。
        let clean = TriggerPayload::new(ScheduledTaskId::from_u64(1), 1, instant(0), 0);
        assert_eq!(clean.missed_fires(), 0);

        let json = ok(serde_json::to_string(&payload), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<TriggerPayload>(&json), "deserialize"),
            payload
        );
    }
}
