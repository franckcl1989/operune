use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};

/// Component 生命周期闭集状态（§12.2 概念状态图：
/// `Installed -> Validated -> Activating -> Active -> Draining -> Disabled`，
/// 以及 `Activating \-> Failed`）。禁止用 `String` / `u32` 表达（§12.2）。
///
/// 与 §19.2 两阶段安装流程的对应：
/// - `Installed`：字节已接收并通过硬大小限制、`ContentDigest` 已计算、digest
///   主键的 quarantine/candidate 记录已持久化——"字节事实"阶段完成（§19.2
///   接收至持久化 candidate 记录之间）；
/// - `Validated`：WebAssembly Component validation 通过、descriptor export
///   已成功读取并验证（`ComponentId` / `ComponentVersion` / metadata），
///   逻辑身份/版本关系已建立——"应用身份"阶段完成（§19.2 / §19.3）；
/// - `Activating`：imports 已按 `InstallationId` 与 grants 解析
///   （deny-by-default，§17.2 / §19.5），runtime candidate 已在目标
///   grant/resource 快照下实例化，readiness/health 验证进行中（§19.3）；
/// - `Active`：readiness 通过后的原子激活（§19.2 末步），实例集合对外服务
///   （§7.3 有界 Instance Set）；
/// - `Draining`：不接新工作，已接受工作在有界 deadline 内完成，到期
///   取消/trap，结束后释放 Store 与 Host 资源（§20.4）；
/// - `Disabled`：drain 完成后的终态（§12.2 概念图终点）；可经重新激活回到
///   `Activating`（enable/disable，§39.2）；
/// - `Failed`：终态。descriptor 超时 / trap / 超预算 / 非法 metadata 或
///   readiness 失败均使 candidate 保持 quarantine/failed（§19.3）；
///   "任何一步失败都不得污染当前 Active Version"（§19.2）。从
///   `Installed` / `Validated` / `Activating` 可达；`Active` 之后的运行期
///   trap 属于 runtime 健康问题，不改变生命周期状态（0.1.0 stateless
///   contract，§20.1）。
///
/// quarantine / candidate 是持久化记录种类（§19.2），不是生命周期状态。
///
/// 错误：`FromStr` 解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentLifecycleState {
    /// 字节事实阶段完成（§19.2）。
    Installed,
    /// 应用身份阶段完成（§19.2 / §19.3）。
    Validated,
    /// runtime candidate 实例化与 readiness 验证中（§19.3）。
    Activating,
    /// 原子激活完成，对外服务（§19.2 / §7.3）。
    Active,
    /// 有界 deadline 内排空（§20.4）。
    Draining,
    /// 终态；可重新激活（§12.2 / §39.2）。
    Disabled,
    /// 终态；候选失败（§19.2 / §19.3）。
    Failed,
}

impl ComponentLifecycleState {
    /// 每个新安装记录（candidate）的初始状态：`Installed`（§19.2 首步）。
    pub const fn initial() -> ComponentLifecycleState {
        ComponentLifecycleState::Installed
    }

    /// 显式转换校验（§12.2）：合法事件返回新状态；非法转换返回
    /// [`DomainError::InvalidTransition`]，绝不静默忽略。
    ///
    /// 转换矩阵：
    /// - `Installed` → `ValidationSucceeded` → `Validated`
    /// - `Installed` → `ValidationFailed` → `Failed`
    /// - `Validated` → `ActivationRequested` → `Activating`
    /// - `Validated` → `ResolutionFailed` → `Failed`
    /// - `Activating` → `ReadinessSucceeded` → `Active`
    /// - `Activating` → `ReadinessFailed` → `Failed`
    /// - `Active` → `DrainStarted` → `Draining`
    /// - `Draining` → `DrainCompleted` → `Disabled`
    /// - `Disabled` → `ActivationRequested` → `Activating`（重新启用）
    /// - `Failed` 是终态，不接受任何事件。
    pub fn transition(
        self,
        event: ComponentLifecycleEvent,
    ) -> Result<ComponentLifecycleState, DomainError> {
        use ComponentLifecycleEvent as E;
        use ComponentLifecycleState as S;

        let next = match (self, event) {
            (S::Installed, E::ValidationSucceeded) => S::Validated,
            (S::Installed, E::ValidationFailed) => S::Failed,
            (S::Validated, E::ActivationRequested) => S::Activating,
            (S::Validated, E::ResolutionFailed) => S::Failed,
            (S::Activating, E::ReadinessSucceeded) => S::Active,
            (S::Activating, E::ReadinessFailed) => S::Failed,
            (S::Active, E::DrainStarted) => S::Draining,
            (S::Draining, E::DrainCompleted) => S::Disabled,
            (S::Disabled, E::ActivationRequested) => S::Activating,
            _ => {
                return Err(DomainError::InvalidTransition { state: self, event });
            }
        };
        Ok(next)
    }

    /// 当前状态是否接受该事件（`transition` 的布尔形式，供 UI/API 查询，
    /// 与 `transition` 结果永远一致）。
    pub fn accepts(self, event: ComponentLifecycleEvent) -> bool {
        self.transition(event).is_ok()
    }
}

/// 驱动生命周期转换的事件（闭集；§12.2 显式转换校验）。
///
/// 事件语义对齐 §19.2 / §19.3 / §20.4 的流程阶段（见各 variant 注释）。
///
/// 错误：`FromStr` 解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ComponentLifecycleEvent {
    /// 校验与 descriptor 读取成功（`Installed` → `Validated`，§19.2）。
    ValidationSucceeded,
    /// 校验或 descriptor 阶段失败（`Installed` → `Failed`，§19.2 / §19.3）。
    ValidationFailed,
    /// 请求激活：grants 解析完成、runtime candidate 实例化开始
    /// （`Validated` → `Activating`；`Disabled` → `Activating` 重新启用，
    /// §19.3 / §39.2）。
    ActivationRequested,
    /// imports 解析 / grant policy 失败（`Validated` → `Failed`；
    /// §19.5 未知/缺失 imports 不得成为 Active；§17.2 deny-by-default）。
    ResolutionFailed,
    /// readiness/health 验证成功（`Activating` → `Active`，§19.3）。
    ReadinessSucceeded,
    /// readiness 失败 / 超时 / trap / 超预算（`Activating` → `Failed`，
    /// §19.3）。
    ReadinessFailed,
    /// 开始排空（`Active` → `Draining`；热升级或管理性停用，§20.4 / §20.1）。
    DrainStarted,
    /// 排空完成：deadline 到期或工作全部结束，Store 与 Host 资源已释放
    /// （`Draining` → `Disabled`，§20.4）。
    DrainCompleted,
}

impl fmt::Display for ComponentLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Installed => "installed",
            Self::Validated => "validated",
            Self::Activating => "activating",
            Self::Active => "active",
            Self::Draining => "draining",
            Self::Disabled => "disabled",
            Self::Failed => "failed",
        };
        f.write_str(s)
    }
}

impl FromStr for ComponentLifecycleState {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "installed" => Ok(Self::Installed),
            "validated" => Ok(Self::Validated),
            "activating" => Ok(Self::Activating),
            "active" => Ok(Self::Active),
            "draining" => Ok(Self::Draining),
            "disabled" => Ok(Self::Disabled),
            "failed" => Ok(Self::Failed),
            _ => Err(DomainError::invalid_value(
                ValueKind::LifecycleState,
                format!("unknown lifecycle state {s:?}"),
            )),
        }
    }
}

impl Serialize for ComponentLifecycleState {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ComponentLifecycleState {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for ComponentLifecycleEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::ValidationSucceeded => "validation-succeeded",
            Self::ValidationFailed => "validation-failed",
            Self::ActivationRequested => "activation-requested",
            Self::ResolutionFailed => "resolution-failed",
            Self::ReadinessSucceeded => "readiness-succeeded",
            Self::ReadinessFailed => "readiness-failed",
            Self::DrainStarted => "drain-started",
            Self::DrainCompleted => "drain-completed",
        };
        f.write_str(s)
    }
}

impl FromStr for ComponentLifecycleEvent {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "validation-succeeded" => Ok(Self::ValidationSucceeded),
            "validation-failed" => Ok(Self::ValidationFailed),
            "activation-requested" => Ok(Self::ActivationRequested),
            "resolution-failed" => Ok(Self::ResolutionFailed),
            "readiness-succeeded" => Ok(Self::ReadinessSucceeded),
            "readiness-failed" => Ok(Self::ReadinessFailed),
            "drain-started" => Ok(Self::DrainStarted),
            "drain-completed" => Ok(Self::DrainCompleted),
            _ => Err(DomainError::invalid_value(
                ValueKind::LifecycleEvent,
                format!("unknown lifecycle event {s:?}"),
            )),
        }
    }
}

impl Serialize for ComponentLifecycleEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ComponentLifecycleEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    use ComponentLifecycleEvent as E;
    use ComponentLifecycleState as S;

    const ALL_STATES: [S; 7] = [
        S::Installed,
        S::Validated,
        S::Activating,
        S::Active,
        S::Draining,
        S::Disabled,
        S::Failed,
    ];

    const ALL_EVENTS: [E; 8] = [
        E::ValidationSucceeded,
        E::ValidationFailed,
        E::ActivationRequested,
        E::ResolutionFailed,
        E::ReadinessSucceeded,
        E::ReadinessFailed,
        E::DrainStarted,
        E::DrainCompleted,
    ];

    /// 期望的转换矩阵（§12.2 概念图 + §39.2 enable/disable 的重新激活边）。
    /// 与实现独立书写，作为穷尽验证的基准。
    fn expected(state: S, event: E) -> Result<S, ()> {
        match (state, event) {
            (S::Installed, E::ValidationSucceeded) => Ok(S::Validated),
            (S::Installed, E::ValidationFailed) => Ok(S::Failed),
            (S::Validated, E::ActivationRequested) => Ok(S::Activating),
            (S::Validated, E::ResolutionFailed) => Ok(S::Failed),
            (S::Activating, E::ReadinessSucceeded) => Ok(S::Active),
            (S::Activating, E::ReadinessFailed) => Ok(S::Failed),
            (S::Active, E::DrainStarted) => Ok(S::Draining),
            (S::Draining, E::DrainCompleted) => Ok(S::Disabled),
            (S::Disabled, E::ActivationRequested) => Ok(S::Activating),
            _ => Err(()),
        }
    }

    #[test]
    fn transition_matrix_exhaustive() {
        // 7 状态 × 8 事件 = 56 个 (state, event) 组合全部断言。
        for state in ALL_STATES {
            for event in ALL_EVENTS {
                let got = state.transition(event);
                match expected(state, event) {
                    Ok(target) => {
                        assert_eq!(
                            got,
                            Ok(target),
                            "{state:?} via {event:?} must reach {target:?}"
                        );
                    }
                    Err(()) => {
                        assert_eq!(
                            got,
                            Err(DomainError::InvalidTransition { state, event }),
                            "{state:?} via {event:?} must be rejected with InvalidTransition"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn accepts_matches_matrix() {
        for state in ALL_STATES {
            for event in ALL_EVENTS {
                assert_eq!(
                    state.accepts(event),
                    expected(state, event).is_ok(),
                    "accepts must agree with the matrix for {state:?} via {event:?}"
                );
            }
        }
    }

    #[test]
    fn happy_path_walk() {
        // 全新安装 → 激活 → 停用 → 重新启用（§19.2 / §39.2 enable/disable）。
        let mut state = S::initial();
        assert_eq!(state, S::Installed);

        state = ok(state.transition(E::ValidationSucceeded), "validation");
        assert_eq!(state, S::Validated);

        state = ok(state.transition(E::ActivationRequested), "activation");
        assert_eq!(state, S::Activating);

        state = ok(state.transition(E::ReadinessSucceeded), "readiness");
        assert_eq!(state, S::Active);

        state = ok(state.transition(E::DrainStarted), "drain start");
        assert_eq!(state, S::Draining);

        state = ok(state.transition(E::DrainCompleted), "drain complete");
        assert_eq!(state, S::Disabled);

        state = ok(state.transition(E::ActivationRequested), "re-enable");
        assert_eq!(state, S::Activating);

        state = ok(state.transition(E::ReadinessSucceeded), "readiness again");
        assert_eq!(state, S::Active);
    }

    #[test]
    fn failure_paths_reach_failed() {
        // 每个候选阶段失败都进入 Failed（§19.2：任何一步失败都不得污染
        // 当前 Active Version；§19.3：candidate 保持 quarantine/failed）。
        assert_eq!(
            ok(
                S::Installed.transition(E::ValidationFailed),
                "validation failed"
            ),
            S::Failed
        );
        assert_eq!(
            ok(
                S::Validated.transition(E::ResolutionFailed),
                "resolution failed"
            ),
            S::Failed
        );
        assert_eq!(
            ok(
                S::Activating.transition(E::ReadinessFailed),
                "readiness failed"
            ),
            S::Failed
        );
    }

    #[test]
    fn failed_is_terminal() {
        for event in ALL_EVENTS {
            assert!(
                matches!(
                    S::Failed.transition(event),
                    Err(DomainError::InvalidTransition {
                        state: S::Failed,
                        ..
                    })
                ),
                "Failed must reject {event:?}"
            );
        }
    }

    #[test]
    fn disabled_only_accepts_activation() {
        for event in ALL_EVENTS {
            let accepted = S::Disabled.transition(event).is_ok();
            assert_eq!(
                accepted,
                event == E::ActivationRequested,
                "Disabled must only accept ActivationRequested, got {event:?} accepted={accepted}"
            );
        }
    }

    #[test]
    fn display_fromstr_roundtrip() {
        for state in ALL_STATES {
            let s = state.to_string();
            assert_eq!(s.parse::<S>(), Ok(state), "state {state:?} string {s:?}");
        }
        for event in ALL_EVENTS {
            let s = event.to_string();
            assert_eq!(s.parse::<E>(), Ok(event), "event {event:?} string {s:?}");
        }
        assert_eq!(S::Installed.to_string(), "installed");
        assert_eq!(E::DrainStarted.to_string(), "drain-started");
    }

    #[test]
    fn fromstr_rejects_unknown() {
        for bad in ["", "INSTALLED", "Active", "installed ", "draining-now"] {
            assert!(
                matches!(
                    bad.parse::<S>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::LifecycleState,
                        ..
                    })
                ),
                "{bad:?} must be rejected as state"
            );
            assert!(
                matches!(
                    bad.parse::<E>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::LifecycleEvent,
                        ..
                    })
                ),
                "{bad:?} must be rejected as event"
            );
        }
    }

    #[test]
    fn serde_roundtrip() {
        for state in ALL_STATES {
            let json = ok(serde_json::to_string(&state), "serialize state");
            assert_eq!(json, format!("\"{state}\""));
            assert_eq!(
                ok(serde_json::from_str::<S>(&json), "deserialize state"),
                state
            );
        }
        for event in ALL_EVENTS {
            let json = ok(serde_json::to_string(&event), "serialize event");
            assert_eq!(
                ok(serde_json::from_str::<E>(&json), "deserialize event"),
                event
            );
        }
    }

    #[test]
    fn serde_rejects_unknown() {
        assert!(serde_json::from_str::<S>("\"boom\"").is_err());
        assert!(serde_json::from_str::<E>("\"boom\"").is_err());
    }

    fn any_state() -> impl Strategy<Value = S> {
        prop_oneof![
            Just(S::Installed),
            Just(S::Validated),
            Just(S::Activating),
            Just(S::Active),
            Just(S::Draining),
            Just(S::Disabled),
            Just(S::Failed),
        ]
    }

    fn any_event() -> impl Strategy<Value = E> {
        prop_oneof![
            Just(E::ValidationSucceeded),
            Just(E::ValidationFailed),
            Just(E::ActivationRequested),
            Just(E::ResolutionFailed),
            Just(E::ReadinessSucceeded),
            Just(E::ReadinessFailed),
            Just(E::DrainStarted),
            Just(E::DrainCompleted),
        ]
    }

    proptest! {
        #[test]
        fn transition_consistency_and_no_self_transition(state in any_state(), event in any_event()) {
            let result = state.transition(event);
            prop_assert_eq!(result.is_ok(), state.accepts(event));
            if let Ok(next) = result {
                prop_assert_ne!(next, state, "no transition may be a self-transition");
            }
        }

        #[test]
        fn state_serde_roundtrip_prop(state in any_state()) {
            let json = match serde_json::to_string(&state) {
                Ok(json) => json,
                Err(e) => unreachable!("serialization of {state:?} failed: {e}"),
            };
            let parsed = match serde_json::from_str::<S>(&json) {
                Ok(parsed) => parsed,
                Err(e) => unreachable!("deserialization of {json:?} failed: {e}"),
            };
            prop_assert_eq!(parsed, state);
        }
    }
}
