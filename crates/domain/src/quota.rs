//! 0.5.0 Security & Governance（§43.2）——resource quota hierarchy。
//!
//! 契约语义（§43.2 resource quota hierarchy；§7.4 资源治理）：
//!
//! - **层级树**：Global（平台全局）→ Group（用户组，组 id 即
//!   [`GroupId`](crate::GroupId)——RBAC 与 quota 的"组"是同一治理实体）→
//!   Installation（安装实例）；同时允许 Global → Installation 的直连
//!   （无组的实例仍要有实例级配额）。树的形状（层级、父子的合法组合、
//!   组/实例 id 全局唯一）由构造校验（§13.4 不合法状态不可表示）；
//! - **预算形态**（§7.4）：每个节点是 [`QuotaBudget`]——七个维度
//!   （linear memory / host buffer / HTTP body / 最大并发 / 最大排队 /
//!   后台任务数量 / 单次调用截止时间），每维 `Option`（`None` = 该层
//!   不约束该维）。字节维度复用 [`ByteSize`](crate::ByteSize)、时间维度
//!   复用 [`Duration`](crate::Duration)，数量维度为 [`QuotaCount`]（§13.1
//!   数量语义）；**Global 层必须全量预算**（构造不变量：任何实例的有效
//!   配额恒有界，§7.4 "每个 Component 实例必须有明确预算"）；
//! - **层级求值裁决**（§43.2 未指定，§25 自主裁决）：**最严格生效**——
//!   有效配额每个维度 = 该安装实例路径上（实例 → 组 → 全局）各层**显式
//!   设置值**的最小值；未设置的层不约束（跳过）。理由：
//!   1. **安全优先**（P7 默认无权限 / §17.2 deny-by-default 精神）：配额
//!      是硬上限（§7.4），min 规则保证任何层级都不能放宽祖先的上限——
//!      组管理员不可能意外把实例预算调到全局上限之上，"放宽"只能是
//!      改全局/组预算这一受权限管控的治理动作（least privilege §17.4）；
//!   2. **确定性**（§40.4 精神）：min over 显式设置值，与迭代顺序无关
//!      （交换律/结合律），同一 hierarchy 恒得同一结果；
//!   3. **可解释**（§43.3）：[`EffectiveQuota::binding`] 为每个维度给出
//!      达到最小值的**最具体**层级（Installation > Group > Global），
//!      "为什么是 512MiB"直接可答；
//!   4. 全局层全量 + min 语义下"组预算 > 全局预算"的非法配置不可能
//!      产生效力，配置合法性检查简单。
//! - 求值（[`QuotaHierarchy::effective`]）不可失败（全局层全量不变量
//!   保证每维有界）；实际 enforcement（§17.5 第 4 层 invocation-time
//!   enforcement）由 application / security 层以 [`EffectiveQuota`] 校验。

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{DomainError, ValueKind};
use crate::{ByteSize, Duration, GroupId, InstallationId};

/// 数量类预算（§7.4 最大并发 / 最大排队 / 后台任务数量；§13.1 数量语义，
/// 与 [`ByteSize`] 同级的领域 newtype）。
///
/// 任意非负 u64 都是合法数量（0 = 禁止该类资源——显式 deny 形态），构造
/// 不可失败。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QuotaCount(u64);

impl QuotaCount {
    /// 从 u64 构造（不可失败；0 = 禁止该类资源）。
    pub const fn from_u64(value: u64) -> Self {
        Self(value)
    }

    /// 原始 u64 视图（持久化 / 展示）。
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for QuotaCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for QuotaCount {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for QuotaCount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Ok(Self::from_u64(value))
    }
}

/// 配额层级（§43.2 resource quota hierarchy 的层级；组层键 =
/// [`GroupId`](crate::GroupId)，实例层键 = [`InstallationId`](crate::InstallationId)）。
///
/// 层级顺序（`Ord`，按声明顺序）：Global < Group < Installation——用于
/// 树的确定性排序与"最具体层级"的绑定判定（见模块文档裁决）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum QuotaLevel {
    /// 平台全局层（全量预算，恒为树的根）。
    Global,
    /// 用户组层（组内所有安装实例共享该预算）。
    Group(GroupId),
    /// 安装实例层。
    Installation(InstallationId),
}

impl fmt::Display for QuotaLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "global"),
            Self::Group(id) => write!(f, "group:{id}"),
            Self::Installation(id) => write!(f, "installation:{id}"),
        }
    }
}

impl FromStr for QuotaLevel {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "global" => Ok(Self::Global),
            _ => {
                let (kind, value) = s.split_once(':').ok_or_else(|| {
                    DomainError::invalid_value(
                        ValueKind::QuotaLevel,
                        format!(
                            "{s:?} is not a quota-level (global | group:<id> | installation:<id>)"
                        ),
                    )
                })?;
                match kind {
                    "group" => Ok(Self::Group(value.parse().map_err(|_| {
                        DomainError::invalid_value(
                            ValueKind::QuotaLevel,
                            format!("group id {value:?} is invalid"),
                        )
                    })?)),
                    "installation" => Ok(Self::Installation(value.parse().map_err(|_| {
                        DomainError::invalid_value(
                            ValueKind::QuotaLevel,
                            format!("installation id {value:?} is invalid"),
                        )
                    })?)),
                    _ => Err(DomainError::invalid_value(
                        ValueKind::QuotaLevel,
                        format!(
                            "{s:?} is not a quota-level (global | group:<id> | installation:<id>)"
                        ),
                    )),
                }
            }
        }
    }
}

/// 预算维度（§7.4 资源治理清单的七个维度；用于有效配额的绑定报告）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum BudgetDimension {
    /// linear memory 上限（§7.4）。
    Memory,
    /// host buffer 上限（§7.4）。
    HostBuffer,
    /// HTTP request/response body 上限（§7.4）。
    BodySize,
    /// 最大并发（§7.4）。
    Concurrent,
    /// 最大排队（§7.4）。
    Queue,
    /// Component 后台任务数量上限（§7.4）。
    Tasks,
    /// 单次调用截止时间（§7.4）。
    CallTimeout,
}

impl BudgetDimension {
    /// 与变体一一对应的小写字符串。
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::HostBuffer => "host-buffer",
            Self::BodySize => "body-size",
            Self::Concurrent => "concurrent",
            Self::Queue => "queue",
            Self::Tasks => "tasks",
            Self::CallTimeout => "call-timeout",
        }
    }

    /// 从字符串解析（适配层 / 持久化边界，§13.3 边界解析一次；闭集之外
    /// 的任何值拒绝）。
    pub fn from_str_checked(s: &str) -> Result<Self, DomainError> {
        match s {
            "memory" => Ok(Self::Memory),
            "host-buffer" => Ok(Self::HostBuffer),
            "body-size" => Ok(Self::BodySize),
            "concurrent" => Ok(Self::Concurrent),
            "queue" => Ok(Self::Queue),
            "tasks" => Ok(Self::Tasks),
            "call-timeout" => Ok(Self::CallTimeout),
            _ => Err(DomainError::invalid_value(
                ValueKind::BudgetDimension,
                format!(
                    "{s:?} is not a budget-dimension variant (memory | host-buffer | body-size | concurrent | queue | tasks | call-timeout)"
                ),
            )),
        }
    }

    /// 全部七个维度（绑定报告 / 求值遍历用；顺序固定）。
    pub const fn all() -> [BudgetDimension; 7] {
        [
            Self::Memory,
            Self::HostBuffer,
            Self::BodySize,
            Self::Concurrent,
            Self::Queue,
            Self::Tasks,
            Self::CallTimeout,
        ]
    }
}

impl fmt::Display for BudgetDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for BudgetDimension {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_str_checked(s)
    }
}

impl Serialize for BudgetDimension {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for BudgetDimension {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_str_checked(&value).map_err(serde::de::Error::custom)
    }
}

/// 单层预算（§7.4 资源治理清单；§43.2 quota hierarchy 的节点预算形态）。
///
/// 每维 `Option`：**`None` = 该层不约束该维度**（层级求值时跳过，
/// 见模块文档裁决——最严格生效）。`Some` 的值是**硬上限**（§7.4）。
///
/// 两个结构性谓词：
/// - [`QuotaBudget::is_total`]：全部维度显式设置——**Global 层必须满足**
///   （[`QuotaNode::new`] 校验），保证任何有效配额恒有界；
/// - [`QuotaBudget::is_unconstrained`]：全部维度 `None`——组/实例层的
///   纯透传节点（合法但无约束力；与"无该节点"等价）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct QuotaBudget {
    max_memory: Option<ByteSize>,
    max_host_buffer: Option<ByteSize>,
    max_body_size: Option<ByteSize>,
    max_concurrent: Option<QuotaCount>,
    max_queue: Option<QuotaCount>,
    max_tasks: Option<QuotaCount>,
    call_timeout: Option<Duration>,
}

impl QuotaBudget {
    /// 从七个可选的维度构造（§13.3 边界解析一次；`None` = 该层不约束）。
    pub fn new(
        max_memory: Option<ByteSize>,
        max_host_buffer: Option<ByteSize>,
        max_body_size: Option<ByteSize>,
        max_concurrent: Option<QuotaCount>,
        max_queue: Option<QuotaCount>,
        max_tasks: Option<QuotaCount>,
        call_timeout: Option<Duration>,
    ) -> Self {
        Self {
            max_memory,
            max_host_buffer,
            max_body_size,
            max_concurrent,
            max_queue,
            max_tasks,
            call_timeout,
        }
    }

    /// 全维度 `None` 的预算（该层不约束任何维度；透传节点）。
    pub fn none() -> Self {
        Self::new(None, None, None, None, None, None, None)
    }

    /// 是否全部维度显式设置（Global 层不变量）。
    pub fn is_total(&self) -> bool {
        self.max_memory.is_some()
            && self.max_host_buffer.is_some()
            && self.max_body_size.is_some()
            && self.max_concurrent.is_some()
            && self.max_queue.is_some()
            && self.max_tasks.is_some()
            && self.call_timeout.is_some()
    }

    /// 是否全部维度 `None`（透传节点）。
    pub fn is_unconstrained(&self) -> bool {
        self.max_memory.is_none()
            && self.max_host_buffer.is_none()
            && self.max_body_size.is_none()
            && self.max_concurrent.is_none()
            && self.max_queue.is_none()
            && self.max_tasks.is_none()
            && self.call_timeout.is_none()
    }

    /// linear memory 上限（§7.4）。
    pub fn max_memory(&self) -> Option<ByteSize> {
        self.max_memory
    }

    /// host buffer 上限（§7.4）。
    pub fn max_host_buffer(&self) -> Option<ByteSize> {
        self.max_host_buffer
    }

    /// HTTP request/response body 上限（§7.4）。
    pub fn max_body_size(&self) -> Option<ByteSize> {
        self.max_body_size
    }

    /// 最大并发（§7.4）。
    pub fn max_concurrent(&self) -> Option<QuotaCount> {
        self.max_concurrent
    }

    /// 最大排队（§7.4）。
    pub fn max_queue(&self) -> Option<QuotaCount> {
        self.max_queue
    }

    /// 后台任务数量上限（§7.4）。
    pub fn max_tasks(&self) -> Option<QuotaCount> {
        self.max_tasks
    }

    /// 单次调用截止时间（§7.4）。
    pub fn call_timeout(&self) -> Option<Duration> {
        self.call_timeout
    }
}

/// 配额层级树的节点（§43.2 resource quota hierarchy）。
///
/// 层级规则（构造校验，§13.4 不合法状态不可表示）：
/// - [`QuotaLevel::Global`]：预算必须全量（[`QuotaBudget::is_total`]，
///   `ValueKind::QuotaBudget` 错误）；子节点为 Group 或 Installation；
/// - [`QuotaLevel::Group`]：子节点只允许 Installation；
/// - [`QuotaLevel::Installation`]：叶子（无子节点）；
/// - 子节点按 [`QuotaLevel`] 的 `Ord` 排序存储（归一化：同一输入集合
///   得到同一棵树，§40.4 确定性精神）；
/// - 组 / 实例 id 在**整棵树内唯一**（一个组 / 一个实例至多出现一次，
///   由 [`QuotaHierarchy::new`] 校验——"实例属于哪个组"因此无歧义）。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct QuotaNode {
    level: QuotaLevel,
    budget: QuotaBudget,
    children: Vec<QuotaNode>,
}

impl QuotaNode {
    /// 构造节点并校验层级规则（§13.3 边界解析一次）。
    pub fn new(
        level: QuotaLevel,
        budget: QuotaBudget,
        mut children: Vec<QuotaNode>,
    ) -> Result<Self, DomainError> {
        match &level {
            QuotaLevel::Global => {
                if !budget.is_total() {
                    return Err(DomainError::invalid_value(
                        ValueKind::QuotaBudget,
                        "the global quota level must specify a total budget (all dimensions set)",
                    ));
                }
                for child in &children {
                    if !matches!(
                        child.level,
                        QuotaLevel::Group(_) | QuotaLevel::Installation(_)
                    ) {
                        return Err(DomainError::invalid_value(
                            ValueKind::QuotaHierarchy,
                            "global-level children must be group or installation nodes",
                        ));
                    }
                }
            }
            QuotaLevel::Group(_) => {
                for child in &children {
                    if !matches!(child.level, QuotaLevel::Installation(_)) {
                        return Err(DomainError::invalid_value(
                            ValueKind::QuotaHierarchy,
                            "group-level children must be installation nodes",
                        ));
                    }
                }
            }
            QuotaLevel::Installation(_) => {
                if !children.is_empty() {
                    return Err(DomainError::invalid_value(
                        ValueKind::QuotaHierarchy,
                        "installation-level nodes must be leaves",
                    ));
                }
            }
        }
        // 确定性归一化：子节点按层级 Ord 排序（§40.4 精神）。
        children.sort();
        Ok(Self {
            level,
            budget,
            children,
        })
    }

    /// 节点层级。
    pub fn level(&self) -> &QuotaLevel {
        &self.level
    }

    /// 节点预算（Global 层恒全量）。
    pub fn budget(&self) -> &QuotaBudget {
        &self.budget
    }

    /// 子节点（按层级 Ord 排序，只读）。
    pub fn children(&self) -> &[QuotaNode] {
        &self.children
    }
}

impl<'de> Deserialize<'de> for QuotaNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            level: QuotaLevel,
            budget: QuotaBudget,
            children: Vec<QuotaNode>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.level, wire.budget, wire.children).map_err(serde::de::Error::custom)
    }
}

/// 资源配额层级（§43.2 resource quota hierarchy）：Global →（Group →）→
/// Installation 的层级树（不可变快照，§15.5 read-mostly）。
///
/// 构造不变量（§13.4）：
/// - 根必须是 [`QuotaLevel::Global`] 且全量预算（[`QuotaNode::new`] 校验）；
/// - 组 / 实例 id 在整棵树内**唯一**（重复 → `InvalidValue{QuotaHierarchy}`）；
/// - 形状规则见 [`QuotaNode`]。
///
/// 求值（[`QuotaHierarchy::effective`]）：给定安装实例，沿其唯一路径
/// （`global`，或 `global → group → installation`，或 `global →
/// installation` 直连）按**最严格生效**（每维取路径上显式设置值的最小值，
/// 见模块文档裁决）得到 [`EffectiveQuota`]；不在树中的实例 = 纯全局预算。
///
/// 错误：构造失败返回 [`DomainError::InvalidValue`]。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuotaHierarchy {
    root: QuotaNode,
}

impl QuotaHierarchy {
    /// 构造配额层级树（§13.3 边界解析一次）。
    pub fn new(root: QuotaNode) -> Result<Self, DomainError> {
        if !matches!(root.level, QuotaLevel::Global) {
            return Err(DomainError::invalid_value(
                ValueKind::QuotaHierarchy,
                "the quota hierarchy root must be the global level",
            ));
        }
        // 组 / 实例 id 整树唯一（"实例属于哪个组"无歧义；确定性命题）。
        let mut group_ids = BTreeMap::new();
        let mut installation_ids = BTreeMap::new();
        for group in &root.children {
            match &group.level {
                QuotaLevel::Group(id) => {
                    if group_ids.insert(id.clone(), ()).is_some() {
                        return Err(DomainError::invalid_value(
                            ValueKind::QuotaHierarchy,
                            format!("group {id} appears more than once in the quota hierarchy"),
                        ));
                    }
                    for child in &group.children {
                        if let QuotaLevel::Installation(id) = &child.level
                            && installation_ids.insert(*id, ()).is_some()
                        {
                            return Err(DomainError::invalid_value(
                                ValueKind::QuotaHierarchy,
                                format!(
                                    "installation {id} appears more than once in the quota hierarchy"
                                ),
                            ));
                        }
                    }
                }
                QuotaLevel::Installation(id) => {
                    if installation_ids.insert(*id, ()).is_some() {
                        return Err(DomainError::invalid_value(
                            ValueKind::QuotaHierarchy,
                            format!(
                                "installation {id} appears more than once in the quota hierarchy"
                            ),
                        ));
                    }
                }
                QuotaLevel::Global => {
                    return Err(DomainError::invalid_value(
                        ValueKind::QuotaHierarchy,
                        "the global level may only appear as the hierarchy root",
                    ));
                }
            }
        }
        Ok(Self { root })
    }

    /// 树的根节点（Global 层）。
    pub fn root(&self) -> &QuotaNode {
        &self.root
    }

    /// 全局预算（恒全量；任何有效配额的起点）。
    pub fn global_budget(&self) -> &QuotaBudget {
        &self.root.budget
    }

    /// 求 `installation` 的有效配额（§43.2 层级求值；不可失败——全局层
    /// 全量不变量保证每维有界）。
    ///
    /// 路径解析：`installation` 是某组节点的子节点 → 路径
    /// `global → 组 → 实例`；是根的直接子节点 → `global → 实例`；
    /// 否则 → 仅 `global`（组/实例 id 唯一，路径至多一条）。
    /// 每维 = 路径上显式设置值的最小值（最严格生效，模块文档裁决）；
    /// 绑定层 = 达到最小值的**最具体**层级（Installation > Group >
    /// Global；并列时最具体者胜出）。
    pub fn effective(&self, installation: InstallationId) -> EffectiveQuota {
        // 路径收集（至多一条；id 唯一不变量）。
        let mut group: Option<(&QuotaBudget, QuotaLevel)> = None;
        let mut direct: Option<(&QuotaBudget, QuotaLevel)> = None;
        for node in &self.root.children {
            match &node.level {
                QuotaLevel::Group(id) => {
                    for child in &node.children {
                        if child.level == QuotaLevel::Installation(installation) {
                            group = Some((&node.budget, QuotaLevel::Group(id.clone())));
                            direct = Some((&child.budget, child.level.clone()));
                        }
                    }
                }
                QuotaLevel::Installation(id) if *id == installation => {
                    direct = Some((&node.budget, node.level.clone()));
                }
                _ => {}
            }
        }
        // 求值链：全局 →（组）→ 实例。
        let global = &self.root.budget;
        let chain: Vec<(&QuotaBudget, QuotaLevel)> = match (group, direct) {
            (Some((group_budget, group_level)), Some((instance_budget, instance_level))) => {
                vec![
                    (global, QuotaLevel::Global),
                    (group_budget, group_level),
                    (instance_budget, instance_level),
                ]
            }
            (None, Some((instance_budget, instance_level))) => vec![
                (global, QuotaLevel::Global),
                (instance_budget, instance_level),
            ],
            (Some(_), None) | (None, None) => vec![(global, QuotaLevel::Global)],
        };
        // 每维以全局值播种（全量不变量），从最不具体到最具体折叠：
        // 更严格（更小）的显式值替换；**并列（相等）时更具体层替换**——
        // 绑定层最终 = 达到最小值的最具体层级（模块文档裁决）。
        let mut memory = fold_seed(global.max_memory(), ByteSize::ZERO, QuotaLevel::Global);
        let mut host_buffer =
            fold_seed(global.max_host_buffer(), ByteSize::ZERO, QuotaLevel::Global);
        let mut body_size = fold_seed(global.max_body_size(), ByteSize::ZERO, QuotaLevel::Global);
        let mut concurrent = fold_seed(
            global.max_concurrent(),
            QuotaCount::from_u64(0),
            QuotaLevel::Global,
        );
        let mut queue = fold_seed(
            global.max_queue(),
            QuotaCount::from_u64(0),
            QuotaLevel::Global,
        );
        let mut tasks = fold_seed(
            global.max_tasks(),
            QuotaCount::from_u64(0),
            QuotaLevel::Global,
        );
        let mut call_timeout = fold_seed(global.call_timeout(), Duration::ZERO, QuotaLevel::Global);
        for (budget, level) in &chain {
            fold_into(&mut memory, budget.max_memory(), level);
            fold_into(&mut host_buffer, budget.max_host_buffer(), level);
            fold_into(&mut body_size, budget.max_body_size(), level);
            fold_into(&mut concurrent, budget.max_concurrent(), level);
            fold_into(&mut queue, budget.max_queue(), level);
            fold_into(&mut tasks, budget.max_tasks(), level);
            fold_into(&mut call_timeout, budget.call_timeout(), level);
        }
        let mut binding = BTreeMap::new();
        binding.insert(BudgetDimension::Memory, memory.1);
        binding.insert(BudgetDimension::HostBuffer, host_buffer.1);
        binding.insert(BudgetDimension::BodySize, body_size.1);
        binding.insert(BudgetDimension::Concurrent, concurrent.1);
        binding.insert(BudgetDimension::Queue, queue.1);
        binding.insert(BudgetDimension::Tasks, tasks.1);
        binding.insert(BudgetDimension::CallTimeout, call_timeout.1);
        EffectiveQuota {
            max_memory: memory.0,
            max_host_buffer: host_buffer.0,
            max_body_size: body_size.0,
            max_concurrent: concurrent.0,
            max_queue: queue.0,
            max_tasks: tasks.0,
            call_timeout: call_timeout.0,
            binding,
        }
    }
}

/// 折叠种子（最严格生效，模块文档裁决）：`Option<T>` 值 + 携带层。
///
/// 全局层全量不变量（[`QuotaNode::new`] 保证）下 `value` 恒为 `Some`；
/// `fallback` 仅是防御性占位（不变量被破坏时保守地取"最严格"的零值——
/// 拒绝一切而非放开上限，§17.2 deny-by-default 精神；参照 `time.rs`
/// `as_unix_parts` 的 `unwrap_or_default` 防御占位先例）。
fn fold_seed<T>(value: Option<T>, fallback: T, level: QuotaLevel) -> (T, QuotaLevel) {
    (value.unwrap_or(fallback), level)
}

/// 把 `(value, level)` 折叠进 `(min, binding)`：**小于或等于**才替换
/// （调用方按最不具体到最具体顺序遍历——相等时更具体层覆盖，绑定层最终
/// = 达到最小值的最具体层级；最小值本身不受影响，§14.4 checked 语义
/// 之外的纯 Ord 比较）。
fn fold_into<T: Ord>(min: &mut (T, QuotaLevel), value: Option<T>, level: &QuotaLevel) {
    if let Some(value) = value
        && value <= min.0
    {
        *min = (value, level.clone());
    }
}

impl<'de> Deserialize<'de> for QuotaHierarchy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            root: QuotaNode,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.root).map_err(serde::de::Error::custom)
    }
}

/// 有效配额（§43.2 层级求值结果）：`QuotaHierarchy::effective` 输出的
/// **全量有界**预算（无 `Option`——全局层全量不变量保证每维确定）。
///
/// [`EffectiveQuota::binding`] 为每个维度给出**绑定层**（达到最严格值的最
/// 具体层级，模块文档裁决），是 §43.3 可解释性的配额侧基础：管理员可
/// 回答"为什么并发上限是 4"——"实例层显式设置为 4"或"组层显式设置为
/// 4，实例未设置"。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EffectiveQuota {
    max_memory: ByteSize,
    max_host_buffer: ByteSize,
    max_body_size: ByteSize,
    max_concurrent: QuotaCount,
    max_queue: QuotaCount,
    max_tasks: QuotaCount,
    call_timeout: Duration,
    binding: BTreeMap<BudgetDimension, QuotaLevel>,
}

impl EffectiveQuota {
    /// linear memory 上限（§7.4；全局层全量保证有界）。
    pub fn max_memory(&self) -> ByteSize {
        self.max_memory
    }

    /// host buffer 上限（§7.4）。
    pub fn max_host_buffer(&self) -> ByteSize {
        self.max_host_buffer
    }

    /// HTTP request/response body 上限（§7.4）。
    pub fn max_body_size(&self) -> ByteSize {
        self.max_body_size
    }

    /// 最大并发（§7.4）。
    pub fn max_concurrent(&self) -> QuotaCount {
        self.max_concurrent
    }

    /// 最大排队（§7.4）。
    pub fn max_queue(&self) -> QuotaCount {
        self.max_queue
    }

    /// 后台任务数量上限（§7.4）。
    pub fn max_tasks(&self) -> QuotaCount {
        self.max_tasks
    }

    /// 单次调用截止时间（§7.4）。
    pub fn call_timeout(&self) -> Duration {
        self.call_timeout
    }

    /// 该维度的绑定层（§43.3：达到最严格值的最具体层级）。
    ///
    /// 全局层全量不变量保证每维绑定都存在；`unwrap_or(&QuotaLevel::Global)`
    /// 仅是防御性占位（不变量被破坏时保守地归因于全局层——只影响报告
    /// 展示，不影响求值本身）。
    pub fn binding(&self, dimension: BudgetDimension) -> &QuotaLevel {
        self.binding.get(&dimension).unwrap_or(&QuotaLevel::Global)
    }

    /// 全部维度的绑定层（只读）。
    pub fn bindings(&self) -> &BTreeMap<BudgetDimension, QuotaLevel> {
        &self.binding
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    fn group_id(value: &str) -> GroupId {
        ok(GroupId::new(value), "group-id")
    }

    fn node(level: QuotaLevel, budget: QuotaBudget, children: Vec<QuotaNode>) -> QuotaNode {
        ok(QuotaNode::new(level, budget, children), "quota-node")
    }

    fn total_budget(memory: u64) -> QuotaBudget {
        QuotaBudget::new(
            Some(ByteSize::from_bytes(memory)),
            Some(ByteSize::from_bytes(1024)),
            Some(ByteSize::from_bytes(1024)),
            Some(QuotaCount::from_u64(4)),
            Some(QuotaCount::from_u64(16)),
            Some(QuotaCount::from_u64(2)),
            Some(Duration::from_secs(30)),
        )
    }

    fn hierarchy(root: QuotaNode) -> QuotaHierarchy {
        ok(QuotaHierarchy::new(root), "quota-hierarchy")
    }

    fn installation() -> InstallationId {
        InstallationId::new()
    }

    // ---- QuotaCount ----

    #[test]
    fn quota_count_roundtrip() {
        let count = QuotaCount::from_u64(4);
        assert_eq!(count.as_u64(), 4);
        assert_eq!(count.to_string(), "4");
        assert_eq!(QuotaCount::from_u64(0).as_u64(), 0, "0 = 禁止该类资源");
        let json = ok(serde_json::to_string(&count), "serialize");
        assert_eq!(json, "4");
        assert_eq!(
            ok(serde_json::from_str::<QuotaCount>(&json), "deserialize"),
            count
        );
    }

    // ---- QuotaLevel ----

    #[test]
    fn quota_level_display_fromstr() {
        let levels = [
            QuotaLevel::Global,
            QuotaLevel::Group(group_id("platform-ops")),
            QuotaLevel::Installation(installation()),
        ];
        for level in &levels {
            assert_eq!(
                ok(level.to_string().parse::<QuotaLevel>(), "parse"),
                *level,
                "display/from_str roundtrip for {level}"
            );
        }
        assert_eq!(QuotaLevel::Global.to_string(), "global");
        for bad in [
            "",
            "group",
            "group:",
            "installation:",
            "global:x",
            "foo:bar",
            "bogus",
        ] {
            assert!(
                matches!(
                    bad.parse::<QuotaLevel>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::QuotaLevel,
                        ..
                    })
                ),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn quota_level_order_is_global_group_installation() {
        assert!(QuotaLevel::Global < QuotaLevel::Group(group_id("a")));
        assert!(QuotaLevel::Group(group_id("a")) < QuotaLevel::Installation(installation()));
    }

    // ---- BudgetDimension ----

    #[test]
    fn budget_dimension_closed_set() {
        assert_eq!(BudgetDimension::all().len(), 7);
        for (dimension, name) in [
            (BudgetDimension::Memory, "memory"),
            (BudgetDimension::HostBuffer, "host-buffer"),
            (BudgetDimension::BodySize, "body-size"),
            (BudgetDimension::Concurrent, "concurrent"),
            (BudgetDimension::Queue, "queue"),
            (BudgetDimension::Tasks, "tasks"),
            (BudgetDimension::CallTimeout, "call-timeout"),
        ] {
            assert_eq!(name.parse::<BudgetDimension>(), Ok(dimension));
            assert_eq!(dimension.to_string(), name);
            let json = ok(serde_json::to_string(&dimension), "serialize");
            assert_eq!(
                ok(
                    serde_json::from_str::<BudgetDimension>(&json),
                    "deserialize"
                ),
                dimension
            );
        }
        for bad in ["", "MEMORY", "cpu", "memory "] {
            assert!(
                matches!(
                    bad.parse::<BudgetDimension>(),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::BudgetDimension,
                        ..
                    })
                ),
                "{bad:?} must be rejected (closed set)"
            );
        }
    }

    // ---- QuotaBudget ----

    #[test]
    fn quota_budget_predicates() {
        assert!(total_budget(512).is_total());
        assert!(!total_budget(512).is_unconstrained());
        assert!(QuotaBudget::none().is_unconstrained());
        assert!(!QuotaBudget::none().is_total());
        let partial = QuotaBudget::new(
            Some(ByteSize::from_bytes(256)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!partial.is_total());
        assert!(!partial.is_unconstrained());
        assert_eq!(partial.max_memory(), Some(ByteSize::from_bytes(256)));
        assert_eq!(partial.call_timeout(), None);
    }

    // ---- QuotaNode / QuotaHierarchy 构造校验 ----

    #[test]
    fn node_rejects_global_without_total_budget() {
        assert!(matches!(
            QuotaNode::new(QuotaLevel::Global, QuotaBudget::none(), vec![]),
            Err(DomainError::InvalidValue {
                kind: ValueKind::QuotaBudget,
                ..
            })
        ));
    }

    #[test]
    fn node_enforces_level_shapes() {
        // 组节点的子节点必须是实例层。
        let bad_group = QuotaNode::new(
            QuotaLevel::Group(group_id("g")),
            QuotaBudget::none(),
            vec![node(
                QuotaLevel::Group(group_id("nested")),
                QuotaBudget::none(),
                vec![],
            )],
        );
        assert!(matches!(
            bad_group,
            Err(DomainError::InvalidValue {
                kind: ValueKind::QuotaHierarchy,
                ..
            })
        ));
        // 实例节点必须是叶子。
        let bad_leaf = QuotaNode::new(
            QuotaLevel::Installation(installation()),
            QuotaBudget::none(),
            vec![node(
                QuotaLevel::Installation(installation()),
                QuotaBudget::none(),
                vec![],
            )],
        );
        assert!(matches!(
            bad_leaf,
            Err(DomainError::InvalidValue {
                kind: ValueKind::QuotaHierarchy,
                ..
            })
        ));
    }

    #[test]
    fn hierarchy_rejects_non_global_root() {
        assert!(matches!(
            QuotaHierarchy::new(node(
                QuotaLevel::Group(group_id("g")),
                QuotaBudget::none(),
                vec![],
            )),
            Err(DomainError::InvalidValue {
                kind: ValueKind::QuotaHierarchy,
                ..
            })
        ));
    }

    #[test]
    fn hierarchy_rejects_duplicate_ids() {
        // 同一组出现两次。
        let duplicate_group = QuotaNode::new(
            QuotaLevel::Global,
            total_budget(512),
            vec![
                node(
                    QuotaLevel::Group(group_id("g")),
                    QuotaBudget::none(),
                    vec![],
                ),
                node(
                    QuotaLevel::Group(group_id("g")),
                    QuotaBudget::none(),
                    vec![],
                ),
            ],
        )
        .ok();
        let duplicate_group = match duplicate_group {
            Some(root) => root,
            None => unreachable!("shape is valid"),
        };
        assert!(matches!(
            QuotaHierarchy::new(duplicate_group),
            Err(DomainError::InvalidValue {
                kind: ValueKind::QuotaHierarchy,
                ..
            })
        ));
    }

    // ---- 层级求值（最严格生效，模块文档裁决） ----

    #[test]
    fn effective_without_group_is_global_only() {
        // 树里没有该实例：纯全局预算。
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                QuotaBudget::none(),
                vec![],
            )],
        );
        let effective = hierarchy(root).effective(installation());
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(512));
        assert_eq!(effective.max_concurrent(), QuotaCount::from_u64(4));
        assert_eq!(effective.call_timeout(), Duration::from_secs(30));
        // 绑定层 = 全局。
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Global
        );
    }

    #[test]
    fn effective_full_chain_most_restrictive_wins() {
        // 实例有自己更严格的预算：min 取实例值。
        let instance = installation();
        let instance_budget = QuotaBudget::new(
            Some(ByteSize::from_bytes(128)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let group_budget = QuotaBudget::new(
            Some(ByteSize::from_bytes(256)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                group_budget,
                vec![node(
                    QuotaLevel::Installation(instance),
                    instance_budget,
                    vec![],
                )],
            )],
        );
        let effective = hierarchy(root).effective(instance);
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(128));
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Installation(instance)
        );
        // 未设置的维度沿用路径上的更宽松显式值（组未设置 → 全局）。
        assert_eq!(effective.max_concurrent(), QuotaCount::from_u64(4));
        assert_eq!(
            effective.binding(BudgetDimension::Concurrent),
            &QuotaLevel::Global
        );
    }

    #[test]
    fn effective_group_binds_when_installation_unset() {
        // 实例未设置 → 组层的显式值生效（绑定层 = 组）。
        let instance = installation();
        let group_budget = QuotaBudget::new(
            Some(ByteSize::from_bytes(256)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                group_budget,
                vec![node(
                    QuotaLevel::Installation(instance),
                    QuotaBudget::none(),
                    vec![],
                )],
            )],
        );
        let effective = hierarchy(root).effective(instance);
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(256));
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Group(group_id("g"))
        );
        // 组未设置并发 → 全局绑定。
        assert_eq!(
            effective.binding(BudgetDimension::Concurrent),
            &QuotaLevel::Global
        );
    }

    #[test]
    fn effective_group_cannot_loosen_global() {
        // 组把 memory 设得比全局还大：min 规则下全局仍生效（硬上限不可
        // 放宽，模块文档裁决理由 1）。
        let instance = installation();
        let group_budget = QuotaBudget::new(
            Some(ByteSize::from_bytes(4096)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                group_budget,
                vec![node(
                    QuotaLevel::Installation(instance),
                    QuotaBudget::none(),
                    vec![],
                )],
            )],
        );
        let effective = hierarchy(root).effective(instance);
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(512));
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Global
        );
    }

    #[test]
    fn effective_direct_installation_child_skips_group() {
        // Global → Installation 直连（无组的实例仍可有实例级配额）。
        let instance = installation();
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Installation(instance),
                QuotaBudget::new(
                    Some(ByteSize::from_bytes(64)),
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                ),
                vec![],
            )],
        );
        let effective = hierarchy(root.clone()).effective(instance);
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(64));
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Installation(instance)
        );
        // 其他实例不受影响：全局预算。
        assert_eq!(
            hierarchy(root).effective(installation()).max_memory(),
            ByteSize::from_bytes(512)
        );
    }

    #[test]
    fn effective_tie_binds_to_most_specific_level() {
        // 组与全局同值并列 → 绑定层 = 组（更具体）；实例同值 → 实例。
        let instance = installation();
        let same_as_global = QuotaBudget::new(
            Some(ByteSize::from_bytes(512)),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                same_as_global.clone(),
                vec![node(
                    QuotaLevel::Installation(instance),
                    QuotaBudget::none(),
                    vec![],
                )],
            )],
        );
        let effective = hierarchy(root).effective(instance);
        assert_eq!(effective.max_memory(), ByteSize::from_bytes(512));
        assert_eq!(
            effective.binding(BudgetDimension::Memory),
            &QuotaLevel::Group(group_id("g"))
        );
        // 实例也显式设为同值 → 实例绑定。
        let root2 = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                same_as_global.clone(),
                vec![node(
                    QuotaLevel::Installation(instance),
                    same_as_global,
                    vec![],
                )],
            )],
        );
        let effective2 = hierarchy(root2).effective(instance);
        assert_eq!(
            effective2.binding(BudgetDimension::Memory),
            &QuotaLevel::Installation(instance)
        );
    }

    #[test]
    fn effective_binding_covers_all_dimensions() {
        let instance = installation();
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Installation(instance),
                QuotaBudget::none(),
                vec![],
            )],
        );
        let effective = hierarchy(root).effective(instance);
        for dimension in BudgetDimension::all() {
            assert!(
                effective.bindings().contains_key(&dimension),
                "binding for {dimension} must be present (global is total)"
            );
        }
    }

    #[test]
    fn quota_hierarchy_serde_roundtrip() {
        let instance = installation();
        let root = node(
            QuotaLevel::Global,
            total_budget(512),
            vec![node(
                QuotaLevel::Group(group_id("g")),
                QuotaBudget::none(),
                vec![node(
                    QuotaLevel::Installation(instance),
                    QuotaBudget::none(),
                    vec![],
                )],
            )],
        );
        let tree = hierarchy(root);
        let json = ok(serde_json::to_string(&tree), "serialize");
        assert_eq!(
            ok(serde_json::from_str::<QuotaHierarchy>(&json), "deserialize"),
            tree
        );
        // 反序列化边界同样执行形状校验（§13.3）：全局层预算非全量拒绝。
        let invalid = r#"{
            "root": {
                "level": "global",
                "budget": {"max_memory": null, "max_host_buffer": null, "max_body_size": null, "max_concurrent": null, "max_queue": null, "max_tasks": null, "call_timeout": null},
                "children": []
            }
        }"#;
        assert!(serde_json::from_str::<QuotaHierarchy>(invalid).is_err());
    }
}
