# Operune 平台工程主规范

**副标题：工业生产级、场景无关、WebAssembly-native / Component-first 的平台级运维产品**  
**文档性质：Normative Platform & Engineering Master Specification / AI Agent Execution Contract**  
**规范修订：Operune Engineering Baseline R2（面向 Operune Platform / Core Runtime 0.1.0 → 1.0.0）**  
**状态：FINAL / Frozen；后续仅可通过本规范定义的变更治理演进**  
**基线日期：2026-08-07**  
**项目名称：Operune**

---

## 0. 文档地位与使用方式

本文件是 **Operune 平台级产品与 Core Runtime** 的统一工程主规范。它同时承担产品定位与边界、架构宪法、技术选型、开发约束、测试规范、验收准则、版本路线图与 AI Agent 执行准则。除本文件明确标记为“事实快照 / Informative”的内容外，其余规范性条款均构成实现、Review、Release 与 AI Agent 的共同约束。

本文件使用以下规范性词汇：

| 词汇 | 含义 |
|---|---|
| **MUST / 必须** | 不满足即违反规范，不得合并或发布。 |
| **MUST NOT / 禁止** | 明确禁止，不得以便利、性能或赶进度为由绕过。 |
| **SHOULD / 应当** | 默认必须遵循；只有存在可证明的工程理由并形成 ADR 才可偏离。 |
| **MAY / 可以** | 在不破坏其他约束的前提下可选。 |

本规范不是“建议集合”。AI Agent、维护者和贡献者在实现过程中不得自行重解释已经冻结的产品哲学、架构边界或安全要求。遇到规范未覆盖的具体实现细节时，必须使用本文件第 25 章的裁决顺序自主判断；只有当决定会改变公开契约、核心哲学、安全边界、数据模型或版本兼容承诺时，才进入 ADR/Owner Decision Gate。

---

# 第一篇：产品与工程宪法

## 1. 产品定义

Operune 是一个**面向运维领域的平台级产品**。它不以“服务器运维”“云运维”“边缘运维”“机器人运维”或“Web 后台”中的任何一种具体场景定义自身，而是为运行在受支持通用计算节点上的运维应用提供统一的执行、组合、授权、治理、Web 呈现、生命周期、状态与分布式控制基础。

Operune 采用 **WebAssembly-native / Component-first** 架构：以 Rust Core Runtime 作为唯一不可卸载的原生基础层；以标准 WebAssembly Component 作为唯一可安装扩展执行单元；以 WIT 作为唯一跨 Component 边界的结构化接口契约语言；标准能力优先直接复用 WASI。产品层可以使用“插件 / Plugin”描述可安装扩展，但其技术语义始终落到标准 WebAssembly Component，不存在第二种插件执行制品。

系统中唯一不可卸载、不可被 Component 替代的原生基础是 Core Runtime。Operune Core Runtime 只负责平台自身“能够存在、能够被管理、能够安全运行和组合 Component、能够治理资源与权限、能够在故障后恢复”所必需的最小能力。

所有具体运维领域功能均不属于 Core，包括但不限于：日常运维控制台、监控、日志、告警、Kubernetes、容器、数据库、中间件、网络、主机/设备观察、诊断、CMDB、备份、发布、自动化、AI 运维能力，以及面向某个云、厂商、机器人平台、车辆计算平台或设备生态的集成逻辑。它们全部由标准 WebAssembly Components 提供。

### 1.1 产品核心关系

```text
              Browser / API Client / Recovery CLI
                           |
                           v
+--------------------------------------------------+
|              Operune Core Runtime               |
|                     Rust                         |
|                                                  |
|  HTTP/TLS          Root Admin / Recovery Plane   |
|  Auth/RBAC         Audit / Policy                |
|  Component Manager Capability Resolver           |
|  Config/Secret     State/Scheduler/Event         |
|  Resource Control  Platform Adapters             |
|                                                  |
|                 Wasmtime Engine                  |
+--------------------------+-----------------------+
                           |
                  Standard Components
                           |
       +-------------------+-------------------+
       v                   v                   v
  ops-console.wasm    monitoring.wasm      diagnostics.wasm
       ...                 ...                 ...
                           |
                           v
             External Systems / Node Resources
```

Browser、API 和本机 Recovery CLI 是不同的交互/恢复表面；Web 是 Operune 的一等呈现能力，但不是产品唯一入口，也不是 Operune 的部署边界。Core Runtime 运行在受支持的宿主 OS/CPU target 上；浏览器中的 HTML/CSS/JavaScript/WebAssembly 只属于用户界面实现或 Component Web 资产，不被误认为 Core Runtime 本体。

### 1.2 Runtime Host Node 与 Managed Resource 必须分离

Operune 必须永久区分两个概念：

- **Runtime Host Node**：实际运行 Operune Core Runtime 的计算节点。它受第 9 章 OS/CPU target、交付、资格认证和分布式 Node 模型约束；
- **Managed Resource**：被 Operune 运维、观察、诊断、配置或治理的对象。它可以是本机资源，也可以是远端服务器、云资源、Kubernetes、数据库、中间件、网络设备、BMC、Web/SaaS 服务、机器人/车辆计算平台或其他可通过 Component 已授权能力真实接入的系统。

Managed Resource **不要求**运行 Operune Core，也不要求使用与 Runtime Host Node 相同的 OS/CPU 架构。Component 可以通过 WASI、Operune 合法 Host capability、网络/API 或成熟外部系统与 Managed Resource 交互。

因此，“Operune 当前 Runtime Host 支持 Linux/Windows/macOS、x86_64/AArch64”只约束 **Core 能部署在哪里**，不能被误读成“Operune 只能管理这些系统”。新增 Managed Resource 类型通常应通过新 Component 完成，而不是扩大 Core Runtime 的宿主平台矩阵。

### 1.3 场景不设限，运维领域有边界

Operune 的产品边界由**运维领域语义**定义，而不是由硬件形态、机房位置、云/边缘标签或设备行业定义。

受支持的部署对象可以包括数据中心服务器、云主机、工作站、边缘计算节点、工业计算机、机器人/自动驾驶计算节点及其他运行受支持通用操作系统的计算设备。上述只是部署形态示例，不形成 Server Edition、Edge Edition、Robot Edition 等平行产品，也不得导致不同的 Core/Component/WIT 基础语义。

Operune 关注的是计算节点和其上软件/基础设施的观察、诊断、配置、维护、治理、升级、恢复、自动化和生命周期管理。一个能力是否属于 Operune，首先看它是不是运维/管理语义，而不是看它能否编译成 Wasm。

因此：

- 任意普通业务/消费应用托管不因为“可以运行在 Wasm 中”就自动成为 Operune 产品目标；
- 机器人、自动驾驶或工业平台可以是 Operune 的部署与管理对象，但 Operune **MUST NOT** 进入制动、转向、电机控制、硬实时闭环或其他 safety-critical control loop；
- 设备/行业特有逻辑必须保持在 Component 或成熟外部系统中，不能反向污染 Core；
- 部署形态可以影响资格测试、默认资源预算和运行策略，但不得产生不同的产品哲学或私有扩展格式。

### 1.4 WebAssembly-native，而不是 WebAssembly 纯粹主义

“全面拥抱 WebAssembly”在 Operune 中具有明确工程含义：

1. 可安装扩展执行单元统一为标准 WebAssembly Component；
2. Core↔Component、Component↔Component 的结构化契约统一为 WIT；
3. 标准已有 Host 能力优先使用 WASI，而不是创建平行 Host API；
4. 隔离、能力授权、可移植性、组合和跨语言互操作优先建立在 Component Model/WASI 的原生语义上；
5. 业务 Web 资产与后端能力可以作为同一 Component 版本交付；浏览器端是否使用 HTML/CSS/JavaScript 或 browser Wasm 属于 Component 的实现选择，只要不突破 Core 浏览器安全边界；
6. 成熟外部系统继续以其原生形态存在，通过 Component 集成，不为了“Wasm 化”而重写；
7. Core Runtime 仍保持最小原生 Rust Host。把 Host 自身强行改造成 Wasm、或为了技术纯粹度牺牲可靠性/可恢复性，不属于“拥抱 Wasm”。

总纲：**Wasm 用来定义可移植、可组合、可治理的扩展边界；不是用来制造新的形式主义。**

### 1.5 产品不是

本项目不是：

- 新的 WebAssembly VM；
- 新的 Wasm 字节码或插件 ABI；
- `.plugin` / `.opsapp` 私有包格式；
- Prometheus、Loki、OpenTelemetry、Kubernetes 等成熟系统的重新实现；
- 一个把所有运维数据强制穿过 Core 的 telemetry 数据面；
- 一个允许 Component 获得 Core 进程全部宿主权限的传统动态库插件系统；
- 一个只服务服务器、云、边缘或某种设备行业的场景专用产品；
- 一个任意业务应用通用 PaaS；
- 一个 safety-critical / hard-real-time 控制系统；
- 一个为了展示 Wasm 技术而存在的 Demo。

它是一个真实可生产部署、可跨计算形态演进的 WebAssembly-native 运维平台。

---

## 2. 全量五要素交叉审计准则

“交叉审计”是本项目的最高设计与工程审查方法，不是普通 checklist，也不是只审当前 diff。任何新需求、结论、设计、代码、依赖、WIT 契约、路线图调整和发布决定，都必须与**截至该时点全部已冻结结论**共同重新审查。新结论不得静默覆盖旧结论；发现冲突必须先显式指出、消解并通过相应 ADR/Owner Gate 后，才能形成新的冻结基线。

每次审计必须同时通过以下五个维度：

1. **哲学统一**：是否继续遵守 Rust 原生设计、Component Model/WASI 原生设计、标准优先、能力最小授权、Core 极薄等顶级原则。
2. **语义一致**：同一概念是否在域模型、WIT、持久化、Web API、日志、测试和路线图中保持同一含义；不得同名异义或异名同义。
3. **逻辑自洽**：生命周期、状态机、错误模型、权限模型、升级/回滚语义及版本间演进是否无循环矛盾、无不可达或未定义状态。
4. **真实有效**：能力是否由当前真实可用的 Rust/Wasmtime/WASI/OS 能力和已验证工程事实支撑；不得把实验能力写成生产承诺，不得用想象代替验证。
5. **完整可靠**：必须覆盖 happy path 与失败路径、崩溃恢复、边界条件、资源耗尽、安全退化、取消/超时、版本迁移、回滚和可观测性。

强制执行流程：

1. **加载基线**：确认当前版本、全部已接受 ADR、本规范全部冻结条款及相关公开 WIT/数据契约；
2. **定位变更**：明确本次新增/修改/删除的语义，不允许只描述代码 diff；
3. **全量撞库**：逐项检查该变更与所有相关冻结结论是否冲突、重复、偷换概念或造成未来锁死；
4. **五维审计**：对变更及受影响的既有结论逐一执行上述五项审计；
5. **冲突处理**：发现冲突时禁止静默选择“新实现”；必须明确冲突、优先级、影响和解决路径；
6. **回归验证**：测试不仅证明新功能成立，还必须证明原冻结语义没有被破坏；
7. **留下证据**：每个非平凡 PR/变更记录必须包含简洁的交叉审计结论，指出检查了哪些既有契约、是否存在冲突以及验证证据。

任何只审查“当前代码是否能工作”、却没有与全部既有冻结基线交叉核对的变更，均视为审计未完成。

---

## 3. 十四条不可违背的顶级原则

### P1. 标准优先

标准 WebAssembly / Component Model / WIT / WASI 已解决的问题，禁止创建平行的私有机制。

### P2. Component 是唯一扩展执行制品

技术上的可安装扩展执行单元是标准 `.wasm` WebAssembly Component。Plugin 仅是产品词汇，不对应新的二进制格式。

### P3. WIT 是唯一跨边界接口契约

Core↔Component、Component↔Component 的结构化能力契约只使用 WIT。不得设计第二套 IDL、Rust ABI、动态符号协议或私有 RPC ABI。

### P4. WASI 能力不重复包装

当 WASI 的标准语义已经准确满足需求时直接提供该标准接口。禁止仅为统一命名再造 `operune:http`、`operune:clock`、`operune:file` 等等价接口。

### P5. 自定义只发生在标准未覆盖且产品必须表达的领域契约

只有 WebAssembly Component Model/WIT/WASI 等正式标准没有准确表达、而本产品确实不可缺失的**平台领域或运维领域语义**，才允许定义项目自己的 WIT package。例如 Component 应用描述/Web 扩展等平台语义，以及资源、诊断、告警等运维领域语义。所有自定义仍必须使用标准 WIT；自定义的是领域契约，不是新的运行机制、插件格式、IDL，也不得复制已有 WASI 语义。

### P6. Core 永远不懂具体运维产品

Core 源码不得出现 Prometheus、Loki、PostgreSQL、Kafka、Kubernetes 等具体集成逻辑。成熟外部系统由 Component 通过标准/通用 Host 能力集成。

### P7. 默认无权限

Component 的权限来自显式 imports + 安装实例上的显式授权。没有授权即没有能力，不存在 ambient authority。

### P8. 版本与状态必须可恢复

所有**需要跨 Core 进程重启继续成立的权威状态**必须持久化，并具有明确的崩溃恢复语义。请求中的临时缓冲、执行中的 Store/Instance、队列游标、派生缓存等瞬态状态不要求伪持久化，但必须定义 crash 后是重建、丢弃、失败还是由 durable journal 恢复。Component linear memory 永远不能成为跨重启权威业务状态的唯一事实源。

### P9. Rust 第一方代码 100% Safe Rust

项目仓库内第一方 Rust 源码禁止 `unsafe`。任何需要 unsafe/FFI 的平台能力只能通过已审计的安全第三方封装获得；没有合格安全封装时，宁可暂不提供能力。

### P10. 类型表达语义

禁止 primitive obsession。ID、版本、大小、时间、状态、权限、端点、路径、资源预算等必须通过有意义的类型建模；边界只解析一次，内部保持强类型。

### P11. 生产可靠性高于形式美学

“完全静态”“一个更酷的新 WASI 版本”“更少依赖”等目标不得凌驾于上游支持等级、安全补丁、可验证性和故障恢复之上。

### P12. 演进必须增量兼容

标准版本、平台和运行时升级必须通过隔离适配层和双栈过渡完成。禁止让 Wasmtime/WASI 具体版本类型泄漏到领域核心，禁止未来通过大规模重构才能升级标准版本。

### P13. 场景不是产品边界

服务器、云、工作站、边缘、工业、机器人或自动驾驶计算节点只是不同部署形态。Runtime Host Node 只要达到宿主平台资格，Operune 就保持同一 Core、Component、WIT、Capability、安全和生命周期模型；Managed Resource 则不要求运行 Core。禁止通过场景 Edition 或“每种被管资源一套 Agent/Core”分裂基础语义。

### P14. Wasm-native，不做 Wasm 纯粹主义

扩展执行、跨边界契约、隔离、组合和可移植性应最大限度顺着 WebAssembly Component Model/WASI 的原生设计；但最小 Core Host、成熟外部系统和浏览器原生技术不因形式美学被强行重写为 Wasm。技术选择必须服务于平台边界与生产可靠性。

---

# 第二篇：标准与架构边界

## 4. 标准技术基线

### 4.1 生产基线（0.1.0）

0.1.0 的生产基线固定为：

- Rust 2024 Edition；
- Rust toolchain **1.97.1**，精确写入 `rust-toolchain.toml`；
- Wasmtime **36 LTS 系列**作为当前已发布 production baseline；
- WebAssembly Component Model；
- WIT；
- WASI 0.2 / WASIp2 作为 production ABI/Host 路径；
- 0.1.0 Linux GNU production CPU architectures：`x86_64` 与 `aarch64` / ARM64；
- Cranelift 作为 Wasmtime 生产编译后端；
- Operune Core Runtime 内嵌 Wasmtime，不要求用户安装外部 runtime。

Wasmtime 的**生产兼容线**固定到已经正式发布且仍受支持的 LTS major，而不是固定到首个 `x.0.0` patch。正常生产升级只在同一 LTS major 的已接受 patch 内进行；精确解析版本由 committed `Cargo.lock` 固定。每个 patch 更新仍必须通过第 23 章 Dependency Update Gate 与生产回归 Gate，不能因为同 major 就无审查漂移。

截至本规范基线日，Wasmtime 48 已于 2026-08-05 进入 LTS branch 阶段，但官方 release date 是 **2026-08-20**，因此它在 2026-08-07 仍不能作为“当前已发布 production baseline”。Operune 当前生产线选择仍受支持的 **Wasmtime 36 LTS**。48 正式发布后可作为下一 LTS promotion candidate，通过独立依赖更新 PR、完整 qualification 和回滚验证后再从 36 升级。

Wasmtime 正常 major 升级采用 **LTS-to-LTS**。不得因为上游发布了更新的普通 major 或未来 LTS 已开分支就自动跟随；安全或正确性事件需要跨 LTS major 时必须形成 ADR，并明确回退路径。

### 4.2 “标准已发布”与“当前实现可生产”必须分离

截至 2026-08-07，WASI 0.3 已经成为正式发布的标准里程碑；但 Operune 的生产准入不由“标准是否发布”单独决定，还必须同时审查所选 Wasmtime LTS 对应 Host 实现的成熟度。

当前 Wasmtime active development/release-train 文档中的 `wasmtime_wasi::p3` 与 `wasmtime_wasi_http::p3` 仍被官方明确标记为 experimental / unstable / incomplete / not ready for production；而 Operune 当前 36 LTS production line 本身也不构成 p3 production 基线。因此：

- **MUST**：0.1.0 production feature set 只启用 WASI 0.2；
- **MUST NOT**：把“WASI 0.3 已发布”解释为“Operune 可以直接把 p3 Host 放入生产路径”；
- **MAY**：仓库存在隔离的 `runtime-wasi-p3-lab` 或等价实验 workspace/crate；它可以跟踪与 production 不同的 Wasmtime line，但不得进入 production dependency closure；
- **MUST**：lab 路径不能成为 production dependency，不能改变 production WIT 契约，也不能被 `--all-features` 的构建成功误认为生产资格；
- **MUST**：p3 生产准入必须经过第 8.3 节成熟度 Gate。

### 4.3 事实快照与规范契约分层

本规范区分两类事实：

1. **长期规范契约**：产品边界、WIT/WASI 原则、Capability、安全、状态、生命周期、兼容性和 Release Gate；这些只能通过本规范的治理机制修改。
2. **时间敏感工程快照**：Rust patch、crate patch、上游支持等级、标准实现成熟度；这些必须在依赖升级或 Release 前重新查询官方 primary source，并通过 Gate 后更新锁文件与基线记录。

不得把第二类快照硬化为阻止安全修复的永久规则，也不得以“事实会变化”为理由绕过第一类契约。

---

## 5. Core 与 Component 的永久边界

### 5.1 Core 必须拥有

本节定义的是 **Operune 1.0 以内的永久责任归属**，不是说这些能力都必须在 0.1.0 已经对 Component 开放。具体进入版本以第九篇路线图为准；但一旦该平台机制进入产品，其所有权只能在 Core，不得由某个业务 Component 私建平行机制。

Core 只拥有平台不可缺失能力：

- Wasmtime Engine 与 Component 运行管理；
- Component 验证、安装、启停、升级、回滚、卸载；
- imports/exports 解析、Capability Resolution；
- 最小 Root Admin Web；
- HTTP/TLS 基础服务；
- 身份认证、平台级 RBAC、Root Admin；
- 权限授权与 Capability Scope；
- Core Config、Component Config、Secret、State 的平台机制；
- Scheduler、Event 基础机制；
- 资源预算、超时、中断、并发治理；
- Runtime 自身结构化日志、指标、审计；
- 安全模式、故障恢复、版本一致性；
- 跨平台 Host Adapter；
- 后续版本中的分布式 Runtime 控制能力。

### 5.2 Core 永久禁止拥有

Core 不包含任何具体运维领域实现，例如：

```text
query_prometheus()
read_loki()
list_kubernetes_pods()
postgres_health_check()
manage_kafka_acl()
```

判断规则：**卸载所有 Component 后，为了管理、保护或恢复 Runtime 自身，这个能力是否仍然必须存在？**

- 是 → 候选 Core 能力；
- 否 → 必须属于 Component；
- 无法明确回答 → 默认不进入 Core，先建模为 Component 或延后。

### 5.3 成熟外部系统

外部成熟系统保持原生部署。例如 Prometheus 仍然是 Prometheus；集成它的 `prometheus.wasm` 负责产品集成、UI、查询适配和领域能力暴露。Core 不理解 PromQL，也不承载 Prometheus 数据面。

这一规则同样适用于云厂商 API、机器人中间件、设备管理服务、GPU/AI 平台、车辆计算平台或其他行业生态。若某个集成依赖厂商 SDK、原生驱动或专有运行时，优先通过该厂商已有守护进程/API、标准 OS 能力或可被明确建模的通用 Host capability 由 Component 接入；Core **MUST NOT** 因某个设备/厂商直接嵌入专有 SDK 或产品知识。无法在现有安全边界内诚实提供的能力，应延后而不是破坏 Core/Component 边界。

---

## 6. Component 模型

### 6.1 唯一制品

Core 的扩展安装输入是标准 WebAssembly Component `.wasm`。不得要求外层私有 manifest 或私有容器才能被识别为可执行插件。

### 6.2 一个 Component 的完整性

一个应用型 Component 可以同时拥有：

- 后端逻辑；
- Web UI 静态资源；
- 图标；
- 对用户展示的元数据；
- 配置描述；
- 导入能力；
- 导出能力。

这些内容属于同一 Component 版本。对于前端资源，推荐在构建 Component 时嵌入，随后通过项目定义的标准 WIT interface 暴露给 Core；Core 可以在激活阶段读取、按 Component 内容摘要缓存并直接提供给浏览器。静态资源请求不必每次重新执行 Wasm。

### 6.3 WIT 契约

WIT package 命名必须稳定、版本化、语义化。项目 WIT 不得复制 WASI 已经准确表达的基础功能。

项目 WIT 中应优先使用：

- `record` 表达结构；
- `enum` 表达闭集状态；
- `variant` 表达互斥的不同形态；
- `flags` 表达可组合权限/特征；
- `resource` 表达有生命周期的宿主/Component 资源；
- `result` 表达预期失败；
- 未来成熟后使用标准 `stream<T>` / `future<T>` / `async func` 表达流与异步。

禁止把所有协议、状态和 ID 都降级成 `string`。

### 6.4 Capability 默认隔离

一个 Component 的 export 只有经过 Core 的 capability resolution 和 policy 授权后，才可用于满足另一个 Component 的 import。Export 本身不自动赋予所有 Consumer 访问权。

### 6.5 组件可移植性

标准 Component 原则上不能泄漏宿主 OS 私有对象，例如 Linux fd、Windows HANDLE、Darwin mach port 等。必须通过 WIT 的可移植领域模型或标准 WASI resource 表达。

---

### 6.6 Operune WIT namespace 与公共契约

Operune 自定义 WIT package 的 namespace **MUST** 使用 `operune:*`。0.1.0 首批公共平台契约至少分为：

- `operune:component@0.1.0`：Component descriptor、平台生命周期/健康检查等仅 Operune 平台拥有而 WASI 不表达的语义；
- `operune:web@0.1.0`：0.1.0 最小 Component Web bridge 所需的 descriptor、静态资源和受控 action 语义。

后续 `state`、`scheduler`、`event`、更完整的 `web` 等契约按各自 package 版本独立演进。WIT package 版本是**接口契约版本**，不是 Core Runtime 发布版本的别名。

任何 `operune:*` package 都必须先证明 WASI/Component Model 没有准确表达相同语义。若未来标准覆盖了某项自定义能力，迁移必须通过显式版本化和兼容层完成，不能静默重解释旧 package。

### 6.7 Component 身份不是文件名，也不是外层 manifest

安装输入只有标准 `.wasm` Component。Operune 不引入私有 manifest 来提前声明身份。

必须明确区分：

- **ContentDigest**：对收到的原始 Component 字节计算得到的不可变内容事实，在执行任何 guest 代码前即可得到；
- **ComponentId**：Component 通过 Operune 标准 descriptor export 声明的逻辑产品/应用身份；
- **ComponentVersion**：作者声明的发布版本；
- **InstallationId**：由 Core 创建并持久化的安装实例身份；授权、运行状态和本机生命周期绑定到它，而不是绑定到文件名；
- **Contract Surface Identity**：从 Component binary type 实际可观察的 imports/exports、package/interface/version 和类型关系得到的接口事实。

Operune **MUST NOT** 假设原始 WIT 源文件的 root package name 或 world name 能从最终 `.wasm` Component 二进制中可靠恢复，也不得把它们当作运行时身份事实源。若产品确实需要作者可见的应用名称/类别，应由 `operune:component` descriptor 显式声明；运行时兼容判断只依赖二进制中真实可观察的 contract surface。

安装早期的 quarantine/candidate 记录以 digest 为主键；只有 descriptor 被成功读取、验证且与现有注册表不冲突后，才建立 `ComponentId + ComponentVersion -> Digest` 的逻辑版本关系并创建/关联 `InstallationId`。文件名、上传路径和 URL 永远不能成为逻辑身份事实源。

---

## 7. Wasmtime 运行模型

### 7.1 Engine

每个 Core Runtime 进程默认创建一个长期共享的 `wasmtime::Engine`。Engine 配置在启动后视为不可变基础设施，不为每个 Component 创建独立 Engine。

### 7.2 Component

`.wasm` 经安全 Wasmtime API 验证/编译形成 `Component`。Compiled Component 可复用；不得把 Wasmtime 私有序列化/AOT 格式升级为用户可见的插件制品格式。

第一方代码禁止调用需要 `unsafe` 的反序列化入口来加载不可信预编译产物。

### 7.3 Store 与 Instance

Store 是一个运行实例的 Wasm 状态和 Host 状态边界。实例化策略默认使用 Wasmtime `OnDemand`，因为它是官方默认且资源在实例化时分配、Store 释放时回收。

一个 Active ComponentVersion 在运行时拥有一个**有界 Instance Set**，而不是把一个 Store/Instance 当成可被任意并发请求共享的全局对象。每个 Store/Instance 必须有单一 owner，在任一时刻只执行一个进入该实例的调用；并发请求通过有界 dispatcher/queue/semaphore 分配到可用实例。0.1.0 的 stateless contract 不承诺跨调用 instance affinity，调用者不得把 linear memory 或实例本地变量当作下一次调用仍存在的事实。热升级切换的是 Active Version 对应的整个 Instance Set snapshot，旧集合再按 drain 契约退出。具体实例数和伸缩策略属于资源 policy/实测实现细节，不进入 Domain 公共语义。

0.1.0 **MUST NOT** 默认启用 pooling allocator。只有性能剖析证明大量高频实例创建成为真实瓶颈，并通过 RSS/虚拟内存/可靠性基准后，才可在后续里程碑 ADR 引入 pooling。

### 7.4 资源治理

每个 Component 实例必须有明确预算，至少覆盖：

- linear memory 上限；
- table/instance 等 Wasmtime 资源上限；
- host buffer 上限；
- 最大并发；
- 最大排队；
- 单次调用截止时间；
- Component 生成的后台任务数量；
- HTTP request/response body 上限。

`StoreLimits` / `ResourceLimiter` 只解决 Wasmtime 可见资源，不能被误认为完整 OS/cgroup 内存限制。Host 分配的缓冲、数据库结果、缓存等必须由 Core 自己有界化。

### 7.5 CPU 中断策略

0.1.0 默认启用 epoch interruption。Core 维护统一 epoch ticker，为每次不可信执行设置 epoch deadline，并在超时后 trap 或取消。

不默认启用 fuel。Fuel 的确定性更强但执行开销更高；只有当产品出现“确定的 Wasm 指令预算”这一明确需求时，才通过 benchmark + ADR 启用。

### 7.6 无 ambient authority

默认 Store 不获得宿主文件系统、网络、环境变量、进程环境或随机任意资源。每一项 Host/WASI 能力均按 Runtime Policy 明确构建。

# 第三篇：可演进性、跨平台与交付

## 8. 标准版本隔离架构

### 8.1 目标

升级 Wasmtime、WASI 或 Component Model 不得迫使业务领域层、Core Domain、Component Registry、RBAC、State、Web 模型发生大范围重构。

### 8.2 强制分层

```text
Domain / Application
        |
Runtime Ports
        |
+---------------------------+
| runtime-wasm              |
|  Engine/Component/Store   |
+-------------+-------------+
              |
      WASI version adapters
       /             \
      v               v
runtime-wasi-p2   runtime-wasi-p3-lab
```

规则：

- `domain`、`application`、`web-admin`、`security`、`storage` **MUST NOT** import `wasmtime_wasi::p2` 或 `p3` 具体类型；
- WASI 版本具体 linker/binding 只存在于明确的 adapter crate；
- 项目领域 WIT 的版本独立于 WASI 版本；
- 项目领域 WIT **SHOULD NOT** 把 `wasi:io@0.2` 的 `input-stream`、`output-stream`、`pollable` 等版本特有类型嵌入自己的长期领域契约；
- 标准 WASI 能力直接作为 Component imports，域能力则保持自己的稳定语义；
- Host 内部的统一运行模型只使用项目自己的 Rust port/value types，不让 p2/p3 数据结构向内扩散。

### 8.3 WASI 0.3 准入 Gate

WASI 0.3 进入 production 必须同时满足：

1. 一个项目认可的 Wasmtime LTS 中，p3 不再被官方标注为 experimental / unstable / incomplete / not ready for production；
2. 对应 WASI HTTP 等项目实际使用的 p3 子系统达到同等生产状态；
3. Rust stable toolchain 可稳定构建项目需要的 p3 guest/host toolchain；
4. p2 与 p3 双栈符合性测试全部通过；
5. 同一业务语义在 p2/p3 下结果一致，除非标准语义本身明确发生变化；
6. 性能、内存、取消、流背压、错误映射均有实测；
7. Security Review 通过；
8. 形成迁移 ADR，说明标准差异和回退策略。

### 8.4 迁移方式

正式迁移必须采用 side-by-side：

```text
Core Runtime
   |
   +-- WASI 0.2 adapter  <-- existing components continue
   |
   +-- WASI 0.3 adapter  <-- new/opt-in components
```

禁止 flag-day：不得要求所有现有 Component 同时重新编译才能升级 Core。

WASI 0.3 官方迁移设计本身允许 Host 同时支持 0.2/0.3，并把 0.2 兼容放在 Host 边界处理；本项目必须顺着该标准演进方式设计，而不是另造兼容协议。

---

## 9. 跨平台、跨架构与部署形态战略

### 9.1 一等 CPU 架构与宿主 OS

从 R2 开始，Operune 的一等 CPU 架构集合冻结为：

- **x86_64 / AMD64**；
- **AArch64 / ARM64**。

两者在领域模型、WIT、Component、Capability、安全、状态和生命周期语义上完全等价。CPU 架构差异只能停留在构建、平台适配、运行时实现和资格测试层，不能向上变成产品功能差异。

当前基础宿主 OS 家族为：

- Linux；
- Windows；
- macOS。

这三个 OS 家族是当前 **Runtime Host Node** 架构与持续 CI 的基础，并不意味着 Operune 永久只允许这三个系统。未来其他通用 OS 只有在 Rust/Wasmtime/安全存储/TLS/服务生命周期等基础条件可真实满足并通过完整资格认证后，才可加入；新增 Host OS 不得要求重解释 Domain、Component 或 WIT 核心语义。这里的 Host OS 支持矩阵与 Managed Resource 类型无关：Operune 可以通过 Component 管理并未运行 Core、甚至不属于这些 OS 家族的资源。

0.1.0 不支持 32 位 x86/ARM。`armv7`、i686、Android、QNX、RTOS、bare-metal 等不因“ARM”或“设备场景”字样自动进入支持范围；它们只能作为独立未来平台决策逐项验证。

### 9.2 架构可移植、Production Supported 与上游 Tier 必须分离

必须严格区分：

1. **Architecture-ready**：源码和依赖方向没有阻止目标加入；
2. **CI Supported**：目标持续构建并运行规定测试；
3. **Operune Production Supported**：Operune 对该精确 target 做出生产承诺，并完成本规范定义的 qualification；
4. **Upstream Tier**：Rust/Wasmtime 对目标的上游支持等级，是 Operune qualification 的重要事实输入，但不是 Operune 产品状态的同义词。

“能编译”不能升级为 Production Supported；同样，上游不是 Tier 1 也不自动等于 Operune 永远不能生产支持。Operune 可以在充分理解上游风险后，对自己实际使用的受限组合完成更强的产品资格证明，但不得虚假改写上游状态。

### 9.3 0.1.0 支持矩阵

| Target | 0.1.0 地位 | 要求 |
|---|---|---|
| `x86_64-unknown-linux-gnu` | **Production Supported** | 全部 Production Qualification Gate；Wasmtime 当前 Tier 1 target。 |
| `aarch64-unknown-linux-gnu` | **Production Supported** | 全部 Production Qualification Gate；Wasmtime 当前 Tier 2，Operune 必须显式承担并验证该风险，不能冒充上游 Tier 1。 |
| `x86_64-pc-windows-msvc` | 一等开发/CI + Production Candidate | 持续构建、单测、集成测试；通过完整生产资格后可晋升。 |
| `aarch64-apple-darwin` | 一等开发/CI + Production Candidate | 持续构建、单测、集成测试；通过完整生产资格后可晋升。 |
| `x86_64-apple-darwin` | 构建/测试候选 | 依据真实用户价值与完整 qualification 决定是否正式支持。 |
| `aarch64-pc-windows-msvc` | Future Candidate | 当前上游支持等级不足以进入 0.1 正式矩阵；架构不得阻碍未来加入。 |
| `x86_64-unknown-linux-musl` | 静态交付资格候选 | 必须单独通过与 GNU production artifact 等价的完整资格。 |
| `aarch64-unknown-linux-musl` | Future Static Candidate | 当前上游 Tier 3；不得因 ARM64 GNU 已生产支持而自动宣称 musl 同等支持。 |

`aarch64-unknown-linux-gnu` 的 0.1 Production Supported 是 **Operune 自己在完整 qualification 成立后的产品承诺**。如果该 target 在 release candidate 上无法通过资源、安全、Crash、Component/WASI conformance 或真实硬件长期运行门禁，则 0.1.0 release 本身必须阻断，不能把 ARM64 临时降级为“文档支持”。

### 9.4 平台与架构代码边界

所有 OS 特定实现必须限定在 `platform-*` adapter crates。Domain/Application 不得直接读取 `/proc`、调用 Win32、依赖 launchd/systemd 或分支处理具体 CPU 架构。

禁止在 Domain/Application 等非平台层散落：

```rust
#[cfg(target_os = "linux")]
#[cfg(target_arch = "aarch64")]
```

允许的结构：

```text
                 Platform Ports
                      |
         +------------+------------+
         |            |            |
         v            v            v
 platform-linux platform-windows platform-macos
         |
         +--> target/arch-specific safe adaptation when truly required
```

只有 platform adapter 或确实属于 Wasmtime 宿主实现边界的 `runtime-wasm` adapter 可以出现不可避免的 OS/architecture 条件实现；这些差异不得泄漏为 Domain 公共契约。

如果某项 OS/设备能力在平台间含义不同，必须先定义真实、可移植的领域语义；无法诚实统一时，应定义 capability availability/variant，而不是用最低公分母伪装相同。

### 9.5 部署形态是资格环境，不是产品 Edition

Operune Release Qualification 至少覆盖两种现实环境：

- **General Compute Qualification**：服务器、云主机、工作站等常规资源环境；
- **Constrained / Edge Qualification**：内存和磁盘更紧、网络可能间歇、重启更频繁的边缘/设备级资源环境。

它们是测试与资源资格环境，不是两个产品版本。Component/WIT/安全/生命周期语义不得因 profile 不同而改变；允许变化的是明确配置的资源预算、缓存/日志上限、并发和部署策略。

对于每一种 Production Supported CPU architecture：

- Release Qualification **MUST** 在真实原生硬件上运行；
- QEMU/仿真/交叉编译可以补充 PR CI，但不能单独构成 Production Qualification；
- ARM64 release 至少应覆盖一个通用 Linux ARM64 硬件环境和一个具代表性的 constrained/edge-class ARM64 环境；不得把某个具体厂商设备写成 Operune 平台依赖；
- 必须验证低内存、磁盘压力、较慢持久存储、重复重启、断网/恢复、长期运行、epoch interruption、Component/WASI conformance、SQLite/fsync/rename crash consistency 与资源泄漏。

### 9.6 Windows 本机开发

Windows 是一等开发环境。开发者应能在 Windows 原生完成：

- Rust 编译；
- 单元测试；
- 绝大多数 Domain/Application/Wasmtime Component 集成测试；
- Root Admin Web 调试；
- WIT/Component 合同测试。

Linux 发布特定测试由 CI 和/或 WSL2 承担，不要求开发者日常在 Linux 物理机工作。

---

## 10. 单二进制交付策略

### 10.1 产品承诺

每个正式支持的 OS/architecture 组合交付**一个自包含的 Operune Core Runtime 可执行文件**。用户不得被要求额外安装 Wasmtime。同一源码和产品语义可以产生多个 target-specific executable；“支持 x86_64 + ARM64”不意味着把两种机器码塞进同一个 universal Linux binary。

“单二进制”只约束**可执行程序交付物**：每个正式支持 target 只有一个 Operune Core Runtime executable，并内嵌 Wasmtime；它不意味着运行时不能拥有显式的数据目录、SQLite 数据库、配置、TLS 证书/私钥、Component `.wasm` 文件或审计输出。“单二进制”也不等价于“所有平台必须完全静态链接”。

### 10.2 Linux GNU 正式基线

0.1.0 同时交付两个正式 Linux GNU production artifacts：

- `x86_64-unknown-linux-gnu`；
- `aarch64-unknown-linux-gnu`。

两者具有同一产品语义和功能承诺，但必须分别完成资格证明。当前 Wasmtime 对 x86_64 Linux GNU 是 Tier 1、对 AArch64 Linux GNU 是 Tier 2；该上游差异必须进入风险记录和 release evidence，不能通过统一写成“Linux 已支持”而抹平。

每个 GNU artifact 必须：

- 单可执行文件交付；
- 明确记录该 target 的最低 glibc/宿主基线；
- 在资格测试矩阵中的真实原生硬件与代表性发行环境实际运行；
- 不依赖用户额外安装 Wasmtime 或项目运行库；
- 与另一个 production architecture 保持相同的公开 Operune/Component/WIT 语义。

### 10.3 完全静态 musl 候选

0.1 CI 构建 `x86_64-unknown-linux-musl` 全静态候选，但不得自动替代 GNU Production Artifact。`aarch64-unknown-linux-musl` 仍是 Future Static Candidate，必须等待自身上游条件与完整 qualification，不能从 AArch64 GNU 的生产支持推导而来。

当前 Wasmtime 官方明确说明其 MUSL binary artifacts 本身仍是动态链接；完全静态需要项目自行源码构建和验证。因此静态候选必须由我们的 release pipeline 负责全部资格证明。

只有同时满足以下条件才能晋升为默认 Linux artifact：

- `file` / `readelf` / `ldd` 等验证无动态 loader/glibc 依赖；
- Wasmtime Component/WASI 全部符合性测试通过；
- 安全测试、模糊测试、并发测试、soak、崩溃恢复通过；
- 性能和 RSS 不发生不可接受退化；
- TLS、SQLite bundled、DNS、socket、文件系统等实际能力在目标发行环境通过；
- 上游 Wasmtime 支持等级和已知问题经重新评估；
- 与 GNU artifact 的功能和安全承诺等价。

若静态构建与生产可靠性冲突，**可靠性优先**。

### 10.4 禁止隐藏动态 sidecar

不得为了“表面单二进制”在运行时下载或悄悄启动一个未经明确架构定义的 runtime/helper 来弥补缺失功能。

---

# 第四篇：Rust 工程宪法

## 11. 第一方代码 100% Safe Rust

### 11.1 机械强制

所有第一方 Rust crate 根模块必须设置：

```rust
#![forbid(unsafe_code)]
```

Workspace lint 必须将 `unsafe_code` 设为 forbid。该规则覆盖：

- production source；
- `build.rs`；
- examples；
- tests；
- benches；
- first-party code generation helpers。

禁止：

- `unsafe { ... }`；
- `unsafe fn`；
- `unsafe trait` / `unsafe impl`；
- 裸 FFI；
- 通过 `allow(unsafe_code)` 局部绕过；
- 以代码生成方式偷偷引入第一方 unsafe。

### 11.2 对“100% 内存安全”的准确承诺

项目可以并且必须机械保证：**第一方源码只使用 Safe Rust**。

不得做不真实承诺：最终二进制的整个第三方依赖树（Wasmtime/JIT/OS/crypto/SQLite 等）内部可能包含经过其项目维护的 unsafe 或 FFI。项目不能诚实宣称整个机器码世界“零 unsafe”。

项目的安全承诺是：

- 第一方代码没有 unsafe escape hatch；
- 只通过第三方 crate 的 safe API 访问需要 unsafe/FFI 的能力；
- 第三方 unsafe 被供应链审计和更新策略约束；
- 发现 soundness issue 视为高优先级安全事件。

### 11.3 没有安全封装怎么办

如果某项平台能力只能通过第一方 unsafe/FFI 实现：

1. 首先寻找成熟、维护良好、许可兼容的 safe Rust crate；
2. 若没有，能力不得进入当前版本；
3. 不得建立仓库内部 `unsafe-platform` 逃生舱；
4. 后续只有顶级原则被项目 Owner 正式修改，才可重新讨论。

---

## 12. Rust 原生设计哲学

### 12.1 所有权表达生命周期

资源生命周期通过 Rust ownership/RAII 建模，而不是通过注释或约定。Component Handle、Lease、Session、Grant、Store Wrapper 等应在 Drop 或显式 state transition 中完成可靠清理。

### 12.2 状态机用类型和 enum 表达

禁止：

```rust
status: String
```

表达 Component 生命周期。

应使用闭集 enum，并对转换进行显式校验。例如概念状态：

```text
Installed -> Validated -> Activating -> Active -> Draining -> Disabled
                         \-> Failed
```

非法转换返回 typed error，不能静默忽略。

### 12.3 Result 表达可预期失败

外部输入、I/O、权限、资源不足、Component trap、版本不兼容都属于正常错误空间，必须返回 `Result`，不能 panic。

### 12.4 不依赖全局可变状态

禁止 `static mut`（同时也会违反 unsafe）以及隐藏的全局 mutable singleton。共享状态必须有明确 owner，通常由 composition root 创建并通过 `Arc` 显式注入。

### 12.5 不为抽象而抽象

只有真实出现第二实现、需要测试替身、平台边界或稳定契约时才创建 trait/port。禁止 Java 风格“一接口一实现”仪式性抽象。

### 12.6 不为未来猜测功能

YAGNI。路线图定义的未来能力可以预留稳定边界，但不得提前实现未被当前里程碑需要的复杂机制。

---

## 13. 类型安全与领域建模规范

### 13.1 Primitive Obsession 禁止

以下语义不得长期以裸 `String`、`u32`、`u64`、`usize` 在 Domain/Application 层传播：

- Component ID；
- Installation ID；
- User ID；
- Session ID；
- Capability ID；
- Node ID；
- Version；
- Byte Size；
- Deadline/Duration；
- URI/URL；
- Socket endpoint；
- File path；
- Digest；
- Permission scope；
- Lifecycle state。

使用 semantic newtype、record、enum、validated value object。

### 13.2 推荐基础类型

- 时间间隔：`std::time::Duration`；
- 文件路径：`Path` / `PathBuf`；
- URL：`url::Url`；
- 网络端点：`SocketAddr` 或项目的 typed endpoint；
- SemVer：`semver::Version` / `VersionReq`；
- 持久 ID：`uuid::Uuid` 再包一层领域 newtype；
- UTC 时间：`time::OffsetDateTime`，但 Domain API 应区分 Timestamp/Expiry 等语义；
- Byte Size：项目 `ByteSize(u64)` newtype，构造时校验；
- Hash：固定长度摘要类型，不用任意 `Vec<u8>`。

### 13.3 边界解析一次

HTTP/CLI/SQLite/WIT adapter 可以接触字符串/整数 wire representation，但必须立即 parse/validate 成领域类型。Domain 不重复校验同一不变量。

### 13.4 不合法状态不可表示

能通过类型消除的错误，不留给运行时 if 判断。例如：

- 已验证 Component 与未验证字节流使用不同类型；
- HashedSecret 与 PlainSecret 不同类型；
- ActiveComponentHandle 不能从任意 ID 直接构造；
- NonZero limit 使用 `NonZeroUsize` 等。

### 13.5 WIT 同样强类型

WIT 里应使用 record/enum/variant/flags/resource 表达语义。由于某些 WIT alias 不提供 Rust 风格 nominal type distinction，对于具有独立身份语义的 ID，应使用明确 record wrapper，而不是多个同为 `string` 的 type alias 让调用者误传。

---

## 14. Error / Panic / Overflow 规范

### 14.1 错误类型

生产 Domain/Application crate 使用 `thiserror` 定义封闭、可匹配的 typed error。

禁止在公开 Domain/Application 边界返回：

```text
anyhow::Error
eyre::Report
Box<dyn Error>
String error
```

适配层必须把第三方错误转换为项目错误语义，并保存可诊断 source/context，但不能让第三方错误类型污染核心契约。

### 14.2 Panic 禁止

第一方 production path 禁止：

- `unwrap()`；
- `expect()`；
- `panic!()`；
- `todo!()`；
- `unimplemented!()`；
- array/index 假定式访问等可避免 panic 的写法。

测试代码可以使用断言表达测试失败，但不能用 panic 逃避测试逻辑。

### 14.3 Release Panic Policy

Production release profile 默认 `panic = "abort"`。第一方代码本身必须设计为 panic-free；如果依赖或不可恢复不变量仍触发 panic，采用 fail-stop，让服务管理器/编排器重启 Core，而不是在未知损坏状态继续运行。

### 14.4 算术

Release 打开 overflow checks。任何外部影响的大小、计数、offset、deadline、容量计算使用 checked/saturating/try-conversion，具体选择必须符合语义；不得依赖整数回绕。

---

## 15. 并发与线程安全规范

### 15.1 Tokio 是 native async runtime

Core 的异步 I/O 和结构化任务运行在 Tokio 上。

### 15.2 有界并发

所有 channel、queue、semaphore 必须有容量或资源上限。禁止 unbounded queue 作为生产默认。

使用：

- `tokio::sync::mpsc` 有界队列；
- `oneshot` 表达单答复；
- `watch` 表达最新快照；
- `broadcast` 只用于允许 lag/drop 的广播语义；
- `Semaphore` 表达并发许可。

### 15.3 Structured Cancellation

使用 `tokio_util::sync::CancellationToken` 构建父子取消树。关键后台任务必须被 supervisor/`JoinSet` 持有，禁止 detached critical task。

### 15.4 无锁不是目标

优先清晰正确的 ownership/actor/snapshot 模型。禁止为了性能未经测量地引入复杂 lock-free 结构。

### 15.5 Read-mostly 快照

路由表、Capability Graph、Active Component Map 等读多写少、需要原子切换的结构优先使用不可变快照 + `arc-swap`，而不是到处持有 `RwLock<HashMap<...>>`。

### 15.6 对数据竞争承诺的准确表达

Safe Rust 在 sound dependencies 前提下机械阻止 unsynchronized memory data race，但并不能阻止：

- logical race；
- lost update；
- deadlock；
- starvation；
- ordering bug；
- crash consistency bug。

因此并发正确性还必须由状态机、事务、Loom/model test、stress test 和 fault injection 证明。

# 第五篇：安全、持久化与生命周期

## 16. Root Admin 安全基线

### 16.1 暴露面与传输安全是两个独立维度

0.1.0 默认 Root Admin listener 只绑定 loopback。绑定非 loopback 地址必须显式配置允许的访问策略，并通过生产 TLS 配置。

**Production Root Admin Browser Plane MUST 使用 HTTPS，即使监听地址是 loopback。** “仅本机可访问”不能替代传输层安全，也不能与后续 `Secure` / `__Host-` Session Cookie 契约矛盾。

如果生产所需 TLS identity 尚未准备好：

- 本地 bootstrap/recovery CLI 仍必须可用；
- 已认证 Root Admin Web **MUST NOT** 自动退化到明文 HTTP；
- 不得为了首次启动方便默认监听 `0.0.0.0` 或接受明文管理员登录。

开发环境可以有明确标记的 insecure loopback 模式，但它必须与 production feature/qualification 分离，不能复用生产 Session Cookie 契约，也不能通过 Release Gate。

### 16.2 TLS

TLS 使用 Rustls 生态，不依赖目标系统的 OpenSSL 版本。TLS 协议版本和 cipher suite 使用 rustls 的安全默认集合，除非 Security ADR 明确调整。

TLS private key 属于 Secret。其来源、文件权限、轮换和错误日志必须符合 Secret 规则；private key 内容不得写入 SQLite 普通 metadata、日志或审计事件。

### 16.3 Bootstrap Admin 与 Recovery Plane

系统不提供默认用户名/密码组合。

首次管理员创建必须通过**本机显式 bootstrap 操作**完成。密码不得通过命令行参数或环境变量传入，避免进入 shell history/process environment；使用 TTY 安全输入或标准输入。

Bootstrap/Recovery CLI 是 Root Admin Web 的恢复前提，不依赖 Component，也不依赖 Web 登录是否可用。其能力必须严格限制为恢复 Operune Runtime 自身所需要的操作，并全部审计。

### 16.4 Password Hashing

使用 Argon2id。绝对最低参数不得低于本规范基线日 OWASP 推荐的 19 MiB memory、2 iterations、parallelism 1。生产默认参数应通过目标平台基准确定并可以更高；降低最低基线必须经过 Security ADR 与重新风险评估。

密码永远不使用 SHA-256 等快速摘要直接存储。

### 16.5 Session

Root Admin 使用服务端 session：

- session bearer token 由 OS CSPRNG 产生至少 32 random bytes；
- 浏览器传输使用 URL-safe 编码；
- authoritative store 只保存 token 的单向 digest，不保存 bearer token 明文；
- 登录、权限提升、敏感身份变化时旋转 session；
- 同时存在 idle expiry 和 absolute expiry；
- production Cookie 使用 `__Host-operune-session`，并设置 `Secure`、`HttpOnly`、`SameSite=Strict`、`Path=/`，不得设置 `Domain`；
- 所有 state-changing request 使用独立 CSRF token，并执行 Origin/Referer 校验；SameSite 只能作为 defense-in-depth；
- Logout、管理员禁用、密码重置和高风险权限撤销必须能够使相关 server-side session 失效。

Session token 与 CSRF token 必须具有不同用途和生命周期，不得复用同一随机值。

### 16.6 Secret 的内存与持久化边界

秘密值在 Rust 内存中使用 `secrecy` 等防泄漏类型包装，并在可实际清理的缓冲上使用 `zeroize`。Secret 不得实现/派生会泄漏内容的 `Debug`、`Display` 或通用 Serialize。

日志、error context、panic report、metrics label、audit event 中禁止记录密码、session bearer token、CSRF secret、private key 和 Component secret 值。

`secrecy` / `zeroize` 只解决**进程内暴露面**，不构成 at-rest secret storage。0.3.0 引入 Component Secret 服务时，必须使用独立 `SecretStore` port；普通 SQLite metadata 表不得保存明文 secret。加密存储时，密钥加密密钥（KEK）不得与密文以等价保护级别存放在同一 SQLite 数据库中。具体跨平台 key provider 在 0.3.0 前通过 ADR 冻结，并继续遵守第一方 Safe Rust Gate。

---

## 17. Capability 安全模型

### 17.1 两阶段含义

WIT import 表示“程序需要这种能力”；Runtime Grant 表示“这个 `InstallationId` 被授权在什么范围使用这种能力”。两者不可合并。Grant 不直接绑定可被作者复用的 `ComponentId`，否则同一逻辑 Component 的另一安装实例会意外继承权限。

示例：

```text
Component import: wasi:http/outgoing-handler
Runtime grant: only https://prometheus.internal:9090
```

### 17.2 Deny-by-default

所有未知 import、未解析 dependency、未授权 capability 都使 Component 保持未激活/隔离状态。不得通过“先运行，失败时 trap”来代替权限解析。

### 17.3 Scope

Capability policy 必须能表达资源级 scope，而不仅是 boolean。例如：

- network host/port/scheme；
- filesystem preopened path + read/write mode；
- secret names；
- event topics；
- scheduler limits；
- Component-to-Component provider identity/version。

### 17.4 Least Authority

安装 UI/API 展示的授权必须来自实际 imports 和 Runtime Policy；不得申请“可能以后会用”的权限。

### 17.5 四层授权链

一次能力调用能够成立必须同时满足：

1. **Contract Need**：Component 的 WIT import 明确需要该能力；
2. **Resolution**：Runtime 能解析到正确的 Host/Provider，并满足版本兼容规则；
3. **Grant**：该安装实例拥有明确、可审计、带 scope 的授权；
4. **Invocation-time Enforcement**：实际请求仍在 grant scope、资源预算和当前 policy snapshot 内。

安装时通过权限解析不意味着后续调用永远放行。授权撤销、scope 变化、provider 切换和资源预算变化必须以确定的 snapshot/version 语义生效；不得依赖 Component 自觉遵守。

Grant 的 durable owner 是 `InstallationId`。升级到新 `ComponentVersion` 时，旧 grant 只有在新版本实际 imports **没有扩大能力种类或 scope 需求**、且 policy 重新验证通过时才可继续适用；新增/扩大权限必须在 activation 前重新显式批准，不能因逻辑 `ComponentId` 相同而静默继承。

0.1.0 的 Resolution 只覆盖 Host/WASI 与 Operune 平台能力；Component-to-Component provider graph 从 0.2.0 开始进入正式模型。

---

## 18. SQLite 持久化基线

### 18.0 Bootstrap Config 与 Runtime Config 必须分离

Operune 启动前必须先获得少量**宿主启动事实**，而 SQLite 中的 Runtime Config 只有数据库打开后才能读取。两者不得混成有隐式优先级的多来源配置系统。

- **BootstrapConfig**：单个 TOML 文件，负责 `data_root`、Root Admin listener、TLS identity 引用、启动期日志等“打开 Runtime 本身之前必须知道”的宿主事实；
- **RuntimeConfig**：Core 启动并打开 authoritative store 后管理的可变运行策略/配置，事务化、版本化并审计；
- BootstrapConfig 的路径解析必须确定。0.1.0 正式交付冻结一个平台默认路径，并允许 CLI 的 `--config <path>` **仅选择整份 BootstrapConfig**；它不是单项 override；
- production 不支持环境变量覆盖 BootstrapConfig 字段，也不做当前目录搜索、多个 TOML merge 或“CLI > env > file > DB”式隐式优先级；
- TLS private key、管理员密码和 Component secret 的**值**不得直接写进普通 BootstrapConfig；配置中只允许受控引用；
- BootstrapConfig 修改通过重启整体生效；RuntimeConfig 修改通过其事务/版本契约生效，Web 管理面不得反向改写宿主 TOML；
- 配置缺失、解析失败或安全不变量不满足时必须 fail closed，并保留本机 recovery/bootstrap CLI 所需的最小恢复路径。

`toml` crate 的存在只服务这个明确边界，不意味着 Operune 建立通用配置框架。

### 18.1 0.1–0.5 单节点权威状态

0.1.0 的 standalone Core authoritative metadata 使用 SQLite，通过 `rusqlite` bundled SQLite 构建，避免依赖目标 OS 的 SQLite 版本。

在 0.1–0.5 的单节点模型中，SQLite 是该节点 Core Runtime 元数据的权威事实源；但 **SQLite 不是 Domain 契约**。Domain/Application 只能依赖 typed storage ports，不得暴露 SQL、`rusqlite::Connection`、SQLite error code 或 schema 细节。

### 18.2 Tokio 集成

实现一个小而明确的第一方 **Storage Executor**：

- 单独持有一个或按明确策略持有有限数量 SQLite connection；
- SQLite blocking 调用不得运行在 Tokio core worker 上；
- request channel 必须有界；
- 每个 storage command 使用 typed request/response；
- 事务边界在 storage adapter 中明确；
- caller cancellation 不得造成半事务状态；
- shutdown 必须等待或确定取消已接纳的关键写事务，不能 detached。

这个 executor 是基础设施适配器，不是通用 Actor Framework，也不能反向成为所有 Core 状态的中央消息总线。

### 18.3 0.1.0 数据所有权

至少持久化：

- Core schema version；
- Component `ComponentId` / `ComponentVersion` / `ContentDigest` 关系；
- `InstallationId` 及其与逻辑版本/当前 active digest 的关系；
- quarantine/candidate/install/enable/active state；
- 绑定 `InstallationId` 的 Component grants；
- Core config；
- users/password hashes；
- sessions；
- audit metadata；
- upgrade/rollback transaction metadata；
- crash recovery 所需的 lifecycle journal / transaction marker。

0.1.0 不把 Component 的复杂业务状态或 secret value 混入普通 metadata 表；它们分别在后续 Stateful Runtime/SecretStore 契约中定义。

### 18.4 Migration

数据库 schema migration：

- 必须版本化；
- migration 必须事务化；
- migration 失败时 Core 不得以半升级 schema 继续；
- release 必须有 old-version → new-version migration test；
- 每个 release contract 必须说明最低可直接升级来源版本；
- 0.x 是否支持 downgrade 由逐版本 migration contract 明确；
- 1.0 前冻结长期 compatibility policy。

### 18.5 Crash Consistency

文件系统 artifact 与数据库 activation state 不能靠操作顺序“希望一致”。安装/升级使用 staging + durable transaction/state-machine，使 Core 在任一 crash point 重启后能够确定：

- candidate 未提交 → 清理或保持 quarantine；
- active version 已提交 → 恢复 active；
- switch 过程中断 → 根据 durable transaction record 恢复旧版本或完成新版本；
- 永远不存在两个版本都被误认为同一逻辑 Component 唯一 active 的歧义。

数据库提交、文件原子 rename、目录 fsync 等真实 OS 语义必须在 qualification 中按平台验证；不得把“事务化 SQLite”误认为自动覆盖文件系统崩溃一致性。

### 18.6 SQLite 到 Distributed/HA 的演进边界

0.6.0 引入多节点时必须先把持久状态分类为：

- **node-local durable state**：单节点运行缓存、local lifecycle journal、节点特有恢复状态；
- **cluster-authoritative control state**：跨节点唯一身份、policy、placement、rollout、全局 ownership 等需要一致性的事实。

0.7.0 HA **MUST** 为 cluster-authoritative state 通过 ADR 选择明确的一致性/复制模型。禁止把多个 Core 实例直接指向共享文件系统上的 SQLite，禁止通过多主写 SQLite 或“最终大家会一致”的约定伪装分布式一致性。

SQLite 可以继续作为节点本地 store、缓存或恢复 journal；是否仍承载某类 cluster state 只能由一致性设计证明，不能因为 0.1 使用 SQLite 就被路线图锁死。

### 18.7 Artifact Store、磁盘预算与审计耐久性

0.1.0 必须把 artifact 文件系统语义与数据库状态一起定义，而不是只定义 SQLite：

- Core 在 `data_root` 下拥有明确的 staging/quarantine/content-addressed artifact 空间；final artifact 以 `ContentDigest` 寻址并视为不可变；
- 如果提交协议依赖原子 rename，staging 与 final store 必须位于满足该原子语义的同一 filesystem/volume；其他平台实现必须给出等价、经过 qualification 的 durable commit protocol；
- 关键 rename/DB commit/fsync 的顺序和 crash points 必须进入 fault-injection test，不得只在正常退出时成立；
- staging、quarantine、artifact cache、runtime log 和临时文件都必须有硬上限、GC/retention 或 admission control，禁止通过重复上传/失败安装无限吃满磁盘；
- 0.1.0 即必须有 runtime log rotation/retention 与 audit retention 基线；0.5.0 可以增加更完整的治理、查询和组织策略，但不能把“避免磁盘无限增长”推迟到 0.5；
- 未到期/未满足 retention policy 的安全审计记录不得因磁盘压力被静默删除。若一个安全/权限/Component 生命周期变更要求写入 durable audit 而 audit 无法可靠落盘，该变更必须在提交前 fail closed；紧急 recovery 的例外流程必须是显式模式并留下独立可追溯证据。

回滚所需的上一已知良好 artifact 必须按 rollback retention policy 保留；GC 不得删除仍被 active、candidate、rollback transaction 或未结束 audit/reference 使用的 digest。

---

## 19. Component 安装与激活状态机

### 19.1 输入不可信

任何 `.wasm` 安装输入都视为不可信字节，即便来自官方仓库、签名仓库或本地管理员。签名/来源验证可以提高来源可信度，但不能跳过字节大小、Component validation、Capability、安全或资源 Gate。

### 19.2 两阶段安装：先确定“字节事实”，再确定“应用身份”

安装必须按以下顺序：

```text
receive bytes
  -> hard size limit
  -> compute ContentDigest
  -> WebAssembly Component validation
  -> inspect binary component type: imports/exports and required Operune contracts
  -> derive preliminary dependency + permission need plan
  -> persist digest-keyed quarantine/candidate record
  -> instantiate a descriptor-only Store with zero operational grants
  -> call operune:component descriptor export
  -> validate ComponentId + ComponentVersion + metadata
  -> persist logical identity/version relationship and InstallationId
  -> resolve/link imports for this InstallationId with deny-by-default grants
  -> instantiate runtime candidate under the intended grant/resource snapshot
  -> readiness/health validation in the intended runtime environment
  -> atomic activation
```

任何一步失败都不得污染当前 Active Version。

Component binary type 的结构化 imports/exports 和接口版本可以在执行 guest 代码前检查；Operune 不依赖源码 root world/package 名可恢复。`ComponentId` / `ComponentVersion` 等作者声明的应用身份只能在 descriptor 成功返回并验证后成为注册表事实。Agent 不得把这两个阶段合并成“parse manifest”。

### 19.3 Descriptor Store 与 Runtime Candidate 必须分阶段

读取 descriptor 的目的只是获得作者声明的逻辑身份和平台 metadata，不能为了读身份先给 guest 正常运行权限。Descriptor 阶段因此必须满足：

- descriptor-only Store 不提供 network/filesystem/secret/scheduler/event 等 operational grants；
- descriptor export 必须是 side-effect-free、bounded、可重复的元数据读取契约，不得依赖当前时间、随机数、外部网络或宿主可变文件；
- 同一 `ContentDigest` 在同一 `operune:component` contract version 下必须得到相同的 canonical descriptor；不一致视为 contract violation；
- descriptor Store 的 memory/table/instance/host-buffer/deadline 预算应比正常运行相同或更严格；
- descriptor 超时、trap、超预算或返回非法 metadata 均使 candidate 保持 quarantine/failed。

只有获得并验证 `ComponentId` / `ComponentVersion`、创建/解析 `InstallationId` 后，Core 才能把实际 imports 与该安装实例的 grants/policy 做完整 resolution，建立 **Runtime Candidate**。`health/readiness` 必须在这个真实 grant/resource 环境中执行；它不能与 descriptor 混在零权限阶段，否则需要依赖能力的健康检查会形成身份/授权循环。

### 19.4 四种身份必须永久分离

- **ComponentId**：逻辑产品/应用身份；
- **ComponentVersion**：作者发布版本；
- **ContentDigest**：实际收到的不可变字节事实；
- **InstallationId**：Core 管理的安装实例身份，承载 grant、enable/active 状态与本机生命周期。

同一个 `ComponentId + ComponentVersion` 默认只能绑定一个已接受 digest；如果收到相同逻辑版本但不同 digest，必须作为供应链/发布冲突显式阻断，不能静默覆盖。

### 19.5 Unknown / Missing Imports

Active Component 必须有完整可解析、可满足且已授权的 import graph。禁止通过 Wasmtime 的“缺失时运行再 trap”式行为把 dependency 缺失的 Component 当作健康 active 服务。

0.1.0 的跨 Component import 若没有 0.2 Provider Graph 支持，应明确判定为当前 Runtime capability 不支持并拒绝激活，而不是临时随机绑定。

---

## 20. 热升级与回滚

### 20.1 0.1.0 Stateless Upgrade Contract

0.1.0 对没有复杂持久业务状态的 Component 支持：

```text
v1 active
  |
  +--> load/validate v2
       -> resolve dependencies/grants
       -> instantiate v2
       -> readiness/health
       -> atomic active snapshot swap
       -> new requests -> v2
       -> drain v1
       -> drop v1 Store
```

### 20.2 不允许 destructive-in-place

禁止先停止/删除 v1 再尝试启动 v2。Candidate 必须在不破坏现有可用版本的前提下验证。

### 20.3 原子路由

Active routing/capability graph 使用不可变快照。切换时通过一个原子指针/快照交换完成，不允许多张表分步修改造成前端 v2、后端 v1 或 provider/consumer 不一致。

### 20.4 Drain

旧实例进入 Draining 后：

- 不接新工作；
- 已接受工作允许在有界 deadline 内完成；
- deadline 到期后取消/trap；
- 所有 background task 必须受 CancellationToken 管理；
- 结束后释放 Store 和 Host resources。

### 20.5 Stateful Upgrade

0.3.0 开始加入 checkpoint/state migration。权威状态必须在 Core-managed state store，不得只在 linear memory。Migration 必须是版本化、原子、可失败并具备 rollback policy 的显式操作。

---

## 21. Root Admin Web 与 Component Web

### 21.1 Root Admin Web

Core 内置 Web 必须保持极小，0.1.0 只覆盖：

- Login/Logout；
- Runtime status；
- Component install/list/detail/enable/disable/upgrade/rollback；
- grants；
- users/RBAC 最小管理；
- Core config；
- audit；
- safe mode / recovery。

Root Admin 是 **Runtime Recovery/Administration Plane**，不是日常运维业务 Console。卸载所有 Component 后它仍必须可用；任何业务 Dashboard、监控、日志、数据库、Kubernetes 页面都禁止进入 Core。

### 21.2 技术形式

Root Admin 使用 Axum + Askama server-side rendering + 最小原生 HTML/CSS/JS。Core 构建链禁止把 Node/npm 作为强制生产构建依赖。

Production Root Admin Web 遵守第 16 章 HTTPS/Session 契约；Root Admin handler 不得提供绕过统一 Auth/RBAC/CSRF 的“内部快捷路径”。

### 21.3 0.1.0 最小 Component Web Bridge

0.1.0 必须形成一个**窄而完整**的 Component Web 闭环，用于证明业务 Web 能力确实可以留在 `.wasm` Component 中，而不是被迫进入 Core。该闭环包括：

- `operune:web@0.1.0` 的最小 web descriptor；
- 一个由 Core 分配、不可冲突的 Component mount namespace；
- Component 内嵌静态 assets 的列举/读取，assets 以 `ContentDigest + asset path` 为缓存事实；
- 有界 request/response 的 backend action 调用；
- UI assets 与 backend exports 随同一 ComponentVersion 原子切换；
- **最小但强制的浏览器隔离底线**。

任何 Component-controlled HTML/JavaScript 都必须被视为与 `.wasm` 本体同等级的不可信代码。0.1.0 production **MUST NOT** 把它直接放进 Root Admin DOM 或赋予 Root Admin 同源权限。最小隔离契约固定为：

- Component UI 运行在 Core 创建的 sandboxed frame/等价独立 browser security context 中；不得获得 parent DOM、Root Admin cookie/storage 或同源 API 权限；
- Core 生成并强制 restrictive CSP；Component 不能自行放宽 sandbox、CSP、frame、navigation、popup、download、form、network connect 等安全策略；
- UI 到 backend action 只能经过 Core-mediated bridge。Core 将 frame/channel 与 `InstallationId + ComponentVersion` 绑定，并在服务端重新执行 authentication、RBAC、grant、action permission、body/deadline/rate/concurrency 检查；浏览器内 Component 代码不接触 Root Admin session bearer 或 CSRF secret；
- Component backend/asset 响应不得设置或覆盖 `Set-Cookie`、CORS、CSP、认证、代理转发等 Core-owned security headers；
- 0.1 bridge 只有 bounded request/response，不提供 WebSocket、任意长连接或 stream/realtime。

0.4.0 再把这个最低隔离边界扩展成完整 navigation、route/action、browser policy、兼容与 realtime 模型；**0.4 不是首次补安全隔离**。如果实现无法满足上述最低隔离，Component-controlled active Web content 就不得进入 0.1 production feature set。

Component 禁止自行 bind 监听端口来绕过 Core Web security boundary。

### 21.4 0.4.0 完整 Web Application Runtime 的边界

0.4.0 在不推翻 0.1 bridge 的前提下增加：

- navigation/pages；
- typed route/action registration 与冲突诊断；
- native stream/realtime extension（仅在第 8.3 production Gate 通过后进入对应 release 的 production scope）；
- page/action permission declaration；
- 在 0.1 最低 sandbox/CSP 边界之上的完整 browser isolation policy、导航/嵌入策略与兼容模型；
- per-Component HTTP quotas/backpressure；
- 完整 app lifecycle 与 Web compatibility contract。

因此 0.1 和 0.4 的关系是**最小闭环 → 完整应用运行时**，不是重复实现两套 Component Web 系统。

### 21.5 Web 原子版本

同一 Component 的 Web assets、descriptor 和 backend exports 属于同一 ComponentVersion。升级通过 active snapshot 一次性切换；旧请求可以在 drain deadline 内完成，但任何新页面加载、asset lookup 和 backend action 必须解析到同一 active version，禁止产生“前端 v2 + 后端 v1”拼接。

---

# 第六篇：冻结技术选型

## 22. Rust 与核心 crate 基线

### 22.0 版本规则：规范冻结选择，Cargo.lock 冻结解析结果

本章是 **2026-08-07 已审查的 direct-dependency 基线快照**，不是“永远追最新”清单。

- `rust-toolchain.toml` 精确固定 Rust toolchain；
- workspace dependency table 固定允许的 direct dependency 与版本约束；
- committed `Cargo.lock` 是每次 production build 的**精确解析版本事实源**；
- Release 必须使用 `--locked`；
- Agent 不得因为 crates.io 出现更新版本就自行升级；
- 同时不得把 `36.0.0` 之类首个 LTS patch 永久化成阻止安全修复的规则。当前 Wasmtime 生产兼容线固定为 36 LTS，精确 36.x patch 由经过 Gate 的 lockfile 决定；48 只能在正式发布并通过 promotion Gate 后切换。

### 22.1 Toolchain

| 项目 | 基线 | 用途/规则 |
|---|---:|---|
| Rust | **1.97.1** | `rust-toolchain.toml` 精确固定；Rust 2024 Edition。 |
| Cargo.lock | committed | 所有 production build/test 使用 `--locked`。 |

### 22.2 Wasm Runtime

| Crate | 兼容基线 | 决策 |
|---|---:|---|
| `wasmtime` | **36.x LTS** | 当前已发布 production line；精确 patch 由 accepted `Cargo.lock` 固定。 |
| `wasmtime-wasi` | **36.x LTS** | 与 Wasmtime 同 release line；production 仅 p2。 |
| `wasmtime-wasi-http` | **36.x LTS** | 与 Wasmtime 同 release line；production 仅 p2。 |

三个 Wasmtime family crate 必须保持上游兼容的同 release line，禁止人为混搭 major/minor。

**48 LTS promotion rule**：48.0.0 在 2026-08-20 正式发布之前不得写入 production lockfile。正式发布后，只有 36→48 的完整依赖升级 PR 同时通过 API/WIT compatibility、Component conformance、WASI p2、resource/cancellation、crash recovery、platform qualification、security 和 performance regression Gate，才可更新本章 production line。

Host WIT binding 使用 `wasmtime::component::bindgen!` / Wasmtime Component API。Host 架构不以 `cargo-component` 为 Host runtime 依赖中心；Guest/fixture 的构建工具可以独立选择，但不能成为 Core ABI。

Wasmtime feature 原则：只启用当前架构真实需要的 Component Model、async/runtime、Cranelift 等生产能力；experimental proposals、p3、pooling、GC、Winch 等不得仅因为“上游提供”就进入 production feature set。最终 production feature list 必须由 0.1.0 implementation PR 固化并由 CI 单独编译测试。

### 22.3 Async / Web / TLS

| Crate | 2026-08-07 审查快照 | 用途/规则 |
|---|---:|---|
| `tokio` | **1.53.1** | Core native async runtime。 |
| `tokio-util` | **0.7.19** | `CancellationToken`。 |
| `axum` | **0.8.9** | Root Admin HTTP / Core Web routing。 |
| `tower` | **0.5.3** | middleware/service composition。 |
| `tower-http` | **0.7.0** | HTTP middleware；只启用所需 feature。 |
| `rustls` | **0.23.42** | TLS；不绑定系统 OpenSSL。 |
| `tokio-rustls` | **0.26.4** | Tokio TLS integration。 |
| `askama` | **0.16.0** | Root Admin SSR templates。 |

### 22.4 Persistence / Serialization / Config

| Crate | 2026-08-07 审查快照 | 用途/规则 |
|---|---:|---|
| `rusqlite` | **0.40.1** | Core SQLite adapter，启用 bundled SQLite。 |
| `serde` | **1.0.229** | Rust 内部持久/配置边界序列化。 |
| `serde_json` | **1.0.151** | JSON boundary；不得作为 Domain 万能动态值。 |
| `toml` | **1.1.4** | Core 人类编辑配置；不是 Component manifest。 |

SQLite 与 Tokio 之间由项目专用、有界、typed Storage Executor 处理；不得为了 async 外观引入会倒逼旧 SQLite/rusqlite 或模糊事务语义的 wrapper。

### 22.5 Domain Types / Errors / Snapshots

| Crate | 2026-08-07 审查快照 | 用途/规则 |
|---|---:|---|
| `thiserror` | **2.0.19** | typed errors。 |
| `uuid` | **1.24.0** | durable IDs 的底层表示；必须封装领域 newtype。 |
| `semver` | **1.0.28** | Component/WIT compatibility version。 |
| `url` | **2.5.8** | validated URL。 |
| `time` | **0.3.54** | timestamp/date-time；Domain 再包语义类型。 |
| `arc-swap` | **1.9.2** | read-mostly immutable active snapshots。 |

### 22.6 Security

| Crate | 2026-08-07 审查快照 | 用途/规则 |
|---|---:|---|
| `argon2` | **0.5.3** | Argon2id password hashing。 |
| `secrecy` | **0.10.3** | secret value wrapper。 |
| `zeroize` | **1.9.0** | 可清理 secret memory。 |
| `getrandom` | **0.4.3** | OS CSPRNG。 |
| `sha2` | **0.11.0** | SHA-256 content/token digest；不是 password hash。 |
| `subtle` | **2.6.1** | 需要时做 constant-time byte comparison。 |
| `base64` | **0.23.0** | token 的 URL-safe encoding；`default-features = false`，只启用所需 `std`，不为该低吞吐安全路径启用默认 `simd-unsafe`。 |
| `cookie` | **0.18.1** | RFC cookie construction/parsing；不自写 cookie parser。 |

### 22.7 CLI / Observability

| Crate | 2026-08-07 审查快照 | 用途/规则 |
|---|---:|---|
| `clap` | **4.6.4** | Core CLI；命令必须 typed、可测试。 |
| `tracing` | **0.1.44** | structured events/spans。 |
| `tracing-subscriber` | **0.3.23** | logging/filter/format subscriber。 |

### 22.8 Test / Dev

| Crate/Tool | 2026-08-07 审查快照 | 用途 |
|---|---:|---|
| `proptest` | **1.11.0** | property testing。 |
| `loom` | **0.7.2** | 并发模型测试。 |
| `tempfile` | **3.27.0** | isolated filesystem tests。 |
| cargo-nextest | CI pinned | 测试执行。 |
| cargo-deny | CI pinned | advisories/licenses/bans/sources。 |
| cargo-audit | CI pinned | RustSec defense-in-depth。 |
| cargo-llvm-cov | CI pinned | coverage。 |
| cargo-fuzz | CI pinned | libFuzzer fuzz targets。 |
| cargo-mutants | optional CI pinned | 关键纯逻辑 mutation testing。 |

CI 工具的“pinned”必须落到可复现的安装版本或受控 tool image，不能每次 CI 运行时无条件安装 latest。

### 22.9 明确不采用的默认方案

- 不用 Actix 作为 Web 基线；Axum/Tower 与 Tokio 类型模型更直接；
- 不用 OpenSSL 作为 Core TLS 基线；
- 不用 SQLx 作为 0.1 Core metadata DB；当前需要的是嵌入式本地 SQLite + 明确事务，不需要通用远端 DB 抽象；
- 不用 `async-trait` 作为默认新接口手段；现代 Rust 原生 async trait/return-position impl Trait 能满足时优先原生能力；
- 不用 anyhow/eyre 作为 Domain/Application 错误契约；
- 不用 DashMap 作为“并发方便”默认数据结构；
- 不用自研 executor、HTTP server、TLS、crypto、Wasm runtime、DB engine；
- 不用 Wasmtime pooling allocator 作为 0.1 默认；
- 不用 experimental Wasmtime WASI p3 Host 进入 production path。

---

## 23. 依赖与供应链治理

### 23.1 新增依赖 Gate

任何新的 direct dependency 必须回答：

1. 它解决哪个当前明确需求？
2. 标准库/现有依赖为什么不足？
3. 是否有 active maintenance？
4. license 是否允许？
5. 是否引入 native system dependency？
6. 对 Windows/Linux/macOS 和 static candidate 有何影响？
7. 是否包含大量 unsafe / FFI；是否存在 soundness/advisory 风险？
8. 是否在 hot path；性能影响是否需要 benchmark？
9. 是否把第三方类型泄漏到 Domain/public contract？

答不清楚不得添加。

### 23.2 版本策略

- direct dependency 版本集中在 workspace dependencies；
- 禁止 wildcard versions；
- production 禁止未固定 commit 的 git dependency；
- `Cargo.lock` 必须提交；
- release `cargo build --locked`；
- 依赖更新单独 PR，不能和大功能混合；
- Wasmtime major 只在 LTS-to-LTS 正常升级，除非 security/correctness ADR；
- 同一 Wasmtime LTS line 的 patch 更新仍要独立 PR + Gate，但不得以“规范写死首个 patch”为理由阻止安全/正确性修复；
- toolchain 更新必须完整跑生产 Gate；
- 任何 dependency update PR 必须记录旧/新 lockfile 关键差异、advisory 变化和五要素交叉审计结论。

### 23.3 Unsafe Inventory

允许使用工具生成第三方 unsafe inventory 作为审计信息，但不能设置“整个依赖树 unsafe=0”的虚假门禁，因为 Wasmtime/JIT/OS integration 本质上会依赖 unsafe 实现。真正硬门禁是：**第一方源码 unsafe=0**。

### 23.4 License

项目自身开源许可证属于 Owner/治理决策，AI Agent **MUST NOT** 自行选择。正式公开发布前必须完成许可证决策和 cargo-deny license allowlist。此前任何引入明显强 copyleft/未知许可证的 dependency 必须阻断并请求治理决定。

# 第七篇：Workspace、模块责任与开发方式

## 24. Workspace 结构与依赖方向

### 24.1 推荐并冻结的初始结构

```text
/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── wit/
│   └── operune/...
├── crates/
│   ├── domain/
│   ├── application/
│   ├── runtime-wasm/
│   ├── runtime-wasi-p2/
│   ├── web-admin/
│   ├── web-component/
│   ├── storage-sqlite/
│   ├── security/
│   ├── platform/
│   ├── platform-linux/
│   ├── platform-windows/
│   ├── platform-macos/
│   ├── observability/
│   └── server/
└── tests/
    ├── conformance/
    ├── fixtures/components/
    ├── integration/
    └── qualification/
```

只有在出现真实独立责任时才拆更多 crate；不得因为“微服务式漂亮”无限碎片化。

### 24.2 责任

**domain**  
纯领域类型、状态机、不变量、兼容规则。禁止 Wasmtime/Tokio/Axum/rusqlite。

**application**  
用例编排和 ports。依赖 domain；不得知道 SQLite/Axum/WASI p2 具体类型。

**runtime-wasm**  
Wasmtime Engine/Component/Store、资源治理、trap/error mapping、instance model。对上暴露项目自己的 typed ports。

**runtime-wasi-p2**  
所有 WASI 0.2 linker/context/binding 适配。这里是未来标准版本替换点。

**web-admin**  
Root Admin Axum/Askama HTTP adapter。

**web-component**  
Component 提供的 Web assets/actions/routes 到 Core Web 的桥接。

**storage-sqlite**  
SQLite schema、migration、repository adapter、Storage Executor。

**security**  
password/session/CSRF/grant policy/secret handling 的实现，不包含具体运维产品权限。

**platform**  
跨平台 port/value definitions，不含 OS 具体实现。

**platform-linux/windows/macos**  
唯一允许承载 OS 特定 `cfg` 和 safe wrapper integration 的地方。

**observability**  
Core 自身 tracing/metrics/audit plumbing。

**server**  
唯一 binary composition root，只负责配置、构造和 wiring；禁止业务规则藏在 `main.rs`。

### 24.3 依赖方向

```text
adapters  ---> application ---> domain
   |
   +------> domain

server ---> all concrete adapters for wiring only
```

Domain 永不反向依赖 adapter。任何 PR 导致 Domain import Axum/Wasmtime/rusqlite/Tokio-specific synchronization type，默认视为架构回归。Domain/Application 出现面向 `x86_64` / `aarch64` 或具体设备厂商的条件分支同样视为架构回归；架构与设备差异必须停留在 adapter/capability availability 层。

---

## 25. AI Agent 自主裁决算法

当规范未指定某个实现细节时，AI Agent 必须按以下顺序判断，不能凭个人偏好选技术。**任何判断开始前先执行 D0，任何实现完成后再执行一次第 2 章全量五要素交叉审计。**

### D0. 加载全部冻结基线

在做局部技术判断之前，必须先读取本规范、当前里程碑、已接受 ADR、公开 WIT、持久化 schema/迁移契约和相关测试基线。不得只根据当前 Issue 或当前文件局部推理。若发现当前任务描述与冻结基线冲突，先进入冲突处理，不得静默按任务描述覆盖既有结论。

### D1. 先分类问题

把问题归入：

1. WebAssembly/WASI 标准机制；
2. 项目平台/运维领域语义；
3. Core Domain；
4. Infrastructure Adapter；
5. OS Platform Adapter；
6. Test/Tooling；
7. Governance/法律/产品 Owner 决策。

分类错误时禁止继续实现。

### D2. 标准优先检查

如果问题属于 WebAssembly 系统边界，先检查当前正式标准和项目已选 Wasmtime LTS 是否已经提供。标准可用且生产成熟 → 直接使用。标准存在但当前 runtime 标记实验 → 保持 adapter boundary，production 不启用。

### D3. Core 边界检查

问：卸载所有 Component 后，为了 Runtime 自身生存/管理/安全/恢复，这个功能是否还必须存在？否 → 不进入 Core。

### D4. Safe Rust Gate

实现是否需要第一方 unsafe/FFI？是 → 停止该方案，寻找安全 crate；找不到则延后能力。

### D5. 类型建模

任何 raw primitive 进入 Domain 前必须问：它是否代表独立语义？若是 → 建立 newtype/enum/record 并在 constructor 校验。

### D6. 失败模型

实现前列出至少：输入无效、权限拒绝、资源耗尽、取消、超时、依赖失败、进程 crash、持久化失败。任何路径没有明确状态/错误/恢复策略，不得认为设计完成。

### D7. 并发模型

优先单 owner + message、不可变 snapshot、短锁。队列必须有界。关键 task 必须受监督和可取消。

### D8. 依赖选择

现有已冻结 crate 能解决则不得加入替代库。必须新增时走 Dependency Gate，不得因为 API 更顺手就替换核心依赖。

### D9. 性能

没有 benchmark/profile 证据不得进行破坏清晰度的性能优化。性能假设必须转化为 benchmark。

### D10. 是否需要 ADR

以下变更必须 ADR + Owner/maintainer review，AI Agent 不得自行最终决定：

- 改变顶级原则；
- 新增私有插件/包/IDL；
- 改 public WIT 兼容语义；
- Core 新增具体运维领域知识；
- 引入第一方 unsafe；
- 改生产平台承诺；
- 改数据持久化核心模型；
- 改 authentication/session security 基线；
- 非 LTS Wasmtime 进入 production；
- 选择/改变项目开源许可证。

其他局部实现 Agent 必须依据规范自行完成，不应反复请求 Owner 选择。

---

## 26. 代码规范与 Review Gate

### 26.1 Clippy / rustfmt

CI 必须至少存在两类明确 job：

```text
# formatting
cargo fmt --check

# production feature set（实际 feature 名由 0.1 implementation PR 冻结）
cargo clippy --workspace --all-targets --locked --no-default-features --features <production-features> -- -D warnings

# lab / compatibility job 独立执行，不计入 production qualification
cargo clippy --workspace --all-targets --locked --features <lab-features> -- -D warnings
```

如果仓库默认 features 本身就是 production set，可以在 ADR/CI 中简化命令，但 Release Gate 必须能机械证明“此次资格测试没有因为 `--all-features` 把 p3 lab/实验 proposal 带入 production”。`--all-features` 可以作为额外兼容性 job，不能替代 production feature qualification。

禁止通过大范围 `#[allow(...)]` 消除 lint。局部 allow 必须有原因注释并经 review。

由于 `unwrap_used` / `expect_used` 等 restriction lint 默认并不是 warning，仅有 `-D warnings` 不能机械证明第 14.2 节。Workspace lint/production CI 必须另外将 `clippy::unwrap_used`、`clippy::expect_used`、`clippy::panic`、`clippy::todo`、`clippy::unimplemented` 设为 `deny`（若对应 toolchain 将其中某项升级/改名，则以 1.97.1 的等价 lint 为准并在 CI 固化）。对 macro/generated code 或工具无法覆盖的 production path，必须有补充 source-policy test，不能靠 review 记忆实现“panic-free”。测试代码的断言语义可以通过明确的 test-only lint policy 区分。

### 26.2 Public API

Public API 越少越好。Crate 默认 `pub(crate)`，只有跨 crate 真正需要且语义稳定的类型才 `pub`。

### 26.3 Documentation

所有 public type/function 必须有说明，重点写：

- 语义；
- 不变量；
- ownership/lifetime；
- 错误；
- 并发保证；
- 安全/权限含义。

不要把实现过程写成文档。

### 26.4 TODO

生产代码不得用无追踪 `TODO`。暂缓项必须 issue ID，且不能位于当前版本 MUST acceptance path。

### 26.5 Fix the Code, Not the Test

测试失败时默认修实现。只有证明测试与本规范冲突时，先修规范/ADR，再改测试。禁止通过删断言、增 sleep、扩大 timeout 掩盖竞态。

---

# 第八篇：测试、质量门禁与验收

## 27. 测试金字塔不是目标，风险覆盖才是目标

每类风险必须有最适合的证明方式：

- 纯状态/规则 → unit + property；
- 并发状态机 → Loom/model；
- WIT/Component → conformance components；
- SQLite/crash state → integration + fault injection；
- Web/security → black-box HTTP tests；
- Wasmtime limits → malicious/adversarial components；
- 平台 → native CI/qualification；
- 长期可靠性 → soak；
- parser/bytes → fuzz。

---

## 28. 单元与 Property Test

Domain 核心规则必须接近穷尽验证：

- lifecycle transition；
- version compatibility；
- capability resolution；
- permission scope；
- resource arithmetic；
- state migration planning；
- path/url validation；
- digest/identity separation。

适合组合空间的规则使用 Proptest，不能只写几个手工例子。

---

## 29. 并发正确性测试

使用 Loom 针对可抽象的小型并发核心测试：

- atomic active snapshot switch；
- drain/stop race；
- install/upgrade state transitions；
- storage request cancellation/response ownership；
- task supervisor shutdown；
- grant snapshot replacement。

大型 Tokio 集成同时运行 stress test 和 randomized cancellation。

验收不是“Safe Rust 编译通过”，而是没有观察到逻辑竞态、不一致状态或不可终止 shutdown。

---

## 30. Component Conformance Suite

仓库必须包含**测试 Component**，它们不是产品插件，而是 Runtime 符合性夹具。

至少包括：

- minimal valid Component；
- malformed bytes；
- incompatible contract/interface version；
- unknown import；
- denied capability；
- memory grow attacker；
- infinite loop；
- trap on init；
- health check failure；
- slow/drain component；
- descriptor deterministic/repeatability fixture；
- grant-expansion upgrade fixture；
- Web assets + sandbox escape attempt component；
- dependency provider/consumer（0.2+）；
- state migration components（0.3+）；
- p2/p3 equivalent fixtures（p3 qualification 时）。

Conformance Suite 是 Runtime 的产品测试，不得依赖任何具体监控/日志插件。

---

## 31. Fuzzing

持续 fuzz 目标至少覆盖：

- Component installation byte/input metadata boundary；
- custom WIT-facing parsers/serializers；
- URL/path/scope parser；
- DB migration metadata parser；
- HTTP boundary inputs that are first-party parsers；
- lifecycle/capability serialized state if applicable。

不要重复 fuzz 已由成熟 dependency 完成的内部解析器而没有项目特有价值。

任何 crash、panic、OOM amplification、infinite loop in host path 都是 defect。

---

## 32. Security Test

必须有自动化测试证明：

- 未授权 Component 无文件/网络/secret 权限；
- Component 不能访问其他 Component 未共享能力；
- HTTP route 不能绕过 Auth/RBAC；
- CSRF 防护有效；
- session rotation/expiry 有效；
- password hash 参数满足最低基线；
- secret 不出现在 logs/audit/debug；
- install 输入无法目录穿越；
- Web asset path 无 traversal；
- Component-controlled HTML/JS 不能读取 Root Admin DOM/cookie/storage，不能绕过 Core bridge 直接访问管理 API；
- Component 响应不能覆盖 `Set-Cookie` / CSP / CORS / authentication 等 Core-owned security headers；
- Component 升级新增或扩大 import/scope 时旧 grant 不会静默继承；
- descriptor 阶段无 operational grant，重复读取同一 digest 的 canonical descriptor 一致；
- oversized input 被提前拒绝；
- malicious Wasm 可被 memory/deadline limit 控制；
- safe mode 不自动激活有问题 Component。

---

## 33. Crash/Fault Injection

对安装、升级、migration、权限变更等关键事务，在每个可持久化阶段注入进程中止并重启，验证：

- DB schema 一致；
- Active Version 唯一；
- staged bytes 可清理；
- artifact rename/fsync/DB commit 任一注入点后，digest store 与 registry 关系仍可唯一恢复；
- audit 写入失败时需要 durable audit 的 mutation 不会先提交；
- 不出现丢失旧版本且新版本不可用；
- audit 能说明最后已提交状态；
- Safe Mode 可恢复。

应覆盖 disk full、permission denied、read-only filesystem、DB busy/corrupt detection 等合理故障。

---

## 34. Soak / Resource / Performance

### 34.1 Soak

0.1.0 release candidate 必须通过长期运行测试，至少覆盖：

- 高频 Component invoke；
- 周期安装/升级/回滚；
- Web login/session；
- Component trap/restart；
- repeated Store create/drop；
- SQLite writes/checkpoints；
- graceful shutdown/restart。

时长由 CI nightly/release 环境定义，但不得用短单测替代 soak 结论。

### 34.2 内存

记录：

- Core idle RSS；
- 每实例 RSS 增量；
- repeated create/drop 后 RSS 趋势；
- Web asset cache；
- SQLite/cache 占用；
- leaked task/Arc/Store detection。

### 34.3 性能基线

0.9 前必须冻结至少：

- cold start；
- Component validate/instantiate；
- WIT invoke latency；
- Core HTTP overhead；
- atomic hot switch；
- max sustainable concurrent invocations；
- idle footprint；
- startup with N Components。

性能回归阈值必须由 benchmark 数据设定，而非猜测。所有 Production Supported architecture 必须分别建立基线；不得用 x86_64 的吞吐/RSS 阈值直接假设 ARM64 等价，也不得因为 ARM64 属于 constrained/edge 常见形态就接受未定义的性能退化。

---

## 35. 覆盖率

代码覆盖率是发现遗漏的信号，不是质量目标。禁止为了达到数字写无意义测试。

Gate：

- Domain/Application 关键逻辑要求 branch/line coverage 可见并持续不下降；
- 安全、生命周期、升级、权限规则必须有明确行为测试；
- 新增未覆盖 critical branch 默认阻断；
- 具体百分比可由初始实现基线建立后在 CI 固化，Agent 不得自行降低。

---

## 36. CI 与 Production Qualification 矩阵

每个 PR 至少：

```text
Linux x86_64 GNU: full build + unit + integration + conformance
Linux aarch64 GNU: build + unit + integration + conformance on native/qualified runner
Windows x86_64: build + unit + integration subset
macOS arm64: build + unit + integration subset
```

Nightly/Release 增加：

```text
Loom
Fuzz corpus regression
Security tests
Crash injection
Soak
Benchmarks
x86_64 Linux full qualification
ARM64 Linux full native-hardware qualification
Constrained / Edge qualification profile
musl static candidate build/qualification
cargo-deny / cargo-audit
coverage
```

所有被声明为 Production Supported 的 target 必须独立完成完整 qualification；不得以另一个架构通过测试作为替代证据。仿真/交叉构建可以增加覆盖，但不能替代 ARM64 的真实原生硬件 release qualification。

ARM64 qualification 发现的架构特有缺陷必须按普通 release blocker 处理，不能以“ARM 只是边缘场景”为理由降低 Gate。平台候选晋升 Production Supported 时也必须执行与既有 Production Supported target 等价的完整 qualification。

---

## 37. Release Gate

任何 production release 必须同时通过：

1. `cargo fmt`；
2. clippy `-D warnings`；
3. `forbid(unsafe_code)` 全 workspace；
4. unit/property/integration/conformance；
5. security tests；
6. dependency advisory/license/source gate；
7. migration test；
8. upgrade/rollback test；
9. crash recovery test；
10. platform production qualification；
11. release binary smoke；
12. SBOM/provenance/sha256/signing（按路线图进入相应版本后为 MUST）；
13. 文档/CLI/API compatibility check；
14. 没有 unresolved release-blocker。

对同一 release 中所有声明为 Production Supported 的 target，上述 Gate 都必须成立。某一 production architecture 的失败会阻断该 release，不能通过把它临时改成“candidate”来绕过已经冻结的平台承诺；改变 production support matrix 属于 Owner/ADR 级变更。

Agent 不得通过改变 Gate 来让 release 通过。

---

# 第九篇：0.1.0 → 1.0.0 路线图

## 38. 路线图原则

路线图只包含 Core Runtime 平台能力，不包含任何具体运维 Component 的产品开发。

每个版本都是可真实运行的前一版本超集，不发布故意残缺的架构过渡态。

```text
0.1 Production Kernel
 -> 0.2 Capability Composition
 -> 0.3 Stateful Runtime
 -> 0.4 Web Application Runtime
 -> 0.5 Security & Governance
 -> 0.6 Distributed Runtime Fabric
 -> 0.7 High Availability & Scale
 -> 0.8 Distribution & Fleet Lifecycle
 -> 0.9 Compatibility Freeze & Hardening
 -> 1.0 Complete Runtime Platform
```

## 39. 0.1.0 — Production Kernel

### 39.1 目标

以最小但闭合的功能集合证明：**Operune Core Runtime 可以在 Linux x86_64 与 Linux ARM64 两种一等 CPU 架构上，安全、可靠、可恢复地承载标准 WebAssembly Components，并达到真实生产使用条件。**

0.1.0 不是 Demo，不允许把身份认证、资源限制、崩溃恢复、升级回滚、ARM64 资格证明或测试 Gate 推迟到“以后”。

### 39.2 MUST Scope

- Rust 1.97.1 / 2024 Edition / workspace Safe Rust gate；
- Wasmtime 36 LTS production line embedded；
- Component Model + WIT；
- WASI 0.2 production adapter；
- `operune:component@0.1.0`；
- `operune:web@0.1.0` 最小 Web bridge；
- Linux `x86_64-unknown-linux-gnu` production artifact；
- Linux `aarch64-unknown-linux-gnu` production artifact；
- Windows x86_64、macOS arm64 一等 CI/架构适配；
- Linux x86_64 musl static candidate pipeline；
- General Compute + Constrained/Edge qualification 基线；
- 每个 target 单 executable 交付；
- 本地 bootstrap/recovery CLI；
- HTTPS-only production Root Admin Web；
- bootstrap admin、password/session/CSRF/TLS security baseline；
- SQLite durable standalone Core state；
- direct `.wasm` install，无私有 manifest；
- digest-first quarantine/candidate model；
- Component validation + binary imports/exports contract inspection；
- deterministic descriptor validation + grant-aware runtime health/readiness validation；
- basic Host/WASI grants；
- enable/disable/start/stop/remove；
- memory/instance/host-buffer/concurrency/queue/deadline limits；
- epoch interruption；
- structured tracing + audit；
- stateless hot upgrade/rollback；
- graceful drain；
- safe mode/recovery；
- Component Web static assets + bounded backend action + mandatory minimal browser isolation 的最小闭环；
- conformance test Components；
- full CI/release gate。

### 39.3 明确不包含

- Component-to-Component provider graph；
- complex persistent Component state；
- public Component scheduler/event API；
- Component SecretStore public API；
- state migration；
- complete Component-driven Web application model；
- navigation/route registry/realtime Web runtime；
- distributed runtime；
- HA；
- remote registry/fleet rollout；
- production Wasmtime WASI p3 Host；
- ARM32、Android、QNX、RTOS、bare-metal 等新增宿主平台；
- safety-critical / hard-real-time control loop。

### 39.4 验收

只有全部成立才可标记 0.1.0：

- 非法/恶意 Component 不能通过 Host 资源或未授权能力拖垮/接管 Core；
- infinite loop 能按 deadline 中断；
- memory/host buffer/concurrency/queue over-limit 有确定拒绝或 trap；
- 未授权/未知 import 不能成为 Active；
- 同一逻辑 `ComponentId + ComponentVersion` 出现不同 digest 时被显式阻断；
- install/upgrade 任意定义的 crash point 后重启状态一致；
- v2 validation/descriptor/health 失败时 v1 保持可用；
- all Components disabled/corrupt 时 Root Admin Recovery Plane + CLI 仍可用；
- Core 重启恢复唯一 active Component registry；
- production browser admin 不存在明文 HTTP 登录退化；
- session/password/CSRF/TLS/security tests 全通过；
- Linux x86_64 GNU full qualification 通过；
- Linux ARM64 GNU full qualification 在真实 ARM64 硬件通过；
- ARM64 Constrained/Edge qualification 无不可接受的内存、磁盘、断连、重启或长期运行退化；
- 同一标准 Component fixtures 在 x86_64 / ARM64 的可观察领域语义一致，除非规范明确声明 capability availability 差异；
- Windows/macOS 架构测试无 Linux 假设泄漏；
- soak 无持续资源泄漏趋势；
- 第一方源码 unsafe=0，production path 无 `unwrap/expect/panic/todo/unimplemented` 逃生路径。

---

## 40. 0.2.0 — Capability Composition

### 40.1 目标

让独立 Components 形成确定、可检查、可授权、可热升级的能力图。

### 40.2 MUST Scope

- Component exports 满足其他 Component imports；
- Capability Provider identity；
- version compatibility resolution；
- provider selection 的确定规则；
- dependency graph；
- activation/deactivation ordering；
- cycle detection；
- missing provider diagnostics；
- shared/restricted capability grants；
- provider upgrade 前 consumer compatibility analysis；
- graph snapshot atomic switch；
- graph persistence/recovery；
- capability composition conformance suite。

### 40.3 裁决原则

依赖关系只能来自 WIT imports/exports + Runtime Policy，禁止创建另一份 `dependencies.json` 作为事实源。

### 40.4 验收

同一 Component set + 同一 policy 必须得到确定的 provider graph；无法唯一合法解析时必须拒绝激活，不得随机选择 provider。

---

## 41. 0.3.0 — Stateful Runtime

### 41.1 目标

让 Component 可以可靠承担长期、有状态应用职责，而不把线性内存当持久事实源，并让 Config / State / Secret 三种语义真正分离。

### 41.2 MUST Scope

- typed Component state service；
- transaction/atomic update semantics；
- Component config storage/validation；
- 独立 `SecretStore` port 与 secret grant/read semantics；
- secret at-rest protection 与跨平台 key-provider ADR；
- scheduler；
- event bus；
- checkpoint；
- graceful lifecycle (`ready/drain/stop/checkpoint`)；
- state schema version；
- explicit state migration；
- failed migration rollback；
- crash recovery across migration；
- scheduler/event backpressure；
- state/config/secret audit。

Config、State、Secret 不能因为都“需要存储”而被统一成一个无类型 KV：

- Config 是管理员/系统提供、具有 validation 和版本语义的输入；
- State 是 Component 产生的权威持久业务状态；
- Secret 是受专门访问控制与防泄漏规则保护的敏感值。

### 41.3 验收

升级、进程 crash、取消、磁盘失败均不得产生“代码版本已切换但状态 schema 不确定”的不可恢复状态；Secret 的读取、拒绝、轮换与审计必须可验证，且普通 SQLite metadata dump 不得直接暴露 secret 明文。

---

## 42. 0.4.0 — Web Application Runtime

### 42.1 目标

在 0.1.0 已验证的最小 Component Web bridge 上，建立完整、稳定、可组合的 Component-driven Web Application Runtime，同时保持 Root Admin Recovery Plane 与日常业务 Console 永久分离。

### 42.2 MUST Scope

通过版本化 `operune:web` WIT 契约增加：

- app descriptor；
- navigation/pages；
- typed backend route/action registration；
- route namespace 与 conflict diagnostics；
- page/action permission declarations；
- bounded request/response 与 cancellation 作为无条件 baseline；
- **只有第 8.3 WASI 0.3 production Gate 已通过时**才把 native `stream<T>` / `future<T>` / async realtime 纳入该版本 production scope；
- Web asset caching/integrity；
- backend/UI atomic version switch；
- browser isolation/CSP/security policy；
- per-Component HTTP quotas/backpressure；
- request cancellation/disconnect semantics；
- Web compatibility/conformance suite。

0.1.0 已存在的 static assets、bounded action、统一 Auth/RBAC/TLS/CSRF 和版本原子性必须继续作为基础，不得重造第二套 bridge。

### 42.3 WASI 0.3 条件

此版本**不强制**采用 WASI 0.3。若届时第 8.3 Gate 全部通过，可加入 p2+p3 双栈并让新 Components opt in；若不通过，继续 p2。路线图不能把稳定性绑到日历。

如果 p3 尚未通过 Gate，0.4 的完整 Web Application Runtime 以 bounded request/response、明确 cancellation 和可选 polling 完成 production baseline；native realtime/stream **明确不进入该版本生产承诺**，并顺延到第一个满足 8.3 Gate 的后续 release。禁止为了维持版本号或路线图表面完整而私造一套平行 async/stream ABI。p2 与未来 p3 的 adapter boundary 必须继续保留。

### 42.4 验收

一个测试 Component 可仅凭标准 `.wasm` 提供完整 UI + backend，安装后出现、升级时整体切换、卸载后完整消失；权限、路由、资源和浏览器安全均由 Core 统一治理，而 Core 不包含该业务页面知识。若本 release 已通过第 8.3 Gate 并宣称 realtime/stream，则还必须通过 native async/stream conformance；若未通过 Gate，验收不得假装该能力已存在。

---

## 43. 0.5.0 — Security & Governance

### 43.1 目标

从“安全运行少量可信 Component”提升为“可治理大量不同来源、不同权限、不同资源需求 Component”。

### 43.2 MUST Scope

- scoped capability policies；
- complete RBAC roles/groups；
- Root Admin/Operator separation；
- fine-grained Component administration permissions；
- resource quota hierarchy；
- rate/queue/concurrency policies；
- Component runtime metrics；
- per-Component invocation/error/trap/limit visibility；
- security/audit query and retention policy；
- permission change impact analysis；
- secret access audit；
- policy snapshot/versioning；
- security hardening review。

### 43.3 验收

管理员能够解释“某 Component 为什么可以/不可以做某件事”，答案必须来自可审计 policy chain，而不是散落配置或隐式 Host 权限。

---

## 44. 0.6.0 — Distributed Runtime Fabric

### 44.1 目标

同一个 Operune Core Runtime binary 支持多节点统一运行，不引入第二个完全不同的 Agent 产品；数据中心、云和间歇联网的边缘/设备节点使用同一节点模型。0.6 建立 distributed control fabric，但**不提前宣称控制面高可用**。

### 44.2 MUST Scope

- node identity；
- secure enrollment；
- mTLS node-to-node/control communication；
- node capability inventory；
- remote Component lifecycle；
- remote config/grant delivery；
- placement primitives；
- node health/heartbeat；
- disconnected/reconnect semantics；
- last-committed local policy/runtime snapshot；
- disconnected operation 的显式允许范围、expiry/lease 与重新同步规则；
- distributed audit identity；
- version compatibility negotiation；
- same binary role/config model；
- node-local state 与 cluster-authoritative state 的显式分类；
- single control-authority ownership semantics，为 0.7 HA 留出替换边界。

### 44.3 数据面原则

Core distributed fabric 主要负责 control/metadata/policy/deployment。禁止因为多节点就要求高吞吐日志/指标等成熟数据面全部经中心 Core 转发。

边缘/设备节点断开控制面时，是否继续运行既有 Component 必须由最后一次已提交 policy 明确决定；允许继续的只能是已经授权、已经落盘并且尚未过期的本地职责。节点断连期间不得自行创造新的 cluster-authoritative policy、grant、placement 或全局 ownership 事实。

### 44.4 验收

网络分区、节点重启、版本不一致必须得到确定状态；中心不可把“最后一次心跳”误报为当前实时事实。0.6 在 control authority 不可达时可以进入明确的 disconnected 状态，并按已提交的本地 continuity policy 继续允许的工作，但不能由多个节点自行选出互相矛盾的全局事实；重新连接后必须有确定的版本比较、过期处理和重同步路径。

---

## 45. 0.7.0 — High Availability & Scale

### 45.1 目标

消除控制面的明显单点，并为 cluster-authoritative state 建立经故障模型证明的一致性与 ownership 语义。

### 45.2 MUST Scope

- multiple Core control instances；
- cluster-authoritative metadata consistency model；
- consensus/leader/lease 或等价、可证明的 deterministic ownership；
- failover；
- durable fencing / stale-owner rejection；
- Component replicas；
- health-aware routing；
- capacity-aware placement；
- rolling update；
- blue/green；
- canary；
- automatic/manual rollback policy；
- admission control；
- load shedding/backpressure；
- failure-domain aware scheduling；
- scale/performance qualification；
- backup/restore 与 disaster recovery 对 cluster state 的正式契约。

具体一致性存储/协调实现必须在该里程碑前通过 ADR 选择。Domain 不得依赖某个数据库/consensus library 的具体类型，以保证该决策仍是 Infrastructure Adapter 层问题。

### 45.3 验收

任一允许的单节点故障不得令整个平台永久不可管理；网络分区期间不能形成两个都可以成功提交同一唯一职责的 owner。旧 leader/旧 lease 的写入必须被 fencing 机制拒绝，而不是只依赖“大家应该停止工作”的协作假设。

---

## 46. 0.8.0 — Distribution & Fleet Lifecycle

### 46.1 目标

把 `.wasm` 从本地安装制品提升为可验证、可离线、可分批、可大规模交付的标准 Component 生命周期。

### 46.2 MUST Scope

- standards-based remote artifact transport（届时优先选择成熟 OCI/Component ecosystem，而非私有 blob protocol）；
- immutable digest identity；
- publisher/signature verification；
- compatibility metadata without inventing executable format；
- fleet install/update/remove；
- node/group/percentage rollout；
- pause/resume；
- staged/canary rollout；
- rollback；
- offline/air-gapped import；
- mirror；
- SBOM/provenance；
- supply-chain policy；
- key rotation/revocation model。

### 46.3 原则

远程 registry/OCI 只是标准分发手段，不改变“最终执行单元是标准 `.wasm` Component”这一事实。

---

## 47. 0.9.0 — Compatibility Freeze & Hardening

### 47.1 目标

停止扩大核心模型，冻结 1.0 compatibility contract，并进行工业化硬化。

### 47.2 MUST Freeze

- Core Runtime lifecycle semantics；
- Component lifecycle；
- WIT package naming/versioning；
- Capability model；
- permission/grant semantics；
- State/Config/Secret semantics；
- Scheduler/Event semantics；
- Web extension semantics；
- resource model；
- upgrade/rollback model；
- distributed node model；
- compatibility/deprecation policy。

### 47.3 MUST Hardening

- conformance suite complete；
- compatibility suite；
- long soak；
- fuzz corpus maturity；
- malicious Component testing；
- disk-full/corruption/crash/partition chaos；
- backup/restore drills；
- security review；
- performance baseline；
- production platform qualification；
- WASI dual-version qualification if p3 has passed maturity gate；
- documentation/API/WIT reference complete。

### 47.4 验收

0.9 RC 周期不得通过引入新的核心抽象解决发现的问题；若发现必须推翻基础模型的问题，1.0 延后，先修模型并重新稳定，而不是带着已知架构债发布。

---

## 48. 1.0.0 — Complete Runtime Platform

### 48.1 1.0 的含义

1.0 表示 Core Runtime 的基础产品模型已完整、稳定、可长期兼容，并不是“以后永远不加功能”。

### 48.2 1.0 必须具备的完整能力

- production single-node runtime；
- standard Component execution；
- WIT contract enforcement；
- WASI stable integration；
- install/remove/enable/disable；
- hot update/rollback；
- capability composition；
- state/config/secret；
- scheduler/event；
- Component-driven Web；
- Root Admin recovery plane；
- scoped security/RBAC/audit；
- resource governance/runtime observability；
- multi-node runtime；
- placement；
- HA/failover；
- rolling/blue-green/canary；
- distribution/signature/offline/fleet；
- backup/recovery/safe mode；
- stable compatibility/deprecation contract；
- conformance/qualification suite；
- published performance and platform support baselines。

### 48.3 最终架构验收问题

在 1.0，任何新的运维领域能力都应该可以：

```text
author standard Component
  -> use WIT imports/exports
  -> build one .wasm
  -> install into Core
  -> grant capabilities
  -> compose with other Components
  -> expose Web/app behavior if needed
  -> persist state if needed
  -> hot upgrade
  -> distribute to fleet
```

而 Core Runtime 不因为“又多了一个运维领域”修改业务源码。

如果这一点不成立，1.0 架构验收失败。

---

# 第十篇：Definition of Done 与变更治理

## 49. 单个 Issue/PR 的 Definition of Done

一个实现任务只有同时满足以下条件才算完成：

- 功能符合当前版本 MUST scope；
- 已与全部相关冻结基线完成全量五要素交叉审计；
- 没有违反 Core/Component 永久边界；
- 第一方 Safe Rust gate 通过；
- typed model，无新增不必要 primitive obsession；
- happy path + failure path 测试；
- 并发/取消/资源边界已处理；
- error 可诊断但不泄密；
- 无 unbounded queue/cache；
- no hidden global mutable state；
- lint/format/test/deny/audit 通过；
- public behavior 有文档；
- 如果影响 compatibility，ADR 已批准；
- benchmark-sensitive path 有测量；
- 不通过削弱测试/安全策略完成。

---

## 50. ADR 规范

ADR 只记录真正架构决策，必须包含：

- Context；
- Decision；
- Alternatives considered；
- 为什么其他方案不选；
- 对五要素审计的影响；
- Compatibility impact；
- Security impact；
- Migration/rollback；
- Status（Proposed/Accepted/Superseded）。

AI Agent 可以起草 ADR，但第 25.10 列出的 Owner Gate 决策不得自行标记 Accepted。

---

## 51. 当前明确延后但不得破坏的事项

以下不是 0.1.0 功能，但 0.1 架构不得让未来只能靠重构实现：

- WASI 0.3 production 双栈；
- Windows/macOS production promotion；
- Windows ARM64 production；
- Linux ARM64 musl/static production qualification；
- Linux/Windows/macOS 之外的新宿主 OS family；
- Component-to-Component graph；
- state migration；
- distributed fabric；
- HA；
- remote registry；
- fleet rollout；
- OS process-level worker isolation。

“不得破坏”不等于提前实现。只要求依赖方向、adapter boundary、typed contract 和生命周期不把未来锁死。

---

## 52. 明确不做的事情

除非未来本规范通过正式 ADR 修改，否则禁止：

- 自研 WebAssembly VM；
- 私有 `.plugin` 包格式；
- 私有 IDL 替代 WIT；
- 复制 WASI 语义的 `operune:*` Host API；
- 把完整业务 Web Console 编进 Core；
- Core 内硬编码具体运维产品、设备厂商、机器人平台或车辆平台 SDK；
- 通过 Server/Edge/Robot 等场景 Edition 分裂 Core/Component/WIT 基础语义；
- 把 Operune 作为 safety-critical / hard-real-time 控制回路；
- 为了“Wasm 纯粹度”强行把最小 Rust Host、成熟外部系统或浏览器原生技术重写成 Wasm；
- 第一方 unsafe/FFI；
- 让所有 telemetry 数据经 Core；
- 默认给 Component 全文件/全网络权限；
- 把 linear memory 当唯一持久状态；
- 把 Component runtime 内部 `.cwasm` 等实现产物作为公开插件标准；
- 为静态链接牺牲已验证的生产可靠性；
- 为追新标准启用官方明确 not-production-ready 的实现。

---

# 第十一篇：AI Agent 启动与执行清单

## 53. 新 Agent 接手项目时的必做顺序

AI Agent 在写任何代码前必须：

1. 阅读本规范；
2. 确认当前目标里程碑及其 MUST / out-of-scope；
3. 读取现有 ADR；
4. 读取 workspace dependency graph；
5. 查看当前 CI Gate；
6. 确认任务属于哪个 crate/边界；
7. 若任务涉及 Wasmtime/WASI/Rust 当前成熟度，查询官方最新 primary source，而不是依赖训练记忆；
8. 明确不变量、失败模式、测试方法；
9. 才开始实现。

## 54. 每次提交前

Agent 必须自行检查：

```text
[ ] 标准已有能力是否被重复发明？
[ ] 是否把具体运维领域塞进 Core？
[ ] 是否泄漏 Wasmtime/WASI 具体版本类型到领域层？
[ ] 是否出现 unsafe/FFI？
[ ] 是否出现 String/u32 等语义裸值扩散？
[ ] 是否出现 unwrap/expect/panic/todo/unimplemented？
[ ] 所有 queue/cache/concurrency 是否有界？
[ ] cancellation/shutdown 是否完整？
[ ] crash/restart 后状态是否确定？
[ ] 权限是否 deny-by-default？
[ ] secret 是否可能进入日志？
[ ] 是否为了测试通过削弱 Gate？
[ ] 是否真的需要新增 dependency/abstraction？
[ ] 当前 OS/CPU 架构特定代码是否只在允许的 adapter 边界？
[ ] 是否把某个部署场景/设备厂商误写成产品基础语义？
[ ] 是否为了“更 Wasm”而制造了标准之外的形式主义或降低可靠性？
[ ] failure tests 是否存在？
[ ] 是否已把本次变更与全部相关冻结结论做全量交叉审计？
[ ] 哲学统一、语义一致、逻辑自洽、真实有效、完整可靠五项是否全部通过？
```

---

# 第十二篇：来源基线与事实校验

## 55. 基线资料（2026-08-07）

以下资料用于本规范中的标准成熟度、Wasmtime 支持等级、Rust 工具链、安全基线和 Web 安全事实。它们不是永远不变的事实；任何依赖/标准升级 PR 必须重新查阅**官方 / primary source**，不能只依赖搜索摘要、博客转载或模型记忆。

1. Wasmtime Release Process / LTS Policy  
   https://docs.wasmtime.dev/stability-release.html

2. Wasmtime Tiers of Support  
   https://docs.wasmtime.dev/stability-tiers.html

3. Wasmtime `wasmtime_wasi::p3`  
   https://docs.wasmtime.dev/api/wasmtime_wasi/p3/index.html

4. Wasmtime `wasmtime_wasi_http::p3`  
   https://docs.wasmtime.dev/api/wasmtime_wasi_http/p3/index.html

5. WASI 0.3 specification / release information  
   https://wasi.dev/  
   https://wasi.dev/interfaces

6. Component Model — Migrating WASI 0.2 to 0.3  
   https://component-model.bytecodealliance.org/design/migrating-to-p3.html

7. Component Model / WIT  
   https://component-model.bytecodealliance.org/design/wit.html

8. Wasmtime Component API  
   https://docs.wasmtime.dev/api/wasmtime/component/index.html

9. Wasmtime interruption (fuel / epoch)  
   https://docs.wasmtime.dev/examples-interrupting-wasm.html

10. Wasmtime resource limiter / allocation APIs  
    https://docs.wasmtime.dev/api/wasmtime/struct.Store.html  
    https://docs.wasmtime.dev/api/wasmtime/enum.InstanceAllocationStrategy.html

11. Rust 1.97.1 release  
    https://blog.rust-lang.org/2026/07/16/Rust-1.97.1/

12. Rust target platform support  
    https://doc.rust-lang.org/rustc/platform-support.html

13. Cargo lockfile / reproducibility documentation  
    https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html

14. OWASP Password Storage Cheat Sheet  
    https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html

15. OWASP Session Management Cheat Sheet  
    https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

16. OWASP CSRF Prevention Cheat Sheet  
    https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html

17. HTTP State Management (`Secure` / `__Host-` cookie semantics)  
    https://httpwg.org/http-extensions/draft-ietf-httpbis-rfc6265bis.html

18. WebAssembly Component Model issue #488（作为保守的二进制身份约束证据：不要依赖 root WIT package/world 名从最终 Component 恢复）  
    https://github.com/WebAssembly/component-model/issues/488

19. Rust Clippy lint reference（以 pinned toolchain 对应版本为准）  
    https://rust-lang.github.io/rust-clippy/

20. `base64` crate source/features（0.23 默认 `simd-unsafe`，Operune 安全路径显式关闭）  
    https://docs.rs/crate/base64/0.23.0/source/Cargo.toml.orig

21. Rust `aarch64-unknown-linux-gnu` target support  
    https://doc.rust-lang.org/rustc/platform-support/aarch64-unknown-linux-gnu.html

22. Wasmtime current target tiers（含 `aarch64-unknown-linux-gnu` Tier 2 / x86_64 Linux Tier 1）  
    https://docs.wasmtime.dev/stability-tiers.html

23. Wasmtime platform support overview  
    https://docs.wasmtime.dev/stability-platform-support.html

24. WASI language / Component interoperability overview  
    https://wasi.dev/languages

25. crates.io / docs.rs 对应 direct dependency 的发布页与 API 文档。

各 crate 的**精确 production 解析版本**以 committed `Cargo.lock`、workspace dependency table 和 Release Gate 记录为事实源；本文第 22 章保存本次规范冻结时的已审查 snapshot 与选择原则。

---

# 56. 最终总纲

Operune 的终极工程判断压缩为以下规则：

> **Operune 是一个场景无关、运维领域有边界的 WebAssembly-native 平台级产品。服务器、云、工作站、边缘、工业、机器人或自动驾驶计算节点只是部署形态，不是产品 Edition；Runtime Host Node 与 Managed Resource 永久分离，被运维对象不要求安装 Core。Core 只做 Runtime 为了存在、管理、安全、治理、组合和恢复自身而必须做的事；所有具体运维能力全部 Component 化。标准能准确解决的绝不私造，WASI 能直接提供的绝不包装成平行 Host API，跨 Component 的项目领域契约只使用 WIT。第一方代码坚持 Safe、强类型、可验证的地道 Rust；Component 遵循 capability-based、deny-by-default、显式 import/export 的 WebAssembly 哲学。生产基线选择成熟 LTS，并把 Wasmtime/WASI/OS/CPU Architecture/Storage 的具体实现锁在可替换适配边界，使标准升级、x86_64↔ARM64、平台扩展和从单机到分布式成为受控演进，而不是系统推倒重来。**

“全面拥抱 Wasm”的最终判定不是“所有东西都写成 Wasm”，而是：

> **一个新的运维领域能力，无论面向数据中心、云、边缘还是设备计算节点，都可以只作为标准 WebAssembly Component 接入、组合、授权、运行、持久化、呈现 Web、升级和分发；Operune Core 无需因为新增领域、硬件类别或厂商生态修改业务源码。与此同时，最小 Rust Host、成熟外部系统和浏览器原生技术保留各自最适合的实现形态，不为了形式主义牺牲生产可靠性。**

发布 1.0.0 的标准不是“支持很多场景”，而是同一平台模型能够在不同计算形态上保持同一语义，并在安全、故障恢复、兼容、跨架构、跨平台、资源治理、测试、供应链和分布式一致性方面形成工业生产级、可验证的长期承诺。

---

# 57. R2 全量五要素交叉审计裁决记录

本章记录 R1 → R2 因“平台级产品、场景无关、ARM64 一等架构、全面拥抱 WebAssembly”产生的全量交叉审计。R2 不是在 9.2 表格增加一行 ARM64，而是对产品定位、平台矩阵、Core 边界、CI/Release、分布式语义和长期演进进行统一修正。

## 57.1 哲学统一

**结论：通过。**

- Operune 从“容易被理解为服务器/数据中心 Runtime”的表述提升为**运维领域的平台级产品**，但没有扩张成任意业务 PaaS；
- Core Runtime 仍是唯一不可卸载原生基础层，没有因为边缘/机器人/ARM64 增加设备厂商知识；
- Component 仍是唯一可安装扩展执行单元，WIT 仍是唯一结构化跨边界契约，WASI 仍标准优先；
- “全面拥抱 Wasm”被冻结为 Wasm-native 而非 Wasm 纯粹主义，没有反向破坏 P11 的生产可靠性优先；
- 场景不设限，但运维领域、安全边界与 hard-real-time control boundary 保持清楚。

## 57.2 语义一致

**结论：通过。**

R2 明确区分并统一以下概念：

- 运维领域边界 / 部署场景；
- Runtime Host Node / Managed Resource；
- CPU Architecture / OS Family / Rust target triple；
- Architecture-ready / CI Supported / Operune Production Supported / Upstream Tier；
- General Compute / Constrained-Edge Qualification 与产品 Edition；
- Component 扩展执行 / Browser UI implementation / External native system；
- ARM64 平台支持 / 某个具体机器人、GPU、车辆或设备厂商集成。

`x86_64` 与 `aarch64` 在 Domain、WIT、Component、Capability、状态和生命周期中没有不同产品语义。

## 57.3 逻辑自洽

**结论：通过。**

1. **Runtime Host vs Managed Resource**：宿主平台矩阵只决定 Core 能部署在哪里，不限制 Operune 能管理什么；新增被管资源通常通过 Component 扩展，不要求安装 Core；
2. **平台级产品 vs 运维领域**：场景不再限制产品，但任意业务应用不会因为能编译成 Wasm 就进入 Operune；
3. **ARM64 production vs 上游 Tier 2**：文档不把 Wasmtime Tier 2 冒充 Tier 1；Operune 只在自己的完整真实硬件 qualification 通过后做 Production Supported 承诺；
4. **多架构 vs 单二进制**：单二进制定义为“每个 target 一个自包含 executable”，不误解成跨 ISA universal binary；
5. **设备场景 vs Core 极薄**：设备/机器人/车辆/厂商差异继续停留在 Component、外部系统或明确 capability adapter，不进入 Core 业务知识；
6. **边缘断连 vs 分布式一致性**：0.6 允许已提交 policy 控制下的本地 continuity，但断连节点不能创造 cluster-authoritative 事实；
7. **Wasm-native vs Core native Rust**：Component/WIT/WASI 是扩展边界，Rust Host 是平台生存边界，两者职责互补而非冲突；
8. **Web 一等能力 vs Web 唯一入口**：Component Web 继续是一等应用呈现面，Recovery CLI/API 仍保持独立，浏览器不被误认为 Runtime 宿主。

## 57.4 真实有效

**结论：通过，但 ARM64 承诺必须持续受 qualification Gate 约束。**

- Rust `aarch64-unknown-linux-gnu` 当前是 Tier 1 with Host Tools；
- Wasmtime 当前 `aarch64-unknown-linux-gnu` 是 Tier 2 / Almost Production Ready，缺 Tier 1 的当前主要项是 continuous fuzzing；因此 R2 明确记录风险而不是伪造上游生产等级；
- Wasmtime 在 x86_64 与 aarch64 上可以使用 Cranelift 执行 WebAssembly，现有 Component/WASI 基础具备跨两种架构落地的现实条件；
- ARM32、Android、QNX、RTOS、bare-metal 和 Windows ARM64 没有被因“平台级”愿景偷渡成 0.1 承诺；
- WASI 0.3 的“标准已发布”与当前生产 Host maturity 继续分离，production 仍遵守既有 p2/p3 Gate；
- R1 已复核的 Rust/Wasmtime LTS/direct dependency 快照继续有效，R2 未无理由改变依赖选型。

## 57.5 完整可靠

**结论：通过。**

R2 新增或强化的完整性要求包括：

- Linux x86_64 与 Linux ARM64 都进入 0.1 Production Release Gate；
- ARM64 必须在真实原生硬件上做完整 qualification，QEMU/交叉编译不能代替；
- 增加 constrained/edge-class 资源环境验证，而不分裂产品；
- 验证低内存、磁盘压力、慢持久存储、反复重启、网络断开/恢复、长期运行与资源泄漏；
- x86_64/ARM64 同一 Component fixtures 的可观察语义一致性进入验收；
- 多节点断连增加 last-committed policy、expiry/lease 和 reconnect/reconcile 语义；
- 明确禁止把 safety-critical / hard-real-time control loop 纳入 Operune；
- 明确禁止因特定设备/厂商把专有 SDK 或业务知识塞进 Core；
- 明确禁止用“全面拥抱 Wasm”作为降低可靠性、重造标准或强行 Wasm 化成熟外部系统的理由。

因此，本文件可以作为 **Operune Engineering Baseline R2 FINAL / Frozen** 直接进入 0.1.0 工程实施。R2 的核心变化可以压缩为：

> **领域聚焦运维，部署形态不设限；x86_64 与 ARM64 一等对待；扩展边界全面 WebAssembly-native；Core 始终最小、原生、可靠。**
