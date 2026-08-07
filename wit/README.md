# Operune 公共 WIT 契约（0.1.0 首批 + 0.3.0 Stateful Runtime 契约 + 0.4.0 Web Application Runtime 契约）

本目录是 Operune 公共平台契约（规范 §6.6），全部为**标准 WIT 语言**
（P3：WIT 是唯一跨边界接口契约；不引入任何私有 IDL / 协议）。
0.1.0 首批契约（§39 的 descriptor / web bridge）、0.3.0 Stateful Runtime
契约（§41 的 state / config / secret / scheduler / event）与 0.4.0 Web
Application Runtime 契约（§42 的 `operune:web@0.2.0`）在同一个
`operune:*` namespace 下按各自 package 版本独立演进。

| Package | 目录 | 内容 |
|---|---|---|
| `operune:component@0.1.0` | `operune/component/` | `descriptor`（Component 身份与平台 metadata 声明）+ 参考 world |
| `operune:web@0.1.0` | `operune/web/` | `descriptor`（Web UI 声明）、`assets`（内嵌静态资产列举/读取）、`actions`（有界 backend action）+ 参考 world |
| `operune:web@0.2.0` | `operune/web@0.2.0/` | `app-descriptor`（0.4.0 app descriptor：entry / features 扩展 / pages / routes / permissions 声明）、`navigation`（页面声明与导航语义）、`routes`（typed route/action 注册与声明期冲突诊断）、`permissions`（页面/action 权限声明）、`route-dispatch`（typed 运行期入口）、`assets`/`actions`（0.1 语义继承 + 0.4 增补）+ 参考 world |
| `operune:state@0.1.0` | `operune/state/` | `state`（typed state service：事务/CAS/版本）、`declaration`（state 契约声明）、`migration`（显式状态迁移）+ 参考 world |
| `operune:config@0.1.0` | `operune/config/` | `config`（只读配置快照/版本）、`declaration`（config 契约声明）、`validator`（配置校验器）+ 参考 world |
| `operune:secret@0.1.0` | `operune/secret/` | `secret`（SecretStore port 的 guest 侧：grant/read + 防泄漏契约）+ 参考 world |
| `operune:scheduler@0.1.0` | `operune/scheduler/` | `scheduler`（注册/取消/状态查询）、`handler`（fire 交付）+ 参考 world |
| `operune:event@0.1.0` | `operune/event/` | `event`（topic 发布）、`handler`（事件投递）+ 参考 world |

WIT package 版本是**接口契约版本**，不是 Core Runtime 发布版本的别名（§6.6）；
0.3.0 运行时引入的能力（§41）以 0.1.0 契约版本表达，是契约独立演进的正常形态。

---

## 1. `operune:component@0.1.0` 的 §6.6 证明

§6.6 要求：任何 `operune:*` package 都必须先证明 WASI / Component Model
没有准确表达相同语义。逐条论证：

### 1.1 组件逻辑身份（ComponentId / ComponentVersion / 作者元数据）

- **Component Model 不提供"组件向宿主声明自己是哪个应用"的运行时契约。**
  Component Model 的类型系统描述的是接口结构（imports / exports / 类型关系，
  即 §6.7 的 Contract Surface Identity），不表达应用身份。`component-id` 是
  逻辑产品身份，与二进制可观察的接口结构是正交事实：两个不同产品可以导出
  相同的接口面，同一产品也可以演进接口面。
- **Component Model 的 package / world 名不是运行时事实源。** 源码层的
  package 名 / 版本是打包元数据；规范 §6.7 明文要求不得假设 root package /
  world 名能从最终 `.wasm` 二进制可靠恢复（规范 §55 引用的
  component-model issue #488 是这一保守约束的证据）。因此"作者声明的
  逻辑身份"必须由明确的运行时契约显式声明，而不能从标准元数据推导。
- **WASI 无此语义。** WASI 0.2 的全部 interface（`wasi:io`、`wasi:filesystem`、
  `wasi:clocks`、`wasi:random`、`wasi:http`、`wasi:cli` 等）都是宿主能力接口，
  不存在"组件向宿主报告自己的身份 / 版本 / 作者"的契约。`wasi:cli/run` 只是
  入口约定，不携带身份信息。
- **descriptor 阶段的确定性强制是平台语义。** §19.3 的"side-effect-free、
  bounded、可重复，同一 ContentDigest + 同一 contract version 得到同一
  canonical descriptor"是 Operune 安装状态机的执行约束（防身份注入 /
  时间依赖 / 随机依赖），标准世界中没有等价物。

→ 结论：`operune:component/descriptor` 表达的是"组件逻辑身份与平台
metadata 的声明契约"，WASI / Component Model 均未准确表达，属于 §6.6
允许的平台领域语义。

### 1.2 平台生命周期 / 健康检查（本版本仅注释预留）

- WASI preview2 没有组件生命周期管理契约：没有 start / stop / ready / drain /
  health 协议；`wasi:cli/run` 只定义入口，宿主如何管理实例生命周期是宿主
  内部事实，标准不表达"平台级组件健康 / 就绪"语义。
- Component Model 的 instance 生命周期（实例化 / 运行 / 销毁）是执行机制，
  不是领域契约，且没有健康检查协议。
- Operune 的 lifecycle / health 属于平台领域语义（§6.6 明文列举），
  0.1.0 有意只注释预留：§19.3 要求 health / readiness 在真实
  grant / resource 环境（Runtime Candidate 阶段）执行；0.3.0 路线图（§41）
  才引入 graceful lifecycle。预留方式见 `operune/component/world.wit` 注释。

### 1.3 禁止复制的 WASI 语义（P4 自检）

本 package 不定义：时钟 / 随机数（`wasi:clocks` / `wasi:random`）、文件访问
（`wasi:filesystem`）、网络（`wasi:http`）、环境与参数（`wasi:cli`）。
descriptor 明确禁止依赖这些能力（§19.3），因此不存在重复包装。

---

## 2. `operune:web@0.1.0` 的 §6.6 证明

### 2.1 组件内嵌静态资产（assets）≠ wasi:filesystem

- `wasi:filesystem` 建模的是**宿主文件系统访问**：preopen 目录、路径解析、
  descriptor 生命周期、读写权限。它是"组件访问宿主 OS 文件"的通用能力。
- `operune:web/assets` 建模的是**从组件自身字节中读取的内嵌只读数据**：
  无 preopen、无宿主文件系统暴露、无可变文件、无路径穿越面；资产以
  `ContentDigest + asset path` 为缓存事实（§21.3），由 Core 激活阶段读取、
  按内容摘要缓存并直供浏览器，静态资产请求不必重新执行 Wasm（§6.2）。
- 语义目标相反：filesystem 把文件暴露给组件；assets 把组件内嵌数据
  交付给 Core 托管的浏览器面。若强行用 wasi:filesystem 表达，要么要求
  Core 把组件资产落盘成宿主文件（引入可变文件与磁盘预算问题，破坏 §7.6
  无 ambient authority 与 §18.7 磁盘治理），要么把 preopen 目录暴露给
  组件（扩大攻击面）。标准语义均不"准确表达"这一场景。
- `wasi:http` 同样不覆盖：它没有"宿主托管组件静态资源并缓存"的语义。

### 2.2 有界 backend action（actions）≠ wasi:http 包装

- `wasi:http/incoming-handler` 让组件成为普通 HTTP 服务端点；但 §21.3
  **明文禁止组件自行 bind 监听端口**。Operune 的 action 桥是
  **Core-mediated 反向通道**：Core 把浏览器请求绑定到
  `InstallationId + ComponentVersion`，在服务端重新执行 authentication、
  RBAC、grant、action permission、body / deadline / rate / concurrency 检查
  （§21.3）。
- 这些是**平台托管与安全语义**：凭据隔离（UI 不接触 Root Admin session
  bearer / CSRF，§16.5）、Core-owned security headers 不可覆盖、sandboxed
  frame + Core 强制 CSP、原子版本切换（§21.5）。WASI 的 HTTP 接口只表达
  "组件收发通用 HTTP"，不表达"宿主托管的、绑定安装身份的、受平台策略
  治理的组件 Web 桥接"，更不表达 Web 资产的版本原子性。
- 若把 actions 包装成 wasi:http incoming-handler 的私有封装，反而违反
  P4 的精神：wasi:http 的授权模型是网络端点暴露面，而 Operune action 的
  授权走 InstallationId grant 链（§17.1 两阶段含义），语义不可互证。
- 0.1.0 明确限定 bounded request / response（无 WebSocket / 流 / 长连接），
  与 0.4.0 的完整 Web Application Runtime 是"最小闭环 → 完整运行时"
  关系，不是两套系统（§21.4）。

### 2.3 挂载命名空间与原子版本

- Core 分配、不可冲突的 mount namespace（§21.3）与"UI assets + backend
  exports 随同一 ComponentVersion 原子切换"（§21.5）都是平台托管语义，
  标准世界（WASI / Component Model / Web 平台）没有"平台托管组件 Web
  面"的模型，无从准确表达。

### 2.4 禁止复制的 WASI 语义（P4 自检）

本 package 不复制：文件读取（`wasi:filesystem`）、HTTP 收发
（`wasi:http`）、流 / poll（`wasi:io/streams` / `pollable`）。契约中没有
把 `wasi:io@0.2` 的版本特有类型嵌入领域契约（§8.2 SHOULD NOT）。

---

## 3. 与冻结技术选型的关系

- **与 §22.9"不用 async-trait 作为默认新接口手段"不冲突。** async-trait 是
  Rust 内部 trait 实现手段；WIT 是跨 Component 边界的契约语言（P3），
  两者处于不同层。本批契约全部使用同步 func，与 0.1.0 bounded
  request / response 语义一致（§21.3）。未来 async 演进只走标准
  `stream<T>` / `future<T>` / async func 路径（§6.3），且必须在 §8.3
  WASI 0.3 production Gate 通过后才进入 production scope（§42.3）；
  不会因此引入自研 async IDL。
- **与 P3 不冲突。** 本目录全部是标准 WIT 文本；没有第二套 IDL、Rust ABI、
  动态符号协议或私有 RPC ABI。
- **与 §8.2 分层不冲突。** 领域 WIT 版本独立于 WASI 版本；契约不嵌入
  p2 / p3 版本特有类型，WASI 0.2 → 0.3 迁移由 adapter crate 承担。
- **descriptor 的确定性如何被 Core 执行（实现注意）。** Core 对同一
  ContentDigest 在同一 contract version 下调用两次
  `get-descriptor`，比较 canonical 结果，不一致视为 contract violation
  （candidate 保持 quarantine / failed，§19.3）；调用在零 operational
  grant 的 descriptor-only Store 中进行（§19.3），并受与正常运行相同或
  更严格的 memory / table / instance / host-buffer / deadline 预算约束
  （§7.4 / §7.5）。
- **参考 world 不是运行时事实源。** `operune-component` 与
  `operune-web-component` world 仅供作者侧打包参考；Core 的识别与兼容
  判断只依赖二进制中真实可观察的 exports（§6.7）。

## 4. 演进策略（不破坏 0.1.0 契约）

- WIT record 添加字段是破坏性变更：身份 / 版本 / descriptor 结构的扩展
  通过新 interface 版本（同一 package 的 0.2.0 等）演进，不修改本版本语义。
- 新增接口（lifecycle、health、路由 / typed action 等）以新 interface 加入
  对应 package，与既有接口共存；0.4.0 的 web 演进（§21.4 / §42.2）不得推翻
  0.1.0 的 assets / actions 既有语义（§21.4 明文）。
- 0.4.0 的 web 演进落地为**新 package 版本** `operune:web@0.2.0`
  （`operune/web@0.2.0/` 目录，与 0.1.0 共存），而不是在 0.1.0 包内增量
  加 interface：0.1.0 `web-features` flags 无法在版本内扩展（flags 成员
  变化即类型变化），app descriptor 的 features 扩展必然落到新版本；设计
  选择与完整理由见 §11.6。旧 0.1.0 组件无需迁移（§8.4 无 flag-day 精神）。
- 若未来标准（Component Model / WASI）覆盖某项自定义能力，按 §6.6
  通过显式版本化与兼容层迁移，不静默重解释旧 package。

---

# 0.3.0 Stateful Runtime 契约（§41）的 §6.6 证明

以下五节逐包论证"WASI / Component Model 没有准确表达相同语义"（§6.6）。
论证以 2026-08-07 冻结基线的 WASI 生态事实为准（§55），并做 P4 自检
（不重复包装已生产可用的 WASI 能力）。

## 5. `operune:state@0.1.0` 的 §6.6 证明

### 5.1 wasi:keyvalue 存在——诚实论证（本包论证的关键项）

必须如实承认：WASI 生态**存在** key-value store 预览接口 `wasi:keyvalue`
（wasmCloud 发起、WebAssembly/wasi-keyvalue 仓库维护）。单键 get/set、
单键 CAS/increment（atomics）、批量 get-many/set-many/delete-many
（batch）是这个提案表达的内容。因此本论证**不**主张"KV 访问 WASI
表达不了"。

但 §6.6 的要求是"WASI **准确表达相同语义**"，逐条对照 §41.2 MUST
后不成立：

1. **成熟度（§8.3 精神）**：`wasi:keyvalue` 是 **Phase 2 draft**（未定稿，
   提案 API 仍在演进）；wasmtime 官方 WASI Proposals Support 表明确
   **不支持**该提案（"Supported in Wasmtime? No"），只存在独立的
   `wasmtime-wasi-keyvalue` crate 且为**纯内存、跨实例不持久、不共享**
   的占位实现（wasmtime issue #11187 自述"beyond the initial inception
   未见进一步实现工作"）。本项目冻结的 wasmtime 36.x LTS 线（§22.2）
   中，wasi:keyvalue 无可生产使用的宿主实现；redb/Redis 后端是社区
   独立 crate，未进 wasmtime。把权威业务状态建立在不可生产、不持久
   的标准接口上是 §8.3 / §41.3 明文排除的路径。
2. **transaction/atomic update semantics（§41.2 MUST）**：wasi:keyvalue
   的 batch 是多键一次调用，**不是原子事务**；单键原子性只有
   increment / 单键 CAS。Operune 契约的 `state-transaction`（多操作
   all-or-nothing、乐观并发冲突检测）与独立于事务的 `cas` 原语无
   对应物。
3. **state schema version + 显式 migration（§41.2 / §20.5 MUST）**：
   wasi:keyvalue 的 key 是裸 string、value 是裸 bytes，存储数据**没有**
   schema 版本概念，也没有"版本化、原子、可失败、带 rollback policy
   的显式迁移"契约面；跨迁移崩溃恢复（§18.5 / §20.5）更是平台语义。
   `operune:state` 的 `declaration`（声明版本）、`migration`（迁移
   handler）、`begin-transaction(schema-version)`（版本化写路径）与
   `unsupported-schema-version` / `not-ready` 错误闭集表达的是
   "versioned state"这一整体，标准世界无等价物。
4. **平台托管语义**：按 InstallationId 作用域的状态存储、§7.4 的
   单值/事务/总预算、§41.2 state audit、与 §7.3 instance 可互换性的
   配套（权威状态在 Core-managed store）都是 Operune 平台事实。

→ 结论：单键 get/set/CAS 子集确由 wasi:keyvalue（draft 形态）表达；
但 §41.2 要求的事务、版本化迁移、崩溃恢复与平台预算/审计语义均不
被表达，且该提案在本项目 LTS 运行时中不可生产使用。`operune:state`
属于 §6.6 允许的平台领域契约。**迁移路径（§6.6）**：若 wasi:keyvalue
将来稳定（Phase 3+ 且进入 wasmtime LTS 线），重新评估；届时本契约
的键值读写面可按兼容层映射，但事务/迁移契约面仍由 Operune 自持。

### 5.2 不把线性内存当持久事实源（§41.1 / §7.3 / P8）

0.3.0 stateful 化**不回归** §7.3 的 stateless 边界：权威状态必须落在
Core-managed state store（§20.5），实例仍可互换，guest 不得把
linear memory / 实例局部变量当跨调用事实（契约注释明文，P8 版本与
状态必须可恢复）。这层"把持久事实移出 linear memory"的托管语义
（§41.1 目标原文）是 WASI 无对应物的。

### 5.3 禁止复制的 WASI 语义（P4 自检）

本 package 不定义：时间读取（`wasi:clocks`）、随机数（`wasi:random`）、
文件访问（`wasi:filesystem`）、HTTP（`wasi:http`）。不嵌入
`wasi:io@0.2` 版本特有类型（§8.2 SHOULD NOT）；不复制 wasi:keyvalue
的 bucket 模型作为内部事实。本 package 全部使用同步 func（§8.3 Gate
通过前不引入 async，§42.3）。

## 6. `operune:config@0.1.0` 的 §6.6 证明

### 6.1 wasi:config 存在——诚实论证

必须如实承认：WASI 生态存在 `wasi:config` 提案，且 wasmtime 已有
实现（`wasmtime-wasi-config` crate；wasmtime PR #11978 同时支持
`0.2.0-draft` 与 `0.2.0-rc.1`）。它的表面是：`get(key: string) ->
option<string>`、`get-all()`——**只读的扁平字符串 KV 配置**。

逐条对照 §41.2 "Config 是管理员/系统提供、具有 validation 和版本
语义的输入"：

1. **无 validation 语义**：wasi:config 是宿主注入的字符串映射，无
   任何校验面（解析、语义、业务不变量）。Operune 的 validation 是
   **契约的一部分**：Component 以 `validator` export 承担校验（P6：
   Core 永远不懂具体运维产品），Core 在写入/升级时调用并据此原子
   接受或拒绝——这一"校验由组件声明并执行、平台强制门禁"的语义
   无标准对应物。
2. **无版本语义**：wasi:config 无快照版本、无 re-validation 门禁。
   Operune 的 `config-version`（修订号 + 原子快照读取）与
   `config-schema-version`（升级 re-validation 门禁）是 §41.2 明文
   要求的输入版本语义。
3. **三分离边界（§41.2 末段）**：wasi:config 的扁平 KV 正是 §41.2
   反对的"都因为需要存储而被统一成一个无类型 KV"的形态；Operune
   config 明确区别于 state（输入 vs 产出、只读 vs 可写、无平台级
   迁移 vs 有迁移）与 secret（非敏感 vs 专门访问控制与防泄漏）。
4. **成熟度**：`0.2.0-draft/rc` 是 pre-release；wasmtime 政策明文
   pre-release 接口可随时破坏性变更。作为生产契约基座不满足 §8.3
   精神。

→ 结论：wasi:config 表达的"读扁平字符串配置"只是 Operune config
的一个退化子集（且为 pre-release）；validation、版本、原子快照、
三分离语义均不被表达。`operune:config` 属于 §6.6 允许的平台领域
契约。**迁移路径**：wasi:config 稳定后，可作为配置**交付通道**的
候选（Core 侧实现细节），但 validation/版本契约仍由 Operune 自持
（按 §6.6 显式迁移规则处理）。

### 6.2 环境变量不可替代

`wasi:cli/environment` 是裸字符串环境变量：无校验、无版本、无快照
原子性；且把配置塞进进程环境破坏 Core 对配置生命周期的托管
（§7.6 无 ambient authority 精神）。

### 6.3 禁止复制的 WASI 语义（P4 自检）

本 package 不定义：文件访问（`wasi:filesystem`）、环境变量
（`wasi:cli/environment`）、HTTP（`wasi:http`）。config 值是有界
字节 + 声明格式（json/toml/raw），非裸字符串 KV。

## 7. `operune:secret@0.1.0` 的 §6.6 证明

### 7.1 WASI 无任何 secret/credential 契约

WASI 0.2/0.3 全部已发布接口中不存在 secret / credential 管理接口；
`wasi:config` 是配置（且 wasmCloud 生态把 secret 并入 config map
是其生态设计，不是 WASI 标准语义——该做法在本项目恰恰被 §41.2
三分离明文排除）；`wasi:cli/environment` 若承载凭据正是 §16.6
禁止的暴露形态。WASI 生态没有"带名称级 grant scope、防泄漏规则、
轮换与审计"的 secret 契约。

### 7.2 防泄漏与授权是平台语义（§16.6 / §17）

- §16.6 防泄漏规则（secret 值永不进入日志/error/panic/metrics/audit；
  进程内 secrecy/zeroize 包装；at-rest 独立 SecretStore port、KEK
  与密文分离）是 Operune 安全基线的契约化表达；
- §17.3 "secret names" 是 grant scope 维度、§17.5 四层授权链（含
  调用时 enforcement）是 Operune capability 模型；
- 本契约的工程细节（错误闭集合并 `denied` 防存在性预言机、值用
  bytes 而非 string、错误变体零载荷）是标准世界不存在、也无法
  凭空"准确表达"的领域设计。

### 7.3 禁止复制的 WASI 语义（P4 自检）

本 package 不包装 `wasi:cli/environment`（凭据进环境变量正是 §16.6
排除形态）、不包装 `wasi:config`、不涉及 filesystem/http。

## 8. `operune:scheduler@0.1.0` 的 §6.6 证明

### 8.1 wasi:clocks 是读时钟，不是任务调度（诚实论证）

必须如实承认：`wasi:clocks` 已生产可用（Phase 3，wasmtime 默认
启用），monotonic-clock 还提供 `subscribe-duration -> pollable`
（睡眠原语）。但它的语义是**读时间**（now/resolution）与**睡眠**，
不是宿主侧任务调度：

- 无任务注册/取消：`schedule(id)` / `cancel(id)` 无对应物；
- 无周期触发：periodic 形态（next-fire-at + interval 序列）无对应物；
- 无宿主侧预算与背压：§7.4 "Component 生成的后台任务数量"上限、
  有界待交付队列、`missed-fires` 错过观测均无对应物；
- 无交付契约：at-most-once、无重试、无补投、cancel 竞态的确定性
  语义无对应物；
- WASI 提案列表中不存在 timers / scheduling 提案。

guest 用 wasi:clocks 自行 poll 自调度在技术上可行，但那是 guest
内部事实：无宿主侧注册/取消/预算/可观测性，且持续占用 guest CPU。
Operune scheduler 的"Core-mediated 注册 + 到期同步调用 guest export
（handler）+ 确定性背压交付"是平台托管语义（§6.6 明文列举的
平台领域）。

### 8.2 禁止复制的 WASI 语义（P4 自检）

本 package 不定义时间读取——guest 的 `datetime` 对比用 `wasi:clocks`
（本契约的 `datetime` 只用于触发时刻声明，且不嵌入 wasi:clocks 的
版本特有类型，§8.2 SHOULD NOT）；不复制 io/poll 的 pollable 睡眠
模型；不定义随机数。

## 9. `operune:event@0.1.0` 的 §6.6 证明

### 9.1 wasi:pubsub 与 wasi:http 均未表达

- `wasi:pubsub` 提案仅 **Phase 1**（CG Feature Proposal 最早阶段），
  wasmtime 官方支持表明确不支持；没有可生产的宿主实现，不能作为
  契约基座（§8.3 精神）。
- `wasi:http` 是请求/响应模型（incoming-handler / outgoing-handler），
  无推送 pub/sub 语义；且 §21.3 明文禁止组件自行 bind 端口，
  wasi:http 的授权模型（网络端点暴露面）与 Operune 的 topic grant
  scope 语义不可互证。
- Operune event bus 的 topic 级 grant scope（§17.3）、发布侧同步
  背压（`over-budget`）+ 投递侧丢弃计数（`dropped`）、Core-mediated
  投递（无 async、§8.3/§42.3 边界）、事件 id 审计关联（§41.2 audit）
  均无标准对应物。

### 9.2 禁止复制的 WASI 语义（P4 自检）

本 package 不包装 `wasi:http`、不嵌入 `wasi:io@0.2` streams/pollable
类型（§8.2 SHOULD NOT）、不复制 clocks/random/filesystem。

## 10. 0.3.0 契约与 0.4 web 演进的边界（§21.4 / §42）

0.3.0 的五个 package 是 stateful substrate：0.4.0 的完整 Web
Application Runtime（§42.2）在这些契约之上演进（复用其状态、配置、
secret、事件与背压语义），0.4 明确不重造第二套状态/事件/调度系统
（§21.4 "最小闭环 → 完整应用运行时"）；0.4 的 native realtime/stream
只在第 8.3 Gate 通过后沿标准 `stream<T>`/`future<T>` 路径演进
（§42.3），与本批同步 func 契约互补，各 package 按自身版本独立
演进（§6.6）。

### 10.1 与冻结技术选型的关系（0.3.0 批次）

- **全部同步 func，无自研 async IDL**：调度/事件交付是 Core 对
  guest export 的同步调用（与 0.1.0 actions 同构），不需要 async
  func；`stream<T>`/`future<T>` 只在 §8.3 Gate 通过后走标准路径
  （§42.3），不因此引入第二套 IDL（P3）。
- **不嵌入 WASI 版本特有类型**：本批契约自持 `datetime`/`duration`
  等类型，不嵌入 `wasi:io@0.2` / `wasi:clocks` 版本类型（§8.2
  SHOULD NOT）；WASI 0.2 → 0.3 迁移由 adapter crate 承担。
- **资源治理一致**：全部宿主侧上限（值体积、任务数、队列深度、
  预算）按 §7.4 语义在 Core 侧执行并在契约注释中对应（§6.6 论证
  与实现可核对）。
- **参考 world 不是运行时事实源**：`operune-state-component`、
  `operune-config-component`、`operune-secret-component`、
  `operune-scheduler-component`、`operune-event-component` 仅供
  作者侧打包参考；Core 的识别与兼容判断只依赖二进制中真实可观察
  的 exports/imports（§6.7）。

### 10.2 语法校验状态

本机无 wasm-tools；`operune:web@0.2.0` 批次的全部文件已用临时验证工具
witverify（wit-parser **0.236.1**，仅存在于本机临时目录，不入库）完成
解析与结构校验（结果见 §11.7）。0.3.0 五包与 0.1.0 首批在本批次中做了
同工具回归，全部通过。bindgen / wasm-tools 集成验证仍在 0.1 / 0.4
implementation PR 阶段执行。

---

# 0.4.0 Web Application Runtime 契约（§42）的 §6.6 证明

## 11. `operune:web@0.2.0` 的 §6.6 证明

`operune:web@0.2.0` 是 0.1.0 web bridge 的版本化演进（§21.4：
"最小闭环 → 完整应用运行时"，不是两套 Component Web 系统）。0.1.0 的
§6.6 论证（本 README §2：assets ≠ wasi:filesystem、actions ≠ wasi:http
包装、mount namespace 与原子版本）在本版本继续成立（语义继承，见
package 注释）；以下论证 0.4.0 **新增**声明面（§42.2 的 navigation /
routes / permissions 及其运行期形态）为何属于 §6.6 允许的平台领域语义。
§42.4 的 Web compatibility / conformance suite（测试 Component 仅凭标准
`.wasm` 提供完整 UI + backend）是验收侧产物，不属于 WIT 面。

### 11.1 app descriptor / navigation / pages

- **Component Model 只表达接口结构，不表达"应用由哪些页面构成"。**
  §6.7 的 contract surface（接口结构 / 类型关系）与"应用导航模型"
  （页面列表、默认页、页面路径、页面权限）是正交事实：二进制可观察
  exports 无法推导导航语义，必须由显式声明契约承载——这与 0.1.0
  web-descriptor 的"作者声明的 Web 能力声明"（§2.1 同款论证）同构，
  app descriptor 是其超集演进。
- **wasi:http 无导航概念。** incoming-handler 是"组件收发通用 HTTP"，
  无页面 / 路由注册、无默认页、无挂载点下导航的宿主托管模型；且
  §21.3 明文禁止组件自行 bind 监听端口（wasi:http 的授权模型是网络
  端点暴露面，与 Operune 的 InstallationId grant 链不可互证，§2.2
  同款论证）。
- **Web 平台（浏览器）不托管组件驱动的应用声明。** 页面列表 / 默认页 /
  导航策略由 Core 在 sandboxed frame + restrictive CSP 边界内执行
  （§21.3 最低隔离 + 0.4 完整 navigation / embedding policy，§42.2）；
  标准世界没有"宿主托管组件 Web 应用的导航声明"模型。
- 页面 / 路由路径解析到 Core 分配的 mount namespace（§21.3），路径
  规范化与越界校验是 §21.3 / §32 平台安全语义（防 path traversal）。

### 11.2 typed route / action registration + route namespace + conflict diagnostics

- **wasi:http 无路由注册语义。** wasi:http 没有 route-id、HTTP 方法 +
  路径模板 + 参数类型的声明模型，没有"宿主托管的路由表"；组件自持
  路由要么靠自解析请求路径（把 Core 的桥当透明代理，破坏 §21.3 的
  Core-mediated 检查点），要么动态 bind 端口（§21.3 明文禁止）。
- **route namespace 是 mount namespace 的扩展（Core 分配、不可冲突）。**
  与 0.1 挂载命名空间同款论证（§2.3）：平台托管语义，标准世界无对应。
- **声明期 conflict diagnostics 是平台状态机语义。** 冲突检测发生在
  安装 / 激活的 descriptor 校验阶段，确定性（同一 ContentDigest + 同一
  contract version 得到同一诊断闭集，§19.3 精神），冲突 candidate 保持
  quarantine / failed；WASI / Component Model 无"安装期声明校验"状态机。
- typed action 的结构化参数（param-type / param-value 闭集）兑现 0.1.0
  actions 注释承诺（"0.4.0 的 typed action 将提供结构化参数"），是
  Core 分发前按声明校验的平台语义（§22.4 精神：禁止万能动态值 payload）。

### 11.3 page / action permission declarations

- **WASI / Component Model 无组件声明权限要求的契约面。** WASI 的授权
  是宿主侧能力注入（preopen、socket 授权等），不存在"组件声明页面 /
  action 需要的命名权限 + 宿主声明期校验 + 运行期强制执行点"的模型；
  组件自身无从表达，宿主亦无从验证声明一致性（§6.7 交叉校验精神）。
- **enforcement 是 Core 平台语义。** 页面请求与 route 调用经
  Core-mediated bridge，服务端重新执行 authentication → RBAC → grant →
  page / action permission 检查（§17.5 四层授权链 / §21.3），未授权以
  确定 HTTP 语义拒绝；permission-name → grant scope 的映射与求值是
  Core 政策。§43（0.5.0）的 scoped capability policy 是后续细化，不
  改变 0.4 "声明面 + Core 强制执行点"的形态。
- 本声明只有命名引用（字符串等价比较），不含凭据 / 角色字段（§21.3
  凭据边界），无泄漏面。

### 11.4 bounded request / response + cancellation 无条件 baseline

- 0.1 论证（§2.2 actions ≠ wasi:http 包装）延续：0.4 的 typed route
  调用仍是 Core-mediated 有界一次调用，不是网络端点。
- cancellation / disconnect 语义（Core 侧 deadline、epoch interruption
  中止、响应交付不保证、已提交副作用不回滚 + operune:state 事务原子性，
  §20.5）、per-Component HTTP quotas / backpressure（超配额以确定 HTTP
  语义拒绝，不进 guest 错误空间）是**平台执行语义**：WASI p2 没有
  "宿主取消 host → guest 调用"的契约，也没有按 InstallationId 的配额
  治理模型。

### 11.5 P4 自检（禁止复制的 WASI 语义）

本 package 不复制：`wasi:io/streams` / `pollable`（契约中无
`stream<T>` / `future<T>` / poll 类型，§42.3）、`wasi:http`（不包装
incoming-handler）、`wasi:filesystem`、`wasi:clocks` / `wasi:random`。
全部 func 为同步有界形态；不嵌入任何 WASI 版本特有类型（§8.2 SHOULD
NOT）；没有第二套 IDL（P3）。0.4 的 native realtime / stream 只走标准
`stream<T>` / `future<T>` / async 路径，且必须在 §8.3 WASI 0.3
production Gate 通过后以**新 interface 版本**顺延加入（§42.3），本
版本明确不包含，未通过 Gate 时验收不得假装该能力已存在（§42.4）。

### 11.6 0.1 → 0.2 兼容策略（§21.4 不重造第二套 bridge）

**设计选择：新 package 版本 `operune:web@0.2.0` 内全量定义契约面**
（`assets` / `actions` 以与 0.1.0 相同的类型形态重新定义、行为语义注释
继承 0.1），而非"0.2.0 增量引用 0.1.0 接口"。理由：

1. **flags 扩展本身就是破坏性变更**：0.1.0 `web-features`
   （static-assets / backend-actions）无法在版本内添加 flag（flags 成员
   变化即类型变化，§4 "WIT record 添加字段是破坏性变更"同款规则）；
   0.4 的 app descriptor 必须扩展 features（navigation / typed-routes /
   permissions），descriptor 演进因此必然落到新 package 版本；
2. **单版本 contract surface**（§6.7）：新组件以 0.2.0 表面表达全部
   能力，Core 的兼容判断不跨版本拼装组件表面；同一语义角色（assets /
   actions）在 0.2.0 表面下携带 0.4 语义（caching / integrity、typed
   入口），并非机械复制；
3. **解析 / 工具链独立**：`operune/web@0.2.0/` 目录单独可解析，不要求
   0.1.0 同在解析图（无跨版本 `use` 边）；
4. **不重造第二套 bridge**（§42.2 明文）：0.2.0 的 assets / actions 是
   0.1 同一桥接实现的**版本分发表面**，不是第二个实现——asset 缓存键
   （ContentDigest + asset path）、Core-mediated 检查点、§21.3 隔离底线
   全部相同。

**旧 0.1 组件继续可运行（无 flag-day，§8.4 精神）**：

- `operune:web@0.1.0` 契约保持冻结且永久受支持：0.1 组件只导出 0.1.0
  表面即按 0.1.0 语义服务（assets / actions / web descriptor / §21.3
  隔离底线 / §21.5 原子版本全部不变），升级到 0.4 runtime 不要求旧组件
  重新导出或迁移（不强制旧组件接受 0.2.0 面）；
- Core 按二进制可观察的 contract surface（§6.7）分发：同一语义角色
  同时出现 0.2.0 与 0.1.0 表面时，确定性规则为**优先 0.2.0、回退
  0.1.0**；同一 ComponentVersion 的 descriptor / assets / backend
  exports 仍属于同一版本，升级整体原子切换（§21.5），不存在"前端 v2 +
  后端 v1"拼接。

### 11.7 语法校验状态

`operune:web@0.2.0` 全部 8 个文件已用本机 wit-parser **0.236.1**
（临时验证工具 witverify，位于本机临时目录，不入库）验证通过：

- **全包解析 PASS**：8 个 package（component、web@0.1.0、web@0.2.0、
  state、config、secret、scheduler、event）同一 Resolve 解析，含
  web@0.2.0 world 对 `operune:component/descriptor@0.1.0` 的跨包引用；
- **关键字核对 PASS**：全部标识符位置（类型名、字段名、case 名、flag
  名、参数名、func 名、world 名、world item）对照 wit-parser 0.236.1
  全关键字表，无保留字（含 from / use / type / async / stream / future /
  error-context / _ 等）；
- **结构惯例 PASS**：每包恰好一个文件在 package 声明前携带包级注释
  （web@0.2.0 → app-descriptor.wit）；所有类型定义在 interface 内；
  world 只引用 interface 名（+ 显式版本化的跨包引用）。

bindgen / wasm-tools 集成验证在 0.4 implementation PR 阶段执行。
