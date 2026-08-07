# Operune 公共 WIT 契约（0.1.0 首批）

本目录是 Operune 0.1.0 首批公共平台契约（规范 §6.6），全部为**标准 WIT 语言**
（P3：WIT 是唯一跨边界接口契约；不引入任何私有 IDL / 协议）。

| Package | 目录 | 内容 |
|---|---|---|
| `operune:component@0.1.0` | `operune/component/` | `descriptor`（Component 身份与平台 metadata 声明）+ 参考 world |
| `operune:web@0.1.0` | `operune/web/` | `descriptor`（Web UI 声明）、`assets`（内嵌静态资产列举/读取）、`actions`（有界 backend action）+ 参考 world |

WIT package 版本是**接口契约版本**，不是 Core Runtime 发布版本的别名（§6.6）。

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
- 若未来标准（Component Model / WASI）覆盖某项自定义能力，按 §6.6
  通过显式版本化与兼容层迁移，不静默重解释旧 package。
