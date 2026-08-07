# ADR-0001：SecretStore 密文加密原语与跨平台 key provider 选型（0.3.0）

- 日期：2026-08-08
- 状态：**Proposed（待 Owner 裁决）**
- 决策类别：**Owner Gate**（§25.10 / D10：改 authentication/session security 基线、改数据持久化核心模型；§50："AI Agent 可以起草 ADR，但第 25.10 列出的 Owner Gate 决策不得自行标记 Accepted"）
- 关联规范：§16.6（Secret 的内存与持久化边界）、§41.2（0.3.0 MUST Scope）、§11（第一方 100% Safe Rust）、§23.1（新增依赖 Gate）、§18.4（schema migration）、§24.2（依赖方向）
- 关联代码：`crates/security/src/secret.rs`（`SecretBytes`，secrecy+zeroize）、`crates/storage-sqlite/`（schema/migration/executor）、根 `Cargo.toml` `[workspace.dependencies]`（§22 冻结清单）

---

## Context

### 需求（§41.2 / §16.6）

0.3.0 Stateful Runtime 的 MUST Scope 包含：独立 `SecretStore` port 与 secret grant/read semantics、secret at-rest protection、跨平台 key-provider ADR。§16.6 明确规定：

- 普通 SQLite metadata 表**不得保存明文 secret**；
- 加密存储时，密钥加密密钥（KEK）**不得与密文以等价保护级别存放在同一 SQLite 数据库中**；
- 具体跨平台 key provider 在 0.3.0 前**通过 ADR 冻结**，并继续遵守第一方 Safe Rust Gate；
- `secrecy` / `zeroize` 只解决进程内暴露面，不构成 at-rest secret storage。

§41.3 验收：Secret 的读取、拒绝、轮换与审计必须可验证，且**普通 SQLite metadata dump 不得直接暴露 secret 明文**。

### 现状

- 内存边界已落地：`crates/security/src/secret.rs` 的 `SecretBytes`（secrecy `SecretBox` + zeroize，Debug 掩码 `[REDACTED]`，无 Display/Serialize/PartialEq）。at-rest 侧**尚无任何实现**。
- 依赖现状：§22 冻结的 `[workspace.dependencies]`（2026-08-07 crates.io 校验，见 `DEPENDENCY_PROBE.md`）**当前没有加密库**——security 侧只有 `argon2`、`secrecy`、`zeroize`、`getrandom`（OS CSPRNG）、`sha2`、`subtle`、`base64`、`cookie`。其中 `getrandom` 可用于随机 nonce 生成，**不需要为此新增依赖**。
- 第一方 Safe Rust Gate：§11.1 `#![forbid(unsafe_code)]` 全仓库机械强制；§11.3：某项平台能力只有第一方 unsafe/FFI 可实现且找不到成熟 safe crate 时，**能力不得进入当前版本**。
- 持久化载体：`crates/storage-sqlite/` 已有版本化、事务化、forward-only 的 migration 机制（§18.4），可承载新增 secret 密文表。依赖方向已冻结：`storage-sqlite → application → domain`；storage-sqlite **不依赖 security**（见其 Cargo.toml）。因此加密实现必须位于 SecretStore 服务侧（security/application 层），storage-sqlite 只接触**不透明密文 BLOB**，不感知加密细节。
- 契约现状：SecretStore 是 0.3.0 **全新 port**（§41.2），无既有 WIT/持久化契约被破坏。

### 约束（本 ADR 必须满足）

1. 普通 SQLite metadata 表不得保存明文 secret（§16.6，MUST）。
2. KEK 不得与密文以等价保护级别存放在同一 SQLite 数据库（§16.6，MUST）——本 ADR 的选型直接受此条款约束。
3. key provider 选择在 0.3.0 前冻结（§16.6，MUST），且是第一方 Safe Rust 允许的方式（§11）。
4. 任何新增 direct dependency 必须通过 §23.1 九问（维护/license/unsafe 面/热路径/平台影响/类型泄漏等）。
5. 0.x 兼容承诺：不得破坏既有 metadata 表与 migration 契约（§18.4 forward-only）。

---

## Decision（推荐方向，待 Owner 裁决）

**0.3.0 采用「方案 A：审计过的 AEAD 加密原语 + 方案 C：`data_root` 下独立权限目录承载文件 KEK + 权限约束」的组合；不引入 OS 级 key provider；OS provider 作为明确声明的未来演进路径保留。** 具体加密原语二选一（见下），亦待 Owner 裁决。

### 决策点 1：密文加密原语（方案 A）

推荐 **RustCrypto `chacha20poly1305` 0.11 线**（或其 `XChaCha20Poly1305` 变体；备选 `aes-gcm` 0.11 线，二选一由 Owner 裁决）。

- **§23.1 九问评估（chacha20poly1305 0.11）**：

  1. **解决哪个需求**：SecretStore at-rest 密文的 AEAD 加密（§16.6/§41.2 MUST）。
  2. **标准库/现有依赖为什么不足**：标准库无 AEAD；现有冻结清单中的 `sha2`/`subtle`/`base64` 均非 AEAD；自研加密被 §22.9/§52 明确禁止（"不用自研 crypto"）。
  3. **active maintenance**：RustCrypto/AEADs 仓库，0.11.0 于 2026-06-28 发布（Rust 2024 edition，MSRV 1.85 < 本项目 1.97.1）；持续维护，下载量级百万/月级。实施时须按 §23 Gate 复核 crates.io 最新版本与 rustsec advisory（本 ADR 冻结的是"选型方向与算法"，不是具体版本号）。
  4. **license**：MIT/Apache-2.0 双许可，与现有依赖栈一致（项目自身许可证待 Owner 决策，cargo-deny allowlist 届时一并处理，§23.4）。
  5. **native system dependency**：无——纯 Rust、`no_std` 兼容，无 C/OpenSSL 链接。
  6. **平台影响**：x86/x86_64/aarch64 均可用；`chacha20poly1305` 的可选 AVX2 路径与 `aes-gcm` 的可选 AES-NI/CLMUL 路径均在 crate 内部做架构分支，第一方无需平台特定代码；对 static candidate 无影响。
  7. **unsafe/FFI 面**：纯 Rust 实现；可选硬件加速路径由 crate 内部以 unsafe 实现——属第三方，符合 §11.2（只通过第三方 safe API 访问需要 unsafe 的能力，供应链面受 §23 审计约束）。两个 crate 均经 **NCC Group 审计（MobileCoin 资助），无重大发现**。
  8. **热路径**：SecretStore 读写非热路径（低频 grant/read/rotate），性能影响可忽略，无需 benchmark；但仍避免在 hot path 上分配——AEAD 一次性调用即可。
  9. **类型泄漏**：仅通过 `aead::AeadInPlace` trait 使用（`chacha20poly1305` 会 re-export `aead`，不新增 direct 依赖）；第三方类型不进入 Domain/public contract，在 SecretStore 服务内部消化。

- **算法与 nonce 布局（推荐冻结为 0.3 密文 envelope 契约）**：
  - 推荐 **XChaCha20Poly1305**（192-bit nonce）：随机 nonce（`getrandom`，已有冻结依赖）即可安全使用，无需维护计数器状态——避免"nonce 复用"这一类最典型的人为错误；若 Owner 选择 aes-gcm 线，则相应采用 96-bit 随机 nonce 并约束复用窗口（或选用 `aes-gcm-siv` 型 misuse-resistant 变体——注意其无认证的 misuse 警告语义，需在实施 ADR 中再评估）。
  - 密文 envelope 必须携带：`算法标识 + 版本 + nonce + 密文+tag`。版本字段为未来换算法/换 provider 预留，不做破坏性变更。
  - 明文 secret 到密文的转换边界：`SecretBytes`（内存）→ SecretStore 服务内加密 → 不透明 BLOB 交 storage-sqlite 落库；storage-sqlite 不感知加密（保持 §24.2 依赖方向，不新增 storage-sqlite → security 依赖边）。

### 决策点 2：KEK 承载方式（方案 C）

- KEK 文件位于 `data_root` 下**独立权限目录**（例如 `<data_root>/secretstore/`，与 SQLite metadata DB 文件不同目录、不同文件、不同权限集），**绝不放进 SQLite**。
- 权限约束：Unix 目录 0700 / 文件 0600（`data_root` 本身已是受控宿主事实）；Windows 侧通过文件 ACL 限定当前用户（实现细节在实施 PR 冻结，若第一方无法以 safe 方式设置 ACL，退化为继承 `data_root` 权限并在文档中声明——见 Security impact 的诚实边界）。
- **诚实声明保护等级**：本组合提供的保护是"**对能读到 SQLite 文件/备份但拿不到 KEK 的 attacker**（如日志收集、错误上传、备份文件散落）的机密性"，**不是**对"与运行进程同一用户/权限的本地 attacker"的隔离——同权限用户可以读 KEK 文件（进程本身也持有 KEK）。该边界必须在文档与产品说明中明示。
- **与 §16.6 的关系**：密文与 KEK 保护级别**不同质**——密文是 AEAD 混淆后的字节（无 KEK 不可读），KEK 是明文密钥文件；二者不同文件、不同目录、不同权限、不同备份语义。满足"KEK 不得与密文以等价保护级别存放在同一 SQLite 数据库"的条款与安全意图。

### 决策点 3：OS provider 的未来演进路径（方案 B，0.3.0 不引入）

- SecretStore port 的 WIT 契约与 provider 抽象从第一天就为 OS credential provider 留位：**加密原语的选择、密文 envelope 版本字段、`KeyProvider` trait（`FileKekProvider` | 未来 `OsCredentialProvider`）** 都是 port 的实现细节，不进入 WIT；0.x 内 provider 切换不破坏组件契约。
- 未来（建议 0.4+，单独 ADR）按平台分别评估：Windows Credential Manager / DPAPI（`windows` crate 官方 safe 封装）、macOS Keychain（`security-framework` safe crate）、Linux Secret Service（`keyring` crate 的 zbus 后端）或 keyutils。届时 KEK 由 OS 保护，攻击者需取得 OS 层身份凭据才能解锁——比方案 C 高一个保护等级。
- **切换路径现在就要可定义**：见 Migration/rollback——重加密路径（旧 KEK 解密 → 新 KEK 重加密 → 原子提交 → 删除旧 KEK）在 0.3.0 以 `KeyProvider` trait + envelope 版本字段的形式预留接口，实际实现随未来 provider ADR。

---

## Alternatives considered

### 方案 B：OS 级 key provider（Windows DPAPI/CNG、macOS Keychain、Linux keyutils/Secret Service）

评估结果：

- **Safe Rust 封装可得性不一致**：
  - Windows：Microsoft 官方 `windows` crate 为 `CryptProtectData`/CNG 提供 safe API 封装（`windows::Win32::Security::Cryptography`），成熟；但 meta-crate 依赖面大，或以 `windows-sys` 手动绑定（维护成本高）。
  - macOS：`security-framework` crate 提供 Keychain 的 safe 封装，成熟但绑定系统 framework。
  - Linux：keyutils 无同等成熟的第一方 safe 封装（`keyutils` crate 封装不完整、C FFI 面）；Secret Service 需走 D-Bus（`zbus` 纯 Rust 或 `dbus` + `libdbus-sys` 引入 native 构建依赖）。
  - 统一抽象候选 `keyring` crate（keyring-rs）：三平台后端抽象成熟（3.x 广泛使用，4.x beta），但 Linux 默认 keyutils 为 **session-scoped、重启即丢**（对长期运行的服务是灾难性 KEK 丢失面），切 D-Bus Secret Service 后端又引入 D-Bus 依赖与守护进程可用性问题。
- **跨平台一致性**：三平台后端的持久性、解锁时机、无头场景行为不一致（headless server 无 D-Bus session；macOS Keychain 首次访问可能弹 UI；Windows 无桌面 session 时 Credential Manager 可用性受限）。0.3.0 的主要部署形态恰恰是本地 server / Edge——Linux 无头场景是**主场景**，而该场景在方案 B 中是最弱、最不可靠的。
- **本机可测性**：Windows/macOS CI runner 可测各自后端，但 Linux headless CI 无 Secret Service 守护进程，测试矩阵三平台行为不一致，无法建立统一的可靠验收。
- **§23.1 Gate**：引入 OS/native 系统依赖（Gate 5）；依赖树显著增大（zbus/security-framework/windows）；第三方 unsafe 面增大（Gate 7，虽由 safe 封装承担，供应链审计面扩大）；三平台行为差异使其成为高维护面。

### 方案 C（纯文件 KEK + 权限，不加密）

评估结果：见"为什么其他方案不选"。单纯文件权限方案无密码学保护，只区分"同用户/其他用户"，且 KEK 与密文保护级别**等价**，不符合 §16.6 的安全意图。

### 其他被排除的方案

- **明文存 SQLite**：直接违反 §16.6/§41.2 MUST——排除。
- **自研加密原语**：§22.9/§52 明确禁止自研 crypto——排除。
- **密钥派生（KDF 自口令）**：Component secret 是无交互的机器凭据，引入"主口令"语义破坏无头部署与轮换模型，且口令管理的风险大于收益——排除。
- **HSM/TPM**：0.3.0 无能力评估与交付面，且涉及平台驱动与第一方 unsafe 风险，违反 §11.3 当前阶段约束——排除（不阻止未来 ADR 单独评估）。

---

## 为什么其他方案不选

### 不选方案 B（OS provider）作为 0.3.0 默认

1. **第一方 Safe Rust Gate 不构成否决因素，但封装成熟度决定可行性**：三个平台能通过第三方 safe crate 满足 §11（windows / security-framework / keyring），但 Linux 主场景（无头 server）中 keyutils 不持久、Secret Service 依赖 D-Bus 守护进程，**"一套 API、同等保护"的跨平台承诺在三平台不成立**——违反语义一致，且把 0.3.0 主部署形态放在最弱后端上。
2. **§23.1 Gate 结论**：引入 native system dependency（Gate 5）与大幅膨胀的第三方 unsafe 依赖面（Gate 7）与 zbus/security-framework/windows 依赖树（维护与 advisory 面扩大），相对 0.3.0 实际要解决的需求（本地 server 单机 at-rest 保护）收益不足；本机可测性（Gate 6 相关）三平台不一致，验收不可统一。
3. **方案 B 的保护等级对"同用户本地 attacker"同样不成立**：OS keyring 在进程以用户身份运行时通常可被同用户进程读取，**不能**为 0.3.0 的目标威胁模型提供本质更高的保护；其真正价值（防备份散落、防跨用户读取）用"方案 A + 方案 C"已能覆盖大部分，且无平台一致性代价。
4. **不是不选，是延后**：方案 B 作为明确的未来演进路径保留（决策点 3），其引入以"本机可测性、headless 场景可靠性、依赖 Gate 通过"为前置条件，随单独 ADR 进入。

### 不选纯方案 C（文件 KEK + 权限，无加密原语）

1. **保护等级不足**：备份/同步/日志收集场景中，`data_root` 目录树常被整体复制——无加密时 KEK 与密文（其实是明文）同备份、同权限，等于明文外泄。
2. **与 §16.6 冲突**：条款要求"KEK 不得与密文以等价保护级别存放"。纯权限方案中 KEK 与（明文）数据同为文件系统权限保护，保护级别等价，违背条款的安全意图；只有引入密码学（方案 A）才使两者不同质。
3. **无法兑现 §41.3 验收的完整含义**：§41.3 要求"普通 SQLite metadata dump 不得直接暴露 secret 明文"——纯方案 C 中 SQLite 本身不存 secret（kept 在 KEK 目录或另一文件），可勉强绕过字面验收，但那是形式合规而非真实保护；本 ADR 拒绝以绕过形式验收替代真实防护。

---

## 对五要素审计的影响

### 哲学统一

Safe Rust Gate 完整保持：本决策**不引入任何第一方 unsafe/FFI**；AEAD 原语经第三方 crate 的 safe API 使用（§11.2 允许），KEK 文件 I/O 走标准库。§11.3 得到遵守——本就没有第一方 safe 封装方案的 OS 能力（Linux keyutils 等）不进入 0.3.0，宁缺毋滥。能力最小授权（§17）语义延续：SecretStore 是独立 port，secret grant/read 走既有四层授权链（Contract Need → Resolution → Grant → Invocation-time Enforcement），本 ADR 不改变该模型。

### 语义一致

"Secret" 概念在各层保持同一含义：内存中 `SecretBytes`（§16.6 现有实现）→ SecretStore 服务内密文（AEAD envelope，携带算法标识/版本/nonce）→ SQLite 中**不透明 BLOB** → WIT 的 SecretStore port 语义（`secret-grant` / `secret-read` / rotation）。"KEK"、"密文"、"provider" 术语与 §16.6/§41.2 字面一致，不引入同名异义（例如不把 KEK 称作 "master key" 之外的别名、不把密文 BLOB 称作文本字段）。storage-sqlite 对密文的语义是"不透明字节"，与 §13.3 边界解析一次原则一致。

### 逻辑自洽

- **KEK 丢失/损坏**：所有以该 KEK 加密的 secret 不可解密——必须 fail closed（明确错误，绝不回退到明文或静默返回空），错误语义与 §18.4 "SchemaTooNew/TooOld fail closed" 一致。
- **密文损坏**：AEAD tag 校验失败 → 明确错误，绝不部分解密。
- **无循环依赖**：加密在 SecretStore 服务侧，storage-sqlite 不感知加密（不新增 storage-sqlite → security 依赖边，§24.3 依赖方向不变）。
- **nonce 模型**：XChaCha20Poly1305 随机 nonce 无状态、无复用窗口管理义务（若 Owner 选 96-bit 线，则必须实现计数器/约束复用窗口——逻辑自洽要求在该选型下把 nonce 管理变成显式状态，而非默认安全）。
- 轮换与 provider 切换的读取/写入顺序在 Migration/rollback 中定义，无"切换一半"的中间状态。

### 真实有效

- `chacha20poly1305` / `aes-gcm` 0.11 线为 2026-06-28 发布的稳定版（Rust 2024 edition，MSRV 1.85 < 项目 1.97.1），是广泛部署、经 NCC Group 审计（无重大发现）的成熟实现——"经审计"是已发生的事实，不依赖未来承诺。**版本号与 advisory 状态在实施 PR 时按 §23 Gate 以 crates.io/rustsec primary source 复核**（本 ADR 冻结算法与选型方向，不冻结版本快照）。
- 不把 OS provider（keyring/Secret Service）写成 0.3.0 的生产承诺：Linux headless 场景的 D-Bus 可用性、keyutils 持久性等限制基于已知平台事实，不基于想象。
- 保护等级声明（"同用户本地 attacker 不在本方案防御范围"）是诚实边界，不是营销措辞。

### 完整可靠

失败路径全覆盖：KEK 文件缺失、KEK 文件损坏、KEK 权限不足、密文 BLOB 损坏（tag 失败）、nonce 冲突（若 96-bit 线）、磁盘写满、写中途 crash（KEK 文件写入采用"临时文件 + rename"原子替换，或同等语义，实施时冻结）、备份目录整体复制场景。安全退化路径：加密失败时**拒绝写入**（fail closed），不降级为明文存储。审计事件（§41.2 "state/config/secret audit"）：secret 的 read/deny/rotation 与 KEK 访问失败必须记录，KEK 值与 secret 值永不进日志（§16.6）。测试覆盖：错误注入（损坏 KEK、损坏密文）、轮换、provider 切换演练、并发读写下的一致性——在 SecretStore 服务侧以 test-only provider 注入实现，不依赖真实 OS keyring。

---

## Compatibility impact

- **0.x 版本内**：SecretStore 是 0.3.0 全新 port（§41.2），无既有 WIT/持久化契约被破坏；本 ADR 只向 storage-sqlite **新增** secret 相关表（密文 BLOB），走既有版本化 migration（§18.4），不改动既有 metadata 表与表内行。
- **未来 OS provider 演进**：WIT 层的 SecretStore port 契约稳定不变——key provider 是 port 内部实现细节（`KeyProvider` trait + `FileKekProvider` / 未来 `OsCredentialProvider`），不进入 WIT，0.x 内 provider 切换不破坏组件契约。密文 envelope 携带算法标识与版本字段，保证未来换算法/换 provider 时旧密文仍可读取（重加密路径见 Migration/rollback）。
- **依赖冻结清单**：新增 `chacha20poly1305`（或 `aes-gcm`，待 Owner 裁决）作为唯一新增 production direct dependency（`aead` trait 经其 re-export，不新增 direct 依赖；nonce 用既有 `getrandom`）。按 §23.2 精确版本约束写入 `[workspace.dependencies]`，独立 PR + Gate。

---

## Security impact

**威胁模型（本方案防御的）**：

1. 本地 attacker 只能读到 SQLite metadata 文件/备份（日志收集、备份散落、误上传、WAL 残留）→ 获得 AEAD 密文，无 KEK 不可读，且 §41.3 验收"metadata dump 不得暴露明文"通过；
2. 读 KEK 文件 → 需与运行进程同等的文件系统权限（Unix 0700/0600；Windows ACL 限定当前用户），且需知道独立目录位置。

**诚实边界（本方案不防御的）**：与运行进程同用户/同权限的本地恶意进程可读 KEK（进程内存本就持有 KEK）——这是 OS credential provider / HSM 的领域，方案 B 同样不防御同用户进程读取 keyring 内容。此边界必须在文档与产品说明中明示，不得宣称"系统级安全存储"。

**不引入的泄漏面**：secret 值/KEK 值不进日志、error context、panic report、metrics label、audit event（§16.6）；`SecretBytes` 不实现 Debug/Display/Serialize 的既有约定延续到密文路径（密文 BLOB 的 Debug 也须掩码）；KEK 文件权限设置失败时 fail closed（拒绝启动 SecretStore），不静默降级。

---

## Migration/rollback

- **0.3.0 内**：SecretStore 为新增能力，**无存量数据迁移**；新增 secret 表走既有 migration 机制（版本化、事务化、forward-only，§18.4）。0.x downgrade 不提供（既有 release contract：打开更高版本数据库立即失败），回退旧版本仅意味着丢失 SecretStore 新功能，不破坏既有数据。
- **未来 key provider 切换（OS provider 引入时）**：重加密路径在 0.3.0 就以 `KeyProvider` trait 与 envelope 版本字段定义接口：
  1. 以旧 provider（文件 KEK）解密全部 secret；
  2. 以新 provider（OS keyring）的新 KEK 重加密，写入新 envelope（版本标记）；
  3. **原子提交**（同一事务/先写后验）：全部新密文落库并验证通过后，才删除旧 KEK 文件；
  4. 任一步失败 → 保持旧 provider 可读，明确报错，无"切换一半"状态。
  - 该路径的实际实现随未来 provider ADR 落地，本 ADR 只冻结接口与顺序语义。KEK 轮换（不换 provider）复用同一重加密路径。

---

## Status

**Proposed —— 待 Owner 裁决。**

依据：§50"AI Agent 可以起草 ADR，但第 25.10 列出的 Owner Gate 决策不得自行标记 Accepted"；§25.10（D10）将"改 authentication/session security 基线"、"改数据持久化核心模型"列为必须 ADR + Owner review 的决策，本 ADR 的 key-provider / at-rest 加密选型属该类别。本文件由 AI Agent 起草，不自行推进为 Accepted；Owner 裁决后按需修订（算法二选一、0.3.0 范围、依赖 Gate 批准），并在实现 PR 前确定最终版本快照。

**待 Owner 裁决的问题**：

1. **加密原语二选一**：`chacha20poly1305` 0.11（推荐，XChaCha20Poly1305 随机 nonce 无状态）vs `aes-gcm` 0.11（生态更普及，96-bit nonce 需约束复用或选 SIV 变体）。
2. **0.3.0 范围**：确认"方案 A 加密 + 方案 C 文件 KEK + 权限"组合作为 0.3.0 冻结方案，OS provider 延后至 0.4+ 单独 ADR。
3. **依赖 Gate 批准**：确认新增 `chacha20poly1305`（或 `aes-gcm`）为唯一新增 production direct dependency（§23.1 九问评估见"决策点 1"，版本快照实施时复核）。
4. **KEK 文件目录形态**：`<data_root>/secretstore/` 独立权限目录的确切路径、权限设置方式与 Windows ACL 处理（若第一方无法以 safe 方式设置 ACL 时的降级声明）。
