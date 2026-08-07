# DEPENDENCY_PROBE — §22 依赖基线校验报告（审计证据）

- 校验日期：2026-08-07（与规范 §22 冻结快照同日）
- 校验方法：逐 crate 查询 crates.io API `https://crates.io/api/v1/crates/<name>`（官方 primary source，§4.3 要求重新查询 primary source）
- 判定规则（按任务规定）：
  - 精确版本存在 → 采用精确版本；
  - 精确版本不存在但同 major 系存在 → 采用同 major 最近发布版本，并列为偏差；
  - Wasmtime 三件套必须同 release line，禁止混搭。
- 本机环境：rustc/cargo 1.97.1（x86_64-pc-windows-msvc）；网络探测使用 curl + crates.io API，单请求硬超时 25s，全部 35 个 crate 均成功返回（wasmtime、clap 首次返回截断，已重取成功）。

## 校验结果总表

| # | Crate | §22 规范版本 | 校验结果 | 采用版本 | 备注 |
|---:|---|---|---|---|---|
| 1 | wasmtime | 36.x LTS 线 | LINE_OK | 36.0.13 | 36.x 线存在；36.0.13 为 2026-08-07 已发布的最新 36.x patch |
| 2 | wasmtime-wasi | 36.x LTS 线 | LINE_OK | 36.0.13 | 与 wasmtime 同 release line ✓ |
| 3 | wasmtime-wasi-http | 36.x LTS 线 | LINE_OK | 36.0.13 | 与 wasmtime 同 release line ✓ |
| 4 | tokio | 1.53.1 | EXACT | 1.53.1 | 精确存在 |
| 5 | tokio-util | 0.7.19 | EXACT | 0.7.19 | 精确存在 |
| 6 | axum | 0.8.9 | EXACT | 0.8.9 | 精确存在 |
| 7 | tower | 0.5.3 | EXACT | 0.5.3 | 精确存在 |
| 8 | tower-http | 0.7.0 | EXACT | 0.7.0 | 精确存在 |
| 9 | rustls | 0.23.42 | EXACT | 0.23.42 | 精确存在（上游已有 0.23.43，按 §22.0 不升级） |
| 10 | tokio-rustls | 0.26.4 | EXACT | 0.26.4 | 精确存在 |
| 11 | askama | 0.16.0 | EXACT | 0.16.0 | 精确存在 |
| 12 | rusqlite | 0.40.1 | EXACT | 0.40.1 | 精确存在 |
| 13 | serde | 1.0.229 | EXACT | 1.0.229 | 精确存在 |
| 14 | serde_json | 1.0.151 | EXACT | 1.0.151 | 精确存在 |
| 15 | toml | 1.1.4 | EXACT* | 1.1.4 | 数值版本一致，见"说明 2" |
| 16 | thiserror | 2.0.19 | EXACT | 2.0.19 | 精确存在 |
| 17 | uuid | 1.24.0 | EXACT | 1.24.0 | 精确存在 |
| 18 | semver | 1.0.28 | EXACT | 1.0.28 | 精确存在 |
| 19 | url | 2.5.8 | EXACT | 2.5.8 | 精确存在 |
| 20 | time | 0.3.54 | EXACT | 0.3.54 | 精确存在（上游已有 0.3.55，按 §22.0 不升级） |
| 21 | arc-swap | 1.9.2 | EXACT | 1.9.2 | 精确存在 |
| 22 | argon2 | 0.5.3 | EXACT | 0.5.3 | 精确存在 |
| 23 | secrecy | 0.10.3 | EXACT | 0.10.3 | 精确存在 |
| 24 | zeroize | 1.9.0 | EXACT | 1.9.0 | 精确存在 |
| 25 | getrandom | 0.4.3 | EXACT | 0.4.3 | 精确存在 |
| 26 | sha2 | 0.11.0 | EXACT | 0.11.0 | 精确存在 |
| 27 | subtle | 2.6.1 | EXACT | 2.6.1 | 精确存在 |
| 28 | base64 | 0.23.0 | EXACT | 0.23.0 | 精确存在（上游已有 0.23.1，按 §22.0 不升级） |
| 29 | cookie | 0.18.1 | EXACT | 0.18.1 | 精确存在 |
| 30 | clap | 4.6.4 | EXACT | 4.6.4 | 精确存在（上游已有 4.6.6，按 §22.0 不升级） |
| 31 | tracing | 0.1.44 | EXACT | 0.1.44 | 精确存在 |
| 32 | tracing-subscriber | 0.3.23 | EXACT | 0.3.23 | 精确存在 |
| 33 | proptest | 1.11.0 | EXACT | 1.11.0 | 精确存在 |
| 34 | loom | 0.7.2 | EXACT | 0.7.2 | 精确存在 |
| 35 | tempfile | 3.27.0 | EXACT | 3.27.0 | 精确存在 |

结果：**35 项全部校验通过；硬性偏差 0 项。**

## 说明 1：Wasmtime 36.x LTS 线（§22.2 三件套）

- 三个 crate 的 36.x 线均存在，最新已发布 patch 均为 **36.0.13**，同一 release line，无混搭。
- 校验时 `max_stable_version` 为 47.0.3（当前普通 major）；按规范 §4.1/§22.2 的 LTS-to-LTS 规则，**47 不进入 production**；48 于 2026-08-20 正式发布并通过 promotion Gate 前不得使用。规范关于 Wasmtime 生产线的表述与 crates.io 实际发布状态完全一致，无需偏差上报。
- workspace.dependencies 将三件套固定为 `36.0.13`（caret 约束，允许 36.x 内 patch 演进，但任何解析变化必须经 §23 Gate + `--locked`）。

## 说明 2：toml 的 build metadata 惯例

- toml-rs 自 1.1.0 起发布的版本携带 build metadata（如 `1.1.4+spec-1.1.0`，表示 TOML 1.1 规范符合度）。crates.io 上不存在裸 `1.1.4`，最新发布为 `1.1.4+spec-1.1.0`。
- 数值版本（major.minor.patch）与规范 §22.4 快照 `1.1.4` **完全一致**；Cargo.toml 约束 `"1.1.4"` 在语义化版本比较中忽略 build metadata，可正确解析到该发布。判定为名义差异，非偏差。

## 说明 3：workspace.dependencies 的"冻结但不解析"状态

- 骨架阶段（YAGNI §12.6）尚无 crate 采用依赖，上述 35 项当前以精确约束形式冻结在根 `Cargo.toml` 的 `[workspace.dependencies]`，但不会进入 `Cargo.lock`（cargo 只解析被实际采用的依赖）。各 crate 后续按真实需求从该表取值，禁止直接写版本字面量（§23.2）。
- 任何升级/新增必须走 §23.1 新增依赖 Gate / §23.2 版本策略（独立 PR、五要素交叉审计、advisory 变化记录）。

## 说明 4：CI 工具版本（§22.8 "CI pinned"）

- cargo-deny：0.20.2（crates.io max stable，2026-08-07）；cargo-audit：0.22.2（同）；均已精确 pin 在 `.github/workflows/ci.yml` 的 `taiki-e/install-action` 中。
- cargo-nextest / cargo-llvm-cov / cargo-fuzz / cargo-mutants 未纳入本骨架（后续 milestone 需要时按 §22.8 做可复现 pin）。

## 结论

规范 §22 全部 35 项 direct-dependency 版本约束均可按原快照直接采用；无需主 agent 走 Dependency Update Gate 的偏差项。若需复核，可在任一机器重跑：

```text
curl -s -H "User-Agent: operune-probe/0.1" "https://crates.io/api/v1/crates/<name>"
```
