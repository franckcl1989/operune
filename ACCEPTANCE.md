# Operune 0.1.0 验收记录（ACCEPTANCE）

- **日期**：2026-08-07
- **验收对象**：Operune Core Runtime 0.1.0（Production Kernel，规范 §39）
- **依据**：规范 §39.4（0.1.0 验收）、§37（Release Gate）、§54（每次提交前）、§35（覆盖率）、§36（CI 与 Production Qualification 矩阵）
- **执行方式**：本机可执行子集验收（Windows x86_64）。全部 `cargo` 命令使用 `--locked`（§22.1 已提交 lockfile 事实源）。未执行任何 git 命令；除本文件外未修改任何文件。
- **环境**：

| 项 | 值 |
|---|---|
| 主机 | Windows 11 Pro（x86_64-pc-windows-msvc），Build 26200 |
| rustc / cargo | 1.97.1（rust-toolchain.toml 精确冻结，§22.1） |
| rustfmt / clippy | 1.9.0-stable / 0.1.97 |
| cargo-deny | 0.20.2（与 CI pin 一致） |
| cargo-audit | 0.22.2（与 CI pin 一致） |
| 基线 | OPERUNE_PLATFORM_ENGINEERING_MASTER_SPEC_R2_FROZEN_2026-08-07.md（R2 冻结） |

---

## 1. 本机全量门禁结果（§37 本机子集 + §54）

| # | 门禁 | 命令 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | 格式化 | `cargo fmt --check` | **PASS** | exit 0，无 diff 输出 |
| 2 | clippy -D warnings | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **PASS** | exit 0；`Finished dev profile in 6.00s`，零警告（workspace.lints 固化 `-D clippy::unwrap_used/-D expect_used/-D panic/-D todo/-D unimplemented` 与 `unsafe_code = "forbid"`，见 Cargo.toml:35-43） |
| 3 | 全量测试 | `cargo test --workspace --locked` | **PASS** | **504 个测试全过、0 失败**：application 65、conformance 22、domain 80、observability 23、platform 9、platform-windows 5、runtime-wasi-p2 12、runtime-wasm 32、security 50、server 72、storage-sqlite 65、web-admin 50（46 单元 + 4 tls.rs 集成）、web-component 18、integration 0（骨架空壳）、observability doc-test 1、platform-linux/macos 0（骨架 stub） |
| 4 | §54 机械检查 | grep crates/ 与 tests/ 下 `.rs` | **PASS** | 见下节 1.1 |
| 5 | 依赖门 | `cargo deny check advisories bans sources`（0.20.2 本机运行） | **PASS** | `advisories ok, bans ok, sources ok`，exit 0（licenses 未启用属 §23.4 Owner 决策，CI 同配置） |
| 6 | 漏洞扫描 | `cargo audit`（0.22.2 本机运行，1190 条 advisory） | **PASS** | 扫描 355 个依赖，**0 vulnerabilities**，exit 0 |
| 7 | release smoke | `cargo build --release --locked -p operune-server` + 运行 | **PASS** | 构建 1m52s exit 0；`operune-server version` → `operune-server 0.1.0` exit 0；`--help` / `recover --help` 正常（recovery plane CLI 面完整）；产物 5,124,608 字节 |

### 1.1 §54 机械检查明细

- **`unsafe`**：代码中 **0 处**。grep 命中仅为：CSP 策略字符串 `'unsafe-inline'`（web-component/src/csp.rs、web-admin/src/headers.rs）与文档注释（application/src/runtime.rs、wit_bindings.rs）。无 `unsafe {}` / `unsafe fn` / `unsafe impl`。workspace 级 `forbid(unsafe_code)` + clippy 通过 = 机械证明。
- **`unwrap(` / `expect(` / `panic!` / `todo!` / `unimplemented!`**：**0 处**（grep 命中仅为文档注释提及，tests/conformance/src/test_support.rs 等）。
- **`unreachable!`**：存在 N 处，逐位置核对**全部位于 `#[cfg(test)]` 模块内**（如 server/src/cli.rs:571、storage-sqlite/src/testutil.rs、platform-windows/src/data_root.rs:91 < cfg(test) 于 :59 之后等；域代码 domain/src/lifecycle.rs:508/512 均位于 :235 起的 test 模块）；生产路径无任何 panic 逃生宏。
- 其余 §54 语义项（能力复用、领域泄漏、有界队列、deny-by-default 权限、审计不落 secret 等）由 §39.4 各验收测试覆盖，见第 2 节。

---

## 2. §39.4 验收逐项核对（本机可执行子集）

结论图例：**PASS** = 本机测试/命令实证；**PASS-部分** = 本机部分实证 + 端到端/目标平台项留待 CI；**NOT-EXECUTABLE-本机** = 需 CI/目标硬件/长时间运行，本机不可执行（如实标注，不以文档化冒充通过）。

| # | 验收项 | 验证方式（测试名/命令/文档） | 结论 |
|---|---|---|---|
| 1 | 非法/恶意 Component 不能通过 Host 资源或未授权能力拖垮/接管 Core | conformance runtime_suite：`malformed_bytes_rejected_as_component`、`core_module_bytes_rejected_by_component_gate`、`memory_grow_attacker_denied_with_minus_one`、`memory_grow_attacker_instantiation_rejected_by_limiter`、`unknown_import_rejected_at_link_time`、`default_store_has_no_ambient_authority`、`trap_on_init_classified_as_typed_failure`；pipeline_suite：`install_rejects_malformed_bytes_without_candidate`、`denied_preopen_capability_fails_closed`；runtime-wasm：`memory_limit_rejects_instantiation`、`memory_grow_over_limit_returns_minus_one`、`instance_count_limit_rejects_second_instance` | **PASS** |
| 2 | infinite loop 能按 deadline 中断 | conformance：`infinite_loop_interrupted_by_epoch_deadline`（SPIN_LOOP，25ms deadline→EpochDeadlineExceeded）、`infinite_loop_on_init_interrupted_by_deadline`（SPIN_ON_INIT，50ms deadline 内中断并有界 <5s）；runtime-wasm：`epoch_deadline_traps_infinite_loop`、`no_deadline_traps_immediately`、engine `epoch_ticker_runs_and_stops`、`deadline_rejected_when_epoch_disabled`/`deadline_rejected_when_zero` | **PASS** |
| 3 | memory/host buffer/concurrency/queue over-limit 有确定拒绝或 trap | runtime-wasm limiter/store：`memory_limit_rejects_instantiation`（typed ResourceLimit::LinearMemory）、`memory_grow_over_limit_returns_minus_one`（-1 非 trap）、`table_element_limit_rejects_instantiation`、`instance_count_limit_rejects_second_instance`；instance set：`dispatch_queues_up_to_max_and_rejects_overflow`（**DispatchError::QueueFull**）、`lease_is_exclusive_per_slot_and_released_on_drop`（Busy）、`store_is_bounded_by_max_concurrent_via_budget`；application：`install_rejects_oversized_bytes`、`web_action_body_over_limit_denied`、`asset_cache_bounded_by_entry_cap`、`rate_limit_denies_burst`；web-admin：`install_oversized_body_rejected_early` | **PASS** |
| 4 | 未授权/未知 import 不能成为 Active | conformance：`unknown_import_rejected_at_link_time`（link 期确定性拒绝，§19.5）、`default_store_has_no_ambient_authority`（§7.6 零能力默认）；pipeline_suite：`unknown_import_denied_at_prepare_without_grant`、`grant_capability_id_must_match_binary_import`；application：`install_denies_unknown_import`、`install_requires_explicit_grants`、`web_action_denied_without_grant`；runtime-wasi-p2：`default_context_has_no_ambient_authority`、`attach_with_default_adapter_installs_zero_capability_context`、`preopen_missing_host_path_fails_whole_build` | **PASS** |
| 5 | 同一逻辑 ComponentId+ComponentVersion 不同 digest 被显式阻断 | storage：`digest_conflict_is_blocked_not_overwritten`（repository.rs:2446，§19.4）；application：`install_supply_chain_conflict_blocked`（install.rs:1287，`RegistryError::VersionBindingConflict` 于 install.rs:372） | **PASS** |
| 6 | install/upgrade 任意 crash point 后重启状态一致 | storage recovery.rs `run_recovery` 决策表（staging 残留/`prepared` marker/artifact 文件位置/CorruptState fail-closed，幂等，audit 同事务）：`prepared_marker_rolled_back_active_preserved`、`prepared_marker_inconsistent_with_active_fails_closed`、`artifact_promoted_when_candidate_committed`、`artifact_demoted_when_candidate_not_committed`、`stale_quarantine_row_removed`、`missing_promoted_artifact_fails_closed`、`staging_leftovers_are_cleaned`、`recovery_is_idempotent`；repository：`switch_atomicity_failure_leaves_no_state`、`failed_mutation_rolls_back_audit_with_it` | **PASS**（本机为**模拟 crash 状态注入子集**：marker/行/文件位置 + cancel；§33 完整进程级 fault-injection 为 nightly/CI 项，本机 NOT-EXECUTABLE） |
| 7 | v2 validation/descriptor/health 失败时 v1 保持可用 | application upgrade.rs：`upgrade_failure_keeps_v1_active`（§39.4 直接对应）、`install_prepare_failure_fails_candidate`、`install_descriptor_failure_fails_candidate`、`install_readiness_failure_fails_candidate`、`install_descriptor_mismatch_quarantines`、`rollback_to_last_good_version`、`rollback_without_target_fails`、`upgrade_same_digest_is_noop`、`upgrade_to_other_component_id_rejected`；storage：`upgrade_and_rollback_retains_artifacts` | **PASS** |
| 8 | all Components disabled/corrupt 时 Root Admin Recovery Plane + CLI 仍可用 | server cli.rs：`clap_parses_recover_subcommands`、`clap_rejects_missing_recover_action`、`safe_mode_enter_exit_roundtrip`（§18.0 事务化标志+审计）、`version_command_prints_version_without_storage`（§16.3 不依赖存储）、`bootstrap_admin_creates_user_with_hashed_password_and_audit`、`bootstrap_admin_refuses_second_admin`；web-admin：`safe_mode_toggle_audited`、`safe_mode_toggle_with_csrf`（http_tests.rs）、`status_and_config_views`；release 二进制 `recover --help`/`version` 冒烟通过 | **PASS-部分**：recovery plane CLI 与 Web safe-mode 功能测试全部本机通过，但**真实损坏存储上的端到端 server 进程恢复未在本机执行**（进程级损坏注入属 §33/CI） |
| 9 | Core 重启恢复唯一 active Component registry | storage schema.rs:85-94：`active_version` 表 `installation_id TEXT PRIMARY KEY`（单行约束）；repository.rs:997-1084：`switch_active_version` 两阶段协议（commit point #1 marker durable → commit point #2 active_version UPSERT，SQLite 同事务原子提交 ⇒ 歧义不可能）；recovery.rs 决策表 `prepared` 时 active 必然 = from；测试：`prepared_marker_rolled_back_active_preserved`、`quarantine_to_candidate_to_active_lifecycle`、`recovery_is_idempotent` | **PASS** |
| 10 | production browser admin 不存在明文 HTTP 登录退化 | web-admin config.rs `AdminListenConfig::validate`（§16.1：insecure dev 仅限 loopback；非 loopback 必须显式生产 TLS 身份，`ProductionIdentityRequired` **无自动退化**）：`default_binds_loopback`、`insecure_dev_rejected_off_loopback`、`insecure_dev_allowed_on_loopback`、`loopback_secure_allowed`；tests/tls.rs：`listen_config_validates_exposure_rules`、`production_identity_flows_into_server_config`、`insecure_dev_has_no_identity`、`ring_provider_installed_and_server_config_builds` | **PASS** |
| 11 | session/password/CSRF/TLS/security tests 全通过 | security 50 测试全过：password（`hash_verify_roundtrip`、`default_params_equal_owasp_baseline`、`params_below_baseline_rejected`、`malformed_stored_hash_rejected`、`verify_rejects_different_value`）、session（`create_then_validate`、`absolute_expiry_invalidates_session`、`idle_expiry_invalidates_session`、`revoke_removes_session`、`store_never_contains_bearer_token`）、CSRF（`csrf_secret_validation_binds_to_session`）、TLS（`identity_from_pem_roundtrip`、`cert_chain_debug_does_not_dump_der`、`key_pem_errors_are_sanitized`、`private_key_debug_is_masked_everywhere`）；web-admin http_tests.rs 黑盒：`login_success_rotates_session_and_old_anon_is_dead`、`login_failure_does_not_rotate_and_password_not_echoed`、`state_changing_without_csrf_token_rejected`、`state_changing_with_wrong_csrf_token_rejected`、`state_changing_with_wrong_origin_rejected`、`production_cookie_has_required_attributes`（security）、`failed_login_password_never_logged`、`disabled_user_session_revoked_at_request_time` | **PASS** |
| 12 | Linux x86_64 GNU full qualification 通过 | CI 矩阵（.github/workflows/ci.yml：ubuntu-latest 跑 fmt/clippy/test/cargo-deny/cargo-audit）；本机为 Windows 无法执行 Linux 原生 qualification | **NOT-EXECUTABLE-本机**（CI/未来项，不以前者替后者） |
| 13 | Linux ARM64 GNU full qualification 在真实 ARM64 硬件通过 | 无 ARM64 硬件/runner 本机；ci.yml 注释明确 aarch64 job 为后续 milestone | **NOT-EXECUTABLE** |
| 14 | ARM64 Constrained/Edge qualification | 同 13 | **NOT-EXECUTABLE** |
| 15 | 同一标准 Component fixtures x86_64/ARM64 可观察领域语义一致 | 需双架构实跑同一套 fixtures（conformance FIXTURES 共 10 个：9 个 wat 夹具 MINIMAL/CORE_MODULE/SPIN_LOOP/SPIN_ON_INIT/TRAP_ON_INIT/MEMORY_GROW/HUGE_MEMORY/UNKNOWN_IMPORT/SLOW + 1 个原始字节 MALFORMED_BYTES） | **NOT-EXECUTABLE** |
| 16 | Windows/macOS 架构测试无 Linux 假设泄漏 | **Windows 部分 PASS**：本次全量 504 测试即在原生 Windows x86_64 上执行并全过（含 conformance/runtime/security/server 全套），platform-windows data_root 5 测试（`resolves_localappdata_operune`、`missing_localappdata_fails_closed` 等）；**macOS NOT-EXECUTABLE**：platform-macos 为骨架 stub（0 测试，无公开 API），macOS 行为验证留 CI | **PASS-部分** |
| 17 | soak 无持续资源泄漏趋势 | 仓库无 soak harness（grep crates/ tests/ 无 soak 代码）；无本机长时间运行证据 | **NOT-EXECUTABLE**（nightly/CI 项） |
| 18 | 第一方源码 unsafe=0，production path 无 unwrap/expect/panic/todo/unimplemented 逃生路径 | 见 §1.1 机械证明：grep 0 命中 + workspace `forbid(unsafe_code)` + clippy `-D` 全通过；`unreachable!` 全部位于 `#[cfg(test)]` | **PASS** |

---

## 3. §37 Release Gate 逐项（本机子集）

| # | Gate | 结论 | 证据 |
|---|---|---|---|
| 1 | `cargo fmt` | **PASS** | 本机 `cargo fmt --check` exit 0 |
| 2 | clippy `-D warnings` | **PASS** | 本机全 workspace 全 targets，零警告 |
| 3 | `forbid(unsafe_code)` 全 workspace | **PASS** | workspace.lints + 每个 crate `#![forbid(unsafe_code)]`（抽查全 crate 首行）+ grep 0 处 unsafe |
| 4 | unit/property/integration/conformance | **PASS** | 504 测试 0 失败（含 conformance 22、集成 0 空壳） |
| 5 | security tests | **PASS** | security 50 + web-admin 黑盒安全测试全过 |
| 6 | dependency advisory/license/source gate | **PASS** | 本机 cargo-deny 0.20.2：advisories/bans/sources 全 ok（355 依赖）；cargo-audit 0.22.2：0 漏洞；licenses 未启用 = §23.4 Owner 决策，CI 同配置 |
| 7 | migration test | **PASS** | storage migration.rs 7 测试：`fresh_db_migrates_to_current`、`reopen_is_idempotent`、`schema_too_new_fails_closed`、`missing_schema_version_table_treated_as_fresh`、`migration_failure_rolls_back_entirely`、`forward_migration_preserves_data_old_to_new`、`migration_set_must_be_sorted_and_ordered` |
| 8 | upgrade/rollback test | **PASS** | application upgrade.rs 8 测试（含 `upgrade_swaps_and_drains_old_version`、`upgrade_grant_expansion_requires_approval`、`rollback_to_last_good_version`）+ storage `upgrade_and_rollback_retains_artifacts` |
| 9 | crash recovery test | **PASS** | storage recovery.rs 9 测试 + `switch_atomicity_failure_leaves_no_state`（本机为模拟 crash 状态子集；§33 完整 fault-injection = nightly/CI） |
| 10 | platform production qualification | **NOT-EXECUTABLE-本机** | 需 Linux x86_64 GNU / aarch64 GNU 原生 runner（§36 矩阵）；Windows x86_64 本机构建+全量测试通过作为"Windows 一等适配"证据 |
| 11 | release binary smoke | **PASS** | `cargo build --release --locked -p operune-server`（1m52s，exit 0）；`operune-server version` → `operune-server 0.1.0`（exit 0）；`--help` 与 `recover --help` 正常 |
| 12 | SBOM/provenance/sha256/signing | **NOT-EXECUTABLE** | §37.12 按路线图进入相应版本后为 MUST；0.1.0 未启用 |
| 13 | 文档/CLI/API compatibility check | **PASS-部分** | CLI 面：clap 解析测试（`clap_parses_version_command`、`clap_parses_recover_subcommands`、`clap_rejects_unknown_subcommand` 等）+ release 二进制 `--help`/`version` 冒烟；0.1.0 为首个版本，无既有 API 需向后兼容；文档：README.md、DEPENDENCY_PROBE.md 与冻结规范在场 |
| 14 | 没有 unresolved release-blocker | **PASS** | 本机子集未发现 blocker；已知缺口均为第 4 节记录在案的非阻塞项 |

---

## 4. 已知非阻塞缺口清单（0.1.0）

1. **conformance 工具链缺口（7 项，gaps.rs `gap_inventory_is_recorded` 审计门保障）**：cargo-component/wasm-tools 本机不可用，无法构建导出 `operune:component@0.1.0` / `operune:web@0.1.0` WIT 契约的 guest 夹具：
   - incompatible contract/interface version 夹具；
   - health check failure 夹具（0.3 健康契约）；
   - descriptor deterministic/repeatability 全链路（§19.3 read_descriptor ×2）；
   - minimal valid Component（完整 descriptor happy path）；
   - grant-expansion upgrade 夹具（§17.5 RequiresApproval 端到端）；
   - Web assets + sandbox escape attempt 组件（§21.3/§32）；
   - supply-chain conflict 端到端（当前由 application/storage 单测以 fake 覆盖，§39.4 第 5 项已本机 PASS）。
   → 补齐条件：cargo-component 工具链就绪。
2. **qualification 项**：Linux x86_64 GNU full qualification（#12）、Linux ARM64 GNU 真实硬件（#13）、ARM64 Constrained/Edge（#14）、x86_64/ARM64 fixtures 语义一致（#15）、macOS 架构测试（#16 之 mac 部分）——需 CI runner/目标硬件，均为 §39.4 明确 NOT-EXECUTABLE 项。
3. **soak（#17）**：无 harness；属 §36 nightly/Release 项。
4. **§33 完整 fault-injection**（进程级 kill 注入）：nightly/CI 项；本机以模拟 crash 状态子集验证。
5. **loom**：workspace 已声明 loom 0.7.2（§22.8），尚无 loom 测试；属 §36 nightly 项。
6. **tests/integration** 为空壳（骨架阶段）；platform-linux / platform-macos 为骨架 stub（0 测试）。
7. **CI 现场状态**：本机无 gh/git 权限，无法直接读取 CI 运行历史；CI 配置（.github/workflows/ci.yml，cargo-deny@0.20.2、cargo-audit@0.22.2、fmt/clippy/test 于 ubuntu + windows 双矩阵）与**本机同版本、同命令**的执行结果完全一致，本机通过即同参数等价验证。

---

## 5. CI 状态引用

- CI 流水线定义：`.github/workflows/ci.yml`（push/PR/workflow_dispatch）。
- CI 命令与本机执行命令逐一对应：fmt（`cargo fmt --check`）、clippy（`cargo clippy --workspace --all-targets --locked -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented`）、test（`cargo test --workspace --locked`）、cargo-deny（`cargo deny check advisories bans sources`，pin 0.20.2）、cargo-audit（pin 0.22.2）。本机以相同版本工具链/命令全部执行并通过。
- Linux 与 Windows 双矩阵：Linux 侧结果需 CI 现场确认；本机提供 Windows x86_64 原生全量证据（504 测试全过）。
- 工具链一致：rust-toolchain.toml 冻结 1.97.1，本机 `rustc 1.97.1 (8bab26f4f)` 与之完全一致。

---

## 6. 结论

**0.1.0 本机可执行验收子集达成**：

- 本机全量门禁（fmt / clippy -D warnings / 504 测试 0 失败 / §54 机械检查 / cargo-deny / cargo-audit / release binary smoke）全部通过；
- §39.4 共 18 项：**PASS 11 项**（#1-7、#9-11、#18），**PASS-部分 2 项**（#8 Recovery Plane 端到端——功能级全过、进程级损坏注入留 CI；#16——Windows 侧全量实证、macOS 侧未执行），**NOT-EXECUTABLE-本机 5 项**（#12-15、#17，外加 #16 的 macOS 侧——均为需 CI/目标硬件/long-run 的 qualification 与 soak 项，如实标注，不以文档化冒充通过）；
- §37 共 14 项：本机可执行 10 项 PASS（含 migration/upgrade-rollback/crash-recovery/security/deny/audit/smoke），1 项 PASS-部分（#13 文档/CLI），3 项 NOT-EXECUTABLE（#10 qualification、#12 SBOM、#9 之 §33 完整 fault-injection 部分），无 release-blocker。

**标记 0.1.0 的前置条件（本机结论）**：本地 Gate 全部成立；剩余 NOT-EXECUTABLE 项必须由 CI/目标硬件完成（Linux x86_64 GNU full qualification、ARM64 真实硬件 qualification、soak、§33 fault-injection），其完成证据与结果需追加至本记录，方可按 §39.4 全文"只有全部成立"的语义完成最终标记。

---

# Operune 0.2.0 验收记录（ACCEPTANCE 增补：Capability Composition）

- **日期**：2026-08-08
- **验收对象**：Operune Core Runtime 0.2.0（Capability Composition，规范 §40）
- **依据**：规范 §40.4（0.2.0 验收）、§37（Release Gate）、§54（每次提交前）、§35（覆盖率）、§36（CI 与 Production Qualification 矩阵）；沿用 0.1.0 验收框架（§38：每个版本是前一版本的真实超集，0.1 的 §39.4 基线验收不因新版本撤销——本次 0.1 全量测试原样包含于 833 测试中）
- **执行方式**：本机可执行子集验收（Windows x86_64）。全部 `cargo` 命令使用 `--locked`（§22.1 已提交 lockfile 事实源）。未执行任何 git 命令；除本文件外未修改任何文件。
- **环境**：

| 项 | 值 |
|---|---|
| 主机 | Windows 11 Pro（x86_64-pc-windows-msvc），Build 26200 |
| rustc / cargo | 1.97.1（rust-toolchain.toml 精确冻结，§22.1；rustc 1.97.1 (8bab26f4f 2026-07-14)，cargo 1.97.1 (c980f4866 2026-06-30)，与 0.1 记录一致） |
| rustfmt / clippy | 1.9.0-stable / 0.1.97（与 0.1 记录一致） |
| cargo-deny | 0.20.2（与 CI pin 一致） |
| cargo-audit | 0.22.2（与 CI pin 一致） |
| 基线 | OPERUNE_PLATFORM_ENGINEERING_MASTER_SPEC_R2_FROZEN_2026-08-07.md（R2 冻结） |

---

## 1. 本机全量门禁结果（§37 本机子集 + §54）

| # | 门禁 | 命令 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | 格式化 | `cargo fmt --check` | **PASS** | exit 0，无 diff 输出 |
| 2 | clippy -D warnings | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **PASS** | exit 0；`Finished dev profile in 11.78s`，零警告（workspace.lints 固化 `-D clippy::unwrap_used/-D expect_used/-D panic/-D todo/-D unimplemented` 与 `unsafe_code = "forbid"`，Cargo.toml:35-43） |
| 3 | 全量测试 | `cargo test --workspace --locked` | **PASS** | **833 个测试全过、0 失败**（0.1 基线 504 → +329）：application 205（204 单元 + 1 stateful_e2e 集成）、conformance 35、domain 189、integration 0（空壳）、observability 23 + doc-test 1、platform 9、platform-windows 5、platform-linux/macos 0（骨架）、runtime-wasi-p2 12、runtime-wasm 45、security 65、server 72、storage-sqlite 104、web-admin 50（46 单元 + 4 tls 集成）、web-component 18 |
| 4 | §54 机械检查 | grep crates/ 与 tests/ 下 `.rs` | **PASS** | 见下节 1.1 |
| 5 | 依赖门 | `cargo deny check advisories bans sources`（0.20.2 本机运行） | **PASS** | `advisories ok, bans ok, sources ok`，exit 0（0.3 新增生产依赖 chacha20poly1305 后复核，licenses 未启用属 §23.4 Owner 决策，CI 同配置） |
| 6 | 漏洞扫描 | `cargo audit`（0.22.2 本机运行，1190 条 advisory） | **PASS** | 扫描 **364 个 crate 依赖**（0.1 为 355，+9 = chacha20poly1305 依赖子树），**0 vulnerabilities**，exit 0 |

### 1.1 §54 机械检查明细（0.2.0/0.3.0 同一轮）

- **`unsafe`**：代码中 **0 处**。grep 39 命中全部为：CSP 策略字符串 `'unsafe-inline'`/`'unsafe-eval'`（web-component/src/csp.rs、web-admin/src/headers.rs，其中 csp.rs:57-58 为测试断言 `unwrap_or` 非 `unwrap()`）与文档注释（application/src/wit_bindings.rs、lib.rs 文档等）。无 `unsafe {}` / `unsafe fn` / `unsafe impl`。workspace 级 `forbid(unsafe_code)` + clippy 通过 = 机械证明。
- **`unwrap(`**：3 命中，全部为 `std::sync::Arc::try_unwrap`（不同 API，且均位于测试代码：application/tests/stateful_e2e.rs:849、storage-sqlite/src/executor.rs:2745、storage-sqlite/src/ports.rs:2121）。**`expect(`**：0。**`panic!`**：17 命中，全部为文档注释。**`todo!`**：7 命中，全部为文档注释。**`unimplemented!`**：7 命中，全部为文档注释。
- **`unreachable!`**：68 处非注释命中，**63 处位于 `#[cfg(test)]` 模块内**（逐一核对各文件 cfg(test) 边界：domain graph.rs:775+、lifecycle.rs:508/512 < :235、upgrade.rs:408 < :199、test_support.rs 均 `#[cfg(test)] mod` 门控，security/server/observability/platform-windows 全部 < cfg(test) 边界）；**5 处位于 0.2 新增生产代码 `crates/domain/src/graph.rs`**（resolve():516/526、compute_activation_order():563/616、find_cycle():664）——均为带不变量说明消息的 fail-stop（§14.3"不可恢复不变量失败采用 fail-stop"，注释明示：compatible 非空、边必指图中 provider、剩余子图必有环、循环条件保证栈非空）。`unreachable!` **不在** workspace deny 清单（仅 deny unwrap_used/expect_used/panic/todo/unimplemented），clippy `-D warnings` 通过。**如实记载的 delta**：0.1 记录"生产路径无任何 panic 逃生宏"在新代码上不再严格成立（0.1 当时如此——graph.rs 为 0.2 新增）；这是带理由的工程选择而非 lint 逃逸，但需 Owner 知悉。
- 其余 §54 语义项（能力复用、领域泄漏、有界队列、deny-by-default 权限、审计不落 secret 等）由 §40.4/§41.3 各验收测试覆盖，见第 2 节。

---

## 2. §40.4 验收逐项核对（本机可执行子集）

结论图例同 0.1 章节：**PASS** = 本机测试/命令实证；**PASS-部分** = 本机部分实证；**NOT-EXECUTABLE-本机** = 需 CI/目标硬件；**MISSING-EVIDENCE** = 验收项无对应测试（如实标注，不伪造）。

| # | 验收项 | 验证方式（测试名/文件） | 结论 |
|---|---|---|---|
| 1 | 同一 Component set + 同一 policy 必须得到确定的 provider graph | conformance composition_suite：`records_input_order_does_not_affect_graph`（records 正序/逆序构建 → `assert_eq!` 相同 graph + 相同拓扑序，§40.3 事实源：真实 `WasmtimeRuntime::contract_surface` 观察推导 records）、`activation_order_variance_produces_identical_graphs_and_calls`（两个独立 harness、同组件集两种合法激活顺序 → 相同 graph/拓扑序/边数，且经 graph 映射的 runtime 链接集合两种顺序下调用均正确 run=54）；domain graph.rs：`build_is_deterministic_regardless_of_input_order`、`ambiguous_provider_rejected_deterministically`、`queries_return_sorted_results`、`providers_iteration_sorted_by_provider_id`（全部内部结构按稳定键排序，BTree 保证）；application composition.rs：`policy_apply_is_deterministic_regardless_of_input_order`（policy 是 map 非 list，与声明顺序无关）、`same_inputs_in_different_activation_order_produce_identical_graphs` | **PASS** |
| 2 | 无法唯一合法解析时必须拒绝激活，不得随机选择 provider | **歧义**：conformance `ambiguous_provider_rejected_without_policy_and_resolved_by_policy`（同一 interface 两个候选 provider、无 policy → `ProviderGraphError::AmbiguousProvider`，诊断含全部候选且按 ProviderId 排序；显式 policy 绑定 → 唯一解析；graph.rs:894 `ambiguous_provider_rejected_deterministically` 双跑同一拒绝结果）；application composition.rs `ambiguous_provider_rejected_without_policy_and_resolved_with_policy`、`policy_binding_resolves_ambiguity`、`policy_exclusion_resolves_ambiguity`、`policy_duplicate_binding_is_rejected`、`policy_binding_to_non_provider_interface_is_rejected_at_apply`；**缺失 provider**：conformance `consumer_activation_without_provider_is_rejected`（graph 层 MissingProvider，诊断含具体需求；runtime 层 UnlinkedImport）、`unlinked_import_rejected_at_graph_and_runtime`；application `consumer_activation_requires_provider_activated_first`（激活门控：provider 未激活时 consumer 的 gate 以 MissingProvider 拒绝，天然强制 activation ordering）、domain `missing_provider_diagnostics`、`incompatible_version_diagnostics`；**环**：conformance `cycle_between_providers_rejected_at_graph_layer`、application `cycle_between_providers_is_rejected`、domain `self_loop_is_a_cycle`/`two_node_cycle_detected`/`three_node_cycle_detected`/`cycle_display_is_readable`；**重复 provider**：domain `duplicate_provider_rejected`/`duplicate_consumer_rejected`；**拒绝不产生副作用**：application `deactivation_of_provider_with_consumers_is_rejected`、`snapshot_switch_is_single_pointer_exchange`（拒绝路径快照不变，§20.3 单指针交换） | **PASS** |
| 3 | §40.2 capability composition conformance suite（MUST scope 逐条） | composition_suite.rs 13 测试，模块文档逐条映射 §40.2 条目：exports→imports 满足（`provider_consumer_link_resolves_and_calls_correctly`）、activation/deactivation ordering（`three_component_chain_resolves_and_calls_correctly`，链式拓扑序）、missing provider diagnostics（#2 已列）、cycle detection（#2 已列）、provider selection 确定规则（`ambiguous_provider_rejected_without_policy_and_resolved_by_policy`）、provider upgrade 前 consumer compatibility analysis（`breaking_provider_upgrade_rejected_with_impact_report`、`version_incompatible_upgrade_rejected_with_reason`、`real_surface_upgrade_gate_allows_safe_and_rejects_breaking`）、graph snapshot atomic switch/persistence（各失败路径测试断言快照与记录不变；application `commit_activation_persists_records_and_swaps_snapshot`、`records_roundtrip_and_recovery_rebuilds_identical_graph`、`update_policy_revalidates_graph_and_is_atomic`）、二进制面校验（`interface_mismatch_rejected_at_runtime_after_graph_resolution`、`wrong_shape_provider_rejected_at_runtime_link`）；application 层同语义覆盖：`safe_provider_upgrade_is_allowed_and_swaps`、`breaking_provider_upgrade_is_rejected_with_impact_report`、`major_version_bump_upgrade_is_rejected_with_reason`、`consumer_upgrade_with_unresolvable_imports_is_rejected`、`provider_then_consumer_chain_activates_in_order`、`highest_compatible_version_is_selected_within_provider`、`real_wasmtime_surface_observation_derives_records`、`real_wasmtime_consumer_surface_derives_requirement`、`real_wasmtime_components_form_resolvable_graph`；持久化侧：storage migration `forward_migration_v3_to_v4_creates_stateful_tables_preserving_data`、`fresh_db_has_empty_graph_tables` | **PASS** |
| 4 | 0.2 全量测试数汇总 | 见第 1 节门禁 #3：workspace **833 测试 0 失败**。0.2 相关新增：domain graph.rs 25、application composition.rs 35、conformance composition_suite 13（+ fixtures 1）、runtime-wasm linked 链接面新增 13、storage migration graph/stateful 表 5；0.1 全部 504 测试原样保留并全过（如 server 72、web-admin 50 计数不变） | **PASS** |

---

## 3. §37 Release Gate 逐项（本机子集，0.2.0 轮）

| # | Gate | 结论 | 证据 |
|---|---|---|---|
| 1 | `cargo fmt` | **PASS** | 本机 `cargo fmt --check` exit 0 |
| 2 | clippy `-D warnings` | **PASS** | 全 workspace 全 targets 零警告（11.78s） |
| 3 | `forbid(unsafe_code)` 全 workspace | **PASS** | workspace.lints + 各 crate `#![forbid(unsafe_code)]` + grep 0 处 unsafe 代码 |
| 4 | unit/property/integration/conformance | **PASS** | 833 测试 0 失败（含 conformance 35、集成 1：stateful_e2e） |
| 5 | security tests | **PASS** | security 65 + web-admin 黑盒 50 全过 |
| 6 | dependency advisory/license/source gate | **PASS** | 本机 cargo-deny 0.20.2：advisories/bans/sources 全 ok（364 依赖）；cargo-audit 0.22.2：0 漏洞；licenses 未启用 = §23.4 Owner 决策 |
| 7 | migration test | **PASS** | storage migration.rs 12 测试（0.1 的 7 + graph/stateful 表 5：`forward_migration_v3_to_v4_creates_stateful_tables_preserving_data`、`stateful_tables_enforce_check_constraints` 等）+ executor 迁移事务 2 |
| 8 | upgrade/rollback test | **PASS** | application upgrade.rs 9 测试（0.1 既有）+ composition provider 升级门控 5 测试（`safe_provider_upgrade_is_allowed_and_swaps`、`breaking_provider_upgrade_is_rejected_with_impact_report`、`major_version_bump_upgrade_is_rejected_with_reason` 等）+ conformance 升级 3 测试 |
| 9 | crash recovery test | **PASS** | storage recovery.rs 9 + `switch_atomicity_failure_leaves_no_state` + `reopen_recovers_interrupted_switch` + 0.3 状态面无残留测试（见 0.3 章节）；§33 完整 fault-injection = nightly/CI |
| 10 | platform production qualification | **NOT-EXECUTABLE-本机** | 需 Linux x86_64 GNU / aarch64 GNU 原生 runner（§36 矩阵）；Windows x86_64 本机全量通过 |
| 11 | release binary smoke | **NOT-RE-RUN** | 0.1 记录已实证（`cargo build --release --locked -p operune-server` + version/--help）；本 0.2/0.3 轮未重跑 release 构建（无 release 面变更证据要求），如实标注 |
| 12 | SBOM/provenance/sha256/signing | **NOT-EXECUTABLE** | §37.12 按路线图进入相应版本后为 MUST；0.2.0 未启用（同 0.1） |
| 13 | 文档/CLI/API compatibility check | **PASS-部分** | 0.2 新增 WIT 契约已提交稳定（wit/operune/{component,config,event,scheduler,secret,state,web}）；0.x 兼容承诺：新增 secret/state/config/event/scheduler 表走既有版本化 migration（§18.4 forward-only），0.1 metadata 表未改；CLI 面 0.1 测试原样通过 |
| 14 | 没有 unresolved release-blocker | **PASS** | 本机子集未发现 blocker；已知缺口均为第 4 节记录在案的非阻塞项 |

---

## 4. 已知非阻塞缺口清单（0.2.0）

1. **conformance 工具链缺口（9 项，gaps.rs `gap_inventory_is_recorded` 审计门保障）**：cargo-component/wasm-tools 本机不可用——0.1 的 7 项不变（incompatible contract/interface version、health check failure、descriptor deterministic、minimal valid Component、grant-expansion upgrade、Web assets + sandbox escape、supply-chain conflict 全链路），**0.2 新增 2 项**：
   - 复杂 WIT 类型的链接端口（record/variant/enum/string 等非 primitive）：0.2 以 `UnsupportedPortType` 明确拒绝非 primitive 端口（runtime-wasm linked.rs），拒绝路径由 conformance primitive 夹具覆盖；**成功链接路径**待工具链；
   - provider upgrade 全链路（同一 interface 两版本真实升级二进制对）：当前以真实 surface 观察 + records 构造覆盖门控语义，完整编排待工具链。
2. **qualification 项**（同 0.1）：Linux x86_64 GNU full qualification、Linux ARM64 真实硬件、ARM64 Constrained/Edge、x86_64/ARM64 fixtures 语义一致、macOS 架构测试——需 CI runner/目标硬件。
3. **soak（#17）**：无 harness；属 §36 nightly/Release 项。
4. **§33 完整 fault-injection**（进程级 kill 注入）：nightly/CI 项；本机以模拟 crash 状态子集验证。
5. **loom**：workspace 已声明 loom 0.7.2，尚无 loom 测试；属 §36 nightly 项。
6. **tests/integration** 为空壳；platform-linux / platform-macos 为骨架 stub（0 测试）。
7. **§54 delta（0.2 新增）**：domain graph.rs 生产路径 5 处 `unreachable!` fail-stop（不变量说明消息，§14.3；不在 workspace deny 清单，clippy -D 通过）——如实记录供 Owner 知悉，见 1.1。
8. **CI 现场状态**：本机无 gh/git 权限，无法直接读取 CI 运行历史；CI 配置（.github/workflows/ci.yml，cargo-deny@0.20.2、cargo-audit@0.22.2、fmt/clippy/test 于 ubuntu + windows 双矩阵）与本机同版本、同命令执行结果完全一致，本机通过即同参数等价验证。

---

## 5. CI 状态引用

- CI 流水线定义：`.github/workflows/ci.yml`（push/PR/workflow_dispatch）；命令与本机逐一对应：fmt、clippy（`--workspace --all-targets --locked -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic -D clippy::todo -D clippy::unimplemented`）、test（`--workspace --locked`）、cargo-deny（0.20.2）、cargo-audit（0.22.2）。
- 本机以相同版本工具链/命令全部执行并通过（fmt/clippy/test/deny/audit 共 6 项，见第 1 节）；Linux 侧结果需 CI 现场确认。
- 工具链一致：rust-toolchain.toml 冻结 1.97.1，本机 `rustc 1.97.1 (8bab26f4f 2026-07-14)` 一致。

---

## 6. 结论（0.2.0）

**0.2.0 本机可执行验收子集达成**：

- 本机全量门禁（fmt / clippy -D warnings / 833 测试 0 失败 / §54 机械检查 / cargo-deny / cargo-audit）全部通过；
- §40.4 验收 4 项：**PASS 4 项**（确定性 provider graph、非唯一解析拒绝激活、conformance suite MUST 覆盖、全量测试数）——确定性与拒绝语义在 conformance/domain/application 三层均有测试证据，无随机选择路径；
- §37 共 14 项：本机可执行项 PASS（含 migration/upgrade-rollback/crash-recovery/security/deny/audit），qualification/SBOM 等 NOT-EXECUTABLE 项同 0.1，无 release-blocker；
- 已知缺口（工具链 9 项、qualification、soak、§33、loom、集成空壳）全部记录在案，无新 blocker。

---

# Operune 0.3.0 验收记录（ACCEPTANCE 增补：Stateful Runtime）

- **日期**：2026-08-08
- **验收对象**：Operune Core Runtime 0.3.0（Stateful Runtime，规范 §41）
- **依据**：规范 §41.3（0.3.0 验收）、§37（Release Gate）、§54、§35、§36；ADR-0001「SecretStore 密文加密原语与跨平台 key provider 选型」（**Proposed，待 Owner 裁决**，按推荐方向实现，见第 4 节）；沿用 0.1/0.2 验收框架
- **执行方式**：本机可执行子集验收（Windows x86_64）。全部 `cargo` 命令使用 `--locked`。未执行任何 git 命令；除本文件外未修改任何文件。
- **环境**：与 0.2.0 章节同一轮执行、同一环境（2026-08-08，Windows 11 Pro Build 26200，rustc/cargo 1.97.1，rustfmt 1.9.0-stable，clippy 0.1.97，cargo-deny 0.20.2，cargo-audit 0.22.2）。门禁结果引用 0.2.0 章节第 1 节（同一轮全量 833 测试），0.3 相关新增测试数见第 2 节 #4。

---

## 1. 门禁引用（0.3.0 轮 = 0.2.0 轮同一轮执行）

fmt / clippy / 全量测试 / §54 / cargo-deny / cargo-audit 六项结果与 0.2.0 章节第 1 节完全相同（833 测试 0 失败；§54 明细见 0.2.0 章节 1.1，含 graph.rs 生产 `unreachable!` delta 记录）。本节只补充 0.3 专项的 §37 变更项。

| # | Gate | 结论 | 0.3 变更证据 |
|---|---|---|---|
| 7 | migration test | **PASS** | storage migration.rs 12 + executor 迁移事务 2（`state_migration_transaction_advances_schema_version_atomically`、`state_migration_is_forward_only_and_rejects_empty_store`）+ application StateMigrationService 12 |
| 8 | upgrade/rollback test | **PASS** | 0.1 upgrade.rs 9 测试原样通过（`upgrade_failure_keeps_v1_active` 等）；0.3 迁移失败 = 升级被阻止且 store 不变（`migrate_guest_failure_rolls_back_guest_writes`、`guest_self_aborting_migration_tx_leads_to_conflict`） |
| 9 | crash recovery test | **PASS** | 新增：`migrate_retry_after_crash_is_idempotent`、`uncommitted_state_transaction_leaves_no_residue_after_reopen`（未提交迁移重启零残留）、`cancelled_state_commit_rolls_back`、`cancelled_state_tx_operation_rolls_back_entire_tx`、`reopen_recovers_interrupted_switch` |
| 11 | release binary smoke | **NOT-RE-RUN** | 同 0.2（0.1 已实证；本轮未重跑 release 构建） |

---

## 2. §41.3 验收逐项核对（本机可执行子集）

| # | 验收项 | 验证方式（测试名/文件） | 结论 |
|---|---|---|---|
| 1 | 升级、进程 crash、取消、磁盘失败均不得产生"代码版本已切换但状态 schema 不确定"的不可恢复状态 | 分五条证据链，见下（1a-1e） | 见各子项 |
| 1a | 迁移原子推进：schema 版本推进与数据写入同一事务（§41.3 核心） | storage executor `state_migration_transaction_advances_schema_version_atomically`（executor.rs:3633）：migration begin(v2) → 写新形态 → **同一事务** commit → 版本=v2 且数据=new-shape；迁移前常规 begin(v2) = `SchemaVersionMismatch`（旧版本继续可运行）、迁移后 begin(v1) 同样 `SchemaVersionMismatch`（混合版本写入被阻止，双向 fail-closed）；`state_migration_is_forward_only_and_rejects_empty_store`、`state_transaction_commit_is_atomic`；application StateMigrationService `migrate_success_commits_and_advances_schema_version`（版本与数据同事务、窗口 RAII 关闭、审计 MigrationStarted/MigrationCommitted metadata-only）；e2e `stateful_runtime_e2e_with_real_executor`（真实 StorageExecutor：migrate v1→v2 原子推进、`AlreadyAtTarget` 幂等重试） | **PASS** |
| 1b | 失败回滚：guest 错误 / 宿主观测失败 / 陈旧计划 / 降级 / guest 契约违规 | application migration.rs：`migrate_guest_failure_rolls_back_guest_writes`（guest 写半途后失败 → 全部回滚、store 停留 v1、审计 MigrationRolledBack）、`migrate_host_observed_failure_rolls_back`（trap/deadline/超预算 = 迁移失败 → 回滚）、`migrate_rejects_stale_plan_version`（调用方声明 from ≠ 存储版本 → 拒绝，信息陈旧不猜测）、`migrate_rejects_downgrade`（WIT 0.1.0 不定义降级）、`guest_self_aborting_migration_tx_leads_to_conflict`（guest 契约违规 → Conflict，升级被阻止、store 不变）、`migrate_is_busy_while_another_transaction_is_open`（排他窗口，正常事务结束后可重试）；storage `migration_failure_rolls_back_entirely`（migration.rs:348：注入中途失败 → 事务整体回滚、schema 停留 v1、t2 不存在） | **PASS** |
| 1c | 进程 crash | application `migrate_retry_after_crash_is_idempotent`（SQLite 原子性保证未提交迁移自然回滚，重启后同 from/to 重跑幂等；WIT：guest 迁移逻辑不得依赖"仅调用一次"）、`migrate_is_noop_when_already_at_target`、`migrate_empty_store_is_noop`；storage `uncommitted_state_transaction_leaves_no_residue_after_reopen`（崩溃后重启零残留）、`reopen_recovers_interrupted_switch` | **PASS**（本机为模拟 crash 状态注入子集；§33 完整进程级 fault-injection 为 nightly/CI 项，本机 NOT-EXECUTABLE） |
| 1d | 取消 | storage executor：`cancelled_state_tx_operation_rolls_back_entire_tx`（事务中取消 → 整事务回滚）、`cancelled_state_commit_rolls_back`（commit 前取消 → 回滚）、`cancelled_request_before_commit_leaves_no_state`、`aborted_task_cancels_queued_request`（任务取消连带取消已排队请求）；application state.rs `transaction_abort_discards_all_writes`、`tx_delete_of_missing_key_is_not_found`；迁移窗口期间运行时操作：`runtime_ops_return_not_ready_during_migration_window`（not-ready 语义，guest 稍后重试而非数据丢失）、`cas_returns_not_ready_during_migration_window`、`begin_transaction_returns_not_ready_during_migration` | **PASS** |
| 1e | 磁盘失败 | storage `migration_failure_rolls_back_entirely`（失败注入模拟磁盘中途失败）+ `switch_atomicity_failure_leaves_no_state`（0.1 既有）+ executor.rs:2588 COMMIT 失败处理注释（磁盘/锁失败 → 事务整体回滚，§18.5 已提交事务语义）——本机为**错误注入模拟级**；§33 完整 fault-injection（进程级/真实磁盘故障注入）本机 NOT-EXECUTABLE | **PASS-模拟**（NOT-EXECUTABLE-本机 于 §33 部分） |
| 1f | "schema 不确定"不可能：声明版本绑定 | application state.rs：`get_rejects_when_store_version_mismatches_declared`、`cas_binds_declared_schema_version`、`begin_transaction_rejects_declared_version_mismatch`、`transaction_commit_establishes_empty_store_version`（首写建立声明版本）；storage 双向 SchemaVersionMismatch（1a）；代码版本切换自身原子性：application `upgrade_failure_keeps_v1_active`、storage `switch_atomicity_failure_leaves_no_state`（0.1 既有，原样通过）——组合语义：迁移失败 → 旧 schema + 旧代码继续；升级失败 → v1 保持可用；二者任一未提交都不会推进 schema | **PASS** |
| 1g | 升级管线触发 state migration 的端到端编排（§20.5 wiring：新 ComponentVersion 的 `state-declaration.schema-version` 与存储版本比较 → 迁移路径） | **无对应测试**：grep `StateSchemaVersion`/`state-declaration` 于 application/src/upgrade.rs 与 install.rs 均 0 命中；wiring 仅文档化于 wit/operune/state/declaration.wit、migration.wit 与 migration.rs 模块文档（"upgrade 管线（§20.5）决定何时迁移，本服务执行迁移协议"）。迁移协议原子性、版本绑定、失败回滚、crash/取消均已单独测试（1a-1f），但"升级动作触发迁移"的组合编排无测试 | **MISSING-EVIDENCE**（编排级；各原子性属性已 PASS，非阻塞但仍属 §41.3 首句的完整语义缺口） |
| 2 | Secret 的读取、拒绝、轮换与审计必须可验证 | **加密层**（security secret_store.rs，16 测试，ADR-0001 方案 A XChaCha20Poly1305 envelope：算法 0x01/版本 0x01/nonce 24B/末 16B tag，header 作 AAD）：`roundtrip_recovers_plaintext`、`roundtrip_empty_plaintext`、`ciphertext_differs_from_plaintext_and_is_random`（每次加密随机 nonce）、`tampered_ciphertext_rejected`、`tampered_header_rejected`、`truncated_envelope_rejected`、`wrong_key_rejected`、`oversized_plaintext_rejected`/`oversized_envelope_rejected`、`secret_cipher_requires_32_byte_key`、`debug_and_display_never_leak_material`；KEK（方案 C FileKeyProvider）：`key_provider_creates_and_reloads_kek`、`key_provider_rejects_corrupt_kek_files`（fail closed，绝不静默回退）、`key_provider_rejects_invalid_data_root`、`provider_kek_roundtrips_through_cipher`、`kek_dir_and_file_have_restrictive_permissions`（Unix 0700/0600；Windows 降级继承 data_root 权限——ADR-0001 披露）；**服务层**（application secret.rs，8 测试，§17.5 四层授权链 + 防泄漏契约）：`read_secret_returns_plaintext_for_granted_name`（读取）、`read_secret_denied_without_grant_even_if_stored`（拒绝）、`read_secret_denied_when_name_missing_even_if_granted`（与不存在合并，防存在性预言机）、`rotate_increments_secret_version_and_read_returns_latest`（轮换）、`delete_secret_removes_and_subsequent_read_is_denied`、`list_granted_secrets_filters_by_grant_scope`、`read_secret_corrupt_ciphertext_is_corrupt`（损坏值绝不返回）、`audit_and_errors_never_contain_secret_value`（审计）；**storage 接线**（executor，2 测试）：`secret_ciphertext_opaque_roundtrip_and_version_increment`（不透明 BLOB 逐字节往返、轮换版本 +1、列表不含值）、`secret_table_has_no_plaintext_column`；**e2e**：stateful_e2e 中 rotate → 密文落库（`assert_ne!` 密文 ≠ 明文）→ 按 grant 读取明文只在返回值 → grant 外 `Denied` → 审计序列含 SecretRead 且序列化后不含明文 | **PASS**（key-provider 选型为 **ADR-0001 Proposed（待 Owner 裁决），按推荐方向实现**，见第 4 节） |
| 3 | 普通 SQLite metadata dump 不得直接暴露 secret 明文 | storage executor `secret_table_has_no_plaintext_column`（executor.rs:3921）：写入明文形态字节 → shutdown → 以原始连接 `PRAGMA table_info(component_secret)` 断言**恰 6 列**（installation_id / secret_name / secret_version / ciphertext / metadata / updated_at）、ciphertext 类型必须 **BLOB**、"不存在任何可容纳明文的列"、明文形态字节只出现在 ciphertext 列（`assert_eq!(ciphertext, plaintext)` 语义为 storage 不解密原样落库）且 secret_name/metadata 不含明文子串；schema.rs component_secret DDL 佐证（§16.6/ADR-0001：storage 只存不透明密文、metadata 只承载非敏感信息、CHECK 约束）；配套：`state_audit_events_never_contain_value_bytes`、`migration_audit_never_contains_data`、`sessions_never_store_plaintext_token`（0.1） | **PASS** |
| 4 | 0.3 全量测试数汇总 | workspace **833 测试 0 失败**（0.2.0 章节第 1 节同轮）。0.3 相关新增：security secret_store 16（security 50→65）、application migration 12 / secret 8 / state 20 / config 5 / event 2 / scheduler 4 / lifecycle 1（application 65→205，含 stateful_e2e 1）、storage-sqlite 104（65→104：executor 状态面含迁移/取消/无残留 ~22 + 迁移表 5）、runtime-wasm 45（32→45，0.2 链接面）、conformance 35（22→35，0.2 composition 13）；observability 23、server 72、web-admin 50、web-component 18、runtime-wasi-p2 12、platform 9+5 等与 0.1 相同 | **PASS** |

---

## 3. §37 Release Gate 逐项（本机子集，0.3.0 轮）

见本节第 1 节表（0.3 变更项）+ 0.2.0 章节第 3 节（未变更项）。补充：Gate 4 unit/property/integration/conformance 含 0.3 状态面全套（state 20 + migration 12 + secret 8 + config 5 + executor 状态面 22 + e2e 1）；Gate 5 security tests 含加密层 16；Gate 7/8/9 见第 1 节表。Gate 14 无 release-blocker：已知缺口见下节。

---

## 4. 已知非阻塞缺口清单（0.3.0）

1. **SecretStore key-provider：ADR-0001「SecretStore 密文加密原语与跨平台 key provider 选型」状态 = Proposed（待 Owner 裁决），按推荐方向实现**。实现采用推荐方向：方案 A（RustCrypto chacha20poly1305 0.11 线 XChaCha20Poly1305，经审计、纯 Rust，§23.1 九问完成）+ 方案 C（`data_root` 下独立目录文件 KEK，Unix 0700/0600，Windows 降级继承 data_root 权限——披露性选择）。待 Owner 裁决点：加密原语二选一（chacha20poly1305 vs aes-gcm）、0.3.0 范围确认、依赖 Gate 批准（chacha20poly1305 为唯一新增 production direct dependency）、KEK 目录/Windows ACL 形态。裁决前不自行标记 Accepted（§50：Owner Gate 决策）。密文 envelope 契约（算法标识/版本/nonce/AAD）已冻结，未来 OS provider（方案 B，0.4+）切换路径已留 KeyProvider trait + 版本字段。
2. **conformance 工具链缺口**：0.1 的 7 项 + 0.2 的 2 项（见 0.2.0 章节第 4 节），`gap_inventory_is_recorded` 审计门保障。0.3 专项：**stateful/secret 真实 guest 夹具未列入缺口清单**——当前迁移以 closure 注入（Core 侧编排不调用 wasm，migration.rs 模块文档）+ 真实 executor e2e 覆盖；导出 `operune:state@0.1.0`/`operune:secret@0.1.0` 契约的真实 guest 组件需 cargo-component，工具链就绪后应补入清单并增补（如实记载：这是当前覆盖方式的边界，不是已实现端到端）。
3. **checkpoint**（§41.2 MUST）：实现为最小入口（`CheckpointPort`，lifecycle.rs 模块文档；`ready_requires_registry_entry` 为唯一 lifecycle 测试）——无端到端 checkpoint 编排测试。§41.3 验收未直接覆盖 checkpoint，列为 scope 内待补项。
4. **升级触发迁移编排**：MISSING-EVIDENCE（§41.3 #1g），见第 2 节——需补齐"upgrade 管线 → state-declaration.schema-version 比较 → 迁移触发"组合测试。
5. **qualification / soak / §33 fault-injection / loom / 集成空壳 / platform-linux-macos 骨架**：同 0.1/0.2 记录。
6. **§54 delta**：domain graph.rs 生产路径 5 处 `unreachable!`（见 0.2.0 章节 1.1），同轮记录。
7. **CI 现场状态**：同 0.2.0 章节第 5 节（本机无 gh/git 权限；ci.yml 同版本同命令，本机通过 = 同参数等价验证）。

---

## 5. CI 状态引用

与 0.2.0 章节第 5 节相同：`.github/workflows/ci.yml` push/PR/workflow_dispatch 矩阵（ubuntu + windows），命令与本机逐一对应（fmt/clippy/test/deny/audit，全部 `--locked`）；本机以相同版本工具链执行全部通过；Linux 侧结果需 CI 现场确认。

---

## 6. 结论（0.3.0）

**0.3.0 本机可执行验收子集达成（含 1 项编排级 MISSING-EVIDENCE）**：

- 本机全量门禁（fmt / clippy -D warnings / 833 测试 0 失败 / §54 / cargo-deny / cargo-audit）全部通过；
- §41.3 验收逐项：**PASS 10 项**（1a 迁移原子推进、1b 失败回滚、1c crash、1d 取消、1e 磁盘失败（模拟级）、1f schema 版本绑定、#2 Secret 读/拒/轮换/审计、#3 SQLite dump 无明文、#4 全量测试数，以及 0.2 章节承接的确定性框架），**PASS-模拟 1 项**（1e 之 §33 进程级注入部分 = NOT-EXECUTABLE-本机），**MISSING-EVIDENCE 1 项**（1g 升级管线触发迁移的端到端编排测试——各原子性属性均已 PASS，组合编排待补）；
- SecretStore key-provider 按 **ADR-0001 Proposed（待 Owner 裁决）的推荐方向**实现（XChaCha20Poly1305 AEAD + 文件 KEK），裁决点见第 4 节；
- 无 release-blocker；全部已知缺口记录在案（工具链 9+ 项、qualification、soak、§33、checkpoint 最小入口、1g 编排缺口）。

---

# Operune 0.4.0 验收记录（ACCEPTANCE 增补：Web Application Runtime）

- **日期**：2026-08-08
- **验收对象**：Operune Core Runtime 0.4.0（Web Application Runtime，规范 §42）
- **依据**：规范 §42.4（0.4.0 验收）、§42.2（MUST Scope）、§42.3（WASI 0.3 条件）、§8.3（WASI 0.3 准入 Gate）、§37（Release Gate）、§54、§35、§36；沿用 0.1/0.2/0.3 验收框架（§38：每个版本是前一版本的真实超集——0.4 全量 1019 测试中原样包含 0.3 的 833 测试，且 0.1 的 §39.4 基线验收不因新版本撤销）
- **执行方式**：本机可执行子集验收（Windows x86_64）。全部 `cargo` 命令使用 `--locked`（§22.1；cargo-deny/cargo-audit 为各自固有调用形态，见下）。未执行任何 git 命令；除本文件外未修改任何文件。
- **环境**：与 0.2.0/0.3.0 章节同一主机环境（Windows 11 Pro Build 26200，rustc/cargo 1.97.1，rustfmt 1.9.0-stable，clippy 0.1.97，cargo-deny 0.20.2，cargo-audit 0.22.2）。**门禁为本轮全新执行**（非引用旧轮结果）。

---

## 1. 本机全量门禁结果（§37 本机子集 + §54，0.4.0 轮全新执行）

| # | 门禁 | 命令 | 结果 | 证据 |
|---|---|---|---|---|
| 1 | 格式化 | `cargo fmt --check` | **PASS** | exit 0，无 diff 输出 |
| 2 | clippy -D warnings | `cargo clippy --workspace --all-targets --locked -- -D warnings` | **PASS** | exit 0；`Finished dev profile in 6.82s`，零警告（workspace.lints 固化 `-D clippy::unwrap_used/-D expect_used/-D panic/-D todo/-D unimplemented` 与 `unsafe_code = "forbid"`，Cargo.toml:35-43） |
| 3 | 全量测试 | `cargo test --workspace --locked` | **PASS** | **1019 个测试全过、0 失败**（0.3 基线 833 → **+186**）：application 295 + stateful_e2e 1、conformance 35、domain 235、integration 0（空壳）、observability 23 + doc-test 1、platform 9、platform-windows 5、platform-linux/macos 0（骨架）、runtime-wasi-p2 12、runtime-wasm 45、security 65、server 72、storage-sqlite 104、web-admin 46（单元）+ 4（tls 集成）、web-component 67 |
| 4 | §54 机械检查 | grep crates/ 与 tests/ 下 `.rs` | **PASS** | 见下节 1.1 |
| 5 | 依赖门 | `cargo deny check advisories bans sources`（0.20.2，本轮运行） | **PASS** | `advisories ok, bans ok, sources ok`，exit 0（licenses 未启用属 §23.4 Owner 决策，CI 同配置） |
| 6 | 漏洞扫描 | `cargo audit`（0.22.2，本轮运行，1190 条 advisory） | **PASS** | 扫描 **364 个 crate 依赖**（与 0.3 轮一致，0.4 未新增生产依赖），**0 vulnerabilities**，exit 0 |

### 1.1 §54 机械检查明细（0.4.0 轮）

- **`unsafe`**：代码中 **0 处**。grep 40 命中全部为：`#![forbid(unsafe_code)]` 指令行（各 crate 根）、CSP 策略字符串 `'unsafe-inline'`/`'unsafe-eval'`（web-component/src/csp.rs、web-admin/src/headers.rs）与文档注释。无 `unsafe {}` / `unsafe fn` / `unsafe impl`。workspace 级 `forbid(unsafe_code)` + clippy 通过 = 机械证明。
- **`unwrap(` / `expect(`**：0 处（排除测试代码 `Arc::try_unwrap` 等不同 API；与 0.2/0.3 记录一致）。**`panic!`**：0 处（仅文档注释）。**`todo!` / `unimplemented!`**：0 处（仅文档注释）。
- **`unreachable!`**：70 处非注释命中，**除 0.2 已记录的 domain graph.rs 生产路径 5 处 §14.3 fail-stop 外（resolve():516/526、compute_activation_order():563/616、find_cycle():664，带不变量说明消息，0.4 未新增），其余全部位于 `#[cfg(test)]` 模块**——本轮逐一核对 cfg(test) 边界：security 6 文件（session_cookie.rs:94、session.rs:372、token.rs:149、tls.rs:333、password.rs:360、csrf.rs:109 均 < cfg(test)）、observability（metrics.rs:341 < cfg(test)；support.rs 经 lib.rs:33 `#[cfg(test)] mod support` 门控）、server（server.rs:200、cli.rs、bootstrap.rs、config.rs、compose.rs、audit.rs 均 < cfg(test)）、storage-sqlite（ports.rs:2092、testutil.rs < cfg(test)）、web-component（http_04_tests.rs、http_tests.rs 为测试文件，test_support.rs 首行 `#![cfg(test)]`）、platform-windows data_root.rs、domain lifecycle.rs:235/upgrade.rs。**0.4 新增生产代码（web-component src 各模块、application web_app.rs/cancel.rs/web.rs、domain web.rs）零新增生产路径 unreachable!**。
- 其余 §54 语义项（能力复用、领域泄漏、有界队列、deny-by-default 权限、审计不落 secret 等）由 §42.4 各验收测试覆盖，见第 2 节。

---

## 2. §42.4 验收逐项核对（本机可执行子集）

结论图例同 0.2/0.3 章节：**PASS** = 本机测试实证；**PASS-部分** = 本机部分实证（层内/架构级，端到端留工具链或 CI）；**NOT-EXECUTABLE-本机** = 需 cargo-component 工具链/CI，本机不可执行（如实标注，不以替代证据冒充端到端）；**MISSING-EVIDENCE** = 验收项无对应实现或测试（如实标注，不伪造）。

| # | 验收项 | 验证方式（测试名/文件） | 结论 |
|---|---|---|---|
| 1 | 测试 Component 仅凭标准 `.wasm` 提供完整 UI + backend，安装后出现 | **端到端 NOT-EXECUTABLE**：本机无 cargo-component/wasm-tools，无法构建导出 `operune:web@0.2.0` 契约的真实 guest 夹具（工具链缺口在案，gaps.rs `gap_inventory_is_recorded`：web assets + sandbox escape 组件、minimal valid Component、descriptor 全链路等，补齐条件 = cargo-component 就绪）——§42.4 核心验收项无法以真实 `.wasm` 实证。**层内替代证据（如实标注非端到端）**：application `activation_builds_web_app_context`（安装→激活→web-app context 建立并持久化）；web-component HTTP 层 `installed04` 夹具安装后：`navigation_index_lists_pages_and_default_page`（UI 出现）、`root_resolves_to_default_page`、`page_navigation_serves_page_asset`（页面可服务）、`dispatch_success_with_typed_params`（backend 可达）；0.1 兼容路径 `legacy_component_keeps_01_asset_and_action_paths` | **NOT-EXECUTABLE**（§42.4 核心项；层内替代证据全 PASS） |
| 2 | 升级时整体切换（§21.5/§42.2 原子版本：backend exports + assets + descriptor 同一 ComponentVersion 一次性切换，禁止前后端版本拼接） | application web_app_tests.rs `upgrade_swaps_web_app_context_atomically`（v2 声明激活后断言 v1 路由 `get-item` 从 registry 消失、v2-only 路由可解析且经同一 WebAppService 分发成功——"旧声明必须在原子切换后消失"）；upgrade.rs `upgrade_swaps_and_drains_old_version`（旧版本实例排空、drain 有 deadline）；0.1 基线 `upgrade_failure_keeps_v1_active` 原样通过 | **PASS** |
| 3 | 卸载后完整消失 | **无卸载操作**：grep crates/ tests/ 全量 `uninstall` 0 命中。存在的近似面：admin `disable`（facade.rs:831：drain(deadline) + 状态 Disabled + `active.remove(id)` + 审计 `component.disable`；测试 `disable_transitions_active_to_disabled`、`users_crud_and_disable_revokes_sessions`；且 `enable` 显式 `Unsupported`——disable 不可逆，非 uninstall）；composition `deactivate`（`deactivation_removes_records_and_swaps_snapshot`，仅清 graph records）；storage 无 installation 删除 API。**"卸载后 UI+backend 完整消失（资产/路由/记录全清）"无可测试对象** | **MISSING-EVIDENCE**（卸载操作本身未实现，属本版本验收缺口，见第 4 节 #1） |
| 4 | 权限由 Core 统一治理（page/action permission 声明，§42.2） | web-component http_04_tests.rs：`page_navigation_with_permission_denied_is_403`、`page_navigation_with_permission_allowed`、`dispatch_unauthorized_is_403`；application web_app_tests.rs：`dispatch_route_permission_denied_before_guest`（拒绝发生在 guest 调用前，`route_calls()==0`）、`dispatch_route_permission_granted_by_named_scope`、`authorize_page_denied_without_grant`、`authorize_page_allowed_with_named_grant`、`authorize_page_not_active_denied`；0.1 基线 `web_action_denied_without_grant`/`web_action_scoped_grant_matches_action_name` 原样通过 | **PASS**（层内证据） |
| 5 | 路由由 Core 统一治理（route namespace + conflict diagnostics，§42.2） | application web_app_tests.rs 声明期诊断：`build_app_declaration_rejects_route_id_conflict`、`rejects_route_path_conflict`、`rejects_page_route_conflict`、`rejects_param_mismatch`、`same_path_different_method_ok`、`rejects_default_page_not_declared`、`validate_contract_surface_cross_checks_exports`（声明与二进制 exports 交叉校验，§6.7 精神）；web-component mount.rs `namespaces_are_disjoint_by_installation`（挂载命名空间按 InstallationId 隔离）、`page_and_navigation_urls_live_under_mount_namespace`；HTTP 层 `dispatch_route_not_matched_is_404`、`navigation_unknown_installation_is_404`、`navigation_unknown_page_is_404`；domain web.rs 46 测试（typed params 闭集解析、整数溢出拒绝、路径规范化） | **PASS**（层内证据） |
| 6 | 资源由 Core 统一治理（bounded request/response + per-Component HTTP quotas/backpressure，§42.2） | web-component http_04_tests.rs：`dispatch_quota_exceeded_is_429`、`dispatch_rate_limit_by_http_gate_is_429`、`dispatch_concurrency_limit_by_http_gate_is_503`（`#[tokio::test(flavor="multi_thread")]` 并发上限）、`dispatch_body_over_limit_rejected_early`、`dispatch_response_over_limit_rejected`；quota.rs 4 测试（`gate_rate_limits_in_window`、`gate_busy_when_in_flight_at_cap`、`gate_instances_are_independent`——quota 按 installation 隔离）；application：`dispatch_route_quota_rate_limit_rejected`（OverQuota(RateLimited)）、`dispatch_route_rejects_oversized_payload`（BodyTooLarge 且 guest 0 调用）、0.1 基线 `web_action_body_over_limit_denied`/`rate_limit_denies_burst` | **PASS**（层内证据） |
| 7 | 浏览器安全由 Core 统一治理（CSP/security policy，§42.2） | web-component csp.rs `csp_covers_minimum_isolation_floor`（restrictive CSP 显式含 `default-src 'none'`/`script-src 'self'` 且无 `'unsafe-inline'`/`'unsafe-eval'`/`form-action 'none'`/`frame-ancestors 'none'`/`base-uri 'none'`/`object-src 'none'`/无外源通配）；http_04_tests.rs `assert_core_headers`（navigation/page/dispatch 响应全部携带 COMPONENT_CSP + `X-Content-Type-Options: nosniff` + **无 Set-Cookie**——Core 最后写，组件不可覆盖）；0.1 基线 CSP/headers 测试原样通过；WIT world.wit 明文：全部 browser isolation 面由 Core 生成并强制，**组件不存在放宽 sandbox/CSP 的配置面** | **PASS**（层内证据） |
| 8 | Core 不包含该业务页面知识 | 架构级证据：navigation.rs 模块文档（"Core 是导航的唯一执行者：页面集合是安装期声明事实，不随运行期变化"；`NavigationIndex::from_declaration` 只搬运声明字段、不解析业务语义）；页面内容对 Core 为不透明字节（资产按 digest+path 缓存直供，`asset_carries_content_digest_and_immutable_cache`）；行为证据：`navigation_unknown_page_is_404`、`page_navigation_for_01_component_is_404`（Core 对未声明页面无知识残留）。完整端到端实证（真实组件携带业务页面走完整生命周期）随 #1 工具链缺口 | **PASS-部分**（架构/层内证据充分，端到端随 #1 NOT-EXECUTABLE） |
| 9 | realtime/stream：仅当 §8.3 Gate 通过并宣称时才有 native async/stream conformance 义务；Gate 未过则不得假装该能力存在 | **Gate 状态确认 = 未通过**：机械证据——crates/ 下 `wasmtime_wasi::p3` 引用 **0 处**、无 wasi:http / stack-switching 引用；runtime-wasi-p2 Cargo.toml 明文 "production 仅 p2"；docs/adr 仅 ADR-0001（无 WASI 0.3 迁移 ADR，Gate 第 8 条不满足）。**未宣称证据**——WIT web@0.2.0 全部契约均为 p2 同步形态：app-descriptor.wit:109 "本版本**没有** realtime / stream flag：§42.3 条件未满足（§8.3 WASI 0.3 production Gate 未通过）"、route-dispatch.wit "同步 p2 形态：无 `stream<T>`、无 `future<T>`、无 async"、actions.wit 继承 0.1 边界（"无 WebSocket、无任意长连接、无流"）；grep crates/ `stream|future<T>|realtime` 实现代码 **0 命中**；无平行 async/stream ABI（§42.3 禁令）。p2/p3 adapter boundary 保留（runtime-wasi-p2 12 测试 + runtime-wasm wasi.rs trait 边界） | **PASS**（如实：Gate 未过 → 能力未宣称 → 无 native conformance 义务，验收不假装该能力存在） |
| 10 | bounded request/response + cancellation 作为无条件 baseline（§42.2/§42.3） | application cancel.rs 6 测试（`fresh_token_is_not_cancelled`、`cancel_is_idempotent`、`cloned_tokens_share_cancellation`、`cancelled_before_await_returns_immediately`、`cancel_wakes_waiting_waiter`、`repeated_cancelled_awaits_are_instant`）；web-component http_04_tests.rs `dispatch_cancelled_maps_to_408`（客户端取消 → 408 确定语义）、`cancellation_token_flows_through_full_http_path`（每次 route 调用绑定 token：调用期间 fresh、handler 完成后 CancelOnDrop 幂等取消——客户端断开 → hyper 丢弃 future → 同机制取消 → epoch interruption 中止 in-flight guest 调用）；application：`dispatch_route_cancelled_token_refuses_to_start`（已取消不启动新调用）、`dispatch_route_post_call_cancellation_discards_result`（调用结束已取消 → 结果丢弃、已提交副作用不回滚、审计仍记录）、`dispatch_route_deadline_exceeded_maps_deterministically`；0.1 基线 epoch deadline 中断（conformance `infinite_loop_interrupted_by_epoch_deadline`）原样通过 | **PASS** |
| 11 | 0.4 全量测试数汇总 | 见第 1 节门禁 #3：workspace **1019 测试 0 失败**（0.3 的 833 全部原样包含并全过）。0.4 相关新增：domain web.rs 46（189→235）、application +90（205→295：web_app_tests 51 + web.rs 11 + cancel 6 + 其余 web-app 接线）+ stateful_e2e 1、web-component +49（18→67：http_04_tests 30 + dispatch 7 + quota 4 + mount 4 + integrity 3 + router 2 + navigation 2 + csp 1）；conformance 35、security 65、storage 104、server 72、web-admin 50、observability 23、runtime-wasm 45、runtime-wasi-p2 12、platform 14 等与 0.3 相同 | **PASS** |

### §42.2 MUST Scope 覆盖对照（供 Gate 8/13 参考）

- **app descriptor / navigation / pages / typed routes / permissions / route-dispatch**：WIT `operune:web@0.2.0` 五新增面（app-descriptor/navigation/routes/permissions/route-dispatch）+ domain `AppDeclaration` + application `WebAppService`——层内测试齐（#4-#7、#10）。
- **Web asset caching/integrity**：http_04_tests.rs `asset_carries_content_digest_and_immutable_cache`（digest 绑定不可变缓存）、`page_carries_content_digest_and_no_cache`；web-component integrity.rs 3 测试；0.1 基线 web.rs 资产缓存 + `asset_url_includes_digest_for_atomic_versioning`（URL 级原子版本）。
- **0.1 基础不重造第二套 bridge**：`legacy_component_keeps_01_asset_and_action_paths`、`root_for_01_component_still_redirects_to_entry_asset`、`navigation_for_01_component_is_404`/`dispatch_for_01_component_is_404`（0.4 面不侵入 0.1 路径）。
- **Web compatibility/conformance suite**：conformance 35 与 0.3 相同，**未新增 0.4 夹具**（工具链缺口，第 4 节 #2）——如实标注。

---

## 3. §37 Release Gate 逐项（本机子集，0.4.0 轮）

| # | Gate | 结论 | 证据 |
|---|---|---|---|
| 1 | `cargo fmt` | **PASS** | 本轮 `cargo fmt --check` exit 0 |
| 2 | clippy `-D warnings` | **PASS** | 本轮全 workspace 全 targets 零警告（6.82s） |
| 3 | `forbid(unsafe_code)` 全 workspace | **PASS** | workspace.lints + 各 crate `#![forbid(unsafe_code)]` + grep 0 处 unsafe 代码 |
| 4 | unit/property/integration/conformance | **PASS** | 1019 测试 0 失败（含 conformance 35、集成 stateful_e2e 1） |
| 5 | security tests | **PASS** | security 65 + web-admin 50（46+4 tls）原样全过（0.4 未触碰 security 面） |
| 6 | dependency advisory/license/source gate | **PASS** | 本轮 cargo-deny 0.20.2：advisories/bans/sources 全 ok（364 依赖）；cargo-audit 0.22.2：0 漏洞；licenses 未启用 = §23.4 Owner 决策 |
| 7 | migration test | **PASS** | storage-sqlite 104 原样全过（0.4 无 schema 变更；0.3 迁移 12+2 在案） |
| 8 | upgrade/rollback test | **PASS** | upgrade.rs 9 + 0.4 新增 `upgrade_swaps_web_app_context_atomically` + composition 升级门控 5 + conformance 升级 3 |
| 9 | crash recovery test | **PASS** | storage recovery 9 + 0.3 状态面无残留全套原样通过；§33 完整 fault-injection = nightly/CI |
| 10 | platform production qualification | **NOT-EXECUTABLE-本机** | 需 Linux x86_64 GNU / aarch64 GNU 原生 runner（§36 矩阵）；Windows x86_64 本机全量通过 |
| 11 | release binary smoke | **NOT-RE-RUN** | 0.1 记录已实证（`cargo build --release --locked -p operune-server` + version/--help）；本 0.4 轮未重跑 release 构建（无 release 面变更证据要求），如实标注 |
| 12 | SBOM/provenance/sha256/signing | **NOT-EXECUTABLE** | §37.12 按路线图进入相应版本后为 MUST；0.4.0 未启用（同 0.1-0.3） |
| 13 | 文档/CLI/API compatibility check | **PASS-部分** | WIT `operune:web@0.2.0` 契约已提交稳定（wit/operune/web@0.2.0/ 七文件 + world.wit，与 0.1.0 package 并存，§8.4 无 flag-day）；0.1 组件兼容路径由 `legacy_component_keeps_01_asset_and_action_paths`、`root_for_01_component_still_redirects_to_entry_asset` 实证；CLI 面 0.1 测试原样通过 |
| 14 | 没有 unresolved release-blocker | **PASS-条件** | 本机子集未发现既有面回归 blocker；但 §42.4 #3 卸载操作为 MISSING-EVIDENCE（见第 4 节 #1）——按 §42.4"全部成立"语义，0.4.0 最终标记前需卸载落地或 Owner 明确裁决 |

---

## 4. 已知非阻塞缺口清单（0.4.0）

1. **卸载操作缺失（§42.4 #3 = MISSING-EVIDENCE，本轮新发现）**：全仓无 uninstall 实现（crates/ tests/ grep 0 命中）；admin 面仅 `disable`（drain + Disabled + active.remove，`enable` 显式 Unsupported）；composition `deactivate` 仅清 graph records；storage 无 installation 删除 API。"卸载后 UI + backend 完整消失"无可测试对象。0.1-0.3 验收未要求卸载，§42.4 首次显式要求——属本版本验收缺口，需实现卸载管线（资产/路由/记录/audit 清理 + 原子性）并补测试。
2. **conformance 工具链缺口（§42.4 #1 端到端不可实证）**：cargo-component / wasm-tools 本机不可用（gaps.rs `gap_inventory_is_recorded` 审计门在案）。0.1 的 7 项 + 0.2 的 2 项不变；**0.4 专项**：导出 `operune:web@0.2.0` 全契约面的真实 Web app 组件（完整 UI + backend 单一 `.wasm`）、web assets + sandbox escape 攻击组件、descriptor 全链路、升级整体切换的真实二进制对——当前全部以 fake port / 声明构造覆盖层内语义，端到端随工具链补齐。
3. **realtime/stream 未宣称（非缺口，如实记录）**：§8.3 Gate 未通过（无 p3 代码、无迁移 ADR），native async/stream 按 §42.3 顺延到第一个满足 Gate 的 release；本版本无 native conformance 义务，验收不假装该能力存在（§42.4 末句）。
4. **qualification / soak / §33 完整 fault-injection / loom / tests/integration 空壳 / platform-linux-macos 骨架**：同 0.1-0.3 记录。
5. **§54 delta**：与 0.2/0.3 相同——domain graph.rs 生产路径 5 处 §14.3 fail-stop `unreachable!`（带不变量说明消息）；**0.4 新增代码零新增生产路径 unreachable!/unsafe/panic 宏**（见 1.1）。
6. **CI 现场状态**：同 0.3（本机无 gh/git 权限，无法直接读取 CI 运行历史；ci.yml 与 0.20.2/0.22.2 pin 及命令与本机一致，本机通过 = 同参数等价验证；Linux 侧结果需 CI 现场确认）。

---

## 5. CI 状态引用

与 0.3.0 章节相同：`.github/workflows/ci.yml`（push/PR/workflow_dispatch，ubuntu + windows 双矩阵），命令与本机逐一对应：fmt（`cargo fmt --check`）、clippy（`cargo clippy --workspace --all-targets --locked -- -D warnings`）、test（`cargo test --workspace --locked`）、cargo-deny（0.20.2）、cargo-audit（0.22.2）。本机以相同版本工具链/命令全部执行并通过（fmt/clippy/test/deny/audit 共 6 项，见第 1 节）。工具链一致：rust-toolchain.toml 冻结 1.97.1，本机 `rustc 1.97.1 (8bab26f4f 2026-07-14)` 一致。

---

## 6. 结论（0.4.0）

**0.4.0 本机可执行验收子集达成（含 1 项 §42.4 MISSING-EVIDENCE 与 1 项核心项 NOT-EXECUTABLE）**：

- 本机全量门禁（fmt / clippy -D warnings / **1019 测试 0 失败** / §54 机械检查 / cargo-deny / cargo-audit）全部通过；0.3 基线 833 → 1019（+186：domain web.rs 46、application web_app_tests 51 + web.rs 11 + cancel 6 等 +90(+1 e2e)、web-component http_04_tests 30 + dispatch/quota/mount/integrity/router/navigation/csp 19 +49）；0.1/0.2/0.3 全部既有测试原样通过（§38 真实超集）；
- §42.4 验收逐项：**PASS 7 项**（#2 升级整体切换、#4 权限、#5 路由、#6 资源、#7 浏览器安全 Core 统一治理、#9 realtime 未宣称（如实）、#10 bounded+cancellation baseline、#11 全量测试数）、**PASS-部分 1 项**（#8 Core 不包含业务页面知识——架构/层内证据充分，端到端随工具链）、**NOT-EXECUTABLE 1 项**（#1 测试 Component 端到端——cargo-component 工具链缺口，层内替代证据全 PASS，如实标注不冒充）、**MISSING-EVIDENCE 1 项**（#3 卸载后完整消失——卸载操作未实现）；
- §37 共 14 项：本机可执行项 PASS（含依赖门/漏洞扫描本轮实测），qualification/SBOM/§33 等 NOT-EXECUTABLE 项同 0.1-0.3，无回归 blocker；
- **0.4.0 最终标记的前置条件（本机结论）**：§42.4 全文语义要求——(a) 卸载管线落地并补齐"卸载后完整消失"测试；(b) cargo-component 工具链就绪后以真实 `.wasm` 完成 #1 端到端验证；(c) 既有 NOT-EXECUTABLE qualification 项由 CI/目标硬件完成。任一未达，0.4.0 不得按 §42.4"只有全部成立"语义完成最终标记。
