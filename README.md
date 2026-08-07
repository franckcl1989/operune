# Operune

Operune 是一个**场景无关、运维领域有边界的 WebAssembly-native 平台级产品**：以 Rust Core Runtime 作为唯一不可卸载的原生基础层，以标准 WebAssembly Component 作为唯一可安装扩展执行单元，以 WIT 作为唯一跨 Component 边界的结构化接口契约语言，标准能力优先直接复用 WASI。具体运维领域能力（监控、日志、告警、Kubernetes、数据库、设备集成等）全部由标准 WebAssembly Components 提供，不属于 Core。（完整产品定义见规范 §1；最终总纲见规范 §56。）

## 当前状态

0.1.0 — Production Kernel 路线图推进中（规范 §39）。当前为**仓库骨架里程碑**（2026-08-07）：

- workspace 结构与 crate 边界按规范 §24 冻结结构就位；
- toolchain 精确固定 Rust 1.97.1（`rust-toolchain.toml`，§22.1）；
- §22 依赖基线已逐项向 crates.io 校验（审计证据：`DEPENDENCY_PROBE.md`），版本约束冻结于 workspace.dependencies；
- lint 门禁（Safe Rust + panic-free restriction lints，§11/§14/§26.1）与 CI（§26.1/§36）就位；
- 各 crate 尚未实现业务逻辑（YAGNI §12.6）。

## 技术基线（0.1.0，规范 §4.1 / §9.3 / §22）

- Rust 2024 Edition；toolchain 精确固定 1.97.1；
- Wasmtime 36 LTS（production line）+ WebAssembly Component Model / WIT / WASI 0.2；
- Production Supported targets：`x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`；Windows x86_64、macOS arm64 为一等 CI/架构适配；
- 第一方代码 100% Safe Rust：`#![forbid(unsafe_code)]`（§11.1）；
- committed `Cargo.lock`，所有 production build 使用 `--locked`（§22.1）。

## Workspace 结构

规范 §24.1 冻结结构：

```text
crates/domain, application, runtime-wasm, runtime-wasi-p2, web-admin,
web-component, storage-sqlite, security, platform, platform-linux,
platform-windows, platform-macos, observability, server
tests/conformance, tests/integration
```

各 crate 责任划分见规范 §24.2；依赖方向（adapter → application → domain）见 §24.3。

## 文档

- 工程主规范：`OPERUNE_PLATFORM_ENGINEERING_MASTER_SPEC_R2_FROZEN_2026-08-07.md`
- 依赖版本校验审计：`DEPENDENCY_PROBE.md`

## 开发

toolchain 由 `rust-toolchain.toml` 自动切换。常用命令：

```text
cargo check --workspace --locked
cargo fmt --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```
