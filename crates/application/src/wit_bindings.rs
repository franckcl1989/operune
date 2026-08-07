//! `operune:*@0.1.0` WIT 契约的编译期权威验证（§22.2 bindgen 集成）。
//!
//! # §25 裁决一：bindgen 全量代码生成与 `#![forbid(unsafe_code)]` 的冲突
//!
//! §11.1 / workspace lints 机械要求本 crate 根模块 `#![forbid(unsafe_code)]`；
//! §22.2 要求 Host WIT binding 使用 `wasmtime::component::bindgen!`。
//! 两者在本 crate 内不可同时满足：wasmtime 36 的 bindgen 生成代码对 guest
//! export 调用使用 `unsafe { TypedFunc::new_unchecked(...) }`
//! （wasmtime-internal-wit-bindgen 36 的 `define_rust_guest_export`），且
//! `Lift`/`Lower`/`ComponentType` 为 unsafe trait（`unsafe impl` 同样被
//! `forbid(unsafe_code)` 拒绝）。`forbid` 不可被任何 `allow` 覆盖（rustc
//! lint 语义），因此 bindgen 全量代码生成无法在本 crate 编译。
//!
//! 裁决（§25 顺序：D1 WebAssembly/WASI 标准机制 → D2 标准优先：bindgen!
//! 是 §22.2 冻结基线中的标准 Host binding 工具，其 unsafe 是第三方 codegen
//! 输出，不是第一方编写；§11.1 禁止的是"第一方 unsafe / 以代码生成方式
//! 偷偷引入第一方 unsafe"）：
//!
//! 1. 本模块以 `stringify: true` 形态消费 bindgen!：**完整的 WIT 解析、
//!    world 解析与代码生成在编译期执行**；若 WIT 存在语法 / 类型错误，
//!    编译失败并给出具体错误（这就是任务要求的"WIT 语法/解析的权威验证点"）。
//!    生成结果以字符串常量保留，不引入任何 unsafe。
//! 2. 运行时 typed 调用改走 **Safe Wasmtime Component API**（`Linker` /
//!    `Instance` / `Func::call` / `Val`，全部 safe），经 runtime-wasm 公开缝
//!    （`engine()` / `store_mut()` / `component()`）集成（见 [`crate::runtime`]）。
//! 3. 需要完整 bindgen 类型面（typed Host/guest 包装）时的最终形态（例如
//!    独立 bindings crate 或 ADR 调整）属于主 agent 的 workspace 级决策，
//!    本任务按 §25 局部自主裁决继续，不伪造通过。
//!
//! # §25 裁决二：WIT 文件解析错误（已修复，2026-08-07）
//!
//! bindgen 曾在 WIT 解析阶段失败——错误指向 WIT 文件本身（**不是**本 crate
//! 的问题）。先后暴露两个错误，均已修复：
//!
//! **第一个错误**（类型定义位于 interface 之外）原文如下
//! （wasmtime 36 内嵌 wit-parser 0.236.1）：
//!
//! ```text
//! error: failed to resolve directory while parsing WIT for path
//!        [\\?\C:\Users\franck\Documents\operune\wit\operune\component]
//! Caused by:
//!     0: failed to parse package:
//!        \\?\C:\Users\franck\Documents\operune\wit\operune\component
//!     1: expected `world`, `interface` or `use`, found keyword `record`
//!            --> \\?\C:\Users\franck\Documents\operune\wit\operune\component\descriptor.wit:37:1
//!             |
//!          37 | record component-id {
//!             | ^-----
//! ```
//!
//! 修复：各 `record` / `enum` / `variant` / `flags` 类型定义已移入其所属
//! `interface` 块内（`component/descriptor.wit`、`web/descriptor.wit`、
//! `web/assets.wit`、`web/actions.wit`），`web/assets.wit` 以
//! `use descriptor.{asset-path}` 从同 package 的 interface 导入；语义不变。
//!
//! **第二个错误**（package 级 doc 注释冲突）完整原文如下：
//!
//! ```text
//! error: failed to resolve directory while parsing WIT for path [\\?\C:\Users\franck\Documents\operune\wit\operune\component]
//!        Caused by:
//!            0: failed to parse package: \\?\C:\Users\franck\Documents\operune\wit\operune\component
//!            1: failed to start resolving path: \\?\C:\Users\franck\Documents\operune\wit\operune\component\world.wit
//!            2: found doc comments on multiple 'package' items
//!                    --> \\?\C:\Users\franck\Documents\operune\wit\operune\component\world.wit:1:1
//!                     |
//!                   1 | /// operune:component@0.1.0 — 参考 world（作者侧便利，非运行时事实源）
//!                     | ^----------------------------------------------------------------------
//! ```
//!
//! 根因（wit-parser 0.236.1 `ast/resolve.rs` `Resolver::push`，
//! "At most one 'package' item can have doc comments"）：multi-file package
//! 的**每个文件**若在 `package` 声明前带注释，该注释都会附加到 package
//! item 上；同一 package 有 ≥2 个文件带 package 级注释即报此错。
//! 关键机制（2026-08-07 实测 + 源码核实）：0.236.1 的 lexer 对 `//` 与
//! `///` 产生同一个 `Comment` token，`parse_docs` 把 `package` 声明前的
//! **所有**注释（`//` / `///` / `/* */` 一律）收集为 package docs——
//! 因此"把 `///` 改为 `//`"无法消除冲突（实测仍报同样错误，错误点指向
//! 改为 `//` 后的注释行）。
//!
//! 修复（2026-08-07 执行，语义零改动）：每个 package 只保留**一个**文件
//! 在 `package` 声明前带注释——`operune:component` 与 `operune:web` 均保留
//! 各自的 `descriptor.wit`（主契约文件，其 `///` 不变）；其余四个文件的
//! 文件头注释块**整体移至 `package` 声明行之后**（内容一字不改、符号保持
//! `//`），成为紧随其后的 world / interface item 的 item 级 doc 注释，
//! 不再与 package item 冲突：
//! - `wit/operune/component/world.wit`：文件头 19 行移至 package 行后；
//! - `wit/operune/web/world.wit`：文件头 5 行移至 package 行后；
//! - `wit/operune/web/assets.wit`：文件头 20 行移至 package 行后；
//! - `wit/operune/web/actions.wit`：文件头 31 行移至 package 行后。
//!
//! interface 内部与类型上的 item 级 `///` doc 注释一律不动。
//!
//! 验证结果（2026-08-07）：两处 bindgen!（`stringify: true`）恢复后
//! `cargo check -p operune-application --locked` 编译通过——WIT 解析 /
//! world 解析 / 代码生成全部在编译期执行，§22.2 权威验证点恢复。
//! 另外发现 stringify 形态的宏展开是单个字符串字面量，模块级
//! `bindgen!(...);` 语句形式被 rustc 拒绝（"macro expansion ignores ..."），
//! 故两处调用以未命名 `const _: &str` 承载（见下方代码）。
//!
//! 依赖跟踪说明：stringify 形态下 bindgen 不生成 `include_str!` 依赖
//! （依赖跟踪只作用于非 stringify 路径），因此本模块仍显式 `include_str!`
//! 全部契约文件，保证 WIT 变更触发重新编译并重新验证（见下方常量）。
//!

// 编译期验证 `operune:component@0.1.0` 的参考 world（§6.6）。
//
// `path` 相对 `CARGO_MANIFEST_DIR`（crates/application）→ 各 package
// 目录；两个 package 都推入同一 resolve（web world 引用
// `operune:component/descriptor@0.1.0`）。若 WIT 解析 / world 选择 /
// 代码生成失败，此处产生编译错误（含具体错误文本），即 WIT 契约的
// 权威验证点（§22.2 / 任务 F）。
//
// stringify: true 形态（§25 裁决一）：宏在编译期执行完整 WIT 解析 /
// world 解析 / 代码生成，展开为生成源码的字符串字面量，以未命名
// `const _: &str` 承载——不引入任何 unsafe，也不生成具名常量；
// 依赖跟踪靠下方 include_str! 常量。
//
// 恢复记录（2026-08-07）：裁决二的两个 WIT 解析错误均已修复（类型层级
// 修复 + package 级 doc 注释冲突修复，细节与错误原文见模块文档裁决二），
// 两处 bindgen! 取消注释恢复 §22.2 权威验证点。
// stringify: true 形态的宏展开是单个字符串字面量：模块级的
// `bindgen!(...);` 语句形式被 rustc 拒绝（"macro expansion ignores ..."，
// 模块级只接受 item），故以未命名 `const _: &str` 承载展开结果。
const _: &str = wasmtime::component::bindgen!({
    path: ["../../wit/operune/component", "../../wit/operune/web"],
    world: "operune:component/operune-component",
    stringify: true,
});

// 编译期验证 `operune:web@0.1.0` 的参考 world（§6.6）——见上方第一个
// bindgen! 调用的说明（stringify 形态，§25 裁决一 / 二）。裁决二的
// WIT 解析错误已修复，随上一处一起恢复。
const _: &str = wasmtime::component::bindgen!({
    path: ["../../wit/operune/component", "../../wit/operune/web"],
    world: "operune:web/operune-web-component",
    stringify: true,
});

// —— WIT 文件内容依赖跟踪（stringify 形态下 bindgen 不自动跟踪；
//    路径相对本文件 crates/application/src/ → 仓库根 wit/）——
#[allow(clippy::items_after_statements)]
const _: &str = include_str!("../../../wit/operune/component/descriptor.wit");
const _: &str = include_str!("../../../wit/operune/component/world.wit");
const _: &str = include_str!("../../../wit/operune/web/descriptor.wit");
const _: &str = include_str!("../../../wit/operune/web/assets.wit");
const _: &str = include_str!("../../../wit/operune/web/actions.wit");
const _: &str = include_str!("../../../wit/operune/web/world.wit");

#[cfg(test)]
mod tests {
    /// §25 裁决二回归测试：wit-parser 0.236 报 "found doc comments on
    /// multiple 'package' items"——multi-file package 每个文件在 `package`
    /// 声明前的**任何**注释（`//` 与 `///` 同为一个 `Comment` token，见
    /// 模块文档裁决二）都会附加到 package item，同一 package 有 ≥2 个文件
    /// 带 package 级注释即报此错。修复规则：每个 package 只有一个文件
    /// （descriptor.wit）在 `package` 声明前带注释，其余文件该处无注释。
    /// bindgen! stringify 形态不生成具名模块 / 常量，无法在编译产物中
    /// 断言宏展开结果，故本测试在源码层面执行同一规则，防止未来新增
    /// 文件再次触发该编译错误。
    #[test]
    fn wit_package_docs_single_source_per_package() {
        fn comments_before_package(wit: &str) -> usize {
            wit.lines()
                .take_while(|line| !line.starts_with("package "))
                .filter(|line| line.starts_with("//"))
                .count()
        }

        let component_files = [
            include_str!("../../../wit/operune/component/descriptor.wit"),
            include_str!("../../../wit/operune/component/world.wit"),
        ];
        let web_files = [
            include_str!("../../../wit/operune/web/descriptor.wit"),
            include_str!("../../../wit/operune/web/world.wit"),
            include_str!("../../../wit/operune/web/assets.wit"),
            include_str!("../../../wit/operune/web/actions.wit"),
        ];

        // 每个 package 恰好一个文件（descriptor.wit）在 package 声明前
        // 带注释；其余文件 package 声明前不得有任何注释。
        assert!(comments_before_package(component_files[0]) > 0);
        assert!(
            component_files[1..]
                .iter()
                .all(|f| comments_before_package(f) == 0)
        );
        assert!(comments_before_package(web_files[0]) > 0);
        assert!(
            web_files[1..]
                .iter()
                .all(|f| comments_before_package(f) == 0)
        );
    }

    #[test]
    fn wit_files_are_tracked() {
        // include_str! 常量编译期展开（含 WIT 文本存在性）；此处验证内容
        // 非空，确保依赖跟踪常量真实引用契约文件。
        let descriptor = include_str!("../../../wit/operune/component/descriptor.wit");
        assert!(descriptor.contains("get-descriptor"));
        let web_world = include_str!("../../../wit/operune/web/world.wit");
        assert!(web_world.contains("operune-web-component"));
    }
}
