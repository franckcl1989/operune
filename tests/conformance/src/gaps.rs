//! §30 本机不可构建夹具的**已知缺口清单**（0.1.0 已知非阻塞）。
//!
//! # 为什么是缺口
//!
//! 下列 §30 条目需要导出 `operune:component@0.1.0`（descriptor）与
//! `operune:web@0.1.0`（web descriptor / assets / actions）WIT 契约的
//! **guest 组件**：canonical ABI 的 lowering/lifting 代码必须由
//! cargo-component（或 wasm-tools 等价物）根据 WIT 生成，手写 wat 无法
//! 表达（wasmtime 36 对 import/export 中的内联 record/variant/enum 有
//! named-type 注册要求——见 application runtime.rs 的测试注释）。
//!
//! 本机工具链状态：cargo-component / wasm-tools **不可用**（已多次确认）；
//! wasmtime 的 `wat` 文本解析（runtime-wasm dev-dependency 已用）只能
//! 解析 core module 与 component 语法，不能代替 WIT 契约工具链。
//!
//! 处置（用户原则："本机无法支持的暂时略过不阻塞整体进度"）：列为
//! 0.1.0 已知非阻塞缺口，待工具链就绪后补充。**不写空测试**——缺口的
//! 存在由 [`gap_inventory_is_recorded`] 显式审计（清单非空、无重复、
//! 每项带 §30 条目与补齐条件），防止静默遗忘或伪造。
//!
//! # 缺口清单
//!
//! | §30 条目 | 缺口夹具 | 需要的 guest 契约 | 补齐条件 |
//! |---|---|---|---|
//! | incompatible contract/interface version | 返回 `unsupported-contract-version` descriptor 的组件 | `operune:component/descriptor` 导出 | cargo-component 工具链就绪后构建 |
//! | health check failure | readiness/health 导出失败、激活期健康校验失败的组件 | `operune:component/descriptor` + 健康面导出 | 同上（0.1.0 readiness 为 stateless 完整性校验，健康面随 0.3 健康契约落地） |
//! | descriptor deterministic/repeatability fixture | 导出 canonical descriptor 的组件（两阶段安装 `read_descriptor` ×2 确定性比对的全链路验证，§19.3） | `operune:component/descriptor` | 同上 |
//! | minimal valid Component（完整版） | 带合法 descriptor 导出、可走通两阶段安装 happy path 的组件 | `operune:component/descriptor` | 同上 |
//! | grant-expansion upgrade fixture | v1（无 WASI import）→ v2（新增 WASI import）升级夹具：`RequiresApproval` 路径与旧 grant 不静默继承（§17.5/§20） | `operune:component/descriptor` ×2 版本 | 同上 |
//! | Web assets + sandbox escape attempt component | 导出 web descriptor/assets/actions 的组件（§21.3 闭环）与尝试逃逸（越权读取、遍历 asset path、绕过 Core bridge）的攻击组件（§32） | `operune:web@0.1.0` 导出 | 同上 |
//! | （间接）supply-chain conflict 全链路 | 同一 `ComponentId+ComponentVersion` 不同 digest 的显式阻断经真实 descriptor 的端到端验证（§39.4；当前由 application 单测以 fake 覆盖） | `operune:component/descriptor` | 同上 |
//!
//! 另注：`wasi:cli/run@0.2.0` 这类**复杂签名**的 WASI import（`result<(), error-code>`
//! 变体）同样无法手写 wat（named-type 注册要求），只支持 primitive 签名
//! 的 WASI import（本套件 `UNKNOWN_IMPORT_COMPONENT_WAT` 采用
//! `wasi:random/random@0.2.0::get-random-u64`，探针验证可表达）。

use super::fixtures::FIXTURES;
use super::test_support::test_failure;

/// 一条缺口记录。
struct Gap {
    /// §30 条目。
    section30: &'static str,
    /// 缺口内容。
    description: &'static str,
}

/// 缺口清单（0.1.0 已知非阻塞；与上方文档表一一对应）。
const GAPS: &[Gap] = &[
    Gap {
        section30: "incompatible contract/interface version",
        description: "返回 unsupported-contract-version 的 descriptor 导出组件不可构建",
    },
    Gap {
        section30: "health check failure",
        description: "readiness/health 导出失败的组件不可构建（0.3 健康契约）",
    },
    Gap {
        section30: "descriptor deterministic/repeatability fixture",
        description: "canonical descriptor 导出组件不可构建（§19.3 read_descriptor ×2 全链路）",
    },
    Gap {
        section30: "minimal valid Component（完整版）",
        description: "带合法 descriptor 导出的 happy-path 安装组件不可构建",
    },
    Gap {
        section30: "grant-expansion upgrade fixture",
        description: "v1→v2 扩大 imports 的升级夹具不可构建（§17.5 RequiresApproval 路径）",
    },
    Gap {
        section30: "Web assets + sandbox escape attempt component",
        description: "operune:web@0.1.0 导出与逃逸攻击组件不可构建（§21.3/§32）",
    },
    Gap {
        section30: "supply-chain conflict 全链路（间接）",
        description: "同一 ComponentId+ComponentVersion 不同 digest 的端到端阻断需真实 descriptor",
    },
];

/// 缺口清单自检（审计门，防止清单漂移/静默遗忘）：非空、无重复 §30 条目、
/// 与已构建夹具清单无重叠。
#[test]
fn gap_inventory_is_recorded() {
    assert!(
        !GAPS.is_empty(),
        "gap inventory must not be empty (toolchain gaps must be explicitly recorded)"
    );
    for (index, gap) in GAPS.iter().enumerate() {
        assert!(
            !gap.section30.is_empty(),
            "gap at index {index} lacks a §30 item"
        );
        assert!(
            !gap.description.is_empty(),
            "gap at index {index} ({}) lacks a description",
            gap.section30
        );
        for (other_index, other) in GAPS.iter().enumerate() {
            if index != other_index && other.section30 == gap.section30 {
                test_failure(format_args!(
                    "duplicate gap entry: {} (indices {index} and {other_index})",
                    gap.section30
                ));
            }
        }
        // 缺口条目不得与已构建夹具重叠（同一 §30 条目不得同时"已覆盖"与
        // "缺口"）。
        for fixture in FIXTURES {
            assert_ne!(
                fixture.section30, gap.section30,
                "fixture {} claims §30 item {} which is also recorded as a toolchain gap",
                fixture.name, gap.section30
            );
        }
    }
}
