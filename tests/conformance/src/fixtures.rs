//! §30 测试 Component 夹具：wat 内联常量（wasmtime 可直接解析的文本格式，
//! 不依赖 cargo-component / wasm-tools 工具链）。
//!
//! 每个夹具带 [`Fixture`] 清单条目：§30 清单条目、验证的验收项（§39.4 /
//! §7.4 / §7.5 / §20.4）与一段用途说明。[`fixture_manifest_is_consistent`]
//! 断言全部清单条目可被 wasmtime 真实解析/编译（夹具完整性门，防止
//! wat 文本漂移后静默失配）。
//!
//! 依赖 WIT 契约（descriptor / web 导出）的夹具**本机不可构建**——见
//! [`super::gaps`]，不在本模块伪造空夹具。

use operune_runtime_wasm::ComponentHandle;

use super::test_support::{engine, test_failure};

/// 一个 §30 夹具的清单条目。
pub(crate) struct Fixture {
    /// 夹具名（wat 常量名）。
    pub(crate) name: &'static str,
    /// §30 清单条目。
    pub(crate) section30: &'static str,
    /// 验证的验收项。
    pub(crate) acceptance: &'static str,
    /// 用途说明。
    pub(crate) purpose: &'static str,
    /// wat 文本（`None` = 非文本夹具，如原始字节）。
    pub(crate) wat: Option<&'static str>,
    /// 是否必须是合法 Component（`false` = 故意非组件的门测试夹具，
    /// 清单门断言其被组件门拒绝）。
    pub(crate) expects_component: bool,
}

/// 非法字节流（§30 malformed bytes）：既不是 wasm 也不是组件，直接拒绝。
pub(crate) const MALFORMED_BYTES: &[u8] = b"this is not a webassembly component";

/// 合法 core wasm 但**不是** Component（§19.2 阶段二组件门：Component::new
/// 必须拒绝非组件二进制）。
pub(crate) const CORE_MODULE_NOT_COMPONENT_WAT: &str = r#"(module (func (export "nop")))"#;

/// minimal valid Component（§30）：core module + core instance，无 import
/// 无 operune 导出——两阶段安装的契约面检查基线（缺 descriptor 导出必须
/// 被拒绝，见 pipeline_suite）。
pub(crate) const MINIMAL_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
    )
    (core instance $i (instantiate $m))
)"#;

/// infinite loop 组件（§30 infinite loop；§39.4 "infinite loop 能按 deadline
/// 中断"）：core module 导出 `spin`（空转循环），canon lift 后由宿主调用。
pub(crate) const SPIN_LOOP_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "spin")
            (loop $l (br $l)))
    )
    (core instance $i (instantiate $m))
    (func (export "spin") (canon lift (core func $i "spin")))
)"#;

/// infinite loop **on init**（§30 infinite loop / trap on init 的实例化面；
/// §7.5）：core module 的 start 函数无限循环——epoch deadline 必须在
/// 实例化（guest 代码执行）期间中断它。
pub(crate) const SPIN_ON_INIT_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func $spin (loop $l (br $l)))
        (start $spin)
    )
    (core instance $i (instantiate $m))
)"#;

/// trap on init（§30 trap on init；§14.1）：core module 的 start 函数
/// 执行 `unreachable`——实例化即 trap，必须映射为 typed 分类且不崩溃宿主。
pub(crate) const TRAP_ON_INIT_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func $boom unreachable)
        (start $boom)
    )
    (core instance $i (instantiate $m))
)"#;

/// memory grow attacker（§30 memory grow attacker；§7.4/§39.4）：core
/// module 以 1 page 初始内存 + `grow` 导出；宿主预算限定时 grow 超限
/// 必须返回 -1（wasm 语义拒绝），初始分配超限必须拒绝实例化。
///
/// 注意组件层函数类型：component 语法用 `s32`/`u32`（非 core `i32`），
/// 且命名参数为字符串——canon lift 把 core `(param i32) (result i32)`
/// 以 `s32` 形态抬升（canonical ABI：s32 ↔ core i32）。
pub(crate) const MEMORY_GROW_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "grow") (param i32) (result i32)
            (local.get 0)
            (memory.grow))
    )
    (core instance $i (instantiate $m))
    (func (export "grow") (param "delta" s32) (result s32)
        (canon lift (core func $i "grow")))
)"#;

/// 巨型初始内存（§30 memory grow attacker 的实例化面）：初始 65536 pages
/// （4 GiB，wasm32 上限）——limiter 必须在分配前拒绝。
pub(crate) const HUGE_MEMORY_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 65536)
    )
    (core instance $i (instantiate $m))
)"#;

/// unknown import（§30 unknown import；§19.5/§17.2）：import
/// `wasi:random/random@0.2.0` 的 `get-random-u64`——签名是纯 primitive，
/// 手写 wat 可表达且与宿主 linker 类型精确匹配（探针已验证：application
/// runtime.rs 的同一夹具经 add_to_linker 全链路成功）。零 grant（空
/// Linker）下必须以**确定性 link 错误**失败，不得"先运行，失败时 trap"。
pub(crate) const UNKNOWN_IMPORT_COMPONENT_WAT: &str = r#"(component
    (import "wasi:random/random@0.2.0" (instance $random
        (export "get-random-u64" (func (result u64)))
    ))
)"#;

/// slow/drain component（§30 slow/drain component；§20.4）：导出 `slow`——
/// 有界时长（约几十毫秒）的计数循环，用于验证 drain 期间已发放租约
/// 运行到结束、关闭后不接新工作。
pub(crate) const SLOW_COMPONENT_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "slow") (result i32)
            (local $i i32)
            (local.set $i (i32.const 0))
            (block $done
                (loop $l
                    (br_if $done (i32.ge_u (local.get $i) (i32.const 20000000)))
                    (local.set $i (i32.add (local.get $i) (i32.const 1)))))
            (local.get $i))
    )
    (core instance $i (instantiate $m))
    (func (export "slow") (result s32)
        (canon lift (core func $i "slow")))
)"#;

/// 全部可构建夹具的清单（§30 覆盖矩阵；断言一致性见
/// [`fixture_manifest_is_consistent`]）。
pub(crate) const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "MINIMAL_COMPONENT_WAT",
        section30: "minimal valid Component",
        acceptance: "§39.4 基线：验证/编译/实例化闭环；缺 operune 契约导出被拒绝",
        purpose: "两阶段安装契约面检查的基线字节（pipeline_suite 拒绝路径）",
        wat: Some(MINIMAL_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "MALFORMED_BYTES",
        section30: "malformed bytes",
        acceptance: "§39.4 非法 Component 不能拖垮 Core；§19.2 阶段二确定拒绝",
        purpose: "非法字节流必须在验证期以 typed 错误拒绝，不产生 candidate",
        wat: None,
        expects_component: false,
    },
    Fixture {
        name: "CORE_MODULE_NOT_COMPONENT_WAT",
        section30: "malformed bytes（合法 wasm 非组件变体）",
        acceptance: "§7.2/§19.2 组件门：非组件二进制不得作为 Component 接受",
        purpose: "验证 Component::new 的组件门（core module 不能冒充 Component）",
        wat: Some(CORE_MODULE_NOT_COMPONENT_WAT),
        expects_component: false,
    },
    Fixture {
        name: "SPIN_LOOP_COMPONENT_WAT",
        section30: "infinite loop",
        acceptance: "§39.4 infinite loop 能按 deadline 中断（epoch，§7.5）",
        purpose: "调用期空转：epoch deadline 到期必须 trap 为 EpochDeadlineExceeded",
        wat: Some(SPIN_LOOP_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "SPIN_ON_INIT_COMPONENT_WAT",
        section30: "infinite loop / trap on init（实例化面）",
        acceptance: "§39.4 infinite loop 能按 deadline 中断；§7.5 实例化也受 epoch 约束",
        purpose: "start 函数空转：实例化期间的 guest 代码同样必须被 deadline 中断",
        wat: Some(SPIN_ON_INIT_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "TRAP_ON_INIT_COMPONENT_WAT",
        section30: "trap on init",
        acceptance: "§14.1 typed trap 分类；§39.4 恶意 Component 不可拖垮宿主",
        purpose: "start 函数 unreachable：实例化即 trap，确定性分类且宿主不受影响",
        wat: Some(TRAP_ON_INIT_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "MEMORY_GROW_COMPONENT_WAT",
        section30: "memory grow attacker",
        acceptance: "§39.4 memory over-limit 有确定拒绝或 trap；§7.4 limiter",
        purpose: "预算内 grow 返回 -1（wasm 语义拒绝）+ 拒绝记录 LinearMemory",
        wat: Some(MEMORY_GROW_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "HUGE_MEMORY_COMPONENT_WAT",
        section30: "memory grow attacker（初始分配超限）",
        acceptance: "§39.4 memory over-limit 确定拒绝；§7.4 实例化期 limiter",
        purpose: "4 GiB 初始内存：实例化被分类为 ResourceLimit::LinearMemory",
        wat: Some(HUGE_MEMORY_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "UNKNOWN_IMPORT_COMPONENT_WAT",
        section30: "unknown import / denied capability",
        acceptance: "§39.4 未授权/未知 import 不能成为 Active；§17.2/§19.5 link 期拒绝",
        purpose: "零 grant 下确定性 link 错误；显式 grant 下成功实例化（能力门控）",
        wat: Some(UNKNOWN_IMPORT_COMPONENT_WAT),
        expects_component: true,
    },
    Fixture {
        name: "SLOW_COMPONENT_WAT",
        section30: "slow/drain component",
        acceptance: "§20.4 drain：关闭后不接新工作、已发放租约运行到结束",
        purpose: "有界时长执行：drain 期间 in-flight 调用完成，新 dispatch 拒绝",
        wat: Some(SLOW_COMPONENT_WAT),
        expects_component: true,
    },
];

/// 夹具完整性门：全部 wat 夹具必须被 wasmtime 真实验证/编译（§30 夹具
/// 是 Runtime 符合性输入，wat 文本漂移 = 套件静默失配）。
#[test]
fn fixture_manifest_is_consistent() {
    let engine = engine();
    assert!(
        !FIXTURES.is_empty(),
        "conformance fixture manifest must not be empty"
    );
    for fixture in FIXTURES {
        // 文档字段必须完整（§30 清单的可审计性：每项带条目与验收项）。
        assert!(
            !fixture.section30.is_empty()
                && !fixture.acceptance.is_empty()
                && !fixture.purpose.is_empty(),
            "fixture {} must document §30 item, acceptance and purpose",
            fixture.name
        );
        let Some(wat) = fixture.wat else {
            continue; // 字节类夹具（MALFORMED_BYTES）不参与 wat 解析门
        };
        let handle = ComponentHandle::new(&engine, wat.as_bytes());
        match (fixture.expects_component, handle) {
            // 合法组件夹具：必须被 wasmtime 真实验证/编译。
            (true, Ok(_)) => {}
            (true, Err(error)) => test_failure(format_args!(
                "fixture {} ({}) must compile as a component: {error}",
                fixture.name, fixture.section30
            )),
            // 故意非组件夹具（core module 冒充组件）：必须被组件门拒绝
            //——该夹具的存在意义即验证 §7.2 组件门。
            (false, Ok(_)) => test_failure(format_args!(
                "fixture {} must be rejected by the component gate",
                fixture.name
            )),
            (false, Err(_)) => {}
        }
    }
    // 非法字节必须被验证拒绝（该夹具的存在意义）。
    if ComponentHandle::new(&engine, MALFORMED_BYTES).is_ok() {
        test_failure("malformed bytes must be rejected");
    }
}
