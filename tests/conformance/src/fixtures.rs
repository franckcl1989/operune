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

// ---------------------------------------------------------------------------
// 0.2.0 Capability Composition（§40.2 / §40.4）链接夹具
//
// wat 写法参考 runtime-wasm linked.rs 测试（探针验证）：命名 instance 导出、
// 组件级 s32/u32 命名参数（canonical ABI：s32 ↔ core i32）、import 声明先于
// core module。实例名即 WIT 世界 import/export 名（`ns:pkg/iface@x.y.z`），
// 与 domain InterfaceId / InterfaceRequirement 的字符串形态一致（§40.3
// 事实源：surface 观察直接可解析）。
// ---------------------------------------------------------------------------

/// 0.2.0 provider（§40.2 "Component exports satisfy other Component
/// imports"）：导出 `test:calc/calc@1.0.0` instance（add / sub，primitive）。
/// 实例导出两个 func：验证整条 instance 链接边（不止单个 func）。
pub(crate) const LINKED_PROVIDER_ADD_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "add") (param i32 i32) (result i32)
            (i32.add (local.get 0) (local.get 1)))
        (func (export "sub") (param i32 i32) (result i32)
            (i32.sub (local.get 0) (local.get 1))))
    (core instance $i (instantiate $m))
    (func $add (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "add")))
    (func $sub (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "sub")))
    (instance $calc
        (export "add" (func $add))
        (export "sub" (func $sub)))
    (export "test:calc/calc@1.0.0" (instance $calc))
)"#;

/// 0.2.0 consumer（§40.2 "Component imports 由 provider exports 满足"）：
/// 导入 `test:calc/calc@1.0.0` 的 add，导出 `run` = add(20, 22) = 42。
/// import 声明先于 core module（canon lower 依赖 import 的 func 句柄）。
pub(crate) const LINKED_CONSUMER_ADD_CALLER_WAT: &str = r#"(component
    (import "test:calc/calc@1.0.0" (instance $calc
        (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
    (core func $calc_add (canon lower (func $calc "add")))
    (core module $m
        (import "calc" "add" (func $add (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "run") (result i32)
            (call $add (i32.const 20) (i32.const 22))))
    (core instance $i (instantiate $m
        (with "calc" (instance (export "add" (func $calc_add))))))
    (func (export "run") (result s32) (canon lift (core func $i "run")))
)"#;

/// 0.2.0 三组件链的中间节点（§40.2 activation ordering）：既是 consumer
/// （导入 add）又是 provider（导出 `test:calc/mul@1.0.0`：mul = add(a,b)+b）。
pub(crate) const LINKED_MIDDLE_MUL_WAT: &str = r#"(component
    (import "test:calc/calc@1.0.0" (instance $calc
        (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
    (core func $calc_add (canon lower (func $calc "add")))
    (core module $m
        (import "calc" "add" (func $add (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "mul") (param i32 i32) (result i32)
            (i32.add (call $add (local.get 0) (local.get 1)) (local.get 1))))
    (core instance $i (instantiate $m
        (with "calc" (instance (export "add" (func $calc_add))))))
    (func $mul (export "mul") (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "mul")))
    (instance $mul_iface (export "mul" (func $mul)))
    (export "test:calc/mul@1.0.0" (instance $mul_iface))
)"#;

/// 0.2.0 三组件链的顶层 consumer（§40.2）：导入 mul，导出 `run` =
/// mul(3, 4) = add(3, 4) + 4 = 11。
pub(crate) const LINKED_TOP_CONSUMER_WAT: &str = r#"(component
    (import "test:calc/mul@1.0.0" (instance $mul
        (export "mul" (func (param "a" s32) (param "b" s32) (result s32)))))
    (core func $cmul (canon lower (func $mul "mul")))
    (core module $m
        (import "mul" "mul" (func $mul (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "run") (result i32)
            (call $mul (i32.const 3) (i32.const 4))))
    (core instance $i (instantiate $m
        (with "mul" (instance (export "mul" (func $cmul))))))
    (func (export "run") (result s32) (canon lift (core func $i "run")))
)"#;

/// 0.2.0 独立 provider（§40.4 确定性测试用）：导出 `test:calc/mul@1.0.0`
/// instance（纯 i32.mul，无任何 import——与 add provider 无依赖，允许两种
/// 合法激活顺序）。
pub(crate) const LINKED_PURE_MUL_PROVIDER_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "mul") (param i32 i32) (result i32)
            (i32.mul (local.get 0) (local.get 1))))
    (core instance $i (instantiate $m))
    (func $mul (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "mul")))
    (instance $mul_iface (export "mul" (func $mul)))
    (export "test:calc/mul@1.0.0" (instance $mul_iface))
)"#;

/// 0.2.0 双依赖 consumer（§40.4 确定性测试用）：同时导入 add 与 mul，
/// 导出 `run` = add(20, 22) + mul(3, 4) = 42 + 12 = 54。
pub(crate) const LINKED_DUAL_CONSUMER_WAT: &str = r#"(component
    (import "test:calc/calc@1.0.0" (instance $calc
        (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
    (import "test:calc/mul@1.0.0" (instance $mul
        (export "mul" (func (param "a" s32) (param "b" s32) (result s32)))))
    (core func $calc_add (canon lower (func $calc "add")))
    (core func $mul_mul (canon lower (func $mul "mul")))
    (core module $m
        (import "calc" "add" (func $add (param i32 i32) (result i32)))
        (import "mul" "mul" (func $mul (param i32 i32) (result i32)))
        (memory (export "memory") 1)
        (func (export "run") (result i32)
            (i32.add
                (call $add (i32.const 20) (i32.const 22))
                (call $mul (i32.const 3) (i32.const 4)))))
    (core instance $i (instantiate $m
        (with "calc" (instance (export "add" (func $calc_add))))
        (with "mul" (instance (export "mul" (func $mul_mul))))))
    (func (export "run") (result s32) (canon lift (core func $i "run")))
)"#;

/// 接口不匹配的 consumer（§40.2 运行时结构签名校验）：期望 add 只有
/// **一个** s32 参数——graph 层（名字 + 版本）可解析，runtime 链接层
/// （LinkedComponentSet 结构签名）必须拒绝。
pub(crate) const LINKED_MISMATCH_CONSUMER_WAT: &str = r#"(component
    (import "test:calc/calc@1.0.0" (instance $calc
        (export "add" (func (param "a" s32) (result s32)))))
    (core module $m (memory (export "memory") 1))
    (core instance $i (instantiate $m))
)"#;

/// 形状不符的 provider：把 interface 名导出为**根级 func**（不是 instance）。
/// surface 观察仍把它当 provider（名字可解析），runtime 链接层必须拒绝
/// （MissingProviderExport）。
pub(crate) const LINKED_PROVIDER_WRONG_SHAPE_WAT: &str = r#"(component
    (core module $m (func (export "f") (result i32) (i32.const 1)))
    (core instance $i (instantiate $m))
    (func $f (result s32) (canon lift (core func $i "f")))
    (export "test:calc/calc@1.0.0" (func $f))
)"#;

/// 未链接导入的 consumer（§40.2 missing provider 诊断 / §40.3 事实源）：
/// 导入 `other:calc/calc@1.0.0`——任何组件集都不提供它。graph 层拒绝
/// （MissingProvider），runtime 层（无链接边、无宿主 hook）拒绝
/// （UnlinkedImport）。
pub(crate) const LINKED_UNLINKED_CONSUMER_WAT: &str = r#"(component
    (import "other:calc/calc@1.0.0" (instance $calc
        (export "add" (func (param "a" s32) (param "b" s32) (result s32)))))
    (core module $m (memory (export "memory") 1))
    (core instance $i (instantiate $m))
)"#;

/// 环检测（§40.2 cycle detection）第 1 成员 v1：导出 `test:calc/cycle-a@1.0.0`
/// instance，无任何 import（合法激活的起点）。wat 可以独立表达环的每一条
/// import 声明——环由 graph 层（无合法激活顺序）拒绝，见 composition_suite。
pub(crate) const LINKED_CYCLE_A_V1_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "ping") (result i32) (i32.const 1)))
    (core instance $i (instantiate $m))
    (func $ping (result s32) (canon lift (core func $i "ping")))
    (instance $iface (export "ping" (func $ping)))
    (export "test:calc/cycle-a@1.0.0" (instance $iface))
)"#;

/// 环检测第 1 成员 v2（升级形态）：v1 + 新增 import `test:calc/cycle-b@1.0.0`
/// ——与 cycle-b 成员构成双向依赖（环）。
pub(crate) const LINKED_CYCLE_A_V2_WAT: &str = r#"(component
    (import "test:calc/cycle-b@1.0.0" (instance $b
        (export "ping" (func (result s32)))))
    (core module $m
        (memory (export "memory") 1)
        (func (export "ping") (result i32) (i32.const 1)))
    (core instance $i (instantiate $m))
    (func $ping (result s32) (canon lift (core func $i "ping")))
    (instance $iface (export "ping" (func $ping)))
    (export "test:calc/cycle-a@1.0.0" (instance $iface))
)"#;

/// 环检测第 2 成员：导出 `test:calc/cycle-b@1.0.0`、导入
/// `test:calc/cycle-a@1.0.0`（与 cycle-a v2 构成环）。
pub(crate) const LINKED_CYCLE_B_WAT: &str = r#"(component
    (import "test:calc/cycle-a@1.0.0" (instance $a
        (export "ping" (func (result s32)))))
    (core module $m
        (memory (export "memory") 1)
        (func (export "ping") (result i32) (i32.const 2)))
    (core instance $i (instantiate $m))
    (func $ping (result s32) (canon lift (core func $i "ping")))
    (instance $iface (export "ping" (func $ping)))
    (export "test:calc/cycle-b@1.0.0" (instance $iface))
)"#;

/// provider 升级（§40.2 provider upgrade 前 consumer compatibility
/// analysis）安全路径：导出 `test:calc/calc@1.2.0`（^1.0.0 仍满足）。
pub(crate) const LINKED_PROVIDER_ADD_V1_2_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "add") (param i32 i32) (result i32)
            (i32.add (local.get 0) (local.get 1))))
    (core instance $i (instantiate $m))
    (func $add (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "add")))
    (instance $calc (export "add" (func $add)))
    (export "test:calc/calc@1.2.0" (instance $calc))
)"#;

/// provider 升级破坏性路径：导出 `test:calc/calc@2.0.0`（^1.0.0 不满足，
/// §13.2 major 破坏性）。
pub(crate) const LINKED_PROVIDER_ADD_V2_WAT: &str = r#"(component
    (core module $m
        (memory (export "memory") 1)
        (func (export "add") (param i32 i32) (result i32)
            (i32.add (local.get 0) (local.get 1))))
    (core instance $i (instantiate $m))
    (func $add (param "a" s32) (param "b" s32) (result s32)
        (canon lift (core func $i "add")))
    (instance $calc (export "add" (func $add)))
    (export "test:calc/calc@2.0.0" (instance $calc))
)"#;

/// 全部可构建夹具的清单（§30 / §40.2 覆盖矩阵；断言一致性见
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
    Fixture {
        name: "LINKED_PROVIDER_ADD_WAT",
        section30: "0.2.0 provider-with-export（§40.2）",
        acceptance: "§40.2 Component exports 满足其他 Component imports；§40.3 导出可观察",
        purpose: "导出 test:calc/calc@1.0.0 instance（add/sub）：graph provider 记录 + 链接边 provider",
        wat: Some(LINKED_PROVIDER_ADD_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_CONSUMER_ADD_CALLER_WAT",
        section30: "0.2.0 consumer-importing-provider（§40.2）",
        acceptance: "§40.2 Component imports 由 provider exports 满足；调用正确性（run=42）",
        purpose: "导入 add 并导出 run：链接成功 + 调用正确性的基线 consumer",
        wat: Some(LINKED_CONSUMER_ADD_CALLER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_MIDDLE_MUL_WAT",
        section30: "0.2.0 三组件链中间节点（§40.2 activation ordering）",
        acceptance: "§40.2 activation/deactivation ordering；链式解析与调用（mul=11）",
        purpose: "既是 consumer（导入 add）又是 provider（导出 mul）",
        wat: Some(LINKED_MIDDLE_MUL_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_TOP_CONSUMER_WAT",
        section30: "0.2.0 三组件链顶层 consumer（§40.2）",
        acceptance: "§40.2 链式依赖解析；经桥接的两跳调用正确性",
        purpose: "导入 mul 并导出 run=mul(3,4)：验证 A→B→C 全链",
        wat: Some(LINKED_TOP_CONSUMER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_PURE_MUL_PROVIDER_WAT",
        section30: "0.2.0 独立 provider（§40.4 确定性）",
        acceptance: "§40.4 同一组件集 + 同一 policy → 同一 graph（激活顺序无关）",
        purpose: "无 import 的纯 mul provider：与 add provider 互不依赖，允许两种合法激活顺序",
        wat: Some(LINKED_PURE_MUL_PROVIDER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_DUAL_CONSUMER_WAT",
        section30: "0.2.0 双依赖 consumer（§40.4 确定性）",
        acceptance: "§40.4 同一组件集 + 同一 policy → 同一 graph；多边链接调用正确性（run=54）",
        purpose: "同时导入 add 与 mul：激活顺序变体下 graph 与调用都确定",
        wat: Some(LINKED_DUAL_CONSUMER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_MISMATCH_CONSUMER_WAT",
        section30: "0.2.0 接口不匹配 consumer（§40.2）",
        acceptance: "§40.2 二进制面结构签名校验：graph 层可解析、runtime 链接层拒绝",
        purpose: "期望 add 单参数：链接期必须 typed 拒绝（InterfaceMismatch）",
        wat: Some(LINKED_MISMATCH_CONSUMER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_PROVIDER_WRONG_SHAPE_WAT",
        section30: "0.2.0 形状不符 provider（§40.2）",
        acceptance: "§40.2 provider 导出形状校验：interface 名导出为 func 必须拒绝",
        purpose: "把 interface 名导出为根级 func：runtime 链接层拒绝（MissingProviderExport）",
        wat: Some(LINKED_PROVIDER_WRONG_SHAPE_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_UNLINKED_CONSUMER_WAT",
        section30: "0.2.0 未链接导入 consumer（§40.2/§40.3）",
        acceptance: "§40.2 missing provider diagnostics；§40.3 未链接导入 deny-by-default",
        purpose: "导入 other:calc/calc@1.0.0：graph 层 MissingProvider、runtime 层 UnlinkedImport",
        wat: Some(LINKED_UNLINKED_CONSUMER_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_CYCLE_A_V1_WAT",
        section30: "0.2.0 环检测成员 A v1（§40.2 cycle detection）",
        acceptance: "§40.2 cycle detection：环在 graph 层拒绝，无合法激活顺序",
        purpose: "导出 cycle-a：环测试的合法起点（无 import）",
        wat: Some(LINKED_CYCLE_A_V1_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_CYCLE_A_V2_WAT",
        section30: "0.2.0 环检测成员 A v2（§40.2 cycle detection）",
        acceptance: "§40.2 cycle detection：升级引入环 → 拒绝且快照不变",
        purpose: "A 升级为导入 cycle-b：与 cycle-b 成员构成双向依赖",
        wat: Some(LINKED_CYCLE_A_V2_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_CYCLE_B_WAT",
        section30: "0.2.0 环检测成员 B（§40.2 cycle detection）",
        acceptance: "§40.2 cycle detection：import 环可被 wat 独立表达，graph 层拒绝",
        purpose: "导出 cycle-b、导入 cycle-a：与 A v2 构成环",
        wat: Some(LINKED_CYCLE_B_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_PROVIDER_ADD_V1_2_WAT",
        section30: "0.2.0 provider 升级安全路径（§40.2）",
        acceptance: "§40.2 provider upgrade 前 consumer compatibility analysis：安全升级放行",
        purpose: "导出 calc@1.2.0：^1.0.0 仍满足 → check_upgrade 放行、commit 成功",
        wat: Some(LINKED_PROVIDER_ADD_V1_2_WAT),
        expects_component: true,
    },
    Fixture {
        name: "LINKED_PROVIDER_ADD_V2_WAT",
        section30: "0.2.0 provider 升级破坏路径（§40.2）",
        acceptance: "§40.2 provider upgrade 门控：major 升级破坏 consumer → typed 拒绝",
        purpose: "导出 calc@2.0.0：^1.0.0 不满足 → ProviderUpgradeIncompatible",
        wat: Some(LINKED_PROVIDER_ADD_V2_WAT),
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
