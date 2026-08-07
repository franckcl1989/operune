//! 0.2.0 Capability Composition（§40）conformance 测试（§40.2 MUST scope /
//! §40.3 事实源 / §40.4 确定性验收）。
//!
//! # 覆盖（§40.2 MUST scope 的 conformance suite 条目）
//!
//! | §40.2 条目 | 测试 | 层 |
//! |---|---|---|
//! | Component exports satisfy other Component imports | [`provider_consumer_link_resolves_and_calls_correctly`] | application（graph）+ runtime-wasm（LinkedComponentSet） |
//! | activation/deactivation ordering | [`three_component_chain_resolves_and_calls_correctly`] | 同左（链式拓扑序） |
//! | missing provider diagnostics | [`consumer_activation_without_provider_is_rejected`] / [`unlinked_import_rejected_at_graph_and_runtime`] | application（graph）+ runtime-wasm（UnlinkedImport） |
//! | cycle detection | [`cycle_between_providers_rejected_at_graph_layer`] | application（try_build） |
//! | provider selection 确定规则 / §40.4 歧义拒绝 | [`ambiguous_provider_rejected_without_policy_and_resolved_by_policy`] | application（GraphPolicy） |
//! | provider upgrade 前 consumer compatibility analysis | [`breaking_provider_upgrade_rejected_with_impact_report`] / [`version_incompatible_upgrade_rejected_with_reason`] / [`real_surface_upgrade_gate_allows_safe_and_rejects_breaking`] | application（check_upgrade） |
//! | graph snapshot atomic switch / persistence | 各测试断言失败路径快照与记录不变 | application |
//! | §40.4 确定性验收 | [`records_input_order_does_not_affect_graph`] / [`activation_order_variance_produces_identical_graphs_and_calls`] | domain（records 乱序）+ application（激活顺序） |
//! | 二进制面校验（graph 层不可见） | [`interface_mismatch_rejected_at_runtime_after_graph_resolution`] / [`wrong_shape_provider_rejected_at_runtime_link`] | runtime-wasm（LinkedComponentSet） |
//!
//! # 方式（真实观察优先）
//!
//! - **事实源（§40.3）**：全部 records 经真实 `WasmtimeRuntime::contract_surface`
//!   观察（compile 真实 wat 组件 → 读二进制 imports/exports）→
//!   [`records_from_surface`] 推导——不伪造 surface；
//! - **graph 层**：`CompositionService`（真实实现）+ conformance 自有的内存
//!   fake ports（[`MemGraphStore`] / [`AuditLog`] / [`MemConfig`]；
//!   pipeline_suite 的 fake ports 模式）；
//! - **runtime 层**：[`LinkedComponentSet`]（§40.2 宿主桥接）——规格从
//!   domain `ProviderGraph` 快照映射（[`build_linked_set`]：`topological_order`
//!   → members，已解析边 → links，import 名从 consumer 二进制 import 面取
//!   精确 WIT 名），即 application 运行时集成层要做的映射；
//! - **环的 wat 表达**：可行。每个组件二进制独立声明 imports/exports（import
//!   合法性不依赖 provider 存在），环在 **graph 层**（[`ProviderGraph::try_build`]
//!   Kahn 环检测）拒绝——不存在合法激活顺序，runtime 层永远看不到环。
//!
//! # 时序契约（§7.5）
//!
//! [`call_run`] 封装每次不可信执行的 `set_deadline` → `begin_execution` →
//! 调用 → `post_return`（桥接契约，见 runtime-wasm linked.rs 的
//! `bridge_closure` 文档）。

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use operune_application::{
    ActiveGraph, ApplicationError, AuditError, AuditEvent, AuditPort, CompositionService,
    ConfigError, ConfigPort, ContractRecords, GraphPolicy, GraphRecords, GraphStoreError,
    InterfaceKey, ProviderGraphPort, RuntimeConfig, WasmRuntime, WasmtimeRuntime,
    records_from_surface,
};
use operune_domain::{
    ComponentVersion, ConsumerRecord, InstallationId, InterfaceId, InterfaceRequirement,
    ProviderGraph, ProviderGraphError, ProviderId, ProviderRecord,
};
use operune_runtime_wasm::{
    CallDeadline, ComponentHandle, EngineConfig, EngineHandle, LinkError, LinkName, LinkSpec,
    LinkedComponentSet, LinkedSetSpec, MemberSpec, ResourceBudget, RuntimeError,
};

use super::fixtures::{
    LINKED_CONSUMER_ADD_CALLER_WAT, LINKED_CYCLE_A_V1_WAT, LINKED_CYCLE_A_V2_WAT,
    LINKED_CYCLE_B_WAT, LINKED_DUAL_CONSUMER_WAT, LINKED_MIDDLE_MUL_WAT,
    LINKED_MISMATCH_CONSUMER_WAT, LINKED_PROVIDER_ADD_V1_2_WAT, LINKED_PROVIDER_ADD_V2_WAT,
    LINKED_PROVIDER_ADD_WAT, LINKED_PROVIDER_WRONG_SHAPE_WAT, LINKED_PURE_MUL_PROVIDER_WAT,
    LINKED_TOP_CONSUMER_WAT, LINKED_UNLINKED_CONSUMER_WAT,
};
use super::test_support::{expect_ok, expect_some, test_failure};

// ---------------------------------------------------------------------------
// 内存 fake ports（§40.2 graph persistence/recovery 的最小面）
// ---------------------------------------------------------------------------

/// 内存 graph records 存储（ProviderGraphPort 的最小实现；与 pipeline_suite
/// 的 fake ports 同模式）。记录是不可变字节事实：`replace_records` 是单次
/// 原子替换边界（§40.2 / §18.5），`load_records` 是恢复输入。
struct MemGraphStore {
    providers: Mutex<BTreeMap<InstallationId, ProviderRecord>>,
    consumers: Mutex<BTreeMap<InstallationId, ConsumerRecord>>,
}

impl MemGraphStore {
    fn new() -> Self {
        Self {
            providers: Mutex::new(BTreeMap::new()),
            consumers: Mutex::new(BTreeMap::new()),
        }
    }

    /// 审计探针：某安装实例的 provider 记录。
    fn provider(&self, installation: InstallationId) -> Option<ProviderRecord> {
        match self.providers.lock() {
            Ok(guard) => guard.get(&installation).cloned(),
            Err(_) => None,
        }
    }

    /// 审计探针：记录总数（provider + consumer）。
    fn count(&self) -> usize {
        let providers = match self.providers.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        };
        let consumers = match self.consumers.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        };
        providers + consumers
    }
}

impl ProviderGraphPort for MemGraphStore {
    fn replace_records(
        &self,
        installation: InstallationId,
        provider: Option<&ProviderRecord>,
        consumer: Option<&ConsumerRecord>,
    ) -> Result<(), GraphStoreError> {
        {
            let mut providers = match self.providers.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    return Err(GraphStoreError::Storage(Box::from(std::io::Error::other(
                        "graph store provider lock poisoned",
                    ))));
                }
            };
            match provider {
                Some(record) => {
                    providers.insert(installation, record.clone());
                }
                None => {
                    providers.remove(&installation);
                }
            }
        }
        {
            let mut consumers = match self.consumers.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    return Err(GraphStoreError::Storage(Box::from(std::io::Error::other(
                        "graph store consumer lock poisoned",
                    ))));
                }
            };
            match consumer {
                Some(record) => {
                    consumers.insert(installation, record.clone());
                }
                None => {
                    consumers.remove(&installation);
                }
            }
        }
        Ok(())
    }

    fn load_records(&self) -> Result<GraphRecords, GraphStoreError> {
        let providers = match self.providers.lock() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => {
                return Err(GraphStoreError::Storage(Box::from(std::io::Error::other(
                    "graph store provider lock poisoned",
                ))));
            }
        };
        let consumers = match self.consumers.lock() {
            Ok(guard) => guard.values().cloned().collect(),
            Err(_) => {
                return Err(GraphStoreError::Storage(Box::from(std::io::Error::other(
                    "graph store consumer lock poisoned",
                ))));
            }
        };
        Ok(GraphRecords {
            providers,
            consumers,
        })
    }
}

/// 内存 audit（§18.7：fail-closed 的 graph 事件可观测）。
struct AuditLog {
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditLog {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    /// 审计探针：是否存在匹配事件。
    fn contains(&self, predicate: impl Fn(&AuditEvent) -> bool) -> bool {
        match self.events.lock() {
            Ok(events) => events.iter().any(predicate),
            Err(_) => false,
        }
    }
}

impl AuditPort for AuditLog {
    fn append(&self, event: AuditEvent) -> Result<(), AuditError> {
        match self.events.lock() {
            Ok(mut events) => {
                events.push(event);
                Ok(())
            }
            Err(_) => Err(AuditError::Storage(Box::from(std::io::Error::other(
                "audit lock poisoned",
            )))),
        }
    }
}

/// 内存 config（§18.0：不可变快照）。
struct MemConfig {
    config: RuntimeConfig,
}

impl MemConfig {
    fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }
}

impl ConfigPort for MemConfig {
    fn snapshot(&self) -> Result<RuntimeConfig, ConfigError> {
        Ok(self.config.clone())
    }
}

// ---------------------------------------------------------------------------
// 真实 harness：真实 WasmtimeRuntime 观察 + 真实 CompositionService
// ---------------------------------------------------------------------------

/// 真实观察 + 真实编排 harness（§40.3 事实源：records 从真实二进制观察；
/// §40.2 编排：真实 CompositionService + 内存 fake ports）。
struct RealHarness {
    engine: Arc<EngineHandle>,
    runtime: Arc<WasmtimeRuntime>,
    graph_store: Arc<MemGraphStore>,
    audit: Arc<AuditLog>,
    composition: CompositionService,
}

impl RealHarness {
    fn new(policy: GraphPolicy) -> Self {
        let engine = Arc::new(expect_ok(
            EngineHandle::new(EngineConfig::default()),
            "conformance engine creation",
        ));
        let config = Arc::new(MemConfig::new(RuntimeConfig::default()));
        let runtime = Arc::new(WasmtimeRuntime::new(Arc::clone(&engine), config));
        let graph_store = Arc::new(MemGraphStore::new());
        let audit = Arc::new(AuditLog::new());
        let active = Arc::new(expect_ok(ActiveGraph::new(), "active graph creation"));
        let composition = CompositionService::new(
            Arc::clone(&graph_store) as Arc<dyn ProviderGraphPort>,
            Arc::clone(&active),
            Arc::clone(&audit) as Arc<dyn AuditPort>,
            policy,
        );
        Self {
            engine,
            runtime,
            graph_store,
            audit,
            composition,
        }
    }

    /// 观察（真实 WasmtimeRuntime::contract_surface，§40.3）+ 推导 records
    /// + 编译链接用 ComponentHandle（同一 Engine；观察与链接是同一二进制的
    ///   两个独立编译产物）。
    fn observe(
        &self,
        installation: InstallationId,
        wat: &'static str,
    ) -> (ComponentHandle, ContractRecords) {
        let observed = expect_ok(
            self.runtime.compile(wat.as_bytes()),
            "compile for surface observation",
        );
        let surface = expect_ok(self.runtime.contract_surface(&observed), "contract surface");
        let records = expect_ok(
            records_from_surface(installation, &surface),
            "derive graph records",
        );
        let handle = expect_ok(
            ComponentHandle::new(&self.engine, wat.as_bytes()),
            "compile for linking",
        );
        (handle, records)
    }

    /// 观察 + 提交激活（§40.2 graph snapshot atomic switch）。
    fn activate(
        &self,
        installation: InstallationId,
        wat: &'static str,
    ) -> (ComponentHandle, Arc<ProviderGraph>) {
        let (handle, records) = self.observe(installation, wat);
        let graph = expect_ok(
            self.composition.commit_activation(installation, &records),
            "commit activation",
        );
        (handle, graph)
    }
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 确定性安装实例（uuid 文本解析；跨 harness 复用同一安装身份，§40.4
/// 可比性要求"同一组件集"）。
fn installation(uuid_text: &str) -> InstallationId {
    expect_ok(uuid_text.parse::<InstallationId>(), "installation id parse")
}

fn requirement(text: &str) -> InterfaceRequirement {
    expect_ok(text.parse::<InterfaceRequirement>(), "requirement parse")
}

fn interface_id(text: &str) -> InterfaceId {
    expect_ok(text.parse::<InterfaceId>(), "interface id parse")
}

/// 从 provider 记录派生 ProviderId（§40.4：安装实例 → 确定性身份）。
fn provider_id_of(record: &ProviderRecord) -> ProviderId {
    record.provider_id()
}

/// 在 consumer 二进制的 import 面中查找与 graph 边需求匹配的**确切 WIT
/// import 名**（§40.3：graph 边按规范化需求键控——`test:calc/calc@1.0.0`
/// 规范化为 `^1.0.0`；链接规格需要二进制的原始 import 名）。
fn import_name_matching(
    engine: &EngineHandle,
    consumer: &ComponentHandle,
    requirement: &InterfaceRequirement,
) -> Option<String> {
    let mut matched = None;
    for (name, _) in consumer
        .component()
        .component_type()
        .imports(engine.engine())
    {
        let parsed = name
            .parse::<InterfaceRequirement>()
            .or_else(|_| format!("{name}@*").parse::<InterfaceRequirement>());
        match parsed {
            Ok(parsed) if parsed == *requirement => {
                matched = Some(name.to_owned());
                break;
            }
            _ => {}
        }
    }
    matched
}

/// 把 domain `ProviderGraph` 快照映射为 runtime 链接规格并构建
/// [`LinkedComponentSet`]（§40.2：application 运行时集成层把
/// `topological_order` → members、已解析边 → links 的映射；本套件在
/// conformance 面复现该映射，验证 graph 顺序与 runtime 链接的衔接）。
///
/// import 名取 consumer 二进制的精确 WIT import 名（host 接口如 `wasi:`/
/// `operune:` 不进图，因此不会产生链接边）。失败路径只可能是规格构造
/// 错误——不变量破坏以 test_failure 中止（夹具不变量）。
fn build_linked_set(
    engine: &EngineHandle,
    graph: &ProviderGraph,
    handles: &BTreeMap<InstallationId, ComponentHandle>,
) -> Result<LinkedComponentSet, RuntimeError> {
    let order = graph.topological_order();
    let positions: BTreeMap<InstallationId, usize> = order
        .iter()
        .enumerate()
        .map(|(index, installation)| (*installation, index))
        .collect();
    let mut links_per_member: Vec<Vec<LinkSpec>> = Vec::with_capacity(order.len());
    for &installation in order {
        let handle = match handles.get(&installation) {
            Some(handle) => handle,
            None => test_failure("component handle missing for graph member"),
        };
        let mut links = Vec::new();
        for edge in graph.edges() {
            if edge.consumer() != installation {
                continue;
            }
            let import_name = expect_some(
                import_name_matching(engine, handle, edge.requirement()),
                "binary import name for graph edge",
            );
            let provider_installation = match graph
                .providers()
                .find(|node| node.provider() == edge.provider())
            {
                Some(node) => node.installation(),
                None => test_failure("edge provider missing from graph"),
            };
            let provider_index = match positions.get(&provider_installation) {
                Some(index) => *index,
                None => test_failure("provider installation missing from activation order"),
            };
            links.push(LinkSpec {
                import: expect_ok(LinkName::new(import_name), "link name construction"),
                provider: provider_index,
            });
        }
        links_per_member.push(links);
    }
    let mut members: Vec<MemberSpec<'_>> = Vec::with_capacity(order.len());
    for (index, &installation) in order.iter().enumerate() {
        let handle = match handles.get(&installation) {
            Some(handle) => handle,
            None => test_failure("component handle missing for graph member"),
        };
        members.push(MemberSpec {
            component: handle,
            links: &links_per_member[index],
        });
    }
    let spec = LinkedSetSpec {
        members: &members,
        host: None,
    };
    LinkedComponentSet::new(engine, &ResourceBudget::default(), &spec)
}

/// 调用集合成员的 `run` 导出（§7.5 时序 + 桥接 post-return 契约；断言
/// 返回值为 `expected`）。
fn call_run(set: &mut LinkedComponentSet, member: usize, expected: i32, what: &str) {
    expect_ok(
        set.store_mut()
            .set_deadline(CallDeadline::new(Duration::from_secs(1))),
        "set deadline",
    );
    set.store_mut().begin_execution();
    let instance = *expect_some(set.instance(member), "member instance");
    let run = expect_ok(
        instance.get_typed_func::<(), (i32,)>(set.store_mut().store_mut(), "run"),
        "run lookup",
    );
    match run.call(set.store_mut().store_mut(), ()) {
        Ok((value,)) => {
            assert_eq!(value, expected, "{what}: run must return {expected}");
            // post-return 契约：成功后必须重置成员实例的 may_enter 锁
            //（bridge_closure 同契约）。
            let _ = run.post_return(set.store_mut().store_mut());
        }
        Err(error) => test_failure(format_args!("{what}: run call failed: {error}")),
    }
}

/// 断言激活顺序满足每条边（provider 先于 consumer，§40.2）。
fn assert_order_valid(graph: &ProviderGraph) {
    let positions: BTreeMap<InstallationId, usize> = graph
        .topological_order()
        .iter()
        .enumerate()
        .map(|(index, installation)| (*installation, index))
        .collect();
    for edge in graph.edges() {
        let provider_installation = match graph
            .providers()
            .find(|node| node.provider() == edge.provider())
        {
            Some(node) => node.installation(),
            None => test_failure("edge provider missing from graph"),
        };
        let consumer_pos = match positions.get(&edge.consumer()) {
            Some(pos) => *pos,
            None => test_failure("consumer missing from activation order"),
        };
        let provider_pos = match positions.get(&provider_installation) {
            Some(pos) => *pos,
            None => test_failure("provider installation missing from activation order"),
        };
        assert!(
            provider_pos < consumer_pos,
            "provider must activate before its consumer"
        );
    }
}

// ---------------------------------------------------------------------------
// §40.2 链接成功 + 调用正确性（真实观察 → graph → LinkedComponentSet）
// ---------------------------------------------------------------------------

#[test]
fn provider_consumer_link_resolves_and_calls_correctly() {
    // §40.2 闭环：真实 surface 观察 → records → CompositionService 提交 →
    // graph 解析出边 → 映射为 LinkedComponentSet → 调用透传正确（42）。
    let harness = RealHarness::new(GraphPolicy::new());
    let provider_installation = installation("00000000-0000-0000-0000-000000000001");
    let consumer_installation = installation("00000000-0000-0000-0000-000000000002");
    let (provider, _) = harness.activate(provider_installation, LINKED_PROVIDER_ADD_WAT);
    let (consumer, _) = harness.activate(consumer_installation, LINKED_CONSUMER_ADD_CALLER_WAT);
    let graph = harness.composition.graph();
    assert_eq!(graph.edges().count(), 1);
    assert_eq!(
        graph.topological_order(),
        &[provider_installation, consumer_installation]
    );
    assert_order_valid(&graph);
    // §40.2 Capability Provider identity：边解析到安装实例派生的 provider。
    let edge = expect_some(
        graph.resolve(consumer_installation, &requirement("test:calc/calc@^1.0.0")),
        "resolved edge",
    );
    assert_eq!(
        edge.provider(),
        ProviderId::from_installation(provider_installation)
    );
    assert_eq!(edge.provided(), &interface_id("test:calc/calc@1.0.0"));
    // 提交事件已审计（§18.7 fail-closed 写入）。
    assert!(
        harness.audit.contains(|event| matches!(
            event,
            AuditEvent::GraphRecordsCommitted { installation: id }
                if *id == consumer_installation
        )),
        "graph records commit must be audited"
    );
    // graph → runtime 链接集合 → 调用正确性（add(20, 22) = 42）。
    let mut handles = BTreeMap::new();
    handles.insert(provider_installation, provider);
    handles.insert(consumer_installation, consumer);
    let mut set = expect_ok(
        build_linked_set(&harness.engine, &graph, &handles),
        "linked set build from graph",
    );
    assert_eq!(set.member_count(), 2);
    call_run(&mut set, 1, 42, "provider+consumer link");
}

#[test]
fn three_component_chain_resolves_and_calls_correctly() {
    // §40.2 activation ordering：A（provider）→ B（provider+consumer）→
    // C（consumer）；链式解析（2 条边）与经桥接的两跳调用（mul(3,4) = 11）。
    let harness = RealHarness::new(GraphPolicy::new());
    let a = installation("00000000-0000-0000-0000-000000000011");
    let b = installation("00000000-0000-0000-0000-000000000012");
    let c = installation("00000000-0000-0000-0000-000000000013");
    let (handle_a, _) = harness.activate(a, LINKED_PROVIDER_ADD_WAT);
    let (handle_b, _) = harness.activate(b, LINKED_MIDDLE_MUL_WAT);
    let (handle_c, _) = harness.activate(c, LINKED_TOP_CONSUMER_WAT);
    let graph = harness.composition.graph();
    assert_eq!(graph.edges().count(), 2);
    assert_eq!(graph.topological_order(), &[a, b, c]);
    assert_order_valid(&graph);
    let mut handles = BTreeMap::new();
    handles.insert(a, handle_a);
    handles.insert(b, handle_b);
    handles.insert(c, handle_c);
    let mut set = expect_ok(
        build_linked_set(&harness.engine, &graph, &handles),
        "linked chain build from graph",
    );
    assert_eq!(set.member_count(), 3);
    call_run(&mut set, 2, 11, "three component chain");
}

// ---------------------------------------------------------------------------
// §40.2 缺失 provider / 未链接导入 / 二进制面不匹配拒绝
// ---------------------------------------------------------------------------

#[test]
fn consumer_activation_without_provider_is_rejected() {
    // §40.2 missing provider diagnostics：provider 未激活时 consumer 的
    // 激活被拒绝，诊断指明哪个 consumer 缺哪个需求；不产生任何持久化 /
    // 快照变化（§40.2 graph snapshot atomic switch：gate 在落盘前）。
    let harness = RealHarness::new(GraphPolicy::new());
    let consumer_installation = installation("00000000-0000-0000-0000-000000000021");
    let (_, records) = harness.observe(consumer_installation, LINKED_CONSUMER_ADD_CALLER_WAT);
    assert!(!records.is_empty());
    let error = match harness
        .composition
        .check_activation(consumer_installation, &records)
    {
        Ok(_) => test_failure("consumer without provider must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderGraphResolution { source } => {
            assert_eq!(
                source,
                ProviderGraphError::MissingProvider {
                    consumer: consumer_installation,
                    requirement: Box::new(requirement("test:calc/calc@^1.0.0")),
                }
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // 未提交：无记录、快照空。
    assert_eq!(harness.graph_store.count(), 0);
    assert_eq!(harness.composition.graph().providers().count(), 0);
    // commit 同样被拒绝（gate 在落盘前）。
    let error = match harness
        .composition
        .commit_activation(consumer_installation, &records)
    {
        Ok(_) => test_failure("commit without provider must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ApplicationError::ProviderGraphResolution { .. }
    ));
    assert_eq!(harness.graph_store.count(), 0);
}

#[test]
fn unlinked_import_rejected_at_graph_and_runtime() {
    // §40.2 missing provider diagnostics 的"任何组件都不提供"形态 +
    // §40.3 deny-by-default（§17.2/§19.5 精神）：同一二进制在 graph 层
    // 以 MissingProvider 拒绝（诊断含具体需求），runtime 层以
    // UnlinkedImport 拒绝（无链接边、无宿主 hook）。
    let harness = RealHarness::new(GraphPolicy::new());
    let consumer_installation = installation("00000000-0000-0000-0000-000000000022");
    let (handle, records) = harness.observe(consumer_installation, LINKED_UNLINKED_CONSUMER_WAT);
    let error = match harness
        .composition
        .check_activation(consumer_installation, &records)
    {
        Ok(_) => test_failure("unlinked import must be rejected at graph layer"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderGraphResolution { source } => {
            assert_eq!(
                source,
                ProviderGraphError::MissingProvider {
                    consumer: consumer_installation,
                    requirement: Box::new(requirement("other:calc/calc@^1.0.0")),
                }
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // runtime 层：单成员集合（无链接边、无宿主 hook）→ UnlinkedImport。
    let members = [MemberSpec {
        component: &handle,
        links: &[],
    }];
    let spec = LinkedSetSpec {
        members: &members,
        host: None,
    };
    let result = LinkedComponentSet::new(&harness.engine, &ResourceBudget::default(), &spec);
    match result {
        Ok(_) => test_failure("unlinked import must be rejected at runtime layer"),
        Err(RuntimeError::Link(LinkError::UnlinkedImport {
            consumer: 0,
            import,
        })) => {
            assert_eq!(import.as_str(), "other:calc/calc@1.0.0");
        }
        Err(other) => test_failure(format_args!("unexpected error: {other}")),
    }
}

#[test]
fn interface_mismatch_rejected_at_runtime_after_graph_resolution() {
    // §40.2 两层校验：graph 层只做名字 + 版本解析（§40.3 事实源）——
    // mismatch consumer（期望 add 单参数）在 graph 层**通过**（名字/版本
    // 匹配）；二进制面结构签名校验在 runtime 链接层（plan_member 结构
    // 签名比较）→ InterfaceMismatch typed 拒绝。
    let harness = RealHarness::new(GraphPolicy::new());
    let provider_installation = installation("00000000-0000-0000-0000-000000000031");
    let consumer_installation = installation("00000000-0000-0000-0000-000000000032");
    let (provider, _) = harness.activate(provider_installation, LINKED_PROVIDER_ADD_WAT);
    let (consumer, _) = harness.activate(consumer_installation, LINKED_MISMATCH_CONSUMER_WAT);
    let graph = harness.composition.graph();
    // graph 层确实解析成功（名字/版本匹配；签名属于运行时面）。
    assert_eq!(graph.edges().count(), 1);
    assert_order_valid(&graph);
    let mut handles = BTreeMap::new();
    handles.insert(provider_installation, provider);
    handles.insert(consumer_installation, consumer);
    let result = build_linked_set(&harness.engine, &graph, &handles);
    match result {
        Ok(_) => test_failure("interface mismatch must be rejected at runtime link"),
        Err(RuntimeError::Link(LinkError::InterfaceMismatch {
            consumer: 1,
            provider: 0,
            export,
            detail,
            ..
        })) => {
            assert_eq!(export, "add");
            assert!(detail.contains("provider exports"), "detail: {detail}");
        }
        Err(other) => test_failure(format_args!("unexpected error: {other}")),
    }
}

#[test]
fn wrong_shape_provider_rejected_at_runtime_link() {
    // §40.2 二进制面校验：provider 把 interface 名导出为根级 func（不是
    // instance）。surface 观察仍产生 provider 记录（名字可解析）、graph
    // 层解析成功；runtime 链接层必须按形状拒绝（MissingProviderExport）。
    let harness = RealHarness::new(GraphPolicy::new());
    let provider_installation = installation("00000000-0000-0000-0000-000000000033");
    let consumer_installation = installation("00000000-0000-0000-0000-000000000034");
    let (provider, _) = harness.activate(provider_installation, LINKED_PROVIDER_WRONG_SHAPE_WAT);
    let (consumer, _) = harness.activate(consumer_installation, LINKED_CONSUMER_ADD_CALLER_WAT);
    let graph = harness.composition.graph();
    assert_eq!(
        graph.edges().count(),
        1,
        "graph layer resolves by name only"
    );
    let mut handles = BTreeMap::new();
    handles.insert(provider_installation, provider);
    handles.insert(consumer_installation, consumer);
    let result = build_linked_set(&harness.engine, &graph, &handles);
    match result {
        Ok(_) => test_failure("wrong-shape provider must be rejected at runtime link"),
        Err(RuntimeError::Link(LinkError::MissingProviderExport {
            consumer: 1,
            provider: 0,
            expected: "instance",
            actual: "func",
            ..
        })) => {}
        Err(other) => test_failure(format_args!("unexpected error: {other}")),
    }
}

// ---------------------------------------------------------------------------
// §40.2 cycle detection（wat 可表达 import 环；graph 层拒绝）
// ---------------------------------------------------------------------------

#[test]
fn cycle_between_providers_rejected_at_graph_layer() {
    // §40.2 cycle detection：A v1 激活（无 import）→ B 激活（依赖 A）→
    // A 升级为 v2（新增依赖 B）→ 双向依赖环。wat 可独立表达环的每条
    // import 声明（import 合法性不依赖 provider 存在）；环在 try_build
    // 层拒绝——不存在合法激活顺序，runtime 层永远看不到环。
    let harness = RealHarness::new(GraphPolicy::new());
    let a = installation("00000000-0000-0000-0000-000000000041");
    let b = installation("00000000-0000-0000-0000-000000000042");
    let (_, _) = harness.activate(a, LINKED_CYCLE_A_V1_WAT);
    let (_, _) = harness.activate(b, LINKED_CYCLE_B_WAT);
    assert_eq!(harness.composition.graph().edges().count(), 1);
    // A 升级：新增对 B 的依赖 → 环。
    let (_, upgrade) = harness.observe(a, LINKED_CYCLE_A_V2_WAT);
    let error = match harness.composition.commit_activation(a, &upgrade) {
        Ok(_) => test_failure("cycle must be rejected at graph layer"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderGraphResolution { source } => {
            assert!(
                matches!(source, ProviderGraphError::CycleDetected { .. }),
                "unexpected error: {source:?}"
            );
            // 诊断含环路径（两个 provider 身份）。
            let message = source.to_string();
            assert!(
                message.contains(&ProviderId::from_installation(a).to_string()),
                "cycle diagnostic must name provider A: {message}"
            );
            assert!(
                message.contains(&ProviderId::from_installation(b).to_string()),
                "cycle diagnostic must name provider B: {message}"
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // 失败的升级未落盘、未切换：旧图（无环）仍是 active，A 的记录仍是 v1。
    assert_eq!(harness.composition.graph().edges().count(), 1);
    assert_eq!(harness.composition.graph().providers().count(), 2);
    let stored = expect_some(harness.graph_store.provider(a), "stored A record");
    assert!(
        stored
            .provided()
            .contains(&interface_id("test:calc/cycle-a@1.0.0"))
    );
}

// ---------------------------------------------------------------------------
// §40.4 确定性验收（同一组件集 + 同一 policy → 同一 provider graph）
// ---------------------------------------------------------------------------

/// 确定性测试的组件集：P1（add provider）+ P2（纯 mul provider）+ C（双
/// 依赖 consumer）。P1/P2 互不依赖 → 存在两种合法激活顺序。
fn determinism_components() -> (&'static str, &'static str, &'static str) {
    (
        LINKED_PROVIDER_ADD_WAT,
        LINKED_PURE_MUL_PROVIDER_WAT,
        LINKED_DUAL_CONSUMER_WAT,
    )
}

#[test]
fn records_input_order_does_not_affect_graph() {
    // §40.4：records 乱序输入 → 相同 graph。records 从真实 surface 推导
    //（§40.3 事实源）；`ProviderGraph::try_build` 直接以正序/逆序输入构建
    // → 相同图 + 相同激活顺序（domain 保证：全部内部结构按稳定键排序）。
    let harness = RealHarness::new(GraphPolicy::new());
    let (provider_add, provider_mul, consumer_dual) = determinism_components();
    let p1 = installation("00000000-0000-0000-0000-000000000051");
    let p2 = installation("00000000-0000-0000-0000-000000000052");
    let c = installation("00000000-0000-0000-0000-000000000053");
    let (_, p1_records) = harness.observe(p1, provider_add);
    let (_, p2_records) = harness.observe(p2, provider_mul);
    let (_, c_records) = harness.observe(c, consumer_dual);
    let p1_record = expect_some(p1_records.provider(), "P1 provider record");
    let p2_record = expect_some(p2_records.provider(), "P2 provider record");
    let c_record = expect_some(c_records.consumer(), "C consumer record");
    let forward = expect_ok(
        ProviderGraph::try_build(
            &[p1_record.clone(), p2_record.clone()],
            std::slice::from_ref(c_record),
        ),
        "forward records build",
    );
    let mut reversed_providers = vec![p1_record.clone(), p2_record.clone()];
    reversed_providers.reverse();
    let reversed = expect_ok(
        ProviderGraph::try_build(&reversed_providers, std::slice::from_ref(c_record)),
        "reversed records build",
    );
    assert_eq!(reversed, forward);
    assert_eq!(reversed.topological_order(), forward.topological_order());
    assert_order_valid(&forward);
}

#[test]
fn activation_order_variance_produces_identical_graphs_and_calls() {
    // §40.4：两个独立 harness，同一组件集（同一安装身份）以不同合法激活
    // 顺序提交（§40.2：provider 必须先于 consumer，两种顺序都满足）→
    // 相同最终图 + 相同激活顺序；且两种顺序下经 graph 映射的 runtime
    // 链接集合都调用正确（run = 54）。
    let (provider_add, provider_mul, consumer_dual) = determinism_components();
    let p1 = installation("00000000-0000-0000-0000-000000000061");
    let p2 = installation("00000000-0000-0000-0000-000000000062");
    let c = installation("00000000-0000-0000-0000-000000000063");
    // 顺序 A：P1 → P2 → C；顺序 B：P2 → P1 → C（两种都是合法激活顺序，
    // §40.2 provider 先于 consumer）。
    let harness_a = RealHarness::new(GraphPolicy::new());
    let (h1_a, _) = harness_a.activate(p1, provider_add);
    let (h2_a, _) = harness_a.activate(p2, provider_mul);
    let (h3_a, _) = harness_a.activate(c, consumer_dual);
    let harness_b = RealHarness::new(GraphPolicy::new());
    let (h1_b, _) = harness_b.activate(p2, provider_mul);
    let (h2_b, _) = harness_b.activate(p1, provider_add);
    let (h3_b, _) = harness_b.activate(c, consumer_dual);
    let graph_a = harness_a.composition.graph();
    let graph_b = harness_b.composition.graph();
    assert_eq!(graph_b, graph_a);
    assert_eq!(graph_b.topological_order(), graph_a.topological_order());
    assert_eq!(graph_a.edges().count(), 2);
    assert_order_valid(&graph_a);
    // 两种顺序下 runtime 链接集合（graph → 规格映射）都调用正确
    //（§40.4：结果与激活顺序无关）。注意 harness B 中 h1_b 是 P2（mul）
    // 的句柄、h2_b 是 P1（add）的句柄——按安装实例键控。
    for (harness, h_p1, h_p2, h_c) in [
        (&harness_a, h1_a, h2_a, h3_a),
        (&harness_b, h2_b, h1_b, h3_b),
    ] {
        let mut handle_map = BTreeMap::new();
        handle_map.insert(p1, h_p1);
        handle_map.insert(p2, h_p2);
        handle_map.insert(c, h_c);
        let graph = harness.composition.graph();
        let mut set = expect_ok(
            build_linked_set(&harness.engine, &graph, &handle_map),
            "linked set build under activation order",
        );
        call_run(&mut set, 2, 54, "dual consumer under activation order");
    }
}

// ---------------------------------------------------------------------------
// §40.4 歧义拒绝 / GraphPolicy（provider selection 确定规则）
// ---------------------------------------------------------------------------

#[test]
fn ambiguous_provider_rejected_without_policy_and_resolved_by_policy() {
    // §40.4："无法唯一合法解析时必须拒绝激活，不得随机选择 provider"。
    // 同一 interface 两个 provider（同一组件二进制、两个安装实例）、无
    // policy → AmbiguousProvider（诊断含全部候选，按 ProviderId 排序）；
    // 显式 policy 绑定 → 唯一解析。
    let harness = RealHarness::new(GraphPolicy::new());
    let p1 = installation("00000000-0000-0000-0000-000000000071");
    let p2 = installation("00000000-0000-0000-0000-000000000072");
    let consumer_installation = installation("00000000-0000-0000-0000-000000000073");
    let (_, _) = harness.activate(p1, LINKED_PROVIDER_ADD_WAT);
    let (_, _) = harness.activate(p2, LINKED_PROVIDER_ADD_WAT);
    let (_, consumer_records) =
        harness.observe(consumer_installation, LINKED_CONSUMER_ADD_CALLER_WAT);
    let error = match harness
        .composition
        .check_activation(consumer_installation, &consumer_records)
    {
        Ok(_) => test_failure("ambiguity must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderGraphResolution { source } => {
            assert!(
                matches!(source, ProviderGraphError::AmbiguousProvider { .. }),
                "unexpected error: {source:?}"
            );
            // 诊断含两个候选（确定性排序）。
            let message = source.to_string();
            assert!(
                message.contains(&ProviderId::from_installation(p1).to_string()),
                "diagnostic must list candidate P1: {message}"
            );
            assert!(
                message.contains(&ProviderId::from_installation(p2).to_string()),
                "diagnostic must list candidate P2: {message}"
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // 显式 policy：绑定 test:calc/calc → P2 → 唯一解析；consumer 提交后
    // 边指向绑定的 provider。
    let mut policy = GraphPolicy::new();
    expect_ok(
        policy.bind(
            expect_ok(
                "test:calc/calc".parse::<InterfaceKey>(),
                "interface key parse",
            ),
            ProviderId::from_installation(p2),
        ),
        "bind policy",
    );
    expect_ok(harness.composition.update_policy(policy), "update policy");
    expect_ok(
        harness
            .composition
            .check_activation(consumer_installation, &consumer_records),
        "activation under bound policy",
    );
    let graph = expect_ok(
        harness
            .composition
            .commit_activation(consumer_installation, &consumer_records),
        "commit consumer under bound policy",
    );
    let edge = expect_some(
        graph.resolve(consumer_installation, &requirement("test:calc/calc@^1.0.0")),
        "resolved edge",
    );
    assert_eq!(edge.provider(), ProviderId::from_installation(p2));
}

// ---------------------------------------------------------------------------
// §40.2 provider 升级门控（consumer compatibility analysis）
// ---------------------------------------------------------------------------

/// 组装升级用的 records（records 驱动，§40.2 输入形态 = 升级后二进制的
/// surface 推导结果）：通过公开的 [`records_from_surface`]（§40.3）推导，
/// 与真实观察共用同一事实源路径。
fn upgrade_records(installation_id: InstallationId, provided: &[&str]) -> ContractRecords {
    let surface = operune_application::ContractSurface {
        imports: Vec::new(),
        exports: provided.iter().map(|text| (*text).to_owned()).collect(),
    };
    expect_ok(
        records_from_surface(installation_id, &surface),
        "derive upgrade records",
    )
}

/// 建立 provider + consumer 的基线 harness（P 提供 calc@1.0.0，C 导入
/// ^1.0.0；返回两个安装实例）。
fn baseline_upgrade_harness() -> (RealHarness, InstallationId, InstallationId) {
    let harness = RealHarness::new(GraphPolicy::new());
    let provider_installation = installation("00000000-0000-0000-0000-000000000081");
    let consumer_installation = installation("00000000-0000-0000-0000-000000000082");
    let (_, _) = harness.activate(provider_installation, LINKED_PROVIDER_ADD_WAT);
    let (_, _) = harness.activate(consumer_installation, LINKED_CONSUMER_ADD_CALLER_WAT);
    assert_eq!(harness.composition.graph().edges().count(), 1);
    (harness, provider_installation, consumer_installation)
}

#[test]
fn breaking_provider_upgrade_rejected_with_impact_report() {
    // §40.2 provider upgrade 前 consumer compatibility analysis（records
    // 驱动）：升级移除 calc interface → check_upgrade 拒绝并携带影响面
    //（哪个 consumer、哪个需求、InterfaceRemoved）；commit 同样被全量重建
    // 门控拒绝（MissingProvider）；快照未切换（v1 仍在服务）。
    let (harness, provider_installation, consumer_installation) = baseline_upgrade_harness();
    let breaking = upgrade_records(provider_installation, &["test:calc/analytics@1.0.0"]);
    let error = match harness
        .composition
        .check_upgrade(provider_installation, &breaking)
    {
        Ok(_) => test_failure("breaking upgrade must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderUpgradeIncompatible {
            installation: upgraded,
            report,
        } => {
            assert_eq!(upgraded, provider_installation);
            assert!(!report.is_safe());
            assert_eq!(report.impacts().len(), 1);
            let impact = &report.impacts()[0];
            assert_eq!(impact.consumer(), consumer_installation);
            assert_eq!(impact.requirement(), &requirement("test:calc/calc@^1.0.0"));
            assert!(!impact.result().is_compatible());
            assert!(impact.result().reason().is_some());
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // commit 路径同样拒绝（全量重建门控：consumer 需求缺 provider）。
    let error = match harness
        .composition
        .commit_activation(provider_installation, &breaking)
    {
        Ok(_) => test_failure("breaking upgrade commit must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderGraphResolution { source } => {
            assert!(
                matches!(source, ProviderGraphError::MissingProvider { .. }),
                "unexpected error: {source:?}"
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    // 快照未切换：v1 仍在服务（边解析到 calc@1.0.0）。
    let graph = harness.composition.graph();
    let edge = expect_some(
        graph.resolve(consumer_installation, &requirement("test:calc/calc@^1.0.0")),
        "v1 edge",
    );
    assert_eq!(edge.provided(), &interface_id("test:calc/calc@1.0.0"));
    assert_eq!(
        expect_some(
            harness.graph_store.provider(provider_installation),
            "stored record"
        )
        .provided()
        .len(),
        1
    );
}

#[test]
fn version_incompatible_upgrade_rejected_with_reason() {
    // §40.2 版本兼容分析（records 驱动）：升级到 calc@2.0.0（major 破坏性，
    // §13.2）→ check_upgrade 拒绝并报告 VersionIncompatible 的最高升级版本。
    let (harness, provider_installation, consumer_installation) = baseline_upgrade_harness();
    let breaking = upgrade_records(provider_installation, &["test:calc/calc@2.0.0"]);
    let error = match harness
        .composition
        .check_upgrade(provider_installation, &breaking)
    {
        Ok(_) => test_failure("version-incompatible upgrade must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderUpgradeIncompatible {
            installation,
            report,
        } => {
            assert_eq!(installation, provider_installation);
            assert!(!report.is_safe());
            // 影响面（typed）：哪个 consumer、哪个需求、什么原因
            //（diagnostics 向上传）。
            assert_eq!(report.impacts().len(), 1);
            let impact = &report.impacts()[0];
            assert_eq!(impact.consumer(), consumer_installation);
            assert_eq!(impact.requirement(), &requirement("test:calc/calc@^1.0.0"));
            assert_eq!(
                impact.result(),
                &operune_domain::UpgradeImpact::Incompatible {
                    reason: operune_domain::UpgradeIncompatibility::VersionIncompatible {
                        upgraded_highest: ComponentVersion::from_parts(2, 0, 0),
                    },
                }
            );
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
}

#[test]
fn real_surface_upgrade_gate_allows_safe_and_rejects_breaking() {
    // §40.2 升级门控全链路（真实 surface 观察）：安全升级（calc@1.2.0，
    // ^1.0.0 仍满足）经 check_upgrade + commit 放行、快照切换；随后破坏性
    // 升级（calc@2.0.0）被 check_upgrade 拒绝（ProviderUpgradeIncompatible）、
    // commit 被全量重建拒绝，快照保持 1.2.0。
    let (harness, provider_installation, consumer_installation) = baseline_upgrade_harness();
    // 安全升级：真实 1.2.0 二进制。
    let (_, safe) = harness.observe(provider_installation, LINKED_PROVIDER_ADD_V1_2_WAT);
    expect_ok(
        harness
            .composition
            .check_upgrade(provider_installation, &safe),
        "safe upgrade gate",
    );
    let graph = expect_ok(
        harness
            .composition
            .commit_activation(provider_installation, &safe),
        "safe upgrade commit",
    );
    let edge = expect_some(
        graph.resolve(consumer_installation, &requirement("test:calc/calc@^1.0.0")),
        "upgraded edge",
    );
    assert_eq!(edge.provided(), &interface_id("test:calc/calc@1.2.0"));
    // 破坏性升级：真实 2.0.0 二进制。
    let (_, breaking) = harness.observe(provider_installation, LINKED_PROVIDER_ADD_V2_WAT);
    let error = match harness
        .composition
        .check_upgrade(provider_installation, &breaking)
    {
        Ok(_) => test_failure("breaking upgrade must be rejected"),
        Err(error) => error,
    };
    match error {
        ApplicationError::ProviderUpgradeIncompatible { report, .. } => {
            assert!(!report.is_safe());
            // 影响面（typed）：哪个 consumer、哪个需求（diagnostics 向上传）。
            assert_eq!(report.impacts().len(), 1);
            let impact = &report.impacts()[0];
            assert_eq!(impact.consumer(), consumer_installation);
            assert_eq!(impact.requirement(), &requirement("test:calc/calc@^1.0.0"));
            assert!(!impact.result().is_compatible());
        }
        other => test_failure(format_args!("unexpected error: {other:?}")),
    }
    let error = match harness
        .composition
        .commit_activation(provider_installation, &breaking)
    {
        Ok(_) => test_failure("breaking upgrade commit must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        ApplicationError::ProviderGraphResolution { .. }
    ));
    // 快照未切换：边仍解析到 1.2.0。
    let graph = harness.composition.graph();
    let edge = expect_some(
        graph.resolve(consumer_installation, &requirement("test:calc/calc@^1.0.0")),
        "edge after rejected upgrade",
    );
    assert_eq!(edge.provided(), &interface_id("test:calc/calc@1.2.0"));
    // 存储记录仍是 1.2.0（失败的升级未落盘）。
    let stored = expect_some(
        harness.graph_store.provider(provider_installation),
        "stored record",
    );
    assert_eq!(
        provider_id_of(&stored),
        ProviderId::from_installation(provider_installation)
    );
    assert!(
        stored
            .provided()
            .contains(&interface_id("test:calc/calc@1.2.0"))
    );
}
