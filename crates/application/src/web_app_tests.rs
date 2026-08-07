//! 0.4.0 Web Application Runtime（§42.2）——[`crate::web_app`] 的测试。
//!
//! 覆盖：app-descriptor 组装与声明期冲突诊断各路径、路由匹配（typed
//! 参数解析成功 / 溢出 / 不匹配）、页面权限检查点、typed route dispatch
//! （fake runtime）、cancellation（deadline 到期 / 取消探针 / 结果丢弃）、
//! per-Component quota 拒绝、0.1 组件回退路径、0.1→0.2 surface 分发。

use std::sync::Arc;

use operune_domain::{
    ByteSize, CapabilityId, ComponentLifecycleState, ContentDigest, HttpMethod, InstallationId,
    PageDeclaration, PageId, PagePath, ParamValue, PermissionName, RouteId, WebDeclarationError,
};

use crate::active::ActiveEntry;
use crate::cancel::CancellationToken;
use crate::contract::{
    GuestActionPayload, GuestAppDescriptor, GuestAppFeatures, GuestPageDeclaration,
    GuestParamValue, GuestPermissionDeclaration, GuestRouteDeclaration, GuestRouteParamDecl,
    GuestRouteRequest, GuestTypedParam,
};
use crate::error::{ApplicationError, RuntimeExecutionError};
use crate::model::{
    ActionDenied, ContractSurface, GrantScope, InstallOutcome, RuntimeConfig, WebAssetPath,
    WebManifestData, WebManifestFeatures, WebSurfaceKind,
};
use crate::ports::{
    AuditEvent, AuditPort, ConfigPort, GrantStorePort, InProcessWebPermissionPolicy,
    InProcessWebQuota, WEB_PERMISSIONS_CAPABILITY, WebPermissionPolicyPort, WebQuotaDenied,
    WebQuotaLimits, WebQuotaPort,
};
use crate::runtime::ActiveRuntime;
use crate::test_support::{
    FakeConfig, FakeGrants, Harness, ok, plain_install_request, some, test_failure,
};
use crate::web_app::{
    AppDescriptorFailure, RouteMatchError, RouteRegistry, WebAppContext, WebAppService,
    WebDispatchError, WebPageDenied,
};

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

/// 一个覆盖全部声明面形态的 guest app-descriptor（§42.2）。
fn sample_guest() -> GuestAppDescriptor {
    GuestAppDescriptor {
        entry: "/index.html".to_owned(),
        features: GuestAppFeatures {
            static_assets: true,
            backend_actions: true,
            navigation: true,
            typed_routes: true,
            permissions: true,
        },
        display_name: Some("Example UI".to_owned()),
        permissions: vec![GuestPermissionDeclaration {
            name: "admin".to_owned(),
            description: Some("管理员操作".to_owned()),
        }],
        pages: vec![
            GuestPageDeclaration {
                page_id: "home".to_owned(),
                path: "/home".to_owned(),
                display_name: Some("Home".to_owned()),
                required_permission: None,
            },
            GuestPageDeclaration {
                page_id: "admin".to_owned(),
                path: "/admin".to_owned(),
                display_name: None,
                required_permission: Some("admin".to_owned()),
            },
        ],
        routes: vec![
            GuestRouteDeclaration {
                route_id: "get-item".to_owned(),
                method: "get".to_owned(),
                path: "/api/{id}".to_owned(),
                params: vec![GuestRouteParamDecl {
                    name: "id".to_owned(),
                    value_type: "integer".to_owned(),
                }],
                required_permission: None,
            },
            GuestRouteDeclaration {
                route_id: "create-item".to_owned(),
                method: "post".to_owned(),
                path: "/api/items".to_owned(),
                params: Vec::new(),
                required_permission: Some("admin".to_owned()),
            },
        ],
        default_page: Some("home".to_owned()),
    }
}

/// 安装一个 0.2.0 表面组件（app-descriptor + navigation + routes +
/// permissions + route-dispatch + assets + actions）并返回 installation。
fn install_web_app_component(harness: &Harness) -> InstallationId {
    harness.runtime.with_surface(ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "descriptor".to_owned(),
            "app-descriptor".to_owned(),
            "navigation".to_owned(),
            "routes".to_owned(),
            "permissions".to_owned(),
            "assets".to_owned(),
            "actions".to_owned(),
            "route-dispatch".to_owned(),
        ],
    });
    harness.runtime.with_manifest(Some(WebManifestData {
        entry: ok(WebAssetPath::new("/index.html"), "entry"),
        features: WebManifestFeatures {
            static_assets: true,
            backend_actions: true,
        },
        assets: Vec::new(),
    }));
    let bytes = b"web app bytes".to_vec();
    harness
        .runtime
        .with_app_descriptor_for(&bytes, sample_guest());
    harness.runtime.with_route_result(Ok(vec![9, 8, 7]));
    let outcome = ok(
        harness.install.install(plain_install_request(bytes)),
        "install web app component",
    );
    match outcome {
        InstallOutcome::Activated { installation, .. } => installation,
    }
}

/// 0.1-only 组件（§21.3：descriptor + assets + actions，无
/// app-descriptor）。
fn install_legacy_web_component(harness: &Harness) -> InstallationId {
    harness.runtime.with_surface(ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "descriptor".to_owned(),
            "assets".to_owned(),
            "actions".to_owned(),
        ],
    });
    harness.runtime.with_manifest(Some(WebManifestData {
        entry: ok(WebAssetPath::new("/index.html"), "entry"),
        features: WebManifestFeatures {
            static_assets: true,
            backend_actions: true,
        },
        assets: Vec::new(),
    }));
    let outcome = ok(
        harness
            .install
            .install(plain_install_request(b"legacy bytes".to_vec())),
        "install legacy web component",
    );
    match outcome {
        InstallOutcome::Activated { installation, .. } => installation,
    }
}

fn route_request(route_id: &str) -> GuestRouteRequest {
    GuestRouteRequest {
        route_id: route_id.to_owned(),
        params: Vec::new(),
        payload: None,
    }
}

/// `get-item` 声明了一个 integer 参数（/api/{id}）：分发请求必须携带
/// 与声明一致的 typed 参数（§42.2 typed 语义）。
fn get_item_request() -> GuestRouteRequest {
    GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![GuestTypedParam {
            name: "id".to_owned(),
            value: GuestParamValue::Integer(7),
        }],
        payload: None,
    }
}

/// 直接构造带指定 limits 的 quota port。
fn quota(limits: WebQuotaLimits) -> Arc<dyn WebQuotaPort> {
    match InProcessWebQuota::new(limits) {
        Ok(quota) => Arc::new(quota),
        Err(_) => test_failure("quota construction failed"),
    }
}

fn permission_policy(grants: &Arc<FakeGrants>) -> Arc<dyn WebPermissionPolicyPort> {
    Arc::new(InProcessWebPermissionPolicy::new(
        Arc::clone(grants) as Arc<dyn GrantStorePort>
    ))
}

fn config_port(config: RuntimeConfig) -> Arc<dyn ConfigPort> {
    Arc::new(FakeConfig::new(config))
}

fn service(harness: &Harness) -> &WebAppService {
    &harness.web_app
}

// ---------------------------------------------------------------------------
// build_app_declaration：组装 + 冲突诊断（§42.2）
// ---------------------------------------------------------------------------

#[test]
fn build_app_declaration_accepts_valid_descriptor() {
    let harness = Harness::new(RuntimeConfig::default());
    let declared = ok(
        service(&harness).build_app_declaration(&sample_guest()),
        "build app declaration",
    );
    assert_eq!(declared.entry().as_str(), "/index.html");
    assert_eq!(declared.pages().len(), 2);
    assert_eq!(declared.routes().len(), 2);
    assert_eq!(declared.permissions().len(), 1);
    assert_eq!(declared.default_page().map(|id| id.as_str()), Some("home"));
    // typed 参数类型映射（integer）。
    assert_eq!(
        declared.routes()[0].params()[0].value_type(),
        operune_domain::ParamType::Integer
    );
}

#[test]
fn build_app_declaration_rejects_route_id_conflict() {
    let mut guest = sample_guest();
    guest.routes.push(GuestRouteDeclaration {
        route_id: "get-item".to_owned(),
        method: "post".to_owned(),
        path: "/api/other".to_owned(),
        params: Vec::new(),
        required_permission: None,
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(
        matches!(
            result,
            Err(AppDescriptorFailure::Declaration {
                source: WebDeclarationError::RouteIdConflict { route_id: ref id }
            }) if id.as_str() == "get-item"
        ),
        "duplicate route-id must be diagnosed: {result:?}"
    );
}

#[test]
fn build_app_declaration_rejects_page_id_conflict() {
    let mut guest = sample_guest();
    guest.pages.push(GuestPageDeclaration {
        page_id: "home".to_owned(),
        path: "/home-2".to_owned(),
        display_name: None,
        required_permission: None,
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::PageIdConflict { page_id }
        }) if page_id.as_str() == "home"
    ));
}

#[test]
fn build_app_declaration_rejects_route_path_conflict() {
    // 同方法参数位置冲突（歧义路由）。
    let mut guest = sample_guest();
    guest.routes.push(GuestRouteDeclaration {
        route_id: "get-item-by-name".to_owned(),
        method: "get".to_owned(),
        path: "/api/{name}".to_owned(),
        params: vec![GuestRouteParamDecl {
            name: "name".to_owned(),
            value_type: "text".to_owned(),
        }],
        required_permission: None,
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(
        matches!(
            result,
            Err(AppDescriptorFailure::Declaration {
                source: WebDeclarationError::PathConflict { .. }
            })
        ),
        "same-method template conflict must be diagnosed: {result:?}"
    );
}

#[test]
fn build_app_declaration_rejects_page_route_conflict() {
    // page 路径与 GET route 模板冲突（歧义路由：页面经 GET 导航）。
    let mut guest = sample_guest();
    guest.routes.push(GuestRouteDeclaration {
        route_id: "wildcard-page".to_owned(),
        method: "get".to_owned(),
        path: "/{x}".to_owned(),
        params: vec![GuestRouteParamDecl {
            name: "x".to_owned(),
            value_type: "text".to_owned(),
        }],
        required_permission: None,
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::PathConflict { .. }
        })
    ));
}

#[test]
fn build_app_declaration_same_path_different_method_ok() {
    // 同 path 不同方法不冲突（§42.2 冲突判定的方法维度）。
    let mut guest = sample_guest();
    guest.routes.push(GuestRouteDeclaration {
        route_id: "delete-item".to_owned(),
        method: "delete".to_owned(),
        path: "/api/{id}".to_owned(),
        params: vec![GuestRouteParamDecl {
            name: "id".to_owned(),
            value_type: "integer".to_owned(),
        }],
        required_permission: None,
    });
    let declared = ok(
        service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest),
        "build app declaration",
    );
    assert_eq!(declared.routes().len(), 3);
}

#[test]
fn build_app_declaration_rejects_default_page_not_declared() {
    let mut guest = sample_guest();
    guest.default_page = Some("missing".to_owned());
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::InvalidDefaultPage { detail }
        }) if detail.contains("missing")
    ));
}

#[test]
fn build_app_declaration_rejects_param_mismatch() {
    // 声明了模板中不存在的参数 → param-mismatch（routes.wit）。
    let mut guest = sample_guest();
    guest.routes[0].params.push(GuestRouteParamDecl {
        name: "extra".to_owned(),
        value_type: "text".to_owned(),
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::ParamMismatch { .. }
        })
    ));
}

#[test]
fn build_app_declaration_rejects_invalid_permission() {
    // required-permission 引用未声明的 permission-name。
    let mut guest = sample_guest();
    guest.routes[1].required_permission = Some("undeclared".to_owned());
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::InvalidPermission { detail }
        }) if detail.contains("undeclared")
    ));
}

#[test]
fn build_app_declaration_rejects_duplicate_permission_name() {
    let mut guest = sample_guest();
    guest.permissions.push(GuestPermissionDeclaration {
        name: "admin".to_owned(),
        description: None,
    });
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(matches!(
        result,
        Err(AppDescriptorFailure::Declaration {
            source: WebDeclarationError::InvalidPermission { .. }
        })
    ));
}

#[test]
fn build_app_declaration_rejects_invalid_path_template() {
    let mut guest = sample_guest();
    guest.routes[0].path = "/api/{ID}".to_owned();
    let result = service(&Harness::new(RuntimeConfig::default())).build_app_declaration(&guest);
    assert!(
        matches!(
            result,
            Err(AppDescriptorFailure::Declaration {
                source: WebDeclarationError::InvalidPathTemplate { .. }
            })
        ),
        "template syntax errors must surface as invalid-path-template: {result:?}"
    );
}

#[test]
fn build_app_declaration_rejects_malformed_structural() {
    // 结构性非法 → malformed（WIT `malformed`）。
    let harness = Harness::new(RuntimeConfig::default());
    let mut bad_entry = sample_guest();
    bad_entry.entry = "../escape".to_owned();
    assert!(matches!(
        service(&harness).build_app_declaration(&bad_entry),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    let mut bad_page = sample_guest();
    bad_page.pages[0].page_id = "bad\nid".to_owned();
    assert!(matches!(
        service(&harness).build_app_declaration(&bad_page),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    let mut bad_method = sample_guest();
    bad_method.routes[1].method = "head".to_owned();
    assert!(matches!(
        service(&harness).build_app_declaration(&bad_method),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    let mut bad_type = sample_guest();
    bad_type.routes[0].params[0].value_type = "string".to_owned();
    assert!(matches!(
        service(&harness).build_app_declaration(&bad_type),
        Err(AppDescriptorFailure::Malformed(_))
    ));
}

#[test]
fn build_app_declaration_rejects_feature_flag_mismatch() {
    // WIT features 交叉不变量（app-descriptor.wit）：声明与 flag 不一致
    // → malformed。
    let harness = Harness::new(RuntimeConfig::default());
    let mut no_navigation = sample_guest();
    no_navigation.features.navigation = false;
    assert!(matches!(
        service(&harness).build_app_declaration(&no_navigation),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    let mut no_routes = sample_guest();
    no_routes.features.typed_routes = false;
    assert!(matches!(
        service(&harness).build_app_declaration(&no_routes),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    let mut no_permissions = sample_guest();
    no_permissions.features.permissions = false;
    assert!(matches!(
        service(&harness).build_app_declaration(&no_permissions),
        Err(AppDescriptorFailure::Malformed(_))
    ));

    // 仅 static-assets / backend-actions 的 0.2.0 组件（兼容路径）合法。
    let legacy = GuestAppDescriptor {
        features: GuestAppFeatures {
            static_assets: true,
            backend_actions: true,
            navigation: false,
            typed_routes: false,
            permissions: false,
        },
        permissions: Vec::new(),
        pages: Vec::new(),
        routes: Vec::new(),
        default_page: None,
        ..sample_guest()
    };
    assert!(service(&harness).build_app_declaration(&legacy).is_ok());
}

#[test]
fn validate_contract_surface_cross_checks_exports() {
    let harness = Harness::new(RuntimeConfig::default());
    let declared = ok(
        service(&harness).build_app_declaration(&sample_guest()),
        "build app declaration",
    );
    // 全表面导出 → 通过。
    let full = ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "navigation".to_owned(),
            "route-dispatch".to_owned(),
            "permissions".to_owned(),
        ],
    };
    assert!(
        service(&harness)
            .validate_contract_surface(&declared, &full)
            .is_ok()
    );
    // 缺 navigation 导出 → ContractViolation。
    let no_navigation = ContractSurface {
        imports: Vec::new(),
        exports: vec!["route-dispatch".to_owned(), "permissions".to_owned()],
    };
    assert!(matches!(
        service(&harness).validate_contract_surface(&declared, &no_navigation),
        Err(AppDescriptorFailure::ContractViolation(_))
    ));
    // 缺 route-dispatch 导出（typed-routes flag）→ ContractViolation。
    let no_dispatch = ContractSurface {
        imports: Vec::new(),
        exports: vec!["navigation".to_owned(), "permissions".to_owned()],
    };
    assert!(matches!(
        service(&harness).validate_contract_surface(&declared, &no_dispatch),
        Err(AppDescriptorFailure::ContractViolation(_))
    ));
}

// ---------------------------------------------------------------------------
// RouteRegistry：匹配与 typed 参数解析（§42.2）
// ---------------------------------------------------------------------------

fn registry(harness: &Harness) -> RouteRegistry {
    let declared = ok(
        service(harness).build_app_declaration(&sample_guest()),
        "build app declaration",
    );
    RouteRegistry::new(&declared)
}

#[test]
fn resolve_literal_route() {
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    let resolution = ok(
        registry.resolve(HttpMethod::Post, "/api/items"),
        "resolve literal route",
    );
    assert_eq!(resolution.route_id.as_str(), "create-item");
    assert!(resolution.params.is_empty());
}

#[test]
fn resolve_template_route_parses_typed_params() {
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    let resolution = ok(
        registry.resolve(HttpMethod::Get, "/api/42"),
        "resolve template route",
    );
    assert_eq!(resolution.route_id.as_str(), "get-item");
    assert_eq!(resolution.params.len(), 1);
    assert_eq!(resolution.params[0].name(), "id");
    assert_eq!(resolution.params[0].value(), &ParamValue::Integer(42));
}

#[test]
fn resolve_params_follow_declaration_order() {
    // §42.2：params 顺序与声明一致（声明顺序 ≠ 模板出现顺序时）。
    let harness = Harness::new(RuntimeConfig::default());
    let mut guest = sample_guest();
    guest.routes = vec![GuestRouteDeclaration {
        route_id: "mixed".to_owned(),
        method: "get".to_owned(),
        path: "/a/{x}/b/{y}".to_owned(),
        params: vec![
            GuestRouteParamDecl {
                name: "y".to_owned(),
                value_type: "unsigned".to_owned(),
            },
            GuestRouteParamDecl {
                name: "x".to_owned(),
                value_type: "text".to_owned(),
            },
        ],
        required_permission: None,
    }];
    let declared = ok(
        service(&harness).build_app_declaration(&guest),
        "build app declaration",
    );
    let registry = RouteRegistry::new(&declared);
    let resolution = ok(
        registry.resolve(HttpMethod::Get, "/a/hello/b/7"),
        "resolve mixed route",
    );
    assert_eq!(
        resolution
            .params
            .iter()
            .map(|param| (param.name().to_owned(), param.value().clone()))
            .collect::<Vec<_>>(),
        vec![
            ("y".to_owned(), ParamValue::Unsigned(7)),
            ("x".to_owned(), ParamValue::Text("hello".to_owned())),
        ],
        "params must follow the declaration order"
    );
}

#[test]
fn resolve_rejects_integer_overflow() {
    // 溢出拒绝（§13.3 宽边界 → 64 位闭集）。
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    let result = registry.resolve(HttpMethod::Get, "/api/99999999999999999999999999");
    assert!(
        matches!(
            result,
            Err(RouteMatchError::InvalidParamValue {
                ref name,
                ref detail,
            }) if name == "id" && detail.contains("overflow")
        ),
        "out-of-range integer must be rejected: {result:?}"
    );
}

#[test]
fn resolve_rejects_unsigned_overflow() {
    let harness = Harness::new(RuntimeConfig::default());
    let mut guest = sample_guest();
    guest.routes[0].params[0].value_type = "unsigned".to_owned();
    let declared = ok(
        service(&harness).build_app_declaration(&guest),
        "build app declaration",
    );
    let registry = RouteRegistry::new(&declared);
    let result = registry.resolve(HttpMethod::Get, "/api/18446744073709551616");
    assert!(
        matches!(
            result,
            Err(RouteMatchError::InvalidParamValue { ref detail, .. })
                if detail.contains("overflow")
        ),
        "out-of-range unsigned must be rejected: {result:?}"
    );
}

#[test]
fn resolve_rejects_non_integer_for_integer_param() {
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    let result = registry.resolve(HttpMethod::Get, "/api/not-a-number");
    assert!(
        matches!(
            result,
            Err(RouteMatchError::InvalidParamValue { ref name, .. })
                if name == "id"
        ),
        "non-integer for integer param must be rejected: {result:?}"
    );
}

#[test]
fn resolve_boolean_param_closed_set() {
    let harness = Harness::new(RuntimeConfig::default());
    let mut guest = sample_guest();
    guest.routes[0].params[0].value_type = "boolean".to_owned();
    let declared = ok(
        service(&harness).build_app_declaration(&guest),
        "build app declaration",
    );
    let registry = RouteRegistry::new(&declared);
    let resolution = ok(
        registry.resolve(HttpMethod::Get, "/api/true"),
        "resolve boolean true",
    );
    assert_eq!(resolution.params[0].value(), &ParamValue::Boolean(true));
    // 闭集外的字符串拒绝。
    let result = registry.resolve(HttpMethod::Get, "/api/yes");
    assert!(
        matches!(
            result,
            Err(RouteMatchError::InvalidParamValue { ref detail, .. })
                if detail.contains("boolean")
        ),
        "non-closed boolean must be rejected: {result:?}"
    );
}

#[test]
fn resolve_decimal_param_accepts_finite_and_rejects_non_finite() {
    let harness = Harness::new(RuntimeConfig::default());
    let mut guest = sample_guest();
    guest.routes[0].params[0].value_type = "decimal".to_owned();
    let declared = ok(
        service(&harness).build_app_declaration(&guest),
        "build app declaration",
    );
    let registry = RouteRegistry::new(&declared);
    let resolution = ok(
        registry.resolve(HttpMethod::Get, "/api/1.5"),
        "resolve decimal",
    );
    assert_eq!(resolution.params[0].value(), &ParamValue::Decimal(1.5));
    // NaN / inf 不是 JSON 数字常规形态 → 拒绝。
    for bad in ["NaN", "inf", "-inf", "not-a-number"] {
        assert!(
            registry
                .resolve(HttpMethod::Get, &format!("/api/{bad}"))
                .is_err(),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn resolve_not_matched_paths() {
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    // 段数不符。
    assert!(matches!(
        registry.resolve(HttpMethod::Get, "/api/1/2"),
        Err(RouteMatchError::NotMatched {
            method: HttpMethod::Get,
            ..
        })
    ));
    // 字面段不符。
    assert!(matches!(
        registry.resolve(HttpMethod::Get, "/other/1"),
        Err(RouteMatchError::NotMatched { .. })
    ));
    // 方法不符（同路径不同方法允许，但请求方法必须匹配）。
    assert!(matches!(
        registry.resolve(HttpMethod::Put, "/api/1"),
        Err(RouteMatchError::NotMatched {
            method: HttpMethod::Put,
            ..
        })
    ));
}

#[test]
fn resolve_rejects_invalid_request_paths() {
    // §32 fail closed：拒绝而不是归一化输入。
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    for bad in [
        "",
        "api/1",
        "/api/../1",
        "/api//1",
        "/api/1/",
        "\\api\\1",
        "/api\n1",
    ] {
        assert!(
            matches!(
                registry.resolve(HttpMethod::Get, bad),
                Err(RouteMatchError::InvalidPath(_))
            ),
            "{bad:?} must be rejected"
        );
    }
}

#[test]
fn registry_route_by_id_lookup() {
    let harness = Harness::new(RuntimeConfig::default());
    let registry = registry(&harness);
    let route = registry.route_by_id(&ok(RouteId::new("get-item"), "route-id"));
    assert!(route.is_some());
    assert_eq!(
        route.map(|declaration| declaration.method()),
        Some(HttpMethod::Get)
    );
    assert!(
        registry
            .route_by_id(&ok(RouteId::new("missing"), "route-id"))
            .is_none()
    );
}

#[test]
fn resolve_page_static_paths() {
    let harness = Harness::new(RuntimeConfig::default());
    let declared = ok(
        service(&harness).build_app_declaration(&sample_guest()),
        "build app declaration",
    );
    let context = WebAppContext::new(declared);
    assert_eq!(
        context
            .resolve_page("/home")
            .map(|page| page.page_id().as_str()),
        Some("home")
    );
    assert_eq!(
        context
            .resolve_page("/admin")
            .map(|page| page.page_id().as_str()),
        Some("admin")
    );
    assert_eq!(context.resolve_page("/missing"), None);
    // 规范化失败（traversal）→ None（fail closed）。
    assert_eq!(context.resolve_page("/a/../b"), None);
    assert_eq!(context.default_page().map(|id| id.as_str()), Some("home"));
    assert!(
        context
            .page_by_id(&ok(PageId::new("home"), "page-id"))
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// 激活期（管线接线）：app-descriptor 校验 + 快照
// ---------------------------------------------------------------------------

#[test]
fn activation_builds_web_app_context() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    // §19.3 精神：同一 digest 重复读取比对 canonical 结果。
    assert_eq!(harness.runtime.app_descriptor_calls(), 2);
    let context = some(
        ok(service(&harness).context(installation), "context"),
        "web app context",
    );
    assert_eq!(context.declaration().routes().len(), 2);
    assert_eq!(context.declaration().pages().len(), 2);
    // 运行期路由解析可用。
    let resolution = ok(
        context.registry().resolve(HttpMethod::Get, "/api/42"),
        "resolve route from context",
    );
    assert_eq!(resolution.route_id.as_str(), "get-item");
}

#[test]
fn activation_conflict_keeps_candidate_failed() {
    // 冲突诊断失败 → candidate Failed（quarantine），Active 不受污染。
    let harness = Harness::new(RuntimeConfig::default());
    let bytes = b"conflicting web bytes".to_vec();
    let mut conflicting = sample_guest();
    conflicting.routes.push(GuestRouteDeclaration {
        route_id: "dup".to_owned(),
        method: "get".to_owned(),
        path: "/dup".to_owned(),
        params: Vec::new(),
        required_permission: None,
    });
    conflicting.routes.push(GuestRouteDeclaration {
        route_id: "dup".to_owned(),
        method: "post".to_owned(),
        path: "/dup-2".to_owned(),
        params: Vec::new(),
        required_permission: None,
    });
    harness.runtime.with_app_descriptor_for(&bytes, conflicting);
    let result = harness
        .install
        .install(plain_install_request(bytes.clone()));
    assert!(matches!(
        result,
        Err(ApplicationError::WebAppDescriptor { .. })
    ));
    let digest = ContentDigest::from_bytes(&bytes);
    assert_eq!(
        harness.registry.candidate_state(digest),
        Some(ComponentLifecycleState::Failed),
        "conflicting candidate must stay Failed (quarantine)"
    );
    assert!(harness.audit.contains(|event| matches!(
        event,
        AuditEvent::ActivationFailed { stage, .. } if *stage == "app-descriptor"
    )));
    assert!(harness.active.is_empty());
}

#[test]
fn activation_determinism_mismatch_fails_candidate() {
    // §19.3：同一 digest 两次读取不一致 = contract violation。
    let harness = Harness::new(RuntimeConfig::default());
    let bytes = b"non-deterministic bytes".to_vec();
    let mut second = sample_guest();
    second.display_name = Some("Changed".to_owned());
    harness
        .runtime
        .with_app_descriptors(vec![sample_guest(), second]);
    let result = harness
        .install
        .install(plain_install_request(bytes.clone()));
    assert!(
        matches!(result, Err(ApplicationError::DescriptorViolation(_))),
        "{result:?}"
    );
    assert_eq!(
        harness
            .registry
            .candidate_state(ContentDigest::from_bytes(&bytes)),
        Some(ComponentLifecycleState::Failed)
    );
}

#[test]
fn activation_rejects_feature_export_mismatch() {
    // features flag 与二进制 exports 不一致 → contract violation →
    // candidate Failed（§6.7 精神）。
    let harness = Harness::new(RuntimeConfig::default());
    let bytes = b"no dispatch export bytes".to_vec();
    harness
        .runtime
        .with_app_descriptor_for(&bytes, sample_guest());
    harness.runtime.with_surface(ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "descriptor".to_owned(),
            "app-descriptor".to_owned(),
            "navigation".to_owned(),
            "permissions".to_owned(),
            "assets".to_owned(),
            "actions".to_owned(),
        ],
    });
    let result = harness.install.install(plain_install_request(bytes));
    assert!(
        matches!(result, Err(ApplicationError::WebAppDescriptor { .. })),
        "missing route-dispatch export must fail activation: {result:?}"
    );
}

#[test]
fn activation_read_failure_fails_candidate() {
    let harness = Harness::new(RuntimeConfig::default());
    let bytes = b"broken descriptor bytes".to_vec();
    harness.runtime.with_app_descriptor_failure();
    let result = harness
        .install
        .install(plain_install_request(bytes.clone()));
    assert!(matches!(result, Err(ApplicationError::Runtime(_))));
    assert_eq!(
        harness
            .registry
            .candidate_state(ContentDigest::from_bytes(&bytes)),
        Some(ComponentLifecycleState::Failed)
    );
}

#[test]
fn legacy_0_1_component_keeps_working() {
    // 0.1-only 组件（无 app-descriptor 导出）：安装成功，web_app 为
    // None（无 flag-day，§8.4 精神）。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_legacy_web_component(&harness);
    assert!(
        ok(service(&harness).context(installation), "context").is_none(),
        "0.1-only components must have no web app context"
    );
    // typed dispatch 确定性拒绝（route-dispatch.wit not-found 语义）。
    assert!(
        matches!(
            service(&harness).dispatch_route(
                installation,
                &route_request("anything"),
                &CancellationToken::new(),
            ),
            Err(WebDispatchError::RouteUnavailable)
        ),
        "0.1-only components must reject typed route dispatch"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
}

// ---------------------------------------------------------------------------
// 升级（§21.5 原子版本切换）
// ---------------------------------------------------------------------------

#[test]
fn upgrade_swaps_web_app_context_atomically() {
    // §21.5：UI assets、app descriptor 与 backend exports 属于同一
    // ComponentVersion；升级经 active snapshot 一次性切换——升级后任何
    // route lookup 解析到同一 active 版本，禁止前后端版本拼接。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    // v2：声明不同的路由集（route namespace 由新 ComponentVersion 重新
    // 登记）。
    let mut v2 = sample_guest();
    v2.routes = vec![GuestRouteDeclaration {
        route_id: "v2-only".to_owned(),
        method: "get".to_owned(),
        path: "/v2/{id}".to_owned(),
        params: vec![GuestRouteParamDecl {
            name: "id".to_owned(),
            value_type: "integer".to_owned(),
        }],
        required_permission: None,
    }];
    let v2_bytes = b"web app bytes v2".to_vec();
    harness.runtime.with_app_descriptor_for(&v2_bytes, v2);
    // v2 是同一逻辑产品的新版本（§20：ComponentId 不变、版本递增；
    // §19.4 同一逻辑版本禁止不同 digest）。
    harness.runtime.with_descriptor_for(
        &v2_bytes,
        crate::contract::GuestComponentDescriptor {
            component_id: "demo".to_owned(),
            major: 1,
            minor: 1,
            patch: 0,
            display_name: "Demo Component".to_owned(),
            author: None,
        },
    );
    harness.runtime.with_route_result(Ok(vec![1, 2]));
    let outcome = ok(
        harness.upgrade.upgrade(crate::model::UpgradeRequest {
            installation,
            bytes: v2_bytes,
            grants: crate::model::GrantApproval::ReuseExisting,
        }),
        "upgrade web app",
    );
    assert!(
        matches!(outcome, crate::model::UpgradeOutcome::Swapped { .. }),
        "{outcome:?}"
    );
    // 快照已切换：新请求解析到 v2 声明（v1 路由不再存在）。
    let context = some(
        ok(service(&harness).context(installation), "context"),
        "web app context",
    );
    assert!(
        context
            .registry()
            .route_by_id(&ok(RouteId::new("v2-only"), "route-id"))
            .is_some(),
        "upgraded declaration must be active"
    );
    assert!(
        context
            .registry()
            .route_by_id(&ok(RouteId::new("get-item"), "route-id"))
            .is_none(),
        "old declaration must be gone after the atomic swap"
    );
    // v2 路由可分发（经同一 WebAppService）。
    let request = GuestRouteRequest {
        route_id: "v2-only".to_owned(),
        params: vec![GuestTypedParam {
            name: "id".to_owned(),
            value: GuestParamValue::Integer(3),
        }],
        payload: None,
    };
    ok(
        service(&harness).dispatch_route(installation, &request, &CancellationToken::new()),
        "dispatch v2 route",
    );
    assert_eq!(harness.runtime.route_calls(), 1);
}

// ---------------------------------------------------------------------------
// typed route dispatch（§42.2）
// ---------------------------------------------------------------------------

#[test]
fn dispatch_route_calls_guest_and_audits() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let response = ok(
        service(&harness).dispatch_route(
            installation,
            &get_item_request(),
            &CancellationToken::new(),
        ),
        "dispatch route",
    );
    assert_eq!(response, vec![9, 8, 7]);
    assert_eq!(harness.runtime.route_calls(), 1);
    // 审计（§16.6 元数据 only；route-id 是 action-name 的 typed 演进，
    // 复用 0.1 action 审计变体）。
    assert!(harness.audit.contains(|event| matches!(
        event,
        AuditEvent::ActionInvoked { action, .. } if action == "get-item"
    )));
}

#[test]
fn dispatch_route_rejects_unknown_route_id() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let result = service(&harness).dispatch_route(
        installation,
        &route_request("missing"),
        &CancellationToken::new(),
    );
    assert!(
        matches!(
            result,
            Err(WebDispatchError::RouteNotFound(ref id)) if id.as_str() == "missing"
        ),
        "{result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
}

#[test]
fn dispatch_route_rejects_invalid_route_id() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let result = service(&harness).dispatch_route(
        installation,
        &route_request("bad\nid"),
        &CancellationToken::new(),
    );
    assert!(
        matches!(result, Err(WebDispatchError::InvalidRouteId(_))),
        "{result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
}

#[test]
fn dispatch_route_validates_params_against_declaration() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    // 类型不符（声明 integer，请求 text）→ InvalidParams。
    let wrong_type = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![GuestTypedParam {
            name: "id".to_owned(),
            value: GuestParamValue::Text("42".to_owned()),
        }],
        payload: None,
    };
    assert!(
        matches!(
            service(&harness).dispatch_route(installation, &wrong_type, &CancellationToken::new(),),
            Err(WebDispatchError::InvalidParams)
        ),
        "type mismatch must be rejected"
    );
    // 数量不符（声明 1 个参数，请求 2 个）→ InvalidParams。
    let wrong_count = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![
            GuestTypedParam {
                name: "id".to_owned(),
                value: GuestParamValue::Integer(1),
            },
            GuestTypedParam {
                name: "extra".to_owned(),
                value: GuestParamValue::Integer(2),
            },
        ],
        payload: None,
    };
    assert!(matches!(
        service(&harness).dispatch_route(installation, &wrong_count, &CancellationToken::new(),),
        Err(WebDispatchError::InvalidParams)
    ));
    // 名称不符 → InvalidParams。
    let wrong_name = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![GuestTypedParam {
            name: "other".to_owned(),
            value: GuestParamValue::Integer(1),
        }],
        payload: None,
    };
    assert!(matches!(
        service(&harness).dispatch_route(installation, &wrong_name, &CancellationToken::new(),),
        Err(WebDispatchError::InvalidParams)
    ));
    // 一致参数 → 调用成功。
    let matching = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![GuestTypedParam {
            name: "id".to_owned(),
            value: GuestParamValue::Integer(7),
        }],
        payload: None,
    };
    ok(
        service(&harness).dispatch_route(installation, &matching, &CancellationToken::new()),
        "dispatch with matching params",
    );
    assert_eq!(harness.runtime.route_calls(), 1);
}

#[test]
fn dispatch_route_permission_denied_before_guest() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    // "create-item" 需要 permission "admin"；无 grant → 403 语义。
    let result = service(&harness).dispatch_route(
        installation,
        &route_request("create-item"),
        &CancellationToken::new(),
    );
    assert!(
        matches!(
            result,
            Err(WebDispatchError::PermissionDenied(
                crate::ports::PermissionDenied::NotGranted
            ))
        ),
        "{result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
    assert!(harness.audit.contains(|event| matches!(
        event,
        AuditEvent::ActionDenied {
            installation: _,
            action,
            reason,
        } if action == "create-item" && *reason == ActionDenied::NotGranted
    )));
}

#[test]
fn dispatch_route_permission_granted_by_named_scope() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    ok(
        harness.grants.replace_grants(
            installation,
            &[crate::model::InstallationGrant {
                capability: ok(CapabilityId::new(WEB_PERMISSIONS_CAPABILITY), "capability"),
                scope: GrantScope::Action {
                    name: "admin".to_owned(),
                },
            }],
        ),
        "replace grants",
    );
    ok(
        service(&harness).dispatch_route(
            installation,
            &route_request("create-item"),
            &CancellationToken::new(),
        ),
        "dispatch granted route",
    );
    assert_eq!(harness.runtime.route_calls(), 1);
}

#[test]
fn dispatch_route_rejects_oversized_payload() {
    // §42.2 body 上限：超过宿主侧硬上限 → 确定拒绝。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let config = RuntimeConfig {
        max_action_body_bytes: ByteSize::from_bytes(4),
        ..RuntimeConfig::default()
    };
    let audit = Arc::clone(&harness.audit) as Arc<dyn AuditPort>;
    let web_app = WebAppService::new(
        Arc::clone(&harness.active),
        permission_policy(&harness.grants),
        quota(WebQuotaLimits::default()),
        config_port(config),
        audit,
    );
    let oversized = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: vec![GuestTypedParam {
            name: "id".to_owned(),
            value: GuestParamValue::Integer(1),
        }],
        payload: Some(GuestActionPayload::Json("{\"a\":1}".to_owned())),
    };
    assert!(
        matches!(
            web_app.dispatch_route(installation, &oversized, &CancellationToken::new()),
            Err(WebDispatchError::BodyTooLarge)
        ),
        "oversized payload must be rejected"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
}

#[test]
fn dispatch_route_quota_rate_limit_rejected() {
    // §42.2 per-Component HTTP quotas：超限确定拒绝（429 语义）。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let audit = Arc::clone(&harness.audit) as Arc<dyn AuditPort>;
    let web_app = WebAppService::new(
        Arc::clone(&harness.active),
        permission_policy(&harness.grants),
        quota(WebQuotaLimits {
            max_requests_per_minute: 1,
            max_concurrent: 8,
            max_queued: 64,
        }),
        config_port(RuntimeConfig::default()),
        audit,
    );
    ok(
        web_app.dispatch_route(installation, &get_item_request(), &CancellationToken::new()),
        "first dispatch within quota",
    );
    let result =
        web_app.dispatch_route(installation, &get_item_request(), &CancellationToken::new());
    assert!(
        matches!(
            result,
            Err(WebDispatchError::OverQuota(WebQuotaDenied::RateLimited))
        ),
        "rate-limit denial must surface as over-quota: {result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 1);
}

#[test]
fn dispatch_route_cancelled_token_refuses_to_start() {
    // §42.2 cancellation：disconnect 后不启动新的 in-flight 调用。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = service(&harness).dispatch_route(installation, &get_item_request(), &cancel);
    assert!(
        matches!(result, Err(WebDispatchError::Cancelled)),
        "{result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 0);
}

#[test]
fn dispatch_route_deadline_exceeded_maps_deterministically() {
    // §7.5 / §42.2：deadline 到期（运行时 epoch 强制）→ 确定拒绝。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    harness.runtime.with_route_deadline();
    let result = service(&harness).dispatch_route(
        installation,
        &get_item_request(),
        &CancellationToken::new(),
    );
    assert!(
        matches!(result, Err(WebDispatchError::DeadlineExceeded)),
        "{result:?}"
    );
}

#[test]
fn dispatch_route_not_active_installation_denied() {
    let harness = Harness::new(RuntimeConfig::default());
    let result = service(&harness).dispatch_route(
        InstallationId::new(),
        &get_item_request(),
        &CancellationToken::new(),
    );
    assert!(
        matches!(result, Err(WebDispatchError::NotActiveForWeb(_))),
        "{result:?}"
    );
}

/// 包装 runtime：invoke_route 期间取消 token（disconnect 竞态形态——
/// 调用结束时客户端已断开）。
struct CancelDuringRoute {
    inner: Arc<dyn ActiveRuntime>,
    token: CancellationToken,
}

impl ActiveRuntime for CancelDuringRoute {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn check_readiness(&self) -> Result<(), RuntimeExecutionError> {
        self.inner.check_readiness()
    }

    fn read_web_manifest(&self) -> Result<Option<WebManifestData>, RuntimeExecutionError> {
        self.inner.read_web_manifest()
    }

    fn read_asset(&self, path: &WebAssetPath) -> Result<Vec<u8>, RuntimeExecutionError> {
        self.inner.read_asset(path)
    }

    fn invoke_action(
        &self,
        request: &crate::contract::GuestActionRequest,
    ) -> Result<Vec<u8>, RuntimeExecutionError> {
        self.inner.invoke_action(request)
    }

    fn invoke_route(&self, request: &GuestRouteRequest) -> Result<Vec<u8>, RuntimeExecutionError> {
        let result = self.inner.invoke_route(request);
        // 调用返回前客户端断开：Core 取消令牌。
        self.token.cancel();
        result
    }

    fn drain(self: Arc<Self>, deadline: std::time::Duration) -> Result<(), RuntimeExecutionError> {
        Arc::clone(&self.inner).drain(deadline)
    }
}

#[test]
fn dispatch_route_post_call_cancellation_discards_result() {
    // §42.2：调用结束后已取消 → 丢弃结果（响应交付不保证；已提交副作用
    // 不回滚）。
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let entry = some(harness.active.get(installation), "active entry");
    let token = CancellationToken::new();
    let wrapper = Arc::new(CancelDuringRoute {
        inner: Arc::clone(&entry.runtime),
        token: token.clone(),
    });
    ok(
        harness.active.swap(
            installation,
            Arc::new(ActiveEntry {
                installation: entry.installation.clone(),
                runtime: wrapper,
                manifest: entry.manifest.clone(),
                web_app: entry.web_app.clone(),
            }),
        ),
        "swap active entry",
    );
    let result = service(&harness).dispatch_route(installation, &get_item_request(), &token);
    assert!(
        matches!(result, Err(WebDispatchError::Cancelled)),
        "result must be discarded when the client disconnected during the call: {result:?}"
    );
    assert_eq!(harness.runtime.route_calls(), 1, "guest call happened");
    // 已提交副作用不回滚：审计仍然记录调用（元数据）。
    assert!(harness.audit.contains(|event| matches!(
        event,
        AuditEvent::ActionInvoked { action, .. } if action == "get-item"
    )));
}

// ---------------------------------------------------------------------------
// 页面权限检查点（§17.5 第四层）
// ---------------------------------------------------------------------------

#[test]
fn authorize_page_without_required_permission_allows() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let context = some(
        ok(service(&harness).context(installation), "context"),
        "web app context",
    );
    let home = some(
        context.page_by_id(&ok(PageId::new("home"), "page-id")),
        "home page",
    );
    assert!(service(&harness).authorize_page(installation, home).is_ok());
}

#[test]
fn authorize_page_denied_without_grant() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    let context = some(
        ok(service(&harness).context(installation), "context"),
        "web app context",
    );
    let admin = some(
        context.page_by_id(&ok(PageId::new("admin"), "page-id")),
        "admin page",
    );
    assert_eq!(
        service(&harness).authorize_page(installation, admin),
        Err(WebPageDenied::Denied(
            crate::ports::PermissionDenied::NotGranted
        ))
    );
    // 拒绝写审计。
    assert!(harness.audit.contains(|event| matches!(
        event,
        AuditEvent::ActionDenied { action, .. } if action == "page:admin"
    )));
}

#[test]
fn authorize_page_allowed_with_named_grant() {
    let harness = Harness::new(RuntimeConfig::default());
    let installation = install_web_app_component(&harness);
    ok(
        harness.grants.replace_grants(
            installation,
            &[crate::model::InstallationGrant {
                capability: ok(CapabilityId::new(WEB_PERMISSIONS_CAPABILITY), "capability"),
                scope: GrantScope::Action {
                    name: "admin".to_owned(),
                },
            }],
        ),
        "replace grants",
    );
    let context = some(
        ok(service(&harness).context(installation), "context"),
        "web app context",
    );
    let admin = some(
        context.page_by_id(&ok(PageId::new("admin"), "page-id")),
        "admin page",
    );
    assert!(
        service(&harness)
            .authorize_page(installation, admin)
            .is_ok()
    );
}

#[test]
fn authorize_page_not_active_denied() {
    let harness = Harness::new(RuntimeConfig::default());
    let page = PageDeclaration::new(
        ok(PageId::new("home"), "page-id"),
        ok(PagePath::new("/home"), "page-path"),
        None,
        Some(ok(PermissionName::new("admin"), "permission")),
    );
    assert!(matches!(
        service(&harness).authorize_page(InstallationId::new(), &page),
        Err(WebPageDenied::NotActiveForWeb(_))
    ));
}

// ---------------------------------------------------------------------------
// 0.1 → 0.2 surface 分发（§42.2）
// ---------------------------------------------------------------------------

#[test]
fn contract_surface_distributes_v020_preferred() {
    // 0.2.0 表面（app-descriptor / route-dispatch 导出）→ V020。
    let v020 = ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "descriptor".to_owned(),
            "app-descriptor".to_owned(),
            "route-dispatch".to_owned(),
            "assets".to_owned(),
            "actions".to_owned(),
        ],
    };
    assert_eq!(v020.web_surface(), WebSurfaceKind::V020);
    // 全限定名形态同样识别（§6.7 实例名不是身份事实源）。
    let qualified = ContractSurface {
        imports: Vec::new(),
        exports: vec!["operune:web/app-descriptor@0.2.0".to_owned()],
    };
    assert_eq!(qualified.web_surface(), WebSurfaceKind::V020);
    // 0.1-only 表面（assets/actions，无 app-descriptor）→ V010。
    let v010 = ContractSurface {
        imports: Vec::new(),
        exports: vec![
            "descriptor".to_owned(),
            "assets".to_owned(),
            "actions".to_owned(),
        ],
    };
    assert_eq!(v010.web_surface(), WebSurfaceKind::V010);
    // 两个版本共有的语义角色（assets/actions）两个版本都识别。
    assert!(v020.exports_web_assets_any());
    assert!(v010.exports_web_assets_any());
    assert!(v010.exports_web_actions_any());
    assert!(!v010.exports_web_route_dispatch());
}

#[test]
fn route_request_shape_has_no_credentials() {
    // §21.3 凭据边界：route-request 结构只有 route-id + params + payload，
    // 无 session / cookie / CSRF 字段。
    let request = GuestRouteRequest {
        route_id: "get-item".to_owned(),
        params: Vec::new(),
        payload: None,
    };
    assert_eq!(request.route_id, "get-item");
    assert!(request.params.is_empty());
    assert!(request.payload.is_none());
}
