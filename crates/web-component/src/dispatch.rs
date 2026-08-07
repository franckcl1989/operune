//! Typed route 分发（§42.2）：HTTP 请求 → route 声明匹配 → 参数解析。
//!
//! 纯逻辑（无 I/O），HTTP 层（[`crate::router::route_dispatch`]）在调用
//! guest 前执行：route 声明是 Core 托管的平台注册表（route namespace，
//! §42.2），匹配与参数构造发生在分发前（WIT route-dispatch 明文：
//! "Core 在分发前按声明校验并构造参数"）。
//!
//! 语义边界：
//! - **方法 + 规范化路径模板匹配**：同方法下声明冲突已在声明期检出
//!   （`path-conflict`，domain `AppDeclaration::new`），因此至多一条 route
//!   命中（方法不同不冲突；不同方法同路径可共存）；
//! - **参数闭集**（§42.2 typed 参数）：按声明顺序、按声明类型解析；
//!   类型不符 → 400 语义，不进 guest 错误空间；本版本全部声明参数都是
//!   路径模板段参数（模板语法无查询部分，domain web.rs 明文），查询串
//!   不属请求契约，忽略；
//! - **有界**：请求路径长度受宿主层（axum 路径捕获上限）约束；参数值
//!   逐段解析，不放大内存。

use operune_domain::{
    HttpMethod, ParamType, ParamValue, PathSegment, RouteDeclaration, TypedParam,
};

/// 规范化挂载命名空间路径（axum `{*path}` 通配捕获不带前导 "/"；WIT
/// 契约要求规范形态带前导 "/"，§21.3 同 0.1 资产路由）。
pub(crate) fn normalize_mount_path(raw: &str) -> String {
    if raw.starts_with('/') {
        raw.to_owned()
    } else {
        format!("/{raw}")
    }
}

/// 在声明路由表中匹配（方法 + 路径模板）并提取模板参数（原始字符串，
/// 按模板出现顺序）。
///
/// 匹配语义（与 domain `PathConflict::detect` 判定互斥性一致）：段数
/// 相同且每一段位置字面段相等或为参数段。返回 `(route, 参数)`；无匹配
/// 返回 `None`（404 语义）。
pub(crate) fn match_route<'a>(
    routes: &'a [RouteDeclaration],
    method: HttpMethod,
    path: &str,
) -> Option<(&'a RouteDeclaration, Vec<(String, String)>)> {
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    for route in routes {
        if route.method() != method {
            continue;
        }
        let template = route.path().segments();
        if template.len() != segments.len() {
            continue;
        }
        let mut extracted = Vec::new();
        let mut matched = true;
        for (segment, value) in template.iter().zip(&segments) {
            match segment {
                PathSegment::Literal(literal) => {
                    if literal.as_str() != *value {
                        matched = false;
                        break;
                    }
                }
                PathSegment::Param(name) => extracted.push((name.clone(), (*value).to_owned())),
            }
        }
        if matched {
            return Some((route, extracted));
        }
    }
    None
}

/// 按声明类型解析单个参数字符串（§42.2 typed 参数闭集；解析失败 →
/// 400 语义）。
pub(crate) fn parse_param(raw: &str, ty: ParamType) -> Option<ParamValue> {
    match ty {
        ParamType::Text => Some(ParamValue::text(raw)),
        ParamType::Integer => raw.parse::<i64>().ok().map(ParamValue::integer),
        ParamType::Unsigned => raw.parse::<u64>().ok().map(ParamValue::unsigned),
        // boolean 闭集 {true, false}（WIT 明文）；"1"/"0" 等不属闭集。
        ParamType::Boolean => match raw {
            "true" => Some(ParamValue::boolean(true)),
            "false" => Some(ParamValue::boolean(false)),
            _ => None,
        },
        ParamType::Decimal => raw.parse::<f64>().ok().map(ParamValue::decimal),
    }
}

/// 按声明顺序构造 typed 参数（名称 + 值；WIT route-request 不变量：
/// params 与声明一致——数量、名称、类型、顺序）。
pub(crate) fn build_typed_params(
    route: &RouteDeclaration,
    extracted: &[(String, String)],
) -> Option<Vec<TypedParam>> {
    let mut params = Vec::with_capacity(route.params().len());
    for declared in route.params() {
        let raw = extracted
            .iter()
            .find(|(name, _)| name.as_str() == declared.name())?;
        let value = parse_param(&raw.1, declared.value_type())?;
        // 名称来自声明（已按 [a-z0-9-]+ 校验），构造不失败；防御性
        // 处理保持闭集（§14.1）。
        let param = TypedParam::new(declared.name(), value).ok()?;
        params.push(param);
    }
    Some(params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ok, some};
    use operune_domain::{RouteId, RouteParam};

    fn template(value: &str) -> operune_domain::PathTemplate {
        ok(operune_domain::PathTemplate::new(value), "path-template")
    }

    fn route(
        id: &str,
        method: HttpMethod,
        path: &str,
        params: Vec<RouteParam>,
    ) -> RouteDeclaration {
        ok(
            RouteDeclaration::new(
                ok(RouteId::new(id), "route-id"),
                method,
                template(path),
                params,
                None,
            ),
            "route-declaration",
        )
    }

    fn param(name: &str, ty: ParamType) -> RouteParam {
        ok(RouteParam::new(name, ty), "route-param")
    }

    #[test]
    fn normalize_adds_leading_slash() {
        assert_eq!(normalize_mount_path("api/42"), "/api/42");
        assert_eq!(normalize_mount_path("/api/42"), "/api/42");
    }

    #[test]
    fn match_literal_and_param_route() {
        let routes = vec![route(
            "get-item",
            HttpMethod::Get,
            "/api/{id}/item",
            vec![param("id", ParamType::Integer)],
        )];
        let (matched, extracted) = some(
            match_route(&routes, HttpMethod::Get, "/api/42/item"),
            "match",
        );
        assert_eq!(matched.route_id().as_str(), "get-item");
        assert_eq!(extracted, vec![("id".to_owned(), "42".to_owned())]);
    }

    #[test]
    fn match_ignores_other_methods() {
        let routes = vec![route(
            "get-item",
            HttpMethod::Get,
            "/api/{id}",
            vec![param("id", ParamType::Integer)],
        )];
        // 同路径不同方法不冲突（§42.2）：POST 请求不命中 GET route。
        assert!(match_route(&routes, HttpMethod::Post, "/api/42").is_none());
        // 方法命中但路径不匹配。
        assert!(match_route(&routes, HttpMethod::Get, "/api/42/extra").is_none());
        assert!(match_route(&routes, HttpMethod::Get, "/other").is_none());
    }

    #[test]
    fn match_distinguishes_literal_and_param_positions() {
        let routes = vec![
            route("literal", HttpMethod::Get, "/a/b", vec![]),
            route(
                "wild",
                HttpMethod::Get,
                "/{x}/b",
                vec![param("x", ParamType::Text)],
            ),
        ];
        let (first, _) = some(match_route(&routes, HttpMethod::Get, "/a/b"), "literal");
        assert_eq!(first.route_id().as_str(), "literal");
        let (second, extracted) = some(match_route(&routes, HttpMethod::Get, "/zz/b"), "wild");
        assert_eq!(second.route_id().as_str(), "wild");
        assert_eq!(extracted, vec![("x".to_owned(), "zz".to_owned())]);
    }

    #[test]
    fn parse_param_closed_set() {
        assert_eq!(
            parse_param("hello", ParamType::Text),
            Some(ParamValue::text("hello"))
        );
        assert_eq!(
            parse_param("-42", ParamType::Integer),
            Some(ParamValue::integer(-42))
        );
        assert_eq!(
            parse_param("42", ParamType::Unsigned),
            Some(ParamValue::unsigned(42))
        );
        assert_eq!(
            parse_param("true", ParamType::Boolean),
            Some(ParamValue::boolean(true))
        );
        assert_eq!(
            parse_param("false", ParamType::Boolean),
            Some(ParamValue::boolean(false))
        );
        assert_eq!(
            parse_param("1.5", ParamType::Decimal),
            Some(ParamValue::decimal(1.5))
        );
        // 类型不符 → None（400 语义）。
        assert!(parse_param("abc", ParamType::Integer).is_none());
        assert!(parse_param("-1", ParamType::Unsigned).is_none());
        assert!(parse_param("1", ParamType::Boolean).is_none());
        assert!(parse_param("TRUE", ParamType::Boolean).is_none());
        assert!(parse_param("1.5x", ParamType::Decimal).is_none());
    }

    #[test]
    fn build_typed_params_follows_declaration_order() {
        let declared = route(
            "mixed",
            HttpMethod::Get,
            "/{a}/{b}",
            vec![param("a", ParamType::Integer), param("b", ParamType::Text)],
        );
        let extracted = vec![
            ("a".to_owned(), "7".to_owned()),
            ("b".to_owned(), "x".to_owned()),
        ];
        let params = some(build_typed_params(&declared, &extracted), "typed params");
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].name(), "a");
        assert_eq!(params[0].value(), &ParamValue::integer(7));
        assert_eq!(params[1].name(), "b");
        assert_eq!(params[1].value(), &ParamValue::text("x"));
    }

    #[test]
    fn build_typed_params_rejects_type_mismatch() {
        let declared = route(
            "int-param",
            HttpMethod::Get,
            "/{id}",
            vec![param("id", ParamType::Integer)],
        );
        assert!(
            build_typed_params(&declared, &[("id".to_owned(), "abc".to_owned())]).is_none(),
            "type mismatch must be rejected (400 semantic)"
        );
    }
}
