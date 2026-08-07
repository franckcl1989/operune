//! 0.4 导航服务的 HTTP 面（§42.2 navigation / pages）。
//!
//! Core 是导航的唯一执行者（页面集合是安装期事实，不随运行期变化）；
//! 本模块是挂载命名空间下页面路由的文档类型与序列化面——
//! `GET /component/{installation}/navigation` 的响应体（页面列表 +
//! 默认页）。页面导航本身（`GET …/pages/{*path}`）在
//! [`crate::router`]；权限声明（`required-permission`）不进入该文档
//! （Core 内部强制执行点，§42.2）。

use operune_domain::AppDeclaration;
use serde::Serialize;

/// 导航索引文档（§42.2：页面列表 + 默认页；Core 生成，浏览器 / SPA
/// 消费）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NavigationIndex {
    /// 页面列表（声明顺序）。
    pub pages: Vec<NavigationPage>,
    /// 默认页（`default-page`；未声明 → null）。
    pub default_page: Option<String>,
}

/// 单个可导航页面。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NavigationPage {
    /// 页面标识符（导航键）。
    pub page_id: String,
    /// 页面路径（挂载命名空间下的静态路径，无参数）。
    pub path: String,
    /// 可选展示名（导航 UI 使用；Core 不解析）。
    pub display_name: Option<String>,
}

impl NavigationIndex {
    /// 从 app declaration 构建（§42.2：页面集合是安装期声明事实）。
    pub fn from_declaration(declaration: &AppDeclaration) -> Self {
        Self {
            pages: declaration
                .pages()
                .iter()
                .map(|page| NavigationPage {
                    page_id: page.page_id().as_str().to_owned(),
                    path: page.path().as_str().to_owned(),
                    display_name: page.display_name().map(str::to_owned),
                })
                .collect(),
            default_page: declaration.default_page().map(|id| id.as_str().to_owned()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use operune_domain::{
        AppFeatures, AssetPath, HttpMethod, PageDeclaration, PageId, PagePath, ParamType,
        PathTemplate, RouteDeclaration, RouteId, RouteParam,
    };

    fn page_id(value: &str) -> PageId {
        ok(PageId::new(value), "page-id")
    }

    fn page_path(value: &str) -> PagePath {
        ok(PagePath::new(value), "page-path")
    }

    fn declaration() -> AppDeclaration {
        ok(
            AppDeclaration::new(
                ok(AssetPath::new("/index.html"), "entry"),
                AppFeatures::new(true, true, true, true, true),
                None,
                vec![],
                vec![
                    PageDeclaration::new(
                        page_id("home"),
                        page_path("/home"),
                        Some("Home".to_owned()),
                        None,
                    ),
                    PageDeclaration::new(page_id("about"), page_path("/about"), None, None),
                ],
                vec![ok(
                    RouteDeclaration::new(
                        ok(RouteId::new("r1"), "route-id"),
                        HttpMethod::Get,
                        ok(PathTemplate::new("/api/{id}"), "template"),
                        vec![ok(RouteParam::new("id", ParamType::Integer), "param")],
                        None,
                    ),
                    "route",
                )],
                Some(page_id("home")),
            ),
            "app-declaration",
        )
    }

    #[test]
    fn index_lists_pages_and_default_page() {
        let index = NavigationIndex::from_declaration(&declaration());
        assert_eq!(index.pages.len(), 2);
        assert_eq!(index.pages[0].page_id, "home");
        assert_eq!(index.pages[0].path, "/home");
        assert_eq!(index.pages[0].display_name.as_deref(), Some("Home"));
        assert_eq!(index.pages[1].display_name, None);
        assert_eq!(index.default_page.as_deref(), Some("home"));
    }

    #[test]
    fn index_serializes_to_json() {
        let index = NavigationIndex::from_declaration(&declaration());
        let json = ok(serde_json::to_string(&index), "serialize");
        // 页面路径与默认页出现在文档中；权限名不进入（Core 内部事实）。
        assert!(json.contains("\"/home\""), "{json}");
        assert!(json.contains("\"default_page\":\"home\""), "{json}");
        assert!(!json.contains("permission"), "{json}");
    }
}
