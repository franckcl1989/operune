//! Component Web 的浏览器隔离底线（§21.3：0.1 最小隔离契约的实现面）。
//!
//! # CSP 生成（Core 强制，Component 不能放宽）
//!
//! 所有 Component-controlled HTML/JavaScript 都被视为与 `.wasm` 本体同等级
//! 的不可信代码（§21.3）。Core 为 asset / action 响应生成并强制 restrictive
//! CSP：
//!
//! - `default-src 'none'`：默认拒绝一切来源；
//! - `script-src 'self'`：无内联脚本、无外部源——Component 必须把 JS 放在
//!   自己的静态资产里，经 Core 的 digest 寻址 URL 加载；
//! - `style-src 'self' 'unsafe-inline'`：0.1 允许内联样式（最小 UI 常见）；
//! - `img-src 'self' data:` / `font-src 'self'` / `media-src 'self'`：
//!   资产只允许来自 Core 挂载命名空间；
//! - `connect-src 'self'`：网络连接只允许同源（即 Core-mediated bridge 的
//!   action 端点；§21.3：backend action 只能经过 Core-mediated bridge）；
//! - `base-uri 'none'`、`form-action 'none'`、`object-src 'none'`：
//!   禁止 form 直发、禁止 `<object>`/`<embed>`、禁止 base 篡改；
//! - `frame-ancestors 'none'`：Component UI 不得被嵌入（尤其不得进入 Root
//!   Admin DOM，§21.3）。
//!
//! 这些响应由 web-component 构造（字节 + 建议 MIME），Core 最后写安全头
//! （§21.3：Component 响应不得设置/覆盖 Set-Cookie、CSP、CORS、认证等
//! Core-owned security headers）。

/// Component 响应的 Core-owned CSP（§21.3 0.1 最小隔离底线）。
pub const COMPONENT_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Core-owned 安全头名（§21.3 测试断言用）。
pub const CORE_HEADERS: &[&str] = &[
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_covers_minimum_isolation_floor() {
        // §21.3：restrictive CSP 必须显式包含隔离要素。
        let csp = COMPONENT_CSP;
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("script-src 'self'"));
        assert!(csp.contains("connect-src 'self'"));
        assert!(csp.contains("form-action 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("base-uri 'none'"));
        assert!(csp.contains("object-src 'none'"));
        // script-src 不得含 'unsafe-inline' / 'unsafe-eval'（style 允许
        // unsafe-inline 是 0.1 最小 UI 的显式决策，见模块文档）。
        let script_directive = csp
            .split(';')
            .find(|directive| directive.trim_start().starts_with("script-src"));
        assert!(script_directive.is_some());
        assert!(!script_directive.unwrap_or("").contains("unsafe-inline"));
        assert!(!script_directive.unwrap_or("").contains("unsafe-eval"));
        // 不允许任意外部来源（无 https:// 通配）。
        assert!(!csp.contains("https:"));
        assert!(!csp.contains('*'));
    }
}
