#![forbid(unsafe_code)]

//! Operune Component Web bridge（规范 §24.2：web-component）。
//!
//! Component 提供的 Web assets / actions 到 Core Web 的桥接
//! （§21.3 最小 Component Web Bridge 的 Core 侧 HTTP 实现）。
//!
//! # 闭环（§21.3）
//!
//! - [`mount::ComponentMount`]：Core 分配的挂载命名空间（`InstallationId`
//!   派生，天然不可冲突）；
//! - 静态资产：`GET /component/{installation}/assets/{digest}/{*path}`，
//!   缓存事实 = ContentDigest + asset path（§6.2 / §21.3，application 的
//!   [`AssetCache`]）；digest 入 URL 保证 §21.5 原子版本切换；
//! - bounded action：`POST /component/{installation}/actions/{action}`，
//!   Core-mediated（绑定 InstallationId + ComponentVersion）；服务端重做
//!   grant/body/rate 检查（application 的 `ActionPolicyPort`，经
//!   `WebBridge::invoke_action`），deadline/concurrency 在运行时强制；
//!   无流 / 长连接（§21.3 只有 bounded request/response）；
//! - 浏览器隔离底线：Core 生成并强制 restrictive CSP（[`csp::COMPONENT_CSP`]），
//!   Core 最后写安全头，Component 响应不能设置/覆盖 Set-Cookie / CSP /
//!   CORS / 认证头（§21.3）；
//! - 凭据边界：本 bridge 不读取 Root Admin session cookie / CSRF 值
//!   （§21.3）；授权 = 安装实例的 grant（deny-by-default，§17.2）。
//!
//! # 测试（§32 对应项）
//!
//! HTTP 黑盒测试（`tower::ServiceExt::oneshot`）：path traversal 拒绝、
//! digest 失配 404、未授权 action 403、body 超限 413、响应超限 502、
//! 无 Set-Cookie、Core-owned headers 存在。
//!
//! # 与 application 的 API 缺口（0.1.0，需主 agent 排期）
//!
//! 1. `ActiveRuntimeRegistry::swap` 为 `pub(crate)`，web-component 无法在
//!    测试中填充 Active 快照——HTTP 测试用 [`test_support::FakeWebPort`]
//!    注入（`ComponentWebPort` 是 web-component 自己的用例 port，
//!    production 由 [`bridge::AppWebBridge`] 适配 application 的
//!    `WebBridge`）。
//! 2. `WebBridge` 是具体结构（非 trait）：`AppWebBridge` 作为适配层定义
//!    的用例 port 提供了替换缝。
//!
//! # 模块
//!
//! - [`mount`]：mount namespace（§21.3）；
//! - [`csp`]：隔离底线 CSP 与 Core-owned 头（§21.3）；
//! - [`bridge`]：用例 port + application `WebBridge` 适配；
//! - [`router`]：Axum 路由与强制点；
//! - [`error`]：封闭 typed 错误 → 确定 HTTP 响应。

pub mod bridge;
pub mod csp;
pub mod error;
pub mod mount;
pub mod router;

#[cfg(test)]
mod http_tests;
#[cfg(test)]
mod test_support;

pub use bridge::{AppWebBridge, ComponentWebPort};
pub use error::BridgeError;
pub use mount::ComponentMount;
pub use router::{BridgeLimits, component_router};
