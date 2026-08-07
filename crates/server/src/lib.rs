#![forbid(unsafe_code)]

//! Operune Core Runtime 二进制（规范 §24.2：server）。
//!
//! 唯一 binary composition root：只负责**配置、构造和 wiring**；业务规则
//! 禁止落入 `main.rs`（§24.2 硬约束）——`main.rs` 是薄壳，全部逻辑在本
//! crate 的模块中（`cli` / `bootstrap` / `config` / `server` / `compose`）。
//!
//! # 模块地图
//!
//! - [`bootstrap`]：BootstrapConfig——单个 TOML 文件解析（§18.0），
//!   fail closed；TLS 身份只允许路径引用，私钥值内嵌直接拒绝（§16.2）；
//! - [`config`]：BootstrapConfig → 各 adapter 配置的确定性映射
//!   （ExecutorConfig / TracingConfig）与 `--config <path>` 路径解析
//!   （§18.0：只选择整份 BootstrapConfig，无单项/环境覆盖）；
//! - [`cli`]：clap 命令面（§22.7 typed、可测试）——`serve` /
//!   `bootstrap-admin`（§16.3）/ `recover`（§16.3）/ `status` / `version`；
//!   密码只从 stdin 读取，绝不从命令行参数或环境变量传入（§16.3）；
//! - [`audit`]：CLI 操作的 durable audit 事件构造（§16.3 全部审计）；
//! - [`cancel`]：最小 CancellationToken（§15.3 structured cancellation；
//!   不引入 tokio-util，§23.1 避免新增依赖）；
//! - [`compose`]：application 用例装配——storage-sqlite 尚未实现
//!   application 的 ports（gap，见下方），本模块以内存 fake 完成装配；
//! - [`server`]：serve 装配——observability → storage → application →
//!   web-admin 装配点 → Axum listener（loopback 默认，§16.1）→ 优雅
//!   shutdown（Ctrl+C → storage shutdown 等待，§15.3 / §18.2）。
//!
//! # 0.1.0 装配缺口（如实声明；§26.4：无追踪 TODO 禁用，以注释+报告替代）
//!
//! 1. **web-admin 尚无公开 API**（并行 agent 实现中）：`serve` 的 router
//!    装配点 `server::build_web_router` 当前返回空 `Router`（所有路径 404）。
//!    0.1 语义：空 router 只证明 server 装配链路可用；登录/session/审计
//!    HTTP 面在 web-admin 落地后替换。
//! 2. **application ports 未由 storage 实现**：`compose` 使用内存 fake
//!    （`InMemoryRegistry` / `InMemoryGrantStore` / `InMemoryAuditLog` /
//!    `StaticConfigPort` / `UnavailableRuntime`）。storage-sqlite 的 port
//!    实现落地后替换为真实注入。
//! 3. **TLS serving 不可用**：§16.2 边界内 server 完成
//!    `TlsIdentity::from_pem_files` → rustls parts（密钥值不入配置/日志）；
//!    但 rustls `ServerConfig` 装配（crypto provider 选择，
//!    `CryptoProvider::install_default`）按 workspace §22.6 与 security
//!    crate 文档属 web-admin 装配层，而 web-admin 尚未提供。因此
//!    BootstrapConfig 配置了 `[tls]` 时 `serve` **fail closed**（§16.1：
//!    已认证管理面不得退化明文），不绑定任何 listener。
//! 4. **platform-linux / platform-macos 尚无 DataRootResolver adapter**：
//!    非 Windows 宿主默认配置路径解析 fail closed（须显式 `--config`）。
//!
//! # Secret 边界（§16.6）
//!
//! 本 crate 不接收/不记录 secret 值：BootstrapConfig 只允许 TLS 路径引用；
//! 管理员密码只存在于 `secrecy::SecretString`（drop 时清零）；审计消息
//! 不包含密码、私钥或 token 值。

pub mod audit;
pub mod bootstrap;
pub mod cancel;
pub mod cli;
pub mod compose;
pub mod config;
pub mod error;
pub mod server;

pub use error::ServerError;
