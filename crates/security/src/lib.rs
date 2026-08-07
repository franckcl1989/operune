#![forbid(unsafe_code)]

//! Operune Security 实现（规范 §24.2：security）。
//!
//! Root Admin 安全基线（规范 §16）的实现，模块划分：
//!
//! - [`password`]：Argon2id 密码哈希（§16.4，OWASP 最低参数基线）；
//! - [`token`]：session bearer token（OS CSPRNG ≥ 32 bytes）与 SHA-256 单向 digest（§16.5）；
//! - [`session`]：服务端 session 生命周期——rotation / idle + absolute expiry / 失效（§16.5）；
//! - [`csrf`]：独立 CSRF token（与 session token 不同用途、生命周期、随机值），
//!   constant-time 校验（§16.5，subtle 2.6.1）；
//! - [`session_cookie`]：production session cookie 构造（§16.5，
//!   `__Host-operune-session`，cookie 0.18.1，不自写解析器）；
//! - [`secret`]：secrecy + zeroize 的内存秘密包装（§16.6，掩码 `Debug`）；
//! - [`tls`]：TLS identity / 配置类型与错误语义（§16.2 边界内，rustls 0.23.42 生态）。
//!
//! ## 边界（§24.2 / §5.2 / §16.6）
//!
//! - 不包含具体运维产品权限模型（grant policy 的实现不含业务权限，§24.2）；
//! - secret 类型只解决进程内暴露面，**不构成 at-rest secret storage**：
//!   0.3.0 引入 Component Secret 服务时使用独立 `SecretStore` port（§16.6）；
//! - 本 crate 不含 HTTP 层（Root Admin Axum 适配是 operune-web-admin 的职责），
//!   不含 SQLite（storage-sqlite 实现本 crate 定义的 store port）。
//!
//! 全部第一方代码为 Safe Rust，且不在生产路径使用 `unwrap`/`expect`/`panic!`
//! （workspace lints 机械强制，§11 / §14.2）。

pub mod csrf;
pub mod password;
pub mod secret;
pub mod session;
pub mod session_cookie;
pub mod tls;
pub mod token;
