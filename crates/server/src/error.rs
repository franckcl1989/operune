//! server 封闭 typed error（§14.1：thiserror 定义封闭、可匹配的 typed
//! error；禁止 anyhow / eyre / `Box<dyn Error>` / String 作为公开错误契约）。
//!
//! 错误信息只含可诊断信息，不含任何 secret（§16.6：密码、私钥值、token
//! 绝不进入错误与日志）。

use std::io;
use std::net::IpAddr;

use operune_application::ApplicationError;
use operune_domain::DomainError;
use operune_observability::TracingError;
use operune_platform::PlatformError;
use operune_security::password::PasswordError;
use operune_security::tls::TlsIdentityError;
use operune_storage_sqlite::StorageError;

use crate::bootstrap::BootstrapError;

/// server 装配/CLI 的封闭错误空间。
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// BootstrapConfig 路径解析失败（§18.0：fail closed）。
    #[error("bootstrap config path resolution failed: {0}")]
    ConfigPath(#[from] PlatformError),

    /// BootstrapConfig 加载/解析/校验失败（§18.0：fail closed）。
    #[error("bootstrap config error: {0}")]
    Bootstrap(#[from] BootstrapError),

    /// 存储层失败（§18.2 executor）。
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// tracing 全局 subscriber 初始化失败（§22.7）。
    #[error("observability initialization failed: {0}")]
    Tracing(#[from] TracingError),

    /// TLS 身份加载失败（§16.2：错误不含私钥值）。
    #[error("TLS identity error: {0}")]
    TlsIdentity(#[from] TlsIdentityError),

    /// 领域层错误透传（第一方契约，§14.1 允许）。
    #[error("domain error: {0}")]
    Domain(#[from] DomainError),

    /// application 用例层错误透传（第一方契约，§14.1 允许）。
    #[error("application error: {0}")]
    Application(#[from] ApplicationError),

    /// 密码哈希失败（§16.4；错误不含密码内容）。
    #[error("password hashing error: {0}")]
    Hash(#[from] PasswordError),

    /// CLI 输入/前置条件错误（§16.3 语义；不含 secret）。
    #[error("cli error: {0}")]
    Cli(String),

    /// 从 stdin 读取密码失败（§16.3）。
    #[error("failed to read password from stdin: {source}")]
    PasswordRead {
        /// 底层 I/O 错误。
        #[source]
        source: io::Error,
    },

    /// 输出写入失败（stdout/stderr）。
    #[error("output write failed: {source}")]
    Output {
        /// 底层 I/O 错误。
        #[source]
        source: io::Error,
    },

    /// listener 绑定失败。
    #[error("failed to bind admin listener on {address}:{port}: {source}")]
    Bind {
        /// 监听地址。
        address: IpAddr,
        /// 监听端口。
        port: u16,
        /// 底层 I/O 错误。
        #[source]
        source: io::Error,
    },

    /// §16.1：非 loopback 监听地址必须配合生产 TLS；0.1 无 TLS serving
    /// （web-admin 缺口）⇒ fail closed，拒绝明文绑定。
    #[error(
        "refusing to bind admin listener on non-loopback address {address} without TLS (§16.1)"
    )]
    NonLoopbackWithoutTls {
        /// 被拒绝的监听地址。
        address: IpAddr,
    },

    /// §16.1：BootstrapConfig 配置了 TLS 身份，但 TLS serving 装配
    /// （web-admin）在 0.1 尚未提供；已认证管理面不得退化明文 ⇒ fail
    /// closed，不绑定 listener。见 crate 模块文档"装配缺口"。
    #[error(
        "TLS identity configured but TLS serving is not yet available in this build (web-admin assembly gap); refusing to serve plaintext (§16.1)"
    )]
    TlsServingUnavailable,

    /// Axum serve 失败。
    #[error("http server failed: {0}")]
    Serve(#[from] axum::Error),
}
