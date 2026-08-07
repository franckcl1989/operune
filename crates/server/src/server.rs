//! serve 装配（§24.2：server 是唯一 binary composition root；本模块只做
//! 配置、构造与 wiring，业务规则禁止进入）。
//!
//! 装配顺序（fail fast）：
//!
//! 1. `--config`/平台默认路径解析（§18.0：只选择整份 BootstrapConfig）；
//! 2. BootstrapConfig 解析（fail closed，§18.0）；
//! 3. observability 初始化（§22.7；audit target 强制可见，§18.7）；
//! 4. TLS 身份加载（§16.2：路径径引用 → `TlsIdentity` → rustls parts）；
//!    配置了 `[tls]` 而 TLS serving 不可用 ⇒ fail closed（§16.1）；
//! 5. loopback listener 绑定（§16.1；非 loopback 无 TLS ⇒ 拒绝）；
//! 6. StorageExecutor 打开（§18.2：open+migration+recovery，fail closed）；
//! 7. application 用例装配（内存 fake ports，见 [`crate::compose`]）；
//! 8. web-admin router 装配点（gap，见 [`build_web_router`]）；
//! 9. Axum serve + 优雅 shutdown（§15.3：Ctrl+C → CancellationToken →
//!    storage shutdown 等待，§18.2 不 detached）。

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use axum::Router;
use operune_platform::DataRootResolver;
use operune_security::tls::TlsIdentity;
use tokio::net::TcpListener;

use crate::bootstrap::BootstrapConfig;
use crate::cancel::CancellationToken;
use crate::compose::{AppServices, compose_application};
use crate::config::executor_config;
use crate::error::ServerError;

/// 平台默认 data root 解析器（§9.4：平台差异只在 platform-* adapter；
/// server 是 composition root，负责按宿主平台选择 adapter 完成 wiring，
/// §24.2）。
#[cfg(target_os = "windows")]
pub fn platform_resolver() -> Box<dyn DataRootResolver> {
    Box::new(operune_platform_windows::WindowsDataRootResolver::real())
}

/// 非 Windows 宿主：platform-linux / platform-macos 的 DataRootResolver
/// adapter 尚未落地（gap，见 crate 模块文档）——默认路径解析 fail closed，
/// 不猜测任何路径；显式 `--config` 仍可用。
#[cfg(not(target_os = "windows"))]
use operune_platform::{DataRoot, PlatformError};

#[cfg(not(target_os = "windows"))]
pub fn platform_resolver() -> Box<dyn DataRootResolver> {
    struct UnsupportedPlatformResolver;

    impl DataRootResolver for UnsupportedPlatformResolver {
        fn default_data_root(&self) -> Result<DataRoot, PlatformError> {
            Err(PlatformError::InvalidDataRoot {
                detail: "no platform adapter for default data root resolution on this OS (linux/macos adapters pending); pass --config explicitly"
                    .into(),
            })
        }
    }

    Box::new(UnsupportedPlatformResolver)
}

/// `serve` 子命令入口（§18.0 路径解析 → serve）。
pub async fn serve_cli(config_arg: Option<PathBuf>) -> Result<(), ServerError> {
    let resolver = platform_resolver();
    let path = crate::config::resolve_config_path(config_arg, resolver.as_ref())?;
    let bootstrap = crate::bootstrap::load_from_path(&path)?;
    serve(&bootstrap).await
}

/// 完整 serve 流程（thin 装配，见模块文档装配顺序）。
pub async fn serve(bootstrap: &BootstrapConfig) -> Result<(), ServerError> {
    // §22.7：全局 subscriber 初始化（进程内一次；失败 fail closed）。
    operune_observability::init(crate::config::tracing_config(bootstrap))?;

    // §15.3：Ctrl+C → 结构化取消。
    let cancel = CancellationToken::new();
    tokio::spawn(wait_for_ctrl_c(cancel.clone()));

    let _bound = serve_with_cancellation(bootstrap, &cancel).await?;
    Ok(())
}

/// serve 的测试面：取消令牌外部注入（§15.3），不做全局 observability
/// 初始化。成功返回实际绑定的 listener 地址（port 0 = 临时端口时有用）。
pub async fn serve_with_cancellation(
    bootstrap: &BootstrapConfig,
    cancel: &CancellationToken,
) -> Result<SocketAddr, ServerError> {
    // §16.2：TLS 身份加载（配置里只有路径引用；错误不含私钥值）。
    let tls_identity = load_tls_identity(bootstrap)?;
    if tls_identity.is_some() {
        // §16.1：已认证管理面 MUST NOT 退化明文；TLS serving 装配属
        // web-admin（0.1 gap）⇒ fail closed，不绑定任何 listener。
        return Err(ServerError::TlsServingUnavailable);
    }

    // §16.1：loopback 默认；非 loopback 必须显式 TLS（0.1 无 TLS ⇒ 拒绝）。
    let listener = bind_listener(bootstrap.admin.address, bootstrap.admin.port).await?;
    let bound = listener.local_addr().map_err(|source| ServerError::Bind {
        address: bootstrap.admin.address,
        port: bootstrap.admin.port,
        source,
    })?;

    // §18.2：打开存储（open + migration + recovery，fail closed）。
    let executor =
        operune_storage_sqlite::StorageExecutor::open(executor_config(bootstrap)?).await?;

    // application 用例装配（内存 fake ports，gap 见 crate::compose 文档）。
    let services = compose_application()?;

    // web-admin router 装配点（gap：web-admin 无公开 API，见模块文档）。
    let router = build_web_router(&services);

    tracing::info!(
        address = %bound,
        data_root = %bootstrap.data_root.display(),
        "operune server starting (insecure plaintext loopback development mode, §16.1)"
    );

    let result = serve_listener(listener, router, executor, cancel).await;
    match result.as_ref() {
        Ok(()) => tracing::info!("operune server stopped cleanly"),
        Err(error) => tracing::error!(%error, "operune server terminated with error"),
    }
    result?;
    Ok(bound)
}

/// 等待 Ctrl+C 并取消（§15.3 信号 → 结构化取消）。
async fn wait_for_ctrl_c(cancel: CancellationToken) {
    let _ = tokio::signal::ctrl_c().await;
    cancel.cancel();
}

/// 加载 TLS 身份（§16.2：路径引用 → `TlsIdentity`；`None` = 未配置）。
///
/// 0.1 只做到 `TlsIdentity`（`from_pem_files` 已做证书链 PEM 与私钥 DER
/// 的完整结构校验；`Debug` 掩码私钥，§16.6）；rustls `ServerConfig` 装配
/// （crypto provider 选择、`CryptoProvider::install_default`）按 workspace
/// §22.6 与 security crate 文档属 web-admin 装配层——web-admin 落地后
/// 在本装配点消费本函数结果。
pub fn load_tls_identity(bootstrap: &BootstrapConfig) -> Result<Option<TlsIdentity>, ServerError> {
    let Some(tls_ref) = &bootstrap.tls else {
        return Ok(None);
    };
    let identity = TlsIdentity::from_pem_files(&tls_ref.cert_chain, &tls_ref.private_key)?;
    Ok(Some(identity))
}

/// 绑定 Root Admin listener（§16.1：loopback 默认；非 loopback 拒绝——
/// 0.1 无 TLS serving）。
async fn bind_listener(address: IpAddr, port: u16) -> Result<TcpListener, ServerError> {
    if !address.is_loopback() {
        return Err(ServerError::NonLoopbackWithoutTls { address });
    }
    let addr = SocketAddr::new(address, port);
    TcpListener::bind(addr)
        .await
        .map_err(|source| ServerError::Bind {
            address,
            port,
            source,
        })
}

/// web-admin 装配点（§26.4：无追踪 TODO 禁用，以注释+报告替代——见 crate
/// 模块文档"装配缺口"）。
///
/// 0.1.0：operune-web-admin 尚无公开 API（并行 agent 实现中），返回空
/// `Router`（所有路径 404），仅证明 server 装配链路可用。web-admin 的
/// Axum 装配 API 落地后，在此替换为 `web_admin::build_router(...)`。
pub fn build_web_router(_services: &AppServices) -> Router {
    Router::new()
}

/// 在已绑定 listener 上 serve（优雅 shutdown：§15.3 取消 → axum graceful →
/// storage shutdown 等待，§18.2 不 detached）。
pub async fn serve_listener(
    listener: TcpListener,
    router: Router,
    executor: operune_storage_sqlite::StorageExecutor,
    cancel: &CancellationToken,
) -> Result<(), ServerError> {
    let graceful = {
        let cancel = cancel.clone();
        async move { cancel.cancelled().await }
    };
    // axum::serve 返回 io::Error；用 axum::Error::new 装箱后经既有
    // `Serve(#[from] axum::Error)` 变体透传，错误面不变。
    axum::serve(listener, router)
        .with_graceful_shutdown(graceful)
        .await
        .map_err(axum::Error::new)?;
    // §18.2：shutdown 等待 worker 排空已接纳请求后退出，不 detached。
    executor.shutdown().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{
        AdminListener, LogFormat, LogLevel, LoggingConfig, StorageConfig, TlsIdentityRef,
    };
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    fn loopback() -> IpAddr {
        ok(IpAddr::from_str("127.0.0.1"), "loopback address")
    }

    fn fixture_path(name: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("test-fixtures")
            .join(name)
    }

    fn bootstrap_in(dir: &std::path::Path, tls: Option<TlsIdentityRef>) -> BootstrapConfig {
        BootstrapConfig {
            data_root: dir.to_path_buf(),
            admin: AdminListener {
                address: loopback(),
                port: 0,
            },
            tls,
            logging: LoggingConfig {
                level: LogLevel::Info,
                format: LogFormat::Compact,
            },
            storage: StorageConfig {
                budget: operune_storage_sqlite::artifact::DiskBudget::default(),
            },
        }
    }

    fn tls_ref() -> TlsIdentityRef {
        TlsIdentityRef {
            cert_chain: fixture_path("localhost-cert.pem"),
            private_key: fixture_path("localhost-key.pem"),
        }
    }

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(_) => unreachable!("tempdir must succeed"),
        }
    }

    #[tokio::test]
    async fn bind_loopback_with_ephemeral_port() {
        let listener = ok(bind_listener(loopback(), 0).await, "bind loopback");
        let addr = ok(listener.local_addr(), "local addr");
        assert_eq!(addr.ip(), loopback());
    }

    #[tokio::test]
    async fn bind_non_loopback_without_tls_fails_closed() {
        // §16.1：非 loopback 必须显式 TLS；0.1 无 TLS serving ⇒ 拒绝。
        let unspecified = ok(IpAddr::from_str("0.0.0.0"), "unspecified address");
        assert!(matches!(
            bind_listener(unspecified, 0).await,
            Err(ServerError::NonLoopbackWithoutTls { .. })
        ));
    }

    #[test]
    fn load_tls_identity_from_fixture_files() {
        let config = bootstrap_in(&std::env::temp_dir(), Some(tls_ref()));
        let identity = ok(load_tls_identity(&config), "load identity");
        assert!(identity.is_some());
        assert_eq!(identity.map(|i| i.cert_chain().len()), Some(1));
    }

    #[test]
    fn load_tls_identity_absent_when_not_configured() {
        let config = bootstrap_in(&std::env::temp_dir(), None);
        assert!(ok(load_tls_identity(&config), "no tls").is_none());
    }

    #[test]
    fn load_tls_identity_fails_closed_on_unreadable_key() {
        // §16.2 来源错误语义：私钥文件不可读 → Read 错误（fail closed）。
        let config = bootstrap_in(&std::env::temp_dir(), None);
        let broken = BootstrapConfig {
            tls: Some(TlsIdentityRef {
                cert_chain: fixture_path("localhost-cert.pem"),
                private_key: fixture_path("does-not-exist-key.pem"),
            }),
            ..config
        };
        assert!(matches!(
            load_tls_identity(&broken),
            Err(ServerError::TlsIdentity(
                operune_security::tls::TlsIdentityError::Read { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn serve_with_tls_configured_fails_closed_before_binding() {
        // §16.1：TLS 身份已配置而 TLS serving 未就绪 ⇒ 不绑定、不退化明文。
        let dir = tempdir();
        let config = bootstrap_in(dir.path(), Some(tls_ref()));
        let cancel = CancellationToken::new();
        assert!(matches!(
            serve_with_cancellation(&config, &cancel).await,
            Err(ServerError::TlsServingUnavailable)
        ));
    }

    #[tokio::test]
    async fn serve_with_cancellation_runs_and_returns_bound_address() {
        // 完整 serve 装配链路（bind → storage open → compose → router →
        // axum serve → graceful shutdown → storage shutdown）。
        let dir = tempdir();
        let config = bootstrap_in(dir.path(), None);
        let cancel = CancellationToken::new();
        let serve_task = tokio::spawn({
            let config = config.clone();
            let cancel = cancel.clone();
            async move { serve_with_cancellation(&config, &cancel).await }
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(10), serve_task)
            .await
            .ok();
        let joined = match joined {
            Some(joined) => joined,
            None => unreachable!("serve must finish after cancellation"),
        };
        let bound = ok(ok(joined, "join serve task"), "serve result");
        assert!(bound.ip().is_loopback());
        // §18.2：storage 已干净关闭（worker 退出、DB 锁释放）——同目录
        // 重新打开必须成功。
        let reopened = ok(
            operune_storage_sqlite::StorageExecutor::open(ok(
                executor_config(&config),
                "executor config",
            ))
            .await,
            "reopen storage after clean shutdown",
        );
        ok(reopened.shutdown().await, "close reopened storage");
    }

    #[tokio::test]
    async fn serve_http_end_to_end_on_known_listener() {
        // 手工组装 serve 装配链（与 serve_with_cancellation 相同的组件），
        // 在已知地址上做真实 HTTP 探针：空 router → 404；取消 → 干净退出。
        let dir = tempdir();
        let config = bootstrap_in(dir.path(), None);
        let listener = ok(bind_listener(loopback(), 0).await, "bind");
        let bound = ok(listener.local_addr(), "local addr");
        let executor = ok(
            operune_storage_sqlite::StorageExecutor::open(ok(
                executor_config(&config),
                "executor config",
            ))
            .await,
            "open storage",
        );
        let services = ok(compose_application(), "compose");
        let router = build_web_router(&services);
        let cancel = CancellationToken::new();
        let serve_task = tokio::spawn({
            let cancel = cancel.clone();
            async move { serve_listener(listener, router, executor, &cancel).await }
        });

        // 轮询连接直到就绪（未监听时连接立即失败，确定性重试）。
        let mut stream = None;
        for _ in 0..100 {
            match TcpStream::connect(bound).await {
                Ok(connected) => {
                    stream = Some(connected);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
        let mut stream = match stream {
            Some(stream) => stream,
            None => unreachable!("serve listener must accept connections"),
        };
        ok(
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await,
            "write request",
        );
        let mut response = Vec::new();
        ok(stream.read_to_end(&mut response).await, "read response");
        let text = String::from_utf8_lossy(&response);
        assert!(
            text.contains("404"),
            "empty router must answer 404, got: {text}"
        );

        // §15.3：结构化取消 → 优雅 shutdown。
        cancel.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(10), serve_task)
            .await
            .ok();
        let joined = match joined {
            Some(joined) => joined,
            None => unreachable!("serve must finish after cancellation"),
        };
        ok(ok(joined, "join serve task"), "serve result");
    }
}
