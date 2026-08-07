//! rustls `ServerConfig` 装配（§16.2 / §22.3：装配层显式选择 crypto provider）。
//!
//! # Crypto provider 选择：ring（2026-08-07 冻结基线）
//!
//! rustls 0.23.42 支持 `aws-lc-rs` 与 `ring` 两个 provider（§22.3 注释要求装配
//! 层显式选择并安装，不随默认 features 隐式引入）。选择 **ring** 的理由：
//!
//! 1. **供应链审计面**（§23 依赖治理）：`aws-lc-rs` 引入大型 C 代码库
//!    （`aws-lc-sys`，含 CMake/NASM 构建链）；`ring` 的依赖面小得多，
//!    与 DEPENDENCY_PROBE.md 逐项审���的工作量成正比。
//! 2. **Windows 开发机可复现性**：本仓库在 Windows 上开发运行，避免
//!    aws-lc-sys 的编译器/汇编器工具链要求。
//! 3. **安全默认集等价**（§16.2）：rustls 的 ring provider 覆盖安全默认
//!    cipher suite（TLS 1.3：AES-128/256-GCM、CHACHA20-POLY1305；TLS 1.2：
//!    ECDHE-RSA/ECDSA + GCM/CHACHA20/CBC）与全部默认 TLS 版本；协议版本与
//!    cipher suite 仍使用 rustls 安全默认集合，无任何 ADR 未批准的放宽。
//! 4. 两个 provider 在 rustls 中接口等价；若未来 Security ADR 要求切换
//!    aws-lc-rs（如 FIPS 或性能评估），只需更换本模块与 Cargo.toml feature。
//!
//! # 装配语义
//!
//! - [`install_ring_provider`]：进程级一次安装（幂等；已安装时保留既有
//!   provider 并记录）。
//! - [`build_server_config`]：消费 [`operune_security::tls::TlsIdentity`]
//!   （经 `into_rustls_parts`）装配 `ServerConfig`；私钥解析错误已由
//!   security crate 净化（§16.6 私钥值不进错误）。
//!
//! `TlsAcceptor` 不在此提供：workspace 冻结的 tokio-rustls 基线未声明
//! `default-features = false`，其默认 provider（aws-lc-rs）与本装配决策
//! 冲突（§23 基线不可由成员改写）；TlsAcceptor 由 server 装配层用
//! `ServerConfig` 构造。

use operune_security::tls::{TlsIdentity, TlsIdentityError};
use rustls::ServerConfig;
use rustls::crypto::ring;

/// ring provider 的 ALPN 列表（0.1.0 只做 HTTP/1.1——axum 默认 features 不含
/// http2；§16.2 未涉及 ALPN，此处保持最小）。
const ALPN_HTTP11: &[&[u8]] = &[b"http/1.1"];

/// 安装 ring crypto provider（§22.3：装配层显式选择并安装）。
///
/// 幂等：rustls 进程级只允许安装一次；若其他装配方已安装 provider，保留
/// 既有安装并记录（不覆盖、不失败——覆盖既有 provider 可能破坏其他组件的
/// 预期）。
pub fn install_ring_provider() {
    let provider = ring::default_provider();
    match rustls::crypto::CryptoProvider::install_default(provider) {
        Ok(()) => {
            tracing::info!("installed rustls ring crypto provider");
        }
        Err(_previous) => {
            // 已安装的 provider 保留（覆盖可能破坏其他组件的预期）。
            tracing::warn!("rustls crypto provider already installed, keeping it");
        }
    }
}

/// 消费 [`TlsIdentity`] 装配 rustls `ServerConfig`（§16.2 / §22.3）。
///
/// - TLS 版本与 cipher suite：rustls 安全默认集（`builder()` 默认 profile）；
/// - 客户端认证：不需要（Root Admin 靠 session bearer，§16.5）；
/// - ALPN：`http/1.1`（0.1 无 HTTP/2，与 axum 默认一致）。
///
/// 私钥内容不进错误：`TlsIdentityError` 已由 security crate 净化（§16.6）。
pub fn build_server_config(identity: TlsIdentity) -> Result<ServerConfig, TlsAssemblyError> {
    let (certs, key) = identity.into_rustls_parts()?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(TlsAssemblyError::Server)
}

/// TLS 装配错误（封闭 typed，§14.1；不携带私钥内容，§16.6）。
#[derive(Debug, thiserror::Error)]
pub enum TlsAssemblyError {
    /// TLS 身份无效（来源/解析失败——已由 security crate 净化）。
    #[error("TLS identity is invalid: {0}")]
    Identity(#[from] TlsIdentityError),
    /// 证书/私钥组合未被 rustls 接受（如算法不匹配）。
    #[error("TLS server config assembly failed: {0}")]
    Server(#[source] rustls::Error),
}

/// ALPN 常量（server 装配可查；0.1 只有 http/1.1）。
pub const fn alpn_http11() -> &'static [&'static [u8]] {
    ALPN_HTTP11
}
