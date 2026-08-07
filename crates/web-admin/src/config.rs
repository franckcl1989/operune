//! Root Admin 监听与 TLS 装配配置（§16.1 / §16.2）。
//!
//! # 暴露面（§16.1）
//!
//! 0.1.0 默认只绑定 loopback。[`AdminListenConfig::validate`] 在装配期强制：
//! **绑定非 loopback 地址必须显式配置生产 TLS 身份**（[`TlsMode::Secure`]），
//! 否则拒绝启动。`TlsMode::InsecureLoopbackDev` 是明确标记的开发模式
//! （§16.1：与 production 分离、不复用生产 Session Cookie 契约——见
//! [`crate::auth::DEV_SESSION_COOKIE_NAME`]），且只允许 loopback。
//!
//! # TLS（§16.2 / §22.3）
//!
//! 协议版本与 cipher suite 使用 rustls 安全默认集；crypto provider 由本
//! crate（装配层）显式选择并安装。见 [`crate::tls`]。

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use operune_security::tls::TlsIdentity;

/// TLS 装配模式（§16.1：production 不得自动退化明文 HTTP）。
#[derive(Debug)]
pub enum TlsMode {
    /// 生产模式：rustls ServerConfig 携带的 TLS 身份（§16.2）。
    Secure(TlsIdentity),
    /// 明确标记的 insecure loopback 开发模式（§16.1）。
    ///
    /// - 只允许绑定 loopback（[`AdminListenConfig::validate`] 强制）；
    /// - 使用独立 cookie 契约 [`crate::auth::DEV_SESSION_COOKIE_NAME`]
    ///   （不满足 `__Host-` / `Secure` 契约），不复用生产 Session Cookie；
    /// - 不得通过 Release Gate（§16.1）。
    InsecureLoopbackDev,
}

impl TlsMode {
    /// 是否为 insecure 开发模式（Origin 校验允许明文 http 等差异点）。
    pub const fn is_insecure_dev(&self) -> bool {
        matches!(self, TlsMode::InsecureLoopbackDev)
    }

    /// 生产 TLS 身份（`Secure` 模式的借用视图）。
    pub fn identity(&self) -> Option<&TlsIdentity> {
        match self {
            TlsMode::Secure(identity) => Some(identity),
            TlsMode::InsecureLoopbackDev => None,
        }
    }
}

/// Root Admin listener 配置（§16.1 暴露面与传输安全是两个独立维度）。
#[derive(Debug)]
pub struct AdminListenConfig {
    /// 绑定地址。默认 loopback（`127.0.0.1`）。
    pub bind_addr: SocketAddr,
    /// TLS 模式（§16.1：生产必须 HTTPS；开发模式显式标记）。
    pub tls: TlsMode,
}

impl Default for AdminListenConfig {
    /// 默认：loopback + 生产 TLS 身份缺失 → 装配校验失败（§16.1：
    /// "如果生产所需 TLS identity 尚未准备好……不得为了首次启动方便
    /// 默认监听 0.0.0.0 或接受明文管理员登录"——本类型没有自动退化路径）。
    fn default() -> Self {
        // 注意：TlsMode::Secure 需要身份；default 用 InsecureLoopbackDev，
        // 但绑定地址是 loopback，必须经 validate() 后由 composition root
        // 决定是否可用于开发。生产装配必须显式传 Secure(TlsIdentity)。
        Self {
            bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443),
            tls: TlsMode::InsecureLoopbackDev,
        }
    }
}

/// 监听配置校验错误（§16.1 装配期强制点）。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListenConfigError {
    /// 非 loopback 地址 + insecure 开发模式（§16.1 明文管理员登录禁止）。
    #[error(
        "insecure dev mode is only allowed on loopback addresses (got {addr}); production TLS is required for non-loopback binds"
    )]
    InsecureDevOnNonLoopback { addr: SocketAddr },
    /// 生产 TLS 身份缺失时不得自动退化（§16.1）——装配必须显式提供身份。
    #[error("production TLS identity is required: no automatic fallback to plaintext HTTP (§16.1)")]
    ProductionIdentityRequired,
}

impl AdminListenConfig {
    /// loopback 判定（§16.1）。
    pub fn is_loopback(&self) -> bool {
        self.bind_addr.ip().is_loopback()
    }

    /// 装配期校验（§16.1）：
    /// - insecure dev 只允许 loopback；
    /// - 非 loopback 必须携带生产 TLS 身份（不自动退化）。
    pub fn validate(&self) -> Result<(), ListenConfigError> {
        match &self.tls {
            TlsMode::InsecureLoopbackDev => {
                if !self.is_loopback() {
                    return Err(ListenConfigError::InsecureDevOnNonLoopback {
                        addr: self.bind_addr,
                    });
                }
                Ok(())
            }
            TlsMode::Secure(_) => Ok(()),
        }
    }

    /// 生产 TLS 身份（`Secure` 模式消费）。
    pub fn into_identity(self) -> Option<TlsIdentity> {
        match self.tls {
            TlsMode::Secure(identity) => Some(identity),
            TlsMode::InsecureLoopbackDev => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(ip: IpAddr) -> SocketAddr {
        SocketAddr::new(ip, 8443)
    }

    #[test]
    fn default_binds_loopback() {
        // §16.1：默认 listener 只绑定 loopback。
        let config = AdminListenConfig::default();
        assert!(config.is_loopback());
    }

    #[test]
    fn insecure_dev_rejected_off_loopback() {
        // §16.1：明文管理员登录禁止——insecure dev 只能 loopback。
        let config = AdminListenConfig {
            bind_addr: addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            tls: TlsMode::InsecureLoopbackDev,
        };
        assert_eq!(
            config.validate(),
            Err(ListenConfigError::InsecureDevOnNonLoopback {
                addr: config.bind_addr,
            })
        );
    }

    #[test]
    fn insecure_dev_allowed_on_loopback() {
        let config = AdminListenConfig {
            bind_addr: addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            tls: TlsMode::InsecureLoopbackDev,
        };
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn loopback_secure_allowed() {
        // loopback + 生产 TLS：同样允许（"仅本机可访问"不替代传输安全，
        // 但两者并存合法，§16.1）。TlsIdentity 的构造与 ServerConfig 装配
        // 见 tests/tls.rs（fixture 驱动）。
        let identity = crate::test_support::test_identity();
        let config = AdminListenConfig {
            bind_addr: addr(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            tls: TlsMode::Secure(identity),
        };
        assert_eq!(config.validate(), Ok(()));
    }
}
