//! TLS identity 与配置类型（§16.2 边界内）。
//!
//! ## 0.1.0 范围（YAGNI §12.6 权衡后的决定）
//!
//! - **TLS private key 属于 Secret 的 typed 处理**：来源（读取失败）、权限、
//!   轮换的错误语义（[`TlsIdentityError`]）；私钥内容不落 SQLite、不入日志——
//!   类型层面：无 `Display`/`Serialize`，`Debug` 掩码；私钥解析错误被**净化**为
//!   [`KeyParseIssue`]（不携带任何 PEM 原文，§16.6 禁止私钥值进入错误日志）；
//! - 证书链与私钥基于 rustls 0.23.42 生态（`rustls::pki_types`），不绑定
//!   OpenSSL（§16.2）；
//! - 安全默认集：rustls 0.23.42 的 TLS 版本与 cipher suite 安全默认即为基线
//!   （[`TlsConfig`] 无 0.1 可调项），任何调整必须经过 Security ADR（§16.2）；
//! - **不实现完整 TLS 服务器**（那是 web-admin）：`ServerConfig` 装配（含 crypto
//!   provider 选择、`CryptoProvider::install_default`）属 web-admin 装配层；
//!   本 crate 通过 [`TlsIdentity::into_rustls_parts`] 提供
//!   `ServerConfig::with_single_cert` 所需的 `CertificateDer`/`PrivateKeyDer` 输入。
//!
//! 文件权限检查（如仅属主可读）属 OS 具体实现，由 platform-* crate 提供
//! （§24.2 唯一允许承载 OS 特定 `cfg` 的地方）；本 crate 定义其错误语义
//! （[`TlsIdentityError::Permission`]）。

use std::fmt;
use std::path::{Path, PathBuf};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::secret::SecretBytes;

/// TLS 私钥（§16.2：private key 属于 Secret）。
///
/// - 内层为 [`SecretBytes`]（secrecy + zeroize，drop 时清零）；
/// - `Debug` 掩码；无 `Display` / `Serialize` / `PartialEq`；
/// - 不实现 Clone 派生：私钥的复制必须显式进行。
pub struct TlsPrivateKey(SecretBytes);

impl TlsPrivateKey {
    fn from_der(bytes: Vec<u8>) -> Self {
        Self(SecretBytes::new(bytes))
    }

    /// DER 字节（构建 rustls 输入时临时取用）。
    fn der_bytes(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for TlsPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsPrivateKey([REDACTED])")
    }
}

/// TLS 证书链（DER 编码）。证书是公开数据，不是 Secret。
#[derive(Clone)]
pub struct TlsCertChain(Vec<CertificateDer<'static>>);

impl TlsCertChain {
    /// 证书数量。
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// 证书 DER 迭代。
    pub fn iter(&self) -> impl Iterator<Item = &CertificateDer<'static>> {
        self.0.iter()
    }
}

impl fmt::Debug for TlsCertChain {
    /// 只输出数量与总字节数，不倾倒 DER 内容。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let total: usize = self.0.iter().map(|cert| cert.as_ref().len()).sum();
        write!(f, "TlsCertChain({} certs, {total} bytes)", self.0.len())
    }
}

/// TLS 服务器身份：证书链 + Secret 包装的私钥（§16.2）。
///
/// 构造入口都做结构校验（pki-types），`Debug` 掩码私钥。
pub struct TlsIdentity {
    cert_chain: TlsCertChain,
    private_key: TlsPrivateKey,
}

impl TlsIdentity {
    /// 从 PEM 文本构造（证书链 PEM 可含多张证书；私钥 PEM 支持
    /// PKCS#8 / PKCS#1 / SEC1，§16.2 rustls 生态）。
    ///
    /// 私钥解析错误被净化为 [`KeyParseIssue`]，不携带 PEM 原文（§16.6）。
    pub fn from_pem(
        cert_chain_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Self, TlsIdentityError> {
        let certs = CertificateDer::pem_slice_iter(cert_chain_pem)
            .collect::<Result<Vec<_>, _>>()
            .map_err(TlsIdentityError::CertPem)?;
        if certs.is_empty() {
            return Err(TlsIdentityError::NoCertificates);
        }
        let key_der = parse_private_key_pem(private_key_pem)?;
        Ok(Self {
            cert_chain: TlsCertChain(certs),
            private_key: TlsPrivateKey::from_der(key_der),
        })
    }

    /// 从 PEM 文件构造（来源错误语义：不可读 → [`TlsIdentityError::Read`]；
    /// 文件权限不满足由调用方结合 platform crate 检查后以
    /// [`TlsIdentityError::Permission`] 表达）。
    pub fn from_pem_files(
        cert_chain_path: &Path,
        private_key_path: &Path,
    ) -> Result<Self, TlsIdentityError> {
        let certs = {
            let iter = CertificateDer::pem_file_iter(cert_chain_path)
                .map_err(|err| map_cert_file_error(err, cert_chain_path))?;
            iter.collect::<Result<Vec<_>, _>>()
                .map_err(TlsIdentityError::CertPem)?
        };
        let key_der = {
            let mut key = PrivateKeyDer::from_pem_file(private_key_path)
                .map_err(|err| map_key_file_error(err, private_key_path))?;
            let der = key.secret_der().to_vec();
            key.zeroize();
            der
        };
        Ok(Self {
            cert_chain: TlsCertChain(certs),
            private_key: TlsPrivateKey::from_der(key_der),
        })
    }

    /// 从 DER 字节构造（证书链为 DER 序列，私钥为 PKCS#8 / PKCS#1 / SEC1 DER）。
    ///
    /// 私钥结构经 pki-types 校验，失败返回 [`TlsIdentityError::InvalidKeyDer`]。
    pub fn from_der_parts(
        cert_chain: Vec<Vec<u8>>,
        private_key_der: Vec<u8>,
    ) -> Result<Self, TlsIdentityError> {
        // 结构校验（借用形式，不产生明文副本）。
        PrivateKeyDer::try_from(private_key_der.as_slice())
            .map_err(|reason| TlsIdentityError::InvalidKeyDer { reason })?;
        let certs: Vec<_> = cert_chain.into_iter().map(CertificateDer::from).collect();
        if certs.is_empty() {
            return Err(TlsIdentityError::NoCertificates);
        }
        Ok(Self {
            cert_chain: TlsCertChain(certs),
            private_key: TlsPrivateKey::from_der(private_key_der),
        })
    }

    /// 证书链。
    pub fn cert_chain(&self) -> &TlsCertChain {
        &self.cert_chain
    }

    /// 转换为 web-admin 装配 rustls `ServerConfig` 所需的输入
    /// （`with_single_cert(certs, key)`，§16.2 边界）。
    ///
    /// 构造期已校验结构，正常路径不会失败；返回 `Result` 以保持 panic-free。
    /// 转换后私钥由 rustls 拥有（其生命周期内的内存清理是 rustls 的职责）。
    pub fn into_rustls_parts(
        self,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TlsIdentityError> {
        let certs = self.cert_chain.0;
        let key_der = self.private_key.der_bytes().to_vec();
        let key = PrivateKeyDer::try_from(key_der)
            .map_err(|reason| TlsIdentityError::InvalidKeyDer { reason })?;
        Ok((certs, key))
    }
}

impl fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsIdentity")
            .field("cert_chain", &self.cert_chain)
            .field("private_key", &self.private_key)
            .finish()
    }
}

/// TLS 服务器配置（§16.2 的 0.1 最小配置类型）。
///
/// 0.1.0 无可调项：rustls 0.23.42 安全默认集（TLS 版本与 cipher suite）即基线，
/// 任何偏离必须经过 Security ADR。`ServerConfig` 的最终装配由 web-admin 完成。
pub struct TlsConfig {
    identity: TlsIdentity,
}

impl TlsConfig {
    /// 以 TLS 身份构造服务器配置。
    pub fn new(identity: TlsIdentity) -> Self {
        Self { identity }
    }

    /// TLS 身份。
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }

    /// 取回身份（装配服务器时消费）。
    pub fn into_identity(self) -> TlsIdentity {
        self.identity
    }
}

impl fmt::Debug for TlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("identity", &self.identity)
            .finish()
    }
}

/// 私钥 PEM 解析失败原因（净化后的封闭枚举，§16.6：绝不携带 PEM 原文）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyParseIssue {
    /// 缺少 END 标记行。
    MissingSectionEnd,
    /// 段起始行语法错误。
    IllegalSectionStart,
    /// base64 解码失败。
    Base64Decode,
    /// 未找到私钥段。
    NoKeyFound,
    /// I/O 错误（读取失败）。
    Io,
    /// 其他/未来错误。
    Other,
}

impl fmt::Display for KeyParseIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            KeyParseIssue::MissingSectionEnd => "缺少 END 标记行",
            KeyParseIssue::IllegalSectionStart => "段起始行语法错误",
            KeyParseIssue::Base64Decode => "base64 解码失败",
            KeyParseIssue::NoKeyFound => "未找到私钥段",
            KeyParseIssue::Io => "I/O 错误",
            KeyParseIssue::Other => "其他解析错误",
        };
        f.write_str(message)
    }
}

impl From<pem::Error> for KeyParseIssue {
    /// 净化转换：只保留错误类别，丢弃 `pem::Error` 中可能携带的
    /// 输入行原文（§16.6 私钥值不得进入错误/日志）。
    fn from(err: pem::Error) -> Self {
        match err {
            pem::Error::MissingSectionEnd { .. } => Self::MissingSectionEnd,
            pem::Error::IllegalSectionStart { .. } => Self::IllegalSectionStart,
            pem::Error::Base64Decode(_) => Self::Base64Decode,
            pem::Error::Io(_) => Self::Io,
            pem::Error::NoItemsFound => Self::NoKeyFound,
            _ => Self::Other,
        }
    }
}

/// TLS identity 错误（封闭 typed error，§14.1；不携带私钥内容）。
#[derive(Debug, thiserror::Error)]
pub enum TlsIdentityError {
    /// 来源不可读（文件读取失败）。
    #[error("TLS 身份来源不可读：{path:?}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// 来源权限不满足 Secret 规则（如文件非仅属主可读；检查逻辑属 platform crate）。
    #[error("TLS 私钥来源权限不满足要求：{path:?}（应仅属主可读，§16.2）")]
    Permission { path: PathBuf },
    /// 证书链 PEM/DER 解析失败（证书是公开数据，可保留解析详情）。
    #[error("TLS 证书链 PEM 解析失败")]
    CertPem(#[from] pem::Error),
    /// 证书链为空（无法构成 TLS 身份）。
    #[error("TLS 证书链为空")]
    NoCertificates,
    /// 私钥解析失败（净化原因，不含 PEM 原文，§16.6）。
    #[error("TLS 私钥解析失败：{issue}")]
    KeyInvalid { issue: KeyParseIssue },
    /// 私钥 DER 结构无效。
    #[error("TLS 私钥 DER 结构无效：{reason}")]
    InvalidKeyDer { reason: &'static str },
    /// 轮换失败（新身份未生效；检测与回滚由装配层完成）。
    #[error("TLS 身份轮换失败（新身份未生效）")]
    Rotation,
}

fn parse_private_key_pem(pem: &[u8]) -> Result<Vec<u8>, TlsIdentityError> {
    let mut key =
        PrivateKeyDer::from_pem_slice(pem).map_err(|err| TlsIdentityError::KeyInvalid {
            issue: KeyParseIssue::from(err),
        })?;
    // 复制进 Secret 包装的缓冲，并立即清零解析过程的中间副本。
    let der = key.secret_der().to_vec();
    key.zeroize();
    Ok(der)
}

fn map_cert_file_error(err: pem::Error, path: &Path) -> TlsIdentityError {
    match err {
        pem::Error::Io(source) => TlsIdentityError::Read {
            path: path.to_path_buf(),
            source,
        },
        other => TlsIdentityError::CertPem(other),
    }
}

fn map_key_file_error(err: pem::Error, path: &Path) -> TlsIdentityError {
    match err {
        pem::Error::Io(source) => TlsIdentityError::Read {
            path: path.to_path_buf(),
            source,
        },
        other => TlsIdentityError::KeyInvalid {
            issue: KeyParseIssue::from(other),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_or_fail<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        assert!(
            result.is_ok(),
            "{what} 应成功，实际 Err: {:?}",
            result.as_ref().err()
        );
        match result {
            Ok(value) => value,
            Err(_) => unreachable!("上面的断言已保证 is_ok"),
        }
    }

    /// 测试用小型 DER 编码器（仅短格式长度，<128 bytes）。
    fn der_tag(tag: u8, content: &[u8]) -> Vec<u8> {
        assert!(content.len() < 128, "测试 fixture 过长");
        let mut out = Vec::with_capacity(content.len() + 2);
        out.push(tag);
        out.push(content.len() as u8);
        out.extend_from_slice(content);
        out
    }

    fn der_sequence(items: &[Vec<u8>]) -> Vec<u8> {
        let content: Vec<u8> = items.concat();
        der_tag(0x30, &content)
    }

    fn der_integer(value: u8) -> Vec<u8> {
        der_tag(0x02, &[value])
    }

    fn der_oid() -> Vec<u8> {
        // 1.2.840.10045.2.1（id-ecPublicKey）。
        der_tag(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01])
    }

    fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
        der_tag(0x04, bytes)
    }

    /// 结构正确的 PKCS#8 PrivateKeyInfo（pki-types 只做结构校验，不需真实密钥数学）。
    fn pkcs8_der() -> Vec<u8> {
        let alg_id = der_sequence(&[der_oid()]);
        let private_key = der_octet_string(&[1, 2, 3, 4, 5, 6, 7, 8]);
        der_sequence(&[der_integer(0), alg_id, private_key])
    }

    fn pem_wrap(label: &str, der: &[u8]) -> String {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        format!(
            "-----BEGIN {label}-----\n{}\n-----END {label}-----",
            STANDARD.encode(der)
        )
    }

    /// 测试 fixtures：单证书链 + PKCS#8 私钥。
    fn fixtures() -> (String, String, Vec<u8>) {
        let key_der = pkcs8_der();
        let cert_der = der_sequence(&[der_integer(1)]);
        (
            pem_wrap("CERTIFICATE", &cert_der),
            pem_wrap("PRIVATE KEY", &key_der),
            key_der,
        )
    }

    #[test]
    fn identity_from_pem_roundtrip() {
        let (cert_pem, key_pem, key_der) = fixtures();
        let identity = ok_or_fail(
            TlsIdentity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()),
            "from_pem",
        );
        assert_eq!(identity.cert_chain().len(), 1);

        let (certs, key) = ok_or_fail(identity.into_rustls_parts(), "into_rustls_parts");
        assert_eq!(certs.len(), 1);
        assert_eq!(key.secret_der(), key_der.as_slice());
    }

    #[test]
    fn identity_from_der_parts_roundtrip() {
        let key_der = pkcs8_der();
        let cert_der = der_sequence(&[der_integer(1)]);
        let identity = ok_or_fail(
            TlsIdentity::from_der_parts(vec![cert_der], key_der.clone()),
            "from_der_parts",
        );
        assert_eq!(identity.cert_chain().len(), 1);

        let (certs, key) = ok_or_fail(identity.into_rustls_parts(), "into_rustls_parts");
        assert_eq!(certs.len(), 1);
        assert_eq!(key.secret_der(), key_der.as_slice());
    }

    #[test]
    fn from_der_parts_rejects_invalid_key_structure() {
        // 首字节不是 SEQUENCE。
        assert!(matches!(
            TlsIdentity::from_der_parts(Vec::new(), vec![0x01, 0x02, 0x03]),
            Err(TlsIdentityError::InvalidKeyDer { .. })
        ));
        // 空输入。
        assert!(matches!(
            TlsIdentity::from_der_parts(Vec::new(), Vec::new()),
            Err(TlsIdentityError::InvalidKeyDer { .. })
        ));
    }

    #[test]
    fn key_pem_errors_are_sanitized() {
        let (cert_pem, _, _) = fixtures();

        // 垃圾输入：无任何 PEM 段。
        assert!(matches!(
            TlsIdentity::from_pem(cert_pem.as_bytes(), b"not a pem"),
            Err(TlsIdentityError::KeyInvalid {
                issue: KeyParseIssue::NoKeyFound
            })
        ));
        // 缺 END 标记。
        let truncated = format!("-----BEGIN PRIVATE KEY-----\n{}", "A".repeat(64));
        assert!(matches!(
            TlsIdentity::from_pem(cert_pem.as_bytes(), truncated.as_bytes()),
            Err(TlsIdentityError::KeyInvalid {
                issue: KeyParseIssue::MissingSectionEnd
            })
        ));
        // 错误信息不得包含 PEM 原文（§16.6 私钥值不得进入错误/日志）。
        let err = TlsIdentity::from_pem(cert_pem.as_bytes(), b"not a pem").err();
        let err_debug = format!("{err:?}");
        assert!(!err_debug.contains("not a pem"));
        let err_display = format!("{err:?}");
        assert!(!err_display.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn cert_pem_errors_are_typed() {
        // 缺 END 标记的证书段 → CertPem。
        let truncated = format!("-----BEGIN CERTIFICATE-----\n{}", "A".repeat(64));
        assert!(matches!(
            TlsIdentity::from_pem(truncated.as_bytes(), b"garbage"),
            Err(TlsIdentityError::CertPem(_))
        ));
    }

    #[test]
    fn empty_cert_chain_rejected() {
        let (_, key_pem, _) = fixtures();
        // 无证书段：必须拒绝（空链无法构成 TLS 身份）。
        assert!(matches!(
            TlsIdentity::from_pem(b"", key_pem.as_bytes()),
            Err(TlsIdentityError::NoCertificates)
        ));
        assert!(matches!(
            TlsIdentity::from_der_parts(Vec::new(), pkcs8_der()),
            Err(TlsIdentityError::NoCertificates)
        ));
    }

    #[test]
    fn private_key_debug_is_masked_everywhere() {
        let (cert_pem, key_pem, key_der) = fixtures();
        let identity = ok_or_fail(
            TlsIdentity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()),
            "from_pem",
        );

        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD;
        let key_b64 = STANDARD.encode(&key_der);

        let identity_debug = format!("{identity:?}");
        assert!(
            !identity_debug.contains(&key_b64),
            "TlsIdentity Debug 泄漏私钥: {identity_debug}"
        );
        assert!(
            identity_debug.contains("REDACTED"),
            "必须掩码: {identity_debug}"
        );

        let config = TlsConfig::new(identity);
        let config_debug = format!("{config:?}");
        assert!(!config_debug.contains(&key_b64));
        assert!(config_debug.contains("REDACTED"));
    }

    #[test]
    fn cert_chain_debug_does_not_dump_der() {
        let (cert_pem, key_pem, _) = fixtures();
        let identity = ok_or_fail(
            TlsIdentity::from_pem(cert_pem.as_bytes(), key_pem.as_bytes()),
            "from_pem",
        );
        let chain_debug = format!("{:?}", identity.cert_chain());
        assert!(chain_debug.starts_with("TlsCertChain(1 certs,"));
        // 不含 DER 原始字节（0x30 = SEQUENCE 标记）。
        assert!(!chain_debug.contains("0x30"));
    }

    #[test]
    fn from_pem_files_reports_read_errors() {
        let missing = Path::new("C:\\operune-test-fixtures-do-not-exist.pem");
        // 证书文件不可读 → Read；私钥文件不可读 → Read。
        assert!(matches!(
            TlsIdentity::from_pem_files(missing, missing),
            Err(TlsIdentityError::Read { .. })
        ));
    }
}
