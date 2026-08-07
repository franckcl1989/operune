//! 独立 CSRF token（§16.5）。
//!
//! - 与 session bearer token **不同用途、不同生命周期、不同随机值**：每个
//!   [`CsrfSecret`] 是一次独立的 OS CSPRNG 抽取，生命周期与所在 session 相同
//!   （session 旋转时一并更换）；
//! - 服务端 session 记录内保存 [`CsrfSecret`]，浏览器端只拿到其 URL-safe 编码
//!   （表单字段/请求头），校验时与请求携带值做 constant-time 比较（subtle 2.6.1）；
//! - SameSite=Strict 只是 defense-in-depth，state-changing 请求的 CSRF 校验
//!   由 web-admin 在 HTTP 层强制（§16.5）。

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretBox};
use subtle::ConstantTimeEq;

/// CSRF secret 的随机字节数（与 bearer token 同量级熵）。
pub const CSRF_SECRET_BYTES: usize = 32;

/// URL-safe 编码（无 padding）后的字符数。
pub const CSRF_SECRET_URLSAFE_LEN: usize = 43;

/// 服务端保存的 CSRF secret（§16.5）。
///
/// - `Debug` 掩码；不实现 `Display` / `Serialize` / `PartialEq`；
/// - 每次 [`CsrfSecret::generate`] 都是独立的 OS CSPRNG 抽取，与
///   session bearer token 不存在任何随机值复用（§16.5）。
pub struct CsrfSecret(SecretBox<[u8; CSRF_SECRET_BYTES]>);

impl CsrfSecret {
    /// 从 OS CSPRNG 生成新的 CSRF secret。
    pub fn generate() -> Result<Self, CsrfError> {
        let mut bytes = [0u8; CSRF_SECRET_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// 从 URL-safe 编码解析（存储层从持久化 session 记录恢复时使用）。
    pub fn from_url_safe(encoded: &str) -> Result<Self, CsrfError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| CsrfError::InvalidEncoding)?;
        let bytes: [u8; CSRF_SECRET_BYTES] =
            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| CsrfError::InvalidLength {
                    expected: CSRF_SECRET_BYTES,
                    got: decoded.len(),
                })?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// URL-safe 编码，用于嵌入表单/请求头（浏览器可见值）。
    pub fn to_url_safe_string(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.expose_secret())
    }

    /// constant-time 校验请求携带的 CSRF 值（subtle 2.6.1，§16.5）。
    pub fn verify(&self, presented: &str) -> Result<(), CsrfError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(presented.as_bytes())
            .map_err(|_| CsrfError::InvalidEncoding)?;
        let presented_bytes: [u8; CSRF_SECRET_BYTES] =
            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| CsrfError::InvalidLength {
                    expected: CSRF_SECRET_BYTES,
                    got: decoded.len(),
                })?;
        if bool::from(self.0.expose_secret().ct_eq(&presented_bytes)) {
            Ok(())
        } else {
            Err(CsrfError::Mismatch)
        }
    }
}

impl Clone for CsrfSecret {
    /// 深拷贝到新的受保护缓冲（session 记录复制时使用）。
    fn clone(&self) -> Self {
        Self(SecretBox::init_with(|| *self.0.expose_secret()))
    }
}

impl fmt::Debug for CsrfSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CsrfSecret([REDACTED])")
    }
}

/// CSRF 校验错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum CsrfError {
    /// OS CSPRNG 不可用。
    #[error("OS CSPRNG 不可用")]
    Rng(#[from] getrandom::Error),
    /// 请求携带值的 URL-safe 编码无效。
    #[error("CSRF token URL-safe 编码无效")]
    InvalidEncoding,
    /// 请求携带值解码后长度不符合要求。
    #[error("CSRF token 长度无效：期望 {expected} 字节，实际 {got}")]
    InvalidLength { expected: usize, got: usize },
    /// constant-time 比较不匹配。
    #[error("CSRF 校验失败")]
    Mismatch,
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

    #[test]
    fn generated_values_are_independent_random_draws() {
        let first = ok_or_fail(CsrfSecret::generate(), "generate");
        let second = ok_or_fail(CsrfSecret::generate(), "generate");
        assert_ne!(
            first.to_url_safe_string(),
            second.to_url_safe_string(),
            "两次生成必须来自独立的随机抽取"
        );
        assert_eq!(first.to_url_safe_string().len(), CSRF_SECRET_URLSAFE_LEN);
    }

    #[test]
    fn verify_roundtrip() {
        let secret = ok_or_fail(CsrfSecret::generate(), "generate");
        let encoded = secret.to_url_safe_string();
        assert!(secret.verify(&encoded).is_ok());
    }

    #[test]
    fn verify_rejects_different_value() {
        let secret = ok_or_fail(CsrfSecret::generate(), "generate");
        let other = ok_or_fail(CsrfSecret::generate(), "generate");
        assert!(matches!(
            secret.verify(&other.to_url_safe_string()),
            Err(CsrfError::Mismatch)
        ));
    }

    #[test]
    fn verify_rejects_invalid_encoding_and_length() {
        let secret = ok_or_fail(CsrfSecret::generate(), "generate");
        assert!(matches!(
            secret.verify("!!!!"),
            Err(CsrfError::InvalidEncoding)
        ));
        assert!(matches!(
            secret.verify(""),
            Err(CsrfError::InvalidLength {
                expected: 32,
                got: 0
            })
        ));
        assert!(matches!(
            secret.verify(&"A".repeat(42)),
            Err(CsrfError::InvalidLength {
                expected: 32,
                got: 31
            })
        ));
    }

    #[test]
    fn from_url_safe_roundtrip() {
        let secret = ok_or_fail(CsrfSecret::generate(), "generate");
        let encoded = secret.to_url_safe_string();
        let parsed = ok_or_fail(CsrfSecret::from_url_safe(&encoded), "from_url_safe");
        assert!(parsed.verify(&encoded).is_ok());
    }

    #[test]
    fn debug_masks_content() {
        let secret = ok_or_fail(CsrfSecret::generate(), "generate");
        let debug = format!("{secret:?}");
        assert!(
            !debug.contains(&secret.to_url_safe_string()),
            "Debug 泄漏 CSRF secret: {debug}"
        );
        assert!(debug.contains("REDACTED"), "Debug 必须掩码: {debug}");
    }
}
