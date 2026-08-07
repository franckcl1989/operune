//! Session bearer token 与单向 digest（§16.5）。
//!
//! - bearer token：OS CSPRNG（getrandom）产生 32 random bytes（≥ 32，§16.5）；
//! - 浏览器传输使用 URL-safe 编码（base64 `URL_SAFE_NO_PAD`，§22.6）；
//! - authoritative store 只保存 [`TokenDigest`]（SHA-256 单向 digest），
//!   不保存 bearer 明文（§16.5）。`TokenDigest` 是 store 的唯一键；
//!   [`SessionToken`] 本身从不进入 store，只在发放瞬间与客户端之间存在。

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use secrecy::{ExposeSecret, SecretBox};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// bearer token 的随机字节数（§16.5：至少 32）。
pub const SESSION_TOKEN_BYTES: usize = 32;

/// URL-safe 编码（无 padding）后的字符数：32 bytes → 43 chars。
pub const SESSION_TOKEN_URLSAFE_LEN: usize = 43;

/// OS CSPRNG 生成的 session bearer token（§16.5）。
///
/// - `Debug` 掩码；不实现 `Display` / `Serialize` / `PartialEq`；
/// - 刻意不实现 [`secrecy::ExposeSecret`]：对外只提供两个用途
///   （URL-safe 编码给客户端、digest 给 store），最小暴露面；
/// - token 只允许在登录/rotation 时交给调用方一次，随后只以 digest 形式存在。
pub struct SessionToken(SecretBox<[u8; SESSION_TOKEN_BYTES]>);

impl SessionToken {
    /// 从 OS CSPRNG 生成新 bearer token。
    pub fn generate() -> Result<Self, TokenError> {
        let mut bytes = [0u8; SESSION_TOKEN_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// 从 URL-safe 编码解析（web-admin 从 cookie 值解析后用 digest 查 store）。
    pub fn from_url_safe(encoded: &str) -> Result<Self, TokenError> {
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| TokenError::InvalidEncoding)?;
        let bytes: [u8; SESSION_TOKEN_BYTES] =
            decoded
                .try_into()
                .map_err(|decoded: Vec<u8>| TokenError::InvalidLength {
                    expected: SESSION_TOKEN_BYTES,
                    got: decoded.len(),
                })?;
        Ok(Self(SecretBox::new(Box::new(bytes))))
    }

    /// URL-safe 传输编码（base64 URL_SAFE_NO_PAD，无 padding，§16.5/§22.6）。
    pub fn to_url_safe_string(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0.expose_secret())
    }

    /// bearer token 的 SHA-256 单向 digest（§16.5）。
    ///
    /// 这是 authoritative store 保存的键；不是密码哈希的替代（§16.4）。
    pub fn digest(&self) -> TokenDigest {
        let digest = Sha256::digest(self.0.expose_secret());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_ref());
        TokenDigest(bytes)
    }
}

impl Clone for SessionToken {
    /// 深拷贝到新的受保护缓冲（login/rotation 处需要同时持有新旧 token）。
    fn clone(&self) -> Self {
        Self(SecretBox::init_with(|| *self.0.expose_secret()))
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken([REDACTED])")
    }
}

/// Session bearer token 的 SHA-256 单向 digest（§16.5 的 store 键）。
///
/// 不是秘密：它是 store 键，存储在权威 store 中。`PartialEq` 使用
/// constant-time 比较（subtle 2.6.1）作为纵深防御；`Hash` 与字节相等性一致
/// （按 32 字节逐字节哈希），因此可用于 `HashMap` 键。
#[derive(Clone, Copy)]
pub struct TokenDigest([u8; 32]);

impl TokenDigest {
    /// 从原始字节重建（存储层从持久化字段恢复记录时使用）。
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 原始 digest 字节。
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 十六进制表示（用于日志/审计——digest 非秘密，可安全记录）。
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in &self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl PartialEq for TokenDigest {
    /// constant-time 比较（subtle 2.6.1，§16.5 纵深防御）。
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}

impl Eq for TokenDigest {}

impl std::hash::Hash for TokenDigest {
    /// 与 [`TokenDigest` 的 `PartialEq`]（constant-time 字节比较）一致：
    /// 按 32 字节内容哈希。
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}

impl fmt::Debug for TokenDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TokenDigest({})", self.to_hex())
    }
}

/// token 处理错误（封闭 typed error，§14.1）。
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// OS CSPRNG 不可用（getrandom 失败）。
    #[error("OS CSPRNG 不可用")]
    Rng(#[from] getrandom::Error),
    /// URL-safe 编码无效。
    #[error("token URL-safe 编码无效")]
    InvalidEncoding,
    /// 解码后字节数不符合要求。
    #[error("token 长度无效：期望 {expected} 字节，实际 {got}")]
    InvalidLength { expected: usize, got: usize },
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
    fn generated_token_has_required_length_and_entropy() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        assert_eq!(token.0.expose_secret().len(), SESSION_TOKEN_BYTES);

        let encoded = token.to_url_safe_string();
        assert_eq!(encoded.len(), SESSION_TOKEN_URLSAFE_LEN);
        assert!(
            !encoded.contains('='),
            "URL-safe 编码不得含 padding 字符: {encoded}"
        );

        // 熵：两次生成不得相同（32 bytes CSPRNG，碰撞概率可忽略）。
        let other = ok_or_fail(SessionToken::generate(), "generate");
        assert_ne!(token.to_url_safe_string(), other.to_url_safe_string());
    }

    #[test]
    fn digest_is_sha256_of_token_bytes() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        let digest = token.digest();
        let expected_digest = Sha256::digest(token.0.expose_secret());
        let expected: &[u8] = expected_digest.as_ref();
        assert_eq!(digest.as_bytes().as_slice(), expected);
    }

    #[test]
    fn digest_roundtrip_via_url_safe() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        let encoded = token.to_url_safe_string();
        let parsed = ok_or_fail(SessionToken::from_url_safe(&encoded), "from_url_safe");
        assert_eq!(parsed.digest(), token.digest());
    }

    #[test]
    fn from_url_safe_rejects_invalid_input() {
        // 空串：解码成功但长度不足。
        assert!(matches!(
            SessionToken::from_url_safe(""),
            Err(TokenError::InvalidLength {
                expected: 32,
                got: 0
            })
        ));
        // 非法字符。
        assert!(matches!(
            SessionToken::from_url_safe("!!!!"),
            Err(TokenError::InvalidEncoding)
        ));
        // 合法编码但长度不足（42 字符 → 31 字节）。
        assert!(matches!(
            SessionToken::from_url_safe(&"A".repeat(42)),
            Err(TokenError::InvalidLength {
                expected: 32,
                got: 31
            })
        ));
        // 合法编码但超长（44 字符 → 33 字节）。
        assert!(matches!(
            SessionToken::from_url_safe(&"A".repeat(44)),
            Err(TokenError::InvalidLength {
                expected: 32,
                got: 33
            })
        ));
    }

    #[test]
    fn token_debug_does_not_leak_value() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        let debug = format!("{token:?}");
        let encoded = token.to_url_safe_string();
        assert!(
            !debug.contains(&encoded),
            "Debug 泄漏 bearer token: {debug}"
        );
        assert!(debug.contains("REDACTED"), "Debug 必须掩码: {debug}");
    }

    #[test]
    fn digest_debug_is_hex_and_does_not_reveal_token() {
        let token = ok_or_fail(SessionToken::generate(), "generate");
        let debug = format!("{:?}", token.digest());
        assert!(debug.starts_with("TokenDigest("));
        assert_eq!(
            debug.len(),
            "TokenDigest(".len() + 64 + 1,
            "32 bytes 的十六进制"
        );
        assert!(!debug.contains(&token.to_url_safe_string()));
    }
}
