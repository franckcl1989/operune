//! Web asset caching / integrity（§42.2；Core 执行）。
//!
//! 0.1 缓存事实是 `ContentDigest + asset path`（组件级 SHA-256，§6.2）——
//! URL 中的 digest 是**组件**摘要，不是资源字节摘要。§42.2 的 Web asset
//! caching / integrity 要求浏览器可校验的完整性事实必须按**资源字节**
//! 计算（SRI 形态），因此资产 / 页面响应额外携带 RFC 9530
//! `Content-Digest` 头（`sha-256=:<base64>:`）——IETF 标准化的响应完整性
//! 声明形态，是本版本"最小可行实现"的选择（替代方案 SRI `integrity`
//! 属性属于页面文档作者面，Core 不生成页面内容；`Content-Digest` 是
//! 逐响应完整性声明）。
//!
//! 摘要计算 sha2 与 base64 均取 workspace 冻结依赖表（§22.6：base64
//! default-features = false，只启用所需 std；§23.2 无新增依赖）。

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use sha2::{Digest, Sha256};

/// 响应完整性声明值（RFC 9530 `Content-Digest` 的 `sha-256` 条目形态：
/// `sha-256=:<base64>:}；32 字节 SHA-256 + base64（44 字符），条目前后
/// 的冒号为 RFC 9530 的 base64 定界。
pub fn content_digest_value(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let encoded = BASE64_STANDARD.encode(digest);
    format!("sha-256=:{encoded}:")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;

    #[test]
    fn known_vector_sha256_abc() {
        // sha256("abc") = ba7816bf…（NIST 向量）；base64 见计算。
        assert_eq!(
            content_digest_value(b"abc"),
            "sha-256=:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=:"
        );
    }

    #[test]
    fn format_is_rfc9530_shape() {
        let value = content_digest_value(b"<html>hello</html>");
        assert!(value.starts_with("sha-256=:"), "{value}");
        assert!(value.ends_with(':'), "{value}");
        // 载荷 = 32 字节 base64（44 字符）。
        let payload = value.trim_start_matches("sha-256=:").trim_end_matches(':');
        assert_eq!(payload.len(), 44, "{value}");
        // base64 可解码且长度 32（解码校验不放大内存：固定 44 → 32）。
        let decoded = ok(BASE64_STANDARD.decode(payload), "decode base64 payload");
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn deterministic_per_bytes() {
        assert_eq!(
            content_digest_value(b"same bytes"),
            content_digest_value(b"same bytes")
        );
        assert_ne!(
            content_digest_value(b"same bytes"),
            content_digest_value(b"different bytes")
        );
    }
}
