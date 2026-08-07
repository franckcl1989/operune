use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::{DomainError, ValueKind};

/// SHA-256 摘要长度（字节）。
pub(crate) const DIGEST_LEN: usize = 32;

/// 对收到的原始 Component 字节计算得到的不可变内容事实（§6.7 / §19.4
/// `ContentDigest`）：固定长度 SHA-256 摘要（32 字节），不是任意 `Vec<u8>`
/// （§13.2：Hash 使用固定长度摘要类型）。在任何 guest 代码执行前即可得到
/// （§6.7），因此同一 digest 即同一字节事实。
///
/// 作为 digest 主键的 quarantine/candidate 记录与最终内容寻址制品的基础
/// （§18.3 / §18.7：final artifact 以 `ContentDigest` 寻址并视为不可变）。
///
/// 构造校验（validate-on-construct，§13.3）：`from_hex` 只接受恰好 64 个
/// 十六进制字符（大小写均可），非十六进制字符或长度不符即构造失败。
///
/// 错误：解析失败返回 [`DomainError::InvalidValue`]。
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContentDigest([u8; DIGEST_LEN]);

impl ContentDigest {
    /// 计算任意字节输入的 SHA-256 摘要（不可失败；输入长度不限）。
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let output = Sha256::digest(bytes);
        Self(output.into())
    }

    /// 从恰好 64 个十六进制字符解析（validate-on-construct，§13.3）。
    pub fn from_hex(hex: &str) -> Result<Self, DomainError> {
        let bytes = hex.as_bytes();
        if bytes.len() != 2 * DIGEST_LEN {
            return Err(DomainError::invalid_value(
                ValueKind::ContentDigest,
                format!(
                    "expected {} hex characters (SHA-256), got {}",
                    2 * DIGEST_LEN,
                    bytes.len()
                ),
            ));
        }
        let mut out = [0u8; DIGEST_LEN];
        for (i, pair) in bytes.chunks_exact(2).enumerate() {
            let hi = hex_value(pair[0]).ok_or_else(|| {
                DomainError::invalid_value(
                    ValueKind::ContentDigest,
                    format!("invalid hex character {:?}", pair[0] as char),
                )
            })?;
            let lo = hex_value(pair[1]).ok_or_else(|| {
                DomainError::invalid_value(
                    ValueKind::ContentDigest,
                    format!("invalid hex character {:?}", pair[1] as char),
                )
            })?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }

    /// 原始 32 字节视图（内容寻址 / 持久化，§18.7）。
    pub fn to_array(self) -> [u8; DIGEST_LEN] {
        self.0
    }
}

/// 单个十六进制字符的数值；非法字符返回 `None`。
fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for ContentDigest {
    /// 64 个小写十六进制字符（规范展示 / 日志形式）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for ContentDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 摘要非机密（§6.7 字节事实），Debug 与 Display 一致便于日志。
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for ContentDigest {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for ContentDigest {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ContentDigest {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::from_hex(&value).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ok;
    use proptest::prelude::*;

    /// SHA-256 标准测试向量（NIST 示例，公开事实）。
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    #[test]
    fn known_vectors() {
        assert_eq!(ContentDigest::from_bytes(b"").to_string(), SHA256_EMPTY);
        assert_eq!(ContentDigest::from_bytes(b"abc").to_string(), SHA256_ABC);
    }

    #[test]
    fn digest_length_invariant() {
        // 任意输入长度（含 0 / 31 / 32 / 33 / 4096 字节）都得到 32 字节摘要。
        for len in [0usize, 1, 31, 32, 33, 4096] {
            let input = vec![0xabu8; len];
            assert_eq!(
                ContentDigest::from_bytes(&input).to_array().len(),
                DIGEST_LEN
            );
        }
    }

    #[test]
    fn deterministic() {
        let input = b"same bytes twice";
        assert_eq!(
            ContentDigest::from_bytes(input),
            ContentDigest::from_bytes(input)
        );
    }

    #[test]
    fn from_hex_roundtrip() {
        let digest = ContentDigest::from_bytes(b"roundtrip");
        let hex = digest.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(ContentDigest::from_hex(&hex), Ok(digest));
        assert_eq!(hex.parse::<ContentDigest>(), Ok(digest));
    }

    #[test]
    fn from_hex_accepts_uppercase() {
        let digest = ContentDigest::from_bytes(b"case");
        let upper = digest.to_string().to_uppercase();
        assert_eq!(ContentDigest::from_hex(&upper), Ok(digest));
    }

    #[test]
    fn from_hex_rejects_invalid() {
        let bad = [
            "",
            "abc",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8550", // 65 字符
            "zz0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   // 非 hex
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",   // 63 字符
        ];
        for s in bad {
            assert!(
                matches!(
                    ContentDigest::from_hex(s),
                    Err(DomainError::InvalidValue {
                        kind: ValueKind::ContentDigest,
                        ..
                    })
                ),
                "{s:?} must be rejected"
            );
        }
    }

    #[test]
    fn serde_roundtrip() {
        let digest = ContentDigest::from_bytes(b"serde");
        let json = ok(serde_json::to_string(&digest), "serialize");
        assert_eq!(json, format!("\"{digest}\""));
        assert_eq!(
            ok(serde_json::from_str::<ContentDigest>(&json), "deserialize"),
            digest
        );
    }

    #[test]
    fn serde_rejects_invalid() {
        // 反序列化边界同样执行校验（§13.3）。
        assert!(serde_json::from_str::<ContentDigest>("\"xyz\"").is_err());
        assert!(serde_json::from_str::<ContentDigest>("\"abc\"").is_err());
    }

    proptest! {
        #[test]
        fn bytes_hex_roundtrip(input in prop::collection::vec(any::<u8>(), 0..512)) {
            let digest = ContentDigest::from_bytes(&input);
            prop_assert_eq!(ContentDigest::from_hex(&digest.to_string()), Ok(digest));
        }

        #[test]
        fn array_hex_roundtrip(bytes in any::<[u8; DIGEST_LEN]>()) {
            let digest = ContentDigest::from_hex(
                &bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            );
            let expected = ContentDigest(bytes);
            prop_assert_eq!(digest, Ok(expected));
        }
    }
}
