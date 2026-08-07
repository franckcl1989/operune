//! 内存秘密包装（§16.6）。
//!
//! [`SecretBytes`] 以 [`secrecy::SecretBox`] 承载可变长度字节，内层缓冲在
//! drop 时清零（zeroize）。`Debug` 显式掩码为 `[REDACTED]`；不实现 `Display`，
//! 不实现 `Serialize`/`Deserialize`——任何序列化输出都必须由调用方显式完成。
//!
//! §16.6 边界：secrecy/zeroize 只解决进程内暴露面，不构成 at-rest secret
//! storage。0.3.0 的 Component Secret 服务必须使用独立 `SecretStore` port。

use std::fmt;

use secrecy::{ExposeSecret, SecretBox};

/// 可变长度字节秘密（§16.6）。
///
/// - drop 时清零（secrecy/zeroize）；
/// - `Debug` 掩码为 `[REDACTED]`，不实现 `Display` / `Serialize`；
/// - 不实现 `PartialEq`/`Eq`/`Hash`（避免泄漏比较的时序面）。
pub struct SecretBytes(SecretBox<[u8]>);

impl SecretBytes {
    /// 从已拥有的字节缓冲构造。调用方仍持有的原始缓冲由调用方负责清理；
    /// 本类型内部持有副本，在 drop 时清零。
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(bytes.into_boxed_slice()))
    }

    /// 从字节切片拷贝构造（内部缓冲在 drop 时清零）。
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(SecretBox::new(bytes.to_vec().into_boxed_slice()))
    }

    /// 秘密字节数。
    pub fn len(&self) -> usize {
        self.0.expose_secret().len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Clone for SecretBytes {
    /// 深拷贝到新的受保护缓冲；原缓冲与新缓冲都将在各自 drop 时清零。
    fn clone(&self) -> Self {
        Self::from_slice(self.0.expose_secret())
    }
}

impl ExposeSecret<[u8]> for SecretBytes {
    /// 唯一取用入口（secrecy 约定）：调用方必须自行约束引用生命周期。
    fn expose_secret(&self) -> &[u8] {
        self.0.expose_secret()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_masks_content() {
        let secret = SecretBytes::from_slice(b"top-secret-bytes".as_slice());
        let debug = format!("{secret:?}");
        assert!(
            !debug.contains("top-secret-bytes"),
            "Debug 泄漏秘密内容: {debug}"
        );
        assert!(debug.contains("REDACTED"), "Debug 必须掩码: {debug}");
    }

    #[test]
    fn len_and_is_empty() {
        let empty = SecretBytes::new(Vec::new());
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());

        let secret = SecretBytes::from_slice(b"abc".as_slice());
        assert_eq!(secret.len(), 3);
        assert!(!secret.is_empty());
    }

    #[test]
    fn clone_produces_independent_buffer() {
        let secret = SecretBytes::from_slice(b"clone-me".as_slice());
        let cloned = secret.clone();
        assert_eq!(cloned.expose_secret(), secret.expose_secret());
        // 两份独立缓冲：修改 clone 的引用不影响原值（互不 alias）。
        assert_eq!(cloned.expose_secret(), b"clone-me".as_slice());
    }
}
