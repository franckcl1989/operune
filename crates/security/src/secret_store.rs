//! 0.3.0 SecretStore 加密层（ADR-0001）。
//!
//! 本模块只提供加密原语与 KEK 管理：AEAD 密文 envelope 构造/解析
//! （XChaCha20Poly1305）、[`KeyProvider`] 端口与 [`FileKeyProvider`]
//! （`data_root` 下独立目录承载 KEK 文件）。SecretStore 服务编排
//! （grant / read / 轮换 / 审计）在 application 层；依赖方向
//! application → security + storage，本 crate **不依赖** storage
//! （§24.3，storage-sqlite 只接触不透明密文 BLOB）。
//!
//! # 密文 envelope 契约（ADR-0001 决策点 1，0.3 冻结）
//!
//! ```text
//! ┌────────────────┬──────────────┬───────────────────────┬────────────────────────┐
//! │ algorithm (u8) │ version (u8) │ nonce (24 bytes)      │ ciphertext ‖ tag       │
//! │ 0x01           │ 0x01         │ XChaCha20 192-bit     │ 变长，末 16B 为 tag    │
//! └────────────────┴──────────────┴───────────────────────┴────────────────────────┘
//! ```
//!
//! - 算法标识 `0x01` = XChaCha20Poly1305；`0x00` 保留（无加密）；
//! - 版本字段为未来换算法 / 换 key provider 预留（ADR-0001 Migration/rollback
//!   重加密路径：旧 KEK 解密 → 新 KEK 重加密 → 原子提交 → 删除旧 KEK）；
//!   未知算法标识 / 版本一律 fail closed，绝不部分解密；
//! - 整个 header（算法 + 版本 + nonce）作为 AAD 绑定到 tag，篡改 header 会被
//!   AEAD 认证拒绝；
//! - nonce 每次加密由 OS CSPRNG（getrandom，§22.6 冻结依赖）生成 24 随机字节：
//!   随机 nonce 无状态、无复用窗口管理义务（ADR 决策点 1 选 XChaCha20Poly1305
//!   的理由）。
//!
//! # 保护等级声明（诚实边界，ADR-0001 Security impact）
//!
//! 本组合防御「能读到 SQLite 文件/备份但拿不到 KEK 的 attacker」；**不防御**
//! 与运行进程同用户/同权限的本地 attacker（进程内存本就持有 KEK）。错误 /
//! 日志 / Display 永不出现密钥材料与明文（§16.6）。
//!
//! # Windows 权限降级（披露，ADR-0001 决策点 2 / §11.3）
//!
//! Unix 上 KEK 目录 0700、KEK 文件 0600，创建时设置，设置失败 fail closed。
//! Windows 上 std 没有 safe ACL API（`windows` crate 不在 §22 冻结清单，未获
//! §23.1 Gate 批准），按 ADR 裁决**降级**：不设置 ACL，KEK 文件继承
//! `data_root` 目录权限（`%LOCALAPPDATA%\operune` 本身是用户级目录）。这是
//! 披露性选择（§11.3 精神：无安全封装宁可不做）——若未来引入 safe ACL
//! 封装，须先过 §23.1 Gate 并单独实施 ADR。

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

use crate::secret::SecretBytes;

/// envelope header 中算法标识的偏移（第 0 字节）。
pub const ALGORITHM_OFFSET: usize = 0;
/// envelope header 中版本字段的偏移（第 1 字节）。
pub const VERSION_OFFSET: usize = 1;
/// envelope header 中 nonce 的偏移（第 2 字节起）。
pub const NONCE_OFFSET: usize = 2;

/// XChaCha20Poly1305 nonce 长度（192-bit）。
pub const XNONCE_LEN: usize = 24;
/// Poly1305 认证 tag 长度。
pub const ENVELOPE_TAG_LEN: usize = 16;

/// 算法标识：XChaCha20Poly1305（ADR-0001 决策点 1 裁决）。
pub const ENVELOPE_ALGORITHM_XCHACHA20POLY1305: u8 = 0x01;
/// 当前 envelope 版本（0.3 冻结契约；未来换算法/换 provider 时递增）。
pub const ENVELOPE_VERSION_CURRENT: u8 = 0x01;
/// envelope header 定长：算法(1) + 版本(1) + nonce(24) = 26 字节。
pub const ENVELOPE_HEADER_LEN: usize = NONCE_OFFSET + XNONCE_LEN;

/// 单条 secret 明文长度预算（1 MiB）。超限 → [`SecretStoreError::OverBudget`]。
pub const SECRET_MAX_PLAINTEXT_LEN: usize = 1024 * 1024;
/// 单条密文 envelope 长度预算（明文预算 + header + tag）。
pub const SECRET_MAX_ENVELOPE_LEN: usize =
    ENVELOPE_HEADER_LEN + SECRET_MAX_PLAINTEXT_LEN + ENVELOPE_TAG_LEN;

/// KEK 长度（XChaCha20Poly1305 256-bit key）。
pub const KEK_SIZE: usize = 32;

/// `<data_root>` 下 KEK 独立目录名（ADR-0001 决策点 2，方案 C）。
const KEK_DIR_NAME: &str = "secretstore";
/// KEK 文件名。
const KEK_FILE_NAME: &str = "kek.bin";
/// 写入用的临时文件名（「临时文件 + rename」原子替换）。
const KEK_TMP_FILE_NAME: &str = "kek.bin.tmp";
/// Unix：KEK 目录权限。
#[cfg(unix)]
const KEK_DIR_MODE: u32 = 0o700;
/// Unix：KEK 文件权限。
#[cfg(unix)]
const KEK_FILE_MODE: u32 = 0o600;

/// SecretStore 加密层错误（§16.6：错误文本永不包含密钥材料与明文）。
///
/// 全部失败语义为 fail closed：任何失败都不得回退到明文存储或静默成功。
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// KEK 不可用：文件缺失 / 不可读 / 创建失败 / OS CSPRNG 不可用 /
    /// data root 配置不允许。Display 只含 io 错误文本，不含密钥材料。
    #[error("KEK 不可用: {0}")]
    KeyUnavailable(#[source] io::Error),
    /// KEK 损坏：KEK 文件大小非法或密钥字节无法构造密码器。fail closed，
    /// 绝不自动重新生成（ADR-0001 逻辑自洽：KEK 丢失/损坏必须显式报错）。
    #[error("KEK 损坏（长度或内容非法）")]
    CorruptKey,
    /// 加密失败（AEAD 错误或 nonce 生成失败）。
    #[error("加密失败")]
    Encryption,
    /// 解密失败：envelope 结构非法（过短 / 算法标识未知 / 版本未知）或 AEAD
    /// tag 校验失败。**绝不包含明文或密钥材料**，绝不部分解密。
    #[error("解密失败（密文被拒绝，不含明文）")]
    Decryption,
    /// 明文 / 密文超过长度预算。
    #[error("secret 超过长度预算")]
    OverBudget,
}

/// XChaCha20Poly1305 密码器（ADR-0001 决策点 1，方案 A）。
///
/// 由 32 字节 KEK 构造（长度不符 → [`SecretStoreError::CorruptKey`]）。
/// 明文输入/输出一律 [`SecretBytes`]（防泄漏 `Debug`，§16.6）；密文输出为
/// 不透明 BLOB（`Vec<u8>`），可交给 storage-sqlite 落库，storage 不感知加密。
///
/// `Debug` 掩码为 `[REDACTED]`：密钥字节不出现在任何格式化输出中。
pub struct SecretCipher {
    inner: XChaCha20Poly1305,
}

impl SecretCipher {
    /// 以 32 字节 KEK 构造密码器。
    pub fn new(kek: &SecretBytes) -> Result<Self, SecretStoreError> {
        let cipher = XChaCha20Poly1305::new_from_slice(kek.expose_secret())
            .map_err(|_| SecretStoreError::CorruptKey)?;
        Ok(Self { inner: cipher })
    }

    /// 加密：`SecretBytes`（明文）→ 不透明密文 envelope（`Vec<u8>` BLOB）。
    ///
    /// 每次加密生成新的随机 nonce（getrandom），header 作为 AAD 绑定。
    pub fn encrypt(&self, plaintext: &SecretBytes) -> Result<Vec<u8>, SecretStoreError> {
        if plaintext.len() > SECRET_MAX_PLAINTEXT_LEN {
            return Err(SecretStoreError::OverBudget);
        }
        let mut header = [0u8; ENVELOPE_HEADER_LEN];
        header[ALGORITHM_OFFSET] = ENVELOPE_ALGORITHM_XCHACHA20POLY1305;
        header[VERSION_OFFSET] = ENVELOPE_VERSION_CURRENT;
        getrandom::fill(&mut header[NONCE_OFFSET..]).map_err(|_| SecretStoreError::Encryption)?;
        let nonce: &XNonce = (&header[NONCE_OFFSET..])
            .try_into()
            .map_err(|_| SecretStoreError::Encryption)?;
        let ciphertext = self
            .inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.expose_secret(),
                    aad: &header,
                },
            )
            .map_err(|_| SecretStoreError::Encryption)?;
        let mut envelope = Vec::with_capacity(ENVELOPE_HEADER_LEN + ciphertext.len());
        envelope.extend_from_slice(&header);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    /// 解密：不透明密文 envelope → `SecretBytes`（明文）。
    ///
    /// 所有失败路径（结构非法 / tag 校验失败）统一为
    /// [`SecretStoreError::Decryption`]，绝不含明文、绝不部分解密
    /// （ADR-0001 逻辑自洽）。未来多算法/多版本演进在此按 header 分发。
    pub fn decrypt(&self, envelope: &[u8]) -> Result<SecretBytes, SecretStoreError> {
        if envelope.len() < ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN {
            return Err(SecretStoreError::Decryption);
        }
        if envelope.len() > SECRET_MAX_ENVELOPE_LEN {
            return Err(SecretStoreError::OverBudget);
        }
        let header = &envelope[..ENVELOPE_HEADER_LEN];
        if header[ALGORITHM_OFFSET] != ENVELOPE_ALGORITHM_XCHACHA20POLY1305 {
            // 未知算法标识 → fail closed（未来多算法重加密路径在此分发）。
            return Err(SecretStoreError::Decryption);
        }
        if header[VERSION_OFFSET] != ENVELOPE_VERSION_CURRENT {
            // 未知版本 → fail closed（未来旧版本重加密路径在此解析）。
            return Err(SecretStoreError::Decryption);
        }
        let nonce: &XNonce = (&header[NONCE_OFFSET..])
            .try_into()
            .map_err(|_| SecretStoreError::Decryption)?;
        let plaintext = self
            .inner
            .decrypt(
                nonce,
                Payload {
                    msg: &envelope[ENVELOPE_HEADER_LEN..],
                    aad: header,
                },
            )
            .map_err(|_| SecretStoreError::Decryption)?;
        Ok(SecretBytes::new(plaintext))
    }
}

impl fmt::Debug for SecretCipher {
    /// 掩码实现：任何格式化输出都不出现密钥字节（§16.6）。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretCipher([REDACTED])")
    }
}

/// KEK provider 端口（ADR-0001 决策点 3：未来演进预留点）。
///
/// 0.3.0 由 [`FileKeyProvider`] 实现；OS credential provider（Windows
/// Credential Manager / DPAPI、macOS Keychain、Linux Secret Service，
/// 0.4+ 单独 ADR）未来实现同一 trait。provider 是 SecretStore 的实现细节，
/// 不进入 WIT 组件契约；provider 切换沿用 ADR-0001 Migration/rollback 的
/// 重加密路径。
pub trait KeyProvider {
    /// 读取或创建 32 字节 KEK。
    ///
    /// 失败一律 fail closed（[`SecretStoreError`]），绝不回退明文；KEK 损坏
    /// 时显式报错，绝不静默重新生成。
    fn load_or_create_key(&self) -> Result<SecretBytes, SecretStoreError>;
}

/// 文件 KEK provider（ADR-0001 决策点 2，方案 C）。
///
/// KEK 文件位于 `<data_root>/secretstore/kek.bin`——与 SQLite metadata 库
/// 不同目录、不同文件、不同权限、不同备份语义（§16.6：KEK 不得与密文以等价
/// 保护级别存放在同一 SQLite 数据库中）。
///
/// 权限：
/// - Unix：目录 0700、文件 0600，创建时设置，设置失败 fail closed；已存在
///   的目录每次调用重新断言 0700（权限加固）；
/// - Windows：std 无 safe ACL API，按 ADR 裁决**降级**为继承 `data_root`
///   权限（披露见模块文档「Windows 权限降级」），不静默宣称已设置 ACL。
///
/// KEK 文件为定长 32 字节；读取先做大小校验再按 32 字节有界读取，长度不符
/// → [`SecretStoreError::CorruptKey`]（fail closed）。
///
/// 写入采用「临时文件 + rename」原子替换（ADR-0001「完整可靠」：写中途
/// crash 不留下半写文件）；临时文件在写入**前**先限权 0600（避免窗口期
/// 暴露），rename 后目录 fsync（Unix）确保持久化；创建后读回校验——若并发
/// 进程同时创建，收敛到磁盘上最终存在的那份 KEK，不产生分脑。
#[derive(Debug)]
pub struct FileKeyProvider {
    kek_dir: PathBuf,
    kek_path: PathBuf,
}

impl FileKeyProvider {
    /// 以 data root 构造 provider。
    ///
    /// 校验 data root 绝对路径、有效 UTF-8、不含 NUL（镜像 platform
    /// `DataRoot` 的不变量，§13.3 边界解析一次；本 crate 不依赖 platform，
    /// §24.3）。失败 → [`SecretStoreError::KeyUnavailable`]（fail closed）。
    pub fn new(data_root: &Path) -> Result<Self, SecretStoreError> {
        let invalid = |detail: &str| {
            SecretStoreError::KeyUnavailable(io::Error::new(io::ErrorKind::InvalidInput, detail))
        };
        let Some(root_str) = data_root.to_str() else {
            return Err(invalid("data root 必须是有效 UTF-8"));
        };
        if root_str.contains('\0') {
            return Err(invalid("data root 不得包含 NUL"));
        }
        if !data_root.is_absolute() {
            return Err(invalid("data root 必须是绝对路径"));
        }
        let kek_dir = data_root.join(KEK_DIR_NAME);
        let kek_path = kek_dir.join(KEK_FILE_NAME);
        Ok(Self { kek_dir, kek_path })
    }

    /// `<data_root>/secretstore` 目录视图（测试/运维工具用）。
    pub fn kek_dir(&self) -> &Path {
        &self.kek_dir
    }

    /// KEK 文件路径视图（测试/运维工具用）。
    pub fn kek_path(&self) -> &Path {
        &self.kek_path
    }

    fn ensure_kek_directory(&self) -> Result<(), SecretStoreError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(KEK_DIR_MODE);
            builder
                .create(&self.kek_dir)
                .map_err(SecretStoreError::KeyUnavailable)?;
            // 既有目录也重新断言 0700（权限加固，ADR 决策点 2）。
            fs::set_permissions(&self.kek_dir, fs::Permissions::from_mode(KEK_DIR_MODE))
                .map_err(SecretStoreError::KeyUnavailable)?;
        }
        #[cfg(not(unix))]
        {
            // Windows：std 无 safe ACL API——降级继承 data_root 权限
            // （披露见模块文档；禁止静默宣称已设置 ACL）。
            fs::create_dir_all(&self.kek_dir).map_err(SecretStoreError::KeyUnavailable)?;
        }
        Ok(())
    }

    fn load_key_file(&self) -> Result<SecretBytes, SecretStoreError> {
        let file = File::open(&self.kek_path).map_err(SecretStoreError::KeyUnavailable)?;
        let metadata = file.metadata().map_err(SecretStoreError::KeyUnavailable)?;
        if metadata.len() != KEK_SIZE as u64 {
            // 有界大小校验：KEK 文件必须恰好 32 字节。
            return Err(SecretStoreError::CorruptKey);
        }
        let mut key = Vec::with_capacity(KEK_SIZE);
        file.take(KEK_SIZE as u64)
            .read_to_end(&mut key)
            .map_err(SecretStoreError::KeyUnavailable)?;
        if key.len() != KEK_SIZE {
            return Err(SecretStoreError::CorruptKey);
        }
        Ok(SecretBytes::new(key))
    }

    fn create_key_file(&self) -> Result<SecretBytes, SecretStoreError> {
        let mut raw = [0u8; KEK_SIZE];
        getrandom::fill(&mut raw)
            .map_err(|e| SecretStoreError::KeyUnavailable(io::Error::other(e)))?;
        let outcome = self.persist_new_key(&raw);
        raw.zeroize();
        outcome
    }

    fn persist_new_key(&self, raw: &[u8]) -> Result<SecretBytes, SecretStoreError> {
        let tmp_path = self.kek_dir.join(KEK_TMP_FILE_NAME);
        {
            let mut tmp = File::create(&tmp_path).map_err(SecretStoreError::KeyUnavailable)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // 临时文件在写入内容前先限权 0600（避免限权前的窗口期暴露）。
                fs::set_permissions(&tmp_path, fs::Permissions::from_mode(KEK_FILE_MODE))
                    .map_err(SecretStoreError::KeyUnavailable)?;
            }
            tmp.write_all(raw)
                .map_err(SecretStoreError::KeyUnavailable)?;
            tmp.sync_all().map_err(SecretStoreError::KeyUnavailable)?;
        }
        fs::rename(&tmp_path, &self.kek_path).map_err(SecretStoreError::KeyUnavailable)?;
        #[cfg(unix)]
        {
            // 目录 fsync：确保 rename 落盘（Linux/macOS 上目录可作 File 打开）。
            let dir = File::open(&self.kek_dir).map_err(SecretStoreError::KeyUnavailable)?;
            dir.sync_all().map_err(SecretStoreError::KeyUnavailable)?;
        }
        // 读回校验 + 并发收敛：若另一进程同时创建并最终胜出，采用磁盘上的
        // 那份 KEK（双方收敛到同一密钥，不产生分脑）；读回失败 fail closed。
        self.load_key_file()
    }
}

impl KeyProvider for FileKeyProvider {
    fn load_or_create_key(&self) -> Result<SecretBytes, SecretStoreError> {
        self.ensure_kek_directory()?;
        match self.load_key_file() {
            Ok(key) => Ok(key),
            Err(SecretStoreError::KeyUnavailable(err)) if err.kind() == io::ErrorKind::NotFound => {
                self.create_key_file()
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_key() -> SecretBytes {
        SecretBytes::from_slice(&[0x42; KEK_SIZE])
    }

    fn other_key() -> SecretBytes {
        SecretBytes::from_slice(&[0x24; KEK_SIZE])
    }

    fn secret(value: &[u8]) -> SecretBytes {
        SecretBytes::from_slice(value)
    }

    /// `haystack` 是否包含 `needle` 字节序列。
    fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// 把解密结果格式化为错误文本；不应到达的成功路径返回给定占位文本。
    fn err_display(result: Result<SecretBytes, SecretStoreError>, fallback: &str) -> String {
        match result {
            Err(e) => format!("{e}"),
            Ok(_) => fallback.to_owned(),
        }
    }

    #[test]
    fn roundtrip_recovers_plaintext() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let plaintext = secret(b"component-token-value");
        let envelope = cipher.encrypt(&plaintext)?;
        let recovered = cipher.decrypt(&envelope)?;
        assert_eq!(recovered.expose_secret(), plaintext.expose_secret());
        Ok(())
    }

    #[test]
    fn roundtrip_empty_plaintext() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let envelope = cipher.encrypt(&secret(b""))?;
        // 空明文：envelope = header(26) + tag(16)，无密文段。
        assert_eq!(envelope.len(), ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN);
        let recovered = cipher.decrypt(&envelope)?;
        assert!(recovered.is_empty());
        Ok(())
    }

    #[test]
    fn ciphertext_differs_from_plaintext_and_is_random() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let plaintext = secret(b"same-plaintext-every-time");
        let first = cipher.encrypt(&plaintext)?;
        let second = cipher.encrypt(&plaintext)?;
        // 密文 ≠ 明文。
        assert_ne!(first, plaintext.expose_secret().to_vec());
        // 同一明文两次加密产生不同密文（随机 nonce）。
        assert_ne!(first, second, "随机 nonce 必须使两次密文不同");
        // nonce 段（header[2..26]）两次不同。
        assert_ne!(
            &first[NONCE_OFFSET..ENVELOPE_HEADER_LEN],
            &second[NONCE_OFFSET..ENVELOPE_HEADER_LEN]
        );
        Ok(())
    }

    #[test]
    fn tampered_ciphertext_rejected() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let envelope = cipher.encrypt(&secret(b"tamper-me"))?;
        let mut tampered = envelope.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            cipher.decrypt(&tampered),
            Err(SecretStoreError::Decryption)
        ));
        Ok(())
    }

    #[test]
    fn tampered_header_rejected() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let envelope = cipher.encrypt(&secret(b"tamper-header"))?;

        // 算法标识被篡改（保留 0x00=无加密）→ fail closed。
        let mut wrong_algorithm = envelope.clone();
        wrong_algorithm[ALGORITHM_OFFSET] = 0x00;
        assert!(matches!(
            cipher.decrypt(&wrong_algorithm),
            Err(SecretStoreError::Decryption)
        ));

        // 版本字段被篡改（envelope 版本解析：非当前版本 → fail closed）。
        let mut wrong_version = envelope.clone();
        wrong_version[VERSION_OFFSET] = ENVELOPE_VERSION_CURRENT + 1;
        assert!(matches!(
            cipher.decrypt(&wrong_version),
            Err(SecretStoreError::Decryption)
        ));

        // nonce 段被篡改（header 作为 AAD 绑定 → tag 校验失败）。
        let mut wrong_nonce = envelope.clone();
        wrong_nonce[NONCE_OFFSET] ^= 0x01;
        assert!(matches!(
            cipher.decrypt(&wrong_nonce),
            Err(SecretStoreError::Decryption)
        ));
        Ok(())
    }

    #[test]
    fn truncated_envelope_rejected() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let envelope = cipher.encrypt(&secret(b"truncate-me"))?;
        // 截断到不足「header + tag」→ 结构非法。
        let truncated = &envelope[..ENVELOPE_HEADER_LEN + ENVELOPE_TAG_LEN - 1];
        assert!(matches!(
            cipher.decrypt(truncated),
            Err(SecretStoreError::Decryption)
        ));
        // 空输入。
        assert!(matches!(
            cipher.decrypt(&[]),
            Err(SecretStoreError::Decryption)
        ));
        Ok(())
    }

    #[test]
    fn wrong_key_rejected() -> TestResult {
        let encrypted = SecretCipher::new(&test_key())?;
        let envelope = encrypted.encrypt(&secret(b"wrong-key"))?;
        let other = SecretCipher::new(&other_key())?;
        assert!(matches!(
            other.decrypt(&envelope),
            Err(SecretStoreError::Decryption)
        ));
        Ok(())
    }

    #[test]
    fn oversized_plaintext_rejected() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let big = secret(&vec![0u8; SECRET_MAX_PLAINTEXT_LEN + 1]);
        assert!(matches!(
            cipher.encrypt(&big),
            Err(SecretStoreError::OverBudget)
        ));
        Ok(())
    }

    #[test]
    fn oversized_envelope_rejected() -> TestResult {
        let cipher = SecretCipher::new(&test_key())?;
        let mut envelope = vec![0u8; SECRET_MAX_ENVELOPE_LEN + 1];
        // 构造可通过算法/版本检查的 header，以走到预算分支。
        envelope[ALGORITHM_OFFSET] = ENVELOPE_ALGORITHM_XCHACHA20POLY1305;
        envelope[VERSION_OFFSET] = ENVELOPE_VERSION_CURRENT;
        assert!(matches!(
            cipher.decrypt(&envelope),
            Err(SecretStoreError::OverBudget)
        ));
        Ok(())
    }

    #[test]
    fn secret_cipher_requires_32_byte_key() {
        for wrong_len in [0usize, 16, 31, 33, KEK_SIZE + 17] {
            let bad = SecretBytes::from_slice(&vec![0u8; wrong_len]);
            assert!(
                matches!(SecretCipher::new(&bad), Err(SecretStoreError::CorruptKey)),
                "长度 {wrong_len} 必须被拒绝"
            );
        }
    }

    #[test]
    fn debug_and_display_never_leak_material() -> TestResult {
        let key = test_key();
        let cipher = SecretCipher::new(&key)?;
        let plaintext = secret(b"plaintext-that-must-not-leak");
        let envelope = cipher.encrypt(&plaintext)?;
        let key_bytes = key.expose_secret();
        let plaintext_bytes = plaintext.expose_secret();

        // SecretCipher 的 Debug 掩码且不含密钥字节。
        let cipher_debug = format!("{cipher:?}");
        assert!(cipher_debug.contains("REDACTED"));
        assert!(
            !contains_bytes(cipher_debug.as_bytes(), key_bytes),
            "Debug 泄漏密钥字节: {cipher_debug}"
        );

        // 解密失败的错误文本不含密钥材料与明文。
        let wrong = SecretCipher::new(&other_key())?;
        let decryption_text = err_display(wrong.decrypt(&envelope), "解密意外成功");
        assert!(!contains_bytes(decryption_text.as_bytes(), key_bytes));
        assert!(!contains_bytes(decryption_text.as_bytes(), plaintext_bytes));

        // 结构错误（算法标识未知）的错误文本同样干净。
        let mut bad = envelope.clone();
        bad[ALGORITHM_OFFSET] = 0x00;
        let structural_text = err_display(cipher.decrypt(&bad), "解密意外成功");
        assert!(!contains_bytes(structural_text.as_bytes(), key_bytes));
        assert!(!contains_bytes(structural_text.as_bytes(), plaintext_bytes));

        // CorruptKey / OverBudget 的 Display 是静态文本，不含任何字节材料。
        let corrupt_key = SecretBytes::from_slice(&[0x11u8; 31]);
        let corrupt_text = err_display(
            SecretCipher::new(&corrupt_key).map(|_| secret(b"")),
            "构造意外成功",
        );
        assert!(!corrupt_text.as_bytes().contains(&0x11));
        let budget_text = err_display(
            cipher.decrypt(&[0u8; SECRET_MAX_ENVELOPE_LEN + 1]),
            "解密意外成功",
        );
        assert!(!budget_text.as_bytes().contains(&0x11));
        Ok(())
    }

    #[test]
    fn key_provider_creates_and_reloads_kek() -> TestResult {
        let dir = tempfile::tempdir()?;
        let provider = FileKeyProvider::new(dir.path())?;
        let first = provider.load_or_create_key()?;

        // 位置与大小契约：<data_root>/secretstore/kek.bin，恰好 32 字节。
        assert_eq!(
            provider.kek_path(),
            dir.path().join(KEK_DIR_NAME).join(KEK_FILE_NAME)
        );
        assert_eq!(
            std::fs::metadata(provider.kek_path())?.len(),
            KEK_SIZE as u64
        );

        // 幂等：再次加载（含独立实例）得到同一 KEK。
        let again = provider.load_or_create_key()?;
        let reloaded = FileKeyProvider::new(dir.path())?.load_or_create_key()?;
        assert_eq!(first.expose_secret(), again.expose_secret());
        assert_eq!(first.expose_secret(), reloaded.expose_secret());

        // provider 的 Debug 只含路径，不含密钥字节。
        let debug = format!("{provider:?}");
        assert!(
            !contains_bytes(debug.as_bytes(), first.expose_secret()),
            "Debug 泄漏密钥: {debug}"
        );

        // trait 对象（未来 OS provider 的替换点）。
        let dyn_provider: &dyn KeyProvider = &provider;
        let through_trait = dyn_provider.load_or_create_key()?;
        assert_eq!(first.expose_secret(), through_trait.expose_secret());
        Ok(())
    }

    #[test]
    fn key_provider_rejects_corrupt_kek_files() -> TestResult {
        let dir = tempfile::tempdir()?;
        let provider = FileKeyProvider::new(dir.path())?;

        // 过短 → CorruptKey（fail closed，不自动重新生成）。
        std::fs::create_dir_all(provider.kek_dir())?;
        std::fs::write(provider.kek_path(), [0u8; 16])?;
        assert!(matches!(
            provider.load_or_create_key(),
            Err(SecretStoreError::CorruptKey)
        ));

        // 过长 → CorruptKey（有界大小校验）。
        std::fs::write(provider.kek_path(), vec![0u8; KEK_SIZE + 1])?;
        assert!(matches!(
            provider.load_or_create_key(),
            Err(SecretStoreError::CorruptKey)
        ));

        // 删除后重新加载 → 重建新 KEK。
        std::fs::remove_file(provider.kek_path())?;
        let key = provider.load_or_create_key()?;
        assert_eq!(key.len(), KEK_SIZE);
        Ok(())
    }

    #[test]
    fn key_provider_rejects_invalid_data_root() {
        // 相对路径。
        assert!(matches!(
            FileKeyProvider::new(Path::new("relative/data")),
            Err(SecretStoreError::KeyUnavailable(_))
        ));
        // NUL。
        assert!(matches!(
            FileKeyProvider::new(Path::new("C:\\data\0root")),
            Err(SecretStoreError::KeyUnavailable(_))
        ));
    }

    #[test]
    fn provider_kek_roundtrips_through_cipher() -> TestResult {
        let dir = tempfile::tempdir()?;
        let provider = FileKeyProvider::new(dir.path())?;
        let kek = provider.load_or_create_key()?;
        let cipher = SecretCipher::new(&kek)?;
        let plaintext = secret(b"stored-component-secret");
        let envelope = cipher.encrypt(&plaintext)?;
        let recovered = cipher.decrypt(&envelope)?;
        assert_eq!(recovered.expose_secret(), plaintext.expose_secret());
        Ok(())
    }

    /// Unix：KEK 目录 0700、KEK 文件 0600（ADR-0001 决策点 2）。
    #[cfg(unix)]
    #[test]
    fn kek_dir_and_file_have_restrictive_permissions() -> TestResult {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let provider = FileKeyProvider::new(dir.path())?;
        let key = provider.load_or_create_key()?;
        let dir_mode = std::fs::metadata(provider.kek_dir())?.permissions().mode() & 0o777;
        let file_mode = std::fs::metadata(provider.kek_path())?.permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "KEK 目录必须 0700");
        assert_eq!(file_mode, 0o600, "KEK 文件必须 0600");
        assert_eq!(key.len(), KEK_SIZE);
        Ok(())
    }
}
