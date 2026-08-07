//! Argon2id 密码哈希（§16.4）。
//!
//! - 绝对最低参数 = 规范基线日 OWASP 推荐：**19 MiB memory、2 iterations、
//!   parallelism 1**，与 argon2 0.5.3 `Params::DEFAULT` 完全一致；低于最低基线的
//!   参数在构造期直接拒绝（`PasswordParams::new` 校验 + argon2 库自身下限双重防线）；
//! - 密码永远不使用 SHA-256 等快速摘要直接存储（§16.4）——digest 只用于
//!   session token（§16.5）；
//! - 存储格式为 PHC 字符串（`$argon2id$v=19$m=…,t=…,p=…$salt$hash`，与 argon2
//!   0.5.3 官方输出互操作），盐由 OS CSPRNG 生成（16 bytes，argon2
//!   `RECOMMENDED_SALT_LEN`）；
//! - 验证时使用**存储 hash 中携带的参数**重新计算并做 constant-time 比较
//!   （subtle 2.6.1），因此参数升级后旧 hash 仍可验证；"登录时重哈希"策略留给
//!   调用方（可用 [`PasswordHashString::meets_minimum_baseline`] 判断）；
//! - PHC 编解码为自包含实现（不引入 workspace 之外的 password-hash 依赖，
//!   §23.1 依赖 Gate），解析对 salt/hash 长度做上限防御。

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use secrecy::{ExposeSecret, SecretString};
use subtle::ConstantTimeEq;

/// 最低 memory 成本：19 MiB（§16.4 OWASP 基线）。
pub const MIN_MEMORY_KIB: u32 = 19 * 1024;

/// 最低迭代次数：2（§16.4 OWASP 基线）。
pub const MIN_ITERATIONS: u32 = 2;

/// 最低并行度：1（§16.4 OWASP 基线）。
pub const MIN_PARALLELISM: u32 = 1;

/// 盐长度：16 bytes（argon2 0.5.3 `RECOMMENDED_SALT_LEN`）。
pub const SALT_LEN_BYTES: usize = 16;

/// 哈希输出长度：32 bytes（argon2 0.5.3 `DEFAULT_OUTPUT_LEN`）。
pub const HASH_OUTPUT_LEN: usize = 32;

/// 存储 hash 的 salt 长度下限（argon2 0.5.3 `MIN_SALT_LEN`）。
const MIN_SALT_BYTES: usize = 8;

/// 存储 hash 的 salt 长度上限（解析期防御，防止恶意存储值引发大分配）。
const MAX_SALT_BYTES: usize = 64;

/// 存储 hash 的哈希段长度下限（argon2 0.5.3 `MIN_OUTPUT_LEN`）。
const MIN_HASH_BYTES: usize = 4;

/// 存储 hash 的哈希段长度上限（解析期防御）。
const MAX_HASH_BYTES: usize = 128;

/// 存储 hash 的 salt/hash 段的 base64 文本长度上限（解码前防御）。
const MAX_SALT_TEXT_LEN: usize = 128;
const MAX_HASH_TEXT_LEN: usize = 200;

/// Argon2id 参数（§16.4）。构造期校验，低于最低基线即拒绝（§13.4）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl PasswordParams {
    /// §16.4 OWASP 最低基线（19 MiB / 2 / 1），与 argon2 `Params::DEFAULT` 一致。
    ///
    /// 生产默认参数应通过目标平台基准确定并可以更高（§16.4）。
    pub const DEFAULT: Self = Self {
        memory_kib: MIN_MEMORY_KIB,
        iterations: MIN_ITERATIONS,
        parallelism: MIN_PARALLELISM,
    };

    /// 校验并构造：任一参数低于最低基线返回
    /// [`PasswordError::BelowMinimumBaseline`]（§16.4；降低基线必须经 Security ADR）。
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, PasswordError> {
        if memory_kib < MIN_MEMORY_KIB
            || iterations < MIN_ITERATIONS
            || parallelism < MIN_PARALLELISM
        {
            return Err(PasswordError::BelowMinimumBaseline {
                memory_kib,
                iterations,
                parallelism,
            });
        }
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    /// memory 成本（KiB）。
    pub const fn memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// 迭代次数。
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// 并行度。
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }

    fn to_argon2_params(self) -> Result<Params, PasswordError> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(HASH_OUTPUT_LEN),
        )
        .map_err(PasswordError::from)
    }
}

/// Argon2id 密码哈希器（§16.4）。构造时冻结参数。
///
/// 验证（[`PasswordHasher::verify`]）使用存储 hash 携带的参数重新计算并做
/// constant-time 比较（subtle 2.6.1），因此验证器自身的参数只影响新哈希的生成。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordHasher {
    params: PasswordParams,
}

impl Default for PasswordHasher {
    /// §16.4 OWASP 最低基线参数（19 MiB / 2 / 1）。
    fn default() -> Self {
        Self::new(PasswordParams::DEFAULT)
    }
}

impl PasswordHasher {
    /// 以指定参数构造哈希器（参数已在 [`PasswordParams::new`] 校验）。
    pub const fn new(params: PasswordParams) -> Self {
        Self { params }
    }

    /// 当前参数。
    pub const fn params(&self) -> PasswordParams {
        self.params
    }

    fn argon2(&self) -> Result<Argon2<'static>, PasswordError> {
        let params = self.params.to_argon2_params()?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// 哈希密码，返回 PHC 字符串。盐由 OS CSPRNG 生成（16 bytes）。
    pub fn hash(&self, password: &SecretString) -> Result<PasswordHashString, PasswordError> {
        let mut salt = [0u8; SALT_LEN_BYTES];
        getrandom::fill(&mut salt)?;
        let mut out = [0u8; HASH_OUTPUT_LEN];
        self.argon2()?
            .hash_password_into(password.expose_secret().as_bytes(), &salt, &mut out)?;
        Ok(PasswordHashString(format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            self.params.memory_kib(),
            self.params.iterations(),
            self.params.parallelism(),
            STANDARD_NO_PAD.encode(salt),
            STANDARD_NO_PAD.encode(out),
        )))
    }

    /// 验证密码与存储的 PHC 字符串。
    ///
    /// - 密码错误返回 [`PasswordError::Mismatch`]（与"hash 无效"区分，便于审计）；
    /// - 存储 hash 不可解析/参数不可用返回
    ///   [`PasswordError::InvalidStoredHash`] / [`PasswordError::InvalidStoredHashParams`]；
    /// - 验证不泄露密码与 hash 值（§16.6）。
    pub fn verify(&self, password: &SecretString, stored_hash: &str) -> Result<(), PasswordError> {
        let parsed = parse_stored_hash(stored_hash)?;
        // 使用存储 hash 携带的参数重新计算（PHC 标准，向后兼容）。
        let params = Params::new(
            parsed.memory_kib,
            parsed.iterations,
            parsed.parallelism,
            None,
        )
        .map_err(PasswordError::InvalidStoredHashParams)?;
        let context = Argon2::new(Algorithm::Argon2id, parsed.version, params);
        let mut out = vec![0u8; parsed.hash.len()];
        context
            .hash_password_into(password.expose_secret().as_bytes(), &parsed.salt, &mut out)
            .map_err(PasswordError::InvalidStoredHashParams)?;
        if bool::from(out.ct_eq(&parsed.hash)) {
            Ok(())
        } else {
            Err(PasswordError::Mismatch)
        }
    }
}

/// 存储���式的密码哈希（PHC 字符串，§16.4）。
///
/// 非秘密：它就是权威存储的值，`Debug` 如实显示（用于审计比对）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordHashString(String);

impl PasswordHashString {
    /// PHC 字符串原文（存储到权威 store 的值）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 存储 hash 的参数是否满足 §16.4 最低基线。
    ///
    /// 用于"登录时检测弱 hash → 重哈希"策略；hash 不可解析时返回错误。
    pub fn meets_minimum_baseline(&self) -> Result<bool, PasswordError> {
        let parsed = parse_stored_hash(&self.0)?;
        Ok(parsed.memory_kib >= MIN_MEMORY_KIB
            && parsed.iterations >= MIN_ITERATIONS
            && parsed.parallelism >= MIN_PARALLELISM)
    }
}

/// 解析后的存储 hash（内部表示，§16.4 PHC 格式）。
struct ParsedStoredHash {
    version: Version,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

/// 解析 PHC 字符串（`$argon2id$v=19$m=…,t=…,p=…$salt$hash`）。
///
/// - 只接受 `argon2id` 与 `v=16`/`v=19`（argon2 0.5 支持的版本）；
/// - 除 `m`/`t`/`p` 外的 PHC 参数忽略（argon2id 不使用，PHC 规范允许扩展参数）；
/// - 解码前对字段长度设上限（防御恶意存储值引发大分配，§32 oversized 提前拒绝）。
fn parse_stored_hash(stored: &str) -> Result<ParsedStoredHash, StoredHashParseError> {
    let fields: Vec<&str> = stored.split('$').collect();
    if fields.len() != 6 {
        return Err(StoredHashParseError::FieldCount);
    }
    if fields[1] != "argon2id" {
        return Err(StoredHashParseError::UnsupportedAlgorithm);
    }
    let version = match fields[2].strip_prefix("v=") {
        Some("16") => Version::V0x10,
        Some("19") => Version::V0x13,
        _ => return Err(StoredHashParseError::UnsupportedVersion),
    };
    let (memory_kib, iterations, parallelism) = parse_params(fields[3])?;

    if fields[4].len() > MAX_SALT_TEXT_LEN || fields[5].len() > MAX_HASH_TEXT_LEN {
        return Err(StoredHashParseError::TooLarge);
    }
    let salt = STANDARD_NO_PAD
        .decode(fields[4].as_bytes())
        .map_err(|_| StoredHashParseError::InvalidSalt)?;
    if !(MIN_SALT_BYTES..=MAX_SALT_BYTES).contains(&salt.len()) {
        return Err(StoredHashParseError::InvalidSalt);
    }
    let hash = STANDARD_NO_PAD
        .decode(fields[5].as_bytes())
        .map_err(|_| StoredHashParseError::InvalidHash)?;
    if !(MIN_HASH_BYTES..=MAX_HASH_BYTES).contains(&hash.len()) {
        return Err(StoredHashParseError::InvalidHash);
    }

    Ok(ParsedStoredHash {
        version,
        memory_kib,
        iterations,
        parallelism,
        salt,
        hash,
    })
}

/// 解析 PHC 参数段（`m=…,t=…,p=…`）。
fn parse_params(field: &str) -> Result<(u32, u32, u32), StoredHashParseError> {
    let mut memory_kib = None;
    let mut iterations = None;
    let mut parallelism = None;
    for item in field.split(',') {
        let Some((key, value)) = item.split_once('=') else {
            return Err(StoredHashParseError::InvalidParameter);
        };
        let parsed = value
            .parse::<u32>()
            .map_err(|_| StoredHashParseError::InvalidParameter)?;
        match key {
            "m" => memory_kib = Some(parsed),
            "t" => iterations = Some(parsed),
            "p" => parallelism = Some(parsed),
            _ => {} // PHC 允许其他参数；argon2id 只使用 m/t/p。
        }
    }
    match (memory_kib, iterations, parallelism) {
        (Some(memory_kib), Some(iterations), Some(parallelism)) => {
            Ok((memory_kib, iterations, parallelism))
        }
        _ => Err(StoredHashParseError::MissingParameter),
    }
}

/// 存储 hash 解析错误（封闭 typed error，§14.1；不携带 hash 内容）。
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum StoredHashParseError {
    /// 不是 6 个 `$` 分隔字段。
    #[error("PHC 字段数无效")]
    FieldCount,
    /// 算法不是 argon2id。
    #[error("不支持的哈希算法（仅 argon2id）")]
    UnsupportedAlgorithm,
    /// 版本不是 v=16 / v=19。
    #[error("不支持的版本（仅 v=16 / v=19）")]
    UnsupportedVersion,
    /// 缺少 m/t/p 参数。
    #[error("缺少 m/t/p 参数")]
    MissingParameter,
    /// 参数值不是合法十进制数。
    #[error("参数值无效")]
    InvalidParameter,
    /// salt 段编码或长度无效。
    #[error("salt 段无效")]
    InvalidSalt,
    /// hash 段编码或长度无效。
    #[error("hash 段无效")]
    InvalidHash,
    /// 字段超长（oversized 输入提前拒绝，§32）。
    #[error("存储 hash 字段超长")]
    TooLarge,
}

/// 密码哈希错误（封闭 typed error，§14.1；不携带任何密码/hash 内容）。
#[derive(Debug, thiserror::Error)]
pub enum PasswordError {
    /// 参数低于 §16.4 最低基线（OWASP 19 MiB / 2 / 1）。
    #[error(
        "密码哈希参数低于最低基线：memory={memory_kib} KiB, iterations={iterations}, parallelism={parallelism}（§16.4）"
    )]
    BelowMinimumBaseline {
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    },
    /// Argon2id 参数/计算失败（本哈希器配置侧）。
    #[error("Argon2id 参数或计算失败")]
    Argon2(#[from] argon2::Error),
    /// 存储 hash 解析失败。
    #[error("存储的密码哈希无效")]
    InvalidStoredHash(#[from] StoredHashParseError),
    /// 存储 hash 的参数无法用于验证（如低于 argon2 自身下限）。
    #[error("存储的密码哈希参数无法用于验证")]
    InvalidStoredHashParams(#[source] argon2::Error),
    /// 密码验证失败（密码不匹配）。
    #[error("密码不匹配")]
    Mismatch,
    /// OS CSPRNG 不可用。
    #[error("OS CSPRNG 不可用")]
    Rng(#[from] getrandom::Error),
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

    /// 弱参数 PHC 字符串（m=8 MiB, t=1, p=1；salt 16 字节零、hash 32 字节零，
    /// base64 为全 'A'）。只用于参数检查测试，不用于验证。
    fn weak_phc() -> String {
        format!(
            "$argon2id$v=19$m=8192,t=1,p=1${}${}",
            "A".repeat(22),
            "A".repeat(43)
        )
    }

    #[test]
    fn default_params_equal_owasp_baseline() {
        assert_eq!(PasswordParams::DEFAULT.memory_kib(), MIN_MEMORY_KIB);
        assert_eq!(PasswordParams::DEFAULT.iterations(), MIN_ITERATIONS);
        assert_eq!(PasswordParams::DEFAULT.parallelism(), MIN_PARALLELISM);
        // 与 argon2 0.5.3 默认值一致（同一 OWASP 基线）。
        assert_eq!(PasswordParams::DEFAULT.memory_kib(), Params::DEFAULT_M_COST);
        assert_eq!(PasswordParams::DEFAULT.iterations(), Params::DEFAULT_T_COST);
        assert_eq!(
            PasswordParams::DEFAULT.parallelism(),
            Params::DEFAULT_P_COST
        );
    }

    #[test]
    fn params_below_baseline_rejected() {
        // memory 低 1 KiB。
        assert!(matches!(
            PasswordParams::new(MIN_MEMORY_KIB - 1, MIN_ITERATIONS, MIN_PARALLELISM),
            Err(PasswordError::BelowMinimumBaseline { .. })
        ));
        // iterations 低 1。
        assert!(matches!(
            PasswordParams::new(MIN_MEMORY_KIB, MIN_ITERATIONS - 1, MIN_PARALLELISM),
            Err(PasswordError::BelowMinimumBaseline { .. })
        ));
        // parallelism 低 1。
        assert!(matches!(
            PasswordParams::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM - 1),
            Err(PasswordError::BelowMinimumBaseline { .. })
        ));
        // 三参数都低于基线。
        assert!(matches!(
            PasswordParams::new(8 * 1024, 1, 1),
            Err(PasswordError::BelowMinimumBaseline { .. })
        ));
    }

    #[test]
    fn params_at_baseline_accepted() {
        assert!(
            PasswordParams::new(MIN_MEMORY_KIB, MIN_ITERATIONS, MIN_PARALLELISM).is_ok(),
            "恰好等于基线必须被接受"
        );
        // 高于基线也接受。
        assert!(
            PasswordParams::new(2 * MIN_MEMORY_KIB, MIN_ITERATIONS + 1, MIN_PARALLELISM).is_ok()
        );
    }

    #[test]
    fn hash_verify_roundtrip() {
        let hasher = PasswordHasher::default();
        let password = SecretString::from("hunter2-super-secret");

        let stored = ok_or_fail(hasher.hash(&password), "hash");
        // PHC 格式：argon2id + v=19 + 基线参数（与 argon2 0.5.3 官方输出互操作）。
        assert!(
            stored
                .as_str()
                .starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "PHC 头不匹配: {}",
            stored.as_str()
        );
        assert!(stored.as_str().contains('$'), "PHC 必须含 salt 与 hash 段");

        ok_or_fail(hasher.verify(&password, stored.as_str()), "verify");

        let wrong = SecretString::from("wrong-password");
        assert!(matches!(
            hasher.verify(&wrong, stored.as_str()),
            Err(PasswordError::Mismatch)
        ));

        let ok = ok_or_fail(stored.meets_minimum_baseline(), "meets baseline");
        assert!(ok, "本 crate 产出的 hash 必须满足最低基线");
    }

    #[test]
    fn hashes_of_same_password_differ_by_salt() {
        let hasher = PasswordHasher::default();
        let password = SecretString::from("same-password");
        let first = ok_or_fail(hasher.hash(&password), "hash1");
        let second = ok_or_fail(hasher.hash(&password), "hash2");
        assert_ne!(first.as_str(), second.as_str(), "随机盐必须使两次哈希不同");
        // 两段盐不同（在 PHC 中位于倒数第二个字段）。
        assert_ne!(
            first.as_str().rsplit('$').nth(1),
            second.as_str().rsplit('$').nth(1)
        );
    }

    #[test]
    fn verify_accepts_hash_with_higher_params() {
        // 更高参数的存储 hash（PHC 参数来自存储值，验证器参数不影响验证）。
        let higher = ok_or_fail(
            PasswordParams::new(2 * MIN_MEMORY_KIB, MIN_ITERATIONS + 2, 2),
            "higher params",
        );
        let hasher = PasswordHasher::new(higher);
        let password = SecretString::from("upgrade-me");
        let stored = ok_or_fail(hasher.hash(&password), "hash");

        // 用默认（基线）验证器验证更高参数的 hash。
        let baseline_hasher = PasswordHasher::default();
        ok_or_fail(
            baseline_hasher.verify(&password, stored.as_str()),
            "verify with baseline hasher",
        );
    }

    #[test]
    fn weak_stored_hash_detected_by_baseline_check() {
        let weak_hash = PasswordHashString(weak_phc());
        let meets = ok_or_fail(weak_hash.meets_minimum_baseline(), "weak baseline");
        assert!(!meets, "m=8192,t=1,p=1 必须判定为低于基线");
    }

    #[test]
    fn malformed_stored_hash_rejected() {
        let malformed = PasswordHashString("not-a-phc-string".into());
        assert!(matches!(
            malformed.meets_minimum_baseline(),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::FieldCount
            ))
        ));

        let hasher = PasswordHasher::default();
        let password = SecretString::from("p");
        assert!(matches!(
            hasher.verify(&password, "not-a-phc-string"),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::FieldCount
            ))
        ));

        // 非 argon2id 算法。
        let wrong_alg = "$argon2i$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(matches!(
            hasher.verify(&password, wrong_alg),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::UnsupportedAlgorithm
            ))
        ));
        // 不支持的版本。
        let wrong_version = "$argon2id$v=17$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(matches!(
            hasher.verify(&password, wrong_version),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::UnsupportedVersion
            ))
        ));
        // 缺少参数。
        let missing_param = "$argon2id$v=19$m=19456,t=2$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(matches!(
            hasher.verify(&password, missing_param),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::MissingParameter
            ))
        ));
        // 参数值非法。
        let bad_param = "$argon2id$v=19$m=x,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(matches!(
            hasher.verify(&password, bad_param),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::InvalidParameter
            ))
        ));
        // 超长字段（oversized 提前拒绝，§32）。
        let oversized = format!(
            "$argon2id$v=19$m=19456,t=2,p=1${}${}",
            "A".repeat(MAX_SALT_TEXT_LEN + 1),
            "A".repeat(43)
        );
        assert!(matches!(
            hasher.verify(&password, &oversized),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::TooLarge
            ))
        ));
        // 空 salt / 空 hash 段。
        let empty_hash = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$";
        assert!(matches!(
            hasher.verify(&password, empty_hash),
            Err(PasswordError::InvalidStoredHash(
                StoredHashParseError::InvalidHash
            ))
        ));
    }

    #[test]
    fn hash_of_long_password_verifies() {
        // 输入边界：较长密码（1024 字节）与空密码都正常工作。
        let hasher = PasswordHasher::default();
        let long = SecretString::from("x".repeat(1024));
        let stored = ok_or_fail(hasher.hash(&long), "hash long");
        ok_or_fail(hasher.verify(&long, stored.as_str()), "verify long");

        let empty = SecretString::from("");
        let stored = ok_or_fail(hasher.hash(&empty), "hash empty");
        ok_or_fail(hasher.verify(&empty, stored.as_str()), "verify empty");
    }
}
