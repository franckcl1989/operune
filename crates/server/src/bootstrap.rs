//! BootstrapConfig：单个 TOML 文件的宿主启动事实解析（§18.0）。
//!
//! # §18.0 语义（本模块严格执行）
//!
//! - **单个 TOML 文件**：`data_root`、Root Admin listener、TLS identity
//!   引用、启动期日志、artifact 磁盘预算等"打开 Runtime 之前必须知道"的
//!   宿主事实；RuntimeConfig（数据库打开后才可读）不在本模块；
//! - **路径解析确定**：`--config <path>` 只选择整份 BootstrapConfig
//!   （clap 参数 → `operune_platform::BootstrapConfigPath` 校验）；无单项
//!   override、无环境变量覆盖、无多 TOML merge、无隐式优先级（MUST NOT）；
//! - **私钥值不得入配置**：`[tls]` 只允许文件路径引用（§18.0 / §16.2）；
//!   文本中含 PEM 段标记（`-----BEGIN`）直接拒绝且不把原文回显进错误；
//! - **管理员密码不得出现在任何配置**：bootstrap 用 CLI 完成（§16.3）；
//! - **fail closed**：文件缺失/不可读、TOML 解析失败、字段缺失/非法、
//!   未知键、安全不变量不满足 ⇒ 一律返回 [`BootstrapError`]，绝不带默认
//!   值继续启动。
//!
//! # TOML 形状（0.1.0 冻结）
//!
//! ```toml
//! # 必需：绝对路径（Windows 或 Unix 风格；相对路径拒绝，fail closed）。
//! data_root = "C:\\Users\\dev\\AppData\\Local\\operune"
//!
//! # 可选；缺省 = loopback（§16.1 默认只绑定 127.0.0.1）。
//! [admin]
//! listen_address = "127.0.0.1"   # 仅 IP 字面量
//! port = 8787                    # 1..=65535
//!
//! # 可选；一旦出现两键都必需，且只允许路径引用（§16.2）。
//! [tls]
//! cert_chain = "certs/chain.pem"
//! private_key = "certs/key.pem"
//!
//! # 可选；缺省 = info / compact（§22.7）。
//! [logging]
//! level = "info"                 # trace|debug|info|warn|error
//! format = "compact"             # compact|json
//!
//! # 可选；缺省 = storage-sqlite 的 DiskBudget 默认值（§18.7）。
//! [storage]
//! staging_budget_mib = 256
//! quarantine_budget_mib = 1024
//! artifacts_budget_mib = 8192
//! ```
//!
//! 未知顶层键与未知小节内键一律拒绝（fail closed：防止拼写错误被静默
//! 忽略；旧二进制对新字段 fail closed 是安全方向）。

use std::collections::BTreeSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use operune_storage_sqlite::artifact::DiskBudget;

/// Root Admin listener 默认地址：loopback（§16.1）。
pub const DEFAULT_ADMIN_ADDRESS: &str = "127.0.0.1";

/// Root Admin listener 默认端口。
pub const DEFAULT_ADMIN_PORT: u16 = 8787;

/// TOML 中不允许出现的 PEM 段标记（§16.2：私钥值不得入配置文本）。
const PEM_SECTION_MARKER: &str = "-----BEGIN";

/// toml 解析错误文本的截断上限（§16.6 防御：解析错误详情不泄漏配置原文）。
const MAX_PARSE_ERROR_DETAIL: usize = 256;

/// BootstrapConfig 文件大小上限（§32：oversized 输入提前拒绝；配置文件
/// 实际只有几百字节，64 KiB 是宽裕的有界上限）。
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// BootstrapConfig：宿主启动事实（§18.0）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConfig {
    /// 宿主数据根目录（绝对路径；经 `operune_platform::DataRoot` 校验）。
    pub data_root: PathBuf,
    /// Root Admin listener（默认 loopback，§16.1）。
    pub admin: AdminListener,
    /// TLS identity 路径引用（§16.2；`None` = 未配置 TLS）。
    pub tls: Option<TlsIdentityRef>,
    /// 启动期日志（§22.7）。
    pub logging: LoggingConfig,
    /// artifact 磁盘预算（§18.7）。
    pub storage: StorageConfig,
}

/// Root Admin listener（§16.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminListener {
    /// 监听地址（IP 字面量；默认 loopback）。
    pub address: IpAddr,
    /// 监听端口。
    pub port: u16,
}

/// TLS identity 的**路径引用**（§16.2：绝不内嵌私钥值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentityRef {
    /// 证书链 PEM 文件路径。
    pub cert_chain: PathBuf,
    /// 私钥 PEM 文件路径。
    pub private_key: PathBuf,
}

/// 启动期日志配置（§22.7）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoggingConfig {
    /// 默认过滤级别。
    pub level: LogLevel,
    /// 输出格式。
    pub format: LogFormat,
}

/// 日志级别（闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// trace。
    Trace,
    /// debug。
    Debug,
    /// info。
    Info,
    /// warn。
    Warn,
    /// error。
    Error,
}

impl LogLevel {
    /// 解析日志级别（§13.3 边界解析一次；未知值 fail closed）。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "trace" => Ok(Self::Trace),
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "invalid logging level {other:?} (expected trace|debug|info|warn|error)"
            )),
        }
    }
}

/// 日志输出格式（闭集）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// 人类可读紧凑格式。
    Compact,
    /// 每行一个 JSON 对象。
    Json,
}

impl LogFormat {
    /// 解析日志格式（未知值 fail closed）。
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "compact" => Ok(Self::Compact),
            "json" => Ok(Self::Json),
            other => Err(format!(
                "invalid logging format {other:?} (expected compact|json)"
            )),
        }
    }
}

/// artifact 磁盘预算（§18.7 宿主事实）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageConfig {
    /// 三个空间（staging / quarantine / final）的硬上限。
    pub budget: DiskBudget,
}

/// BootstrapConfig 加载/解析/校验错误（§14.1 封闭 typed error）。
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// 配置文件不可读（§18.0 fail closed）。
    #[error("bootstrap config file {path:?} is not readable: {source}")]
    Read {
        /// 文件路径（路径不是 secret，§16.6）。
        path: PathBuf,
        /// 底层 I/O 错误。
        #[source]
        source: std::io::Error,
    },

    /// TOML 解析失败（§18.0 fail closed；详情截断，§16.6）。
    #[error("bootstrap config parse failed: {detail}")]
    Parse {
        /// 可诊断原因（截断，不含配置原文）。
        detail: String,
    },

    /// 字段缺失/类型非法/取值非法（§18.0 fail closed）。
    #[error("bootstrap config validation failed: {detail}")]
    Validation {
        /// 可诊断原因。
        detail: String,
    },

    /// 未知键（fail closed：防止拼写错误被静默忽略）。
    #[error("unknown key {key:?} in bootstrap config (fail closed, §18.0)")]
    UnknownKey {
        /// 未知键名。
        key: String,
    },

    /// 私钥值内嵌（§16.2：配置只允许路径引用；拒绝且不回显原文）。
    #[error(
        "private key value embedded in bootstrap config field {field:?}: only path references are allowed (§18.0 / §16.2)"
    )]
    EmbeddedSecretValue {
        /// 违规字段名（静态字符串）。
        field: &'static str,
    },
}

/// 从文件加载并解析 BootstrapConfig（§18.0：缺失/不可读 fail closed）。
///
/// 有界读取（§32）：文件超过 [`MAX_CONFIG_BYTES`] 字节时提前拒绝（超出
/// 上限后 `read_to_string` 返回部分内容，长度检查拒绝）。
pub fn load_from_path(path: &Path) -> Result<BootstrapConfig, BootstrapError> {
    let mut text = String::new();
    let file = std::fs::File::open(path).map_err(|source| BootstrapError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let read = file
        .take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|source| BootstrapError::Read {
            path: path.to_path_buf(),
            source,
        })?;
    if read as u64 > MAX_CONFIG_BYTES {
        return Err(BootstrapError::Validation {
            detail: format!("bootstrap config exceeds {MAX_CONFIG_BYTES} bytes"),
        });
    }
    parse(&text)
}

/// 解析 BootstrapConfig 文本（§13.3 边界解析一次：TOML → Value → typed）。
pub fn parse(text: &str) -> Result<BootstrapConfig, BootstrapError> {
    // §16.2 防御第一层：原始文本含 PEM 段标记 ⇒ 立即拒绝，错误不回显原文。
    if text.contains(PEM_SECTION_MARKER) {
        return Err(BootstrapError::EmbeddedSecretValue {
            field: "config text",
        });
    }
    let value: toml::Value = toml::from_str(text).map_err(|error| {
        let detail = error.to_string();
        let truncated: String = detail.chars().take(MAX_PARSE_ERROR_DETAIL).collect();
        BootstrapError::Parse { detail: truncated }
    })?;
    parse_value(&value)
}

/// 顶层键集合（fail closed：未知键拒绝）。
const TOP_LEVEL_KEYS: [&str; 5] = ["data_root", "admin", "tls", "logging", "storage"];

fn parse_value(value: &toml::Value) -> Result<BootstrapConfig, BootstrapError> {
    let table = value.as_table().ok_or_else(|| BootstrapError::Validation {
        detail: "bootstrap config must be a TOML table".into(),
    })?;
    reject_unknown_keys(table, &TOP_LEVEL_KEYS, None)?;

    let data_root = parse_data_root(table)?;
    let admin = parse_admin(table)?;
    let tls = parse_tls(table)?;
    let logging = parse_logging(table)?;
    let storage = parse_storage(table)?;

    Ok(BootstrapConfig {
        data_root,
        admin,
        tls,
        logging,
        storage,
    })
}

/// 校验路径字符串：非空、有效 UTF-8、不含 NUL、不含换行/回车、
/// 不含 PEM 段标记（§16.2 防御第二层）。
fn validate_path_text(value: &str, field: &'static str) -> Result<(), BootstrapError> {
    if value.is_empty() {
        return Err(BootstrapError::Validation {
            detail: format!("{field} must not be empty"),
        });
    }
    if value.contains('\0') {
        return Err(BootstrapError::Validation {
            detail: format!("{field} must not contain NUL"),
        });
    }
    if value.contains('\n') || value.contains('\r') {
        return Err(BootstrapError::EmbeddedSecretValue { field });
    }
    if value.contains(PEM_SECTION_MARKER) {
        return Err(BootstrapError::EmbeddedSecretValue { field });
    }
    Ok(())
}

fn parse_data_root(table: &toml::map::Map<String, toml::Value>) -> Result<PathBuf, BootstrapError> {
    let value = table
        .get("data_root")
        .ok_or_else(|| BootstrapError::Validation {
            detail: "missing required key `data_root`".into(),
        })?;
    let text = value.as_str().ok_or_else(|| BootstrapError::Validation {
        detail: "`data_root` must be a string path".into(),
    })?;
    validate_path_text(text, "data_root")?;
    let path = PathBuf::from(text);
    // §18.0：绝对路径（跨平台校验 + 平台默认路径语义）。
    operune_platform::DataRoot::new(path.clone()).map_err(|error| BootstrapError::Validation {
        detail: format!("invalid `data_root`: {error}"),
    })?;
    Ok(path)
}

fn parse_admin(
    table: &toml::map::Map<String, toml::Value>,
) -> Result<AdminListener, BootstrapError> {
    let default_address =
        IpAddr::from_str(DEFAULT_ADMIN_ADDRESS).map_err(|error| BootstrapError::Validation {
            detail: format!("internal error: default admin address invalid: {error}"),
        })?;
    let Some(section) = table.get("admin") else {
        return Ok(AdminListener {
            address: default_address,
            port: DEFAULT_ADMIN_PORT,
        });
    };
    let section = section
        .as_table()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[admin]` must be a table".into(),
        })?;
    reject_unknown_keys(section, &["listen_address", "port"], Some("admin"))?;

    let address = match section.get("listen_address") {
        Some(value) => {
            let text = value.as_str().ok_or_else(|| BootstrapError::Validation {
                detail: "`admin.listen_address` must be a string IP address".into(),
            })?;
            IpAddr::from_str(text).map_err(|_| BootstrapError::Validation {
                detail: format!("`admin.listen_address` is not a valid IP address: {text:?}"),
            })?
        }
        None => default_address,
    };
    let port = match section.get("port") {
        Some(value) => {
            let raw = value
                .as_integer()
                .ok_or_else(|| BootstrapError::Validation {
                    detail: "`admin.port` must be an integer".into(),
                })?;
            u16::try_from(raw).map_err(|_| BootstrapError::Validation {
                detail: format!("`admin.port` must be in 1..=65535, got {raw}"),
            })?
        }
        None => DEFAULT_ADMIN_PORT,
    };
    if port == 0 {
        return Err(BootstrapError::Validation {
            detail: "`admin.port` must be in 1..=65535, got 0".into(),
        });
    }
    Ok(AdminListener { address, port })
}

fn parse_tls(
    table: &toml::map::Map<String, toml::Value>,
) -> Result<Option<TlsIdentityRef>, BootstrapError> {
    let Some(section) = table.get("tls") else {
        return Ok(None);
    };
    let section = section
        .as_table()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[tls]` must be a table".into(),
        })?;
    reject_unknown_keys(section, &["cert_chain", "private_key"], Some("tls"))?;
    let cert_chain = section
        .get("cert_chain")
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[tls]` requires `cert_chain` (path reference only, §16.2)".into(),
        })?;
    let private_key = section
        .get("private_key")
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[tls]` requires `private_key` (path reference only, §16.2)".into(),
        })?;
    let cert_chain = cert_chain
        .as_str()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`tls.cert_chain` must be a string path".into(),
        })?;
    let private_key = private_key
        .as_str()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`tls.private_key` must be a string path".into(),
        })?;
    validate_path_text(cert_chain, "tls.cert_chain")?;
    validate_path_text(private_key, "tls.private_key")?;
    Ok(Some(TlsIdentityRef {
        cert_chain: PathBuf::from(cert_chain),
        private_key: PathBuf::from(private_key),
    }))
}

fn parse_logging(
    table: &toml::map::Map<String, toml::Value>,
) -> Result<LoggingConfig, BootstrapError> {
    let Some(section) = table.get("logging") else {
        return Ok(LoggingConfig {
            level: LogLevel::Info,
            format: LogFormat::Compact,
        });
    };
    let section = section
        .as_table()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[logging]` must be a table".into(),
        })?;
    reject_unknown_keys(section, &["level", "format"], Some("logging"))?;

    let level = match section.get("level") {
        Some(value) => {
            let text = value.as_str().ok_or_else(|| BootstrapError::Validation {
                detail: "`logging.level` must be a string".into(),
            })?;
            LogLevel::parse(text).map_err(|detail| BootstrapError::Validation { detail })?
        }
        None => LogLevel::Info,
    };
    let format = match section.get("format") {
        Some(value) => {
            let text = value.as_str().ok_or_else(|| BootstrapError::Validation {
                detail: "`logging.format` must be a string".into(),
            })?;
            LogFormat::parse(text).map_err(|detail| BootstrapError::Validation { detail })?
        }
        None => LogFormat::Compact,
    };
    Ok(LoggingConfig { level, format })
}

fn parse_storage(
    table: &toml::map::Map<String, toml::Value>,
) -> Result<StorageConfig, BootstrapError> {
    let Some(section) = table.get("storage") else {
        return Ok(StorageConfig {
            budget: DiskBudget::default(),
        });
    };
    let section = section
        .as_table()
        .ok_or_else(|| BootstrapError::Validation {
            detail: "`[storage]` must be a table".into(),
        })?;
    reject_unknown_keys(
        section,
        &[
            "staging_budget_mib",
            "quarantine_budget_mib",
            "artifacts_budget_mib",
        ],
        Some("storage"),
    )?;

    let default = DiskBudget::default();
    let staging = parse_budget_mib(section, "staging_budget_mib", default.staging())?;
    let quarantine = parse_budget_mib(section, "quarantine_budget_mib", default.quarantine())?;
    let artifacts = parse_budget_mib(section, "artifacts_budget_mib", default.artifacts())?;
    Ok(StorageConfig {
        budget: DiskBudget::new(staging, quarantine, artifacts),
    })
}

fn parse_budget_mib(
    section: &toml::map::Map<String, toml::Value>,
    key: &str,
    fallback: operune_domain::ByteSize,
) -> Result<operune_domain::ByteSize, BootstrapError> {
    let Some(value) = section.get(key) else {
        return Ok(fallback);
    };
    let mib = value
        .as_integer()
        .ok_or_else(|| BootstrapError::Validation {
            detail: format!("`storage.{key}` must be an integer (MiB)"),
        })?;
    let mib = u64::try_from(mib).map_err(|_| BootstrapError::Validation {
        detail: format!("`storage.{key}` must be non-negative, got {mib}"),
    })?;
    operune_domain::ByteSize::mib(mib).map_err(|error| BootstrapError::Validation {
        detail: format!("`storage.{key}` invalid: {error}"),
    })
}

/// 拒绝未知键（§18.0 fail closed：拼写错误不得被静默忽略）。
fn reject_unknown_keys(
    table: &toml::map::Map<String, toml::Value>,
    allowed: &[&str],
    section: Option<&str>,
) -> Result<(), BootstrapError> {
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    for key in table.keys() {
        if !allowed.contains(key.as_str()) {
            let label = match section {
                Some(section) => format!("{section}.{key}"),
                None => key.clone(),
            };
            return Err(BootstrapError::UnknownKey { key: label });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 断言式取值助手（§14.2：测试不允许 unwrap/expect）。
    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    fn err<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> E {
        match result {
            Err(error) => error,
            Ok(_) => unreachable!("{context}: expected Err"),
        }
    }

    /// 平台无关的绝对 data root（§18.0：data_root 必须绝对）。
    fn absolute_root() -> std::path::PathBuf {
        std::env::temp_dir().join("operune-bootstrap-test")
    }

    /// 以 TOML literal string（单引号）嵌入路径：不做转义处理，Windows
    /// 反斜杠原样合法（§13.3 边界解析一次）。
    fn root_decl() -> String {
        format!("data_root = '{}'", absolute_root().to_string_lossy())
    }

    fn full_config() -> String {
        format!(
            r#"
data_root = '{root}'

[admin]
listen_address = "127.0.0.1"
port = 8787

[tls]
cert_chain = "certs/chain.pem"
private_key = "certs/key.pem"

[logging]
level = "debug"
format = "json"

[storage]
staging_budget_mib = 256
quarantine_budget_mib = 1024
artifacts_budget_mib = 8192
"#,
            root = absolute_root().to_string_lossy()
        )
    }

    #[test]
    fn parses_full_config() {
        let config = ok(parse(&full_config()), "full config");
        assert_eq!(config.data_root, absolute_root());
        assert_eq!(config.admin.address.to_string(), "127.0.0.1");
        assert_eq!(config.admin.port, 8787);
        let tls = match config.tls {
            Some(tls) => tls,
            None => unreachable!("tls must be configured in this test"),
        };
        assert_eq!(tls.cert_chain, PathBuf::from("certs/chain.pem"));
        assert_eq!(tls.private_key, PathBuf::from("certs/key.pem"));
        assert_eq!(config.logging.level, LogLevel::Debug);
        assert_eq!(config.logging.format, LogFormat::Json);
        assert_eq!(
            config.storage.budget.staging(),
            ok(operune_domain::ByteSize::mib(256), "staging")
        );
    }

    #[test]
    fn defaults_when_sections_omitted() {
        let config = ok(parse(&root_decl()), "minimal config");
        assert_eq!(config.admin.address.to_string(), DEFAULT_ADMIN_ADDRESS);
        assert_eq!(config.admin.port, DEFAULT_ADMIN_PORT);
        assert_eq!(config.tls, None);
        assert_eq!(config.logging.level, LogLevel::Info);
        assert_eq!(config.logging.format, LogFormat::Compact);
        assert_eq!(config.storage.budget, DiskBudget::default());
    }

    #[test]
    fn empty_and_whitespace_rejected() {
        // toml 把空串/纯空白解析为空表，随后因缺 data_root 在
        // validate 阶段拒绝——无论 Parse 还是 Validation 都算 fail closed。
        assert!(parse("").is_err());
        assert!(parse("   \n\t  ").is_err());
    }

    #[test]
    fn invalid_toml_fails_closed() {
        assert!(matches!(
            parse("data_root = [1, 2,"),
            Err(BootstrapError::Parse { .. })
        ));
        assert!(matches!(
            parse("not a table at all"),
            Err(BootstrapError::Parse { .. })
        ));
    }

    #[test]
    fn non_table_root_fails_closed() {
        assert!(matches!(
            parse("data_root"),
            Err(BootstrapError::Parse { .. })
        ));
        // 非表根（如裸值 "42"）：toml 按语法拒绝或按非表校验拒绝，
        // 两种路径都 fail closed（§13.3 边界解析一次）。
        assert!(parse("42").is_err());
    }

    #[test]
    fn missing_data_root_fails_closed() {
        assert!(matches!(
            parse("[admin]\nport = 8787"),
            Err(BootstrapError::Validation { detail })
                if detail.contains("data_root")
        ));
    }

    #[test]
    fn relative_data_root_fails_closed() {
        assert!(matches!(
            parse("data_root = 'relative/operune'"),
            Err(BootstrapError::Validation { detail })
                if detail.contains("data_root")
        ));
        assert!(matches!(
            parse("data_root = 'operune'"),
            Err(BootstrapError::Validation { detail })
                if detail.contains("data_root")
        ));
    }

    #[test]
    fn empty_or_nul_data_root_fails_closed() {
        assert!(matches!(
            parse("data_root = ''"),
            Err(BootstrapError::Validation { .. })
        ));
        // TOML basic string 的 NUL 转义 -> 实际 NUL 字符 -> 拒绝（§13.3）。
        assert!(matches!(
            parse("data_root = \"a\\u0000b\""),
            Err(BootstrapError::Validation { .. })
        ));
    }

    #[test]
    fn unknown_top_level_key_fails_closed() {
        assert!(matches!(
            parse(&format!("{}\ntypo_key = 1", root_decl())),
            Err(BootstrapError::UnknownKey { key })
                if key == "typo_key"
        ));
    }

    #[test]
    fn unknown_section_key_fails_closed() {
        assert!(matches!(
            parse(&format!("{}\n[admin]\nlistene_address = \"127.0.0.1\"", root_decl())),
            Err(BootstrapError::UnknownKey { key })
                if key == "admin.listene_address"
        ));
        assert!(matches!(
            parse(&format!("{}\n[tls]\ncert_chain = \"a.pem\"\nkey = \"b.pem\"", root_decl())),
            Err(BootstrapError::UnknownKey { key })
                if key == "tls.key"
        ));
    }

    #[test]
    fn embedded_private_key_value_rejected_without_echo() {
        // §16.2：私钥值内嵌必须拒绝，且错误不得回显 PEM 原文（§16.6）。
        let text = format!(
            "{}\n[tls]\nprivate_key = \"-----BEGIN PRIVATE KEY-----\\nabc\\n-----END PRIVATE KEY-----\"\ncert_chain = \"c.pem\"",
            root_decl()
        );
        let error = err(parse(&text), "embedded pem");
        let message = format!("{error}");
        assert!(!message.contains("BEGIN PRIVATE KEY"));
        assert!(!message.contains("abc"));
        assert!(message.contains("path references"));
    }

    #[test]
    fn embedded_key_detected_even_before_toml_parse() {
        // 解析失败路径也不得回显原文：原始文本含 PEM 标记即整体拒绝。
        let text = format!(
            "{}\nnot valid toml [\n-----BEGIN PRIVATE KEY-----",
            root_decl()
        );
        let error = err(parse(&text), "raw scan");
        let message = format!("{error}");
        assert!(!message.contains("PRIVATE KEY"));
        assert!(matches!(error, BootstrapError::EmbeddedSecretValue { .. }));
    }

    #[test]
    fn tls_section_requires_both_paths() {
        assert!(matches!(
            parse(&format!("{}\n[tls]\ncert_chain = \"c.pem\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("private_key")
        ));
        assert!(matches!(
            parse(&format!("{}\n[tls]\nprivate_key = \"k.pem\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("cert_chain")
        ));
        assert!(matches!(
            parse(&format!("{}\n[tls]", root_decl())),
            Err(BootstrapError::Validation { .. })
        ));
    }

    #[test]
    fn invalid_admin_values_fail_closed() {
        assert!(matches!(
            parse(&format!("{}\n[admin]\nlisten_address = \"not-an-ip\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("listen_address")
        ));
        assert!(matches!(
            parse(&format!("{}\n[admin]\nport = 0", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("port")
        ));
        assert!(matches!(
            parse(&format!("{}\n[admin]\nport = 70000", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("port")
        ));
        assert!(matches!(
            parse(&format!("{}\n[admin]\nport = \"8787\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("port")
        ));
    }

    #[test]
    fn invalid_logging_values_fail_closed() {
        assert!(matches!(
            parse(&format!("{}\n[logging]\nlevel = \"verbose\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("level")
        ));
        assert!(matches!(
            parse(&format!("{}\n[logging]\nformat = \"yaml\"", root_decl())),
            Err(BootstrapError::Validation { detail })
                if detail.contains("format")
        ));
    }

    #[test]
    fn negative_budget_fails_closed() {
        assert!(matches!(
            parse(&format!(
                "{}\n[storage]\nstaging_budget_mib = -1",
                root_decl()
            )),
            Err(BootstrapError::Validation { .. })
        ));
    }

    #[test]
    fn load_from_path_fails_closed_when_missing() {
        let missing = Path::new("C:\\operune-test-config-does-not-exist.toml");
        assert!(matches!(
            load_from_path(missing),
            Err(BootstrapError::Read { .. })
        ));
    }

    #[test]
    fn load_from_path_rejects_oversized_file() {
        // §32：oversized 输入提前拒绝（有界读取，不整块读入内存）。
        let dir = match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(_) => unreachable!("tempdir must succeed"),
        };
        let path = dir.path().join("huge.toml");
        let oversized = format!(
            "data_root = '{}'\n# {}\n",
            absolute_root().to_string_lossy(),
            "x".repeat(MAX_CONFIG_BYTES as usize + 1)
        );
        std::fs::write(&path, oversized).ok();
        assert!(matches!(
            load_from_path(&path),
            Err(BootstrapError::Validation { detail })
                if detail.contains("exceeds")
        ));
    }
}
