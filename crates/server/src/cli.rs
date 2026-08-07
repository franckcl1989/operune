//! Bootstrap/Recovery CLI 命令面（§16.3 / §22.7：clap 4.6.4，命令 typed、
//! 可测试）。
//!
//! # §16.3 语义
//!
//! - **bootstrap-admin**：本机显式创建首个管理员。密码**绝不**经命令行
//!   参数或环境变量传入（避免 shell history / process environment）——
//!   只从 stdin 读取（TTY 或管道；0.1 Windows 构建无 TTY 回显关闭——
//!   rpassword 不在 §23 冻结基线，见 [`read_password`] 文档）；
//! - **recover**：Web 不可用时恢复 Runtime 自身所需的最小操作面——
//!   safe mode 进入/退出（§21.1；RuntimeConfig 事务化标志）、Component
//!   列表/禁用/启用；不依赖 Component，也不依赖 Web 登录是否可用；
//! - **全部操作审计**（§16.3）：durable audit 随存储命令同事务写入
//!   （§18.7 fail closed：audit 失败 ⇒ 不提交）；读命令追加 audit；
//! - 不提供默认用户名/密码组合（§16.3）。

use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use operune_platform::BootstrapConfigPath;
use operune_security::password::PasswordHasher;
use operune_storage_sqlite::StorageExecutor;
use secrecy::SecretString;

use crate::audit;
use crate::bootstrap::BootstrapConfig;
use crate::error::ServerError;

/// 密码最大长度（字节）：有界输入，§7.4 host-buffer 纪律。
const MAX_PASSWORD_BYTES: usize = 1024;

/// 本地 CLI 默认管理员用户名（§16.3：系统不提供默认密码；用户名只是
/// bootstrap 时使用的标识，本机显式操作）。
const DEFAULT_ADMIN_USERNAME: &str = "admin";

/// RuntimeConfig 中 safe mode 的标志键（§18.0 RuntimeConfig 语义；
/// §21.1 safe mode/recovery）。
const SAFE_MODE_CONFIG_KEY: &str = "runtime.safe_mode";

/// CLI I/O 接线（可注入：测试用内存 reader/writer，生产用 stdin/stdout/
/// stderr）。
pub struct CliIo<'a> {
    /// 密码与提示输入源（§16.3：密码只从 stdin）。
    pub stdin: &'a mut dyn BufRead,
    /// 命令输出。
    pub stdout: &'a mut dyn Write,
    /// 提示与警告。
    pub stderr: &'a mut dyn Write,
}

/// CLI 顶层命令（typed、可测试，§22.7）。
#[derive(Debug, Parser)]
#[command(
    name = "operune-server",
    version,
    about = "Operune Core Runtime binary (composition root, spec §24.2)"
)]
pub struct Cli {
    /// `--config <path>` 只选择整份 BootstrapConfig（§18.0：无单项覆盖、
    /// 无环境变量覆盖、无多 TOML merge）；缺省用平台默认路径。
    #[arg(long, global = true, value_name = "PATH", value_parser = parse_bootstrap_config_path)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

/// 顶层子命令。
#[derive(Debug, Subcommand)]
pub enum Command {
    /// 启动 Core Runtime 服务器（§24.2 composition root）。
    Serve,
    /// 打印版本并退出（不打开存储，不产生 audit——durable audit 目标在
    /// 存储打开后才存在，§16.3）。
    Version,
    /// 打印本机 Runtime 状态（存储/recovery 报告/safe mode/admin 用户/
    /// 磁盘预算）；操作本身也写入 audit。
    Status,
    /// 本机显式 bootstrap：创建首个管理员（§16.3）。密码只从 stdin 读取，
    /// 绝不从命令行参数或环境变量传入。
    BootstrapAdmin {
        /// 管理员用户名（非 secret）。
        #[arg(long, default_value = DEFAULT_ADMIN_USERNAME, value_name = "NAME")]
        username: String,
    },
    /// Recovery plane（§16.3：Web 不可用时恢复 Runtime 自身；全部审计；
    /// 不依赖 Component/Web 登录）。
    Recover {
        #[command(subcommand)]
        action: RecoverAction,
    },
}

/// recovery 动作（§16.3 最小操作面）。
#[derive(Debug, Subcommand)]
pub enum RecoverAction {
    /// 进入 safe mode（§21.1：RuntimeConfig 标志，事务化并审计）。
    EnterSafeMode,
    /// 退出 safe mode。
    ExitSafeMode,
    /// Component 最小操作（列表/禁用/启用，§16.3）。
    Component {
        #[command(subcommand)]
        action: ComponentAction,
    },
}

/// Component recovery 动作。
#[derive(Debug, Subcommand)]
pub enum ComponentAction {
    /// 列出安装实例（含生命周期状态/enabled/当前 active 版本）。
    List,
    /// 禁用安装实例（停止接受请求，§39.2）。
    Disable {
        /// 安装实例 ID（UUID 字面量）。
        installation_id: String,
    },
    /// 启用安装实例。
    Enable {
        /// 安装实例 ID（UUID 字面量）。
        installation_id: String,
    },
}

/// `--config <path>` 的 CLI 边界校验（§13.3：边界解析一次；
/// §18.0：只选择整份 BootstrapConfig）。
fn parse_bootstrap_config_path(value: &str) -> Result<PathBuf, String> {
    BootstrapConfigPath::new(PathBuf::from(value))
        .map(BootstrapConfigPath::into_path)
        .map_err(|error| error.to_string())
}

/// CLI 入口：分派并返回进程退出码（0 = 成功；1 = 失败；clap 自身的
/// help/parse 错误在 `Cli::parse` 中处理）。
pub async fn run(cli: Cli, io: &mut CliIo<'_>) -> i32 {
    let result = dispatch(cli, io).await;
    match result {
        Ok(()) => 0,
        Err(error) => {
            let _ = writeln!(io.stderr, "error: {error}");
            1
        }
    }
}

/// 分派（纯路由，无业务规则）。
async fn dispatch(cli: Cli, io: &mut CliIo<'_>) -> Result<(), ServerError> {
    match cli.command {
        Command::Serve => crate::server::serve_cli(cli.config).await,
        Command::Version => run_version(io),
        Command::Status => run_status(cli.config, io).await,
        Command::BootstrapAdmin { username } => run_bootstrap_admin(cli.config, username, io).await,
        Command::Recover { action } => run_recover(cli.config, action, io).await,
    }
}

/// 命令上下文：BootstrapConfig + 已打开的 StorageExecutor。
struct CommandContext {
    /// 宿主启动事实（§18.0）。
    config: BootstrapConfig,
    /// 已打开存储（§18.2）。
    executor: StorageExecutor,
}

/// 打开命令上下文（§18.0 路径解析 → 配置加载 → 存储打开，fail closed）。
async fn open_context(config_arg: Option<PathBuf>) -> Result<CommandContext, ServerError> {
    let resolver = crate::server::platform_resolver();
    let path = crate::config::resolve_config_path(config_arg, resolver.as_ref())?;
    let config = crate::bootstrap::load_from_path(&path)?;
    let executor = StorageExecutor::open(crate::config::executor_config(&config)?).await?;
    Ok(CommandContext { config, executor })
}

/// 关闭存储（§18.2：shutdown 等待 worker 排空，不 detached）。
async fn close_context(ctx: CommandContext) -> Result<(), ServerError> {
    ctx.executor.shutdown().await.map_err(ServerError::from)
}

/// 命令的统一收尾：
/// - 失败时记录 failure audit（§16.3 全部审计：失败也审计）；
/// - 始终显式关闭存储（§18.2）；
/// - 主错误优先于关闭错误（关闭失败不掩盖主失败）。
async fn finish_command(
    ctx: CommandContext,
    action: &str,
    target: Option<String>,
    result: Result<(), ServerError>,
) -> Result<(), ServerError> {
    if let Err(error) = &result {
        // §16.3：失败审计（best effort；主错误优先）。
        let _ = audit::record_failure(&ctx.executor, action, target, error.to_string()).await;
    }
    match (result, close_context(ctx).await) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

/// `version` 命令：不打开存储，不产生 audit（§16.3：durable audit 目标
/// 在存储打开后才存在）。
fn run_version(io: &mut CliIo<'_>) -> Result<(), ServerError> {
    writeln!(io.stdout, "operune-server {}", env!("CARGO_PKG_VERSION"))
        .map_err(|source| ServerError::Output { source })
}

/// `status` 命令（§21.1 管理面只读信息；操作本身审计）。
async fn run_status(config_arg: Option<PathBuf>, io: &mut CliIo<'_>) -> Result<(), ServerError> {
    let ctx = open_context(config_arg).await?;
    let result = status_inner(&ctx, io).await;
    finish_command(ctx, audit::ACTION_STATUS, None, result).await
}

async fn status_inner(ctx: &CommandContext, io: &mut CliIo<'_>) -> Result<(), ServerError> {
    let report = ctx.executor.recovery_report().await?;
    let safe_mode = ctx
        .executor
        .get_config(SAFE_MODE_CONFIG_KEY.to_string())
        .await?;
    let admin = ctx
        .executor
        .get_user_by_username(DEFAULT_ADMIN_USERNAME.to_string())
        .await?;
    let usage = ctx.executor.get_budget_usage().await?;
    let installations = ctx.executor.list_installations().await?;

    writeln!(io.stdout, "operune-server {}", env!("CARGO_PKG_VERSION"))
        .map_err(|source| ServerError::Output { source })?;
    writeln!(io.stdout, "data root: {}", ctx.config.data_root.display())
        .map_err(|source| ServerError::Output { source })?;
    let safe_mode = match safe_mode {
        Some(entry) => entry.value == "true",
        None => false,
    };
    writeln!(
        io.stdout,
        "safe mode: {}",
        if safe_mode { "enabled" } else { "disabled" }
    )
    .map_err(|source| ServerError::Output { source })?;
    match admin {
        Some(record) => writeln!(
            io.stdout,
            "admin user: {} (id {}, disabled: {})",
            record.username, record.user_id, record.disabled
        )
        .map_err(|source| ServerError::Output { source })?,
        None => writeln!(io.stdout, "admin user: none (run `bootstrap-admin`)")
            .map_err(|source| ServerError::Output { source })?,
    }
    writeln!(
        io.stdout,
        "artifact budget usage: staging={} quarantine={} final={}",
        usage.staging.as_u64(),
        usage.quarantine.as_u64(),
        usage.final_store.as_u64()
    )
    .map_err(|source| ServerError::Output { source })?;
    if report.is_empty() {
        writeln!(io.stdout, "recovery report: clean")
            .map_err(|source| ServerError::Output { source })?;
    } else {
        writeln!(io.stdout, "recovery report: {} action(s)", report.len())
            .map_err(|source| ServerError::Output { source })?;
        for action in &report {
            writeln!(io.stdout, "  recovery: {action:?}")
                .map_err(|source| ServerError::Output { source })?;
        }
    }

    // §16.3：读操作同样审计（durable；失败 fail closed）。
    let event = audit::recovery_event(
        audit::ACTION_STATUS,
        None,
        operune_storage_sqlite::model::AuditOutcome::Success,
        Some(format!(
            "status: {} installation(s), {} recovery action(s)",
            installations.len(),
            report.len()
        )),
    )?;
    ctx.executor.append_audit(event).await?;
    Ok(())
}

/// `bootstrap-admin` 命令（§16.3：本机显式创建首个管理员）。
async fn run_bootstrap_admin(
    config_arg: Option<PathBuf>,
    username: String,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    let ctx = open_context(config_arg).await?;
    let result = bootstrap_admin_inner(&ctx, username.clone(), io).await;
    finish_command(
        ctx,
        audit::ACTION_BOOTSTRAP_ADMIN_CREATE,
        Some(username),
        result,
    )
    .await
}

async fn bootstrap_admin_inner(
    ctx: &CommandContext,
    username: String,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    // §16.3：系统不提供默认用户名/密码组合；首个管理员必须本机显式创建，
    // 且不覆盖已存在的用户（用户名校验由存储层执行，§13.3）。
    let existing = ctx.executor.get_user_by_username(username.clone()).await?;
    if existing.is_some() {
        return Err(ServerError::Cli(format!(
            "admin user {username:?} already exists; bootstrap-admin creates the first admin only (§16.3)"
        )));
    }

    // §16.3：密码只从 stdin 读取（TTY 或管道），绝不从 argv/env 传入。
    let password = read_password(io)?;

    // §16.4：Argon2id 哈希（OWASP 最低基线参数；盐 OS CSPRNG 生成）。
    let hasher = PasswordHasher::default();
    let hash = hasher.hash(&password).map_err(ServerError::Hash)?;

    // §18.7：用户 + 审计同事务写入；audit 写入失败 ⇒ 不提交（fail closed）。
    let event = audit::user_event(
        audit::ACTION_BOOTSTRAP_ADMIN_CREATE,
        Some(username.clone()),
        operune_storage_sqlite::model::AuditOutcome::Success,
        Some("first admin created via local bootstrap CLI (§16.3)".into()),
    )?;
    let user_id = ctx
        .executor
        .create_user(username.clone(), hash.as_str().to_string(), event)
        .await?;
    writeln!(
        io.stdout,
        "created admin user {username:?} (user id {user_id})"
    )
    .map_err(|source| ServerError::Output { source })
}

/// 从 stdin 读取密码（§16.3）。
///
/// # 实现说明（0.1 Windows 构建）
///
/// - 密码**绝不**经命令行参数或环境变量传入；本函数只从 stdin 读取单行；
/// - TTY 回显关闭：rpassword 不在 §23 冻结依赖基线，本构建不引入；在
///   交互终端输入时密码**会回显**（main 入口已向 stderr 提示）；推荐
///   从可信管道注入（`echo`/密钥管理器）或等待后续安全读取支持；
/// - 有界输入：最多 [`MAX_PASSWORD_BYTES`] 字节（§7.4 host-buffer 纪律）；
/// - 返回 [`SecretString`]（secrecy：drop 时清零，§16.6）。
pub fn read_password(io: &mut CliIo<'_>) -> Result<SecretString, ServerError> {
    let _ = io.stderr.write_all(b"Password: ");
    let _ = io.stderr.flush();
    // 有界读取：超过上限后 read_line 返回部分行，长度检查拒绝（§32）。
    let mut line = String::new();
    let read = io
        .stdin
        .take((MAX_PASSWORD_BYTES + 2) as u64)
        .read_line(&mut line)
        .map_err(|source| ServerError::PasswordRead { source })?;
    if read == 0 {
        return Err(ServerError::Cli(
            "no password provided on stdin (EOF)".into(),
        ));
    }
    // 去掉行尾换行（\n 与 \r\n 均处理）。
    if line.ends_with('\n') {
        line.pop();
        if line.ends_with('\r') {
            line.pop();
        }
    }
    if line.is_empty() {
        return Err(ServerError::Cli("password must not be empty".into()));
    }
    if line.len() > MAX_PASSWORD_BYTES {
        return Err(ServerError::Cli(format!(
            "password must not exceed {MAX_PASSWORD_BYTES} bytes"
        )));
    }
    // 移入 SecretString（secrecy 拥有缓冲，drop 时清零，§16.6）。
    Ok(SecretString::from(line))
}

/// `recover` 命令分派（§16.3）。
async fn run_recover(
    config_arg: Option<PathBuf>,
    action: RecoverAction,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    match action {
        RecoverAction::EnterSafeMode => {
            let ctx = open_context(config_arg).await?;
            let result = safe_mode_inner(&ctx, true, io).await;
            finish_command(ctx, audit::ACTION_RECOVER_SAFE_MODE_ENTER, None, result).await
        }
        RecoverAction::ExitSafeMode => {
            let ctx = open_context(config_arg).await?;
            let result = safe_mode_inner(&ctx, false, io).await;
            finish_command(ctx, audit::ACTION_RECOVER_SAFE_MODE_EXIT, None, result).await
        }
        RecoverAction::Component { action } => match action {
            ComponentAction::List => {
                let ctx = open_context(config_arg).await?;
                let result = component_list_inner(&ctx, io).await;
                finish_command(ctx, audit::ACTION_RECOVER_COMPONENT_LIST, None, result).await
            }
            ComponentAction::Disable { installation_id } => {
                run_component_set_enabled(config_arg, installation_id, false, io).await
            }
            ComponentAction::Enable { installation_id } => {
                run_component_set_enabled(config_arg, installation_id, true, io).await
            }
        },
    }
}

/// safe mode 进入/退出（§21.1：RuntimeConfig 事务化标志；§18.0
/// RuntimeConfig 语义——事务化、版本化并审计）。
async fn safe_mode_inner(
    ctx: &CommandContext,
    enter: bool,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    let action = if enter {
        audit::ACTION_RECOVER_SAFE_MODE_ENTER
    } else {
        audit::ACTION_RECOVER_SAFE_MODE_EXIT
    };
    let current = ctx
        .executor
        .get_config(SAFE_MODE_CONFIG_KEY.to_string())
        .await?;
    let already = match current {
        Some(entry) => entry.value == "true",
        None => false,
    };
    if already == enter {
        return Err(ServerError::Cli(format!(
            "safe mode is already {}",
            if enter { "enabled" } else { "disabled" }
        )));
    }
    let event = audit::recovery_event(
        action,
        None,
        operune_storage_sqlite::model::AuditOutcome::Success,
        Some(format!(
            "safe mode {}",
            if enter { "entered" } else { "exited" }
        )),
    )?;
    // §18.7：配置 + 审计同事务写入（audit 失败 ⇒ 不提交，fail closed）。
    ctx.executor
        .set_config(
            SAFE_MODE_CONFIG_KEY.to_string(),
            if enter { "true" } else { "false" }.to_string(),
            event,
        )
        .await?;
    writeln!(
        io.stdout,
        "safe mode {}",
        if enter { "entered" } else { "exited" }
    )
    .map_err(|source| ServerError::Output { source })
}

/// Component 列表（§16.3 最小操作面；读操作也审计）。
async fn component_list_inner(ctx: &CommandContext, io: &mut CliIo<'_>) -> Result<(), ServerError> {
    let installations = ctx.executor.list_installations().await?;
    for record in &installations {
        let active = ctx
            .executor
            .get_active_binding(record.installation_id)
            .await?;
        let active = active
            .map(|binding| format!("{} @ {}", binding.component_version, binding.content_digest))
            .unwrap_or_else(|| "none".to_string());
        writeln!(
            io.stdout,
            "{}\t{}\tstate={}\tenabled={}\tactive={}",
            record.installation_id,
            record.component_id,
            record.lifecycle_state,
            record.enabled,
            active
        )
        .map_err(|source| ServerError::Output { source })?;
    }
    let event = audit::recovery_event(
        audit::ACTION_RECOVER_COMPONENT_LIST,
        None,
        operune_storage_sqlite::model::AuditOutcome::Success,
        Some(format!("{} installation(s)", installations.len())),
    )?;
    ctx.executor.append_audit(event).await?;
    Ok(())
}

/// Component 禁用/启用（§16.3 最小操作面；§39.2 enable/disable 事实）。
async fn run_component_set_enabled(
    config_arg: Option<PathBuf>,
    installation_id: String,
    enabled: bool,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    let action = if enabled {
        audit::ACTION_RECOVER_COMPONENT_ENABLE
    } else {
        audit::ACTION_RECOVER_COMPONENT_DISABLE
    };
    let ctx = open_context(config_arg).await?;
    let result = component_set_enabled_inner(&ctx, installation_id.clone(), enabled, io).await;
    finish_command(ctx, action, Some(installation_id), result).await
}

async fn component_set_enabled_inner(
    ctx: &CommandContext,
    installation_id: String,
    enabled: bool,
    io: &mut CliIo<'_>,
) -> Result<(), ServerError> {
    // §13.3 边界解析一次：UUID 字面量 → InstallationId。
    let installation = installation_id
        .parse::<operune_domain::InstallationId>()
        .map_err(|error| {
            ServerError::Cli(format!(
                "invalid installation id {installation_id:?}: {error}"
            ))
        })?;
    let action = if enabled {
        audit::ACTION_RECOVER_COMPONENT_ENABLE
    } else {
        audit::ACTION_RECOVER_COMPONENT_DISABLE
    };
    let event = audit::recovery_event(
        action,
        Some(installation_id.clone()),
        operune_storage_sqlite::model::AuditOutcome::Success,
        Some(format!(
            "installation {} {}",
            installation_id,
            if enabled { "enabled" } else { "disabled" }
        )),
    )?;
    // §18.7：变更 + 审计同事务写入（audit 失败 ⇒ 不提交，fail closed）。
    ctx.executor
        .set_installation_enabled(installation, enabled, event)
        .await?;
    writeln!(
        io.stdout,
        "installation {installation_id} {}",
        if enabled { "enabled" } else { "disabled" }
    )
    .map_err(|source| ServerError::Output { source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use operune_storage_sqlite::StorageError;
    use secrecy::ExposeSecret;
    use std::io::Cursor;

    /// 断言式取值助手（§14.2：测试不允许 unwrap/expect）。
    fn ok<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => unreachable!("{context}: expected Ok, got {error}"),
        }
    }

    /// 测试 I/O 视图：注入 stdin 文本、捕获 stdout/stderr。
    struct TestIo {
        stdin: Cursor<Vec<u8>>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl TestIo {
        fn new(stdin_text: &str) -> Self {
            Self {
                stdin: Cursor::new(stdin_text.as_bytes().to_vec()),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        }

        fn io(&mut self) -> CliIo<'_> {
            CliIo {
                stdin: &mut self.stdin,
                stdout: &mut self.stdout,
                stderr: &mut self.stderr,
            }
        }

        fn stdout_text(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }

        fn stderr_text(&self) -> String {
            String::from_utf8_lossy(&self.stderr).into_owned()
        }
    }

    /// 写一个最小 BootstrapConfig 到临时目录并返回路径。
    fn write_config(dir: &std::path::Path) -> std::path::PathBuf {
        let path = dir.join("operune.toml");
        let data_root = dir.join("data");
        std::fs::write(
            &path,
            format!(
                "data_root = {:?}\n[admin]\nlisten_address = \"127.0.0.1\"\nport = 8787\n",
                data_root.to_string_lossy()
            ),
        )
        .ok();
        path
    }

    fn tempdir() -> tempfile::TempDir {
        match tempfile::tempdir() {
            Ok(dir) => dir,
            Err(_) => unreachable!("tempdir must succeed"),
        }
    }

    // ---- clap 解析（typed、可测试，§22.7） ----

    #[test]
    fn clap_parses_version_command() {
        let cli = ok(Cli::try_parse_from(["operune-server", "version"]), "parse");
        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn clap_parses_bootstrap_admin_with_username() {
        let cli = ok(
            Cli::try_parse_from(["operune-server", "bootstrap-admin", "--username", "root"]),
            "parse",
        );
        assert!(matches!(
            cli.command,
            Command::BootstrapAdmin { username } if username == "root"
        ));
    }

    #[test]
    fn clap_parses_bootstrap_admin_default_username() {
        let cli = ok(
            Cli::try_parse_from(["operune-server", "bootstrap-admin"]),
            "parse",
        );
        assert!(matches!(
            cli.command,
            Command::BootstrapAdmin { username } if username == DEFAULT_ADMIN_USERNAME
        ));
    }

    #[test]
    fn clap_parses_recover_subcommands() {
        let cli = ok(
            Cli::try_parse_from(["operune-server", "recover", "enter-safe-mode"]),
            "parse",
        );
        assert!(matches!(
            cli.command,
            Command::Recover {
                action: RecoverAction::EnterSafeMode
            }
        ));

        let cli = ok(
            Cli::try_parse_from(["operune-server", "recover", "component", "list"]),
            "parse",
        );
        assert!(matches!(
            cli.command,
            Command::Recover {
                action: RecoverAction::Component {
                    action: ComponentAction::List
                }
            }
        ));

        let cli = ok(
            Cli::try_parse_from([
                "operune-server",
                "recover",
                "component",
                "disable",
                "11111111-2222-3333-4444-555555555555",
            ]),
            "parse",
        );
        assert!(matches!(
            cli.command,
            Command::Recover {
                action: RecoverAction::Component {
                    action: ComponentAction::Disable { installation_id }
                }
            } if installation_id == "11111111-2222-3333-4444-555555555555"
        ));
    }

    #[test]
    fn clap_global_config_flag_works_before_and_after_subcommand() {
        let cli = ok(
            Cli::try_parse_from(["operune-server", "--config", "a.toml", "version"]),
            "parse before",
        );
        assert_eq!(cli.config, Some(PathBuf::from("a.toml")));

        let cli = ok(
            Cli::try_parse_from(["operune-server", "status", "--config", "b.toml"]),
            "parse after",
        );
        assert_eq!(cli.config, Some(PathBuf::from("b.toml")));
    }

    #[test]
    fn clap_rejects_invalid_config_path() {
        assert!(Cli::try_parse_from(["operune-server", "--config", "", "version"]).is_err());
        assert!(
            Cli::try_parse_from(["operune-server", "version", "--config", "a\0b.toml"]).is_err()
        );
    }

    #[test]
    fn clap_rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["operune-server", "frobnicate"]).is_err());
    }

    #[test]
    fn clap_rejects_missing_recover_action() {
        assert!(Cli::try_parse_from(["operune-server", "recover"]).is_err());
    }

    // ---- 密码读取（§16.3：只从 stdin；argv/env 无入口） ----

    #[test]
    fn read_password_from_pipe() {
        let mut io = TestIo::new("s3cret-password\n");
        let password = ok(read_password(&mut io.io()), "read");
        assert_eq!(password.expose_secret(), "s3cret-password");
        // stderr 上有提示，stdout 干净（可管道化输出）。
        assert!(io.stderr_text().contains("Password:"));
        assert!(io.stdout_text().is_empty());
    }

    #[test]
    fn read_password_strips_crlf() {
        let mut io = TestIo::new("s3cret\r\n");
        let password = ok(read_password(&mut io.io()), "read");
        assert_eq!(password.expose_secret(), "s3cret");
    }

    #[test]
    fn read_password_rejects_eof() {
        let mut io = TestIo::new("");
        assert!(matches!(
            read_password(&mut io.io()),
            Err(ServerError::Cli(detail)) if detail.contains("EOF")
        ));
    }

    #[test]
    fn read_password_rejects_empty_line() {
        let mut io = TestIo::new("\n");
        assert!(matches!(
            read_password(&mut io.io()),
            Err(ServerError::Cli(detail)) if detail.contains("empty")
        ));
    }

    #[test]
    fn read_password_rejects_oversized_input() {
        // 有界输入（§7.4 / §32）：超过上限拒绝，不整块读入内存。
        let huge = format!("{}x\n", "a".repeat(MAX_PASSWORD_BYTES + 1));
        let mut io = TestIo::new(&huge);
        assert!(matches!(
            read_password(&mut io.io()),
            Err(ServerError::Cli(detail)) if detail.contains("must not exceed")
        ));
    }

    // ---- 端到端命令（真实临时存储） ----

    /// 构造命令上下文（临时 data root + 打开存储）。
    async fn open_test_context(dir: &std::path::Path) -> CommandContext {
        let config_text = match std::fs::read_to_string(write_config(dir)) {
            Ok(text) => text,
            Err(_) => unreachable!("config written by test must be readable"),
        };
        let config = match crate::bootstrap::parse(&config_text) {
            Ok(config) => config,
            Err(_) => unreachable!("config written by test must parse"),
        };
        let executor = ok(
            StorageExecutor::open(ok(
                crate::config::executor_config(&config),
                "executor config",
            ))
            .await,
            "open storage",
        );
        CommandContext { config, executor }
    }

    /// 命令 future 类型（统一装箱：inner 都是 async fn 项）。
    ///
    /// 无 `+ Send`：命令捕获 `&mut CliIo`，而 stdin/stdout/stderr 的
    /// 生产锁柄（StdinLock/StdoutLock/StderrLock，Windows 上内含
    /// ReentrantLockGuard/RefCell）不满足 Send；`#[tokio::test]` 的
    /// current_thread + block_on 不要求 Send（§16.3 CLI 测试面）。
    type CommandFuture<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ServerError>> + 'a>>;

    /// 测试用例骨架：打开上下文 → 运行 → 关闭 → 返回 (结果, io)。
    ///
    /// `CliIo` 由本函数创建并借给命令（统一生命周期 'a：ctx / cli_io /
    /// future 都受 'a 约束——闭包把传入的 `&mut CliIo` 原样转交 inner，
    /// 不产生悬挂临时值）。
    async fn run_case(
        dir: &std::path::Path,
        stdin_text: &str,
        command: impl for<'a> FnOnce(&'a CommandContext, &'a mut CliIo<'a>) -> CommandFuture<'a>,
    ) -> (Result<(), ServerError>, TestIo) {
        let ctx = open_test_context(dir).await;
        let mut io = TestIo::new(stdin_text);
        let mut cli_io = io.io();
        let result = command(&ctx, &mut cli_io).await;
        let close = ctx.executor.shutdown().await;
        let result = match (result, close) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Ok(()), Ok(())) => Ok(()),
        };
        (result, io)
    }

    #[tokio::test]
    async fn bootstrap_admin_creates_user_with_hashed_password_and_audit() {
        let dir = tempdir();
        let (result, _io) = run_case(dir.path(), "s3cret-password\n", |ctx, io| {
            Box::pin(bootstrap_admin_inner(ctx, "admin".into(), io))
        })
        .await;
        ok(result, "bootstrap admin");

        // 重新打开存储验证持久事实（§18.1 权威存储）。
        let ctx = open_test_context(dir.path()).await;
        let record = some(
            ok(
                ctx.executor.get_user_by_username("admin".into()).await,
                "get user",
            ),
            "admin user must exist",
        );
        assert_eq!(record.username, "admin");
        assert!(
            record.password_hash.starts_with("$argon2id$"),
            "only an Argon2id PHC hash must be stored (§16.4), got {}",
            record.password_hash
        );
        // 哈希可验证（§16.4：验证使用存储 hash 携带的参数）。
        let hasher = PasswordHasher::default();
        ok(
            hasher.verify(
                &SecretString::from("s3cret-password"),
                &record.password_hash,
            ),
            "verify password",
        );
        // 审计记录（§16.3 全部审计；用户创建与审计同事务，§18.7）。
        let events = ok(ctx.executor.list_audit_recent(10).await, "list audit");
        assert!(
            events
                .iter()
                .any(|event| event.action == audit::ACTION_BOOTSTRAP_ADMIN_CREATE),
            "bootstrap admin create must be audited"
        );
        ok(ctx.executor.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn bootstrap_admin_refuses_second_admin() {
        let dir = tempdir();
        // 预置第一个 admin（顺序打开/关闭，避免并发连接，§18.2 单连接）。
        {
            let ctx = open_test_context(dir.path()).await;
            let event = ok(
                audit::user_event(
                    audit::ACTION_BOOTSTRAP_ADMIN_CREATE,
                    Some("admin".into()),
                    operune_storage_sqlite::model::AuditOutcome::Success,
                    None,
                ),
                "seed event",
            );
            ok(
                ctx.executor
                    .create_user(
                        "admin".into(),
                        "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA".into(),
                        event,
                    )
                    .await,
                "seed first admin",
            );
            ok(ctx.executor.shutdown().await, "shutdown seed");
        }
        // 走完整命令路径（open_context + inner + finish_command）：失败
        // 审计由 finish_command 统一落盘（§16.3 全部审计；§18.7 fail closed）。
        let mut io = TestIo::new("another-password\n");
        let result =
            run_bootstrap_admin(Some(write_config(dir.path())), "admin".into(), &mut io.io()).await;
        assert!(matches!(
            result,
            Err(ServerError::Cli(detail)) if detail.contains("already exists")
        ));
        // 失败同样审计（§16.3 全部审计）。
        let ctx = open_test_context(dir.path()).await;
        let events = ok(ctx.executor.list_audit_recent(10).await, "list audit");
        assert!(
            events
                .iter()
                .any(|event| event.action == audit::ACTION_BOOTSTRAP_ADMIN_CREATE
                    && event.outcome == operune_storage_sqlite::model::AuditOutcome::Failure),
            "failed bootstrap admin must be audited"
        );
        ok(ctx.executor.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn safe_mode_enter_exit_roundtrip() {
        let dir = tempdir();
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(safe_mode_inner(ctx, true, io))
        })
        .await;
        ok(result, "enter safe mode");

        // 重复进入 → 显式拒绝（§16.3 最小操作面语义；确定性失败）。
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(safe_mode_inner(ctx, true, io))
        })
        .await;
        assert!(matches!(result, Err(ServerError::Cli(_))));

        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(safe_mode_inner(ctx, false, io))
        })
        .await;
        ok(result, "exit safe mode");

        let ctx = open_test_context(dir.path()).await;
        let entry = some(
            ok(
                ctx.executor
                    .get_config(SAFE_MODE_CONFIG_KEY.to_string())
                    .await,
                "get safe mode",
            ),
            "safe mode flag",
        );
        assert_eq!(
            entry.value, "false",
            "flag must be persisted (事务化, §18.0)"
        );
        // 进入/退出/拒绝都被审计（§16.3）。
        let events = ok(ctx.executor.list_audit_recent(100).await, "list audit");
        for action in [
            audit::ACTION_RECOVER_SAFE_MODE_ENTER,
            audit::ACTION_RECOVER_SAFE_MODE_EXIT,
        ] {
            assert!(
                events.iter().any(|event| event.action == action),
                "action {action} must be audited"
            );
        }
        ok(ctx.executor.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn component_disable_unknown_installation_fails_closed() {
        let dir = tempdir();
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(component_set_enabled_inner(
                ctx,
                "11111111-2222-3333-4444-555555555555".into(),
                false,
                io,
            ))
        })
        .await;
        assert!(matches!(
            result,
            Err(ServerError::Storage(StorageError::NotFound(_)))
        ));
    }

    #[tokio::test]
    async fn component_disable_rejects_malformed_id() {
        let dir = tempdir();
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(component_set_enabled_inner(
                ctx,
                "not-a-uuid".into(),
                false,
                io,
            ))
        })
        .await;
        assert!(matches!(
            result,
            Err(ServerError::Cli(detail)) if detail.contains("installation id")
        ));
    }

    #[tokio::test]
    async fn component_list_and_disable_end_to_end() {
        let dir = tempdir();
        // 预置一个安装实例（§19.2 最小安装路径：stage→quarantine→candidate→
        // install，用 storage typed API 直接驱动）。
        let installation = {
            let ctx = open_test_context(dir.path()).await;
            let limit = ok(operune_domain::ByteSize::mib(16), "limit");
            let staged = ok(
                ctx.executor.stage_bytes(b"bytes".to_vec(), limit).await,
                "stage",
            );
            let digest = staged.digest;
            ok(
                ctx.executor
                    .record_quarantine(staged, audit_event("test"))
                    .await,
                "quarantine",
            );
            ok(
                ctx.executor
                    .commit_candidate(
                        digest,
                        ok(
                            operune_domain::ComponentId::new("com.example.demo"),
                            "component id",
                        ),
                        ok(
                            "1.0.0".parse::<operune_domain::ComponentVersion>(),
                            "version",
                        ),
                        audit_event("candidate"),
                    )
                    .await,
                "candidate",
            );
            let installation = ok(
                ctx.executor
                    .create_installation(
                        ok(
                            operune_domain::ComponentId::new("com.example.demo"),
                            "component id",
                        ),
                        audit_event("install"),
                    )
                    .await,
                "install",
            );
            ok(ctx.executor.shutdown().await, "shutdown seed");
            installation
        };

        // 列表：1 个安装、enabled=true。
        let (result, io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(component_list_inner(ctx, io))
        })
        .await;
        ok(result, "list");
        assert!(io.stdout_text().contains(&installation.to_string()));

        // 禁用 → enabled=false（§39.2；变更 + 审计同事务）。
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(component_set_enabled_inner(
                ctx,
                installation.to_string(),
                false,
                io,
            ))
        })
        .await;
        ok(result, "disable");
        {
            let ctx = open_test_context(dir.path()).await;
            let record = some(
                ok(
                    ctx.executor.get_installation(installation).await,
                    "get installation",
                ),
                "installation",
            );
            assert!(!record.enabled, "must be disabled after recover disable");
            ok(ctx.executor.shutdown().await, "shutdown");
        }

        // 重新启用（恢复路径对称操作）。
        let (result, _io) = run_case(dir.path(), "", |ctx, io| {
            Box::pin(component_set_enabled_inner(
                ctx,
                installation.to_string(),
                true,
                io,
            ))
        })
        .await;
        ok(result, "enable");

        // 全部操作都审计（§16.3）。
        let ctx = open_test_context(dir.path()).await;
        let events = ok(ctx.executor.list_audit_recent(100).await, "list audit");
        for action in [
            audit::ACTION_RECOVER_COMPONENT_LIST,
            audit::ACTION_RECOVER_COMPONENT_DISABLE,
            audit::ACTION_RECOVER_COMPONENT_ENABLE,
        ] {
            assert!(
                events.iter().any(|event| event.action == action),
                "action {action} must be audited"
            );
        }
        ok(ctx.executor.shutdown().await, "shutdown");
    }

    #[tokio::test]
    async fn status_reports_fresh_storage_and_audits_itself() {
        let dir = tempdir();
        let (result, io) =
            run_case(dir.path(), "", |ctx, io| Box::pin(status_inner(ctx, io))).await;
        ok(result, "status");
        let text = io.stdout_text();
        assert!(text.contains("operune-server"));
        assert!(text.contains("safe mode: disabled"));
        assert!(text.contains("admin user: none"));

        let ctx = open_test_context(dir.path()).await;
        let events = ok(ctx.executor.list_audit_recent(10).await, "list audit");
        assert!(
            events
                .iter()
                .any(|event| event.action == audit::ACTION_STATUS),
            "status itself must be audited (§16.3)"
        );
        ok(ctx.executor.shutdown().await, "shutdown");
    }

    #[test]
    fn version_command_prints_version_without_storage() {
        let mut io = TestIo::new("");
        ok(run_version(&mut io.io()), "version");
        assert!(
            io.stdout_text()
                .contains(&format!("operune-server {}", env!("CARGO_PKG_VERSION"))),
            "version output mismatch: {}",
            io.stdout_text()
        );
        // version 不打开存储 ⇒ 不产生 audit（durable audit 目标在存储打开
        // 后才存在，§16.3）。
        assert!(io.stderr_text().is_empty());
    }

    /// 测试用存储审计事件。
    fn audit_event(action: &str) -> operune_storage_sqlite::model::AuditEvent {
        ok(
            operune_storage_sqlite::model::AuditEvent::new(
                operune_storage_sqlite::model::AuditActor::System,
                operune_storage_sqlite::model::AuditCategory::ComponentLifecycle,
                action,
                None,
                operune_storage_sqlite::model::AuditOutcome::Success,
                None,
            ),
            "audit event",
        )
    }

    /// 断言式 Option 取值。
    fn some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => unreachable!("{context}: expected Some"),
        }
    }
}
