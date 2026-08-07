#![forbid(unsafe_code)]

//! Operune Core Runtime 唯一二进制入口（§24.2 / §10：单二进制交付）。
//!
//! **薄壳**：只做参数收集（clap）与 stdin/stdout/stderr 接线，然后进入
//! lib 的 `cli::run`。全部配置、构造与 wiring（composition root）在
//! `operune_server` lib 的模块中；**业务规则禁止落入本文件**（§24.2
//! 硬约束）。

use std::io::IsTerminal;

use clap::Parser;

use operune_server::cli::{Cli, CliIo};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // §16.3：密码只从 stdin 读取（绝不 argv/env）。0.1 Windows 构建没有
    // TTY 回显关闭（rpassword 不在 §23 冻结基线）：交互终端输入时密码
    // 会回显，进入 bootstrap-admin 前向 stderr 提示（仅提示，不收集）。
    if matches!(
        cli.command,
        operune_server::cli::Command::BootstrapAdmin { .. }
    ) && std::io::stdin().is_terminal()
    {
        eprintln!(
            "warning: password will be echoed (no TTY echo-off in this build; \
             prefer piping via a trusted source, see cli::read_password docs)"
        );
    }

    // 锁柄存为具名局部变量，CliIo 持有其 `&mut` 引用（'a 生命周期）。
    let mut stdin_handle = std::io::stdin().lock();
    let mut stdout_handle = std::io::stdout().lock();
    let mut stderr_handle = std::io::stderr().lock();
    let mut io = CliIo {
        stdin: &mut stdin_handle,
        stdout: &mut stdout_handle,
        stderr: &mut stderr_handle,
    };
    let code = operune_server::cli::run(cli, &mut io).await;
    std::process::exit(code);
}
