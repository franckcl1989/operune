#![forbid(unsafe_code)]

//! Operune Core Runtime 二进制入口（composition root，规范 §24.2：server）。
//!
//! 唯一 binary；只负责配置、构造和 wiring，禁止业务规则藏在 main.rs。
//! 骨架阶段：仅打印版本与启动占位并返回，不允许业务逻辑（YAGNI §12.6）。

fn main() {
    println!(
        "operune-server {} (skeleton: version probe only, no runtime services)",
        env!("CARGO_PKG_VERSION")
    );
}
