#![forbid(unsafe_code)]

//! Operune WASI 0.2 adapter（规范 §24.2：runtime-wasi-p2）。
//!
//! 所有 WASI 0.2 linker / context / binding 适配；这里是未来标准版本替换点
//! （§8）。0.1.0 production 仅启用 WASI 0.2，p3 Host 不得进入 production
//! dependency closure（§4.2 / §22.2）。
//!
//! 骨架阶段：暂无公开 API，按 YAGNI（§12.6）随真实需求增加。

// 骨架阶段无公开项。
