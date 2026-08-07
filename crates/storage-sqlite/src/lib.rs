#![forbid(unsafe_code)]

//! Operune SQLite 持久化 adapter（规范 §24.2：storage-sqlite）。
//!
//! SQLite schema、migration、repository adapter、Storage Executor
//! （§18）。SQLite 与 Tokio 之间由项目专用、有界、typed Storage Executor
//! 处理（§22.4），不得引入倒逼旧 SQLite/rusqlite 或模糊事务语义的 wrapper。
//!
//! 骨架阶段：暂无公开 API，按 YAGNI（§12.6）随真实需求增加。

// 骨架阶段无公开项。
