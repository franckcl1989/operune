//! 0.3.0 Stateful Runtime（§41.2）——SecretStore port 与 secret grant 集
//! port（application 定义，storage-sqlite 接线实现）。
//!
//! 语义（契约面 `operune:secret@0.1.0` secret.wit，已提交稳定；§41.2
//! 独立 SecretStore port 与 secret grant/read semantics；§16.6 防泄漏
//! 边界；ADR-0001 密文 envelope）：
//!
//! - **本 port 不含任何明文**：值永远经 security 层（[`SecretCipher`]，
//!   crates/security）加解密；本 port 只承载**不透明密文 BLOB**（storage
//!   不解密、不解释、不回显内容）与**非敏感元数据**（名称/版本）；
//! - 读侧（ciphertext）由 [`crate::secret::SecretService`] 按 grant 集
//!   检查后解密；管理侧（put/delete/list）是 Root Admin / Core 系统面
//!   的轮换与枚举；
//! - **密文边界（§16.6 / ADR-0001，已裁决）**：KEK 绝不进入存储库；
//!   普通 SQLite metadata 表不保存明文 secret。
//!
//! [`SecretGrantPort`] 与 [`crate::ports::GrantStorePort`] 分开定义的原因：
//! 既有 grant 模型（`InstallationGrant` = capability + [`GrantScope`]）
//! 的 scope 变体集被 web-admin 等多处穷尽匹配（闭集），无法在不破坏
//! 其他 crate 的前提下新增名称级 scope 变体；§17.3 "secret names" 是
//! scope 维度之一，因此名称集以独立 port 面表达——storage 接线层从
//! grants 表筛选 `operune:secret/secret` 能力面的名称范围实现。

use operune_domain::{InstallationId, SecretMetadata, SecretName, SecretVersion};

use crate::error::ErrorSource;

/// secret 存储错误（封闭 typed error，§14.1；**错误文本不含明文与密钥
/// 材料**，§16.6）。
#[derive(Debug, thiserror::Error)]
pub enum SecretStoreError {
    /// 名称或安装实例不存在。
    #[error("secret not found: {0}")]
    NotFound(String),

    /// 参数非法（如密文超存储侧硬上限）。
    #[error("invalid secret argument: {0}")]
    InvalidArgument(String),

    /// 存储的密文/元数据未通过完整性检查（损坏；需管理员轮换）。
    #[error("secret data corrupt: {0}")]
    Corrupt(String),

    /// 底层存储失败（类型擦除的可诊断 source，§14.1）。
    #[error("secret store failure: {0}")]
    Storage(#[source] ErrorSource),
}

/// secret 密文记录（§16.6：名称 + 版本 + **不透明密文 BLOB**；本类型
/// 只承载密文，永不承载明文——明文只存在于 [`crate::secret::SecretService`]
/// 的返回值）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretCiphertextRecord {
    /// secret 名称（grant scope 的键，§17.3）。
    pub name: SecretName,
    /// 轮换版本（每次轮换递增，WIT `secret-version`）。
    pub version: SecretVersion,
    /// 不透明密文 BLOB（ADR-0001 envelope：算法标识 + 版本 + nonce +
    /// 密文 + tag；storage 不解密）。
    pub ciphertext: Vec<u8>,
}

/// SecretStore port（§24.2：trait 定义在本 crate，storage-sqlite 层实现；
/// 全部方法只接触密文与元数据，**不含明文**）。
pub trait SecretStorePort: Send + Sync {
    /// 写入/轮换 secret 密文（insert or replace，版本递增，§41.2）。
    ///
    /// `ciphertext` 是 SecretStore 服务侧加密后的**不透明密文 BLOB**；
    /// `metadata` 只承载非敏感元数据（绝不含值/密钥材料，§16.6）。
    /// 返回新版本（审计关联，§41.2 secret audit）。
    fn put(
        &self,
        installation: InstallationId,
        name: &SecretName,
        ciphertext: Vec<u8>,
        metadata: &str,
    ) -> Result<SecretVersion, SecretStoreError>;

    /// 读取 secret 密文（不透明字节原样返回；`None` = 名称不存在）。
    fn ciphertext(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<Option<SecretCiphertextRecord>, SecretStoreError>;

    /// 列出安装实例的全部 secret 名称与版本（**不含值**，§41.2 防泄漏；
    /// WIT `list-granted-secrets` 的存储输入）。
    fn list(&self, installation: InstallationId) -> Result<Vec<SecretMetadata>, SecretStoreError>;

    /// 删除 secret（名称不存在 → [`SecretStoreError::NotFound`]）。
    fn delete(
        &self,
        installation: InstallationId,
        name: &SecretName,
    ) -> Result<(), SecretStoreError>;
}

/// secret grant 集（§17.3 "secret names" scope 维度；§17.5 第三层 Grant：
/// durable owner 是 [`InstallationId`]）。
///
/// 返回安装实例被授予的全部 secret 名称（空 = 该安装没有任何 secret
/// 能力，§17.2 deny-by-default）。storage 接线层从 grants 表筛选
/// `operune:secret/secret` 能力面实现；应用层（[`crate::secret::SecretService`]）
/// 按名称做 invocation-time enforcement（§17.5 第四层：授权撤销/scope
/// 变化以确定语义生效，不依赖 Component 自觉）。
pub trait SecretGrantPort: Send + Sync {
    /// 安装实例被授予的 secret 名称集。
    fn granted_names(
        &self,
        installation: InstallationId,
    ) -> Result<Vec<SecretName>, crate::ports::GrantError>;
}
