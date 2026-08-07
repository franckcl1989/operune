//! Artifact store（§18.7）：`data_root` 下的 staging / quarantine /
//! content-addressed artifact 空间、磁盘预算、GC/retention 与崩溃点协议。
//!
//! # 目录布局
//!
//! ```text
//! data_root/
//!   core.db            SQLite 权威元数据（§18.1）
//!   staging/           上传暂存（瞬态：打开时清空，绝不权威）
//!   quarantine/<digest> 字节已接收、未验证（§19.2 字节事实阶段）
//!   artifacts/<digest>  final content-addressed 空间（不可变，§18.7）
//! ```
//!
//! final artifact 以 [`ContentDigest`]（64 hex）寻址并视为不可变；同一 digest
//! 永远对应同一字节事实（§6.7），因此**重命名目标永远不会已存在**
//! （digest 唯一 → 无覆盖语义），这同时消除了 Windows `std::fs::rename`
//! 目标已存在即失败的平台差异（本机 Windows 语义如实记录见下）。
//!
//! # 文件原子 rename / fsync 的 OS 语义边界（§18.5）
//!
//! - 提交协议依赖同一 filesystem/volume 上的原子 rename：staging ↔ quarantine
//!   与 quarantine ↔ final 的迁移用 `std::fs::rename`。staging / quarantine /
//!   artifacts 全部位于 `data_root` 之下（同一 volume）→ 满足 §18.7 的
//!   同 filesystem/volume 约束；
//! - **Windows**：`std::fs::rename`（`MoveFileExW`）在目标已存在时失败。
//!   本 crate 的命名保证目标不存在（digest 寻址），且显式处理"目标已存在"
//!   的重复上传分支（校验大小后丢弃重复源文件），如实记录该平台语义；
//!   目录级 fsync（POSIX 上保证 rename 跨断电存活的手段）在
//!   `std::fs` 上不可用，**真正的 fsync/rename 崩溃一致性验证属于
//!   qualification（§18.5 / §33 crash injection），不是本 crate 的运行时承诺**；
//! - **DB 提交语义**：SQLite WAL + synchronous=FULL（见 migration.rs）保证已
//!   提交事务跨进程崩溃存活；"SQLite 事务化 ≠ 自动覆盖文件系统崩溃一致性"
//!   （§18.5）——文件与 DB 的一致性由本模块与 `recovery.rs` 的确定性对账协议
//!   提供，fault-injection 验证属于 #33 / qualification 阶段。
//!
//! # 关键 rename/DB commit/fsync 顺序与 crash points（§18.5 / §33）
//!
//! 原则：**DB 事务是 commit point，文件位置是派生态，可在打开时对账**。
//!
//! 1. `stage_bytes`：只写 `staging/`（瞬态，不 fsync，不建行）。
//!    crash point：staging 残留 → 打开时清空（`cleanup_staging`）。
//! 2. `record_quarantine`：rename `staging → quarantine/<digest>`，随后一个 DB
//!    事务（INSERT `artifacts` 行 + audit）。
//!    - crash between rename and DB commit → 孤儿 quarantine 文件（无行）→
//!      GC 清理；
//!    - crash after DB commit → 一致（quarantine 行 + quarantine 文件）。
//! 3. `commit_candidate`：注册表冲突预检（§19.4）→ rename
//!    `quarantine → artifacts/<digest>` → 一个 DB 事务（registry 绑定 +
//!    `artifacts.state = 'candidate'` + audit）。
//!    - crash between rename and DB commit → 文件在 final、行仍是 quarantine →
//!      recovery 把文件移回 quarantine（candidate 未提交 → 保持 quarantine，
//!      §18.5）；
//!    - crash after DB commit → 行 candidate、文件在 quarantine → recovery
//!      把文件移动到 final（完成候选提交）。
//! 4. `switch_active_version`：DB-only 两阶段（prepare marker → switch 事务），
//!    无文件操作（候选文件在步骤 3 已进入 final）。crash points 与恢复决策
//!    见 `repository.rs` 与 `recovery.rs`。
//!
//! # 磁盘预算（§18.7）
//!
//! 三个空间各有硬上限（[`DiskBudget`]）：staging（瞬态）、quarantine、
//! final。准入检查在写入前执行（`record_quarantine` / `commit_candidate` /
//! `stage_bytes`）；超限返回 [`StorageError::BudgetExceeded`]。
//!
//! # GC / retention 基线（§18.7）
//!
//! - staging：打开时清空（瞬态）；
//! - quarantine：无行文件 / 无文件行 / 超龄（[`GcPolicy::quarantine_max_age`]）
//!   均可回收——quarantine 从未被外键引用（只有 candidate/installed digest
//!   会被 registry / installation / active / upgrade 事务引用），删除安全；
//! - final：**只有无任何 `artifacts` 行的孤儿文件才可删**。仍被
//!   `component_versions` / `installation_versions` / `active_version` /
//!   `upgrade_transactions` 引用的 digest 由 SQLite 外键直接拒绝删除
//!   （`foreign_keys = ON`）→ 回滚所需的上一已知良好 artifact 按
//!   `installation_versions` 历史（rollback retention）保留，GC 不删
//!   （§18.7：不得删除仍被 active / candidate / rollback transaction /
//!   未结束 audit/reference 使用的 digest）；
//! - 审计记录不做磁盘压力静默删除（§18.7：audit 只追加；retention 策略属
//!   0.5+ 治理，本版本基线 = 不删）。

use std::path::{Path, PathBuf};

use operune_domain::{ByteSize, ContentDigest, Duration};

use crate::error::StorageError;
use crate::model::Timestamp;

/// Core 数据根目录（BootstrapConfig 提供，§18.0）。
///
/// 必须为绝对路径（消除 cwd 依赖歧义）；`db_path` 与三个 artifact 空间
/// （staging / quarantine / artifacts）均位于其下，保证同 volume 原子
/// rename 语义（§18.7）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRoot(PathBuf);

impl DataRoot {
    /// 构造并校验（validate-on-construct，§13.3）：非空 + 绝对路径。
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let path = path.into();
        if path.as_os_str().is_empty() {
            return Err(StorageError::InvalidArgument(
                "data_root must not be empty".into(),
            ));
        }
        if !path.is_absolute() {
            return Err(StorageError::InvalidArgument(format!(
                "data_root must be absolute, got {}",
                path.display()
            )));
        }
        Ok(Self(path))
    }

    /// 原始路径。
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// SQLite 数据库路径。
    pub(crate) fn db_path(&self) -> PathBuf {
        self.0.join("core.db")
    }

    /// staging 空间（上传暂存，瞬态）。
    pub(crate) fn staging_dir(&self) -> PathBuf {
        self.0.join("staging")
    }

    /// quarantine 空间（digest 寻址）。
    pub(crate) fn quarantine_dir(&self) -> PathBuf {
        self.0.join("quarantine")
    }

    /// final content-addressed 空间（digest 寻址，不可变）。
    pub(crate) fn artifacts_dir(&self) -> PathBuf {
        self.0.join("artifacts")
    }

    /// 创建目录布局（幂等）。
    pub(crate) fn ensure_layout(&self) -> Result<(), StorageError> {
        for dir in [
            self.as_path(),
            &self.staging_dir(),
            &self.quarantine_dir(),
            &self.artifacts_dir(),
        ] {
            std::fs::create_dir_all(dir)
                .map_err(|e| StorageError::io("create data root layout", e))?;
        }
        Ok(())
    }
}

/// 磁盘预算硬上限（§18.7）。
///
/// 默认值（可配置）：staging 256 MiB、quarantine 1 GiB、final 8 GiB。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskBudget {
    staging: ByteSize,
    quarantine: ByteSize,
    artifacts: ByteSize,
}

impl DiskBudget {
    /// 从三个空间的硬上限构造。
    pub const fn new(staging: ByteSize, quarantine: ByteSize, artifacts: ByteSize) -> Self {
        Self {
            staging,
            quarantine,
            artifacts,
        }
    }

    /// staging 上限。
    pub const fn staging(self) -> ByteSize {
        self.staging
    }

    /// quarantine 上限。
    pub const fn quarantine(self) -> ByteSize {
        self.quarantine
    }

    /// final 上限。
    pub const fn artifacts(self) -> ByteSize {
        self.artifacts
    }
}

impl Default for DiskBudget {
    fn default() -> Self {
        Self::new(
            ByteSize::from_bytes(256 * 1024 * 1024),
            ByteSize::from_bytes(1024 * 1024 * 1024),
            ByteSize::from_bytes(8 * 1024 * 1024 * 1024),
        )
    }
}

/// 当前各空间占用（§18.7 预算核算；quarantine/final 以 DB 行为准，staging
/// 以文件系统扫描为准——staging 文件不建行）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetUsage {
    /// staging 占用（文件系统扫描）。
    pub staging: ByteSize,
    /// quarantine 占用（`artifacts` 表 state = 'quarantine' 行合计）。
    pub quarantine: ByteSize,
    /// final 占用（`artifacts` 表 state ∈ {candidate, installed} 行合计）。
    pub final_store: ByteSize,
}

/// GC 策略（§18.7 GC/retention 基线）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcPolicy {
    /// quarantine 记录的最大存活期；超过即文件+行一起回收
    /// （"candidate 未提交 → 清理"语义，§18.5）。`Duration::ZERO` = 立即回收。
    pub quarantine_max_age: Duration,
}

impl Default for GcPolicy {
    fn default() -> Self {
        Self {
            quarantine_max_age: Duration::from_secs(24 * 3600),
        }
    }
}

/// GC 执行报告（供测试与 audit）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    /// 删除的文件数。
    pub removed_files: u64,
    /// 删除的 DB 行数。
    pub removed_rows: u64,
    /// 释放的字节数。
    pub bytes_freed: ByteSize,
}

impl Default for GcReport {
    fn default() -> Self {
        Self {
            removed_files: 0,
            removed_rows: 0,
            bytes_freed: ByteSize::ZERO,
        }
    }
}

/// artifact 文件空间（staging 单独处理）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ArtifactSpace {
    /// `data_root/quarantine`。
    Quarantine,
    /// `data_root/artifacts`（final）。
    Final,
}

impl ArtifactSpace {
    fn dir(self, root: &DataRoot) -> PathBuf {
        match self {
            Self::Quarantine => root.quarantine_dir(),
            Self::Final => root.artifacts_dir(),
        }
    }
}

/// digest 命名的文件系统条目。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DigestFile {
    /// 文件名解析出的 digest。
    pub digest: ContentDigest,
    /// 文件大小。
    pub byte_size: ByteSize,
}

/// 文件系统 artifact 空间（由 Storage Executor worker 独占持有，§18.2）。
#[derive(Debug, Clone)]
pub(crate) struct ArtifactStore {
    data_root: DataRoot,
    budget: DiskBudget,
}

impl ArtifactStore {
    pub(crate) fn new(data_root: DataRoot, budget: DiskBudget) -> Self {
        Self { data_root, budget }
    }

    pub(crate) fn data_root(&self) -> &DataRoot {
        &self.data_root
    }

    pub(crate) fn budget(&self) -> DiskBudget {
        self.budget
    }

    /// staging 占用（文件系统扫描）。
    pub(crate) fn staging_usage(&self) -> Result<ByteSize, StorageError> {
        let mut total = ByteSize::ZERO;
        for entry in self.scan_dir_entries(&self.data_root.staging_dir())? {
            if !entry.path().is_file() {
                continue;
            }
            let metadata = entry
                .metadata()
                .map_err(|e| StorageError::io("staging metadata", e))?;
            let size = ByteSize::from_bytes(metadata.len());
            total = total.saturating_add(size);
        }
        Ok(total)
    }

    /// 写入 staging 暂存文件（不 fsync：瞬态，打开时清空）。
    pub(crate) fn write_staging(&self, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
        let path = self.data_root.staging_dir().join(name);
        std::fs::write(&path, bytes).map_err(|e| StorageError::io("write staging file", e))
    }

    /// 删除 staging 暂存文件（不存在视为成功——瞬态）。
    pub(crate) fn remove_staging_file(&self, name: &str) -> Result<(), StorageError> {
        let path = self.data_root.staging_dir().join(name);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError::io("remove staging file", e)),
        }
    }

    /// 清空 staging（打开时执行，瞬态空间绝不权威）。
    ///
    /// 返回 (删除文件数, 释放字节)。
    pub(crate) fn cleanup_staging(&self) -> Result<(u64, ByteSize), StorageError> {
        let mut files = 0u64;
        let mut bytes = ByteSize::ZERO;
        for entry in self.scan_dir_entries(&self.data_root.staging_dir())? {
            let len = entry
                .metadata()
                .map_err(|e| StorageError::io("staging metadata", e))?
                .len();
            let path = entry.path();
            if path.is_file() {
                std::fs::remove_file(&path)
                    .map_err(|e| StorageError::io("remove staging file", e))?;
                files = files.saturating_add(1);
                bytes = bytes.saturating_add(ByteSize::from_bytes(len));
            }
        }
        Ok((files, bytes))
    }

    /// 移动 staging 文件 → quarantine（同一 volume 原子 rename；Windows 目标
    /// 已存在即失败，但 digest 命名保证目标不存在——重复上传由
    /// `repository::record_quarantine` 的预检处理）。
    pub(crate) fn promote_staging_to_quarantine(
        &self,
        name: &str,
        digest: ContentDigest,
    ) -> Result<(), StorageError> {
        let source = self.data_root.staging_dir().join(name);
        let target = self.data_root.quarantine_dir().join(digest.to_string());
        self.rename_replace_if_duplicate(&source, &target)
    }

    /// 移动 quarantine 文件 → final（同一 volume 原子 rename；目标不存在，
    /// 因为 digest 唯一——重复分支由调用方预检，见 `repository` 文档）。
    pub(crate) fn promote_quarantine_to_final(
        &self,
        digest: ContentDigest,
    ) -> Result<(), StorageError> {
        let source = self.data_root.quarantine_dir().join(digest.to_string());
        let target = self.data_root.artifacts_dir().join(digest.to_string());
        self.rename_replace_if_duplicate(&source, &target)
    }

    /// 把 final 文件移回 quarantine（recovery 对账：candidate 未提交 →
    /// 保持 quarantine，§18.5）。
    pub(crate) fn demote_final_to_quarantine(
        &self,
        digest: ContentDigest,
    ) -> Result<(), StorageError> {
        let source = self.data_root.artifacts_dir().join(digest.to_string());
        let target = self.data_root.quarantine_dir().join(digest.to_string());
        if target.exists() {
            // 对账前已保证目标不存在（两空间同 digest 并存 = CorruptState）。
            return Err(StorageError::CorruptState(format!(
                "quarantine target already exists for {digest} during demote"
            )));
        }
        self.rename_replace_if_duplicate(&source, &target)
    }

    /// 原子 rename（同一 volume）。目标已存在 = 重复字节上传：校验大小一致后
    /// 丢弃源文件（digest 相同 ⇒ 内容相同，§6.7）；大小不一致 ⇒ CorruptState。
    fn rename_replace_if_duplicate(
        &self,
        source: &Path,
        target: &Path,
    ) -> Result<(), StorageError> {
        if target.exists() {
            let source_len = std::fs::metadata(source)
                .map_err(|e| StorageError::io("duplicate source metadata", e))?
                .len();
            let target_len = std::fs::metadata(target)
                .map_err(|e| StorageError::io("duplicate target metadata", e))?
                .len();
            if source_len != target_len {
                return Err(StorageError::CorruptState(format!(
                    "duplicate digest files with different sizes: {} vs {} bytes",
                    source_len, target_len
                )));
            }
            // 相同字节事实：丢弃重复源文件（瞬态/待迁移文件，可安全删除）。
            return match std::fs::remove_file(source) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(StorageError::io("remove duplicate source file", e)),
            };
        }
        std::fs::rename(source, target).map_err(|e| StorageError::io("atomic rename", e))
    }

    /// 删除空间内 digest 文件；不存在返回 `Ok(false)`。
    pub(crate) fn remove_file(
        &self,
        space: ArtifactSpace,
        digest: ContentDigest,
    ) -> Result<bool, StorageError> {
        let path = space.dir(&self.data_root).join(digest.to_string());
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(StorageError::io("remove artifact file", e)),
        }
    }

    /// digest 文件是否存在于该空间。
    pub(crate) fn file_exists(
        &self,
        space: ArtifactSpace,
        digest: ContentDigest,
    ) -> Result<bool, StorageError> {
        Ok(space
            .dir(&self.data_root)
            .join(digest.to_string())
            .is_file())
    }

    /// 读取 digest 文件字节（不存在返回 `None`；读取失败 fail closed）。
    ///
    /// 用途：application 的 `ComponentRegistryPort::artifact_bytes`
    ///（§18.7 rollback retention：回滚目标字节按 digest 读取）。读取大小
    /// 以写入时的硬上限为界（§19.1：写入前已拒绝超限字节），此处不做
    /// 额外上限——文件是写入时校验过的字节事实（§6.7）。
    pub(crate) fn read_digest_file(
        &self,
        space: ArtifactSpace,
        digest: ContentDigest,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let path = space.dir(&self.data_root).join(digest.to_string());
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(StorageError::io("read artifact file", e)),
        }
    }

    /// 扫描空间目录中 digest 命名的文件（跳过非 digest 命名条目，
    /// 如平台元数据文件）。
    pub(crate) fn scan_digest_files(
        &self,
        space: ArtifactSpace,
    ) -> Result<Vec<DigestFile>, StorageError> {
        let mut files = Vec::new();
        for entry in self.scan_dir_entries(&space.dir(&self.data_root))? {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            let digest = match ContentDigest::from_hex(&name) {
                Ok(digest) => digest,
                Err(_) => continue, // 非 digest 命名条目（如 .gitkeep）忽略。
            };
            let metadata = entry
                .metadata()
                .map_err(|e| StorageError::io("artifact metadata", e))?;
            if metadata.is_file() {
                files.push(DigestFile {
                    digest,
                    byte_size: ByteSize::from_bytes(metadata.len()),
                });
            }
        }
        Ok(files)
    }

    fn scan_dir_entries(&self, dir: &Path) -> Result<Vec<std::fs::DirEntry>, StorageError> {
        let mut entries = Vec::new();
        for entry in std::fs::read_dir(dir).map_err(|e| StorageError::io("scan artifact dir", e))? {
            let entry = entry.map_err(|e| StorageError::io("read artifact dir entry", e))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// 时间是否超过保留期（饱和算术，§14.4）。
    pub(crate) fn older_than(created_at: Timestamp, max_age: Duration, now: Timestamp) -> bool {
        created_at
            .as_unix_seconds()
            .saturating_add(max_age.as_secs())
            <= now.as_unix_seconds()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::StorageError;
    use crate::testutil::{err, ok, tempdir};

    fn store(dir: &std::path::Path) -> ArtifactStore {
        let root = ok(DataRoot::new(dir.to_path_buf()), "data root");
        ok(root.ensure_layout(), "layout");
        ArtifactStore::new(root, DiskBudget::default())
    }

    #[test]
    fn data_root_requires_absolute_path() {
        assert!(matches!(
            DataRoot::new("relative/path"),
            Err(StorageError::InvalidArgument(_))
        ));
        assert!(matches!(
            DataRoot::new(""),
            Err(StorageError::InvalidArgument(_))
        ));
        let dir = tempdir();
        assert!(DataRoot::new(dir.path().to_path_buf()).is_ok());
    }

    #[test]
    fn ensure_layout_creates_all_spaces() {
        let dir = tempdir();
        let root = ok(DataRoot::new(dir.path().to_path_buf()), "data root");
        ok(root.ensure_layout(), "layout");
        assert!(root.db_path().parent().is_some());
        assert!(root.staging_dir().is_dir());
        assert!(root.quarantine_dir().is_dir());
        assert!(root.artifacts_dir().is_dir());
    }

    #[test]
    fn write_and_promote_staging_to_quarantine() {
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"bytes");
        ok(store.write_staging("stage-test", b"bytes"), "write staging");
        assert!(store.data_root().staging_dir().join("stage-test").is_file());
        ok(
            store.promote_staging_to_quarantine("stage-test", digest),
            "promote",
        );
        assert!(!store.data_root().staging_dir().join("stage-test").exists());
        assert!(
            store
                .data_root()
                .quarantine_dir()
                .join(digest.to_string())
                .is_file()
        );
    }

    #[test]
    fn promote_duplicate_discards_source_file() {
        // 重复字节（同 digest）上传：目标已存在 → 校验大小后丢弃重复源文件
        // （§6.7 同 digest 即同字节事实；Windows rename 目标已存在的平台语义）。
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"dup");
        ok(store.write_staging("s1", b"dup"), "write 1");
        ok(
            store.promote_staging_to_quarantine("s1", digest),
            "promote 1",
        );
        ok(store.write_staging("s2", b"dup"), "write 2");
        ok(
            store.promote_staging_to_quarantine("s2", digest),
            "promote duplicate",
        );
        assert!(!store.data_root().staging_dir().join("s2").exists());
        assert!(
            store
                .data_root()
                .quarantine_dir()
                .join(digest.to_string())
                .is_file()
        );
    }

    #[test]
    fn promote_duplicate_size_mismatch_is_corrupt() {
        // 同 digest 名但大小不同 = 内容不一致 → CorruptState（绝不静默覆盖）。
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"same");
        ok(store.write_staging("s1", b"same"), "write 1");
        ok(
            store.promote_staging_to_quarantine("s1", digest),
            "promote 1",
        );
        ok(store.write_staging("s2", b"same!"), "write 2");
        let error = err(
            store.promote_staging_to_quarantine("s2", digest),
            "promote mismatch",
        );
        assert!(matches!(error, StorageError::CorruptState(_)));
    }

    #[test]
    fn cleanup_staging_removes_transient_files() {
        let dir = tempdir();
        let store = store(dir.path());
        ok(store.write_staging("a", b"12345"), "write a");
        ok(store.write_staging("b", b"123"), "write b");
        let (files, bytes) = ok(store.cleanup_staging(), "cleanup");
        assert_eq!(files, 2);
        assert_eq!(bytes.as_u64(), 8);
        assert_eq!(ok(store.staging_usage(), "usage").as_u64(), 0);
    }

    #[test]
    fn scan_digest_files_skips_non_digest_names() {
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"scan-me");
        ok(store.write_staging("stage-x", b"scan-me"), "write");
        ok(
            store.promote_staging_to_quarantine("stage-x", digest),
            "promote",
        );
        // 非 digest 命名条目（如 .gitkeep）必须被忽略。
        ok(
            std::fs::write(store.data_root().quarantine_dir().join(".gitkeep"), b""),
            "write gitkeep",
        );
        let files = ok(store.scan_digest_files(ArtifactSpace::Quarantine), "scan");
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].digest, digest);
    }

    #[test]
    fn quarantine_to_final_promotion_and_removal() -> Result<(), StorageError> {
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"final");
        ok(store.write_staging("s", b"final"), "write");
        ok(
            store.promote_staging_to_quarantine("s", digest),
            "promote to quarantine",
        );
        ok(
            store.promote_quarantine_to_final(digest),
            "promote to final",
        );
        assert!(!store.file_exists(ArtifactSpace::Quarantine, digest)?);
        assert!(store.file_exists(ArtifactSpace::Final, digest)?);
        assert!(ok(
            store.remove_file(ArtifactSpace::Final, digest),
            "remove"
        ));
        assert!(!ok(
            store.remove_file(ArtifactSpace::Final, digest),
            "remove again"
        ));
        Ok(())
    }

    #[test]
    fn demote_final_to_quarantine_moves_back() -> Result<(), StorageError> {
        let dir = tempdir();
        let store = store(dir.path());
        let digest = ContentDigest::from_bytes(b"demote");
        ok(store.write_staging("s", b"demote"), "write");
        ok(
            store.promote_staging_to_quarantine("s", digest),
            "promote to quarantine",
        );
        ok(
            store.promote_quarantine_to_final(digest),
            "promote to final",
        );
        ok(store.demote_final_to_quarantine(digest), "demote");
        assert!(store.file_exists(ArtifactSpace::Quarantine, digest)?);
        assert!(!store.file_exists(ArtifactSpace::Final, digest)?);
        Ok(())
    }

    #[test]
    fn older_than_uses_saturating_arithmetic() {
        let now = Timestamp::from_unix_seconds(1_000_000);
        // created + age <= now → 到期。
        assert!(ArtifactStore::older_than(
            Timestamp::from_unix_seconds(1_000_000),
            Duration::ZERO,
            now
        ));
        assert!(ArtifactStore::older_than(
            Timestamp::from_unix_seconds(999_999),
            Duration::from_secs(1),
            now
        ));
        assert!(!ArtifactStore::older_than(
            Timestamp::from_unix_seconds(1_000_000),
            Duration::from_secs(1),
            now
        ));
        // 饱和：u64::MAX 时间戳 + 任何 age 不回绕（若回绕到 0 会被误判为
        // 早已到期而错误回收；§14.4 禁止整数回绕）。
        assert!(!ArtifactStore::older_than(
            Timestamp::from_unix_seconds(u64::MAX),
            Duration::from_secs(1),
            now
        ));
    }

    #[test]
    fn staging_usage_counts_only_files() {
        let dir = tempdir();
        let store = store(dir.path());
        ok(store.write_staging("f1", b"12345"), "write f1");
        ok(
            std::fs::write(store.data_root().staging_dir().join("sub"), b""),
            "write dir marker",
        );
        assert_eq!(ok(store.staging_usage(), "usage").as_u64(), 5);
    }
}
