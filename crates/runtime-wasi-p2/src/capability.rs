//! Typed WASI capability 规格（Host 侧 policy 形状，规范 §7.6 / §17）。
//!
//! 这些类型是 **Host 侧 policy 配置**：决定把哪些**标准** WASI 接口（P4：
//! 不创建 `operune:http` / `operune:clock` / `operune:file` 等平行接口，
//! 见 §52）以什么范围构建进 context。它们不是 guest 可见接口，也不是
//! WASI 的替身。
//!
//! 无 ambient authority（§7.6 / P7）：`WasiCapabilities::empty()` 不包含任何
//! 能力；每个能力通过 `add_preopen` / `add_env` 显式加入，且构建时校验。
//!
//! 0.1.0 形状范围：文件系统 preopen 与环境变量（两者在 WASI 0.2 中只能通过
//! context 配置注入）。socket 许可（§17.3 的 host/port/scheme scope）、
//! ip-name-lookup、宿主熵随机源等能力留给 application/集成阶段实际接线
//! （YAGNI §12.6）；本阶段的"安全默认"由 [`crate::context::WasiContextBuilder`]
//! 的零权限默认表达（§7.6：默认无文件系统、网络、环境变量、随机资源）。

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::WasiP2Error;

/// Guest 视角的 preopen 目录名（WASI 0.2 preopen 的 guest path）。
///
/// 不变量：非空、不含 NUL 字节；在边界一次性校验（§13.3"边界解析一次"），
/// 内部保持强类型。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GuestPath(String);

impl GuestPath {
    /// 构造并校验 guest 路径。
    ///
    /// # Errors
    ///
    /// - `WasiP2Error::EmptyGuestPath`：空字符串；
    /// - `WasiP2Error::NulInGuestPath`：含 NUL 字节。
    pub fn new(path: impl Into<String>) -> Result<Self, WasiP2Error> {
        let path = path.into();
        if path.is_empty() {
            return Err(WasiP2Error::EmptyGuestPath);
        }
        if path.as_bytes().contains(&0) {
            return Err(WasiP2Error::NulInGuestPath);
        }
        Ok(Self(path))
    }

    /// 返回 guest 路径字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuestPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// WASI 文件系统权限（目录级 / 文件级通用形状）。
///
/// 与 `wasi:filesystem` 的 descriptor permission 语义对应，但不暴露
/// wasmtime_wasi 的 bitflags 具体类型（§8.2：不把 p2 具体类型泄漏到公开 API）。
/// 默认全 `false` = 拒绝一切（deny-by-default，§7.6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FsPerms {
    /// 允许读取（映射到 `DirPerms::READ` / `FilePerms::READ`）。
    pub read: bool,
    /// 允许写入/变更（映射到 `DirPerms::MUTATE` / `FilePerms::WRITE`）。
    pub write: bool,
}

impl FsPerms {
    /// 只读权限。
    pub const READ_ONLY: Self = Self {
        read: true,
        write: false,
    };
    /// 读写权限。
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };
}

/// 一个 preopen 目录能力：host 路径 → guest 路径 + 权限。
///
/// 构造即校验（§13.3）；"guest 路径是否与集合内其他 preopen 重复"属于集合
/// 不变量，在 [`WasiCapabilities::add_preopen`] 检查。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreopenDirSpec {
    guest_path: GuestPath,
    host_path: PathBuf,
    dir_perms: FsPerms,
    file_perms: FsPerms,
}

impl PreopenDirSpec {
    /// 构造 preopen 规格。
    ///
    /// # Errors
    ///
    /// - `WasiP2Error::EmptyHostPath`：host 路径为空（不表达隐式的"当前目录"）。
    /// - `GuestPath::new` 的校验错误（空 / NUL）。
    pub fn new(
        guest_path: GuestPath,
        host_path: PathBuf,
        dir_perms: FsPerms,
        file_perms: FsPerms,
    ) -> Result<Self, WasiP2Error> {
        if host_path.as_os_str().is_empty() {
            return Err(WasiP2Error::EmptyHostPath);
        }
        Ok(Self {
            guest_path,
            host_path,
            dir_perms,
            file_perms,
        })
    }

    /// Guest 视角的 preopen 目录名。
    pub fn guest_path(&self) -> &GuestPath {
        &self.guest_path
    }

    /// Host 侧的目录路径。
    pub fn host_path(&self) -> &Path {
        &self.host_path
    }

    /// 目录本身的操作权限。
    pub fn dir_perms(&self) -> FsPerms {
        self.dir_perms
    }

    /// 目录内文件允许的最大权限。
    pub fn file_perms(&self) -> FsPerms {
        self.file_perms
    }
}

/// 一个显式注入 guest 的环境变量能力（§7.6：默认无环境变量，杜绝把宿主
/// 进程环境泄漏给 guest）。
///
/// 构造即校验：key 非空、key/value 不含 NUL 字节。
///
/// 说明：与 wasmtime-wasi 一致，同 key 重复注入时 guest 会看到两条记录
/// （WASI 0.2 的 `wasi:cli/environment` 语义），本类型不做去重。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVarSpec {
    key: String,
    value: String,
}

impl EnvVarSpec {
    /// 构造环境变量规格。
    ///
    /// # Errors
    ///
    /// - `WasiP2Error::EmptyEnvKey`：key 为空；
    /// - `WasiP2Error::NulInEnvVar`：key 或 value 含 NUL。
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, WasiP2Error> {
        let key = key.into();
        let value = value.into();
        if key.is_empty() {
            return Err(WasiP2Error::EmptyEnvKey);
        }
        if key.as_bytes().contains(&0) || value.as_bytes().contains(&0) {
            return Err(WasiP2Error::NulInEnvVar);
        }
        Ok(Self { key, value })
    }

    /// 环境变量名。
    pub fn key(&self) -> &str {
        &self.key
    }

    /// 环境变量值。
    pub fn value(&self) -> &str {
        &self.value
    }
}

/// 一个实例的 WASI 能力集合（Runtime Policy 的形状，§7.6 / §17）。
///
/// deny-by-default（P7）：`WasiCapabilities::empty()` 不包含任何能力；
/// 每个能力经 `add_preopen` / `add_env` 显式加入。集合一经传给
/// [`crate::context::WasiContextBuilder::with_capabilities`] 即整体生效
/// （replace 语义，不合并）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WasiCapabilities {
    preopens: Vec<PreopenDirSpec>,
    environment: Vec<EnvVarSpec>,
}

impl WasiCapabilities {
    /// 空能力集合（无任何 WASI 权限）。
    pub fn empty() -> Self {
        Self::default()
    }

    /// 集合是否不包含任何能力。
    pub fn is_empty(&self) -> bool {
        self.preopens.is_empty() && self.environment.is_empty()
    }

    /// 追加一个 preopen 目录能力。
    ///
    /// # Errors
    ///
    /// `WasiP2Error::DuplicateGuestPath`：集合中已存在相同 guest 路径
    /// （两个 preopen 暴露同一 guest 名会让 guest 解析产生歧义，显式拒绝）。
    pub fn add_preopen(&mut self, spec: PreopenDirSpec) -> Result<(), WasiP2Error> {
        if self
            .preopens
            .iter()
            .any(|existing| existing.guest_path() == spec.guest_path())
        {
            return Err(WasiP2Error::DuplicateGuestPath(
                spec.guest_path().as_str().to_owned(),
            ));
        }
        self.preopens.push(spec);
        Ok(())
    }

    /// 追加一个环境变量能力。
    pub fn add_env(&mut self, spec: EnvVarSpec) {
        self.environment.push(spec);
    }

    /// 集合中的 preopen 目录规格（只读）。
    pub fn preopens(&self) -> &[PreopenDirSpec] {
        &self.preopens
    }

    /// 集合中的环境变量规格（只读）。
    pub fn environment(&self) -> &[EnvVarSpec] {
        &self.environment
    }
}
