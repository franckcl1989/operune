//! WASI 0.2 context 构建：无 ambient authority 默认（§7.6）。
//!
//! [`WasiContextBuilder`] 是本 crate 公开的 WASI context 构建入口：
//!
//! - `new()` 即**零权限安全默认**：无文件系统、无网络、无环境变量/参数、
//!   零熵确定性随机源（§7.6）；
//! - `with_capabilities(caps)` 按 Runtime Policy 显式加入能力（§7.6 / §17.4
//!   least authority）；
//! - `build()` 产出不透明句柄 [`WasiContext`]，内部持有 wasmtime_wasi 的
//!   WASI 0.2 context（`WasiCtx`）——该具体类型**不出现在本 crate 公开 API**
//!   （§8.2），只在本 crate 内部使用。
//!
//! 安全默认的逐项表达：
//!
//! | 能力域 | 默认 | 依据 |
//! |---|---|---|
//! | 文件系统 | 无 preopen（WASI 0.2 guest 只能经 preopen 句柄访问文件系统） | §7.6 |
//! | 网络 | 显式关闭 TCP / UDP / ip-name-lookup（不依赖上游默认值漂移；p2 默认的地址检查也拒绝全部地址） | §7.6 |
//! | 环境变量 / 参数 | 无 | §7.6 |
//! | stdio | p2 上游默认：stdin 关闭、stdout/stderr 丢弃（不继承宿主进程） | §7.6 |
//! | 随机资源 | 安装零熵确定性 RNG（`wasmtime_wasi::Deterministic` 全零循环）；`insecure-seed` 固定 0。guest 的 `wasi:random/*` 拿不到任何宿主熵 | §7.6 |
//!
//! 需要宿主熵或 socket 许可的实例属于后续集成阶段的显式能力（本阶段不
//! 提供对应入口，YAGNI §12.6）。

use crate::capability::{FsPerms, WasiCapabilities};
use crate::error::WasiP2Error;

/// 安全默认上下文构建器（§7.6 无 ambient authority）。
///
/// 构建是消费性的：`build(self)` 之后该 builder 不可再使用
/// （"不合法状态不可表示"，§13.4），从而不会触发 wasmtime-wasi 的
/// "重复 build 即 panic" 路径。
#[derive(Default)]
pub struct WasiContextBuilder {
    capabilities: WasiCapabilities,
    inner: wasmtime_wasi::WasiCtxBuilder,
}

impl WasiContextBuilder {
    /// 创建零权限安全默认的构建器。
    ///
    /// 默认状态（§7.6）：无 preopen、无环境变量、无参数、网络关闭、
    /// 随机源零熵；每一项能力必须经 [`Self::with_capabilities`] 显式构建。
    pub fn new() -> Self {
        Self::default()
    }

    /// 用一份 policy 能力集合整体替换当前集合（replace 语义，可预期）。
    ///
    /// 消费并返回自身，支持链式
    /// `WasiContextBuilder::new().with_capabilities(caps).build()`；
    /// 传入 [`WasiCapabilities::empty`] 等价于保持零权限默认。
    pub fn with_capabilities(mut self, capabilities: WasiCapabilities) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// 构建 WASI context。
    ///
    /// 能力应用顺序固定：preopen → 环境变量 → 网络关闭 → 零熵随机源；
    /// 全部显式化，不依赖 wasmtime-wasi 上游默认值的变化。
    ///
    /// # Errors
    ///
    /// - `WasiP2Error::PreopenOpen`：policy 中的某个 preopen host 路径无法
    ///   打开（不存在 / 无权限），**整个构建失败**——deny-by-default 不允许
    ///   静默跳过已声明的能力（§17.2）。
    pub fn build(self) -> Result<WasiContext, WasiP2Error> {
        let mut inner = self.inner;

        // 文件系统：只有显式 policy 中的 preopen 会被打开（§7.6）。
        for spec in self.capabilities.preopens() {
            inner
                .preopened_dir(
                    spec.host_path(),
                    spec.guest_path().as_str(),
                    to_p2_dir_perms(spec.dir_perms()),
                    to_p2_file_perms(spec.file_perms()),
                )
                .map_err(|source| WasiP2Error::PreopenOpen {
                    guest_path: spec.guest_path().as_str().to_owned(),
                    host_path: spec.host_path().to_string_lossy().into_owned(),
                    source: Box::new(crate::error::AdapterSource::new(source)),
                })?;
        }

        // 环境变量：默认无；按显式 policy 注入（§7.6）。
        for env in self.capabilities.environment() {
            inner.env(env.key(), env.value());
        }

        // 网络：显式关闭 TCP / UDP / ip-name-lookup（§7.6 默认不获得网络）。
        // 即使上游 p2 默认的 socket 地址检查已拒绝全部地址，这里仍结构性关闭，
        // 保证"无网络"不依赖上游默认值。
        inner.allow_ip_name_lookup(false);
        inner.allow_tcp(false);
        inner.allow_udp(false);

        // 随机资源：零熵确定性 RNG（§7.6 默认不获得随机任意资源）。
        // guest 的 wasi:random/random、wasi:random/insecure、insecure-seed
        // 均得不到宿主熵；需要宿主熵的实例必须等集成阶段显式能力。
        inner.insecure_random_seed(0);
        inner.secure_random(wasmtime_wasi::Deterministic::new(vec![0; 64]));
        inner.insecure_random(wasmtime_wasi::Deterministic::new(vec![0; 64]));

        Ok(WasiContext {
            inner: inner.build(),
        })
    }
}

/// 不透明 WASI 0.2 context 句柄。
///
/// 内部持有 `wasmtime_wasi::WasiCtx`（WASI 0.2 的 Host 状态），该具体类型
/// 只存在于本 crate 内部（§8.2：不把 p2 具体类型泄漏到公开 API）。
///
/// 集成阶段衔接点：runtime-wasm 的 Store 类型定型后，本句柄需要把内部
/// WASI context 交由其持有并实现 wasmtime_wasi 的 `WasiView` binding trait；
/// 由于 orphan rule，`WasiView` 的实现只能写在持有 Store 类型的 crate，
/// 本 crate 提供 context 构建与（内部的）linker 组装（见 [`crate::linker`]
/// 模块文档）。跨 crate 的公开暴露形态届时由主 agent 按
/// runtime-wasm 的 Store 形状决定。
pub struct WasiContext {
    // 0.1.0 阶段该字段只被测试（及未来的集成接线）消费，lib 构建允许 dead_code
    //（集成阶段 runtime-wasm 的 Store 定型后由公开访问路径替代，见模块文档）。
    #[cfg_attr(not(test), allow(dead_code))]
    inner: wasmtime_wasi::WasiCtx,
}

impl WasiContext {
    /// 供本 crate 内部（及 linker 组装）访问 WASI 0.2 context。
    #[cfg_attr(not(test), allow(dead_code))] // 同上：0.1.0 集成接线点
    pub(crate) fn as_p2_mut(&mut self) -> &mut wasmtime_wasi::WasiCtx {
        &mut self.inner
    }
}

/// 把项目 `FsPerms` 映射为 wasmtime_wasi 的目录权限位（内部实现细节）。
fn to_p2_dir_perms(perms: FsPerms) -> wasmtime_wasi::DirPerms {
    let mut dir_perms = wasmtime_wasi::DirPerms::empty();
    if perms.read {
        dir_perms |= wasmtime_wasi::DirPerms::READ;
    }
    if perms.write {
        dir_perms |= wasmtime_wasi::DirPerms::MUTATE;
    }
    dir_perms
}

/// 把项目 `FsPerms` 映射为 wasmtime_wasi 的文件权限位（内部实现细节）。
fn to_p2_file_perms(perms: FsPerms) -> wasmtime_wasi::FilePerms {
    let mut file_perms = wasmtime_wasi::FilePerms::empty();
    if perms.read {
        file_perms |= wasmtime_wasi::FilePerms::READ;
    }
    if perms.write {
        file_perms |= wasmtime_wasi::FilePerms::WRITE;
    }
    file_perms
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{EnvVarSpec, GuestPath, PreopenDirSpec};

    #[test]
    fn default_context_has_no_ambient_authority() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = WasiContextBuilder::new().build()?;
        let wasi = ctx.as_p2_mut();

        // 环境变量与参数：空（§7.6）。
        assert!(wasi.cli().environment.is_empty());
        assert!(wasi.cli().arguments.is_empty());

        // 网络：结构性关闭（§7.6）。
        let sockets = wasi.sockets();
        let network = &sockets.allowed_network_uses;
        assert!(!network.tcp);
        assert!(!network.udp);
        assert!(!network.ip_name_lookup);

        // 随机资源：零熵确定性（§7.6）。全零循环的 next_u64 恒为 0，
        // insecure-seed 固定 0。
        assert_eq!(wasi.random().insecure_random_seed, 0);
        assert_eq!(wasi.random().random.next_u64(), 0);
        assert_eq!(wasi.random().insecure_random.next_u64(), 0);

        Ok(())
    }

    #[test]
    fn default_context_is_built_from_empty_policy() -> Result<(), Box<dyn std::error::Error>> {
        let mut ctx = WasiContextBuilder::new()
            .with_capabilities(WasiCapabilities::empty())
            .build()?;
        let wasi = ctx.as_p2_mut();
        assert!(wasi.cli().environment.is_empty());
        assert!(!wasi.sockets().allowed_network_uses.tcp);
        Ok(())
    }

    #[test]
    fn env_capability_is_applied_explicitly() -> Result<(), Box<dyn std::error::Error>> {
        let mut caps = WasiCapabilities::empty();
        caps.add_env(EnvVarSpec::new("OPERUNE_P2_TEST", "visible")?);
        let mut ctx = WasiContextBuilder::new().with_capabilities(caps).build()?;
        let wasi = ctx.as_p2_mut();
        assert_eq!(
            wasi.cli().environment,
            vec![("OPERUNE_P2_TEST".to_owned(), "visible".to_owned())]
        );
        // 其他维度仍为零权限默认。
        assert!(wasi.cli().arguments.is_empty());
        assert!(!wasi.sockets().allowed_network_uses.tcp);
        Ok(())
    }

    #[test]
    fn preopen_capability_is_applied_with_real_dir() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let guest = GuestPath::new("data")?;
        let spec = PreopenDirSpec::new(
            guest,
            dir.path().to_path_buf(),
            FsPerms::READ_ONLY,
            FsPerms::READ_ONLY,
        )?;
        let mut caps = WasiCapabilities::empty();
        caps.add_preopen(spec)?;

        // build 成功即证明 host 目录被打开并经标准 preopened_dir 注册。
        // （preopen 内部状态是 wasmtime-wasi 的 pub(crate)，无法从本 crate
        // 直接断言；开放目录路径在 §30 conformance 阶段用 guest fixture 验证。）
        let _ctx = WasiContextBuilder::new().with_capabilities(caps).build()?;
        Ok(())
    }

    #[test]
    fn preopen_missing_host_path_fails_whole_build() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let missing = dir.path().join("does-not-exist");
        let guest = GuestPath::new("data")?;
        let spec = PreopenDirSpec::new(guest, missing, FsPerms::READ_ONLY, FsPerms::READ_ONLY)?;
        let mut caps = WasiCapabilities::empty();
        caps.add_preopen(spec)?;

        // deny-by-default（§17.2）：已声明的能力不能静默跳过，必须整体失败。
        let err = WasiContextBuilder::new().with_capabilities(caps).build();
        let err = match err {
            Err(err) => err,
            Ok(_) => return Err("expected build to fail for missing host path".into()),
        };
        match err {
            WasiP2Error::PreopenOpen { .. } => {}
            other => return Err(format!("expected PreopenOpen, got: {other:?}").into()),
        }
        Ok(())
    }
}
