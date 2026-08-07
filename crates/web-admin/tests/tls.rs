//! TLS 装配集成测试（§16.2 / §22.3：ring provider + ServerConfig 装配；
//! 本机 Windows 只测装配，不做真实握手）。
//!
//! fixture（`tests/fixtures/`，openssl 一次性生成并提交）：
//! - `server-cert.pem` / `server-key.pem`：RSA 2048 自签测试证书。

use operune_security::tls::TlsIdentity;
use operune_web_admin::{
    AdminListenConfig, ListenConfigError, TlsMode, build_server_config, install_ring_provider,
};

/// 断言式辅助（workspace lints 禁止 expect/unwrap，§26.1）。
fn ok_or_fail<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
    assert!(
        result.is_ok(),
        "{what} 应成功，实际 Err: {:?}",
        result.as_ref().err()
    );
    match result {
        Ok(value) => value,
        Err(_) => unreachable!("上面的断言已保证 is_ok"),
    }
}

/// 读取测试 fixture 的 TLS 身份。
fn test_identity() -> TlsIdentity {
    let manifest_dir = match std::env::var("CARGO_MANIFEST_DIR") {
        Ok(dir) => dir,
        Err(error) => unreachable!("CARGO_MANIFEST_DIR 缺失: {error}"),
    };
    let cert_path = std::path::Path::new(&manifest_dir).join("tests/fixtures/server-cert.pem");
    let key_path = std::path::Path::new(&manifest_dir).join("tests/fixtures/server-key.pem");
    ok_or_fail(
        TlsIdentity::from_pem_files(&cert_path, &key_path),
        "load fixture identity",
    )
}

#[test]
fn ring_provider_installed_and_server_config_builds() {
    // §22.3：装配层显式安装 ring provider；幂等（重复调用保留既有安装）。
    install_ring_provider();
    install_ring_provider();

    let identity = test_identity();
    let config = ok_or_fail(build_server_config(identity), "build server config");

    // §16.2：rustls 安全默认集——装配即证明 provider（ring）已接线：
    // cipher suite 由默认 provider 提供（非空）。
    assert!(
        !config.crypto_provider().cipher_suites.is_empty(),
        "默认 cipher suite 集必须非空"
    );
    // 装配成功即证明 fixture 证书/私钥组合被 rustls + ring 接受。
}

#[test]
fn listen_config_validates_exposure_rules() {
    // §16.1：insecure dev 只允许 loopback。
    let dev_off_loopback = AdminListenConfig {
        bind_addr: ok_or_fail("0.0.0.0:8443".parse(), "addr"),
        tls: TlsMode::InsecureLoopbackDev,
    };
    assert!(matches!(
        dev_off_loopback.validate(),
        Err(ListenConfigError::InsecureDevOnNonLoopback { .. })
    ));

    // §16.1：非 loopback 必须显式生产 TLS（不自动退化明文）。
    let secure_off_loopback = AdminListenConfig {
        bind_addr: ok_or_fail("0.0.0.0:8443".parse(), "addr"),
        tls: TlsMode::Secure(test_identity()),
    };
    assert_eq!(secure_off_loopback.validate(), Ok(()));
    assert!(!secure_off_loopback.is_loopback());

    // loopback + 生产 TLS 合法（"仅本机可访问"不替代传输安全，§16.1）。
    let secure_loopback = AdminListenConfig {
        bind_addr: ok_or_fail("127.0.0.1:8443".parse(), "addr"),
        tls: TlsMode::Secure(test_identity()),
    };
    assert_eq!(secure_loopback.validate(), Ok(()));
    assert!(secure_loopback.is_loopback());
}

#[test]
fn production_identity_flows_into_server_config() {
    // §16.1/§16.2：生产身份消费路径（listen config → ServerConfig）。
    let config = AdminListenConfig {
        bind_addr: ok_or_fail("127.0.0.1:8443".parse(), "addr"),
        tls: TlsMode::Secure(test_identity()),
    };
    assert_eq!(config.validate(), Ok(()));
    let identity = match config.into_identity() {
        Some(identity) => identity,
        None => unreachable!("Secure 模式必须携带身份"),
    };
    let server_config = ok_or_fail(build_server_config(identity), "build");
    assert!(!server_config.alpn_protocols.iter().any(|p| p.is_empty()));
}

#[test]
fn insecure_dev_has_no_identity() {
    let config = AdminListenConfig {
        bind_addr: ok_or_fail("127.0.0.1:8443".parse(), "addr"),
        tls: TlsMode::InsecureLoopbackDev,
    };
    assert!(config.into_identity().is_none());
}
