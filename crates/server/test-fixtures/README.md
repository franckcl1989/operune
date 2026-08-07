# Test fixtures（仅测试用，绝不进入生产配置）

本目录只包含**测试专用**的 throwaway TLS 身份：

- `localhost-cert.pem`：自签名证书（CN=localhost，2048-bit RSA）。
- `localhost-key.pem`：配套私钥。

两者均由 openssl 一次性生成（2026-08-07，10 年有效期）：

```sh
openssl req -x509 -newkey rsa:2048 -keyout localhost-key.pem \
    -out localhost-cert.pem -days 3650 -nodes -subj "//CN=localhost"
```

用途：`crates/server/src/server.rs` 的 TLS 装配测试
（`TlsIdentity::from_pem_files` → rustls parts，§16.2 边界）。

安全声明：这是测试自签密钥，**不是任何真实身份的凭据**；任何环境不得在
生产配置中引用本目录文件（生产 TLS 身份引用见 BootstrapConfig 的 `[tls]`
路径引用，§18.0 / §16.2）。
