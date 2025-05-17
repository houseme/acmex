# acmex

[English](./README.md) | 中文

acmex 是一个用于 ACME 协议（如 Let's Encrypt）的 Rust 客户端库和命令行工具，支持自动化证书申请和管理。

## 用法

### 作为库使用

```rust
use acmex::{AcmeClient, AcmeConfig, ChallengeType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = AcmeConfig::new(vec!["example.com".to_string()])
        .contact(vec!["mailto:user@example.com".to_string()])
        .prod(false);
    let client = AcmeClient::new(config);
    let (cert, key) = client.provision_certificate(ChallengeType::TlsAlpn01, None).await?;
    // 使用 cert 和 key 配合 rustls
    Ok(())
}
```

### 作为命令行工具使用

```bash
cargo run -- --domains example.com --email user@example.com --cache-dir ./acmex_cache
```

使用 Redis：

```bash
cargo run --features redis -- --domains example.com --email user@example.com --redis-url redis://127.0.0.1:6379
```

## 许可证

本项目采用双许可证协议，您可以任选其一：

- [MIT 许可证](LICENSE-MIT)
- [Apache 许可证 2.0 版](LICENSE-APACHE)

您可以根据需要选择其中任意一个许可证来使用本项目。除非您明确声明，您为本项目提交的任何贡献将默认采用上述双许可证协议，无需附加其他条款或条件。

详细内容请参阅 [LICENSE-MIT](./LICENSE-MIT) 和 [LICENSE-APACHE](./LICENSE-APACHE) 文件。
