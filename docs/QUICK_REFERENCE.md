# AcmeX v0.1.0 快速参考指南

## 核心 API 速查表

### 1. 错误处理

```rust
use acmex::error::{AcmeError, Result};

// 创建错误
let err = AcmeError::protocol("Something went wrong");
let err = AcmeError::crypto("Invalid key");

// 使用 Result
fn operation() -> Result<String> {
    Ok("success".to_string())
}
```

### 2. 通用类型

```rust
use acmex::types::*;

// 创建标识符
let id = Identifier::dns("example.com");
let id = Identifier::ip("192.168.1.1");

// 创建联系方式
let contact = Contact::email("admin@example.com");
let contact = Contact::phone("+1-234-567-8900");

// 挑战类型
let ct = ChallengeType::Http01;
let ct = ChallengeType::Dns01;
let ct = ChallengeType::TlsAlpn01;

// 订单状态
let status = OrderStatus::Pending;
let status = OrderStatus::Ready;
let status = OrderStatus::Valid;
```

### 3. ACME 协议

```rust
use acmex::protocol::*;

// 目录管理
let dir_mgr = DirectoryManager::new(
"https://acme-staging-v02.api.letsencrypt.org/directory",
http_client,
);
let directory = dir_mgr.get().await?;

// Nonce 管理
let nonce_mgr = NonceManager::new( & directory.new_nonce, http_client);
let nonce = nonce_mgr.get_nonce().await?;
nonce_mgr.cache_nonce("fresh-nonce".to_string()).await;

// JWK 操作
let jwk = Jwk::new_ed25519("AAAA...");
let jwk = Jwk::new_rsa("AAAA...", "AQAB");
let thumbprint = jwk.thumbprint_sha256() ?;

// JWS 签名
let signer = JwsSigner::new( & key_pair);
let jws = signer.sign( & header, & payload) ?;
let jws = signer.sign_empty( & header) ?;
```

### 4. 账户管理

```rust
use acmex::account::*;

// 生成密钥
let key_pair = KeyPair::generate() ?;

// PEM 操作
key_pair.save_to_file("key.pem") ?;
let key_pair = KeyPair::load_from_file("key.pem") ?;
let pem_string = String::from_utf8(pem_encode) ?;
let key_pair = KeyPair::from_pem( & pem_string) ?;

// 账户管理
let account_mgr = AccountManager::new(
& key_pair,
& nonce_manager,
& dir_manager,
& http_client,
) ?;

let account = account_mgr.register(
vec![Contact::email("admin@example.com")],
true,
).await?;

let account = account_mgr.get_account( & account_id).await?;
let account = account_mgr.update_contacts(
& account_id,
vec![Contact::email("newemail@example.com")],
).await?;

account_mgr.deactivate( & account_id).await?;
```

### 5. 订单管理

```rust
use acmex::order::*;

// 创建订单请求
let order_req = NewOrderRequest::new(vec![
    "example.com".to_string(),
    "www.example.com".to_string(),
]);

// 访问订单数据
let status = order.status_enum();
if order.is_pending() { /* ... */ }
if order.is_ready() { /* ... */ }
if order.is_valid() { /* ... */ }

// 处理授权
if let Some(challenge) = auth.get_challenge("http-01") {
println ! ("Challenge token: {}", challenge.token);
}
```

## 完整示例

### 最小化示例

```rust
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 创建配置
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    // 创建 HTTP 客户端
    let http_client = reqwest::Client::new();

    // 获取 ACME 目录
    let dir_mgr = acmex::protocol::DirectoryManager::new(
        &config.directory_url,
        http_client.clone(),
    );
    let directory = dir_mgr.get().await?;

    // 生成密钥对
    let key_pair = KeyPair::generate()?;

    // 创建 Nonce 管理器
    let nonce_mgr = acmex::protocol::NonceManager::new(
        &directory.new_nonce,
        http_client.clone(),
    );

    // 创建账户管理器
    let account_mgr = AccountManager::new(
        &key_pair,
        &nonce_mgr,
        &dir_mgr,
        &http_client,
    )?;

    // 注册账户
    let account = account_mgr.register(
        vec![Contact::email("admin@example.com")],
        true,
    ).await?;

    println!("✅ Account registered: {}", account.id);
    Ok(())
}
```

## 常见模式

### 错误处理

```rust
// 链式错误处理
operation().await.map_err( | e| {
eprintln ! ("Operation failed: {}", e);
e
}) ?;

// 错误转换
fn convert_error(e: AcmeError) -> String {
    match e {
        AcmeError::Transport(msg) => format!("Network error: {}", msg),
        AcmeError::Crypto(msg) => format!("Crypto error: {}", msg),
        _ => "Unknown error".to_string(),
    }
}
```

### 配置预设

```rust
// Let's Encrypt 生产环境
let config = AcmeConfig::lets_encrypt()
.with_contact(Contact::email("admin@example.com"));

// Let's Encrypt 测试环境
let config = AcmeConfig::lets_encrypt_staging()
.with_contact(Contact::email("admin@example.com"));

// 自定义 CA
let config = AcmeConfig::new("https://custom-ca.example.com/directory")
.with_contact(Contact::email("admin@example.com"));
```

### 密钥对管理

```rust
// 生成新密钥
let key_pair = KeyPair::generate() ?;

// 保存到文件
key_pair.save_to_file("private_key.pem") ?;

// 从文件加载
let key_pair = KeyPair::load_from_file("private_key.pem") ?;

// PEM 字符串转换
let pem_str = std::fs::read_to_string("key.pem") ?;
let key_pair = KeyPair::from_pem( & pem_str) ?;
```

## 性能提示

1. **重用 HTTP 客户端** - 创建一次，多次使用
   ```rust
   let http_client = reqwest::Client::new();
   // 多个地方使用这个客户端
   ```

2. **缓存目录信息** - 避免重复请求
   ```rust
   let directory = dir_mgr.get().await?;  // 使用缓存
   dir_mgr.clear_cache().await;  // 需要时清空
   ```

3. **使用 Nonce 池** - 减少网络往返
   ```rust
   nonce_mgr.cache_nonce(nonce).await;  // 缓存多个 nonce
   ```

4. **关键路径优化** - 异步调用不阻塞
   ```rust
   // 所有 I/O 操作都是非阻塞的
   let (dir, nonce) = tokio::join!(
       dir_mgr.get(),
       nonce_mgr.get_nonce(),
   );
   ```

## 故障排查

### 常见错误

| 错误                                              | 原因           | 解决方案             |
|-------------------------------------------------|--------------|------------------|
| `Protocol("Missing replay-nonce header")`       | 服务器未返回 nonce | 检查网络连接和 ACME 服务器 |
| `Crypto("Failed to generate Ed25519 key pair")` | 密钥生成失败       | 检查系统随机数生成器       |
| `Transport(...)`                                | HTTP 请求失败    | 检查网络连接和代理设置      |
| `Account("Missing location header...")`         | 服务器响应不完整     | 确保使用兼容的 ACME 服务器 |

### 调试

启用日志输出：

```rust
use tracing_subscriber;

fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    // 现在所有操作都会输出日志
}
```

## 类型速查

| 类型              | 用途           | 位置                |
|-----------------|--------------|-------------------|
| `AcmeError`     | 错误类型         | `acmex::error`    |
| `Result<T>`     | 结果类型         | `acmex::error`    |
| `Contact`       | 联系信息         | `acmex::types`    |
| `Identifier`    | 域名/IP 标识     | `acmex::types`    |
| `ChallengeType` | 挑战类型         | `acmex::types`    |
| `OrderStatus`   | 订单状态         | `acmex::types`    |
| `Directory`     | ACME 目录      | `acmex::protocol` |
| `Jwk`           | JSON Web Key | `acmex::protocol` |
| `KeyPair`       | 密钥对          | `acmex::account`  |
| `Account`       | 账户信息         | `acmex::account`  |
| `Order`         | 证书订单         | `acmex::order`    |
| `Challenge`     | ACME 挑战      | `acmex::order`    |

## 版本信息

- **版本**: 0.1.0
- **发布日期**: 2026-02-07
- **Rust 版本**: 1.75.0+
- **状态**: 稳定

---

更多信息参见 [完整实现文档](IMPLEMENTATION_v0.1.0.md)

