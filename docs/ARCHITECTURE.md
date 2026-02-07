# AcmeX 项目架构设计文档

**文档版本**: 1.0  
**项目版本**: v0.4.0  
**更新时间**: 2026-02-07  
**编辑**: houseme

---

## 📋 目录

1. [架构概览](#架构概览)
2. [分层设计](#分层设计)
3. [核心模块](#核心模块)
4. [依赖关系](#依赖关系)
5. [扩展性设计](#扩展性设计)
6. [性能优化](#性能优化)

---

## 架构概览

### 整体架构图

```
┌─────────────────────────────────────────────────────────┐
│                    应用层 (Application)                 │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │   CLI Tools     │  │  Web Server  │  │  Libraries │ │
│  └────────┬────────┘  └──────┬───────┘  └──────┬─────┘ │
└───────────┼──────────────────┼──────────────────┼────────┘
            │                  │                  │
┌───────────▼──────────────────▼──────────────────▼────────┐
│              编排层 (Orchestration)                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  │
│  │Provisioner│ │Validator │ │Renewer   │  │Cleanup  │  │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘  │
└───────────┬─────────────────────────────────────────┬────┘
            │                                         │
┌───────────▼─────────────────────────────────────────▼────┐
│              业务逻辑层 (Business Logic)                  │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐ ┌────────────────┐│
│  │ Account │ │  Order  │ │Challenge │ │ Certificate    ││
│  └─────────┘ └─────────┘ └──────────┘ └────────────────┘│
│  ┌──────────────────────────────────────────────────────┐│
│  │          Protocol (ACME v2 / RFC 8555)              ││
│  │  Directory | Nonce | JWS | Authorization | Objects  ││
│  └──────────────────────────────────────────────────────┘│
└───────────┬──────────────────────────────────────┬────────┘
            │                                      │
┌───────────▼──────────────────────────────────────▼────────┐
│           传输和支持层 (Transport & Support)              │
│  ┌──────────────┐ ┌─────────────┐ ┌────────────────────┐ │
│  │HTTP Client   │ │Retry Policy │ │Rate Limiter        │ │
│  └──────────────┘ └─────────────┘ └────────────────────┘ │
│  ┌──────────────┐ ┌─────────────┐ ┌────────────────────┐ │
│  │Config Mgmt   │ │Crypto (ECC) │ │Encoding (B64/PEM) │ │
│  └──────────────┘ └─────────────┘ └────────────────────┘ │
└───────────┬──────────────────────────────────────┬────────┘
            │                                      │
┌───────────▼──────────────────────────────────────▼────────┐
│         持久化和观测层 (Persistence & Observability)      │
│  ┌─────────────┐ ┌──────────────┐ ┌────────────────────┐ │
│  │File Storage │ │Redis Storage │ │Encrypted Storage   │ │
│  └─────────────┘ └──────────────┘ └────────────────────┘ │
│  ┌──────────────────────────────────────────────────────┐ │
│  │   Metrics (Prometheus) | Logging (Tracing) | Events │ │
│  └──────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 分层设计

### 1. 应用层 (Application Layer)

负责用户交互和外部集成。

#### 1.1 CLI 工具 (`src/cli/`)

- **主要职责**: 命令行参数解析、用户交互、输出格式化
- **核心文件**:
    - `args.rs` - 使用 clap 的参数定义
    - `commands/obtain.rs` - 证书申请命令
    - `commands/renew.rs` - 证书续期命令
    - `commands/daemon.rs` - 后台守护进程
    - `commands/info.rs` - 证书信息查看
- **关键接口**: `CommandHandler`, `OutputFormatter`

#### 1.2 Web 服务器 (`src/server/`) [计划中]

- **主要职责**: REST API、Webhook 处理、健康检查
- **使用框架**: Axum
- **端点规划**:
    - `GET /api/certificates` - 列表
    - `POST /api/certificates` - 新建
    - `GET /api/status` - 健康检查

#### 1.3 库 API (`src/lib.rs`)

- **主要职责**: 为外部应用提供 Rust API
- **导出**: `AcmeClient`, `AcmeConfig`, 各类型和 trait

### 2. 编排层 (Orchestration Layer)

协调各业务模块，实现高层工作流。

#### 2.1 Provisioner (证书申请编排器) [计划中]

```rust
pub struct CertificateProvisioner {
    client: Arc<AcmeClient>,
    account_manager: Arc<AccountManager>,
    order_manager: Arc<OrderManager>,
    challenge_solver: Arc<ChallengeSolver>,
}

impl CertificateProvisioner {
    pub async fn provision(&self, domains: Vec<String>) -> Result<CertificateBundle>;
}
```

#### 2.2 Validator (验证编排器) [计划中]

```rust
pub struct ChallengeValidator {
    challenge_solver: Arc<ChallengeSolver>,
    dns_resolver: Arc<DnsResolver>,
}

impl ChallengeValidator {
    pub async fn validate(&self, authorization: &Authorization) -> Result<()>;
}
```

#### 2.3 Renewer (续期编排器) [计划中]

```rust
pub struct CertificateRenewer {
    provisioner: Arc<CertificateProvisioner>,
    storage: Arc<CertificateStore>,
    metrics: Arc<MetricsRegistry>,
}

impl CertificateRenewer {
    pub async fn renew(&self, domains: Vec<String>) -> Result<CertificateBundle>;
}
```

### 3. 业务逻辑层 (Business Logic Layer)

实现 ACME 协议和证书管理核心逻辑。

#### 3.1 Protocol 模块 (`src/protocol/`)

处理 ACME 协议细节：

- **directory.rs** - 发现 ACME 服务端点
  ```rust
  pub struct DirectoryManager {
      url: String,
      cache: Option<Directory>,
  }
  ```

- **nonce.rs** - Nonce 管理（防重放）
  ```rust
  pub struct NonceManager {
      pool: Vec<String>,
      endpoint: String,
  }
  ```

- **jws.rs** - JWS 签名生成
  ```rust
  pub struct JwsSigner {
      key_pair: rcgen::KeyPair,
      jwk: JwkPublicKey,
  }
  ```

- **objects.rs** - ACME 对象序列化/反序列化

#### 3.2 Account 模块 (`src/account/`)

账户和身份管理：

- **manager.rs** - 账户生命周期
  ```rust
  pub struct AccountManager {
      directory: Arc<DirectoryManager>,
      key_pair: rcgen::KeyPair,
      contact: Vec<String>,
  }
  ```

- **credentials.rs** - 密钥对管理
- **eab.rs** - 外部账户绑定

#### 3.3 Order 模块 (`src/order/`)

证书订单管理：

- **order.rs** - 订单状态机
  ```rust
  pub struct OrderManager {
      orders: HashMap<String, Order>,
      account: Arc<AccountManager>,
  }
  ```

- **authorization.rs** - 授权资源跟踪
- **finalize.rs** - CSR 提交和证书下载

#### 3.4 Challenge 模块 (`src/challenge/`)

挑战验证实现：

- **solver.rs** - 通用求解器接口
- **http01/server.rs** - HTTP-01 验证服务器
  ```rust
  pub struct Http01Solver {
      server: AxumServer,
      tokens: Arc<Mutex<HashMap<String, String>>>,
  }
  ```

- **dns01/provider.rs** - DNS-01 提供商接口
  ```rust
  pub trait DnsProvider: Send + Sync {
      async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;
      async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()>;
  }
  ```

### 4. 传输和支持层 (Transport & Support)

#### 4.1 Transport 模块 (`src/transport/`)

HTTP 通信抽象：

- **http_client.rs** - HTTP 客户端封装
  ```rust
  pub struct HttpClient {
      client: reqwest::Client,
      config: HttpClientConfig,
  }
  ```

- **retry.rs** - 重试策略
  ```rust
  pub enum RetryStrategy {
      ExponentialBackoff { ... },
      LinearBackoff { ... },
      FixedDelay(Duration),
  }
  ```

- **rate_limit.rs** - 速率限制 (令牌桶)
  ```rust
  pub struct RateLimiter {
      max_tokens: u32,
      tokens: Arc<Mutex<f64>>,
  }
  ```

- **middleware.rs** - 请求中间件
  ```rust
  pub trait Middleware: Send + Sync {
      async fn before_request(&self, url: &str, method: &str) -> Result<()>;
      async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()>;
  }
  ```

#### 4.2 Crypto 模块 (`src/crypto/`)

密码学原语：

- **keypair.rs** - 密钥对生成 (Ed25519, ECDSA)
  ```rust
  pub struct KeyPairGenerator {
      key_type: KeyType,
  }
  
  impl KeyPairGenerator {
      pub fn generate(&self) -> Result<rcgen::KeyPair>;
  }
  ```

- **signer.rs** - 签名接口
  ```rust
  pub trait Signer: Send + Sync {
      fn sign(&self, data: &[u8]) -> Result<Signature>;
  }
  ```

- **hash.rs** - 哈希工具 (SHA256, SHA384, SHA512)
  ```rust
  pub struct Sha256Hash;
  impl Sha256Hash {
      pub fn hash(data: &[u8]) -> Result<Vec<u8>>;
      pub fn hash_hex(data: &[u8]) -> Result<String>;
  }
  ```

- **encoding.rs** - Base64/PEM/Hex 编码
  ```rust
  pub struct Base64Encoding;
  pub struct PemEncoding;
  pub struct HexEncoding;
  ```

#### 4.3 Config 模块 (`src/config/`) [计划中]

配置管理：

- **builder.rs** - 配置构建器模式
- **ca.rs** - CA 预设 (Let's Encrypt, Google, ZeroSSL)
- **validation.rs** - 配置验证
- **env.rs** - 环境变量加载

### 5. 持久化和观测层

#### 5.1 Storage 模块 (`src/storage/`)

证书存储抽象：

- **file.rs** - 文件系统存储
  ```rust
  pub struct FileStorage {
      base_dir: PathBuf,
  }
  ```

- **redis.rs** - Redis 存储 (可选)
  ```rust
  pub struct RedisStorage {
      client: redis::Client,
  }
  ```

- **encrypted.rs** - 加密存储包装器
  ```rust
  pub struct EncryptedStorage<B: StorageBackend> {
      backend: B,
      cipher: Aes256Gcm,
  }
  ```

- **backend.rs** - 存储后端 trait

#### 5.2 Metrics 模块 (`src/metrics/`)

Prometheus 监控：

- **collector.rs** - 指标收集
- **exporter.rs** - Prometheus 导出
- **events.rs** - 事件追踪

#### 5.3 Renewal 模块 (`src/renewal/`)

自动续期：

- **mod.rs** - RenewalScheduler
  ```rust
  pub struct RenewalScheduler<B: StorageBackend> {
      scheduler: tokio::task::JoinHandle<()>,
  }
  ```

---

## 核心模块

### 模块通信流

```
CLI 用户输入
    ↓
┌─────────────────────┐
│ AcmeClient (主入口) │
└──────────┬──────────┘
           ↓
┌──────────────────────────────────────┐
│ CertificateProvisioner (编排器)      │
└──┬───────────────┬──────────────┬────┘
   ↓               ↓              ↓
AccountMgr    OrderManager   ChallengeSolver
   ↓               ↓              ↓
Protocol        Protocol      DNS/HTTP
JWS/Directory   Nonce         Validation
   ↓               ↓              ↓
HttpClient (传输层，重试+限流)
   ↓
ACME 服务器
```

### 关键数据结构

```
Certificate
├── certificate: X509 PEM
├── private_key: PEM encoded
├── chain: Vec<Certificate>
├── not_before: DateTime
├── not_after: DateTime
├── domains: Vec<String>
└── serial_number: String

Order
├── id: String
├── status: OrderStatus
├── identifiers: Vec<Identifier>
├── authorizations: Vec<Authorization>
├── certificate_url: Option<String>
├── finalize_url: String
└── created_at: DateTime

Authorization
├── identifier: Identifier
├── status: AuthorizationStatus
├── challenges: Vec<Challenge>
├── expires: DateTime
└── wildcard: bool

Challenge
├── type: ChallengeType
├── url: String
├── status: ChallengeStatus
├── token: String
└── validated: Option<DateTime>
```

---

## 依赖关系

### 外部依赖

```
acmex
├── async-trait        # 异步 trait 支持
├── axum              # Web 框架
├── base64            # Base64 编码
├── clap              # CLI 参数
├── jiff              # 时间处理
├── hickory-resolver  # DNS 解析
├── pem               # PEM 编码/解码
├── rcgen             # CSR/证书生成
├── reqwest           # HTTP 客户端
├── serde             # 序列化
├── sha2              # 哈希算法
├── tokio             # 异步运行时
├── tracing           # 日志和追踪
├── aws-lc-rs 或 ring # 加密后端
└── redis (可选)       # Redis 支持
```

### 内部依赖关系

```
lib.rs (公开 API)
├── protocol/ (底层)
│   ├── directory.rs
│   ├── nonce.rs
│   ├── jws.rs
│   └── objects.rs
├── account/ (依赖 protocol)
├── order/ (依赖 account, protocol)
├── challenge/ (依赖 protocol, transport)
├── client/ (依赖 account, order, challenge)
├── storage/ (独立)
├── renewal/ (依赖 client, storage)
├── metrics/ (独立)
├── transport/ (底层)
├── crypto/ (底层)
└── cli/ (依赖所有)
```

---

## 扩展性设计

### Trait 系统

通过 trait 实现可插拔架构：

#### 1. DNS 提供商扩展

```rust
pub trait DnsProvider: Send + Sync {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;
    async fn delete_txt_record(&self, domain: &str, record_id: &str) -> Result<()>;
    async fn query_txt_record(&self, domain: &str) -> Result<Vec<String>>;
}
```

添加新提供商：

- 在 `src/dns/providers/` 下创建文件
- 实现 `DnsProvider` trait
- 通过 feature gate 启用

#### 2. 存储后端扩展

```rust
pub trait StorageBackend: Send + Sync {
    async fn save(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
}
```

支持的后端：

- FileStorage (默认)
- RedisStorage (feature: redis)
- EncryptedStorage (通用包装器)
- 自定义后端 (实现 trait)

#### 3. 中间件扩展

```rust
pub trait Middleware: Send + Sync {
    async fn before_request(&self, url: &str, method: &str) -> Result<()>;
    async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()>;
    async fn on_error(&self, url: &str, error: &AcmeError) -> Result<()>;
}
```

#### 4. Challenge 类型扩展

```rust
pub trait ChallengeSolver: Send + Sync {
    async fn prepare(&self, authorization: &Authorization) -> Result<()>;
    async fn validate(&self, authorization: &Authorization) -> Result<bool>;
    async fn cleanup(&self, authorization: &Authorization) -> Result<()>;
    fn challenge_type(&self) -> ChallengeType;
}
```

### Feature Flags

```toml
[features]
default = ["aws-lc-rs"]

# 加密后端
aws-lc-rs = ["dep:aws-lc-rs"]
ring-crypto = ["dep:ring"]

# 存储后端
redis = ["dep:redis"]

# DNS 提供商
dns-cloudflare = []
dns-digitalocean = []
dns-linode = []
dns-route53 = []
dns-azure = []      # 计划
dns-gcloud = []     # 计划

# CA 服务
google-ca = []
zerossl-ca = []

# 功能模块
metrics = []
cli = []
```

---

## 性能优化

### 1. 连接池

```rust
pub struct HttpClientConfig {
    pub pool_size: usize,
    pub timeout: Duration,
    pub follow_redirects: bool,
}
```

### 2. Nonce 缓存

```rust
pub struct NonceManager {
    pool: Vec<String>,  // 预缓存 nonce
    endpoint: String,
}
```

### 3. 并发处理

- 并行验证多个域名的挑战
- 使用 `tokio::spawn` 处理独立任务
- 异步 I/O 避免阻塞

### 4. 内存优化

- 使用 `Arc<T>` 共享所有权
- `Mutex` 而不是 `RwLock` 减少竞争
- 及时释放大对象

### 5. 缓存策略

- Directory 缓存 (可配置 TTL)
- DNS 解析结果缓存
- Certificate 元数据缓存

---

## 安全考虑

### 1. 密钥保护

- 使用 `zeroize` 清除敏感数据
- 密钥通过环境变量配置
- 支持加密存储

### 2. TLS 安全

- 强制使用 TLS 1.3
- 证书固定支持
- HSTS 支持

### 3. 请求验证

- JWS 签名验证
- Nonce 防重放
- 时间戳验证

### 4. 访问控制

- API 认证 (令牌)
- 速率限制
- IP 白名单

---

**文档版本**: 1.0  
**最后更新**: 2026-02-07  
**维护者**: houseme

