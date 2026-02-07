# AcmeX 架构设计与功能规划方案

## 一、项目架构重构

### 1.1 核心架构层级

```
acmex/
├── src/
│   ├── lib.rs                      # 公共 API 导出
│   ├── error.rs                    # 统一错误类型定义
│   ├── types.rs                    # 通用类型定义
│   │
│   ├── protocol/                   # ACME 协议层
│   │   ├── mod.rs
│   │   ├── directory.rs            # 目录资源管理
│   │   ├── nonce.rs                # Nonce 管理器
│   │   ├── jws.rs                  # JWS 签名引擎
│   │   ├── jwk.rs                  # JWK 密钥表示
│   │   └── objects.rs              # ACME 对象序列化
│   │
│   ├── account/                    # 账户管理层
│   │   ├── mod.rs
│   │   ├── manager.rs              # 账户生命周期管理
│   │   ├── credentials.rs          # 密钥对管理
│   │   ├── eab.rs                  # 外部账户绑定
│   │   └── key_authorization.rs   # 密钥授权计算
│   │
│   ├── order/                      # 订单管理层
│   │   ├── mod.rs
│   │   ├── builder.rs              # 订单构建器
│   │   ├── state.rs                # 订单状态机
│   │   ├── authorization.rs        # 授权资源
│   │   └── finalize.rs             # 订单完成流程
│   │
│   ├── challenge/                  # 挑战处理层
│   │   ├── mod.rs
│   │   ├── solver.rs               # 挑战求解器抽象
│   │   ├── http01/
│   │   │   ├── mod.rs
│   │   │   ├── server.rs           # HTTP-01 验证服务器
│   │   │   └── prover.rs           # 证明生成器
│   │   ├── dns01/
│   │   │   ├── mod.rs
│   │   │   ├── provider.rs         # DNS 提供商抽象
│   │   │   ├── txt_record.rs       # TXT 记录管理
│   │   │   └── resolver.rs         # DNS 解析验证
│   │   └── tls_alpn01/
│   │       ├── mod.rs
│   │       ├── server.rs           # TLS-ALPN-01 服务器
│   │       └── certificate.rs      # 自签名证书生成
│   │
│   ├── certificate/                # 证书管理层
│   │   ├── mod.rs
│   │   ├── csr.rs                  # CSR 生成器
│   │   ├── parser.rs               # 证书解析
│   │   ├── chain.rs                # 证书链验证
│   │   └── renewal.rs              # 自动续期引擎
│   │
│   ├── crypto/                     # 加密原语层
│   │   ├── mod.rs
│   │   ├── keypair.rs              # 密钥对生成
│   │   ├── signer.rs               # 签名器抽象
│   │   ├── hash.rs                 # 哈希工具
│   │   └── encoding.rs             # Base64/PEM 编码
│   │
│   ├── transport/                  # 传输层
│   │   ├── mod.rs
│   │   ├── http_client.rs          # HTTP 客户端封装
│   │   ├── retry.rs                # 重试策略
│   │   ├── rate_limit.rs           # 速率限制
│   │   └── middleware.rs           # 请求中间件
│   │
│   ├── storage/                    # 存储抽象层
│   │   ├── mod.rs
│   │   ├── backend.rs              # 存储后端 trait
│   │   ├── file.rs                 # 文件系统存储
│   │   ├── redis.rs                # Redis 存储
│   │   ├── memory.rs               # 内存存储(测试用)
│   │   └── encryption.rs           # 加密存储包装器
│   │
│   ├── config/                     # 配置管理层
│   │   ├── mod.rs
│   │   ├── builder.rs              # 配置构建器
│   │   ├── ca.rs                   # CA 预设配置
│   │   ├── validation.rs           # 配置验证
│   │   └── env.rs                  # 环境变量加载
│   │
│   ├── orchestrator/               # 编排层
│   │   ├── mod.rs
│   │   ├── provisioner.rs          # 证书申请编排器
│   │   ├── validator.rs            # 验证编排器
│   │   └── renewer.rs              # 续期编排器
│   │
│   ├── scheduler/                  # 调度层
│   │   ├── mod.rs
│   │   ├── renewal_scheduler.rs   # 续期调度器
│   │   └── cleanup_scheduler.rs   # 清理调度器
│   │
│   ├── metrics/                    # 监控层
│   │   ├── mod.rs
│   │   ├── collector.rs            # 指标收集器
│   │   ├── exporter.rs             # Prometheus 导出器
│   │   └── events.rs               # 事件追踪
│   │
│   ├── server/                     # 服务器层
│   │   ├── mod.rs
│   │   ├── api.rs                  # REST API 服务器
│   │   ├── webhook.rs              # Webhook 处理器
│   │   └── health.rs               # 健康检查
│   │
│   └── cli/                        # CLI 层
│       ├── mod.rs
│       ├── commands/
│       │   ├── mod.rs
│       │   ├── account.rs          # 账户命令
│       │   ├── order.rs            # 订单命令
│       │   ├── cert.rs             # 证书命令
│       │   └── serve.rs            # 服务器命令
│       ├── output.rs               # 输出格式化
│       └── args.rs                 # 参数定义
│
├── tests/
│   ├── integration/                # 集成测试
│   ├── fixtures/                   # 测试夹具
│   └── mock_server/                # 模拟 ACME 服务器
│
├── examples/                       # 示例代码
│   ├── simple.rs
│   ├── http01.rs
│   ├── dns01.rs
│   ├── tls_alpn01.rs
│   ├── auto_renewal.rs
│   └── custom_storage.rs
│
└── benches/                        # 性能基准测试
    ├── signing.rs
    └── challenge_solving.rs
```

## 二、核心模块设计

### 2.1 错误处理系统

```rust
// src/error.rs
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AcmeError {
    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Account error: {0}")]
    Account(String),

    #[error("Order error: {status}, detail: {detail}")]
    Order { status: String, detail: String },

    #[error("Challenge failed: {challenge_type}, error: {error}")]
    Challenge { challenge_type: String, error: String },

    #[error("Certificate error: {0}")]
    Certificate(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] ring::error::Unspecified),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rate limited, retry after: {0:?}")]
    RateLimited(Option<std::time::Duration>),
}

pub type Result<T> = std::result::Result<T, AcmeError>;
```

### 2.2 协议层抽象

```rust
// src/protocol/directory.rs
use crate::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    pub new_nonce: String,
    #[serde(rename = "newAccount")]
    pub new_account: String,
    #[serde(rename = "newOrder")]
    pub new_order: String,
    #[serde(rename = "revokeCert")]
    pub revoke_cert: String,
    #[serde(rename = "keyChange")]
    pub key_change: String,
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DirectoryMeta {
    #[serde(rename = "termsOfService")]
    pub terms_of_service: Option<String>,
    pub website: Option<String>,
    #[serde(rename = "caaIdentities")]
    pub caa_identities: Option<Vec<String>>,
    #[serde(rename = "externalAccountRequired")]
    pub external_account_required: Option<bool>,
}

pub struct DirectoryManager {
    url: String,
    directory: Arc<RwLock<Option<Directory>>>,
    http_client: reqwest::Client,
}

impl DirectoryManager {
    pub async fn fetch(&self) -> Result<Directory> {
        // 实现目录获取逻辑
        todo!()
    }

    pub async fn get_cached(&self) -> Result<Directory> {
        // 实现缓存目录获取
        todo!()
    }
}
```

### 2.3 存储抽象层

```rust
// src/storage/backend.rs
use async_trait::async_trait;
use crate::Result;

#[async_trait]
pub trait StorageBackend: Send + Sync {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()>;
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn exists(&self, key: &str) -> Result<bool>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>>;
}

pub struct EncryptedStorage<B: StorageBackend> {
    backend: B,
    cipher: ring::aead::LessSafeKey,
}

impl<B: StorageBackend> EncryptedStorage<B> {
    pub fn new(backend: B, key: &[u8]) -> Result<Self> {
        // 实现加密存储包装器
        todo!()
    }
}
```

### 2.4 挑战求解器抽象

```rust
// src/challenge/solver.rs
use async_trait::async_trait;
use crate::Result;

#[derive(Debug, Clone)]
pub enum ChallengeType {
    Http01,
    Dns01,
    TlsAlpn01,
}

#[async_trait]
pub trait ChallengeSolver: Send + Sync {
    fn challenge_type(&self) -> ChallengeType;

    async fn prepare(&mut self, challenge: &Challenge) -> Result<()>;

    async fn present(&self) -> Result<()>;

    async fn verify(&self) -> Result<bool>;

    async fn cleanup(&mut self) -> Result<()>;
}

pub struct SolverRegistry {
    solvers: HashMap<ChallengeType, Box<dyn ChallengeSolver>>,
}

impl SolverRegistry {
    pub fn register<S: ChallengeSolver + 'static>(&mut self, solver: S) {
        self.solvers.insert(solver.challenge_type(), Box::new(solver));
    }

    pub fn get(&self, challenge_type: &ChallengeType) -> Option<&dyn ChallengeSolver> {
        self.solvers.get(challenge_type).map(|s| s.as_ref())
    }
}
```

## 三、功能增强规划

### 3.1 核心功能

1. **完整 ACME v2 协议支持**
    - RFC 8555 完全实现
    - 账户密钥轮换 (Key Rollover)
    - 证书吊销支持
    - 预授权 (Pre-authorization)

2. **多 CA 支持**
    - Let's Encrypt (默认)
    - Google Trust Services (feature: `google-ca`)
    - ZeroSSL (feature: `zerossl-ca`)
    - 自定义 CA 端点

3. **高级挑战验证**
    - HTTP-01: 内置验证服务器
    - DNS-01: 可插拔 DNS 提供商
    - TLS-ALPN-01: 零停机验证
    - 并发多域名验证

4. **智能证书管理**
    - 自动续期引擎 (续期窗口可配置)
    - 证书链验证
    - OCSP Stapling 支持
    - 通配符证书支持

5. **企业级存储**
    - 文件系统存储 (默认)
    - Redis 集群支持
    - 加密存储选项
    - 存储迁移工具

### 3.2 性能优化

1. **并发与异步**
    - 完全异步 I/O
    - 并行挑战验证
    - 连接池复用
    - 请求批处理

2. **缓存策略**
    - Directory 缓存
    - Nonce 池管理
    - DNS 查询缓存
    - 证书元数据缓存

3. **资源管理**
    - 内存占用优化
    - 连接数限制
    - 超时控制
    - 优雅关闭

### 3.3 可观测性

1. **结构化日志**
    - tracing 集成
    - 分级日志输出
    - 上下文传播
    - 敏感信息脱敏

2. **指标监控**
    - Prometheus 指标导出
    - 证书过期监控
    - 请求成功率
    - 挑战验证时长

3. **事件追踪**
    - 订单生命周期事件
    - 证书续期事件
    - 错误事件聚合

### 3.4 安全加固

1. **密钥安全**
    - 密钥材料零拷贝
    - 安全内存擦除
    - 权限最小化
    - 密钥轮换支持

2. **传输安全**
    - TLS 1.3 强制
    - 证书固定 (可选)
    - HSTS 支持
    - 请求签名验证

3. **访问控制**
    - API 认证
    - 速率限制
    - IP 白名单
    - Webhook 验证

## 四、API 设计

### 4.1 库 API

```rust
// 高级 API
pub struct AcmeClient {
    config: AcmeConfig,
    account: AccountManager,
    orchestrator: Provisioner,
    storage: Arc<dyn StorageBackend>,
}

impl AcmeClient {
    pub fn builder() -> AcmeClientBuilder { /* ... */ }

    pub async fn new_account(&self, contacts: Vec<String>) -> Result<Account> { /* ... */ }

    pub async fn provision(
        &self,
        domains: Vec<String>,
        challenge_type: ChallengeType,
    ) -> Result<Certificate> { /* ... */ }

    pub async fn renew(&self, cert_id: &str) -> Result<Certificate> { /* ... */ }

    pub async fn revoke(&self, cert: &Certificate, reason: RevocationReason) -> Result<()> { /* ... */ }
}

// 低级 API
pub struct LowLevelClient {
    directory: DirectoryManager,
    http: HttpClient,
}

impl LowLevelClient {
    pub async fn new_order(&self, account: &Account, order: NewOrder) -> Result<Order> { /* ... */ }

    pub async fn get_authorizations(&self, order: &Order) -> Result<Vec<Authorization>> { /* ... */ }

    pub async fn finalize_order(&self, order: &Order, csr: &[u8]) -> Result<Order> { /* ... */ }
}
```

### 4.2 CLI 命令

```bash
# 账户管理
acmex account create --email user@example.com --accept-tos
acmex account show
acmex account update --contacts mailto:admin@example.com

# 证书申请
acmex cert new --domains example.com,*.example.com --challenge dns-01
acmex cert renew --cert-id abc123
acmex cert revoke --cert-id abc123 --reason key-compromise

# 服务器模式
acmex serve --port 8443 --tls-cert cert.pem --tls-key key.pem

# 状态查询
acmex status --cert-id abc123
acmex list --filter expiring-soon
```

## 五、测试策略

### 5.1 单元测试

- 每个模块 >80% 覆盖率
- 加密函数完整测试
- 边界条件测试

### 5.2 集成测试

- 模拟 ACME 服务器
- 端到端证书申请流程
- 多挑战类型验证
- 存储后端切换测试

### 5.3 性能测试

- 并发申请压力测试
- 内存泄漏检测
- 签名性能基准
- 网络延迟容忍度

## 六、文档规范

1. **API 文档**: 所有公共 API 必须有 rustdoc 注释
2. **示例代码**: 每个主要功能提供可运行示例
3. **架构文档**: 维护架构决策记录 (ADR)
4. **操作手册**: 部署、配置、故障排查指南

## 七、发布计划

- **v0.1.0**: 核心 ACME 协议实现
- **v0.2.0**: HTTP-01/DNS-01 挑战支持
- **v0.3.0**: 自动续期引擎
- **v0.4.0**: TLS-ALPN-01 支持
- **v0.5.0**: 多 CA 支持
- **v1.0.0**: 生产就绪版本
