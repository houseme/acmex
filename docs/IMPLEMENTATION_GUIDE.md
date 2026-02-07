# AcmeX 模块补充实现指南

**文档版本**: 1.0  
**最后更新**: 2026-02-07  
**完成度**: 已完成 crypto 和 transport 模块

---

## 📋 待补充模块清单

基于项目架构，以下模块需要进一步完善或补充实现：

### 第一优先级 (核心功能)

- [ ] **config 模块** (src/config/)
    - 预期工作量：3-4 小时
    - 依赖：None
    - 阻塞：orchestrator, server 模块

- [ ] **orchestrator 模块** (src/orchestrator/)
    - 预期工作量：4-5 小时
    - 依赖：account, order, challenge, config
    - 阻塞：CLI 完整实现

### 第二优先级 (增强功能)

- [ ] **server 模块** (src/server/)
    - 预期工作量：4-5 小时
    - 依赖：orchestrator, storage, metrics
    - 用途：Web API 和 Webhook

- [ ] **scheduler 模块扩展** (src/scheduler/)
    - 预期工作量：2-3 小时
    - 依赖：renewal, metrics
    - 用途：清理任务调度

### 第三优先级 (可选功能)

- [ ] **webhook 系统** (src/notifications/)
    - 预期工作量：3-4 小时
    - 依赖：metrics, transport

- [ ] **缓存系统** (src/cache/)
    - 预期工作量：2-3 小时
    - 依赖：storage, crypto

---

## 🔧 Config 模块实现指南

### 目标

提供灵活的配置管理，支持 TOML 文件、环境变量和默认值。

### 结构设计

```rust
// src/config/mod.rs
pub mod builder;
pub mod ca;
pub mod env;
pub mod validation;

pub use builder::ConfigBuilder;
pub use ca::{CAPreset, CaConfig};
```

### 核心实现

#### 1. builder.rs - 配置构建器

```rust
pub struct ConfigBuilder {
    directory: Option<String>,
    contact: Vec<String>,
    storage_config: StorageConfig,
    challenge_config: ChallengeConfig,
}

impl ConfigBuilder {
    pub fn new() -> Self { ... }
    pub fn directory(mut self, url: String) -> Self { ... }
    pub fn storage_backend(mut self, backend: StorageBackend) -> Self { ... }
    pub fn build(self) -> Result<AcmeConfig> { ... }
}
```

#### 2. ca.rs - CA 预设

```rust
pub enum CAPreset {
    LetsEncryptStaging,
    LetsEncryptProduction,
    GoogleTrustServices,
    ZeroSSL,
    Custom(String),
}

impl CAPreset {
    pub fn directory_url(&self) -> &str { ... }
    pub fn root_certs(&self) -> &[&str] { ... }
}
```

#### 3. env.rs - 环境变量

```rust
pub struct EnvConfig;

impl EnvConfig {
    pub fn load_from_env() -> Result<AcmeConfig> {
        // 从环境变量读取配置
        // ACMEX_DIRECTORY_URL
        // ACMEX_CONTACT_EMAIL
        // ACMEX_STORAGE_BACKEND
        // ...
    }
}
```

#### 4. validation.rs - 配置验证

```rust
pub struct ConfigValidator;

impl ConfigValidator {
    pub fn validate_directory_url(url: &str) -> Result<()> { ... }
    pub fn validate_contact(contact: &[String]) -> Result<()> { ... }
    pub fn validate_domains(domains: &[String]) -> Result<()> { ... }
}
```

---

## 🎯 Orchestrator 模块实现指南

### 目标

协调各业务模块，实现完整的证书生命周期管理工作流。

### 结构设计

```rust
// src/orchestrator/mod.rs
pub mod provisioner;
pub mod validator;
pub mod renewer;

pub use provisioner::CertificateProvisioner;
pub use validator::ChallengeValidator;
pub use renewer::CertificateRenewer;
```

### 核心实现

#### 1. provisioner.rs - 证书申请编排

```rust
pub struct CertificateProvisioner {
    client: Arc<AcmeClient>,
    account_manager: Arc<AccountManager>,
    order_manager: Arc<OrderManager>,
    challenge_solver: Arc<ChallengeSolverRegistry>,
    metrics: Arc<MetricsRegistry>,
}

impl CertificateProvisioner {
    pub async fn provision(&self, domains: Vec<String>) -> Result<CertificateBundle> {
        // 1. 检查或创建账户
        // 2. 创建订单
        // 3. 获取授权
        // 4. 验证挑战
        // 5. 发送 CSR
        // 6. 下载证书
    }

    async fn verify_account(&self) -> Result<()> { ... }
    async fn create_order(&self, domains: &[String]) -> Result<Order> { ... }
    async fn validate_challenges(&self, authorizations: &[Authorization]) -> Result<()> { ... }
    async fn finalize_order(&self, order: &Order, csr: &[u8]) -> Result<Certificate> { ... }
}
```

#### 2. validator.rs - 挑战验证编排

```rust
pub struct ChallengeValidator {
    challenge_solver: Arc<ChallengeSolverRegistry>,
    dns_resolver: Arc<DnsResolver>,
    http_client: Arc<HttpClient>,
    timeout: Duration,
}

impl ChallengeValidator {
    pub async fn validate(&self, challenges: &[Challenge]) -> Result<()> {
        // 1. 启动所有挑战服务器/记录
        // 2. 等待验证传播
        // 3. 通知 ACME 服务器验证
        // 4. 轮询验证结果
        // 5. 清理资源
    }

    async fn setup_challenges(&self, challenges: &[Challenge]) -> Result<()> { ... }
    async fn wait_for_propagation(&self) -> Result<()> { ... }
    async fn request_verification(&self, challenge_urls: &[String]) -> Result<()> { ... }
    async fn poll_verification(&self, authorization_urls: &[String]) -> Result<()> { ... }
    async fn cleanup_challenges(&self, challenges: &[Challenge]) -> Result<()> { ... }
}
```

#### 3. renewer.rs - 续期编排

```rust
pub struct CertificateRenewer {
    provisioner: Arc<CertificateProvisioner>,
    certificate_store: Arc<CertificateStore>,
    metrics: Arc<MetricsRegistry>,
}

impl CertificateRenewer {
    pub async fn check_and_renew(&self, domains: &[String]) -> Result<bool> {
        // 1. 加载现有证书
        // 2. 检查是否需要续期
        // 3. 申请新证书
        // 4. 备份旧证书
        // 5. 保存新证书
        // 6. 发送通知
    }

    async fn load_certificate(&self, domains: &[String]) -> Result<Option<CertificateBundle>> { ... }
    fn should_renew(&self, cert: &Certificate, renew_before_days: u32) -> bool { ... }
    async fn backup_certificate(&self, cert: &CertificateBundle) -> Result<()> { ... }
}
```

---

## 🌐 Server 模块实现指南

### 目标

提供 REST API 和 Webhook 支持，使用 Axum web 框架。

### 结构设计

```rust
// src/server/mod.rs
pub mod api;
pub mod health;
pub mod webhook;

pub struct ApiServer {
    port: u16,
    provisioner: Arc<CertificateProvisioner>,
    storage: Arc<CertificateStore>,
}

impl ApiServer {
    pub async fn run(&self) -> Result<()> { ... }
}
```

### API 端点规划

#### 证书管理

```
POST   /api/v1/certificates          创建新证书申请
GET    /api/v1/certificates          列表所有证书
GET    /api/v1/certificates/{id}     获取证书详情
PUT    /api/v1/certificates/{id}     更新证书配置
DELETE /api/v1/certificates/{id}     删除证书
POST   /api/v1/certificates/{id}/renew 强制续期
GET    /api/v1/certificates/{id}/download 下载证书
```

#### 账户管理

```
GET    /api/v1/account               获取账户信息
POST   /api/v1/account/register      注册新账户
PUT    /api/v1/account               更新账户信息
POST   /api/v1/account/key-rollover  密钥轮换
```

#### 监控和状态

```
GET    /health                       健康检查
GET    /metrics                      Prometheus 指标
POST   /webhooks/renewal             续期事件 Webhook
GET    /api/v1/logs                  操作日志
```

---

## 📝 实现步骤

### 第 1 步：配置模块 (3-4 小时)

```bash
# 1. 创建配置模块结构
touch src/config/{mod.rs,builder.rs,ca.rs,env.rs,validation.rs}

# 2. 实现各个子模块
# - builder.rs: ConfigBuilder 模式
# - ca.rs: CA 预设枚举
# - env.rs: 环境变量加载
# - validation.rs: 配置验证

# 3. 更新 lib.rs
echo "pub mod config;" >> src/lib.rs

# 4. 编写单元测试
cargo test config

# 5. 验证编译
cargo check --all-features
```

### 第 2 步：编排模块 (4-5 小时)

```bash
# 1. 创建编排模块结构
touch src/orchestrator/{mod.rs,provisioner.rs,validator.rs,renewer.rs}

# 2. 实现各个编排器
# - provisioner.rs: 证书申请工作流
# - validator.rs: 挑战验证工作流
# - renewer.rs: 续期工作流

# 3. 与现有模块集成
# 关键集成点：
# - account_manager 获取账户
# - order_manager 管理订单
# - challenge_solver 验证挑战
# - metrics 记录指标

# 4. 编写集成测试
cargo test orchestrator

# 5. 验证编译
cargo check --all-features
```

### 第 3 步：Web 服务器模块 (4-5 小时)

```bash
# 1. 创建服务器模块
touch src/server/{mod.rs,api.rs,health.rs,webhook.rs}

# 2. 实现 API 端点
# 使用 Axum 框架
# 路由: /api/v1/certificates, /api/v1/account, /health, /metrics

# 3. 实现 Webhook 系统
# 支持续期事件、错误通知等

# 4. 编写 API 测试
cargo test server

# 5. 验证编译
cargo check --all-features
```

---

## 🧪 测试策略

### 配置模块测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = ConfigBuilder::new()
            .directory("https://acme-v02.api.letsencrypt.org/directory".to_string())
            .contact(vec!["admin@example.com".to_string()])
            .build()
            .expect("Should build config");

        assert_eq!(config.directory, "https://...");
    }

    #[test]
    fn test_ca_preset_urls() {
        assert_eq!(
            CAPreset::LetsEncryptProduction.directory_url(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn test_config_validation() {
        let result = ConfigValidator::validate_directory_url("invalid-url");
        assert!(result.is_err());
    }
}
```

### 编排模块测试

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_certificate_provisioner() {
        // Mock 所有依赖
        let provisioner = setup_test_provisioner().await;
        
        // 执行
        let result = provisioner.provision(vec!["example.com".to_string()]).await;
        
        // 验证
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_challenge_validator() {
        let validator = setup_test_validator().await;
        let challenges = create_test_challenges();
        
        let result = validator.validate(&challenges).await;
        assert!(result.is_ok());
    }
}
```

---

## 📦 依赖管理

### 新增依赖 (如需要)

```toml
# HTTP 框架已有 (axum)
# 配置解析已有 (serde, toml)
# 异步运行时已有 (tokio)

# 可能需要的新依赖：
# tower = "0.4"        # 中间件
# tower-http = "0.5"   # HTTP 中间件
# uuid = "1.0"         # UUID 生成
```

---

## 🎯 完成标准

### 代码标准

- [ ] 零编译错误
- [ ] 无 Clippy 警告
- [ ] 所有 public API 有 docstring
- [ ] 单元测试覆盖 >80%
- [ ] 集成测试通过

### 文档标准

- [ ] README.md 更新
- [ ] API 文档完整
- [ ] 示例代码可运行
- [ ] 架构文档更新

### 性能标准

- [ ] 内存占用 <50MB
- [ ] 响应时间 <1s (HTTP 请求)
- [ ] 无内存泄漏

---

**文档版本**: 1.0  
**最后更新**: 2026-02-07  
**维护者**: houseme

