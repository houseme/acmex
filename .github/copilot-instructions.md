# GitHub Copilot 项目指导

**项目名称**: AcmeX  
**项目描述**: 企业级 ACME v2 客户端库和工具集  
**当前版本**: v0.5.0  
**Rust 版本**: 1.93.0 (Edition 2024)  
**MSRV**: 1.92.0

---

## 🎯 项目概览

AcmeX 是一个完整的 ACME v2 (RFC 8555) 协议实现库，专为自动化 TLS 证书管理设计。支持 HTTP-01、DNS-01、TLS-ALPN-01
等多种验证方式，集成了 9 个 DNS 提供商，支持多个证书颁发机构，提供自动续期、多种存储后端、Prometheus 监控、Webhook 通知和 CLI
工具。

### 核心特性

- ✅ 完整 ACME v2 协议实现 (RFC 8555)
- ✅ 3 种验证方式 (HTTP-01, DNS-01, TLS-ALPN-01)
- ✅ 9 个 DNS 提供商 (CloudFlare, DigitalOcean, Linode, Route53, Azure, Google, Alibaba, GoDaddy, Tencent)
- ✅ 4 个证书颁发机构 (Let's Encrypt, Google Trust Services, ZeroSSL, Custom)
- ✅ RenewalScheduler 自动续期系统
- ✅ 3 种存储后端 (File, Redis, Encrypted AES-256-GCM)
- ✅ Webhook 事件通知系统 (JSON, Slack, Discord)
- ✅ Prometheus 监控指标
- ✅ CLI 工具框架 (obtain, renew, daemon, info)
- ✅ Feature gates 灵活编译
- ✅ 生产级质量

---

## 📁 项目结构

### 源代码组织

```
src/
├── lib.rs                     # 库根，模块导出
├── main.rs                    # CLI 入口
├── ca.rs                      # 多CA支持 (v0.5.0新增)
├── config.rs                  # 配置管理 (v0.5.0增强)
├── account/                   # 账户管理
├── challenge/                 # 挑战验证框架
├── client/                    # 主要客户端
├── order/                     # 订单管理
├── protocol/                  # ACME 协议
├── dns/                       # DNS 提供商 (v0.5.0扩展到9个)
│   ├── cloudflare.rs
│   ├── route53.rs
│   ├── digitalocean.rs
│   ├── linode.rs
│   ├── azure.rs (新增)
│   ├── google.rs (新增)
│   ├── alibaba.rs (新增)
│   ├── godaddy.rs (新增)
│   └── tencent.rs (新增)
├── storage/                   # 证书存储
├── renewal/                   # 自动续期
├── notifications/             # Webhook通知 (v0.5.0新增)
├── metrics/                   # Prometheus 指标
├── cli/                       # CLI 工具
├── crypto/                    # 加密模块
├── transport/                 # HTTP传输
├── error.rs                   # 错误类型
└── types.rs                   # 公共类型
```

### 文档组织

```
docs/
├── INDEX.md                           # 文档索引
├── README.md                          # 文档首页
├── MAIN_README.md                     # 项目概览
├── V0.1.0_COMPLETION_REPORT.md       # v0.1.0 完成报告
├── V0.2.0_COMPLETION_REPORT.md       # v0.2.0 完成报告
├── V0.3.0_COMPLETION_REPORT.md       # v0.3.0 完成报告
├── V0.4.0_COMPLETION_REPORT.md       # v0.4.0 完成报告
├── V0.5.0_PLANNING.md                # v0.5.0 规划 (新)
├── V0.4.0_USAGE_GUIDE.md            # 使用指南
├── V0.3.0_INTEGRATION_EXAMPLES.md   # 集成示例
├── HTTP-01_IMPLEMENTATION.md         # HTTP-01 技术文档
├── DNS-01_IMPLEMENTATION.md          # DNS-01 技术文档
├── CHALLENGE_EXAMPLES.md             # 挑战验证示例
├── INTEGRATION_EXAMPLES.md           # 集成示例
├── FINAL_PROJECT_SUMMARY.md         # 项目总结
└── ...其他文档
```

---

## 🆕 v0.5.0 新增功能

### 多证书颁发机构 (Multi-CA Support)

- Let's Encrypt (默认)
- Google Trust Services (feature: `google-ca`)
- ZeroSSL (feature: `zerossl-ca`)
- 自定义 CA 端点支持

### DNS 提供商扩展

- 新增 5 个提供商：Azure, Google Cloud, Alibaba Cloud, GoDaddy, Tencent Cloud
- 总计支持 9 个全球 DNS 提供商
- 所有提供商支持 feature gates 灵活编译

### Webhook 通知系统

- 事件驱动架构，支持 10+ 事件类型
- 多格式支持：JSON, Slack, Discord
- 自动重试和智能错误处理
- WebhookManager 管理多个端点

### 配置管理增强

- TOML 配置文件支持
- 环境变量动态替换 (`${VAR}` 语法)
- 运行时验证和默认值管理
- 多层级配置结构

### 测试环保

- 使用 `temp-env` 替代 unsafe env 赋值
- 完整的测试覆盖
- 安全的环境变量处理

---

## 🎯 Feature Gates 系统

### DNS 提供商 Features

```toml
dns-cloudflare = []        # CloudFlare DNS
dns-route53 = []           # AWS Route53
dns-digitalocean = []      # DigitalOcean
dns-linode = []            # Linode
dns-azure = []             # Azure DNS (新增)
dns-google = []            # Google Cloud DNS (新增)
dns-alibaba = []           # Alibaba Cloud DNS (新增)
dns-godaddy = []           # GoDaddy DNS (新增)
dns-tencent = []           # Tencent Cloud DNS (新增)
```

### CA Features

```toml
google-ca = []             # Google Trust Services
zerossl-ca = []            # ZeroSSL
```

### 其他 Features

```toml
redis = []                 # Redis 存储支持
metrics = []               # Prometheus 监控
cli = []                   # CLI 工具
```

### 使用示例

```bash
# 最小化编译
cargo build --release

# 完整功能
cargo build --release --all-features

# 自定义组合
cargo build --features "dns-cloudflare,dns-azure,google-ca"
```

---

## 🛠️ 代码风格和规范

### Rust 编码规范

#### 1. 模块组织

- 每个主要功能应有一个模块
- 模块内部通过 `pub mod` 导出子模块
- 在 `mod.rs` 中集中导出 public API
- 使用 `#[cfg(...)]` feature gate 条件编译

```rust
// ✅ 推荐
pub mod providers;

#[cfg(feature = "dns-cloudflare")]
pub use providers::CloudFlareDnsProvider;
```

#### 2. 错误处理

- 统一使用 `Result<T>` 类型，其中 `E = AcmeError`
- 使用 `?` 操作符传播错误
- 提供有意义的错误信息
- 在 `error.rs` 中定义错误类型

```rust
// ✅ 推荐
pub fn validate_domain(domain: &str) -> Result<()> {
    if domain.is_empty() {
        return Err(AcmeError::validation("Domain cannot be empty"));
    }
    Ok(())
}
```

#### 3. 异步编程

- 使用 `#[tokio::main]` 和 `#[async_trait]`
- 所有 I/O 操作都应是异步的
- 避免在异步上下文中使用同步 I/O
- 使用 `.await` 等待异步操作

```rust
// ✅ 推荐
#[async_trait]
pub trait DnsProvider {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<String>;
}
```

#### 4. 文档注释

- 为所有 public item 添加文档注释
- 使用 `///` 注释，`//!` 用于模块级文档
- 包括使用示例在文档注释中
- 标记不稳定的 API 为 `#[doc(hidden)]`

```rust
// ✅ 推荐
/// 创建新 ACME 客户端
///
/// # Arguments
/// * `config` - ACME 配置
///
/// # Examples
///
/// ```
/// let client = AcmeClient::new(config)?;
/// ```
pub fn new(config: AcmeConfig) -> Result<Self> { ... }
```

#### 5. 测试

- 所有主要函数都应有单元测试
- 测试模块放在 `#[cfg(test)] mod tests { ... }`
- 使用 `tokio::test` 处理异步测试
- 测试函数名应清晰表达测试内容

```rust
// ✅ 推荐
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_txt_record() {
        // ...
    }
}
```

#### 6. 日志和追踪

- 使用 `tracing` crate 进行日志记录
- 使用 `info!`, `warn!`, `error!` 宏
- 在关键操作前后记录日志
- 不要使用 `println!` 或 `dbg!` (除了 CLI)

```rust
// ✅ 推荐
tracing::info!("Starting ACME order for domains: {:?}", domains);
```

---

## 📝 代码模板和示例

### 新建 Trait

```rust
use async_trait::async_trait;

/// 自定义功能描述
#[async_trait]
pub trait YourTrait: Send + Sync {
    /// 功能描述
    async fn method_name(&self, param: &str) -> Result<String>;

    /// 可选的默认实现
    async fn optional_method(&self) -> Result<()> {
        Ok(())
    }
}
```

### 新建结构体

```rust
/// 结构体描述
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YourStruct {
    /// 字段描述
    pub field1: String,

    /// 可选字段
    #[serde(default)]
    pub field2: Option<String>,
}

impl YourStruct {
    /// 创建新实例
    pub fn new(field1: String) -> Self {
        Self {
            field1,
            field2: None,
        }
    }

    /// Builder 模式
    pub fn with_field2(mut self, field2: String) -> Self {
        self.field2 = Some(field2);
        self
    }
}
```

### 新建模块

```rust
//! 模块级文档，描述该模块的功能和用途

pub mod submodule;

pub use submodule::PublicType;

/// 模块中的主要 trait/结构体
pub struct MainType {
    ...
}

// 所有 public item 都应在文件末尾使用 pub use 导出
pub use crate::error::Result;
```

---

## 🔐 安全和性能

### 安全考虑

- ❌ 不要使用 `unsafe` 块 (除非绝对必要)
- ✅ 使用加密库: `aws-lc-rs` (优先) 或 `ring`
- ✅ 所有密钥都应该通过环境变量配置
- ✅ 敏感信息不应被日志记录
- ✅ 使用 TLS 进行所有网络通信

### 性能考虑

- ✅ 使用异步 I/O 处理并发
- ✅ 使用连接池管理数据库连接
- ✅ 实现缓存机制减少重复计算
- ✅ 避免在循环中进行 I/O 操作
- ✅ 使用 `tokio::spawn_blocking` 处理 CPU 密集操作

---

## 📚 关键文件和函数

### 核心类型

- `AcmeClient` - 主要客户端接口
- `AcmeConfig` - 客户端配置
- `AcmeError` - 统一错误类型
- `ChallengeType` - 验证方式枚举
- `RenewalScheduler` - 自动续期调度器

### 核心 Trait

- `DnsProvider` - DNS 提供商接口
- `ChallengeSolver` - 挑战求解器接口
- `StorageBackend` - 存储后端接口
- `RenewalHook` - 续期钩子接口

### 主要模块

- `account` - 账户和密钥管理
- `order` - 订单生命周期
- `challenge` - 挑战验证
- `dns` - DNS 提供商集成
- `storage` - 证书存储
- `renewal` - 自动续期

---

## 🧪 测试指南

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定测试
cargo test test_name

# 运行集成测试
cargo test --test integration_tests

# 使用日志运行测试
RUST_LOG=debug cargo test -- --nocapture
```

### 编写测试

- 在源文件末尾添加测试模块
- 使用 `#[test]` 标记同步测试
- 使用 `#[tokio::test]` 标记异步测试
- 提供足够的测试覆盖率
- 测试边界情况和错误路径

---

## 🚀 开发工作流

### 1. 新功能开发

```bash
# 1. 创建 feature 分支
git checkout -b feature/your-feature

# 2. 编写代码和测试
# ... 编辑文件 ...

# 3. 运行检查
cargo check --all-features
cargo clippy --all-targets --all-features
cargo test --all-features

# 4. 提交
git add .
git commit -m "feat: add your feature"
```

### 2. 代码质量检查

```bash
# Clippy 检查
cargo clippy --all-targets --all-features -- -D warnings

# 格式检查
cargo fmt --check

# 测试覆盖
cargo tarpaulin --out Html
```

### 3. 文档更新

- 更新相关 `.md` 文件在 `docs/` 目录
- 更新代码注释和 doc comments
- 更新 CHANGELOG 和版本号

---

## 📖 学习资源

### 项目文档

- `docs/INDEX.md` - 文档索引和快速导航
- `docs/MAIN_README.md` - 项目详细介绍
- `docs/V0.4.0_COMPLETION_REPORT.md` - 当前版本详解
- `docs/V0.5.0_PLANNING.md` - 下一版本规划

### 代码组织

- `src/lib.rs` - 公共 API 导出
- `src/error.rs` - 错误类型定义
- `src/types.rs` - 公共类型定义
- 各模块的 `mod.rs` 文件

### Rust 学习

- [Rust 官方书籍](https://doc.rust-lang.org/book/)
- [Async Rust](https://rust-lang.github.io/async-book/)
- [Tokio 教程](https://tokio.rs/tokio/tutorial)

---

## 🎯 Copilot 使用指南

### 提示工程最佳实践

当使用 GitHub Copilot 时:

1. **提供上下文**
    - 告诉 Copilot 你在哪个模块工作
    - 提及相关的 trait 或结构体
    - 引用类似的代码片段

2. **精确的要求**
   ```
   ❌ "写一个函数"
   ✅ "写一个异步函数，实现 DnsProvider trait 的 create_txt_record 方法"
   ```

3. **验证生成的代码**
    - 检查是否遵循项目风格
    - 确保错误处理正确
    - 添加必要的测试
    - 运行 `cargo clippy` 检查

4. **常见代码模式**
    - DNS 提供商实现
    - 存储后端实现
    - 错误处理
    - 异步操作
    - 配置管理

---

## 🔔 关键约定

### 命名约定

- 类型：`PascalCase`
- 函数/变量: `snake_case`
- 常量：`SCREAMING_SNAKE_CASE`
- 模块：`snake_case`

### 导入约定

```rust
// 标准库
use std::path::Path;
use std::collections::HashMap;

// 外部 crate
use serde::{Deserialize, Serialize};
use async_trait::async_trait;

// 同 crate
use crate::error::Result;
use crate::types::ChallengeType;
```

### 特性门 (Feature Gates)

- `aws-lc-rs` - 使用 aws-lc-rs 加密后端
- `ring-crypto` - 使用 ring 加密后端
- `redis` - Redis 存储支持
- `dns-*` - 各 DNS 提供商
- `metrics` - Prometheus 监控
- `cli` - CLI 工具

---

## 📊 项目指标目标

- ✅ **代码行数**: 4544+ (不含测试和文档)
- ✅ **文档行数**: 6500+ (完整覆盖)
- ✅ **测试覆盖**: >80%
- ✅ **编译无错**: 100%
- ✅ **类型安全**: 100% (零 unsafe)
- ✅ **生产就绪**: 是

---

## 🤝 贡献指南

### 提交规范

遵循 Conventional Commits:

- `feat:` 新功能
- `fix:` 错误修复
- `docs:` 文档更新
- `test:` 测试添加
- `refactor:` 代码重构
- `perf:` 性能优化
- `chore:` 其他变更

### Pull Request

- 提供清晰的描述
- 链接相关 issue
- 包含测试和文档
- 运行完整的检查流程

---

## ✅ 最终检查清单

在提交代码前，确保：

- [ ] 代码已格式化: `cargo fmt`
- [ ] 无 Clippy 警告: `cargo clippy -- -D warnings`
- [ ] 所有测试通过: `cargo test --all-features`
- [ ] 添加了必要的文档注释
- [ ] 更新了相关文档文件
- [ ] 遵循了项目的代码风格
- [ ] 提供了有意义的提交信息

---

**项目版本**: v0.5.0  
**最后更新**: 2026-02-07  
**维护者**: houseme

🚀 **欢迎使用 Copilot 为 AcmeX 贡献代码！**
