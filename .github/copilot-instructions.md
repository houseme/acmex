# GitHub Copilot 项目指导

**项目名称**: AcmeX  
**项目描述**: 企业级 ACME v2 客户端库和工具集  
**当前版本**: v0.6.0  
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
- ✅ CLI 工具框架 (obtain, renew, daemon, info, account, server)
- ✅ Feature gates 灵活编译
- ✅ 生产级质量
- ✅ 证书链验证与 Key Rollover
- ✅ DNS 查询缓存

---

## 📁 项目结构

### 源代码组织

```
src/
├── lib.rs                     # 库根，模块导出
├── main.rs                    # CLI 入口
├── ca.rs                      # 多CA支持
├── config.rs                  # 配置管理
├── account/                   # 账户管理 (含 Key Rollover)
├── challenge/                 # 挑战验证框架 (含 DNS 缓存)
├── client/                    # 主要客户端
├── order/                     # 订单管理 (含 Revocation)
├── protocol/                  # ACME 协议
├── dns/                       # DNS 提供商
├── storage/                   # 证书存储
├── renewal/                   # 自动续期
├── notifications/             # Webhook通知
├── metrics/                   # Prometheus 指标
├── cli/                       # CLI 工具 (含 account, server 命令)
├── crypto/                    # 加密模块
├── transport/                 # HTTP传输
├── orchestrator/              # 编排层 (Provisioner, Validator)
├── server/                    # 服务器层 (API, Webhook, Health)
├── certificate/               # 证书管理 (Chain verification)
├── scheduler/                 # 调度层 (v0.6.0+ 正在实现)
├── error.rs                   # 错误类型
└── types.rs                   # 公共类型
```

---

## 🚀 Phase 3 (第三周) 目标

### 1. 高级调度器 (Advanced Scheduler)
- `src/scheduler/renewal_scheduler.rs`: 支持多任务并发、优先级管理、故障恢复。
- `src/scheduler/cleanup_scheduler.rs`: 自动清理过期证书和临时文件。

### 2. 存储迁移工具 (Storage Migration)
- 支持在不同存储后端（如 File 到 Redis）之间迁移数据。

### 3. 分布式追踪 (Distributed Tracing)
- 集成 `tracing-opentelemetry`，支持全链路追踪。

### 4. 高级 CLI 命令
- 完善 `order` 和 `cert` 相关命令，提供更丰富的交互体验。

---

## 🛠️ 代码风格和规范 (保持一致)

### 1. 异步与并发
- 使用 `tokio` 进行异步调度。
- 任务执行应具备超时控制和重试机制。

### 2. 错误处理
- 延续 `AcmeError` 体系。
- 调度器中的错误应记录详细上下文，不影响其他并发任务。

### 3. 监控与日志
- 调度任务的开始、成功、失败均需记录 `tracing` 日志。
- 暴露任务执行状态的 Prometheus 指标。

---

## 🎯 Copilot 使用指南 (Phase 3 专用)

### 调度器实现提示
```
"实现一个基于 tokio 的任务调度器，支持 Cron 表达式或固定间隔，具备优雅关闭功能。"
"为调度器添加任务优先级队列，确保紧急续期任务优先执行。"
```

### 存储迁移提示
```
"编写一个工具函数，将所有账户和证书数据从 FileStorage 批量迁移到 RedisStorage，并验证完整性。"
```

---

**项目版本**: v0.6.0  
**最后更新**: 2026-02-07  
**维护者**: houseme
