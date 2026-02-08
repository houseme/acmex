# AcmeX 架构设计文档

## 1. 概述
AcmeX 是一个高性能、模块化的 Rust ACME v2 (RFC 8555) 客户端库和服务器。它旨在为企业提供自动化证书管理（PKI）的完整解决方案。

## 2. 分层架构

### 2.1 应用层 (Application Layer)
- **CLI**: 提供命令行工具，用于手动触发证书签发、账户管理等。
- **Server**: 基于 Axum 的 REST API 服务器，支持异步任务处理和 Webhook 通知。

### 2.2 编排层 (Orchestration Layer)
- **Orchestrator**: 核心状态机，负责协调从域名验证到证书下载的完整流程。
- **Provisioner**: 处理证书的实际部署逻辑。

### 2.3 调度层 (Scheduling Layer)
- **Scheduler**: 管理证书续订任务的定时触发。
- **Task Tracker**: 监控后台任务的状态和进度。

### 2.4 协议层 (Protocol Layer)
- **JWS/JWK**: 实现 RFC 7515/7517 标准的签名和密钥管理。
- **Nonce Manager**: 自动处理 ACME 协议中的防重放随机数。
- **Directory Manager**: 发现和缓存 ACME 服务端点。

### 2.5 存储层 (Storage Tier)
- **File Storage**: 本地文件系统持久化。
- **Redis Storage**: 分布式环境下的状态共享。
- **Encrypted Storage**: 对敏感数据（如私钥）进行静态加密。

## 3. 核心流程：证书签发
1. **账户注册**: 使用 Ed25519 密钥对在 ACME 服务器注册。
2. **创建订单**: 提交需要签发证书的域名列表。
3. **域名验证**:
   - `HTTP-01`: 通过 Web 服务放置验证文件。
   - `DNS-01`: 通过 DNS 提供商（如 Cloudflare）添加 TXT 记录。
4. **订单完成**: 提交 CSR（证书签名请求）。
5. **下载证书**: 获取完整的证书链并持久化存储。

## 4. 可观测性
- **Tracing**: 结构化日志记录，支持 OpenTelemetry。
- **Metrics**: 导出 Prometheus 格式的指标（请求成功率、续订状态等）。

## 5. 安全性
- **内存安全**: 利用 Rust 的所有权模型。
- **敏感数据保护**: 使用 `zeroize` 库在内存中擦除密钥。
- **标准化错误**: 遵循 RFC 7807 提供详细的错误反馈。
