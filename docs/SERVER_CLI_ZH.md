# AcmeX 服务端与命令行工具 (Server & CLI) 功能文档

## 1. 概述
AcmeX 提供了两种主要的交互方式：基于 Axum 的高性能 REST API 服务端和功能丰富的命令行工具（CLI）。两者共享底层的 ACME 协议栈、编排逻辑和存储后端。

## 2. REST API 服务端 (`server`)

### 2.1 核心特性
- **异步任务处理**: 耗时的证书签发和验证任务在后台运行，API 立即返回任务 ID。
- **安全性**: 
  - 支持基于 API Key 的身份验证（通过 `ACMEX_API_KEYS` 环境变量配置）。
  - 结构化错误报告（遵循 RFC 7807）。
- **可观测性**: 
  - 内置 `/health` 端点，支持集成到 Kubernetes 或负载均衡器。
  - 支持 Webhook 通知，实时推送证书状态变更。

### 2.2 主要端点
- `POST /api/accounts`: 注册新账户。
- `POST /api/orders`: 创建证书订单。
- `GET /api/certificates`: 列出所有托管的证书。
- `POST /api/certificates/:id/renew`: 手动触发特定证书的续订。

## 3. 命令行工具 (`cli`)

### 3.1 核心命令
- **`obtain`**: 一键获取新证书。支持 `HTTP-01` 和 `DNS-01` 挑战。
- **`renew`**: 检查并续订即将过期的证书。支持 `--force` 强制续订。
- **`daemon`**: 以守护进程模式运行，自动执行定时续订任务。
- **`account`**: 管理 ACME 账户，支持注册、更新、停用和密钥轮转（Rotate Key）。
- **`serve`**: 启动 REST API 服务器。

### 3.2 日志与调试
- 支持通过 `--log-level` 动态调整日志详细程度（`debug`, `info`, `warn`, `error`）。
- 结构化输出，包含线程 ID 和时间戳，方便排查并发问题。

## 4. 部署建议
- **单机环境**: 直接使用 CLI 的 `daemon` 模式。
- **集群环境**: 部署 `serve` 模式，并配置 Redis 存储后端以实现状态共享。
