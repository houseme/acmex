# GitHub Copilot 项目指导

**项目名称**: AcmeX  
**项目描述**: 企业级 ACME v2 客户端库和工具集  
**当前版本**: v0.7.0-dev (Phase 4 Ready)  
**Rust 版本**: 1.93.0 (Edition 2024)  
**MSRV**: 1.92.0

---

## 🎯 项目概览

AcmeX 是一个完整的 ACME v2 (RFC 8555) 协议实现库，专为自动化 TLS 证书管理设计。

### 核心特性 (v0.7.0 已强化)

- ✅ **完整协议支持**: 涵盖 JWS, Nonce Pool, EAB, Key Rollover。
- ✅ **多挑战类型**: HTTP-01, DNS-01, TLS-ALPN-01。
- ✅ **广阔 DNS 生态**: 集成 11 个提供商 (CloudFlare, AWS, Ali, Tencent, Huawei, CloudNS 等)。
- ✅ **高性能 Nonce 管理**: 具备预取与缓存能力的 `NoncePool`。
- ✅ **企业级服务器**: Axum 驱动的核心 API，支持 `X-API-Key` 认证。
- ✅ **异步任务架构**: 202 Accepted 响应模型，支持后台进度追踪。
- ✅ **OCSP 实时验证**: 自动解析 AIA 扩展并查询撤销状态。
- ✅ **灵活存储与审计**: 支持 4 种后端并具备事件审计日志 (`EventAuditor`)。

---

## 📁 核心架构

- `src/orchestrator/`: 编排层 (Provisioner, Validator, Renewer)，支持状态汇报。
- `src/scheduler/`: 调度层 (Priority, Concurrency, Retry)。
- `src/server/`: API 服务器层 (Auth, Routes, Tasks Tracker)。
- `src/protocol/nonce_pool.rs`: 预取 Nonce 优化请求往返。
- `src/certificate/ocsp.rs`: OCSP 验证工具。

---

## 🚀 Phase 5 (v0.7.0+) 目标：测试与文档强化

### 1. 自动化测试体系

- 实现基于 `mockito` 的 ACME 服务端模拟桩。
- 覆盖 DNS-01 (Route53, Huawei, Alibaba) 的端到端集成测试。
- 压力测试：并发 100+ 证书申请任务的性能表现。

### 2. 文档与开发者体验

- 完整补全 `docs/` 下的各模块开发者手册。
- 提供 OpenTelemetry + Prometheus 的 Grafana 仪表盘配置示例。
- 编写 API 生成的 OpenAPI (Swagger) 定义文件。

### 3. 发布准备

- 修复所有编译警告与 Clippy 建议。
- 确保集成测试在 GitHub Actions 中 100% 通过。

---

## 🛠️ 代码规范与最佳实践 (v0.7.0 专用)

### 1. 异步任务处理

- API 处理器 **不应** 阻塞。始终使用 `rand::rng().sample_iter(...)` 生成 `task_id`。
- 始终将任务状态更新至 `AppState::tasks` 以供前端轮询。

### 2. 错误处理与审计

- 始终调用 `AcmeError::to_problem_details()`。
- 关键业务行为必须调用 `EventAuditor::track_event`。

### 3. 特征门控 (Feature Gating)

- 新增组件或 Provider 必须在 `Cargo.toml` 中定义独立 feature 并在 `mod.rs` 中使用 `#[cfg(feature = "...")]`。

---

## 🎯 Copilot 调用提示 (v0.7.0 进阶)

### API 扩展

```
"在 src/server/order.rs 中重构 list_orders，使其返回 AppState 中所有任务的 TaskInfo。"
"在 src/server/auth.rs 中实现基于环境变量动态加载 API Keys 的逻辑。"
```

### 挑战实现

```
"为 HuaweiCloudDnsProvider 增加基于 reqwest::Client 的真实 POST 请求逻辑，实现 TXT 记录的物理删除。"
```

---

**项目版本**: v0.7.0-dev  
**最后更新**: 2026-02-08  
**维护者**: houseme
