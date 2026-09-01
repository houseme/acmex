# AcmeX 文档中心

**当前代码版本**：v0.8.0
**下一架构演进版本**：v0.9.0
**最后更新**：2026-08-31

## 当前推荐阅读

1. [当前功能、架构评估与目标架构设计](./ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md)
2. [v0.9.0 架构演进实施路线图](./roadmap/v0.9.0/README.md)
3. [完整文档索引](./INDEX.md)
4. [仓库 Agent 开发约定](../AGENTS.md)

## v0.9.0 任务包

| ID | 任务 | 作用 |
|---|---|---|
| T01 | [领域模型与策略](./roadmap/v0.9.0/T01_DOMAIN_MODEL_AND_POLICY.md) | 建立 DNS/IP、Intent、Lineage 和兼容矩阵 |
| T02 | [Repository 与迁移](./roadmap/v0.9.0/T02_REPOSITORY_AND_MIGRATION.md) | 建立持久化实体、CAS、Lease 和旧数据迁移 |
| T03 | [持久化 Workflow](./roadmap/v0.9.0/T03_DURABLE_WORKFLOW_ENGINE.md) | 支持幂等、恢复、取消和补偿 |
| T04 | [CA Backend](./roadmap/v0.9.0/T04_CA_BACKEND_AND_PROTOCOL.md) | 统一 ACME Session、Retry、Profiles 和 ARI |
| T05 | [Challenge 生命周期](./roadmap/v0.9.0/T05_CHALLENGE_LIFECYCLE.md) | 独立 Session、Lease 和最终清理 |
| T06 | [DNS Provider 与传播](./roadmap/v0.9.0/T06_DNS_PROVIDER_AND_PROPAGATION.md) | Provider Factory、Zone、委派和传播 quorum |
| T07 | [HTTP/TLS 与 IP](./roadmap/v0.9.0/T07_HTTP_TLS_AND_IP_VALIDATION.md) | Edge Presenter 和 RFC 8738 IPv4/IPv6 |
| T08 | [Application/API/CLI](./roadmap/v0.9.0/T08_APPLICATION_SERVICE_AND_API.md) | 统一所有上游入口，移除模拟业务逻辑 |
| T09 | [续签控制器](./roadmap/v0.9.0/T09_RENEWAL_CONTROLLER.md) | ARI、fallback、jitter、Lease 和短周期证书 |
| T10 | [KeyProvider 与 Sink](./roadmap/v0.9.0/T10_KEY_PROVIDER_AND_SINKS.md) | 密钥边界、不可变版本、原子部署和回滚 |
| T11 | [安全、可观测性、HA](./roadmap/v0.9.0/T11_SECURITY_OBSERVABILITY_HA.md) | Secret、审计、指标、健康和多实例 |
| T12 | [E2E 与发布门槛](./roadmap/v0.9.0/T12_E2E_AND_RELEASE_GATES.md) | Pebble、故障注入、恢复矩阵和 CI 准入 |

## 历史文档说明

`docs/` 中保留了 v0.1.0-v0.8.0 的规划、完成报告和使用指南。这些文档用于追踪历史演进；其中部分“已完成”描述不等价于当前生产闭环已经通过验证。

评估当前能力时，以当前代码、测试证据和 [当前架构总纲](./ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md) 为准。
