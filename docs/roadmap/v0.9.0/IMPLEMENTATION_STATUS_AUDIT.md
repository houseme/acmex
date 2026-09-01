# AcmeX v0.9.0 实现状态核查

**核查日期**：2026-09-01
**核查基线**：`main@3ead534`
**结论**：T01-T12 代码与本地发布门槛已全部合并(常规测试证据齐全)；Pebble 与 L4/L5 外部环境证据按 KNOWN_LIMITATIONS 显式列为未执行,不作为已通过发布门槛。

本文以 `docs/roadmap/v0.9.0/` 下的任务文档为验收来源，避免旧版本完成报告覆盖当前真实状态。除非有明确测试或源码证据，不把占位、fake adapter、局部模型或文档草案视为生产闭环完成。

## 总览

| 任务 | 当前状态 | 主要证据 | 主要缺口 |
|---|---|---|---|
| T01 | 已合并 | PR #189；`src/domain/*`；`T01_MIGRATION_NOTES.md` | 后续任务扩展仍需保持序列化兼容 |
| T02 | 已合并 | PR #190；`src/repository/*`；`tests/repository_contract.rs` | Redis repository 合同测试仍属于后续扩展 |
| T03 | 已合并 | PR #191；`src/workflow/*`；`tests/workflow_engine_test.rs` | 真实外部崩溃恢复仍待 T12 扩展 |
| T04 | 已合并 | PR #192；`src/ca_backend/*`；`tests/ca_backend_test.rs` | 真实 CA staging E2E 未由本任务证明 |
| T05 | 已合并 | PR #193；`src/challenge/session.rs`、`src/challenge/steps.rs`；`tests/challenge_lifecycle_test.rs` | 真实 DNS/HTTP/TLS adapter E2E 依赖 T06/T07/T12 |
| T06 | 已合并 | PR #194；`src/dns/factory.rs`、`src/dns/zone.rs`、`src/dns/propagation.rs`；`tests/dns_provider_contract.rs` | 真实云 Provider 默认仍需 ignored/manual 验证 |
| T07 | 已合并 | PR #195；`src/challenge/http01_presenter.rs`、`src/challenge/tls_alpn01.rs`、`src/challenge/edge.rs` | Pebble 级 HTTP/TLS/IP E2E 待 T12 |
| T08 | 已合并 | PR #196；`src/application/*`、`src/server/api_v1.rs`、CLI obtain/renew 接入 Application Service | Legacy `/api` 路由仍保留旧 task 兼容面 |
| T09 | 已合并 | PR #197、#198；`src/renewal/mod.rs`；`tests/renewal_controller_test.rs` | Deployment 子 Operation 需要 T10 Sink 完成后闭环 |
| T10 | 已合并 | PR #201/#202/#204/#206;`src/key`、`src/delivery`、File/FakeAgent/HttpAgent Sink、部署编排门控、`tests/key_provider_test.rs`、`tests/certificate_sink_contract.rs`、`tests/http_agent_sink_test.rs` | Redis/K8s/Vault 实例与远端 Agent 实环境未执行 |
| T11 | 已合并 | PR #200/#205;哈希 API Key + 常量时间校验、SecretRef 全链路、Outbox Consumer(DLQ/重放)、`docs/SECURITY_OBSERVABILITY_HA.md`、`tests/outbox_consumer_test.rs` | mTLS/OIDC 留待后续;多实例 fencing 的真实多进程演练待 T12 环境 |
| T12 | 已合并(本地门槛) | PR #203;`scripts/`(pebble/feature/restart/docs/performance)、`tests/e2e_restart_matrix.rs`、`tests/fault_injection_matrix.rs`、`tests/release_gate_docs.rs`、CI workflow、RELEASE_CHECKLIST/KNOWN_LIMITATIONS/PERFORMANCE_BASELINE | Pebble/L4/L5 需外部环境显式执行后才算发布通过 |

## 今日合并记录

| PR | 任务 | Merge commit |
|---|---|---|
| #206 | HttpAgentSink 契约测试 | `df6e9df` |
| #205 | T11 安全可观测性/Outbox 加固 | `f3b3124` |
| #204 | T10 部署编排门控 | `899fde1` |
| #203 | T12 发布门槛 | `d847d41` |
| #202 | T10 冲突解决合并(含 HttpAgentSink) | `aa9da4a` |
| #201 | T10 KeyProvider/Sink 单文件实现 | `aa82dd2` |
| #189 | T01 Domain Model | `e4ee51f` |
| #190 | T02 Repository | `6fe3a57` |
| #191 | T03 Workflow | `a70efff` |
| #192 | T04 CA Backend | `1a47b3f` |
| #193 | T05 Challenge Lifecycle | `a947391` |
| #194 | T06 DNS Provider/Propagation | `7802c8a` |
| #195 | T07 HTTP/TLS/IP | `3eced66` |
| #196 | T08 Application/API | `bb9f111` |
| #197 | T09 Renewal Controller | `76638ce` |
| #198 | T09 Review Optimization | `3ead534` |

## 仍不能标记 v0.9.0 完成的原因

1. **从 Intent 到 Active Deployment 的完整闭环尚未存在**：T10 的 KeyProvider、CertificateSink、File Sink 原子激活、第二 Sink/Agent 和 Deployment 子 Operation 还没有实现。
2. **生产安全基线尚未闭合**：虽然没有继续使用默认管理密钥，且本次认证状态不再保存明文 API key，但 T11 要求的 AuthN/AuthZ、权限、审计主体、Webhook Consumer、SLO 和多实例 Outbox fencing 仍未完整交付。
3. **发布门槛尚未建立**：T12 要求 Pebble E2E、崩溃恢复矩阵、故障注入、CI feature matrix、docs/OpenAPI/config 校验和性能基线。当前仓库没有 `scripts/` 目录，也没有相应 E2E harness。
4. **真实外部验证仍是边界条件**：真实 CA staging、真实 DNS Provider、Redis/Kubernetes/Vault 等环境验证不能由本地 fake/contract 测试推导为完成。

## 建议后续顺序

1. **T10 优先**：实现 `KeyProvider`、`CertificateMaterialBuilder`、`CertificateSink`、File Sink 与 HTTP Agent/Fake Server 契约测试，使 T09 的 active version 切换具备真实部署前提。
2. **T11 第二步**：在 T10 的 deployment/outbox 事件稳定后，补 Authenticator/Authorizer、Webhook Consumer、审计主体、低基数指标和多实例消费 fencing。
3. **T12 最后收口**：建立 Pebble E2E、restart/fault harness、feature/docs/OpenAPI/config 校验和 release checklist，再更新 roadmap 状态为完成。

## 本次安全修复关联

本次分支同时修复 Dependabot #11、#12、#14：通过关闭 AWS SDK legacy `rustls` feature，移除 `rustls-webpki 0.101.7`、`rustls 0.21.12`、`hyper-rustls 0.24.2` 等旧 TLS 依赖链；全 feature 依赖图仅保留 `rustls-webpki 0.103.15`。
