# 📑 AcmeX 项目文档索引

> 本文件是 `docs/` 目录的导航索引。文档之间存在大量历史快照，阅读任何一份文档前，请先对照下方「现行事实来源」排序判断其权威度。

**最后更新**: 2026-09-05  
**索引覆盖**: `docs/` 全部现存文档（含 `roadmap/`、`api/` 子目录）  
**说明**: 索引只做归类与标注，文档文件本身保持在原位。`docs/PROJECT_ANALYSIS_AND_PLAN_ZH.md` 未纳入版本库，故不在本索引中。

---

## 🧭 现行事实来源（按权威度排序）

文档内容冲突时，**按以下顺序取信**；历史存档类文档一律以下方现行来源为准：

1. **现行路线图与收口状态** — [roadmap/v0.10.0/README.md](roadmap/v0.10.0/README.md)（v0.10.0 验证与收口路线图，承接 v0.9.0 T01-T12 的遗留缺口与外部门槛；另有 [RELEASE_DECISION.md](roadmap/v0.10.0/RELEASE_DECISION.md) 与 T13-T21 任务文档）。
2. **v0.9.0 实现审计与已知限制** — [roadmap/v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md](roadmap/v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md) 与 [roadmap/v0.9.0/KNOWN_LIMITATIONS.md](roadmap/v0.9.0/KNOWN_LIMITATIONS.md)（已核实的实现事实、明确不做的部分与外部门槛；配套 [VALIDATION_EVIDENCE.md](roadmap/v0.9.0/VALIDATION_EVIDENCE.md)、[E2E_RELEASE_GATES.md](roadmap/v0.9.0/E2E_RELEASE_GATES.md)、[FEATURE_MATRIX.md](roadmap/v0.9.0/FEATURE_MATRIX.md)）。
3. **架构文档** — [ARCHITECTURE.md](ARCHITECTURE.md)（目标架构与模块设计；描述的是设计意图，实际完成度以上面第 1、2 层为准）。
4. **历史报告（存档，不代表现状）** — 各版本完成报告、交付清单、状态快照等，见下方[历史存档](#-历史存档不代表现状)章节。它们记录的是写作当时的状态，其中的 API、命令、功能清单普遍已过时。

版本变更事实以仓库根目录 `CHANGELOG.md` 为准（本次不在索引改动范围内，仅作指针）。

---

## 📚 现行文档

### 路线图（roadmap/）

| 文档 | 描述 |
|------|------|
| [roadmap/v0.10.0/README.md](roadmap/v0.10.0/README.md) | 现行路线图：v0.9.0 之后的验证与收口（T13-T21） |
| [roadmap/v0.10.0/RELEASE_DECISION.md](roadmap/v0.10.0/RELEASE_DECISION.md) | 发布决策记录（明确未验证的外部门槛） |
| [roadmap/v0.9.0/README.md](roadmap/v0.9.0/README.md) | v0.9.0 实施路线图（T01-T12）总入口 |
| [roadmap/v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md](roadmap/v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md) | 实现状态审计：每项任务的核实结果 |
| [roadmap/v0.9.0/KNOWN_LIMITATIONS.md](roadmap/v0.9.0/KNOWN_LIMITATIONS.md) | 已知限制与明确不做的事项 |
| [roadmap/v0.9.0/T01…T12](roadmap/v0.9.0/T03_DURABLE_WORKFLOW_ENGINE.md) | 各任务设计/验收文档（T01 领域模型 … T12 端到端与发布门禁） |
| [roadmap/v0.9.0/FEATURE_MATRIX.md](roadmap/v0.9.0/FEATURE_MATRIX.md) | Cargo feature 与文档/实现的对照矩阵 |
| [roadmap/v0.9.0/E2E_RELEASE_GATES.md](roadmap/v0.9.0/E2E_RELEASE_GATES.md) / [RELEASE_CHECKLIST.md](roadmap/v0.9.0/RELEASE_CHECKLIST.md) | L1-L5 发布门禁与发布检查单 |
| [roadmap/v0.9.0/PERFORMANCE_BASELINE.md](roadmap/v0.9.0/PERFORMANCE_BASELINE.md) / [LIVE_INFRASTRUCTURE_EVIDENCE.md](roadmap/v0.9.0/LIVE_INFRASTRUCTURE_EVIDENCE.md) / [EXTERNAL_E2E_ENVIRONMENT.md](roadmap/v0.9.0/EXTERNAL_E2E_ENVIRONMENT.md) | 性能基线与外部环境证据 |

### 架构与设计

| 文档 | 描述 |
|------|------|
| [ARCHITECTURE.md](ARCHITECTURE.md) / [ARCHITECTURE_ZH.md](ARCHITECTURE_ZH.md) | 系统架构设计（英文/中文）；设计意图层面最完整的文档 |
| [ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md](ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md) | 当前状态与目标架构评估（中文，2026 年评估稿） |

### API 与迁移

| 文档 | 描述 |
|------|------|
| [api/openapi.yaml](api/openapi.yaml) | API v1 的 OpenAPI 规范（与 `src/server/api_v1.rs` 路由锁步，由 `tests/release_gate_docs.rs` 门禁约束） |
| [API_V1_MIGRATION.md](API_V1_MIGRATION.md) | 旧 `/api` 到 API v1 的迁移指南（含 Sunset 日期） |
| [MIGRATION_v0.9.0.md](MIGRATION_v0.9.0.md) / [MIGRATION_v0.10.0.md](MIGRATION_v0.10.0.md) | v0.9.0 / v0.10.0 迁移说明 |
| [RELEASE_NOTES_v0.9.0.md](RELEASE_NOTES_v0.9.0.md) / [RELEASE_NOTES_v0.10.0.md](RELEASE_NOTES_v0.10.0.md) | 版本发布说明 |
| [MIGRATION_v0.8.0.md](MIGRATION_v0.8.0.md) / [RELEASE_NOTES_v0.5.0.md](RELEASE_NOTES_v0.5.0.md) / [RELEASE_NOTES_v0.8.0.md](RELEASE_NOTES_v0.8.0.md) | 早期版本迁移与发布说明（快照性质，按需参考） |

### 专题参考

| 文档 | 描述 |
|------|------|
| [OBSERVABILITY.md](OBSERVABILITY.md) | 指标、日志与追踪配置 |
| [CRYPTO.md](CRYPTO.md) / [CRYPTO_ZH.md](CRYPTO_ZH.md) | 加密后端（aws-lc-rs / ring）说明 |
| [DNS_PROVIDERS.md](DNS_PROVIDERS.md) | DNS 提供商与凭据配置 |
| [SECURITY_OBSERVABILITY_HA.md](SECURITY_OBSERVABILITY_HA.md) | 安全 / 可观测 / 高可用专题（早期稿，细节以 v0.9.0 T11 文档为准） |

### 中文专题文档（早期 API 快照，注意滞后）

> 以下中文专题文档写于 v0.8 及之前，描述的调度器/编排 API 部分已被 v0.9+ 的 `RenewalController` 与 durable workflow 取代；概念介绍仍有价值，API 细节以代码和 roadmap 文档为准。

| 文档 | 主题 |
|------|------|
| [SERVER_CLI_ZH.md](SERVER_CLI_ZH.md) | 服务器与 CLI 使用 |
| [STORAGE_ZH.md](STORAGE_ZH.md) | 存储后端 |
| [TRANSPORT_ZH.md](TRANSPORT_ZH.md) | ACME 传输层 |
| [ORCHESTRATOR_ZH.md](ORCHESTRATOR_ZH.md) | 编排层概念 |
| [RENEWAL_SCHEDULER_ZH.md](RENEWAL_SCHEDULER_ZH.md) | 续订与调度（描述的是已废弃的 Simple/Advanced 调度器，现行方案见 `RenewalController` 与 [roadmap/v0.9.0/T09_RENEWAL_CONTROLLER.md](roadmap/v0.9.0/T09_RENEWAL_CONTROLLER.md)） |
| [MULTI_CA_SUPPORT_ZH.md](MULTI_CA_SUPPORT_ZH.md) | 多 CA 支持 |

### 示例代码

见 [examples/README.md](../examples/README.md)（含「现行 durable workflow API」与「legacy `AcmeClient` 风格」的划分）：

- [intent_issuance.rs](../examples/intent_issuance.rs) — v0.9+ 意图签发全流程（离线可跑）
- [renewal_controller.rs](../examples/renewal_controller.rs) — v0.9+ `RenewalController` 续订决策（离线可跑）
- [basic_issuance.rs](../examples/basic_issuance.rs) / [api_server_custom.rs](../examples/api_server_custom.rs) / [dns_01_challenge.rs](../examples/dns_01_challenge.rs) — legacy 风格

---

## 🗄 历史存档（不代表现状）

> 以下 **55 份**文档是 v0.1-v0.7 各阶段的完成报告、交付/验收清单、状态快照与阶段性规划。它们只在写作当时成立：其中的 API 签名、命令行、功能清单、行数统计和「完成度」结论均已过时，**不得作为现行行为的依据**。文件保留原位仅作历史参考；现行事实请按本文件顶部排序取信。

### 版本完成报告与总结（V0.x）

| 文档 | 阶段 |
|------|------|
| [FINAL_V0.2.0_SUMMARY.md](FINAL_V0.2.0_SUMMARY.md) / [V0.2.0_COMPLETION_REPORT.md](V0.2.0_COMPLETION_REPORT.md) / [V0.2.0_README.md](V0.2.0_README.md) / [V0.2.0_SUMMARY.md](V0.2.0_SUMMARY.md) | v0.2.0 |
| [V0.3.0_COMPLETION_REPORT.md](V0.3.0_COMPLETION_REPORT.md) / [V0.3.0_INTEGRATION_EXAMPLES.md](V0.3.0_INTEGRATION_EXAMPLES.md) | v0.3.0 |
| [V0.4.0_COMPLETION_REPORT.md](V0.4.0_COMPLETION_REPORT.md) / [V0.4.0_USAGE_GUIDE.md](V0.4.0_USAGE_GUIDE.md) | v0.4.0 |
| [V0.5.0_CHECKLIST.md](V0.5.0_CHECKLIST.md) / [V0.5.0_COMPLETION_REPORT.md](V0.5.0_COMPLETION_REPORT.md) / [V0.5.0_FEATURES_GUIDE.md](V0.5.0_FEATURES_GUIDE.md) / [V0.5.0_FINAL_STATUS.md](V0.5.0_FINAL_STATUS.md) / [V0.5.0_FINAL_SUMMARY.md](V0.5.0_FINAL_SUMMARY.md) / [V0.5.0_IMPLEMENTATION_REPORT.md](V0.5.0_IMPLEMENTATION_REPORT.md) / [V0.5.0_IMPLEMENTATION_SUMMARY.md](V0.5.0_IMPLEMENTATION_SUMMARY.md) / [V0.5.0_NEXT_STEPS.md](V0.5.0_NEXT_STEPS.md) / [V0.5.0_PLANNING.md](V0.5.0_PLANNING.md) / [V0.5.0_STATUS.md](V0.5.0_STATUS.md) / [V0.5.0_WORK_REPORT.md](V0.5.0_WORK_REPORT.md) | v0.5.0 |
| [V0.6.0_COMPLETION_REPORT.md](V0.6.0_COMPLETION_REPORT.md) / [V0.6.0_IMPLEMENTATION_ROADMAP.md](V0.6.0_IMPLEMENTATION_ROADMAP.md) | v0.6.0 |
| [V0.7.0_PLANNING.md](V0.7.0_PLANNING.md) / [V0.7.0_IMPLEMENTATION_DETAIL_PLAN.md](V0.7.0_IMPLEMENTATION_DETAIL_PLAN.md) / [V0.7.0_PHASE_5_PLAN.md](V0.7.0_PHASE_5_PLAN.md) | v0.7.0 |

### 交付与完成声明（跨版本）

| 文档 | 主题 |
|------|------|
| [FINAL_DELIVERABLES.md](FINAL_DELIVERABLES.md) / [FINAL_DELIVERY_CHECKLIST.md](FINAL_DELIVERY_CHECKLIST.md) / [DELIVERABLES_CHECKLIST.md](DELIVERABLES_CHECKLIST.md) | 交付物清单 |
| [FINAL_PROJECT_SUMMARY.md](FINAL_PROJECT_SUMMARY.md) / [FINAL_REPORT_ZH.md](FINAL_REPORT_ZH.md) | 项目级总结报告 |
| [PROJECT_COMPLETION.md](PROJECT_COMPLETION.md) / [PROJECT_COMPLETION_REPORT.md](PROJECT_COMPLETION_REPORT.md) / [PROJECT_COMPLETION_STATEMENT.md](PROJECT_COMPLETION_STATEMENT.md) / [PROJECT_DELIVERY_STATEMENT.md](PROJECT_DELIVERY_STATEMENT.md) | 完成/交付声明 |
| [TASK_COMPLETION_REPORT.md](TASK_COMPLETION_REPORT.md) / [IMPLEMENTATION_COMPLETION_REPORT.md](IMPLEMENTATION_COMPLETION_REPORT.md) / [ARCHITECTURE_COMPLETION_REPORT.md](ARCHITECTURE_COMPLETION_REPORT.md) | 单任务/架构完成报告 |
| [COMPLETE_CHECKLIST.md](COMPLETE_CHECKLIST.md) / [COMPLETION_CHECKLIST.md](COMPLETION_CHECKLIST.md) | 文件/完成度清单 |
| [ARCHITECTURE_COMPARISON_REPORT.md](ARCHITECTURE_COMPARISON_REPORT.md) | 架构对比报告（快照） |
| [COMPILATION_STATUS_REPORT.md](COMPILATION_STATUS_REPORT.md) / [COMPILATION_SUCCESS_REPORT.md](COMPILATION_SUCCESS_REPORT.md) | 编译状态快照 |
| [CLI_IMPLEMENTATION_SUMMARY.md](CLI_IMPLEMENTATION_SUMMARY.md) / [FUNCTIONALITY_ANALYSIS.md](FUNCTIONALITY_ANALYSIS.md) | CLI 实现总结与功能完成度评估（当时结论） |

### 早期实现专题与规划（v0.1-v0.6，教学快照）

| 文档 | 主题 |
|------|------|
| [IMPLEMENTATION_v0.1.0.md](IMPLEMENTATION_v0.1.0.md) / [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) / [ACMEX_ARCHITECTURE_DESIGN_AND_FUNCTIONAL_PLANNING_SOLUTION.md](ACMEX_ARCHITECTURE_DESIGN_AND_FUNCTIONAL_PLANNING_SOLUTION.md) | 早期实现计划与架构重构规划 |
| [UNIMPLEMENTED_FEATURES.md](UNIMPLEMENTED_FEATURES.md) | 功能对比与待实现清单（已自我标注为 v0.6.0 时期过时快照） |
| [HTTP-01_IMPLEMENTATION.md](HTTP-01_IMPLEMENTATION.md) / [DNS-01_IMPLEMENTATION.md](DNS-01_IMPLEMENTATION.md) / [CHALLENGE_EXAMPLES.md](CHALLENGE_EXAMPLES.md) | 挑战验证实现专题（现行入口见 `src/challenge/` 与 roadmap T05/T06/T07） |
| [QUICK_REFERENCE.md](QUICK_REFERENCE.md) / [QUICK_REFERENCE_0.4.0.md](QUICK_REFERENCE_0.4.0.md) / [MAIN_README.md](MAIN_README.md) | 早期快速参考/介绍页 |
| [INDEX.md](INDEX.md) / [README.md](README.md) | 早期的 docs 索引/首页（v0.8 时代快照，本文件为其后继） |

---

## 🔗 外部资源

- **ACME 协议规范**: <https://tools.ietf.org/html/rfc8555>
- **RFC 9773 (ARI)**: <https://tools.ietf.org/html/rfc9773>
- **Let's Encrypt 文档**: <https://letsencrypt.org/docs/>
- **Rust 异步生态**: <https://tokio.rs/>

---

**索引版本**: v3（2026-09-05 重排：新增事实来源排序，历史文档统一归档标注）  
**维护约定**: 新增文档时请按「现行 / 历史存档」二分归类；完成报告类文档默认进入历史存档章节。
