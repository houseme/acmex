# AcmeX v0.9.0 实现状态核查

**核查日期**：2026-09-01（二次复核同日完成）
**核查基线**：`main@f38a460`
**结论**：T01-T12 代码与本地发布门槛已全部合并(常规测试证据齐全)；Pebble 与 L4/L5 外部环境证据按 KNOWN_LIMITATIONS 显式列为未执行,不作为已通过发布门槛。二次复核确认："已合并"不等于"验收标准全部达成"，详见下文"仍不能标记 v0.9.0 完成的原因"。

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
| T09 | 已合并 | PR #197、#198；`src/renewal/mod.rs`；`tests/renewal_controller_test.rs` | Deployment 子 Operation 的 executor/worker 接线待完成；ARI 生产接线缺失 |
| T10 | 已合并 | PR #201/#202/#204/#206;`src/key`、`src/delivery`、File/FakeAgent/HttpAgent Sink、部署编排门控、`tests/key_provider_test.rs`、`tests/certificate_sink_contract.rs`、`tests/http_agent_sink_test.rs` | Redis/K8s/Vault 实例与远端 Agent 实环境未执行 |
| T11 | 已合并 | PR #200/#205;哈希 API Key + 常量时间校验、SecretRef 全链路、Outbox Consumer(DLQ/重放)、`docs/SECURITY_OBSERVABILITY_HA.md`、`tests/outbox_consumer_test.rs` | mTLS/OIDC 留待后续;多实例 fencing 的真实多进程演练待 T12 环境 |
| T12 | 已合并(本地门槛) | PR #203;`scripts/`(pebble/feature/restart/docs/performance)、`tests/e2e_restart_matrix.rs`、`tests/fault_injection_matrix.rs`、`tests/release_gate_docs.rs`、CI workflow、RELEASE_CHECKLIST/KNOWN_LIMITATIONS/PERFORMANCE_BASELINE | Pebble/L4/L5 需外部环境显式执行后才算发布通过 |

## 今日合并记录

| PR | 任务 | Merge commit |
|---|---|---|
| #208 | HttpAgentSink 健康语义修复 | `f38a460` |
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

## 仍不能标记 v0.9.0 完成的原因（2026-09-01 二次复核 + 两轮优化批次后修订）

以下条目已按代码现状逐条核实，替代本文档此前基于合并前状态的陈旧描述（旧文所称"T10 未实现""仓库没有 scripts/ 目录"均已失效）。标注 ✅ 已修复 的是同日优化批次完成项：

1. ~~**生产运行时未组装新管线**~~ → ✅ 已修复（2026-09-01 第二轮批次）：新增 `src/workflow/issuance.rs` 为签发 spine 补齐全部真实 executor（Plan/CreateCsr/FinalizeOrder/WaitOrder/DownloadCertificate/VerifyCertificate/PersistVersion/ScheduleDeployments + Stage/Activate/VerifyDeployment + Complete 激活门控 + SubmitRevocation）；新增 `src/server/worker.rs` 生产 worker 装配（`register_executors` + `spawn_from_config`：账户密钥经 FileSecretStore 持久化、DNS-01/HTTP-01 presenter 按配置组装、File sink 默认注册、InstrumentedAcmeTransport 指标接入），`start_server` 现已内嵌 worker 循环。CreateOrderStep 支持从 subject 解析标识符并下发 ARI `replaces` 与 CA profile；CreateCsrStep 消费 KeyRotationPolicy（Reuse 复用旧 key）。端到端行为见 `tests/issuance_spine_test.rs`（fake CA 全 spine：签发即时激活 + 续签 replaces/key 复用/File 部署健康后激活并替代旧版本）。仍缺：真实网络环境 E2E（KNOWN_LIMITATIONS 既有边界）、revoke spine 的 Fake CA 行为测试、CLI 侧 worker。
2. ~~**ARI 生产接线缺失**~~ → ✅ 已修复（engine 侧）：`src/server/api.rs` 现通过无密钥的 `DirectoryAriProvider`（经 `InstrumentedAcmeTransport`，目录发现带缓存）调用 `with_ari_provider`；`RenewalController` 同时接入指标。仍缺：`CreateOrderStep` 给 `replaces` 赋值（依赖 workflow worker 装配）。
3. ~~**T11 指标只有注册没有打点**~~ → ✅ 已修复（数据面 + T18 收口）：`operations_total`/`operation_step_duration_seconds`（WorkflowEngine）、`renewal_due`/`renewal_failures_total`/`certificate_seconds_to_expiry`（RenewalController）、`outbox_pending`（OutboxConsumer）、`challenge_cleanup_pending`（ChallengeCleanupScanner）、`deployment_total`（DeploymentOrchestrator）、`acme_requests_total`/`acme_request_duration_seconds`/`bad_nonce_total`（InstrumentedAcmeTransport）均有打点并有行为测试；新增 `src/server/metrics_endpoint.rs` 在 `[metrics].listen_addr`（默认 127.0.0.1:9090）暴露 `/metrics`。`repository_errors_total` 已由统一 Repository decorator 按 `{backend,operation}` 打点；trace span 字段已覆盖 HTTP、workflow、CA/challenge、deployment 与 renewal lineage 边界；webhook 验签助手、配置窗口与消费者文档已落地。
4. ~~**T04 EAB 为 stub**~~ → ✅ 已修复（2026-09-02 第四轮）：真实 HMAC-SHA256 EAB JWS + SecretRef 凭据。Account Key Rollover 已实现（第五轮）。v0.10.0 T14 收口将 EAB 配置迁至稳定 `[ca.eab]`（保留旧 `[acme.external_account_binding]` 只读兼容别名并拒绝双写），生产 worker 的 `EnsureAccountStep` 已消费该配置；keyChange 内层 JWS 构造已由 legacy `KeyRollover` 与 `ca_backend` 共享。仍缺：旧 `AcmeClient`/Manager 的整段 HTTP/nonce/error facade 迁移尚未完成，不能宣称旧栈完全单源化。
5. ~~**T06 仅 cloudflare 经 legacy 适配器可创建**~~ → ✅ 已修复：`DefaultDnsProviderFactory` 为全部 11 个 provider 提供创建分支（route53/digitalocean/linode/azure/google/alibaba/godaddy/tencent/huawei/cloudns 均经 legacy 适配器，凭据走 SecretRef + `extra` 中的 secret 引用，拒绝明文 secret）；修复 `known_types` 特性判断反转（feature 已启用时不再误报"需要启用 feature"）；新增 `supported_types()`/`known_types()` 供测试与诊断。传播策略配置 schema 已接入（第四轮）。仍缺：真实云 `#[ignore]` 契约测试、`HickoryPropagationObserver` 对 `recursive_quorum` 的实际消费（现硬编码 AtLeast(1)）。
6. ~~**VerifyCertificate 步骤无 executor**~~ → ✅ 部分修复：新增 `VerifyCertificateStep`（SAN 精确匹配 + 有效期窗口校验，mismatch 即终态拒绝，见 `tests/issuance_spine_test.rs`）。第四轮已补齐：结构化 `CertificateVerificationReport`、`supports_identifier_type` 消费、`validate_identifier_scope` 私网拒绝。第五轮补齐：CSR 公钥一致性、链内签名一致性、profile 与 CA 能力交叉校验（检查项 6 项，负向测试各一）。仍缺：外部信任锚（CA 根证书）可配置校验。
7. ~~**legacy revoke 假 204**~~ → ✅ 已修复：`/api/certificates/{id}/revoke` 现经 Application Service 创建持久化 Revoke Operation（202 或明确错误）；429 响应现按契约输出 `Retry-After` HTTP header。intents 分页 + daemon 真实管线 + `PATCH` 真实现（第五轮：可变字段白名单/If-Match 乐观并发/审计事件）。T08 验收缺口清零。
8. **真实外部验证仍是边界条件**：真实 CA staging、真实 DNS Provider、Redis/Kubernetes/Vault 等环境验证不能由本地 fake/contract 测试推导为完成；Pebble E2E 目前没有任何实现代码（`scripts/run_pebble_e2e.sh` 在环境齐备时也只运行 fake-adapter 测试）。

## 2026-09-02 第五轮批次记录（并行：T04 rollover / T07 扩展 / T08 PATCH / T11 trace+webhook / T12 Pebble）

四路并行 + 主线，集成后全量门槛通过（388 tests / fmt / clippy 双模式 0 警告 / doctest 全绿）。

- **T04 Account Key Rollover**：`CaBackend::roll_account_key`（trait 的 T04 扩展，冻结策略内文档化）——RFC 8555 §7.3.5 双重 JWS（内层新钥签 `{account, oldKey}`、外层经 `execute_jws` 由旧钥签），成功后原子切换：先持久化新 KeyRef 再换内存 `key_pair` 并逐出该账户的会话缓存；失败路径全态保持（测试证明旧钥继续签名）。测试含 Ed25519 确定性重签逐字节验证（并发现 rcgen 默认 P-256 随机签名的坑）。
- **T07 验收扩展（三项全落地）**：`csr_public_key_matches`（CSR SPKI 与叶证书 SPKI 逐字节比对——fixture 改为真实 CA 行为：从托管库加载 CSR 私钥签发叶证书）；`chain_internally_consistent`（x509-parser verify-aws 特性验证叶被链内中间证书签名/自签，无新依赖）；`profile_offered`（CreateOrderStep 在下单前对 intent 钉住的 profile 做 `supports_profile` 交叉校验，零 new-order POST 证明）。Verification Report 检查项扩至 6 项。
- **T08 PATCH /certificate-intents/{id} 真实现**：仅 `renewal_policy`/`delivery_targets` 可变（其余字段点名 400）；`If-Match: <generation>` 乐观并发（裸/带引号 ETag），不匹配 409；值相同重放为 no-op 不 bump generation；CAS 循环 + `intent.updated` outbox 审计；权限 PATCH→IntentWrite；OpenAPI 同步；3 个新 API 测试。
- **T11 trace 注入 + webhook 验签**：引擎两级 DEBUG span（`workflow.operation`/`workflow.step`，字段 operation_id/kind/intent_id/lineage_id/version_id/workflow_step，`future.instrument` 正确跨 await）；行为测试用自定义 Layer 断言字段（set_global_default 规避并行 Interest 缓存问题）。`verify_webhook_signature` 消费端助手（三头校验→时间戳 ±max_skew 重放窗口→HMAC 常量时间比较），8 个单测 + 真实 axum 端到端往返；**顺带修复真实 bug**：签名时间戳原用本地时区格式化却标 Z，非 UTC 主机（UTC+8 复现）上任何重放窗口都会误杀。
- **T12 主线：真实 Pebble harness**：`tests/live_pebble_e2e.rs`（生产 `register_executors` 装配 + 不安全 TLS 传输（Pebble 设计如此）+ challtestsrv DNS-01 presenter（set-txt/clear-txt/dump-dns admin API）驱动完整签发到版本激活）；`scripts/docker-compose.pebble.yml`（pebble `dnsResolvers` 指向 challtestsrv）+ `scripts/pebble/pebble.json`；`scripts/run_pebble_e2e.sh` 重写为真实编排（compose up --wait → `--ignored` 运行 → teardown，保留 exit 77 语义）。**注意：本机未实际执行**（需 docker 环境），代码路径与断言已就绪，执行后才能计为 L4 通过。
- **T06 收尾**：`HickoryPropagationObserver` 消费 `policy.recursive_quorum`（原硬编码 AtLeast(1)）；新增 `tests/dns_provider_live.rs` 真实云 `#[ignore]` 契约脚手架（env 驱动 spec+SecretRef，双值共存/精确清理/幂等）。
- **lib 导出**：`UpdateCertificateIntent`、`ChallengeSessionView`/`ChallengeLeaseView`、`verify_webhook_signature`/`WebhookVerificationError` 进入顶层 API 面。

## 2026-09-02 第四轮批次记录（并行：T04/T05/T06/T11 收口 + T07 主线）

四个工作流按严格文件分区并行推进（互不冲突），集成后全量门槛通过（365 tests / fmt / clippy 双模式 0 警告 / doctest 全绿）。

- **T04 EAB 假实现 → 真实现**：删除恒返 `None` 的 `resolve_eab_hmac`/空 `eab_protected` stub；`ExternalAccountBindingRef` 携带 `hmac_key: SecretRef`（旧文本形式反序列化自动迁移）；`ensure_account` 按 RFC 8555 §7.3.4 生成 HMAC-SHA256 EAB JWS（protected `{HS256,kid,url}`、payload 为账户 JWK）写入 newAccount；密钥仅以 `SecretBytes` 短存、错误只提引用。4 个新行为测试（签名逐字节重算比对、无 EAB 注册不受影响、非法 base64url/不可解析 secret 均显式报错且零 POST）。
- **T05 challenge 运维 API**：新增 `GET /operations/{id}/challenges`（会话状态视图，无任何 token 字段——测试断言原始 body 不含 "token"）、`GET /challenge-cleanup?pending=true`（待清理租约，locator 脱敏摘要）、`POST /challenge-cleanup/{id}/retry`（CleanupFailed→CleanupPending 的 CAS 幂等迁移，保留 attempts 审计轨迹，后台扫描器接管；非 failed 409/不存在 404）。权限：GET→`IntentRead`、retry→`Admin`。OpenAPI 与路由门禁测试同步。`CertificateQuery` 扩展两个视图方法。
- **T06/T16 传播策略配置 schema**：第四轮批次的 `[challenge.dns01.propagation]` 为过渡兼容入口；v0.10.0 T16 已收敛到稳定 `[dns.propagation]` 主面（authoritative_quorum="all"|N、recursive_resolvers 空列表显式 opt-out、recursive_quorum、max_wait_secs、poll_interval_secs、query_timeout_secs），并支持 `[dns.providers.<id>.propagation]` 字段级覆盖。worker 通过 `Config::dns_propagation_policy_for()` 单入口消费策略；旧 `[challenge.dns01.propagation]` 仅在新主面缺失时 fallback。
- **T11/T18 `repository_errors_total` 打点**：`RepositorySet` 通过统一 decorator 记录仓储 trait-object 边界的失败；指标标签为 `{backend,operation}`，其中 `operation` 是闭集 `read/write/scan/cas/migrate`。Workflow/OutboxConsumer 不再散点手动递增仓储错误，破坏 file 后端目录的确定性行为测试覆盖 scan 失败，投递失败不计入仓储错误。
- **T07 主线**：`VerifyCertificate` 步骤产出结构化 `CertificateVerificationReport`（chain_parsed/san_exact/validity_window/serial_present 四项检查 + 有效期/序列号/CA/profile），持久化为步骤输出供审计，任一失败即终态拒绝并列出全部失败项；`CreateOrderStep` 在下单前消费 `CaCapabilities::supports_identifier_type`（IP 标识符遇不支持 IP 的 CA → PolicyViolation，零 new-order POST，测试证明）；`validate_identifier_scope` 在 Plan 步拒绝私网/保留/文档段 IP（RFC 1918/loopback/link-local/TEST-NET-1..3/fc00::/7/fe80::/2001:db8::），`CaPolicy.allow_private_identifiers` 显式放行私网 PKI；测试覆盖 11 种拒绝地址 + 公网/放行路径 + spine 集成。
- **修复（并发暴露）**：spine 测试 fixture 临时目录仅以进程 ID+冻结时钟命名，并行测试共享目录互相删除密钥 → 改为每 fixture 唯一序号。

## 2026-09-02 第三轮优化批次记录（CLI 接入 + lib crate 兼容 + 注释）

- **重大修复：二进制从未接入 CLI**——`src/main.rs` 一直是硬编码的 ACME 协议演示脚本，`cli` 模块的全部命令（含此前的 obtain/renew/serve）对二进制用户完全不可达。重写 main.rs：分发到 `cli::run()`、失败输出非零退出码、OpenTelemetry 改为可选（`OTEL_EXPORTER_OTLP_ENDPOINT` 存在才启用，导出器失败降级为警告而非 panic）。
- **CLI `acmex init`（新）**：项目脚手架——生成带注释的 `acmex.toml`（SecretRef 凭据约定、迁移开关、metrics 端点）、创建 `.acmex/{certs,repository,secrets}` 目录、写后回读校验配置、拒绝覆盖既有配置、打印后续步骤。2 个新单元测试（含"模板不含明文 secret"断言）。
- **CLI `obtain --wait`（新）**：经 `worker::build_engine_from_config` 在进程内组装生产引擎并 `run_until_terminal` 驱动到终态（默认模式仍为提交即走）。
- **CLI daemon 重写（去假成功）**：原实现"判定需续签后仅 `renewed_count += 1` 并打印 Renewing…"（注释自认 In production, would call...）+ 假邮件通知。现在运行与 server 相同的生产管线：workflow worker（真实 CA/ presenter/sink）+ ARI 优先的 RenewalController 扫描循环，SIGINT/SIGTERM 优雅停止；`--domains`/`--renew-before-days` 保留但明示被仓储扫描取代。
- **worker 重构**：抽出 `build_engine_from_config`（server/CLI/lib 三方共用装配）与 `build_ari_provider`（server 与 daemon 共用）；`spawn_from_config` 复用之。
- **lib crate 兼容**：crate 级文档重写（架构图、可运行 quick start doctest、模块地图、feature 说明）；re-export 补齐（`server::worker::*`、全部 issuance 步骤 executor、`DirectoryAriProvider`、`InstrumentedAcmeTransport`）；prelude 扩展（worker/engine 入口）。
- **注释增强**：`server/worker.rs`（完整模块文档 + doctest：装配内容/失败哲学/三种运行形态）、`workflow/issuance.rs`（步骤间数据流图、幂等/错误分类/职责归属规则）、`dns/factory.rs`（带 doctest 的使用示例与凭据约定）。

## 2026-09-01 第二轮优化批次记录（生产链路接线）

- **T03/T05/T07/T09/T10 生产闭环**：`src/workflow/issuance.rs`（9 个新 executor + spine 补齐）、`src/server/worker.rs`（装配 + spawn）、`start_server` 接线；`CreateOrderStep` 支持运行时标识符解析 + ARI `replaces` + profile；`CreateCsrStep` 消费 `KeyRotationPolicy`。
- **真实生产 bug 修复 1（T04，行为级）**：`classify_response` 曾对 2xx 强制 JSON 解析，导致 **证书下载（PEM 响应）在任何真实 CA 下都必然失败**。拆分出 `classify_status`（仅状态/问题分类），`execute_jws`/`post_as_get_bytes` 不再解析二进制体。
- **真实生产 bug 修复 2（T10，职责冲突）**：`run_deployment_once` 内嵌的 Deploy Operation 记账（`record_deploy_operation_step`/`finish_deploy_operation`）与 Workflow 引擎的 CAS 记账互相踩踏（步骤完成被 CAS 丢弃、操作被提前置终态）。已将 Operation 记账完全归引擎，编排器只维护 deployment 记录；`certificate_sink_contract` 相应断言更新。
- **Revoke spine 去假成功**：Revoke spine 原为 [Plan, EnsureAccount, Complete]——不执行任何吊销即成功。新增 `WorkflowStepKind::SubmitRevocation` + `SubmitRevocationStep`（经 `CaBackend::revoke`），spine 改为 [Plan, EnsureAccount, SubmitRevocation, Complete]。
- **端到端测试**：`tests/issuance_spine_test.rs`——真实 rcgen CA 签发链 + SoftwareKeyProvider（FileSecretStore）+ MemoryPresenter + File sink，驱动完整签发与续签 spine（含 key 复用、replaces、部署健康门控激活、旧版本 superseded）。
- **T08**：`GET /certificate-intents` 支持 `limit` 分页（1..=500，稳定排序）。

## 2026-09-01 第一轮优化批次记录

- **修复**：`ca_backend/backend.rs` profile `short_lived` 判断条件重复（漏检 `short-lived`/`short_lived` 命名）。
- **T06**：factory 全 provider 接入 + 特性判断修复 + `known/supported types` API + 明文 secret 拒绝（4 个新单元测试 + 契约测试重写）。
- **T09/T11**：ARI 生产接线（`DirectoryAriProvider`，3 个新单元测试覆盖窗口获取/未通告/404 语义与目录缓存）、server 侧 `with_ari_provider` + `with_metrics` 接线。
- **T11**：全组件指标打点 + `/metrics` 端点（`metrics_endpoint` 模块，含 HTTP 行为测试）；新增行为测试：`engine_records_operation_and_step_metrics`、`outbox_consumer_tracks_pending_backlog_per_event_type`、`renewal_scan_records_metrics`、`renewal_scan_records_failure_metric`、`cleanup_scanner_sets_pending_backlog_metric`。
- **T08**：legacy revoke 从假 204 改为经 Application Service 创建 Operation（202/明确错误）；429 输出 `Retry-After` header（新增 2 个 API 测试）。
- **文档**：本审计文档陈旧段落重写、`UNIMPLEMENTED_FEATURES.md` 加过时标注并修正 OCSP 模拟实现描述、`E2E_RELEASE_GATES.md` 明确 Pebble 脚本当前只跑 fake-adapter、基线更新至 `main@f38a460` 并补记 #208。
- **杂项**：`CertificateRenewer` 加 `#[deprecated]` 指向 RenewalController。

## 建议后续顺序

> 2026-09-02 更新：下列后续工作已整理为 [v0.10.0 验证与收口路线图](../v0.10.0/README.md) 的任务包（T13-T21），领取实施以该路线图为准。

1. **剩余验收缺口**：旧 `AcmeClient`/Manager facade 化（两套 JWS 并存）、T07 外部信任锚校验、T11 其余约定 span 字段注入、步骤执行器侧 `ca_id` 等 span 字段。
2. **执行已就绪的门槛**：`RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh`（需 docker）；`ACMEX_LIVE_DNS_* cargo test --test dns_provider_live -- --ignored`（需真实 DNS 凭据）。
3. **T12 收口**：CI 增加 pebble/secret-scan job；在真实环境执行上述门槛后更新 roadmap 状态为完成。

## 本次安全修复关联

本次分支同时修复 Dependabot #11、#12、#14：通过关闭 AWS SDK legacy `rustls` feature，移除 `rustls-webpki 0.101.7`、`rustls 0.21.12`、`hyper-rustls 0.24.2` 等旧 TLS 依赖链；全 feature 依赖图仅保留 `rustls-webpki 0.103.15`。
