# AcmeX 项目全景功能分析与后续规划方案

**分析基线**：`main@77adc51`（2026-09-05）
**包版本**：Cargo.toml `0.8.0`（工作树已按 v0.10.0 路线图推进，发布路径决策为"合并为单次 0.10.0 发布"）
**代码规模**：`src/` 139 个文件约 42,400 行；`tests/` 约 11,500 行（测试/源码比约 27%）
**事实来源**：本文档基于源码逐模块核查 + `docs/roadmap/v0.9.0/`、`docs/roadmap/v0.10.0/` 路线图交叉验证，取代散落在 `docs/` 下的 80+ 份历史完成度报告。

---

## 1. 执行摘要

AcmeX 是一个模块化的 ACME v2 (RFC 8555) 客户端 + 证书生命周期控制平面，Rust 编写，含 REST API 服务端与 CLI。

**当前真实状态一句话概括**：

> v0.9.0 的"持久化证书生命周期控制平面"架构闭环已代码级落地并通过本地测试门槛；项目正处于 v0.10.0 的"证据与收口"阶段——代码缺口基本清零，**阻塞发布的是外部环境证据**（Pebble E2E、Let's Encrypt staging、真实 DNS/Redis/K8s/Vault、双实例 fencing）尚未执行。

三个最重要的判断：

1. **主链路已完整**：`Intent → 签发 Operation（17 步持久化工作流）→ Challenge 租约 → 严格证书校验 → 不可变版本持久化 → 原子部署激活 → ARI 续签 → 吊销` 全链路无 `todo!`/`unimplemented!`，有签发主干测试与崩溃/故障注入矩阵佐证。
2. **发布被证据阻塞，而非被代码阻塞**：v0.10.0 的 T13-T18 代码级任务已落地，T19/T20（真实环境实测）只有 runbook 和门禁脚本，未执行。
3. **最大技术债是三代代码路径并存**：legacy 客户端栈（`client.rs`/`orchestrator`/`storage`/旧 `protocol` 直连 reqwest）与新控制面（`application`/`workflow`/`ca_backend`/`repository`）双轨运行，约占客户端层一半代码量；另有若干"孤岛组件"（`transport::HttpClient`、`NoncePool`）写好但未接入主路径。

---

## 2. 项目定位与演进脉络

### 2.1 版本演进主线

| 版本 | 主题 | 状态 |
|---|---|---|
| ≤0.6.0 | 协议原语、适配器骨架、功能数量扩张 | 已发布 |
| 0.7.0-0.8.0 | 调度、可观测性、CLI/API 完善 | 已发布 |
| **0.9.0** | **架构**：可恢复、可扩展的证书生命周期控制平面（T01-T12） | 代码全部合并，未发布 |
| **0.10.0** | **证据与收口**：清零 stub、建立 L4/L5 外部证据体系（T13-T21） | 实施中，"pending external evidence" |
| 0.11+ | 生产化扩展（见第 8 节建议） | 未规划 |

发布决策（`docs/roadmap/v0.10.0/RELEASE_DECISION.md`）：**优先合并为单次 0.10.0 发布**；仅当 Pebble L4 门槛明显早于 live CA/infra 门槛变绿时才先切 0.9.0。legacy `/api` Sunset 定为 2027-03-31。

### 2.2 目标架构形态

模块化单体控制平面 + 可插拔执行适配器（六边形架构）：

```text
上游入口（Rust SDK / REST /api/v1 / CLI / 未来 K8s、gRPC）
    │ CertificateIntent（期望状态）
应用服务层（幂等、鉴权、Policy Planning、CQRS 读写分离）
    │ 持久化 Command
工作流引擎（17 步 Saga：Step 状态持久化 / 租约围栏 / CAS / 逆序补偿 / 崩溃恢复）
    ├── CA Backend 端口（ACME 会话 / EAB / ARI / profiles）
    ├── Challenge 端口（Planner/Presenter/Observer/Cleaner + 可持久化 Lease）
    └── KeyProvider 端口（Managed Key / External CSR，SecretRef）
仓储层（memory/file 双后端 + 事务性 Outbox + 分布式 Lease）
    │ Deployment Event
Certificate Sink（File / HTTP Agent / 未来 K8s、Vault、LB）
```

领域层（`src/domain/`）零基础设施依赖；API、CLI、Scheduler 统一走同一个 Application Service。

---

## 3. 功能清单与成熟度矩阵

成熟度分级：**生产级**（主路径使用、有行为测试）｜**完整但旁路**（实现完整、未被生产运行时使用）｜**部分实现**（有真实逻辑但含 stub/限制）｜**stub/缺口**。

### 3.1 协议与 CA 层

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| Directory 解析+缓存（含 ARI/profiles 扩展字段） | `protocol/directory.rs` | 生产级 | serde flatten 前向兼容 |
| JWS 签名 / JWK thumbprint (RFC 7638) | `protocol/jws.rs`, `jwk.rs` | 生产级 | Ed25519/EdDSA；RSA/EC 构造器存在但账号密钥固定 Ed25519 |
| Nonce 管理 | `protocol/nonce.rs` | 生产级（legacy 路径） | |
| NoncePool 预取池 | `protocol/nonce_pool.rs` | **完整但旁路** | 仅 ca_backend 新路径接入；legacy account/order 各自新建 NonceManager |
| ACME 会话（badNonce 重试、Retry-After、POST-as-GET） | `ca_backend/session.rs` | 生产级 | 新路径统一 JWS 执行点 |
| EAB 外部账户绑定 (RFC 8555 §7.3.4) | `ca_backend/backend.rs` | 生产级 | HS256 detached JWS，凭据全链路 SecretRef（v0.10 T14 补齐） |
| 账户密钥轮换 (§7.3.5) | `ca_backend/backend.rs`, `account/key_rollover.rs` | 生产级 | 内外双 JWS，持久化→内存原子切换 |
| ARI 续签信息 (RFC 9773) | `ca_backend/ari.rs` | 生产级 | 免密钥 CertId DER 编码、目录发现缓存、404 降级 |
| 错误分类（429/5xx/401/403→稳定错误类） | `ca_backend/transport.rs` | 生产级 | `InstrumentedAcmeTransport` 打点 |
| 传输抽象 `transport::HttpClient`/`RetryPolicy`/`RateLimiter` | `transport/` | **完整但旁路（孤岛）** | 主流程（legacy `client.rs`）仍直连裸 `reqwest::Client`；仅 ca_backend 经 `AcmeTransport` 间接复用重试策略思想 |
| 多 CA 预设（LE/Google/ZeroSSL/Custom） | `ca.rs` | 部分实现 | google-ca/zerossl-ca 仅是常量级薄 feature，无专属逻辑 |

### 3.2 客户端核心流程（legacy 路径，仍可用）

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| 账户注册/查询/更新/停用 | `account/manager.rs` | 生产级 | 真实 HTTP+JWS；**EAB 注册发起仅在 ca_backend 新路径** |
| 订单创建/授权/挑战响应/finalize/证书下载 | `order/manager.rs` | 生产级 | 含 RFC 8738 IP identifier 解析 |
| CSR 生成与证书 SAN 精确校验 | `order/csr.rs` | 生产级 | DNS+IP SAN |
| 证书吊销 | `order/revocation.rs` | 生产级 | |
| `AcmeClient::issue_certificate(Vec<String>)` | `client.rs` | 生产级（兼容入口） | README 已声明为 DNS-only 兼容面；wildcard/IP 须走 `issue_identifiers` |

### 3.3 Challenge 与 DNS（项目最强部分之一）

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| ChallengePresenter 新端口（prepare/observe/cleanup + 可持久化 Lease） | `challenge/presenter.rs` | 生产级 | 替代 `&mut self` 旧 Solver |
| HTTP-01（本地 axum 临时服务） | `challenge/http01_presenter.rs` | 生产级 | TokenRegistry 精确匹配；多路由 Edge 端口已抽象 |
| DNS-01（zone 解析→路由→present→传播观察→精确清理闭环） | `dns/presenter.rs` | 生产级 | TXT 只传 hash 不传明文 |
| TLS-ALPN-01（acmeValidation 扩展证书生成） | `challenge/tls_alpn01.rs` | **部分实现** | Presenter 完整，但**生产 worker 未装配本地 TLS 服务**（`server/worker.rs:451`：pinned to tls-alpn-01 的 intent 在 prepare 时显式失败）；真实 TLS 监听器在 legacy Solver 中 |
| Zone 发现（SOA 上溯 + CNAME/NS 委派） | `dns/zone.rs` | 生产级 | hickory-resolver 真实现 |
| 传播观察（多递归解析器 + quorum 法定人数） | `dns/propagation.rs` | 生产级 | 策略可配置（v0.10 T16 `[dns.propagation]`） |
| Provider Factory + SecretRef 凭据 | `dns/factory.rs` | 生产级 | 拒绝明文凭据；feature 未编译时显式报错 |
| **11 个 DNS Provider**（Cloudflare/Route53/阿里/腾讯/华为/Azure/Google/DigitalOcean/Linode/GoDaddy/ClouDNS） | `dns/providers/` | **全部真实现，无一空壳** | 各自手写签名（阿里 POP HMAC-SHA1、华为 SDK-HMAC、腾讯 TC3-HMAC-SHA256、Azure OAuth 等）；唯一语义 stub：Route53 `verify_record` 恒 true（交给 CA 侧校验） |
| Challenge 租约清理扫描器 | `challenge/cleanup.rs` | 生产级 | 过期租约重试 + 手动 retry API |
| Legacy ChallengeSolver 三件套 | `challenge/{dns01,http01,tls_alpn01}.rs` | 完整但旁路 | 经 `LegacySolverPresenter` 适配器兼容 |

### 3.4 领域模型与持久化（v0.9 新架构地基）

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| 强类型领域模型（Identifier/Intent/Lineage/Version/Operation/Lease/Deployment） | `domain/`（9 文件） | 生产级 | 纯类型层零外依；挑战兼容矩阵（wildcard→DNS-01、IP→HTTP-01/TLS-ALPN-01） |
| Repository 抽象（9 聚合 + CAS + Lease fencing + Outbox + Clock） | `repository/mod.rs` | 生产级 | 接口面 v0.9 冻结 |
| Memory + File 双后端 | `repository/{memory,file}.rs` | 生产级 | 原子写（temp+fsync+rename）、防路径穿越、双后端跑同一契约测试套件 |
| **Redis 聚合仓储** | — | **缺口** | `repository/mod.rs:17` 明示 follow-up；旧 `storage::RedisStorage` 是另一套 KV 接口，不满足新 trait |
| Legacy Bundle 迁移器（旧 cert bundle → lineage+version） | `repository/migration.rs` | 生产级 | DryRun/Execute/VerifyOnly 三模式 |
| 旧版 `storage/`（File/Memory/Redis/Encrypted AES-256-GCM） | `storage/` | 完整但旁路 | 服务 legacy 栈；Redis `list` 用 KEYS（生产阻塞隐患）、每操作重建连接 |

### 3.5 工作流引擎与编排（项目核心）

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| 持久化步进引擎（StepResult 四态、租约围栏、CAS、确定性 jitter 退避、wake_at 等待） | `workflow/engine.rs` | 生产级 | 崩溃标记先于外部调用持久化；多 worker 安全 |
| 逆序补偿 + 取消（补偿耗尽→OperatorActionRequired） | `workflow/engine.rs` | 生产级 | |
| 签发 17 步 spine（Plan→CSR→Finalize→Download→**7 项严格验证**→Persist→Deploy→Activate） | `workflow/issuance.rs` + `challenge/steps.rs` | 生产级 | 验证含链信任（须显式 trust anchor）、SAN 精确匹配、CSR 公钥一致性 |
| 部署子 Operation（确定性 ID `op_deploy_<ver>_<target>`） | `delivery/mod.rs` | 生产级 | |
| ARI 优先续签控制器（窗口决策纯函数、稳定 SHA-256 抖动、5 级优先级、租约防重、shadow_mode） | `renewal/mod.rs` | 生产级 | 全项目完整度最高模块之一 |
| 版本健康门激活（Required/Quorum/BestEffort + supersede 旧版本） | `renewal/` + `delivery/` | 生产级 | |
| 旧 `CertificateProvisioner`/`DomainValidator` | `orchestrator/` | 完整但旁路 | 已 `#[deprecated]`；DNS-01 分支未注册 solver（注释明示） |
| 旧 `CertificateRenewer` / `AdvancedRenewalScheduler` | `orchestrator/renewer.rs`, `scheduler/` | **stub（已废弃）** | renewer 只打日志不续期；旧 scheduler 扫描不看有效期——均被 RenewalController 取代 |

### 3.6 交付（Delivery / Sink）

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| 持久化部署状态机（Pending→Staging→Staged→Activating→Active/Failed/RollingBack→RolledBack） | `delivery/mod.rs` | 生产级 | 每步 CAS + outbox 事件 |
| File Sink（版本目录 + `current` 符号链接原子切换 + health 比对 sha256 + rollback） | `delivery/mod.rs` | 生产级 | 私钥 0600 |
| HTTP Agent Sink（五阶段 REST + Idempotency-Key + Bearer） | `delivery/http_sink.rs` | 生产级 | 不可达归 Unknown 而非 Unhealthy，防误回滚 |
| **Kubernetes Secret / Vault KV Sink** | — | **缺口** | 枚举与配置位存在，无实现，运行时报 `no sink registered` |
| 回滚失败后的重试路径 | `delivery/mod.rs:523` | 部分实现 | RollbackFailed 等状态原样返回，未闭环 |

### 3.7 API / CLI / 安全 / 可观测

| 能力 | 模块 | 成熟度 | 说明 |
|---|---|---|---|
| `/api/v1` 生命周期 API（intents/lineages/versions/operations/challenge-cleanup，17 条路由） | `server/api_v1.rs` | 生产级 | 强制 `Idempotency-Key`、`If-Match` 乐观并发、202+Operation、RFC 7807 |
| API Key 认证 + 细粒度权限 | `server/auth.rs` | 生产级 | SHA-256 哈希存储、常量时间比较、过期/禁用；未配置时不挂管理路由 |
| mTLS/OIDC 认证 | — | **显式延后** | `Authenticator`/`Authorizer` trait 已预留 |
| legacy `/api`（含 Sunset 头 RFC 8594） | `server/api.rs` | 兼容面只减不增 | **`server/account.rs` 为假数据 stub**（get/update 返回硬编码 "valid"/admin@example.com）；legacy 证书列表部分字段固定值 |
| CLI（init/obtain/renew/daemon/serve/account/order/cert/status） | `cli/` | 生产级 | obtain 已迁移到 Application Service（`--wait` 进程内驱动）；order list/show 查询持久化 operations |
| 多租户隔离（越权 404 掩蔽）+ 审计事件 | `application/service.rs` | 生产级 | AuditEvent 经 outbox |
| Prometheus 指标（16 项 + 低基数标签白名单） | `metrics/` | 生产级 | 独立 `/metrics` 监听器 |
| OpenTelemetry tracing（workflow.operation/step span） | 全局 | 生产级 | OTLP 环境变量开启 |
| Webhook 出站（多端点、HMAC-SHA256 签名、重放窗口、Slack/Discord 格式） | `notifications/` | 生产级 | |
| **OutboxConsumer（持久化事件消费→webhook 投递）** | `notifications/mod.rs:434` | **完整但未接线（关键缺口）** | 实现+测试齐全（租约/退避/死信），但 `start_server`/`daemon`/`serve` 均未 spawn——**生产中 outbox 事件只写不消费** |

---

## 4. 质量保障体系

### 4.1 测试金字塔（诚实分层，skip ≠ pass）

| 层级 | 内容 | 证据 |
|---|---|---|
| L1 单元 | 各模块内联测试 | `cargo test` 常规通过 |
| L2 fake-CA 主干 | **issuance spine 12 测试**（生产 executor 全集 + 脚本化 CA + 真实签发证书链）；ca_backend 行为学 18 测试；workflow 引擎 21 测试（崩溃恢复/补偿/多 worker）；repository 契约 28+（memory+file 双后端） | `tests/{issuance_spine,ca_backend,workflow_engine,repository_contract}_test.rs` |
| L3 矩阵 | **重启矩阵**（每步骤"外部调用前/后/存储后"三窗口崩溃，真实 panic 注入）；**故障注入**（429+Retry-After、DNS 清理故障、invalid authz） | `tests/e2e_restart_matrix.rs`, `fault_injection_matrix.rs` |
| L4 真实 E2E | **Pebble docker compose**（challtestsrv，固定网段）：三类 Challenge 签发/续签/吊销/重启/回滚，6 个 `#[ignore]` 场景 | `tests/live_pebble_e2e.rs` + `scripts/run_pebble_e2e.sh`（未设 gate 时 exit 77） |
| L5 外部证据 | LE staging（7 场景，**当前仅 preflight**）、live DNS 契约、live infra、性能基线 | `tests/{le_staging,dns_provider_live,live_infra_evidence,performance_baseline}.rs` |
| 文档门禁 | OpenAPI 与 axum 路由面精确一致；FEATURE_MATRIX 必须记录每个 feature；迁移文档与 Sunset 契约一致 | `tests/release_gate_docs.rs` |

### 4.2 CI/CD（5 条流水线）

- `build.yml`：check/fmt/clippy/test（all-features）+ tag 时 publish。
- `v090-release-gates.yml`：**质量核心**——本地发布门槛 + secret-scan + semver-check（cargo-semver-checks）；pebble-e2e 仅手动/定时触发（PR 不跑）。
- `audit.yml`（每日 RUSTSEC）、`rust-clippy.yml`（SARIF）、`docs.yml`（仅构建，无 Pages 部署）。

---

## 5. 缺口与风险清单（按严重度）

### P0 —— 阻塞发布（v0.10.0 既定范围）

1. **外部证据未执行**：Pebble L4（三类 Challenge/续签/吊销/重启/回滚）、LE staging（T19）、live DNS/Redis/K8s/Vault/双实例 fencing（T20）、性能基线重跑。这是 CHANGELOG 明示的 "Not Yet Release-Validated" 全部内容。
2. **OutboxConsumer 未接入运行时**（`notifications/mod.rs:434`）：事件在 `start_server`/`daemon` 中只写不消费，`pending_outbox` 会无限积压。实现与测试已齐全，缺的只是几行 spawn 接线——**性价比最高的一个修复**。
3. **LE staging 测试仅 preflight**（`tests/le_staging.rs`）：目前只校验目录可达 + 环境资产齐全，未做真实签发，文档自认 "not a release pass"。

### P1 —— 已知功能缺口（部分属 v0.10，部分建议进 v0.11）

4. **TLS-ALPN-01 生产 presenter 未装配**（`server/worker.rs:451`）：pinned tls-alpn-01 的 intent 显式失败；缺本地多路由 TLS 监听器。
5. **Kubernetes Secret / Vault KV Sink 无实现**：`sink_key` 枚举占位，运行时报错（T20 需要）。
6. **Redis 聚合仓储未实现**（`repository/mod.rs:17`）：多实例 HA 故事缺一半——file 后端的 CAS 跨进程保护仅靠写时 revision 校验。
7. **legacy `server/account.rs` 假数据**（`account.rs:69-97` 硬编码返回）：建议随 legacy 面收缩直接删除或代理到 v1。
8. **回滚失败重试路径未闭环**（`delivery/mod.rs:523`）。

### P2 —— 协议与实现限制

9. 账户密钥仅 Ed25519/EdDSA（部分 CA 如 ZeroSSL 可能要求 EC/RSA）；`Jwk::new_rsa/new_ec` 无生产签名路径。
10. OCSP/CRL 真实吊销检查未实现（旧模拟实现已被**有意移除**，`certificate/chain.rs:112`；处置决策在 T15 记录）。
11. Route53 `verify_record` 恒 true；部分 legacy provider 的 zone 推导用"取最后两段"启发式（多级 TLD 会算错，新 `HickoryZoneResolver` 已是正确做法，legacy 面收敛时一并解决）。
12. `SoftwareKeyProvider::destroy` 永远返回 Refused（保守策略，密钥无法真正销毁）。
13. KMS/Vault/PKCS#11 KeyProvider、External CSR 模式有 trait 但无云 KMS 实现。

### P3 —— 技术债与工程卫生

14. **三代路径并存**：legacy 客户端栈约占客户端层一半代码量；`transport::HttpClient`、`NoncePool`（legacy 侧）、`crypto::Signer`（非 HMAC 部分）是孤岛组件。
15. **`docs/` 有 80+ 份历史完成度报告**，与真实现状混杂（UNIMPLEMENTED_FEATURES.md 已标注过时但仍在）；`verify_build.sh` 是硬编码他人路径的 v0.4 遗留物。
16. **examples 全部停留在 v0.8 旧 API**：无 durable workflow / `/api/v1` / CLI 新命令示例；`dns_01_challenge.rs` 缺 `required-features` 声明。
17. **空壳 feature**：`metrics`、`cli` feature 在源码中 0 处 cfg gating（纯安慰剂）；`google-ca`/`zerossl-ca` 仅常量级。文档门禁强制"每个 feature 被记录"，但"被记录"≠"有实现差异"。
18. 小项：README badge "rust 1.92+" 与 `rust-version = "1.97.1"` 不一致；legacy order 响应 `domains` 恒空；`renewals_total`/`certs_managed` 指标新链路无写入点；`EventType`（13 种）与 outbox 事件字符串是两套并行体系。

---

## 6. 已有后续规划（v0.10.0 路线图现状）

`docs/roadmap/v0.10.0/` 采用可独立领取的工程任务包模式，T13-T21 状态：

| 里程碑 | 任务 | 状态 |
|---|---|---|
| M1 真实 E2E 底座 | T13 Pebble Harness | Harness 代码就绪（三类 Challenge/续签/吊销/重启/回滚），**Docker L4 未执行** |
| M2 代码级收口 | T14 EAB/账户生命周期、T15 验收报告、T16 DNS 传播配置、T17 API 收口、T18 可观测收尾 | **代码全部落地**，待复跑 gate 与 Pebble 覆盖 |
| M3 真实环境证据 | T19 LE staging、T20 生产基础设施 | runbook/门禁就绪，**未执行** |
| M4 发布 | T21 发布工程 | CHANGELOG/迁移文档/semver gate 已落地；版本 bump/tag/publish 被外部证据阻塞 |

路线图明确的非目标：Web UI、自建 CA、扩充 DNS provider、mTLS/OIDC、任意脚本 Hook、微服务拆分、把 OCSP 包装成生产能力。

---

## 7. 面向 v0.10.0 之后的规划建议（v0.11+ 草案）

以下按主题分组，供下一轮路线图（v0.11.0 "生产化扩展"）参考，均从第 5 节缺口自然延伸：

### 7.1 HA 与多实例（主题：从"单实例正确"到"多实例生产"）

- **Redis 聚合仓储**（实现 `RepositorySet` 的 Redis 后端 + 契约测试 + live 验证）——解锁真正的多实例部署与跨进程 CAS。
- **分布式 Lease 实战强化**：双进程 fencing 演练从"证据动作"升级为 CI 可重复演练。
- 回滚失败重试闭环、CleanupFailed 的自动重试策略。

### 7.2 交付面扩展（主题：证书"最后一公里"）

- **Kubernetes Secret Sink**（in-cluster RBAC，自然衔接未来 K8s Issuer/Controller 上游入口）。
- **Vault KV/PKI Sink** + 云 LB/CDN Sink（按用户需求优先级排序）。
- HTTP/TLS Edge Agent 的独立进程形态（Challenge Agent），支撑多节点/Anycast 拓扑。

### 7.3 协议与密码学补强

- 账户密钥 ECDSA P-256/RS256 签名路径（兼容更多 CA 的 EAB/注册要求）。
- TLS-ALPN-01 本地多路由监听器（补齐生产 presenter）。
- 按需评估真实 OCSP/CRL 检查（坚持"不宣称未验证能力"原则）。
- ACME Profiles 深化（短周期 6-day 证书、IP 证书的组合策略）。

### 7.4 密钥管理深化

- 云 KMS KeyProvider（AWS KMS / GCP KMS / Azure KeyVault，按用户群优先级）。
- External CSR 模式的 API/CLI 完整暴露（`KeyManagementMode::ExternalCsr` 已在领域模型中）。
- `destroy` 语义落地（操作员显式确认的密钥销毁流程）。

### 7.5 接入面扩展

- gRPC / Kubernetes Controller 上游适配器（目标架构 6.1 节已预留）。
- mTLS/OIDC 管理面认证（`Authenticator` trait 已预留；若 T20 多实例演练暴露硬需求可提前）。
- Web 管理界面（当前明确非目标，维持）。

### 7.6 工程卫生专项（可与任意版本并行）

- **docs/ 大扫除**：80+ 历史报告移入 `docs/history/` 归档，`docs/README.md` 只保留现行事实来源索引（DOCUMENTATION_INDEX.md 已有雏形）。
- **examples 现代化**：新增 durable workflow / `/api/v1` / `acmex daemon` 三个新路径示例；补 `required-features`。
- **feature 清理**：删除或实装 `metrics`/`cli` 空壳 feature；评估 `google-ca`/`zerossl-ca` 是否值得保留。
- **legacy 面收敛时间表**：随 2027-03-31 Sunset 临近，分阶段删除 `server/account.rs` 假数据、旧 orchestrator/scheduler、`transport`/`NoncePool` 孤岛组件。
- docs.yml 补 GitHub Pages 部署（homepage 已指向 Pages）。

---

## 8. 推荐行动方案（优先级排序）

### 立即执行（解锁发布，1-2 周量级）

1. **接线 OutboxConsumer**：在 `server/api.rs::start_server` 与 `daemon`/`serve` 中按配置 spawn 消费循环（含开关配置与 diagnostics 暴露）。这是唯一"实现已齐全、只差接线"的 P0 项。
2. **执行 Pebble L4**（T13）：`RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh`，归档 6 个场景证据，勾选 v0.9 RELEASE_CHECKLIST Required E2E 区。
3. **补 TLS-ALPN-01 决策**：要么在 M1 前给 worker 装配本地 TLS presenter（可先单路由），要么在 FEATURE_MATRIX/KNOWN_LIMITATIONS 中把 tls-alpn-01 显式降级为"Pebble 验证通过但生产 worker 暂不支持"——不能留模糊地带。

### 短期（发布 0.10.0 的硬路径）

4. T19：将 `tests/le_staging.rs` 从 preflight 升级为真实签发冒烟（硬依赖 T13+T14 证据先行）。
5. T20：至少 Cloudflare + Route53 两个 live DNS 契约、一项远端 sink（建议先做 K8s Secret Sink 的最小实现以满足"至少一个远端 sink"门槛）、双进程 fencing 演练。
6. 性能基线重跑 → T21 执行发布决策 → bump 0.10.0 → tag/publish。

### 中期（0.10.0 发布后启动 v0.11）

7. Redis 聚合仓储（P1 中对架构影响最大的一项）。
8. K8s Secret / Vault Sink 完整实现 + 契约测试。
9. docs/ 归档大扫除 + examples 现代化 + 空壳 feature 清理（工程卫生专项，可交给并行任务）。
10. 账户密钥 ECDSA/RSA 支持（按真实用户/CA 反馈排期）。

---

## 9. 与既有文档的关系

- 本文是**单一当前视图**，周期性更新；与 `docs/roadmap/v0.10.0/README.md`（任务级验收标准）、`docs/roadmap/v0.9.0/{IMPLEMENTATION_STATUS_AUDIT,KNOWN_LIMITATIONS,FEATURE_MATRIX}.md`（证据矩阵）互补，冲突时以 roadmap 任务文档的验收标准为准。
- `docs/` 下其余历史报告（V0.x_COMPLETION_REPORT 等）仅作历史参考，不代表现状。
- 建议在每次发布 cut 时刷新本文第 3/5 节的成熟度与缺口矩阵。
