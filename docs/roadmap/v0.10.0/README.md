# AcmeX v0.10.0 验证与收口实施路线图

**状态**：实施中；代码级收口已部分落地，发布工程 baseline 已建立，L4/L5 外部证据仍待执行
**基线**：`main@f38a460` + 2026-09-02 多轮优化批次；当前 main 后续已追加 T13-T18 与 T21 本地发布工程实现
**目标**：把 v0.9.0 已合并的控制平面闭环，变成被可复现证据验证过的可发布产品
**最后更新**：2026-09-02

---

## 1. 使用方式

本目录延续 v0.9.0 的工程任务包模式：每个任务文件包含项目背景、边界、目标接口、实施步骤、验证方法和验收标准。

执行者开始任何任务前必须：

1. 阅读仓库根目录 `AGENTS.md`。
2. 阅读本文件。
3. 阅读所领取任务文档的全部内容。
4. 检查当前分支、工作树、Cargo feature 和相关代码是否已经变化。
5. 只实现该任务的范围；依赖任务未完成时使用文档指定的临时兼容策略，不私自扩展范围。
6. 保持旧 API 的兼容边界，除非任务明确要求迁移或弃用。

事实来源（按优先级）：

- 遗留缺口清单：[v0.9.0 实现状态核查](../v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md)（"仍不能标记 v0.9.0 完成的原因"与"建议后续顺序"两节）
- 显式未验证项：[v0.9.0 Known Limitations](../v0.9.0/KNOWN_LIMITATIONS.md)、[v0.9.0 Release Checklist](../v0.9.0/RELEASE_CHECKLIST.md)
- 架构总纲：[AcmeX 当前功能、架构评估与目标架构设计](../../ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md)
- 安全与可观测基线：[Security, Observability and HA Baseline](../../SECURITY_OBSERVABILITY_HA.md)

---

## 2. 与 v0.9.0 的关系

v0.9.0 的 T01-T12 已全部合并，本地门槛（fmt/test/check/feature matrix/restart matrix/docs gate）通过，三轮优化批次补齐了生产运行时装配、CLI 接入和指标打点。本路线图初稿撰写时：

- `docs/roadmap/v0.9.0/RELEASE_CHECKLIST.md` 的 **Required E2E Evidence** 与 **Explicit External Evidence** 区全部未勾选。
- `scripts/run_pebble_e2e.sh` 即使设置 `RUN_PEBBLE_E2E=1` 也只运行 fake-adapter 套件，不存在任何启动 Pebble 的实现。
- `Cargo.toml` 版本仍为 `0.8.0`，v0.9.0 尚未发布。
- v0.9.0 审计确认了若干代码级验收缺口：EAB 为 stub、Account Key Rollover 缺失、双 JWS 栈并存、证书验收报告不完整、DNS 传播策略无配置入口、`PATCH /certificate-intents` 为 stub、可观测性三项收尾未完成。

**当前实现复核（2026-09-02）**：main 已补入真实 Pebble DNS-01 harness 骨架、EAB/keyChange、VerificationReport、DNS propagation schema、PATCH/challenge status API、repository error metrics 与 webhook replay-window。上述代码仍需按各任务验收标准复跑 focused/full gates；Pebble/LE/live DNS/Redis/K8s/Vault/双实例等 L4/L5 证据未执行前不得标记为发布通过。

v0.10.0 承接两类工作：

1. **补齐 v0.9.0 发布门槛所需的外部证据**（T13、T19、T20）。
2. **收口审计确认的代码级缺口**（T14-T18）。

发布路径决策——外部门槛完成后先发布 0.9.0 再发布 0.10.0，还是合并为一次 0.10.0 发布——由 T21 记录并执行。在 T13/T19/T20 完成前，任何文档不得把 Pebble、真实 CA、远端 sink 能力描述为已验证。

---

## 3. 版本目标

v0.9.0 的主题是架构：可恢复、可扩展、可安全接入上下游的证书生命周期控制平面。v0.10.0 的主题是**证据与收口**：

- 每个文档声称的能力都有对应层级（L4/L5）的可复现验证证据。
- v0.9.0 审计列出的 stub 与验收缺口清零。
- 至少一个真实 CA staging、至少两个真实 DNS provider 隔离 zone、至少一个远端 sink 通过全流程验证。
- 双实例并发演练证明续签与部署无重复副作用。
- 发布流程可重复，文档、OpenAPI、配置示例与运行行为一致。

```text
已合并的架构闭环（v0.9.0）
→ 真实 E2E 底座（Pebble）
→ 代码级收口（EAB/验收报告/传播策略/API/可观测）
→ 真实环境证据（LE staging / DNS zone / Redis / K8s·Vault / 双实例）
→ 发布
```

---

## 4. 全局架构约束

继承 v0.9.0 README 第 3 节全部约束（领域层无基础设施依赖、API/CLI/Scheduler 只调用 Application Service、外部副作用返回可持久化 locator/lease、Step 幂等或显式不可重试、私钥与凭据不入日志/错误/指标、证书版本不可变、错误区分 retryable 与 terminal、不允许 sleep 模拟成功、不允许编译通过代替行为验证），另加：

- v0.9.0 冻结接口（`Identifier`、`CertificateIntent`、`CertificateLineage`、`CertificateVersion`、`Operation`、`WorkflowStep`、`ChallengeLease`、Repository trait、Error Class）在 v0.10.0 内继续稳定；如需修改仍走 v0.9.0 README 第 7 节的变更流程。
- 新增公共面（`CertificateVerificationReport`、DNS 传播策略配置、EAB 配置）必须有版本化序列化兼容测试、文档和配置示例。
- 外部证据必须可复现：环境准备脚本 + 运行说明 + 输出存档（日志/测试输出），不接受口头描述或不可重放的截图。
- L4/L5 未执行时不得由 L1-L3 测试推断为通过；跳过必须显式输出原因（exit 77 约定保留）。
- 不得重新引入任何已被移除的假成功路径；不得回退 v0.9.0 各优化批次的行为修复。
- legacy `/api` 兼容面只减不增；新能力只进 `/api/v1`。
- 外部验证使用的真实凭据经 SecretRef 或环境注入，不得进入仓库、日志、测试输出与证据存档。

---

## 5. 子任务清单

| ID | 任务 | 主要产出 | 前置依赖 | 建议里程碑 | 当前状态 |
|---|---|---|---|---|---|
| T13 | [Pebble E2E Harness 与真实进程验证](./T13_PEBBLE_E2E_HARNESS.md) | compose 环境、三类 Challenge 真实签发/续签/吊销、真实 executor 重启演练、CI pebble/secret-scan job | 无（复用 `server::worker` 装配） | M1 | Harness 已覆盖三类 Challenge、File sink deploy、续签、吊销、三窗口重启与失败回滚；未执行 Docker L4，release checklist 仍需真实证据 |
| T14 | [EAB 与账户生命周期收口](./T14_EAB_AND_ACCOUNT_LIFECYCLE.md) | EAB SecretResolver 接线、Account Key Rollover、JWS 栈收敛 | 无 | M2 | 代码已落地，待 focused/full gate 与 Pebble 覆盖 |
| T15 | [证书验收报告与 CA 能力消费](./T15_CERTIFICATE_VERIFICATION_REPORT.md) | 完整 VerificationReport、`supports_identifier_type` 预检、OCSP 处置 | 无 | M2 | 代码已落地，待验收复核 |
| T16 | [DNS 传播策略配置化](./T16_DNS_PROPAGATION_POLICY_CONFIG.md) | quorum/递归 resolver 配置 schema 与运行时接线 | 无 | M2 | 代码已落地，待验收复核 |
| T17 | [API 契约与遗留面收口](./T17_API_CONTRACT_CLOSURE.md) | PATCH intents、授权/挑战状态 API、legacy `/api` 弃用计划、OpenAPI 校验门槛 | 无 | M2 | 代码已落地，待验收复核 |
| T18 | [可观测性收尾](./T18_OBSERVABILITY_CLOSEOUT.md) | `repository_errors_total`、trace span 注入、webhook 重放窗口、告警资产 | 无 | M2 | 代码已落地，待验收复核 |
| T19 | [Let's Encrypt Staging 与真实 CA 特性实测](./T19_LETSENCRYPT_STAGING_VALIDATION.md) | staging 冒烟、ARI replaces、profiles、IPv4/IPv6 证据 | T13、T14（硬）；T15、T16、T20（软） | M3 | 本地 gate/runbook 已就绪；未执行 live CA |
| T20 | [生产基础设施实测与多实例证据](./T20_LIVE_INFRASTRUCTURE_AND_HA_EVIDENCE.md) | live DNS zone 契约、K8s/Vault/远端 agent、Redis live、双进程 fencing | 无硬依赖（建议在 T18 后） | M3 | 本地 gate/runbook 已就绪；未执行 live infra |
| T21 | [发布工程与版本策略](./T21_RELEASE_ENGINEERING.md) | 发布路径决策、CHANGELOG、迁移文档、性能基线、版本 cut | T13-T20 | M4 | 部分实现；CHANGELOG/RELEASE_NOTES/MIGRATION/semver gate 已落地，性能基线重跑、版本 bump/tag/publish 被外部证据阻塞 |

---

## 6. 依赖关系

```text
M1  T13 Pebble E2E Harness
      │
M2  T14 EAB/账户生命周期 ──┐
    T15 证书验收报告 ──────┤  五个任务相互独立，可并行领取
    T16 DNS 传播配置 ──────┤
    T17 API 收口 ──────────┤
    T18 可观测收尾 ────────┘
      │
M3  T19 LE Staging 实测（硬依赖 T13+T14；复用 T15 报告、T16 策略、T20 live zone）
    T20 生产基础设施实测（建议在 T18 后，演练带完整观测）
      │
M4  T21 发布工程（依赖 T13-T20 全部完成）
```

T19 的 DNS-01 冒烟需要 T20 的 live zone harness；若 T20 未就绪，T19 允许先以 HTTP-01 完成主体冒烟并显式记录降级。T20 的双进程 fencing 演练建议在 T18 之后执行，以便观测信号完整，但不构成硬依赖。

---

## 7. 里程碑

### M1：真实 E2E 底座

完成 T13。

退出条件：

- `RUN_PEBBLE_E2E=1` 的脚本真实启动 Pebble 并驱动 HTTP-01、DNS-01、TLS-ALPN-01 完整签发。
- 重启矩阵在真实 T04/T05/T10 executor 上演练（对应 v0.9.0 checklist 行）。
- 吊销与续签流程在 Pebble 上验证。
- CI 具备环境门控的 pebble job 与 secret-scan job。
- v0.9.0 RELEASE_CHECKLIST 的 Required E2E Evidence 区可全部勾选并附证据链接。

### M2：代码级收口

完成 T14-T18。

退出条件：

- EAB 账户注册可用且凭据全链路 SecretRef；Account Key Rollover 在 fake CA 与 Pebble 上可用。
- VerificationReport 完整（链信任/profile/密钥一致性/能力预检）、持久化并经 API 可查。
- DNS 传播策略可经配置文件控制并有行为测试。
- `/api/v1` 无 "not implemented" 路由；legacy `/api` 有成文弃用计划与迁移表。
- `SECURITY_OBSERVABILITY_HA.md` 不再有 "not yet instrumented / not yet wired" 段落。

### M3：真实环境证据

完成 T19、T20。

退出条件：

- Let's Encrypt staging 冒烟、ARI `replaces`、profile 行为、IPv4/IPv6 标识符证据完成。
- 至少两个真实 DNS provider 在隔离 zone 通过 create/find/delete/idempotency 契约。
- Kubernetes/Vault/远端 agent 至少各一项实环境验证；Redis repository live 契约与 failover 范围文档完成。
- 双进程 fencing 演练通过：同 lineage 并发续签/部署仅产生一次副作用。
- v0.9.0 RELEASE_CHECKLIST 的 Explicit External Evidence 区可全部勾选；FEATURE_MATRIX 的 external evidence 列与事实一致。

### M4：发布

完成 T21。

退出条件：

- 发布路径决策（0.9.0/0.10.0 顺序或合并）已记录并执行。
- CHANGELOG、RELEASE_NOTES、MIGRATION 文档（覆盖 0.8→0.10）齐备。
- 性能基线在参考平台重跑并记录。
- 版本发布 cut 完成，README、docs、FEATURE_MATRIX、KNOWN_LIMITATIONS 与实际行为一致。

---

## 8. 接口冻结策略

v0.9.0 冻结的接口在 v0.10.0 内继续冻结（清单见 v0.9.0 README 第 7 节）。新增以下公共面时，必须从合入第一天起满足：

- `CertificateVerificationReport`：版本化序列化 + 兼容测试 + 字段演进策略（新增字段必须可被旧读者忽略）。
- DNS 传播策略配置（`[dns.propagation]`）：toml schema、默认值、per-provider 覆盖语义，一经发布视为稳定配置面。
- EAB 配置（`[ca.eab]` SecretRef 约定）：同上；不得引入明文 secret 字段。
- 授权/挑战状态 API 资源：稳定枚举、RFC 7807 错误、与 OpenAPI 同步。

修改任何冻结接口或已发布配置面，必须：

1. 给出无法通过扩展字段解决的证据。
2. 更新所有 Repository、序列化兼容测试与 OpenAPI。
3. 更新本路线图及受影响任务文档。
4. 提供迁移或兼容层，并更新 MIGRATION 文档。

---

## 9. 通用验收门槛

每个任务至少执行：

```bash
cargo fmt --all --check
cargo test <与任务相关的精确测试目标>
cargo check --all-features
cargo check --no-default-features
git diff --check
```

若任务修改公共 API、feature 或配置，还必须：

- 更新或新增 doctest/example。
- 更新 OpenAPI 或配置示例。
- 运行对应 Repository/Provider/Sink 契约测试。

外部证据类任务（T13、T19、T20）额外要求：

- 提供环境准备脚本与运行手册（所需的二进制、镜像、环境变量、网络条件）。
- 证据存档（测试输出/日志）进入仓库或发布工件，并从任务文档可链接。
- 环境缺失时的跳过路径必须显式（exit 77 + 原因），不得静默通过。
- 完成后更新 v0.9.0 RELEASE_CHECKLIST、FEATURE_MATRIX、KNOWN_LIMITATIONS 的对应行。

最终报告必须分别说明：

- 已完成的代码范围。
- 已执行并通过的本地验证。
- 已执行的外部环境验证及其存档位置。
- 未执行的外部环境验证及原因。
- 是否存在迁移、兼容或回滚要求。
- 是否引入后续任务依赖。

---

## 10. 非目标

v0.10.0 默认不包含：

- Web 管理界面。
- 自建完整 CA 服务端。
- 扩充 DNS provider 数量——广度让位于对现有 provider 的真实验证。
- mTLS/OIDC 管理面认证——继续显式延后；若 T20 多实例演练暴露硬需求，另立任务处理。
- 无约束的任意脚本 Hook 执行平台。
- 微服务拆分。
- 将 OCSP/CRL 吊销状态检查包装为生产能力——处置决策在 T15 记录，真实检查实现前不得宣称。
- 在公共 PR CI 上强制执行 Pebble/真实外部环境门槛（保持环境门控，避免不可复用的抖动）。

---

## 11. 项目级完成定义

所有子任务完成后，还必须满足：

- v0.9.0 RELEASE_CHECKLIST 全区勾选；未勾选行必须有显式降级决策与说明。
- KNOWN_LIMITATIONS 仅保留"明确决定不验证"的条目，不再包含"尚未执行"类欠账。
- 从上游 Intent 到下游 Active Deployment 的完整 E2E 在 Pebble 与至少一个真实 CA staging 各跑通一次并留档。
- IPv4/IPv6 标识符、Wildcard、三类 Challenge 均有真实环境证据。
- 双实例并发续签/部署演练无重复副作用、无版本覆盖。
- `scripts/verify_docs_and_openapi.sh`、feature matrix、restart matrix、性能基线全部通过。
- 0.9.0/0.10.0 发布完成，迁移文档覆盖 0.8→0.10 全路径。
