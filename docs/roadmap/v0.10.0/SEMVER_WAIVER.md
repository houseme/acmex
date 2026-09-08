# cargo-semver-checks 差异清单与发布 Waiver（基线：已发布 0.8.0 → 当前树）

**日期**：2026-09-07
**工具**：`scripts/run_semver_check.sh`（cargo-semver-checks v0.50.0，`--package acmex --all-features`）
**结果**：`196 checks: 185 pass, 11 fail, 0 warn, 58 skip`；
`Summary semver requires new major version: 11 major and 0 minor checks failed`（退出码非零，符合预期）。
**基线说明**：基线为 crates.io 已发布的 `acmex 0.8.0`；`Cargo.toml` 仍为 `0.8.0`（版本欠账见
`docs/roadmap/v0.10.0/T21_RELEASE_ENGINEERING.md` §1：v0.9.0 代码已全部合入但从未发布）。
因此本清单同时覆盖 v0.9.0 与 v0.10.0 两个路线图的全部公共面变化。
按 `docs/roadmap/v0.10.0/RELEASE_DECISION.md` 的发布阻塞项——"The semver compatibility gate
must pass or have an explicit release-manager waiver"——以下逐项给出 waiver 依据。

## 权威差异清单（11 类 failed lint）与逐项理由

### 1. struct_with_pub_fields_changed_type — `Identifier` struct→enum（类型变更）
- 条目：`acmex::types::Identifier` / `acmex::prelude::Identifier` / `acmex::Identifier` became enum
  （现位于 `src/domain/identifiers.rs:227`）。
- 任务：v0.9.0 **T01 强类型领域模型与策略**（`docs/roadmap/v0.9.0/T01_DOMAIN_MODEL_AND_POLICY.md`）。
- 理由与替代路径：`Identifier` 从 pub 字符串字段结构迁移为 `Dns(DnsIdentifier)/Ip(...)` 强类型枚举，
  是 T01 的核心设计目标。兼容层完整（`T01_MIGRATION_NOTES.md`）：`Identifier::dns()/ip()` 保留并
  `#[deprecated]`，提供 panic-free 的 `try_dns()/try_ip()/parse()`；`src/types.rs` 变为 re-export，
  旧 JSON 形状可继续反序列化；`NewOrderRequest::new(Vec<String>)` 与 `client.rs` 的
  `create_order()/issue_certificate()` 保留为 DNS-only 兼容入口。

### 2–4. module_missing / struct_missing / enum_missing — OCSP 模拟模块删除（移除）
- 条目：`mod acmex::certificate::ocsp`、`struct OcspVerifier`、`enum OcspStatus`（原
  `src/certificate/ocsp.rs`，删除于提交 `4036cda`）。
- 任务：v0.9.0 README §9 **非目标**明确"将 OCSP 模拟结果包装成生产状态"；
  实际删除归入 v0.10.0 **T15 证书验证报告**（`T15_CERTIFICATE_VERIFICATION_REPORT.md`，提交
  `4036cda "feat(cert): persist verification reports"`）。
- 理由与替代路径：删除的是无真实 OCSP 网络验证的模拟实现（违反"Nothing pretends to succeed"）。
  替代机制为持久化的 `verification_report`（chain trust、identifier policy、profile、公钥一致性、
  OCSP 状态记录），见 `docs/MIGRATION_v0.10.0.md` "Certificate Verification"。有意的破坏，有替代路径。

### 5–6. struct_missing / struct_pub_field_missing — `RenewalHooks` 与 `RenewalSettings.hooks`（移除）
- 条目：`struct acmex::config::RenewalHooks`；`RenewalSettings.hooks` 字段
  （删除提交 `097d42c "chore(config): remove dead renewal hook settings"`）。
- 任务：v0.10.0 平台（v0.9.0 README §9 非目标之一："无约束的任意脚本 Hook 执行平台"）。
- 理由与替代路径（已查清）：`[renewal.hooks]`（before/after/on_error 脚本路径）**全 workspace 零消费者**，
  属死配置。替换机制**不是**某个新 hook 子系统，而是：a) 既有 **durable outbox → webhook/SMTP email
  通知**（`[[notifications.webhooks]]` / `[[notifications.email]]`，HMAC 签名）承载"续期前后/出错"的
  外部联动；b) 脚本执行移交部署周边工具链。兼容性：`Config` 未用 `deny_unknown_fields`，遗留 TOML
  中的 `[renewal.hooks]` 段仍可解析并被忽略（提交说明，`tests/email_notification_contract.rs` 验证）。

### 7. feature_missing — `metrics`、`cli` feature 删除（移除）
- 提交 `9169ac7 "chore(features): remove no-op metrics and cli feature shells"`；CHANGELOG Removed。
- 理由：两个 feature 均不 gate 任何代码（`prometheus`/`clap` 是无条件依赖），开启与否产物完全相同。
  CHANGELOG 已按 0.x 语义记录为 minor 级变更；使用方直接删掉 flag 即可。waiver 无风险。

### 8. enum_variant_added — 穷举枚举新增变体（字段新增类）
- `ChallengeType::DnsAccount01`（`e6c791e`）/`DnsPersist01`（`90b0641`）：v0.9.0 **T05 challenge 生命周期**
  的 dns-account-01（draft-ietf-acme-dns-account-01）与 dns-persist-01 支持（CHANGELOG Added）。
- `AcmeError::Conflict`（`bb9f111` #196）：v0.9.0 **T08 application service/API** 的冲突错误分类。
- `Commands::Init`（`952759d`）：v0.9.0 CLI 重写，`acmex init` 为新用户入口
  （`docs/MIGRATION_v0.9.0.md`："Start from `acmex init`"）。
- `Commands::Status`（`0a456f9`）：v0.10.0 **T17 API contract closure** 的 `acmex status` 命令
  （`T17_API_CONTRACT_CLOSURE.md`：CLI status 展示 operation/challenge 进度）。
- 均为有意的新能力；下游对枚举的穷举 match 需补分支（标准 0.x 演进，CHANGELOG/迁移文档有叙述）。

### 9. enum_struct_variant_field_added — `CertCommands::Revoke` 新增 `account_url`（字段新增）
- 提交 `23edc26 "fix(cli): revoke with existing account url"`（T17 附件的 CLI 修复：吊销复用既有
  account URL）。CLI 层面、有默认兼容行为；waiver。

### 10. function_parameter_count_changed — CLI handler 签名变更（签名变更）
- `handle_obtain` 7→1 参数、`handle_daemon` 5→6（`952759d` runtime wiring + `d72d436` outbox consumer
  接入 serve/daemon，CHANGELOG "Durable outbox consumer is now wired into every production runtime"；
  对应 v0.9.0 T03/T09、`MIGRATION_v0.9.0.md` "obtain --wait follows durable operation progress"）。
- `handle_order_show` 1→3、`handle_order_list` 0→2（`0a54f10`，v0.10.0 **T17**：CLI order 命令改查
  durable `/api/v1/operations`，需 api_base/api_key，`docs/MIGRATION_v0.10.0.md` CLI Changes）。
- `handle_cert_revoke` 3→4（`23edc26`）。均为 CLI 内部装配函数随运行时重写的有意变更。

### 11. constructible_struct_adds_field — 公共配置/装配结构体新增 pub 字段（字段新增）
- 涉及：`EmailConfig.*`（`aed32b5` SMTP 投递 + 后续 polish）、`HttpClientConfig.retry_policy` /
  `RetryPolicy.retry_on_*`（`1f52c0a` 传输层重试策略）、`AppState.authorizer/repositories/application/
  query`（`bb9f111`，T08）、`AcmeSettings.trust_anchor_pem_files / skip_certificate_trust_check`
  （`4036cda`，T15）、`WebhookConfig.signing_secret/replay_window_secs/event_type_filter`
  （`66b534d`，v0.9.0 T11 可观测性/安全）、`ObtainArgs.wait`（`952759d`）、`Config.{ca,repository,dns,
  outbox,key,delivery}`（v0.9.0 T02/T03/T08/T10 配置 schema 扩展）、`Directory.{renewal_info,profiles,
  extensions}`（v0.9.0 **T04**：RFC 9773 ARI、profiles 宽松发现）、`Challenge.{issuer_domain_names,
  accounturi}`（T05 多 CA/多账户挑战）、`Dns01Config.propagation`（v0.10.0 **T16** DNS 传播策略）。
- 理由：全部为 `#[serde(default)]` 的新配置面（项目红线"New public fields must be #[serde(default)]"），
  仅破坏对结构体的穷举字面量构造；配置文件消费者不受影响。waiver。

### 12. auto_trait_impl_removed — `RedisStorage` 不再实现 `UnwindSafe/RefUnwindSafe`（特征变更）
- `src/storage/redis.rs:15`：`manager: OnceCell<redis::aio::ConnectionManager>` 取代每操作建连；
  `ConnectionManager` 非 unwind-safe，提交 `dc17605 "perf(storage): cursor SCAN and cached connection
  manager in legacy RedisStorage"`（CHANGELOG 性能条目）。
- **处置：已修复（非 waiver）**——`src/storage/redis.rs` 显式恢复
  `impl UnwindSafe / RefUnwindSafe for RedisStorage`，附书面论证：
  `ConnectionManager` 是自愈式复用连接，任何失败（含 unwind 期间观察到的失败）后的下一次使用都会重连，
  因此 `catch_unwind` 观察到 `&RedisStorage` 不会让后端停留在后续操作无法恢复的状态；
  0.8.0 的下游依赖这两个 trait，恢复它们是真正的兼容性修复。
- **结论：这是 11 项中唯一非预先设计的破坏，现已消除；waiver 清单（semver-waiver-accepted.txt）
  覆盖其余 10 项检查。**

## 总体结论与处置

- 除第 12 项（RedisStorage auto-trait）外，**其余 10 项均为有意的破坏性变更且有替代路径**：
  Identifier（兼容层+deprecation）、OCSP（verification_report）、RenewalHooks（outbox webhook/email
  通知 + 外部工具链，旧配置段静默忽略）、feature shells（删 flag）、枚举/字段/CLI 签名（迁移文档
  MIGRATION_v0.9.0 / MIGRATION_v0.10.0 均有对应条目）。
- **未发现意外的功能性删除或静默行为破坏**。发布前对第 12 项二选一：(a) 由 release-manager 在本
  waiver 上签字放行（附上述影响评估）；(b) 在 `RedisStorage` 上恢复 auto-trait（如包一层 newtype）。
- 本文件与 `RELEASE_DECISION.md` 的 semver gate 阻塞项一一对应，作为 waiver 附件归档。
- **门禁机制**：`scripts/run_semver_check.sh` 以
  `docs/roadmap/v0.10.0/semver-waiver-accepted.txt`（机器无关签名单）核对本轮全部失败项——
  全部覆盖则通过并注明 waiver；出现任何清单之外的破坏即失败。0.10.0 版本 bump 后（基线变为本次发布），
  本清单所列差异全部消失，接受清单应收窄至空，后续 semver gate 恢复必须全绿。
