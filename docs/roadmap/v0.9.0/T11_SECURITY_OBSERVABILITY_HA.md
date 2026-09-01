# T11：安全、可观测性与多实例强化

**任务性质**：生产运行保障
**前置依赖**：T02、T03、T08；T09/T10 提供续签和部署事件
**主要后继**：T12
**建议改动范围**：auth、config、metrics、events、tracing、repository lease、运维文档

---

## 1. 背景与当前问题

当前项目具有 API Key、Tracing、OTLP、Prometheus、Webhook 和 EventAuditor，但：

- 未配置 API Key 时使用固定默认密钥。
- 凭据主要以普通 String 存储。
- 业务 Trace 缺少统一 Operation/Lineage 关联。
- 关键指标没有覆盖 Challenge Lease、续签安全窗口和 Deployment。
- 多实例任务领取、Lease/Fencing 尚未形成端到端验证。
- Webhook 不是持久化 Outbox 消费者。

本任务在业务闭环完成后建立生产安全与运行保障，不重新实现核心 Workflow。

---

## 2. 目标

1. 建立 SecretRef/SecretResolver，消除配置和日志中的明文凭据扩散。
2. 删除默认管理密钥，建立可替换 AuthN/AuthZ。
3. 建立结构化审计、Outbox 和可靠 Webhook。
4. 统一 Trace/Metric/Event 关联字段和低基数规范。
5. 完成多实例 Lease/Fencing、Leaderless Worker 和 Scheduler 安全。
6. 定义健康检查、就绪检查、SLO 和告警。
7. 完成安全配置和生产部署基线。

---

## 3. 非目标

- 不建立完整企业 IAM 产品。
- 不把敏感 Identifier 原文放入 Metric label。
- 不允许 Webhook 失败回滚已经完成的 ACME 签发。
- 不以本任务替代专门安全审计。

---

## 4. Secret 管理

```rust
pub enum SecretRef {
    Env { name: String },
    File { path: PathBuf },
    Vault { mount: String, path: String, key: String },
    ProviderSpecific { scheme: String, reference: String },
}

pub trait SecretResolver {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretBytes>;
}
```

要求：

- Config 反序列化只产生 SecretRef。
- Secret 类型实现受控 Debug，永不输出内容。
- DNS、EAB、Webhook、SMTP、API credentials 使用 SecretRef。
- Secret 生命周期尽可能短；可用时使用 zeroize/secret wrapper。
- env/file resolver 作为首版，Vault/KMS 可增量实现。
- `/health` 不验证所有 secret；`/ready` 验证必要依赖但不泄露原因细节给未授权用户。

---

## 5. AuthN/AuthZ

- 无管理凭据配置时，管理 API 启动失败；健康端点可以保留。
- API Key 使用 hash 存储和常量时间比较。
- 支持 key ID、状态、过期时间和轮换窗口。
- ActorContext 包含 subject、tenant、roles、request ID。
- 最低权限：intent.read/write、issue、renew、revoke、deploy、key.export、admin。
- key export 必须独立高权限和审计。
- 为后续 mTLS/OIDC 留 Authenticator trait，但首版不必全部实现。

---

## 6. 审计和 Outbox

审计事件至少包括：

- actor/tenant/action/resource。
- request/operation ID。
- outcome、stable error code。
- before/after revision 或安全摘要。
- timestamp、source IP/agent（受隐私策略控制）。

敏感值只记录 hash/reference。

Webhook 通过 Outbox 消费：

- 至少一次投递。
- event ID 用于消费者去重。
- 指数退避和 Retry-After。
- dead-letter 状态和人工重放。
- HMAC 签名、时间戳和重放窗口。
- Webhook 失败不改变领域事务结果。

---

## 7. Trace 规范

所有主要 span 包含：

- `tenant_id`
- `intent_id`
- `lineage_id`
- `operation_id`
- `workflow_step`
- `ca_id`
- `challenge_type`
- `provider_id` 或 `sink_id`

不得包含：

- 私钥、token、key authorization。
- EAB/DNS/API secret。
- 完整 JWS。
- 证书私钥 PEM。

Identifier 根据配置记录规范化 hash 或受控原文，默认使用 hash。

---

## 8. Metric 规范

低基数 label：ca、challenge type、provider type、sink type、result、error class。

禁止使用 operation ID、domain、serial 作为 Prometheus label。

最低指标：

- `acmex_operations_total`
- `acmex_operation_step_duration_seconds`
- `acmex_acme_requests_total`
- `acmex_acme_request_duration_seconds`
- `acmex_bad_nonce_total`
- `acmex_challenge_propagation_seconds`
- `acmex_challenge_cleanup_pending`
- `acmex_renewal_due`
- `acmex_renewal_failures_total`
- `acmex_certificate_seconds_to_expiry`
- `acmex_deployment_total`
- `acmex_outbox_pending`
- `acmex_repository_errors_total`

---

## 9. 健康与就绪

### Liveness

只证明进程事件循环可运行，不依赖 CA、DNS 或 Redis 短暂可用性。

### Readiness

检查：

- Repository 读写或轻量 ping。
- Worker 是否在运行且 Lease 时钟健康。
- 必需 Secret Resolver 是否可用。
- 配置是否已验证。

不要求每个 CA/DNS Provider 实时成功，否则外部故障会导致所有 API 摘除；这些依赖通过专用 diagnostics 展示。

---

## 10. 多实例

- 所有 Worker 通过 T03 Lease 竞争任务，无固定单点 leader。
- Scheduler scan 可使用分片或 scanner lease，重复扫描也不能重复创建 Operation。
- Outbox consumer 使用 partition/lease 和 fencing。
- Instance shutdown 停止领取新任务，等待当前短 Step 或释放 Lease。
- 时钟偏差影响 Lease 时使用 Repository/server time 或明确容忍范围。
- 配置和 schema migration 需要兼容滚动升级。

---

## 11. 安全配置基线

- API 默认绑定 loopback；公网监听必须显式配置。
- 管理 API 要求认证。
- TLS/mTLS termination 责任明确。
- File secret/keys 权限校验。
- 自定义 CA URL、Webhook URL、Provider endpoint 有 allowlist/SSRF 保护。
- 请求体、证书链和 webhook body 有大小上限。
- 所有外部请求有 connect/read/total timeout。
- 禁止无限重试和无限队列。
- Config validation 覆盖不兼容 feature、空 directory、无 DNS provider 等。

---

## 12. SLO 与告警

建议：

- 签发 Operation 成功率和 P95/P99。
- Renewal 在 window 内成功率 >= 99.9%。
- `seconds_to_expiry` 小于安全阈值立即告警。
- CleanupPending 超过 Lease TTL 告警。
- CompensationFailed、RollbackFailed 立即告警。
- Outbox backlog 和 oldest event age 告警。
- CA 429/badNonce 突增告警。
- IP/短周期证书单独阈值。

提供至少一份 Prometheus rule 示例和 dashboard 字段说明。

---

## 13. 实施步骤

1. 定义 SecretRef/Resolver/Secret wrapper，迁移配置字段。
2. 删除默认 API Key，新增 Authenticator/Authorizer。
3. 为 Application Command 注入 ActorContext。
4. 将 EventAuditor 改造为持久化 Audit/Outbox。
5. 实现可靠 Webhook Consumer、签名、DLQ、重放。
6. 定义 tracing field/span convention 并接入 Workflow/CA/Challenge/Sink。
7. 补全 metrics 和低基数检查。
8. 实现 liveness/readiness/diagnostics。
9. 完成多实例 Worker/Scanner/Outbox 测试。
10. 编写生产安全配置和告警示例。

---

## 14. 测试要求

- Secret Debug/Error 不含原值。
- 无 API credential 时管理 API 启动失败。
- API key 常量时间校验和轮换。
- key.export 权限隔离和审计。
- Webhook 重试、重复、签名、DLQ、重放。
- Metric 不出现域名/operation ID 等高基数 label。
- Trace 不出现 token/JWS/private key。
- 两个 Worker/Scanner/Outbox consumer 并发和 fencing。
- 优雅关停/Lease 接管。
- Repository 短暂失败时 liveness 与 readiness 语义。

命令：

```bash
cargo test security
cargo test auth
cargo test outbox
cargo test observability
cargo test multi_instance
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 15. 验收标准

- 没有默认生产管理密钥。
- 凭据使用 SecretRef，不在 Debug/Trace/Problem 中出现。
- 业务状态与 Outbox 原子写入或有等价保证。
- 多实例不会重复推进相同 fenced Step。
- liveness/readiness 语义明确并有测试。
- 关键 SLO 指标和告警示例完整。

---

## 16. 风险与回滚

- Auth 配置变化可能锁死管理入口，提供离线配置校验命令。
- 指标 label 变更影响 dashboard，提供迁移说明。
- SecretRef 迁移保留受控兼容期，但不再打印旧明文字段。
- 多实例启用前先在单实例走相同 Lease 路径。

---

## 17. 交付物

- SecretRef/Resolver。
- Authenticator/Authorizer 和权限模型。
- Audit/Outbox/Webhook Consumer。
- Trace/Metric conventions 和实现。
- Health/Readiness/Diagnostics。
- 多实例验证、SLO、告警和生产安全文档。

