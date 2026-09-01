# T04：CA Backend 与 ACME 协议生产化

**任务性质**：上游 CA 接入和协议可靠性
**前置依赖**：T01；与 T03 对接时需要其 ErrorClass/Step 约定
**主要后继**：T07-T09
**建议改动范围**：`src/protocol/`、`src/account/`、`src/order/`、`src/transport/`、新增 `src/ca_backend/`

---

## 1. 背景与当前问题

当前账户和订单管理器各自直接使用 `reqwest::Client`、DirectoryManager 和 NonceManager。项目虽然拥有 HttpClient、RetryPolicy、RateLimiter、MiddlewareChain 和 NoncePool，但没有进入主要 ACME 路径。

现有模型也没有：

- CA Capability Discovery。
- ACME Profiles。
- RFC 9773 ARI。
- 统一 `badNonce` 恢复。
- Retry-After 和 Problem Document 分类。
- 稳定复用的 Account/Directory/HTTP Session。

本任务把现有协议实现包装成稳定 `CaBackend`，并完成协议生产化；不负责业务 Workflow 和 Challenge 外部资源。

---

## 2. 目标

1. 建立 `CaBackend` 和 `AcmeCaBackend`。
2. 建立可复用 `AcmeSession`，统一 Directory、Account、Nonce、Transport。
3. 统一 ACME POST-as-GET、JWS、Replay-Nonce 和 Problem Document。
4. 正确处理 badNonce、Retry-After、429 和临时服务错误。
5. 支持 Directory capability、ARI 和 Certificate Profiles 的宽松发现。
6. 持久化 Account Key/Account URL 引用，而不是每次创建临时账户状态。
7. 保留当前 `AccountManager`、`OrderManager` 的兼容 facade。

---

## 3. 非目标

- 不实现 CA 服务端。
- 不自动跨 CA failover；只提供能力和明确策略输入。
- 不实现 Challenge Presenter。
- 不在此任务决定最终续签时间，只返回 RenewalWindow。

---

## 4. 目标接口

```rust
#[async_trait]
pub trait CaBackend: Send + Sync {
    async fn capabilities(&self) -> Result<CaCapabilities>;
    async fn ensure_account(&self, account: &AccountRef) -> Result<AccountHandle>;
    async fn create_order(&self, request: &OrderRequest) -> Result<OrderHandle>;
    async fn get_order(&self, order: &OrderHandle) -> Result<OrderResource>;
    async fn get_authorizations(&self, order: &OrderHandle) -> Result<Vec<AuthorizationResource>>;
    async fn acknowledge_challenge(&self, challenge: &ChallengeRef) -> Result<()>;
    async fn get_authorization(&self, authz: &AuthorizationRef) -> Result<AuthorizationResource>;
    async fn finalize(&self, order: &OrderHandle, csr_der: &[u8]) -> Result<()>;
    async fn download_certificate(&self, order: &OrderHandle) -> Result<IssuedChain>;
    async fn renewal_window(&self, version: &CertificateVersion)
        -> Result<Option<RenewalWindow>>;
    async fn revoke(&self, request: &RevocationRequest) -> Result<()>;
}
```

所有 handle 必须可序列化，以便 Workflow 重启恢复。

---

## 5. AcmeSession

```rust
pub struct AcmeSession {
    ca_id: CaId,
    directory: Arc<DirectoryCache>,
    account: AccountHandle,
    signer: Arc<dyn AccountSigner>,
    transport: Arc<dyn AcmeTransport>,
    nonce_source: Arc<NonceSource>,
    limiter: Arc<CaRateLimiter>,
}
```

要求：

- Session 以 tenant/CA/account 为边界复用。
- Directory 有 TTL、主动刷新和 schema 宽松字段。
- Account Key 从 AccountRepository/KeyProvider 加载。
- Nonce 来自统一 source，所有 ACME 响应 Replay-Nonce 自动回收。
- 不在每次 Order 中重新构造 DirectoryManager 和 AccountManager。

---

## 6. Transport 和请求执行

建立单一请求执行函数：

```rust
async fn execute_jws<T: DeserializeOwned>(
    &self,
    endpoint: &Url,
    payload: JwsPayload,
    mode: RequestMode,
) -> Result<AcmeResponse<T>>;
```

必须处理：

- JWS protected header 中 alg、nonce、url、kid/jwk。
- POST-as-GET 空 payload 的规范编码。
- 所有响应的 Replay-Nonce。
- ACME Problem Document 解析。
- 请求和响应 body 大小上限。
- timeout、连接池、代理/CA roots 配置。
- Trace 中不记录 JWS payload、EAB HMAC、私钥。

### badNonce

- 发现 `urn:ietf:params:acme:error:badNonce` 后丢弃旧 nonce。
- 使用响应携带 nonce 或重新获取 nonce。
- 仅在明确 badNonce 时进行有限即时重试。
- 重试次数耗尽返回稳定 `ACME_BAD_NONCE_EXHAUSTED`。
- 该内部重试不应让 Workflow 重新创建 Order。

### Retry-After

- 支持秒数和 HTTP Date。
- 429、503 和 CA Problem 根据 error type 分类。
- 返回 `ErrorClass::RateLimited { retry_after }` 或 `Retryable`。
- Polling 优先采用 CA Retry-After，而不是固定 2 秒。

---

## 7. Directory Capabilities

Directory 模型增加宽松可选字段：

- `renewalInfo`
- `profiles`
- 未知扩展保存在 `extensions`，不得因新增字段解析失败。

`CaCapabilities` 至少包含：

- 支持的 Identifier 类型。
- 支持的 Challenge 类型或 unknown。
- 是否支持 ARI。
- 可用 profile 名称和元数据。
- 是否要求 EAB。
- revoke/keyChange endpoint。
- CA policy overrides，例如 IP 必须 short-lived。

不得把 Let's Encrypt 特定 profile 写死成通用规范；CA Adapter 可提供 policy hint。

---

## 8. ACME Profiles

- OrderRequest 增加可选 profile。
- profile 必须来自 Intent/Planner 或 CA capability，不从 CSR 隐式推断。
- 未知 profile 返回稳定 Policy/CA 错误。
- 实现应对 Internet-Draft 变化保持宽松解析，并用适配层隔离 wire field。
- 添加 Let's Encrypt `shortlived` 场景的 fixture，但不要让通用领域模型依赖该字符串。

---

## 9. ARI

实现 RFC 9773：

- 从 Directory `renewalInfo` 发现 endpoint。
- 从证书 AKI keyIdentifier 与 serial DER 构造 CertID。
- 未认证 GET 获取 RenewalInfo。
- 解析 suggestedWindow 和 Retry-After。
- 支持 `replaces`/replacement 标识所需 Order 扩展。
- ARI 不可用或格式错误时返回 `Ok(None)` 或可分类错误，由 Renewal Controller 决定 fallback。
- ARI 请求不能阻塞正常证书扫描。

---

## 10. Account 持久化

- Account identity 至少由 tenant、CA directory identity、account key ref 唯一确定。
- Account URL 创建成功立即持久化。
- 重启后优先复用 Account URL 和 signer。
- EAB 只用于创建需要 EAB 的账户，凭据来自 SecretRef。
- Account Key Rollover 成功后原子切换 key ref；失败保留旧 key。

---

## 11. 实施步骤

1. 盘点 AccountManager、OrderManager、NonceManager 的所有请求代码。
2. 定义 CaBackend、Handle、Capabilities 和稳定错误码。
3. 实现统一 AcmeTransport/JWS executor。
4. 将 Replay-Nonce、badNonce、Problem Document、Retry-After 移入 Transport。
5. 实现 AcmeSession 和 Session Factory。
6. 改造现有 Account/Order 方法委托给 AcmeCaBackend。
7. 扩展 Directory 和 Order wire model 支持 ARI/Profile。
8. 实现 ARI CertID、RenewalInfo 请求和 fixture。
9. 接入 AccountRepository 和 AccountSigner/KeyRef。
10. 为旧 AcmeClient 保留兼容构造器。

---

## 12. 测试要求

- Directory 未知扩展宽松解析。
- POST-as-GET payload 字节准确。
- 每个响应 Replay-Nonce 回收。
- badNonce 第一次失败、第二次成功。
- badNonce 耗尽。
- Retry-After 秒数和 HTTP Date。
- 429/503/ACME Problem ErrorClass。
- Account 重启复用，不重复注册。
- Profile Order JSON fixture。
- ARI CertID golden vector、RenewalInfo 解析和不支持 fallback。
- 并发请求不会复用同一个 nonce。

命令：

```bash
cargo test ca_backend
cargo test protocol
cargo test ari
cargo test account
cargo test order
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 13. 验收标准

- 生产 ACME 请求只经过统一 Transport。
- `transport::HttpClient` 等不再是与主流程脱节的孤立模块。
- badNonce 和 Retry-After 有行为测试。
- Account URL 和 KeyRef 可跨重启复用。
- Handle 可持久化并由 Workflow 恢复。
- ARI/Profile 不支持时有明确 capability/fallback，不会解析崩溃。

---

## 14. 风险与回滚

- ACME Profiles 仍可能变化，wire model 与 domain model 必须隔离。
- 迁移期间避免同时维护两套不同 JWS 逻辑；旧 Manager 只做 facade。
- 真实 CA 测试必须使用 staging，避免生产速率限制。
- 如新 Session 出现问题，可保留旧 AcmeClient 兼容入口，但不允许新 Workflow 回退到旧整段重试。

---

## 15. 交付物

- CaBackend/AcmeCaBackend。
- AcmeSession/Session Factory。
- 统一 Transport、Nonce、Problem、Retry。
- Profiles 和 ARI 支持。
- Account 持久化集成。
- 协议 fixture、golden tests 和 staging 测试说明。

