# AcmeX 当前功能、架构评估与目标架构设计

**文档状态**：目标架构总纲
**分析基线**：`main@de078b0`
**当前包版本**：v0.8.0
**目标演进版本**：v0.9.0 及后续版本
**最后更新**：2026-08-31
**适用读者**：架构师、维护者、功能实现 Agent、上下游集成方、测试与运维人员

---

## 1. 文档目的

本文档以当前仓库代码为事实来源，完成以下工作：

1. 说明 AcmeX 当前真正具备的功能、架构边界和验证状态。
2. 区分“代码已闭环实现”“已有模块但未接入主流程”“文档声明或演示逻辑”。
3. 找出阻碍证书签发、续签、域名验证、IP 验证以及上下游快速接入的关键问题。
4. 给出一个可以渐进落地的目标架构，而不是一次性拆成大量微服务。
5. 为 `docs/roadmap/v0.9.0/` 下的独立实施任务提供统一上下文和设计约束。

本文件不代表当前功能已经完成。所有“目标状态”必须经过对应任务的代码、测试和验收门槛后，才能更新为“已实现”。

---

## 2. 执行摘要

AcmeX 当前已经具备较丰富的 ACME v2 基础模块：Directory、Nonce、JWS、账户、订单、CSR、三类 Challenge、多个 DNS Provider、存储抽象、REST API、CLI、调度器和可观测性组件。

但是，当前系统还没有形成一个生产级证书生命周期闭环。最主要的问题不是缺少更多模块，而是已有模块之间没有通过统一、持久化、可恢复、可补偿的业务工作流连接起来。

当前项目应更准确地定义为：

> 具有较完整协议和适配器骨架的 ACME 客户端原型，尚未成为可靠的证书生命周期控制平面。

下一阶段的第一目标必须从“增加功能数量”切换为：

> 让任意一次签发和续签都可追踪、可恢复、可重试、可清理、可验证、可原子部署。

建议采用“模块化单体控制平面 + 可插拔执行适配器”的目标形态。先稳定领域模型、端口接口和持久化工作流；当吞吐、租户隔离或部署拓扑确实需要时，再把 Worker、Challenge Agent 或 Sink 拆成独立进程。

---

## 3. 当前验证基线

本次评估完成了以下验证：

| 验证项 | 结果 | 能证明的范围 | 不能证明的范围 |
|---|---|---|---|
| `cargo test` | 通过 | 71 个单元测试、4 个集成测试、1 个 doctest 可通过 | 不能证明真实 CA 完整签发、续签、传播和故障恢复 |
| `cargo check --all-features` | 通过 | 当前所有 feature 组合可以完成类型检查 | 不能证明每个 DNS Provider 的真实 API 行为 |
| Git 工作树 | 干净 | 分析前没有未提交修改 | 不代表远程 CI 或外部系统状态 |

现有集成测试主要覆盖账户注册和订单创建，尚未覆盖：

- 完整授权获取和 Challenge 选择。
- HTTP-01、DNS-01、TLS-ALPN-01 的真实验证生命周期。
- Challenge 失败后的资源清理。
- CSR finalize、证书下载、证书校验和持久化。
- 续签窗口、并发续签、重启恢复和重复任务抑制。
- 证书向 Nginx、Ingress、Kubernetes Secret、Vault 或负载均衡器部署。
- IPv4/IPv6 Identifier 的完整签发。

因此，测试全部通过只能作为当前代码基线健康证据，不能作为“生产就绪”结论。

---

## 4. 当前功能清单与真实成熟度

### 4.1 协议层

当前已实现：

- ACME Directory 获取和进程内缓存。
- Nonce 获取与响应头缓存。
- JWK、JWS、账户密钥和账户注册。
- Order、Authorization、Challenge 对象解析。
- Order 创建、查询、Challenge 响应、finalize 和证书下载。
- CSR 生成、证书 PEM 解析和基础 SAN 读取。
- 账户 Key Rollover 和证书吊销接口。

当前主要不足：

- 高层流程仍直接使用 `reqwest::Client`，没有真正复用 `transport::HttpClient`、RetryPolicy、RateLimiter 和 MiddlewareChain。
- `NoncePool` 可被启用，但订单和账户管理器仍直接使用自己的 `NonceManager`，没有进入主要请求路径。
- 缺少统一的 `badNonce` 恢复、`Retry-After`、429/5xx 分类重试和 CA 速率预算。
- Directory 数据模型缺少 ACME Renewal Information 和 Certificate Profiles 等扩展能力。
- 账户、Directory、Nonce 和 HTTP Client 被多个流程重复创建，缺少稳定的 CA Session。

### 4.2 Challenge 层

当前已实现：

- `ChallengeSolver` trait。
- HTTP-01 临时 Axum 服务。
- DNS-01 TXT 值计算和 `DnsProvider` 抽象。
- TLS-ALPN-01 临时 TLS 服务和 `acmeValidation-v1` 扩展生成。
- Challenge Solver Registry。

当前主要不足：

- 主签发流程只调用 `prepare()`、`present()`，没有调用 `verify()` 和 `cleanup()`。
- Challenge 未形成独立 Session；Registry 每种类型只有一个可变 Solver，不能安全表达多个域名同时验证。
- 没有持久化 Challenge Lease，进程崩溃后无法清理 DNS Record 或恢复临时服务。
- `verify()` 多数只是检查内存字段存在，不代表从 CA 视角可访问。
- HTTP-01 只保存一个 key authorization，不能并发服务多个 token。
- 中央服务直接绑定 80/443，无法自然适配已有 Nginx、Ingress、CDN、Anycast 或多节点边缘。

### 4.3 DNS Provider 层

当前已有 Cloudflare、Route53、DigitalOcean、Linode、Azure、Google Cloud、Alibaba Cloud、GoDaddy、Tencent Cloud、Huawei Cloud 和 ClouDNS 等 Provider 代码。

当前主要不足：

- 配置中的 Provider 名称没有对应统一 Provider Factory。
- `CertificateProvisioner` 的 DNS-01 分支没有真正注册 `Dns01Solver`。
- 没有可靠的权威 Zone 查找、SOA 发现和 CNAME/NS 委派处理。
- Provider 同时承担“写记录”和“判断传播”，职责不清。
- 缺少权威 NS 与多个递归解析器的传播一致性检查。
- 缺少真实 Provider 契约测试、凭据权限最小化检查和错误分类。

### 4.4 存储层

当前已实现：

- `StorageBackend` trait。
- File、Memory、Redis 后端。
- EncryptedStorage 包装器。
- CertificateStore 和 StorageMigrator。

当前主要不足：

- 存储抽象只是一组 KV 方法，尚未表达证书、账户、订单、任务、Challenge Lease、部署状态和事件 Outbox。
- FileStorage 保存、列举、再次加载时的 key 与 `.bin` 后缀处理不对称。
- Provisioner 签发完成后没有保存 CertificateBundle。
- API 任务只存放在进程内 HashMap，重启全部丢失。
- 证书与私钥作为同一个 JSON Bundle 存储，缺少 KeyProvider、密钥引用和分级访问策略。
- `encrypted` 配置没有在 server 启动路径中真正构造 EncryptedStorage。

### 4.5 编排和调度层

当前已实现：

- `Orchestrator` trait。
- CertificateProvisioner、DomainValidator、CertificateRenewer。
- SimpleRenewalScheduler 和 AdvancedRenewalScheduler。
- Priority Queue、Semaphore 和最多三次重试。

当前主要不足：

- Orchestrator 状态没有由实现维护，`status()` 和 `cancel()` 仍是默认空行为。
- Provisioner 的重试覆盖整段签发流程，可能重复创建账户或订单。
- 没有持久化状态机，也没有步骤级幂等键。
- Advanced Scheduler 扫描时不检查有效期，而是把所有证书入队。
- Server 只运行队列消费者，没有周期调用存储扫描。
- 续签成功后没有保存新证书，也没有原子切换当前版本。
- 没有分布式 Lease，多实例会重复续签。
- 没有 ARI、随机抖动、证书有效期百分比和短周期证书策略。

### 4.6 API、CLI 和上下游集成

当前已实现：

- Rust Library API。
- Axum REST API、API Key 中间件和异步任务返回形式。
- Account、Order、Certificate、Health、Webhook 路由。
- CLI obtain、renew、serve、cert、account、order 等命令入口。

当前主要不足：

- CLI obtain 写入占位证书和私钥。
- CLI renew 只备份旧证书并模拟续签成功。
- REST 证书列表和部分证书字段是固定示例值。
- 单证书 renew API 通过 sleep 模拟成功。
- API、CLI 和 Scheduler 没有调用同一个 Application Service。
- API 返回格式和 RFC 7807 错误格式不完全一致。
- 默认 API Key 是公开可猜测的固定值。
- 没有 Idempotency-Key、租户、RBAC、操作审计主体和请求版本。
- 没有标准 Certificate Sink，因此签发结果无法可靠交付给下游。

### 4.7 证书验证和状态检查

当前已实现证书 PEM 解析、SAN 读取、基础有效期判断、签名链一致性、可配置信任锚校验和 OCSP URL 提取。

当前主要不足：

- 系统信任根自动发现尚未接入；当前信任锚需经 ACME 配置显式提供。默认配置下缺少
  `trust_anchor_pem_files` 会使 `chain_trusted` 失败；只有显式设置
  `skip_certificate_trust_check = true` 时报告才允许记录为 `not-checked`。
- Key Usage 和 Extended Key Usage 尚未形成统一验收。
- 原 `OcspVerifier` 模拟 `Good` 的公共能力已移除；真实 OCSP/CRL 请求、响应验证仍未实现。
- 不应把 OCSP 作为所有 CA 的通用假设；目标架构应按 CA capability 支持 OCSP、CRL 或短周期证书策略。

---

## 5. 当前主要根因

上述问题可以归纳为六个架构根因：

1. **缺少统一领域模型**：域名、IP、证书意图、逻辑证书、证书版本和操作任务都没有稳定类型。
2. **缺少应用服务边界**：API、CLI、Scheduler 各自拼装流程，导致行为漂移。
3. **缺少持久化工作流**：状态只存在调用栈或内存中，不能恢复和补偿。
4. **端口与适配器没有真正解耦**：虽然存在 trait，但主流程仍直接依赖具体 reqwest、文件和临时监听器。
5. **证书签发与证书部署混为一谈或完全断开**：没有版本化、原子激活、回滚和下游交付模型。
6. **测试更偏模块存在性，而非生命周期行为**：缺少真实 E2E、故障注入和重启恢复测试。

---

## 6. 目标能力边界

### 6.1 上游接入

上游是向 AcmeX 提交证书期望状态的系统，包括：

- Rust SDK 调用方。
- REST API 客户端。
- 后续可选的 gRPC 客户端。
- Kubernetes Controller、Issuer 或内部平台。
- CMDB、资产平台、域名平台和负载均衡平台。
- 人工 CLI 操作。

所有上游入口必须转换成统一 `CertificateIntent`，并通过同一个 Application Service 进入系统。

### 6.2 外部依赖

外部依赖包括：

- Let's Encrypt、Google Trust Services、ZeroSSL、私有 ACME CA。
- DNS Provider。
- HTTP/TLS Edge Agent、Ingress、CDN 或 Load Balancer。
- KMS、Vault、PKCS#11 或本地软件密钥。

这些能力通过稳定端口接入，不允许直接渗透到领域工作流。

### 6.3 下游交付

下游是消费证书的系统，包括：

- 文件目录。
- Kubernetes Secret。
- Vault KV/PKI。
- Nginx、HAProxy、Caddy。
- 云负载均衡器、CDN、API Gateway。
- Java KeyStore、PKCS#12 或其他格式化目标。
- 仅需要公钥证书、不允许 AcmeX 持有私钥的外部 CSR 系统。

下游交付必须通过 Certificate Sink 完成，并与证书签发事务解耦。

---

## 7. 目标架构

```text
┌──────────────────────────────────────────────────────────────────┐
│ 上游入口                                                         │
│ REST API │ Rust SDK │ CLI │ Kubernetes │ gRPC/Platform Adapter  │
└──────────────────────────────┬───────────────────────────────────┘
                               │ CertificateIntent
┌──────────────────────────────▼───────────────────────────────────┐
│ Application Service                                                │
│ 规范化 │ 幂等 │ 鉴权 │ Policy Planning │ Operation 查询/取消      │
└──────────────────────────────┬───────────────────────────────────┘
                               │ Durable Command
┌──────────────────────────────▼───────────────────────────────────┐
│ 持久化 Workflow Engine                                             │
│ Step 状态 │ Lease │ Retry │ Timeout │ Compensation │ Resume       │
└───────────────┬──────────────────┬───────────────────┬─────────────┘
                │                  │                   │
       ┌────────▼────────┐ ┌───────▼────────┐ ┌────────▼──────────┐
       │ CA Backend      │ │ Challenge      │ │ Key Provider      │
       │ ACME/Profiles   │ │ DNS/HTTP/TLS   │ │ Local/KMS/Vault   │
       └────────┬────────┘ └───────┬────────┘ └────────┬──────────┘
                │                  │                   │
┌───────────────▼──────────────────▼───────────────────▼─────────────┐
│ Repository + Secret Store + Outbox                                 │
│ Account │ Intent │ Operation │ Lease │ CertificateVersion │ Event  │
└──────────────────────────────┬────────────────────────────────────┘
                               │ Deployment Event
┌──────────────────────────────▼────────────────────────────────────┐
│ Certificate Sink                                                   │
│ File │ K8s Secret │ Vault │ Nginx │ LB/CDN │ Custom Webhook       │
└───────────────────────────────────────────────────────────────────┘
```

### 7.1 架构形态选择

v0.9.0 推荐维持单仓库、单进程可运行的模块化单体：

- 领域层不依赖 Axum、Redis、具体 DNS SDK 和具体 CA。
- Application Service 只依赖端口 trait。
- Adapter 可以通过 feature 或构造器启用。
- Workflow 与 Repository 接口从第一天支持多实例 Lease。
- HTTP/TLS Edge Agent 和 Certificate Sink 允许独立进程实现，但本地实现仍可内嵌运行。

满足下列条件之一后再拆微服务：

- Challenge 执行必须跨多个网络区域。
- 单个控制平面需要管理大量租户或百万级证书。
- Secret 权限要求控制平面不能接触私钥。
- 不同 Sink 或 Provider 需要独立扩缩容和发布周期。

---

## 8. 核心领域模型

### 8.1 Identifier

```rust
pub enum Identifier {
    Dns(DnsName),
    Ip(std::net::IpAddr),
}
```

要求：

- DNS Name 必须标准化大小写、尾点和 IDNA 表示。
- Wildcard 是 DNS Identifier 的显式属性或经过验证的值，不依靠散落的字符串判断。
- IP 使用 `IpAddr`，自然获得 IPv4/IPv6 规范化。
- 序列化仍遵循 ACME `{"type":"dns|ip","value":"..."}`。

### 8.2 CertificateIntent

表示上游期望，而不是某一次 ACME Order：

```rust
pub struct CertificateIntent {
    pub id: IntentId,
    pub tenant_id: TenantId,
    pub identifiers: Vec<Identifier>,
    pub ca_policy: CaPolicy,
    pub validation_policy: ValidationPolicy,
    pub key_policy: KeyPolicy,
    pub renewal_policy: RenewalPolicy,
    pub delivery_targets: Vec<DeliveryTarget>,
    pub idempotency_key: String,
    pub generation: u64,
}
```

### 8.3 CertificateLineage 与 CertificateVersion

`CertificateLineage` 表示逻辑证书；`CertificateVersion` 表示一次不可变签发结果。续签不覆盖旧文件，而是创建新版本并原子切换 `active_version_id`。

版本至少记录：

- 精确 Identifier 集合和规范化哈希。
- 证书链、叶子证书、序列号、AKI、SKI。
- `not_before`、`not_after`、签发 CA、profile。
- Key Reference，而非必然存储明文私钥。
- 取代的旧版本和被哪个版本取代。
- 验证报告和部署状态。

### 8.4 Operation

所有异步签发、续签、吊销、部署和清理都表示为 Operation：

- Operation ID 全局唯一。
- 有明确类型、状态、当前 Step、进度和稳定错误码。
- 记录 request hash 与 idempotency key。
- 支持查询、取消和重试。
- 支持父子 Operation，例如续签产生多个部署子任务。

### 8.5 ChallengeLease

ChallengeLease 保存可以恢复和清理的外部状态：

- Authorization URL 和 Challenge URL。
- Identifier、Challenge Type、token 哈希。
- DNS Record Locator、HTTP Edge Route ID 或 TLS Route ID。
- 创建时间、过期时间、当前状态和清理重试次数。
- Provider/Agent 标识，但不直接持久化明文凭据。

---

## 9. 核心端口接口

### 9.1 CA Backend

```rust
#[async_trait]
pub trait CaBackend: Send + Sync {
    async fn capabilities(&self) -> Result<CaCapabilities>;
    async fn ensure_account(&self, account: &AccountRef) -> Result<AccountHandle>;
    async fn create_order(&self, request: OrderRequest) -> Result<OrderHandle>;
    async fn fetch_authorizations(&self, order: &OrderHandle) -> Result<Vec<Authorization>>;
    async fn acknowledge_challenge(&self, challenge: &ChallengeRef) -> Result<()>;
    async fn poll_authorization(&self, authorization: &AuthorizationRef) -> Result<AuthzState>;
    async fn finalize(&self, order: &OrderHandle, csr: &[u8]) -> Result<()>;
    async fn poll_order(&self, order: &OrderHandle) -> Result<OrderState>;
    async fn download_certificate(&self, order: &OrderHandle) -> Result<IssuedChain>;
    async fn renewal_window(&self, certificate: &CertificateVersion) -> Result<Option<RenewalWindow>>;
}
```

### 9.2 Challenge 端口

建议从当前单一 Solver 拆分为：

- `ChallengePlanner`：选择可行 challenge。
- `ChallengePresenter`：创建外部验证资源。
- `PropagationObserver`：判断外部可见性。
- `ChallengeCleaner`：幂等清理资源。

每次 `prepare` 返回可序列化 Lease，而不是把 record ID 只放在 Solver 内存中。

### 9.3 KeyProvider

必须支持两类模式：

1. Managed Key：AcmeX 生成密钥，通过 Secret Store/KMS 加密保存。
2. External CSR/Signer：私钥始终保留在下游或 KMS 中，AcmeX 只接收 CSR 或签名引用。

```rust
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn create_key(&self, policy: &KeyPolicy) -> Result<KeyRef>;
    async fn create_csr(&self, key: &KeyRef, identifiers: &[Identifier]) -> Result<Vec<u8>>;
    async fn export_private_key(&self, key: &KeyRef) -> Result<Option<SecretBytes>>;
}
```

### 9.4 CertificateSink

```rust
#[async_trait]
pub trait CertificateSink: Send + Sync {
    async fn stage(&self, deployment: &DeploymentSpec, version: &CertificateVersion)
        -> Result<StagedDeployment>;
    async fn activate(&self, staged: &StagedDeployment) -> Result<()>;
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth>;
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()>;
}
```

---

## 10. 目标签发工作流

```text
Requested
  → Planned
  → AccountReady
  → Ordered
  → AuthorizationsLoaded
  → ChallengesPrepared
  → PropagationVerified
  → ChallengesAcknowledged
  → AuthorizationsValid
  → Ready
  → Finalized
  → Issued
  → CertificateVerified
  → Persisted
  → Deploying
  → Active
```

每一步必须满足：

- 输入和输出可序列化。
- 完成状态写入 Repository 后才进入下一步。
- 重试不会重复产生不可控外部资源。
- 对外错误可分类为 retryable、terminal、policy、operator_action_required。
- `ChallengesPrepared` 之后，无论后续成功、失败、取消或超时，都注册持久化清理补偿。
- Operation 完成不等于证书可用；只有至少满足 Intent 所要求的部署策略后才标记证书 Active。

### 10.1 幂等策略

- API 层要求 `Idempotency-Key`，CLI 自动生成并可显式指定。
- Intent 使用规范化 Identifier、CA Policy、Key Policy 和 generation 生成 request hash。
- ACME Order URL 一经创建立即持久化，恢复时优先查询旧 Order。
- DNS Presenter 创建记录后保存 Provider Record Locator；重试时查询或复用，不盲目追加。
- Sink 以 `lineage_id + version_id + target_id` 作为幂等键。

### 10.2 补偿策略

- 清理失败不覆盖原始业务错误，而是创建独立 Cleanup Operation。
- DNS TXT 删除必须精确匹配本任务创建的 record locator，不能删除其他并行 TXT。
- HTTP/TLS 临时路由使用 Lease TTL，控制平面失联后 Agent 可自动过期。
- 已签发但部署失败的证书保留为 Inactive，允许重试部署，不重复签发。

---

## 11. 域名验证设计

### 11.1 普通域名

可选择 HTTP-01、DNS-01 或 TLS-ALPN-01。Planner 应结合以下信息选择：

- CA 提供的 challenge 集合。
- Intent 显式策略。
- 是否存在 Wildcard。
- 是否有 DNS 凭据。
- HTTP/TLS Edge Agent 是否可达。
- 端口 80/443 是否能够从公网访问。
- 多节点、Anycast、CDN 和 Ingress 拓扑。

### 11.2 Wildcard

Wildcard 必须使用 DNS-01。Planner 在创建 Order 前就应拒绝不可能的策略组合，不能等待 CA 返回错误。

### 11.3 DNS Zone 与委派

Zone 发现不能只按字符串截取二级域名。推荐流程：

1. 规范化 `_acme-challenge.<identifier>`。
2. 从目标名称逐级向上查询 SOA，确定权威 Zone。
3. 识别 `_acme-challenge` 的 CNAME 或 NS 委派。
4. 按最终写入 Zone 选择 Provider Credential。
5. 创建 TXT 并保存 record locator。
6. 查询权威 NS，再查询配置的递归解析器集合。
7. 达到传播 quorum 后再 acknowledge challenge。

多个 TXT 可以合法并存。清理只能删除当前任务创建的记录。

---

## 12. IP 验证设计

RFC 8738 定义了 `ip` Identifier，并规定：

- IP 可使用 HTTP-01。
- IP 可使用 TLS-ALPN-01。
- IP 不得使用 DNS-01。
- HTTP-01 跳过 DNS 解析，直接访问 Identifier IP。
- IPv6 URL Host 必须正确使用方括号。
- TLS-ALPN 验证证书必须包含单个 `iPAddress` SAN。
- TLS SNI 不能直接使用 IP，必须使用对应的 `IN-ADDR.ARPA` 或 `IP6.ARPA` 反向地址。

当前 Let's Encrypt 已支持 IPv4 和 IPv6 证书，这类证书有效期为 160 小时，并要求短周期策略。因此 IP 支持不能只修改 Identifier 序列化，还必须同时完成：

- CA Capability 和 Profile 支持。
- IP 类型 CSR SAN。
- HTTP/TLS Presenter 的 IP 行为。
- 更短的续签检查周期。
- ARI 或高频带抖动的续签调度。
- 部署健康检查和快速回滚。

对于私网、保留地址或组织内部地址，Planner 应根据 CA Policy 路由到私有 ACME CA，不能盲目提交给公共 CA。

---

## 13. 续签设计

### 13.1 Renewal Window

续签窗口优先级：

1. CA 提供的 ACME Renewal Information。
2. Intent 显式窗口。
3. 证书有效期百分比，例如有效期经过三分之二后。
4. 兼容旧配置的固定提前天数，但不得作为唯一策略。

最终时间点必须加入稳定随机抖动，避免所有证书在整点或同一天集中续签。

### 13.2 调度和并发

- Scheduler 只负责产生 Renewal Operation，不直接执行协议流程。
- 使用 Repository Lease 保证同一 Lineage 同时只有一个有效续签任务。
- 按过期时间、ARI 窗口、部署失败和证书类型计算优先级。
- CA 级别并发和速率限制独立配置。
- Retry-After 优先于本地指数退避。
- 短周期/IP 证书使用独立 SLO 和告警阈值。

### 13.3 版本切换

续签生成新 CertificateVersion：

1. 验证新证书。
2. 持久化新版本。
3. 向所有必须 Sink stage。
4. 原子 activate。
5. 健康检查。
6. 更新 active version。
7. 标记旧版本 superseded。
8. 异步清理过期版本。

任何 Sink 失败时，根据 Intent 的部署策略决定部分成功、回滚或等待人工处理。

---

## 14. API 契约方向

推荐的新 API 资源：

- `POST /api/v1/certificate-intents`
- `GET /api/v1/certificate-intents/{id}`
- `PATCH /api/v1/certificate-intents/{id}`
- `POST /api/v1/certificate-intents/{id}:issue`
- `POST /api/v1/certificate-lineages/{id}:renew`
- `GET /api/v1/certificate-lineages/{id}/versions`
- `GET /api/v1/operations/{id}`
- `POST /api/v1/operations/{id}:cancel`
- `POST /api/v1/certificate-versions/{id}:deploy`
- `POST /api/v1/certificate-versions/{id}:revoke`

约束：

- 写请求必须支持 `Idempotency-Key`。
- 长流程统一返回 `202 Accepted + operation_id`。
- Operation 状态是稳定枚举，不以 Rust Debug 文本作为 API 值。
- 错误统一 RFC 7807，并包含稳定 `error_code`、`retryable` 和 `operation_id`。
- 默认 API 不返回私钥；只有显式授权的 managed-key export 才允许获取。
- OpenAPI 文件必须由实现测试持续校验。

---

## 15. 安全设计底线

- 不允许存在默认生产 API Key。
- DNS、CA EAB、Webhook、SMTP 等凭据不得以普通 Debug 输出。
- Secret 配置使用 SecretRef，不在领域对象中保存明文字符串。
- Account Key 和 Certificate Key 分离管理。
- 支持密钥轮换、最小权限和审计。
- 文件存储必须使用安全权限和原子写入。
- 私钥禁止进入普通事件、指标、Trace 和 ProblemDetails。
- 所有外部 URL 适配器必须有 SSRF 边界和允许列表策略。
- Webhook 和 Sink 必须有超时、签名、重试及重复投递处理。

---

## 16. 可观测性和 SLO

每个日志、Trace、Metric 和事件至少关联：

- `tenant_id`
- `intent_id`
- `lineage_id`
- `operation_id`
- `order_url_hash`
- `identifier_hash` 或脱敏 Identifier
- `ca_id`
- `challenge_type`
- `provider_id`/`sink_id`

建议指标：

- Operation 各步骤耗时和失败数。
- CA 请求延迟、状态码、badNonce、Retry-After。
- DNS 创建、传播和清理耗时。
- Challenge Lease 残留数量。
- 距证书过期的最小剩余时间。
- 续签成功率、重试次数和错过窗口数量。
- 各 Sink stage、activate、health、rollback 状态。
- Active 证书与存储/部署目标一致性。

建议首批 SLO：

- 不因进程重启重复创建 ACME Order。
- 所有已创建 Challenge Lease 最终进入 Cleaned 或显式告警状态。
- 所有 Active CertificateVersion 都有完整验证报告。
- 续签在目标窗口内成功率达到 99.9%，且在过期前保留至少一次人工处置窗口。
- 160 小时 IP 证书不能使用每日以下频率的调度检查。

---

## 17. 测试策略

### 17.1 单元测试

- Identifier 规范化和 Challenge Compatibility Matrix。
- Workflow 状态迁移和非法迁移拒绝。
- Retry 分类、Backoff、Jitter 和 Lease。
- DNS Zone/CNAME/NS 解析。
- Certificate Verification Report。
- Repository 并发更新和幂等。

### 17.2 契约测试

- 所有 CA Backend 通过统一测试套件。
- 所有 DNS Provider 通过 create/find/delete/idempotency 契约。
- 所有 Certificate Sink 通过 stage/activate/health/rollback 契约。
- File、Memory、Redis Repository 行为一致。

### 17.3 E2E

- 使用 Pebble 完成三类域名 Challenge。
- 使用支持 IP 的测试 CA/Pebble 配置完成 IPv4/IPv6。
- 使用 Let's Encrypt Staging 做受控冒烟。
- 进程在每个 Workflow Step 后退出并恢复。
- DNS 创建成功、传播失败、CA 失败时最终清理。
- 新证书持久化成功但 Sink 激活失败时不丢失版本。

### 17.4 故障注入

- 网络超时、DNS Provider 429、CA 429/5xx、badNonce。
- Redis 暂时不可用、并发 CAS 冲突。
- Agent 离线、Sink 部署失败、健康检查失败。
- Operation Cancel 与 Step 完成同时发生。
- 系统时间跳变和调度器重复扫描。

---

## 18. 兼容与迁移原则

- 保留当前 `AcmeClient` 作为低层兼容 API，但新能力通过 Application Service 提供。
- 为旧 `Vec<String>` 域名接口提供到强类型 Identifier 的显式转换，并标记后续弃用计划。
- 旧 CertificateBundle 导入为一个 CertificateLineage 和 CertificateVersion。
- 旧 FileStorage 数据迁移必须可重复运行、可校验、可回滚。
- 新 API 使用 `/api/v1`，现有 `/api` 在迁移期保持但不再扩展。
- 历史完成报告保留原样；只有当前状态文档和路线图反映真实实现状态。

---

## 19. 推荐交付顺序

1. 强类型领域模型和兼容矩阵。
2. Repository 数据模型、迁移和 KeyProvider 基础。
3. 持久化 Operation/Workflow Engine。
4. CA Backend 生产化和协议扩展。
5. Challenge Session、Lease 和补偿。
6. DNS Factory、Zone、Propagation。
7. HTTP/TLS Edge 和 RFC 8738 IP 支持。
8. Application Service 与 API/CLI 统一。
9. ARI 驱动的续签控制器。
10. Certificate Sink 和原子部署。
11. 安全、可观测性和多实例 Lease 强化。
12. 完整 E2E、故障注入和发布门槛。

详细依赖和每个独立任务的执行方案见：

- [v0.9.0 实施路线图](./roadmap/v0.9.0/README.md)

---

## 20. 完成定义

目标架构不能以“模块文件已经存在”作为完成标准。v0.9.0 核心闭环完成必须同时满足：

1. API、CLI 和 Scheduler 使用同一个 Application Service。
2. 签发和续签流程拥有持久化 Operation，并可在重启后恢复。
3. Challenge 外部资源拥有 Lease，并保证最终清理。
4. DNS-01 能正确发现 Zone、处理委派并验证传播。
5. 域名和 IP Identifier 使用强类型和明确兼容矩阵。
6. 证书保存为不可变版本，并通过 Sink 原子激活。
7. 续签支持 ARI、fallback、jitter、Lease 和部署回滚。
8. 私钥、账户密钥和 Provider 凭据具有明确 Key/Secret Provider 边界。
9. Pebble E2E、重启恢复和故障注入测试通过。
10. 文档、OpenAPI、配置示例和运行行为一致，不再返回演示性成功。

---

## 21. 外部规范与事实来源

- [RFC 8555: Automatic Certificate Management Environment](https://datatracker.ietf.org/doc/html/rfc8555)
- [RFC 8737: ACME TLS-ALPN-01 Challenge](https://datatracker.ietf.org/doc/html/rfc8737)
- [RFC 8738: ACME IP Identifier Validation Extension](https://datatracker.ietf.org/doc/html/rfc8738)
- [RFC 9773: ACME Renewal Information](https://datatracker.ietf.org/doc/html/rfc9773)
- [ACME Profiles Internet-Draft](https://datatracker.ietf.org/doc/html/draft-ietf-acme-profiles)
- [Let's Encrypt Challenge Types](https://letsencrypt.org/docs/challenge-types/)
- [Let's Encrypt 6-day and IP Address Certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability.html)
