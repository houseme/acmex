# T06：DNS Provider Factory、Zone 与传播确认

**任务性质**：DNS-01 生产闭环
**前置依赖**：T05；领域类型来自 T01
**主要后继**：T08、T09、T12
**建议改动范围**：`src/dns/`、`src/challenge/dns01.rs`、配置、Provider 契约测试

---

## 1. 背景与当前问题

仓库已经包含多个 DNS Provider，但配置中的 provider 名称没有统一 Factory，Provisioner 的 DNS-01 分支也没有注册真实 Dns01Solver。当前 Solver 通过构造参数绑定一个 domain，`verify()` 只检查 record ID 存在，不能证明 TXT 从权威 DNS 或 CA 视角可见。

域名到 Zone 的处理也分散在 Provider 内部，容易错误处理多级公共后缀、子 Zone、CNAME 或 `_acme-challenge` 委派。

本任务完成 DNS-01 从配置到写记录、传播确认和精确清理的生产闭环。

---

## 2. 目标

1. 建立 DNS Provider Factory 和版本化 Provider 配置。
2. 分离 ZoneResolver、RecordPresenter 和 PropagationObserver。
3. 使用 SOA 发现权威 Zone，支持 CNAME/NS 委派。
4. 支持权威 NS 与多个递归 Resolver 的传播 quorum。
5. 返回可持久化 DNS Record Locator 并精确删除。
6. 建立所有 Provider 可复用的契约测试。
7. 将现有 DNS Cache/hickory-resolver 作为观察层的一部分，而非成功真相。

---

## 3. 非目标

- 不新增更多 Provider，除非为契约测试需要 Fake Provider。
- 不在 AcmeX 内实现权威 DNS Server。
- 不支持 IP Identifier 的 DNS-01；必须在 Planner 层拒绝。
- 不把 Provider API 返回成功当作传播完成。

---

## 4. 目标接口

### 4.1 Provider Factory

```rust
#[async_trait]
pub trait DnsProviderFactory: Send + Sync {
    async fn create(
        &self,
        config: &DnsProviderSpec,
        secrets: &dyn SecretResolver,
    ) -> Result<Arc<dyn DnsRecordProvider>>;
}
```

`DnsProviderSpec` 至少包含：

- stable provider type。
- instance ID。
- credential SecretRef。
- 可选 zone selector/account/project/region。
- API endpoint override，仅允许显式安全配置。
- timeout、rate limit 和 provider-specific extra。

启动时验证 feature 是否启用；未启用返回明确配置错误，不能 fallback 到其他 Provider。

### 4.2 Record Provider

```rust
#[async_trait]
pub trait DnsRecordProvider: Send + Sync {
    async fn present_txt(&self, request: PresentTxt) -> Result<DnsRecordLocator>;
    async fn get_txt(&self, locator: &DnsRecordLocator) -> Result<Option<TxtRecord>>;
    async fn cleanup_txt(&self, locator: &DnsRecordLocator) -> Result<CleanupOutcome>;
}
```

Provider 不负责公共 DNS 传播判断。

### 4.3 Zone Resolver

```rust
pub trait ZoneResolver {
    async fn resolve(&self, fqdn: &DnsName) -> Result<ZoneResolution>;
}
```

输出包含 source name、最终 delegated name、zone apex、authoritative NS、CNAME/NS chain 和 TTL。

### 4.4 Propagation Observer

```rust
pub trait DnsPropagationObserver {
    async fn observe(&self, expected: &ExpectedTxt) -> Result<PropagationReport>;
}
```

报告必须记录查询目标、响应值 hash、TTL、错误和是否达到 quorum。

---

## 5. Zone 和委派算法

推荐步骤：

1. 生成 `_acme-challenge.<base-domain>`；Wildcard 去除 `*.` 后生成。
2. 查询目标名称的 CNAME；若存在，跟随到最终名称，限制最大深度并检测循环。
3. 检查 `_acme-challenge` 子域 NS 委派。
4. 从最终名称逐级向上查询 SOA，找到权威 Zone Apex。
5. 根据 zone selector 选择拥有该 Zone 的 Provider 实例。
6. 在 Provider API 中使用相对于 zone 的 record name，或由 Provider Adapter 明确转换。

禁止仅使用“最后两个标签”推断 Zone。

---

## 6. 传播策略

默认建议：

- 首先查询所有或配置比例的权威 NS。
- 再查询至少两个独立递归 Resolver。
- 所有查询使用无缓存或明确 cache policy；本地 cache 不得掩盖变化。
- 达到 `authoritative_quorum` 且 `recursive_quorum` 后视为 Propagated。
- 对 NXDOMAIN、NODATA、SERVFAIL、timeout 分别记录。
- 轮询间隔考虑 TTL、Provider hint 和指数退避，但受 deadline 限制。
- 观察值只记录 hash，避免 token 洩露到日志。

配置示例：

```toml
[challenge.dns01.propagation]
timeout_secs = 600
initial_interval_secs = 2
max_interval_secs = 30
authoritative_quorum = "all"
recursive_resolvers = ["1.1.1.1:53", "8.8.8.8:53"]
recursive_quorum = 1
```

---

## 7. 多 TXT 和精确清理

- 同一名称允许存在多个 TXT。
- `present_txt` 不得覆盖其他值，除非 Provider API 只能提交完整 RRSet；此时 Adapter 必须先读、合并、CAS/重试。
- `DnsRecordLocator` 保存 provider record ID 或 RRSet 中的 value hash。
- cleanup 只删除本任务值，并保留其他 TXT。
- cleanup 后可进行一次确认查询，但 AlreadyAbsent 视为幂等成功。

---

## 8. Provider 路由

支持多个 Provider 实例：

```toml
[[challenge.dns01.providers]]
id = "cloudflare-prod"
type = "cloudflare"
credential = "env://CF_DNS_TOKEN"
zones = ["example.com", "example.net"]

[[challenge.dns01.providers]]
id = "route53-main"
type = "route53"
credential = "aws-default://"
zone_suffixes = ["internal.example.org"]
```

路由优先级：

1. Intent 显式 Provider selector。
2. 精确 Zone ID/Apex 匹配。
3. 最长 suffix selector。
4. 唯一 default Provider。
5. 多个候选或无候选时返回配置错误，不随机选择。

---

## 9. Feature Gating

- Provider 模块本身应按 feature gate 编译，而不仅是 re-export。
- Factory 通过 `#[cfg]` 注册可用类型。
- `cargo check --no-default-features` 不应编译不需要的云 SDK。
- `dns-route53` 只引入 AWS 依赖；其他空 feature 应确认是否真的减小编译面。
- 文档列出的 feature 必须和 Factory 可创建的 Provider 一致。

---

## 10. 实施步骤

1. 定义 DnsProviderSpec、Factory、RecordProvider、Locator。
2. 将现有 Provider 逐个适配到新 trait。
3. 将明文凭据字段改为 SecretRef/构造期解析。
4. 实现基于 hickory-resolver 的 ZoneResolver。
5. 实现 CNAME/NS/SOA chain 和循环检测。
6. 实现权威 + 递归 PropagationObserver。
7. 实现 Provider Router 和配置校验。
8. 将 T05 DNS Presenter 接入 Factory/Zone/Observer。
9. 修复各 Provider 多 TXT 和精确 cleanup 行为。
10. 调整 feature gate、Cargo 和文档。

---

## 11. 测试要求：Provider 契约

每个 Provider Adapter 必须通过相同测试：

- create 返回稳定 locator。
- get 能定位刚创建记录。
- duplicate present 幂等或返回可识别 AlreadyExists。
- 同名多 TXT 不互相覆盖。
- cleanup 只删除自己的值。
- cleanup 重复调用成功。
- 401/403、404、409、429、5xx 分类。
- API timeout 和 Retry-After。
- 凭据不出现在 Debug/Error。

真实云测试默认 `#[ignore]`，通过环境变量和最小权限临时 Zone 运行；Mock/Fake 必须进入常规 CI。

---

## 12. Resolver 测试

- 普通 Zone。
- 深层子域和独立子 Zone。
- `_acme-challenge` CNAME 委派。
- NS 委派。
- CNAME 循环和最大深度。
- Authoritative NS 部分传播。
- Recursive resolver 分歧。
- 多段 TXT 合并。
- NXDOMAIN/NODATA/SERVFAIL/timeout。
- Cache 失效和 TTL。

命令：

```bash
cargo test dns
cargo test dns_provider_contract
cargo test dns_propagation
cargo check --all-features
cargo check --no-default-features
cargo fmt --all --check
git diff --check
```

---

## 13. 验收标准

- 配置中的 Provider 可以真正被 Factory 创建。
- 默认 DNS-01 配置缺失时启动或请求前明确失败。
- DNS-01 在 acknowledge CA 前完成传播观察。
- Zone 不通过简单后缀猜测。
- CNAME/NS 委派有测试。
- 多 TXT 不被误删。
- 所有 Provider 至少通过 Fake API 契约测试；真实测试边界明确。

---

## 14. 风险与回滚

- Provider API 的 RRSet 语义差异很大，必须在 Adapter 内消化。
- 公共 Resolver 可能被网络环境拦截，允许配置但不能静默跳过权威查询。
- 迁移阶段可保留旧 DnsProvider trait 适配器，但新 Workflow 只依赖新端口。
- DNS 清理不可通过“删除整个 RRSet”快速实现，除非已证明没有其他值。

---

## 15. 交付物

- DNS Factory、Router、配置 schema。
- 所有现有 Provider 的新 trait 适配。
- ZoneResolver 和委派解析。
- PropagationObserver 和报告。
- Provider 契约测试与可选真实测试说明。
- 更新后的 DNS Provider/feature 文档。
