# T01：强类型领域模型与策略规划

**任务性质**：基础架构，必须优先完成
**前置依赖**：无
**主要后继**：T02-T10
**建议改动范围**：`src/domain/`、`src/types.rs`、`src/order/objects.rs`、`src/client.rs`、测试和文档

---

## 1. 背景与当前问题

当前 `Identifier` 使用两个公开 `String` 字段表示类型和值。虽然提供了 `Identifier::dns()` 和 `Identifier::ip()`，高层 `AcmeClient` 仍将所有字符串转换成 DNS Identifier。CSR、证书匹配、Challenge 选择和预检也以域名字符串为核心。

结果是：

- 编译期无法阻止对 IP 使用 DNS-01。
- 无法区分普通域名、Wildcard、IPv4、IPv6。
- IPv6 文本规范化、URL 方括号和 TLS 反向 SNI 容易散落在业务代码中。
- 上游请求、ACME Order 和逻辑证书缺少不同生命周期的模型。
- 续签仍以 `Vec<String>` 作为逻辑证书身份，不能表达策略和版本。

本任务只建立稳定的领域语言和策略规划，不实现持久化工作流、DNS API 或真实 IP 签发。

---

## 2. 目标

1. 建立强类型 `Identifier`、`DnsName`、Wildcard 和 IP 表达。
2. 建立 `CertificateIntent`、`CertificateLineage`、`CertificateVersion` 的核心数据结构。
3. 建立 CA、Validation、Key、Renewal、Delivery Policy。
4. 实现 Challenge Compatibility Matrix，在创建 ACME Order 前拒绝非法组合。
5. 保持 ACME JSON 序列化兼容。
6. 为当前 `Vec<String>` API 提供明确兼容转换和弃用路径。

---

## 3. 非目标

- 不创建数据库表。
- 不修改真实 DNS Provider。
- 不实现 RFC 8738 的 HTTP/TLS 网络行为。
- 不重写整个 `AcmeClient`。
- 不在本任务删除旧公共 API。

---

## 4. 目标目录

建议新增：

```text
src/domain/
├── mod.rs
├── identifiers.rs
├── intent.rs
├── certificate.rs
├── operation.rs
└── policy.rs
```

如果维护者决定暂不新增目录，也必须保持相同的领域边界，不能继续把所有公共类型堆入 `src/types.rs`。

---

## 5. 目标类型

### 5.1 Identifier

```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Identifier {
    Dns(DnsIdentifier),
    Ip(std::net::IpAddr),
}

pub struct DnsIdentifier {
    ascii_name: String,
    wildcard: bool,
}
```

要求：

- `DnsIdentifier::parse()` 验证空值、非法标签、Wildcard 位置和长度。
- 输入统一去除末尾根点并转换为小写 ASCII/IDNA 形式。
- `*.example.com` 只允许最左侧一个 `*.`。
- `IpAddr` 使用标准库解析；序列化输出规范化地址。
- 不允许通过公开字段构造非法 Identifier。
- ACME JSON 仍输出 `{ "type": "dns|ip", "value": "..." }`。

### 5.2 Intent 和策略

至少定义：

```rust
pub struct CertificateIntent {
    pub id: IntentId,
    pub tenant_id: TenantId,
    pub identifiers: NonEmptyIdentifiers,
    pub ca_policy: CaPolicy,
    pub validation_policy: ValidationPolicy,
    pub key_policy: KeyPolicy,
    pub renewal_policy: RenewalPolicy,
    pub delivery_targets: Vec<DeliveryTarget>,
    pub idempotency_key: String,
    pub generation: u64,
}
```

策略最低字段：

- `CaPolicy`：固定 CA、允许 CA 集合、环境、profile、是否允许 fallback。
- `ValidationPolicy`：允许的 Challenge、Provider/Agent selector、传播 quorum、timeout。
- `KeyPolicy`：算法、managed/external、轮换策略、是否可导出。
- `RenewalPolicy`：ARI 优先、fallback 百分比、固定窗口兼容值、最小安全余量。
- `DeliveryTarget`：类型、目标引用、required/best-effort。

### 5.3 Lineage 和 Version

本任务只定义类型和不变量：

- Lineage 由 Intent 和规范化 Identifier 集合唯一关联。
- Version 不可变。
- Active Version 只能通过 Repository/Application Service 切换。
- 私钥使用 `KeyRef`，不直接放进通用领域结构。

---

## 6. Compatibility Matrix

新增纯函数：

```rust
pub fn compatible_challenges(identifier: &Identifier) -> ChallengeSet;
pub fn validate_order_policy(
    identifiers: &[Identifier],
    offered: ChallengeSet,
    policy: &ValidationPolicy,
) -> Result<ValidationPlan>;
```

最低规则：

| Identifier | HTTP-01 | DNS-01 | TLS-ALPN-01 |
|---|---:|---:|---:|
| 普通 DNS | 是 | 是 | 是 |
| Wildcard DNS | 否 | 是 | 否 |
| IPv4 | 是 | 否 | 是 |
| IPv6 | 是 | 否 | 是 |

Planner 必须对每个 Authorization 生成独立 `ValidationPlanItem`，不能只选择一个全局 Solver。

---

## 7. 兼容策略

- 保留旧 `Identifier::dns()`、`Identifier::ip()`，内部调用新 parse 并返回 `Result`；若当前签名无法兼容，新增 `try_dns/try_ip`，旧方法标记 deprecated 并明确 panic-free 迁移方案。
- 保留 `AcmeClient::issue_certificate(Vec<String>, ...)`，将其视为 DNS-only 兼容入口。
- 新增强类型入口，例如 `issue_identifiers(Vec<Identifier>, ...)`，但暂不要求在本任务完成真实网络流程。
- `NewOrderRequest::new(Vec<String>)` 保持兼容，同时新增 `from_identifiers()`。

不得静默把可解析 IP 字符串当作 DNS。如果旧接口保持 DNS-only，文档必须明确这一点。

---

## 8. 实施步骤

1. 盘点 `Identifier`、`domains: Vec<String>`、`Identifier::dns` 的所有生产和测试调用点。
2. 新增领域模块和 ID newtype。
3. 实现 DNS/IP 解析、规范化、Display、Serde。
4. 实现非空、去重和稳定排序的 Identifier 集合。
5. 定义 Intent、Policy、Lineage、Version、KeyRef。
6. 实现 Compatibility Matrix 和 ValidationPlan。
7. 为旧类型提供转换层。
8. 修改 Order 对象使用新的序列化实现，但不改变 RFC 8555 JSON。
9. 更新 Prelude，只导出真正需要稳定公开的类型。
10. 更新 README 示例和 API 文档，明确 DNS-only 兼容入口。

---

## 9. 测试要求

### 单元测试

- 普通域名大小写和末尾点规范化。
- IDN 的 ASCII 序列化。
- 合法和非法 Wildcard。
- IPv4、压缩/非压缩 IPv6 解析与标准化。
- DNS/IP ACME JSON round-trip。
- 重复 Identifier 去重和稳定 hash。
- 四类 Identifier 的 Compatibility Matrix。
- Wildcard + HTTP-only、IP + DNS-only 等非法策略拒绝。

### 兼容测试

- 当前测试中的 DNS Order JSON 不变化。
- 旧 `Vec<String>` 入口仍可编译。
- 新类型增加字段时使用显式 schema version 或 serde default。

### 命令

```bash
cargo test domain
cargo test order::objects
cargo test types
cargo test --test order_test
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 10. 验收标准

- 核心业务代码不再读取公开 `id_type: String` 判断类型。
- IP 和 DNS 不能在核心层被无意混用。
- 非法 Challenge 组合在任何外部副作用前失败。
- 所有 ACME Identifier JSON 与标准兼容。
- 旧 DNS-only API 有测试和迁移说明。
- 后续任务可以只依赖领域类型，不需要依赖 Axum 或具体 Provider。

---

## 11. 风险与回滚

- 最大风险是公共 API 破坏。必须通过兼容 wrapper 和 deprecation 分阶段迁移。
- IDNA 依赖选择不得隐式改变现有域名行为；加入显式测试。
- 若一次性迁移所有调用点过大，可先让旧 `types::Identifier` 成为新类型的 re-export/兼容包装，但不能同时保留两套含义不同的 Identifier。

---

## 12. 交付物

- 新领域模型代码。
- Compatibility Matrix。
- 旧 API 兼容层。
- 单元和序列化兼容测试。
- 更新后的公共 API 文档和示例。
- 一份调用点迁移记录，列明仍使用 DNS-only 兼容入口的位置。

