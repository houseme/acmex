# T01 迁移记录:强类型 Identifier 调用点

**状态**:已实现(v0.9.0 T01)
**涉及提交**:T01 Domain Model PR

---

## 1. 变更摘要

`Identifier` 从公开字符串字段结构:

```rust
// 旧(0.8 及之前)
pub struct Identifier {
    pub id_type: String, // "dns" | "ip"
    pub value: String,
}
```

迁移为强类型枚举(`src/domain/identifiers.rs`):

```rust
pub enum Identifier {
    Dns(DnsIdentifier),  // 规范化小写 ASCII/IDNA,无尾点;wildcard 为显式属性
    Ip(std::net::IpAddr),
}
```

- ACME JSON 兼容性保持:`{"type":"dns"|"ip","value":"..."}` 序列化/反序列化不变,并有 round-trip 测试。
- 旧的 `Identifier::dns()` / `Identifier::ip()` 保留并标记 `#[deprecated]`(0.9.0 起),提供 panic-free 迁移路径 `try_dns()` / `try_ip()` / `parse()`。
- `ChallengeType` 增加稳定 serde(wire 字符串)与 `Ord`。

## 2. 已迁移到强类型的调用点

| 位置 | 说明 |
|---|---|
| `src/order/objects.rs` | `NewOrderRequest::new(Vec<String>)` 保留为 DNS-only 兼容入口(内部 lenient 归一化);新增 `from_identifiers()`(强类型)与 `parse_names()`(自动识别 IP,校验失败返回错误) |
| `src/client.rs` | `create_order()` / `issue_certificate()` 保留为 DNS-only 兼容入口;新增 `create_order_for_identifiers()`、`issue_identifiers()`;签发流程的 challenge 选择改用兼容矩阵 `compatible_challenges()` |
| `src/challenge/tls_alpn01.rs` | `identifier.value` 字段访问改为 `identifier.acme_value()` |
| `src/challenge/http01.rs` / `dns01.rs` 测试 | 改用 `Identifier::try_dns()` |
| `src/types.rs` | `Identifier` 变为 `crate::domain::identifiers::Identifier` 的 re-export,旧 JSON 形状可继续反序列化 |

## 3. 仍使用 DNS-only 兼容入口的位置(后续任务迁移)

| 位置 | 当前行为 | 迁移计划 |
|---|---|---|
| `AcmeClient::issue_certificate(Vec<String>, _)` | 所有输入按 DNS 处理 | T08 Application Service 统一后转为 facade |
| `NewOrderRequest::new(Vec<String>)` | 同上,lenient 归一化 | 保留整个 0.9.x;0.10 评估 deprecate |
| `CsrGenerator::new(Vec<String>)`(T07 扩展) | CSR SAN 只生成 dNSName | T07 基于 `Identifier` 生成 dNSName/iPAddress |
| `verify_certificate_domains`(order 模块) | 仅比较 DNSName 集合 | T07 扩展为 DNS/IP 精确匹配 |
| `CertificateProvisioner` / orchestrator | 域名字符串驱动 | T03/T05/T08 接入 Workflow 后替换 |

## 4. 新增领域模块

```text
src/domain/
├── identifiers.rs   # Identifier/DnsIdentifier/IdentifierSet/IdentifierError
├── ids.rs           # IntentId/TenantId/LineageId/VersionId/OperationId/KeyId/TargetId
├── intent.rs        # CertificateIntent + 校验不变量
├── policy.rs        # CaPolicy/ValidationPolicy/KeyPolicy/RenewalPolicy/DeliveryTarget + 兼容矩阵
├── certificate.rs   # CertificateLineage/CertificateVersion/KeyRef/VersionState
├── operation.rs     # OperationKind/OperationSubject/OperationRef(T03 扩展)
└── mod.rs
```

兼容矩阵(`compatible_challenges` / `validate_order_policy`)在创建任何 ACME Order 之前拒绝非法组合:

| Identifier | HTTP-01 | DNS-01 | TLS-ALPN-01 |
|---|---:|---:|---:|
| 普通 DNS | ✓ | ✓ | ✓ |
| Wildcard DNS | ✗ | ✓ | ✗ |
| IPv4 / IPv6 | ✓ | ✗ | ✓ |

## 5. 验证命令

```bash
cargo test domain
cargo test order::objects
cargo test --test order_test
cargo check --all-features
cargo fmt --all --check
git diff --check
```

全部通过;完整 `cargo test` 116 个单元/集成测试通过(基线为 71+4+1)。
