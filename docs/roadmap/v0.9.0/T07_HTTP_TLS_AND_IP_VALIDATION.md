# T07：HTTP/TLS Edge 与 RFC 8738 IP 支持

**任务性质**：HTTP-01、TLS-ALPN-01 和 IP Identifier 完整实现
**前置依赖**：T01、T04、T05
**主要后继**：T08、T09、T12
**建议改动范围**：`src/challenge/http01.rs`、`src/challenge/tls_alpn01.rs`、新增 edge presenter、CSR/证书验证

---

## 1. 背景与当前问题

当前 HTTP-01 Solver 直接绑定中心进程的监听地址，并只保存一个 key authorization；TLS-ALPN-01 同样直接绑定 443。它们不适合已有 Nginx/Ingress/CDN、多个边缘节点或并行 token。

虽然存在 `Identifier::ip()`，高层流程仍把所有输入转换成 DNS；TLS 证书生成使用域名 SAN，没有 RFC 8738 所需的单个 `iPAddress` SAN 和反向 SNI。证书匹配函数也只检查 DNSName。

本任务同时完成本地 Presenter、可插拔 Edge Presenter 和 IPv4/IPv6 规范行为。

---

## 2. 目标

1. HTTP Presenter 支持并发多 token、独立 Lease 和外部可达观察。
2. TLS Presenter 支持并发路由、正确 ALPN 扩展和独立 Lease。
3. 定义 EdgeAgent 端口，以适配 Ingress、Proxy、LB 或远端 Agent。
4. 完成 RFC 8738 的 IP Identifier 行为。
5. CSR 和最终证书验证支持 DNSName 与 iPAddress SAN。
6. 建立 IPv4、IPv6、Wildcard 和混合 Identifier 的明确策略。

---

## 3. 非目标

- 不实现 DNS-01。
- 不在本任务交付所有云负载均衡 Edge Adapter；至少提供本地和 Fake/HTTP Agent Adapter。
- 不保证所有公共 CA 支持混合 DNS+IP Order；由 CaCapabilities/Planner 决定拆单或拒绝。

---

## 4. HTTP-01 Presenter

### 4.1 本地实现

- 一个共享 Listener 服务多个 token。
- Map key 使用完整 token，不使用 `contains()`。
- 路径严格为 `/.well-known/acme-challenge/{token}`。
- 返回精确 key authorization 和正确 Content-Type。
- Lease cleanup 只删除当前 token；没有 token 时 Listener 可以按 idle policy 关闭。
- 绑定 80 失败返回明确 OperatorActionRequired。

### 4.2 观察

Domain Identifier：

- 请求 `http://<domain>/.well-known/acme-challenge/<token>`。
- 可配置是否验证多个 A/AAAA 地址或 Edge Agent 状态。

IP Identifier：

- 跳过 DNS 解析，直接访问 Identifier IP。
- IPv6 URL 使用 `[addr]`。
- Host header 按 RFC 8738 使用 IP 文本形式。
- 不自动跟随到不受策略允许的外部地址。

### 4.3 Edge Adapter

```rust
pub trait HttpChallengeEdge {
    async fn install(&self, route: HttpChallengeRoute) -> Result<EdgeRouteLease>;
    async fn inspect(&self, lease: &EdgeRouteLease) -> Result<EdgeRouteState>;
    async fn remove(&self, lease: &EdgeRouteLease) -> Result<CleanupOutcome>;
}
```

Agent API 必须支持 idempotency key、TTL、认证和多副本状态。

---

## 5. TLS-ALPN-01 Presenter

### 5.1 Domain

- ALPN 仅包含或优先协商 `acme-tls/1`。
- validation certificate SAN 为目标 dNSName。
- `id-pe-acmeIdentifier` 扩展内容是 key authorization SHA-256 digest 的 DER OCTET STRING，并按 RFC 标记 critical。
- SNI 精确路由到 challenge certificate。

### 5.2 IP

RFC 8738 要求：

- SAN 必须只有一个与 Identifier 相同的 iPAddress。
- SNI 不能直接是 IP。
- IPv4 使用 `IN-ADDR.ARPA` 反向名称。
- IPv6 使用 nibble-reversed `IP6.ARPA` 名称。

必须提供纯函数：

```rust
fn ip_validation_sni(ip: IpAddr) -> DnsName;
fn build_tls_alpn_validation_cert(
    identifier: &Identifier,
    key_authorization: &SecretString,
) -> Result<ValidationCertificate>;
```

### 5.3 Edge Adapter

- 支持已有 TLS 终止层动态安装证书。
- Route Lease 包含 edge ID、SNI、certificate fingerprint、TTL。
- 多节点环境需要配置 required quorum 或 all-nodes。
- cleanup 只删除该 Lease 的 route/version。

---

## 6. CSR 与证书验收

CSR Builder 必须基于强类型 Identifier：

- DNS -> `dNSName`。
- IP -> `iPAddress`。
- 不把 IP 字符串写成 dNSName。
- Identifier 集合和最终证书 SAN 必须精确匹配；不允许只检查包含关系而忽略额外 SAN，除非 Policy 明确允许。

Certificate Verification Report 至少包含：

- SAN DNS/IP 集合比较。
- notBefore/notAfter。
- public key 与 CSR key 一致。
- chain/signature/trust 结果。
- profile/validity policy。
- Identifier 类型与 CA capability。

---

## 7. CA/Profile 策略

- IP Order 创建前查询 CaCapabilities。
- 对 Let's Encrypt IP 证书，支持短周期 profile/policy；不得假定其他 CA 也使用相同名称。
- CA 不支持 IP 时返回 PolicyViolation，不退化为 DNS。
- 公网/私网/保留地址检查由 CaPolicy 决定：公共 CA 默认拒绝私网和保留地址，私有 CA 可允许。
- 若混合 DNS+IP 不被 CA/profile 支持，Planner 应明确拆分 Lineage/Order 或拒绝；不可静默丢弃 Identifier。

---

## 8. 实施步骤

1. 重写 HTTP 本地 Presenter 为共享 token registry。
2. 实现 HTTP Edge trait、Fake Agent 和可选 HTTP Agent client。
3. 重写 TLS certificate builder，确保 critical extension 和类型化 SAN。
4. 实现 domain/IP SNI 路由和反向名称算法。
5. 实现 TLS Edge trait 和本地 Listener 多 route 支持。
6. 将 T05 Presenter 接入 HTTP/TLS Adapter。
7. 修改 CSR Generator 接收强类型 Identifier。
8. 修改证书验证支持 DNS/IP 精确 SAN。
9. 接入 T04 CaCapabilities/Profile。
10. 更新配置、CLI 输入和示例。

---

## 9. 测试要求

### 纯函数和证书测试

- IPv4 reverse SNI golden vectors。
- IPv6 reverse SNI golden vectors。
- TLS validation cert 的 SAN 类型、数量、ALPN extension OID、critical 和 digest。
- CSR 的 DNS/IP SAN DER。
- 最终证书额外/缺失/错误类型 SAN 拒绝。

### HTTP 测试

- 两个并发 token 均返回精确值。
- 删除一个 token 不影响另一个。
- IP Host header 和 IPv6 URL。
- 错误 token 返回 404。
- 重启后通过 Agent Lease 恢复/清理。

### TLS 测试

- Domain SNI 成功。
- IPv4/IPv6 reverse SNI 成功。
- 错误 ALPN/SNI 不返回 challenge cert。
- 多 route 并行和独立 cleanup。

命令：

```bash
cargo test http01
cargo test tls_alpn01
cargo test ip_identifier
cargo test csr
cargo test certificate_verification
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 10. 验收标准

- HTTP/TLS Presenter 不再把单个 challenge 状态放在全局可变 Solver 中。
- HTTP 多 token 和 TLS 多 route 可并发。
- IPv4/IPv6 行为符合 RFC 8738。
- IP 不会进入 DNS-01 或 DNS 预解析路径。
- CSR 和最终证书使用正确 SAN 类型。
- 中央服务无需强制占用 80/443，允许 Edge Agent 模式。

---

## 11. 风险与回滚

- TLS 扩展 DER/critical 标记错误会导致 CA 验证失败，必须有 DER 级测试和 Pebble E2E。
- 本地 80/443 仅作为单机模式；生产文档优先 Edge Adapter。
- 不应通过 `rustls` 默认 SNI 假设处理 IP，必须显式 route。
- 如外部 Agent 尚未部署，可使用本地 Presenter，但领域接口不能回退。

---

## 12. 交付物

- 并发 HTTP Presenter。
- TLS domain/IP validation certificate builder。
- Edge Agent 端口、Fake 和至少一个可运行 Adapter。
- RFC 8738 Planner/CSR/验证实现。
- 完整纯函数、Listener、证书和恢复测试。
- IP 证书配置和使用说明。

