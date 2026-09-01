# T10：KeyProvider 与 Certificate Sink

**任务性质**：密钥边界和下游交付
**前置依赖**：T01、T02、T08；续签激活与 T09 对接
**主要后继**：T11、T12
**建议改动范围**：新增 `src/key/`、`src/delivery/`，调整 CSR、CertificateVersion、CLI/API

---

## 1. 背景与当前问题

当前 CSR Generator 在进程内生成私钥并返回 PEM；CertificateBundle 将证书和私钥一起序列化。签发后可以直接写两个文件，但没有版本化、权限、原子切换、健康检查和回滚。

对于 Kubernetes、Vault、云负载均衡器或外部 KMS，AcmeX 需要支持：

- 不持有私钥的 External CSR 模式。
- 只保存 KeyRef 的 Managed Key 模式。
- 多个下游目标的 stage/activate/health/rollback。
- 证书签发和部署解耦。

---

## 2. 目标

1. 定义 KeyProvider，支持 Managed Key 和 External CSR/Signer。
2. CertificateVersion 只引用 KeyRef，不默认包含私钥。
3. 定义 CertificateSink 生命周期。
4. 实现 File Sink 和至少一个远端/平台 Sink。
5. 支持不可变版本、原子激活、健康检查和回滚。
6. 通过 Outbox/Deployment Operation 解耦签发与下游交付。

---

## 3. 非目标

- 不实现所有云厂商证书服务。
- 不允许任意 shell 命令作为默认 Sink。
- 不在普通 API 返回私钥。
- 不把 KMS 私钥导出作为必须能力。

---

## 4. KeyProvider

```rust
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn create_key(&self, request: CreateKey) -> Result<KeyRef>;
    async fn create_csr(&self, request: CreateCsr) -> Result<CsrArtifact>;
    async fn public_key(&self, key: &KeyRef) -> Result<PublicKeyInfo>;
    async fn export(&self, key: &KeyRef, authz: ExportAuthorization)
        -> Result<Option<SecretBytes>>;
    async fn destroy(&self, key: &KeyRef) -> Result<DestroyOutcome>;
}
```

### Managed Key

首版至少提供：

- SoftwareKeyProvider：生成 key，写入加密 Secret Store。
- 算法策略：P-256/其他已支持算法，默认安全值。
- KeyRef 包含 provider、key ID、algorithm、exportability。

后续或同任务可提供：

- Vault Transit/PKI。
- 云 KMS。
- PKCS#11/HSM。

### External CSR

- 上游提交 CSR 和证明过的 key reference。
- AcmeX 验证 CSR 签名、SAN 和 Intent 精确匹配。
- AcmeX 不保存或返回私钥。
- 续签时需要上游重新提供 CSR，或调用 External Signer Adapter。

---

## 5. Key Policy

至少支持：

- algorithm。
- managed/external。
- exportable true/false。
- renewal 时 reuse/rotate/periodic rotate。
- provider selector。
- secret retention 和 destroy policy。

规则：

- Account Key 与 Certificate Key 必须是不同用途和不同 KeyRef。
- key 创建成功、Order 失败时是否保留由 policy 决定。
- active/superseded Version 仍引用 key 时不得销毁。
- export 操作必须独立审计和授权。

---

## 6. Certificate Sink

```rust
#[async_trait]
pub trait CertificateSink: Send + Sync {
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment>;

    async fn activate(&self, staged: &StagedDeployment) -> Result<()>;
    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth>;
    async fn rollback(&self, staged: &StagedDeployment) -> Result<()>;
    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome>;
}
```

`CertificateMaterialRef` 只在调用期间提供所需 material；Sink 不应把私钥写入日志或普通状态实体。

---

## 7. Deployment 状态

```text
Pending
→ Staging
→ Staged
→ Activating
→ Active
→ Healthy

失败 → Failed
Active 后失败 → RollingBack → RolledBack/RollbackFailed
旧版本 → CleanupPending → Cleaned
```

每个 target 独立 Deployment。Intent 可声明：

- `required`：全部健康后才能切换 Lineage active version。
- `quorum`：达到指定数量即可。
- `best_effort`：不阻止证书 Active，但产生告警。

---

## 8. File Sink

推荐布局：

```text
<target>/
├── versions/<version-id>/fullchain.pem
├── versions/<version-id>/cert.pem
├── versions/<version-id>/key.pem
├── versions/<version-id>/metadata.json
└── current -> versions/<version-id>
```

要求：

- stage 写新目录，不覆盖 current。
- 文件权限符合证书/私钥要求。
- fsync 后原子切换 symlink 或平台等价 pointer。
- health check 重新读取 current、解析证书并匹配 version fingerprint。
- rollback 原子恢复旧 pointer。
- Windows/不支持 symlink 平台有替代实现和文档。

---

## 9. 第二个 Sink

至少选择一个：

- Kubernetes Secret。
- Vault KV。
- Nginx/HAProxy Agent。

推荐 Kubernetes Secret，契约：

- stage 写版本化 Secret 或 annotations。
- activate 更新目标 Secret/引用。
- 使用 resourceVersion 防止覆盖并发修改。
- health 读取 Secret fingerprint。
- rollback 恢复旧 resourceVersion/content。

如果当前环境不适合引入 Kubernetes 依赖，可以先实现 HTTP Sink Agent，但必须提供 Fake Server 契约测试。

---

## 10. 证书格式

Sink 可请求明确格式：

- PEM leaf/fullchain/key。
- PKCS#12。
- JKS 作为后续可选。

格式转换应由 `CertificateMaterialBuilder` 完成，不复制到每个 Sink。输出必须验证可解析、证书与 key 匹配。

---

## 11. 实施步骤

1. 定义 KeyRef、KeyPolicy、KeyProvider、SecretBytes。
2. 实现 SoftwareKeyProvider 和加密 Secret Store。
3. 修改 CSR 和 CertificateVersion 使用 KeyRef。
4. 实现 External CSR 校验路径。
5. 定义 Sink、DeploymentSpec、DeploymentState、MaterialBuilder。
6. 实现 File Sink 原子版本切换。
7. 实现第二个 Sink 或 HTTP Agent Adapter。
8. 将 Deployment 表达为 T03 子 Operation。
9. 与 T09 active version CAS 对接。
10. 增加受限 export API/CLI 或明确首版禁用。

---

## 12. 测试要求

### Key

- managed key 创建、CSR、public key。
- external CSR 签名和 SAN 验证。
- certificate 与 key 匹配。
- non-exportable key 不能 export。
- key rotation/reuse policy。
- Secret 不进入 Debug/Error。

### Sink 契约

- stage 幂等。
- activate 原子。
- health fingerprint。
- activate 失败 rollback。
- 重复 rollback/cleanup。
- 并发 deployment CAS。
- required/quorum/best-effort 聚合。

### File Sink

- stage 期间 current 不变化。
- 激活后读取的是完整新版本，不存在半写状态。
- 模拟进程在写入/rename 前后退出。
- 权限检查。

命令：

```bash
cargo test key_provider
cargo test external_csr
cargo test certificate_sink_contract
cargo test file_sink
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 13. 验收标准

- CertificateVersion 不包含明文私钥字段。
- Managed 和 External CSR 至少各有一个可运行流程。
- File Sink 完成 stage/activate/health/rollback。
- 至少一个非文件 Sink/Agent 通过契约测试。
- 部署失败不会丢失新 Version，也不会覆盖健康旧版本。
- active version 只在 required 部署策略满足后切换。

---

## 14. 风险与回滚

- 私钥迁移是高风险操作，旧 Bundle 只读兼容期必须保留。
- 不允许在回滚时把 Secret 重新写回普通 JSON。
- File symlink 行为需跨平台处理。
- 远端 Sink API 可能最终一致，health check 必须有 timeout 和重试。

---

## 15. 交付物

- KeyProvider/KeyRef/KeyPolicy。
- Software Managed Key 和 External CSR。
- CertificateSink 和 Deployment 工作流。
- File Sink、第二个 Sink/Agent。
- Material Builder 和格式验证。
- 密钥迁移、安全和运维文档。

