# T02：Repository、数据模型与迁移

**任务性质**：持久化基础
**前置依赖**：T01 领域模型
**主要后继**：T03、T08-T11
**建议改动范围**：`src/storage/`、新增 `src/repository/`、迁移工具、测试

---

## 1. 背景与当前问题

当前 `StorageBackend` 只提供 store/load/delete/list KV 接口，`CertificateStore` 用排序域名拼接 key 并把包含私钥的 CertificateBundle 整体序列化。Operation、Order、Challenge Lease、CertificateVersion 和 Deployment 没有持久化模型。

FileStorage 还有 key/list 不对称：存储自动追加 `.bin`，list 返回文件名，再次 load 时可能重复追加后缀。API Task 则仅保存在内存 HashMap 中。

本任务需要建立领域 Repository，而不是继续让上层直接拼字符串 key。

---

## 2. 目标

1. 定义稳定 Repository trait 和持久化实体。
2. 支持 Intent、Lineage、Version、Operation、Workflow Step、Challenge Lease、Deployment、Account、Outbox。
3. 提供 Memory 和 File 的完整实现；Redis 实现可以在相同任务或紧随其后完成，但接口必须一次稳定。
4. 提供 CAS/乐观锁和 Lease 所需原语。
5. 修复 FileStorage key/list 行为。
6. 提供旧 CertificateBundle 和旧文件数据迁移工具。

---

## 3. 非目标

- 不实现 Workflow 执行器。
- 不实现续签策略。
- 不在本任务实现 Vault/KMS。
- 不把 Repository 设计成任意 SQL ORM 抽象。

---

## 4. Repository 设计

建议定义聚合级接口，而不是把 KV 暴露给业务层：

```rust
#[async_trait]
pub trait IntentRepository: Send + Sync {
    async fn create(&self, intent: &CertificateIntent) -> Result<CreateOutcome>;
    async fn get(&self, id: IntentId) -> Result<Option<Versioned<CertificateIntent>>>;
    async fn compare_and_set(
        &self,
        expected_revision: Revision,
        intent: &CertificateIntent,
    ) -> Result<CasOutcome>;
}
```

同类接口至少包括：

- `CertificateRepository`
- `OperationRepository`
- `ChallengeLeaseRepository`
- `AccountRepository`
- `DeploymentRepository`
- `OutboxRepository`

可以由一个 `RepositorySet` 聚合，Application Service 不应依赖具体 File/Redis 类型。

---

## 5. 数据不变量

- 所有实体包含 `schema_version`、`created_at`、`updated_at`、`revision`。
- ID 使用不可猜测 newtype，序列化为稳定字符串。
- CertificateVersion 不可覆盖。
- Lineage 的 active version 使用 CAS 切换。
- Operation 的 Step 只能按合法状态迁移。
- ChallengeLease 的 cleanup 状态独立于签发 Operation 终态。
- Outbox 事件和领域状态更新在同一 Repository transaction 或等效原子操作中完成。
- 私钥只保存 `KeyRef`；旧 Bundle 迁移时使用受控 Secret Storage 兼容区。

---

## 6. File Repository 设计

建议目录：

```text
<base>/
├── intents/<id>.json
├── lineages/<id>.json
├── versions/<id>.json
├── operations/<id>.json
├── challenge-leases/<id>.json
├── deployments/<id>.json
├── accounts/<id>.json
├── outbox/<sequence>.json
├── secrets/<key-ref>.enc
└── locks/
```

要求：

- 临时文件写入、fsync、原子 rename。
- Unix 权限至少保证 Secret 不对 group/other 可读；跨平台行为需文档说明。
- ID 必须严格编码，不能通过 `/` 或 `..` 逃逸目录。
- list 返回领域 ID，而不是带后缀文件名。
- 写入前后检查 revision，避免 lost update。
- 损坏 JSON 返回明确 CorruptData，不静默忽略。

---

## 7. Redis Repository 设计

如果本任务包含 Redis：

- key 使用版本化命名空间，例如 `acmex:v1:operation:<id>`。
- 使用 Lua 或 WATCH/MULTI 实现 CAS。
- Lease 使用 owner、expires_at 和 fencing token，不能只用 SETNX 不续约。
- 列表使用索引 Set/Sorted Set，不能依赖生产环境 `KEYS`。
- Outbox 使用有序 Stream 或显式 sequence。
- Redis 暂时不可用不得让业务误判为资源不存在。

---

## 8. 迁移方案

### 8.1 旧 CertificateBundle

迁移工具必须：

1. 枚举旧 `cert:*` 数据。
2. 修复/兼容 `.bin` 后缀问题。
3. 解析证书链和 SAN。
4. 创建 Lineage 与 Version。
5. 将私钥放入兼容 Secret Store，生成 KeyRef。
6. 校验写入后数据。
7. 记录迁移 manifest，不删除原始文件。

### 8.2 重复运行

- 同一源记录重复迁移返回 AlreadyMigrated。
- 使用源内容 hash 和目标 ID 保证幂等。
- 支持 dry-run 和 verify-only。
- 删除旧数据必须是未来单独、显式授权的操作，不属于本任务默认行为。

---

## 9. 实施步骤

1. 基于 T01 类型定义持久化 schema。
2. 定义 Revision、Versioned、CAS、Lease、Outbox 类型。
3. 定义聚合 Repository trait。
4. 实现 MemoryRepository，作为契约测试参考实现。
5. 修复底层 FileStorage key 编解码，或以新 FileRepository 替代业务直接使用。
6. 实现 FileRepository 原子写、CAS、list 和损坏检测。
7. 实现旧 Bundle migrator 和 manifest。
8. 让旧 `CertificateStore` 通过兼容适配器工作，标记后续迁移。
9. 如范围允许，实现 RedisRepository；否则建立完整测试桩和后续 issue。
10. 更新配置 schema，明确 backend、path、namespace、migration 模式。

---

## 10. 测试要求

建立可对所有后端复用的 `repository_contract` 测试：

- create/get/list/delete 或 archive。
- duplicate create。
- CAS success/conflict。
- 并发 active version 切换只能一个成功。
- Lease acquire/renew/release/expire/fencing。
- Outbox 顺序和重复投递。
- File key 包含冒号、逗号、Unicode 时安全。
- 损坏文件明确报错。
- 进程中断前临时文件不会被当成有效实体。
- 旧 `.bin` 数据迁移一次和重复迁移。

命令：

```bash
cargo test repository_contract
cargo test storage
cargo test migration
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 11. 验收标准

- 业务层不再拼 `cert:<domains>` 等字符串 key。
- File list 后返回的 ID 可以直接 get。
- Lineage active version 切换具备并发保护。
- Operation 和 ChallengeLease 可以持久化。
- 旧 Bundle 可 dry-run、迁移、验证和重复运行。
- 所有后端通过相同契约测试。
- Repository 错误不会被静默当成 NotFound。

---

## 12. 风险与回滚

- 数据 schema 必须包含版本；新增字段需要 serde default 或迁移函数。
- File 原子性在不同文件系统上不同，文档明确同目录 rename 要求。
- 不直接删除旧文件；回滚时仍可使用旧 CertificateStore。
- Redis Lease 必须使用 fencing token，避免过期 owner 恢复后继续写入。

---

## 13. 交付物

- Repository trait 和实体 schema。
- Memory/File 实现，Redis 实现或明确后续包。
- 契约测试套件。
- FileStorage key/list 修复。
- 旧数据 migrator、dry-run、verify-only。
- 配置和迁移文档。

