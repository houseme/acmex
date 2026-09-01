# T12：E2E、故障注入与发布门槛

**任务性质**：最终集成、验证和发布准入
**前置依赖**：T01-T11
**主要后继**：v0.9.0 发布
**建议改动范围**：`tests/`、`scripts/`、CI、fixtures、docs、release notes

---

## 1. 背景与当前问题

当前测试全部通过，但集成测试只覆盖账户注册和订单创建。部分测试只验证方法存在或忽略实际结果；没有完整签发、传播、恢复、续签、部署和多实例证据。

本任务不是简单补几个测试，而是建立发布门槛：只有全生命周期行为通过，文档才能把能力标记为已完成。

---

## 2. 目标

1. 建立可重复的 Pebble E2E 环境。
2. 覆盖 DNS、HTTP、TLS、Wildcard、IPv4、IPv6。
3. 覆盖签发、续签、吊销、版本切换和下游部署。
4. 覆盖每个 Workflow Step 的崩溃恢复。
5. 覆盖外部依赖故障、限流和补偿清理。
6. 建立 default/all/no-default feature CI 矩阵。
7. 建立 OpenAPI、配置、文档和实现一致性门槛。
8. 输出 v0.9.0 发布检查表和已知限制。

---

## 3. 非目标

- 不在公共 CI 使用真实生产 CA。
- 不要求每次 PR 调用所有真实云 DNS Provider。
- 不通过增加 timeout 掩盖不稳定测试。
- 不把未完成验证描述为成功。

---

## 4. 测试要求与分层

### L1 单元和属性测试

- Domain、Policy、Workflow、Retry、Lease、ARI、SNI、CSR。
- 属性测试：Identifier round-trip、状态机非法迁移、jitter 分布边界。

### L2 Adapter 契约

- Repository Contract。
- CA Backend Contract。
- DNS Provider Contract。
- Challenge Presenter Contract。
- KeyProvider Contract。
- Certificate Sink Contract。

### L3 进程内集成

- Application Service + Memory Repository + Fake CA/Presenter/Sink。
- API/CLI 映射、Idempotency、ProblemDetails。

### L4 本地 E2E

- Pebble、Challenge Test Server、临时 DNS/Agent、File/Redis Repository。
- 真实进程启动、停止、重启。

### L5 受控外部验证

- Let's Encrypt Staging 冒烟。
- 真实 DNS Provider `#[ignore]`/手动 CI。
- Kubernetes/Vault 测试环境。

L5 未执行时必须明确报告，不能由 L1-L4 推断。

---

## 5. E2E 场景矩阵

### 初次签发

- 单 DNS + HTTP-01。
- 多 DNS SAN + HTTP-01 并发 token。
- 单 DNS + DNS-01。
- Wildcard + DNS-01。
- CNAME 委派 DNS-01。
- TLS-ALPN-01 domain。
- IPv4 + HTTP-01。
- IPv4 + TLS-ALPN-01。
- IPv6 + HTTP-01。
- IPv6 + TLS-ALPN-01。
- CA 不支持 IP/profile 时明确失败。

### 续签

- ARI window。
- ARI 不支持 fallback。
- 45/90 天虚拟证书。
- 160 小时短周期证书多轮续签。
- key reuse、key rotate、external CSR。
- 多实例同时扫描只一个 Operation。

### 部署

- File Sink 原子激活。
- 第二 Sink 正常。
- required Sink 失败回滚。
- best-effort Sink 失败不阻止 Active，但告警。
- 签发成功、部署失败后只重试部署。

### 吊销和清理

- 吊销 active/old version。
- DNS/HTTP/TLS cleanup 正常。
- cleanup 临时失败最终重试。
- 已不存在资源视为幂等成功。

---

## 6. 崩溃恢复矩阵

测试 harness 在每个 Step 的三个窗口注入退出：

1. 外部调用前。
2. 外部调用成功但 Repository 保存前。
3. Repository 保存后。

至少覆盖：

- EnsureAccount。
- CreateOrder。
- PrepareChallenge。
- AcknowledgeChallenge。
- FinalizeOrder。
- DownloadCertificate。
- PersistVersion。
- StageDeployment。
- ActivateDeployment。
- CleanupChallenge。

断言：

- 不产生不可接受的重复 Order/record/route/version。
- Operation 最终可继续或进入明确人工状态。
- Challenge 最终清理。
- active version 不指向半完成部署。

---

## 7. 故障注入矩阵

### CA

- badNonce 一次/连续。
- 429 + Retry-After。
- 500/503、timeout、连接重置。
- Order invalid、Authorization invalid。
- certificate URL 缺失、无效 chain。

### DNS

- create 成功但传播超时。
- 权威已更新但递归未更新。
- 多 TXT 并行。
- 401/403/429/5xx。
- cleanup 失败。

### Repository

- CAS 冲突。
- Redis 短暂不可用。
- File JSON 损坏、磁盘写失败、rename 前退出。
- Lease 过期和 fencing。

### Edge/Sink

- Agent 离线。
- 部分节点安装成功。
- activate/health/rollback 失败。
- Webhook 重复/延迟/永久失败。

---

## 8. 测试基础设施

建议新增：

```text
tests/
├── contracts/
├── integration/
├── e2e/
├── fixtures/
└── support/

scripts/
├── run_pebble_e2e.sh
├── run_restart_matrix.sh
├── run_feature_matrix.sh
└── verify_docs_and_openapi.sh
```

要求：

- 使用随机可用端口和临时目录。
- 每个测试拥有独立 namespace/zone。
- 失败时收集日志和 Operation 快照，不输出 secret。
- 测试结束检查残留进程、DNS record、Lease 和临时文件。
- macOS/Linux 差异显式处理。
- 脚本可重复执行，不依赖人工清理。

---

## 9. CI 矩阵

最低：

```text
format
unit-default
unit-all-features
check-no-default-features
repository-contract-file
repository-contract-memory
api-integration
pebble-http01
pebble-dns01
pebble-tlsalpn01
restart-recovery
docs-openapi
security-secret-scan
```

Redis、Kubernetes、真实 DNS Provider 根据环境分为 required 或 scheduled/manual job。

所有 job 必须报告真实完成状态；取消、timeout、未配置不算通过。

---

## 10. 文档和契约门槛

- OpenAPI 与实际 Router/DTO 校验。
- `acmex.toml.example` 可以 parse、env override、validate。
- README 示例可以编译。
- feature 表与 Cargo/Factory 一致。
- 文档中不得出现“实际实现”但代码仍为 placeholder/simulate。
- 当前状态总纲根据实际完成度更新。
- 所有任务文档的验收框有真实证据后才标记完成。

---

## 11. 性能和容量基线

不是追求极限 benchmark，而是建立回归基线：

- 1k/10k Intent 扫描内存和耗时。
- 100/1000 并发 waiting Operation 不占用 100/1000 个长时间任务。
- DNS propagation poll 的并发限制。
- Repository CAS/Lease 延迟。
- Outbox backlog 消费能力。
- 证书解析/验证 CPU。

结果必须记录硬件、feature、后端和测试规模，不能泛化为生产吞吐承诺。

---

## 12. 发布门槛

### 必须通过

- `cargo fmt --all --check`
- `cargo test`
- `cargo check --all-features`
- `cargo check --no-default-features`
- `git diff --check`
- 三类 Challenge Pebble E2E。
- Workflow restart matrix。
- Repository/Provider/Sink contract。
- API/OpenAPI/config/docs 校验。
- 无默认 secret 和占位业务成功。

### 必须有明确证据或限制说明

- IPv4/IPv6 E2E 测试 CA 能力。
- Let's Encrypt Staging 冒烟。
- 真实 DNS Provider 测试范围。
- Redis/Kubernetes/Vault 后端范围。
- 不同操作系统验证范围。

### 阻断发布

- Challenge cleanup 可能永久静默丢失。
- 重启后重复创建 Order。
- active version 指向未健康部署。
- 私钥出现在日志/API 普通响应。
- 自动续签没有真实周期扫描。
- API/CLI 仍返回模拟成功。

---

## 13. 实施步骤

1. 整理现有测试，移除只验证“方法存在”的弱断言。
2. 建立 Adapter Contract harness。
3. 建立 Pebble 和 Challenge 测试环境。
4. 实现全签发 E2E 场景。
5. 实现虚拟时钟续签测试。
6. 实现 restart/crash harness。
7. 实现 fault proxy/fake adapter 故障注入。
8. 实现 CI feature/repository/OS 矩阵。
9. 实现 docs/OpenAPI/config 校验。
10. 输出性能基线、release checklist、known limitations。

---

## 14. 验收标准

- 至少一个完整请求从 Intent 到 Active File Deployment 自动通过。
- DNS、HTTP、TLS 三类 Challenge 均有 E2E。
- IPv4/IPv6 有标准行为测试，并尽可能有 E2E；未有外部 E2E 时明确限制。
- 每个持久化 Step 的恢复矩阵通过。
- cleanup、rollback、fencing 故障可复现并验证。
- CI 明确区分本地、模拟、staging、真实 Provider 证据。
- 发布文档与代码实际能力一致。

---

## 15. 风险与回滚

- E2E 不稳定时先修复隔离、时钟和端口管理，不能简单扩大 timeout。
- 外部 staging/Provider 故障与代码回归分开报告。
- 发布失败时保留所有 Operation/fixture 证据，但确保 secret 脱敏。
- 测试基础设施不应修改生产 DNS/证书；使用专用 staging account 和 zone。

---

## 16. 交付物

- Adapter Contract suites。
- Pebble E2E、IPv4/IPv6 和续签场景。
- restart/fault injection harness。
- CI 矩阵和可重复脚本。
- 性能基线报告。
- v0.9.0 release checklist、known limitations 和验证证据索引。
