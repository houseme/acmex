# T05：Challenge Session、Lease 与补偿清理

**任务性质**：验证生命周期内核
**前置依赖**：T01、T03；Repository 使用 T02
**主要后继**：T06、T07、T08
**建议改动范围**：`src/challenge/`、`src/workflow/`、ChallengeLease Repository

---

## 1. 背景与当前问题

当前 ChallengeSolver Registry 每种 challenge type 只保存一个可变 Solver。AcmeClient 对授权逐个调用 `prepare()` 和 `present()`，但没有调用 `verify()` 和 `cleanup()`。Solver 将 token、record ID 和 server handle 放在内存字段中。

这导致：

- 多域名或并行授权会复用错误状态。
- DNS TXT、HTTP 端口、TLS 服务在失败后残留。
- 进程重启后无法恢复或清理。
- `verify()` 只检查内存状态，不证明外部可见。

本任务重新定义 Challenge 生命周期和可持久化 Lease；具体 DNS、HTTP、TLS Adapter 分别由 T06/T07 完成。

---

## 2. 目标

1. 每个 Authorization/Challenge 创建独立 ChallengeSession。
2. Presenter 返回可序列化 ChallengeLease。
3. 明确 prepare、observe、acknowledge、poll、cleanup 顺序。
4. 所有清理幂等、可重试、可在主 Operation 结束后继续。
5. 支持多 Challenge 并行但有边界并发。
6. 让当前三类 Solver 通过兼容适配器逐步迁移。

---

## 3. 非目标

- 不实现具体 DNS Zone/传播算法。
- 不实现 RFC 8738 IP 网络细节。
- 不决定 CA 最终选择哪个 challenge；Planner 来自 T01/T04。

---

## 4. 目标模型

```rust
pub struct ChallengeSession {
    pub id: ChallengeSessionId,
    pub operation_id: OperationId,
    pub authorization_url: SecretUrlRef,
    pub challenge_url: SecretUrlRef,
    pub identifier: Identifier,
    pub challenge_type: ChallengeType,
    pub token_hash: String,
    pub state: ChallengeSessionState,
    pub lease_id: Option<ChallengeLeaseId>,
    pub deadline: Timestamp,
}
```

状态：

```text
Selected
→ Preparing
→ Prepared
→ Observing
→ Propagated
→ Acknowledged
→ Processing
→ Valid

任何阶段 → Failed/Cancelled
Prepared 之后 → CleanupPending → Cleaned/CleanupFailed
```

Valid 与 Cleaned 是不同维度；授权成功后仍必须清理。

---

## 5. 端口接口

```rust
#[async_trait]
pub trait ChallengePresenter: Send + Sync {
    fn kind(&self) -> ChallengeType;
    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease>;
    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation>;
    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome>;
}
```

要求：

- Presenter 实例应无单个 challenge 的可变业务状态。
- `prepare` 成功返回完整 locator。
- `observe` 只验证外部状态，不修改 CA。
- `cleanup` 幂等；AlreadyAbsent 视为成功。
- 凭据通过 ProviderRef/SecretRef 获取，不进入 Lease。

---

## 6. Lease 设计

通用字段：

- lease ID、presenter ID、challenge type。
- operation/session ID。
- created_at、expires_at。
- external locator。
- expected content hash，不存原始 secret/token，除非协议确实需要且有加密边界。
- cleanup attempts、last error、cleaned_at。

类型化 locator：

- DNS：zone、record name、provider record ID/value hash。
- HTTP：agent/route ID、token hash、endpoint。
- TLS：agent/route ID、certificate fingerprint、reverse SNI。

---

## 7. 工作流行为

### Prepare

1. 读取最新 Authorization。
2. Planner 选择 Challenge。
3. 创建 ChallengeSession。
4. Presenter prepare。
5. 持久化 ChallengeLease 和 Prepared 状态。
6. 注册 Cleanup Compensation。

如果外部副作用成功但 Repository 写入失败，Presenter 必须支持基于幂等键查询已有资源，或使用确定性 locator 恢复。

### Observe

- 根据 challenge 类型调用外部观察。
- 未传播返回 `WaitUntil`，而不是 Worker 内 sleep。
- timeout 进入 Failed 并触发 cleanup。
- 达到策略 quorum 后才 acknowledge CA。

### CA Processing

- acknowledge 后轮询 Authorization，不只轮询 Order。
- `invalid` 保存 CA Problem 和验证时间。
- `valid` 后立即安排 cleanup，不等整个 Order 完成。

### Cleanup

- 主流程成功、失败、取消、超时均执行。
- cleanup 失败创建/保留独立可重试工作。
- 清理不得删除同名的其他并行记录。

---

## 8. 并发模型

- 每个 Authorization 一个 Session。
- 同一 Order 的 Session 可并行 prepare/observe。
- 受全局、tenant、Provider、Agent 四级 Semaphore/Rate Limit 控制。
- 同一 Identifier 的相同 record name 允许多个 TXT 并存。
- HTTP Presenter 必须支持多 token map，不再只有一个 key authorization。
- TLS 端口共享由 Edge Adapter 路由，不为每个 Session独占中心端口。

---

## 9. 旧 Solver 兼容

- 新增 `LegacySolverPresenter` 仅用于过渡和测试。
- Legacy Adapter 必须在同一个进程生命周期内将 Solver 封装为独立 Session，禁止全局 Registry 复用。
- 新 Application Service 不得直接调用旧 `get_mut(challenge_type)`。
- 当 T06/T07 完成后，旧 Solver 标记 deprecated。

---

## 10. 实施步骤

1. 定义 ChallengeSession、State、Lease、Locator、Observation。
2. 定义 ChallengePresenter 和 PresenterRegistry/Factory。
3. 扩展 Repository 保存 Session 和 Lease。
4. 实现 Workflow Step：Prepare、Observe、Acknowledge、Poll、Cleanup。
5. 实现补偿和独立 cleanup retry。
6. 实现并发限制和 deadline。
7. 实现 LegacySolverPresenter 迁移当前测试。
8. 修改 AcmeClient/Provisioner 新路径不再直接使用可变 Registry。
9. 添加残留 Lease 扫描器。
10. 输出运行时管理命令或 API，用于查询/重试 CleanupFailed。

---

## 11. 测试要求

- 两个相同类型 challenge 拥有独立状态。
- prepare 成功、持久化失败、恢复后不重复创建资源。
- observe 未传播多次等待，最终成功。
- acknowledge 后 auth invalid，仍 cleanup。
- finalize 失败，已 valid challenge 已 cleanup。
- cancel 在 Prepared/Observing/Processing 各状态下 cleanup。
- cleanup AlreadyAbsent 幂等成功。
- cleanup 临时失败后后台重试。
- 多 TXT Session 清理只删除自己记录。
- 进程重启后扫描并清理过期 Lease。

命令：

```bash
cargo test challenge_lifecycle
cargo test challenge_cleanup
cargo test workflow_restart
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 12. 验收标准

- 新主流程不再依赖每类型一个可变 Solver。
- 所有外部 challenge 副作用都有持久化 Lease。
- `prepare` 之后所有终态都有 cleanup 路径。
- 重启后能继续 observe 或 cleanup。
- API 可查询 ChallengeSession 和 Cleanup 状态，但不泄露 token/key authorization。
- 残留 Lease 有指标和人工重试入口。

---

## 13. 风险与回滚

- 外部副作用与 Repository 无法做分布式事务，必须用幂等键和恢复查询解决。
- 不要在 Drop 中依赖异步 cleanup；Drop 只能作为最后日志提示。
- 旧 Solver 兼容只作为迁移手段，不应继续扩展。
- 如新并行模式不稳定，可配置并发为 1，但仍使用独立 Session。

---

## 14. 交付物

- ChallengeSession/Lease 模型。
- Presenter 端口和 Registry/Factory。
- Prepare/Observe/Acknowledge/Poll/Cleanup Workflow Step。
- Legacy Solver 兼容适配器。
- Lease 清扫和人工重试入口。
- 生命周期、并发、失败和恢复测试。

