# T03：持久化 Operation 与 Workflow Engine

**任务性质**：证书生命周期执行内核
**前置依赖**：T01、T02
**主要后继**：T05、T08、T09、T11
**建议改动范围**：新增 `src/workflow/`，调整 `src/orchestrator/`、scheduler 和 server task 模型

---

## 1. 背景与当前问题

当前 Orchestrator 是一次性 async 调用。状态通常存在调用栈中，API Task 仅保存在内存 HashMap。Provisioner 对整段流程进行重试，无法知道旧 Order、Challenge 或 finalize 是否已经成功。`status()`、`cancel()` 仍为默认行为。

这会导致：

- 重启后任务消失。
- 重试可能创建重复 Order。
- Challenge 资源无法可靠补偿。
- API 无法返回稳定进度。
- 多实例不能安全接管。

本任务建立通用持久化 Operation/Workflow Engine，并以“证书签发工作流骨架”验证；具体 CA、DNS 和 Sink 行为由后续任务接入。

---

## 2. 目标

1. 定义稳定 Operation、Workflow、Step 和错误分类。
2. 每个 Step 开始/完成都持久化，并支持重启恢复。
3. 支持幂等执行、退避重试、timeout、cancel 和 compensation。
4. 支持单机 Worker，并从接口层面支持多实例 Lease/Fencing。
5. 替换 API 内存 HashMap 作为最终任务事实来源。

---

## 3. 非目标

- 不构建通用 BPMN 平台。
- 不允许用户上传任意 Workflow 脚本。
- 不实现具体 DNS Provider 和 Certificate Sink。
- 不要求当前任务拆独立消息队列服务。

---

## 4. 状态模型

### 4.1 OperationStatus

```rust
pub enum OperationStatus {
    Queued,
    Running,
    Waiting,
    Succeeded,
    Failed,
    CancelRequested,
    Cancelled,
    Compensating,
    CompensationFailed,
}
```

状态必须使用稳定 serde 值，禁止把 `Debug` 文本作为 API 值。

### 4.2 Workflow Step

初始签发 Step：

```text
Plan
EnsureAccount
CreateOrResumeOrder
LoadAuthorizations
PrepareChallenges
WaitPropagation
AcknowledgeChallenges
WaitAuthorizations
CreateCsr
FinalizeOrder
WaitOrder
DownloadCertificate
VerifyCertificate
PersistVersion
ScheduleDeployments
CleanupChallenges
Complete
```

每个 Step 记录：

- attempt、started_at、finished_at。
- input_ref、output_ref。
- lease owner/fencing token。
- last error code、retry_at。
- side-effect locator。
- compensation 状态。

---

## 5. 错误分类

```rust
pub enum ErrorClass {
    Retryable,
    RateLimited { retry_after: Option<Timestamp> },
    Terminal,
    PolicyViolation,
    OperatorActionRequired,
    Cancelled,
}
```

规则：

- 网络 timeout、临时 5xx 通常 Retryable。
- CA 429 使用 Retry-After。
- badNonce 由 CA Backend 内部有限重试，不推进 Workflow attempt。
- Identifier/Challenge 不兼容是 PolicyViolation。
- 无权限或错误凭据可根据 Provider 错误标记 OperatorActionRequired。
- 不得通过字符串匹配决定核心错误分类。

---

## 6. Step 接口

```rust
#[async_trait]
pub trait WorkflowStepExecutor: Send + Sync {
    fn kind(&self) -> WorkflowStepKind;
    async fn execute(&self, ctx: StepContext) -> StepResult;
    async fn compensate(&self, ctx: CompensationContext) -> CompensationResult;
}
```

要求：

- Step 输入来自持久化实体或引用，不依赖上一次调用栈局部变量。
- StepResult 显式返回 Complete、WaitUntil、RetryAt、Fail。
- 外部副作用创建成功后必须在同一步返回 locator，并尽快持久化。
- Executor 不直接修改 API 响应。

---

## 7. Worker 和 Lease

Worker 循环：

1. 查询 ready Operation。
2. 获取带 fencing token 的 Lease。
3. 重新读取最新 revision。
4. 执行一个 Step。
5. CAS 保存结果与 Outbox。
6. 释放或续约 Lease。

约束：

- 每次只推进一个持久化 Step，避免长事务。
- 等待 CA/DNS 的任务保存 `wake_at`，不在 Worker 中长时间 sleep。
- 旧 fencing token 的写入必须被 Repository 拒绝。
- 单机实现也必须走 Lease 接口，以便后续多实例不重构状态机。

---

## 8. Cancel 和 Compensation

- Cancel 是请求，不是立即把状态改成 Cancelled。
- 不可中断的外部请求完成后，Worker 再观察 CancelRequested。
- 已创建 Challenge Lease 时，取消必须进入 Compensating。
- Compensation 本身可重试，失败进入 CompensationFailed 并告警。
- 已签发证书不能“撤销签发事实”；取消只停止后续部署并保留审计记录。

---

## 9. 与旧 Orchestrator 的兼容

- `Orchestrator::execute()` 可以暂时创建 Operation 并等待终态，供旧 Library API 使用。
- API 新路径直接返回 Operation ID。
- 旧 `OrchestrationStatus` 通过映射从 OperationStatus 生成，不再成为事实来源。
- `CertificateProvisioner` 逐步转为“创建 Issue Workflow 的 facade”，不继续内部实现整段重试。

---

## 10. 实施步骤

1. 定义 Operation、Step、Status、ErrorClass、RetryPolicy。
2. 扩展 T02 Repository 支持 ready query、wake_at、Lease、CAS。
3. 实现 Workflow Registry 和 Step Executor 注册。
4. 实现单机 Worker、优雅关停和 Lease 续约。
5. 实现 retry/backoff/jitter，支持 Retry-After 覆盖。
6. 实现 cancel、compensation 和独立 cleanup retry。
7. 建立签发 Workflow 骨架，外部动作先使用 Fake Adapter。
8. 将 API Task 查询切换为 OperationRepository。
9. 提供旧 Orchestrator 等待式兼容 facade。
10. 添加 crash/restart harness。

---

## 11. 测试要求

### 状态机测试

- 合法状态迁移。
- 终态不可再次推进。
- CAS 冲突后重新读取。
- Retryable、RateLimited、Terminal、Policy 错误路径。
- Cancel 在每个主要 Step 的行为。

### 恢复测试

对每个 Step：

1. 执行外部副作用前退出。
2. 外部副作用成功但保存结果前退出。
3. 保存结果后退出。
4. 重启 Worker。
5. 断言不产生不可接受的重复副作用。

### 并发测试

- 两个 Worker 同时领取同一 Operation，只有一个有效。
- Lease 过期接管后旧 Worker 写入被 fencing 拒绝。
- Cancel 和 Step Complete 并发。

命令：

```bash
cargo test workflow
cargo test operation_repository
cargo test workflow_restart
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 12. 验收标准

- API 任务不再依赖进程内 HashMap。
- Operation 在重启后可继续。
- 任一 Step 错误具有稳定错误码和分类。
- retry 不会从头盲目执行整个签发流程。
- Cancel 能触发持久化补偿。
- 双 Worker 不会同时推进同一个 revision。
- 等待任务不占用长时间 sleep 或 Semaphore permit。

---

## 13. 风险与回滚

- Workflow schema 是长期兼容面，必须有 `workflow_version`。
- 不要在首版引入复杂 DAG；线性 Step + 子 Operation 足够。
- 旧同步 facade 必须有明确 timeout，不能无限等待。
- 若新 Worker 出现问题，可暂时停止领取新 Operation；已保存状态不得回写旧内存 Task 模型。

---

## 14. 交付物

- Operation/Workflow 数据结构。
- Worker、Lease、Retry、Cancel、Compensation 实现。
- 签发工作流骨架。
- API Task 到 Operation 的兼容映射。
- 状态机、并发和重启恢复测试。
- Workflow version 和运维说明。

