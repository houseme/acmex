# T08：Application Service 与 API/CLI 统一

**任务性质**：统一上游入口和用例编排
**前置依赖**：T02、T03、T04、T05；T06/T07 可通过 Presenter Registry 增量接入
**主要后继**：T09-T12
**建议改动范围**：新增 `src/application/`，调整 `src/server/`、`src/cli/`、`src/client.rs`、OpenAPI

---

## 1. 背景与当前问题

当前 API、CLI、AcmeClient、Provisioner 和 Scheduler 各自拼装流程：

- CLI obtain 写占位 PEM。
- CLI renew 模拟成功。
- Certificate API 返回固定示例。
- API Task 使用内存 HashMap。
- Provisioner 签发后不保存 Bundle。

本任务建立唯一 Application Service，使所有上游入口只负责协议转换、鉴权和展示。

---

## 2. 目标

1. 定义证书生命周期 Use Case/Application Service。
2. API、CLI、Scheduler 和 Rust 高层 API 统一调用这些用例。
3. 提供 `/api/v1` 资源模型和稳定 Operation API。
4. 实现 Idempotency-Key 和请求规范化。
5. 移除所有模拟成功、固定证书和 sleep 成功路径。
6. 统一 RFC 7807 错误、稳定 error code 和 HTTP 状态映射。
7. 默认不通过 API 返回私钥。

---

## 3. 非目标

- 不实现 Web UI。
- 不在 Handler 中实现业务流程。
- 不把 Application Service 绑定到 Axum 类型。
- 不在本任务实现复杂租户计费。

---

## 4. Application Service

```rust
#[async_trait]
pub trait CertificateApplication: Send + Sync {
    async fn create_intent(
        &self,
        command: CreateCertificateIntent,
    ) -> Result<IntentView>;

    async fn issue(&self, command: IssueCertificate) -> Result<OperationRef>;
    async fn renew(&self, command: RenewCertificate) -> Result<OperationRef>;
    async fn revoke(&self, command: RevokeCertificate) -> Result<OperationRef>;
    async fn deploy(&self, command: DeployCertificate) -> Result<OperationRef>;
    async fn cancel_operation(&self, command: CancelOperation) -> Result<OperationView>;
}
```

Query Service 独立：

- get/list Intent。
- get Lineage 和版本。
- get/list Operation。
- get Deployment 状态。
- 获取证书链；私钥导出走独立受限接口。

---

## 5. Command 行为

Application Service 负责：

1. 鉴权后的 tenant/actor 上下文检查。
2. 输入规范化和领域验证。
3. Idempotency-Key 查重。
4. 创建/更新 Intent。
5. 创建 Operation 和 Workflow 初始状态。
6. 写 Outbox 审计事件。
7. 返回 OperationRef，不等待长流程完成。

不得：

- 直接 sleep 轮询。
- 在 API 请求中绑定 80/443。
- 把私钥写入普通响应。
- 直接构造具体 FileStorage/DNS Provider。

---

## 6. API v1

最低资源：

```text
POST   /api/v1/certificate-intents
GET    /api/v1/certificate-intents
GET    /api/v1/certificate-intents/{id}
PATCH  /api/v1/certificate-intents/{id}
POST   /api/v1/certificate-intents/{id}:issue

GET    /api/v1/certificate-lineages/{id}
POST   /api/v1/certificate-lineages/{id}:renew
GET    /api/v1/certificate-lineages/{id}/versions
GET    /api/v1/certificate-versions/{id}
GET    /api/v1/certificate-versions/{id}/chain
POST   /api/v1/certificate-versions/{id}:deploy
POST   /api/v1/certificate-versions/{id}:revoke

GET    /api/v1/operations
GET    /api/v1/operations/{id}
POST   /api/v1/operations/{id}:cancel
```

### 写请求

- 要求 `Idempotency-Key`；允许服务为 CLI 自动生成，但必须返回。
- 创建异步工作返回 202、Operation Location 和 body。
- 重复相同 key+payload 返回原 Operation。
- 相同 key 不同 payload 返回 409。

### Operation Response

必须包含：

- id、type、stable status、current step、progress。
- created/started/updated/finished。
- intent/lineage/version reference。
- error problem reference，不包含 secret。
- retry_at、cancel_allowed。

---

## 7. 错误契约

统一 RFC 7807：

```json
{
  "type": "https://acmex.example/problems/policy-violation",
  "title": "Validation policy is incompatible",
  "status": 422,
  "detail": "IP identifiers cannot use dns-01",
  "error_code": "VALIDATION_CHALLENGE_INCOMPATIBLE",
  "retryable": false,
  "operation_id": "op_..."
}
```

映射原则：

- 输入格式 400。
- 未认证 401、无权限 403。
- 资源不存在 404。
- 幂等冲突/CAS 冲突 409。
- 策略不兼容 422。
- Rate Limit 429 + Retry-After。
- 下游暂不可用 503。
- 内部未知错误 500，detail 不泄露 secret。

---

## 8. API 安全和私钥

- 删除默认 `secret-admin-key` 行为；无凭据时管理 API 不得启动，或只启动 health。
- 私钥不包含在 CertificateVersion 普通 JSON。
- managed key export 使用独立 endpoint、独立权限、一次性审计和 no-store header。
- external CSR 模式永远无私钥可导出。
- 列表 API 支持分页和稳定排序，避免一次加载所有证书。

---

## 9. CLI 统一

CLI 只做两类客户端：

1. Embedded：直接调用 Application Service。
2. Remote：调用 REST API。

`obtain`：

- 创建 Intent 或 one-shot Intent。
- 创建 Issue Operation。
- 默认显示 Operation ID；`--wait` 才轮询。
- 成功后通过 Sink 或受控 export 输出，不写占位 PEM。

`renew`：

- 根据 Lineage/Intent 创建 Renewal Operation。
- `--force` 作为 Policy Override，记录审计。
- 不在 CLI 中解析、备份和模拟替换证书。

`serve`：

- 完整执行配置解析、env override、validation、repository/factory/application 构造。
- `Config::default()` 也必须解析有效 CA directory，不能保留空 URL。

---

## 10. Rust API 兼容

- 保留低层 `AcmeClient` 给需要手工 ACME 流程的用户。
- 新增高层 `AcmeXService` 或 `CertificateApplication` builder。
- 旧 `issue_certificate` 可继续同步等待，但内部创建 Operation。
- 明确低层与管理平台 API 的差异，避免两个“主入口”职责重叠。

---

## 11. 实施步骤

1. 定义 Application Command、View、Service 和 Query Service。
2. 实现依赖注入 Builder，组装 Repository、Workflow、CA、Presenter、Key、Sink。
3. 实现 create intent/issue/renew/revoke/deploy/cancel。
4. 新增 `/api/v1` Handler，只进行 DTO 转换。
5. 实现 Idempotency-Key 和分页。
6. 统一 ProblemDetails/error code 映射。
7. 迁移 CLI obtain/renew/serve。
8. 迁移 Scheduler 调用 Application Service。
9. 将旧 `/api` 标记兼容/弃用并删除模拟数据。
10. 更新 OpenAPI、examples 和 README。

---

## 12. 测试要求

- Handler 不直接调用 CaBackend/Presenter。
- 同 idempotency key 同 payload 返回同 Operation。
- 同 key 不同 payload 409。
- 所有写 API 202/Location/Operation body。
- Operation status 使用稳定字符串。
- 各 ErrorClass HTTP/RFC7807 映射。
- API 无凭据配置时拒绝启动管理路由。
- 证书普通响应不包含 private key。
- CLI obtain 不写占位数据。
- CLI/API 对同一 Intent 产生相同 Application Command。
- Server default config 得到有效 directory 或启动前失败。

命令：

```bash
cargo test application
cargo test --test api_test
cargo test cli
cargo test config
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 13. 验收标准

- API、CLI、Scheduler 使用同一个 Application Service。
- 代码中不存在 `(Actual data from ACME)`、固定 cert ID 或 sleep 模拟续签成功。
- Task 状态来自 OperationRepository。
- 所有异步写请求可通过 Operation 查询。
- OpenAPI 与路由/DTO 有自动校验。
- 默认 API 不返回私钥，也没有默认管理密钥。

---

## 14. 风险与回滚

- 保留旧 `/api` 一段迁移期，但不得继续扩展。
- CLI 输出格式变化需提供明确 release note。
- 旧 Library 同步等待接口要有 timeout 和 cancellation 行为。
- 迁移时可用 feature 暂时控制 v1 route，但主分支不能保留模拟成功。

---

## 15. 交付物

- Application/Query Service。
- API v1 路由、DTO、ProblemDetails、Idempotency。
- 统一 CLI 和 Rust 高层入口。
- 删除模拟业务路径。
- OpenAPI、示例、兼容和迁移文档。

