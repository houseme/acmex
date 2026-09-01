# AcmeX v0.9.0 架构演进实施路线图

**状态**：T01-T12 代码与本地门槛已全部合并；L4/L5 外部环境证据(Pebble/真实 CA/云 Sink)按 KNOWN_LIMITATIONS 显式未执行
**基线**：`main@3ead534`
**目标**：建立可恢复、可扩展、可安全接入上下游的证书生命周期控制平面
**最后更新**：2026-09-01

---

## 1. 使用方式

本目录不是高层愿望清单，而是一组可以独立领取的工程任务包。每个任务文件都包含完成该任务所需的项目背景、边界、目标接口、实施步骤、验证方法和验收标准。

执行者开始任何任务前必须：

1. 阅读仓库根目录 `AGENTS.md`。
2. 阅读本文件。
3. 阅读所领取任务文档的全部内容。
4. 检查当前分支、工作树、Cargo feature 和相关代码是否已经变化。
5. 只实现该任务的范围；依赖任务未完成时使用文档指定的临时兼容策略，不私自扩展范围。
6. 保持旧 API 的兼容边界，除非任务明确要求迁移或弃用。

架构总纲：

- [AcmeX 当前功能、架构评估与目标架构设计](../../ACMEX_CURRENT_STATE_AND_TARGET_ARCHITECTURE_ZH.md)
- [v0.9.0 实现状态核查](./IMPLEMENTATION_STATUS_AUDIT.md)

---

## 2. 版本目标

v0.9.0 的主题不是继续增加 Provider 数量，而是完成以下可运行闭环：

```text
统一请求
→ 持久化 Operation
→ CA Order
→ Challenge Lease
→ 传播确认
→ Challenge 验证
→ Finalize
→ 证书严格校验
→ 不可变版本保存
→ 下游原子部署
→ ARI/策略驱动续签
```

---

## 3. 全局架构约束

所有任务必须遵循：

- 领域层不得依赖 Axum、Redis、具体云 SDK。
- API、CLI、Scheduler 不得自行实现证书流程，只能调用 Application Service。
- 外部副作用必须返回可持久化 locator/lease。
- Workflow Step 必须幂等或显式声明不可重试。
- 私钥和凭据不得出现在普通日志、错误或指标标签中。
- 证书版本不可覆盖；通过 active pointer 激活。
- 所有新公共类型必须有序列化兼容测试和文档。
- 所有异步 API 错误必须区分 retryable 与 terminal。
- 不允许用 sleep 模拟业务成功。
- 不允许以编译通过代替行为验证。

---

## 4. 子任务清单

| ID | 任务 | 主要产出 | 前置依赖 | 建议里程碑 | 当前状态 |
|---|---|---|---|---|---|
| T01 | [强类型领域模型与策略规划](./T01_DOMAIN_MODEL_AND_POLICY.md) | Identifier、Intent、Lineage、兼容矩阵 | 无 | M1 | 已合并 |
| T02 | [Repository、数据模型与迁移](./T02_REPOSITORY_AND_MIGRATION.md) | 持久化实体、CAS、迁移、FileStorage 修复 | T01 | M1 | 已合并 |
| T03 | [持久化 Operation 与 Workflow Engine](./T03_DURABLE_WORKFLOW_ENGINE.md) | Step、Lease、Retry、Resume、Cancel | T01、T02 | M2 | 已合并 |
| T04 | [CA Backend 与 ACME 协议生产化](./T04_CA_BACKEND_AND_PROTOCOL.md) | CA Session、badNonce、Retry-After、Profiles、ARI | T01 | M2 | 已合并 |
| T05 | [Challenge Session、Lease 与补偿清理](./T05_CHALLENGE_LIFECYCLE.md) | 每授权独立 Session、可靠 cleanup | T01、T03 | M2 | 已合并 |
| T06 | [DNS Provider Factory、Zone 与传播确认](./T06_DNS_PROVIDER_AND_PROPAGATION.md) | Provider 装配、SOA/CNAME/NS、quorum | T05 | M3 | 已合并 |
| T07 | [HTTP/TLS Edge 与 RFC 8738 IP 支持](./T07_HTTP_TLS_AND_IP_VALIDATION.md) | Edge Presenter、IPv4/IPv6、TLS reverse SNI | T01、T04、T05 | M3 | 已合并 |
| T08 | [Application Service 与 API/CLI 统一](./T08_APPLICATION_SERVICE_AND_API.md) | 统一用例、API v1、移除模拟逻辑 | T02、T03、T04、T05 | M3 | 已合并 |
| T09 | [ARI 驱动续签控制器](./T09_RENEWAL_CONTROLLER.md) | Window、jitter、Lease、优先级续签 | T02、T03、T04、T08 | M4 | 已合并 |
| T10 | [KeyProvider 与 Certificate Sink](./T10_KEY_PROVIDER_AND_SINKS.md) | Managed/External Key、版本部署、回滚 | T01、T02、T08 | M4 | 已合并(#201/#202/#204/#206) |
| T11 | [安全、可观测性与多实例强化](./T11_SECURITY_OBSERVABILITY_HA.md) | SecretRef、审计、SLO、分布式 Lease | T02、T03、T08 | M5 | 已合并(#200/#205) |
| T12 | [E2E、故障注入与发布门槛](./T12_E2E_AND_RELEASE_GATES.md) | Pebble E2E、恢复测试、发布检查 | T01-T11 | M5 | 已合并(#203;Pebble/L4/L5 待环境执行) |

---

## 5. 依赖关系

```text
T01 Domain Model
 ├─→ T02 Repository ─→ T03 Workflow ─→ T05 Challenge ─→ T06 DNS
 │                    │                └───────────────→ T07 HTTP/TLS/IP
 ├─→ T04 CA Backend ──┴───────────────────────────────→ T07 HTTP/TLS/IP
 │
 └─→ T08 Application Service ← T02/T03/T04/T05
                         ├─→ T09 Renewal
                         ├─→ T10 Key/Sinks
                         └─→ T11 Security/HA

T01-T11 ─→ T12 E2E and Release Gates
```

任务文档可以独立交给 Agent，但不代表所有任务可以无视依赖并行合并。依赖未合并时允许先在独立分支实现 trait 或内存适配器，最终集成必须回到这里定义的接口和状态模型。

---

## 6. 里程碑

### M1：真实领域和持久化基础

完成 T01、T02。

退出条件：

- 域名、Wildcard、IPv4、IPv6 均为强类型。
- Intent、Lineage、Version、Operation、Lease 拥有版本化序列化模型。
- File 和 Memory Repository 契约测试通过。
- 旧 CertificateBundle 可以导入新模型。

### M2：可恢复签发内核

完成 T03、T04、T05。

退出条件：

- Operation 在每个 Step 后持久化。
- 进程重启后不会重复创建 ACME Order。
- Challenge 外部资源拥有 Lease 和最终清理任务。
- ACME 请求统一处理 badNonce、Retry-After 和稳定错误分类。

### M3：域名/IP 验证和统一入口

完成 T06、T07、T08。

退出条件：

- DNS Provider 能由配置创建并正确处理 Zone/委派/传播。
- HTTP/TLS Challenge 可通过本地或 Edge Presenter 执行。
- IPv4/IPv6 Compatibility Matrix 和 RFC 8738 行为有测试。
- API、CLI、Scheduler 不再包含独立签发实现或模拟成功。

### M4：续签与下游部署

完成 T09、T10。

退出条件：

- ARI 优先、fallback、jitter 和分布式 Lease 生效。
- Managed Key 和 External CSR 至少各有一个可运行实现。
- File Sink 和 Kubernetes/Vault 中至少一个远端 Sink 通过契约测试。
- 新版本可以 stage、activate、health check 和 rollback。

### M5：生产门槛

完成 T11、T12。

退出条件：

- 无默认密钥，Secret 不进入日志。
- 关键 Operation、Challenge、Renewal 和 Deployment 指标完整。
- Pebble 全流程、重启恢复、故障注入通过。
- OpenAPI、配置示例、README 和实际行为一致。

---

## 7. 跨任务接口冻结策略

T01、T02、T03 完成后，以下接口在 v0.9.0 内进入稳定期：

- `Identifier`
- `CertificateIntent`
- `CertificateLineage`
- `CertificateVersion`
- `Operation`、`WorkflowStep`、`ChallengeLease`
- Repository trait
- Error Class 和 stable error code

后续任务如需修改上述接口，必须：

1. 给出无法通过扩展字段解决的证据。
2. 更新所有 Repository 和序列化兼容测试。
3. 更新本路线图及受影响任务文档。
4. 提供迁移或兼容层。

---

## 8. 通用验收门槛

每个任务至少执行：

```bash
cargo fmt --all --check
cargo test <与任务相关的精确测试目标>
cargo check --all-features
git diff --check
```

若任务修改公共 API、feature 或配置，还必须：

- 更新或新增 doctest/example。
- 更新 OpenAPI 或配置示例。
- 检查 default features 和 no-default-features。
- 运行对应 Repository/Provider/Sink 契约测试。

最终报告必须分别说明：

- 已完成的代码范围。
- 已执行并通过的本地验证。
- 未执行的真实外部环境验证。
- 是否存在迁移、兼容或回滚要求。
- 是否引入后续任务依赖。

---

## 9. 非目标

v0.9.0 默认不包含：

- 自建完整 CA 服务端。
- Web 管理界面。
- 无约束的任意脚本 Hook 执行平台。
- 一次性支持所有云厂商的所有证书产品。
- 在没有需求和容量证据时拆分完整微服务体系。
- 将 OCSP 模拟结果包装成生产状态。

---

## 10. 项目级完成定义

所有子任务完成后，还必须满足：

- 从上游 Intent 到下游 Active Deployment 的一次完整 E2E。
- 域名、Wildcard、IPv4、IPv6 的策略和失败行为都有测试。
- 进程可在任意 Workflow Step 后重启恢复。
- DNS/HTTP/TLS Challenge 均可证明最终清理。
- 续签不覆盖旧版本，不会因多实例重复执行。
- 文档不再将占位或模拟路径描述为已完成能力。
