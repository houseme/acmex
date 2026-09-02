# T18：可观测性收尾

**任务性质**：T11 验收缺口收口
**前置依赖**：无（基于已合并的 T11 指标/Outbox 基础设施）
**主要后继**：T20（多实例演练带完整观测）
**建议改动范围**：`src/repository/`（错误打点包装）、`src/workflow/`、`src/renewal/`、`src/delivery/`（trace 注入）、`src/notifications/`（webhook 重放窗口）、`docs/`（告警与 dashboard 资产）、tests

---

## 1. 背景与当前问题

任务创建时，`SECURITY_OBSERVABILITY_HA.md` 的 "Metrics Exposure (2026-09-01)" 一节记录了两处未完成项，且 v0.9.0 审计"建议后续顺序"第 2 条将其列为 T11 收尾项。当前实现状态见第 7 节：

1. **`acmex_repository_errors_total` 未打点**：Prometheus 规则示例中已有该指标的告警（`AcmeXRepositoryErrors`），但没有任何代码产出它——告警永远不触发，是"文档先于实现"的假信号。
2. **Trace span 字段注入未接线**：Trace Convention（tenant_id/intent_id/lineage_id/operation_id/workflow_step/ca_id/challenge_type/provider_id/sink_id/request_id）只停留在文档，span 中没有这些字段；跨异步边界无法用 trace 关联一次签发的全链路。
3. **Webhook HMAC 重放窗口验证缺失**：签名头（`X-AcmeX-Event-Id`、`X-AcmeX-Signature-Timestamp`、`X-AcmeX-Signature`）已定义，但时间戳窗口校验未实现——持有历史有效签名的重放不会被拒绝。
4. **告警/dashboard 只是文档示例**：Prometheus rules 与 dashboard 字段清单写在文档里，没有作为可直接导入的资产随仓库发布。

---

## 2. 目标

1. **`repository_errors_total{backend,operation}` 打点**：
   - 覆盖 File/Memory/Redis（以及涉及的封装层）repository 操作失败；`backend` 取存储类型（低基数），`operation` 取粗粒度操作类别（read/write/scan/cas）；
   - 实现方式优先统一包装层（decorator repository），避免在每个后端散落 `metrics.record`；
   - 行为测试：注入失败断言计数递增；成功不递增。
2. **Trace span 字段注入**：
   - 按 Trace Convention 在关键 span 落字段：WorkflowEngine（operation_id/workflow_step/intent_id/lineage_id）、RenewalController（ca_id）、Challenge 步骤（challenge_type/provider_id）、Deployment（sink_id）、HTTP 入口（request_id/tenant_id）；
   - identifier 值默认记录 normalized hash（共享遥测不落明文域名/IP）；
   - 测试：以 tracing test subscriber 断言字段存在与脱敏（私钥/token/key authorization 不得出现于任何 span 字段）。
3. **Webhook HMAC 重放窗口**：
   - 签名验证加入时间戳窗口（建议默认 ±5 分钟，可配置）与 `event_id` 去重说明文档化；
   - 行为测试：窗口外时间戳被拒（401/明确错误）、窗口内重放签名校验结果一致；文档更新签名校验规范（含消费者示例）。
4. **告警与 dashboard 资产化**：
   - `docs/observability/`（或 `extras/`）提供可直接导入的 Prometheus rules YAML 与 Grafana dashboard JSON，与文档示例保持同源；
   - 文档改为引用资产文件，消除双份漂移。
5. **文档对齐**：`SECURITY_OBSERVABILITY_HA.md` 移除 "Not yet instrumented / not yet wired" 段落。

---

## 3. 非目标

- 不引入新的 APM/后端依赖（OTLP 既有可选路径不变）。
- 不做 metrics/tracing 的采样策略调优（默认全量计数器、trace 采样交由 operator）。
- 不实现 webhook 的消费者 SDK（只定义校验规范与示例）。
- 不新增高基数标签（域名、操作 ID、序列号等仍禁止作为指标标签）。

---

## 4. 设计要点

- repository 打点的 `operation` 类别必须闭集（read/write/scan/cas/migrate），不得透传方法名等自由字符串。
- span 字段注入注意异步边界：字段随 span 携带而非依赖 task-local 继承；`workflow_step` 在 Step span 上、`operation_id` 在引擎级 span 上，避免每个日志行重复全量字段。
- 重放窗口配置 `[notifications.webhook]`（或对应既有配置节）扩展；默认值写入文档。
- Grafana dashboard JSON 首版覆盖文档 "Dashboard Fields" 清单即可，不做可视化精修。

---

## 5. 实施步骤

1. repository decorator + 注册指标 + 三后端行为测试。
2. span 字段注入（engine/renewal/challenge/delivery/http 入口）+ subscriber 断言测试。
3. webhook 时间戳窗口 + 测试 + 消费者规范文档。
4. 告警/dashboard 资产出与文档引用切换。
5. `SECURITY_OBSERVABILITY_HA.md` 更新；审计"建议后续顺序"第 2 条勾销。

---

## 6. 验证方法

```bash
cargo test repository
cargo test outbox_consumer
cargo test --test api_test        # /metrics 暴露新指标
cargo check --all-features && cargo check --no-default-features
```

---

## 7. 验收标准

实现状态（2026-09-02，`houseme/v010-t18-observability`）：

- [x] `acmex_repository_errors_total{backend,operation}` 有真实打点与行为测试；Prometheus 示例与实现同名同标签。
- [x] Trace Convention 全部字段在对应 span 可观测；脱敏断言（无明文 identifier/密钥/token）有测试。
- [x] webhook 窗口外时间戳被拒并有测试；消费者校验规范文档化。
- [x] Prometheus rules 与 Grafana dashboard 以资产文件形式随仓库发布，文档引用之。
- [x] `SECURITY_OBSERVABILITY_HA.md` 无 "not yet" 段落；v0.9.0 审计对应条目可标记关闭。
