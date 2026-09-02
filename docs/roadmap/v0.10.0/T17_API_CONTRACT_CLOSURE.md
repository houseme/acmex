# T17：API 契约与遗留面收口

**任务性质**：T05/T08 验收缺口收口（API/CLI 契约面）
**前置依赖**：无（基于已合并的 Application Service 与 api_v1）
**主要后继**：T21（迁移文档引用弃用计划）
**建议改动范围**：`src/server/api_v1.rs`、`src/server/api.rs`、`src/application/`、CLI status 命令、OpenAPI、`tests/api_test.rs`、docs

---

## 1. 背景与当前问题

v0.9.0 审计确认的 API 面缺口：

1. **PATCH intents 为显式 stub**：`src/server/api_v1.rs` 中 `update_intent` 返回 "intent patch is not implemented in v0.9.0 M3"。目标架构 §14 将 `PATCH /api/v1/certificate-intents/{id}` 列为推荐资源。
2. **授权/挑战状态不可观察**（审计"建议后续顺序"第 1 条的 challenge 状态 API）：Operation 进行中，操作者无法经 API/CLI 查看各授权/挑战处于 pending/valid/invalid、最后一次 CA 轮询结果与错误——只能翻日志。这是 T05 验收面（Challenge Session 状态可见性）的缺口。
3. **legacy `/api` 兼容面全量保留**（T08 缺口）：旧 task 语义路由与新 `/api/v1` 并存，没有弃用信号（Deprecation/Sunset header）、没有迁移表，运维无法判断哪些面会消失。
4. **revoke spine 缺 Fake CA 行为测试**（审计第 1 条"仍缺"）：`SubmitRevocationStep` 已接线，但没有"经真实 backend.revoke 调用"的行为测试。
5. **OpenAPI 一致性门槛不足**：目标架构 §14 要求"OpenAPI 文件必须由实现测试持续校验"，当前 `release_gate_docs.rs` 只做文档层面校验，路由 ↔ OpenAPI 双向覆盖没有测试化。

---

## 2. 目标

1. **PATCH `/api/v1/certificate-intents/{id}` 实现**：
   - 可更新字段白名单（建议：renewal policy、sink 引用、enable/disable、描述性标签）；
   - 不可变字段（identifiers、CA、challenge profile）变更返回稳定 error code 的 4xx；
   - 有进行中 Operation 时的更新策略显式（建议：允许更新，作用于后续续签；当前语义写入文档）；
   - Idempotency-Key 语义与其他写路由一致。
2. **授权/挑战状态查询**：
   - `GET /api/v1/operations/{id}` 详情扩展（或子资源）暴露：每个 authorization 的 identifier、challenge 类型、状态（pending/valid/invalid）、CA 报告的错误摘要、最后轮询时间、传播确认结果；
   - CLI `acmex status`（或既有等价命令）同步展示；
   - 状态枚举稳定（不以 Rust Debug 文本作 API 值），进入 OpenAPI。
3. **legacy `/api` 弃用计划**：
   - 所有 legacy 路由响应携带 `Deprecation: true` 与 `Sunset: <日期>` header（日期与 T21 发布计划对齐）；
   - 文档迁移表：旧 task 语义 → `/api/v1` 等价资源与行为差异；
   - legacy 面从此只减不增（全局约束既有条款，落为 CI/评审检查项说明）。
4. **revoke spine 行为测试**：Fake CA 契约——吊销请求真实到达 backend、证书状态迁移、CA 拒绝时的错误分类与终态。
5. **OpenAPI 双向校验门槛**：扩展 release gate 测试——实现路由 ⊆ OpenAPI 路径、OpenAPI 路径 ⊆ 实现路由（显式豁免清单除外）、响应 schema 与序列化输出一致性抽查。

---

## 3. 非目标

- 不删除 legacy `/api` 路由（只发弃用信号；实际移除时间由 Sunset 与 T21 决定）。
- 不新增 WebSocket/SSE 推送（轮询语义维持，与 202 Accepted 模式一致）。
- 不做 API 分页/过滤的全面改造（intents 已有 `limit`；其余资源有需求再立项）。
- 不改变 Operation 状态机（仅暴露既有状态）。

---

## 4. 设计要点

- PATCH 的字段白名单是公共契约：进入 OpenAPI 与冻结面；字段演进走兼容测试。
- 挑战状态数据来源：Challenge Session/Workflow 持久化状态，禁止为展示重新查询 CA（避免读路径产生外部副作用）；"最后轮询时间"如实反映持久化值，陈旧时展示 stale 标记。
- 错误摘要脱敏：CA 返回的 problem detail 摘要不得包含 key authorization、完整 JWS、token 等值（T11 约定）。
- Sunset 日期必须与 T21 发布节奏一致，避免发布未定而 header 先承诺日期。

---

## 5. 实施步骤

1. PATCH 实现 + Application Service 用例 + 测试（白名单、不可变字段、幂等）。
2. 挑战状态暴露：Repository 查询路径、API 资源、CLI 展示、OpenAPI。
3. legacy 弃用 middleware + 迁移表文档。
4. revoke spine fake CA 行为测试。
5. OpenAPI 双向校验测试合入 `tests/release_gate_docs.rs` 或新文件。
6. 文档更新与审计条目勾销。

---

## 6. 验证方法

```bash
cargo test --test api_test
cargo test --test issuance_spine    # revoke 行为
cargo test release_gate             # OpenAPI 双向校验
scripts/verify_docs_and_openapi.sh
```

---

## 7. 验收标准

- [ ] PATCH intents 白名单更新生效；不可变字段返回稳定 error code（有测试），无 "not implemented" 残留于 `/api/v1`。
- [ ] 进行中 Operation 的授权/挑战状态可经 API 与 CLI 查询，含状态、错误摘要、最后轮询时间；OpenAPI 同步。
- [ ] legacy `/api` 响应带 Deprecation/Sunset header；迁移表文档合入。
- [ ] revoke spine 有 Fake CA 行为测试（真实 backend 调用 + 拒绝分类）。
- [ ] OpenAPI 双向校验进入常规测试集，豁免清单显式且非空需说明理由。
- [ ] v0.9.0 审计第 7 条"仍缺 PATCH stub"与"建议后续顺序"第 1 条对应项可标记关闭。
