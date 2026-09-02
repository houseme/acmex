# T14：EAB 与账户生命周期收口

**任务性质**：协议完备性与 T04 验收缺口收口
**前置依赖**：无（基于已合并的 T04 代码）
**主要后继**：T19（EAB CA staging 实测）
**建议改动范围**：`src/ca_backend/`（backend、session、types）、`src/application/`、配置 schema、`tests/ca_backend_test.rs`、`tests/issuance_spine_test.rs`、docs

---

## 1. 背景与当前问题

v0.9.0 审计（第 4 条）确认：

1. **EAB 为 stub**：`src/ca_backend/backend.rs` 中 `AccountRef::resolve_eab_hmac` 恒返回 `None`。这意味着所有要求 External Account Binding 的 CA（ZeroSSL、Google Trust Services，以及启用了 EAB 的 Let's Encrypt 账户）在 v0.9.0 管线下无法注册——T06 修复了全部 11 个 DNS provider 的凭据接入，但 CA 侧账户凭据仍是空转。
2. **Account Key Rollover 未实现**：RFC 8555 §7.3.5 的 keyChange 资源只存在于旧栈（`src/account/key_rollover.rs`），新 `ca_backend` 无对应能力；审计将其列为 T04 遗留。
3. **双 JWS 栈并存**：旧 `AcmeClient`（protocol 层）与新 `ca_backend` 各自实现 JWS 签名/nonce 处理。目标架构 §18 要求"保留 `AcmeClient` 作为低层兼容 API，但新能力通过 Application Service 提供"，目前缺一条明确的收敛路径，双栈漂移风险持续存在。

---

## 2. 目标

1. **EAB 全链路**：
   - `ExternalAccountBindingRef` 经 `SecretResolver` 解析 HMAC key（支持 `env:`/`file:`/`vault:`，与 T11 SecretRef 约定一致），拒绝明文。
   - 注册请求按 RFC 8555 §7.3.4 构造 `externalAccountBinding`（payload 内嵌 JWS：以 EAB MAC key 签名，`kid` 为 CA 侧 key identifier，`url` 为 account 资源 URL）。
   - 配置面：`[ca.eab]`（kid + SecretRef）进入配置 schema、`acmex init` 模板与文档。
2. **Account Key Rollover**：
   - `ca_backend` 实现 keyChange：旧账户 key 签内层 payload（含 `oldKey` JWK 与 account URL），新 key 签外层 JWS。
   - 账户 key 存储经 KeyProvider/FileSecretStore 原子轮换：先在 CA 确认 keyChange 成功，再提交本地存储切换；失败时本地保留旧 key（禁止出现 CA 与本地不一致的中间态提交）。
   - 暴露为 Application Service 用例与 API/CLI 操作（触发式，不自动轮换）。
3. **JWS 栈收敛决策与执行**：
   - 旧 `AcmeClient` 保持兼容 facade：公共 API 不删除，内部逐步委托 `ca_backend`（或经适配层复用其 nonce/JWS 实现），并标注弃用时间表（与 T17 的 legacy `/api` 弃用联动）。
   - 本任务至少完成：消除重复实现中的行为分歧（badNonce、Retry-After、错误分类以 `ca_backend` 为准），旧栈缺陷修复直接委托而非双写。
4. **测试**：fake CA 契约覆盖 EAB 注册（正确 MAC、错误 MAC、缺失 kid 的分类）与 rollover（成功、CA 拒绝、本地不切换）；Pebble 上验证 EAB 注册与 rollover（Pebble 支持 EAB）。

---

## 3. 非目标

- 不自动定期轮换账户 key（仅提供触发式用例；策略化轮换留待有需求证据后立项）。
- 不移除旧 `AcmeClient` 公共 API（只做委托收敛与弃用标注）。
- 不在本任务内做真实 EAB CA 注册（归 T19，但契约测试必须先就绪）。
- 不引入多账户池/账户复用调度。

---

## 4. 设计要点

- EAB MAC 计算遵循 RFC 8555 §7.3.4：HMAC-SHA256(key, ASCII(accountURL)) 作为内层 JWS 签名；`alg` 取决于 CA（HS256 为主）。
- `resolve_eab_hmac` 的签名从 `Option<Vec<u8>>` 演进为注入 `SecretResolver` 的实现时，注意它属于 ca_backend 内部 trait 方法，不在 v0.9.0 冻结面内，但仍需序列化兼容审查（`ExternalAccountBindingRef` 若持久化于账户实体）。
- rollover 的幂等性：keyChange 失败重试不得把 CA 拒绝视为可无限重试（区分 retryable/terminal）；本地存储写入使用原子替换 + 旧 key 保留一个周期（便于诊断，不作为回滚依据——CA 侧状态不可回滚）。
- 审计与日志：EAB HMAC 值、账户 key PEM 不得进入任何日志/指标/trace（遵守 T11 约定）；事件审计记录 rollover 成功/失败。

---

## 5. 实施步骤

1. `ca_backend` 账户创建路径接入 `SecretResolver`，实现真实 `resolve_eab_hmac`；补配置 schema 与 `acmex init` 模板。
2. fake CA 契约测试：EAB 正确/错误/缺失三分支；序列化兼容测试更新。
3. 实现 keyChange（backend + session 两层）与 Application Service 用例、API/CLI 接线。
4. fake CA + Pebble 的 rollover 行为测试（成功/拒绝/本地一致性断言）。
5. 旧 `AcmeClient` 委托收敛第一步：nonce/JWS/错误分类统一到 `ca_backend` 实现，双栈行为差异清单归档。
6. 文档更新：MULTI_CA/协议文档中的 EAB 说明、审计文档对应条目勾销。

---

## 6. 验证方法

```bash
cargo test ca_backend
cargo test issuance_spine
cargo check --all-features && cargo check --no-default-features
RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh   # EAB/rollover 场景（依赖 T13 harness）
```

---

## 7. 验收标准

- [ ] 配置了 `[ca.eab]` 的账户在 fake CA 与 Pebble 上注册成功；错误 MAC/kid 返回稳定 error code 且分类为 terminal。
- [ ] 未配置 EAB 时行为与现状一致（不回归 LE staging 类无 EAB 路径）。
- [ ] Account Key Rollover 在 fake CA 与 Pebble 上成功；CA 拒绝时本地 key 不变，且有终态错误。
- [ ] 配置、模板、文档中的 EAB 凭据均为 SecretRef 形式，明文 secret 被拒绝（有测试）。
- [ ] 双 JWS 栈的行为分歧清单归档，nonce/JWS/错误分类单源化。
- [ ] v0.9.0 审计第 4 条（EAB stub / rollover / facade）可标记关闭。
