# T15：证书验收报告与 CA 能力消费

**任务性质**：签发内核验收强化（T04/T08 验收缺口）
**前置依赖**：无（基于已合并的 `VerifyCertificateStep` 与 `CaCapabilities`）
**主要后继**：T19（真实 CA 上运行验收报告）
**建议改动范围**：`src/workflow/issuance.rs`、`src/ca_backend/types.rs`、`src/domain/`（报告模型）、`src/repository/`、`src/server/api_v1.rs`、`src/certificate/ocsp.rs`（处置）、tests、docs

---

## 1. 背景与当前问题

v0.9.0 审计（第 6 条，"部分修复"）确认：

1. `VerifyCertificateStep`（`src/workflow/issuance.rs`）目前只做 SAN 精确匹配 + 有效期窗口校验。缺失项：
   - 链信任验证（对配置的信任锚）；
   - profile 合规（如 `short_lived` 的有效期上限、算法白名单）；
   - 公钥一致性（证书公钥 vs CSR/KeyProvider 公钥）。
2. `CaCapabilities::supports_identifier_type`（`src/ca_backend/types.rs`）已定义且有单元测试，但**没有任何生产调用点**——向仅支持 dns 的 CA 提交 IP intent 只会在 CA 侧报错，而不是计划期终态拒绝。
3. 私网/保留地址策略缺失：为私网/保留 IP 申请公网证书没有策略闸门。
4. `src/certificate/ocsp.rs` 是模拟实现（仅校验 AIA URL 形状即返回 `Good`）。v0.9.0 非目标明确禁止将其包装为生产状态；处置（删除或真实实现）一直悬置。
5. 目标架构 §20 完成定义要求"所有 Active CertificateVersion 都有完整验证报告"——当前报告既不完整也未持久化。

---

## 2. 目标

1. **`CertificateVerificationReport` 完整结构**（版本化序列化 + 兼容测试）：
   - 每项检查为 `{ check, status: pass|fail|not-checked, detail }`；
   - 覆盖：SAN 精确匹配、有效期窗口、链信任、profile 合规、密钥一致性、identifier 能力预检；
   - 整体结论 `accepted | rejected`，rejected 必须关联稳定 error code 并区分 terminal。
2. **链信任验证**：信任锚来自 CA 配置（Pebble 测试根、LE staging ISRG Root X1/X2 等）；校验链构建、SAN/IP 匹配、有效期；`not-checked` 仅允许在显式配置跳过时出现（默认不允许）。
3. **profile 合规**：对照 CA profile 声明校验有效期上限与算法（T04 已有 profile/short_lived 元数据）。
4. **密钥一致性**：Managed Key 场景断言证书公钥 == KeyProvider 公钥；External CSR 场景断言证书公钥 == CSR 公钥。不一致为终态拒绝（防 CA 错发/响应被替换）。
5. **`supports_identifier_type` 消费**：Plan/预检阶段消费 CA 能力——IP intent 提交给仅 dns 的 CA 在计划期终态拒绝，携带稳定 error code；能力未知时行为显式（保守放行至 CA，或按配置保守拒绝，二选一并记录决策）。
6. **私网/保留地址策略**：默认拒绝为私网/保留/环回 IP 签发公网证书；提供显式配置豁免（记录豁免原因于报告）。
7. **报告持久化与暴露**：报告挂接到 CertificateVersion（或 Operation 详情），`GET /api/v1/certificate-versions/{id}` 返回；不含私钥。
8. **OCSP 处置决策**：本任务内完成并记录——默认方案为删除模拟实现与公共导出（LE 生态已转向 CRL；保留模拟只会制造假能力），若决定实现真实检查则单独立任务承接。决策与理由写入文档。

---

## 3. 非目标

- 不实现 CRL/OCSP 真实吊销状态检查（若决策保留，另立任务）。
- 不做 CT log 存在性校验（SCT 解析与监控超出收口范围）。
- 不改变 VerifyCertificate 失败后的重试语义（验收失败是终态；传输类失败仍按现有分类）。
- 不在报告中断言 CA 侧业务属性（如 rate limit 状态）。

---

## 4. 设计要点

- 报告属于新公共面：进入 v0.10.0 冻结清单（README 第 8 节），首日即带序列化兼容测试；新增字段必须可被旧读者忽略。
- 链验证依赖 `aws-lc-rs`/`ring` 双 feature 下可用（遵循现有 crypto feature 约定）；信任锚配置引用 PEM 文件路径（SecretRef 不适用——证书非机密，但路径需存在性校验）。
- `not-checked` 语义必须窄：仅"配置显式跳过"与"该 CA 无 profile 声明"两种来源，其余一律 pass/fail，防止报告退化为装饰。
- 能力预检失败发生在 Plan 阶段（不产生 CA Order），这是与"CA 拒绝后再失败"的关键行为差异，测试需覆盖两者。

---

## 5. 实施步骤

1. 定义 `CertificateVerificationReport` 域模型 + 序列化兼容测试。
2. 扩展 `VerifyCertificateStep`：链信任、profile、密钥一致性三项检查接入，构造报告并持久化。
3. Plan/预检接入 `supports_identifier_type`；补私网/保留地址策略与配置。
4. API 暴露报告；OpenAPI 与文档更新。
5. 测试：fake CA 全绿报告；篡改证书（错 SAN/断链/换公钥/超期）逐项 fail 断言；IP 能力拒绝路径；`not-checked` 仅来自允许来源。
6. OCSP 处置执行 + 决策记录；`UNIMPLEMENTED_FEATURES.md` 对应备注更新。

---

## 6. 验证方法

```bash
cargo test workflow
cargo test issuance_spine
cargo test --test api_test
cargo check --all-features && cargo check --no-default-features
```

---

## 7. 验收标准

- [ ] 报告六类检查齐备且持久化；`GET /api/v1/certificate-versions/{id}` 可查（无私钥泄漏）。
- [ ] 篡改证书场景（错 SAN、断链、公钥不一致、超有效期、违反 profile）全部终态拒绝且报告逐项可解释。
- [ ] IP intent 对仅 dns CA 在计划期被拒，不产生 ACME Order；有测试。
- [ ] 私网/保留 IP 默认拒绝、显式豁免生效；豁免记录于报告。
- [ ] `supports_identifier_type` 至少有一个生产调用点（非仅测试）。
- [ ] OCSP 模拟实现已删除或决策已记录；文档不再含糊描述该能力。
- [ ] 报告有序列化兼容测试；v0.9.0 审计第 6 条可标记关闭。
