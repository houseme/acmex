# T19：Let's Encrypt Staging 与真实 CA 特性实测

**任务性质**：L5 受控外部验证（发布证据）
**前置依赖**：T13（harness 经验与脚本模式）、T14（EAB，硬）；T15（验收报告）、T16（传播策略）、T20（live zone harness，软——未就绪时 DNS-01 可降级为 HTTP-01 并显式记录）
**主要后继**：T21（发布）
**建议改动范围**：`scripts/run_le_staging.sh`（新增）、`tests/le_staging.rs`（新增，环境门控）、`docs/roadmap/v0.9.0/{RELEASE_CHECKLIST,KNOWN_LIMITATIONS,FEATURE_MATRIX}.md` 更新、docs

---

## 1. 背景与当前问题

v0.9.0 KNOWN_LIMITATIONS 明确：

- Let's Encrypt staging 从未验证；ARI `replaces`、profiles（含 short-lived）、IP 标识符均无真实 CA 证据。
- IP 标识符只有域策略单测，外部 CA 对 IP 的实际行为未验证（RELEASE_CHECKLIST 的 IPv4/IPv6 各两行未勾选）。
- FEATURE_MATRIX 中 `google-ca`、`zerossl-ca` 的 external evidence 均为 "not yet validated"（两者都要求 EAB，且 T14 前根本无法注册）。

T04/T09 的 ARI 实现（`DirectoryAriProvider`、`replaces` 下发）与 T15 的验收报告，都需要至少一个真实 CA 上的运行证据，才能把"实现正确"升级为"行为验证"。

---

## 2. 目标

在**受控测试资产**（自有域名、隔离 IP、staging 环境）上完成以下证据，全部可复现、留档：

1. **LE staging 冒烟（主路径）**：
   - HTTP-01 与 DNS-01（DNS-01 依赖 T20 live zone；未就绪则显式降级）各完成一次：intent → order → challenge → finalize → 验收报告（T15）→ File sink 部署 → 激活；
   - 续签一次：验证 ARI 窗口获取（或显式记录 CA 未通告时的 fallback）、`replaces` 提交被接受、旧版本 superseded。
2. **profiles**：对支持 profile 的 CA（LE 的 profile 头或 ZeroSSL/Google 等价物）验证 profile 选择生效：证书有效期/算法与 profile 声明一致；`short_lived` profile 若可用则纳入（对应 160 小时证书的续签节奏观察）。
3. **IP 标识符（RFC 8738）**：LE 已 GA IP 证书——在受控 IPv4 与 IPv6 地址上完成 HTTP-01 与 TLS-ALPN-01 各一次，勾选 RELEASE_CHECKLIST 的 IPv4/IPv6 行；失败则记录 CA 侧行为差异（如 ALPN 要求、限制条款）。
4. **EAB CA 验证（依赖 T14）**：ZeroSSL 或 Google Trust Services staging（或 LE EAB 账户）完成注册 + 一次签发，勾选 FEATURE_MATRIX 对应行；EAB 凭据经环境注入。
5. **badNonce/限流行为抽样**：staging 的重复 nonce 拒绝与 rate limit 响应（429 + Retry-After）在真实服务器上的行为与 T04 分类一致（抽样即可，不压测）。
6. **文档对齐**：RELEASE_CHECKLIST "Let's Encrypt staging smoke completed" 勾选；KNOWN_LIMITATIONS 移除对应条目；FEATURE_MATRIX external evidence 列更新并附证据链接。

---

## 3. 非目标

- 不使用生产（非 staging）CA 签发。
- 不进入公共 PR CI（手动/受控触发；staging rate limit 与测试资产限制决定频度）。
- 不做压测或配额探测（rate limit 只做行为抽样）。
- 不把 staging 行为外推为所有 CA 的行为（每个结论标注来源 CA）。

---

## 4. 设计要点

- **凭据纪律**：staging 账户、EAB kid/HMAC、DNS API token 一律经 SecretRef/环境注入；脚本与测试代码中不得出现任何真实值；secret-scan 覆盖本任务产物。
- **脚本模式沿用 T13**：`RUN_LE_STAGING=1` 门控、环境探测（域名解析权、IP 归属、目录可达性）、缺环境 exit 77 + 原因；证据存档（测试输出 + 证书指纹/有效期摘要，不存私钥）。
- **可重复性**：测试资产清单（域名、IP、账户）以 runbook 描述；任何人按 runbook 可重跑。
- **验收报告联动**：staging 证书必须走完整 T15 报告（信任锚为 LE staging 根），证明报告在真实链上可用——这是 T15 的最终验证场。
- **降级显式化**：T20 未就绪时的 HTTP-01-only、profile 不可用、IP 不可申请等任何降级都必须写入证据文档，不得静默缩小范围。

---

## 5. 实施步骤

1. 准备 runbook：staging 目录、测试域名与 IP、EAB 凭据获取方式、环境变量约定。
2. 编写环境门控测试（场景按节 2 展开）与 `scripts/run_le_staging.sh`。
3. 执行并归档证据；失败项归因（客户端 bug → 修复回归；CA 行为差异 → 记录并调整能力声明）。
4. 更新 RELEASE_CHECKLIST / KNOWN_LIMITATIONS / FEATURE_MATRIX。
5. 若发现客户端缺陷：修复必须带回本地测试（fake CA 或 Pebble 复现），不允许只修不测。

---

## 6. 验证方法

```bash
RUN_LE_STAGING=1 scripts/run_le_staging.sh   # 具备测试资产的环境
# 无环境：脚本 exit 77；默认 cargo test 集不受影响
cargo fmt --all --check && cargo check --all-features
```

---

## 7. 验收标准

- [ ] LE staging HTTP-01（及 DNS-01 或显式降级记录）全流程留档：签发、验收报告、部署、激活。
- [ ] 续签证据：ARI 窗口与 `replaces` 行为（或 CA 未通告时的 fallback 记录）、旧版本 superseded。
- [ ] IPv4/IPv6 × HTTP-01/TLS-ALPN-01 证据完成，或失败行为差异被完整记录（RELEASE_CHECKLIST 对应行有结论）。
- [ ] 至少一个 EAB CA（ZeroSSL/Google/LE EAB）注册+签发证据；FEATURE_MATRIX 更新。
- [ ] profile 行为证据（选择生效、有效期/算法一致）或不可用性记录。
- [ ] 全部凭据无入库；secret-scan 通过。
- [ ] runbook 与证据存档在任务文档中链接。
