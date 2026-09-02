# T13：Pebble E2E Harness 与真实进程验证

**任务性质**：测试基础设施与发布门槛（L4）
**前置依赖**：无（复用 T12 的脚本骨架与 `server::worker` 装配）
**主要后继**：T19（真实 CA staging）、T21（发布）
**建议改动范围**：`scripts/`、`tests/e2e_pebble.rs`（新增）、`docker/pebble/`（新增，compose 与配置）、`.github/workflows/`、`src/dns/`（challtestsd presenter 适配，test-only）、docs

---

## 1. 背景与当前问题

T12 建立了发布门槛的骨架，但 Pebble 侧从未落地：

1. `scripts/run_pebble_e2e.sh` 在设置 `RUN_PEBBLE_E2E=1` 时也只运行 fake-adapter fault-injection 套件——仓库中没有任何启动 Pebble、接线 WFE 目录、驱动真实签发的实现（`E2E_RELEASE_GATES.md` "Known boundary" 一节明确记录）。
2. v0.9.0 RELEASE_CHECKLIST 的 Required E2E Evidence 区（三类 Challenge、真实 executor 重启矩阵、sink 回滚）全部未勾选。
3. 现有 `tests/e2e_restart_matrix.rs` 使用幂等 fake 外部账本证明重试不重复创建逻辑资源，但不是"真实 CA/DNS/sink adapter"上的重启演练。
4. 第二轮批次补齐的 `src/workflow/issuance.rs` 真实 executor 与 `src/server/worker.rs` 生产装配，只被 `tests/issuance_spine_test.rs`（进程内 fake CA）覆盖，从未在真实 ACME 服务器上运行过。

本任务的目标是把"环境门控的 Pebble E2E"从占位脚本变成可重复执行的 L4 发布门槛。

---

## 2. 目标

1. **可重复的 Pebble 环境**：compose 或等价脚本拉起 `pebble` 与 `pebble-challenge-test-server`（challtestsd），固定 `PEBBLE_VA_NOSLEEP=1`、`PEBBLE_VA_ALWAYS_VALID=0`，暴露 WFE 目录（默认 `https://127.0.0.1:14000/dir`）与 challtestsd 管理 API（`:8055`）。
2. **三类 Challenge 的真实签发**：
   - HTTP-01：经 challtestsd HTTP 模式回写验证文件；
   - DNS-01：经 challtestsd DNS API 的 test-only presenter（`/set-txt`、`/clear-txt`），走与生产相同的 PropagationObserver 路径；
   - TLS-ALPN-01：经 challtestsd TLS 模式或本地 edge presenter。
3. **全生命周期**：签发 → 验收 → File sink 部署 → 激活；续签（验证 `replaces` 提交与旧版本 superseded）；吊销（`SubmitRevocationStep` 真实生效）。
4. **真实 executor 重启演练**：至少在 CreateOrder 后、传播确认后、Finalize 后三个窗口终止并重启进程，证明恢复不产生重复 Order/重复 TXT 记录/重复部署。
5. **脚本语义**：`RUN_PEBBLE_E2E=1` 且环境可用时真实执行；环境缺失时保留 exit 77 与显式跳过原因。
6. **CI**：环境门控的 pebble job（手动触发或 nightly，不在 PR 必跑集）与 secret-scan job。
7. **证据存档**：定义输出存档约定（测试输出、Pebble 日志位置），供 RELEASE_CHECKLIST 勾选时引用。

---

## 3. 非目标

- 不在公共 PR CI 强制执行（时间与稳定性由门控管理）。
- 不覆盖真实公网 DNS 传播（那是 T20 的 live zone 范围；challtestsd 是本地假权威）。
- IP 标识符验证以 Pebble 所用版本能力为准：Pebble 支持 RFC 8738 IP 标识符，若环境可用则纳入 HTTP-01/TLS-ALPN-01 的 IP 场景，否则记录跳过原因，真实 CA 的 IP 证据归 T19。
- 不做多实例并发（归 T20）。
- 不通过放大 timeout 掩盖不稳定；间歇失败必须归因。

---

## 4. 设计要点

### 4.1 单一装配来源

Harness 必须复用 `server::worker::build_engine_from_config`（与 server/CLI/lib 相同装配路径），通过一份指向 Pebble 的 `acmex.toml`（测试 fixture）驱动。禁止为测试另写旁路签发管线——那会使门槛失去意义。

### 4.2 CA 信任与目录接线

- Pebble 使用自签测试根；证书验收（`VerifyCertificateStep`）需接受经配置注入的测试信任锚，不得为测试全局关闭校验。
- `PEBBLE_WFE_NONCEREJECT`（如设为 2）可强制 badNonce 路径，用于验证 T04 的 nonce 重试在真实服务器行为下成立。
- Pebble 支持 EAB 与 IP 标识符；EAB 端到端验证主要在 T14 实现后纳入（本任务可先预留配置位）。

### 4.3 DNS-01 presenter 适配

challtestsd presenter 实现 `DnsProvider`/presenter 端口（create/find/delete 语义映射到 `/set-txt`、`/clear-txt`），以 `#[cfg(test)]` 或独立 feature（如 `e2e-pebble`）编译，不进入默认构建。清理路径（Challenge Cleanup Scanner）必须对 challtestsd 记录同样生效。

### 4.4 重启演练形态

真实进程形态优先：以子进程方式启动 `acmex`（server 或 CLI `obtain --wait`），在选定窗口 kill 后重新拉起，断言最终状态与外部副作用唯一性。若子进程编排成本过高，允许降级为"同进程内重建引擎 + 独立 Repository"，但必须在证据中显式声明降级程度。

---

## 5. 实施步骤

1. 新增 `docker/pebble/`（compose 文件、环境变量、健康检查）与 `scripts/` 下的环境准备/探测函数（docker 可用性、端口占用检查）。
2. 新增 challtestsd presenter 适配与测试信任锚配置注入。
3. 编写 `tests/e2e_pebble.rs`：环境门控（无环境时 `#[ignore]` 或早退 exit 77 语义），场景按节 2 矩阵展开。
4. 重写 `scripts/run_pebble_e2e.sh`：环境准备 → 运行测试 → 输出存档路径。
5. 增加 CI workflow：`pebble`（workflow_dispatch/nightly）与 `secret-scan`（扫描仓库与测试输出无明文凭据模式）。
6. 更新 `E2E_RELEASE_GATES.md`、RELEASE_CHECKLIST 对应行与证据链接；KNOWN_LIMITATIONS 移除已验证条目。

---

## 6. 验证方法

- 本地具备 Docker 时：`RUN_PEBBLE_E2E=1 scripts/run_pebble_e2e.sh` 全绿并产出存档。
- 无环境时：脚本 exit 77 且原因明确；`cargo test` 默认集不受影响。
- `cargo check --no-default-features` 证明 test-only 适配不污染默认构建。

---

## 7. 验收标准

- [ ] HTTP-01、DNS-01、TLS-ALPN-01 三类 Challenge 在 Pebble 上完成真实签发并留档。
- [ ] 续签（含 `replaces` 与旧版本 superseded）与吊销在 Pebble 上验证。
- [ ] 重启演练覆盖至少三个窗口，外部副作用唯一性有断言。
- [ ] File sink stage/activate/health/rollback 至少一条失败回滚场景被覆盖（对应 checklist 行）。
- [ ] CI pebble job 与 secret-scan job 合入（可手动触发）。
- [ ] `E2E_RELEASE_GATES.md` 的 "Known boundary" 段落移除或改写为已实现描述；RELEASE_CHECKLIST Required E2E Evidence 区可勾选并附证据。
- [ ] 证据存档位置在任务文档中链接。
