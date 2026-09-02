# T20：生产基础设施实测与多实例证据

**任务性质**：L5 受控外部验证（发布证据）
**前置依赖**：无硬代码依赖（T10/T11/T02 代码已合并）；建议在 T18 后执行（演练带完整观测信号）
**主要后继**：T21（发布）
**建议改动范围**：`tests/`（`#[ignore]` 契约与演练测试）、`scripts/run_live_infra.sh`（新增）、`src/repository/`（Redis live 契约缺口）、`src/delivery/`（如暴露配置缺口）、docs（failover 范围文档）

---

## 1. 背景与当前问题

RELEASE_CHECKLIST "Explicit External Evidence" 区的剩余行与 FEATURE_MATRIX 的 external evidence 列确认以下欠账，且 v0.9.0 审计在多处标注"真实环境未执行"：

1. **Live DNS provider**：11 个 provider 全部只有 compile-gate 与 legacy 适配器接线；`#[ignore]`/手动契约从未在隔离 zone 上执行（"At least one live DNS provider zone completed" 未勾选）。
2. **Redis repository**：T02 审计明确"Redis repository 合同测试属于后续扩展"；RELEASE_CHECKLIST 要求 "Redis repository failover scope documented"。
3. **远端 Sink**：File sink 与 fake agent 有本地契约，HttpAgentSink 有本地 fake agent 契约；但 Kubernetes、Vault、真实远端 agent 环境均未验证（"Kubernetes/Vault/agent sink scope documented" 未勾选）。
4. **多实例**：T11 的分布式 Lease 只有单进程测试；"多实例 fencing 的真实多进程演练待 T12 环境"（审计 T11 行），从未有两个真实进程并发操作的证据。
5. 目标架构 §17.4 故障注入清单中"Redis 暂时不可用、并发 CAS 冲突""系统时间跳变和调度器重复扫描"在真实组件上未演练。

---

## 2. 目标

1. **Live DNS provider 契约**：
   - 为契约测试提供环境门控入口（`#[ignore]` + `RUN_LIVE_DNS_<PROVIDER>=1` + 凭据经环境/SecretRef）；
   - 至少在 **Cloudflare 与 Route53 各一个隔离 zone** 上完整执行 create/find/delete/idempotency（含删除后重建、重复删除幂等）；
   - 传播确认配合 T16 策略真实运行（权威 NS 查询）；
   - 其余 provider 保留门控入口与 runbook，按资产可用性执行并如实记录。
2. **Redis repository live 契约**：
   - 对真实 Redis（docker 或受控实例）运行与 File/Memory 相同的 repository 契约套件；
   - **failover 范围文档**：连接丢失/超时期间的行为（CAS 结果未知时的重试语义、Operation 状态不回退、恢复后 resume）、数据持久性边界（AOF/RDB 差异说明）、以及"哪些故障需要人工介入"清单。
3. **远端 Sink 实测（至少两项）**：
   - Kubernetes Secret sink（kind 或受控集群）：stage/activate/health/rollback 全契约；
   - Vault KV sink（dev server 或受控实例）：同上；
   - 真实远端 agent（与 HttpAgentSink 协议一致的可执行 agent 部署于独立进程/主机）：部署、健康、回滚；
   - 每项产出 "scope documented"：支持的资源形态、权限要求、已知限制。
4. **双进程 fencing 演练**：
   - 两个真实 `acmex` 进程（File repository 共享目录，或 Redis）对同一 lineage 并发续签：断言仅一个完成 ACME 续签与部署激活，另一个观察到 lease/CAS 冲突并安全退出重试；
   - 并发部署同一 version：仅一次 stage/activate 生效于 sink；
   - 时钟偏差场景：调度器重复扫描（同刻双扫描）不产生重复副作用；
   - 演练全程有 T18 指标/trace 截获，作为观测完整性的附带证据。
5. **文档对齐**：RELEASE_CHECKLIST 剩余 external 行勾选；FEATURE_MATRIX `redis` 行与 sink 相关状态更新；KNOWN_LIMITATIONS 移除已验证条目。

---

## 3. 非目标

- 不做性能压测（性能基线另有门槛）。
- 不要求全部 11 个 DNS provider 都有 live run（至少 Cloudflare+Route53；其余按资产可用性，未执行者如实留在 FEATURE_MATRIX）。
- 不引入新的 Sink 类型（只验证既有实现的实环境行为）。
- 不演练跨机房/多区域部署拓扑（单环境双进程足以证明 fencing 语义）。

---

## 4. 设计要点

- 所有 live 契约测试与 T13/T19 相同的纪律：环境门控、缺环境 exit 77/`#[ignore]`、凭据不入库、证据存档、secret-scan 覆盖。
- 隔离 zone 纪律：只操作专用于测试的 zone（前缀如 `_acme-challenge-acmex-test.<zone>`），测试结束断言无记录残留（残留即失败，呼应 challenge 最终清理承诺）。
- 双进程演练的判定标准写在测试断言里（唯一 ACME order/唯一激活），不靠事后人工比对日志。
- Redis failover 文档必须区分"协议保证"（CAS 冲突可检测）与"部署保证"（持久化配置建议），避免把应用层语义写成运维承诺。

---

## 5. 实施步骤

1. live DNS 契约 harness（provider 参数化、zone 清理断言）+ Cloudflare/Route53 执行与存档。
2. Redis repository 契约在真实实例上跑通；failover 行为测试（kill Redis 中途 + 恢复）与文档。
3. K8s/Vault/agent sink 实测（kind/dev vault/独立 agent 进程）与 scope 文档。
4. 双进程 fencing 与时钟偏差演练测试。
5. 更新 RELEASE_CHECKLIST / FEATURE_MATRIX / KNOWN_LIMITATIONS；审计 T02/T10/T11 行对应缺口勾销。

---

## 6. 验证方法

```bash
RUN_LIVE_DNS_CLOUDFLARE=1 ... cargo test --test dns_provider_contract -- --ignored
RUN_REDIS=... cargo test --test repository_contract -- --ignored
scripts/run_live_infra.sh    # 编排上述门控入口
# 无环境：全部显式跳过；默认测试集不受影响
```

---

## 7. 验收标准

- [ ] Cloudflare 与 Route53 隔离 zone 契约通过且无记录残留断言；其余 provider 状态如实记录。
- [ ] Redis repository live 契约通过；failover 范围文档合入（RELEASE_CHECKLIST 对应行勾选）。
- [ ] K8s、Vault、远端 agent 至少两项实环境契约通过；各项 scope 文档合入。
- [ ] 双进程并发续签/部署演练通过（唯一副作用有测试断言）；时钟偏差扫描无重复副作用。
- [ ] 全部凭据无入库；secret-scan 通过；证据存档在任务文档中链接。
- [ ] FEATURE_MATRIX 与 KNOWN_LIMITATIONS 与事实一致。
