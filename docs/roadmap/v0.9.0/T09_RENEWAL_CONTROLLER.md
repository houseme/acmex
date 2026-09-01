# T09：ARI 驱动续签控制器

**任务性质**：证书续签生命周期
**前置依赖**：T02、T03、T04、T08；部署完成判定与 T10 对接
**主要后继**：T11、T12
**建议改动范围**：`src/renewal/`、`src/scheduler/`、Workflow、Repository、metrics

---

## 1. 背景与当前问题

当前存在 SimpleRenewalScheduler、AdvancedRenewalScheduler 和 CertificateRenewer 三套路径：

- Simple 以固定 30 天窗口工作。
- Advanced 扫描时把所有证书入队，不检查有效期。
- Server 只启动队列消费者，没有周期扫描。
- Advanced 续签忽略 store，新证书不持久化。
- CertificateRenewer 只记录日志，不触发真实签发。

对 160 小时 IP/短周期证书，固定提前 30 天模型完全不适用。本任务将三套路径收敛为一个 Renewal Controller。

---

## 2. 目标

1. 建立 Lineage 级 Renewal Decision。
2. 优先使用 RFC 9773 ARI，支持 fallback 和稳定 jitter。
3. 周期扫描只创建 Renewal Operation，不直接执行 ACME。
4. 通过 Lease 防止多实例重复续签。
5. 根据有效期、ARI、失败历史、证书类型计算优先级。
6. 新版本持久化并完成必需部署后才更新 active version。
7. 替换现有三套续签实现。

---

## 3. 非目标

- 不在 Scheduler 内直接调用 DNS/HTTP/TLS。
- 不把“旧证书即将过期”当成允许覆盖旧文件的理由。
- 不实现任意 shell Hook；通知和部署走 Outbox/Sink。

---

## 4. Renewal Decision

```rust
pub struct RenewalDecision {
    pub lineage_id: LineageId,
    pub source: RenewalWindowSource,
    pub window_start: Timestamp,
    pub window_end: Timestamp,
    pub selected_at: Timestamp,
    pub safety_deadline: Timestamp,
    pub priority: RenewalPriority,
    pub reason: RenewalReason,
}
```

Window source 优先级：

1. ARI suggestedWindow。
2. Intent 显式窗口。
3. 证书生命周期百分比。
4. 旧固定天数兼容配置。

### Fallback 百分比

推荐默认在证书生命周期经过三分之二后进入窗口，具体值配置化。不能假定所有证书 90 天。

### Jitter

- 在窗口内基于 `lineage_id + active_version_id` 计算稳定随机点。
- 重启后同一证书选择时间不变化。
- 手动 force renewal 跳过窗口但必须记录审计和速率风险。

---

## 5. 扫描器

扫描器定期查询 Active Lineage：

1. 读取 active CertificateVersion。
2. 校验证书时间和 Repository 状态。
3. 查询/缓存 ARI；失败时应用 fallback。
4. 计算 RenewalDecision。
5. 若到达 selected_at 且没有 active renewal operation，尝试获取 Lineage Lease。
6. 创建 Renewal Operation。
7. 写审计 Outbox。

要求：

- 分页扫描。
- 多实例安全。
- 不在一个扫描周期内加载全部证书。
- 系统时间回拨/跳跃有保护。
- 每个 CA 有独立并发与 rate budget。

---

## 6. 优先级

建议：

- Critical：已过 safety deadline 或部署中无健康版本。
- Urgent：剩余有效期不足最小人工处置窗口。
- High：已进入 ARI 窗口后半段。
- Normal：达到 selected_at。
- Low：预取 ARI、预检查配置，不创建签发。

优先级不能只看“剩余天数”，必须适配小时级证书。

---

## 7. Renewal Workflow

Renewal 与初次签发共享核心 Step，但增加：

- 读取 active version 和 replaces 信息。
- 根据 KeyPolicy 决定复用或轮换 key。
- 创建 Order 时携带 profile/replaces。
- 新版本验证时比较 Intent，而不是复制旧证书字段。
- 保存新 Version，状态为 Issued/Inactive。
- 创建 required Deployment 子 Operation。
- 所有 required Sink 健康后 CAS 切换 active version。
- 标记旧版本 superseded。

如果部署失败：

- 保留新版本，不重复签发。
- 重试 Deployment。
- 旧版本仍 Active，除非已经过期；过期时进入 Critical 告警。

---

## 8. 多实例 Lease

- Lease key 为 Lineage ID。
- 获取 Lease 时生成 fencing token。
- Operation 创建和 Lease 持有状态原子关联。
- Lease 续约失败后 Worker 停止推进。
- 旧 token 不能切换 active version。
- 手动 renewal 和自动 renewal 使用同一 Lease，避免竞争。

---

## 9. Retry 策略

- badNonce 在 CA Backend 内处理。
- CA 429 严格遵守 Retry-After。
- Challenge 传播失败按 Provider/Observer 策略重试，必要时创建新 Order。
- terminal policy 错误不自动无限重试。
- 凭据错误进入 OperatorActionRequired。
- 每次失败重新计算是否仍在安全窗口。
- 到达 safety deadline 后升级告警，但不提高到违反 CA rate limit 的无界重试。

---

## 10. 短周期/IP 策略

- 160 小时证书扫描间隔必须按小时或更高频率配置。
- ARI 刷新频率遵守 Retry-After。
- 至少保留多个续签尝试窗口和人工处置余量。
- 指标统一使用秒/时间戳，不只使用 days_left。
- 测试使用虚拟时钟推进，不实际等待数小时。

---

## 11. 兼容和迁移

- `SimpleRenewalScheduler`、`AdvancedRenewalScheduler` 和 `CertificateRenewer` 标记 deprecated。
- `RenewalScheduler::run_once()` 可作为新 Controller `scan_once()` 的兼容 facade。
- 旧 `renew_before_days` 转换为 fallback policy，不再是唯一窗口。
- 旧 hook 迁移为 Outbox Event Consumer 或 Sink，不直接在 Worker 执行任意命令。

---

## 12. 实施步骤

1. 定义 RenewalDecision、WindowSource、Priority、Reason。
2. 实现 ARI + fallback + stable jitter 计算器。
3. 实现分页 Scanner 和 Lineage Lease。
4. 实现 Renewal Operation 创建去重。
5. 扩展签发 Workflow 支持 replaces、KeyPolicy、新 Version。
6. 接入 Deployment 子 Operation 和 active CAS。
7. 实现失败升级、告警事件和安全 deadline。
8. 迁移 server scheduler 和手动 renew API。
9. 弃用旧三套续签路径。
10. 更新配置、文档和 metrics。

---

## 13. 测试要求

- 90 天、45 天、6 天、160 小时证书 fallback。
- ARI window 优先于固定配置。
- ARI 不支持/超时/错误 fallback。
- stable jitter 重启不变化，不同 Lineage 分散。
- 两个 Scanner 只创建一个 Operation。
- 手动和自动续签竞争只一个成功。
- 新 Version 保存但部署失败时旧 Version 仍 active。
- 部署成功后 CAS active，并标记旧版本。
- 系统时间回拨和跳跃。
- 到 safety deadline 的优先级和告警。
- 虚拟时钟完成短周期证书多轮续签。

命令：

```bash
cargo test renewal
cargo test renewal_ari
cargo test renewal_lease
cargo test renewal_short_lived
cargo check --all-features
cargo fmt --all --check
git diff --check
```

---

## 14. 验收标准

- Server 启动后真实周期扫描。
- Scanner 只创建 Operation，不直接执行 ACME。
- 到期判断不依赖固定 30 天。
- ARI、fallback、jitter 有确定性测试。
- 多实例不会重复续签同一 Lineage。
- 新证书保存并部署成功后才成为 Active。
- 短周期/IP 证书有独立测试和告警门槛。

---

## 15. 风险与回滚

- 错误窗口可能导致集中续签，必须先对历史证书做 dry-run 分布报告。
- 上线前允许 shadow mode：只计算 Decision/指标，不创建 Operation。
- 旧 Scheduler 可在回滚窗口保留，但不能和新 Controller 同时启用。
- active version CAS 是最终安全栅栏，不得绕过。

---

## 16. 交付物

- Renewal Controller/Scanner。
- ARI/fallback/jitter 决策器。
- Lineage Lease 和去重。
- Renewal Workflow 扩展和部署联动。
- 旧 Scheduler 迁移/弃用。
- 虚拟时钟、并发和短周期测试。
- shadow mode 与上线说明。

