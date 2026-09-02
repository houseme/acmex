# T16：DNS 传播策略配置化

**任务性质**：T06 验收缺口收口（配置面）
**前置依赖**：无（基于已合并的 `src/dns/propagation.rs`、`zone.rs`）
**主要后继**：T19（staging DNS-01 使用真实传播策略）、T20（live zone）
**建议改动范围**：`src/dns/`（propagation、factory）、配置 schema（`[dns.propagation]`）、`src/application/`（策略传递）、`acmex init` 模板、tests、docs

---

## 1. 背景与当前问题

T06 任务文档第 6 节定义了完整传播策略与配置示例：

```toml
[dns.propagation]
authoritative_quorum = "all"        # 或 N
recursive_resolvers = ["1.1.1.1:53", "8.8.8.8:53"]
recursive_quorum = 1
```

策略要求：先确认权威 NS 可见 TXT 记录，再查询至少两个独立递归 resolver，达到 `authoritative_quorum` 且 `recursive_quorum` 后才视为 Propagated，并记录查询目标、响应值 hash、TTL、错误与 quorum 达成情况。

但 v0.9.0 审计（第 5 条"仍缺"）确认：**传播策略没有配置入口**——quorum/递归 resolver 策略无法经 `acmex.toml` 控制，运行时实际执行的等待与确认行为与文档定义脱节。同时 fake DNS 契约测试只覆盖固定等待路径，没有 quorum 不足时"不进入 valid"的行为断言。

---

## 2. 目标

1. **配置 schema**：`[dns.propagation]` 进入配置模型并文档化：
   - `authoritative_quorum`（`"all"` 或正整数）；
   - `recursive_resolvers`（地址列表，空表示跳过递归确认——显式 opt-out）；
   - `recursive_quorum`（正整数，≤ resolver 数）；
   - 等待参数：`max_wait`、`poll_interval`、单查询超时。
2. **per-provider 覆盖**：`[dns.providers.<id>.propagation]` 可覆盖全局策略（例如内网 provider 只查权威 NS）。覆盖语义：字段级覆盖，未设置字段回落全局。
3. **运行时接线**：PropagationObserver 消费上述配置——quorum 未达成不判定 Propagated；报告记录每次查询结果（值 hash/TTL/错误/quorum），失败可重试，超过 `max_wait` 为可重试错误（按现有错误分类，DNS 传播慢不属于 terminal）。
4. **行为测试**：fake/内网 resolver 环境断言——权威可见但递归 quorum 不足时不进入 valid；权威不可见时持续重试至超时；per-provider 覆盖生效。
5. **模板与文档**：`acmex init` 生成带注释的传播配置；DNS_PROVIDERS/DNS-01 文档与配置示例一致（`verify_docs_and_openapi.sh` 覆盖）。

---

## 3. 非目标

- 不新增传播算法（多地域 vantage point、DNSSEC 验证链等留待证据驱动）。
- 不为单个 intent 级别提供传播策略覆盖（provider 级足够；intent 级在无需求证据下不做）。
- 不把 hickory-resolver 缓存当作成功真相（遵循 T06 既定边界，缓存仅作观察层加速）。
- 不默认内置公共 resolver 列表之外的出站依赖（默认值需文档写明并允许清空）。

---

## 4. 设计要点

- 配置面一经发布即稳定（README 第 8 节冻结策略）：字段命名、默认值、覆盖语义需要一次定准；默认策略建议 `authoritative_quorum = "all"`、`recursive_resolvers = []`（默认不做递归确认，避免开箱即依赖外网 resolver），由 operator 显式启用递归 quorum。
- 观察报告中的响应值只记录 hash，不记录完整 TXT 值（TXT 值本身非机密，但保持 T06 报告约定）。
- resolver 地址支持 `ip:port` 与 DoT 形态可后置；首版 UDP/TCP `ip:port` 即可，但类型设计不得把"仅 UDP"写死。
- 与 T13 的 challtestsd 环境协同：Pebble E2E 的 DNS-01 应使用"权威 only"策略（challtestsd 即权威），作为 per-provider 覆盖的第一个真实用例。

---

## 5. 实施步骤

1. 扩展配置模型与解析（含校验：quorum ≤ resolver 数、端口合法、max_wait 下限）。
2. PropagationObserver 接线配置；provider 级覆盖合并逻辑。
3. fake resolver（in-process UDP 或 trait fake）行为测试三场景。
4. `acmex init` 模板、DNS 文档、配置示例更新。
5. 审计文档第 5 条"仍缺"清单勾销。

---

## 6. 验证方法

```bash
cargo test dns
cargo test --test dns_provider_contract
cargo check --all-features && cargo check --no-default-features
scripts/verify_docs_and_openapi.sh
```

---

## 7. 验收标准

- [x] `[dns.propagation]` 全字段可配置并有校验错误信息（非法组合被拒绝且有测试）。
- [x] provider 级字段覆盖生效，未设置字段回落全局（有测试）。
- [x] quorum 不足不判定 Propagated；超时归类为可重试错误（有行为测试）。
- [x] 观察报告记录查询目标/值 hash/TTL/错误/quorum 达成情况。
- [x] `acmex init` 模板与文档示例与 schema 一致；v0.9.0 审计对应条目可标记关闭。
