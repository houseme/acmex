# T21：发布工程与版本策略

**任务性质**：发布收口
**前置依赖**：T13-T20 全部完成
**主要后继**：v0.10.0 发布；v0.11.0 规划输入
**建议改动范围**：`Cargo.toml`、`CHANGELOG.md`（新增或确立）、`docs/RELEASE_NOTES_*`、`docs/MIGRATION_*`、`docs/roadmap/v0.9.0/`（状态收口）、`docs/roadmap/v0.10.0/`（本目录收口）、CI、README

---

## 1. 背景与当前问题

1. **版本欠账**：`Cargo.toml` 版本仍为 `0.8.0`。v0.9.0 的代码（T01-T12 + 三轮优化批次）已全部合入 main，但因外部门槛未执行，0.9.0 从未发布。v0.10.0 完成外部门槛后，存在两条路径：
   - 先按 v0.9.0 RELEASE_CHECKLIST 发布 `0.9.0`（以 T13 完成为界），再发布 `0.10.0`（以 T19/T20 完成为界）；
   - 或合并为一次 `0.10.0` 发布（若外部证据完成时点靠近，两个 tag 的增量对用户无独立价值）。
   该决策悬置会影响 T17 的 Sunset 日期与迁移文档结构，必须先定。
2. **CHANGELOG 缺位**：仓库有零散的 RELEASE_NOTES 文档，但没有持续维护的变更日志；三轮优化批次的行为级修复（如证书下载 PEM 解析失败、部署记账冲突）没有面向用户的叙述入口。
3. **迁移文档断档**：`MIGRATION_v0.8.0.md` 是最近一份；0.8→当前 main 之间的 breaking/behavioral 变化（legacy `/api` 语义、新配置 schema、`/metrics` 端点、CLI 行为重写、deprecation）没有成文档。
4. **性能基线未在受控平台复跑**：`PERFORMANCE_BASELINE.md` 标注为 host-dependent；发布前需要一次参考平台复跑并记录。
5. **公共 API 稳定性无门槛**：lib crate 公共面（含三轮批次的 re-export 扩展）没有 semver 检查机制。

---

## 2. 目标

1. **发布路径决策记录**：
   - 以简短决策文档（或本任务文档附录）记录：一次还是两次发布、依据（外部证据完成时点、用户可见差异、维护成本）、T17 Sunset 日期随之定稿；
   - 决策原则：0.x 阶段 y 表示行为变化粒度，不为流程而拆分无意义的小版本。
2. **CHANGELOG 确立**：引入 Keep a Changelog 风格 `CHANGELOG.md`，回填 0.9.0（若分开发布）/0.10.0 的变更；后续版本要求 PR 级维护（可先由发布负责人汇总，CI 不强制）。
3. **RELEASE_NOTES**：`RELEASE_NOTES_v0.9.0.md`（若适用）与 `RELEASE_NOTES_v0.10.0.md`：面向用户的能力叙述 + **显式未验证项**（任何仍未执行的 L5 项必须出现在发布说明，延续"不把未验证包装成成功"的纪律）。
4. **MIGRATION 文档**：
   - `MIGRATION_v0.9.0.md`：legacy `/api` → `/api/v1` 迁移表（引用 T17 产物）、配置 schema 变化（SecretRef、`[metrics]`、worker 装配）、CertificateBundle → Lineage/Version、CLI 行为变化（daemon/obtain --wait）；
   - `MIGRATION_v0.10.0.md`：新增配置（`[dns.propagation]`、`[ca.eab]`、webhook 窗口）、API 新资源（PATCH、挑战状态）、OCSP 处置影响、弃用信号（Deprecation/Sunset）。
5. **性能基线复跑**：在文档声明的参考平台复跑 `scripts/run_performance_baseline.sh`，更新 `PERFORMANCE_BASELINE.md` 并注明平台与日期；与上版基线的显著回归需归因。
6. **semver 门槛**：引入 `cargo-semver-checks`（或等价）于 CI 对 lib crate 公共面生效；基线在本次发布时建立，此后作为常规门槛。
7. **版本收口**：
   - 按决策 bump 版本、打 tag、按项目既定分发渠道发布（GitHub release / crates.io，以 README 声明为准）；
   - v0.9.0 路线图目录状态收口（README 状态行、RELEASE_CHECKLIST 全区结论、KNOWN_LIMITATIONS 终态）；本目录同样收口；
   - README 快速开始与 `acmex init` 输出一致（新用户路径以 init 为准）。

---

## 3. 非目标

- 不改变发布渠道或引入新的发布基础设施（沿用现状）。
- 不承诺 1.0 或 API 稳定保证（0.x 语义维持）。
- 不为历史版本补写发布说明（只覆盖 0.9.0/0.10.0）。
- 不做发布自动化流水线（人工 cut + checklist 即可，自动化待发布频度证明需求）。

---

## 4. 设计要点

- 发布顺序若为"先 0.9.0"：T13 完成（E2E 区可勾选）即可 cut 0.9.0，此时 External 区未完成项必须进入 0.9.0 发布说明；0.10.0 再补 External 证据——两份发布说明的未验证项清单必须衔接，不能互相矛盾。
- 若合并为一次 0.10.0：v0.9.0 路线图以"并入 0.10.0 发布"收口，决策记录写明。
- CHANGELOG 的行为级修复条目（如"真实 CA 下证书下载必然失败的解析缺陷修复"）比罗列 PR 更有价值；从 v0.9.0 审计的三轮批次记录提取。
- Sunset 日期（legacy `/api`）与发布决策强耦合：先决策、后定日期、再让 T17 的 header 值与文档一致（若 T17 已先合并占位日期，此处校准）。

---

## 5. 实施步骤

1. 发布路径决策（附录记录）+ 与 T17 Sunset 校准。
2. 回填 CHANGELOG；撰写两份（或一份）RELEASE_NOTES。
3. 撰写 MIGRATION_v0.9.0 / v0.10.0。
4. 参考平台复跑性能基线并更新文档。
5. semver 检查接入 CI，建立基线。
6. 版本 bump、tag、发布；两个 roadmap 目录状态收口；README/FEATURE_MATRIX/KNOWN_LIMITATIONS 终态核对。
7. `verify_docs_and_openapi.sh` 与全部门槛最终跑一遍作为发布前检查。

---

## 6. 验证方法

```bash
cargo fmt --all --check && cargo clippy --all-features -- -D warnings
cargo test && cargo check --all-features && cargo check --no-default-features
scripts/run_feature_matrix.sh && scripts/run_restart_matrix.sh && scripts/verify_docs_and_openapi.sh
# T13/T19/T20 门控脚本按各自 runbook 复跑并确认证据链接有效
```

---

## 7. 验收标准

- [ ] 发布路径决策已记录；Sunset 日期与 T17 实现一致。
- [ ] CHANGELOG 存在且覆盖本次发布；RELEASE_NOTES 含显式未验证项清单（若有残留）。
- [ ] MIGRATION 文档覆盖 0.8→0.9→0.10 全路径，含 API、配置、CLI、存储模型。
- [ ] 性能基线在声明的参考平台复跑并记录日期与平台。
- [ ] semver 检查在 CI 生效并建立基线。
- [ ] 版本已发布（tag + 分发渠道）；v0.9.0 与 v0.10.0 路线图目录状态收口，README 与实际行为一致。
- [ ] 最终发布前检查全绿。
