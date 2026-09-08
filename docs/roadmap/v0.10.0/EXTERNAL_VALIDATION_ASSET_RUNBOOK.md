# T19/T20 外部验证资产准备手册

**适用范围**：T19 Let's Encrypt staging / 真实 CA 特性验证，T20 live DNS、外部 HTTP agent、Redis managed failover、Kubernetes/Vault/fencing 外部证据准备。
**最后更新**：2026-09-07
**核心原则**：目录查询、环境预检、compile gate、单节点本地契约都不是 release pass；只有使用受控外部资产完成对应场景并归档证据，才能勾选 T19/T20 的外部验收项。

---

## 1. 准备顺序

按下面顺序准备资料，可以最大化复用资产并减少重复排错：

1. **确认仓库基线**：记录 `git rev-parse HEAD`、当前分支、执行人、执行日期；所有证据目录必须包含这些非敏感元数据。
2. **创建证据目录**：为 T19 与 T20 各准备独立 artifact 目录，不混放不同 run 的日志。
3. **准备专用测试域名**：域名只用于 AcmeX 外部验证，避免影响生产证书、生产 DNS 与真实业务流量。
4. **准备 live DNS zone**：至少 Cloudflare 与 Route53 各一个隔离 zone；T19 DNS-01 会复用 T20 的 live zone 能力。
5. **准备 HTTP-01/TLS-ALPN-01 主机**：公网可达、可绑定 80/443，能部署 AcmeX challenge responder 或等价受控入口。
6. **准备公网 IP 标识符资产**：IPv4 与 IPv6 都需要可控、可路由、可绑定 challenge 端口。
7. **准备 CA 账户与信任锚**：Let's Encrypt staging 账户邮箱、staging trust anchor PEM；EAB CA 额外需要 key id 与 HMAC SecretRef。
8. **准备外部 HTTP agent**：部署独立于测试进程的 agent，暴露 HttpAgentSink 协议入口和 token SecretRef。
9. **准备 Redis managed failover 环境**：托管 Redis/Sentinel/Cluster/云 HA，具备可控 failover 触发和日志/指标导出。
10. **准备 K8s/Vault/fencing 证据资料**：当前脚本对 K8s/Vault/fencing 要求归档证据文件；没有 runner 时不得让脚本假绿。
11. **按场景执行脚本**：先跑最小 smoke，再逐项扩展到完整 release pass；每次失败都记录是环境问题、CA 行为差异，还是 AcmeX bug。

---

## 2. 共同资料

### 2.1 仓库与执行信息

每次 T19/T20 run 都应记录：

| 项 | 说明 |
|---|---|
| `git_sha` | `git rev-parse HEAD` 的结果 |
| 分支 | 执行所在分支；发布证据建议使用 main 或待发布 commit |
| 执行时间 | UTC 与本地时区都可记录，脚本默认写 UTC |
| 执行人/环境 | 只写角色或环境名，不写个人密钥、机器私有路径、内网地址 |
| 场景列表 | `ACMEX_LE_STAGING_SCENARIOS` 或 `ACMEX_LIVE_INFRA_SCENARIOS` |
| artifact 目录 | 保存日志、manifest、scope 文档的位置 |

### 2.2 SecretRef 纪律

凭据必须以 SecretRef 或环境变量方式注入，不写入仓库、配置示例、测试输出或证据归档：

```bash
export ACMEX_LIVE_HTTP_AGENT_TOKEN_REF="env:ACMEX_AGENT_TOKEN"
export ACMEX_EAB_HMAC_KEY_REF="file:/secure/acmex/eab-hmac.txt"
```

允许的 SecretRef 形态以当前 resolver 为准；内置路径主要支持 `env:` 与 `file:`。`vault:` / `provider:` 只能在部署环境提供自定义 resolver 后使用。证据中可以记录 SecretRef 的**引用类型和用途**，不得记录解析后的值。

### 2.3 证据目录规范

建议按下面结构归档：

```text
target/
  le-staging/<timestamp>/
    environment.txt
    preflight-manifest.json
    cargo-test-le-staging.log
    issuance-http-01-summary.md
    issuance-dns-01-summary.md
    renewal-ari-replaces-summary.md
    ip-identifier-summary.md
    eab-ca-summary.md
  live-infra/<timestamp>/
    environment.txt
    preflight-manifest.json
    live-dns-cloudflare.log
    live-dns-route53.log
    redis-repository-contract.log
    redis-managed-failover-summary.md
    sink-http-agent.log
    sink-kubernetes-scope.md
    sink-vault-scope.md
    dual-process-fencing.log
```

证据允许记录：证书指纹、序列号、not_before/not_after、CA directory URL、order/challenge 的非敏感状态、DNS record 名称、资源版本、测试摘要、失败分类。

证据不得记录：账户私钥、证书私钥、DNS token、EAB HMAC、HTTP agent bearer token、Vault token、AWS secret、Kubeconfig 原文、可直接访问内部系统的 URL 或内网拓扑细节。

---

## 3. T19：真实签发、续签、ARI、profile、IP、EAB CA

入口脚本：

```bash
RUN_LE_STAGING=1 ACMEX_LE_STAGING_SCENARIOS=directory scripts/run_le_staging.sh
RUN_LE_STAGING=1 ACMEX_LE_STAGING_SCENARIOS=http-01,dns-01,renewal,profile,ip-http-01,ip-tls-alpn-01,eab-ca scripts/run_le_staging.sh
```

支持的场景：

| 场景 | 目的 | 是否变更外部资源 |
|---|---|---|
| `directory` | 获取 CA directory，确认 `newNonce`、`newAccount`、`newOrder`、ARI/profile 广告状态 | 否 |
| `http-01` | 域名 HTTP-01 完整签发 | 是 |
| `dns-01` | 域名 DNS-01 完整签发，复用 T20 live DNS zone | 是 |
| `renewal` | 同一 lineage 续签，验证 ARI window 与 `replaces` | 是 |
| `profile` | 验证 CA profile 选择生效或记录 CA 不支持 | 是 |
| `ip-http-01` | IPv4/IPv6 标识符 HTTP-01 签发行为 | 是 |
| `ip-tls-alpn-01` | IPv4/IPv6 标识符 TLS-ALPN-01 签发行为 | 是 |
| `eab-ca` | ZeroSSL/Google/LE EAB 等要求 EAB 的 CA 注册并签发 | 是 |

### 3.1 T19 公共变量

| 变量 | 必需场景 | 准备内容 |
|---|---|---|
| `RUN_LE_STAGING=1` | 全部执行 | 显式打开外部 CA gate |
| `ACMEX_LE_STAGING_SCENARIOS` | 建议显式设置 | 逗号分隔：`directory,http-01,dns-01,renewal,profile,ip-http-01,ip-tls-alpn-01,eab-ca`；`all` 表示全部 |
| `ACMEX_LE_STAGING_ARTIFACT_DIR` | 全部执行 | 证据目录；未设置时脚本生成 `target/le-staging/<timestamp>` |
| `ACMEX_LE_STAGING_DIRECTORY_URL` | 可选 | 默认 `https://acme-staging-v02.api.letsencrypt.org/directory`；EAB CA 场景可使用专门变量覆盖 |

### 3.2 T19 签发类公共资产

以下变量在除 `directory` 以外的签发场景中必需：

| 变量 | 准备内容 | 匹配要求 |
|---|---|---|
| `ACMEX_LE_STAGING_ACCOUNT_EMAIL` | 测试 CA 账户邮箱 | 使用可接收 CA 通知的邮件；不要使用个人主业务邮箱 |
| `ACMEX_LE_STAGING_DOMAIN` | 专用测试域名或子域名 | 必须由执行团队控制 DNS；建议如 `acmex-test.example.com` |
| `ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE` | CA staging 根/中间信任锚 PEM 文件 | 文件只包含公开证书；用于 T15 VerificationReport 链验证 |

域名建议：

- 使用独立 zone 或委派子域，避免测试 TXT/A/AAAA 记录影响生产。
- 为 HTTP-01 准备 `A`/`AAAA` 指向测试主机。
- 为 DNS-01 允许创建和删除 `_acme-challenge.<domain>` TXT。
- Wildcard 若后续纳入验证，必须走 DNS-01，不应复用 HTTP-01 资产判断。

### 3.3 HTTP-01 资料

需要准备：

| 资料 | 要求 |
|---|---|
| 公网主机 | CA 能访问 TCP/80；无企业防火墙、CDN、WAF 篡改 challenge 响应 |
| DNS 记录 | `ACMEX_LE_STAGING_DOMAIN` 的 A/AAAA 指向该主机 |
| 进程权限 | 能启动 AcmeX HTTP-01 responder，或能把 `/.well-known/acme-challenge/` 路由到 AcmeX |
| 清理权限 | 验证后能移除 challenge 文件/路由 |

通过标准：

- intent → order → authorization → challenge → finalize → certificate download 全链路完成。
- T15 验收报告包含 SAN、有效期、链信任、profile、密钥一致性、identifier capability 结论。
- File sink 部署并激活；旧 active 指针不被错误覆盖。
- artifact 中有签发摘要，不包含私钥。

### 3.4 DNS-01 资料

DNS-01 复用 T20 live DNS provider 资产。通用变量：

| 变量 | 准备内容 |
|---|---|
| `ACMEX_LIVE_DNS_TYPE` | `cloudflare` 或 `route53`，与实际 provider 匹配 |
| `ACMEX_LIVE_DNS_ZONE` | 隔离 zone 名称 |
| `ACMEX_LIVE_DNS_TOKEN` | provider token；Route53 由 AWS credential 提供时该变量会在脚本中 unset |

通过标准：

- `_acme-challenge` TXT 创建、权威 NS 可见、CA challenge valid、finalize 成功。
- 删除后权威 NS 不再返回测试 TXT。
- T16 propagation 策略真实参与等待，不使用固定 sleep 假成功。

### 3.5 续签与 ARI `replaces`

需要准备：

| 资料 | 要求 |
|---|---|
| 初始证书版本 | 同一 lineage 已有 active version，可作为后续 renewal 的 `replaces` 来源 |
| ARI 可达性 | CA directory 含 `renewalInfo` 时记录 window；不支持时记录 fallback |
| 续签触发条件 | 使用 staging 测试窗口或显式缩短 renewal policy，避免等待真实到期 |
| 持久化仓储 | 保留 lineage/version/operation 状态，证明旧版本 superseded |

通过标准：

- renewal order 带上 `replaces` 或在 CA 不支持时留下明确 fallback 证据。
- 新版本激活后旧版本标记为 superseded。
- 没有重复创建 order、重复部署或覆盖旧 active 指针的副作用。

### 3.6 Profile 资料

需要准备：

| 资料 | 要求 |
|---|---|
| CA profile 名称 | 来自 CA directory `profiles` 广告或 CA 文档，不凭空填写 |
| profile 期望 | 有效期上限、算法、key type、是否 short-lived |
| 对照记录 | 记录证书 not_after/not_before 与 profile 声明的匹配关系 |

通过标准：

- CA 支持 profile：下单指定 profile，签发证书行为与声明一致。
- CA 不支持 profile：记录 directory/profile 缺失或拒绝响应；不得把未验证写成通过。

### 3.7 IP 标识符资料

需要准备：

| 变量/资料 | 要求 |
|---|---|
| `ACMEX_LE_STAGING_IPV4` | 受控公网 IPv4，不是 RFC1918、loopback、link-local、TEST-NET |
| `ACMEX_LE_STAGING_IPV6` | 受控公网 IPv6，不是 ULA、loopback、link-local、documentation prefix |
| HTTP-01 端口 | CA 能访问 IP 的 TCP/80 |
| TLS-ALPN-01 端口 | CA 能访问 IP 的 TCP/443，能返回 ACME ALPN 证书 |
| 授权证明 | 云实例、公网 IP 分配、DNS/反代配置或等价操作权限说明 |

通过标准：

- IPv4/IPv6 分别完成 HTTP-01 与 TLS-ALPN-01，或记录 CA 对 IP 标识符的拒绝原因。
- 私网/保留地址仍应由 AcmeX 策略在外部副作用前拒绝。
- 证据只保留 IP、challenge 类型、CA 状态、证书摘要，不保留私钥。

### 3.8 EAB CA 资料

需要准备：

| 变量 | 准备内容 |
|---|---|
| `ACMEX_EAB_CA_DIRECTORY_URL` | 要求 EAB 的 CA staging directory，例如 ZeroSSL/Google/LE EAB 账户对应目录 |
| `ACMEX_EAB_KEY_ID` | CA 签发的 EAB key identifier |
| `ACMEX_EAB_HMAC_KEY_REF` | EAB HMAC key 的 SecretRef，推荐 `env:` 或 `file:` |

通过标准：

- newAccount 请求包含有效 External Account Binding。
- 错误 HMAC 或缺失 kid 的失败分类与本地契约一致。
- EAB CA 完成至少一次签发，FEATURE_MATRIX 对应 CA external evidence 更新。

---

## 4. T20：Live DNS、外部 Agent、Redis HA、K8s/Vault/Fencing

入口脚本：

```bash
RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=reference-http-agent scripts/run_live_infra.sh
RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=redis scripts/run_live_infra.sh
RUN_LIVE_INFRA=1 ACMEX_LIVE_INFRA_SCENARIOS=dns-cloudflare,dns-route53,sink-http-agent scripts/run_live_infra.sh
```

支持的场景：

| 场景 | 当前入口行为 | 是否仍需外部环境 |
|---|---|---|
| `dns-cloudflare` | 已路由到 live DNS provider ignored test | 是 |
| `dns-route53` | 已路由到 live DNS provider ignored test | 是 |
| `redis` | 已路由到 Redis repository contract | 单节点可本地跑；managed failover 仍需外部 HA |
| `reference-http-agent` | 已启动真实 reference agent 子进程契约 | 否，属于本地/子进程证据 |
| `sink-http-agent` | 已路由到外部 HTTP agent ignored test | 是 |
| `sink-kubernetes` | 当前要求归档 `sink-kubernetes-scope.md` | 是，仓库内无 runner |
| `sink-vault` | 当前要求归档 `sink-vault-scope.md` | 是，仓库内无 runner |
| `dual-process-fencing` | 当前要求归档 `dual-process-fencing.log` | 是，直到 first-class runner 合入 |

### 4.1 T20 公共变量

| 变量 | 准备内容 |
|---|---|
| `RUN_LIVE_INFRA=1` | 显式打开 live infra gate |
| `ACMEX_LIVE_INFRA_SCENARIOS` | 逗号分隔场景名；建议一次只跑一类外部系统，便于归因 |
| `ACMEX_LIVE_INFRA_ARTIFACT_DIR` | 证据目录；未设置时脚本生成 `target/live-infra/<timestamp>` |

脚本会先运行 `live-infra-preflight`。未知场景名会直接失败；选中 K8s/Vault/fencing 但没有对应非空归档文件也会失败。

### 4.2 Cloudflare Live DNS

需要准备：

| 变量 | 准备内容 |
|---|---|
| `RUN_LIVE_DNS_CLOUDFLARE=1` | 显式打开 Cloudflare live DNS |
| `ACMEX_LIVE_DNS_CLOUDFLARE_ZONE` | 专用 zone 名称 |
| `ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN` | 只允许该 zone 的 DNS edit/read token |

权限建议：

- Token 只授予测试 zone 的 DNS 记录读写权限。
- 禁止使用全账户 token。
- Zone 中预留 `_acme-challenge-acmex-test` 或随机前缀，测试结束必须清理。

通过标准：

- create/find/delete/idempotency 全部通过。
- 删除后重建通过，重复删除为幂等成功或可解释的 already-clean。
- artifact 中有 `live-dns-cloudflare.log`。

### 4.3 Route53 Live DNS

需要准备：

| 变量 | 准备内容 |
|---|---|
| `RUN_LIVE_DNS_ROUTE53=1` | 显式打开 Route53 live DNS |
| `ACMEX_LIVE_DNS_ROUTE53_ZONE` | 专用 hosted zone 名称 |
| `ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID` | Hosted Zone ID |
| `AWS_PROFILE` | 推荐使用，指向最小权限 profile |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | 如不用 `AWS_PROFILE`，才使用 keypair |

权限建议：

- IAM policy 限制到目标 hosted zone 的 `ChangeResourceRecordSets`、`ListResourceRecordSets`、`GetChange`。
- 准备执行区所在 region/account 的说明，但不要把 secret 写入 artifact。

通过标准：

- create/find/delete/idempotency 全部通过。
- 权威查询能观察到 TXT 传播。
- artifact 中有 `live-dns-route53.log`。

### 4.4 外部 HTTP Agent Sink

需要准备：

| 变量 | 准备内容 |
|---|---|
| `ACMEX_LIVE_HTTP_AGENT_URL` | 已部署 agent 的 base URL，必须由测试环境控制 |
| `ACMEX_LIVE_HTTP_AGENT_TOKEN_REF` | agent token SecretRef，例如 `env:ACMEX_AGENT_TOKEN` |
| `ACMEX_LIVE_HTTP_AGENT_ID` | 可选；默认 `external-agent` |
| `ACMEX_LIVE_HTTP_AGENT_TARGET_ID` | 可选；默认 `edge-live-external` |

Agent 要求：

- 独立部署，不由 `tests/agent_live.rs` 在同一测试进程中启动。
- 实现 HttpAgentSink 期望的 stage/activate/health/rollback/cleanup 协议。
- route table 或证书存储必须是测试专用命名空间。
- token 最小权限，仅允许该测试 target。

通过标准：

- v1 stage 后 health 为可达但未 active。
- v1 activate 后 health healthy。
- v2 stage 不覆盖 v1 active。
- v2 activate 后可 rollback 到 v1。
- cleanup 可重复执行且最终 already clean。
- artifact 中有 `sink-http-agent.log`。

### 4.5 Redis Managed Failover

当前 `redis` 场景已能运行 Redis repository contract；外部发布证据还需要 managed failover 资料：

| 变量/资料 | 准备内容 |
|---|---|
| `ACMEX_LIVE_REDIS_URL` | 测试 Redis endpoint；单节点 contract 可用 `redis://host:port/db` |
| HA 拓扑 | Sentinel、Redis Cluster、云托管主从切换或等价 managed failover |
| 持久化策略 | AOF/RDB/托管快照配置；写明数据丢失边界 |
| 故障触发方式 | 控制台 failover、kill primary、网络隔离或 provider 提供的 failover API |
| 测试隔离 | 独立 DB 或 key prefix；确认不会清理非测试 key |
| 日志/指标 | 连接断开、重连、CAS/lease 冲突、恢复后 resume 的观测输出 |

通过标准：

- 正常 contract 通过：intent/lineage/version/operation/challenge/deployment/account/outbox/lease/manifest 等路径行为与 File/Memory 一致。
- failover 期间不可把未知 CAS 写入结果误判为业务不存在。
- 恢复后 operation 可 resume，不回退到旧状态。
- 记录哪些故障是应用可重试，哪些依赖 Redis 部署持久性或人工介入。
- artifact 中有 `redis-repository-contract.log` 与 `redis-managed-failover-summary.md`。

### 4.6 Kubernetes Sink Scope

当前仓库脚本没有 Kubernetes sink runner；选中 `sink-kubernetes` 时必须准备非空 `sink-kubernetes-scope.md`。

建议记录：

| 资料 | 要求 |
|---|---|
| `ACMEX_LIVE_KUBECONFIG` | 只记录引用位置或 SecretRef，不记录内容 |
| `ACMEX_LIVE_K8S_NAMESPACE` | 专用 namespace |
| RBAC | 最小权限：目标 namespace 中 Secret create/get/update/delete/list/watch |
| Secret 形态 | type、key 名称、owner label/annotation、版本标签 |
| 演练结果 | stage/activate/health/rollback/cleanup，每步资源版本和最终清理状态 |

通过标准：

- scope 文档能证明实环境演练完成，而不只是权限说明。
- Secret 不残留，或残留原因和手工清理步骤明确。
- 不能把 scope 文档替代为代码级实现声明。

### 4.7 Vault Sink Scope

当前仓库脚本没有 Vault sink runner；选中 `sink-vault` 时必须准备非空 `sink-vault-scope.md`。

建议记录：

| 资料 | 要求 |
|---|---|
| `ACMEX_LIVE_VAULT_ADDR` | 测试 Vault endpoint；证据可脱敏记录环境名 |
| `ACMEX_LIVE_VAULT_TOKEN_REF` | Vault token SecretRef |
| KV mount/path | 专用 mount 或 path prefix |
| Policy | 对目标 path 的 create/read/update/delete/list 最小权限 |
| 演练结果 | stage/activate/health/rollback/cleanup，每步版本和最终清理状态 |

通过标准：

- KV 写入、激活指针、回滚指针和 cleanup 行为都有证据。
- Vault token 不出现在日志和 artifact 中。
- 失败时能区分 auth/permission/path/version 冲突。

### 4.8 Dual-process Fencing

当前仓库脚本没有 first-class fencing runner；选中 `dual-process-fencing` 时必须准备非空 `dual-process-fencing.log`。

需要准备：

| 变量/资料 | 准备内容 |
|---|---|
| `ACMEX_LIVE_FENCING_REPOSITORY` | 两个进程共享的 repository，File 共享目录或 Redis 均可 |
| `ACMEX_LIVE_FENCING_WORKERS=2` | 至少两个真实 worker 进程 |
| 同一 lineage | 两个 worker 同时扫描/续签同一 lineage |
| 外部副作用计数 | order、challenge、deployment activate 的唯一性断言 |
| 观测输出 | lease 获取/续约/CAS 冲突/worker 退出或重试日志 |

通过标准：

- 两个真实进程并发时，只有一个 worker 完成续签和部署激活。
- 另一个 worker 明确观察到 lease/CAS/fencing 冲突并安全退出或重试。
- 同一 version 的 stage/activate 不重复产生不可接受副作用。
- 调度器重复扫描不创建重复 order。

---

## 5. 推荐执行批次

### 批次 A：非变更 smoke

目的：确认脚本、网络、CA directory 与证据目录正常。

```bash
RUN_LE_STAGING=1 \
ACMEX_LE_STAGING_SCENARIOS=directory \
scripts/run_le_staging.sh
```

预期：生成 `preflight-manifest.json`，确认 `newNonce`、`newAccount`、`newOrder`。这不是签发 release pass。

### 批次 B：Live DNS

目的：先关闭 T20 live zone 缺口，并为 T19 DNS-01 准备基础。

```bash
RUN_LIVE_INFRA=1 \
ACMEX_LIVE_INFRA_SCENARIOS=dns-cloudflare \
RUN_LIVE_DNS_CLOUDFLARE=1 \
ACMEX_LIVE_DNS_CLOUDFLARE_ZONE=<test-zone> \
ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN=<secret> \
scripts/run_live_infra.sh
```

```bash
RUN_LIVE_INFRA=1 \
ACMEX_LIVE_INFRA_SCENARIOS=dns-route53 \
RUN_LIVE_DNS_ROUTE53=1 \
ACMEX_LIVE_DNS_ROUTE53_ZONE=<test-zone> \
ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID=<hosted-zone-id> \
AWS_PROFILE=<least-privilege-profile> \
scripts/run_live_infra.sh
```

### 批次 C：域名签发与续签

目的：完成 T19 HTTP-01/DNS-01、ARI `replaces`、VerificationReport、File sink 激活证据。

```bash
RUN_LE_STAGING=1 \
ACMEX_LE_STAGING_SCENARIOS=http-01,dns-01,renewal \
ACMEX_LE_STAGING_ACCOUNT_EMAIL=<test-account-email> \
ACMEX_LE_STAGING_DOMAIN=<test-domain> \
ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE=<staging-root-pem> \
ACMEX_LIVE_DNS_TYPE=cloudflare \
ACMEX_LIVE_DNS_ZONE=<test-zone> \
ACMEX_LIVE_DNS_TOKEN=<secret> \
scripts/run_le_staging.sh
```

### 批次 D：Profile/IP/EAB CA

目的：覆盖真实 CA 的能力差异，不把本地 fake/Pebble 结果外推为公网 CA 行为。

```bash
RUN_LE_STAGING=1 \
ACMEX_LE_STAGING_SCENARIOS=profile,ip-http-01,ip-tls-alpn-01,eab-ca \
ACMEX_LE_STAGING_ACCOUNT_EMAIL=<test-account-email> \
ACMEX_LE_STAGING_DOMAIN=<test-domain> \
ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE=<staging-root-pem> \
ACMEX_LE_STAGING_IPV4=<controlled-public-ipv4> \
ACMEX_LE_STAGING_IPV6=<controlled-public-ipv6> \
ACMEX_EAB_CA_DIRECTORY_URL=<eab-ca-directory-url> \
ACMEX_EAB_KEY_ID=<eab-key-id> \
ACMEX_EAB_HMAC_KEY_REF=<secret-ref> \
scripts/run_le_staging.sh
```

### 批次 E：外部 HTTP agent

```bash
RUN_LIVE_INFRA=1 \
ACMEX_LIVE_INFRA_SCENARIOS=sink-http-agent \
ACMEX_LIVE_HTTP_AGENT_URL=<agent-url> \
ACMEX_LIVE_HTTP_AGENT_TOKEN_REF=env:ACMEX_AGENT_TOKEN \
scripts/run_live_infra.sh
```

### 批次 F：Redis managed failover

```bash
RUN_LIVE_INFRA=1 \
ACMEX_LIVE_INFRA_SCENARIOS=redis \
ACMEX_LIVE_REDIS_URL=<managed-redis-url> \
scripts/run_live_infra.sh
```

随后执行受控 failover，并补充 `redis-managed-failover-summary.md`。该 summary 至少写清：触发方式、故障窗口、客户端观察到的错误、恢复后 resume 结果、是否有重复副作用、持久化边界。

### 批次 G：K8s/Vault/fencing 归档证据

在没有 first-class runner 前，先把真实演练输出整理成脚本要求的文件名：

```text
sink-kubernetes-scope.md
sink-vault-scope.md
dual-process-fencing.log
```

再运行：

```bash
RUN_LIVE_INFRA=1 \
ACMEX_LIVE_INFRA_SCENARIOS=sink-kubernetes,sink-vault,dual-process-fencing \
ACMEX_LIVE_KUBECONFIG=<kubeconfig-ref> \
ACMEX_LIVE_K8S_NAMESPACE=<namespace> \
ACMEX_LIVE_VAULT_ADDR=<vault-addr> \
ACMEX_LIVE_VAULT_TOKEN_REF=<secret-ref> \
ACMEX_LIVE_FENCING_REPOSITORY=<shared-repository> \
ACMEX_LIVE_FENCING_WORKERS=2 \
ACMEX_LIVE_INFRA_ARTIFACT_DIR=<dir-containing-required-evidence-files> \
scripts/run_live_infra.sh
```

如果三个文件不存在或为空，脚本应失败。这是预期行为，用于防止没有真实 runner 时出现假绿。

---

## 6. 资料匹配矩阵

| 目标 | 最少资料 | 关键变量 | 证据文件 |
|---|---|---|---|
| LE directory smoke | 外网访问 LE staging directory | `RUN_LE_STAGING`、`ACMEX_LE_STAGING_SCENARIOS=directory` | `preflight-manifest.json` |
| HTTP-01 签发 | 域名、A/AAAA、公网 80、账户邮箱、trust anchor | `ACMEX_LE_STAGING_DOMAIN`、`ACMEX_LE_STAGING_ACCOUNT_EMAIL`、`ACMEX_LE_STAGING_TRUST_ANCHOR_PEM_FILE` | `issuance-http-01-summary.md` |
| DNS-01 签发 | 域名、live DNS zone、DNS token | `ACMEX_LIVE_DNS_TYPE`、`ACMEX_LIVE_DNS_ZONE`、`ACMEX_LIVE_DNS_TOKEN` | `issuance-dns-01-summary.md` |
| 续签/ARI `replaces` | 初始 active version、ARI window/fallback 记录 | `ACMEX_LE_STAGING_SCENARIOS=renewal` | `renewal-ari-replaces-summary.md` |
| Profile | CA 广告的 profile 名称和预期 | `ACMEX_LE_STAGING_SCENARIOS=profile` | `profile-summary.md` |
| IP 标识符 | 受控公网 IPv4/IPv6、80/443 | `ACMEX_LE_STAGING_IPV4`、`ACMEX_LE_STAGING_IPV6` | `ip-identifier-summary.md` |
| EAB CA | EAB CA directory、kid、HMAC SecretRef | `ACMEX_EAB_CA_DIRECTORY_URL`、`ACMEX_EAB_KEY_ID`、`ACMEX_EAB_HMAC_KEY_REF` | `eab-ca-summary.md` |
| Cloudflare DNS | Cloudflare test zone/token | `RUN_LIVE_DNS_CLOUDFLARE`、`ACMEX_LIVE_DNS_CLOUDFLARE_ZONE`、`ACMEX_LIVE_DNS_CLOUDFLARE_TOKEN` | `live-dns-cloudflare.log` |
| Route53 DNS | Hosted zone、zone id、AWS credential | `RUN_LIVE_DNS_ROUTE53`、`ACMEX_LIVE_DNS_ROUTE53_HOSTED_ZONE_ID`、`AWS_PROFILE` | `live-dns-route53.log` |
| 外部 HTTP agent | 独立 agent URL、token SecretRef | `ACMEX_LIVE_HTTP_AGENT_URL`、`ACMEX_LIVE_HTTP_AGENT_TOKEN_REF` | `sink-http-agent.log` |
| Redis managed failover | HA Redis、failover 权限、日志/指标 | `ACMEX_LIVE_REDIS_URL` | `redis-repository-contract.log`、`redis-managed-failover-summary.md` |
| Kubernetes scope | kubeconfig、namespace、RBAC、Secret 形态 | `ACMEX_LIVE_KUBECONFIG`、`ACMEX_LIVE_K8S_NAMESPACE` | `sink-kubernetes-scope.md` |
| Vault scope | Vault addr、token SecretRef、KV path/policy | `ACMEX_LIVE_VAULT_ADDR`、`ACMEX_LIVE_VAULT_TOKEN_REF` | `sink-vault-scope.md` |
| 双进程 fencing | 共享 repo、两个 worker、唯一副作用断言 | `ACMEX_LIVE_FENCING_REPOSITORY`、`ACMEX_LIVE_FENCING_WORKERS=2` | `dual-process-fencing.log` |

---

## 7. 完成判定

一项外部验证可以标记完成，需要同时满足：

1. 对应场景在脚本或手册中有明确入口。
2. 环境变量和资料与场景匹配，不靠默认空值或无关 token 通过。
3. 真实外部系统发生了预期副作用，并在测试结束后完成清理或记录残留原因。
4. artifact 中有非敏感日志、manifest 或 summary。
5. 失败与降级有明确归因：环境缺失、CA 不支持、provider 权限不足、网络不可达、AcmeX bug。
6. `scripts/secret_scan.sh` 通过。
7. v0.9.0/v0.10.0 的 RELEASE_CHECKLIST、FEATURE_MATRIX、KNOWN_LIMITATIONS、T19/T20 文档按事实同步。

不能标记完成的情况：

- 只运行 `directory` smoke。
- 只运行默认 `cargo test` 或 compile gate。
- 只提供权限说明，没有 stage/activate/health/rollback/cleanup 或签发链路证据。
- 只在本地 fake/Pebble 中通过，却声明真实 CA/DNS/Agent/Redis managed failover 通过。
- artifact 中包含真实 secret，需要先废弃该 artifact 并轮换泄露凭据。
