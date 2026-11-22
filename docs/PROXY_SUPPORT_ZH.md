# HTTP 代理支持(`[acme.proxy]`)

> 对应 [issue #171](https://github.com/houseme/acmex/issues/171):服务器无法直连
> ZeroSSL 等 CA,需要让 ACME 请求走 HTTP 代理。

## 配置方式

在配置文件的 `[acme.proxy]` 段声明代理;配置后,**所有 ACME 出站请求**
(目录发现、nonce、JWS POST、证书下载、ARI 轮询)都会经由代理:

```toml
[acme.proxy]
url = "http://proxy.internal:3128"
# 可选:socks5://proxy.internal:1080 或 socks5h://…(reqwest socks 特性默认启用)
# 可选:NO_PROXY 语法的主机/IP/CIDR 排除列表(逗号分隔)
# no_proxy = "localhost,.internal,10.0.0.0/8"
# 可选:代理 Basic 认证
# username = "proxy-user"
# password = "env:PROXY_PASSWORD"   # SecretRef,支持 env:/file:
```

环境变量覆盖(可完全脱离配置文件,凭据只存在于环境中):

```bash
ACMEX_ACME_PROXY_URL="http://user:pass@proxy.internal:3128"
ACMEX_ACME_NO_PROXY="127.0.0.1,.local"
```

## 行为语义

- **显式配置替换环境变量探测**:未配置 `[acme.proxy]` 时,reqwest 默认的
  system-proxy 探测(`https_proxy`/`HTTPS_PROXY`/`ALL_PROXY`)仍然生效;
  一旦配置了显式代理,该探测被禁用,显式代理完全接管,`no_proxy` 用于
  把直连主机从显式代理中排除出去。
- **凭据安全**:URL 中的 userinfo 支持 `${VAR}` 展开(变量未设置时配置
  校验直接报错,不会变成奇怪的主机名);`password` 走 SecretRef,在客户端
  组装时立即解析(错误在启动时报出,而不是第一个 ACME 请求时);
  `ProxySettings` 的 `Debug`/日志输出会对 userinfo 做 `***` 脱敏
  (红线:密钥不进日志)。
- **校验前置**:`Config::validate` 与 `apply_env_overrides` 拒绝空 URL、
  无法解析的 URL、未展开的 `${VAR}`、不支持的 scheme(仅
  `http`/`https`/`socks5`/`socks5h`)、含空项的 `no_proxy` 以及
  `password` 缺 `username` 的组合。
- **失败显式**:代理不可达时 ACME 请求按 transport 错误处理并分类重试,
  绝不会静默回退为直连("Nothing pretends to succeed")。

## 覆盖范围

| 出站路径 | 代理来源 |
|----------|----------|
| v0.10 durable workflow 的 `ReqwestAcmeTransport`(worker / ARI / key rollover) | `[acme.proxy]` |
| 旧门面 `AcmeClient`(`serve`、`obtain`、`provisioner`、server 账号注册/更新/停用) | `[acme.proxy]` |
| 独立 CLI 账号/证书工具(`acmex account …`、`acmex cert revoke` 等不加载配置文件的命令) | `ACMEX_ACME_PROXY_URL` 环境变量 |
| DNS 提供商 API、delivery sinks、webhook/SMTP 通知 | ❌(按 issue #171 范围只代理 ACME;如需可后续按相同 `ProxySettings` 类型扩展) |

环境变量覆盖(`ACMEX_ACME_PROXY_URL` / `ACMEX_ACME_NO_PROXY`)在
`serve`、`daemon`、`obtain` 的配置加载路径统一生效,可以完全脱离配置
文件使用。

## 库用户注入自定义 HTTP 客户端

issue 中提到 `AcmeClient.http_client` 是私有的。除 `[acme.proxy]` 外,
v0.10 提供完全控制逃生舱——代理、自定义 TLS 根、拦截器都可以自行构建后注入:

```rust
let http_client = reqwest::Client::builder()
    .proxy(reqwest::Proxy::all("http://proxy:3128")?)
    .build()?;
let client = AcmeClient::with_http_client(config, key_pair, http_client);
```

注意:注入的客户端原样使用,`AcmeConfig.proxy` 不再对其生效。

## 行为测试证据

`tests/proxy_support.rs`(纯本地,无外部依赖):

- `explicit_proxy_routes_acme_traffic`:目录 GET、nonce HEAD、newAccount
  POST 全部以绝对形式 URI 经本地 stub 代理完成注册流程;
- `no_proxy_bypasses_proxy_for_excluded_hosts`:排除列表命中的 127.0.0.1
  流量绕过(指向死端口的)代理,以 origin-form 直连完成;
- `dead_proxy_fails_acme_requests_explicitly`:代理不可达时注册显式失败;
- `reqwest_acme_transport_routes_through_proxy`:v0.10 传输层同样生效。
