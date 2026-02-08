# AcmeX 传输层 (Transport) 功能文档

## 1. 概述
传输层是 AcmeX 的网络通信核心，负责处理所有与 ACME 服务器的 HTTP 交互。它在 `reqwest` 之上构建，提供了重试机制、速率限制和结构化响应处理。

## 2. 核心组件

### 2.1 HTTP 客户端 (`HttpClient`)
- **功能**: 提供统一的 GET, POST, POST-JSON, HEAD 请求接口。
- **配置**: 支持自定义超时、连接池大小、User-Agent 和重定向策略。
- **响应处理**: 自动将原始响应转换为 `HttpResponse` 结构体，支持便捷的文本和 JSON 解析。

### 2.2 重试策略 (`RetryPolicy`)
- **用途**: 应对不稳定的网络环境或 ACME 服务器的临时故障。
- **策略**: 支持固定间隔重试和指数退避（Exponential Backoff）重试。

### 2.3 速率限制 (`RateLimiter`)
- **用途**: 确保客户端遵循 ACME 服务器的速率限制要求（RFC 8555），防止被封禁。
- **实现**: 基于令牌桶或类似算法限制单位时间内的请求数。

### 2.4 中间件系统 (`Middleware`)
- **功能**: 允许在请求发起前或响应返回后注入自定义逻辑。
- **应用场景**: 自动注入 Nonce、记录请求耗时、统一错误处理等。

## 3. 工业级特性
- **结构化日志**: 记录每个请求的 URL、方法、状态码及响应体大小，极大地方便了协议层面的调试。
- **错误分类**: 将网络异常、解析失败和协议错误进行明确分类，提供清晰的故障上下文。
- **连接池优化**: 通过配置 `pool_max_idle_per_host` 提升高并发场景下的性能。

## 4. 使用示例
```rust
let config = HttpClientConfig {
    timeout: Duration::from_secs(10),
    ..Default::default()
};
let client = HttpClient::new(config)?;

let resp = client.get("https://acme-v02.api.letsencrypt.org/directory").await?;
if resp.is_success() {
    let directory: Directory = resp.json()?;
}
```
