# AcmeX 可观测性指南 (Observability)

AcmeX 内置了完善的监控、日志和链路追踪支持，基于 `tracing` 和 `OpenTelemetry` 体系。

## 1. 链路追踪 (Distributed Tracing)

AcmeX 支持 OTLP (OpenTelemetry Line Protocol) 协议，可以将追踪数据发送到 Jaeger, Tempo, 或 Datadog。

### 配置

在启动服务器时，可以通过环境变量配置 OTLP 导出器：

```bash
# 启用 OTLP 导出 (默认推送到 http://localhost:4317)
export OTEL_EXPORTER_OTLP_ENDPOINT="http://jaeger-collector:4317"
export OTEL_SERVICE_NAME="acmex-server"

# 运行服务器
acmex serve
```

### 追踪范围

- **ACME 请求**: 记录每个与子服务器（Let's Encrypt 等）交互的延迟和状态。
- **挑战验证**: 追踪 DNS/HTTP 验证的详细步骤。
- **存储操作**: 监控 Redis 或文件系统的读写性能。

## 2. 指标监控 (Metrics)

AcmeX 集成了 Prometheus 指标导出。

### 端点

- `GET /metrics` (如果启用 API 模式)

### 关键指标

| 指标名称                                | 类型        | 说明           |
|-------------------------------------|-----------|--------------|
| `acmex_orders_total`                | Counter   | 总订单数 (按状态分类) |
| `acmex_challenges_duration_seconds` | Histogram | 挑战验证耗时       |
| `acmex_cert_expiry_timestamp`       | Gauge     | 证书过期时间戳      |
| `acmex_nonce_pool_size`             | Gauge     | 当前 Nonce 池余量 |

## 3. 审计日志 (Audit Logs)

关键业务行为（如：撤销证书、删除账户）会生成审计事件。

```rust
// 示例审计事件
event_auditor.track_event(Event {
action: "certificate_revoke",
actor: "admin-api-key-1",
resource: "example.com",
timestamp: 1700000000
});
```

## 4. Grafana 仪表盘

我们提供了预设的 Grafana 面板 JSON（位于 `examples/grafana/`），可以快速可视化：

- 证书续期成功率。
- 即将到期的域名预警。
- API 响应分布。

