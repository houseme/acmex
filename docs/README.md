```
src/
├── lib.rs                  # crate 入口
├── client/                 # 核心客户端逻辑
│   ├── mod.rs
│   ├── acme_client.rs      # 主要 API 接口
│   └── acme_config.rs      # 配置管理
├── account/                # 账户管理
│   ├── account.rs          # 注册、密钥生成、JWS 签名
│   └── external_binding.rs # 外部账户绑定（EAB）
├── order/                  # 订单生命周期管理
│   ├── order.rs            # 创建、验证、finalize、下载证书
│   └── authorization.rs    # 授权状态跟踪
├── challenge/              # 挑战验证逻辑
│   ├── challenge.rs        # 通用挑战接口
│   ├── http01.rs           # HTTP-01 实现
│   ├── dns01.rs            # DNS-01 实现（使用 hickory-resolver）
│   └── tls_alpn01.rs       # TLS-ALPN-01 实现
├── cache/                  # 缓存支持
│   ├── file_cache.rs       # 文件缓存（默认）
│   └── redis_cache.rs      # Redis 缓存（通过 feature gate 启用）
├── dns/                    # DNS 工具模块
│   └── resolver.rs         # 封装 hickory-resolver
├── tls/                    # TLS 工具模块
│   └── rustls_utils.rs     # rustls 配置工具
├── cli/                    # 命令行工具
│   ├── main.rs             # CLI 入口
│   └── args.rs             # 参数解析
└── metrics/                # 监控指标（Prometheus）
    └── prometheus.rs       # 指标注册与采集
```

> Rust MSRV: `1.92.0` (对应 `Cargo.toml` 的 `rust-version = "1.92.0"`)
