# AcmeX 多 CA (Certificate Authority) 支持文档

## 1. 概述
AcmeX 支持多种 ACME v2 兼容的证书颁发机构。通过统一的配置接口，用户可以轻松地在不同的 CA 之间切换，或配置私有的 ACME 服务端点。

## 2. 支持的 CA 类型

### 2.1 Let's Encrypt (默认)
- **标识符**: `letsencrypt`
- **环境**: 
  - `production`: 签发受信任的正式证书。
  - `staging`: 用于测试，签发不受信任的证书，但速率限制较宽松。

### 2.2 Google Trust Services
- **标识符**: `google`
- **特性开关**: 需要启用 `google-ca` feature。
- **说明**: Google 提供的免费 ACME 服务，通常需要 External Account Binding (EAB)。

### 2.3 ZeroSSL
- **标识符**: `zerossl`
- **特性开关**: 需要启用 `zerossl-ca` feature。
- **说明**: 支持签发 90 天免费证书。

### 2.4 自定义 CA (Custom)
- **标识符**: `custom`
- **说明**: 用于企业内部的 ACME 服务器（如 Step-CA, HashiCorp Vault）。
- **配置**: 必须提供 `ca_custom_url`。

## 3. 配置指南 (TOML)

### 示例：使用 Let's Encrypt 测试环境
```toml
[acme]
ca = "letsencrypt"
ca_environment = "staging"
contact = ["mailto:admin@example.com"]
```

### 示例：使用 Google Trust Services
```toml
[acme]
ca = "google"
# Google 通常需要 EAB
[acme.external_account_binding]
key_id = "your-key-id"
hmac_key = "your-hmac-key"
```

### 示例：使用自定义 CA
```toml
[acme]
ca = "custom"
ca_custom_url = "https://acme.internal.corp/directory"
```

## 4. 环境变量覆盖
可以通过以下环境变量动态修改 CA 配置：
- `ACMEX_ACME_CA`: 设置 CA 类型（如 `google`）。
- `ACMEX_ACME_ENV`: 设置环境（如 `production`）。

## 5. 架构设计优势
- **类型安全**: 使用 Rust 枚举管理 CA 类型，避免拼写错误。
- **延迟解析**: Directory URL 在配置加载阶段自动解析，业务逻辑层只需调用 `acme_directory()`。
- **可扩展性**: 增加新的 CA 只需在 `ca.rs` 中添加一行端点定义。
