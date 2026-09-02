# AcmeX 架构规划 vs 现有实现 - 功能对比与待实现清单

> **⚠️ 过时文档（2026-09-01 标注）**：本文是 v0.6.0 时期的架构快照，模块地图不包含 v0.9.0 的新架构
> （`src/domain/`、`src/repository/`、`src/workflow/`、`src/application/`、`src/ca_backend/`、`src/key/`、
> `src/delivery/` 等）。当前真实的功能与验收状态以下列文档为准，本文仅作历史参考：
> - `docs/roadmap/v0.9.0/IMPLEMENTATION_STATUS_AUDIT.md`（实现状态核查）
> - `docs/roadmap/v0.9.0/KNOWN_LIMITATIONS.md`（显式未验证项）
> - `docs/roadmap/v0.9.0/FEATURE_MATRIX.md`（feature 与外部验证矩阵）

**生成日期**: 2026-02-07  
**版本**: v0.6.0  
**状态**: 功能分析报告（已过时，见上方标注）

---

## 📊 总体进度

| 指标     | 规划 | 已实现 | 未实现 | 完成度  |
|--------|----|-----|-----|------|
| 主要模块   | 18 | 18  | 0   | 100% |
| 核心功能   | 23 | 23  | 0   | 100% |
| API 接口 | 12 | 12  | 0   | 100% |
| 测试框架   | 3  | 2.0 | 1.0 | 67%  |

---

## ✅ 已实现的模块 (18 个)

### 核心模块

1. **lib.rs** - 公共 API 导出 ✅
2. **error.rs** - 统一错误类型定义 ✅
3. **types.rs** - 通用类型定义 ✅

### 主要功能模块

4. **protocol/** - ACME 协议层 ✅
    - directory.rs - 目录资源管理
    - nonce.rs - Nonce 管理
    - nonce_pool.rs - Nonce 预取池 ✅ (新增)
    - jws.rs - JWS 签名
    - jwk.rs - JWK 密钥表示

5. **account/** - 账户管理层 ✅
    - manager.rs - 账户生命周期管理 (支持 EAB)
    - credentials.rs - 密钥对管理
    - key_rollover.rs - 密钥轮换 ✅ (新增)

6. **order/** - 订单管理层 ✅
    - manager.rs - 订单管理
    - csr.rs - CSR 生成
    - objects.rs - 订单对象序列化
    - revocation.rs - 证书吊销 ✅ (新增)

7. **challenge/** - 挑战处理层 ✅
    - http01.rs - HTTP-01 验证
    - dns01.rs - DNS-01 验证 (基础)
    - tls_alpn01.rs - TLS-ALPN-01 验证 ✅ (新增)
    - dns_cache.rs - DNS 查询缓存 ✅ (新增)

8. **crypto/** - 加密原语层 ✅
    - keypair.rs - 密钥对生成
    - signer.rs - 签名器
    - hash.rs - 哈希工具
    - encoding.rs - Base64/PEM 编码

9. **transport/** - 传输层 ✅
    - http_client.rs - HTTP 客户端
    - middleware.rs - 请求中间件
    - rate_limit.rs - 速率限制
    - retry.rs - 重试策略

10. **storage/** - 存储抽象层 ✅
    - file.rs - 文件系统存储
    - redis.rs - Redis 存储
    - encrypted.rs - 加密存储
    - memory.rs - 内存存储 ✅ (新增)
    - migration.rs - 存储迁移工具 ✅ (新增)

11. **config/** - 配置管理层 ✅
    - config.rs - 配置解析和管理
    - ca.rs - CA 预设配置

12. **ca.rs** - 多 CA 支持 ✅
    - Let's Encrypt
    - Google Trust Services
    - ZeroSSL
    - Custom CA

13. **renewal/** - 自动续期 ✅
    - RenewalScheduler 实现

14. **metrics/** - 监控层 ✅
    - 基础指标收集

15. **notifications/** - 通知层 ✅
    - Webhook 事件通知

16. **cli/** - CLI 工具层 ✅
    - 基础命令框架
    - 账户管理命令 ✅
    - 证书管理命令 ✅ (新增)
    - 订单管理命令 ✅ (新增)
    - 服务器启动命令 ✅

17. **orchestrator/** - 编排层 ✅
    - provisioner.rs - 证书申请编排器
    - validator.rs - 验证编排器
    - renewer.rs - 续期编排器 ✅ (新增)

18. **scheduler/** - 调度层 ✅
    - renewal_scheduler.rs - 高级续期调度器 ✅ (新增)
    - cleanup_scheduler.rs - 清理调度器 ✅ (新增)

19. **server/** - 服务器层 ✅
    - api.rs - REST API 路由
    - account.rs - 账户 API ✅ (新增)
    - order.rs - 订单 API ✅ (新增)
    - certificate.rs - 证书 API ✅ (新增)
    - webhook.rs - Webhook 处理器
    - health.rs - 健康检查

20. **certificate/** - 证书管理层 ✅
    - chain.rs - 证书链验证

---

## 📋 系统优化计划 (v0.7.0+)

### 1. **OCSP/CRL 实时吊销状态检查**

- **规划位置**: 后续任务重新设计真实 OCSP/CRL verifier；当前仅保留证书 AIA 中 OCSP URL 的解析辅助。
- **优先级**: 中
- **2026-09-02 备注**: T15 已移除原 `src/certificate/ocsp.rs` 模拟实现和公共导出。旧实现只校验
  OCSP URL 形状即返回 `Good`，会把未验证的吊销状态包装成生产能力；在真实 OCSP 请求/响应
  或 CRL 处理实现之前，AcmeX 不宣称提供证书吊销状态检查。
- **信任锚边界**: 证书链信任验收默认要求 `[acme].trust_anchor_pem_files` 提供根 PEM；缺省
  anchors 是失败，不是 `not-checked`。`skip_certificate_trust_check = true` 仅作为显式
  测试/私有 CA bootstrap 逃生口。

### 2. **REST API 业务逻辑完整化**

- **描述**: 目前 API 处理器已建立，但部分复杂业务逻辑（如订单状态实时轮询）需进一步与 Orchestrator 深度整合。
- **优先级**: 高

---

## 🎯 实现路线图

### Phase 1 & 2 (已完成)

- [x] Account Key Rollover
- [x] Certificate Revocation
- [x] Basic Orchestrator
- [x] Account CLI Commands
- [x] TLS-ALPN-01 Support
- [x] Certificate Chain Verification
- [x] Server Mode (基础)
- [x] DNS Query Caching

### Phase 3 (已完成)

- [x] Advanced Scheduler (优先级/并发/重试)
- [x] Storage Migration (跨后端迁移)
- [x] Distributed Tracing (OTLP/Tracing)
- [x] Advanced CLI Commands (Cert/Order 集成)
- [x] Nonce Pool (性能优化)
- [x] Memory Storage (测试驱动)

---

**报告版本**: v1.3
**生成日期**: 2026-02-07  
**下一次审查**: v0.7.0 规划时
