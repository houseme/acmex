# 📚 AcmeX 项目文档索引

**项目版本**: v0.7.0 (Development)  
**最后更新**: 2026-02-08  
**文档语言**: 中文

---

## 🚀 快速导航

### 🎯 我是新用户

1. 先读 → [项目主要介绍](./MAIN_README.md)
2. 再看 → [5 分钟快速开始](../README.md)
3. 查阅 → [v0.7.0 规划方案](./V0.7.0_PLANNING.md) - ⭐ 推荐 (New Phase)
4. 学习 → [v0.5.0 功能指南](./V0.5.0_FEATURES_GUIDE.md)

### 📖 我想学习详细内容

1. **v0.1.0-v0.5.0** → [核心到企业特性的演进报告](./FINAL_PROJECT_SUMMARY.md)
2. **v0.6.0** → [高级调度与性能优化完成报告](./V0.6.0_COMPLETION_REPORT.md) - ⭐ 最新完成
3. **v0.7.0** → [服务器模式强化实现方案](./V0.7.0_IMPLEMENTATION_DETAIL_PLAN.md) - 🚀 施工中

### 💻 我想写代码

1. [AGENTS.md](../AGENTS.md) - ⭐ **必读：Agent 开发规范**
2. [V0.7.0_IMPLEMENTATION_DETAIL_PLAN.md](./V0.7.0_IMPLEMENTATION_DETAIL_PLAN.md) - 服务器异步架构详解
3. [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md) - 基础功能配置参考
4. [V0.3.0_INTEGRATION_EXAMPLES.md](./V0.3.0_INTEGRATION_EXAMPLES.md) - v0.3.0 示例

### 🔍 我想深入某个功能

- **多 CA 支持** → [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-多ca支持)
- **新 DNS 提供商** → [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-dns-提供商扩展)
- **Webhook 通知** → [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-webhook-通知系统)
- HTTP-01 验证 → [HTTP-01_IMPLEMENTATION.md](./HTTP-01_IMPLEMENTATION.md)
- DNS-01 验证 → [DNS-01_IMPLEMENTATION.md](./DNS-01_IMPLEMENTATION.md)
- 自动续期 → [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-自动续期系统)
- DNS 提供商 → [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-内置-dns-提供商)
- 证书存储 → [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-证书存储后端)

### 📊 我想了解项目全貌

1. [FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md) - 最终项目总结
2. [V0.5.0_FINAL_STATUS.md](./V0.5.0_FINAL_STATUS.md) - v0.5.0 最终状态
3. [COMPLETE_CHECKLIST.md](./COMPLETE_CHECKLIST.md) - 完整文件清单
4. [DELIVERABLES_CHECKLIST.md](./DELIVERABLES_CHECKLIST.md) - 交付清单

---

## 📑 文档分类

### 📖 版本报告 (5 个)

按时间顺序阅读，了解项目演进：

1. **[V0.1.0_COMPLETION_REPORT.md](./V0.1.0_COMPLETION_REPORT.md)** (500+ 行)
    - 核心 ACME 协议实现
    - Account、KeyPair、Directory、Nonce
    - 基础错误处理和类型系统

2. **[V0.2.0_COMPLETION_REPORT.md](./V0.2.0_COMPLETION_REPORT.md)** (500+ 行)
    - HTTP-01 验证服务器
    - DNS-01 记录管理
    - ChallengeSolver 框架
    - Mock DNS 提供商

3. **[V0.3.0_COMPLETION_REPORT.md](./V0.3.0_COMPLETION_REPORT.md)** (500+ 行)
    - OrderManager 订单管理
    - CSR 生成和签署
    - 高级 AcmeClient API
    - 证书验证工具

4. **[V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md)** (600+ 行)
    - 4 个 DNS 提供商
    - RenewalScheduler 自动续期
    - 3 种存储后端 + 加密
    - Prometheus 监控
    - CLI 工具骨架

5. **[V0.5.0_COMPLETION_REPORT.md](./V0.5.0_COMPLETION_REPORT.md)** ⭐ 最新 (800+ 行)
    - 多 CA 支持 (4 个 CA)
    - 5 个新 DNS 提供商
    - Webhook 通知系统
    - Feature gates 灵活编译
    - 配置管理增强
    - temp-env 安全测试

### 💡 使用指南和特性 (4 个)

实战代码和最佳实践：

1. **[MAIN_README.md](./MAIN_README.md)**
    - 项目概览和快速开始
    - 核心特性总结
    - 使用场景分类
    - 快速命令参考

2. **[V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md)** ⭐ 推荐 (470+ 行)
    - 多 CA 使用指南
    - Feature gates 使用说明
    - 9 个 DNS 提供商配置
    - Webhook 通知配置
    - 安全测试实践

3. **[V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md)** (800+ 行)
    - DNS 提供商详细用法
    - 自动续期系统使用
    - 存储后端选择和配置
    - Prometheus 指标集成
    - CLI 工具命令大全
    - Feature flags 使用

4. **[V0.3.0_INTEGRATION_EXAMPLES.md](./V0.3.0_INTEGRATION_EXAMPLES.md)** (600+ 行)
    - HTTP-01 完整示例
    - DNS-01 完整示例
    - 手动订单流程
    - 自定义 DNS 提供商
    - 批量操作示例
    - 错误处理示例
    - 错误处理示例

### 🔬 技术文档 (4 个)

深入实现细节：

1. **[HTTP-01_IMPLEMENTATION.md](./HTTP-01_IMPLEMENTATION.md)**
    - Axum 服务器架构
    - Token 路由实现
    - 生命周期管理
    - 并发处理

2. **[DNS-01_IMPLEMENTATION.md](./DNS-01_IMPLEMENTATION.md)**
    - DnsProvider 接口设计
    - SHA256 哈希计算
    - Mock 实现详解
    - 记录管理流程

3. **[CHALLENGE_EXAMPLES.md](./CHALLENGE_EXAMPLES.md)** (600+ 行)
    - 各种挑战验证示例
    - 错误处理最佳实践
    - 性能优化建议

4. **[INTEGRATION_EXAMPLES.md](./INTEGRATION_EXAMPLES.md)**
    - 完整集成工作流
    - 多提供商配置
    - 企业部署模式

### 📋 项目总结 (5 个)

总结和索引：

1. **[FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md)** ⭐ 推荐
    - 完整的项目演进路径
    - 功能对比表
    - 代码和文档统计
    - 生产就绪性评估
    - 学习价值和应用场景
    - 下一步规划

2. **[V0.5.0_FINAL_STATUS.md](./V0.5.0_FINAL_STATUS.md)**
    - v0.5.0 最终状态总结
    - 功能完成情况统计
    - 编译状态和修复指南
    - 后续工作计划

3. **[V0.5.0_IMPLEMENTATION_REPORT.md](./V0.5.0_IMPLEMENTATION_REPORT.md)**
    - v0.5.0 实现详细报告
    - 每个功能的完成度
    - 编译问题和解决方案
    - 代码统计和质量指标

4. **[COMPLETE_CHECKLIST.md](./COMPLETE_CHECKLIST.md)**
    - 文件完整清单
    - 代码行数统计
    - 功能映射表
    - 快速导航

5. **[DELIVERABLES_CHECKLIST.md](./DELIVERABLES_CHECKLIST.md)**
    - 交付物清单
    - 功能完成情况
    - 文档覆盖范围

### 📊 项目统计 (2 个)

1. **[FINAL_V0.2.0_SUMMARY.md](./FINAL_V0.2.0_SUMMARY.md)**
    - v0.2.0 项目完成总结

2. **[README.md](./README.md)**
    - 文档主页和导航

---

## 🎯 按使用场景选择文档

### 场景 1: 我是新手，想快速了解

→ [MAIN_README.md](./MAIN_README.md)  
→ [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md) - 快速开始部分  
→ [CHALLENGE_EXAMPLES.md](./CHALLENGE_EXAMPLES.md) - 基础示例

**预计时间**: 30 分钟

### 场景 2: 我想申请简单的证书

→ [MAIN_README.md](./MAIN_README.md)  
→ [CHALLENGE_EXAMPLES.md](./CHALLENGE_EXAMPLES.md) - HTTP-01 示例  
→ [V0.3.0_COMPLETION_REPORT.md](./V0.3.0_COMPLETION_REPORT.md)

**预计时间**: 1 小时

### 场景 3: 我想使用 DNS-01 和通配符

→ [V0.2.0_COMPLETION_REPORT.md](./V0.2.0_COMPLETION_REPORT.md) - DNS-01 基础  
→ [DNS-01_IMPLEMENTATION.md](./DNS-01_IMPLEMENTATION.md) - 实现细节  
→ [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md) - DNS 提供商部分

**预计时间**: 1-2 小时

### 场景 4: 我要部署企业级系统

→ [FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md) - 架构概览  
→ [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md) - 各功能详解  
→ [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md) - 完整功能使用  
→ [INTEGRATION_EXAMPLES.md](./INTEGRATION_EXAMPLES.md) - 企业部署示例

**预计时间**: 3-4 小时

### 场景 5: 我想贡献代码

→ [COMPLETE_CHECKLIST.md](./COMPLETE_CHECKLIST.md) - 文件结构  
→ [V0.1.0_COMPLETION_REPORT.md](./V0.1.0_COMPLETION_REPORT.md) - 架构设计  
→ 相应版本的完成报告  
→ 源代码中的文档注释

**预计时间**: 2-3 小时学习

---

## 📚 按主题查找

### 主题：ACME 协议

- [V0.1.0_COMPLETION_REPORT.md](./V0.1.0_COMPLETION_REPORT.md) ⭐ 最详细
- [FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md#-核心模块)

### 主题：挑战验证

- [HTTP-01_IMPLEMENTATION.md](./HTTP-01_IMPLEMENTATION.md)
- [DNS-01_IMPLEMENTATION.md](./DNS-01_IMPLEMENTATION.md)
- [V0.2.0_COMPLETION_REPORT.md](./V0.2.0_COMPLETION_REPORT.md)
- [CHALLENGE_EXAMPLES.md](./CHALLENGE_EXAMPLES.md)

### 主题：证书管理

- [V0.3.0_COMPLETION_REPORT.md](./V0.3.0_COMPLETION_REPORT.md)
- [V0.3.0_INTEGRATION_EXAMPLES.md](./V0.3.0_INTEGRATION_EXAMPLES.md)

### 主题：DNS 提供商

- [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md#1-内置-dns-提供商)
- [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-内置-dns-提供商)

### 主题：自动续期

- [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md#2-自动续期支持)
- [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-自动续期系统)

### 主题：存储和加密

- [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md#3-证书存储后端)
- [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-证书存储后端)

### 主题：CLI 工具

- [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md#5-cli-工具)
- [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-cli-工具使用)

### 主题：监控和指标

- [V0.4.0_COMPLETION_REPORT.md](./V0.4.0_COMPLETION_REPORT.md#4-prometheus-指标)
- [V0.4.0_USAGE_GUIDE.md](./V0.4.0_USAGE_GUIDE.md#-prometheus-指标)

---

## 🔗 关键链接

### 源代码位置

- `/Users/qun/Documents/rust/acme/acmex/src/` - 源代码
- `/Users/qun/Documents/rust/acme/acmex/docs/` - 文档
- `/Users/qun/Documents/rust/acme/acmex/Cargo.toml` - 项目配置

### 快速命令

```bash
# 构建项目
cd /Users/qun/Documents/rust/acme/acmex
cargo build --release

# 运行测试
cargo test

# 生成 API 文档
cargo doc --lib --no-deps --open

# 完整功能构建
cargo build --release \
  --features dns-cloudflare,dns-route53,dns-digitalocean,dns-linode,redis,metrics,cli
```

---

## 📊 文档统计

| 类别     | 数量       | 行数        |
|--------|----------|-----------|
| 版本报告   | 5 个      | 2500+     |
| 使用指南   | 4 个      | 2200+     |
| 技术文档   | 4 个      | 1200+     |
| 项目总结   | 5 个      | 800+      |
| **总计** | **18 个** | **6700+** |

---

## ✨ 推荐阅读顺序

### 第一级 (快速概览 - 30 分钟)

1. [MAIN_README.md](./MAIN_README.md)
2. [FINAL_PROJECT_SUMMARY.md](./FINAL_PROJECT_SUMMARY.md) 快速浏览
3. [V0.5.0_FINAL_STATUS.md](./V0.5.0_FINAL_STATUS.md) - v0.5.0 亮点

### 第二级 (了解功能 - 2 小时)

1. 版本报告系列 (v0.1.0 → v0.5.0)
2. 对应的使用指南

### 第三级 (深入学习 - 4-6 小时)

1. 技术实现文档
2. 完整示例集合
3. 项目架构分析

### 第四级 (生产部署 - 8+ 小时)

1. 完整的 v0.5.0 功能指南
2. 企业部署示例
3. 最佳实践指南
4. 性能优化建议

---

## 🎯 最常提问

**Q: v0.5.0 新增了什么？**  
A: 读 [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md) 了解新功能

**Q: 如何使用多 CA？**  
A: 查看 [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-多ca支持)

**Q: 如何使用新的 DNS 提供商？**  
A: 查看 [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-dns-提供商扩展)

**Q: 如何配置 Webhook 通知？**  
A: 查看 [V0.5.0_FEATURES_GUIDE.md](./V0.5.0_FEATURES_GUIDE.md#-webhook-通知系统)

**Q: Feature gates 有什么用？**  
A: 查看 copilot-instructions.md 中的 Feature Gates 系统部分

---

## 📊 架构分析与缺口补完

### 架构规划 vs 实现对比

- [ARCHITECTURE_COMPARISON_REPORT.md](./ARCHITECTURE_COMPARISON_REPORT.md) ⭐ 全面对比分析
    - 规划：18 个模块，8000+ 行代码
    - 实现：14 个模块，6200+ 行代码 (v0.5.0)
    - 缺口：4 个模块，1800+ 行代码
    - **完成度：78%**

### 未实现功能清单

- [UNIMPLEMENTED_FEATURES.md](./UNIMPLEMENTED_FEATURES.md) - 详细功能规格
    - 4 个完全未实现的模块
    - 10 个部分未实现的功能
    - 优先级分类和工作量估计
    - 3 阶段实现路线图 (v0.6.0, v0.7.0, v1.0.0)

### v0.6.0 实现指南

- [V0.6.0_IMPLEMENTATION_ROADMAP.md](./V0.6.0_IMPLEMENTATION_ROADMAP.md) - 详细步骤指南
    - 每个功能的具体实现步骤
    - 代码框架模板
    - 时间和难度估计
    - 完整的检查清单

---

**文档版本**: v0.7.0 (Development)  
**最后更新**: 2026-02-08  
**维护者**: houseme

🎉 **祝您使用 AcmeX 愉快！**
