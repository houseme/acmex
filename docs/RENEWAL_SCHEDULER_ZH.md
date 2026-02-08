# AcmeX 续订与调度系统 (Renewal & Scheduler) 功能文档

## 1. 概述
AcmeX 提供了一套完整的自动化证书续订机制，旨在确保用户托管的证书永远不会过期。系统包含简单的定时轮询器和支持高并发、优先级的先进调度器。

## 2. 证书续订逻辑 (`renewal`)

### 2.1 续订触发机制
- **过期检查**: 系统会自动解析存储中的 X.509 证书，提取 `NotAfter` 时间戳。
- **续订窗口**: 默认在证书过期前 30 天触发续订流程（可配置）。
- **预检逻辑**: 在发起 ACME 请求前，会对比当前时间、过期时间和续订阈值。

### 2.2 续订钩子 (`RenewalHook`)
提供了一套回调接口，允许用户在续订的关键节点注入自定义逻辑：
- `before_renewal`: 续订开始前触发（可用于清理旧配置）。
- `after_renewal`: 续订成功后触发（可用于重启 Web 服务器或分发证书）。
- `on_error`: 续订失败时触发（可用于发送告警通知）。

## 3. 任务调度层 (`scheduler`)

### 3.1 简单调度器 (`SimpleRenewalScheduler`)
- **特点**: 单线程、顺序执行。
- **适用场景**: 证书数量较少（< 100）的简单部署环境。

### 3.2 先进调度器 (`AdvancedRenewalScheduler`)
- **优先级队列**: 使用 `BinaryHeap` 管理任务，支持 `Urgent`（紧急）、`High`（高）、`Normal`（普通）、`Low`（低）四级优先级。
- **并发控制**: 基于 `tokio::sync::Semaphore` 实现并发限制，防止因同时发起大量签发请求而被 ACME 服务器限流。
- **异步通知**: 使用 `tokio::sync::Notify` 实现任务唤醒，确保低延迟响应。
- **自动重试**: 任务失败后会自动重新入队，支持最多 3 次重试。

## 4. 优先级定义
- **Urgent**: 证书已过期或将在 24 小时内过期。
- **High**: 证书将在 7 天内过期。
- **Normal**: 证书进入续订窗口（30 天内）。
- **Low**: 证书有效期充足，仅进行例行检查。

## 5. 配置与使用示例

### 启动先进调度器
```rust
let (scheduler, tx) = AdvancedRenewalScheduler::new(client, store, 5); // 并发数为 5
let scheduler_arc = Arc::new(scheduler);

// 在后台运行调度器
tokio::spawn(async move {
    scheduler_arc.run().await;
});

// 手动添加一个紧急续订任务
tx.send(RenewalTask {
    domains: vec!["example.com".to_string()],
    priority: Priority::Urgent,
    retry_count: 0,
}).await?;
```
