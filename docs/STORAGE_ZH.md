# AcmeX 存储层 (Storage) 功能文档

## 1. 概述
存储层负责 AcmeX 中所有持久化数据的管理，包括账户私钥、已签发的证书链、订单状态以及会话 Nonce。它采用可插拔的架构，支持多种后端并提供透明的加密保护。

## 2. 核心后端

### 2.1 文件存储 (`FileStorage`)
- **用途**: 适用于单机部署或简单的 CLI 工具。
- **特性**: 将数据以文件形式存储在指定的本地目录中，支持自动创建子目录。

### 2.2 Redis 存储 (`RedisStorage`)
- **用途**: 适用于分布式环境或高可用集群。
- **特性**: 
  - 使用 `ConnectionManager` 实现自动重连和连接池管理。
  - 支持跨实例的状态共享，确保集群中只有一个节点执行续订任务。
  - 基于前缀的键值管理。

### 2.3 内存存储 (`MemoryStorage`)
- **用途**: 仅用于单元测试或临时会话。
- **特性**: 基于 `HashMap` 和 `RwLock` 实现，进程退出后数据丢失。

## 3. 安全增强：加密包装器 (`EncryptedStorage`)
为了保护敏感数据（如账户私钥），AcmeX 提供了一个透明的加密层。
- **算法**: AES-256-GCM (Authenticated Encryption)。
- **特性**:
  - **静态加密**: 数据在写入底层后端（如 Redis 或文件）前被加密。
  - **唯一随机数**: 每个存储条目都使用独立的 12 字节 Nonce，防止重放攻击和模式分析。
  - **后端无关**: 可以包装任何实现了 `StorageBackend` trait 的后端。

## 4. 存储迁移工具 (`StorageMigrator`)
支持在不同存储后端之间进行数据迁移（例如从文件迁移到 Redis），确保系统升级时的平滑过渡。

## 5. 证书存储抽象 (`CertificateStore`)
在 `StorageBackend` 之上提供了更高层的 API，专门用于管理证书包（Certificate Bundle），支持按域名检索和自动关联私钥。

## 6. 配置示例 (YAML)
```yaml
storage:
  type: "redis"
  redis_url: "redis://127.0.0.1:6379/0"
  encryption_key: "32-byte-hex-encoded-key..."
```
