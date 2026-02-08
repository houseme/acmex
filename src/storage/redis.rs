/// Redis storage backend implementation.
/// This module provides a distributed storage backend using Redis,
/// supporting high-availability and shared state across multiple instances.
use async_trait::async_trait;
use redis::AsyncCommands;

use super::StorageBackend;
use crate::error::{AcmeError, Result};

/// A storage backend that uses Redis for persistence.
pub struct RedisStorage {
    /// The Redis client.
    client: redis::Client,
}

impl RedisStorage {
    /// Creates a new `RedisStorage` instance with the specified Redis URL.
    pub fn new(redis_url: &str) -> Result<Self> {
        tracing::debug!("Connecting to Redis at: {}", redis_url);
        let client = redis::Client::open(redis_url)
            .map_err(|e| {
                tracing::error!("Failed to open Redis client: {}", e);
                AcmeError::storage(format!("Redis connect error: {}", e))
            })?;
        Ok(Self { client })
    }

    /// Obtains an asynchronous connection manager for Redis.
    async fn conn(&self) -> Result<redis::aio::ConnectionManager> {
        self.client
            .get_connection_manager()
            .await
            .map_err(|e| {
                tracing::error!("Failed to get Redis connection manager: {}", e);
                AcmeError::storage(format!("Redis conn error: {}", e))
            })
    }
}

#[async_trait]
impl StorageBackend for RedisStorage {
    /// Stores a value in Redis using the SET command.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        tracing::debug!("Redis: Storing key '{}'", key);
        let mut conn = self.conn().await?;
        let _: () = conn
            .set(key, value)
            .await
            .map_err(|e| {
                tracing::error!("Redis SET failed for key '{}': {}", key, e);
                AcmeError::storage(format!("Redis set error: {}", e))
            })?;
        Ok(())
    }

    /// Retrieves a value from Redis using the GET command.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        tracing::debug!("Redis: Loading key '{}'", key);
        let mut conn = self.conn().await?;
        let data: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| {
                tracing::error!("Redis GET failed for key '{}': {}", key, e);
                AcmeError::storage(format!("Redis get error: {}", e))
            })?;
        Ok(data)
    }

    /// Deletes a value from Redis using the DEL command.
    async fn delete(&self, key: &str) -> Result<()> {
        tracing::info!("Redis: Deleting key '{}'", key);
        let mut conn = self.conn().await?;
        let _: () = conn
            .del(key)
            .await
            .map_err(|e| {
                tracing::error!("Redis DEL failed for key '{}': {}", key, e);
                AcmeError::storage(format!("Redis del error: {}", e))
            })?;
        Ok(())
    }

    /// Lists keys in Redis matching the prefix using the KEYS command.
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        tracing::debug!("Redis: Listing keys with prefix '{}'", prefix);
        let mut conn = self.conn().await?;
        let pattern = format!("{}*", prefix);
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| {
                tracing::error!("Redis KEYS failed for pattern '{}': {}", pattern, e);
                AcmeError::storage(format!("Redis keys error: {}", e))
            })?;
        Ok(keys)
    }
}
