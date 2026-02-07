/// Redis storage backend
use async_trait::async_trait;
use redis::AsyncCommands;

use super::StorageBackend;
use crate::error::{AcmeError, Result};

/// Redis storage
pub struct RedisStorage {
    client: redis::Client,
}

impl RedisStorage {
    pub fn new(redis_url: &str) -> Result<Self> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| AcmeError::storage(format!("Redis connect error: {}", e)))?;
        Ok(Self { client })
    }

    async fn conn(&self) -> Result<redis::aio::ConnectionManager> {
        self.client
            .get_connection_manager()
            .await
            .map_err(|e| AcmeError::storage(format!("Redis conn error: {}", e)))
    }
}

#[async_trait]
impl StorageBackend for RedisStorage {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let mut conn = self.conn().await?;
        let _: () = conn
            .set(key, value)
            .await
            .map_err(|e| AcmeError::storage(format!("Redis set error: {}", e)))?;
        Ok(())
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let mut conn = self.conn().await?;
        let data: Option<Vec<u8>> = conn
            .get(key)
            .await
            .map_err(|e| AcmeError::storage(format!("Redis get error: {}", e)))?;
        Ok(data)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let _: () = conn
            .del(key)
            .await
            .map_err(|e| AcmeError::storage(format!("Redis del error: {}", e)))?;
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        let mut conn = self.conn().await?;
        let pattern = format!("{}*", prefix);
        let keys: Vec<String> = conn
            .keys(pattern)
            .await
            .map_err(|e| AcmeError::storage(format!("Redis keys error: {}", e)))?;
        Ok(keys)
    }
}
