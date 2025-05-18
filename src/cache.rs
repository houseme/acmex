use async_trait::async_trait;
use redis::AsyncCommands;
use std::error::Error;

#[async_trait]
pub trait Cache: Send + Sync {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>>;
    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>>;
}

pub struct FileCache {
    path: std::path::PathBuf,
}

impl FileCache {
    pub fn new(path: impl Into<std::path::PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

#[async_trait]
impl Cache for FileCache {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let path = self.path.join(key);
        if path.exists() {
            Ok(Some(std::fs::read(path)?))
        } else {
            Ok(None)
        }
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        let path = self.path.join(key);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, value)?;
        Ok(())
    }
}

#[cfg(feature = "redis")]
pub struct RedisCache {
    client: redis::Client,
}

#[cfg(feature = "redis")]
impl RedisCache {
    pub fn new(redis_url: &str) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            client: redis::Client::open(redis_url)?,
        })
    }
}

#[cfg(feature = "redis")]
#[async_trait]
impl Cache for RedisCache {
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        Ok(conn.get(key).await?)
    }

    async fn store(&self, key: &str, value: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let _: () = conn.set(key, value).await?;
        Ok(())
    }
}
