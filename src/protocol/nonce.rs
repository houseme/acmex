/// Nonce management for ACME protocol
use crate::error::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Manager for ACME nonce with pooling
pub struct NonceManager {
    new_nonce_url: String,
    http_client: reqwest::Client,
    nonce_pool: Arc<Mutex<Vec<String>>>,
}

impl NonceManager {
    /// Create a new nonce manager
    pub fn new(new_nonce_url: impl Into<String>, http_client: reqwest::Client) -> Self {
        Self {
            new_nonce_url: new_nonce_url.into(),
            http_client,
            nonce_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Get a nonce from the pool or fetch a new one
    pub async fn get_nonce(&self) -> Result<String> {
        {
            let mut pool = self.nonce_pool.lock().await;
            if let Some(nonce) = pool.pop() {
                return Ok(nonce);
            }
        }

        self.fetch_nonce().await
    }

    /// Fetch a fresh nonce from the server
    async fn fetch_nonce(&self) -> Result<String> {
        let response = self
            .http_client
            .head(&self.new_nonce_url)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to fetch nonce: {}", e))
            })?;

        if !response.status().is_success() {
            return Err(crate::error::AcmeError::protocol(format!(
                "Failed to fetch nonce: HTTP {}",
                response.status()
            )));
        }

        response
            .headers()
            .get("replay-nonce")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                crate::error::AcmeError::protocol("Missing replay-nonce header".to_string())
            })
    }

    /// Cache a nonce for future use
    pub async fn cache_nonce(&self, nonce: String) {
        let mut pool = self.nonce_pool.lock().await;
        pool.push(nonce);
    }

    /// Clear the nonce pool
    pub async fn clear_pool(&self) {
        let mut pool = self.nonce_pool.lock().await;
        pool.clear();
    }

    /// Get current pool size (for testing/debugging)
    pub async fn pool_size(&self) -> usize {
        let pool = self.nonce_pool.lock().await;
        pool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nonce_manager_creation() {
        let manager =
            NonceManager::new("https://example.com/acme/new-nonce", reqwest::Client::new());
        assert_eq!(manager.pool_size().await, 0);
    }

    #[tokio::test]
    async fn test_cache_nonce() {
        let manager =
            NonceManager::new("https://example.com/acme/new-nonce", reqwest::Client::new());
        manager.cache_nonce("test-nonce-123".to_string()).await;
        assert_eq!(manager.pool_size().await, 1);

        let nonce = manager.get_nonce().await;
        assert!(nonce.is_ok());
        assert_eq!(nonce.unwrap(), "test-nonce-123");
        assert_eq!(manager.pool_size().await, 0);
    }

    #[tokio::test]
    async fn test_clear_pool() {
        let manager =
            NonceManager::new("https://example.com/acme/new-nonce", reqwest::Client::new());
        manager.cache_nonce("nonce-1".to_string()).await;
        manager.cache_nonce("nonce-2".to_string()).await;
        assert_eq!(manager.pool_size().await, 2);

        manager.clear_pool().await;
        assert_eq!(manager.pool_size().await, 0);
    }
}
