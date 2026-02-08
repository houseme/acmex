/// Nonce management for the ACME protocol.
/// This module provides the `NonceManager` which handles the acquisition and
/// caching of anti-replay nonces required for JWS-signed requests.
use crate::error::Result;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A thread-safe manager for ACME nonces.
/// It maintains a local pool of nonces to reduce the number of HEAD requests to the server.
#[derive(Debug, Clone)]
pub struct NonceManager {
    /// The URL used to fetch new nonces.
    nonce_url: String,
    /// The HTTP client used for network requests.
    http_client: reqwest::Client,
    /// A thread-safe pool of cached nonces.
    nonce_pool: Arc<Mutex<Vec<String>>>,
}

impl NonceManager {
    /// Creates a new `NonceManager` with the specified nonce URL and HTTP client.
    pub fn new(new_nonce_url: impl Into<String>, http_client: reqwest::Client) -> Self {
        let url = new_nonce_url.into();
        tracing::debug!("Initializing NonceManager with URL: {}", url);
        Self {
            nonce_url: url,
            http_client,
            nonce_pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Retrieves a nonce from the local pool or fetches a fresh one from the server.
    pub async fn get_nonce(&self) -> Result<String> {
        {
            let mut pool = self.nonce_pool.lock().await;
            if let Some(nonce) = pool.pop() {
                tracing::debug!("Using cached nonce from pool (remaining: {})", pool.len());
                return Ok(nonce);
            }
        }

        tracing::debug!("Nonce pool empty, fetching fresh nonce from server");
        self.fetch_nonce().await
    }

    /// Fetches a fresh anti-replay nonce from the ACME server using a HEAD request.
    async fn fetch_nonce(&self) -> Result<String> {
        tracing::info!("Fetching new nonce from: {}", self.nonce_url);
        let response = self
            .http_client
            .head(&self.nonce_url)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("Network error while fetching nonce: {}", e);
                crate::error::AcmeError::transport(format!("Failed to fetch nonce: {}", e))
            })?;

        if !response.status().is_success() {
            tracing::error!("Failed to fetch nonce, server returned status: {}", response.status());
            return Err(crate::error::AcmeError::protocol(format!(
                "Failed to fetch nonce: HTTP {}",
                response.status()
            )));
        }

        let nonce = response
            .headers()
            .get("replay-nonce")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                tracing::error!("Server response missing 'replay-nonce' header");
                crate::error::AcmeError::protocol("Missing replay-nonce header".to_string())
            })?;

        tracing::debug!("Successfully fetched new nonce");
        Ok(nonce)
    }

    /// Caches a nonce for future use.
    /// This is typically called when a nonce is returned in the header of a successful ACME request.
    pub async fn cache_nonce(&self, nonce: String) {
        let mut pool = self.nonce_pool.lock().await;
        tracing::debug!("Caching nonce (pool size before: {})", pool.len());
        pool.push(nonce);
    }

    /// Clears all nonces from the local pool.
    pub async fn clear_pool(&self) {
        tracing::debug!("Clearing nonce pool");
        let mut pool = self.nonce_pool.lock().await;
        pool.clear();
    }

    /// Returns the current number of nonces in the pool.
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
