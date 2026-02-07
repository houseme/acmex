use crate::error::Result;
use crate::protocol::nonce::NonceManager;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info};

/// Nonce pool for pre-fetching and caching nonces to improve performance
pub struct NoncePool {
    nonce_manager: NonceManager,
    nonces: Arc<Mutex<VecDeque<String>>>,
    min_size: usize,
    max_size: usize,
}

impl NoncePool {
    /// Create a new nonce pool
    pub fn new(nonce_manager: NonceManager, min_size: usize, max_size: usize) -> Self {
        Self {
            nonce_manager,
            nonces: Arc::new(Mutex::new(VecDeque::with_capacity(max_size))),
            min_size,
            max_size,
        }
    }

    /// Get a nonce from the pool, fetching more if necessary
    pub async fn get_nonce(&self) -> Result<String> {
        let mut n = self.nonces.lock().await;

        // If we have nonces, return one and trigger refill if below min_size
        if let Some(nonce) = n.pop_front() {
            if n.len() < self.min_size {
                let pool_clone = self.clone_internal();
                tokio::spawn(async move {
                    if let Err(e) = pool_clone.refill().await {
                        debug!("Failed to refill nonce pool: {}", e);
                    }
                });
            }
            return Ok(nonce);
        }

        // No nonces available, fetch one immediately
        drop(n);
        info!("Nonce pool empty, fetching immediate nonce");
        self.nonce_manager.get_nonce().await
    }

    /// Refill the pool to max_size
    pub async fn refill(&self) -> Result<()> {
        let mut n = self.nonces.lock().await;
        let to_fetch = self.max_size - n.len();

        if to_fetch == 0 {
            return Ok(());
        }

        debug!("Refilling nonce pool, fetching {} nonces", to_fetch);
        for _ in 0..to_fetch {
            match self.nonce_manager.get_nonce().await {
                Ok(nonce) => n.push_back(nonce),
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    fn clone_internal(&self) -> Self {
        Self {
            nonce_manager: self.nonce_manager.clone(),
            nonces: self.nonces.clone(),
            min_size: self.min_size,
            max_size: self.max_size,
        }
    }
}
