/// Rate limiting and concurrency control for network requests.
/// This module provides a token bucket-based rate limiter and a concurrent
/// request limiter to ensure compliance with ACME server limits.
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// A rate limiter based on the token bucket algorithm.
/// It controls the rate of requests by requiring a token for each operation.
pub struct RateLimiter {
    /// Maximum number of tokens the bucket can hold.
    max_tokens: u32,
    /// Rate at which tokens are added to the bucket (tokens per second).
    refill_rate: u32,
    /// Current number of tokens in the bucket.
    tokens: Arc<Mutex<f64>>,
    /// Timestamp of the last token refill.
    last_update: Arc<AtomicU64>,
}

impl RateLimiter {
    /// Creates a new `RateLimiter` with the specified capacity and refill rate.
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        tracing::debug!("Initializing RateLimiter (max: {}, rate: {}/s)", max_tokens, refill_rate);
        Self {
            max_tokens,
            refill_rate,
            tokens: Arc::new(Mutex::new(max_tokens as f64)),
            last_update: Arc::new(AtomicU64::new(now)),
        }
    }

    /// Creates a rate limiter that allows a specific number of requests per second.
    pub fn per_second(rate: u32) -> Self {
        Self::new(rate * 10, rate)
    }

    /// Attempts to acquire the specified number of tokens. Returns `true` if successful.
    pub async fn acquire(&self, tokens: u32) -> bool {
        let mut current = self.tokens.lock().await;

        // Refill tokens based on elapsed time
        self.refill(&mut current);

        if *current >= tokens as f64 {
            *current -= tokens as f64;
            tracing::debug!("Token acquired (remaining: {:.2})", *current);
            true
        } else {
            tracing::warn!("Rate limit exceeded: not enough tokens (available: {:.2})", *current);
            false
        }
    }

    /// Blocks until the specified number of tokens can be acquired.
    pub async fn wait_for_token(&self, tokens: u32) {
        tracing::debug!("Waiting for {} tokens...", tokens);
        loop {
            if self.acquire(tokens).await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Internal helper to refill the token bucket based on elapsed time.
    fn refill(&self, tokens: &mut f64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let last = self.last_update.load(Ordering::Relaxed);
        let elapsed_ms = now.saturating_sub(last);
        let elapsed_secs = elapsed_ms as f64 / 1000.0;

        let new_tokens = *tokens + (self.refill_rate as f64 * elapsed_secs);
        *tokens = new_tokens.min(self.max_tokens as f64);

        self.last_update.store(now, Ordering::Relaxed);
    }

    /// Returns the current number of tokens in the bucket (approximate).
    pub async fn current_tokens(&self) -> f64 {
        *self.tokens.lock().await
    }
}

/// A limiter that restricts the number of concurrent requests.
pub struct RequestLimiter {
    /// Maximum number of concurrent requests allowed.
    max_concurrent: u32,
    /// Current number of active requests.
    current: Arc<AtomicU64>,
}

impl RequestLimiter {
    /// Creates a new `RequestLimiter` with the specified concurrency limit.
    pub fn new(max_concurrent: u32) -> Self {
        tracing::debug!("Initializing RequestLimiter (max concurrent: {})", max_concurrent);
        Self {
            max_concurrent,
            current: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns true if a new request can be started.
    pub fn can_request(&self) -> bool {
        let current = self.current.load(Ordering::Acquire);
        current < self.max_concurrent as u64
    }

    /// Attempts to start a new request. Returns a `RequestGuard` on success.
    pub fn start_request(&self) -> Result<RequestGuard, &'static str> {
        if self.can_request() {
            let prev = self.current.fetch_add(1, Ordering::Release);
            tracing::debug!("Request started (active: {})", prev + 1);
            Ok(RequestGuard {
                limiter: Arc::new(self.clone()),
            })
        } else {
            tracing::warn!("Concurrency limit reached: {}", self.max_concurrent);
            Err("Maximum concurrent requests exceeded")
        }
    }

    /// Returns the current number of active requests.
    pub fn current_requests(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    /// Internal helper to decrement the active request count.
    fn finish_request(&self) {
        let prev = self.current.fetch_sub(1, Ordering::Release);
        tracing::debug!("Request finished (active: {})", prev - 1);
    }
}

impl Clone for RequestLimiter {
    fn clone(&self) -> Self {
        Self {
            max_concurrent: self.max_concurrent,
            current: Arc::clone(&self.current),
        }
    }
}

/// A guard that automatically decrements the active request count when dropped.
pub struct RequestGuard {
    /// Reference to the parent limiter.
    limiter: Arc<RequestLimiter>,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        self.limiter.finish_request();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(10, 10);

        // Should succeed
        assert!(limiter.acquire(5).await);

        // Should succeed
        assert!(limiter.acquire(5).await);

        // Should fail (no tokens left)
        assert!(!limiter.acquire(1).await);
    }

    #[test]
    fn test_request_limiter() {
        let limiter = RequestLimiter::new(2);

        assert!(limiter.can_request());
        let _guard1 = limiter.start_request().unwrap();

        assert!(limiter.can_request());
        let _guard2 = limiter.start_request().unwrap();

        assert!(!limiter.can_request());

        drop(_guard1);
        assert!(limiter.can_request());
    }
}
