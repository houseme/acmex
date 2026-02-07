//! 速率限制 - 防止请求超限

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

/// 速率限制器 - 基于令牌桶算法
pub struct RateLimiter {
    /// 最大令牌数
    max_tokens: u32,
    /// 令牌补充速率 (令牌/秒)
    refill_rate: u32,
    /// 当前令牌数
    tokens: Arc<Mutex<f64>>,
    /// 最后更新时间
    last_update: Arc<AtomicU64>,
}

impl RateLimiter {
    /// 创建新的速率限制器
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        Self {
            max_tokens,
            refill_rate,
            tokens: Arc::new(Mutex::new(max_tokens as f64)),
            last_update: Arc::new(AtomicU64::new(now)),
        }
    }

    /// 每秒 10 个请求的限制器
    pub fn per_second(rate: u32) -> Self {
        Self::new(rate * 10, rate)
    }

    /// 尝试获取令牌
    pub async fn acquire(&self, tokens: u32) -> bool {
        let mut current = self.tokens.lock().await;

        // 更新令牌
        self.refill(&mut current);

        if *current >= tokens as f64 {
            *current -= tokens as f64;
            true
        } else {
            false
        }
    }

    /// 等待直到可以获取令牌
    pub async fn wait_for_token(&self, tokens: u32) {
        loop {
            if self.acquire(tokens).await {
                return;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// 补充令牌
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

    /// 获取当前令牌数 (近似值)
    pub async fn current_tokens(&self) -> f64 {
        *self.tokens.lock().await
    }
}

/// 请求限制器 - 限制并发请求数
pub struct RequestLimiter {
    /// 最大并发请求
    max_concurrent: u32,
    /// 当前请求数
    current: Arc<AtomicU64>,
}

impl RequestLimiter {
    /// 创建新的请求限制器
    pub fn new(max_concurrent: u32) -> Self {
        Self {
            max_concurrent,
            current: Arc::new(AtomicU64::new(0)),
        }
    }

    /// 检查是否可以开始新请求
    pub fn can_request(&self) -> bool {
        let current = self.current.load(Ordering::Acquire);
        current < self.max_concurrent as u64
    }

    /// 开始请求
    pub fn start_request(&self) -> Result<RequestGuard, &'static str> {
        if self.can_request() {
            self.current.fetch_add(1, Ordering::Release);
            Ok(RequestGuard {
                limiter: Arc::new(self.clone()),
            })
        } else {
            Err("Maximum concurrent requests exceeded")
        }
    }

    /// 获取当前请求数
    pub fn current_requests(&self) -> u64 {
        self.current.load(Ordering::Acquire)
    }

    fn finish_request(&self) {
        self.current.fetch_sub(1, Ordering::Release);
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

/// 请求守卫 - 自动管理请求生命周期
pub struct RequestGuard {
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

        // 应该成功获取 5 个令牌
        assert!(limiter.acquire(5).await);

        // 应该成功获取 5 个令牌
        assert!(limiter.acquire(5).await);

        // 应该失败 (没有足够的令牌)
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
