//! 重试策略 - 指数退避、线性退避等

use std::time::Duration;

/// 重试策略枚举
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    /// 指数退避 (初始延迟，最大延迟，倍数)
    ExponentialBackoff {
        initial_delay: Duration,
        max_delay: Duration,
        multiplier: f64,
    },
    /// 线性退避 (初始延迟，增量)
    LinearBackoff {
        initial_delay: Duration,
        increment: Duration,
    },
    /// 固定延迟
    FixedDelay(Duration),
    /// 不重试
    NoRetry,
}

impl Default for RetryStrategy {
    fn default() -> Self {
        Self::ExponentialBackoff {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl RetryStrategy {
    /// 计算第 N 次重试的延迟
    pub fn delay(&self, attempt: u32) -> Duration {
        match self {
            RetryStrategy::ExponentialBackoff {
                initial_delay,
                max_delay,
                multiplier,
            } => {
                let delay_ms = initial_delay.as_millis() as f64 * multiplier.powi(attempt as i32);
                let delay = Duration::from_millis(delay_ms as u64);
                delay.min(*max_delay)
            }
            RetryStrategy::LinearBackoff {
                initial_delay,
                increment,
            } => initial_delay.saturating_add(increment.saturating_mul(attempt)),
            RetryStrategy::FixedDelay(delay) => *delay,
            RetryStrategy::NoRetry => Duration::ZERO,
        }
    }
}

/// 重试策略配置
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// 重试次数
    pub max_retries: u32,
    /// 重试策略
    pub strategy: RetryStrategy,
    /// 是否重试 4xx 错误
    pub retry_on_client_error: bool,
    /// 是否重试 5xx 错误
    pub retry_on_server_error: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            strategy: RetryStrategy::default(),
            retry_on_client_error: false,
            retry_on_server_error: true,
        }
    }
}

impl RetryPolicy {
    /// 检查是否应该重试
    pub fn should_retry(&self, status_code: u16, attempt: u32) -> bool {
        if attempt >= self.max_retries {
            return false;
        }

        match status_code {
            400..=499 => self.retry_on_client_error,
            500..=599 => self.retry_on_server_error,
            _ => false,
        }
    }

    /// 获取重试延迟
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        self.strategy.delay(attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exponential_backoff() {
        let strategy = RetryStrategy::ExponentialBackoff {
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        };

        let delay0 = strategy.delay(0);
        let delay1 = strategy.delay(1);
        let delay2 = strategy.delay(2);

        assert!(delay0 < delay1);
        assert!(delay1 < delay2);
    }

    #[test]
    fn test_retry_policy_should_retry() {
        let policy = RetryPolicy::default();

        assert!(!policy.should_retry(200, 0)); // Success, don't retry
        assert!(policy.should_retry(500, 0)); // Server error, retry
        assert!(!policy.should_retry(500, 3)); // Max retries exceeded
    }
}
