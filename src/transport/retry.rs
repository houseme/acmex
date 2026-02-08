/// Retry strategies and policies for network requests.
/// This module provides various algorithms for calculating retry delays,
/// such as exponential backoff and linear backoff, to improve system resilience.
use std::time::Duration;

/// Enumeration of supported retry strategies.
#[derive(Debug, Clone)]
pub enum RetryStrategy {
    /// Exponential backoff: delay increases exponentially with each attempt.
    /// Formula: `initial_delay * multiplier ^ attempt`, capped at `max_delay`.
    ExponentialBackoff {
        /// The delay for the first retry.
        initial_delay: Duration,
        /// The maximum allowable delay between retries.
        max_delay: Duration,
        /// The factor by which the delay increases each time.
        multiplier: f64,
    },
    /// Linear backoff: delay increases by a fixed increment with each attempt.
    LinearBackoff {
        /// The delay for the first retry.
        initial_delay: Duration,
        /// The amount to add to the delay for each subsequent attempt.
        increment: Duration,
    },
    /// Fixed delay: the same delay is used for every retry attempt.
    FixedDelay(Duration),
    /// No retry: requests are never retried.
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
    /// Calculates the delay duration for the specified attempt number (0-indexed).
    pub fn delay(&self, attempt: u32) -> Duration {
        let d = match self {
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
        };

        tracing::debug!("Calculated retry delay for attempt {}: {:?}", attempt, d);
        d
    }
}

/// Configuration for a retry policy, defining when and how to retry failed requests.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// The maximum number of retry attempts allowed.
    pub max_retries: u32,
    /// The strategy used to calculate delays between retries.
    pub strategy: RetryStrategy,
    /// Whether to retry requests that failed with a 4xx client error.
    pub retry_on_client_error: bool,
    /// Whether to retry requests that failed with a 5xx server error.
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
    /// Determines whether a request should be retried based on the status code and attempt count.
    pub fn should_retry(&self, status_code: u16, attempt: u32) -> bool {
        if attempt >= self.max_retries {
            tracing::warn!("Maximum retry attempts ({}) reached", self.max_retries);
            return false;
        }

        let retry = match status_code {
            400..=499 => self.retry_on_client_error,
            500..=599 => self.retry_on_server_error,
            _ => false,
        };

        if retry {
            tracing::info!("Request failed with status {}, scheduling retry attempt {}", status_code, attempt + 1);
        } else {
            tracing::debug!("Request failed with status {}, no retry scheduled", status_code);
        }

        retry
    }

    /// Returns the delay duration for the specified retry attempt.
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
