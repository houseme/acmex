/// Middleware system for HTTP request and response interception.
/// This module defines the `Middleware` trait and `MiddlewareChain` to allow
/// custom logic to be injected into the HTTP request lifecycle.
use super::http_client::HttpResponse;
use super::retry::{RetryPolicy, RetryStrategy};
use crate::error::Result;
use async_trait::async_trait;
use std::time::Duration;

/// A trait for objects that can intercept and process HTTP requests and responses.
#[async_trait]
pub trait Middleware: Send + Sync {
    /// Called before an HTTP request is sent.
    async fn before_request(&self, _url: &str, _method: &str) -> Result<()> {
        Ok(())
    }

    /// Called after an HTTP response is received.
    async fn after_response(&self, _url: &str, _response: &HttpResponse) -> Result<()> {
        Ok(())
    }

    /// Called when an error occurs during the HTTP request lifecycle.
    async fn on_error(&self, _url: &str, _error: &crate::error::AcmeError) -> Result<()> {
        Ok(())
    }

    /// Optional per-request timeout override applied by `HttpClient`.
    fn timeout(&self) -> Option<Duration> {
        None
    }

    /// Optional retry policy override applied by `HttpClient`.
    fn retry_policy(&self) -> Option<RetryPolicy> {
        None
    }
}

/// A chain of middlewares that are executed in sequence.
pub struct MiddlewareChain {
    /// The list of registered middlewares.
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareChain {
    /// Creates a new, empty `MiddlewareChain`.
    pub fn new() -> Self {
        tracing::debug!("Creating new MiddlewareChain");
        Self {
            middlewares: Vec::new(),
        }
    }

    /// Adds a middleware to the end of the chain.
    pub fn push<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    /// Executes the `before_request` hook for all middlewares in the chain.
    pub async fn before_request(&self, url: &str, method: &str) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.before_request(url, method).await?;
        }
        Ok(())
    }

    /// Executes the `after_response` hook for all middlewares in the chain.
    pub async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.after_response(url, response).await?;
        }
        Ok(())
    }

    /// Executes the `on_error` hook for all middlewares in the chain.
    pub async fn on_error(&self, url: &str, error: &crate::error::AcmeError) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.on_error(url, error).await?;
        }
        Ok(())
    }

    /// Returns the tightest timeout requested by registered middlewares.
    pub fn timeout(&self) -> Option<Duration> {
        self.middlewares
            .iter()
            .filter_map(|middleware| middleware.timeout())
            .min()
    }

    /// Returns the most recently registered retry policy override.
    pub fn retry_policy(&self) -> Option<RetryPolicy> {
        self.middlewares
            .iter()
            .rev()
            .find_map(|middleware| middleware.retry_policy())
    }
}

impl Default for MiddlewareChain {
    fn default() -> Self {
        Self::new()
    }
}

/// A middleware that logs request and response details.
pub struct LoggingMiddleware {
    /// Whether to log the full response body (currently unused).
    #[allow(dead_code)]
    log_body: bool,
}

impl LoggingMiddleware {
    /// Creates a new `LoggingMiddleware`.
    pub fn new(log_body: bool) -> Self {
        Self { log_body }
    }
}

#[async_trait]
impl Middleware for LoggingMiddleware {
    /// Logs the outgoing request method and URL.
    async fn before_request(&self, url: &str, method: &str) -> Result<()> {
        tracing::info!("HTTP Request: {} {}", method, url);
        Ok(())
    }

    /// Logs the incoming response status.
    async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()> {
        tracing::info!("HTTP Response: {} (Status: {})", url, response.status);
        Ok(())
    }

    /// Logs request failures.
    async fn on_error(&self, url: &str, error: &crate::error::AcmeError) -> Result<()> {
        tracing::error!("HTTP Request Failed: {} - Error: {:?}", url, error);
        Ok(())
    }
}

/// A middleware that enforces per-request timeouts.
pub struct TimeoutMiddleware {
    /// Timeout duration in seconds.
    timeout_secs: u64,
}

impl TimeoutMiddleware {
    /// Creates a new `TimeoutMiddleware`.
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }

    /// Returns the configured timeout duration.
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }
}

#[async_trait]
impl Middleware for TimeoutMiddleware {
    async fn before_request(&self, url: &str, _method: &str) -> Result<()> {
        tracing::debug!("Enforcing {:?} timeout for: {}", self.duration(), url);
        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(self.duration())
    }
}

/// A middleware that configures automatic retries.
pub struct RetryMiddleware {
    /// Maximum number of retries.
    max_retries: u32,
}

impl RetryMiddleware {
    /// Creates a new `RetryMiddleware`.
    pub fn new(max_retries: u32) -> Self {
        Self { max_retries }
    }

    /// Builds the retry policy represented by this middleware.
    pub fn policy(&self) -> RetryPolicy {
        RetryPolicy {
            max_retries: self.max_retries,
            strategy: RetryStrategy::default(),
            retry_on_client_error: false,
            retry_on_server_error: true,
            retry_on_transport_error: true,
        }
    }
}

#[async_trait]
impl Middleware for RetryMiddleware {
    async fn on_error(&self, url: &str, error: &crate::error::AcmeError) -> Result<()> {
        tracing::debug!(
            "Retry middleware intercepted error for {}: {:?}",
            url,
            error
        );
        Ok(())
    }

    fn retry_policy(&self) -> Option<RetryPolicy> {
        Some(self.policy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestMiddleware {
        called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl Middleware for TestMiddleware {
        async fn before_request(&self, _url: &str, _method: &str) -> Result<()> {
            self.called
                .store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_middleware_chain() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let middleware = TestMiddleware {
            called: called.clone(),
        };

        let chain = MiddlewareChain::new().push(middleware);
        chain.before_request("http://example.com", "GET").await.ok();

        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
    }

    #[test]
    fn middleware_chain_exposes_transport_policies() {
        let chain = MiddlewareChain::new()
            .push(TimeoutMiddleware::new(10))
            .push(TimeoutMiddleware::new(3))
            .push(RetryMiddleware::new(5));

        assert_eq!(chain.timeout(), Some(Duration::from_secs(3)));
        assert_eq!(chain.retry_policy().unwrap().max_retries, 5);
    }
}
