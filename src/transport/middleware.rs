/// Middleware system for HTTP request and response interception.
/// This module defines the `Middleware` trait and `MiddlewareChain` to allow
/// custom logic to be injected into the HTTP request lifecycle.
use super::http_client::HttpResponse;
use crate::error::Result;
use async_trait::async_trait;

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

/// A middleware that enforces request timeouts (placeholder).
pub struct TimeoutMiddleware {
    /// Timeout duration in seconds.
    #[allow(dead_code)]
    timeout_secs: u64,
}

impl TimeoutMiddleware {
    /// Creates a new `TimeoutMiddleware`.
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

#[async_trait]
impl Middleware for TimeoutMiddleware {
    async fn before_request(&self, url: &str, _method: &str) -> Result<()> {
        tracing::debug!("Enforcing timeout for: {}", url);
        Ok(())
    }
}

/// A middleware that handles automatic retries (placeholder).
pub struct RetryMiddleware {
    /// Maximum number of retries.
    #[allow(dead_code)]
    max_retries: u32,
}

impl RetryMiddleware {
    /// Creates a new `RetryMiddleware`.
    pub fn new(max_retries: u32) -> Self {
        Self { max_retries }
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
}
