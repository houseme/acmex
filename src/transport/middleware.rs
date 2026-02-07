//! 中间件 - 请求/响应拦截和处理

use super::http_client::HttpResponse;
use crate::error::Result;
use async_trait::async_trait;

/// 中间件特征
#[async_trait]
pub trait Middleware: Send + Sync {
    /// 处理请求前
    async fn before_request(&self, _url: &str, _method: &str) -> Result<()> {
        Ok(())
    }

    /// 处理请求后
    async fn after_response(&self, _url: &str, _response: &HttpResponse) -> Result<()> {
        Ok(())
    }

    /// 处理错误
    async fn on_error(&self, _url: &str, _error: &crate::error::AcmeError) -> Result<()> {
        Ok(())
    }
}

/// 中间件链
pub struct MiddlewareChain {
    middlewares: Vec<Box<dyn Middleware>>,
}

impl MiddlewareChain {
    /// 创建新的中间件链
    pub fn new() -> Self {
        Self {
            middlewares: Vec::new(),
        }
    }

    /// 添加中间件
    pub fn add<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares.push(Box::new(middleware));
        self
    }

    /// 执行请求前钩子
    pub async fn before_request(&self, url: &str, method: &str) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.before_request(url, method).await?;
        }
        Ok(())
    }

    /// 执行响应后钩子
    pub async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()> {
        for middleware in &self.middlewares {
            middleware.after_response(url, response).await?;
        }
        Ok(())
    }

    /// 执行错误钩子
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

/// 日志中间件
pub struct LoggingMiddleware {
    /// 是否记录请求体
    log_body: bool,
}

impl LoggingMiddleware {
    /// 创建新的日志中间件
    pub fn new(log_body: bool) -> Self {
        Self { log_body }
    }
}

#[async_trait]
impl Middleware for LoggingMiddleware {
    async fn before_request(&self, url: &str, method: &str) -> Result<()> {
        tracing::debug!("{}  {}", method, url);
        Ok(())
    }

    async fn after_response(&self, url: &str, response: &HttpResponse) -> Result<()> {
        tracing::debug!("<- {} (status: {})", url, response.status);
        Ok(())
    }

    async fn on_error(&self, url: &str, error: &crate::error::AcmeError) -> Result<()> {
        tracing::error!("Request failed: {} - {:?}", url, error);
        Ok(())
    }
}

/// 超时中间件
pub struct TimeoutMiddleware {
    timeout_secs: u64,
}

impl TimeoutMiddleware {
    /// 创建新的超时中间件
    pub fn new(timeout_secs: u64) -> Self {
        Self { timeout_secs }
    }
}

#[async_trait]
impl Middleware for TimeoutMiddleware {
    async fn before_request(&self, _url: &str, _method: &str) -> Result<()> {
        // 实现实际的超时检查
        Ok(())
    }
}

/// 重试中间件
pub struct RetryMiddleware {
    max_retries: u32,
}

impl RetryMiddleware {
    /// 创建新的重试中间件
    pub fn new(max_retries: u32) -> Self {
        Self { max_retries }
    }
}

#[async_trait]
impl Middleware for RetryMiddleware {
    async fn on_error(&self, _url: &str, _error: &crate::error::AcmeError) -> Result<()> {
        // 实现实际的重试逻辑
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

        let chain = MiddlewareChain::new().add(middleware);
        chain.before_request("http://example.com", "GET").await.ok();

        assert!(called.load(std::sync::atomic::Ordering::Relaxed));
    }
}
