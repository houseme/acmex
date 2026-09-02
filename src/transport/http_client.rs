/// HTTP client implementation for AcmeX.
/// This module wraps `reqwest` to provide a high-level interface for ACME protocol requests,
/// including support for custom configurations and structured responses.
use super::middleware::{Middleware, MiddlewareChain};
use super::retry::RetryPolicy;
use crate::error::Result;
use std::time::Duration;

/// Represents a structured HTTP response.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code (e.g., 200, 404).
    pub status: u16,
    /// A map of response headers.
    pub headers: std::collections::HashMap<String, String>,
    /// The raw response body as bytes.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Returns the response body as a UTF-8 string.
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone()).map_err(|e| {
            tracing::error!("Failed to decode HTTP response body as UTF-8: {}", e);
            crate::error::AcmeError::transport(format!("Invalid UTF-8: {}", e))
        })
    }

    /// Deserializes the response body from JSON into the specified type.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body).map_err(|e| {
            tracing::error!("Failed to parse HTTP response body as JSON: {}", e);
            crate::error::AcmeError::transport(format!("JSON parse error: {}", e))
        })
    }

    /// Returns true if the status code indicates success (2xx).
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// Returns true if the status code indicates a client error (4xx).
    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }

    /// Returns true if the status code indicates a server error (5xx).
    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }
}

/// Configuration for the `HttpClient`.
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Request timeout duration.
    pub timeout: Duration,
    /// Maximum number of idle connections in the pool.
    pub pool_size: usize,
    /// Custom User-Agent string.
    pub user_agent: String,
    /// Whether to follow HTTP redirects.
    pub follow_redirects: bool,
    /// Policy for retrying transient request failures.
    pub retry_policy: RetryPolicy,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            pool_size: 10,
            user_agent: "AcmeX/0.7.0".to_string(),
            follow_redirects: true,
            retry_policy: RetryPolicy::default(),
        }
    }
}

enum RequestBody {
    Empty,
    Raw(Vec<u8>),
    Json(Vec<u8>),
}

/// A high-level HTTP client for ACME operations.
pub struct HttpClient {
    /// The underlying reqwest client.
    client: reqwest::Client,
    /// The client configuration.
    config: HttpClientConfig,
    /// Request lifecycle middlewares.
    middlewares: MiddlewareChain,
}

impl Default for HttpClient {
    /// Creates a new `HttpClient` with default settings.
    fn default() -> Self {
        Self::new(HttpClientConfig::default()).expect("Failed to initialize default HttpClient")
    }
}

impl HttpClient {
    /// Creates a new `HttpClient` with the specified configuration.
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        tracing::debug!("Initializing HttpClient with timeout: {:?}", config.timeout);
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .pool_max_idle_per_host(config.pool_size)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::default()
            } else {
                reqwest::redirect::Policy::limited(0)
            })
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| {
                tracing::error!("Failed to build reqwest client: {}", e);
                crate::error::AcmeError::transport(format!("Failed to create client: {}", e))
            })?;

        Ok(Self {
            client,
            config,
            middlewares: MiddlewareChain::new(),
        })
    }

    /// Adds a request lifecycle middleware to this client.
    pub fn with_middleware<M: Middleware + 'static>(mut self, middleware: M) -> Self {
        self.middlewares = self.middlewares.push(middleware);
        self
    }

    /// Executes an asynchronous GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        tracing::debug!("HTTP GET: {}", url);
        self.execute_request(reqwest::Method::GET, url, RequestBody::Empty)
            .await
    }

    /// Executes an asynchronous POST request with a raw byte body.
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        tracing::debug!("HTTP POST: {} ({} bytes)", url, body.len());
        self.execute_request(reqwest::Method::POST, url, RequestBody::Raw(body.to_vec()))
            .await
    }

    /// Executes an asynchronous POST request with a JSON-serializable body.
    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<HttpResponse> {
        tracing::debug!("HTTP POST JSON: {}", url);
        let body = serde_json::to_vec(body).map_err(|e| {
            tracing::error!("Failed to serialize HTTP JSON request body: {}", e);
            crate::error::AcmeError::transport(format!("JSON serialize error: {}", e))
        })?;
        self.execute_request(reqwest::Method::POST, url, RequestBody::Json(body))
            .await
    }

    /// Executes an asynchronous HEAD request.
    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        tracing::debug!("HTTP HEAD: {}", url);
        self.execute_request(reqwest::Method::HEAD, url, RequestBody::Empty)
            .await
    }

    /// Internal helper to execute a request and transform the response.
    async fn execute_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: RequestBody,
    ) -> Result<HttpResponse> {
        let retry_policy = self
            .middlewares
            .retry_policy()
            .unwrap_or_else(|| self.config.retry_policy.clone());
        let timeout = self.middlewares.timeout().unwrap_or(self.config.timeout);
        let mut attempt = 0;

        loop {
            self.middlewares
                .before_request(url, method.as_str())
                .await?;
            let request = self
                .build_request(method.clone(), url, &body)
                .timeout(timeout);

            match Self::send_request(request).await {
                Ok(response) => {
                    self.middlewares.after_response(url, &response).await?;
                    if retry_policy.should_retry_method(method.as_str(), response.status, attempt) {
                        tokio::time::sleep(retry_policy.retry_delay(attempt)).await;
                        attempt += 1;
                        continue;
                    }
                    return Ok(response);
                }
                Err(error) => {
                    self.middlewares.on_error(url, &error).await?;
                    if retry_policy
                        .should_retry_transport_error_for_method(method.as_str(), attempt)
                    {
                        tokio::time::sleep(retry_policy.retry_delay(attempt)).await;
                        attempt += 1;
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    fn build_request(
        &self,
        method: reqwest::Method,
        url: &str,
        body: &RequestBody,
    ) -> reqwest::RequestBuilder {
        let request = self.client.request(method, url);
        match body {
            RequestBody::Empty => request,
            RequestBody::Raw(bytes) => request.body(bytes.clone()),
            RequestBody::Json(bytes) => request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(bytes.clone()),
        }
    }

    async fn send_request(request: reqwest::RequestBuilder) -> Result<HttpResponse> {
        let response = request.send().await.map_err(|e| {
            tracing::error!("Network request failed: {}", e);
            crate::error::AcmeError::transport(format!("Request failed: {}", e))
        })?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();

        let body = response
            .bytes()
            .await
            .map_err(|e| {
                tracing::error!("Failed to read HTTP response body: {}", e);
                crate::error::AcmeError::transport(format!("Failed to read body: {}", e))
            })?
            .to_vec();

        tracing::debug!("HTTP Response: {} ({} bytes)", status, body.len());
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// Returns a reference to the client configuration.
    pub fn config(&self) -> &HttpClientConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::middleware::RetryMiddleware;
    use crate::transport::retry::RetryStrategy;
    use axum::{
        Router,
        http::StatusCode,
        routing::{get, post},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn test_http_response_status() {
        let response = HttpResponse {
            status: 200,
            headers: Default::default(),
            body: vec![],
        };

        assert!(response.is_success());
        assert!(!response.is_client_error());
        assert!(!response.is_server_error());
    }

    #[tokio::test]
    async fn test_http_client_creation() {
        let client = HttpClient::default();
        assert_eq!(client.config().user_agent, "AcmeX/0.7.0");
        assert_eq!(client.config().timeout.as_secs(), 30);
        assert!(client.config().follow_redirects);
    }

    #[tokio::test]
    async fn http_client_retries_server_errors_with_middleware_policy() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let route_attempts = attempts.clone();
        let app = Router::new().route(
            "/unstable",
            get(move || {
                let route_attempts = route_attempts.clone();
                async move {
                    match route_attempts.fetch_add(1, Ordering::SeqCst) {
                        0 => (StatusCode::INTERNAL_SERVER_ERROR, "try again"),
                        _ => (StatusCode::OK, "ok"),
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = HttpClientConfig::default();
        config.retry_policy.strategy = RetryStrategy::FixedDelay(Duration::ZERO);
        let client = HttpClient::new(config)
            .unwrap()
            .with_middleware(RetryMiddleware::new(1));

        let response = client
            .get(&format!("http://{addr}/unstable"))
            .await
            .unwrap();

        assert_eq!(response.status, 200);
        assert_eq!(response.text().unwrap(), "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn http_client_does_not_blindly_retry_post_server_errors() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let route_attempts = attempts.clone();
        let app = Router::new().route(
            "/create",
            post(move || {
                let route_attempts = route_attempts.clone();
                async move {
                    route_attempts.fetch_add(1, Ordering::SeqCst);
                    (StatusCode::INTERNAL_SERVER_ERROR, "not replayed")
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut config = HttpClientConfig::default();
        config.retry_policy.strategy = RetryStrategy::FixedDelay(Duration::ZERO);
        let client = HttpClient::new(config)
            .unwrap()
            .with_middleware(RetryMiddleware::new(3));

        let response = client
            .post(&format!("http://{addr}/create"), b"{}")
            .await
            .unwrap();

        assert_eq!(response.status, 500);
        assert_eq!(response.text().unwrap(), "not replayed");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }
}
