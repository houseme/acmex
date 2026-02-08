/// HTTP client implementation for AcmeX.
/// This module wraps `reqwest` to provide a high-level interface for ACME protocol requests,
/// including support for custom configurations and structured responses.
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
        String::from_utf8(self.body.clone())
            .map_err(|e| {
                tracing::error!("Failed to decode HTTP response body as UTF-8: {}", e);
                crate::error::AcmeError::transport(format!("Invalid UTF-8: {}", e))
            })
    }

    /// Deserializes the response body from JSON into the specified type.
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| {
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
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            pool_size: 10,
            user_agent: "AcmeX/0.7.0".to_string(),
            follow_redirects: true,
        }
    }
}

/// A high-level HTTP client for ACME operations.
pub struct HttpClient {
    /// The underlying reqwest client.
    client: reqwest::Client,
    /// The client configuration.
    config: HttpClientConfig,
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

        Ok(Self { client, config })
    }

    /// Creates a new `HttpClient` with default settings.
    pub fn default() -> Result<Self> {
        Self::new(HttpClientConfig::default())
    }

    /// Executes an asynchronous GET request.
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        tracing::debug!("HTTP GET: {}", url);
        self.execute_request(self.client.get(url)).await
    }

    /// Executes an asynchronous POST request with a raw byte body.
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        tracing::debug!("HTTP POST: {} ({} bytes)", url, body.len());
        let request = self.client.post(url).body(body.to_vec());
        self.execute_request(request).await
    }

    /// Executes an asynchronous POST request with a JSON-serializable body.
    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<HttpResponse> {
        tracing::debug!("HTTP POST JSON: {}", url);
        let request = self.client.post(url).json(body);
        self.execute_request(request).await
    }

    /// Executes an asynchronous HEAD request.
    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        tracing::debug!("HTTP HEAD: {}", url);
        self.execute_request(self.client.head(url)).await
    }

    /// Internal helper to execute a request and transform the response.
    async fn execute_request(&self, request: reqwest::RequestBuilder) -> Result<HttpResponse> {
        let response = request
            .send()
            .await
            .map_err(|e| {
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
        assert!(client.is_ok());
    }
}
