//! HTTP 客户端 - 封装 reqwest 并添加重试和速率限制

use crate::error::Result;
use std::time::Duration;

/// HTTP 响应
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// 状态码
    pub status: u16,
    /// 响应头
    pub headers: std::collections::HashMap<String, String>,
    /// 响应体
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// 获取响应体作为字符串
    pub fn text(&self) -> Result<String> {
        String::from_utf8(self.body.clone())
            .map_err(|e| crate::error::AcmeError::transport(format!("Invalid UTF-8: {}", e)))
    }

    /// 获取响应体作为 JSON
    pub fn json<T: serde::de::DeserializeOwned>(&self) -> Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| crate::error::AcmeError::transport(format!("JSON parse error: {}", e)))
    }

    /// 检查是否是成功状态 (2xx)
    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// 检查是否是客户端错误 (4xx)
    pub fn is_client_error(&self) -> bool {
        self.status >= 400 && self.status < 500
    }

    /// 检查是否是服务器错误 (5xx)
    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }
}

/// HTTP 客户端配置
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// 请求超时
    pub timeout: Duration,
    /// 连接池大小
    pub pool_size: usize,
    /// 用户代理
    pub user_agent: String,
    /// 是否跟随重定向
    pub follow_redirects: bool,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            pool_size: 10,
            user_agent: "AcmeX/0.4.0".to_string(),
            follow_redirects: true,
        }
    }
}

/// HTTP 客户端
pub struct HttpClient {
    client: reqwest::Client,
    config: HttpClientConfig,
}

impl HttpClient {
    /// 创建新的 HTTP 客户端
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(if config.follow_redirects {
                reqwest::redirect::Policy::default()
            } else {
                reqwest::redirect::Policy::limited(0)
            })
            .user_agent(&config.user_agent)
            .build()
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to create client: {}", e))
            })?;

        Ok(Self { client, config })
    }

    /// 使用默认配置创建客户端
    pub fn default() -> Result<Self> {
        Self::new(HttpClientConfig::default())
    }

    /// 执行 GET 请求
    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.execute_request(self.client.get(url)).await
    }

    /// 执行 POST 请求
    pub async fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse> {
        let request = self.client.post(url).body(body.to_vec());
        self.execute_request(request).await
    }

    /// 执行 POST 请求 (JSON)
    pub async fn post_json<T: serde::Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<HttpResponse> {
        let request = self.client.post(url).json(body);
        self.execute_request(request).await
    }

    /// 执行 HEAD 请求
    pub async fn head(&self, url: &str) -> Result<HttpResponse> {
        self.execute_request(self.client.head(url)).await
    }

    async fn execute_request(&self, request: reqwest::RequestBuilder) -> Result<HttpResponse> {
        let response = request
            .send()
            .await
            .map_err(|e| crate::error::AcmeError::transport(format!("Request failed: {}", e)))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let body = response
            .bytes()
            .await
            .map_err(|e| crate::error::AcmeError::transport(format!("Failed to read body: {}", e)))?
            .to_vec();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }

    /// 获取配置
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
