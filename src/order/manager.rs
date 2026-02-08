use crate::account::AccountManager;
/// Order lifecycle management
use crate::error::Result;
use crate::order::{Authorization, Challenge, NewOrderRequest, Order};
use crate::protocol::{DirectoryManager, NonceManager};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use std::time::Duration;

/// Order manager for handling order lifecycle
pub struct OrderManager<'a> {
    account_manager: &'a AccountManager<'a>,
    directory_manager: &'a DirectoryManager,
    nonce_manager: &'a NonceManager,
    http_client: &'a reqwest::Client,
    account_id: String,
}

impl<'a> OrderManager<'a> {
    /// Create a new order manager
    pub fn new(
        account_manager: &'a AccountManager<'a>,
        directory_manager: &'a DirectoryManager,
        nonce_manager: &'a NonceManager,
        http_client: &'a reqwest::Client,
        account_id: String,
    ) -> Self {
        Self {
            account_manager,
            directory_manager,
            nonce_manager,
            http_client,
            account_id,
        }
    }

    /// Create a new order
    pub async fn create_order(&self, request: &NewOrderRequest) -> Result<(String, Order)> {
        let directory = self.directory_manager.get().await?;
        let nonce = self.nonce_manager.get_nonce().await?;

        // Build JWS header
        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": &directory.new_order,
        });

        // Build payload
        let payload = json!(request);

        // Sign the request
        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        // Send request
        let response = self
            .http_client
            .post(&directory.new_order)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to create order: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        // Get order URL from Location header
        let order_url = response
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                crate::error::AcmeError::order(
                    "Missing Location header in order response".to_string(),
                    "".to_string(),
                )
            })?
            .to_string();

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(crate::error::AcmeError::order(
                format!("Failed to create order: HTTP {}", status),
                error_text,
            ));
        }

        // Parse order
        let order: Order = response.json().await.map_err(|e| {
            crate::error::AcmeError::order("Failed to parse order".to_string(), e.to_string())
        })?;

        tracing::info!("Order created: {}", order_url);
        Ok((order_url, order))
    }

    /// Get order status
    pub async fn get_order(&self, order_url: &str) -> Result<Order> {
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": order_url,
        });

        let payload = json!({});
        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        let response = self
            .http_client
            .post(order_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to get order: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::order(
                format!("Failed to get order: HTTP {}", status),
                "".to_string(),
            ));
        }

        let order: Order = response.json().await.map_err(|e| {
            crate::error::AcmeError::order("Failed to parse order".to_string(), e.to_string())
        })?;

        Ok(order)
    }

    /// Get authorization
    pub async fn get_authorization(&self, auth_url: &str) -> Result<Authorization> {
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": auth_url,
        });

        let payload = json!({});
        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        let response = self
            .http_client
            .post(auth_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to get authorization: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::order(
                format!("Failed to get authorization: HTTP {}", status),
                "".to_string(),
            ));
        }

        let auth: Authorization = response.json().await.map_err(|e| {
            crate::error::AcmeError::order(
                "Failed to parse authorization".to_string(),
                e.to_string(),
            )
        })?;

        Ok(auth)
    }

    /// Respond to challenge (tell ACME server we're ready)
    pub async fn respond_to_challenge(&self, challenge_url: &str) -> Result<Challenge> {
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": challenge_url,
        });

        // Empty payload triggers validation
        let payload = json!({});
        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        let response = self
            .http_client
            .post(challenge_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to respond to challenge: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::challenge(
                "unknown".to_string(),
                format!("Failed to respond to challenge: HTTP {}", status),
            ));
        }

        let challenge: Challenge = response.json().await.map_err(|e| {
            crate::error::AcmeError::challenge(
                "unknown".to_string(),
                format!("Failed to parse challenge: {}", e),
            )
        })?;

        tracing::info!("Challenge response submitted: {}", challenge_url);
        Ok(challenge)
    }

    /// Poll order until it reaches a final state
    pub async fn poll_order(
        &self,
        order_url: &str,
        max_attempts: u32,
        interval: Duration,
    ) -> Result<Order> {
        for attempt in 0..max_attempts {
            let order = self.get_order(order_url).await?;

            match order.status.as_str() {
                "ready" | "valid" | "invalid" => {
                    tracing::info!("Order status: {} (attempt {})", order.status, attempt + 1);
                    return Ok(order);
                }
                "pending" | "processing" => {
                    tracing::debug!("Order still pending, waiting... (attempt {})", attempt + 1);
                    tokio::time::sleep(interval).await;
                }
                status => {
                    return Err(crate::error::AcmeError::order(
                        format!("Unexpected order status: {}", status),
                        "".to_string(),
                    ));
                }
            }
        }

        Err(crate::error::AcmeError::order(
            "Order polling timeout".to_string(),
            format!("Exceeded {} attempts", max_attempts),
        ))
    }

    /// Finalize order with CSR
    pub async fn finalize_order(&self, finalize_url: &str, csr_der: &[u8]) -> Result<Order> {
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": finalize_url,
        });

        // Encode CSR as base64url
        let csr_b64 = URL_SAFE_NO_PAD.encode(csr_der);

        let payload = json!({
            "csr": csr_b64
        });

        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        let response = self
            .http_client
            .post(finalize_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to finalize order: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(crate::error::AcmeError::order(
                format!("Failed to finalize order: HTTP {}", status),
                error_text,
            ));
        }

        let order: Order = response.json().await.map_err(|e| {
            crate::error::AcmeError::order(
                "Failed to parse finalized order".to_string(),
                e.to_string(),
            )
        })?;

        tracing::info!("Order finalized successfully");
        Ok(order)
    }

    /// Download certificate
    pub async fn download_certificate(&self, certificate_url: &str) -> Result<String> {
        let nonce = self.nonce_manager.get_nonce().await?;

        let header = json!({
            "alg": "EdDSA",
            "kid": &self.account_id,
            "nonce": nonce,
            "url": certificate_url,
        });

        let payload = json!({});
        let jws = self.account_manager.get_signer().sign(&header, &payload)?;

        let response = self
            .http_client
            .post(certificate_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to download certificate: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str()
        {
            self.nonce_manager.cache_nonce(nonce_str.to_string()).await;
        }

        let status = response.status();
        if !status.is_success() {
            return Err(crate::error::AcmeError::certificate(format!(
                "Failed to download certificate: HTTP {}",
                status
            )));
        }

        let cert_pem = response.text().await.map_err(|e| {
            crate::error::AcmeError::certificate(format!("Failed to read certificate: {}", e))
        })?;

        tracing::info!("Certificate downloaded successfully");
        Ok(cert_pem)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_order_manager_creation() {
        // This is a compile test - actual tests require full ACME setup
    }
}
