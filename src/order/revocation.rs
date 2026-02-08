/// Certificate revocation implementation
use crate::account::AccountManager;
use crate::error::Result;
use crate::types::RevocationReason;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;

/// Certificate revocation handler
pub struct CertificateRevocation<'a> {
    account_manager: &'a AccountManager<'a>,
    account_id: String,
    certificate_der: Vec<u8>,
    reason: Option<RevocationReason>,
}

impl<'a> CertificateRevocation<'a> {
    /// Create a new revocation request
    pub fn new(
        account_manager: &'a AccountManager<'a>,
        account_id: impl Into<String>,
        certificate_der: Vec<u8>,
    ) -> Self {
        Self {
            account_manager,
            account_id: account_id.into(),
            certificate_der,
            reason: None,
        }
    }

    /// Set revocation reason
    pub fn with_reason(mut self, reason: RevocationReason) -> Self {
        self.reason = Some(reason);
        self
    }

    /// Execute revocation
    pub async fn revoke(&self) -> Result<()> {
        let directory = self.account_manager.directory_manager.get().await?;
        let revoke_url = directory.revoke_cert;
        let nonce = self.account_manager.nonce_manager.get_nonce().await?;

        let cert_b64 = URL_SAFE_NO_PAD.encode(&self.certificate_der);

        let mut payload = json!({
            "certificate": cert_b64,
        });

        if let Some(reason) = self.reason {
            payload["reason"] = json!(reason.as_u8());
        }

        let header = json!({
            "alg": "EdDSA",
            "kid": self.account_id,
            "nonce": nonce,
            "url": revoke_url,
        });

        let jws = self.account_manager.signer.sign(&header, &payload)?;

        let response = self
            .account_manager
            .http_client
            .post(&revoke_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to revoke certificate: {}", e))
            })?;

        // Cache nonce
        if let Some(nonce_header) = response.headers().get("replay-nonce")
            && let Ok(nonce_str) = nonce_header.to_str() {
                self.account_manager
                    .nonce_manager
                    .cache_nonce(nonce_str.to_string())
                    .await;
            }

        let status = response.status();
        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(crate::error::AcmeError::order(
                format!("Failed to revoke certificate: HTTP {}", status),
                error_text,
            ));
        }

        tracing::info!("Certificate revoked successfully");
        Ok(())
    }
}
