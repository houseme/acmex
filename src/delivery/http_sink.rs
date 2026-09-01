//! HTTP agent sink: second sink over a remote delivery agent.
//!
//! The agent contract (idempotent per version, authenticated, supports
//! stage → activate → health → rollback):
//!
//! * `POST {base}/stages` — body: version id, full chain, key (optional),
//!   fingerprint; idempotency key header `Idempotency-Key: <version id>`.
//! * `POST {base}/stages/{version}/activate`
//! * `GET  {base}/stages/{version}/health` → `{"healthy": bool}`
//! * `POST {base}/stages/{version}/rollback`
//! * `DELETE {base}/stages/{version}`
//!
//! `tests/certificate_sink_test.rs` runs a fake agent (axum) through the
//! same contract suite as the file sink.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::certificate::CertificateChain;
use crate::domain::CertificateVersion;
use crate::error::{AcmeError, Result};

use super::{
    CertificateMaterial, CertificateSink, DeploymentHealth, DeploymentSpec, SinkCleanupOutcome,
    StagedDeployment,
};

#[derive(Serialize)]
struct StageRequest<'a> {
    version_id: &'a str,
    lineage_id: &'a str,
    full_chain_pem: &'a str,
    leaf_pem: &'a str,
    key_pem: Option<&'a str>,
    fingerprint: String,
}

#[derive(Deserialize)]
struct HealthResponse {
    healthy: bool,
    #[serde(default)]
    detail: Option<String>,
}

/// A sink driving a remote HTTP delivery agent.
#[derive(Clone)]
pub struct HttpAgentSink {
    agent_id: String,
    base_url: String,
    token: String,
    client: reqwest::Client,
}

impl HttpAgentSink {
    /// A sink for the agent at `base_url` authenticated with `token`.
    pub fn new(
        agent_id: impl Into<String>,
        base_url: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            agent_id: agent_id.into(),
            base_url: base_url.into(),
            token: token.into(),
            client,
        }
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/stages{suffix}", self.base_url.trim_end_matches('/'))
    }

    fn fingerprint(material: &CertificateMaterial) -> Result<String> {
        let chain = CertificateChain::from_pem(material.full_chain_pem.as_bytes())?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&chain.leaf);
        Ok(hex::encode(hasher.finalize()))
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: &str,
        idempotency_key: Option<&str>,
        body: Option<&StageRequest<'_>>,
    ) -> Result<reqwest::Response> {
        let mut builder = self
            .client
            .request(method, url)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/json");
        if let Some(key) = idempotency_key {
            builder = builder.header("Idempotency-Key", key);
        }
        let body_bytes = match body {
            Some(payload) => Some(
                serde_json::to_vec(payload)
                    .map_err(|e| AcmeError::InvalidInput(format!("payload: {e}")))?,
            ),
            None => None,
        };
        builder
            .body(body_bytes.unwrap_or_default())
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("agent request failed: {e}")))
    }
}

#[async_trait]
impl CertificateSink for HttpAgentSink {
    fn sink_id(&self) -> &str {
        &self.agent_id
    }

    async fn stage(
        &self,
        _spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: &CertificateMaterial,
    ) -> Result<StagedDeployment> {
        let version_id = version.id.to_string();
        let payload = StageRequest {
            version_id: &version_id,
            lineage_id: &version.lineage_id.to_string(),
            full_chain_pem: &material.full_chain_pem,
            leaf_pem: &material.leaf_pem,
            key_pem: material.key_pem.as_deref(),
            fingerprint: Self::fingerprint(material)?,
        };
        let response = self
            .request(
                reqwest::Method::POST,
                &self.url(""),
                Some(&version_id),
                Some(&payload),
            )
            .await?;
        if !response.status().is_success() {
            return Err(AcmeError::transport(format!(
                "agent stage failed: HTTP {}",
                response.status()
            )));
        }
        Ok(StagedDeployment {
            sink_id: self.agent_id.clone(),
            version_id: version.id.clone(),
            staged_ref: self.url(&format!("/{version_id}")),
            deployment_id: None,
        })
    }

    async fn activate(&self, staged: &StagedDeployment) -> Result<()> {
        let response = self
            .request(
                reqwest::Method::POST,
                &self.url(&format!("/{}/activate", staged.version_id)),
                None,
                None,
            )
            .await?;
        if !response.status().is_success() {
            return Err(AcmeError::transport(format!(
                "agent activate failed: HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn health_check(&self, staged: &StagedDeployment) -> Result<DeploymentHealth> {
        let response = self
            .request(
                reqwest::Method::GET,
                &self.url(&format!("/{}/health", staged.version_id)),
                None,
                None,
            )
            .await?;
        if !response.status().is_success() {
            return Ok(DeploymentHealth {
                healthy: false,
                detail: Some(format!("health endpoint HTTP {}", response.status())),
            });
        }
        let health: HealthResponse = response
            .json()
            .await
            .map_err(|e| AcmeError::transport(format!("health body invalid: {e}")))?;
        Ok(DeploymentHealth {
            healthy: health.healthy,
            detail: health.detail,
        })
    }

    async fn rollback(&self, staged: &StagedDeployment) -> Result<()> {
        let response = self
            .request(
                reqwest::Method::POST,
                &self.url(&format!("/{}/rollback", staged.version_id)),
                None,
                None,
            )
            .await?;
        if !response.status().is_success() {
            return Err(AcmeError::transport(format!(
                "agent rollback failed: HTTP {}",
                response.status()
            )));
        }
        Ok(())
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<SinkCleanupOutcome> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &self.url(&format!("/{}", staged.version_id)),
                None,
                None,
            )
            .await?;
        match response.status().as_u16() {
            200 | 204 => Ok(SinkCleanupOutcome::Removed),
            404 => Ok(SinkCleanupOutcome::AlreadyAbsent),
            status => Err(AcmeError::transport(format!(
                "agent cleanup failed: HTTP {status}"
            ))),
        }
    }
}
