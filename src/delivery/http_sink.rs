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
//! `tests/certificate_sink_contract.rs` covers the same lifecycle contract
//! through the in-memory fake agent sink.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::domain::{CertificateVersion, DeliveryTargetKind};
use crate::error::{AcmeError, Result};

use super::{
    CertificateMaterialRef, CertificateSink, CleanupOutcome, DeploymentHealth, DeploymentSpec,
    StagedDeployment,
};

#[derive(Serialize)]
struct StageRequest<'a> {
    version_id: &'a str,
    lineage_id: &'a str,
    target_id: &'a str,
    fullchain_pem: &'a str,
    cert_pem: &'a str,
    private_key_pem: Option<&'a str>,
    leaf_sha256: &'a str,
}

#[derive(Deserialize)]
struct StageResponse {
    #[serde(default)]
    staged_ref: Option<String>,
    #[serde(default)]
    previous_active_ref: Option<String>,
    #[serde(default)]
    resource_version: u64,
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

    /// Stable delivery agent identity used by orchestration and audit logs.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    fn url(&self, suffix: &str) -> String {
        format!("{}/stages{suffix}", self.base_url.trim_end_matches('/'))
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
    async fn stage(
        &self,
        spec: &DeploymentSpec,
        version: &CertificateVersion,
        material: CertificateMaterialRef<'_>,
    ) -> Result<StagedDeployment> {
        if spec.kind != DeliveryTargetKind::Webhook {
            return Err(AcmeError::invalid_input(
                "HTTP agent sink requires webhook target",
            ));
        }
        let version_id = version.id.to_string();
        let target_id = spec.target_id.to_string();
        let private_key_pem = material.material.private_key_pem.as_ref().map(|key| {
            std::str::from_utf8(key.expose_secret())
                .map_err(|err| AcmeError::pem(format!("private key is not UTF-8 PEM: {err}")))
        });
        let private_key_pem = private_key_pem.transpose()?;
        let payload = StageRequest {
            version_id: &version_id,
            lineage_id: &version.lineage_id.to_string(),
            target_id: &target_id,
            fullchain_pem: &material.material.fullchain_pem,
            cert_pem: &material.material.cert_pem,
            private_key_pem,
            leaf_sha256: &material.material.leaf_sha256,
        };
        let response = self
            .request(
                reqwest::Method::POST,
                &self.url(""),
                Some(&version_id),
                Some(&payload),
            )
            .await?;
        let status = response.status();
        if !status.is_success() {
            return Err(AcmeError::transport(format!(
                "agent stage failed: HTTP {}",
                status
            )));
        }
        let staged_ref = self.url(&format!("/{version_id}"));
        let stage_response = if status == reqwest::StatusCode::NO_CONTENT {
            StageResponse {
                staged_ref: None,
                previous_active_ref: None,
                resource_version: 0,
            }
        } else {
            response
                .json()
                .await
                .map_err(|err| AcmeError::transport(format!("stage body invalid: {err}")))?
        };
        Ok(StagedDeployment {
            kind: spec.kind,
            target_id: spec.target_id.clone(),
            version_id: version.id.clone(),
            staged_ref: stage_response.staged_ref.unwrap_or(staged_ref),
            previous_active_ref: stage_response.previous_active_ref,
            leaf_sha256: material.material.leaf_sha256.clone(),
            resource_version: stage_response.resource_version,
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
        let status = response.status();
        if !status.is_success() {
            return Err(AcmeError::transport(format!(
                "agent activate failed: HTTP {}",
                status
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
        let status = response.status();
        if !status.is_success() {
            return Ok(DeploymentHealth::Unknown(format!(
                "health endpoint HTTP {status}"
            )));
        }
        let health: HealthResponse = response
            .json()
            .await
            .map_err(|e| AcmeError::transport(format!("health body invalid: {e}")))?;
        if health.healthy {
            Ok(DeploymentHealth::Healthy)
        } else {
            Ok(DeploymentHealth::Unhealthy(
                health
                    .detail
                    .unwrap_or_else(|| "agent reported unhealthy".into()),
            ))
        }
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
        let status = response.status();
        if !status.is_success() {
            return Err(AcmeError::transport(format!(
                "agent rollback failed: HTTP {}",
                status
            )));
        }
        Ok(())
    }

    async fn cleanup(&self, staged: &StagedDeployment) -> Result<CleanupOutcome> {
        let response = self
            .request(
                reqwest::Method::DELETE,
                &self.url(&format!("/{}", staged.version_id)),
                None,
                None,
            )
            .await?;
        match response.status().as_u16() {
            200 | 204 => Ok(CleanupOutcome::Cleaned),
            404 => Ok(CleanupOutcome::AlreadyClean),
            status => Err(AcmeError::transport(format!(
                "agent cleanup failed: HTTP {status}"
            ))),
        }
    }
}
