/// Certificate storage helper
use crate::client::CertificateBundle;
use crate::error::{AcmeError, Result};
use crate::storage::StorageBackend;

/// Certificate store using a storage backend
#[derive(Clone)]
pub struct CertificateStore<B: StorageBackend> {
    backend: B,
}

impl<B: StorageBackend> CertificateStore<B> {
    pub fn new(backend: B) -> Self {
        Self { backend }
    }

    /// Get the storage backend
    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn key_for_domains(domains: &[String]) -> String {
        let mut domains = domains.to_vec();
        domains.sort();
        format!("cert:{}", domains.join(","))
    }

    /// Save a certificate bundle
    pub async fn save(&self, bundle: &CertificateBundle) -> Result<()> {
        let key = Self::key_for_domains(&bundle.domains);
        let data = serde_json::to_vec(bundle)
            .map_err(|e| AcmeError::storage(format!("Serialize cert bundle failed: {}", e)))?;
        self.backend.store(&key, &data).await
    }

    /// Load a certificate bundle by domains
    pub async fn load(&self, domains: &[String]) -> Result<Option<CertificateBundle>> {
        let key = Self::key_for_domains(domains);
        let data = self.backend.load(&key).await?;
        match data {
            Some(bytes) => {
                let bundle: CertificateBundle = serde_json::from_slice(&bytes).map_err(|e| {
                    AcmeError::storage(format!("Deserialize cert bundle failed: {}", e))
                })?;
                Ok(Some(bundle))
            }
            None => Ok(None),
        }
    }

    /// Delete a certificate bundle by domains
    pub async fn delete(&self, domains: &[String]) -> Result<()> {
        let key = Self::key_for_domains(domains);
        self.backend.delete(&key).await
    }

    /// List all certificate bundles
    pub async fn list_all(&self) -> Result<Vec<CertificateBundle>> {
        let keys = self.backend.list("cert:").await?;
        let mut bundles = Vec::new();
        for key in keys {
            if let Some(bytes) = self.backend.load(&key).await? {
                if let Ok(bundle) = serde_json::from_slice(&bytes) {
                    bundles.push(bundle);
                }
            }
        }
        Ok(bundles)
    }
}
