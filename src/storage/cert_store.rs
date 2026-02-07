/// Certificate storage helper
use crate::client::CertificateBundle;
use crate::error::{AcmeError, Result};
use crate::storage::StorageBackend;

/// Certificate store using a storage backend
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
}
