/// Encrypted storage wrapper
use async_trait::async_trait;
use rand::RngExt;

use super::StorageBackend;
use crate::error::{AcmeError, Result};

/// Encrypted storage wrapper using AES-256-GCM
pub struct EncryptedStorage<B: StorageBackend> {
    backend: B,
    key: [u8; 32],
}

impl<B: StorageBackend> EncryptedStorage<B> {
    pub fn new(backend: B, key: [u8; 32]) -> Self {
        Self { backend, key }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key".to_string()))?;
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; 12];
            rand::rng().fill(&mut nonce_bytes);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Encrypt failed".to_string()))?;

            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&in_out);
            return Ok(out);
        }

        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring-crypto"))]
        {
            use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key".to_string()))?;
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill(&mut nonce_bytes);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Encrypt failed".to_string()))?;

            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&in_out);
            return Ok(out);
        }

        #[cfg(all(not(feature = "aws-lc-rs"), not(feature = "ring-crypto")))]
        {
            Err(AcmeError::configuration(
                "No crypto backend enabled (aws-lc-rs or ring-crypto)".to_string(),
            ))
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(AcmeError::crypto("Ciphertext too short".to_string()));
        }

        let (nonce_bytes, data) = ciphertext.split_at(12);

        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key".to_string()))?;
            let key = LessSafeKey::new(unbound);

            let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
            let mut in_out = data.to_vec();
            let plaintext = key
                .open_in_place(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Decrypt failed".to_string()))?;

            return Ok(plaintext.to_vec());
        }

        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring-crypto"))]
        {
            use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key".to_string()))?;
            let key = LessSafeKey::new(unbound);

            let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
            let mut in_out = data.to_vec();
            let plaintext = key
                .open_in_place(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Decrypt failed".to_string()))?;

            return Ok(plaintext.to_vec());
        }

        #[cfg(all(not(feature = "aws-lc-rs"), not(feature = "ring-crypto")))]
        {
            Err(AcmeError::configuration(
                "No crypto backend enabled (aws-lc-rs or ring-crypto)".to_string(),
            ))
        }
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for EncryptedStorage<B> {
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        self.backend.store(key, &encrypted).await
    }

    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let data = self.backend.load(key).await?;
        match data {
            Some(ciphertext) => Ok(Some(self.decrypt(&ciphertext)?)),
            None => Ok(None),
        }
    }

    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.backend.list(prefix).await
    }
}
