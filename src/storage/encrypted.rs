/// Encrypted storage wrapper.
/// This module provides a transparent encryption layer for any `StorageBackend`,
/// using AES-256-GCM to protect sensitive data at rest.
use async_trait::async_trait;
use super::StorageBackend;
use crate::error::{AcmeError, Result};

/// A storage wrapper that encrypts data before storing it in the underlying backend.
/// It uses AES-256-GCM with a unique 12-byte nonce for each entry.
pub struct EncryptedStorage<B: StorageBackend> {
    /// The underlying storage backend.
    backend: B,
    /// The 32-byte symmetric key used for encryption and decryption.
    key: [u8; 32],
}

impl<B: StorageBackend> EncryptedStorage<B> {
    /// Creates a new `EncryptedStorage` wrapper.
    pub fn new(backend: B, key: [u8; 32]) -> Self {
        tracing::debug!("Initializing EncryptedStorage wrapper");
        Self { backend, key }
    }

    /// Encrypts the plaintext and prepends the nonce to the ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        tracing::debug!("Encrypting data ({} bytes)", plaintext.len());

        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
            use rand::RngCore;

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key"))?;
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                .map_err(|e| {
                    tracing::error!("AES-GCM encryption failed: {}", e);
                    AcmeError::crypto("Encryption failed")
                })?;

            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&in_out);
            Ok(out)
        }

        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring-crypto"))]
        {
            use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
            use rand::RngCore;

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key"))?;
            let key = LessSafeKey::new(unbound);

            let mut nonce_bytes = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);

            let mut in_out = plaintext.to_vec();
            key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Encryption failed"))?;

            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&in_out);
            Ok(out)
        }

        #[cfg(all(not(feature = "aws-lc-rs"), not(feature = "ring-crypto")))]
        {
            tracing::error!("No cryptographic backend enabled for EncryptedStorage");
            Err(AcmeError::configuration(
                "No crypto backend enabled (aws-lc-rs or ring-crypto)".to_string(),
            ))
        }
    }

    /// Decrypts the ciphertext using the prepended nonce.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            tracing::error!("Ciphertext is too short to contain a nonce");
            return Err(AcmeError::crypto("Ciphertext too short"));
        }

        let (nonce_bytes, data) = ciphertext.split_at(12);
        tracing::debug!("Decrypting data ({} bytes)", data.len());

        #[cfg(feature = "aws-lc-rs")]
        {
            use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key"))?;
            let key = LessSafeKey::new(unbound);

            let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
            let mut in_out = data.to_vec();
            let plaintext = key
                .open_in_place(nonce, Aad::empty(), &mut in_out)
                .map_err(|e| {
                    tracing::error!("AES-GCM decryption failed: {}", e);
                    AcmeError::crypto("Decryption failed")
                })?;

            Ok(plaintext.to_vec())
        }

        #[cfg(all(not(feature = "aws-lc-rs"), feature = "ring-crypto"))]
        {
            use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};

            let unbound = UnboundKey::new(&AES_256_GCM, &self.key)
                .map_err(|_| AcmeError::crypto("Invalid encryption key"))?;
            let key = LessSafeKey::new(unbound);

            let nonce = Nonce::assume_unique_for_key(nonce_bytes.try_into().unwrap());
            let mut in_out = data.to_vec();
            let plaintext = key
                .open_in_place(nonce, Aad::empty(), &mut in_out)
                .map_err(|_| AcmeError::crypto("Decryption failed"))?;

            Ok(plaintext.to_vec())
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
    /// Encrypts the value and stores it in the underlying backend.
    async fn store(&self, key: &str, value: &[u8]) -> Result<()> {
        let encrypted = self.encrypt(value)?;
        self.backend.store(key, &encrypted).await
    }

    /// Loads the ciphertext from the backend and decrypts it.
    async fn load(&self, key: &str) -> Result<Option<Vec<u8>>> {
        let data = self.backend.load(key).await?;
        match data {
            Some(ciphertext) => Ok(Some(self.decrypt(&ciphertext)?)),
            None => Ok(None),
        }
    }

    /// Deletes the value from the underlying backend.
    async fn delete(&self, key: &str) -> Result<()> {
        self.backend.delete(key).await
    }

    /// Lists keys from the underlying backend.
    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        self.backend.list(prefix).await
    }
}
