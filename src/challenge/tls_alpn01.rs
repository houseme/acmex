/// TLS-ALPN-01 challenge implementation
use async_trait::async_trait;
use rcgen::CertificateParams;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use super::ChallengeSolver;
use crate::error::Result;
use crate::order::Challenge;
use crate::types::{ChallengeType, Identifier};

/// TLS-ALPN-01 challenge solver
pub struct TlsAlpn01Solver {
    /// Server listening address
    listen_addr: SocketAddr,
    /// Key authorization token
    key_authorization: Arc<RwLock<Option<String>>>,
    /// Server handle for shutdown
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl Default for TlsAlpn01Solver {
    /// Create with default address (0.0.0.0:443)
    fn default() -> Self {
        Self::new("0.0.0.0:443".parse().expect("Invalid default address"))
    }
}
impl TlsAlpn01Solver {
    /// Create a new TLS-ALPN-01 solver
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            key_authorization: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Generate a self-signed certificate with the acme-tls/1 ALPN extension
    fn generate_cert(
        domain: &str,
        key_auth_sha256: &[u8],
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to create cert params: {}", e))
        })?;

        // Add the acmeValidation-v1 extension (OID 1.3.6.1.5.5.7.1.31)
        // The value is the SHA-256 digest of the key authorization
        // We need to construct the ASN.1 DER encoding manually or use a library
        // For simplicity, we'll use a custom extension if rcgen supports it,
        // or we might need to use a lower-level library if rcgen doesn't support custom extensions easily.
        // Note: rcgen 0.14 supports custom extensions.

        // OID: 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
        let oid = vec![1, 3, 6, 1, 5, 5, 7, 1, 31];

        // The value is an OCTET STRING containing the SHA-256 digest
        // ASN.1 encoding: Tag (0x04) | Length | Value
        let mut value = vec![0x04, 0x20]; // Tag for OCTET STRING, Length 32
        value.extend_from_slice(key_auth_sha256);

        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(&oid, value));

        // Generate a key pair for signing
        let key_pair = rcgen::KeyPair::generate().map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate key pair: {}", e))
        })?;

        let cert = params.self_signed(&key_pair).map_err(|e| {
            crate::error::AcmeError::crypto(format!("Failed to generate certificate: {}", e))
        })?;

        let cert_der = cert.der();
        let key_der = key_pair.serialize_der();

        Ok((
            vec![CertificateDer::from(cert_der.to_vec())],
            PrivateKeyDer::try_from(key_der).map_err(|_| {
                crate::error::AcmeError::crypto("Failed to parse private key".to_string())
            })?,
        ))
    }

    /// Start the TLS server
    async fn start_server(&self, domain: String, key_auth: String) -> Result<()> {
        // Calculate SHA-256 of key authorization
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(key_auth.as_bytes());
        let key_auth_sha256 = hasher.finalize();

        // Generate certificate
        let (certs, key) = Self::generate_cert(&domain, &key_auth_sha256)?;

        // Configure TLS server
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                crate::error::AcmeError::transport(format!("Failed to create TLS config: {}", e))
            })?;

        // Set ALPN protocols - MUST include "acme-tls/1"
        config.alpn_protocols = vec![b"acme-tls/1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(self.listen_addr).await.map_err(|e| {
            crate::error::AcmeError::transport(format!("Failed to bind TLS server: {}", e))
        })?;

        tracing::info!("TLS-ALPN-01 server listening on {}", self.listen_addr);

        // Spawn server task
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        tracing::debug!("Accepted connection from {}", peer_addr);
                        let acceptor = acceptor.clone();

                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    // Handshake completed successfully
                                    // We don't need to do anything else, the handshake proves possession of the key
                                    // The ACME server will verify the certificate we presented
                                    tracing::debug!("TLS handshake completed with {}", peer_addr);

                                    // Keep connection open for a bit?
                                    // Usually the ACME server will close it after verification
                                    use tokio::io::AsyncWriteExt;
                                    let (_, mut writer) = tokio::io::split(tls_stream);
                                    let _ = writer.shutdown().await;
                                }
                                Err(e) => {
                                    tracing::warn!("TLS handshake failed: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept failed: {}", e);
                        // Don't break loop on accept error
                    }
                }
            }
        });

        let mut server = self.server_handle.write().await;
        *server = Some(handle);

        Ok(())
    }
}

#[async_trait]
impl ChallengeSolver for TlsAlpn01Solver {
    fn challenge_type(&self) -> ChallengeType {
        ChallengeType::TlsAlpn01
    }

    async fn prepare(
        &mut self,
        challenge: &Challenge,
        identifier: &Identifier,
        key_authorization: &str,
    ) -> Result<()> {
        // Store the key authorization
        let mut auth = self.key_authorization.write().await;
        *auth = Some(key_authorization.to_string());

        // Use the identifier value as the domain
        let domain = identifier.value.clone();

        // Start the server
        self.start_server(domain, key_authorization.to_string())
            .await?;

        tracing::info!(
            "TLS-ALPN-01 challenge prepared for token: {}",
            challenge.token
        );

        Ok(())
    }

    async fn present(&self) -> Result<()> {
        tracing::debug!("TLS-ALPN-01 challenge presented");
        Ok(())
    }

    async fn verify(&self) -> Result<bool> {
        let auth_guard = self.key_authorization.read().await;
        Ok(auth_guard.is_some())
    }

    async fn cleanup(&mut self) -> Result<()> {
        // Clear the key authorization
        let mut auth = self.key_authorization.write().await;
        *auth = None;

        // Stop the server
        let mut handle = self.server_handle.write().await;
        if let Some(h) = handle.take() {
            h.abort();
            tracing::info!("TLS-ALPN-01 server stopped");
        }

        Ok(())
    }
}
