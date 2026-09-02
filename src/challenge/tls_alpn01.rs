//! TLS-ALPN-01 challenge implementation.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use super::ChallengeSolver;
use super::edge::{TlsChallengeEdge, TlsChallengeRoute, TlsRouteLease};
use super::presenter::{CleanupOutcome, Observation, PrepareChallenge};
use super::{ChallengePresenter, ChallengeSession};
use crate::domain::challenge::{ChallengeLease, ChallengeLeaseLocator, ChallengeLeaseState};
use crate::domain::{ChallengeLeaseId, DnsIdentifier};
use crate::error::{AcmeError, Result};
use crate::order::Challenge;
use crate::types::{ChallengeType, Identifier};

/// TLS-ALPN protocol required by RFC 8737.
pub const ACME_TLS_ALPN_PROTOCOL: &[u8] = b"acme-tls/1";

/// Self-signed validation material for one TLS-ALPN-01 challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCertificate {
    /// SNI name the edge must route on. IP identifiers use RFC 8738 reverse DNS.
    pub sni: String,
    /// DER-encoded validation certificate.
    pub certificate_der: Vec<u8>,
    /// DER-encoded private key.
    pub private_key_der: Vec<u8>,
    /// SHA-256 fingerprint of the certificate DER.
    pub fingerprint: String,
    /// SHA-256 digest of key authorization, hex-encoded.
    pub acme_identifier_sha256: String,
}

/// Returns the TLS SNI name used for validation. DNS identifiers use their
/// DNS base name; IP identifiers use RFC 8738 reverse DNS names.
pub fn tls_alpn_validation_sni(identifier: &Identifier) -> Result<String> {
    match identifier {
        Identifier::Dns(dns) => {
            if dns.is_wildcard() {
                return Err(AcmeError::invalid_input(
                    "TLS-ALPN-01 cannot validate wildcard DNS identifiers",
                ));
            }
            Ok(dns.base_name().to_string())
        }
        Identifier::Ip(ip) => Ok(ip_validation_sni(*ip).to_wire_value()),
    }
}

/// Builds the RFC 8738 reverse DNS SNI name for an IP identifier.
pub fn ip_validation_sni(ip: IpAddr) -> DnsIdentifier {
    let name = match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ip) => {
            let nibbles = ip
                .octets()
                .iter()
                .rev()
                .flat_map(|byte| [byte & 0x0f, byte >> 4])
                .map(|nibble| format!("{nibble:x}"))
                .collect::<Vec<_>>()
                .join(".");
            format!("{nibbles}.ip6.arpa")
        }
    };
    DnsIdentifier::parse(&name).expect("reverse IP validation SNI is a valid DNS name")
}

/// Builds a TLS-ALPN-01 self-signed validation certificate.
pub fn build_tls_alpn_validation_cert(
    identifier: &Identifier,
    key_authorization: &str,
) -> Result<ValidationCertificate> {
    let sni = tls_alpn_validation_sni(identifier)?;
    let mut digest = Sha256::new();
    digest.update(key_authorization.as_bytes());
    let acme_identifier = digest.finalize();

    let mut params = CertificateParams::default();
    params.subject_alt_names = match identifier {
        Identifier::Dns(dns) => {
            if dns.is_wildcard() {
                return Err(AcmeError::invalid_input(
                    "TLS-ALPN-01 cannot validate wildcard DNS identifiers",
                ));
            }
            vec![SanType::DnsName(dns.base_name().try_into().map_err(
                |err| AcmeError::crypto(format!("invalid DNS SAN for TLS-ALPN-01: {err}")),
            )?)]
        }
        Identifier::Ip(ip) => vec![SanType::IpAddress(*ip)],
    };
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(&acme_identifier));

    let key_pair = KeyPair::generate()
        .map_err(|err| AcmeError::crypto(format!("generate TLS-ALPN-01 key: {err}")))?;
    let cert = params
        .self_signed(&key_pair)
        .map_err(|err| AcmeError::crypto(format!("generate TLS-ALPN-01 certificate: {err}")))?;

    let certificate_der = cert.der().to_vec();
    let private_key_der = key_pair.serialize_der();
    Ok(ValidationCertificate {
        sni,
        fingerprint: sha256_hex(&certificate_der),
        certificate_der,
        private_key_der,
        acme_identifier_sha256: hex::encode(acme_identifier),
    })
}

/// TLS-ALPN-01 presenter backed by an edge agent.
pub struct TlsAlpn01Presenter {
    edge: Arc<dyn TlsChallengeEdge>,
}

impl TlsAlpn01Presenter {
    /// Creates a presenter backed by a TLS edge agent.
    pub fn with_edge(edge: Arc<dyn TlsChallengeEdge>) -> Self {
        Self { edge }
    }
}

#[async_trait]
impl ChallengePresenter for TlsAlpn01Presenter {
    fn kind(&self) -> ChallengeType {
        ChallengeType::TlsAlpn01
    }

    async fn prepare(&self, request: PrepareChallenge) -> Result<ChallengeLease> {
        if request.session.challenge_type != ChallengeType::TlsAlpn01 {
            return Err(AcmeError::invalid_input(format!(
                "TLS-ALPN-01 presenter cannot prepare {:?}",
                request.session.challenge_type
            )));
        }

        let validation = build_tls_alpn_validation_cert(
            &request.session.identifier,
            &request.key_authorization,
        )?;
        let route_lease = self
            .edge
            .install(TlsChallengeRoute {
                idempotency_key: request.session.id.clone(),
                sni: validation.sni.clone(),
                certificate_der: validation.certificate_der,
                private_key_der: validation.private_key_der,
                fingerprint: validation.fingerprint.clone(),
                ttl_secs: 3600,
            })
            .await?;

        let now = jiff::Timestamp::now();
        Ok(ChallengeLease {
            id: ChallengeLeaseId::generate(),
            operation_id: request.session.operation_id,
            identifier: request.session.identifier,
            challenge_type: ChallengeType::TlsAlpn01,
            locator: ChallengeLeaseLocator::Tls {
                agent_id: route_lease.agent_id,
                route_id: route_lease.route_id,
                sni: route_lease.sni,
                fingerprint: route_lease.fingerprint,
            },
            created_at: now,
            expires_at: now.checked_add(jiff::Span::new().hours(1)).unwrap_or(now),
            state: ChallengeLeaseState::Active,
            cleanup_attempts: 0,
            last_cleanup_error: None,
            cleaned_at: None,
        })
    }

    async fn observe(&self, lease: &ChallengeLease) -> Result<Observation> {
        let ChallengeLeaseLocator::Tls {
            agent_id,
            route_id,
            sni,
            fingerprint,
        } = &lease.locator
        else {
            return Ok(Observation::Propagated);
        };

        let state = self
            .edge
            .inspect(&TlsRouteLease {
                agent_id: agent_id.clone(),
                route_id: route_id.clone(),
                sni: sni.clone(),
                fingerprint: fingerprint.clone(),
            })
            .await?;
        Ok(if state.serving {
            Observation::Propagated
        } else {
            Observation::NotYet {
                retry_after: Duration::from_secs(2),
            }
        })
    }

    async fn cleanup(&self, lease: &ChallengeLease) -> Result<CleanupOutcome> {
        let ChallengeLeaseLocator::Tls {
            agent_id,
            route_id,
            sni,
            fingerprint,
        } = &lease.locator
        else {
            return Ok(CleanupOutcome::AlreadyAbsent);
        };
        self.edge
            .remove(&TlsRouteLease {
                agent_id: agent_id.clone(),
                route_id: route_id.clone(),
                sni: sni.clone(),
                fingerprint: fingerprint.clone(),
            })
            .await
    }
}

/// TLS-ALPN-01 legacy single-listener challenge solver.
pub struct TlsAlpn01Solver {
    /// Server listening address.
    listen_addr: SocketAddr,
    /// Key authorization token.
    key_authorization: Arc<RwLock<Option<String>>>,
    /// Server handle for shutdown.
    server_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl Default for TlsAlpn01Solver {
    fn default() -> Self {
        Self::new("0.0.0.0:443".parse().expect("invalid default address"))
    }
}

impl TlsAlpn01Solver {
    /// Creates a new TLS-ALPN-01 solver.
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self {
            listen_addr,
            key_authorization: Arc::new(RwLock::new(None)),
            server_handle: Arc::new(RwLock::new(None)),
        }
    }

    /// Generates rustls-ready validation material for compatibility callers.
    fn generate_cert(
        identifier: &Identifier,
        key_authorization: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let validation = build_tls_alpn_validation_cert(identifier, key_authorization)?;
        let key = PrivateKeyDer::try_from(validation.private_key_der).map_err(|_| {
            AcmeError::crypto("failed to parse TLS-ALPN-01 private key".to_string())
        })?;
        Ok((vec![CertificateDer::from(validation.certificate_der)], key))
    }

    async fn start_server(&self, identifier: Identifier, key_authorization: String) -> Result<()> {
        let (certs, key) = Self::generate_cert(&identifier, &key_authorization)?;
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| AcmeError::transport(format!("create TLS-ALPN-01 config: {err}")))?;
        config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .map_err(|err| AcmeError::transport(format!("bind TLS-ALPN-01 listener: {err}")))?;

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    use tokio::io::AsyncWriteExt;
                                    let (_, mut writer) = tokio::io::split(tls_stream);
                                    let _ = writer.shutdown().await;
                                }
                                Err(err) => {
                                    tracing::warn!(error = %err, %peer_addr, "TLS-ALPN-01 handshake failed");
                                }
                            }
                        });
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "TLS-ALPN-01 accept failed");
                    }
                }
            }
        });

        *self.server_handle.write().await = Some(handle);
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
        *self.key_authorization.write().await = Some(key_authorization.to_string());
        self.start_server(identifier.clone(), key_authorization.to_string())
            .await?;
        tracing::info!(
            token_hash = %ChallengeSession::hash_token(&challenge.token),
            "TLS-ALPN-01 challenge prepared"
        );
        Ok(())
    }

    async fn present(&self) -> Result<()> {
        tracing::debug!("TLS-ALPN-01 challenge presented");
        Ok(())
    }

    async fn verify(&self) -> Result<bool> {
        Ok(self.key_authorization.read().await.is_some())
    }

    async fn cleanup(&mut self) -> Result<()> {
        *self.key_authorization.write().await = None;
        if let Some(handle) = self.server_handle.write().await.take() {
            handle.abort();
        }
        Ok(())
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    hex::encode(digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::ChallengeSessionState;
    use crate::domain::OperationId;
    use x509_parser::prelude::*;

    fn session(identifier: Identifier) -> ChallengeSession {
        ChallengeSession {
            id: "session-tls".to_string(),
            operation_id: OperationId::generate(),
            authorization_url: "https://ca.example/authz/1".to_string(),
            challenge_url: "https://ca.example/challenge/1".to_string(),
            identifier,
            challenge_type: ChallengeType::TlsAlpn01,
            token_hash: ChallengeSession::hash_token("token-a"),
            state: ChallengeSessionState::Selected,
            lease_id: None,
            deadline: jiff::Timestamp::now()
                .checked_add(jiff::Span::new().minutes(30))
                .unwrap(),
            last_propagation_check_at: None,
            last_propagation_status: None,
            last_ca_poll_at: None,
            last_ca_status: None,
            last_error: None,
        }
    }

    #[test]
    fn ip_identifier_sni_uses_reverse_dns_names() {
        let v4 = Identifier::try_ip("192.0.2.1").unwrap();
        assert_eq!(
            tls_alpn_validation_sni(&v4).unwrap(),
            "1.2.0.192.in-addr.arpa"
        );

        let v6 = Identifier::try_ip("2001:db8::1").unwrap();
        assert_eq!(
            tls_alpn_validation_sni(&v6).unwrap(),
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }

    #[test]
    fn tls_alpn_cert_for_ip_has_single_ip_san_and_critical_acme_extension() {
        let identifier = Identifier::try_ip("192.0.2.1").unwrap();
        let validation = build_tls_alpn_validation_cert(&identifier, "token.thumbprint").unwrap();

        let (_, cert) = X509Certificate::from_der(&validation.certificate_der).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(san.value.general_names.len(), 1);
        assert_eq!(
            san.value.general_names[0],
            GeneralName::IPAddress(&[192, 0, 2, 1])
        );

        let ext = cert
            .extensions()
            .iter()
            .find(|ext| ext.oid.to_id_string() == "1.3.6.1.5.5.7.1.31")
            .expect("acmeIdentifier extension");
        assert!(ext.critical);

        let mut digest = Sha256::new();
        digest.update(b"token.thumbprint");
        let expected = digest.finalize();
        assert_eq!(&ext.value[0..2], &[0x04, 0x20]);
        assert_eq!(&ext.value[2..], expected.as_slice());
    }

    #[test]
    fn tls_alpn_cert_for_dns_uses_dns_san_without_wildcard() {
        let identifier = Identifier::try_dns("WWW.example.com").unwrap();
        let validation = build_tls_alpn_validation_cert(&identifier, "token.thumbprint").unwrap();
        assert_eq!(validation.sni, "www.example.com");

        let (_, cert) = X509Certificate::from_der(&validation.certificate_der).unwrap();
        let san = cert.subject_alternative_name().unwrap().unwrap();
        assert_eq!(
            san.value.general_names,
            vec![GeneralName::DNSName("www.example.com")]
        );
    }

    #[tokio::test]
    async fn tls_presenter_installs_and_cleans_edge_route() {
        let presenter =
            TlsAlpn01Presenter::with_edge(Arc::new(super::super::edge::FakeTlsEdge::new("edge")));
        let lease = presenter
            .prepare(PrepareChallenge {
                session: session(Identifier::try_ip("192.0.2.1").unwrap()),
                key_authorization: "token.thumbprint".to_string(),
            })
            .await
            .unwrap();

        let ChallengeLeaseLocator::Tls { sni, .. } = &lease.locator else {
            panic!("expected TLS locator");
        };
        assert_eq!(sni, "1.2.0.192.in-addr.arpa");
        assert_eq!(
            presenter.observe(&lease).await.unwrap(),
            Observation::Propagated
        );
        assert_eq!(
            presenter.cleanup(&lease).await.unwrap(),
            CleanupOutcome::Cleaned
        );
    }
}
