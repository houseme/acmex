//! TLS-ALPN-01 challenge implementation.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock as StdRwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use async_trait::async_trait;
use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::{CertifiedKey, SingleCertAndKey};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use super::ChallengeSolver;
use super::edge::{TlsChallengeEdge, TlsChallengeRoute, TlsRouteLease, TlsRouteState};
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

/// Converts DER validation material into rustls certificate chain and key.
///
/// Shared by the legacy solver and the local multi-route listener so both
/// parse and serve byte-identical validation certificates.
fn rustls_validation_material(
    certificate_der: &[u8],
    private_key_der: &[u8],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let key = PrivateKeyDer::try_from(private_key_der.to_vec())
        .map_err(|_| AcmeError::crypto("failed to parse TLS-ALPN-01 private key".to_string()))?;
    Ok((vec![CertificateDer::from(certificate_der.to_vec())], key))
}

/// Returns the process-default rustls crypto provider.
///
/// Every TLS assembly in this module calls `ServerConfig::builder()` first,
/// which lazily installs the process default, so this only fails if that
/// never happened.
fn active_crypto_provider() -> Result<&'static CryptoProvider> {
    CryptoProvider::get_default()
        .map(|provider| provider.as_ref())
        .ok_or_else(|| AcmeError::crypto("no rustls CryptoProvider for TLS-ALPN-01 keys"))
}

/// Builds rustls signing material for DER validation certificate parts.
///
/// `CertifiedKey::from_der` is deliberately avoided: its consistency check
/// parses the end-entity certificate and rejects the critical acmeIdentifier
/// extension that RFC 8737 §5 requires validation certificates to carry.
fn validation_certified_key(
    certificate_der: &[u8],
    private_key_der: &[u8],
) -> Result<Arc<CertifiedKey>> {
    let provider = active_crypto_provider()?;
    let (certs, key) = rustls_validation_material(certificate_der, private_key_der)?;
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|err| AcmeError::crypto(format!("invalid TLS-ALPN-01 validation key: {err}")))?;
    Ok(Arc::new(CertifiedKey::new(certs, signing_key)))
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

/// One installed SNI route: rustls-ready validation material plus the lease
/// metadata needed for idempotent install/inspect/remove.
struct InstalledRoute {
    sni: String,
    fingerprint: String,
    certified_key: Arc<CertifiedKey>,
}

/// Route table shared between the edge adapter and the rustls cert resolver.
///
/// The resolver runs inside the TLS handshake (a synchronous callback), so
/// the table uses a short-lived `std` lock that is never held across `.await`.
#[derive(Default)]
struct TlsRouteTable {
    /// Route id (the challenge session id) → route.
    by_id: HashMap<String, Arc<InstalledRoute>>,
    /// Lowercased SNI → route. The latest install for an SNI wins.
    by_sni: HashMap<String, Arc<InstalledRoute>>,
}

/// RFC 8737 certificate resolver: selects the validation certificate by SNI
/// and aborts the handshake when the client does not offer `acme-tls/1` or
/// the SNI name has no route.
struct SniCertResolver {
    table: Arc<StdRwLock<TlsRouteTable>>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately opaque: route entries hold private key material.
        f.debug_struct("SniCertResolver").finish_non_exhaustive()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // RFC 8737 §3: the validation connection MUST use the acme-tls/1
        // ALPN protocol; offering nothing else or nothing at all must fail
        // the handshake instead of leaking a validation certificate.
        let offers_acme = client_hello.alpn().is_some_and(|mut protocols| {
            protocols.any(|protocol| protocol == ACME_TLS_ALPN_PROTOCOL)
        });
        if !offers_acme {
            return None;
        }
        let server_name = client_hello.server_name()?.to_ascii_lowercase();
        let table = self.table.read().ok()?;
        table
            .by_sni
            .get(&server_name)
            .map(|route| Arc::clone(&route.certified_key))
    }
}

/// Local multi-route TLS-ALPN-01 listener and edge adapter.
///
/// Binds one real TLS endpoint (rustls + tokio-rustls) and serves one
/// RFC 8737 validation certificate per SNI, so several TLS-ALPN-01
/// challenges can be prepared concurrently — the single key-authorization
/// limitation of [`TlsAlpn01Solver`] does not apply here. Handshakes without
/// the `acme-tls/1` ALPN or with an unrouted SNI name fail, per RFC 8737.
///
/// Dropping the listener stops the accept loop and releases the port;
/// [`LocalTlsListener::shutdown`] does the same and awaits the loop.
pub struct LocalTlsListener {
    local_addr: SocketAddr,
    routes: Arc<StdRwLock<TlsRouteTable>>,
    shutdown: watch::Sender<()>,
    accept_loop: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for LocalTlsListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately coarse: route entries hold private key material.
        let routes = self
            .routes
            .read()
            .map(|table| table.by_id.len())
            .unwrap_or(0);
        f.debug_struct("LocalTlsListener")
            .field("local_addr", &self.local_addr)
            .field("routes", &routes)
            .finish_non_exhaustive()
    }
}

impl LocalTlsListener {
    /// Binds the listener. Bind failures mirror the HTTP-01 listener's
    /// error style: the worker logs them as warnings and degrades, so the
    /// message must carry the operator hint.
    pub async fn bind(listen_addr: SocketAddr) -> Result<Self> {
        let listener = TcpListener::bind(listen_addr).await.map_err(|err| {
            AcmeError::transport(format!(
                "[OPERATOR_ACTION_REQUIRED] cannot bind TLS-ALPN-01 listener at {listen_addr}: {err}; \
                 configure a TLS edge agent, ingress route or port permission"
            ))
        })?;
        let local_addr = listener.local_addr().map_err(|err| {
            AcmeError::transport(format!("read TLS-ALPN-01 local address: {err}"))
        })?;

        // `ServerConfig::builder` lazily installs the process default crypto
        // provider, which `validation_certified_key` reads back afterwards.
        let table = Arc::new(StdRwLock::new(TlsRouteTable::default()));
        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SniCertResolver {
                table: Arc::clone(&table),
            }));
        config.alpn_protocols = vec![ACME_TLS_ALPN_PROTOCOL.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let (shutdown, shutdown_rx) = watch::channel(());
        let accept_loop = tokio::spawn(accept_loop(listener, acceptor, shutdown_rx));
        Ok(Self {
            local_addr,
            routes: table,
            shutdown,
            accept_loop,
        })
    }

    /// The bound local address (ephemeral when configured with port 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Number of currently installed routes.
    pub fn route_count(&self) -> usize {
        self.read_table().by_id.len()
    }

    /// Stops the accept loop and waits for it to exit. Dropping the listener
    /// has the same effect without awaiting.
    pub async fn shutdown(self) {
        let _ = self.shutdown.send(());
        let _ = self.accept_loop.await;
    }

    fn read_table(&self) -> RwLockReadGuard<'_, TlsRouteTable> {
        self.routes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_table(&self) -> RwLockWriteGuard<'_, TlsRouteTable> {
        self.routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

async fn accept_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    mut shutdown: watch::Receiver<()>,
) {
    loop {
        tokio::select! {
            // `changed()` resolves on the shutdown send and on a dropped
            // sender (Err); spurious wakes are filtered inside `changed()`.
            _ = shutdown.changed() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer_addr)) => {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        // RFC 8737: only the handshake matters — the validation
                        // client inspects the certificate and closes, so no
                        // application data is served.
                        match acceptor.accept(stream).await {
                            Ok(mut tls) => {
                                use tokio::io::AsyncWriteExt;
                                let _ = tls.shutdown().await;
                            }
                            Err(err) => {
                                // Expected for ALPN violations and unrouted
                                // SNI probes; anything else shows up here too.
                                tracing::debug!(error = %err, %peer_addr, "TLS-ALPN-01 handshake rejected");
                            }
                        }
                    });
                }
                Err(err) => {
                    tracing::warn!(error = %err, "TLS-ALPN-01 accept failed");
                }
            },
        }
    }
}

#[async_trait]
impl TlsChallengeEdge for LocalTlsListener {
    fn agent_id(&self) -> &str {
        "local-tls-listener"
    }

    async fn install(&self, route: TlsChallengeRoute) -> Result<TlsRouteLease> {
        let sni = route.sni.to_ascii_lowercase();
        let certified_key =
            validation_certified_key(&route.certificate_der, &route.private_key_der)?;
        let installed = Arc::new(InstalledRoute {
            fingerprint: route.fingerprint.clone(),
            certified_key,
            sni: sni.clone(),
        });
        let route_id = route.idempotency_key.clone();
        let mut table = self.write_table();
        // Reinstalling the same session id replaces its route in place, so
        // prepare retries stay idempotent at the route-id level.
        table.by_id.insert(route_id.clone(), Arc::clone(&installed));
        table.by_sni.insert(sni.clone(), installed);
        drop(table);
        tracing::debug!(route_id, sni, "TLS-ALPN-01 route installed");
        Ok(TlsRouteLease {
            agent_id: self.agent_id().to_string(),
            route_id,
            sni,
            fingerprint: route.fingerprint,
        })
    }

    async fn inspect(&self, lease: &TlsRouteLease) -> Result<TlsRouteState> {
        let table = self.read_table();
        let serving = table.by_id.get(&lease.route_id).is_some_and(|route| {
            route.sni == lease.sni.to_ascii_lowercase() && route.fingerprint == lease.fingerprint
        });
        Ok(TlsRouteState {
            serving,
            ttl_secs: None,
        })
    }

    async fn remove(&self, lease: &TlsRouteLease) -> Result<CleanupOutcome> {
        let mut table = self.write_table();
        let removed = table.by_id.remove(&lease.route_id);
        match removed {
            Some(route) => {
                // Drop the SNI pointer only while this route still owns it.
                let sni = lease.sni.to_ascii_lowercase();
                if table
                    .by_sni
                    .get(&sni)
                    .is_some_and(|current| Arc::ptr_eq(current, &route))
                {
                    table.by_sni.remove(&sni);
                }
                drop(table);
                tracing::debug!(route_id = lease.route_id, sni, "TLS-ALPN-01 route removed");
                Ok(CleanupOutcome::Cleaned)
            }
            None => Ok(CleanupOutcome::AlreadyAbsent),
        }
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

    async fn start_server(&self, identifier: Identifier, key_authorization: String) -> Result<()> {
        let validation = build_tls_alpn_validation_cert(&identifier, &key_authorization)?;
        // `ServerConfig::builder` lazily installs the process default crypto
        // provider, which `validation_certified_key` reads back afterwards.
        let builder = ServerConfig::builder();
        let certified_key =
            validation_certified_key(&validation.certificate_der, &validation.private_key_der)?;
        let mut config = builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));
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
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
    use rustls::pki_types::{ServerName, UnixTime};
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

    fn tls_route(idempotency_key: &str, validation: &ValidationCertificate) -> TlsChallengeRoute {
        TlsChallengeRoute {
            idempotency_key: idempotency_key.to_string(),
            sni: validation.sni.clone(),
            certificate_der: validation.certificate_der.clone(),
            private_key_der: validation.private_key_der.clone(),
            fingerprint: validation.fingerprint.clone(),
            ttl_secs: 30,
        }
    }

    #[tokio::test]
    async fn local_listener_routes_concurrent_idents_and_unroutes_idempotently() {
        let edge = LocalTlsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let dns =
            build_tls_alpn_validation_cert(&Identifier::try_dns("example.com").unwrap(), "ka-dns")
                .unwrap();
        let ip = build_tls_alpn_validation_cert(&Identifier::try_ip("192.0.2.1").unwrap(), "ka-ip")
            .unwrap();

        let lease_dns = edge.install(tls_route("session-dns", &dns)).await.unwrap();
        assert_eq!(lease_dns.sni, "example.com");
        // Reinstall with the same idempotency key keeps the same lease.
        assert_eq!(
            edge.install(tls_route("session-dns", &dns)).await.unwrap(),
            lease_dns
        );
        let lease_ip = edge.install(tls_route("session-ip", &ip)).await.unwrap();
        assert_eq!(lease_ip.sni, "1.2.0.192.in-addr.arpa");
        assert_eq!(edge.route_count(), 2);

        assert!(edge.inspect(&lease_dns).await.unwrap().serving);
        assert!(edge.inspect(&lease_ip).await.unwrap().serving);

        assert_eq!(
            edge.remove(&lease_dns).await.unwrap(),
            CleanupOutcome::Cleaned
        );
        assert_eq!(
            edge.remove(&lease_dns).await.unwrap(),
            CleanupOutcome::AlreadyAbsent
        );
        assert!(!edge.inspect(&lease_dns).await.unwrap().serving);
        // The untouched route keeps serving.
        assert!(edge.inspect(&lease_ip).await.unwrap().serving);
        assert_eq!(edge.route_count(), 1);
        edge.shutdown().await;
    }

    /// A test TLS client that trusts any server certificate (the validation
    /// certificate is self-signed by design).
    #[derive(Debug)]
    struct AcceptAnyServerCert;

    impl rustls::client::danger::ServerCertVerifier for AcceptAnyServerCert {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> std::result::Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
            ]
        }
    }

    fn test_connector(alpn_protocols: Vec<Vec<u8>>) -> tokio_rustls::TlsConnector {
        let mut config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
            .with_no_client_auth();
        config.alpn_protocols = alpn_protocols;
        tokio_rustls::TlsConnector::from(Arc::new(config))
    }

    async fn connect(
        connector: &tokio_rustls::TlsConnector,
        addr: SocketAddr,
        server_name: &str,
    ) -> std::result::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>, std::io::Error>
    {
        let server_name = ServerName::try_from(server_name.to_string()).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, err.to_string())
        })?;
        let tcp = tokio::net::TcpStream::connect(addr).await?;
        let handshake = connector.connect(server_name, tcp);
        tokio::time::timeout(Duration::from_secs(5), handshake)
            .await
            .expect("TLS handshake timed out")
    }

    #[tokio::test]
    async fn local_listener_serves_validation_cert_for_acme_tls_alpn() {
        let edge = LocalTlsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let validation = build_tls_alpn_validation_cert(
            &Identifier::try_dns("example.com").unwrap(),
            "token.thumbprint",
        )
        .unwrap();
        let lease = edge
            .install(tls_route("session-live", &validation))
            .await
            .unwrap();
        let addr = edge.local_addr();

        // The validation client negotiates acme-tls/1 and must see exactly
        // the self-signed validation certificate for the routed SNI.
        let connector = test_connector(vec![ACME_TLS_ALPN_PROTOCOL.to_vec()]);
        let tls = connect(&connector, addr, "example.com").await.unwrap();
        let (_, connection) = tls.get_ref();
        assert_eq!(connection.alpn_protocol(), Some(ACME_TLS_ALPN_PROTOCOL));
        let peer_cert = connection
            .peer_certificates()
            .expect("server presents validation certificate")
            .first()
            .expect("certificate chain is non-empty")
            .clone();
        assert_eq!(
            peer_cert.as_ref(),
            validation.certificate_der.as_slice(),
            "served certificate must be the installed validation certificate"
        );
        drop(tls);

        // An unrouted SNI fails the handshake (RFC 8737: serve nothing).
        assert!(
            connect(&connector, addr, "other.example.net")
                .await
                .is_err()
        );

        // After cleanup the SNI is unrouted and fails the handshake too.
        assert_eq!(edge.remove(&lease).await.unwrap(), CleanupOutcome::Cleaned);
        assert!(connect(&connector, addr, "example.com").await.is_err());

        edge.shutdown().await;
    }

    #[tokio::test]
    async fn local_listener_rejects_handshakes_without_acme_tls_alpn() {
        let edge = LocalTlsListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let validation = build_tls_alpn_validation_cert(
            &Identifier::try_dns("example.com").unwrap(),
            "token.thumbprint",
        )
        .unwrap();
        edge.install(tls_route("session-alpn", &validation))
            .await
            .unwrap();
        let addr = edge.local_addr();

        // RFC 8737 §3: a validation connection not offering acme-tls/1 must
        // fail the handshake instead of receiving the validation certificate.
        let https_connector = test_connector(vec![b"http/1.1".to_vec()]);
        assert!(
            connect(&https_connector, addr, "example.com")
                .await
                .is_err()
        );

        // No ALPN at all is rejected the same way.
        let plain_connector = test_connector(Vec::new());
        assert!(
            connect(&plain_connector, addr, "example.com")
                .await
                .is_err()
        );

        edge.shutdown().await;
    }
}
