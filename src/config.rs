use crate::ca::{CAConfig, CertificateAuthority, Environment};
use crate::dns::spec::SecretRef;
/// Configuration management for AcmeX.
/// This module provides comprehensive configuration support, including TOML parsing,
/// environment variable overrides, and validation for multi-CA setups.
use crate::error::{AcmeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

/// Main configuration structure for the AcmeX application.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// ACME protocol and CA settings.
    #[serde(default)]
    pub acme: AcmeSettings,

    /// CA-specific runtime settings for new v0.10 surfaces.
    #[serde(default)]
    pub ca: CaSettings,

    /// Storage backend settings.
    #[serde(default)]
    pub storage: StorageSettings,

    /// Repository (v0.9 domain persistence) settings.
    #[serde(default)]
    pub repository: RepositorySettings,

    /// Challenge solving settings.
    #[serde(default)]
    pub challenge: ChallengeSettings,

    /// DNS provider and propagation settings.
    #[serde(default)]
    pub dns: DnsSettings,

    /// Certificate renewal settings.
    #[serde(default)]
    pub renewal: RenewalSettings,

    /// Metrics and observability settings.
    #[serde(default)]
    pub metrics: Option<MetricsSettings>,

    /// Notification settings (Webhooks, Email).
    #[serde(default)]
    pub notifications: Option<NotificationSettings>,

    /// Durable outbox consumer settings.
    #[serde(default)]
    pub outbox: OutboxSettings,

    /// Key management settings.
    #[serde(default)]
    pub key: Option<KeySettings>,

    /// Remote certificate delivery sinks (Kubernetes Secret, Vault KV).
    #[serde(default)]
    pub delivery: DeliverySettings,

    /// CLI-specific settings.
    #[serde(default)]
    pub cli: Option<CliSettings>,

    /// API server settings.
    #[serde(default)]
    pub server: Option<ServerSettings>,
}

/// ACME protocol and Certificate Authority (CA) settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSettings {
    /// Selected Certificate Authority: "letsencrypt", "google", "zerossl", or "custom".
    #[serde(default = "default_ca")]
    pub ca: String,

    /// CA environment: "production" or "staging".
    #[serde(default = "default_ca_env")]
    pub ca_environment: String,

    /// Custom CA directory URL (required if ca = "custom").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_custom_url: Option<String>,

    /// Contact information (e.g., ["mailto:admin@example.com"]).
    #[serde(default)]
    pub contact: Vec<String>,

    /// Whether the Terms of Service (ToS) have been agreed to.
    #[serde(default = "default_true")]
    pub tos_agreed: bool,

    /// Optional External Account Binding (EAB) for CAs like Google or ZeroSSL.
    #[serde(default)]
    pub external_account_binding: Option<ExternalAccountBinding>,

    /// PEM files containing trusted roots for issued-certificate acceptance.
    #[serde(default)]
    pub trust_anchor_pem_files: Vec<String>,

    /// Explicitly skip issued-certificate trust-anchor verification.
    ///
    /// This is intended only for controlled test or private-CA bootstrap
    /// environments. When false, an empty `trust_anchor_pem_files` list fails
    /// certificate verification instead of silently accepting the chain.
    #[serde(default)]
    pub skip_certificate_trust_check: bool,

    /// Internal cache for the resolved directory URL.
    #[serde(skip)]
    pub directory: String,
}

/// CA-specific runtime configuration.
///
/// New v0.10 settings live under `[ca]` so they are not confused with the
/// legacy ACME endpoint selector in `[acme]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaSettings {
    /// Optional External Account Binding configuration (`[ca.eab]`).
    #[serde(default)]
    pub eab: Option<ExternalAccountBinding>,

    /// ACME account key type: `"ed25519"` (default), `"ecdsa_p256"`,
    /// `"ecdsa_p384"`, `"ecdsa_p521"`, `"rsa2048"` or `"rsa4096"`.
    ///
    /// Only applied when a *new* account key is generated; an existing
    /// stored PEM key keeps its own type. The default is unchanged from
    /// previous releases.
    #[serde(default = "default_account_key_type")]
    pub account_key_type: String,
}

impl Default for CaSettings {
    fn default() -> Self {
        Self {
            eab: None,
            account_key_type: default_account_key_type(),
        }
    }
}

fn default_account_key_type() -> String {
    "ed25519".to_string()
}

impl CaSettings {
    /// Resolves `account_key_type` to the crypto [`KeyType`], rejecting
    /// unknown values with an explicit configuration error.
    pub fn resolve_account_key_type(&self) -> Result<crate::crypto::keypair::KeyType> {
        crate::crypto::keypair::KeyType::from_config_str(&self.account_key_type).ok_or_else(|| {
            AcmeError::configuration(format!(
                "ca.account_key_type `{}` is not supported; expected one of \
                 ed25519, ecdsa_p256, ecdsa_p384, ecdsa_p521, rsa2048, rsa4096",
                self.account_key_type
            ))
        })
    }
}

impl AcmeSettings {
    /// Converts the settings into a `CAConfig` for endpoint resolution.
    pub fn to_ca_config(&self) -> Result<CAConfig> {
        let ca_type = match self.ca.to_lowercase().as_str() {
            "letsencrypt" => CertificateAuthority::LetsEncrypt,
            "google" => {
                #[cfg(not(feature = "google-ca"))]
                return Err(AcmeError::configuration(
                    "Feature 'google-ca' is not enabled",
                ));
                #[cfg(feature = "google-ca")]
                CertificateAuthority::Google
            }
            "zerossl" => {
                #[cfg(not(feature = "zerossl-ca"))]
                return Err(AcmeError::configuration(
                    "Feature 'zerossl-ca' is not enabled",
                ));
                #[cfg(feature = "zerossl-ca")]
                CertificateAuthority::ZeroSSL
            }
            "custom" => CertificateAuthority::Custom,
            _ => {
                return Err(AcmeError::configuration(format!(
                    "Unsupported CA type: {}",
                    self.ca
                )));
            }
        };

        let env = match self.ca_environment.to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "staging" | "test" | "dev" => Environment::Staging,
            _ => {
                return Err(AcmeError::configuration(format!(
                    "Invalid environment: {}",
                    self.ca_environment
                )));
            }
        };

        let mut config = CAConfig::new(ca_type, env);
        if let Some(ref url) = self.ca_custom_url {
            config = config.with_custom_url(url.clone());
        }

        if let Some(first_contact) = self.contact.first() {
            config = config.with_contact_email(first_contact.clone());
        }

        Ok(config)
    }
}

/// External account binding configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    pub key_id: String,
    pub hmac_key: SecretRef,
}

impl ExternalAccountBinding {
    /// Converts config into the CA backend reference type.
    pub fn to_backend_ref(&self) -> crate::ca_backend::ExternalAccountBindingRef {
        crate::ca_backend::ExternalAccountBindingRef {
            key_id: self.key_id.clone(),
            hmac_key: self.hmac_key.clone(),
        }
    }
}

/// Repository settings for the v0.9 domain persistence layer.
///
/// The repository stores intents, lineages, versions, operations, leases
/// and outbox events; it is separate from (and supersedes, for new code)
/// the legacy `storage` KV settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepositorySettings {
    /// Repository backend: "memory", "file" or (with the `redis` feature)
    /// "redis".
    #[serde(default = "default_repository_backend")]
    pub backend: String,

    /// File backend configuration (required when backend = "file").
    #[serde(default)]
    pub file: Option<FileRepositoryConfig>,

    /// Redis backend configuration (required when backend = "redis" and the
    /// `redis` feature is compiled in).
    #[serde(default)]
    pub redis: Option<RedisRepositoryConfig>,

    /// Optional namespace prefix (reserved for multi-tenant deployments).
    #[serde(default)]
    pub namespace: Option<String>,

    /// Legacy-data migration mode applied at startup.
    #[serde(default)]
    pub migration: MigrationSettings,
}

impl Default for RepositorySettings {
    fn default() -> Self {
        Self {
            backend: default_repository_backend(),
            file: None,
            redis: None,
            namespace: None,
            migration: MigrationSettings::default(),
        }
    }
}

fn default_repository_backend() -> String {
    "memory".to_string()
}

/// File repository configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRepositoryConfig {
    /// Root directory for all repository aggregates.
    pub path: String,
}

/// Redis repository configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisRepositoryConfig {
    /// Redis connection URL, e.g. `redis://127.0.0.1:6379/0`. Credentials
    /// embedded in the URL must use SecretRef-style injection in deployment
    /// tooling; the value is never logged (the repository redacts it).
    pub url: String,
}

/// Legacy migration settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSettings {
    /// "off" (default), "dry-run", "execute" or "verify-only".
    #[serde(default = "default_migration_mode")]
    pub mode: String,
}

impl Default for MigrationSettings {
    fn default() -> Self {
        Self {
            mode: default_migration_mode(),
        }
    }
}

fn default_migration_mode() -> String {
    "off".to_string()
}

/// Storage backend settings for certificate and account data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Storage backend type: "file", "redis", "encrypted".
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// File storage configuration.
    #[serde(default)]
    pub file: Option<FileStorageConfig>,

    /// Redis storage configuration.
    #[serde(default)]
    pub redis: Option<RedisStorageConfig>,

    /// Encrypted storage configuration.
    #[serde(default)]
    pub encrypted: Option<EncryptedStorageConfig>,
}

/// File storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStorageConfig {
    /// Directory path for certificates and account data.
    #[serde(default = "default_cert_path")]
    pub path: String,
}

/// Redis storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisStorageConfig {
    /// Redis connection URL.
    pub url: String,
    /// Connection pool size.
    #[serde(default = "default_pool_size")]
    pub connection_pool_size: usize,
    /// Database number.
    #[serde(default)]
    pub db: u32,
}

/// Encrypted storage configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStorageConfig {
    /// The underlying backend to encrypt.
    pub inner_backend: String,
    /// Encryption key (supports ${VAR} syntax).
    pub encryption_key: SecretRef,
    /// Key format: "hex" or "base64".
    #[serde(default = "default_key_format")]
    pub key_format: String,
}

/// Challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSettings {
    /// Default challenge type: "http-01", "dns-01", "tls-alpn-01".
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,
    /// HTTP-01 challenge configuration.
    #[serde(default)]
    pub http01: Option<Http01Config>,
    /// DNS-01 challenge configuration.
    #[serde(default)]
    pub dns01: Option<Dns01Config>,
    /// TLS-ALPN-01 challenge configuration.
    #[serde(default)]
    pub tls_alpn: Option<TlsAlpnConfig>,
}

/// HTTP-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http01Config {
    /// Listen address for the temporary HTTP server.
    #[serde(default = "default_http_listen")]
    pub listen_addr: String,
    /// Domain for validation.
    pub domain: Option<String>,
    /// Path where the challenge token will be served.
    #[serde(default = "default_challenge_path")]
    pub challenge_path: String,
}

/// DNS-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns01Config {
    /// Primary DNS provider name.
    pub provider: Option<String>,
    /// API token/key.
    pub api_token: Option<SecretRef>,
    /// Zone ID or domain.
    pub zone_id: Option<String>,
    /// Multiple provider configurations.
    #[serde(default)]
    pub providers: Vec<DnsProviderConfig>,
    /// DNS propagation timeout in seconds.
    #[serde(default = "default_dns_timeout")]
    pub propagation_timeout_secs: u64,
    /// Legacy DNS propagation observation policy. Prefer `[dns.propagation]`.
    #[serde(default)]
    pub propagation: Option<PropagationSettings>,
}

/// DNS provider and propagation configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsSettings {
    /// Global DNS propagation observation policy.
    #[serde(default)]
    pub propagation: Option<PropagationSettings>,
    /// Provider-specific overrides keyed by provider id.
    #[serde(default)]
    pub providers: HashMap<String, DnsProviderPolicyConfig>,
}

/// Provider-specific DNS settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DnsProviderPolicyConfig {
    /// Field-level propagation override for this provider.
    #[serde(default)]
    pub propagation: Option<PropagationOverrideSettings>,
}

/// DNS-01 propagation observation settings
/// (`[dns.propagation]`).
///
/// Controls how AcmeX observes TXT propagation before acknowledging a
/// DNS-01 challenge: which recursive resolvers are queried and the quorum
/// required over authoritative and recursive answers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationSettings {
    /// Quorum over authoritative nameservers: "all" or a positive integer.
    #[serde(default = "default_authoritative_quorum")]
    pub authoritative_quorum: QuorumSpec,
    /// Recursive resolvers queried after the authoritative nameservers,
    /// as `ip:port` (a bare IP defaults to port 53).
    #[serde(default = "default_recursive_resolvers")]
    pub recursive_resolvers: Vec<String>,
    /// Quorum over recursive resolvers: "all" or a positive integer.
    #[serde(default = "default_recursive_quorum")]
    pub recursive_quorum: QuorumSpec,
    /// Overall wait budget, in seconds.
    #[serde(default = "default_dns_timeout", alias = "max_wait")]
    pub max_wait_secs: u64,
    /// Re-check interval while waiting for propagation, in seconds.
    #[serde(
        default = "default_poll_interval_secs",
        alias = "poll_interval",
        alias = "initial_interval_secs"
    )]
    pub poll_interval_secs: u64,
    /// Per-DNS-query timeout, in seconds.
    #[serde(default = "default_query_timeout_secs", alias = "query_timeout")]
    pub query_timeout_secs: u64,
}

impl Default for PropagationSettings {
    fn default() -> Self {
        Self {
            authoritative_quorum: default_authoritative_quorum(),
            recursive_resolvers: default_recursive_resolvers(),
            recursive_quorum: default_recursive_quorum(),
            max_wait_secs: default_dns_timeout(),
            poll_interval_secs: default_poll_interval_secs(),
            query_timeout_secs: default_query_timeout_secs(),
        }
    }
}

impl PropagationSettings {
    fn apply_override(&mut self, override_settings: &PropagationOverrideSettings) {
        if let Some(authoritative_quorum) = override_settings.authoritative_quorum.clone() {
            self.authoritative_quorum = authoritative_quorum;
        }
        if let Some(recursive_resolvers) = override_settings.recursive_resolvers.clone() {
            self.recursive_resolvers = recursive_resolvers;
        }
        if let Some(recursive_quorum) = override_settings.recursive_quorum.clone() {
            self.recursive_quorum = recursive_quorum;
        }
        if let Some(max_wait_secs) = override_settings.max_wait_secs {
            self.max_wait_secs = max_wait_secs;
        }
        if let Some(poll_interval_secs) = override_settings.poll_interval_secs {
            self.poll_interval_secs = poll_interval_secs;
        }
        if let Some(query_timeout_secs) = override_settings.query_timeout_secs {
            self.query_timeout_secs = query_timeout_secs;
        }
    }

    /// Maps the settings onto the propagation policy used by the observer.
    ///
    /// Bare resolver IPs are normalized to `ip:53` so downstream consumers
    /// always see a full socket address.
    pub fn to_policy(&self) -> crate::dns::propagation::PropagationPolicyV2 {
        crate::dns::propagation::PropagationPolicyV2::from_config(
            self.authoritative_quorum.to_quorum(),
            self.recursive_resolvers
                .iter()
                .map(|resolver| normalize_resolver(resolver))
                .collect(),
            self.recursive_quorum.to_quorum(),
            Duration::from_secs(self.max_wait_secs),
            Duration::from_secs(self.poll_interval_secs),
            Duration::from_secs(self.query_timeout_secs),
        )
    }

    /// Validates interval bounds and resolver addresses.
    fn validate(&self, path: &str) -> Result<()> {
        if self.max_wait_secs == 0 {
            return Err(AcmeError::configuration(format!(
                "{path}.max_wait_secs must be at least 1 second"
            )));
        }
        if self.poll_interval_secs == 0 {
            return Err(AcmeError::configuration(format!(
                "{path}.poll_interval_secs must be at least 1 second"
            )));
        }
        if self.query_timeout_secs == 0 {
            return Err(AcmeError::configuration(format!(
                "{path}.query_timeout_secs must be at least 1 second"
            )));
        }
        if self.max_wait_secs < self.poll_interval_secs {
            return Err(AcmeError::configuration(format!(
                "{path}.max_wait_secs must be greater than or equal to poll_interval_secs"
            )));
        }
        for resolver in &self.recursive_resolvers {
            let valid = resolver.parse::<std::net::SocketAddr>().is_ok()
                || resolver.parse::<std::net::IpAddr>().is_ok();
            if !valid {
                return Err(AcmeError::configuration(format!(
                    "{path}.recursive_resolvers entry `{resolver}` is not a valid ip[:port] address"
                )));
            }
        }
        if let QuorumSpec::AtLeast(n) = &self.recursive_quorum
            && !self.recursive_resolvers.is_empty()
            && *n > self.recursive_resolvers.len()
        {
            return Err(AcmeError::configuration(format!(
                "{path}.recursive_quorum must be less than or equal to recursive_resolvers length ({})",
                self.recursive_resolvers.len()
            )));
        }
        Ok(())
    }
}

/// Field-level provider override for `[dns.providers.<id>.propagation]`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PropagationOverrideSettings {
    /// Override authoritative quorum.
    #[serde(default)]
    pub authoritative_quorum: Option<QuorumSpec>,
    /// Override recursive resolver list. Empty list explicitly skips recursive confirmation.
    #[serde(default)]
    pub recursive_resolvers: Option<Vec<String>>,
    /// Override recursive quorum.
    #[serde(default)]
    pub recursive_quorum: Option<QuorumSpec>,
    /// Override overall wait budget, in seconds.
    #[serde(default, alias = "max_wait")]
    pub max_wait_secs: Option<u64>,
    /// Override poll interval, in seconds.
    #[serde(default, alias = "poll_interval", alias = "initial_interval_secs")]
    pub poll_interval_secs: Option<u64>,
    /// Override single DNS query timeout, in seconds.
    #[serde(default, alias = "query_timeout")]
    pub query_timeout_secs: Option<u64>,
}

/// Quorum requirement as written in configuration: `"all"` or a count.
///
/// Config-layer mirror of [`crate::domain::Quorum`]; deserialization
/// accepts the string `"all"` or a positive integer (>= 1) and rejects
/// anything else with an explicit error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumSpec {
    /// All observed servers must agree.
    All,
    /// At least `n` observed servers must agree (n >= 1).
    AtLeast(usize),
}

impl QuorumSpec {
    /// Converts the spec into the domain quorum type.
    pub fn to_quorum(&self) -> crate::domain::Quorum {
        match self {
            QuorumSpec::All => crate::domain::Quorum::All,
            QuorumSpec::AtLeast(n) => crate::domain::Quorum::AtLeast(*n),
        }
    }
}

impl Serialize for QuorumSpec {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            QuorumSpec::All => serializer.serialize_str("all"),
            QuorumSpec::AtLeast(n) => serializer.serialize_u64(*n as u64),
        }
    }
}

impl<'de> Deserialize<'de> for QuorumSpec {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct QuorumSpecVisitor;

        impl<'de> serde::de::Visitor<'de> for QuorumSpecVisitor {
            type Value = QuorumSpec;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(r#"quorum "all" or a positive integer (>= 1)"#)
            }

            fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value == "all" {
                    Ok(QuorumSpec::All)
                } else {
                    Err(E::custom(format!(
                        "invalid quorum value `{value}`: expected \"all\" or a positive integer (>= 1)"
                    )))
                }
            }

            fn visit_i64<E>(self, value: i64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value < 1 {
                    return Err(E::custom(format!(
                        "invalid quorum value `{value}`: quorum must be a positive integer (>= 1)"
                    )));
                }
                usize::try_from(value)
                    .map(QuorumSpec::AtLeast)
                    .map_err(|_| {
                        E::custom(format!(
                            "invalid quorum value `{value}`: quorum is too large"
                        ))
                    })
            }

            fn visit_u64<E>(self, value: u64) -> std::result::Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if value < 1 {
                    return Err(E::custom(format!(
                        "invalid quorum value `{value}`: quorum must be a positive integer (>= 1)"
                    )));
                }
                usize::try_from(value)
                    .map(QuorumSpec::AtLeast)
                    .map_err(|_| {
                        E::custom(format!(
                            "invalid quorum value `{value}`: quorum is too large"
                        ))
                    })
            }
        }

        deserializer.deserialize_any(QuorumSpecVisitor)
    }
}

/// Normalizes a configured resolver to a full socket address.
///
/// `ip:port` entries are kept as-is; bare IPs get the DNS default port 53
/// (IPv6 addresses are bracketed correctly).
fn normalize_resolver(resolver: &str) -> String {
    if let Ok(addr) = resolver.parse::<std::net::SocketAddr>() {
        return addr.to_string();
    }
    if let Ok(ip) = resolver.parse::<std::net::IpAddr>() {
        return std::net::SocketAddr::new(ip, 53).to_string();
    }
    resolver.to_string()
}

/// DNS provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub name: String,
    pub api_token: Option<SecretRef>,
    pub zone_id: Option<String>,
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// TLS-ALPN-01 challenge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAlpnConfig {
    #[serde(default = "default_tls_listen")]
    pub listen_addr: String,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
}

/// Renewal settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalSettings {
    /// Check interval in seconds.
    #[serde(default = "default_check_interval")]
    pub check_interval: u64,
    /// Days before expiry to trigger renewal.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,
    /// Maximum retry attempts.
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    /// Retry delay in seconds.
    #[serde(default = "default_retry_delay")]
    pub retry_delay_secs: u64,
    /// Concurrency level for renewals.
    #[serde(default = "default_concurrency")]
    pub concurrency: u32,
}

/// Metrics settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSettings {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen_addr: String,
    #[serde(default = "default_metrics_prefix")]
    pub prefix: String,
}

/// Notification settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationSettings {
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,
    #[serde(default)]
    pub email: Vec<EmailConfig>,
}

/// Webhook notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub name: Option<String>,
    pub url: String,
    /// Outbox event-type filter applied to the durable delivery (for example
    /// `"operation.created"` or `"deployment.activated"`). An empty list
    /// delivers every outbox event to this endpoint.
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_webhook_format")]
    pub format: String,
    pub auth_token: Option<SecretRef>,
    #[serde(default)]
    pub signing_secret: Option<SecretRef>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_webhook_replay_window")]
    pub replay_window_secs: u64,
}

/// Email notification configuration (`[[notifications.email]]`).
///
/// Consumed by `notifications::email::EmailNotifier`, which delivers outbox
/// events over SMTP. The plain `String` settings (`tls_mode`,
/// `body_format`) are validated at notifier assembly time; unknown or
/// unsafe values fail assembly instead of every delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// Optional instance name used in logs and error messages; derived
    /// from the endpoint address when omitted.
    #[serde(default)]
    pub name: Option<String>,
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    pub from: String,
    pub to: Vec<String>,
    /// Outbox event-type filter (for example `"operation.created"`); an
    /// empty list delivers every outbox event, matching the webhook
    /// `events` semantics.
    #[serde(default)]
    pub events: Vec<String>,
    /// SMTP `AUTH PLAIN` user; must be configured together with `password`.
    pub username: Option<String>,
    /// SMTP password SecretRef (`env:`/`file:`/`vault:`); resolved per
    /// delivery and never logged.
    pub password: Option<SecretRef>,
    /// Transport security: `starttls` (default), `implicit` (smtps/465) or
    /// `none` (explicit plaintext opt-in for local relays).
    #[serde(default = "default_smtp_tls_mode")]
    pub tls_mode: String,
    /// Prefix prepended to every message subject.
    #[serde(default = "default_smtp_subject_prefix")]
    pub subject_prefix: String,
    /// Name presented in the SMTP `EHLO` greeting.
    #[serde(default = "default_smtp_helo_name")]
    pub helo_name: String,
    /// Body MIME type: `text` (default) or `html`.
    #[serde(default = "default_smtp_body_format")]
    pub body_format: String,
    /// Overall timeout for one SMTP delivery (connect + conversation).
    #[serde(default = "default_smtp_timeout_secs")]
    pub timeout_secs: u64,
    /// PEM files with trust anchors for the TLS modes (required for them —
    /// the SMTP client verifies certificates against exactly these).
    #[serde(default)]
    pub ca_pem_files: Vec<String>,
}

/// Key management settings (`[key]`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KeySettings {
    /// Key provider backend: "software" (default) or "kms-aws" (requires
    /// the `kms-aws` feature).
    #[serde(default = "default_key_backend")]
    pub backend: String,
    /// AWS KMS settings (required when backend = "kms-aws").
    #[serde(default)]
    pub kms: Option<KmsKeySettings>,
}

/// AWS KMS provider settings.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KmsKeySettings {
    /// AWS region (e.g. `us-east-1`). Omit to use the ambient AWS
    /// configuration chain.
    #[serde(default)]
    pub region: Option<String>,
    /// KMS endpoint override (VPC endpoints, contract tests).
    #[serde(default)]
    pub endpoint_url: Option<String>,
    /// Pending-deletion window for destroyed keys, in days (7-30).
    #[serde(default)]
    pub key_deletion_window_days: Option<i32>,
}

fn default_key_backend() -> String {
    "software".to_string()
}

/// Durable outbox consumer settings (`[outbox]`).
///
/// The consumer drains `operation.*`/`deployment.*`/`audit.*` events from the
/// repository outbox to the webhook delivery; without it the outbox grows
/// without bound.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxSettings {
    /// Whether the runtime spawns the outbox consumer loop.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Seconds between consumer passes.
    #[serde(default = "default_outbox_interval_secs")]
    pub interval_secs: u64,
    /// Maximum events claimed per pass (maps to the consumer batch size).
    #[serde(default = "default_outbox_batch_size")]
    pub batch_size: usize,
}

impl Default for OutboxSettings {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            interval_secs: default_outbox_interval_secs(),
            batch_size: default_outbox_batch_size(),
        }
    }
}

/// Remote certificate delivery sink settings (`[delivery]`).
///
/// A sink section registers the corresponding [`crate::delivery::CertificateSink`]
/// implementation with the workflow worker; intents whose delivery targets
/// reference the kind then deploy to it. Absent sections simply leave the
/// sink unregistered (issuing still succeeds — activation waits on the
/// targets the intent actually declares).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeliverySettings {
    /// Kubernetes TLS Secret sink (`[delivery.kubernetes]`).
    #[serde(default)]
    pub kubernetes: Option<KubernetesSinkSettings>,
    /// HashiCorp Vault KV v2 sink (`[delivery.vault]`).
    #[serde(default)]
    pub vault: Option<VaultSinkSettings>,
}

/// Kubernetes Secret sink settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesSinkSettings {
    /// API server base URL. Omit to discover the in-cluster endpoint from
    /// `KUBERNETES_SERVICE_HOST`/`KUBERNETES_SERVICE_PORT`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Namespace that owns the target and staging Secrets.
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    /// PEM bundle used to verify the API server (defaults to the in-cluster
    /// `ca.crt` when the endpoint is discovered).
    #[serde(default)]
    pub ca_path: Option<String>,
    #[serde(default = "default_sink_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_sink_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Bearer token SecretRef (`env:`/`file:`/`vault:`). Omit when running
    /// in-cluster so the service account token is used.
    #[serde(default)]
    pub auth_token: Option<SecretRef>,
}

impl Default for KubernetesSinkSettings {
    fn default() -> Self {
        Self {
            endpoint: None,
            namespace: default_k8s_namespace(),
            ca_path: None,
            connect_timeout_secs: default_sink_connect_timeout_secs(),
            request_timeout_secs: default_sink_request_timeout_secs(),
            auth_token: None,
        }
    }
}

/// Vault KV v2 sink settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultSinkSettings {
    /// Vault base URL (e.g. `https://vault.internal:8200`).
    pub endpoint: String,
    /// KV v2 engine mount (e.g. `secret`).
    #[serde(default = "default_vault_mount")]
    pub mount: String,
    /// Enterprise namespace sent as `X-Vault-Namespace` (optional).
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default = "default_sink_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_sink_request_timeout_secs")]
    pub request_timeout_secs: u64,
    /// Vault token SecretRef (`env:`/`file:`/`vault:`).
    pub auth_token: SecretRef,
}

fn default_k8s_namespace() -> String {
    "default".to_string()
}

fn default_vault_mount() -> String {
    "secret".to_string()
}

fn default_sink_connect_timeout_secs() -> u64 {
    5
}

fn default_sink_request_timeout_secs() -> u64 {
    30
}

/// CLI settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliSettings {
    #[serde(default = "default_output_format")]
    pub output_format: String,
    #[serde(default = "default_true")]
    pub colors: bool,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    pub log_file: Option<String>,
    #[serde(default = "default_log_max_size")]
    pub log_max_size: u64,
    #[serde(default = "default_log_backup_count")]
    pub log_backup_count: u32,
}

/// Server settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    #[serde(default = "default_server_listen")]
    pub listen_addr: String,
    #[serde(default = "default_true")]
    pub enable_api: bool,
    #[serde(default = "default_true")]
    pub enable_webhook: bool,
}

// Default value functions
fn default_ca() -> String {
    "letsencrypt".to_string()
}
fn default_ca_env() -> String {
    "production".to_string()
}
fn default_true() -> bool {
    true
}
fn default_storage_backend() -> String {
    "file".to_string()
}
fn default_cert_path() -> String {
    ".acmex/certs".to_string()
}
fn default_pool_size() -> usize {
    10
}
fn default_key_format() -> String {
    "hex".to_string()
}
fn default_challenge_type() -> String {
    "dns-01".to_string()
}
fn default_http_listen() -> String {
    "0.0.0.0:80".to_string()
}
fn default_challenge_path() -> String {
    ".well-known/acme-challenge".to_string()
}
fn default_tls_listen() -> String {
    "0.0.0.0:443".to_string()
}
fn default_dns_timeout() -> u64 {
    300
}
fn default_authoritative_quorum() -> QuorumSpec {
    QuorumSpec::All
}
fn default_recursive_resolvers() -> Vec<String> {
    Vec::new()
}
fn default_recursive_quorum() -> QuorumSpec {
    QuorumSpec::AtLeast(1)
}
fn default_poll_interval_secs() -> u64 {
    5
}
fn default_query_timeout_secs() -> u64 {
    3
}
fn default_check_interval() -> u64 {
    3600
}
fn default_renew_before_days() -> u32 {
    30
}
fn default_max_retries() -> u32 {
    3
}
fn default_retry_delay() -> u64 {
    300
}
fn default_concurrency() -> u32 {
    5
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9090".to_string()
}
fn default_metrics_prefix() -> String {
    "acmex".to_string()
}
fn default_webhook_format() -> String {
    "json".to_string()
}
fn default_webhook_timeout() -> u64 {
    30
}

fn default_webhook_replay_window() -> u64 {
    300
}
fn default_outbox_interval_secs() -> u64 {
    5
}
/// Matches `OutboxConsumerConfig::default().batch_size`.
fn default_outbox_batch_size() -> usize {
    32
}
fn default_smtp_port() -> u16 {
    587
}
fn default_smtp_tls_mode() -> String {
    "starttls".to_string()
}
fn default_smtp_subject_prefix() -> String {
    "[AcmeX] ".to_string()
}
fn default_smtp_helo_name() -> String {
    "acmex.local".to_string()
}
fn default_smtp_body_format() -> String {
    "text".to_string()
}
fn default_smtp_timeout_secs() -> u64 {
    30
}
fn default_output_format() -> String {
    "text".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_max_size() -> u64 {
    100
}
fn default_log_backup_count() -> u32 {
    10
}
fn default_server_listen() -> String {
    "127.0.0.1:8080".to_string()
}

impl Default for AcmeSettings {
    fn default() -> Self {
        Self {
            ca: default_ca(),
            ca_environment: default_ca_env(),
            ca_custom_url: None,
            contact: Vec::new(),
            tos_agreed: true,
            external_account_binding: None,
            trust_anchor_pem_files: Vec::new(),
            skip_certificate_trust_check: false,
            directory: String::new(),
        }
    }
}

impl Default for StorageSettings {
    fn default() -> Self {
        Self {
            backend: default_storage_backend(),
            file: Some(FileStorageConfig {
                path: default_cert_path(),
            }),
            redis: None,
            encrypted: None,
        }
    }
}

impl Default for ChallengeSettings {
    fn default() -> Self {
        Self {
            challenge_type: default_challenge_type(),
            http01: None,
            dns01: None,
            tls_alpn: None,
        }
    }
}

impl Default for RenewalSettings {
    fn default() -> Self {
        Self {
            check_interval: default_check_interval(),
            renew_before_days: default_renew_before_days(),
            max_retries: default_max_retries(),
            retry_delay_secs: default_retry_delay(),
            concurrency: default_concurrency(),
        }
    }
}

impl Default for MetricsSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_metrics_listen(),
            prefix: default_metrics_prefix(),
        }
    }
}

impl Default for CliSettings {
    fn default() -> Self {
        Self {
            output_format: default_output_format(),
            colors: true,
            log_level: default_log_level(),
            log_file: None,
            log_max_size: default_log_max_size(),
            log_backup_count: default_log_backup_count(),
        }
    }
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            listen_addr: default_server_listen(),
            enable_api: true,
            enable_webhook: true,
        }
    }
}

impl Config {
    /// Creates a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Loads configuration from a TOML file.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            tracing::error!("Failed to read config file: {}", e);
            AcmeError::configuration(format!("Failed to read config file: {}", e))
        })?;
        content.parse()
    }
}

impl FromStr for Config {
    type Err = AcmeError;

    /// Loads configuration from a TOML string.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let mut config: Config = toml::from_str(s).map_err(|e| {
            tracing::error!("Failed to parse TOML configuration: {}", e);
            AcmeError::configuration(format!("Failed to parse TOML: {}", e))
        })?;

        // Resolve the ACME directory URL immediately after loading
        let ca_config = config.acme.to_ca_config()?;
        config.acme.directory = ca_config
            .directory_url()
            .map_err(AcmeError::configuration)?;

        Ok(config)
    }
}

impl Config {
    /// High-standard environment variable override implementation: supports all parameters and ensures core state synchronization.
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        tracing::debug!("Applying comprehensive environment variable overrides");

        // 1. Core CA configuration overrides
        if let Ok(ca) = env::var("ACMEX_ACME_CA") {
            self.acme.ca = ca;
        }
        if let Ok(env) = env::var("ACMEX_ACME_ENV") {
            self.acme.ca_environment = env;
        }
        if let Ok(url) = env::var("ACMEX_ACME_CUSTOM_URL") {
            self.acme.ca_custom_url = Some(url);
        }

        // 2. Storage backend overrides (solves the issue where Redis couldn't be initialized from scratch in the original code)
        if let Ok(backend) = env::var("ACMEX_STORAGE_BACKEND") {
            self.storage.backend = backend;
        }

        if let Ok(redis_url) = env::var("ACMEX_STORAGE_REDIS_URL") {
            // Initialize if it doesn't exist, ensuring environment variables can take effect independently
            if self.storage.redis.is_none() {
                self.storage.redis = Some(RedisStorageConfig {
                    url: redis_url,
                    connection_pool_size: 10,
                    db: 0,
                });
            } else if let Some(ref mut r) = self.storage.redis {
                r.url = redis_url;
            }
        }

        // 3. Business policy overrides
        if let Ok(ct) = env::var("ACMEX_CHALLENGE_TYPE") {
            self.challenge.challenge_type = ct;
        }

        if let Ok(interval) = env::var("ACMEX_RENEWAL_CHECK_INTERVAL")
            && let Ok(secs) = interval.parse::<u64>()
        {
            self.renewal.check_interval = secs;
        }

        if let Ok(days) = env::var("ACMEX_RENEWAL_BEFORE_DAYS")
            && let Ok(d) = days.parse::<u32>()
        {
            self.renewal.renew_before_days = d;
        }

        // 4. Critical: Re-trigger resolution of derived state
        // Regardless of what was modified, ensure the Directory URL aligns with the latest CA configuration
        let ca_config = self.acme.to_ca_config()?;
        self.acme.directory = ca_config.directory_url().map_err(|e| {
            AcmeError::configuration(format!(
                "Failed to re-resolve directory after overrides: {}",
                e
            ))
        })?;

        tracing::info!(
            "Configuration overrides applied. Active Directory: {}",
            self.acme.directory
        );
        Ok(())
    }

    /// Expands environment variables in the format `${VAR}` within a string.
    pub fn expand_env_var(value: &str) -> Result<String> {
        let re = regex::Regex::new(r"\$\{([^}]+)}")
            .map_err(|_| AcmeError::configuration("Invalid regex pattern"))?;

        let result = re
            .replace_all(value, |caps: &regex::Captures| {
                let var_name = &caps[1];
                env::var(var_name).unwrap_or_else(|_| format!("${{{}}}", var_name))
            })
            .to_string();

        Ok(result)
    }

    /// Validates the configuration settings.
    pub fn validate(&self) -> Result<()> {
        tracing::debug!("Validating configuration");

        if self.acme.directory.is_empty() {
            return Err(AcmeError::configuration(
                "ACME directory URL could not be resolved",
            ));
        }

        match self.storage.backend.as_str() {
            "file" => {
                if let Some(ref file_config) = self.storage.file
                    && file_config.path.is_empty()
                {
                    return Err(AcmeError::configuration(
                        "File storage path cannot be empty",
                    ));
                }
            }
            "redis" => {
                if let Some(ref redis_config) = self.storage.redis
                    && redis_config.url.is_empty()
                {
                    return Err(AcmeError::configuration("Redis URL cannot be empty"));
                }
            }
            _ => {}
        }

        if self.repository.backend == "redis"
            && let Some(ref redis) = self.repository.redis
            && redis.url.is_empty()
        {
            return Err(AcmeError::configuration(
                "repository.redis.url cannot be empty",
            ));
        }

        if let Some(ref vault) = self.delivery.vault {
            if vault.endpoint.is_empty() {
                return Err(AcmeError::configuration(
                    "delivery.vault.endpoint cannot be empty",
                ));
            }
            if vault.mount.is_empty() {
                return Err(AcmeError::configuration(
                    "delivery.vault.mount cannot be empty",
                ));
            }
        }
        if let Some(ref kubernetes) = self.delivery.kubernetes
            && kubernetes.namespace.is_empty()
        {
            return Err(AcmeError::configuration(
                "delivery.kubernetes.namespace cannot be empty",
            ));
        }

        if let Some(ref key) = self.key {
            if key.backend != "software" && key.backend != "kms-aws" {
                return Err(AcmeError::configuration(format!(
                    "key.backend `{}` is not one of software|kms-aws",
                    key.backend
                )));
            }
            if key.backend == "kms-aws" && key.kms.is_none() {
                return Err(AcmeError::configuration(
                    "key.kms settings are required when key.backend = \"kms-aws\"",
                ));
            }
        }

        if let Some(ref propagation) = self.dns.propagation {
            propagation.validate("dns.propagation")?;
        }
        if let Some(dns01) = self.challenge.dns01.as_ref()
            && let Some(ref propagation) = dns01.propagation
        {
            propagation.validate("challenge.dns01.propagation")?;
        }
        for provider_id in self.dns.providers.keys() {
            self.dns_propagation_settings_for(Some(provider_id))?
                .validate(&format!("dns.providers.{provider_id}.propagation"))?;
        }

        if self.outbox.interval_secs == 0 {
            return Err(AcmeError::configuration(
                "outbox.interval_secs must be at least 1 second",
            ));
        }
        if self.outbox.batch_size == 0 {
            return Err(AcmeError::configuration(
                "outbox.batch_size must be at least 1",
            ));
        }

        self.external_account_binding_ref()?;
        // Unknown account key types are configuration errors, caught at
        // validation time instead of first key generation.
        self.ca.resolve_account_key_type()?;

        Ok(())
    }

    /// Returns the configured EAB reference for account registration.
    ///
    /// `[ca.eab]` is the stable v0.10 location. `[acme.external_account_binding]`
    /// remains accepted as a deprecated compatibility alias, but setting both
    /// locations is rejected so one deployment cannot silently bind different
    /// account credentials in different code paths.
    pub fn external_account_binding_ref(
        &self,
    ) -> Result<Option<crate::ca_backend::ExternalAccountBindingRef>> {
        let stable = self.ca.eab.as_ref();
        let legacy = self.acme.external_account_binding.as_ref();
        let selected = match (stable, legacy) {
            (Some(_), Some(_)) => {
                return Err(AcmeError::configuration(
                    "configure EAB in either [ca.eab] or deprecated [acme.external_account_binding], not both",
                ));
            }
            (Some(eab), None) | (None, Some(eab)) => Some(eab),
            (None, None) => None,
        };
        if let Some(eab) = selected {
            if eab.key_id.trim().is_empty() {
                return Err(AcmeError::configuration("EAB key_id cannot be empty"));
            }
            return Ok(Some(eab.to_backend_ref()));
        }
        Ok(None)
    }

    /// Resolves the effective DNS propagation settings for a provider.
    ///
    /// `[dns.propagation]` is the stable v0.10.0 configuration surface.
    /// Legacy `[challenge.dns01.propagation]` remains a fallback for old
    /// configs when the new global section is absent. Provider-level
    /// overrides merge field-by-field on top of the chosen global settings.
    pub fn dns_propagation_settings_for(
        &self,
        provider_id: Option<&str>,
    ) -> Result<PropagationSettings> {
        let settings = self.dns.propagation.clone().or_else(|| {
            self.challenge
                .dns01
                .as_ref()
                .and_then(|dns01| dns01.propagation.clone())
        });
        let mut settings = settings.unwrap_or_else(|| {
            let mut settings = PropagationSettings::default();
            if let Some(dns01) = self.challenge.dns01.as_ref() {
                settings.max_wait_secs = dns01.propagation_timeout_secs;
            }
            settings
        });

        if let Some(provider_id) = provider_id
            && let Some(provider) = self.dns.providers.get(provider_id)
            && let Some(propagation) = provider.propagation.as_ref()
        {
            settings.apply_override(propagation);
        }
        Ok(settings)
    }

    /// Resolves the runtime DNS propagation policy for a provider.
    pub fn dns_propagation_policy_for(
        &self,
        provider_id: Option<&str>,
    ) -> Result<crate::dns::propagation::PropagationPolicyV2> {
        let settings = self.dns_propagation_settings_for(provider_id)?;
        settings.validate("dns.propagation")?;
        Ok(settings.to_policy())
    }

    /// Returns the resolved ACME directory URL.
    pub fn acme_directory(&self) -> &str {
        &self.acme.directory
    }

    /// Returns the storage backend type.
    pub fn storage_backend(&self) -> &str {
        &self.storage.backend
    }

    /// Returns the selected challenge type.
    pub fn challenge_type(&self) -> &str {
        &self.challenge.challenge_type
    }

    /// Returns the renewal check interval as a `Duration`.
    pub fn renewal_check_interval(&self) -> Duration {
        Duration::from_secs(self.renewal.check_interval)
    }

    /// Returns the number of days before expiry to trigger renewal.
    pub fn should_renew_days_before(&self) -> u32 {
        self.renewal.renew_before_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.acme.ca, "letsencrypt");
        assert_eq!(config.storage.backend, "file");
    }

    #[test]
    fn test_ca_resolution() {
        let toml = r#"
[acme]
ca = "letsencrypt"
ca_environment = "staging"
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config.acme_directory(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn secret_fields_deserialize_as_references() {
        let toml = r#"
[acme]
ca = "letsencrypt"
ca_environment = "staging"

[ca.eab]
key_id = "kid-1"
hmac_key = "env:EAB_HMAC"

[challenge.dns01]
provider = "cloudflare"
api_token = "file:/run/secrets/cf-token"

[[notifications.webhooks]]
url = "https://hooks.example.test/acmex"
auth_token = "env:WEBHOOK_TOKEN"
signing_secret = "vault:secret:acmex/webhooks:signing"
replay_window_secs = 300

[[notifications.email]]
smtp_host = "smtp.example.test"
from = "acmex@example.test"
to = ["ops@example.test"]
password = "env:SMTP_PASSWORD"
"#;
        let config = Config::from_str(toml).unwrap();
        assert!(matches!(
            config.ca.eab.unwrap().hmac_key,
            SecretRef::Env { .. }
        ));
        assert!(matches!(
            config.challenge.dns01.unwrap().api_token.unwrap(),
            SecretRef::File { .. }
        ));
        let notifications = config.notifications.unwrap();
        assert!(matches!(
            notifications.webhooks[0].auth_token,
            Some(SecretRef::Env { .. })
        ));
        assert!(matches!(
            notifications.webhooks[0].signing_secret,
            Some(SecretRef::Vault { .. })
        ));
        assert_eq!(notifications.webhooks[0].replay_window_secs, 300);
        assert!(matches!(
            notifications.email[0].password,
            Some(SecretRef::Env { .. })
        ));
    }

    #[test]
    fn deprecated_acme_eab_alias_still_parses() {
        let toml = r#"
[acme.external_account_binding]
key_id = "kid-legacy"
hmac_key = "file:/run/secrets/eab"
"#;
        let config = Config::from_str(toml).unwrap();
        let eab = config.external_account_binding_ref().unwrap().unwrap();
        assert_eq!(eab.key_id, "kid-legacy");
        assert!(matches!(eab.hmac_key, SecretRef::File { .. }));
    }

    #[test]
    fn eab_rejects_ambiguous_double_configuration() {
        let toml = r#"
[ca.eab]
key_id = "kid-stable"
hmac_key = "env:EAB_HMAC"

[acme.external_account_binding]
key_id = "kid-legacy"
hmac_key = "file:/run/secrets/eab"
"#;
        let err = Config::from_str(toml)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("[ca.eab]"), "got: {err}");
        assert!(
            err.contains("[acme.external_account_binding]"),
            "got: {err}"
        );
    }

    #[test]
    fn eab_rejects_empty_key_id() {
        let toml = r#"
[ca.eab]
key_id = " "
hmac_key = "env:EAB_HMAC"
"#;
        let err = Config::from_str(toml)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("EAB key_id cannot be empty"), "got: {err}");
    }

    #[test]
    fn dns_propagation_parses_string_and_int_quorum() {
        let toml = r#"
[dns.propagation]
authoritative_quorum = "all"
recursive_resolvers = ["9.9.9.9:53", "149.112.112.112:53"]
recursive_quorum = 2
max_wait_secs = 120
poll_interval_secs = 3
query_timeout_secs = 2
"#;
        let config = Config::from_str(toml).unwrap();
        config.validate().unwrap();
        let propagation = config
            .dns
            .propagation
            .expect("propagation section should parse");
        assert_eq!(propagation.authoritative_quorum, QuorumSpec::All);
        assert_eq!(
            propagation.recursive_resolvers,
            vec!["9.9.9.9:53".to_string(), "149.112.112.112:53".to_string()]
        );
        assert_eq!(propagation.recursive_quorum, QuorumSpec::AtLeast(2));
        assert_eq!(propagation.max_wait_secs, 120);
        assert_eq!(propagation.poll_interval_secs, 3);
        assert_eq!(propagation.query_timeout_secs, 2);
    }

    #[test]
    fn dns_propagation_absent_section_keeps_policy_defaults() {
        let config =
            Config::from_str("[challenge.dns01]\npropagation_timeout_secs = 300\n").unwrap();
        config.validate().unwrap();

        assert_eq!(
            config.dns_propagation_policy_for(None).unwrap(),
            crate::dns::propagation::PropagationPolicyV2::default()
        );
    }

    #[test]
    fn dns_propagation_rejects_invalid_quorum_values() {
        for (toml, expected_error) in [
            (
                r#"
[dns.propagation]
authoritative_quorum = "majority"
"#,
                "invalid quorum value `majority`",
            ),
            (
                r#"
[dns.propagation]
recursive_quorum = 0
"#,
                "invalid quorum value `0`",
            ),
            (
                r#"
[dns.propagation]
authoritative_quorum = -1
"#,
                "invalid quorum value `-1`",
            ),
        ] {
            let err = Config::from_str(toml).unwrap_err().to_string();
            assert!(
                err.contains(expected_error),
                "unexpected error for {toml}: {err}"
            );
            assert!(
                err.contains("positive integer"),
                "error must explain the accepted quorum syntax: {err}"
            );
        }
    }

    #[test]
    fn dns_propagation_validation_rejects_bad_intervals_resolvers_and_quorum() {
        let base = |propagation: &str| format!("[dns.propagation]\n{propagation}");

        let zero_poll = base("poll_interval_secs = 0");
        let err = Config::from_str(&zero_poll).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("poll_interval_secs must be at least 1 second")
        );

        let inverted = base("poll_interval_secs = 30\nmax_wait_secs = 10");
        let err = Config::from_str(&inverted).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("max_wait_secs must be greater than or equal to poll_interval_secs")
        );

        let bad_resolver = base("recursive_resolvers = [\"not-a-resolver\"]");
        let err = Config::from_str(&bad_resolver).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("`not-a-resolver` is not a valid ip[:port] address")
        );

        let impossible_quorum =
            base("recursive_resolvers = [\"1.1.1.1:53\"]\nrecursive_quorum = 2");
        let err = Config::from_str(&impossible_quorum).unwrap().validate();
        assert!(
            err.unwrap_err().to_string().contains(
                "recursive_quorum must be less than or equal to recursive_resolvers length"
            )
        );

        let empty_resolvers = base("recursive_resolvers = []\nrecursive_quorum = 2");
        Config::from_str(&empty_resolvers)
            .unwrap()
            .validate()
            .unwrap();

        let valid = base("recursive_resolvers = [\"1.1.1.1\", \"8.8.8.8:53\"]");
        Config::from_str(&valid).unwrap().validate().unwrap();
    }

    #[test]
    fn dns_propagation_maps_settings_onto_policy() {
        let toml = r#"
[dns.propagation]
authoritative_quorum = 2
recursive_resolvers = ["1.1.1.1", "8.8.8.8:53"]
recursive_quorum = "all"
max_wait_secs = 90
poll_interval_secs = 7
query_timeout_secs = 4
"#;
        let config = Config::from_str(toml).unwrap();
        let policy = config.dns_propagation_policy_for(None).unwrap();

        assert_eq!(
            policy,
            crate::dns::propagation::PropagationPolicyV2::from_config(
                crate::domain::Quorum::AtLeast(2),
                vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()],
                crate::domain::Quorum::All,
                Duration::from_secs(90),
                Duration::from_secs(7),
                Duration::from_secs(4),
            )
        );
    }

    #[test]
    fn dns_provider_propagation_override_merges_field_by_field() {
        let toml = r#"
[dns.propagation]
authoritative_quorum = "all"
recursive_resolvers = ["1.1.1.1:53", "8.8.8.8:53"]
recursive_quorum = 1
max_wait_secs = 120
poll_interval_secs = 5
query_timeout_secs = 3

[dns.providers.internal.propagation]
recursive_resolvers = []
poll_interval_secs = 2
"#;
        let config = Config::from_str(toml).unwrap();
        config.validate().unwrap();

        let global = config.dns_propagation_policy_for(None).unwrap();
        let internal = config.dns_propagation_policy_for(Some("internal")).unwrap();

        assert_eq!(global.recursive_resolvers.len(), 2);
        assert!(internal.recursive_resolvers.is_empty());
        assert_eq!(internal.authoritative_quorum, crate::domain::Quorum::All);
        assert_eq!(internal.recursive_quorum, crate::domain::Quorum::AtLeast(1));
        assert_eq!(internal.max_wait, Duration::from_secs(120));
        assert_eq!(internal.poll_interval, Duration::from_secs(2));
        assert_eq!(internal.query_timeout, Duration::from_secs(3));
    }

    #[test]
    fn legacy_challenge_dns01_propagation_is_fallback_only() {
        let toml = r#"
[challenge.dns01]
propagation_timeout_secs = 45

[challenge.dns01.propagation]
recursive_resolvers = ["9.9.9.9:53"]
poll_interval_secs = 6

[dns.propagation]
recursive_resolvers = []
poll_interval_secs = 3
"#;
        let config = Config::from_str(toml).unwrap();
        config.validate().unwrap();
        let policy = config.dns_propagation_policy_for(None).unwrap();

        assert!(policy.recursive_resolvers.is_empty());
        assert_eq!(policy.poll_interval, Duration::from_secs(3));
        assert_eq!(policy.max_wait, Duration::from_secs(300));
    }

    #[test]
    fn outbox_settings_default_to_enabled_consuming() {
        let settings = OutboxSettings::default();
        assert!(settings.enabled);
        assert_eq!(settings.interval_secs, 5);
        assert_eq!(settings.batch_size, 32);
    }

    /// Config files written before the `[outbox]` section existed must keep
    /// parsing unchanged and pick up the consuming defaults.
    #[test]
    fn config_without_outbox_section_keeps_defaults() {
        let config = Config::from_str(
            "[acme]\nca = \"letsencrypt\"\nca_environment = \"staging\"\n\n[[notifications.webhooks]]\nurl = \"https://hooks.example.test/acmex\"\n",
        )
        .unwrap();
        assert!(config.outbox.enabled);
        assert_eq!(config.outbox.interval_secs, 5);
        assert_eq!(config.outbox.batch_size, 32);
    }

    #[test]
    fn outbox_section_overrides_defaults() {
        let toml = "\n[outbox]\nenabled = false\ninterval_secs = 15\nbatch_size = 8\n";
        let config = Config::from_str(toml).unwrap();
        assert!(!config.outbox.enabled);
        assert_eq!(config.outbox.interval_secs, 15);
        assert_eq!(config.outbox.batch_size, 8);
    }

    #[test]
    fn outbox_validation_rejects_zero_interval_and_batch() {
        let err = Config::from_str("[outbox]\ninterval_secs = 0\n")
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("outbox.interval_secs must be at least 1 second"),
            "got: {err}"
        );

        let err = Config::from_str("[outbox]\nbatch_size = 0\n")
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("outbox.batch_size must be at least 1"),
            "got: {err}"
        );
    }

    /// The redis repository backend parses from config and keeps the older
    /// sections untouched; an empty URL is rejected by validation.
    #[test]
    fn repository_redis_backend_parses_and_validates() {
        let config = Config::from_str(
            "[repository]\nbackend = \"redis\"\n\n[repository.redis]\nurl = \"redis://127.0.0.1:6379/0\"\n",
        )
        .unwrap();
        assert_eq!(config.repository.backend, "redis");
        assert_eq!(
            config.repository.redis.as_ref().unwrap().url,
            "redis://127.0.0.1:6379/0"
        );
        // Legacy sections keep their defaults.
        assert!(config.outbox.enabled);

        let err = Config::from_str(
            "[repository]\nbackend = \"redis\"\n\n[repository.redis]\nurl = \"\"\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("repository.redis.url cannot be empty"),
            "got: {err}"
        );
    }

    #[test]
    fn challenge_tls_alpn_section_is_optional_for_old_configs() {
        let config = Config::from_str("[acme]\nca = \"letsencrypt\"\n").unwrap();
        assert!(config.challenge.tls_alpn.is_none());
    }

    /// `[delivery]` sink settings parse with defaults and reject empty
    /// required fields at validation time.
    #[test]
    fn delivery_sink_settings_parse_and_validate() {
        let config = Config::from_str(
            "[delivery.kubernetes]\nnamespace = \"certs\"\n\n[delivery.vault]\nendpoint = \"https://vault.internal:8200\"\nauth_token = \"env:VAULT_TOKEN\"\n",
        )
        .unwrap();
        let kubernetes = config.delivery.kubernetes.as_ref().unwrap();
        assert_eq!(kubernetes.namespace, "certs");
        assert!(kubernetes.endpoint.is_none());
        assert!(kubernetes.auth_token.is_none());
        let vault = config.delivery.vault.as_ref().unwrap();
        assert_eq!(vault.mount, "secret");
        assert_eq!(vault.connect_timeout_secs, 5);

        let err = Config::from_str(
            "[delivery.vault]\nendpoint = \"\"\nauth_token = \"env:VAULT_TOKEN\"\n",
        )
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("delivery.vault.endpoint cannot be empty"),
            "got: {err}"
        );
    }

    /// `[key]` parses with the software default; the kms-aws backend
    /// requires its kms settings section at validation time.
    #[test]
    fn key_backend_settings_parse_and_validate() {
        let config: Config = "[key]\nbackend = \"kms-aws\"\n\n[key.kms]\nregion = \"us-east-1\"\nendpoint_url = \"http://127.0.0.1:8200\"\n".parse().unwrap();
        let key = config.key.as_ref().unwrap();
        assert_eq!(key.backend, "kms-aws");
        assert_eq!(
            key.kms.as_ref().unwrap().region.as_deref(),
            Some("us-east-1")
        );
        // Omitting the section entirely keeps the software default.
        let config: Config = "[outbox]\nenabled = false\n".parse().unwrap();
        assert!(config.key.is_none());

        let err = Config::from_str("[key]\nbackend = \"kms-aws\"\n")
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("key.kms settings are required"), "got: {err}");
    }

    /// The default account key type stays Ed25519 — the compatibility
    /// baseline for the ECDSA/RSA account key feature.
    #[test]
    fn account_key_type_defaults_to_ed25519() {
        let config = Config::from_str("[acme]\nca = \"letsencrypt\"\n").unwrap();
        assert_eq!(config.ca.account_key_type, "ed25519");
        assert_eq!(
            config.ca.resolve_account_key_type().unwrap(),
            crate::crypto::keypair::KeyType::Ed25519
        );
        // Serializing and re-parsing keeps the default explicit.
        let serialized = toml::to_string(&config.ca).unwrap();
        assert!(
            serialized.contains("account_key_type = \"ed25519\""),
            "got: {serialized}"
        );
    }

    #[test]
    fn account_key_type_parses_every_documented_value() {
        use crate::crypto::keypair::KeyType;
        let cases = [
            ("ecdsa_p256", KeyType::EcdsaP256),
            ("ecdsa_p384", KeyType::EcdsaP384),
            ("ecdsa_p521", KeyType::EcdsaP521),
            ("rsa2048", KeyType::Rsa2048),
            ("rsa4096", KeyType::Rsa4096),
        ];
        for (value, expected) in cases {
            let toml = format!("[ca]\naccount_key_type = \"{value}\"\n");
            let config = Config::from_str(&toml).unwrap();
            config.validate().unwrap();
            assert_eq!(config.ca.resolve_account_key_type().unwrap(), expected);
        }
    }

    #[test]
    fn account_key_type_rejects_unknown_values_at_validation() {
        let err = Config::from_str("[ca]\naccount_key_type = \"p256\"\n")
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ca.account_key_type"),
            "error must name the setting: {err}"
        );
        assert!(
            err.contains("ed25519"),
            "error must list the accepted values: {err}"
        );
    }
}
