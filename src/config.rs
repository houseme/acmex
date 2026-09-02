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

    /// Certificate renewal settings.
    #[serde(default)]
    pub renewal: RenewalSettings,

    /// Metrics and observability settings.
    #[serde(default)]
    pub metrics: Option<MetricsSettings>,

    /// Notification settings (Webhooks, Email).
    #[serde(default)]
    pub notifications: Option<NotificationSettings>,

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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CaSettings {
    /// Optional External Account Binding configuration (`[ca.eab]`).
    #[serde(default)]
    pub eab: Option<ExternalAccountBinding>,
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
    /// Repository backend: "memory" or "file".
    #[serde(default = "default_repository_backend")]
    pub backend: String,

    /// File backend configuration (required when backend = "file").
    #[serde(default)]
    pub file: Option<FileRepositoryConfig>,

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
    /// DNS propagation observation policy (absent = built-in defaults).
    #[serde(default)]
    pub propagation: Option<PropagationSettings>,
}

/// DNS-01 propagation observation settings
/// (`[challenge.dns01.propagation]`).
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
    /// First re-check interval while waiting for propagation, in seconds.
    #[serde(default = "default_initial_interval_secs")]
    pub initial_interval_secs: u64,
    /// Upper bound of the exponential back-off between re-checks, in seconds.
    #[serde(default = "default_max_interval_secs")]
    pub max_interval_secs: u64,
}

impl Default for PropagationSettings {
    fn default() -> Self {
        Self {
            authoritative_quorum: default_authoritative_quorum(),
            recursive_resolvers: default_recursive_resolvers(),
            recursive_quorum: default_recursive_quorum(),
            initial_interval_secs: default_initial_interval_secs(),
            max_interval_secs: default_max_interval_secs(),
        }
    }
}

impl PropagationSettings {
    /// Maps the settings onto the propagation policy used by the observer.
    ///
    /// Bare resolver IPs are normalized to `ip:53` so downstream consumers
    /// always see a full socket address.
    pub fn to_policy(&self) -> crate::dns::propagation::PropagationPolicyV2 {
        crate::dns::propagation::PropagationPolicyV2::from_parts(
            self.authoritative_quorum.to_quorum(),
            self.recursive_resolvers
                .iter()
                .map(|resolver| normalize_resolver(resolver))
                .collect(),
            self.recursive_quorum.to_quorum(),
        )
    }

    /// Validates interval bounds and resolver addresses.
    fn validate(&self) -> Result<()> {
        if self.initial_interval_secs == 0 {
            return Err(AcmeError::configuration(
                "challenge.dns01.propagation.initial_interval_secs must be at least 1 second",
            ));
        }
        if self.max_interval_secs < self.initial_interval_secs {
            return Err(AcmeError::configuration(
                "challenge.dns01.propagation.max_interval_secs must be greater than or equal to initial_interval_secs",
            ));
        }
        if self.recursive_resolvers.is_empty() {
            return Err(AcmeError::configuration(
                "challenge.dns01.propagation.recursive_resolvers must list at least one resolver",
            ));
        }
        for resolver in &self.recursive_resolvers {
            let valid = resolver.parse::<std::net::SocketAddr>().is_ok()
                || resolver.parse::<std::net::IpAddr>().is_ok();
            if !valid {
                return Err(AcmeError::configuration(format!(
                    "challenge.dns01.propagation.recursive_resolvers entry `{resolver}` is not a valid ip[:port] address"
                )));
            }
        }
        Ok(())
    }
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
    /// Renewal hooks.
    #[serde(default)]
    pub hooks: Option<RenewalHooks>,
}

/// Renewal hooks configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalHooks {
    pub before: Option<String>,
    pub after: Option<String>,
    pub on_error: Option<String>,
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
    #[serde(default)]
    pub events: Vec<String>,
    #[serde(default = "default_webhook_format")]
    pub format: String,
    pub auth_token: Option<SecretRef>,
    #[serde(default)]
    pub signing_secret: Option<SecretRef>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,
}

/// Email notification configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub events: Vec<String>,
    pub username: Option<String>,
    pub password: Option<SecretRef>,
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
    vec!["1.1.1.1:53".to_string(), "8.8.8.8:53".to_string()]
}
fn default_recursive_quorum() -> QuorumSpec {
    QuorumSpec::AtLeast(1)
}
fn default_initial_interval_secs() -> u64 {
    5
}
fn default_max_interval_secs() -> u64 {
    60
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
fn default_smtp_port() -> u16 {
    587
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
            hooks: None,
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

        if let Some(dns01) = self.challenge.dns01.as_ref()
            && let Some(ref propagation) = dns01.propagation
        {
            propagation.validate()?;
        }

        self.external_account_binding_ref()?;

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
    fn dns01_propagation_parses_string_and_int_quorum() {
        let toml = r#"
[challenge.dns01]
propagation_timeout_secs = 120

[challenge.dns01.propagation]
authoritative_quorum = "all"
recursive_resolvers = ["9.9.9.9:53", "149.112.112.112:53"]
recursive_quorum = 2
initial_interval_secs = 3
max_interval_secs = 45
"#;
        let config = Config::from_str(toml).unwrap();
        config.validate().unwrap();
        let propagation = config
            .challenge
            .dns01
            .unwrap()
            .propagation
            .expect("propagation section should parse");
        assert_eq!(propagation.authoritative_quorum, QuorumSpec::All);
        assert_eq!(
            propagation.recursive_resolvers,
            vec!["9.9.9.9:53".to_string(), "149.112.112.112:53".to_string()]
        );
        assert_eq!(propagation.recursive_quorum, QuorumSpec::AtLeast(2));
        assert_eq!(propagation.initial_interval_secs, 3);
        assert_eq!(propagation.max_interval_secs, 45);
    }

    #[test]
    fn dns01_propagation_absent_section_keeps_policy_defaults() {
        let config =
            Config::from_str("[challenge.dns01]\npropagation_timeout_secs = 300\n").unwrap();
        let dns01 = config.challenge.dns01.as_ref().unwrap();
        assert!(dns01.propagation.is_none());
        config.validate().unwrap();

        // Default settings must map onto the built-in policy defaults so
        // "section present with defaults" and "section absent" agree.
        assert_eq!(
            PropagationSettings::default().to_policy(),
            crate::dns::propagation::PropagationPolicyV2::default()
        );
    }

    #[test]
    fn dns01_propagation_rejects_invalid_quorum_values() {
        for (toml, expected_error) in [
            (
                r#"
[challenge.dns01.propagation]
authoritative_quorum = "majority"
"#,
                "invalid quorum value `majority`",
            ),
            (
                r#"
[challenge.dns01.propagation]
recursive_quorum = 0
"#,
                "invalid quorum value `0`",
            ),
            (
                r#"
[challenge.dns01.propagation]
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
    fn dns01_propagation_validation_rejects_bad_intervals_and_resolvers() {
        let base = |propagation: &str| format!("[challenge.dns01.propagation]\n{propagation}");

        let zero_initial = base("initial_interval_secs = 0\nmax_interval_secs = 60");
        let err = Config::from_str(&zero_initial).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("initial_interval_secs must be at least 1 second")
        );

        let inverted = base("initial_interval_secs = 30\nmax_interval_secs = 10");
        let err = Config::from_str(&inverted).unwrap().validate();
        assert!(
            err.unwrap_err().to_string().contains(
                "max_interval_secs must be greater than or equal to initial_interval_secs"
            )
        );

        let bad_resolver = base("recursive_resolvers = [\"not-a-resolver\"]");
        let err = Config::from_str(&bad_resolver).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("`not-a-resolver` is not a valid ip[:port] address")
        );

        let empty_resolvers = base("recursive_resolvers = []");
        let err = Config::from_str(&empty_resolvers).unwrap().validate();
        assert!(
            err.unwrap_err()
                .to_string()
                .contains("recursive_resolvers must list at least one resolver")
        );

        // Bare IPs (port defaults to 53) and full socket addresses pass.
        let valid = base("recursive_resolvers = [\"1.1.1.1\", \"8.8.8.8:53\"]");
        Config::from_str(&valid).unwrap().validate().unwrap();
    }

    #[test]
    fn dns01_propagation_maps_settings_onto_policy() {
        let toml = r#"
[challenge.dns01.propagation]
authoritative_quorum = 2
recursive_resolvers = ["1.1.1.1", "8.8.8.8:53"]
recursive_quorum = "all"
"#;
        let config = Config::from_str(toml).unwrap();
        let policy = config
            .challenge
            .dns01
            .unwrap()
            .propagation
            .unwrap()
            .to_policy();

        assert_eq!(
            policy,
            crate::dns::propagation::PropagationPolicyV2::from_parts(
                crate::domain::Quorum::AtLeast(2),
                vec![
                    "1.1.1.1:53".to_string(), // bare IP normalized with :53
                    "8.8.8.8:53".to_string()
                ],
                crate::domain::Quorum::All,
            )
        );
    }
}
