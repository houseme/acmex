/// Configuration management for AcmeX.
/// This module provides comprehensive configuration support, including TOML parsing,
/// environment variable overrides, and validation for multi-CA setups.
use crate::error::{AcmeError, Result};
use crate::ca::{CAConfig, CertificateAuthority, Environment};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::time::Duration;

/// Main configuration structure for the AcmeX application.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Config {
    /// ACME protocol and CA settings.
    #[serde(default)]
    pub acme: AcmeSettings,

    /// Storage backend settings.
    #[serde(default)]
    pub storage: StorageSettings,

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

/// ACME protocol and Certificate Authority settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSettings {
    /// The selected Certificate Authority: "letsencrypt", "google", "zerossl", or "custom".
    #[serde(default = "default_ca")]
    pub ca: String,

    /// The CA environment: "production" or "staging".
    #[serde(default = "default_ca_env")]
    pub ca_environment: String,

    /// Custom CA directory URL (required if ca = "custom").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_custom_url: Option<String>,

    /// Contact information (e.g., ["mailto:admin@example.com"]).
    #[serde(default)]
    pub contact: Vec<String>,

    /// Whether the Terms of Service have been agreed to.
    #[serde(default = "default_true")]
    pub tos_agreed: bool,

    /// Optional External Account Binding (EAB) for CAs like Google or ZeroSSL.
    #[serde(default)]
    pub external_account_binding: Option<ExternalAccountBinding>,

    /// Internal cache for the resolved directory URL.
    #[serde(skip)]
    pub directory: String,
}

impl AcmeSettings {
    /// Converts the settings into a `CAConfig` for endpoint resolution.
    pub fn to_ca_config(&self) -> Result<CAConfig> {
        let ca_type = match self.ca.to_lowercase().as_str() {
            "letsencrypt" => CertificateAuthority::LetsEncrypt,
            "google" => {
                #[cfg(not(feature = "google-ca"))]
                return Err(AcmeError::configuration("Feature 'google-ca' is not enabled"));
                #[cfg(feature = "google-ca")]
                CertificateAuthority::Google
            },
            "zerossl" => {
                #[cfg(not(feature = "zerossl-ca"))]
                return Err(AcmeError::configuration("Feature 'zerossl-ca' is not enabled"));
                #[cfg(feature = "zerossl-ca")]
                CertificateAuthority::ZeroSSL
            },
            "custom" => CertificateAuthority::Custom,
            _ => return Err(AcmeError::configuration(format!("Unsupported CA type: {}", self.ca))),
        };

        let env = match self.ca_environment.to_lowercase().as_str() {
            "production" | "prod" => Environment::Production,
            "staging" | "test" | "dev" => Environment::Staging,
            _ => return Err(AcmeError::configuration(format!("Invalid environment: {}", self.ca_environment))),
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
    pub hmac_key: String,
}

/// Storage backend settings.
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
    pub encryption_key: String,
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
    /// HTTP-01 configuration.
    #[serde(default)]
    pub http01: Option<Http01Config>,
    /// DNS-01 configuration.
    #[serde(default)]
    pub dns01: Option<Dns01Config>,
    /// TLS-ALPN-01 configuration.
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
    pub api_token: Option<String>,
    /// Zone ID or domain.
    pub zone_id: Option<String>,
    /// Multiple provider configurations.
    #[serde(default)]
    pub providers: Vec<DnsProviderConfig>,
    /// DNS propagation timeout in seconds.
    #[serde(default = "default_dns_timeout")]
    pub propagation_timeout_secs: u64,
}

/// DNS provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub name: String,
    pub api_token: Option<String>,
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
    pub auth_token: Option<String>,
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
    pub password: Option<String>,
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
fn default_ca() -> String { "letsencrypt".to_string() }
fn default_ca_env() -> String { "production".to_string() }
fn default_true() -> bool { true }
fn default_storage_backend() -> String { "file".to_string() }
fn default_cert_path() -> String { ".acmex/certs".to_string() }
fn default_pool_size() -> usize { 10 }
fn default_key_format() -> String { "hex".to_string() }
fn default_challenge_type() -> String { "dns-01".to_string() }
fn default_http_listen() -> String { "0.0.0.0:80".to_string() }
fn default_challenge_path() -> String { ".well-known/acme-challenge".to_string() }
fn default_tls_listen() -> String { "0.0.0.0:443".to_string() }
fn default_dns_timeout() -> u64 { 300 }
fn default_check_interval() -> u64 { 3600 }
fn default_renew_before_days() -> u32 { 30 }
fn default_max_retries() -> u32 { 3 }
fn default_retry_delay() -> u64 { 300 }
fn default_concurrency() -> u32 { 5 }
fn default_metrics_listen() -> String { "127.0.0.1:9090".to_string() }
fn default_metrics_prefix() -> String { "acmex".to_string() }
fn default_webhook_format() -> String { "json".to_string() }
fn default_webhook_timeout() -> u64 { 30 }
fn default_smtp_port() -> u16 { 587 }
fn default_output_format() -> String { "text".to_string() }
fn default_log_level() -> String { "info".to_string() }
fn default_log_max_size() -> u64 { 100 }
fn default_log_backup_count() -> u32 { 10 }
fn default_server_listen() -> String { "127.0.0.1:8080".to_string() }

impl Default for AcmeSettings {
    fn default() -> Self {
        Self {
            ca: default_ca(),
            ca_environment: default_ca_env(),
            ca_custom_url: None,
            contact: Vec::new(),
            tos_agreed: true,
            external_account_binding: None,
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
        let content = std::fs::read_to_string(path)
            .map_err(|e| {
                tracing::error!("Failed to read config file: {}", e);
                AcmeError::configuration(format!("Failed to read config file: {}", e))
            })?;
        Self::from_str(&content)
    }

    /// Loads configuration from a TOML string.
    pub fn from_str(content: &str) -> Result<Self> {
        let mut config: Config = toml::from_str(content)
            .map_err(|e| {
                tracing::error!("Failed to parse TOML configuration: {}", e);
                AcmeError::configuration(format!("Failed to parse TOML: {}", e))
            })?;

        // Resolve the ACME directory URL immediately after loading
        let ca_config = config.acme.to_ca_config()?;
        config.acme.directory = ca_config.directory_url()
            .map_err(|e| AcmeError::configuration(e))?;

        Ok(config)
    }

    /// Applies environment variable overrides to the configuration.
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        tracing::debug!("Applying environment variable overrides");

        if let Ok(ca) = env::var("ACMEX_ACME_CA") {
            self.acme.ca = ca;
        }

        if let Ok(env) = env::var("ACMEX_ACME_ENV") {
            self.acme.ca_environment = env;
        }

        if let Ok(backend) = env::var("ACMEX_STORAGE_BACKEND") {
            self.storage.backend = backend;
        }

        if let Ok(path) = env::var("ACMEX_STORAGE_FILE_PATH") {
            if let Some(ref mut file_config) = self.storage.file {
                file_config.path = Self::expand_env_var(&path)?;
            }
        }

        // Re-resolve directory after overrides
        let ca_config = self.acme.to_ca_config()?;
        self.acme.directory = ca_config.directory_url()
            .map_err(|e| AcmeError::configuration(e))?;

        Ok(())
    }

    /// Expands environment variables in the format `${VAR}` within a string.
    pub fn expand_env_var(value: &str) -> Result<String> {
        let re = regex::Regex::new(r"\$\{([^}]+)\}")
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
            return Err(AcmeError::configuration("ACME directory URL could not be resolved"));
        }

        match self.storage.backend.as_str() {
            "file" => {
                if let Some(ref file_config) = self.storage.file {
                    if file_config.path.is_empty() {
                        return Err(AcmeError::configuration("File storage path cannot be empty"));
                    }
                }
            }
            "redis" => {
                if let Some(ref redis_config) = self.storage.redis {
                    if redis_config.url.is_empty() {
                        return Err(AcmeError::configuration("Redis URL cannot be empty"));
                    }
                }
            }
            _ => {}
        }

        Ok(())
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
        assert_eq!(config.acme_directory(), "https://acme-staging-v02.api.letsencrypt.org/directory");
    }
}
