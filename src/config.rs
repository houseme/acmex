//! Configuration management for AcmeX
//!
//! This module provides comprehensive configuration support for AcmeX, including:
//! - TOML configuration file parsing
//! - Environment variable overrides
//! - Configuration validation
//! - Default settings

use crate::error::{AcmeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::time::Duration;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub acme: AcmeSettings,

    #[serde(default)]
    pub storage: StorageSettings,

    #[serde(default)]
    pub challenge: ChallengeSettings,

    #[serde(default)]
    pub renewal: RenewalSettings,

    #[serde(default)]
    pub metrics: Option<MetricsSettings>,

    #[serde(default)]
    pub notifications: Option<NotificationSettings>,

    #[serde(default)]
    pub cli: Option<CliSettings>,

    #[serde(default)]
    pub server: Option<ServerSettings>,
}

/// ACME protocol settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSettings {
    /// ACME directory URL
    #[serde(default = "default_acme_url")]
    pub directory: String,

    /// Certificate Authority: "letsencrypt" (default), "google", "zerossl", or "custom"
    #[serde(default = "default_ca")]
    pub ca: String,

    /// CA environment: "production" or "staging"
    #[serde(default = "default_ca_env")]
    pub ca_environment: String,

    /// Custom CA URL (only used if ca = "custom")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_custom_url: Option<String>,

    /// Contact information
    #[serde(default)]
    pub contact: Vec<String>,

    /// Agree to TOS
    #[serde(default = "default_true")]
    pub tos_agreed: bool,

    /// External account binding (optional)
    #[serde(default)]
    pub external_account_binding: Option<ExternalAccountBinding>,
}

/// External account binding configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalAccountBinding {
    pub key_id: String,
    pub hmac_key: String,
}

/// Storage backend settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageSettings {
    /// Storage backend type: "file", "redis", "encrypted"
    #[serde(default = "default_storage_backend")]
    pub backend: String,

    /// File storage configuration
    #[serde(default)]
    pub file: Option<FileStorageConfig>,

    /// Redis storage configuration
    #[serde(default)]
    pub redis: Option<RedisStorageConfig>,

    /// Encrypted storage configuration
    #[serde(default)]
    pub encrypted: Option<EncryptedStorageConfig>,
}

/// File storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileStorageConfig {
    /// Directory path for certificates
    #[serde(default = "default_cert_path")]
    pub path: String,
}

/// Redis storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedisStorageConfig {
    /// Redis connection URL
    pub url: String,

    /// Connection pool size
    #[serde(default = "default_pool_size")]
    pub connection_pool_size: usize,

    /// Database number
    #[serde(default)]
    pub db: u32,
}

/// Encrypted storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedStorageConfig {
    /// Inner backend type
    pub inner_backend: String,

    /// Encryption key (supports ${VAR} syntax)
    pub encryption_key: String,

    /// Key format: "hex" or "base64"
    #[serde(default = "default_key_format")]
    pub key_format: String,
}

/// Challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeSettings {
    /// Default challenge type: "http-01", "dns-01", "tls-alpn-01"
    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,

    /// HTTP-01 configuration
    #[serde(default)]
    pub http01: Option<Http01Config>,

    /// DNS-01 configuration
    #[serde(default)]
    pub dns01: Option<Dns01Config>,

    /// TLS-ALPN-01 configuration
    #[serde(default)]
    pub tls_alpn: Option<TlsAlpnConfig>,
}

/// HTTP-01 challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http01Config {
    /// Listen address
    #[serde(default = "default_http_listen")]
    pub listen_addr: String,

    /// Domain for validation
    pub domain: Option<String>,

    /// Challenge token path
    #[serde(default = "default_challenge_path")]
    pub challenge_path: String,
}

/// DNS-01 challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dns01Config {
    /// Primary DNS provider
    pub provider: Option<String>,

    /// API token/key (supports ${VAR} syntax)
    pub api_token: Option<String>,

    /// Zone ID or domain (supports ${VAR} syntax)
    pub zone_id: Option<String>,

    /// Multiple provider configurations
    #[serde(default)]
    pub providers: Vec<DnsProviderConfig>,

    /// DNS propagation timeout
    #[serde(default = "default_dns_timeout")]
    pub propagation_timeout_secs: u64,
}

/// DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    /// Provider name
    pub name: String,

    /// API token/key
    pub api_token: Option<String>,

    /// Zone ID or domain
    pub zone_id: Option<String>,

    /// Additional configuration
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

/// TLS-ALPN-01 challenge configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAlpnConfig {
    /// Listen address
    #[serde(default = "default_tls_listen")]
    pub listen_addr: String,

    /// Certificate path
    pub cert_path: Option<String>,

    /// Key path
    pub key_path: Option<String>,
}

/// Renewal settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalSettings {
    /// Check interval in seconds
    #[serde(default = "default_check_interval")]
    pub check_interval: u64,

    /// Days before expiry to renew
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,

    /// Maximum retry attempts
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,

    /// Retry delay in seconds
    #[serde(default = "default_retry_delay")]
    pub retry_delay_secs: u64,

    /// Renewal hooks
    #[serde(default)]
    pub hooks: Option<RenewalHooks>,
}

/// Renewal hooks configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenewalHooks {
    /// Before renewal hook
    pub before: Option<String>,

    /// After renewal hook
    pub after: Option<String>,

    /// On error hook
    pub on_error: Option<String>,
}

/// Metrics settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSettings {
    /// Enable metrics
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics listen address
    #[serde(default = "default_metrics_listen")]
    pub listen_addr: String,

    /// Metrics prefix
    #[serde(default = "default_metrics_prefix")]
    pub prefix: String,
}

/// Notification settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationSettings {
    /// Webhook configurations
    #[serde(default)]
    pub webhooks: Vec<WebhookConfig>,

    /// Email configurations
    #[serde(default)]
    pub email: Vec<EmailConfig>,
}

/// Webhook notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook name
    pub name: Option<String>,

    /// Webhook URL
    pub url: String,

    /// Events to trigger on
    #[serde(default)]
    pub events: Vec<String>,

    /// Response format
    #[serde(default = "default_webhook_format")]
    pub format: String,

    /// Authentication token
    pub auth_token: Option<String>,

    /// Request timeout
    #[serde(default = "default_webhook_timeout")]
    pub timeout_secs: u64,
}

/// Email notification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    /// SMTP server host
    pub smtp_host: String,

    /// SMTP server port
    #[serde(default = "default_smtp_port")]
    pub smtp_port: u16,

    /// From email address
    pub from: String,

    /// Recipient email addresses
    pub to: Vec<String>,

    /// Events to trigger on
    #[serde(default)]
    pub events: Vec<String>,

    /// SMTP username (optional)
    pub username: Option<String>,

    /// SMTP password (optional)
    pub password: Option<String>,
}

/// CLI settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliSettings {
    /// Output format: "text", "json", "csv"
    #[serde(default = "default_output_format")]
    pub output_format: String,

    /// Enable colored output
    #[serde(default = "default_true")]
    pub colors: bool,

    /// Log level: "trace", "debug", "info", "warn", "error"
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log file path
    pub log_file: Option<String>,

    /// Log file max size in MB
    #[serde(default = "default_log_max_size")]
    pub log_max_size: u64,

    /// Number of log files to keep
    #[serde(default = "default_log_backup_count")]
    pub log_backup_count: u32,
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    /// Listen address
    #[serde(default = "default_server_listen")]
    pub listen_addr: String,

    /// Enable API
    #[serde(default = "default_true")]
    pub enable_api: bool,

    /// Enable Webhook handler
    #[serde(default = "default_true")]
    pub enable_webhook: bool,
}

// Default values
fn default_acme_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

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
            directory: default_acme_url(),
            ca: default_ca(),
            ca_environment: default_ca_env(),
            ca_custom_url: None,
            contact: Vec::new(),
            tos_agreed: true,
            external_account_binding: None,
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

impl Default for NotificationSettings {
    fn default() -> Self {
        Self {
            webhooks: Vec::new(),
            email: Vec::new(),
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

impl Default for Config {
    fn default() -> Self {
        Self {
            acme: AcmeSettings::default(),
            storage: StorageSettings::default(),
            challenge: ChallengeSettings::default(),
            renewal: RenewalSettings::default(),
            metrics: None,
            notifications: None,
            cli: None,
            server: None,
        }
    }
}

impl Config {
    /// Create a new configuration with defaults
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| AcmeError::configuration(&format!("Failed to read config file: {}", e)))?;
        Self::from_str(&content)
    }

    /// Load configuration from a TOML string
    pub fn from_str(content: &str) -> Result<Self> {
        toml::from_str(content)
            .map_err(|e| AcmeError::configuration(&format!("Failed to parse TOML: {}", e)))
    }

    /// Apply environment variable overrides
    pub fn apply_env_overrides(&mut self) -> Result<()> {
        // Override ACME settings
        if let Ok(url) = env::var("ACMEX_ACME_DIRECTORY") {
            self.acme.directory = Self::expand_env_var(&url)?;
        }

        // Override storage backend
        if let Ok(backend) = env::var("ACMEX_STORAGE_BACKEND") {
            self.storage.backend = backend;
        }

        // Override file path
        if let Ok(path) = env::var("ACMEX_STORAGE_FILE_PATH") {
            if let Some(ref mut file_config) = self.storage.file {
                file_config.path = Self::expand_env_var(&path)?;
            }
        }

        // Override Redis URL
        if let Ok(url) = env::var("ACMEX_STORAGE_REDIS_URL") {
            if let Some(ref mut redis_config) = self.storage.redis {
                redis_config.url = Self::expand_env_var(&url)?;
            }
        }

        // Override challenge type
        if let Ok(challenge_type) = env::var("ACMEX_CHALLENGE_TYPE") {
            self.challenge.challenge_type = challenge_type;
        }

        // Override renewal check interval
        if let Ok(interval) = env::var("ACMEX_RENEWAL_CHECK_INTERVAL") {
            if let Ok(secs) = interval.parse::<u64>() {
                self.renewal.check_interval = secs;
            }
        }

        // Override renewal window
        if let Ok(days) = env::var("ACMEX_RENEWAL_BEFORE_DAYS") {
            if let Ok(d) = days.parse::<u32>() {
                self.renewal.renew_before_days = d;
            }
        }

        Ok(())
    }

    /// Expand environment variables in format ${VAR}
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

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate ACME directory URL
        if self.acme.directory.is_empty() {
            return Err(AcmeError::configuration(
                "ACME directory URL cannot be empty",
            ));
        }

        // Validate storage backend
        match self.storage.backend.as_str() {
            "file" => {
                if let Some(ref file_config) = self.storage.file {
                    if file_config.path.is_empty() {
                        return Err(AcmeError::configuration(
                            "File storage path cannot be empty",
                        ));
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
            "encrypted" => {
                if let Some(ref encrypted_config) = self.storage.encrypted {
                    if encrypted_config.encryption_key.is_empty() {
                        return Err(AcmeError::configuration("Encryption key cannot be empty"));
                    }
                }
            }
            backend => {
                return Err(AcmeError::configuration(&format!(
                    "Invalid storage backend: {}",
                    backend
                )));
            }
        }

        // Validate challenge type
        match self.challenge.challenge_type.as_str() {
            "http-01" | "dns-01" | "tls-alpn-01" => {}
            challenge_type => {
                return Err(AcmeError::configuration(&format!(
                    "Invalid challenge type: {}",
                    challenge_type
                )));
            }
        }

        // Validate renewal settings
        if self.renewal.check_interval == 0 {
            return Err(AcmeError::configuration(
                "Check interval must be greater than 0",
            ));
        }

        Ok(())
    }

    /// Get ACME directory URL
    pub fn acme_directory(&self) -> &str {
        &self.acme.directory
    }

    /// Get storage backend type
    pub fn storage_backend(&self) -> &str {
        &self.storage.backend
    }

    /// Get challenge type
    pub fn challenge_type(&self) -> &str {
        &self.challenge.challenge_type
    }

    /// Get renewal check interval as Duration
    pub fn renewal_check_interval(&self) -> Duration {
        Duration::from_secs(self.renewal.check_interval)
    }

    /// Check if certificate should be renewed
    pub fn should_renew_days_before(&self) -> u32 {
        self.renewal.renew_before_days
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(test)]
    use temp_env;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(
            config.acme.directory,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.storage.backend, "file");
        assert_eq!(config.challenge.challenge_type, "dns-01");
    }

    #[test]
    fn test_config_from_string() {
        let toml = r#"
[acme]
directory = "https://acme-staging-v02.api.letsencrypt.org/directory"
tos_agreed = true

[storage]
backend = "file"

[storage.file]
path = "/etc/acme/certs"

[challenge]
challenge_type = "http-01"

[renewal]
check_interval = 1800
renew_before_days = 14
"#;

        let config = Config::from_str(toml).unwrap();
        assert_eq!(
            config.acme.directory,
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(config.storage.backend, "file");
        assert_eq!(config.challenge.challenge_type, "http-01");
        assert_eq!(config.renewal.check_interval, 1800);
        assert_eq!(config.renewal.renew_before_days, 14);
    }

    #[test]
    fn test_config_validation() {
        let config = Config::default();
        assert!(config.validate().is_ok());

        let mut invalid_config = Config::default();
        invalid_config.acme.directory.clear();
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_expand_env_var() {
        // Use temp-env to safely set environment variables in tests
        temp_env::with_var("TEST_VAR", Some("test_value"), || {
            let result = Config::expand_env_var("prefix_${TEST_VAR}_suffix").unwrap();
            assert_eq!(result, "prefix_test_value_suffix");
        });
    }
}
