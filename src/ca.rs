/// Multiple Certificate Authority (CA) support for AcmeX.
/// This module provides configuration and endpoint discovery for various ACME providers,
/// including Let's Encrypt, Google Trust Services, and ZeroSSL.
use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported Certificate Authorities.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "lowercase")]
pub enum CertificateAuthority {
    /// Let's Encrypt (default).
    #[serde(rename = "letsencrypt")]
    #[default]
    LetsEncrypt,

    /// Google Trust Services.
    #[cfg(feature = "google-ca")]
    #[serde(rename = "google")]
    Google,

    /// ZeroSSL.
    #[cfg(feature = "zerossl-ca")]
    #[serde(rename = "zerossl")]
    ZeroSSL,

    /// A custom CA endpoint.
    #[serde(rename = "custom")]
    Custom,
}

impl fmt::Display for CertificateAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CertificateAuthority::LetsEncrypt => write!(f, "Let's Encrypt"),
            #[cfg(feature = "google-ca")]
            CertificateAuthority::Google => write!(f, "Google Trust Services"),
            #[cfg(feature = "zerossl-ca")]
            CertificateAuthority::ZeroSSL => write!(f, "ZeroSSL"),
            CertificateAuthority::Custom => write!(f, "Custom CA"),
        }
    }
}

/// Configuration for a specific Certificate Authority.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CAConfig {
    /// The type of Certificate Authority.
    pub ca: CertificateAuthority,

    /// The environment (Production or Staging).
    #[serde(default)]
    pub environment: Environment,

    /// The URL of the custom CA directory (only used when `ca` is `Custom`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_url: Option<String>,

    /// Contact email address for account notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
}

/// ACME Environment types.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// Production environment for real certificates.
    #[serde(rename = "production")]
    #[default]
    Production,

    /// Staging environment for testing and development.
    #[serde(rename = "staging")]
    Staging,
}

impl CAConfig {
    /// Creates a new `CAConfig` with the specified CA and environment.
    pub fn new(ca: CertificateAuthority, environment: Environment) -> Self {
        tracing::debug!("Creating new CAConfig for {} ({:?})", ca, environment);
        Self {
            ca,
            environment,
            custom_url: None,
            contact_email: None,
        }
    }

    /// Sets a custom CA directory URL.
    pub fn with_custom_url(mut self, url: String) -> Self {
        self.custom_url = Some(url);
        self
    }

    /// Sets the contact email for the CA account.
    pub fn with_contact_email(mut self, email: String) -> Self {
        self.contact_email = Some(email);
        self
    }

    /// Returns the ACME directory URL for the configured CA and environment.
    pub fn directory_url(&self) -> Result<String, String> {
        let url = match self.ca {
            CertificateAuthority::LetsEncrypt => match self.environment {
                Environment::Production => {
                    "https://acme-v02.api.letsencrypt.org/directory".to_string()
                }
                Environment::Staging => {
                    "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
                }
            },

            #[cfg(feature = "google-ca")]
            CertificateAuthority::Google => {
                "https://dv.google.com/acme/directory".to_string()
            }

            #[cfg(feature = "zerossl-ca")]
            CertificateAuthority::ZeroSSL => "https://acme.zerossl.com/v2/DV90".to_string(),

            CertificateAuthority::Custom => self
                .custom_url
                .clone()
                .ok_or_else(|| "Custom CA requires custom_url to be set".to_string())?,
        };

        tracing::debug!("Resolved directory URL: {}", url);
        Ok(url)
    }

    /// Validates the CA configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.ca == CertificateAuthority::Custom && self.custom_url.is_none() {
            tracing::error!("Validation failed: Custom CA selected but no URL provided");
            return Err("Custom CA requires custom_url to be set".to_string());
        }
        Ok(())
    }
}

impl fmt::Display for CAConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({:?})",
            self.ca,
            self.environment
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_ca() {
        let config = CAConfig::default();
        assert_eq!(config.ca, CertificateAuthority::LetsEncrypt);
        assert_eq!(config.environment, Environment::Production);
    }

    #[test]
    fn test_letsencrypt_urls() {
        let prod = CAConfig::new(CertificateAuthority::LetsEncrypt, Environment::Production);
        assert_eq!(
            prod.directory_url().unwrap(),
            "https://acme-v02.api.letsencrypt.org/directory"
        );

        let staging = CAConfig::new(CertificateAuthority::LetsEncrypt, Environment::Staging);
        assert_eq!(
            staging.directory_url().unwrap(),
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        );
    }

    #[test]
    fn test_custom_ca() {
        let config = CAConfig::new(CertificateAuthority::Custom, Environment::Production)
            .with_custom_url("https://ca.example.com/acme/directory".to_string());

        assert_eq!(
            config.directory_url().unwrap(),
            "https://ca.example.com/acme/directory"
        );
    }

    #[test]
    fn test_custom_ca_validation() {
        let config = CAConfig::new(CertificateAuthority::Custom, Environment::Production);
        assert!(config.validate().is_err());

        let config = config.with_custom_url("https://ca.example.com/acme/directory".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_ca_display() {
        let config = CAConfig::default();
        assert_eq!(config.to_string(), "Let's Encrypt (Production)");
    }

    #[cfg(feature = "google-ca")]
    #[test]
    fn test_google_ca_url() {
        let config = CAConfig::new(CertificateAuthority::Google, Environment::Production);
        assert_eq!(
            config.directory_url().unwrap(),
            "https://dv.google.com/acme/directory"
        );
    }

    #[cfg(feature = "zerossl-ca")]
    #[test]
    fn test_zerossl_ca_url() {
        let config = CAConfig::new(CertificateAuthority::ZeroSSL, Environment::Production);
        assert_eq!(
            config.directory_url().unwrap(),
            "https://acme.zerossl.com/v2/DV90"
        );
    }
}
