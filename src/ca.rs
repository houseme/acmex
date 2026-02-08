//! Multiple CA (Certificate Authority) support for AcmeX
//!
//! This module provides support for multiple certificate authorities:
//! - Let's Encrypt (default)
//! - Google Trust Services (feature: `google-ca`)
//! - ZeroSSL (feature: `zerossl-ca`)
//! - Custom CA endpoints

use serde::{Deserialize, Serialize};
use std::fmt;

/// Supported Certificate Authorities
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CertificateAuthority {
    /// Let's Encrypt (default)
    #[serde(rename = "letsencrypt")]
    #[default]
    LetsEncrypt,

    /// Google Trust Services
    #[cfg(feature = "google-ca")]
    #[serde(rename = "google")]
    Google,

    /// ZeroSSL
    #[cfg(feature = "zerossl-ca")]
    #[serde(rename = "zerossl")]
    ZeroSSL,

    /// Custom CA endpoint
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

/// CA Configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CAConfig {
    /// Certificate Authority type
    pub ca: CertificateAuthority,

    /// Environment: production or staging
    #[serde(default)]
    pub environment: Environment,

    /// Custom CA endpoint URL (only used when ca = Custom)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_url: Option<String>,

    /// Email for notifications
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
}

/// ACME Environment
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Environment {
    /// Production environment
    #[serde(rename = "production")]
    #[default]
    Production,

    /// Staging/Testing environment
    #[serde(rename = "staging")]
    Staging,
}


impl CAConfig {
    /// Create a new CA configuration
    pub fn new(ca: CertificateAuthority, environment: Environment) -> Self {
        Self {
            ca,
            environment,
            custom_url: None,
            contact_email: None,
        }
    }

    /// Set custom CA URL
    pub fn with_custom_url(mut self, url: String) -> Self {
        self.custom_url = Some(url);
        self
    }

    /// Set contact email
    pub fn with_contact_email(mut self, email: String) -> Self {
        self.contact_email = Some(email);
        self
    }

    /// Get the ACME directory URL for this CA
    pub fn directory_url(&self) -> Result<String, String> {
        match self.ca {
            // Let's Encrypt
            CertificateAuthority::LetsEncrypt => match self.environment {
                Environment::Production => {
                    Ok("https://acme-v02.api.letsencrypt.org/directory".to_string())
                }
                Environment::Staging => {
                    Ok("https://acme-staging-v02.api.letsencrypt.org/directory".to_string())
                }
            },

            #[cfg(feature = "google-ca")]
            CertificateAuthority::Google => {
                // Google doesn't have a separate staging environment
                Ok("https://dv.google.com/acme/directory".to_string())
            }

            #[cfg(feature = "zerossl-ca")]
            CertificateAuthority::ZeroSSL => Ok("https://acme.zerossl.com/v2/DV90".to_string()),

            // Custom CA
            CertificateAuthority::Custom => self
                .custom_url
                .clone()
                .ok_or_else(|| "Custom CA requires custom_url to be set".to_string()),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.ca == CertificateAuthority::Custom && self.custom_url.is_none() {
            return Err("Custom CA requires custom_url to be set".to_string());
        }
        Ok(())
    }
}

impl fmt::Display for CAConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            self.ca,
            match self.environment {
                Environment::Production => "Production",
                Environment::Staging => "Staging",
            }
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
