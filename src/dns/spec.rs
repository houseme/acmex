//! DNS provider specification and secret references.
//!
//! Providers are created *from configuration* through the factory (never
//! hand-instantiated by business code). Credentials are referenced via
//! [`SecretRef`] and resolved at construction time — plaintext values never
//! sit in configuration structs or logs.

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::{AcmeError, Result};

/// A reference to a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum SecretRef {
    /// Read from an environment variable.
    Env {
        /// Variable name.
        name: String,
    },
    /// Read from a file (first line, trimmed).
    File {
        /// File path.
        path: PathBuf,
    },
    /// Vault-style reference, intentionally unresolved by the built-in
    /// resolver until a deployment wires its own implementation.
    Vault {
        /// Vault mount or namespace.
        mount: String,
        /// Secret path below the mount.
        path: String,
        /// Key within the secret payload.
        key: String,
    },
    /// Provider-specific scheme (resolved by a dedicated resolver).
    ProviderSpecific {
        /// Scheme identifier (e.g. `aws-default`).
        scheme: String,
        /// Opaque reference under that scheme.
        reference: String,
    },
}

impl SecretRef {
    /// Parses wire forms like `env:CF_DNS_TOKEN` / `file:/run/secret` /
    /// `aws-default://profile-x`.
    pub fn parse(value: &str) -> Result<Self> {
        if let Some(name) = value.strip_prefix("env:") {
            return Ok(Self::Env {
                name: name.to_string(),
            });
        }
        if let Some(path) = value.strip_prefix("file:") {
            return Ok(Self::File {
                path: PathBuf::from(path),
            });
        }
        if let Some(rest) = value.strip_prefix("vault:") {
            let mut parts = rest.splitn(3, ':');
            let mount = parts.next().unwrap_or_default();
            let path = parts.next().unwrap_or_default();
            let key = parts.next().unwrap_or_default();
            if mount.is_empty() || path.is_empty() || key.is_empty() {
                return Err(AcmeError::InvalidInput(format!(
                    "vault secret needs `vault:<mount>:<path>:<key>`, got {value:?}"
                )));
            }
            return Ok(Self::Vault {
                mount: mount.to_string(),
                path: path.to_string(),
                key: key.to_string(),
            });
        }
        if let Some(rest) = value.strip_prefix("provider:") {
            let (scheme, reference) = rest.split_once(':').ok_or_else(|| {
                AcmeError::InvalidInput(format!(
                    "provider secret needs `provider:<scheme>:<reference>`, got {value:?}"
                ))
            })?;
            return Ok(Self::ProviderSpecific {
                scheme: scheme.to_string(),
                reference: reference.to_string(),
            });
        }
        Err(AcmeError::InvalidInput(format!(
            "unrecognized secret reference {value:?} (expected env:/file:/provider:)"
        )))
    }

    /// A debug-safe description (never the secret itself).
    pub fn describe(&self) -> String {
        match self {
            Self::Env { name } => format!("env:{name}"),
            Self::File { path } => format!("file:{}", path.display()),
            Self::Vault { mount, path, key } => format!("vault:{mount}:{path}:{key}"),
            Self::ProviderSpecific { scheme, reference } => {
                format!("provider:{scheme}:{reference}")
            }
        }
    }
}

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case", tag = "kind")]
        enum TaggedSecretRef {
            Env {
                name: String,
            },
            File {
                path: PathBuf,
            },
            Vault {
                mount: String,
                path: String,
                key: String,
            },
            ProviderSpecific {
                scheme: String,
                reference: String,
            },
        }

        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Text(String),
            Tagged(TaggedSecretRef),
        }

        match Wire::deserialize(deserializer)? {
            Wire::Text(value) => SecretRef::parse(&value).map_err(serde::de::Error::custom),
            Wire::Tagged(TaggedSecretRef::Env { name }) => Ok(SecretRef::Env { name }),
            Wire::Tagged(TaggedSecretRef::File { path }) => Ok(SecretRef::File { path }),
            Wire::Tagged(TaggedSecretRef::Vault { mount, path, key }) => {
                Ok(SecretRef::Vault { mount, path, key })
            }
            Wire::Tagged(TaggedSecretRef::ProviderSpecific { scheme, reference }) => {
                Ok(SecretRef::ProviderSpecific { scheme, reference })
            }
        }
    }
}

/// Secret bytes with redacted Debug (contents must never leak to logs).
#[derive(Clone)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps raw secret bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The raw value (use briefly; zeroize when done).
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// The value as UTF-8, if valid.
    pub fn expose_utf8(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes(**redacted**)")
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Resolves [`SecretRef`] references.
#[async_trait]
pub trait SecretResolver: Send + Sync {
    /// Resolves a reference; errors mention the reference, never the value.
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretBytes>;
}

/// Resolves `env:` and `file:` references.
#[derive(Debug, Clone, Default)]
pub struct EnvFileSecretResolver;

#[async_trait]
impl SecretResolver for EnvFileSecretResolver {
    async fn resolve(&self, reference: &SecretRef) -> Result<SecretBytes> {
        match reference {
            SecretRef::Env { name } => std::env::var(name)
                .map(|value| SecretBytes::new(value.into_bytes()))
                .map_err(|_| {
                    AcmeError::Configuration(format!(
                        "secret {} is not set in the environment",
                        reference.describe()
                    ))
                }),
            SecretRef::File { path } => {
                let content = std::fs::read_to_string(path).map_err(|err| {
                    AcmeError::Configuration(format!(
                        "failed to read secret {}: {err}",
                        reference.describe()
                    ))
                })?;
                Ok(SecretBytes::new(
                    content
                        .lines()
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_string()
                        .into_bytes(),
                ))
            }
            SecretRef::Vault { .. } => Err(AcmeError::Configuration(format!(
                "secret {} requires a vault resolver",
                reference.describe()
            ))),
            SecretRef::ProviderSpecific { .. } => Err(AcmeError::Configuration(format!(
                "secret {} requires a provider-specific resolver",
                reference.describe()
            ))),
        }
    }
}

/// Versioned, typed provider specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsProviderSpec {
    /// Stable provider instance id (referenced by intent selectors).
    pub id: String,
    /// Provider type (`cloudflare`, `route53`, `fake`, ...).
    #[serde(rename = "type")]
    pub provider_type: String,
    /// Credential reference; never a literal secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<SecretRef>,
    /// Exact zone apices this instance owns.
    #[serde(default)]
    pub zones: Vec<String>,
    /// Longest-suffix match zones (e.g. `internal.example.org`).
    #[serde(default)]
    pub zone_suffixes: Vec<String>,
    /// Optional API endpoint override (must be explicitly configured).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Request timeout for provider API calls.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Provider-specific extra settings (opaque to the router).
    #[serde(default)]
    pub extra: HashMap<String, String>,
}

fn default_timeout_secs() -> u64 {
    30
}

impl DnsProviderSpec {
    /// Normalizes zone selectors for matching.
    pub fn normalized_zones(&self) -> Vec<String> {
        let mut zones: Vec<_> = self
            .zones
            .iter()
            .chain(self.zone_suffixes.iter())
            .map(|z| z.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        zones.sort();
        zones.dedup();
        zones
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_ref_parses_wire_forms() {
        assert_eq!(
            SecretRef::parse("env:CF_TOKEN").unwrap(),
            SecretRef::Env {
                name: "CF_TOKEN".to_string()
            }
        );
        assert_eq!(
            SecretRef::parse("file:/run/secrets/cf").unwrap(),
            SecretRef::File {
                path: PathBuf::from("/run/secrets/cf")
            }
        );
        assert!(matches!(
            SecretRef::parse("provider:aws-default:prod").unwrap(),
            SecretRef::ProviderSpecific { .. }
        ));
        assert!(matches!(
            SecretRef::parse("vault:secret:acmex/webhook:token").unwrap(),
            SecretRef::Vault { .. }
        ));
        assert!(SecretRef::parse("raw-token").is_err());
    }

    #[test]
    fn secret_bytes_debug_is_redacted() {
        let secret = SecretBytes::new(b"super-secret-token".to_vec());
        let text = format!("{secret:?}");
        assert!(!text.contains("super-secret-token"));
        assert!(text.contains("redacted"));
        assert_eq!(secret.expose(), b"super-secret-token");
    }

    #[test]
    fn spec_zones_normalize() {
        let spec = DnsProviderSpec {
            id: "cf-prod".to_string(),
            provider_type: "cloudflare".to_string(),
            credential: Some(SecretRef::Env {
                name: "CF_TOKEN".to_string(),
            }),
            zones: vec!["Example.COM.".to_string()],
            zone_suffixes: vec!["example.net".to_string()],
            endpoint: None,
            timeout_secs: 30,
            extra: HashMap::new(),
        };
        assert_eq!(
            spec.normalized_zones(),
            vec!["example.com".to_string(), "example.net".to_string()]
        );
    }
}
