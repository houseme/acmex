//! CA backend types: handles, requests and capability discovery results.
//!
//! Handles are serializable so the workflow engine (T03) can persist them
//! and resume an in-flight order after a restart.

use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use crate::domain::Identifier;
use crate::order::{Authorization, Order};
use crate::types::RevocationReason;

/// Logical CA identity (configuration-level, e.g. `letsencrypt-staging`).
pub type CaId = String;

/// Reference to the account a backend should use or create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRef {
    /// Owning tenant.
    pub tenant_id: String,
    /// Contact URIs (`mailto:...`).
    #[serde(default)]
    pub contacts: Vec<String>,
    /// Whether the terms of service are agreed.
    pub terms_of_service_agreed: bool,
    /// External account binding, when the CA requires it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_binding: Option<ExternalAccountBindingRef>,
}

/// EAB credential reference (values are supplied by the secret resolver;
/// never persisted in domain objects).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalAccountBindingRef {
    /// EAB key id (`kid`).
    pub key_id: String,
    /// Where the HMAC key is resolved from (env var name, file path...).
    pub hmac_key_source: String,
}

impl ExternalAccountBindingRef {
    /// A debug-safe description (never the HMAC value).
    pub fn redacted(&self) -> String {
        format!("eab(kid={}, key={})", self.key_id, self.hmac_key_source)
    }
}

/// A usable CA account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountHandle {
    /// The CA this account belongs to.
    pub ca_id: CaId,
    /// The ACME account URL (used as JWS `kid`).
    pub account_url: String,
    /// Reference to the account key (never key material).
    pub key_id: String,
}

/// A request to create an ACME order.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OrderRequest {
    /// The identifiers to certify.
    pub identifiers: Vec<Identifier>,
    /// Requested notBefore (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// Requested notAfter (RFC 3339).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    /// Requested certificate profile (ACME profiles draft); must come from
    /// intent/planner or CA capabilities, never inferred from the CSR.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// ARI `replaces` claim: the certificate this order replaces.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replaces: Option<String>,
}

impl OrderRequest {
    /// A request for the given identifiers.
    pub fn for_identifiers(identifiers: Vec<Identifier>) -> Self {
        Self {
            identifiers,
            not_before: None,
            not_after: None,
            profile: None,
            replaces: None,
        }
    }
}

/// A persisted handle on a created ACME order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderHandle {
    /// The CA that owns the order.
    pub ca_id: CaId,
    /// The order resource URL; persisted immediately after creation so a
    /// restart resumes instead of re-ordering.
    pub url: String,
}

/// A fetched order resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderResource {
    /// Resource URL.
    pub url: String,
    /// The order object.
    pub order: Order,
}

/// A fetched authorization resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResource {
    /// Resource URL.
    pub url: String,
    /// The authorization object.
    pub authorization: Authorization,
}

/// Reference to one challenge on an authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeRef {
    /// Challenge resource URL.
    pub url: String,
    /// The challenge type (`http-01`, ...).
    pub challenge_type: String,
}

/// Reference to an authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRef {
    /// Authorization resource URL.
    pub url: String,
}

/// An issued certificate chain (PEM, leaf first).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedChain {
    /// PEM text of the full chain.
    pub pem: String,
    /// The URL the chain was downloaded from.
    pub url: String,
}

/// RFC 9773 renewal window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenewalWindow {
    /// Window start.
    pub start: Timestamp,
    /// Window end (last sensible renewal point).
    pub end: Timestamp,
    /// Server-provided Retry-After for the next ARI check, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<Timestamp>,
    /// Human-readable explanation URL, if provided.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explanation_url: Option<String>,
}

/// A certificate revocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationRequest {
    /// DER-encoded certificate to revoke.
    pub certificate_der: Vec<u8>,
    /// Revocation reason.
    pub reason: RevocationReason,
}

/// What a CA supports, derived from its directory (loosely).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaCapabilities {
    /// The CA identity.
    pub ca_id: CaId,
    /// Directory URL.
    pub directory_url: String,
    /// Identifier types the CA is known to support (`dns`, `ip`). An empty
    /// vector means *unknown* — callers should treat only `dns` as safe.
    pub identifier_types: Vec<String>,
    /// Whether the directory advertises an ARI endpoint.
    pub supports_ari: bool,
    /// Advertised certificate profiles.
    pub profiles: Vec<CaProfile>,
    /// Whether the CA requires external account binding.
    pub requires_eab: bool,
    /// The ARI endpoint, when advertised.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub renewal_info_url: Option<String>,
    /// The keyChange endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_change_url: Option<String>,
    /// The revokeCert endpoint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revoke_cert_url: Option<String>,
}

/// A certificate profile advertised by a CA.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaProfile {
    /// Profile name (wire value used in orders).
    pub name: String,
    /// Whether this profile is known to issue short-lived certificates.
    #[serde(default)]
    pub short_lived: bool,
}

impl CaCapabilities {
    /// Whether the CA is known to support the given identifier type.
    ///
    /// Unknown capability lists default to DNS-only support.
    pub fn supports_identifier_type(&self, acme_type: &str) -> bool {
        if self.identifier_types.is_empty() {
            acme_type == "dns"
        } else {
            self.identifier_types.iter().any(|t| t == acme_type)
        }
    }

    /// Whether a profile name is advertised.
    pub fn supports_profile(&self, name: &str) -> bool {
        self.profiles.iter().any(|p| p.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handles_are_serializable() {
        let handle = OrderHandle {
            ca_id: "letsencrypt".to_string(),
            url: "https://acme.example/order/1".to_string(),
        };
        let json = serde_json::to_string(&handle).unwrap();
        let back: OrderHandle = serde_json::from_str(&json).unwrap();
        assert_eq!(handle, back);
    }

    #[test]
    fn unknown_identifier_capability_defaults_to_dns() {
        let caps = CaCapabilities {
            ca_id: "test".to_string(),
            directory_url: "https://example.com/dir".to_string(),
            identifier_types: vec![],
            supports_ari: false,
            profiles: vec![],
            requires_eab: false,
            renewal_info_url: None,
            key_change_url: None,
            revoke_cert_url: None,
        };
        assert!(caps.supports_identifier_type("dns"));
        assert!(!caps.supports_identifier_type("ip"));

        let mut ip_capable = caps.clone();
        ip_capable.identifier_types = vec!["dns".to_string(), "ip".to_string()];
        assert!(ip_capable.supports_identifier_type("ip"));
    }

    #[test]
    fn eab_ref_never_leaks_the_key_value() {
        let eab = ExternalAccountBindingRef {
            key_id: "kid-1".to_string(),
            hmac_key_source: "env:EAB_HMAC".to_string(),
        };
        let text = format!("{eab:?}");
        assert!(text.contains("env:EAB_HMAC"));
        // The source is a reference, not the secret itself; nothing else to leak.
        assert_eq!(eab.redacted(), "eab(kid=kid-1, key=env:EAB_HMAC)");
    }
}
