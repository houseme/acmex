/// Order-related objects for the ACME protocol.
/// This module defines the structures for orders, authorizations, and challenges
/// as specified in RFC 8555.
use crate::types::{AuthorizationStatus, Identifier, OrderStatus};
use serde::{Deserialize, Serialize};

/// Represents an ACME authorization challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// The type of challenge (e.g., "http-01", "dns-01", "tls-alpn-01").
    #[serde(rename = "type")]
    pub challenge_type: String,

    /// The URL to which a response should be posted to trigger validation.
    pub url: String,

    /// The current status of the challenge (e.g., "pending", "processing", "valid", "invalid").
    pub status: String,

    /// A token used to construct the key authorization string.
    pub token: String,

    /// The computed key authorization string, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorization: Option<String>,

    /// Additional validation details provided by the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<String>,

    /// The timestamp when the challenge was last updated.
    #[serde(default)]
    pub updated: Option<String>,

    /// Error information if the challenge validation failed.
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

/// Represents an authorization for a specific identifier (e.g., a domain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// The identifier being authorized.
    pub identifier: Identifier,

    /// The current status of the authorization.
    pub status: String,

    /// The expiration timestamp for this authorization.
    pub expires: String,

    /// A list of challenges offered by the server to fulfill this authorization.
    pub challenges: Vec<Challenge>,

    /// Indicates if this authorization is for a wildcard domain.
    #[serde(default)]
    pub wildcard: Option<bool>,

    /// A convenience field for storing combined challenge data.
    #[serde(default)]
    pub combined_challenges: Option<Vec<Challenge>>,
}

impl Authorization {
    /// Returns a reference to a specific challenge by its type.
    pub fn get_challenge(&self, challenge_type: &str) -> Option<&Challenge> {
        self.challenges
            .iter()
            .find(|c| c.challenge_type == challenge_type)
    }

    /// Parses the status string into an `AuthorizationStatus` enum.
    pub fn status_enum(&self) -> Option<AuthorizationStatus> {
        self.status.parse().ok()
    }
}

/// Represents an ACME certificate order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    /// The current status of the order.
    pub status: String,

    /// The expiration timestamp for the order.
    pub expires: String,

    /// The list of identifiers (domains) included in this order.
    pub identifiers: Vec<Identifier>,

    /// A list of URLs for the authorizations required to fulfill this order.
    pub authorizations: Vec<String>,

    /// The URL to which the CSR should be posted to finalize the order.
    pub finalize: String,

    /// The URL from which the issued certificate can be downloaded.
    #[serde(default)]
    pub certificate: Option<String>,

    /// A convenience field for storing combined authorization data.
    #[serde(skip)]
    pub combined_authorizations: Option<Vec<Authorization>>,
}

impl Order {
    /// Parses the status string into an `OrderStatus` enum.
    pub fn status_enum(&self) -> Option<OrderStatus> {
        self.status.parse().ok()
    }

    /// Returns true if the order is in the 'ready' status.
    pub fn is_ready(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Ready))
    }

    /// Returns true if the order is in the 'valid' status (certificate issued).
    pub fn is_valid(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Valid))
    }

    /// Returns true if the order is in the 'pending' status.
    pub fn is_pending(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Pending))
    }
}

/// A request to create a new certificate order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrderRequest {
    /// The identifiers (domains) to be included in the order.
    pub identifiers: Vec<Identifier>,

    /// Optional requested 'not before' timestamp for the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "notBefore")]
    pub not_before: Option<String>,

    /// Optional requested 'not after' timestamp for the certificate.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
}

impl NewOrderRequest {
    /// Creates a new order request for the specified list of domains.
    pub fn new(domains: Vec<String>) -> Self {
        tracing::debug!("Creating NewOrderRequest for domains: {:?}", domains);
        let identifiers = domains.into_iter().map(Identifier::dns).collect();

        Self {
            identifiers,
            not_before: None,
            not_after: None,
        }
    }

    /// Sets the 'not before' timestamp for the order request.
    pub fn with_not_before(mut self, not_before: String) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Sets the 'not after' timestamp for the order request.
    pub fn with_not_after(mut self, not_after: String) -> Self {
        self.not_after = Some(not_after);
        self
    }
}

/// A request to finalize an order by submitting a CSR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizationRequest {
    /// The Certificate Signing Request (CSR) in base64url-encoded DER format.
    pub csr: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge_parsing() {
        let json = r#"{
            "type": "http-01",
            "url": "https://example.com/acme/challenge/123",
            "status": "pending",
            "token": "test-token"
        }"#;

        let challenge: Challenge = serde_json::from_str(json).expect("Failed to parse challenge");
        assert_eq!(challenge.challenge_type, "http-01");
        assert_eq!(challenge.token, "test-token");
    }

    #[test]
    fn test_authorization_get_challenge() {
        let json = r#"{
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "expires": "2024-01-01T00:00:00Z",
            "challenges": [
                {
                    "type": "http-01",
                    "url": "https://example.com/acme/challenge/1",
                    "status": "pending",
                    "token": "token1"
                },
                {
                    "type": "dns-01",
                    "url": "https://example.com/acme/challenge/2",
                    "status": "pending",
                    "token": "token2"
                }
            ]
        }"#;

        let auth: Authorization =
            serde_json::from_str(json).expect("Failed to parse authorization");
        assert!(auth.get_challenge("http-01").is_some());
        assert!(auth.get_challenge("dns-01").is_some());
        assert!(auth.get_challenge("tls-alpn-01").is_none());
    }

    #[test]
    fn test_order_status_checks() {
        let mut order: Order = serde_json::from_str(
            r#"{
            "status": "pending",
            "expires": "2024-01-01T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://example.com/acme/authz/1"],
            "finalize": "https://example.com/acme/finalize/1"
        }"#,
        )
        .expect("Failed to parse order");

        assert!(order.is_pending());
        assert!(!order.is_ready());
        assert!(!order.is_valid());

        order.status = "ready".to_string();
        assert!(!order.is_pending());
        assert!(order.is_ready());
        assert!(!order.is_valid());

        order.status = "valid".to_string();
        assert!(!order.is_pending());
        assert!(!order.is_ready());
        assert!(order.is_valid());
    }

    #[test]
    fn test_new_order_request() {
        let req = NewOrderRequest::new(vec![
            "example.com".to_string(),
            "www.example.com".to_string(),
        ]);

        assert_eq!(req.identifiers.len(), 2);
        assert_eq!(req.identifiers[0].value, "example.com");
        assert_eq!(req.identifiers[0].id_type, "dns");
    }
}
