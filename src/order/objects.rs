/// Order objects for ACME protocol
use crate::types::{AuthorizationStatus, Identifier, OrderStatus};
use serde::{Deserialize, Serialize};

/// Authorization challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Challenge type (http-01, dns-01, tls-alpn-01)
    #[serde(rename = "type")]
    pub challenge_type: String,

    /// Challenge URL
    pub url: String,

    /// Challenge status
    pub status: String,

    /// Challenge token for validation
    pub token: String,

    /// Key authorization (computed from token and JWK thumbprint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_authorization: Option<String>,

    /// Validation details (varies by challenge type)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<String>,

    /// Timestamp when this challenge was updated
    #[serde(default)]
    pub updated: Option<String>,

    /// Error information if validation failed
    #[serde(default)]
    pub error: Option<serde_json::Value>,
}

/// Authorization for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// Authorization identifier
    pub identifier: Identifier,

    /// Authorization status
    pub status: String,

    /// Expiration timestamp
    pub expires: String,

    /// List of challenges
    pub challenges: Vec<Challenge>,

    /// Wildcard flag
    #[serde(default)]
    pub wildcard: Option<bool>,

    /// Combined challenges for convenience
    #[serde(default)]
    pub combined_challenges: Option<Vec<Challenge>>,
}

impl Authorization {
    /// Get a specific challenge by type
    pub fn get_challenge(&self, challenge_type: &str) -> Option<&Challenge> {
        self.challenges
            .iter()
            .find(|c| c.challenge_type == challenge_type)
    }

    /// Get status as AuthorizationStatus enum
    pub fn status_enum(&self) -> Option<AuthorizationStatus> {
        AuthorizationStatus::from_str(&self.status)
    }
}

/// ACME Order
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    /// Order status
    pub status: String,

    /// Expiration timestamp
    pub expires: String,

    /// List of identifiers (domains) in this order
    pub identifiers: Vec<Identifier>,

    /// List of authorization URLs
    pub authorizations: Vec<String>,

    /// Finalization URL
    pub finalize: String,

    /// Certificate URL (populated when status is valid)
    #[serde(default)]
    pub certificate: Option<String>,

    /// Combined data for convenience
    #[serde(skip)]
    pub combined_authorizations: Option<Vec<Authorization>>,
}

impl Order {
    /// Get status as OrderStatus enum
    pub fn status_enum(&self) -> Option<OrderStatus> {
        OrderStatus::from_str(&self.status)
    }

    /// Check if order is ready for finalization
    pub fn is_ready(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Ready))
    }

    /// Check if order is valid (certificate issued)
    pub fn is_valid(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Valid))
    }

    /// Check if order is pending (needs authorization)
    pub fn is_pending(&self) -> bool {
        matches!(self.status_enum(), Some(OrderStatus::Pending))
    }
}

/// New order request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrderRequest {
    /// Identifiers to order
    pub identifiers: Vec<Identifier>,

    /// Not before (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "notBefore")]
    pub not_before: Option<String>,

    /// Not after (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "notAfter")]
    pub not_after: Option<String>,
}

impl NewOrderRequest {
    /// Create a new order request for given domains
    pub fn new(domains: Vec<String>) -> Self {
        let identifiers = domains.into_iter().map(Identifier::dns).collect();

        Self {
            identifiers,
            not_before: None,
            not_after: None,
        }
    }

    /// Set not before timestamp
    pub fn with_not_before(mut self, not_before: String) -> Self {
        self.not_before = Some(not_before);
        self
    }

    /// Set not after timestamp
    pub fn with_not_after(mut self, not_after: String) -> Self {
        self.not_after = Some(not_after);
        self
    }
}

/// Finalization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizationRequest {
    /// Certificate Signing Request (base64url encoded DER)
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
