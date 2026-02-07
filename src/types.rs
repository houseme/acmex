/// Common types and structures for ACME protocol
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// JWS header structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwsHeader {
    /// Algorithm
    pub alg: String,
    /// JSON Web Key (for new keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<serde_json::Value>,
    /// Key ID (for existing keys)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Replay nonce
    pub nonce: String,
    /// URL of the resource being accessed
    pub url: String,
}

/// JSON Web Key representation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    /// Key type (e.g., "RSA", "EC", "OKP")
    pub kty: String,
    /// Use (typically "sig" for signing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    /// Key operations
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    /// Additional parameters
    #[serde(flatten)]
    pub params: HashMap<String, serde_json::Value>,
}

/// ACME error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeErrorDetail {
    /// Error type URI
    #[serde(rename = "type")]
    pub error_type: String,
    /// Error detail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// HTTP status code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Error title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Problem instance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Sub-problems
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subproblems: Option<Vec<AcmeSubproblem>>,
}

/// ACME sub-problem
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeSubproblem {
    /// Error type URI
    #[serde(rename = "type")]
    pub error_type: String,
    /// Error detail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identifier: Option<Identifier>,
}

/// Identifier for domain authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    /// Type: "dns" or "ip"
    #[serde(rename = "type")]
    pub id_type: String,
    /// Value: domain name or IP address
    pub value: String,
}

impl Identifier {
    /// Create a DNS identifier
    pub fn dns(domain: impl Into<String>) -> Self {
        Self {
            id_type: "dns".to_string(),
            value: domain.into(),
        }
    }

    /// Create an IP identifier
    pub fn ip(ip: impl Into<String>) -> Self {
        Self {
            id_type: "ip".to_string(),
            value: ip.into(),
        }
    }
}

/// Certificate revocation reason
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum RevocationReason {
    /// Reason unspecified
    Unspecified = 0,
    /// Key compromise
    KeyCompromise = 1,
    /// CA compromise
    CaCompromise = 2,
    /// Affiliation changed
    AffiliationChanged = 3,
    /// Superseded
    Superseded = 4,
    /// Cessation of operation
    CessationOfOperation = 5,
    /// Certificate hold
    CertificateHold = 6,
    /// Remove from CRL
    RemoveFromCRL = 8,
    /// Privilege withdrawn
    PrivilegeWithdrawn = 9,
    /// AA compromise
    AACompromise = 10,
}

impl RevocationReason {
    /// Get the numeric value
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Contact information for account
#[derive(Debug, Clone)]
pub struct Contact {
    /// Email address
    pub email: Option<String>,
    /// Phone number
    pub phone: Option<String>,
    /// URL
    pub url: Option<String>,
}

impl Contact {
    /// Create email contact
    pub fn email(email: impl Into<String>) -> Self {
        Self {
            email: Some(email.into()),
            phone: None,
            url: None,
        }
    }

    /// Create phone contact
    pub fn phone(phone: impl Into<String>) -> Self {
        Self {
            email: None,
            phone: Some(phone.into()),
            url: None,
        }
    }

    /// Create URL contact
    pub fn url(url: impl Into<String>) -> Self {
        Self {
            email: None,
            phone: None,
            url: Some(url.into()),
        }
    }

    /// Convert to ACME URI format
    pub fn to_uri(&self) -> String {
        if let Some(email) = &self.email {
            format!("mailto:{}", email)
        } else if let Some(phone) = &self.phone {
            format!("tel:{}", phone)
        } else if let Some(url) = &self.url {
            url.clone()
        } else {
            String::new()
        }
    }
}

/// Challenge type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChallengeType {
    /// HTTP-01 challenge
    Http01,
    /// DNS-01 challenge
    Dns01,
    /// TLS-ALPN-01 challenge
    TlsAlpn01,
}

impl ChallengeType {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            ChallengeType::Http01 => "http-01",
            ChallengeType::Dns01 => "dns-01",
            ChallengeType::TlsAlpn01 => "tls-alpn-01",
        }
    }
}

impl std::str::FromStr for ChallengeType {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "http-01" => Ok(ChallengeType::Http01),
            "dns-01" => Ok(ChallengeType::Dns01),
            "tls-alpn-01" => Ok(ChallengeType::TlsAlpn01),
            _ => Err(format!("Unknown challenge type: {}", s)),
        }
    }
}

impl std::fmt::Display for ChallengeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Order status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderStatus {
    /// Pending authorization
    Pending,
    /// Validated and ready for finalization
    Ready,
    /// Processing finalization
    Processing,
    /// Certificate issued
    Valid,
    /// Invalid
    Invalid,
    /// Expired
    Expired,
    /// Deactivated
    Deactivated,
}

impl std::str::FromStr for OrderStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(OrderStatus::Pending),
            "ready" => Ok(OrderStatus::Ready),
            "processing" => Ok(OrderStatus::Processing),
            "valid" => Ok(OrderStatus::Valid),
            "invalid" => Ok(OrderStatus::Invalid),
            "expired" => Ok(OrderStatus::Expired),
            "deactivated" => Ok(OrderStatus::Deactivated),
            _ => Err(format!("Unknown order status: {}", s)),
        }
    }
}

impl OrderStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            OrderStatus::Pending => "pending",
            OrderStatus::Ready => "ready",
            OrderStatus::Processing => "processing",
            OrderStatus::Valid => "valid",
            OrderStatus::Invalid => "invalid",
            OrderStatus::Expired => "expired",
            OrderStatus::Deactivated => "deactivated",
        }
    }
}

impl std::fmt::Display for OrderStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Authorization status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationStatus {
    /// Pending validation
    Pending,
    /// Validated
    Valid,
    /// Invalid
    Invalid,
    /// Deactivated
    Deactivated,
    /// Expired
    Expired,
}

impl std::str::FromStr for AuthorizationStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "pending" => Ok(AuthorizationStatus::Pending),
            "valid" => Ok(AuthorizationStatus::Valid),
            "invalid" => Ok(AuthorizationStatus::Invalid),
            "deactivated" => Ok(AuthorizationStatus::Deactivated),
            "expired" => Ok(AuthorizationStatus::Expired),
            _ => Err(format!("Unknown authorization status: {}", s)),
        }
    }
}

impl AuthorizationStatus {
    /// Get string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthorizationStatus::Pending => "pending",
            AuthorizationStatus::Valid => "valid",
            AuthorizationStatus::Invalid => "invalid",
            AuthorizationStatus::Deactivated => "deactivated",
            AuthorizationStatus::Expired => "expired",
        }
    }
}

impl std::fmt::Display for AuthorizationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identifier_dns() {
        let id = Identifier::dns("example.com");
        assert_eq!(id.id_type, "dns");
        assert_eq!(id.value, "example.com");
    }

    #[test]
    fn test_contact_email() {
        let contact = Contact::email("test@example.com");
        assert_eq!(contact.to_uri(), "mailto:test@example.com");
    }

    #[test]
    fn test_challenge_type() {
        assert_eq!(ChallengeType::Http01.as_str(), "http-01");
        assert_eq!("dns-01".parse::<ChallengeType>(), Ok(ChallengeType::Dns01));
    }

    #[test]
    fn test_order_status() {
        assert_eq!("pending".parse::<OrderStatus>(), Ok(OrderStatus::Pending));
        assert_eq!(OrderStatus::Valid.as_str(), "valid");
    }
}
