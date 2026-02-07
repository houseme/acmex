use serde::{Deserialize, Serialize};
/// Comprehensive error handling for the ACME client
use thiserror::Error;

/// Result type for ACME operations
pub type Result<T> = std::result::Result<T, AcmeError>;

/// Error types for ACME operations
#[derive(Error, Debug)]
pub enum AcmeError {
    /// Protocol-level error from ACME server
    #[error("Protocol error: {0}")]
    Protocol(String),

    /// Account-related error
    #[error("Account error: {0}")]
    Account(String),

    /// Order creation or processing error
    #[error("Order error: {status}, detail: {detail}")]
    Order { status: String, detail: String },

    /// Challenge verification failed
    #[error("Challenge failed: {challenge_type}, error: {error}")]
    Challenge {
        challenge_type: String,
        error: String,
    },

    /// Certificate-related error
    #[error("Certificate error: {0}")]
    Certificate(String),

    /// Cryptographic operation error
    #[error("Crypto error: {0}")]
    Crypto(String),

    /// Storage/persistence error
    #[error("Storage error: {0}")]
    Storage(String),

    /// HTTP transport error
    #[error("Transport error: {0}")]
    Transport(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON serialization/deserialization error
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Operation timed out
    #[error("Timeout: {0}")]
    Timeout(String),

    /// Resource not found
    #[error("Not found: {0}")]
    NotFound(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// PEM encoding/decoding error
    #[error("PEM error: {0}")]
    Pem(String),

    /// Rate limited by server
    #[error("Rate limited, retry after: {0:?}")]
    RateLimited(Option<std::time::Duration>),
}

/// RFC 7807 Problem Details for HTTP APIs
#[derive(Debug, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

impl AcmeError {
    /// Create a protocol error
    pub fn protocol<S: Into<String>>(msg: S) -> Self {
        AcmeError::Protocol(msg.into())
    }

    /// Create an account error
    pub fn account<S: Into<String>>(msg: S) -> Self {
        AcmeError::Account(msg.into())
    }

    /// Create an order error
    pub fn order<S: Into<String>>(status: S, detail: S) -> Self {
        AcmeError::Order {
            status: status.into(),
            detail: detail.into(),
        }
    }

    /// Create a challenge error
    pub fn challenge<S: Into<String>>(challenge_type: S, error: S) -> Self {
        AcmeError::Challenge {
            challenge_type: challenge_type.into(),
            error: error.into(),
        }
    }

    /// Create a certificate error
    pub fn certificate<S: Into<String>>(msg: S) -> Self {
        AcmeError::Certificate(msg.into())
    }

    /// Create a crypto error
    pub fn crypto<S: Into<String>>(msg: S) -> Self {
        AcmeError::Crypto(msg.into())
    }

    /// Create a storage error
    pub fn storage<S: Into<String>>(msg: S) -> Self {
        AcmeError::Storage(msg.into())
    }

    /// Create a transport error
    pub fn transport<S: Into<String>>(msg: S) -> Self {
        AcmeError::Transport(msg.into())
    }

    /// Create an invalid input error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        AcmeError::InvalidInput(msg.into())
    }

    /// Create a timeout error
    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        AcmeError::Timeout(msg.into())
    }

    /// Create a not found error
    pub fn not_found<S: Into<String>>(msg: S) -> Self {
        AcmeError::NotFound(msg.into())
    }

    /// Create a configuration error
    pub fn configuration<S: Into<String>>(msg: S) -> Self {
        AcmeError::Configuration(msg.into())
    }

    /// Create a PEM error
    pub fn pem<S: Into<String>>(msg: S) -> Self {
        AcmeError::Pem(msg.into())
    }

    /// Convert AcmeError to RFC 7807 ProblemDetails
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            Self::Protocol(d) => ProblemDetails {
                problem_type: "https://acmex.sh/errors/protocol".into(),
                title: "ACME Protocol Error".into(),
                status: 400,
                detail: d.clone(),
                instance: None,
            },
            Self::Account(d) => ProblemDetails {
                problem_type: "https://acmex.sh/errors/account".into(),
                title: "Account Operation Failed".into(),
                status: 403,
                detail: d.clone(),
                instance: None,
            },
            Self::Order { status, detail } => ProblemDetails {
                problem_type: "https://acmex.sh/errors/order".into(),
                title: format!("Order Failed (Status: {})", status),
                status: 400,
                detail: detail.clone(),
                instance: None,
            },
            Self::Storage(d) => ProblemDetails {
                problem_type: "https://acmex.sh/errors/storage".into(),
                title: "Storage Error".into(),
                status: 500,
                detail: d.clone(),
                instance: None,
            },
            Self::Transport(d) => ProblemDetails {
                problem_type: "https://acmex.sh/errors/transport".into(),
                title: "Network Transport Error".into(),
                status: 502,
                detail: d.clone(),
                instance: None,
            },
            _ => ProblemDetails {
                problem_type: "https://acmex.sh/errors/internal".into(),
                title: "Internal Server Error".into(),
                status: 500,
                detail: self.to_string(),
                instance: None,
            },
        }
    }
}

// From trait implementations for error conversion

impl From<std::time::SystemTimeError> for AcmeError {
    fn from(err: std::time::SystemTimeError) -> Self {
        AcmeError::Protocol(format!("SystemTime error: {}", err))
    }
}
