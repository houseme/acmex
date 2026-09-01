//! Opaque, unguessable entity identifiers.
//!
//! Each ID is a newtype over a string with a stable prefix (`int_`, `lin_`,
//! ...) so entities cannot be mixed up, plus a random generator producing
//! 128-bit unguessable values suitable for use in public APIs.

use std::fmt;
use std::str::FromStr;

use crate::error::{AcmeError, Result};

macro_rules! entity_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal, $kind:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Generates a fresh unguessable ID.
            pub fn generate() -> Self {
                let bytes: [u8; 16] = rand::random();
                Self(format!("{}{}", $prefix, hex::encode(bytes)))
            }

            /// Creates an ID from an externally supplied string.
            ///
            /// The value must be non-empty and must not contain control
            /// characters or path separators, since IDs are used in storage
            /// keys and URLs.
            pub fn new(value: impl Into<String>) -> Result<Self> {
                let kind = $kind;
                let value = value.into();
                if value.is_empty() {
                    return Err(AcmeError::InvalidInput(format!(
                        "{kind} id must not be empty"
                    )));
                }
                if value
                    .chars()
                    .any(|c| c.is_control() || c == '/' || c == '\\')
                {
                    return Err(AcmeError::InvalidInput(format!(
                        "{kind} id contains forbidden characters: {value:?}"
                    )));
                }
                Ok(Self(value))
            }

            /// The underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = AcmeError;

            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

entity_id!(
    /// Identity of a [`CertificateIntent`](super::CertificateIntent) — the
    /// upstream's desired state for a logical certificate.
    IntentId,
    "int_",
    "intent"
);
entity_id!(
    /// Tenant owning an intent/lineage; `"default"` is used when no tenancy
    /// is configured.
    TenantId,
    "ten_",
    "tenant"
);
entity_id!(
    /// Identity of a logical certificate lineage (one continuously renewed
    /// certificate, many immutable versions).
    LineageId,
    "lin_",
    "lineage"
);
entity_id!(
    /// Identity of an immutable issued certificate version.
    VersionId,
    "ver_",
    "certificate version"
);
entity_id!(
    /// Identity of a durable operation (issue/renew/revoke/deploy/cleanup).
    OperationId,
    "op_",
    "operation"
);
entity_id!(
    /// Identity of a key managed by a KeyProvider.
    KeyId,
    "key_",
    "key"
);
entity_id!(
    /// Identity of a delivery target configured on an intent.
    TargetId,
    "tgt_",
    "delivery target"
);

impl TenantId {
    /// The tenant used when no multi-tenancy is configured.
    pub fn default_tenant() -> Self {
        // Bypasses validation: the constant is known-good.
        Self("ten_default".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_prefixed_and_unique() {
        let a = OperationId::generate();
        let b = OperationId::generate();
        assert!(a.as_str().starts_with("op_"));
        assert_ne!(a, b);
        assert_eq!(a.as_str().len(), 3 + 32);
    }

    #[test]
    fn ids_reject_empty_and_unsafe_values() {
        assert!(IntentId::new("").is_err());
        assert!(IntentId::new("a/b").is_err());
        assert!(IntentId::new("a\\b").is_err());
        assert!(IntentId::new("ok-id").is_ok());
    }

    #[test]
    fn ids_roundtrip_through_json() {
        let id = LineageId::generate();
        let json = serde_json::to_string(&id).unwrap();
        let back: LineageId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
