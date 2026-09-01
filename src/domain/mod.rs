//! Strongly-typed domain model for the certificate lifecycle.
//!
//! This module is the stable domain language introduced by v0.9.0:
//!
//! * [`identifiers`] — validated/normalized DNS (incl. wildcard) and IP
//!   identifiers plus the [`IdentifierSet`] canonical collection;
//! * [`ids`] — unguessable entity identifiers;
//! * [`intent`] — the upstream's desired state ([`CertificateIntent`]);
//! * [`policy`] — CA/validation/key/renewal/delivery policies and the
//!   challenge compatibility matrix;
//! * [`certificate`] — [`CertificateLineage`] and immutable
//!   [`CertificateVersion`] with [`KeyRef`] (never raw key material);
//! * [`operation`] — operation identity/kind vocabulary for the workflow
//!   engine.
//!
//! The domain layer depends only on `serde`, hashing and `std` — never on
//! Axum, Redis, cloud SDKs or `reqwest`.

pub mod certificate;
pub mod identifiers;
pub mod ids;
pub mod intent;
pub mod operation;
pub mod policy;

pub use certificate::{
    CertificateLineage, CertificateVersion, ImportedBundle, KeyRef, VersionState,
};
pub use identifiers::{DnsIdentifier, Identifier, IdentifierError, IdentifierKind, IdentifierSet};
pub use ids::{IntentId, KeyId, LineageId, OperationId, TargetId, TenantId, VersionId};
pub use intent::{CertificateIntent, IntentCreation};
pub use operation::{OperationKind, OperationRef, OperationSubject};
pub use policy::{
    CaEnvironment, CaPolicy, ChallengeExclusion, ChallengeSet, DeliveryRequirement, DeliveryTarget,
    DeliveryTargetKind, ExclusionReason, KeyAlgorithm, KeyManagementMode, KeyPolicy,
    KeyRotationPolicy, PropagationPolicy, Quorum, RenewalPolicy, ValidationPlan,
    ValidationPlanItem, ValidationPolicy, compatible_challenges, validate_order_policy,
};
