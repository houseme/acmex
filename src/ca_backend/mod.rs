//! CA backend: the stable port over any certificate authority.
//!
//! `CaBackend` (see [`backend`]) is the interface the workflow engine and
//! application service use; [`AcmeCaBackend`] implements it for RFC 8555
//! CAs over a shared [`AcmeSession`] with a single JWS execution path
//! (badNonce recovery, Replay-Nonce capture, Retry-After classification).
//! [`ari`] implements RFC 9773 renewal information.
//!
//! All handles are serializable so the durable workflow can persist them
//! and resume orders across restarts.

pub mod ari;
pub mod backend;
pub mod session;
pub mod transport;
pub mod types;

pub use ari::{
    RenewalInfo, SuggestedWindow, ari_cert_id, ari_cert_id_from_pem, leaf_id_components,
    parse_renewal_window, renewal_info_url,
};
pub use backend::{AcmeCaBackend, CaBackend, account_key_id, identifiers_to_wire};
pub use session::{AcmeSession, JwsPayload, SessionAuth, SharedNoncePool};
pub use transport::{
    AcmeMethod, AcmeProblem, AcmeRequest, AcmeResponse, AcmeTransport, FakeAcmeTransport,
    ReqwestAcmeTransport, ScriptedResponse, classify_response, parse_retry_after,
};
pub use types::{
    AccountHandle, AccountRef, AuthorizationRef, AuthorizationResource, CaCapabilities, CaId,
    CaProfile, ChallengeRef, ExternalAccountBindingRef, IssuedChain, OrderHandle, OrderRequest,
    OrderResource, RenewalWindow, RevocationRequest,
};
