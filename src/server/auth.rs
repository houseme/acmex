use crate::server::api::AppState;
use crate::{
    application::{ActorContext, Permission},
    domain::TenantId,
};
use axum::{
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use jiff::Timestamp;
use sha2::{Digest, Sha256};
use tracing::Instrument;

const SHA256_LEN: usize = 32;

/// Runtime status of a management API key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStatus {
    Active,
    Disabled,
}

/// API-key configuration after plaintext has been hashed.
#[derive(Clone)]
pub struct ApiKeyCredential {
    pub key_id: String,
    pub tenant_id: TenantId,
    pub digest: [u8; SHA256_LEN],
    pub status: ApiKeyStatus,
    pub expires_at: Option<Timestamp>,
    pub rotation_not_after: Option<Timestamp>,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
}

impl ApiKeyCredential {
    /// Builds a credential while keeping plaintext at the call boundary.
    pub fn from_plaintext(
        key_id: impl Into<String>,
        tenant_id: TenantId,
        plaintext: &str,
        permissions: Vec<Permission>,
    ) -> Option<Self> {
        let plaintext = plaintext.trim();
        if plaintext.is_empty() {
            return None;
        }
        let roles = if permissions.contains(&Permission::Admin) {
            vec!["admin".to_string()]
        } else {
            vec!["api".to_string()]
        };
        Some(Self {
            key_id: key_id.into(),
            tenant_id,
            digest: digest_api_key(plaintext),
            status: ApiKeyStatus::Active,
            expires_at: None,
            rotation_not_after: None,
            roles,
            permissions,
        })
    }

    fn accepts_at(&self, now: Timestamp) -> bool {
        if self.status != ApiKeyStatus::Active {
            return false;
        }
        match (self.expires_at, self.rotation_not_after) {
            (Some(expires_at), Some(rotation_not_after)) => {
                now < expires_at || now < rotation_not_after
            }
            (Some(expires_at), None) => now < expires_at,
            (None, Some(rotation_not_after)) => now < rotation_not_after,
            (None, None) => true,
        }
    }
}

impl std::fmt::Debug for ApiKeyCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyCredential")
            .field("key_id", &self.key_id)
            .field("tenant_id", &self.tenant_id)
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("rotation_not_after", &self.rotation_not_after)
            .field("roles", &self.roles)
            .field("permissions", &self.permissions)
            .finish_non_exhaustive()
    }
}

/// Hashed API key set used by management API authentication.
#[derive(Clone, Default)]
pub struct ApiKeySet {
    credentials: Vec<ApiKeyCredential>,
}

impl ApiKeySet {
    /// Creates a key set from plaintext configuration values.
    pub fn from_plaintext_keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let credentials = keys
            .into_iter()
            .enumerate()
            .filter_map(|(idx, key)| {
                ApiKeyCredential::from_plaintext(
                    format!("env-key-{idx}"),
                    TenantId::default_tenant(),
                    key.as_ref(),
                    Permission::admin_set(),
                )
            })
            .collect();

        Self { credentials }
    }

    pub fn from_credentials(credentials: Vec<ApiKeyCredential>) -> Self {
        Self { credentials }
    }

    /// Returns true when no management API credential is configured.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Verifies a presented key without storing plaintext secrets in memory.
    pub fn verify(&self, presented: &str) -> bool {
        self.authenticate(presented, None, None).is_some()
    }

    /// Verifies and returns an actor context for authorized requests.
    pub fn authenticate(
        &self,
        presented: &str,
        request_id: Option<String>,
        source: Option<String>,
    ) -> Option<ActorContext> {
        if self.credentials.is_empty() {
            return None;
        }

        let presented_digest = digest_api_key(presented);
        let now = Timestamp::now();
        let mut selected = None;
        let mut matched_any = 0u8;
        for credential in &self.credentials {
            let matched = constant_time_eq(&credential.digest, &presented_digest);
            matched_any |= matched;
            if matched == 1 && credential.accepts_at(now) {
                selected = Some(credential);
            }
        }

        let credential = selected?;
        (matched_any == 1).then(|| {
            ActorContext::new(
                credential.tenant_id.clone(),
                format!("api-key:{}", credential.key_id),
                credential.roles.clone(),
                credential.permissions.clone(),
                request_id,
                source,
            )
        })
    }
}

impl std::fmt::Debug for ApiKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeySet")
            .field("configured_keys", &self.credentials.len())
            .finish()
    }
}

fn digest_api_key(key: &str) -> [u8; SHA256_LEN] {
    Sha256::digest(key.as_bytes()).into()
}

fn constant_time_eq(a: &[u8; SHA256_LEN], b: &[u8; SHA256_LEN]) -> u8 {
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    u8::from(diff == 0)
}

/// Pluggable authentication boundary for future mTLS/OIDC integrations.
pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: &Request, presented_secret: &str) -> Option<ActorContext>;
}

impl Authenticator for ApiKeySet {
    fn authenticate(&self, request: &Request, presented_secret: &str) -> Option<ActorContext> {
        self.authenticate(
            presented_secret,
            request_id(request),
            request
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|value| value.chars().take(128).collect()),
        )
    }
}

/// Pluggable authorization boundary.
pub trait Authorizer: Send + Sync {
    fn authorize(&self, actor: &ActorContext, permission: Permission) -> bool;
}

#[derive(Debug, Clone, Default)]
pub struct PermissionAuthorizer;

impl Authorizer for PermissionAuthorizer {
    fn authorize(&self, actor: &ActorContext, permission: Permission) -> bool {
        actor.has_permission(permission)
    }
}

pub fn required_permission(method: &Method, path: &str) -> Permission {
    if path.contains("/chain") && *method == Method::GET {
        return Permission::IntentRead;
    }
    // Challenge inspection (T05) is token-safe operational read state and
    // shares the read tier with intents and operations.
    if path.contains("/challenges")
        || (path.contains("/challenge-cleanup") && *method == Method::GET)
    {
        return Permission::IntentRead;
    }
    // Manual cleanup retry is an operator remediation that can drive
    // external infrastructure changes on the scanner's next pass — it is
    // not a certificate-intent mutation — so it requires the admin tier
    // instead of `intent.write`; read-only keys are rejected with 403.
    if path.contains("/challenge-cleanup") && *method == Method::POST {
        return Permission::Admin;
    }
    if path.contains("/issue") {
        return Permission::Issue;
    }
    if path.contains("/renew") || path.contains("renew-all") {
        return Permission::Renew;
    }
    if path.contains("/revoke") {
        return Permission::Revoke;
    }
    if path.contains("/deploy") {
        return Permission::Deploy;
    }
    if path.contains("key") && path.contains("export") {
        return Permission::KeyExport;
    }
    // Intent policy patches (PATCH /certificate-intents/{id}, T08) mutate
    // the intent aggregate in place and stay in the intent.write tier with
    // the other intent mutations; the method-based fallback below would
    // map them the same way, this keeps the tier explicit.
    if path.contains("/certificate-intents") && *method == Method::PATCH {
        return Permission::IntentWrite;
    }
    match *method {
        Method::GET => Permission::IntentRead,
        Method::POST | Method::PATCH | Method::PUT | Method::DELETE => Permission::IntentWrite,
        _ => Permission::Admin,
    }
}

fn request_id(req: &Request) -> Option<String> {
    req.headers()
        .get("x-request-id")
        .and_then(|h| h.to_str().ok())
        .map(|value| value.chars().take(128).collect())
}

/// Middleware for API Key authentication
pub async fn api_key_auth(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok());

    match auth_header {
        Some(key) => {
            let Some(actor) =
                <ApiKeySet as Authenticator>::authenticate(state.api_keys.as_ref(), &req, key)
            else {
                tracing::warn!("Unauthorized access attempt to API");
                return Err(StatusCode::UNAUTHORIZED);
            };
            let required = required_permission(req.method(), req.uri().path());
            if !state.authorizer.authorize(&actor, required) {
                tracing::warn!(
                    subject = %actor.subject,
                    required = required.as_str(),
                    "Forbidden management API request"
                );
                return Err(StatusCode::FORBIDDEN);
            }
            let span = tracing::debug_span!(
                "http.request",
                tenant_id = %actor.tenant_id,
                request_id = tracing::field::Empty,
            );
            if let Some(request_id) = actor.request_id.as_deref() {
                span.record("request_id", tracing::field::display(request_id));
            }
            req.extensions_mut().insert(actor);
            Ok(next.run(req).instrument(span).await)
        }
        _ => {
            tracing::warn!("Unauthorized access attempt to API");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiKeyCredential, ApiKeySet, required_permission};
    use crate::{application::Permission, domain::TenantId};
    use axum::http::Method;
    use jiff::Timestamp;
    use std::str::FromStr;

    #[test]
    fn api_key_set_verifies_configured_keys() {
        let keys = ApiKeySet::from_plaintext_keys(["first-key", "second-key"]);

        assert!(keys.verify("first-key"));
        assert!(keys.verify("second-key"));
        assert!(!keys.verify("missing-key"));
    }

    #[test]
    fn api_key_set_filters_empty_config_values() {
        let keys = ApiKeySet::from_plaintext_keys(["", "  ", "real-key"]);

        assert!(!keys.is_empty());
        assert!(keys.verify("real-key"));
        assert!(!keys.verify(""));
    }

    #[test]
    fn api_key_set_debug_does_not_expose_plaintext_or_hashes() {
        let keys = ApiKeySet::from_plaintext_keys(["super-secret-key"]);
        let debug = format!("{keys:?}");

        assert!(debug.contains("configured_keys"));
        assert!(!debug.contains("super-secret-key"));
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn api_key_set_rejects_disabled_and_expired_keys() {
        let mut active = ApiKeyCredential::from_plaintext(
            "old",
            TenantId::default_tenant(),
            "expired-key",
            Permission::admin_set(),
        )
        .unwrap();
        active.expires_at = Some(Timestamp::from_str("2020-01-01T00:00:00Z").unwrap());

        let mut disabled = ApiKeyCredential::from_plaintext(
            "disabled",
            TenantId::default_tenant(),
            "disabled-key",
            Permission::admin_set(),
        )
        .unwrap();
        disabled.status = super::ApiKeyStatus::Disabled;

        let keys = ApiKeySet::from_credentials(vec![active, disabled]);
        assert!(!keys.verify("expired-key"));
        assert!(!keys.verify("disabled-key"));
    }

    #[test]
    fn required_permission_maps_high_risk_routes() {
        assert_eq!(
            required_permission(&Method::POST, "/api/v1/certificate-versions/ver_1/revoke"),
            Permission::Revoke
        );
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/certificate-versions/ver_1/chain"),
            Permission::IntentRead
        );
        assert_eq!(
            required_permission(&Method::POST, "/api/v1/keys/key_1/export"),
            Permission::KeyExport
        );
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/operations/op_1/challenges"),
            Permission::IntentRead
        );
        assert_eq!(
            required_permission(&Method::GET, "/api/v1/challenge-cleanup"),
            Permission::IntentRead
        );
        assert_eq!(
            required_permission(&Method::POST, "/api/v1/challenge-cleanup/chl_1/retry"),
            Permission::Admin
        );
        assert_eq!(
            required_permission(&Method::PATCH, "/api/v1/certificate-intents/int_1"),
            Permission::IntentWrite
        );
    }
}
