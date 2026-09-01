use crate::server::api::AppState;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};

const SHA256_LEN: usize = 32;

/// Hashed API key set used by management API authentication.
#[derive(Clone, Default)]
pub struct ApiKeySet {
    digests: Vec<[u8; SHA256_LEN]>,
}

impl ApiKeySet {
    /// Creates a key set from plaintext configuration values.
    pub fn from_plaintext_keys<I, S>(keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let digests = keys
            .into_iter()
            .filter_map(|key| {
                let key = key.as_ref().trim();
                (!key.is_empty()).then(|| digest_api_key(key))
            })
            .collect();

        Self { digests }
    }

    /// Returns true when no management API credential is configured.
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
    }

    /// Verifies a presented key without storing plaintext secrets in memory.
    pub fn verify(&self, presented: &str) -> bool {
        if self.digests.is_empty() {
            return false;
        }

        let presented_digest = digest_api_key(presented);
        let mut matched = 0u8;
        for expected in &self.digests {
            matched |= constant_time_eq(expected, &presented_digest);
        }

        matched == 1
    }
}

impl std::fmt::Debug for ApiKeySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeySet")
            .field("configured_keys", &self.digests.len())
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

/// Middleware for API Key authentication
pub async fn api_key_auth(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get("X-API-Key").and_then(|h| h.to_str().ok());

    match auth_header {
        Some(key) if state.api_keys.verify(key) => Ok(next.run(req).await),
        _ => {
            tracing::warn!("Unauthorized access attempt to API");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ApiKeySet;

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
}
