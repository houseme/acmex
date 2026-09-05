use crate::account::{AccountManager, KeyPair};
use crate::domain::{AccountRecord, AccountStatus, KeyAlgorithm, KeyId, KeyRef, TenantId};
use crate::error::{AcmeError, ProblemDetails, Result};
use crate::metrics::AcmeEvent;
use crate::metrics::events::EventAuditor;
use crate::protocol::{DirectoryManager, NonceManager};
use crate::server::api::AppState;
use crate::types::Contact;
use crate::{AcmeClient, AcmeConfig};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct CreateAccountRequest {
    pub email: String,
    pub tos_agreed: bool,
}

#[derive(Debug, Serialize)]
pub struct AccountResponse {
    pub id: String,
    pub status: String,
    pub contact: Vec<String>,
}

pub async fn create_account(
    State(state): State<AppState>,
    Json(payload): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    let (email_hash, email_domain) = redact_email(&payload.email);
    tracing::debug!(
        email_hash = %email_hash,
        email_domain = %email_domain,
        "request to create account"
    );
    if let Some(problem) = validate_account_request(&payload) {
        return problem_response(problem);
    }

    let Some(repositories) = &state.repositories else {
        return problem_response(unavailable_problem(
            "Account repository is not configured".to_string(),
        ));
    };
    let account_id = AccountRecord::compute_id(&TenantId::default_tenant(), &state.config.acme.ca);

    // A stored account that is no longer active must never be reset to
    // active by a re-registration: report the state conflict instead.
    match repositories.accounts.get(&account_id).await {
        Ok(Some(existing)) if existing.value.status != AccountStatus::Active => {
            return problem_response(
                AcmeError::conflict(format!(
                    "account `{}` is {} and cannot be re-registered as active",
                    account_id,
                    account_status_wire(existing.value.status)
                ))
                .to_problem_details(),
            );
        }
        Ok(_) => {}
        Err(err) => return problem_response(err.to_problem_details()),
    }

    let Some(client) = &state.client else {
        return problem_response(unavailable_problem(
            "ACME client not configured on server".to_string(),
        ));
    };

    // Register with the request's contact and ToS answer, reusing the
    // server's account key so later updates sign for the same account.
    // (An owned copy is required here because the registration client
    // outlives the shared client borrow; create is a rare operation.)
    let key_pair = match client_key_pair(client) {
        Ok(key_pair) => key_pair,
        Err(err) => return problem_response(err.to_problem_details()),
    };
    let config = AcmeConfig::new(state.config.acme_directory())
        .with_contact(Contact::email(payload.email.clone()))
        .with_tos_agreed(payload.tos_agreed);
    let mut registration_client = AcmeClient::with_key_pair(config, key_pair);
    let account_url = match registration_client.register_account().await {
        Ok(account_url) => account_url,
        Err(err) => return problem_response(err.to_problem_details()),
    };
    let key_ref = match legacy_key_ref(client) {
        Ok(key_ref) => key_ref,
        Err(err) => return problem_response(err.to_problem_details()),
    };

    let now = repositories.clock.now();
    let record = AccountRecord {
        id: account_id,
        tenant_id: TenantId::default_tenant(),
        ca_id: state.config.acme.ca.clone(),
        directory_url: state.config.acme_directory().to_string(),
        account_url: Some(account_url),
        key_ref,
        contacts: vec![format!("mailto:{}", payload.email)],
        eab_bound: false,
        status: AccountStatus::Active,
        created_at: now,
        updated_at: now,
    };
    if let Err(err) = repositories.accounts.upsert(record.clone()).await {
        return problem_response(err.to_problem_details());
    }

    EventAuditor::track_event(AcmeEvent::AccountCreated {
        email: payload.email,
    });

    (
        StatusCode::CREATED,
        Json(AccountResponse::from_record(&record)),
    )
        .into_response()
}

pub async fn get_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(repositories) = &state.repositories else {
        return problem_response(unavailable_problem(
            "Account repository is not configured".to_string(),
        ));
    };
    match repositories.accounts.get(&id).await {
        Ok(Some(stored)) => Json(AccountResponse::from_record(&stored.value)).into_response(),
        Ok(None) => problem_response(not_found_problem(format!("No account found with ID: {id}"))),
        Err(err) => problem_response(err.to_problem_details()),
    }
}

pub async fn update_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(payload): Json<CreateAccountRequest>,
) -> impl IntoResponse {
    info!("Request to update account {}", id);
    if let Some(problem) = validate_account_request(&payload) {
        return problem_response(problem);
    }

    let Some(repositories) = &state.repositories else {
        return problem_response(unavailable_problem(
            "Account repository is not configured".to_string(),
        ));
    };
    let stored = match repositories.accounts.get(&id).await {
        Ok(Some(stored)) => stored.value,
        Ok(None) => {
            return problem_response(not_found_problem(format!("No account found with ID: {id}")));
        }
        Err(err) => return problem_response(err.to_problem_details()),
    };
    let Some(account_url) = stored.account_url.clone() else {
        return problem_response(bad_request_problem(format!(
            "Account {id} has not been registered with the CA yet"
        )));
    };
    let Some(client) = &state.client else {
        return problem_response(unavailable_problem(
            "ACME client not configured on server".to_string(),
        ));
    };
    if let Err(err) = ensure_stored_key_matches_client(client, &stored) {
        return problem_response(err.to_problem_details());
    }

    let contacts = vec![Contact::email(payload.email.clone())];
    if let Err(err) = perform_account_operation(
        state.config.acme_directory(),
        client,
        &account_url,
        AccountOperation::UpdateContacts(contacts),
    )
    .await
    {
        return problem_response(err.to_problem_details());
    }

    let mut record = stored;
    record.contacts = vec![format!("mailto:{}", payload.email)];
    record.updated_at = repositories.clock.now();
    if let Err(err) = repositories.accounts.upsert(record.clone()).await {
        return problem_response(err.to_problem_details());
    }
    Json(AccountResponse::from_record(&record)).into_response()
}

pub async fn deactivate_account(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let Some(repositories) = &state.repositories else {
        return problem_response(unavailable_problem(
            "Account repository is not configured".to_string(),
        ));
    };
    let stored = match repositories.accounts.get(&id).await {
        Ok(Some(stored)) => stored.value,
        Ok(None) => {
            return problem_response(not_found_problem(format!("No account found with ID: {id}")));
        }
        Err(err) => return problem_response(err.to_problem_details()),
    };
    let Some(account_url) = stored.account_url.clone() else {
        return problem_response(bad_request_problem(format!(
            "Account {id} has not been registered with the CA yet"
        )));
    };
    let Some(client) = &state.client else {
        return problem_response(unavailable_problem(
            "ACME client not configured on server".to_string(),
        ));
    };
    if let Err(err) = ensure_stored_key_matches_client(client, &stored) {
        return problem_response(err.to_problem_details());
    }

    if let Err(err) = perform_account_operation(
        state.config.acme_directory(),
        client,
        &account_url,
        AccountOperation::Deactivate,
    )
    .await
    {
        return problem_response(err.to_problem_details());
    }

    let mut record = stored;
    record.status = AccountStatus::Deactivated;
    record.updated_at = repositories.clock.now();
    if let Err(err) = repositories.accounts.upsert(record).await {
        return problem_response(err.to_problem_details());
    }
    StatusCode::NO_CONTENT.into_response()
}

/// Remote account operation performed through the legacy client.
enum AccountOperation {
    UpdateContacts(Vec<Contact>),
    Deactivate,
}

/// Shared HTTP client for CA round-trips: building a fresh client per request
/// re-did the TLS/connection-pool setup every time and had no timeouts. One
/// client with connect + whole-request timeouts is created lazily and reused.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Calls the CA for an account operation, signing with the legacy account
/// key. The HTTP client is shared across requests (see [`http_client`]); the
/// transport managers borrow it and the key, so they cannot outlive this call.
async fn perform_account_operation(
    directory_url: &str,
    client: &AcmeClient,
    account_url: &str,
    operation: AccountOperation,
) -> Result<()> {
    // The client already holds a parsed key pair: borrow it instead of the
    // per-request PEM serialize + re-parse round trip.
    let key_pair = client.key_pair();
    let http_client = http_client().clone();
    let directory_manager = DirectoryManager::new(directory_url, http_client.clone());
    let directory = directory_manager.get().await?;
    let nonce_manager = NonceManager::new(&directory.new_nonce, http_client.clone());
    let account_manager =
        AccountManager::new(key_pair, &nonce_manager, &directory_manager, &http_client)?;
    match operation {
        AccountOperation::UpdateContacts(contacts) => {
            account_manager
                .update_contacts(account_url, contacts)
                .await?;
        }
        AccountOperation::Deactivate => {
            account_manager.deactivate(account_url).await?;
        }
    }
    Ok(())
}

/// Ensures the stored account was registered with the server's current key.
/// Signing an update/deactivate with a different key is rejected by the CA
/// anyway, so fail fast with an operator-actionable error instead of sending
/// a request that cannot succeed.
fn ensure_stored_key_matches_client(client: &AcmeClient, stored: &AccountRecord) -> Result<()> {
    let expected = legacy_key_ref(client)?;
    if stored.key_ref.provider != expected.provider || stored.key_ref.key_id != expected.key_id {
        return Err(AcmeError::configuration(format!(
            "stored account `{}` is registered under key `{}` but the server signs with `{}`; \
             re-register the account or restore the original server key",
            stored.id, stored.key_ref.key_id, expected.key_id
        )));
    }
    Ok(())
}

/// Redacts an email address for logging: only a short hash of the full
/// address and the domain part are kept.
fn redact_email(email: &str) -> (String, String) {
    let trimmed = email.trim();
    let digest = Sha256::digest(trimmed.as_bytes());
    let hash = hex::encode(&digest[..6]);
    let domain = trimmed.rsplit('@').next().unwrap_or("invalid").to_string();
    (hash, domain)
}

/// Validates the contact/ToS payload shared by create and update.
fn validate_account_request(payload: &CreateAccountRequest) -> Option<ProblemDetails> {
    if !payload.tos_agreed {
        return Some(bad_request_problem(
            "terms of service must be agreed before account operations".to_string(),
        ));
    }
    let email = payload.email.trim();
    if email.is_empty() || !email.contains('@') {
        return Some(bad_request_problem(format!(
            "invalid contact email: `{}`",
            payload.email
        )));
    }
    None
}

/// Wire status for a stored account, mirroring RFC 8555 vocabulary.
fn account_status_wire(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "valid",
        AccountStatus::Deactivated => "deactivated",
        AccountStatus::Revoked => "revoked",
    }
}

impl AccountResponse {
    fn from_record(record: &AccountRecord) -> Self {
        Self {
            id: record.id.clone(),
            status: account_status_wire(record.status).to_string(),
            contact: record.contacts.clone(),
        }
    }
}

/// Rebuilds the legacy client's account key pair so registration and later
/// account operations sign with the same identity.
fn client_key_pair(client: &AcmeClient) -> Result<KeyPair> {
    KeyPair::from_pem(&client.key_pair().serialize_pem())
}

/// Deterministic key reference for the legacy client's in-memory account key.
/// Only the fingerprint is stored, never key material.
fn legacy_key_ref(client: &AcmeClient) -> Result<KeyRef> {
    let digest = Sha256::digest(client.key_pair().public_key_bytes());
    Ok(KeyRef {
        provider: "legacy-client".to_string(),
        key_id: KeyId::new(format!("legacy-{}", hex::encode(&digest[..8])))?,
        algorithm: KeyAlgorithm::Ed25519,
        exportable: false,
    })
}

fn problem_response(problem: ProblemDetails) -> Response {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, Json(problem)).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    response
}

fn not_found_problem(detail: String) -> ProblemDetails {
    ProblemDetails {
        problem_type: "https://acmex.sh/errors/not-found".into(),
        title: "Account Not Found".into(),
        status: 404,
        detail,
        instance: None,
    }
}

fn bad_request_problem(detail: String) -> ProblemDetails {
    ProblemDetails {
        problem_type: "https://acmex.sh/errors/invalid-input".into(),
        title: "Invalid Account Request".into(),
        status: 400,
        detail,
        instance: None,
    }
}

fn unavailable_problem(detail: String) -> ProblemDetails {
    ProblemDetails {
        problem_type: "https://acmex.sh/errors/config".into(),
        title: "Server poorly configured".into(),
        status: 503,
        detail,
        instance: None,
    }
}
