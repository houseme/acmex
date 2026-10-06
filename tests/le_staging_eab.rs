//! Controlled EAB CA evidence gate for roadmap T19.
//!
//! This runner is intentionally ignored and reaches a caller-selected public
//! ACME CA only after all of the following are explicit:
//!
//! ```text
//! RUN_LE_STAGING=1
//! ACMEX_LE_STAGING_SCENARIOS=eab-ca
//! ACMEX_EAB_CA_DIRECTORY_URL=https://…/directory
//! ACMEX_EAB_CA_ACCOUNT_EMAIL=acme-test@example.invalid
//! ACMEX_EAB_CA_DOMAIN=acme-test.example.invalid
//! ACMEX_EAB_KEY_ID=<CA issued id>
//! ACMEX_EAB_HMAC_KEY_REF=env:ACMEX_EAB_HMAC_KEY
//! ACMEX_LE_STAGING_ARTIFACT_DIR=target/le-staging/<run>
//! ```
//!
//! The HMAC is resolved only through [`SecretRef`]. Evidence deliberately
//! excludes the contact, key id, secret reference, account URL and order URL.
//! Optional protocol samples are deliberately non-probing: a badNonce sample
//! sends exactly one invalid nonce only with an additional opt-in, and the
//! rate-limit sample performs one GET of an operator-supplied URL that is
//! already expected to return `429`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use acmex::account::KeyPair;
use acmex::ca_backend::{
    AccountRef, AcmeCaBackend, AcmeMethod, AcmeRequest, AcmeSession, AcmeTransport, CaBackend,
    ExternalAccountBindingRef, OrderRequest, ReqwestAcmeTransport, SessionAuth, classify_status,
};
use acmex::dns::spec::SecretRef;
use acmex::domain::Identifier;
use acmex::protocol::{Jwk, JwsSigner};
use acmex::repository::MemoryRepository;
use serde_json::json;

const EAB_SCENARIO: &str = "eab-ca";
const REQUIRED_ENV: &[&str] = &[
    "ACMEX_EAB_CA_DIRECTORY_URL",
    "ACMEX_EAB_CA_ACCOUNT_EMAIL",
    "ACMEX_EAB_CA_DOMAIN",
    "ACMEX_EAB_KEY_ID",
    "ACMEX_EAB_HMAC_KEY_REF",
    "ACMEX_LE_STAGING_ARTIFACT_DIR",
];

#[derive(Clone, Debug)]
struct LiveEabConfig {
    directory_url: String,
    directory_origin: String,
    account_email: String,
    order_domain: String,
    binding: ExternalAccountBindingRef,
    artifact_dir: PathBuf,
    run_bad_nonce_sample: bool,
    rate_limit_sample_url: Option<String>,
}

impl LiveEabConfig {
    fn from_env() -> Result<Self, Vec<String>> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    fn from_values(get: impl Fn(&str) -> Option<String>) -> Result<Self, Vec<String>> {
        let missing = REQUIRED_ENV
            .iter()
            .filter(|name| get(name).is_none_or(|value| value.trim().is_empty()))
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>();

        if !missing.is_empty() {
            return Err(missing);
        }

        let directory_url =
            get("ACMEX_EAB_CA_DIRECTORY_URL").expect("required EAB CA directory was checked above");
        let directory_origin = safe_origin(&directory_url).map_err(|_| {
            vec![
                "ACMEX_EAB_CA_DIRECTORY_URL must be an absolute http(s) URL without user info"
                    .to_string(),
            ]
        })?;
        let hmac_ref =
            get("ACMEX_EAB_HMAC_KEY_REF").expect("required EAB HMAC reference was checked above");
        let hmac_key = SecretRef::parse(&hmac_ref).map_err(|_| {
            vec![
                "ACMEX_EAB_HMAC_KEY_REF must be a SecretRef (for example env:NAME or file:/path)"
                    .to_string(),
            ]
        })?;
        let rate_limit_sample_url =
            get("ACMEX_EAB_CA_RATE_LIMIT_SAMPLE_URL").filter(|value| !value.trim().is_empty());
        if let Some(sample_url) = &rate_limit_sample_url {
            let sample_origin = safe_origin(sample_url).map_err(|_| {
                vec![
                    "ACMEX_EAB_CA_RATE_LIMIT_SAMPLE_URL must be an absolute http(s) URL without user info"
                        .to_string(),
                ]
            })?;
            if sample_origin != directory_origin {
                return Err(vec![
                    "ACMEX_EAB_CA_RATE_LIMIT_SAMPLE_URL must belong to the configured EAB CA origin"
                        .to_string(),
                ]);
            }
        }

        Ok(Self {
            directory_url,
            directory_origin,
            account_email: get("ACMEX_EAB_CA_ACCOUNT_EMAIL")
                .expect("required EAB CA account email was checked above"),
            order_domain: get("ACMEX_EAB_CA_DOMAIN")
                .expect("required EAB CA order domain was checked above"),
            binding: ExternalAccountBindingRef {
                key_id: get("ACMEX_EAB_KEY_ID").expect("required EAB key id was checked above"),
                hmac_key,
            },
            artifact_dir: PathBuf::from(
                get("ACMEX_LE_STAGING_ARTIFACT_DIR")
                    .expect("required artifact directory was checked above"),
            ),
            run_bad_nonce_sample: get("ACMEX_EAB_CA_ALLOW_BAD_NONCE_SAMPLE").as_deref()
                == Some("1"),
            rate_limit_sample_url,
        })
    }

    fn safe_manifest(
        &self,
        requires_eab: bool,
        bad_nonce: serde_json::Value,
        rate_limit: serde_json::Value,
    ) -> serde_json::Value {
        json!({
            "scenario": EAB_SCENARIO,
            "recorded_at": jiff::Timestamp::now().to_string(),
            "directory_origin": self.directory_origin,
            "directory_advertises_eab_required": requires_eab,
            "eab_secret_reference_scheme": secret_ref_scheme(&self.binding.hmac_key),
            "registration": { "attempted": true, "succeeded": true },
            "new_order": { "attempted": true, "succeeded": true },
            "bad_nonce_sample": bad_nonce,
            "rate_limit_sample": rate_limit,
            "private_material_recorded": false,
            "external_resource_urls_recorded": false,
        })
    }
}

fn safe_origin(value: &str) -> Result<String, ()> {
    let (scheme, remainder) = value.split_once("://").ok_or(())?;
    if !matches!(scheme, "http" | "https") {
        return Err(());
    }
    let authority = remainder.split('/').next().ok_or(())?;
    if authority.is_empty()
        || authority.contains('@')
        || authority.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(());
    }
    Ok(format!("{scheme}://{}", authority.to_ascii_lowercase()))
}

fn secret_ref_scheme(reference: &SecretRef) -> &'static str {
    match reference {
        SecretRef::Env { .. } => "env",
        SecretRef::File { .. } => "file",
        SecretRef::Vault { .. } => "vault",
        SecretRef::ProviderSpecific { .. } => "provider",
    }
}

fn eab_scenario_selected() -> bool {
    if std::env::var("RUN_LE_STAGING").as_deref() != Ok("1") {
        return false;
    }
    std::env::var("ACMEX_LE_STAGING_SCENARIOS")
        .unwrap_or_else(|_| "all".to_string())
        .split(',')
        .map(str::trim)
        .any(|scenario| scenario == "all" || scenario == EAB_SCENARIO)
}

async fn sample_bad_nonce(
    directory_url: &str,
    transport: Arc<dyn AcmeTransport>,
) -> Result<serde_json::Value, String> {
    let key = Arc::new(
        KeyPair::generate().map_err(|_| "could not generate sample account key".to_string())?,
    );
    let session = AcmeSession::new(
        "eab-ca-bad-nonce-sample",
        directory_url,
        SessionAuth::key_only(key.clone()),
        transport.clone(),
    );
    let directory = session
        .directory()
        .await
        .map_err(|_| "could not discover the EAB CA directory for badNonce sampling".to_string())?;
    let signer = JwsSigner::new(&key.0);
    let new_account_url = directory.new_account;
    let header = json!({
        "alg": signer.jwa_algorithm().map_err(|_| "could not choose the sample JWS algorithm".to_string())?,
        "jwk": Jwk::for_key_pair(signer.key_pair()).map_err(|_| "could not derive the sample JWK".to_string())?.to_value(),
        "nonce": "acmex-intentionally-invalid-nonce",
        "url": new_account_url,
    });
    let body = signer
        .sign(&header, &json!({ "termsOfServiceAgreed": true }))
        .map_err(|_| "could not sign the badNonce sample".to_string())?;
    let response = transport
        .request(AcmeRequest {
            url: new_account_url,
            method: AcmeMethod::Post,
            body: Some(body.into_bytes()),
        })
        .await
        .map_err(|_| "badNonce sample request could not reach the configured CA".to_string())?;
    if response.status != 400 || !response.is_bad_nonce() || response.replay_nonce.is_none() {
        return Err(
            "configured CA did not return the expected badNonce response with Replay-Nonce"
                .to_string(),
        );
    }
    Ok(json!({
        "performed": true,
        "http_status": response.status,
        "problem_type": "badNonce",
        "replay_nonce_present": true,
        "request_count": 1,
    }))
}

async fn sample_rate_limit(
    sample_url: Option<&str>,
    transport: Arc<dyn AcmeTransport>,
) -> Result<serde_json::Value, String> {
    let Some(sample_url) = sample_url else {
        return Ok(json!({
            "performed": false,
            "reason": "ACMEX_EAB_CA_RATE_LIMIT_SAMPLE_URL not configured; no rate-limit probe was sent",
        }));
    };
    let response = transport
        .request(AcmeRequest {
            url: sample_url.to_string(),
            method: AcmeMethod::Get,
            body: None,
        })
        .await
        .map_err(|_| "rate-limit sample request could not reach the configured CA".to_string())?;
    if response.status != 429
        || response.retry_after.is_none()
        || classify_status(&response).is_ok()
    {
        return Err(
            "configured rate-limit sample did not return classified 429 with Retry-After"
                .to_string(),
        );
    }
    Ok(json!({
        "performed": true,
        "http_status": response.status,
        "retry_after_present": true,
        "request_count": 1,
    }))
}

#[test]
fn eab_live_config_requires_secret_ref_and_all_explicit_inputs() {
    let error = LiveEabConfig::from_values(|_| None).expect_err("missing config must be rejected");
    assert_eq!(
        error,
        REQUIRED_ENV
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>()
    );

    let values = BTreeMap::from([
        (
            "ACMEX_EAB_CA_DIRECTORY_URL",
            "https://ca.example.test/acme/directory",
        ),
        ("ACMEX_EAB_CA_ACCOUNT_EMAIL", "staging-contact@example.test"),
        ("ACMEX_EAB_CA_DOMAIN", "acme-test.example.test"),
        ("ACMEX_EAB_KEY_ID", "eab-key-id"),
        ("ACMEX_EAB_HMAC_KEY_REF", "not-a-secret-ref"),
        ("ACMEX_LE_STAGING_ARTIFACT_DIR", "target/test-evidence"),
    ]);
    let error =
        LiveEabConfig::from_values(|name| values.get(name).map(|value| (*value).to_string()))
            .expect_err("literal EAB material must not be accepted");
    assert_eq!(
        error,
        vec!["ACMEX_EAB_HMAC_KEY_REF must be a SecretRef (for example env:NAME or file:/path)"]
    );
}

#[test]
fn eab_evidence_manifest_has_no_contact_binding_or_external_resource_identifiers() {
    let values = BTreeMap::from([
        (
            "ACMEX_EAB_CA_DIRECTORY_URL",
            "https://ca.example.test/acme/directory",
        ),
        ("ACMEX_EAB_CA_ACCOUNT_EMAIL", "staging-contact@example.test"),
        ("ACMEX_EAB_CA_DOMAIN", "acme-test.example.test"),
        ("ACMEX_EAB_KEY_ID", "eab-key-id"),
        ("ACMEX_EAB_HMAC_KEY_REF", "env:ACMEX_EAB_HMAC"),
        ("ACMEX_LE_STAGING_ARTIFACT_DIR", "target/test-evidence"),
    ]);
    let config =
        LiveEabConfig::from_values(|name| values.get(name).map(|value| (*value).to_string()))
            .expect("complete safe config");
    let manifest = config.safe_manifest(
        true,
        json!({ "performed": false, "reason": "not opted in" }),
        json!({ "performed": false, "reason": "not configured" }),
    );
    let text = serde_json::to_string(&manifest).expect("manifest JSON");
    for forbidden in [
        "staging-contact@example.test",
        "acme-test.example.test",
        "eab-key-id",
        "ACMEX_EAB_HMAC",
        "/acme/directory",
    ] {
        assert!(
            !text.contains(forbidden),
            "safe evidence must omit {forbidden}"
        );
    }
    assert!(text.contains("https://ca.example.test"));
}

#[tokio::test]
#[ignore = "talks to a caller-selected EAB CA; requires RUN_LE_STAGING=1 and eab-ca assets"]
async fn eab_ca_registration_new_order_and_protocol_samples_live() {
    if !eab_scenario_selected() {
        panic!(
            "EAB CA evidence runner requires RUN_LE_STAGING=1 and eab-ca in ACMEX_LE_STAGING_SCENARIOS; no evidence was collected"
        );
    }

    let config = LiveEabConfig::from_env().unwrap_or_else(|problems| {
        panic!(
            "EAB CA evidence was requested but is not configured: {}; no evidence was collected",
            problems.join(", ")
        )
    });
    let identifiers = vec![
        Identifier::try_dns(&config.order_domain)
            .expect("ACMEX_EAB_CA_DOMAIN must be a valid DNS identifier"),
    ];
    std::fs::create_dir_all(&config.artifact_dir)
        .expect("create configured EAB evidence directory");

    let account_key = Arc::new(KeyPair::generate().expect("generate ephemeral EAB account key"));
    let transport: Arc<dyn AcmeTransport> = Arc::new(ReqwestAcmeTransport::new());
    let repositories = MemoryRepository::new().into_set();
    let backend: Arc<dyn CaBackend> = Arc::new(AcmeCaBackend::new(
        "t19-eab-ca",
        config.directory_url.clone(),
        transport.clone(),
        account_key,
        repositories,
    ));

    let capabilities = backend
        .capabilities()
        .await
        .expect("discover EAB CA capabilities");
    assert!(
        capabilities.requires_eab,
        "configured EAB CA directory must advertise externalAccountRequired=true"
    );
    let account = backend
        .ensure_account(&AccountRef {
            tenant_id: "t19-eab-live".to_string(),
            contacts: vec![format!("mailto:{}", config.account_email)],
            terms_of_service_agreed: true,
            external_account_binding: Some(config.binding.clone()),
        })
        .await
        .expect("register an EAB-bound account");
    let order = backend
        .create_order(&account, &OrderRequest::for_identifiers(identifiers))
        .await
        .expect("create a real EAB CA order");
    let _ = order;

    let bad_nonce = if config.run_bad_nonce_sample {
        sample_bad_nonce(&config.directory_url, transport.clone())
            .await
            .expect("one opted-in badNonce sample")
    } else {
        json!({
            "performed": false,
            "reason": "ACMEX_EAB_CA_ALLOW_BAD_NONCE_SAMPLE=1 not set; no invalid-nonce request was sent",
        })
    };
    let rate_limit = sample_rate_limit(config.rate_limit_sample_url.as_deref(), transport)
        .await
        .expect("at most one supplied rate-limit sample");
    let manifest = config.safe_manifest(capabilities.requires_eab, bad_nonce, rate_limit);
    std::fs::write(
        config.artifact_dir.join("eab-ca-manifest.json"),
        serde_json::to_vec_pretty(&manifest).expect("serialize safe EAB evidence"),
    )
    .expect("write safe EAB evidence");
    println!(
        "EAB CA registration and newOrder evidence archived without credentials or resource URLs"
    );
}
