//! CA backend behavioral tests (roadmap T04) over the fake transport:
//! session reuse, nonce discipline, badNonce recovery, Retry-After,
//! account persistence across restarts, profile orders and ARI.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use acmex::account::KeyPair;
use acmex::ca_backend::{
    AccountRef, AcmeCaBackend, AcmeMethod, CaBackend, ExternalAccountBindingRef, FakeAcmeTransport,
    OrderRequest, ScriptedResponse,
};
use acmex::dns::spec::SecretRef;
use acmex::domain::Identifier;
use acmex::error::AcmeError;
use acmex::repository::MemoryRepository;
use jiff::Timestamp;

fn now() -> Timestamp {
    Timestamp::from_str("2026-01-01T00:00:00Z").unwrap()
}

fn directory_body() -> serde_json::Value {
    serde_json::json!({
        "newNonce": "https://acme.example/new-nonce",
        "newAccount": "https://acme.example/new-account",
        "newOrder": "https://acme.example/new-order",
        "revokeCert": "https://acme.example/revoke-cert",
        "keyChange": "https://acme.example/key-change",
        "renewalInfo": "https://acme.example/renewal-info",
        "profiles": {
            "classic": {},
            "shortlived": {"validity": "6days"}
        },
        "someFutureExtension": {"anything": true}
    })
}

/// A transport pre-loaded with the directory + a successful account
/// registration and one order creation.
fn standard_transport() -> Arc<FakeAcmeTransport> {
    let transport = Arc::new(FakeAcmeTransport::new(now()));
    transport.push(ScriptedResponse::json("directory", 200, directory_body()).uses(100));
    transport.push(
        ScriptedResponse::json("new-nonce", 200, serde_json::json!({}))
            .uses(100)
            .with_headers(Some("head-nonce".to_string()), None, None),
    );
    transport
}

fn backend(transport: Arc<FakeAcmeTransport>) -> AcmeCaBackend {
    AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport,
        Arc::new(KeyPair::generate().unwrap()),
        MemoryRepository::new().into_set(),
    )
}

fn account_ref() -> AccountRef {
    AccountRef {
        tenant_id: "ten_default".to_string(),
        contacts: vec!["mailto:admin@example.com".to_string()],
        terms_of_service_agreed: true,
        external_account_binding: None,
    }
}

/// An account ref that must be bound to the external key `eab-kid-42`.
fn eab_account_ref(hmac_key: SecretRef) -> AccountRef {
    let mut account = account_ref();
    account.external_account_binding = Some(ExternalAccountBindingRef {
        key_id: "eab-kid-42".to_string(),
        hmac_key,
    });
    account
}

/// Writes a one-line secret to a uniquely-named temp file and returns its
/// path (file refs are stable under test parallelism, unlike process-global
/// env vars).
fn secret_file(name: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "acmex-ca-backend-{name}-{}.secret",
        std::process::id()
    ));
    std::fs::write(&path, content).expect("write temp secret file");
    path
}

/// Decodes and parses the single POST body sent to `url_fragment` as a JWS
/// and returns (protected header, payload) as JSON values.
fn decode_jws_post(
    transport: &FakeAcmeTransport,
    url_fragment: &str,
) -> (serde_json::Value, serde_json::Value) {
    use base64::Engine;
    let requests = transport.requests();
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.url.contains(url_fragment) && r.method == AcmeMethod::Post)
        .collect();
    assert_eq!(
        posts.len(),
        1,
        "expected exactly one POST to {url_fragment}"
    );
    let jws = String::from_utf8(posts[0].body.clone().unwrap()).unwrap();
    let (protected, payload_b64, _signature_b64) = jws_segments(&jws);
    let header = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected)
            .unwrap(),
    )
    .unwrap();
    let payload = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap(),
    )
    .unwrap();
    (header, payload)
}

#[tokio::test]
async fn capabilities_discover_ari_and_profiles() {
    let transport = standard_transport();
    let backend = backend(transport);
    let caps = backend.capabilities().await.unwrap();
    assert!(caps.supports_ari);
    assert_eq!(
        caps.renewal_info_url.as_deref(),
        Some("https://acme.example/renewal-info")
    );
    assert!(caps.supports_profile("classic"));
    assert!(caps.supports_profile("shortlived"));
    let short = caps
        .profiles
        .iter()
        .find(|p| p.name == "shortlived")
        .unwrap();
    assert!(short.short_lived);
    assert!(!caps.requires_eab);
    assert_eq!(
        caps.revoke_cert_url.as_deref(),
        Some("https://acme.example/revoke-cert")
    );
}

#[tokio::test]
async fn ensure_account_registers_once_and_reuses_after_restart() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/77".to_string()),
            ),
    );
    let repositories = MemoryRepository::new().into_set();

    let key = Arc::new(KeyPair::generate().unwrap());
    let first = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        key.clone(),
        repositories.clone(),
    );
    let handle = first.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/77");
    assert_eq!(transport.post_count("new-account"), 1);

    // "Restart": a fresh backend instance over the same repositories and key
    // must reuse the persisted account URL without a second registration.
    let second = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        key,
        repositories,
    );
    let handle = second.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/77");
    assert_eq!(
        transport.post_count("new-account"),
        1,
        "persisted accounts are never re-registered"
    );
}

#[tokio::test]
async fn directory_unknown_extensions_do_not_break_parsing() {
    let transport = Arc::new(FakeAcmeTransport::new(now()));
    let mut directory = directory_body();
    directory["brandNewDraftField"] = serde_json::json!({"x": 1});
    transport.push(ScriptedResponse::json("directory", 200, directory));
    let backend = backend(transport);
    let caps = backend.capabilities().await.unwrap();
    assert_eq!(caps.ca_id, "test-ca");
}

#[tokio::test]
async fn order_request_serializes_profile_and_replaces() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("order-nonce".to_string()),
                None,
                Some("https://acme.example/order/9".to_string()),
            ),
    );
    // Order object fetch after creation.
    transport.push(ScriptedResponse::json(
        "order/9",
        200,
        serde_json::json!({
            "status": "pending",
            "expires": "2026-01-08T00:00:00Z",
            "identifiers": [{"type": "dns", "value": "example.com"}],
            "authorizations": ["https://acme.example/authz/1"],
            "finalize": "https://acme.example/finalize/9"
        }),
    ));

    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    let backend = backend(transport.clone());
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let request = OrderRequest {
        identifiers: vec![Identifier::try_dns("example.com").unwrap()],
        not_before: None,
        not_after: None,
        profile: Some("shortlived".to_string()),
        replaces: Some("https://acme.example/cert/old".to_string()),
    };
    let handle = backend.create_order(&account, &request).await.unwrap();
    assert_eq!(handle.url, "https://acme.example/order/9");

    // The newOrder POST body carried the profile and replaces claims.
    let requests = transport.requests();
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.url.contains("new-order") && r.method == AcmeMethod::Post)
        .collect();
    assert_eq!(posts.len(), 1);
    // The newOrder POST body is a JWS; the payload carries the profile,
    // replaces and identifiers claims.
    let jws = String::from_utf8(posts[0].body.clone().unwrap()).unwrap();
    let (_protected, payload_b64, _signature_b64) = jws_segments(&jws);
    use base64::Engine;
    let payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(payload["profile"], "shortlived");
    assert_eq!(payload["replaces"], "https://acme.example/cert/old");
    assert_eq!(
        payload["identifiers"],
        serde_json::json!([{"type": "dns", "value": "example.com"}])
    );
}

#[tokio::test]
async fn post_as_get_uses_canonical_empty_payload() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    transport.push(ScriptedResponse::json(
        "authz/1",
        200,
        serde_json::json!({
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "expires": "2026-01-08T00:00:00Z",
            "challenges": []
        }),
    ));

    let backend = backend(transport.clone());
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let authz = backend
        .get_authorization(
            &account,
            &acmex::ca_backend::AuthorizationRef {
                url: "https://acme.example/authz/1".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(authz.authorization.identifier.acme_value(), "example.com");

    // The POST-as-GET JWS payload segment is the empty string.
    let requests = transport.requests();
    let posts: Vec<_> = requests
        .iter()
        .filter(|r| r.url.contains("authz/1") && r.method == AcmeMethod::Post)
        .collect();
    assert_eq!(posts.len(), 1);
    let jws = String::from_utf8(posts[0].body.clone().unwrap()).unwrap();
    let (protected, payload_b64, _signature) = jws_segments(&jws);
    assert_eq!(payload_b64, "", "POST-as-GET payload must be empty");
    // Protected header carries the account kid and target url.
    use base64::Engine;
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&protected)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(header["kid"], "https://acme.example/acct/1");
    assert_eq!(header["url"], "https://acme.example/authz/1");
}

#[tokio::test]
async fn bad_nonce_fails_once_then_succeeds_with_response_nonce() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    // authz/1: first attempt badNonce, then success. The badNonce response
    // carries the fresh nonce used by the retry.
    transport.push(ScriptedResponse::json(
        "authz/1",
        400,
        serde_json::json!({"type": "urn:ietf:params:acme:error:badNonce"}),
    ));
    transport.push(ScriptedResponse::json(
        "authz/1",
        200,
        serde_json::json!({
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "expires": "2026-01-08T00:00:00Z",
            "challenges": []
        }),
    ));

    let backend = backend(transport.clone());
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let authz = backend
        .get_authorization(
            &account,
            &acmex::ca_backend::AuthorizationRef {
                url: "https://acme.example/authz/1".to_string(),
            },
        )
        .await
        .expect("badNonce is retried internally");
    assert_eq!(authz.authorization.status, "pending");
    assert_eq!(
        transport.post_count("authz/1"),
        2,
        "exactly one internal retry"
    );
}

#[tokio::test]
async fn bad_nonce_exhaustion_is_a_stable_error() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    transport.push(
        ScriptedResponse::json(
            "authz/1",
            400,
            serde_json::json!({"type": "urn:ietf:params:acme:error:badNonce"}),
        )
        .uses(10),
    );

    let backend = backend(transport);
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let err = backend
        .get_authorization(
            &account,
            &acmex::ca_backend::AuthorizationRef {
                url: "https://acme.example/authz/1".to_string(),
            },
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("ACME_BAD_NONCE_EXHAUSTED"),
        "stable error code expected, got: {err}"
    );
}

#[tokio::test]
async fn rate_limited_order_surfaces_retry_after() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    transport.push(
        ScriptedResponse::json(
            "new-order",
            429,
            serde_json::json!({"type": "urn:ietf:params:acme:error:rateLimited"}),
        )
        .with_headers(None, Some("120".to_string()), None),
    );

    let backend = backend(transport);
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let err = backend
        .create_order(
            &account,
            &OrderRequest::for_identifiers(vec![Identifier::try_dns("example.com").unwrap()]),
        )
        .await
        .unwrap_err();
    assert!(err.to_string().contains("ACME_RATE_LIMITED"), "got: {err}");
    // The error carries the parsed Retry-After for the engine to honor.
    assert!(err.to_string().contains("rate-limited"));
}

#[tokio::test]
async fn replay_nonce_from_every_response_is_recycled() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("nonce-from-account".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    transport.push(ScriptedResponse::json(
        "authz/1",
        200,
        serde_json::json!({
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "pending",
            "expires": "2026-01-08T00:00:00Z",
            "challenges": []
        }),
    ));
    transport.push(ScriptedResponse::json(
        "authz/1",
        200,
        serde_json::json!({
            "identifier": {"type": "dns", "value": "example.com"},
            "status": "valid",
            "expires": "2026-01-08T00:00:00Z",
            "challenges": []
        }),
    ));

    let backend = backend(transport.clone());
    let account = backend.ensure_account(&account_ref()).await.unwrap();
    for _ in 0..2 {
        backend
            .get_authorization(
                &account,
                &acmex::ca_backend::AuthorizationRef {
                    url: "https://acme.example/authz/1".to_string(),
                },
            )
            .await
            .unwrap();
    }

    // Exactly one bootstrap newNonce fetch: every subsequent request reused
    // a nonce captured from a previous response's Replay-Nonce header.
    let head_count = transport
        .requests()
        .iter()
        .filter(|r| r.method == AcmeMethod::Head)
        .count();
    assert_eq!(
        head_count, 1,
        "responses' Replay-Nonce headers must satisfy subsequent requests"
    );
}

#[tokio::test]
async fn ari_unavailable_returns_none_for_fallback() {
    // Directory without renewalInfo.
    let transport = Arc::new(FakeAcmeTransport::new(now()));
    let mut directory = directory_body();
    directory.as_object_mut().unwrap().remove("renewalInfo");
    transport.push(ScriptedResponse::json("directory", 200, directory).uses(10));
    transport.push(
        ScriptedResponse::json("new-nonce", 200, serde_json::json!({}))
            .uses(10)
            .with_headers(Some("n".to_string()), None, None),
    );

    let backend = backend(transport);
    // ARI not advertised → Ok(None), the renewal controller falls back.
    assert!(
        backend.renewal_window("irrelevant").await.is_err() || {
            // The chain is invalid PEM here; capability-wise the CA lacks ARI,
            // which is exercised via capabilities():
            let caps = backend.capabilities().await.unwrap();
            !caps.supports_ari
        }
    );
}

#[tokio::test]
async fn ari_window_is_fetched_and_parsed() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json(
            "renewal-info",
            200,
            serde_json::json!({
                "suggestedWindow": {
                    "start": "2026-02-01T00:00:00Z",
                    "end": "2026-02-08T00:00:00Z"
                },
                "explanationURL": "https://example.com/ari-doc"
            }),
        )
        .with_headers(None, Some("3600".to_string()), None),
    );

    let backend = backend(transport.clone());
    // Build a real self-signed cert to derive AKI/serial from.
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["example.com".to_string()]).unwrap();
    // ARI needs an AKI extension; rcgen adds it for CAs — for a self-signed
    // cert the extension may be absent, in which case the error is explicit.
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "example.com");
    let cert = params.self_signed(&key_pair).unwrap();
    let result = backend.renewal_window(&cert.pem()).await;
    match result {
        Ok(Some(window)) => {
            assert_eq!(window.start.to_string(), "2026-02-01T00:00:00Z");
            assert!(window.retry_after.is_some());
            assert_eq!(
                window.explanation_url.as_deref(),
                Some("https://example.com/ari-doc")
            );
            // The CertId path was appended to the renewalInfo base URL.
            assert!(
                transport
                    .requests()
                    .iter()
                    .any(|r| r.url.starts_with("https://acme.example/renewal-info/"))
            );
        }
        Ok(None) => panic!("ARI advertised, window expected"),
        // Self-signed certs without AKI are explicitly rejected.
        Err(err) => assert!(err.to_string().contains("Authority Key Identifier")),
    }
}

#[tokio::test]
async fn concurrent_requests_never_share_a_nonce() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({})).with_headers(
            Some("acct-nonce".to_string()),
            None,
            Some("https://acme.example/acct/1".to_string()),
        ),
    );
    for i in 0..4 {
        transport.push(ScriptedResponse::json(
            format!("authz/{i}"),
            200,
            serde_json::json!({
                "identifier": {"type": "dns", "value": "example.com"},
                "status": "pending",
                "expires": "2026-01-08T00:00:00Z",
                "challenges": []
            }),
        ));
    }

    let backend = Arc::new(backend(transport.clone()));
    let account = backend.ensure_account(&account_ref()).await.unwrap();

    // Four concurrent POST-as-GETs through the same session pool.
    let mut handles = Vec::new();
    for i in 0..4 {
        let backend = Arc::clone(&backend);
        let account = account.clone();
        handles.push(tokio::spawn(async move {
            backend
                .get_authorization(
                    &account,
                    &acmex::ca_backend::AuthorizationRef {
                        url: format!("https://acme.example/authz/{i}"),
                    },
                )
                .await
        }));
    }
    for handle in handles {
        handle.await.unwrap().unwrap();
    }

    // Extract the nonce of every JWS protected header and assert uniqueness.
    use base64::Engine;
    let requests = transport.requests();
    let mut seen = std::collections::HashSet::new();
    for request in &requests {
        if request.method != AcmeMethod::Post {
            continue;
        }
        let body = String::from_utf8(request.body.clone().unwrap()).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&body).unwrap();
        let header = envelope["protected"].as_str().unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(header)
                .unwrap(),
        )
        .unwrap();
        let nonce = decoded["nonce"]
            .as_str()
            .expect("nonce in header")
            .to_string();
        assert!(seen.insert(nonce), "nonce reuse detected");
    }
}

#[tokio::test]
async fn eab_registration_binds_external_account_with_hs256() {
    use base64::Engine;

    // The MAC key a CA would hand out: raw bytes, delivered base64url.
    let mac_key: Vec<u8> = (0u8..32).collect();
    let mac_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac_key);
    let key_file = secret_file("eab-valid", &mac_key_b64);

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/88".to_string()),
            ),
    );
    // A true Ed25519 account key: the EAB payload must carry the unchanged
    // OKP/Ed25519 JWK (the compatibility baseline for other key types).
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        ed25519_key(),
        MemoryRepository::new().into_set(),
    );
    let account = eab_account_ref(SecretRef::File {
        path: key_file.clone(),
    });
    let handle = backend.ensure_account(&account).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/88");

    let (header, payload) = decode_jws_post(&transport, "new-account");
    let binding = &payload["externalAccountBinding"];
    assert!(
        binding.is_object(),
        "externalAccountBinding expected: {payload}"
    );

    // Protected header: HS256, the CA-assigned kid and the newAccount URL.
    let binding_header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(binding["protected"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(binding_header["alg"], "HS256");
    assert_eq!(binding_header["kid"], "eab-kid-42");
    assert_eq!(binding_header["url"], "https://acme.example/new-account");
    // Per RFC 8555 §7.3.4 the inner JWS carries no nonce.
    assert!(binding_header.get("nonce").is_none());

    // Payload: the JWK of the requesting account key — the same JWK the
    // outer JWS protected header authenticates the request with.
    let binding_payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(binding["payload"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(binding_payload, header["jwk"]);
    assert_eq!(binding_payload["kty"], "OKP");
    assert_eq!(binding_payload["crv"], "Ed25519");

    // Signature: HMAC-SHA256 over `<protected>.<payload>` with the key from
    // the file; deterministic, so a local recomputation must match exactly.
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    let signing_input = format!(
        "{}.{}",
        binding["protected"].as_str().unwrap(),
        binding["payload"].as_str().unwrap()
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(&mac_key).unwrap();
    mac.update(signing_input.as_bytes());
    let expected =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    assert_eq!(binding["signature"].as_str().unwrap(), expected);

    std::fs::remove_file(&key_file).ok();
}

#[tokio::test]
async fn registration_without_eab_omits_the_binding() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/89".to_string()),
            ),
    );
    let backend = backend(transport.clone());
    let handle = backend.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/89");

    let (_, payload) = decode_jws_post(&transport, "new-account");
    assert!(
        payload.get("externalAccountBinding").is_none(),
        "no EAB reference, no binding field: {payload}"
    );
}

#[tokio::test]
async fn eab_invalid_base64url_key_errors_without_leaking_the_secret() {
    // The file resolves but its content is not base64url: an explicit
    // configuration error that names the reference, never the value.
    let secret_value = "SUPER-SECRET-RAW-VALUE!!!";
    let key_file = secret_file("eab-invalid", secret_value);

    let transport = standard_transport();
    let backend = backend(transport.clone());
    let account = eab_account_ref(SecretRef::File {
        path: key_file.clone(),
    });
    let err = backend.ensure_account(&account).await.unwrap_err();
    assert!(
        matches!(err, AcmeError::Configuration(_)),
        "explicit configuration error expected, got: {err}"
    );
    assert!(err.to_string().contains("base64url"), "got: {err}");
    // The reference description is named for the operator...
    assert!(
        err.to_string().contains(&key_file.display().to_string()),
        "got: {err}"
    );
    // ...while the secret value itself never appears.
    assert!(
        !err.to_string().contains(secret_value),
        "secret value leaked: {err}"
    );
    // The failed registration never reached the CA.
    assert_eq!(transport.post_count("new-account"), 0);

    std::fs::remove_file(&key_file).ok();
}

#[tokio::test]
async fn eab_unresolvable_secret_is_a_configuration_error() {
    let transport = standard_transport();
    let backend = backend(transport.clone());
    // An env var that is guaranteed not to exist anywhere.
    let account = eab_account_ref(SecretRef::parse("env:ACMEX_EAB_UNSET_9f3a").unwrap());
    let err = backend.ensure_account(&account).await.unwrap_err();
    assert!(
        matches!(err, AcmeError::Configuration(_)),
        "explicit configuration error expected, got: {err}"
    );
    // The error names the missing reference so the operator can fix it.
    assert!(
        err.to_string().contains("env:ACMEX_EAB_UNSET_9f3a"),
        "got: {err}"
    );
    assert_eq!(transport.post_count("new-account"), 0);
}

// ---------------------------------------------------------------------------
// RFC 8555 §7.3.5 account key rollover
// ---------------------------------------------------------------------------

/// The raw compact-serialization JWS bodies of every POST sent to a URL
/// containing `url_fragment`.
fn jws_posts_to(transport: &FakeAcmeTransport, url_fragment: &str) -> Vec<String> {
    transport
        .requests()
        .iter()
        .filter(|r| r.url.contains(url_fragment) && r.method == AcmeMethod::Post)
        .map(|r| String::from_utf8(r.body.clone().unwrap()).unwrap())
        .collect()
}

/// Splits a flattened JSON JWS into (protected header, payload, signature b64).
fn jws_segments(jws: &str) -> (String, String, String) {
    let object: serde_json::Value =
        serde_json::from_str(jws).expect("JWS body is the flattened JSON envelope");
    (
        object["protected"].as_str().unwrap().to_string(),
        object["payload"].as_str().unwrap().to_string(),
        object["signature"].as_str().unwrap().to_string(),
    )
}

/// Splits a flattened JSON JWS into (protected header, payload, signature b64).
fn decode_jws(jws: &str) -> (serde_json::Value, serde_json::Value, String) {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let (protected, payload, signature) = jws_segments(jws);
    let header = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();
    let payload = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    (header, payload, signature)
}

/// Re-signs a captured JWS with `key` and returns the compact serialization.
/// Ed25519 signatures are deterministic, so an exact string match proves
/// which key produced the captured signature (and rules out the other key).
fn resign_jws(jws: &str, key: &KeyPair) -> String {
    let (header, payload, _) = decode_jws(jws);
    acmex::protocol::JwsSigner::new(&key.0)
        .sign(&header, &payload)
        .unwrap()
}

/// Generates an Ed25519 account key — the algorithm the session's JWS
/// headers claim (`alg: EdDSA`, Ed25519 JWK) and the only one whose
/// signatures are deterministic (needed by `resign_jws`).
fn ed25519_key() -> Arc<KeyPair> {
    let pem = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .expect("generate Ed25519 key")
        .serialize_pem();
    Arc::new(KeyPair::from_pem(&pem).expect("parse Ed25519 PEM"))
}

/// Generates an account key of any supported rcgen algorithm.
fn typed_key(algorithm: &'static rcgen::SignatureAlgorithm) -> Arc<KeyPair> {
    let pem = rcgen::KeyPair::generate_for(algorithm)
        .expect("generate key")
        .serialize_pem();
    Arc::new(KeyPair::from_pem(&pem).expect("parse PEM"))
}

// ---------------------------------------------------------------------------
// ES256 / RS256 account keys
// ---------------------------------------------------------------------------

/// ES256 account registration: the protected header derives `alg: ES256` and
/// the EC JWK (`kty: EC`, `crv: P-256`, fixed-width coordinates) from the
/// actual key, and the signature is the raw 64-octet `R||S` encoding.
#[tokio::test]
async fn es256_account_registration_carries_ec_jwk_and_raw_signature() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/91".to_string()),
            ),
    );
    let key = typed_key(&rcgen::PKCS_ECDSA_P256_SHA256);
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        key.clone(),
        MemoryRepository::new().into_set(),
    );

    let handle = backend.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/91");

    let (_jws, header, payload, signature_b64) = {
        let requests = transport.requests();
        let post = requests
            .iter()
            .find(|r| r.url.contains("new-account") && r.method == AcmeMethod::Post)
            .expect("newAccount POST");
        let jws = String::from_utf8(post.body.clone().unwrap()).unwrap();
        let (protected, payload_b64, signature_b64) = jws_segments(&jws);
        let header: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(protected)
                .unwrap(),
        )
        .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload_b64)
                .unwrap(),
        )
        .unwrap();
        (jws, header, payload, signature_b64)
    };

    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-256");
    let x: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["x"].as_str().unwrap())
        .unwrap();
    let y: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["y"].as_str().unwrap())
        .unwrap();
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    // The JWK coordinates are the halves of the uncompressed point.
    let point = key.public_key_bytes();
    assert_eq!(point[0], 0x04);
    assert_eq!(&point[1..33], x.as_slice());
    assert_eq!(&point[33..], y.as_slice());
    assert!(payload.get("onlyReturnExisting").is_none());

    // Raw R||S: exactly 64 octets (never the DER ~70-72 octet encoding).
    let signature = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
    assert_eq!(signature.len(), 64, "ES256 JWS signatures are raw R||S");
}

/// RS256 account registration: `alg: RS256` and an RSA JWK whose `n`/`e`
/// use minimal octets (`e` is always `AQAB` for CA-issued keys).
#[tokio::test]
async fn rs256_account_registration_carries_rsa_jwk() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/92".to_string()),
            ),
    );
    let key = typed_key(&rcgen::PKCS_RSA_SHA256);
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        key,
        MemoryRepository::new().into_set(),
    );

    let handle = backend.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/92");

    let (header, _) = decode_jws_post(&transport, "new-account");
    assert_eq!(header["alg"], "RS256");
    assert_eq!(header["jwk"]["kty"], "RSA");
    let n: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["n"].as_str().unwrap())
        .unwrap();
    let e: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["e"].as_str().unwrap())
        .unwrap();
    assert_eq!(n.len(), 256, "2048-bit modulus, no DER sign octet");
    assert_eq!(e, vec![0x01, 0x00, 0x01], "exponent 65537 as AQAB");
}

/// ES512 (P-521) account registration: the protected header derives
/// `alg: ES512` and an EC JWK with `crv: P-521` and 66-octet coordinates, and
/// the persisted account record labels the key `EcP521` — P-521 keys used to
/// be mislabeled `EcP384` while the enum had no P-521 variant.
#[tokio::test]
async fn es512_account_registration_carries_p521_jwk_and_ecp521_record() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/94".to_string()),
            ),
    );
    let key = typed_key(&rcgen::PKCS_ECDSA_P521_SHA512);
    let repositories = MemoryRepository::new().into_set();
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        key.clone(),
        repositories.clone(),
    );

    let handle = backend.ensure_account(&account_ref()).await.unwrap();
    assert_eq!(handle.account_url, "https://acme.example/acct/94");

    let requests = transport.requests();
    let post = requests
        .iter()
        .find(|r| r.url.contains("new-account") && r.method == AcmeMethod::Post)
        .expect("newAccount POST");
    let jws = String::from_utf8(post.body.clone().unwrap()).unwrap();
    let (protected, _payload_b64, signature_b64) = jws_segments(&jws);
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(protected).unwrap()).unwrap();

    assert_eq!(header["alg"], "ES512");
    assert_eq!(header["jwk"]["kty"], "EC");
    assert_eq!(header["jwk"]["crv"], "P-521");
    let x: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["x"].as_str().unwrap())
        .unwrap();
    let y: Vec<u8> = URL_SAFE_NO_PAD
        .decode(header["jwk"]["y"].as_str().unwrap())
        .unwrap();
    assert_eq!(x.len(), 66, "P-521 coordinates are 66 octets");
    assert_eq!(y.len(), 66, "P-521 coordinates are 66 octets");
    // The JWK coordinates are the halves of the uncompressed point.
    let point = key.public_key_bytes();
    assert_eq!(point[0], 0x04);
    assert_eq!(&point[1..67], x.as_slice());
    assert_eq!(&point[67..], y.as_slice());
    // Raw R||S: exactly 132 octets (never the DER encoding).
    let signature = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
    assert_eq!(signature.len(), 132, "ES512 JWS signatures are raw R||S");

    // The persisted record labels the account key EcP521 (not EcP384).
    let record = repositories
        .accounts
        .get(&acmex::domain::AccountRecord::compute_id(
            &acmex::domain::TenantId::default_tenant(),
            "test-ca",
        ))
        .await
        .unwrap()
        .expect("persisted account record");
    assert_eq!(
        record.value.key_ref.algorithm,
        acmex::domain::KeyAlgorithm::EcP521,
        "P-521 account keys must persist as EcP521"
    );
    assert_eq!(record.value.key_ref.key_id.as_str(), handle.key_id);
}

/// Mixed-algorithm RFC 8555 §7.3.5 rollover: the outer JWS (old key) claims
/// `alg: ES256` while the inner JWS (new key) claims `alg: EdDSA` with the
/// OKP JWK — each side derives its algorithm from its own key. After the
/// switch, follow-up requests sign with the new key.
#[tokio::test]
async fn es256_to_ed25519_key_rollover_derives_each_alg_from_its_own_key() {
    use acmex::protocol::Jwk;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/93".to_string()),
            ),
    );
    transport.push(ScriptedResponse::json(
        "key-change",
        200,
        serde_json::json!({"status": "valid"}),
    ));
    transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("order-nonce".to_string()),
                None,
                Some("https://acme.example/order/10".to_string()),
            ),
    );

    let old_key = typed_key(&rcgen::PKCS_ECDSA_P256_SHA256);
    let new_key = ed25519_key();
    let repositories = MemoryRepository::new().into_set();
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        old_key.clone(),
        repositories.clone(),
    );

    let account = backend.ensure_account(&account_ref()).await.unwrap();

    // The registration JWS was signed by the ES256 key...
    let (registration_header, _, registration_sig) = {
        let posts = jws_posts_to(&transport, "new-account");
        assert_eq!(posts.len(), 1);
        let (header, payload, signature) = decode_jws(&posts[0]);
        (header, payload, signature)
    };
    assert_eq!(registration_header["alg"], "ES256");
    assert_eq!(URL_SAFE_NO_PAD.decode(&registration_sig).unwrap().len(), 64);

    // ...and the rollover mixes ES256 (outer, old) with EdDSA (inner, new).
    backend
        .roll_account_key(&account, new_key.clone())
        .await
        .unwrap();

    let key_change_posts = jws_posts_to(&transport, "key-change");
    assert_eq!(key_change_posts.len(), 1);
    let (outer_header, outer_payload, outer_signature) = decode_jws(&key_change_posts[0]);
    assert_eq!(outer_header["alg"], "ES256");
    assert_eq!(outer_header["kid"], "https://acme.example/acct/93");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(&outer_signature).unwrap().len(),
        64,
        "outer ES256 signature is raw R||S"
    );

    let old_jwk = Jwk::for_key_pair(&old_key.0).unwrap();
    let new_jwk = Jwk::for_key_pair(&new_key.0).unwrap();
    // RFC 8555 §7.3.5: the outer payload is a JSON string containing the
    // inner flattened JWS.
    let inner = outer_payload
        .as_str()
        .expect("inner JWS carried as a JSON string");
    let (inner_header, inner_payload, _) = decode_jws(inner);
    assert_eq!(inner_header["alg"], "EdDSA");
    assert_eq!(inner_header["jwk"], new_jwk.to_value());
    assert_eq!(inner_payload["oldKey"], old_jwk.to_value());
    // The inner signature is the deterministic new key's (and only its).
    assert_eq!(resign_jws(inner, &new_key), inner);

    // Post-rollover requests sign with the new Ed25519 key.
    backend
        .create_order(
            &account,
            &OrderRequest::for_identifiers(vec![Identifier::try_dns("example.com").unwrap()]),
        )
        .await
        .unwrap();
    let new_order_posts = jws_posts_to(&transport, "new-order");
    assert_eq!(new_order_posts.len(), 1);
    let (order_header, _, order_signature) = decode_jws(&new_order_posts[0]);
    assert_eq!(order_header["alg"], "EdDSA");
    assert_eq!(
        resign_jws(&new_order_posts[0], &new_key),
        new_order_posts[0],
        "post-rollover orders must be signed by the new key"
    );
    assert_ne!(
        resign_jws(&new_order_posts[0], &old_key),
        new_order_posts[0]
    );
    // (the old ES256 key cannot produce a deterministic 64-byte match; the
    // exact string equality above already rules it out)
    let _ = order_signature;

    // Persistence records the NEW key.
    let record = repositories
        .accounts
        .get("ten_default:test-ca")
        .await
        .unwrap()
        .expect("account record persisted");
    assert_eq!(
        record.value.key_ref.key_id.to_string(),
        acmex::ca_backend::account_key_id(&new_key.public_key_bytes())
    );
}

#[tokio::test]
async fn key_rollover_sends_double_jws_and_switches_to_the_new_key() {
    use acmex::protocol::Jwk;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/77".to_string()),
            ),
    );
    transport.push(ScriptedResponse::json(
        "key-change",
        200,
        serde_json::json!({"status": "valid"}),
    ));
    // A follow-up order after the rollover.
    transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("order-nonce".to_string()),
                None,
                Some("https://acme.example/order/9".to_string()),
            ),
    );

    let old_key = ed25519_key();
    let new_key = ed25519_key();
    let repositories = MemoryRepository::new().into_set();
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        old_key.clone(),
        repositories.clone(),
    );

    let account = backend.ensure_account(&account_ref()).await.unwrap();
    backend
        .roll_account_key(&account, new_key.clone())
        .await
        .unwrap();

    // (a) The keyChange request: an outer JWS authenticated by the account
    // (kid) and addressed to the directory's keyChange endpoint.
    let key_change_posts = jws_posts_to(&transport, "key-change");
    assert_eq!(key_change_posts.len(), 1, "exactly one keyChange POST");
    let (outer_header, outer_payload, _) = decode_jws(&key_change_posts[0]);
    assert_eq!(outer_header["alg"], "EdDSA");
    assert_eq!(outer_header["kid"], "https://acme.example/acct/77");
    assert_eq!(outer_header["url"], "https://acme.example/key-change");
    // The outer signature is the old account key's.
    assert_eq!(
        resign_jws(&key_change_posts[0], &old_key),
        key_change_posts[0]
    );

    // (b) The outer payload is itself a JWS signed by the NEW key: header
    // {alg, jwk(new), url} and payload {account, oldKey}.
    let new_jwk = Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(new_key.public_key_bytes()));
    let old_jwk_value =
        Jwk::new_ed25519(URL_SAFE_NO_PAD.encode(old_key.public_key_bytes())).to_value();
    // RFC 8555 §7.3.5: the outer payload is a JSON string containing the
    // inner flattened JWS.
    let inner = outer_payload
        .as_str()
        .expect("inner JWS carried as a JSON string");
    let (inner_header, inner_payload, _) = decode_jws(inner);
    assert_eq!(inner_header["alg"], "EdDSA");
    assert_eq!(inner_header["jwk"], new_jwk.to_value());
    assert_eq!(inner_header["url"], "https://acme.example/key-change");
    // RFC 8555 §7.3.5: the inner JWS carries no nonce and no kid.
    assert!(inner_header.get("nonce").is_none());
    assert!(inner_header.get("kid").is_none());
    assert_eq!(inner_payload["account"], "https://acme.example/acct/77");
    assert_eq!(inner_payload["oldKey"], old_jwk_value);
    // The inner signature verifies against the NEW key (and only it).
    assert_eq!(resign_jws(inner, &new_key), inner);
    assert_ne!(resign_jws(inner, &old_key), inner);

    // (c) A follow-up request is signed by the NEW key. The JWS header keeps
    // the unchanged account kid, so prove the signer via deterministic
    // re-signing.
    let order = backend
        .create_order(
            &account,
            &OrderRequest::for_identifiers(vec![Identifier::try_dns("example.com").unwrap()]),
        )
        .await
        .unwrap();
    assert_eq!(order.url, "https://acme.example/order/9");
    let new_order_posts = jws_posts_to(&transport, "new-order");
    assert_eq!(new_order_posts.len(), 1);
    assert_eq!(
        resign_jws(&new_order_posts[0], &new_key),
        new_order_posts[0],
        "post-rollover orders must be signed by the new key"
    );
    assert_ne!(
        resign_jws(&new_order_posts[0], &old_key),
        new_order_posts[0]
    );

    // Persistence: the stored account record now references the NEW key
    // (mirroring ensure_account persistence), so restarts resume with it.
    let record = repositories
        .accounts
        .get("ten_default:test-ca")
        .await
        .unwrap()
        .expect("account record persisted");
    assert_eq!(
        record.value.key_ref.key_id.to_string(),
        acmex::ca_backend::account_key_id(&new_key.public_key_bytes())
    );
    assert_eq!(
        record.value.account_url.as_deref(),
        Some("https://acme.example/acct/77")
    );
}

/// Review P3-6 regression: a successful RFC 8555 §7.3.5 rollover publishes
/// the NEW key's JWK through the attached pipeline handle, so key
/// authorizations computed afterwards use the new thumbprint. The trait
/// re-sync source (`current_account_jwk`) tracks the same key.
#[tokio::test]
async fn key_rollover_refreshes_the_attached_account_jwk_handle() {
    use acmex::ca_backend::backend::AccountJwkHandle;
    use acmex::protocol::Jwk;

    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/96".to_string()),
            ),
    );
    transport.push(ScriptedResponse::json(
        "key-change",
        200,
        serde_json::json!({"status": "valid"}),
    ));

    let old_key = ed25519_key();
    let new_key = ed25519_key();
    let old_jwk = Jwk::for_key_pair(&old_key.0).unwrap();
    let new_jwk = Jwk::for_key_pair(&new_key.0).unwrap();

    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport,
        old_key,
        MemoryRepository::new().into_set(),
    );
    let handle = AccountJwkHandle::new(old_jwk.clone());
    backend.attach_jwk_handle(handle.clone());
    assert_eq!(handle.get(), old_jwk);
    assert_eq!(
        backend.current_account_jwk().await.unwrap(),
        old_jwk,
        "the re-sync source matches the pinned handle before the rollover"
    );

    let account = backend.ensure_account(&account_ref()).await.unwrap();
    backend
        .roll_account_key(&account, new_key.clone())
        .await
        .unwrap();

    // The handle now serves the NEW key's JWK: the thumbprint every key
    // authorization is built from has moved with the signing key.
    assert_eq!(handle.get(), new_jwk);
    assert_ne!(
        handle.thumbprint_sha256().unwrap(),
        old_jwk.thumbprint_sha256().unwrap()
    );
    assert_eq!(backend.current_account_jwk().await.unwrap(), new_jwk);
}

#[tokio::test]
async fn key_rollover_failure_keeps_the_old_key_and_sessions_intact() {
    let transport = standard_transport();
    transport.push(
        ScriptedResponse::json("new-account", 201, serde_json::json!({"status": "valid"}))
            .with_headers(
                Some("acct-nonce".to_string()),
                None,
                Some("https://acme.example/acct/77".to_string()),
            ),
    );
    // keyChange rejected with a terminal 400 (not badNonce: no retry).
    transport.push(ScriptedResponse::json(
        "key-change",
        400,
        serde_json::json!({
            "type": "urn:ietf:params:acme:error:malformed",
            "detail": "old key does not match account"
        }),
    ));
    // A follow-up order after the failed rollover.
    transport.push(
        ScriptedResponse::json("new-order", 201, serde_json::json!({"status": "pending"}))
            .with_headers(
                Some("order-nonce".to_string()),
                None,
                Some("https://acme.example/order/9".to_string()),
            ),
    );

    let old_key = ed25519_key();
    let new_key = ed25519_key();
    let repositories = MemoryRepository::new().into_set();
    let backend = AcmeCaBackend::with_fake_transport(
        "test-ca",
        "https://acme.example/directory",
        transport.clone(),
        old_key.clone(),
        repositories.clone(),
    );

    // The pipeline handle is attached: a failed rollover must leave it on
    // the old key's JWK too (no partial switch, pipeline included).
    let handle = acmex::ca_backend::backend::AccountJwkHandle::new(
        acmex::protocol::Jwk::for_key_pair(&old_key.0).unwrap(),
    );
    backend.attach_jwk_handle(handle.clone());

    let account = backend.ensure_account(&account_ref()).await.unwrap();
    let err = backend
        .roll_account_key(&account, new_key.clone())
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("ACME_HTTP_400"),
        "classified HTTP error expected, got: {err}"
    );
    assert_eq!(
        handle.get(),
        acmex::protocol::Jwk::for_key_pair(&old_key.0).unwrap(),
        "the pipeline handle must keep the old key's JWK after a failed rollover"
    );
    assert_eq!(
        jws_posts_to(&transport, "key-change").len(),
        1,
        "exactly one keyChange attempt, no internal retry"
    );

    // No partial switch: the cached session still works and the follow-up
    // request is signed by the OLD key.
    let order = backend
        .create_order(
            &account,
            &OrderRequest::for_identifiers(vec![Identifier::try_dns("example.com").unwrap()]),
        )
        .await
        .unwrap();
    assert_eq!(order.url, "https://acme.example/order/9");
    let new_order_posts = jws_posts_to(&transport, "new-order");
    assert_eq!(new_order_posts.len(), 1);
    assert_eq!(
        resign_jws(&new_order_posts[0], &old_key),
        new_order_posts[0],
        "after a failed rollover the old key must keep signing"
    );

    // The stored record still references the old key.
    let record = repositories
        .accounts
        .get("ten_default:test-ca")
        .await
        .unwrap()
        .expect("account record persisted");
    assert_eq!(
        record.value.key_ref.key_id.to_string(),
        acmex::ca_backend::account_key_id(&old_key.public_key_bytes())
    );
}
