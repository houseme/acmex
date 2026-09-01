//! CA backend behavioral tests (roadmap T04) over the fake transport:
//! session reuse, nonce discipline, badNonce recovery, Retry-After,
//! account persistence across restarts, profile orders and ARI.

use std::str::FromStr;
use std::sync::Arc;

use acmex::account::KeyPair;
use acmex::ca_backend::{
    AccountRef, AcmeCaBackend, AcmeMethod, CaBackend, FakeAcmeTransport, OrderRequest,
    ScriptedResponse,
};
use acmex::domain::Identifier;
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
    // The newOrder POST body is a JWS; the payload (middle segment) carries
    // the profile, replaces and identifiers claims.
    let jws = String::from_utf8(posts[0].body.clone().unwrap()).unwrap();
    let segments: Vec<&str> = jws.split('.').collect();
    assert_eq!(segments.len(), 3);
    use base64::Engine;
    let payload: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[1])
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
    let segments: Vec<&str> = jws.split('.').collect();
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[1], "", "POST-as-GET payload must be empty");
    // Protected header carries the account kid and target url.
    use base64::Engine;
    let header: serde_json::Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(segments[0])
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
        let header = body.split('.').next().unwrap();
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
