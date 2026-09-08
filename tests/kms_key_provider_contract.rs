//! Contract tests for the AWS KMS [`KeyProvider`] (feature `kms-aws`).
//!
//! A mockito server stands in for AWS KMS (the SDK client is pointed at it
//! with an endpoint override, mirroring the Route53 provider tests). The
//! fixtures speak the AWS JSON 1.1 protocol: `POST /` with an `X-Amz-Target`
//! header, JSON bodies, and `{"__type": "<ErrorCode>"}` error responses.
//! Request shapes are asserted with body matchers, so a provider that sends
//! the wrong `KeySpec`, tags, key id, signing algorithm or deletion window
//! never matches its mock and the test fails.
//!
//! These tests prove request/response shape, CSR structure and error
//! classification against the fake — live AWS KMS behavior is not exercised
//! here (see the task report's known limitations).

#![cfg(feature = "kms-aws")]

use acmex::key::{DestroyAuthorization, KmsKeyProvider, KmsKeyProviderConfig};
use acmex::{
    CreateCsr, CreateKey, DestroyOutcome, ExportAuthorization, IdentifierSet, KeyAlgorithm, KeyId,
    KeyManagementMode, KeyPolicy, KeyProvider, KeyRef,
};
use base64::Engine as _;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::json;
use sha2::Digest;
use x509_parser::prelude::*;

const KMS_KEY_ID: &str = "098fe2ff-d1fc-4ad1-b1e5-165eb2b113ce";
const KMS_ARN: &str = "arn:aws:kms:us-east-1:111122223333:key/098fe2ff-d1fc-4ad1-b1e5-165eb2b113ce";

fn managed_policy(algorithm: KeyAlgorithm) -> KeyPolicy {
    KeyPolicy {
        algorithm,
        mode: KeyManagementMode::Managed,
        rotation: Default::default(),
        exportable: false,
    }
}

fn provider_against(endpoint: &str) -> KmsKeyProvider {
    let sdk_config = aws_sdk_kms::config::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .credentials_provider(aws_sdk_kms::config::Credentials::new(
            "test-access-key",
            "test-secret-key",
            None,
            None,
            "kms-unit-test",
        ))
        .region(aws_sdk_kms::config::Region::new("us-east-1"))
        .endpoint_url(endpoint)
        // Deterministic single-attempt behavior for the throttling test.
        .retry_config(aws_sdk_kms::config::retry::RetryConfig::disabled())
        .build();
    KmsKeyProvider::from_client(
        KmsKeyProviderConfig::default(),
        aws_sdk_kms::Client::from_conf(sdk_config),
    )
    .expect("valid provider config")
}

/// Registers a mock for one KMS operation.
///
/// `extra_matchers` are combined with the `X-Amz-Target` check so each mock
/// only accepts requests with the expected payload.
async fn kms_target_mock(
    server: &mut mockito::Server,
    target: &'static str,
    status: usize,
    body: &str,
    extra_matchers: Vec<mockito::Matcher>,
) -> mockito::Mock {
    let mut mock = server
        .mock("POST", "/")
        .match_header("X-Amz-Target", target)
        .with_status(status)
        .with_header("content-type", "application/x-amz-json-1.1")
        .with_body(body);
    for matcher in extra_matchers {
        mock = mock.match_body(matcher);
    }
    mock.create_async().await
}

fn key_metadata_json() -> serde_json::Value {
    json!({
        "KeyId": KMS_KEY_ID,
        "Arn": KMS_ARN,
        "AWSAccountId": "111122223333",
        "CreationDate": 1757000000.0,
        "Enabled": true,
        "KeyState": "Enabled",
        "KeyUsage": "SIGN_VERIFY",
        "KeySpec": "ECC_NIST_P256",
        "CustomerMasterKeySpec": "ECC_NIST_P256",
        "SigningAlgorithms": ["ECDSA_SHA_256"]
    })
}

/// Generates a real P-256 SPKI DER (what `GetPublicKey` would return) plus
/// its SHA-256 fingerprint.
fn generated_p256_spki() -> (Vec<u8>, String) {
    let pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 keygen");
    let pem_str = pair.public_key_pem();
    let block = ::pem::parse(pem_str.as_bytes()).expect("parse SPKI PEM");
    let der = block.contents().to_vec();
    let fingerprint = hex::encode(sha2::Sha256::digest(&der));
    (der, fingerprint)
}

fn kms_key_ref() -> KeyRef {
    KeyRef {
        provider: "kms-aws".to_string(),
        key_id: KeyId::new(KMS_KEY_ID).unwrap(),
        algorithm: KeyAlgorithm::EcP256,
        exportable: false,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_key_maps_algorithm_tags_and_key_ref() {
    let mut server = mockito::Server::new_async().await;
    // The mock only matches when KeySpec, KeyUsage and the owner/requested-id
    // tags are all present and correct.
    let create = kms_target_mock(
        &mut server,
        "TrentService.CreateKey",
        200,
        &json!({ "KeyMetadata": key_metadata_json() }).to_string(),
        vec![mockito::Matcher::PartialJson(json!({
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "Tags": [
                { "TagKey": "owner", "TagValue": "acmex" },
                { "TagKey": "acmex-key-id", "TagValue": "contract-key" }
            ]
        }))],
    )
    .await;

    let provider = provider_against(&server.url());
    let key = provider
        .create_key(CreateKey {
            policy: managed_policy(KeyAlgorithm::EcP256),
            key_id: Some(KeyId::new("contract-key").unwrap()),
        })
        .await
        .expect("create_key");

    create.assert_async().await;

    // The KeyRef stores the bare KMS key id — never any key material.
    assert_eq!(key.provider, "kms-aws");
    assert_eq!(key.key_id.as_str(), KMS_KEY_ID);
    assert_eq!(key.algorithm, KeyAlgorithm::EcP256);
    assert!(!key.exportable, "KMS keys are never exportable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_key_rejects_unsupported_policies_before_calling_kms() {
    let server = mockito::Server::new_async().await;
    let provider = provider_against(&server.url());

    // Exportable managed keys contradict the KMS model.
    let exportable = KeyPolicy {
        exportable: true,
        ..managed_policy(KeyAlgorithm::EcP256)
    };
    let outcome = provider
        .create_key(CreateKey {
            policy: exportable,
            key_id: None,
        })
        .await;
    assert!(matches!(outcome, Err(acmex::AcmeError::InvalidInput(_))));

    // External CSR mode belongs to caller-side providers.
    let outcome = provider
        .create_key(CreateKey {
            policy: KeyPolicy {
                mode: KeyManagementMode::ExternalCsr,
                ..managed_policy(KeyAlgorithm::EcP256)
            },
            key_id: None,
        })
        .await;
    assert!(matches!(outcome, Err(acmex::AcmeError::InvalidInput(_))));

    // Ed25519 has no KMS signing-algorithm match for rcgen CSRs.
    let outcome = provider
        .create_key(CreateKey {
            policy: managed_policy(KeyAlgorithm::Ed25519),
            key_id: None,
        })
        .await;
    assert!(matches!(outcome, Err(acmex::AcmeError::InvalidInput(_))));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn create_csr_signs_via_kms_with_exact_sans_and_signature() {
    let (spki_der, spki_sha256) = generated_p256_spki();
    let signature_bytes = vec![0xAB_u8; 64];
    let mut server = mockito::Server::new_async().await;

    let create = kms_target_mock(
        &mut server,
        "TrentService.CreateKey",
        200,
        &json!({ "KeyMetadata": key_metadata_json() }).to_string(),
        vec![mockito::Matcher::PartialJson(json!({
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY"
        }))],
    )
    .await;
    let get_key = kms_target_mock(
        &mut server,
        "TrentService.GetPublicKey",
        200,
        &json!({
            "KeyId": KMS_KEY_ID,
            "PublicKey": base64::engine::general_purpose::STANDARD.encode(&spki_der),
            "KeySpec": "ECC_NIST_P256",
            "KeyUsage": "SIGN_VERIFY",
            "SigningAlgorithms": ["ECDSA_SHA_256"]
        })
        .to_string(),
        vec![mockito::Matcher::PartialJson(json!({
            "KeyId": KMS_KEY_ID
        }))],
    )
    .await;
    // The remote signer must target the KMS key id with RAW message mode and
    // ECDSA_SHA_256, and must carry a base64 Message (the CSR TBS bytes).
    let sign = kms_target_mock(
        &mut server,
        "TrentService.Sign",
        200,
        &json!({
            "KeyId": KMS_KEY_ID,
            "Signature": base64::engine::general_purpose::STANDARD.encode(&signature_bytes),
            "SigningAlgorithm": "ECDSA_SHA_256"
        })
        .to_string(),
        vec![
            mockito::Matcher::PartialJson(json!({
                "KeyId": KMS_KEY_ID,
                "MessageType": "RAW",
                "SigningAlgorithm": "ECDSA_SHA_256"
            })),
            mockito::Matcher::Regex(r#""Message":"[A-Za-z0-9+/=]+""#.to_string()),
        ],
    )
    .await;

    let provider = provider_against(&server.url());
    let key = provider
        .create_key(CreateKey {
            policy: managed_policy(KeyAlgorithm::EcP256),
            key_id: None,
        })
        .await
        .expect("create_key");
    let identifiers = IdentifierSet::parse(["example.com", "192.0.2.10"]).unwrap();
    let artifact = provider
        .create_csr(CreateCsr {
            identifiers: identifiers.clone(),
            policy: managed_policy(KeyAlgorithm::EcP256),
            key_ref: Some(key.clone()),
            external_csr: None,
        })
        .await
        .expect("create_csr");

    create.assert_async().await;
    get_key.assert_async().await;
    sign.assert_async().await;

    // Structural CSR verification.
    let (_, csr) = X509CertificationRequest::from_der(artifact.csr_der.as_slice())
        .expect("parse generated CSR");

    // SANs must be exactly the intent identifiers.
    let mut sans = Vec::new();
    for extension in csr.requested_extensions().expect("extension request") {
        if let ParsedExtension::SubjectAlternativeName(san) = extension {
            for name in &san.general_names {
                match name {
                    GeneralName::DNSName(dns) => sans.push(format!("dns:{dns}")),
                    GeneralName::IPAddress(bytes) => sans.push(format!("ip:{bytes:?}")),
                    other => panic!("unexpected SAN type: {other:?}"),
                }
            }
        }
    }
    sans.sort();
    assert_eq!(
        sans,
        vec![
            "dns:example.com".to_string(),
            "ip:[192, 0, 2, 10]".to_string()
        ],
        "CSR SANs must equal the identifiers exactly"
    );

    // The signature algorithm must be ecdsa-with-SHA256 and its BIT STRING
    // must be exactly the bytes the fake KMS returned — proof that the KMS
    // signature flows through unmodified (no DER/raw conversion needed).
    assert_eq!(
        csr.signature_algorithm.algorithm.to_string(),
        "1.2.840.10045.4.3.2",
        "CSR signature algorithm must be ecdsa-with-SHA256"
    );
    assert_eq!(
        csr.signature_value.data.as_ref(),
        signature_bytes.as_slice()
    );

    // Artifact bookkeeping.
    assert!(!artifact.external, "KMS CSRs are managed, not external");
    assert_eq!(artifact.key_ref, key);
    assert_eq!(artifact.identifiers.as_slice(), identifiers.as_slice());
    assert_eq!(artifact.public_key_sha256, spki_sha256);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_key_returns_spki_metadata_from_kms() {
    let (spki_der, spki_sha256) = generated_p256_spki();
    let mut server = mockito::Server::new_async().await;
    let get_key = kms_target_mock(
        &mut server,
        "TrentService.GetPublicKey",
        200,
        &json!({
            "KeyId": KMS_KEY_ID,
            "PublicKey": base64::engine::general_purpose::STANDARD.encode(&spki_der),
            "KeySpec": "ECC_NIST_P256"
        })
        .to_string(),
        vec![],
    )
    .await;

    let provider = provider_against(&server.url());
    let key = kms_key_ref();
    let info = provider.public_key(&key).await.expect("public_key");

    get_key.assert_async().await;
    assert_eq!(info.key_ref, key);
    assert_eq!(info.spki_sha256, spki_sha256);
    assert!(
        info.spki_pem.starts_with("-----BEGIN PUBLIC KEY-----"),
        "SPKI PEM shape: {}",
        info.spki_pem
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn export_always_returns_none_even_when_authorized() {
    let server = mockito::Server::new_async().await;
    let provider = provider_against(&server.url());
    let outcome = provider
        .export(
            &kms_key_ref(),
            ExportAuthorization {
                actor: "security-team".to_string(),
                key_export_granted: true,
                reason: "contract test".to_string(),
            },
        )
        .await
        .expect("export must not fail");
    assert!(
        outcome.is_none(),
        "KMS-held key material can never be exported"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_probe_never_schedules_deletion() {
    let mut server = mockito::Server::new_async().await;
    // Existing key: refuse destruction (only destroy_confirmed may delete).
    let describe = kms_target_mock(
        &mut server,
        "TrentService.DescribeKey",
        200,
        &json!({ "KeyMetadata": key_metadata_json() }).to_string(),
        vec![mockito::Matcher::PartialJson(json!({
            "KeyId": KMS_KEY_ID
        }))],
    )
    .await;
    // Absent key: report NotFound honestly.
    let describe_missing = kms_target_mock(
        &mut server,
        "TrentService.DescribeKey",
        400,
        r#"{"__type":"NotFoundException","message":"Key 'does-not-exist' does not exist"}"#,
        vec![mockito::Matcher::PartialJson(json!({
            "KeyId": "does-not-exist"
        }))],
    )
    .await;

    let provider = provider_against(&server.url());
    let outcome = provider
        .destroy(&kms_key_ref())
        .await
        .expect("destroy probe");
    assert_eq!(outcome, DestroyOutcome::Refused);

    let missing = KeyRef {
        key_id: KeyId::new("does-not-exist").unwrap(),
        ..kms_key_ref()
    };
    let outcome = provider.destroy(&missing).await.expect("destroy probe");
    assert_eq!(outcome, DestroyOutcome::NotFound);

    describe.assert_async().await;
    describe_missing.assert_async().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn destroy_confirmed_schedules_key_deletion() {
    let mut server = mockito::Server::new_async().await;
    // The mock only matches when the key id and the configured 7-day window
    // are both present.
    let schedule = kms_target_mock(
        &mut server,
        "TrentService.ScheduleKeyDeletion",
        200,
        &json!({
            "KeyId": KMS_KEY_ID,
            "DeletionDate": 1757600000.0,
            "KeyState": "PendingDeletion",
            "PendingWindowInDays": 7
        })
        .to_string(),
        vec![mockito::Matcher::PartialJson(json!({
            "KeyId": KMS_KEY_ID,
            "PendingWindowInDays": 7
        }))],
    )
    .await;

    let provider = provider_against(&server.url());
    let key = kms_key_ref();

    // Unconfirmed requests are refused without touching KMS.
    let refused = provider
        .destroy_confirmed(
            &key,
            DestroyAuthorization {
                actor: "test".to_string(),
                confirmed: false,
                reason: "no confirmation".to_string(),
            },
        )
        .await
        .expect("destroy_confirmed");
    assert_eq!(refused, DestroyOutcome::Refused);

    let confirmed = provider
        .destroy_confirmed(
            &key,
            DestroyAuthorization {
                actor: "security-team".to_string(),
                confirmed: true,
                reason: "rotation cleanup".to_string(),
            },
        )
        .await
        .expect("destroy_confirmed");
    assert_eq!(confirmed, DestroyOutcome::Destroyed);

    schedule.assert_async().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kms_error_codes_are_classified() {
    type Classifier = fn(&acmex::AcmeError) -> bool;
    let cases: &[(&str, &str, Classifier)] = &[
        // KMS returns not-found as HTTP 400 + __type; the classification is
        // driven by the error code, not the status.
        (
            "NotFoundException",
            r#"{"__type":"NotFoundException","message":"Key 'xyz' does not exist"}"#,
            |err| matches!(err, acmex::AcmeError::NotFound(_)),
        ),
        (
            "DisabledException",
            r#"{"__type":"DisabledException","message":"key is disabled"}"#,
            |err| matches!(err, acmex::AcmeError::Configuration(_)),
        ),
        (
            "ThrottlingException",
            r#"{"__type":"ThrottlingException","message":"rate exceeded"}"#,
            |err| matches!(err, acmex::AcmeError::RateLimited(_)),
        ),
    ];

    for (code, body, matches_classifier) in cases {
        let mut server = mockito::Server::new_async().await;
        let error_mock =
            kms_target_mock(&mut server, "TrentService.GetPublicKey", 400, body, vec![]).await;
        let provider = provider_against(&server.url());
        let outcome = provider.public_key(&kms_key_ref()).await;
        error_mock.assert_async().await;
        let err = outcome.expect_err("{code} must surface as an error");
        assert!(
            matches_classifier(&err),
            "{code} must map to its classified AcmeError, got: {err:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_provider_key_refs_are_rejected_without_kms_calls() {
    let server = mockito::Server::new_async().await;
    let provider = provider_against(&server.url());
    let key = KeyRef {
        provider: "software".to_string(),
        key_id: KeyId::new("some-software-key").unwrap(),
        algorithm: KeyAlgorithm::EcP256,
        exportable: false,
    };
    let outcome = provider.public_key(&key).await;
    assert!(matches!(outcome, Err(acmex::AcmeError::InvalidInput(_))));
}

#[test]
fn debug_output_never_contains_sensitive_material() {
    let sdk_config = aws_sdk_kms::config::Config::builder()
        .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
        .credentials_provider(aws_sdk_kms::config::Credentials::new(
            "contract-access-key",
            "contract-secret-key",
            None,
            None,
            "kms-contract-test",
        ))
        .region(aws_sdk_kms::config::Region::new("us-east-1"))
        .build();
    let provider = KmsKeyProvider::from_client(
        KmsKeyProviderConfig::default(),
        aws_sdk_kms::Client::from_conf(sdk_config),
    )
    .expect("valid provider config");
    let debug = format!("{provider:?}");
    assert!(!debug.contains("contract-access-key"), "leaked: {debug}");
    assert!(!debug.contains("contract-secret-key"), "leaked: {debug}");
}
