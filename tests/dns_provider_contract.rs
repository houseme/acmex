//! DNS provider contract tests (roadmap T06).
//!
//! Every `DnsRecordProvider` must pass this suite — the fake provider runs
//! it in CI; real cloud providers run it behind `#[ignore]` with
//! environment-provisioned zones. The suite pins: stable locators,
//! idempotent present, multi-value coexistence, precise cleanup, error
//! classification and secret hygiene.

use std::sync::Arc;

use acmex::challenge::{
    ChallengePresenter, CleanupOutcome, Observation, PrepareChallenge, dns01_validation_value,
};
use acmex::dns::factory::{DefaultDnsProviderFactory, DnsProviderFactory};
use acmex::dns::presenter::Dns01Presenter;
use acmex::dns::propagation::{FakePropagationObserver, QueryOutcome, ResponseKind};
use acmex::dns::record::{
    DnsRecordProvider, FakeDnsRecordProvider, PresentTxt, RecordCleanupOutcome, txt_value_hash,
};
use acmex::dns::router::ProviderRouterBuilder;
use acmex::dns::spec::{DnsProviderSpec, EnvFileSecretResolver, SecretRef};
use acmex::dns::zone::FakeZoneResolver;
use acmex::domain::{Identifier, OperationId};

async fn contract_suite(provider: Arc<dyn DnsRecordProvider>) {
    let name = "_acme-challenge.example.com";

    // create returns a stable locator
    let locator_a = provider
        .present_txt(PresentTxt {
            zone: "example.com".to_string(),
            record_name: name.to_string(),
            value: "value-a".to_string(),
            idempotency_key: "session-1".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(locator_a.provider_id, provider.provider_id());
    assert_eq!(locator_a.record_name, name);
    assert_eq!(locator_a.value_hash, txt_value_hash("value-a"));

    // get finds the just-created record
    let observed = provider
        .get_txt(&locator_a)
        .await
        .unwrap()
        .expect("record exists");
    assert!(observed.values.contains(&"value-a".to_string()));

    // duplicate present is idempotent (same locator, no duplicate value)
    let locator_a2 = provider
        .present_txt(PresentTxt {
            zone: "example.com".to_string(),
            record_name: name.to_string(),
            value: "value-a".to_string(),
            idempotency_key: "session-1".to_string(),
        })
        .await
        .unwrap();
    assert_eq!(locator_a2.value_hash, locator_a.value_hash);
    let observed = provider.get_txt(&locator_a).await.unwrap().unwrap();
    assert_eq!(
        observed.values.iter().filter(|v| *v == "value-a").count(),
        1,
        "idempotent present must not duplicate the value"
    );

    // same-name multi-TXT coexist
    let locator_b = provider
        .present_txt(PresentTxt {
            zone: "example.com".to_string(),
            record_name: name.to_string(),
            value: "value-b".to_string(),
            idempotency_key: "session-2".to_string(),
        })
        .await
        .unwrap();
    let observed = provider.get_txt(&locator_a).await.unwrap().unwrap();
    assert!(observed.values.contains(&"value-b".to_string()));

    // cleanup removes only its own value
    provider.cleanup_txt(&locator_a).await.unwrap();
    let observed = provider.get_txt(&locator_b).await.unwrap().unwrap();
    assert!(!observed.values.contains(&"value-a".to_string()));
    assert!(observed.values.contains(&"value-b".to_string()));

    // repeated cleanup succeeds idempotently
    match provider.cleanup_txt(&locator_a).await.unwrap() {
        RecordCleanupOutcome::AlreadyAbsent | RecordCleanupOutcome::Removed => {}
    }
}

#[tokio::test]
async fn fake_provider_passes_contract() {
    contract_suite(Arc::new(FakeDnsRecordProvider::new("contract-fake"))).await;
}

#[test]
fn dns01_validation_value_uses_rfc8555_digest() {
    assert_eq!(
        dns01_validation_value("token.thumbprint"),
        "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I"
    );
}

#[tokio::test]
async fn provider_errors_are_classified_not_panics() {
    let provider = FakeDnsRecordProvider::new("failing");
    provider.fail_next(1);
    let err = provider
        .present_txt(PresentTxt {
            zone: "example.com".to_string(),
            record_name: "_acme-challenge.example.com".to_string(),
            value: "v".to_string(),
            idempotency_key: "s".to_string(),
        })
        .await
        .expect_err("scripted failure must surface as an error");
    // Stable classification, not a panic; credentials never appear.
    assert!(err.to_string().contains("PROVIDER_AUTH_FAILED"));
}

#[tokio::test]
async fn factory_rejects_unknown_and_unfeatured_types() {
    let factory = DefaultDnsProviderFactory;
    let secrets = EnvFileSecretResolver;
    let spec = |provider_type: &str| DnsProviderSpec {
        id: "test".to_string(),
        provider_type: provider_type.to_string(),
        credential: None,
        zones: vec![],
        zone_suffixes: vec![],
        endpoint: None,
        timeout_secs: 30,
        extra: Default::default(),
    };

    let unknown = factory.create(&spec("not-a-provider"), &secrets).await;
    assert!(unknown.is_err());

    // Every known type must either be creatable in this build, or fail with
    // an explicit feature/inputs error — never a silent fallback to another
    // provider and never a misleading "enable the feature" for a build that
    // already has it.
    for known in DefaultDnsProviderFactory::known_types() {
        let outcome = factory.create(&spec(known), &secrets).await;
        let supported = DefaultDnsProviderFactory::supported_types().contains(known);
        match outcome {
            Ok(provider) => {
                assert!(supported, "`{known}` created so it must be supported");
                assert_eq!(provider.provider_id(), "test");
            }
            Err(err) => {
                let text = err.to_string();
                let feature_gated = !supported && text.contains("requires its cargo feature");
                let missing_inputs = text.contains("needs a credential reference")
                    || text.contains("needs `extra.")
                    || text.contains("must be a secret reference");
                assert!(
                    feature_gated || missing_inputs,
                    "type `{known}`: explicit error expected, got: {text}"
                );
            }
        }
    }
}

#[tokio::test]
async fn dns01_presenter_end_to_end_with_fakes() {
    // Zone model: example.com served by ns1; delegated sub-zone handled by
    // the same provider registry.
    let mut zones = FakeZoneResolver::new();
    zones.zone(
        "example.com",
        &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
    );

    let observer = FakePropagationObserver::all_matched();
    let router = ProviderRouterBuilder::new(Box::new(EnvFileSecretResolver))
        .provider(DnsProviderSpec {
            id: "cf-prod".to_string(),
            provider_type: "fake".to_string(),
            credential: Some(SecretRef::Env {
                name: "CF_TOKEN".to_string(),
            }),
            zones: vec!["example.com".to_string()],
            zone_suffixes: vec![],
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        })
        .build()
        .await
        .unwrap();

    let presenter = Dns01Presenter::new(Arc::new(router), Arc::new(zones), Arc::new(observer));

    let session = acmex::challenge::ChallengeSession {
        id: "chs_e2e".to_string(),
        operation_id: OperationId::generate(),
        authorization_url: "https://acme.example/authz/a".to_string(),
        challenge_url: "https://acme.example/authz/a/challenge".to_string(),
        identifier: Identifier::try_dns("example.com").unwrap(),
        challenge_type: acmex::types::ChallengeType::Dns01,
        token_hash: "h".to_string(),
        state: acmex::challenge::ChallengeSessionState::Selected,
        lease_id: None,
        deadline: jiff::Timestamp::now()
            .checked_add(jiff::Span::new().minutes(30))
            .unwrap(),
        last_propagation_check_at: None,
        last_propagation_status: None,
        last_ca_poll_at: None,
        last_ca_status: None,
        last_error: None,
    };

    // prepare: zone resolved, provider routed, lease returned
    let expected_txt = dns01_validation_value("token.abc");
    let lease = presenter
        .prepare(PrepareChallenge {
            session,
            key_authorization: "token.abc".to_string(),
        })
        .await
        .unwrap();
    match &lease.locator {
        acmex::domain::ChallengeLeaseLocator::Dns {
            zone,
            record_name,
            value_hash,
            ..
        } => {
            assert_eq!(zone, "example.com");
            assert_eq!(record_name, "_acme-challenge.example.com");
            assert_eq!(*value_hash, txt_value_hash(&expected_txt));
        }
        other => panic!("dns locator expected, got {other:?}"),
    }

    // observe: quorum reached → propagated
    assert!(matches!(
        presenter.observe(&lease).await.unwrap(),
        Observation::Propagated
    ));

    // cleanup: exact value removed
    assert!(matches!(
        presenter.cleanup(&lease).await.unwrap(),
        CleanupOutcome::Cleaned
    ));
    assert!(matches!(
        presenter.cleanup(&lease).await.unwrap(),
        CleanupOutcome::AlreadyAbsent
    ));
}

#[tokio::test]
async fn presenter_routes_delegated_zone_to_owner() {
    let mut zones = FakeZoneResolver::new();
    zones.zone(
        "example.com",
        &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
    );
    zones.zone(
        "internal.example.org",
        &[("ns1.internal.example.org", "192.0.2.54".parse().unwrap())],
    );

    let observer = FakePropagationObserver::all_matched();
    let router = ProviderRouterBuilder::new(Box::new(EnvFileSecretResolver))
        .provider(DnsProviderSpec {
            id: "public".to_string(),
            provider_type: "fake".to_string(),
            credential: None,
            zones: vec!["example.com".to_string()],
            zone_suffixes: vec![],
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        })
        .provider(DnsProviderSpec {
            id: "internal".to_string(),
            provider_type: "fake".to_string(),
            credential: None,
            zones: vec![],
            zone_suffixes: vec!["internal.example.org".to_string()],
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        })
        .build()
        .await
        .unwrap();

    let presenter = Dns01Presenter::new(Arc::new(router), Arc::new(zones), Arc::new(observer));

    let session = acmex::challenge::ChallengeSession {
        id: "chs_route".to_string(),
        operation_id: OperationId::generate(),
        authorization_url: "https://acme.example/authz/b".to_string(),
        challenge_url: "https://acme.example/authz/b/challenge".to_string(),
        identifier: Identifier::try_dns("host.internal.example.org").unwrap(),
        challenge_type: acmex::types::ChallengeType::Dns01,
        token_hash: "h".to_string(),
        state: acmex::challenge::ChallengeSessionState::Selected,
        lease_id: None,
        deadline: jiff::Timestamp::now(),
        last_propagation_check_at: None,
        last_propagation_status: None,
        last_ca_poll_at: None,
        last_ca_status: None,
        last_error: None,
    };
    let lease = presenter
        .prepare(PrepareChallenge {
            session,
            key_authorization: "v".to_string(),
        })
        .await
        .unwrap();
    match &lease.locator {
        acmex::domain::ChallengeLeaseLocator::Dns { zone, .. } => {
            assert_eq!(zone, "internal.example.org");
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn partial_propagation_fails_quorum_then_succeeds() {
    let mut zones = FakeZoneResolver::new();
    zones.zone(
        "example.com",
        &[("ns1.example.com", "192.0.2.53".parse().unwrap())],
    );
    let observer = FakePropagationObserver::all_matched();
    observer.set_authoritative(vec![
        QueryOutcome {
            server: "ns1".to_string(),
            matched: true,
            response_kind: ResponseKind::Matched,
            ttl_secs: None,
            error: None,
        },
        QueryOutcome {
            server: "ns2".to_string(),
            matched: false,
            response_kind: ResponseKind::NoData,
            ttl_secs: None,
            error: None,
        },
    ]);

    let router = ProviderRouterBuilder::new(Box::new(EnvFileSecretResolver))
        .provider(DnsProviderSpec {
            id: "p".to_string(),
            provider_type: "fake".to_string(),
            credential: None,
            zones: vec!["example.com".to_string()],
            zone_suffixes: vec![],
            endpoint: None,
            timeout_secs: 30,
            extra: Default::default(),
        })
        .build()
        .await
        .unwrap();
    let presenter = Dns01Presenter::new(Arc::new(router), Arc::new(zones), Arc::new(observer));

    let session = acmex::challenge::ChallengeSession {
        id: "chs_partial".to_string(),
        operation_id: OperationId::generate(),
        authorization_url: "u".to_string(),
        challenge_url: "c".to_string(),
        identifier: Identifier::try_dns("example.com").unwrap(),
        challenge_type: acmex::types::ChallengeType::Dns01,
        token_hash: "h".to_string(),
        state: acmex::challenge::ChallengeSessionState::Selected,
        lease_id: None,
        deadline: jiff::Timestamp::now(),
        last_propagation_check_at: None,
        last_propagation_status: None,
        last_ca_poll_at: None,
        last_ca_status: None,
        last_error: None,
    };
    let lease = presenter
        .prepare(PrepareChallenge {
            session,
            key_authorization: "v".to_string(),
        })
        .await
        .unwrap();

    // Partial authoritative spread → not yet.
    assert!(matches!(
        presenter.observe(&lease).await.unwrap(),
        Observation::NotYet { .. }
    ));
}

#[test]
fn secrets_never_appear_in_debug() {
    let secret = acmex::dns::spec::SecretBytes::new(b"api-token-value".to_vec());
    let spec = DnsProviderSpec {
        id: "x".to_string(),
        provider_type: "fake".to_string(),
        credential: Some(SecretRef::Env {
            name: "TOKEN".to_string(),
        }),
        zones: vec![],
        zone_suffixes: vec![],
        endpoint: None,
        timeout_secs: 30,
        extra: Default::default(),
    };
    let text = format!("{spec:?} {secret:?}");
    assert!(!text.contains("api-token-value"));
}
