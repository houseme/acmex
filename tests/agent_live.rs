//! Live remote-agent evidence (roadmap T20, last gap): the real `acmex
//! agent serve` binary runs as a child process and `HttpAgentSink` drives
//! the full stage → activate → health → rollback → cleanup contract against
//! it — the networked counterpart of the in-process fake agent in
//! `tests/http_agent_sink_test.rs`.
//!
//! The tests are self-contained (no `#[ignore]`): each one binds an ephemeral
//! port for the child, waits for the unauthenticated `GET /healthz` probe to
//! answer 200, and only then starts the contract traffic. A kill -9 of the
//! child must surface as `DeploymentHealth::Unknown` at the sink (PR #208
//! semantics: an unreachable agent is never `Unhealthy`, so it can not
//! trigger a rollback), and the token must never appear in any child output.

use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

use acmex::delivery::http_sink::HttpAgentSink;
use acmex::{
    CertificateMaterialBuilder, CertificateMaterialRef, CertificateSink, CertificateVersion,
    CleanupOutcome, DeploymentHealth, DeploymentSpec, IdentifierSet, KeyAlgorithm, KeyId, KeyRef,
    LineageId, SecretBytes, TargetId, VersionId, VersionState,
};

/// Bearer token handed to the child through an `env:` SecretRef.
const TOKEN: &str = "agent-live-secret-token-7f3a";
const TOKEN_ENV: &str = "ACMEX_AGENT_LIVE_TOKEN";

/// How long the child gets to answer `/healthz` before the test fails.
const READINESS_TIMEOUT: Duration = Duration::from_secs(60);

/// An ephemeral listen address (bind-then-drop; the readiness poll rejects
/// anything that is not the real agent).
fn free_listen_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").to_string()
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build http client")
}

struct AgentProcess {
    child: tokio::process::Child,
    base_url: String,
}

impl Drop for AgentProcess {
    fn drop(&mut self) {
        // Never leak the listener into the next test; a no-op once exited.
        // tokio's global orphan reaper collects the killed child, so no
        // zombie survives this test process.
        let _ = self.child.start_kill();
    }
}

/// Spawns `acmex agent serve` (the real binary) with the token provided via
/// an `env:` SecretRef and waits for the readiness probe.
async fn spawn_agent() -> AgentProcess {
    let listen = free_listen_addr();
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_acmex"))
        .args([
            "agent",
            "serve",
            "--listen",
            &listen,
            "--token-ref",
            &format!("env:{TOKEN_ENV}"),
        ])
        .env(TOKEN_ENV, TOKEN)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acmex agent serve");
    let base_url = format!("http://{listen}");
    let mut agent = AgentProcess { child, base_url };
    wait_until_ready(&mut agent).await;
    agent
}

/// Polls `GET /healthz` until the live agent answers 200. The loop checks
/// for early child exit so a crashing binary fails fast with its output
/// instead of burning the whole deadline — and nothing here pretends
/// success: only an observed 200 counts.
async fn wait_until_ready(agent: &mut AgentProcess) {
    let client = http_client();
    let probe = format!("{}/healthz", agent.base_url);
    let deadline = tokio::time::Instant::now() + READINESS_TIMEOUT;
    loop {
        if let Some(status) = agent.child.try_wait().expect("poll agent process") {
            let (stdout, stderr) = drain_pipes(&mut agent.child).await;
            panic!("acmex agent serve exited early ({status}): stdout={stdout} stderr={stderr}");
        }
        if tokio::time::Instant::now() >= deadline {
            let _ = agent.child.start_kill();
            let _ = agent.child.wait().await;
            let (stdout, stderr) = drain_pipes(&mut agent.child).await;
            panic!("agent readiness (GET {probe}) timed out: stdout={stdout} stderr={stderr}");
        }
        if let Ok(response) = client
            .get(format!("{}/healthz", agent.base_url))
            .send()
            .await
            && response.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Reads whatever the exited child left in its (still piped) stdout/stderr.
async fn drain_pipes(child: &mut tokio::process::Child) -> (String, String) {
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout).await;
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr).await;
    }
    (stdout, stderr)
}

fn sample_version(domain: &str) -> (CertificateVersion, String) {
    let certified = rcgen::generate_simple_self_signed([domain.to_string()]).unwrap();
    let version = CertificateVersion {
        id: VersionId::generate(),
        lineage_id: LineageId::generate(),
        identifiers: IdentifierSet::parse([domain]).unwrap(),
        certificate_chain_pem: certified.cert.pem(),
        serial: "01".into(),
        not_before: "2026-01-01T00:00:00Z".into(),
        not_after: "2026-04-01T00:00:00Z".into(),
        issued_by: "contract-ca".into(),
        profile: None,
        key_ref: KeyRef::software(KeyId::generate(), KeyAlgorithm::EcP256),
        replaces: None,
        superseded_by: None,
        verification_report: None,
        state: VersionState::Issued,
    };
    (version, certified.signing_key.serialize_pem())
}

fn webhook_spec() -> DeploymentSpec {
    DeploymentSpec {
        target_id: TargetId::new("edge").unwrap(),
        kind: acmex::DeliveryTargetKind::Webhook,
        reference: "edge-live-1".to_string(),
        requirement: acmex::DeliveryRequirement::Required,
    }
}

fn keyed_material(version: &CertificateVersion, key_pem: &str) -> acmex::CertificateMaterial {
    CertificateMaterialBuilder::new()
        .require_private_key()
        .build(version, Some(SecretBytes::new(key_pem.as_bytes().to_vec())))
        .expect("build certificate material")
}

/// Full sink contract against the live binary: stage (active pointer
/// unchanged) → activate → Healthy → staged-but-not-activated tamper proxy
/// (old pointer survives) → rollback → idempotent cleanup, plus bearer
/// enforcement probed with raw HTTP.
#[tokio::test]
async fn agent_live_full_lifecycle_contract() {
    let mut agent = spawn_agent().await;
    let sink = HttpAgentSink::new("edge-live-1", agent.base_url.clone(), TOKEN);

    // Stage v1: accepted, activation target untouched.
    let (version1, key1) = sample_version("agent-live.example.com");
    let material1 = keyed_material(&version1, &key1);
    let staged1 = sink
        .stage(
            &webhook_spec(),
            &version1,
            CertificateMaterialRef {
                material: &material1,
            },
        )
        .await
        .expect("stage v1 on live agent");
    assert!(staged1.resource_version >= 1, "resource_version must grow");
    assert!(
        matches!(
            sink.health_check(&staged1).await.unwrap(),
            DeploymentHealth::Unhealthy(_)
        ),
        "staged-but-inactive must be Unhealthy (agent reachable, answered)"
    );

    // Activate v1 → the live agent serves it.
    sink.activate(&staged1).await.unwrap();
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Tamper proxy (subprocess state is not directly mutable): stage v2 but
    // do NOT activate it. v2 must read Unhealthy while v1 stays Healthy —
    // staging alone must never move the active pointer.
    let (version2, key2) = sample_version("agent-live-b.example.com");
    let material2 = keyed_material(&version2, &key2);
    let staged2 = sink
        .stage(
            &webhook_spec(),
            &version2,
            CertificateMaterialRef {
                material: &material2,
            },
        )
        .await
        .expect("stage v2 on live agent");
    assert!(matches!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));
    assert_eq!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Healthy,
        "staging v2 must not move the active pointer"
    );

    // Bearer enforcement on the live binary: raw HTTP without/with a wrong
    // token is 401 on both write and read routes.
    let client = http_client();
    let probes = [
        client
            .post(format!("{}/stages", agent.base_url))
            .header("Content-Type", "application/json")
            .body(r#"{"version_id":"intruder","leaf_sha256":"00"}"#),
        client
            .post(format!("{}/stages", agent.base_url))
            .bearer_auth("not-the-token")
            .json(&serde_json::json!({"version_id": "intruder", "leaf_sha256": "00"})),
        client
            .get(format!(
                "{}/stages/{}/health",
                agent.base_url, staged1.version_id
            ))
            .bearer_auth("not-the-token"),
    ];
    for probe in probes {
        let response = probe.send().await.expect("raw HTTP probe");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "expected 401 from the live agent"
        );
    }

    // Rollback deactivates the active route.
    sink.rollback(&staged1).await.unwrap();
    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unhealthy(_)
    ));

    // The staged v2 can still be promoted, then everything is cleaned up;
    // cleanup is idempotent (Cleaned once, AlreadyClean afterwards).
    sink.activate(&staged2).await.unwrap();
    assert_eq!(
        sink.health_check(&staged2).await.unwrap(),
        DeploymentHealth::Healthy
    );
    assert_eq!(
        sink.cleanup(&staged1).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    assert_eq!(
        sink.cleanup(&staged1).await.unwrap(),
        CleanupOutcome::AlreadyClean
    );
    assert_eq!(
        sink.cleanup(&staged2).await.unwrap(),
        CleanupOutcome::Cleaned
    );
    // A cleaned route reads as Unknown (HTTP 404), never as a panic.
    assert!(matches!(
        sink.health_check(&staged1).await.unwrap(),
        DeploymentHealth::Unknown(_)
    ));

    // The token must not have leaked into any child output.
    agent.child.kill().await.expect("stop live agent");
    let _ = agent.child.wait().await;
    let (stdout, stderr) = drain_pipes(&mut agent.child).await;
    assert!(!stdout.contains(TOKEN), "token leaked into agent stdout");
    assert!(!stderr.contains(TOKEN), "token leaked into agent stderr");
}

/// PR #208 evidence on a live process: after `kill -9` of the agent, the
/// sink reports `Unknown` — no panic, no `Unhealthy`, no rollback trigger.
#[tokio::test]
async fn agent_live_unreachable_after_kill_is_unknown() {
    let mut agent = spawn_agent().await;
    let sink = HttpAgentSink::new("edge-live-1", agent.base_url.clone(), TOKEN);

    let (version, key) = sample_version("agent-live-kill.example.com");
    let material = keyed_material(&version, &key);
    let staged = sink
        .stage(
            &webhook_spec(),
            &version,
            CertificateMaterialRef {
                material: &material,
            },
        )
        .await
        .expect("stage on live agent");
    sink.activate(&staged).await.unwrap();
    assert_eq!(
        sink.health_check(&staged).await.unwrap(),
        DeploymentHealth::Healthy
    );

    // Hard-kill and reap the child; the port is closed for good.
    agent.child.kill().await.expect("kill live agent");
    let status = agent.child.wait().await.expect("reap live agent");
    assert!(!status.success(), "killed agent must not exit cleanly");

    let health = sink
        .health_check(&staged)
        .await
        .expect("health check must not error on an unreachable agent");
    assert!(
        matches!(health, DeploymentHealth::Unknown(_)),
        "unreachable agent must be Unknown, got {health:?}"
    );
}

/// `--token-ref` must refuse bare strings (only `env:`/`file:` SecretRefs
/// are accepted) and the rejection output must not echo the plaintext.
#[tokio::test]
async fn agent_live_rejects_bare_token_without_leaking_it() {
    let bare = "bare-plaintext-token-do-not-log";
    let child = tokio::process::Command::new(env!("CARGO_BIN_EXE_acmex"))
        .args([
            "agent",
            "serve",
            "--listen",
            &free_listen_addr(),
            "--token-ref",
            bare,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn acmex agent serve with bare token");
    let output = child.wait_with_output().await.expect("agent output");
    assert!(
        !output.status.success(),
        "bare-string --token-ref must be rejected, got {output:?}"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("env:") || combined.contains("file:"),
        "rejection should explain the env:/file: SecretRef form: {combined}"
    );
    assert!(
        !combined.contains(bare),
        "bare token leaked into CLI output: {combined}"
    );
}
