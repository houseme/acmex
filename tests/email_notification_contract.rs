//! Contract tests for the SMTP email notification delivery.
//!
//! A fake SMTP server (raw `TcpListener`, optionally upgraded to TLS with a
//! self-signed certificate) drives the real client state machine: greeting,
//! `EHLO` capabilities, `AUTH PLAIN`, envelope, `DATA` with dot-stuffing and
//! `QUIT`. Reply codes are scriptable per command so the terminal/retryable
//! classification and the STARTTLS upgrade path are exercised end to end,
//! without touching a real network.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use acmex::config::{Config, EmailConfig};
use acmex::error::AcmeError;
use acmex::notifications::email::EmailNotifier;
use acmex::notifications::{OutboxDelivery, WebhookManager};
use acmex::repository::OutboxEvent;
use jiff::Timestamp;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Fake SMTP server
// ---------------------------------------------------------------------------

/// Everything the fake server saw, for contract assertions.
#[derive(Default)]
struct Transcript {
    connections: AtomicUsize,
    commands: Mutex<Vec<String>>,
    messages: Mutex<Vec<String>>,
}

impl Transcript {
    fn commands(&self) -> Vec<String> {
        self.commands.lock().unwrap().clone()
    }

    fn messages(&self) -> Vec<String> {
        self.messages.lock().unwrap().clone()
    }
}

/// Scripted server behavior; every field defaults to the happy path.
#[derive(Clone, Default)]
struct Script {
    /// EHLO capability lines advertised after the greeting.
    capabilities: Vec<String>,
    /// Reply code for `MAIL FROM` (default 250).
    mail_from_code: u16,
    /// Reply code for `RCPT TO` (default 250).
    rcpt_to_code: u16,
    /// TLS acceptor used when the client issues `STARTTLS`.
    tls: Option<Arc<tokio_rustls::TlsAcceptor>>,
}

struct FakeServer {
    addr: SocketAddr,
    transcript: Arc<Transcript>,
}

fn ok_script() -> Script {
    Script {
        capabilities: vec!["8BITMIME".to_string(), "SIZE 10485760".to_string()],
        mail_from_code: 250,
        rcpt_to_code: 250,
        tls: None,
    }
}

/// Binds 127.0.0.1:0 and serves connections until the listener is dropped.
async fn spawn_fake_smtp(script: Script) -> FakeServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let transcript = Arc::new(Transcript::default());
    let shared = transcript.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            shared.connections.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            let transcript = shared.clone();
            tokio::spawn(async move {
                let boxed: BoxedStream = Box::new(stream);
                let _ = serve_connection(boxed, &script, &transcript).await;
            });
        }
    });
    FakeServer { addr, transcript }
}

/// Accepts and then never speaks; drives the timeout classification.
async fn spawn_stalled_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                // Hold the socket open without ever sending a byte; both
                // halves must stay alive or the client would see EOF.
                let _held = stream;
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            });
        }
    });
    addr
}

/// Read+write stream bound for type erasure across the STARTTLS upgrade.
trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}

/// Type-erased stream usable both before and after the STARTTLS upgrade.
type BoxedStream = Box<dyn AsyncStream>;

/// One SMTP conversation. When the client issues `STARTTLS` the session is
/// upgraded in place and the command loop continues — per RFC 3207 the
/// server stays silent after the `220` go-ahead and the client re-issues
/// `EHLO` over TLS (no second greeting).
async fn serve_connection(
    stream: BoxedStream,
    script: &Script,
    transcript: &Transcript,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    reader
        .get_mut()
        .write_all(b"220 fake.test ESMTP ready\r\n")
        .await?;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).await? == 0 {
            return Ok(()); // client hung up
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("EHLO") {
            transcript.commands.lock().unwrap().push(line);
            let mut out = String::new();
            if script.capabilities.is_empty() {
                out.push_str("250 fake.test\r\n");
            } else {
                out.push_str("250-fake.test\r\n");
                let last = script.capabilities.len() - 1;
                for (index, capability) in script.capabilities.iter().enumerate() {
                    if index == last {
                        out.push_str(&format!("250 {capability}\r\n"));
                    } else {
                        out.push_str(&format!("250-{capability}\r\n"));
                    }
                }
            }
            reader.get_mut().write_all(out.as_bytes()).await?;
        } else if upper.starts_with("STARTTLS") {
            transcript.commands.lock().unwrap().push(line);
            let Some(acceptor) = &script.tls else {
                reader.get_mut().write_all(b"502 not available\r\n").await?;
                continue;
            };
            reader
                .get_mut()
                .write_all(b"220 ready to start TLS\r\n")
                .await?;
            let plaintext = reader.into_inner();
            let tls = acceptor.accept(plaintext).await?;
            // No new greeting after the upgrade; the client re-EHLOs.
            reader = BufReader::new(Box::new(tls));
        } else if upper.starts_with("AUTH") {
            transcript.commands.lock().unwrap().push(line);
            reader.get_mut().write_all(b"235 authenticated\r\n").await?;
        } else if upper.starts_with("MAIL FROM") {
            transcript.commands.lock().unwrap().push(line);
            reply_code(&mut reader, script.mail_from_code).await?;
        } else if upper.starts_with("RCPT TO") {
            transcript.commands.lock().unwrap().push(line);
            reply_code(&mut reader, script.rcpt_to_code).await?;
        } else if upper.starts_with("DATA") {
            transcript.commands.lock().unwrap().push(line);
            reader
                .get_mut()
                .write_all(b"354 end with <CRLF>.<CRLF>\r\n")
                .await?;
            let mut message = String::new();
            loop {
                let mut data_line = String::new();
                if reader.read_line(&mut data_line).await? == 0 {
                    return Ok(());
                }
                let trimmed = data_line.trim_end_matches(['\r', '\n']);
                if trimmed == "." {
                    break;
                }
                // De-dot-stuffing mirrors the client-side obligation; the
                // CRLF line separators are preserved for header assertions.
                let unstuffed = trimmed.strip_prefix('.').unwrap_or(trimmed);
                message.push_str(unstuffed);
                message.push_str("\r\n");
            }
            transcript.messages.lock().unwrap().push(message);
            reader
                .get_mut()
                .write_all(b"250 queued as fake\r\n")
                .await?;
        } else if upper.starts_with("QUIT") {
            transcript.commands.lock().unwrap().push(line);
            reader.get_mut().write_all(b"221 bye\r\n").await?;
            return Ok(());
        } else {
            reader
                .get_mut()
                .write_all(b"500 unknown command\r\n")
                .await?;
        }
    }
}

async fn reply_code(reader: &mut BufReader<BoxedStream>, code: u16) -> std::io::Result<()> {
    let text = match code {
        200..=399 => "ok".to_string(),
        400..=499 => "try again later".to_string(),
        _ => "requested action not taken".to_string(),
    };
    reader
        .get_mut()
        .write_all(format!("{code} {text}\r\n").as_bytes())
        .await
}

// ---------------------------------------------------------------------------
// Test materialization helpers
// ---------------------------------------------------------------------------

fn unique_temp_file(label: &str) -> PathBuf {
    unique_temp_file_with(label, b"smtp-password-value")
}

/// Collision-proof across parallel tests: pid + process-lifetime counter.
fn unique_temp_file_with(label: &str, contents: &[u8]) -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let seq = COUNTER.fetch_add(1, Ordering::SeqCst);
    let path = std::env::temp_dir().join(format!(
        "acmex-email-contract-{}-{seq}-{label}",
        std::process::id()
    ));
    std::fs::write(&path, contents).expect("write temp file");
    path
}

fn outbox_event(event_type: &str) -> OutboxEvent {
    OutboxEvent {
        sequence: 42,
        event_id: "evt_42".to_string(),
        event_type: event_type.to_string(),
        payload: serde_json::json!({
            "lineage_id": "ln_1",
            "domains": ["example.com", "www.example.com"],
        }),
        created_at: Timestamp::now(),
        attempts: 0,
        last_error: None,
        next_attempt_at: None,
        processed: false,
        dead_lettered: false,
    }
}

/// Builds an `EmailConfig` from JSON (serde is format-agnostic) so each
/// test only spells out the fields it cares about; everything else keeps
/// its serde defaults.
fn email_config(port: u16, extra: &str) -> EmailConfig {
    let json = format!(
        r#"{{
            "smtp_host": "{host}",
            "smtp_port": {port},
            "from": "AcmeX <acmex@example.test>",
            "to": ["ops@example.test", "audit@example.test"],
            {extra}
        }}"#,
        host = "127.0.0.1",
    );
    serde_json::from_str(&json).expect("email config")
}

async fn deliver_to(notifier: &EmailNotifier, event_type: &str) -> Result<(), AcmeError> {
    notifier.deliver(&outbox_event(event_type)).await
}

/// Self-signed TLS material for the fake relay: an acceptor plus the CA
/// PEM the client configures as its only trust anchor.
fn self_signed_tls() -> (tokio_rustls::TlsAcceptor, PathBuf) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
    let cert = params.self_signed(&key_pair).unwrap();
    let ca_pem = unique_temp_file_with("ca.pem", cert.pem().as_bytes());
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
            )
            .expect("server cert"),
    ));
    (acceptor, ca_pem)
}

// ---------------------------------------------------------------------------
// Contract tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plaintext_smtp_delivers_the_full_message_contract() {
    let server = spawn_fake_smtp(ok_script()).await;
    let config = email_config(
        server.addr.port(),
        r#""tls_mode": "none",
           "subject_prefix": "[AcmeX] ",
           "events": []"#,
    );
    let notifier = EmailNotifier::new(config).unwrap();

    deliver_to(&notifier, "operation.created")
        .await
        .expect("delivery succeeds");

    let commands = server.transcript.commands();
    // Protocol state machine: greeting (implicit), EHLO, envelope, data, quit.
    assert!(
        commands.iter().any(|c| c.starts_with("EHLO ")),
        "commands: {commands:?}"
    );
    assert!(
        commands
            .iter()
            .any(|c| c == "MAIL FROM:<acmex@example.test>"),
        "envelope sender missing: {commands:?}"
    );
    assert!(
        commands.iter().any(|c| c == "RCPT TO:<ops@example.test>"),
        "first recipient missing: {commands:?}"
    );
    assert!(
        commands.iter().any(|c| c == "RCPT TO:<audit@example.test>"),
        "second recipient missing: {commands:?}"
    );
    assert!(
        commands.iter().any(|c| c == "DATA"),
        "commands: {commands:?}"
    );
    assert!(
        commands.iter().any(|c| c == "QUIT"),
        "commands: {commands:?}"
    );

    let messages = server.transcript.messages();
    assert_eq!(messages.len(), 1, "exactly one message: {messages:?}");
    let message = &messages[0];
    assert!(message.starts_with("From: AcmeX <acmex@example.test>\r\n"));
    assert!(message.contains("To: ops@example.test, audit@example.test\r\n"));
    assert!(message.contains("Subject: [AcmeX] operation.created\r\n"));
    assert!(message.contains("Date: "), "RFC 5322 date missing");
    assert!(message.contains("MIME-Version: 1.0\r\n"));
    assert!(message.contains("Content-Type: text/plain; charset=utf-8\r\n"));
    // The event type and payload content appear in the body.
    assert!(message.contains("AcmeX event: operation.created"));
    assert!(message.contains("example.com"));
    assert!(message.contains("evt_42"));
}

#[tokio::test]
async fn auth_plain_uses_the_resolved_secret_and_debug_stays_redacted() {
    let server = spawn_fake_smtp(ok_script()).await;
    let password_file = unique_temp_file("password");
    let password_ref = serde_json::json!({
        "kind": "file",
        "path": password_file.to_string_lossy().replace('\\', "/"),
    })
    .to_string();
    let extra = format!(
        r#""tls_mode": "none",
           "username": "acmex-relay",
           "password": {password_ref}"#
    );
    let config = email_config(server.addr.port(), &extra);
    let notifier = EmailNotifier::new(config).unwrap();

    // The Debug output must never carry the user or the secret reference.
    let rendered = format!("{notifier:?}");
    assert!(!rendered.contains("acmex-relay"), "got: {rendered}");
    assert!(!rendered.contains("smtp-password-value"), "got: {rendered}");

    deliver_to(&notifier, "deployment.activated")
        .await
        .expect("authenticated delivery succeeds");

    let commands = server.transcript.commands();
    let auth = commands
        .iter()
        .find(|c| c.starts_with("AUTH PLAIN "))
        .expect("AUTH PLAIN command sent");
    // The wire form is base64("\0user\0password") — verify it decodes to
    // exactly the resolved secret, then make sure nothing else logged it.
    use base64::Engine;
    let encoded = auth.strip_prefix("AUTH PLAIN ").unwrap();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .unwrap();
    let decoded = String::from_utf8(decoded).unwrap();
    assert_eq!(decoded, "\0acmex-relay\0smtp-password-value");
    // AUTH runs after EHLO, before MAIL FROM.
    let ehlo_index = commands.iter().position(|c| c.starts_with("EHLO")).unwrap();
    let auth_index = commands.iter().position(|c| c.starts_with("AUTH")).unwrap();
    let mail_index = commands
        .iter()
        .position(|c| c.starts_with("MAIL FROM"))
        .unwrap();
    assert!(ehlo_index < auth_index && auth_index < mail_index);
}

#[tokio::test]
async fn five_xx_reply_is_a_terminal_error() {
    let script = Script {
        rcpt_to_code: 550,
        ..ok_script()
    };
    let server = spawn_fake_smtp(script).await;
    let config = email_config(server.addr.port(), r#""tls_mode": "none""#);
    let notifier = EmailNotifier::new(config).unwrap();

    let err = deliver_to(&notifier, "operation.created")
        .await
        .expect_err("550 must fail");
    // Terminal failures map to `AcmeError::Protocol` (surfaced as the
    // stable `SMTP_TERMINAL` code in the outbox).
    assert!(
        matches!(err, AcmeError::Protocol(_)),
        "expected terminal classification, got: {err:?}"
    );
    assert!(err.to_string().contains("550"), "got: {err}");
    // MAIL FROM was accepted; the client stops at the rejected recipient.
    let commands = server.transcript.commands();
    assert!(commands.iter().any(|c| c.starts_with("MAIL FROM")));
    assert!(commands.iter().any(|c| c.starts_with("RCPT TO")));
    assert!(
        !commands.iter().any(|c| c == "DATA"),
        "must not send DATA: {commands:?}"
    );
}

#[tokio::test]
async fn four_xx_reply_is_a_retryable_error() {
    let script = Script {
        mail_from_code: 451,
        ..ok_script()
    };
    let server = spawn_fake_smtp(script).await;
    let config = email_config(server.addr.port(), r#""tls_mode": "none""#);
    let notifier = EmailNotifier::new(config).unwrap();

    let err = deliver_to(&notifier, "operation.created")
        .await
        .expect_err("451 must fail");
    assert!(
        matches!(err, AcmeError::Transport(_)),
        "expected retryable classification, got: {err:?}"
    );
    assert!(err.to_string().contains("451"), "got: {err}");
}

#[tokio::test]
async fn event_filter_skips_delivery_without_touching_the_network() {
    let server = spawn_fake_smtp(ok_script()).await;
    let config = email_config(
        server.addr.port(),
        r#""tls_mode": "none", "events": ["operation.created"]"#,
    );
    let notifier = EmailNotifier::new(config).unwrap();

    deliver_to(&notifier, "audit.event")
        .await
        .expect("filtered events are a successful no-op");
    assert_eq!(
        server.transcript.connections.load(Ordering::SeqCst),
        0,
        "filtered-out events must not open a connection"
    );
}

#[tokio::test]
async fn html_body_format_sets_the_html_content_type() {
    let server = spawn_fake_smtp(ok_script()).await;
    let config = email_config(
        server.addr.port(),
        r#""tls_mode": "none", "body_format": "html""#,
    );
    let notifier = EmailNotifier::new(config).unwrap();
    deliver_to(&notifier, "renewal.failed").await.unwrap();

    let message = &server.transcript.messages()[0];
    assert!(message.contains("Content-Type: text/html; charset=utf-8\r\n"));
    assert!(message.contains("<html><body>"));
    assert!(message.contains("AcmeX event: renewal.failed"));
}

#[tokio::test]
async fn implicit_tls_delivers_over_a_verified_channel() {
    let (acceptor, ca_pem) = self_signed_tls();
    // The fake relay terminates TLS immediately (smtps-style).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let transcript = Arc::new(Transcript::default());
    let script = ok_script();
    let shared = transcript.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            shared.connections.fetch_add(1, Ordering::SeqCst);
            let script = script.clone();
            let transcript = shared.clone();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let boxed: BoxedStream = Box::new(tls);
                let _ = serve_connection(boxed, &script, &transcript).await;
            });
        }
    });

    let mut config = email_config(addr.port(), r#""tls_mode": "implicit""#);
    config.smtp_host = "localhost".to_string();
    config.ca_pem_files = vec![ca_pem.to_string_lossy().to_string()];
    let notifier = EmailNotifier::new(config).unwrap();

    deliver_to(&notifier, "certificate.obtained")
        .await
        .expect("implicit-TLS delivery succeeds");
    let messages = transcript.messages();
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("Subject: [AcmeX] certificate.obtained"));
}

#[tokio::test]
async fn starttls_upgrades_the_connection_and_delivers() {
    let (acceptor, ca_pem) = self_signed_tls();
    let script = Script {
        capabilities: vec!["8BITMIME".to_string(), "STARTTLS".to_string()],
        tls: Some(Arc::new(acceptor)),
        ..ok_script()
    };
    let server = spawn_fake_smtp(script).await;

    let mut config = email_config(server.addr.port(), r#""tls_mode": "starttls""#);
    config.smtp_host = "localhost".to_string();
    config.ca_pem_files = vec![ca_pem.to_string_lossy().to_string()];
    let notifier = EmailNotifier::new(config).unwrap();

    deliver_to(&notifier, "operation.created")
        .await
        .expect("STARTTLS delivery succeeds");

    let commands = server.transcript.commands();
    let starttls = commands
        .iter()
        .position(|c| c.eq_ignore_ascii_case("STARTTLS"))
        .expect("STARTTLS issued");
    let ehlo_count = commands.iter().filter(|c| c.starts_with("EHLO ")).count();
    assert_eq!(
        ehlo_count, 2,
        "EHLO before and after the upgrade: {commands:?}"
    );
    // All envelope traffic happens after the STARTTLS command.
    let mail_index = commands
        .iter()
        .position(|c| c.starts_with("MAIL FROM"))
        .expect("MAIL FROM sent");
    assert!(mail_index > starttls);
    assert_eq!(server.transcript.messages().len(), 1);
}

#[tokio::test]
async fn starttls_refused_when_the_server_lacks_the_capability() {
    let script = Script {
        capabilities: vec!["8BITMIME".to_string()],
        ..ok_script()
    };
    let server = spawn_fake_smtp(script).await;
    let config = email_config(server.addr.port(), r#""tls_mode": "starttls""#);
    let notifier = EmailNotifier::new(config).unwrap();

    let err = deliver_to(&notifier, "operation.created")
        .await
        .expect_err("missing STARTTLS capability must fail");
    assert!(
        matches!(err, AcmeError::Protocol(_)),
        "refusing plaintext fallback is terminal, got: {err:?}"
    );
    assert!(err.to_string().contains("STARTTLS"), "got: {err}");
}

#[tokio::test]
async fn tls_without_trust_anchors_reports_the_missing_configuration() {
    // The relay accepts plaintext TCP; the implicit-TLS branch must reject
    // the anchor-less configuration before attempting any handshake.
    let server = spawn_fake_smtp(ok_script()).await;
    let config = email_config(server.addr.port(), r#""tls_mode": "implicit""#);
    let notifier = EmailNotifier::new(config).unwrap();
    let err = notifier
        .deliver(&outbox_event("operation.created"))
        .await
        .expect_err("no trust anchors configured");
    assert!(err.to_string().contains("ca_pem_files"), "got: {err}");
}

#[tokio::test]
async fn stalled_server_classifies_as_timeout() {
    let addr = spawn_stalled_server().await;
    let mut config = email_config(addr.port(), r#""tls_mode": "none", "timeout_secs": 1"#);
    config.timeout_secs = 1;
    let notifier = EmailNotifier::new(config).unwrap();

    let err = deliver_to(&notifier, "operation.created")
        .await
        .expect_err("stalled server must time out");
    assert!(
        matches!(err, AcmeError::Timeout(_)),
        "expected timeout classification, got: {err:?}"
    );
}

#[tokio::test]
async fn fanout_delivers_email_even_when_the_webhook_fails() {
    let server = spawn_fake_smtp(ok_script()).await;
    let config: Config = format!(
        r#"
[[notifications.webhooks]]
url = "http://127.0.0.1:9/hook"

[[notifications.email]]
smtp_host = "127.0.0.1"
smtp_port = {port}
tls_mode = "none"
from = "AcmeX <acmex@example.test>"
to = ["ops@example.test"]
"#,
        port = server.addr.port()
    )
    .parse()
    .unwrap();
    let manager = WebhookManager::from_config(&config).unwrap();

    // The webhook endpoint is dead, but the email must still go out; the
    // aggregated error carries the webhook failure (the environment's
    // HTTP proxy answers the unroutable target with a 502).
    let err = manager
        .deliver(&outbox_event("operation.created"))
        .await
        .expect_err("webhook failure must surface");
    // Case-insensitive: the rendered text differs by network environment
    // (a system proxy's 502 vs a direct connection refusal), but the
    // webhook channel is always named in the failure.
    assert!(
        err.to_string().to_lowercase().contains("webhook"),
        "got: {err}"
    );
    assert_eq!(
        server.transcript.messages().len(),
        1,
        "email delivered despite the webhook failure"
    );
}

#[tokio::test]
async fn fanout_aggregates_errors_from_both_channels() {
    let script = Script {
        rcpt_to_code: 550,
        ..ok_script()
    };
    let server = spawn_fake_smtp(script).await;
    let config: Config = format!(
        r#"
[[notifications.webhooks]]
url = "http://127.0.0.1:9/hook"

[[notifications.email]]
smtp_host = "127.0.0.1"
smtp_port = {port}
tls_mode = "none"
from = "acmex@example.test"
to = ["ops@example.test"]
"#,
        port = server.addr.port()
    )
    .parse()
    .unwrap();
    let manager = WebhookManager::from_config(&config).unwrap();

    let err = manager
        .deliver(&outbox_event("operation.created"))
        .await
        .expect_err("both channels fail");
    let rendered = err.to_string();
    // The terminal SMTP 5xx wins the classification: returning it verbatim
    // (rather than a retryable transport aggregate) means the outbox
    // consumer dead-letters the event instead of retrying to exhaustion.
    // Both channels were still attempted (webhook failure logged above the
    // returned error).
    assert!(
        matches!(err, AcmeError::Protocol(_)),
        "expected the terminal classification to win, got: {rendered}"
    );
    assert!(
        rendered.contains("550"),
        "email error in aggregate: {rendered}"
    );
}

#[tokio::test]
async fn email_only_manager_reports_success_and_respects_the_filter() {
    let server = spawn_fake_smtp(ok_script()).await;
    let config: Config = format!(
        r#"
[[notifications.email]]
smtp_host = "127.0.0.1"
smtp_port = {port}
tls_mode = "none"
events = ["operation.created"]
from = "acmex@example.test"
to = ["ops@example.test"]
"#,
        port = server.addr.port()
    )
    .parse()
    .unwrap();
    let manager = WebhookManager::from_config(&config).unwrap();
    assert!(!manager.is_empty());

    manager
        .deliver(&outbox_event("audit.event"))
        .await
        .expect("filtered event is a no-op success");
    assert_eq!(server.transcript.messages().len(), 0);

    manager
        .deliver(&outbox_event("operation.created"))
        .await
        .expect("matching event delivers");
    assert_eq!(server.transcript.messages().len(), 1);
}

#[test]
fn legacy_config_still_parses_and_unknown_sections_are_ignored() {
    // A pre-change configuration: only the original email fields, plus a
    // `[renewal.hooks]` section that no longer exists. serde ignores
    // unknown fields (no `deny_unknown_fields` anywhere on `Config`), so
    // old files keep parsing — the hooks are silently dropped.
    let legacy = r#"
[renewal]
check_interval = 600

[renewal.hooks]
before = "/usr/local/bin/pre-renew.sh"
after = "/usr/local/bin/post-renew.sh"
on_error = "/usr/local/bin/on-error.sh"

[[notifications.email]]
smtp_host = "relay.example.test"
smtp_port = 25
from = "acmex@example.test"
to = ["ops@example.test"]

[[notifications.webhooks]]
url = "https://hooks.example.test/acmex"
format = "json"
"#;
    let config: Config = legacy.parse().expect("legacy config must keep parsing");
    assert_eq!(config.renewal.check_interval, 600);

    let email = &config.notifications.as_ref().unwrap().email[0];
    assert_eq!(email.smtp_host, "relay.example.test");
    assert_eq!(email.smtp_port, 25);
    // New fields take their serde defaults, keeping old files compatible.
    assert_eq!(email.tls_mode, "starttls");
    assert_eq!(email.subject_prefix, "[AcmeX] ");
    assert_eq!(email.body_format, "text");
    assert_eq!(email.timeout_secs, 30);
    assert_eq!(email.helo_name, "acmex.local");
    assert!(email.ca_pem_files.is_empty());
    assert!(email.events.is_empty());
    assert_eq!(
        config.notifications.as_ref().unwrap().webhooks.len(),
        1,
        "webhooks section unaffected"
    );

    // Assembly still works from the legacy file (defaults to STARTTLS; the
    // relay handshake would fail at delivery time, not at parse time).
    WebhookManager::from_config(&config).expect("legacy config assembles");
}

#[tokio::test]
async fn email_notifier_is_usable_behind_the_outbox_delivery_trait() {
    let server = spawn_fake_smtp(ok_script()).await;
    let mut config = email_config(server.addr.port(), r#""tls_mode": "none""#);
    config.events = vec!["operation.created".to_string()];
    let notifier = EmailNotifier::new(config).unwrap();
    let delivery: Arc<dyn OutboxDelivery> = Arc::new(notifier);

    delivery
        .deliver(&outbox_event("audit.event"))
        .await
        .expect("filtered event is a no-op");
    delivery
        .deliver(&outbox_event("operation.created"))
        .await
        .expect("delivered through the trait object");
    assert_eq!(server.transcript.messages().len(), 1);
}
