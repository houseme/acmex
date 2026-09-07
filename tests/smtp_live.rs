//! Live SMTP email delivery evidence — `#[ignore]`d because it talks to a
//! real SMTP server and asserts delivery through the server's REST API.
//!
//! Live counterpart of the fake-server coverage in
//! `tests/email_notification_contract.rs`: the real `EmailNotifier` SMTP
//! client (greeting, `EHLO`, optional `AUTH PLAIN`, envelope, `DATA`) sends
//! one outbox event to a local SMTP relay, and an *independent* read path —
//! the relay's REST API — proves the message actually arrived. Nothing
//! pretends to succeed: without the REST cross-check this test fails.
//!
//! Configuration (all via environment):
//!
//! ```text
//! ACMEX_LIVE_SMTP_HOST=127.0.0.1        # SMTP host (required)
//! ACMEX_LIVE_SMTP_PORT=1025             # SMTP port (required)
//! ACMEX_LIVE_SMTP_FROM=acmex@example.test  # envelope/header From (required)
//! ACMEX_LIVE_SMTP_TO=ops@example.test   # recipient (default: FROM value)
//! ACMEX_LIVE_SMTP_API=http://127.0.0.1:1825  # REST API base for cross-check
//! ACMEX_LIVE_SMTP_USERNAME=...          # optional; enables AUTH PLAIN
//! ACMEX_LIVE_SMTP_PASSWORD=...          # optional; consumed only through
//!                                       # the `env:` SecretRef below
//! ```
//!
//! Setup used for the recorded evidence run (throwaway local relay):
//!
//! ```text
//! docker run -d --name acmex-smtp-ev -p 1025:1025 -p 1825:8025 axllent/mailpit:latest
//! ```
//!
//! Run: `cargo test --test smtp_live -- --ignored --nocapture`
//!
//! The test sends exactly one message with a unique subject, asserts it in
//! `GET /api/v1/messages`, then deletes that message by id (the relay's
//! store is left untouched otherwise, so a shared relay is safe). SMTP credentials are never hardcoded: the
//! password travels as an `env:` SecretRef resolved per delivery, matching
//! the production configuration contract. A missing environment variable
//! prints an explicit SKIP line — that counts as *no evidence collected*,
//! never as a pass.

use acmex::config::EmailConfig;
use acmex::notifications::OutboxDelivery;
use acmex::notifications::email::EmailNotifier;
use acmex::repository::OutboxEvent;
use jiff::Timestamp;
use serde_json::{Value, json};

const SKIP_MESSAGE: &str = "SKIP: set ACMEX_LIVE_SMTP_HOST, ACMEX_LIVE_SMTP_PORT and \
ACMEX_LIVE_SMTP_FROM against a throwaway local SMTP relay (e.g. Mailpit with its REST \
API at ACMEX_LIVE_SMTP_API, default http://127.0.0.1:1825) to collect live SMTP \
delivery evidence";

struct LiveSmtpConfig {
    host: String,
    port: u16,
    from: String,
    to: String,
    api_base: String,
    username: Option<String>,
}

fn config() -> Option<LiveSmtpConfig> {
    let host = std::env::var("ACMEX_LIVE_SMTP_HOST").ok()?;
    let port = std::env::var("ACMEX_LIVE_SMTP_PORT").ok()?;
    let from = std::env::var("ACMEX_LIVE_SMTP_FROM").ok()?;
    let to = std::env::var("ACMEX_LIVE_SMTP_TO").unwrap_or_else(|_| from.clone());
    let api_base =
        std::env::var("ACMEX_LIVE_SMTP_API").unwrap_or_else(|_| "http://127.0.0.1:1825".into());
    let username = std::env::var("ACMEX_LIVE_SMTP_USERNAME").ok();
    Some(LiveSmtpConfig {
        host,
        port: port
            .parse()
            .unwrap_or_else(|_| panic!("ACMEX_LIVE_SMTP_PORT must be a port number, got {port:?}")),
        from,
        to,
        api_base: api_base.trim_end_matches('/').to_string(),
        username,
    })
}

/// One outbox event with a unique event type, so the expected subject
/// (`[prefix]{event_type}`) cannot collide with older relay contents.
fn live_event(event_type: &str) -> OutboxEvent {
    OutboxEvent {
        sequence: 1,
        event_id: format!("evt_live_{event_type}"),
        event_type: event_type.to_string(),
        payload: json!({"lineage_id": "ln_live_smtp", "evidence": "smtp_live"}),
        created_at: Timestamp::now(),
        attempts: 0,
        last_error: None,
        next_attempt_at: None,
        processed: false,
        dead_lettered: false,
    }
}

#[tokio::test]
#[ignore = "talks to a real SMTP relay and asserts delivery over its REST API"]
async fn live_smtp_email_delivery_is_observed_by_the_relay_api() {
    let Some(config) = config() else {
        eprintln!("{SKIP_MESSAGE}");
        return;
    };
    let now = Timestamp::now();
    let event_type = format!(
        "live.smtp.{}.{:09}",
        now.as_second(),
        now.as_nanosecond() % 1_000_000_000
    );
    let expected_subject = format!("[AcmeX-live] {event_type}");
    println!("live smtp target: {}:{}", config.host, config.port);

    let mut settings = json!({
        "smtp_host": config.host,
        "smtp_port": config.port,
        "from": config.from,
        "to": [config.to],
        "tls_mode": "none",
        "subject_prefix": "[AcmeX-live] ",
        "helo_name": "acmex.live.test",
        "timeout_secs": 20
    });
    if let Some(username) = &config.username {
        // The password itself only ever travels as an `env:` SecretRef; the
        // notifier resolves it per delivery and never logs it.
        std::env::var("ACMEX_LIVE_SMTP_PASSWORD").expect(
            "ACMEX_LIVE_SMTP_PASSWORD must be set when ACMEX_LIVE_SMTP_USERNAME is configured",
        );
        settings["username"] = json!(username);
        settings["password"] = json!("env:ACMEX_LIVE_SMTP_PASSWORD");
        println!("AUTH PLAIN enabled for user {username} (password via env: SecretRef)");
    }
    let settings: EmailConfig = serde_json::from_value(settings).expect("email settings");
    let notifier = EmailNotifier::new(settings).expect("notifier assembly");

    // Sanity before the delivery: the relay API must be reachable so a later
    // assertion cannot silently pass on a stale store.
    let client = reqwest::Client::new();
    let before: Value = client
        .get(format!("{}/api/v1/messages", config.api_base))
        .send()
        .await
        .expect("reach the relay REST API for the pre-check")
        .json()
        .await
        .expect("relay REST API JSON");
    println!(
        "relay API reachable; messages in store before delivery: {}",
        before["total"]
    );

    let event = live_event(&event_type);
    OutboxDelivery::deliver(&notifier, &event)
        .await
        .expect("SMTP delivery must succeed against the live relay");
    println!("SMTP transaction completed; expected subject: {expected_subject}");

    // Independent read path: poll the relay's REST API until the message
    // shows up (well-behaved relays accept almost instantly, but delivery
    // must be *observed*, not assumed).
    let mut delivered: Option<Value> = None;
    for _ in 0..20 {
        let listing: Value = client
            .get(format!("{}/api/v1/messages", config.api_base))
            .send()
            .await
            .expect("relay REST API GET")
            .json()
            .await
            .expect("relay REST API JSON");
        if let Some(matched) = listing["messages"]
            .as_array()
            .expect("relay message list")
            .iter()
            .find(|message| message["Subject"] == json!(expected_subject))
        {
            delivered = Some(matched.clone());
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    let message = delivered.expect("the sent message must appear in the relay's REST API");
    println!(
        "relay API observed the message: id={} from={} to={} subject={}",
        message["ID"], message["From"]["Address"], message["To"][0]["Address"], message["Subject"]
    );
    assert_eq!(
        message["Subject"], expected_subject,
        "the relay must hold exactly the subject the notifier rendered"
    );

    // Cleanup: delete exactly the message this run produced (by id), so a
    // shared relay store is left untouched; assert the deletion removed it.
    let message_id = message["ID"]
        .as_str()
        .expect("relay message carries an id")
        .to_string();
    let deleted = client
        .delete(format!("{}/api/v1/message/{message_id}", config.api_base))
        .send()
        .await
        .expect("relay REST API DELETE");
    assert!(
        deleted.status().is_success(),
        "cleanup DELETE failed: HTTP {}",
        deleted.status()
    );
    let after: Value = client
        .get(format!("{}/api/v1/messages", config.api_base))
        .send()
        .await
        .expect("relay REST API GET after cleanup")
        .json()
        .await
        .expect("relay REST API JSON");
    assert!(
        !after["messages"]
            .as_array()
            .expect("relay message list")
            .iter()
            .any(|message| message["ID"] == json!(message_id)),
        "the deleted message must be gone from the relay"
    );
    println!(
        "✅ live SMTP delivery observed via {} and cleaned up",
        config.api_base
    );
}
