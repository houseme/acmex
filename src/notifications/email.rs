//! SMTP email delivery for the durable outbox (`[[notifications.email]]`).
//!
//! [`EmailNotifier`] consumes [`OutboxEvent`]s and hands them to an SMTP
//! relay over a hand-written, minimal SMTP client (RFC 5321): implicit TLS
//! (smtps, usually port 465), STARTTLS upgrade (587/25) or — explicitly
//! configured — plaintext. The `events` list mirrors the webhook
//! `event_type_filter` semantics: outbox event-type strings, empty = all.
//!
//! Error semantics align with the rest of the notifications module:
//!
//! * 2xx replies succeed;
//! * 4xx replies, connection failures and timeouts are retryable
//!   ([`AcmeError::Transport`] / [`AcmeError::Timeout`]);
//! * 5xx replies and protocol violations are terminal
//!   ([`AcmeError::Protocol`]) — retrying the same message cannot succeed.
//!
//! Credentials (`AUTH PLAIN` user/password resolved from a
//! [`SecretRef`]) live only inside a single delivery call: they are never
//! logged, never appear in [`std::fmt::Debug`] output and never surface in
//! error messages.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use jiff::tz::TimeZone;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tracing::debug;

use crate::config::EmailConfig;
use crate::dns::spec::{EnvFileSecretResolver, SecretResolver};
use crate::error::{AcmeError, Result};
use crate::repository::OutboxEvent;

/// Upper bound for the TCP connect phase; the overall delivery timeout
/// ([`EmailConfig::timeout_secs`]) still applies on top of this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Retry semantics of a failed SMTP delivery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpErrorClass {
    /// 4xx replies, connection problems, timeouts: the message may be
    /// retried later by the outbox consumer.
    Retryable,
    /// 5xx replies and protocol violations: retrying the same message is
    /// pointless (the consumer will dead-letter it after its attempt
    /// budget).
    Terminal,
}

/// Transport-level TLS mode for the SMTP session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpTlsMode {
    /// TLS is negotiated immediately on connect (smtps, usually port 465).
    Implicit,
    /// Plain connect, then upgrade through `STARTTLS` (ports 587/25). The
    /// server must advertise the capability or delivery fails.
    StartTls,
    /// No TLS at all. Explicit opt-in for local relays; never a fallback.
    None,
}

impl SmtpTlsMode {
    /// Parses the configured `tls_mode` string. Unknown values are a
    /// configuration error instead of silently downgrading security.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "implicit" | "smtps" => Ok(Self::Implicit),
            "none" | "plain" => Ok(Self::None),
            other => Err(AcmeError::configuration(format!(
                "notifications.email.tls_mode `{other}` is not one of starttls|implicit|none"
            ))),
        }
    }
}

/// MIME type used for the message body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmailBodyFormat {
    /// `text/plain` (default).
    Text,
    /// `text/html`; the JSON payload is rendered inside an escaped `<pre>`.
    Html,
}

impl EmailBodyFormat {
    /// Parses the configured `body_format` string.
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "text" | "plain" => Ok(Self::Text),
            "html" => Ok(Self::Html),
            other => Err(AcmeError::configuration(format!(
                "notifications.email.body_format `{other}` is not one of text|html"
            ))),
        }
    }

    /// The MIME content type for the single-part message.
    fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain",
            Self::Html => "text/html",
        }
    }
}

/// Why an SMTP exchange failed, with its retry classification.
#[derive(Debug, Clone)]
struct SmtpFailure {
    class: SmtpErrorClass,
    message: String,
}

impl SmtpFailure {
    fn terminal(message: impl Into<String>) -> Self {
        Self {
            class: SmtpErrorClass::Terminal,
            message: message.into(),
        }
    }

    fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: SmtpErrorClass::Retryable,
            message: message.into(),
        }
    }

    /// Maps onto the crate error type. `AcmeError::Protocol` is reused as
    /// the "permanent SMTP failure" carrier: on the outbox delivery path it
    /// can only originate from this module, and `stable_delivery_error`
    /// surfaces it as a distinct stable code.
    fn into_acme_error(self, endpoint: &str) -> AcmeError {
        match self.class {
            SmtpErrorClass::Terminal => {
                AcmeError::Protocol(format!("email {endpoint}: {}", self.message))
            }
            SmtpErrorClass::Retryable => {
                AcmeError::Transport(format!("email {endpoint}: {}", self.message))
            }
        }
    }
}

impl From<std::io::Error> for SmtpFailure {
    fn from(err: std::io::Error) -> Self {
        SmtpFailure::retryable(format!("SMTP connection I/O failed: {err}"))
    }
}

impl From<AcmeError> for SmtpFailure {
    /// Assembly-level problems (bad TLS mode, unreadable trust anchors)
    /// are permanent: no amount of retrying fixes a broken configuration.
    fn from(err: AcmeError) -> Self {
        SmtpFailure::terminal(err.to_string())
    }
}

/// One complete SMTP reply: a numeric code plus the payload lines of the
/// (possibly multi-line) response.
#[derive(Debug, Clone)]
struct SmtpReply {
    code: u16,
    lines: Vec<String>,
}

impl SmtpReply {
    fn class(&self) -> SmtpErrorClass {
        if self.code >= 500 {
            SmtpErrorClass::Terminal
        } else {
            SmtpErrorClass::Retryable
        }
    }

    /// Fails unless the reply is a 2xx success.
    fn ensure_success(self, command: &str) -> std::result::Result<Self, SmtpFailure> {
        if (200..300).contains(&self.code) {
            Ok(self)
        } else {
            Err(self.into_failure(command))
        }
    }

    /// Fails unless the reply carries exactly the expected code (used for
    /// the 220 greeting, 354 DATA continuation and 220 STARTTLS go-ahead).
    fn ensure_code(self, expected: u16, command: &str) -> std::result::Result<Self, SmtpFailure> {
        if self.code == expected {
            Ok(self)
        } else {
            Err(self.into_failure(command))
        }
    }

    fn into_failure(self, command: &str) -> SmtpFailure {
        let class = self.class();
        let message = format!(
            "{command} rejected with {code}: {text}",
            code = self.code,
            text = self.lines.join(" | ")
        );
        SmtpFailure { class, message }
    }
}

/// Reads one complete SMTP reply, transparently consuming `250-`
/// continuation lines until the final `250 ` line.
///
/// Malformed lines (fewer than three digits, non-digit prefixes such as a
/// leading `-`, garbage codes) are terminal protocol violations; a peer
/// that closes the connection mid-reply is retryable. Never panics.
async fn read_reply<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> std::result::Result<SmtpReply, SmtpFailure> {
    let mut lines = Vec::new();
    loop {
        let mut raw = Vec::new();
        let read = reader.read_until(b'\n', &mut raw).await?;
        if read == 0 {
            return Err(SmtpFailure::retryable(
                "connection closed by the SMTP server before a complete reply",
            ));
        }
        let text = String::from_utf8_lossy(&raw);
        let text = text.trim_end_matches(['\r', '\n']);
        let bytes = text.as_bytes();
        if bytes.len() < 3 || !bytes[..3].iter().all(u8::is_ascii_digit) {
            return Err(SmtpFailure::terminal(format!(
                "malformed SMTP reply line {text:?}"
            )));
        }
        // Manual digit math keeps this panic-free by construction.
        let code = (bytes[0] - b'0') as u16 * 100
            + (bytes[1] - b'0') as u16 * 10
            + (bytes[2] - b'0') as u16;
        let continuation = bytes.get(3) == Some(&b'-');
        let text = text[3..].trim_start_matches([' ', '-']).to_string();
        lines.push(text);
        if !continuation {
            return Ok(SmtpReply { code, lines });
        }
    }
}

/// Sends one command line (CRLF is appended here) and reads the reply.
async fn send_command<S>(
    reader: &mut BufReader<S>,
    command: &str,
) -> std::result::Result<SmtpReply, SmtpFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    reader.get_mut().write_all(command.as_bytes()).await?;
    reader.get_mut().write_all(b"\r\n").await?;
    reader.get_mut().flush().await?;
    // Only the command verb is ever logged; arguments may carry credentials.
    debug!(
        verb = command.split(' ').next().unwrap_or(""),
        "smtp command sent"
    );
    read_reply(reader).await
}

/// Reads and validates the initial `220` greeting.
async fn read_greeting<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> std::result::Result<(), SmtpFailure> {
    let reply = read_reply(reader).await?;
    reply.ensure_code(220, "greeting").map(|_| ())
}

/// Sends `EHLO` and returns the advertised capability lines.
async fn ehlo<S>(
    reader: &mut BufReader<S>,
    helo_name: &str,
) -> std::result::Result<Vec<String>, SmtpFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let reply = send_command(reader, &format!("EHLO {helo_name}")).await?;
    reply.ensure_success("EHLO").map(|reply| reply.lines)
}

/// The full mail transaction after the transport is in its final (post-TLS)
/// state: `EHLO`, optional `AUTH PLAIN`, envelope and data.
async fn mail_transaction<S>(
    reader: &mut BufReader<S>,
    helo_name: &str,
    auth_line: Option<&str>,
    message: &PreparedMessage,
) -> std::result::Result<(), SmtpFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    ehlo(reader, helo_name).await?;

    if let Some(auth_line) = auth_line {
        let reply = send_command(reader, auth_line).await?;
        reply.ensure_success("AUTH PLAIN").map(|_| ())?;
    }

    let reply = send_command(reader, &format!("MAIL FROM:<{}>", message.envelope_from)).await?;
    reply.ensure_success("MAIL FROM").map(|_| ())?;

    for recipient in &message.recipients {
        let reply = send_command(reader, &format!("RCPT TO:<{recipient}>")).await?;
        reply.ensure_success("RCPT TO").map(|_| ())?;
    }

    let reply = send_command(reader, "DATA").await?;
    reply.ensure_code(354, "DATA").map(|_| ())?;

    reader
        .get_mut()
        .write_all(message.wire_data.as_bytes())
        .await?;
    reader.get_mut().flush().await?;
    let reply = read_reply(reader).await?;
    reply.ensure_success("message body").map(|_| ())?;

    // QUIT is best-effort: the message is already accepted.
    let _ = send_command(reader, "QUIT").await;
    Ok(())
}

/// Plaintext preamble of a STARTTLS session: greeting, `EHLO` (requiring
/// the STARTTLS capability) and the `STARTTLS` command up to (excluding)
/// the actual TLS handshake.
async fn starttls_negotiate<S>(
    reader: &mut BufReader<S>,
    helo_name: &str,
) -> std::result::Result<(), SmtpFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    read_greeting(reader).await?;
    let capabilities = ehlo(reader, helo_name).await?;
    let supports_starttls = capabilities
        .iter()
        .any(|capability| capability.trim().eq_ignore_ascii_case("STARTTLS"));
    if !supports_starttls {
        return Err(SmtpFailure::terminal(
            "server does not advertise STARTTLS; refusing to send credentials or content in plaintext",
        ));
    }
    let reply = send_command(reader, "STARTTLS").await?;
    reply.ensure_code(220, "STARTTLS").map(|_| ())
}

/// Everything the SMTP session needs, already validated and rendered.
struct PreparedMessage {
    envelope_from: String,
    recipients: Vec<String>,
    /// Full DATA payload: headers + body, dot-stuffed, `.`-terminated.
    wire_data: String,
}

/// Outbound email delivery over a minimal hand-written SMTP client.
pub struct EmailNotifier {
    settings: EmailConfig,
    tls_mode: SmtpTlsMode,
    body_format: EmailBodyFormat,
    secrets: Arc<dyn SecretResolver>,
}

impl fmt::Debug for EmailNotifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Credentials are deliberately never part of the Debug output, not
        // even the secret *reference* — only whether one is configured.
        f.debug_struct("EmailNotifier")
            .field("name", &self.name())
            .field("smtp_host", &self.settings.smtp_host)
            .field("smtp_port", &self.settings.smtp_port)
            .field("from", &self.settings.from)
            .field("recipients", &self.settings.to)
            .field("tls_mode", &self.tls_mode)
            .field("body_format", &self.body_format)
            .field("events", &self.settings.events)
            .field("helo_name", &self.settings.helo_name)
            .field("timeout_secs", &self.settings.timeout_secs)
            .field("auth_configured", &self.settings.username.is_some())
            .field("password_configured", &self.settings.password.is_some())
            .finish()
    }
}

impl EmailNotifier {
    /// Creates a notifier from `[notifications.email]` settings with the
    /// default `env:`/`file:` secret resolver.
    ///
    /// Fails fast on unusable settings (empty host/recipients, unknown TLS
    /// or body-format mode, half-configured credentials) so a broken email
    /// section surfaces at assembly time instead of failing every delivery.
    pub fn new(settings: EmailConfig) -> Result<Self> {
        Self::new_with_resolver(settings, Arc::new(EnvFileSecretResolver))
    }

    /// Creates a notifier with an explicit secret resolver.
    pub fn new_with_resolver(
        mut settings: EmailConfig,
        secrets: Arc<dyn SecretResolver>,
    ) -> Result<Self> {
        if settings.name.is_none() {
            settings.name = Some(format!(
                "smtp://{}:{}",
                settings.smtp_host, settings.smtp_port
            ));
        }
        if settings.smtp_host.trim().is_empty() {
            return Err(AcmeError::configuration(
                "notifications.email.smtp_host cannot be empty",
            ));
        }
        if settings.from.trim().is_empty() {
            return Err(AcmeError::configuration(
                "notifications.email.from cannot be empty",
            ));
        }
        if settings.to.is_empty() {
            return Err(AcmeError::configuration(
                "notifications.email.to cannot be empty",
            ));
        }
        match (&settings.username, &settings.password) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) | (None, Some(_)) => {
                return Err(AcmeError::configuration(
                    "notifications.email.username and password must be configured together",
                ));
            }
        }
        let tls_mode = SmtpTlsMode::parse(&settings.tls_mode)?;
        let body_format = EmailBodyFormat::parse(&settings.body_format)?;
        // Header injection guard: these values become message headers.
        for (field, value) in [
            ("from", settings.from.as_str()),
            ("subject_prefix", settings.subject_prefix.as_str()),
            ("helo_name", settings.helo_name.as_str()),
        ] {
            if value.chars().any(is_forbidden_header_char) {
                return Err(AcmeError::configuration(format!(
                    "notifications.email.{field} contains CR/LF/NUL characters"
                )));
            }
        }
        for recipient in &settings.to {
            if recipient.chars().any(is_forbidden_header_char) {
                return Err(AcmeError::configuration(
                    "notifications.email.to entries must not contain CR/LF/NUL characters",
                ));
            }
        }
        Ok(Self {
            settings,
            tls_mode,
            body_format,
            secrets,
        })
    }

    /// The configured (or derived) instance name for logs and errors.
    pub fn name(&self) -> String {
        self.settings.name.clone().unwrap_or_else(|| {
            format!(
                "smtp://{}:{}",
                self.settings.smtp_host, self.settings.smtp_port
            )
        })
    }

    /// Whether this notifier accepts the given outbox event type. An empty
    /// `events` list delivers everything, matching the webhook
    /// `event_type_filter` semantics.
    pub fn should_deliver(&self, event_type: &str) -> bool {
        self.settings.events.is_empty() || self.settings.events.iter().any(|e| e == event_type)
    }

    /// Delivers one outbox event as a single-part MIME email.
    ///
    /// Filtered-out events are skipped without touching the network.
    pub async fn deliver(&self, event: &OutboxEvent) -> Result<()> {
        if !self.should_deliver(&event.event_type) {
            debug!(
                endpoint = %self.name(),
                event_type = %event.event_type,
                "skipping outbox event not in email filter"
            );
            return Ok(());
        }
        let auth_line = self.auth_command_line().await?;
        let message = prepare_message(&self.settings, self.body_format, event)?;
        let overall = Duration::from_secs(self.settings.timeout_secs.max(1));
        match tokio::time::timeout(overall, self.send_message(message, auth_line)).await {
            Ok(result) => result,
            Err(_) => Err(AcmeError::Timeout(format!(
                "email {}: SMTP exchange exceeded the overall timeout of {}s",
                self.name(),
                overall.as_secs()
            ))),
        }
    }

    /// Connects and runs the session according to the TLS mode. The whole
    /// future is bounded by the caller's overall timeout.
    async fn send_message(
        &self,
        message: PreparedMessage,
        auth_line: Option<String>,
    ) -> Result<()> {
        let host = self.settings.smtp_host.as_str();
        let port = self.settings.smtp_port;
        let connect_timeout =
            CONNECT_TIMEOUT.min(Duration::from_secs(self.settings.timeout_secs.max(1)));
        let tcp =
            match tokio::time::timeout(connect_timeout, TcpStream::connect((host, port))).await {
                Ok(Ok(tcp)) => tcp,
                Ok(Err(err)) => {
                    return Err(AcmeError::Transport(format!(
                        "email {}: connecting to {host}:{port} failed: {err}",
                        self.name()
                    )));
                }
                Err(_) => {
                    return Err(AcmeError::Timeout(format!(
                        "email {}: connecting to {host}:{port} exceeded {}s",
                        self.name(),
                        connect_timeout.as_secs()
                    )));
                }
            };

        let endpoint = self.name();
        let outcome: std::result::Result<(), SmtpFailure> = match self.tls_mode {
            SmtpTlsMode::Implicit => {
                async {
                    let connector = self.tls_connector()?;
                    let server_name = self.tls_server_name()?;
                    let tls = self.tls_connect(tcp, &connector, server_name).await?;
                    let mut reader = BufReader::new(tls);
                    read_greeting(&mut reader).await?;
                    mail_transaction(
                        &mut reader,
                        &self.settings.helo_name,
                        auth_line.as_deref(),
                        &message,
                    )
                    .await
                }
                .await
            }
            SmtpTlsMode::StartTls => {
                async {
                    // Negotiate first: a server that cannot upgrade must be
                    // rejected before any TLS assembly is even attempted.
                    let mut reader = BufReader::new(tcp);
                    starttls_negotiate(&mut reader, &self.settings.helo_name).await?;
                    let connector = self.tls_connector()?;
                    let server_name = self.tls_server_name()?;
                    let tls = self
                        .tls_connect(reader.into_inner(), &connector, server_name)
                        .await?;
                    let mut reader = BufReader::new(tls);
                    mail_transaction(
                        &mut reader,
                        &self.settings.helo_name,
                        auth_line.as_deref(),
                        &message,
                    )
                    .await
                }
                .await
            }
            SmtpTlsMode::None => {
                async {
                    let mut reader = BufReader::new(tcp);
                    read_greeting(&mut reader).await?;
                    mail_transaction(
                        &mut reader,
                        &self.settings.helo_name,
                        auth_line.as_deref(),
                        &message,
                    )
                    .await
                }
                .await
            }
        };
        outcome.map_err(|failure| failure.into_acme_error(&endpoint))
    }

    /// TLS handshake wrapper; failures are retryable transport errors.
    async fn tls_connect(
        &self,
        tcp: TcpStream,
        connector: &TlsConnector,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> std::result::Result<tokio_rustls::client::TlsStream<TcpStream>, SmtpFailure> {
        connector.connect(server_name, tcp).await.map_err(|err| {
            SmtpFailure::retryable(format!(
                "TLS handshake with {}:{} failed: {err}",
                self.settings.smtp_host, self.settings.smtp_port
            ))
        })
    }

    /// Resolves the configured credentials and builds the `AUTH PLAIN`
    /// command line. The line is a transient value scoped to one delivery;
    /// it is never logged and the resolved password bytes are zeroized when
    /// the resolver's `SecretBytes` is dropped.
    async fn auth_command_line(&self) -> Result<Option<String>> {
        let (Some(username), Some(password_ref)) =
            (&self.settings.username, &self.settings.password)
        else {
            return Ok(None);
        };
        let password = self.secrets.resolve(password_ref).await?;
        let password = password.expose_utf8().ok_or_else(|| {
            AcmeError::configuration(format!(
                "email {}: SMTP password {} is not valid UTF-8",
                self.name(),
                password_ref.describe()
            ))
        })?;
        let plain = format!("\u{0}{username}\u{0}{password}");
        let encoded = BASE64_STANDARD.encode(plain.as_bytes());
        Ok(Some(format!("AUTH PLAIN {encoded}")))
    }

    /// Builds the rustls connector from the configured trust anchors.
    ///
    /// TLS modes require at least one `ca_pem_files` entry: with no
    /// system-root dependency, a verifier without anchors could only fail
    /// every handshake, so that misconfiguration is rejected upfront.
    fn tls_connector(&self) -> Result<TlsConnector> {
        let mut roots = rustls::RootCertStore::empty();
        for path in &self.settings.ca_pem_files {
            let pem = std::fs::read(path).map_err(|err| {
                AcmeError::configuration(format!(
                    "email {}: cannot read CA PEM file {path}: {err}",
                    self.name()
                ))
            })?;
            for item in ::pem::parse_many(pem.as_slice()).map_err(|err| {
                AcmeError::configuration(format!(
                    "email {}: cannot parse CA PEM file {path}: {err}",
                    self.name()
                ))
            })? {
                if item.tag() != "CERTIFICATE" {
                    continue;
                }
                let certificate = rustls::pki_types::CertificateDer::from(item.contents().to_vec());
                roots.add(certificate).map_err(|err| {
                    AcmeError::configuration(format!(
                        "email {}: cannot add CA from {path}: {err}",
                        self.name()
                    ))
                })?;
            }
        }
        if roots.is_empty() {
            return Err(AcmeError::configuration(format!(
                "email {}: TLS mode `{}` requires at least one trust anchor in ca_pem_files",
                self.name(),
                self.settings.tls_mode
            )));
        }
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }

    /// The TLS server name from `smtp_host`.
    fn tls_server_name(&self) -> Result<rustls::pki_types::ServerName<'static>> {
        rustls::pki_types::ServerName::try_from(self.settings.smtp_host.clone()).map_err(|err| {
            AcmeError::configuration(format!(
                "email {}: invalid TLS server name {:?}: {err}",
                self.name(),
                self.settings.smtp_host
            ))
        })
    }
}

#[async_trait::async_trait]
impl crate::notifications::OutboxDelivery for EmailNotifier {
    async fn deliver(&self, event: &OutboxEvent) -> Result<()> {
        EmailNotifier::deliver(self, event).await
    }
}

fn is_forbidden_header_char(c: char) -> bool {
    matches!(c, '\r' | '\n' | '\0')
}

/// Extracts the bare address from a mailbox that may be written as
/// `"Display Name" <user@host>` or plain `user@host`.
fn envelope_address(mailbox: &str) -> Result<String> {
    let trimmed = mailbox.trim();
    let address = match (trimmed.find('<'), trimmed.find('>')) {
        (Some(start), Some(end)) if end > start => trimmed[start + 1..end].trim(),
        _ => trimmed,
    };
    if address.is_empty() || !address.contains('@') || address.chars().any(is_forbidden_header_char)
    {
        return Err(AcmeError::configuration(format!(
            "invalid SMTP mailbox {trimmed:?}: expected user@host or Name <user@host>"
        )));
    }
    Ok(address.to_string())
}

/// RFC 5322 date from the current time (jiff, UTC).
fn rfc5322_date() -> String {
    jiff::Timestamp::now()
        .to_zoned(TimeZone::UTC)
        .strftime("%a, %d %b %Y %H:%M:%S %z")
        .to_string()
}

/// RFC 2047 B-encodes the subject when it is not plain ASCII, split across
/// folded encoded words so no line exceeds the 78-character guideline.
fn encode_subject(subject: &str) -> String {
    if subject.is_ascii() {
        return subject.to_string();
    }
    // 45 base64 payload chars keep `=?utf-8?B?...?=` under 76 chars; split
    // on char boundaries so multi-byte characters stay intact.
    const MAX_CHUNK_BYTES: usize = 45;
    let mut words: Vec<String> = Vec::new();
    let mut chunk = String::new();
    let mut chunk_bytes = 0usize;
    for c in subject.chars() {
        let len = c.len_utf8();
        if chunk_bytes + len > MAX_CHUNK_BYTES {
            words.push(format!(
                "=?utf-8?B?{}?=",
                BASE64_STANDARD.encode(chunk.as_bytes())
            ));
            chunk.clear();
            chunk_bytes = 0;
        }
        chunk.push(c);
        chunk_bytes += len;
    }
    if !chunk.is_empty() {
        words.push(format!(
            "=?utf-8?B?{}?=",
            BASE64_STANDARD.encode(chunk.as_bytes())
        ));
    }
    // Folding whitespace between encoded words is ignored by mail parsers.
    words.join("\r\n ")
}

/// Minimal HTML escaping for the `<pre>` payload block.
fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Renders headers plus body for one outbox event.
fn prepare_message(
    settings: &EmailConfig,
    body_format: EmailBodyFormat,
    event: &OutboxEvent,
) -> Result<PreparedMessage> {
    let envelope_from = envelope_address(&settings.from)?;
    let mut recipients = Vec::with_capacity(settings.to.len());
    for recipient in &settings.to {
        recipients.push(envelope_address(recipient)?);
    }

    let subject = encode_subject(&format!("{}{}", settings.subject_prefix, event.event_type));
    let payload = serde_json::to_string_pretty(&event.payload).unwrap_or_else(|_| "{}".to_string());
    let body = match body_format {
        EmailBodyFormat::Text => format!(
            "AcmeX event: {}\r\n\r\nevent_id: {}\r\nsequence: {}\r\ncreated_at: {}\r\n\r\npayload:\r\n{}",
            event.event_type, event.event_id, event.sequence, event.created_at, payload
        ),
        EmailBodyFormat::Html => format!(
            "<html><body><p>AcmeX event: {}</p><pre>{}</pre></body></html>",
            escape_html(&event.event_type),
            escape_html(&payload)
        ),
    };

    let message = format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Subject: {subject}\r\n\
         Date: {date}\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: {content_type}; charset=utf-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\
         \r\n\
         {body}",
        from = settings.from,
        to = settings.to.join(", "),
        subject = subject,
        date = rfc5322_date(),
        content_type = body_format.content_type(),
        body = body,
    );
    // The rendered message has \r\n line separators and no trailing CRLF;
    // to_wire_data adds per-line stuffing and the final terminator.
    let wire_data = to_wire_data(&message);

    Ok(PreparedMessage {
        envelope_from,
        recipients,
        wire_data,
    })
}

/// Applies SMTP dot-stuffing to every line and appends the `.` terminator,
/// producing the exact byte sequence sent after the `354` continuation.
fn to_wire_data(message: &str) -> String {
    let mut wire_data = String::with_capacity(message.len() + 8);
    for line in message.split("\r\n") {
        if line.starts_with('.') {
            wire_data.push('.');
        }
        wire_data.push_str(line);
        wire_data.push_str("\r\n");
    }
    wire_data.push_str(".\r\n");
    wire_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::spec::SecretRef;

    fn event(event_type: &str) -> OutboxEvent {
        OutboxEvent {
            sequence: 7,
            event_id: "evt_7".to_string(),
            event_type: event_type.to_string(),
            payload: serde_json::json!({"lineage_id": "ln_1"}),
            created_at: jiff::Timestamp::now(),
            attempts: 0,
            last_error: None,
            next_attempt_at: None,
            processed: false,
            dead_lettered: false,
        }
    }

    fn settings() -> EmailConfig {
        serde_json::from_str::<EmailConfig>(
            r#"{
                "smtp_host": "relay.example.test",
                "from": "AcmeX <acmex@example.test>",
                "to": ["ops@example.test"]
            }"#,
        )
        .expect("settings")
    }

    #[test]
    fn tls_mode_parsing_is_strict() {
        assert_eq!(
            SmtpTlsMode::parse("starttls").unwrap(),
            SmtpTlsMode::StartTls
        );
        assert_eq!(
            SmtpTlsMode::parse("implicit").unwrap(),
            SmtpTlsMode::Implicit
        );
        assert_eq!(SmtpTlsMode::parse("none").unwrap(), SmtpTlsMode::None);
        assert!(SmtpTlsMode::parse("opportunistic").is_err());
    }

    #[test]
    fn envelope_address_extracts_angle_form() {
        assert_eq!(
            envelope_address("AcmeX <acmex@example.test>").unwrap(),
            "acmex@example.test"
        );
        assert_eq!(
            envelope_address("ops@example.test").unwrap(),
            "ops@example.test"
        );
        assert!(envelope_address("not-a-mailbox").is_err());
        assert!(envelope_address("bad\r\n@x.test").is_err());
    }

    #[test]
    fn reply_parsing_handles_multiline_continuations() {
        let parse = |input: &[u8]| {
            let bytes = input.to_vec();
            async move {
                let mut reader = BufReader::new(std::io::Cursor::new(bytes));
                read_reply(&mut reader).await
            }
        };
        // Covered through read_reply over an in-memory stream.
        let multi = tokio_test_block_on(parse(
            b"250-relay.test\r\n250-8BITMIME\r\n250 SIZE 1024\r\n",
        ));
        let multi = multi.unwrap();
        assert_eq!(multi.code, 250);
        assert_eq!(multi.lines, vec!["relay.test", "8BITMIME", "SIZE 1024"]);

        let bare = tokio_test_block_on(parse(b"235 ok\r\n")).unwrap();
        assert_eq!(bare.code, 235);

        // Negative / non-numeric codes are terminal protocol violations.
        let negative = tokio_test_block_on(parse(b"-250 nonsense\r\n"));
        assert_eq!(negative.unwrap_err().class, SmtpErrorClass::Terminal);
        let garbage = tokio_test_block_on(parse(b"2X5 what\r\n"));
        assert_eq!(garbage.unwrap_err().class, SmtpErrorClass::Terminal);

        // A peer that hangs up mid-reply is retryable.
        let truncated = tokio_test_block_on(parse(b"250-on"));
        assert_eq!(truncated.unwrap_err().class, SmtpErrorClass::Retryable);

        // 5xx classifies terminal, 4xx retryable.
        assert_eq!(
            tokio_test_block_on(parse(b"550 nope\r\n")).unwrap().class(),
            SmtpErrorClass::Terminal
        );
        assert_eq!(
            tokio_test_block_on(parse(b"451 busy\r\n")).unwrap().class(),
            SmtpErrorClass::Retryable
        );
    }

    /// Minimal block-on for the parser tests; the contract tests in
    /// `tests/` use full tokio runtimes.
    fn tokio_test_block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("test runtime")
            .block_on(future)
    }

    #[test]
    fn dot_stuffing_escapes_leading_dots_and_terminates() {
        let wire = to_wire_data("Subject: dot test\r\n.leading line\r\nplain");
        assert!(wire.starts_with("Subject: dot test\r\n..leading line\r\n"));
        assert!(wire.ends_with("\r\n.\r\n"));
        // The empty (header/body separator) line is passed through as-is.
        let wire = to_wire_data("Subject: t\r\n\r\nbody");
        assert!(wire.contains("Subject: t\r\n\r\nbody\r\n.\r\n"));
    }

    #[test]
    fn message_headers_and_body_are_rendered() {
        let settings = settings();
        let message = prepare_message(
            &settings,
            EmailBodyFormat::Text,
            &event("operation.created"),
        )
        .unwrap();
        assert_eq!(message.envelope_from, "acmex@example.test");
        assert_eq!(message.recipients, vec!["ops@example.test"]);
        let data = &message.wire_data;
        assert!(data.starts_with("From: AcmeX <acmex@example.test>\r\n"));
        assert!(data.contains("To: ops@example.test\r\n"));
        assert!(data.contains("Subject: [AcmeX] operation.created\r\n"));
        assert!(data.contains("Date: "));
        assert!(data.contains("MIME-Version: 1.0\r\n"));
        assert!(data.contains("Content-Type: text/plain; charset=utf-8\r\n"));
        assert!(data.contains("AcmeX event: operation.created"));
        assert!(data.contains("lineage_id"));
    }

    #[test]
    fn non_ascii_subjects_are_rfc2047_encoded() {
        let encoded = encode_subject("[AcmeX] Zertifikat erneuert ✓");
        assert!(
            !encoded.contains("erneuert"),
            "raw non-ASCII must not appear"
        );
        assert!(encoded.starts_with("=?utf-8?B?"));
        // ASCII subjects pass through untouched.
        assert_eq!(encode_subject("[AcmeX] plain"), "[AcmeX] plain");
    }

    #[test]
    fn notifier_debug_redacts_credentials() {
        let mut settings = settings();
        settings.username = Some("smtp-user".to_string());
        settings.password = Some(SecretRef::parse("file:/run/secrets/smtp").unwrap());
        let notifier = EmailNotifier::new(settings).unwrap();
        let rendered = format!("{notifier:?}");
        assert!(!rendered.contains("smtp-user"), "got: {rendered}");
        assert!(!rendered.contains("/run/secrets/smtp"), "got: {rendered}");
        assert!(rendered.contains("auth_configured: true"));
    }

    #[test]
    fn new_rejects_broken_settings() {
        let mut bad_host = settings();
        bad_host.smtp_host = "  ".to_string();
        assert!(EmailNotifier::new(bad_host).is_err());

        let mut no_recipients = settings();
        no_recipients.to = Vec::new();
        assert!(EmailNotifier::new(no_recipients).is_err());

        let mut half_auth = settings();
        half_auth.username = Some("user".to_string());
        assert!(EmailNotifier::new(half_auth).is_err());

        let mut injectable_from = settings();
        injectable_from.from = "bad\r\nname <x@y.test>".to_string();
        assert!(EmailNotifier::new(injectable_from).is_err());
    }

    #[test]
    fn event_filter_matches_webhook_semantics() {
        let mut filtered = settings();
        filtered.events = vec!["operation.created".to_string()];
        let notifier = EmailNotifier::new(filtered).unwrap();
        assert!(notifier.should_deliver("operation.created"));
        assert!(!notifier.should_deliver("audit.event"));

        let catch_all = EmailNotifier::new(settings()).unwrap();
        assert!(catch_all.should_deliver("anything.at.all"));
    }
}
