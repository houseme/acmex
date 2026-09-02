//! ACME transport abstraction: one request path for every CA call.
//!
//! `execute_jws` (see `session.rs`) builds on this trait, giving every ACME
//! request the same treatment: Replay-Nonce capture, RFC 7807 problem
//! parsing, `Retry-After` handling (seconds or HTTP-date) and error
//! classification. `ReqwestAcmeTransport` is the production implementation;
//! `FakeAcmeTransport` powers the behavioral tests without network access.

use std::collections::VecDeque;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use jiff::Timestamp;

use crate::domain::{ClassifiedError, ErrorClass, StableErrorCode, error_codes};
use crate::error::{AcmeError, Result};

/// An outgoing ACME HTTP request.
#[derive(Debug, Clone)]
pub struct AcmeRequest {
    /// Target URL.
    pub url: String,
    /// HTTP method (`GET`, `HEAD` or `POST`).
    pub method: AcmeMethod,
    /// Body bytes (JWS JSON for POSTs).
    pub body: Option<Vec<u8>>,
}

/// HTTP method for ACME requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMethod {
    /// Plain GET (directory, ARI).
    Get,
    /// HEAD (nonce fetching).
    Head,
    /// POST with `application/jose+json`.
    Post,
}

/// A raw ACME HTTP response.
#[derive(Debug, Clone)]
pub struct AcmeResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body bytes (JSON or PEM).
    pub body: Vec<u8>,
    /// `Replay-Nonce` header, when present.
    pub replay_nonce: Option<String>,
    /// Parsed `Retry-After` (seconds or HTTP-date).
    pub retry_after: Option<Timestamp>,
    /// `Location` header, when present.
    pub location: Option<String>,
}

impl AcmeResponse {
    /// Parses the body as JSON.
    pub fn json(&self) -> Result<serde_json::Value> {
        serde_json::from_slice(&self.body)
            .map_err(|e| AcmeError::protocol(format!("invalid ACME JSON response: {e}")))
    }

    /// Parses the body as an ACME problem document (RFC 7807 §7.3.3).
    pub fn problem(&self) -> Option<AcmeProblem> {
        serde_json::from_slice(&self.body).ok()
    }

    /// Whether the response carries the badNonce problem type.
    pub fn is_bad_nonce(&self) -> bool {
        self.problem()
            .is_some_and(|p| p.error_type == "urn:ietf:params:acme:error:badNonce")
    }
}

/// An ACME problem document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcmeProblem {
    /// Problem type URI.
    #[serde(rename = "type")]
    pub error_type: String,
    /// Human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// HTTP status echoed by the server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
}

/// Classifies an ACME response into a stable, actionable error.
///
/// This is the *only* place HTTP-status-based classification happens;
/// callers never match on status strings themselves.
pub fn classify_response(response: &AcmeResponse) -> Result<serde_json::Value> {
    classify_status(response)?;
    response.json()
}

/// Status/problem classification without parsing the body.
///
/// Use for endpoints whose 2xx body is not JSON (e.g. the PEM certificate
/// download) — `classify_response` would reject any non-JSON 2xx body.
pub fn classify_status(response: &AcmeResponse) -> Result<()> {
    if (200..300).contains(&response.status) {
        return Ok(());
    }

    let problem = response.problem();
    let detail = problem
        .as_ref()
        .and_then(|p| p.detail.clone())
        .unwrap_or_else(|| format!("HTTP {}", response.status));

    let classified = match response.status {
        // Rate limited: honor Retry-After when present.
        429 => ClassifiedError {
            code: error_codes::ACME_RATE_LIMITED,
            class: ErrorClass::RateLimited {
                retry_after: response.retry_after,
            },
            detail: Some(detail),
        },
        // Temporary server errors.
        500 | 502 | 503 | 504 => {
            if response.status == 503 && response.retry_after.is_some() {
                ClassifiedError {
                    code: error_codes::ACME_RATE_LIMITED,
                    class: ErrorClass::RateLimited {
                        retry_after: response.retry_after,
                    },
                    detail: Some(detail),
                }
            } else {
                ClassifiedError {
                    code: error_codes::ACME_SERVER_ERROR,
                    class: ErrorClass::Retryable,
                    detail: Some(detail),
                }
            }
        }
        // Authentication/authorization problems need an operator.
        401 | 403 => ClassifiedError {
            code: error_codes::PROVIDER_AUTH_FAILED,
            class: ErrorClass::OperatorActionRequired,
            detail: Some(detail),
        },
        // Other 4xx: terminal unless the problem type is retryable.
        _ => {
            let class = match problem.as_ref().map(|p| p.error_type.as_str()) {
                Some("urn:ietf:params:acme:error:serverInternal")
                | Some("urn:ietf:params:acme:error:connection") => ErrorClass::Retryable,
                _ => ErrorClass::Terminal,
            };
            ClassifiedError {
                code: StableErrorCode::from_owned(format!(
                    "ACME_HTTP_{}_{}",
                    response.status,
                    problem
                        .as_ref()
                        .map(|p| p.error_type.rsplit(':').next().unwrap_or("error"))
                        .unwrap_or("error")
                        .to_uppercase()
                )),
                class,
                detail: Some(detail),
            }
        }
    };
    Err(classified.into())
}

impl From<ClassifiedError> for AcmeError {
    fn from(error: ClassifiedError) -> Self {
        AcmeError::protocol(format!(
            "[{}] {}{}",
            error.code,
            match error.class {
                ErrorClass::Retryable => "retryable",
                ErrorClass::RateLimited { .. } => "rate-limited",
                ErrorClass::Terminal => "terminal",
                ErrorClass::PolicyViolation => "policy-violation",
                ErrorClass::OperatorActionRequired => "operator-action-required",
                ErrorClass::Cancelled => "cancelled",
            },
            error.detail.map(|d| format!(": {d}")).unwrap_or_default()
        ))
    }
}

/// Parses a `Retry-After` header value (delta-seconds or HTTP-date).
pub fn parse_retry_after(value: &str, now: Timestamp) -> Option<Timestamp> {
    let trimmed = value.trim();
    if let Ok(seconds) = trimmed.parse::<i64>() {
        return now.checked_add(jiff::Span::new().seconds(seconds)).ok();
    }
    // HTTP-date (RFC 9110) equals RFC 2822 date-time; jiff can parse that.
    jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(trimmed)
        .ok()
        .or_else(|| Timestamp::from_str(trimmed).ok())
}

/// The transport every ACME request goes through.
#[async_trait]
pub trait AcmeTransport: Send + Sync {
    /// Executes one request. Implementations must not retry; retry policy
    /// belongs to the session/engine layers.
    async fn request(&self, request: AcmeRequest) -> Result<AcmeResponse>;
}

/// Production transport over `reqwest`.
#[derive(Clone)]
pub struct ReqwestAcmeTransport {
    client: reqwest::Client,
}

impl ReqwestAcmeTransport {
    /// Creates a transport with sane ACME defaults (timeouts, limits).
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .expect("reqwest client builder"),
        }
    }
}

impl Default for ReqwestAcmeTransport {
    fn default() -> self::ReqwestAcmeTransport {
        Self::new()
    }
}

#[async_trait]
impl AcmeTransport for ReqwestAcmeTransport {
    async fn request(&self, request: AcmeRequest) -> Result<AcmeResponse> {
        let url = reqwest::Url::parse(&request.url)
            .map_err(|e| AcmeError::InvalidInput(format!("invalid ACME URL: {e}")))?;
        let builder = match request.method {
            AcmeMethod::Get => self.client.get(url),
            AcmeMethod::Head => self.client.head(url),
            AcmeMethod::Post => self
                .client
                .post(url)
                .header("Content-Type", "application/jose+json"),
        };
        let builder = match &request.body {
            Some(body) => builder.body(body.clone()),
            None => builder,
        };
        let response = builder
            .send()
            .await
            .map_err(|e| AcmeError::transport(format!("ACME request failed: {e}")))?;

        let status = response.status().as_u16();
        let replay_nonce = response
            .headers()
            .get("Replay-Nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let location = response
            .headers()
            .get("Location")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let retry_after = response
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| parse_retry_after(v, Timestamp::now()));
        let body = response
            .bytes()
            .await
            .map_err(|e| AcmeError::transport(format!("ACME body read failed: {e}")))?
            .to_vec();

        Ok(AcmeResponse {
            status,
            body,
            replay_nonce,
            retry_after,
            location,
        })
    }
}

/// Transport decorator that records ACME request metrics (total, duration,
/// badNonce count) without altering responses. Labels stay low-cardinality:
/// the CA id plus coarse result/error classes.
pub struct InstrumentedAcmeTransport {
    inner: Arc<dyn AcmeTransport>,
    ca: String,
    metrics: crate::metrics::SharedMetrics,
}

impl InstrumentedAcmeTransport {
    /// Wraps `inner`; `ca` is the low-cardinality CA label (e.g. `letsencrypt`).
    pub fn wrap(
        ca: impl Into<String>,
        inner: Arc<dyn AcmeTransport>,
        metrics: crate::metrics::SharedMetrics,
    ) -> Arc<dyn AcmeTransport> {
        Arc::new(Self {
            inner,
            ca: ca.into(),
            metrics,
        })
    }

    fn observe(&self, response: &AcmeResponse, elapsed: std::time::Duration) {
        let bad_nonce = response.is_bad_nonce();
        let (result, error_class) = if bad_nonce {
            ("bad_nonce".to_string(), "urn_bad_nonce".to_string())
        } else if (200..400).contains(&response.status) {
            ("ok".to_string(), "none".to_string())
        } else {
            // Problem types are a bounded RFC set; keep only the short
            // suffix to stay label-safe.
            let class = response
                .problem()
                .map(|p| {
                    p.error_type
                        .rsplit(':')
                        .next()
                        .unwrap_or("problem")
                        .to_string()
                })
                .unwrap_or_else(|| format!("http_{}xx", response.status / 100));
            ("error".to_string(), class)
        };
        self.metrics
            .acme_requests_total
            .with_label_values(&[&self.ca, &result, &error_class])
            .inc();
        self.metrics
            .acme_request_duration_seconds
            .with_label_values(&[&self.ca, &result, &error_class])
            .observe(elapsed.as_secs_f64());
        if bad_nonce {
            self.metrics
                .bad_nonce_total
                .with_label_values(&[&self.ca])
                .inc();
        }
    }
}

#[async_trait]
impl AcmeTransport for InstrumentedAcmeTransport {
    async fn request(&self, request: AcmeRequest) -> Result<AcmeResponse> {
        let start = std::time::Instant::now();
        match self.inner.request(request).await {
            Ok(response) => {
                self.observe(&response, start.elapsed());
                Ok(response)
            }
            Err(err) => {
                let elapsed = start.elapsed();
                self.metrics
                    .acme_requests_total
                    .with_label_values(&[&self.ca, "error", "transport"])
                    .inc();
                self.metrics
                    .acme_request_duration_seconds
                    .with_label_values(&[&self.ca, "error", "transport"])
                    .observe(elapsed.as_secs_f64());
                Err(err)
            }
        }
    }
}

/// One scripted response for [`FakeAcmeTransport`].
#[derive(Debug, Clone)]
pub struct ScriptedResponse {
    /// Responds only to requests whose URL contains this fragment.
    pub url_contains: String,
    /// Status code.
    pub status: u16,
    /// Body bytes.
    pub body: Vec<u8>,
    /// Replay-Nonce header value.
    pub replay_nonce: Option<String>,
    /// Retry-After header value (raw).
    pub retry_after_raw: Option<String>,
    /// Location header value.
    pub location: Option<String>,
    /// Consume this entry after `uses` requests (1 = single-shot).
    pub uses: usize,
}

impl ScriptedResponse {
    /// A single-shot JSON response.
    pub fn json(url_contains: impl Into<String>, status: u16, body: serde_json::Value) -> Self {
        Self {
            url_contains: url_contains.into(),
            status,
            body: serde_json::to_vec(&body).expect("serialize fake body"),
            replay_nonce: Some(format!("nonce-{}", counter_next())),
            retry_after_raw: None,
            location: None,
            uses: 1,
        }
    }

    /// A response with explicit header control.
    pub fn with_headers(
        mut self,
        nonce: Option<String>,
        retry_after: Option<String>,
        location: Option<String>,
    ) -> Self {
        self.replay_nonce = nonce;
        self.retry_after_raw = retry_after;
        self.location = location;
        self
    }

    /// Repeat the response `uses` times.
    pub fn uses(mut self, uses: usize) -> Self {
        self.uses = uses;
        self
    }
}

fn counter_next() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// An in-memory transport with scripted responses, for tests.
///
/// Responses match the first entry whose `url_contains` matches; exhausted
/// entries are dropped. Requests are recorded for assertions.
pub struct FakeAcmeTransport {
    responses: Mutex<VecDeque<ScriptedResponse>>,
    requests: Mutex<Vec<AcmeRequest>>,
    now: Timestamp,
}

impl FakeAcmeTransport {
    /// An empty transport with a fixed clock.
    pub fn new(now: Timestamp) -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
            requests: Mutex::new(Vec::new()),
            now,
        }
    }

    /// Queues a scripted response.
    pub fn push(&self, response: ScriptedResponse) -> &Self {
        self.responses
            .lock()
            .expect("fake transport lock")
            .push_back(response);
        self
    }

    /// All requests seen so far.
    pub fn requests(&self) -> Vec<AcmeRequest> {
        self.requests.lock().expect("fake transport lock").clone()
    }

    /// Fragments of the still-queued scripted responses (debugging aid).
    pub fn queued_fragments(&self) -> Vec<(String, usize)> {
        self.responses
            .lock()
            .expect("fake transport lock")
            .iter()
            .map(|r| (r.url_contains.clone(), r.uses))
            .collect()
    }

    /// Number of POSTs sent to URLs containing `fragment`.
    pub fn post_count(&self, fragment: &str) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.method == AcmeMethod::Post && r.url.contains(fragment))
            .count()
    }
}

#[async_trait]
impl AcmeTransport for FakeAcmeTransport {
    async fn request(&self, request: AcmeRequest) -> Result<AcmeResponse> {
        self.requests
            .lock()
            .expect("fake transport lock")
            .push(request.clone());
        let mut responses = self.responses.lock().expect("fake transport lock");
        let position = responses
            .iter()
            .position(|r| request.url.contains(&r.url_contains))
            .ok_or_else(|| {
                AcmeError::protocol(format!(
                    "fake transport has no response for {}",
                    request.url
                ))
            })?;
        let scripted = &mut responses[position];
        let response = AcmeResponse {
            status: scripted.status,
            body: scripted.body.clone(),
            replay_nonce: scripted.replay_nonce.clone(),
            retry_after: scripted
                .retry_after_raw
                .as_deref()
                .and_then(|v| parse_retry_after(v, self.now)),
            location: scripted.location.clone(),
        };
        if scripted.uses > 1 {
            scripted.uses -= 1;
        } else {
            responses.remove(position);
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> Timestamp {
        Timestamp::from_str("2026-01-01T00:00:00Z").unwrap()
    }

    #[test]
    fn retry_after_seconds_and_http_date() {
        let t = now();
        assert_eq!(
            parse_retry_after("120", t),
            Some(t.checked_add(jiff::Span::new().seconds(120)).unwrap())
        );
        assert_eq!(
            parse_retry_after("Wed, 21 Oct 2026 07:28:00 GMT", t).map(|x| x.to_string()),
            Some("2026-10-21T07:28:00Z".to_string())
        );
        assert_eq!(parse_retry_after("garbage", t), None);
    }

    #[test]
    fn classification_rate_limited_uses_retry_after() {
        let response = AcmeResponse {
            status: 429,
            body: b"{}".to_vec(),
            replay_nonce: Some("n".to_string()),
            retry_after: Some(now().checked_add(jiff::Span::new().seconds(30)).unwrap()),
            location: None,
        };
        let err = classify_response(&response).unwrap_err();
        assert!(err.to_string().contains("ACME_RATE_LIMITED"));
    }

    #[test]
    fn classification_server_error_retryable() {
        let response = AcmeResponse {
            status: 500,
            body: b"{}".to_vec(),
            replay_nonce: None,
            retry_after: None,
            location: None,
        };
        let err = classify_response(&response).unwrap_err();
        assert!(err.to_string().contains("retryable"));
    }

    #[test]
    fn bad_nonce_detection() {
        let response = AcmeResponse {
            status: 400,
            body: br#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"bad nonce"}"#
                .to_vec(),
            replay_nonce: Some("fresh".to_string()),
            retry_after: None,
            location: None,
        };
        assert!(response.is_bad_nonce());
    }

    #[tokio::test]
    async fn fake_transport_matches_and_records() {
        let transport = FakeAcmeTransport::new(now());
        transport.push(ScriptedResponse::json(
            "new-order",
            201,
            serde_json::json!({"status": "pending"}),
        ));
        let response = transport
            .request(AcmeRequest {
                url: "https://acme.example/new-order".to_string(),
                method: AcmeMethod::Post,
                body: Some(b"{}".to_vec()),
            })
            .await
            .unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(transport.post_count("new-order"), 1);
    }
}
