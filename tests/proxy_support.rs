//! Behavioral tests for `[acme.proxy]` outbound proxy support (issue #171).
//!
//! A local stub plays two roles at once: the HTTP proxy every request is
//! routed through *and* the ACME server behind it. Because the stub serves
//! every request itself, a passing flow proves the requests really
//! transited the proxy (absolute-form request lines) instead of reaching
//! the (unresolvable) CA host directly.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use acmex::ca_backend::{AcmeMethod, AcmeRequest, AcmeTransport, ReqwestAcmeTransport};
use acmex::{AcmeClient, AcmeConfig, ProxySettings};

/// The fake ACME host the client is pointed at; never resolvable, so any
/// success proves the proxy carried the traffic.
const FAKE_CA_HOST: &str = "acme.proxy.test";

/// A recorded request: method + raw target from the request line.
#[derive(Debug, Clone)]
struct RecordedRequest {
    method: String,
    target: String,
}

/// Stub with its advertised endpoints under the fake CA host: every
/// endpoint is only reachable when the proxy carries the traffic.
async fn spawn_stub() -> (std::net::SocketAddr, Arc<Mutex<Vec<RecordedRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    spawn_stub_on(listener, FAKE_CA_HOST.to_string()).await
}

/// Stub whose advertised endpoints point back at its own 127.0.0.1
/// address, for `no_proxy` bypass tests where the whole flow must stay on
/// an excluded host.
async fn spawn_direct_stub() -> (std::net::SocketAddr, Arc<Mutex<Vec<RecordedRequest>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    spawn_stub_on(listener, format!("127.0.0.1:{}", addr.port())).await
}

/// Accept loop shared by both stub variants. `directory_host` decides the
/// host advertised inside the directory body, so tests can pin every
/// endpoint to the host they expect to be proxied (or excluded).
async fn spawn_stub_on(
    listener: TcpListener,
    directory_host: String,
) -> (std::net::SocketAddr, Arc<Mutex<Vec<RecordedRequest>>>) {
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let server_requests = requests.clone();

    tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => break,
            };
            let server_requests = server_requests.clone();
            let directory_host = directory_host.clone();
            tokio::spawn(async move {
                // Read until end of headers, then drain the body so the
                // client never sees a truncated write.
                let mut buf = Vec::new();
                let header_end;
                loop {
                    let mut chunk = [0u8; 4096];
                    let read = match socket.read(&mut chunk).await {
                        Ok(0) => return,
                        Ok(read) => read,
                        Err(_) => return,
                    };
                    buf.extend_from_slice(&chunk[..read]);
                    if let Some(position) = find_subsequence(&buf, b"\r\n\r\n") {
                        header_end = position;
                        break;
                    }
                }
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let request_line = head.lines().next().unwrap_or_default().to_string();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if !name.trim().eq_ignore_ascii_case("content-length") {
                            return None;
                        }
                        value.trim().parse::<usize>().ok()
                    })
                    .unwrap_or(0);
                let body_start = header_end + 4;
                while buf.len() < body_start + content_length {
                    let mut chunk = [0u8; 4096];
                    let read = match socket.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(read) => read,
                        Err(_) => return,
                    };
                    buf.extend_from_slice(&chunk[..read]);
                }

                let mut parts = request_line.split(' ');
                let method = parts.next().unwrap_or_default().to_string();
                let target = parts.next().unwrap_or_default().to_string();
                server_requests.lock().await.push(RecordedRequest {
                    method: method.clone(),
                    target: target.clone(),
                });

                let nonce_header = "Replay-Nonce: proxy-test-nonce\r\n";
                let response = match method.as_str() {
                    "HEAD" => format!(
                        "HTTP/1.1 200 OK\r\n{nonce_header}Content-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                    "POST" => {
                        // newAccount: 201 + Location + account resource.
                        let body = r#"{"id":"http://stub/acct/1","status":"valid","contact":[]}"#;
                        format!(
                            "HTTP/1.1 201 Created\r\n{nonce_header}Location: http://{directory_host}/acct/1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                    _ => {
                        // GET (directory): full RFC 8555 directory, all
                        // endpoints under the advertised host.
                        let body = format!(
                            r#"{{"newNonce":"http://{directory_host}/new-nonce","newAccount":"http://{directory_host}/new-account","newOrder":"http://{directory_host}/new-order","newAuthz":"http://{directory_host}/new-authz","revokeCert":"http://{directory_host}/revoke-cert","keyChange":"http://{directory_host}/key-change"}}"#
                        );
                        format!(
                            "HTTP/1.1 200 OK\r\n{nonce_header}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    }
                };
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
                let _ = socket.shutdown().await;
            });
        }
    });

    (addr, requests)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn proxy_settings(url: String, no_proxy: Option<String>) -> ProxySettings {
    ProxySettings {
        url,
        no_proxy,
        username: None,
        password: None,
    }
}

/// Explicit proxy: ACME traffic flows through it (absolute-form request
/// lines) and the full directory → nonce → newAccount flow completes
/// against the stub behind it.
#[tokio::test]
async fn explicit_proxy_routes_acme_traffic() {
    let (proxy_addr, requests) = spawn_stub().await;

    let config = AcmeConfig::new(format!("http://{FAKE_CA_HOST}/directory"))
        .with_tos_agreed(true)
        .with_proxy(proxy_settings(format!("http://{proxy_addr}"), None));
    let mut client = AcmeClient::new(config).unwrap();

    let account_url = tokio::time::timeout(Duration::from_secs(15), client.register_account())
        .await
        .expect("register_account must not hang behind the proxy")
        .expect("register_account through the stub proxy must succeed");
    assert!(account_url.contains(FAKE_CA_HOST), "got: {account_url}");

    let requests = requests.lock().await.clone();
    let methods: Vec<&str> = requests.iter().map(|r| r.method.as_str()).collect();
    assert!(
        methods.contains(&"GET") && methods.contains(&"POST"),
        "expected directory GET and newAccount POST, got: {requests:?}"
    );
    for request in &requests {
        assert!(
            request
                .target
                .starts_with(&format!("http://{FAKE_CA_HOST}/")),
            "request behind a proxy must use absolute-form target, got: {request:?}"
        );
    }
}

/// `no_proxy` exempts matching hosts: with the proxy pointing at a dead
/// port, excluded 127.0.0.1 traffic still completes — directly.
#[tokio::test]
async fn no_proxy_bypasses_proxy_for_excluded_hosts() {
    let (stub_addr, requests) = spawn_direct_stub().await;

    let config = AcmeConfig::new(format!("http://{stub_addr}/directory"))
        .with_tos_agreed(true)
        .with_proxy(proxy_settings(
            // A port that refuses connections: any proxied attempt fails.
            "http://127.0.0.1:1".to_string(),
            Some("127.0.0.1".to_string()),
        ));
    let mut client = AcmeClient::new(config).unwrap();

    let account_url = tokio::time::timeout(Duration::from_secs(15), client.register_account())
        .await
        .expect("register_account must not hang")
        .expect("no_proxy traffic must bypass the dead proxy and succeed");
    assert!(account_url.contains("acct/1"), "got: {account_url}");

    let requests = requests.lock().await.clone();
    for request in &requests {
        assert!(
            !request.target.starts_with("http://"),
            "excluded host must be reached with origin-form target (direct), got: {request:?}"
        );
    }
}

/// A broken proxy is an explicit failure — never a silent fallback to
/// direct access (nothing pretends to succeed).
#[tokio::test]
async fn dead_proxy_fails_acme_requests_explicitly() {
    let config = AcmeConfig::new(format!("http://{FAKE_CA_HOST}/directory"))
        .with_tos_agreed(true)
        .with_proxy(proxy_settings("http://127.0.0.1:1".to_string(), None));
    let mut client = AcmeClient::new(config).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(15), client.register_account())
        .await
        .expect("dead proxy must fail fast, not hang");
    assert!(
        result.is_err(),
        "register_account must not succeed via a dead proxy"
    );
}

/// The v0.10 `ReqwestAcmeTransport` honors the same proxy settings.
#[tokio::test]
async fn reqwest_acme_transport_routes_through_proxy() {
    let (proxy_addr, requests) = spawn_stub().await;

    let transport = ReqwestAcmeTransport::new_with_proxy(Some(&proxy_settings(
        format!("http://{proxy_addr}"),
        None,
    )))
    .unwrap();

    let response = tokio::time::timeout(
        Duration::from_secs(15),
        transport.request(AcmeRequest {
            url: format!("http://{FAKE_CA_HOST}/directory"),
            method: AcmeMethod::Get,
            body: None,
        }),
    )
    .await
    .expect("transport request must not hang behind the proxy")
    .expect("transport request through the stub proxy must succeed");
    assert_eq!(response.status, 200);
    let directory: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(
        directory["newAccount"],
        format!("http://{FAKE_CA_HOST}/new-account")
    );

    let requests = requests.lock().await.clone();
    assert!(
        requests
            .iter()
            .any(|r| r.target == format!("http://{FAKE_CA_HOST}/directory")),
        "directory GET must arrive at the proxy in absolute form, got: {requests:?}"
    );
}
