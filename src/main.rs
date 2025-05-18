use acmex::challenge::ChallengeType;
use acmex::{cache::FileCache, dns::MockDnsProvider, AcmeClient, AcmeConfig};
use axum::{
    http::StatusCode, routing::{get, post},
    Json,
    Router,
};
use chrono::Utc;
use clap::Parser;
use prometheus::{Encoder, Gauge, Registry, TextEncoder};
use redis::AsyncCommands;
use rustls_pki_types::PrivateKeyDer;
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use x509_parser::prelude::*;

#[derive(Parser)]
struct Args {
    #[arg(short, long, required = true)]
    domains: Vec<String>,
    #[arg(short, long)]
    email: Vec<String>,
    #[arg(long)]
    cache_dir: Option<std::path::PathBuf>,
    #[arg(long)]
    redis_url: Option<String>,
    #[arg(long)]
    prod: bool,
    #[arg(short, long, default_value = "443")]
    port: u16,
    #[arg(long, default_value = "letsencrypt")]
    ca: String,
    #[arg(long, default_value = "tls-alpn-01")]
    challenge: String,
}

async fn hello_world() -> &'static str {
    "Hello, acmex!"
}

async fn metrics(req: axum::http::Request<axum::body::Body>) -> Result<String, StatusCode> {
    let registry = req
        .extensions()
        .get::<Registry>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut buffer = vec![];
    TextEncoder::new()
        .encode(&registry.gather(), &mut buffer)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    String::from_utf8(buffer).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Serialize, Deserialize)]
struct CertRequest {
    domain: String,
    email: String,
}

async fn apply_cert(Json(cert_req): Json<CertRequest>) -> Result<StatusCode, StatusCode> {
    let config = AcmeConfig::new(vec![cert_req.domain])
        .contact(vec![format!("mailto:{}", cert_req.email)])
        .cache(FileCache::new("./acmex_cache"));
    let client = AcmeClient::new(config);
    client
        .provision_certificate(ChallengeType::TlsAlpn01, None)
        .await
        .map(|_| StatusCode::OK)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

async fn renew_if_needed(
    cert_path: &str,
    redis_client: Option<redis::Client>,
    success_gauge: Gauge,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let cert_content = std::fs::read(cert_path)?;
    let (_, parser) = X509Certificate::from_der(&cert_content)?;
    let time_offset_dt = parser.tbs_certificate.validity.not_after.to_datetime();
    let expires_at =
        chrono::DateTime::<Utc>::from_timestamp(time_offset_dt.unix_timestamp(), 0).unwrap();

    if expires_at < Utc::now() + chrono::Duration::days(30) {
        info!("证书即将到期，触发续期：{}", cert_path);
        if let Some(client) = redis_client {
            let mut conn = client.get_multiplexed_async_connection().await?;
            let lock_key = "acme_renew_lock";
            if conn.set_nx::<_, _, bool>(lock_key, "locked").await? {
                let _: () = conn.expire(lock_key, 300).await?;
                success_gauge.inc();
                let _: () = conn.del(lock_key).await?;
            }
        } else {
            success_gauge.inc();
        }
    }
    Ok(())
}

async fn schedule_renewal(
    cert_path: &str,
    redis_url_owned: Option<String>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let registry = Registry::new();
    let success_gauge = Gauge::new("acme_renew_success", "Successful certificate renewals")?;
    registry.register(Box::new(success_gauge.clone()))?;

    let redis_client = redis_url_owned
        .as_ref()
        .map(|url| redis::Client::open(url.as_str()))
        .transpose()?;

    let sched = JobScheduler::new().await?;

    // 为作业创建拥有所有权的数据副本
    // cert_path 是 schedule_renewal 函数的 &str 参数
    let cert_path_for_job = cert_path.to_string();
    // redis_client 是 schedule_renewal 函数作用域内的 Option<redis::Client>
    let redis_client_for_job = redis_client.clone();
    // success_gauge 是 schedule_renewal 函数作用域内的 Gauge
    let success_gauge_for_job = success_gauge.clone();

    sched
        .add(Job::new_async("0 0 * * *", move |_uuid, _l| {
            // 为 async 块创建新的克隆，以便 FnMut 闭包可以多次调用
            println!("uuid: {:?}", _uuid);
            let cert_path_clone = cert_path_for_job.clone();
            let redis_client_clone = redis_client_for_job.clone();
            let success_gauge_clone = success_gauge_for_job.clone();

            Box::pin(async move {
                if let Err(e) =
                    renew_if_needed(&cert_path_clone, redis_client_clone, success_gauge_clone).await
                {
                    tracing::error!("续期失败：{}", e);
                }
            })
        })?)
        .await?; // Added `?` to handle the Result<Uuid, JobSchedulerError>
    sched.start().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();
    let registry = Registry::new();
    let cert_success = Gauge::new("acme_cert_success", "Successful certificate issuances")?;
    registry.register(Box::new(cert_success.clone()))?;

    let challenge_type = match args.challenge.as_str() {
        "tls-alpn-01" => ChallengeType::TlsAlpn01,
        "http-01" => ChallengeType::Http01,
        "dns-01" => ChallengeType::Dns01,
        _ => return Err("无效的挑战类型".into()),
    };

    let mut config = AcmeConfig::new(args.domains.clone())
        .contact(args.email)
        .directory_url(args.ca)
        .prod(args.prod);

    if let Some(cache_dir) = args.cache_dir {
        config = config.cache(FileCache::new(cache_dir));
    }
    #[cfg(feature = "redis")]
    if let Some(redis_url) = &args.redis_url {
        config = config.redis_cache(redis_url)?;
    }

    let client = AcmeClient::new(config);
    let dns_provider = if challenge_type == ChallengeType::Dns01 {
        Some(MockDnsProvider)
    } else {
        None
    };

    // Explicitly type the argument for provision_certificate
    let dns_provider_arg: Option<&dyn acmex::dns::DnsProvider> = dns_provider
        .as_ref()
        .map(|p: &MockDnsProvider| p as &dyn acmex::dns::DnsProvider);

    let (cert, key) = client
        .provision_certificate(challenge_type, dns_provider_arg)
        .await
        .map_err(|e| Box::new(e) as Box<dyn Error>)?;
    cert_success.inc();

    let cert_der = rustls_pki_types::CertificateDer::from(cert); // This is already 'static due to From<Vec<u8>>

    // 直接从 key Vec<u8> 创建静态生命周期的 PrivateKeyDer
    // 无需转换为切片再解析，直接使用原始数据创建一个静态的 PrivateKeyDer
    let static_key_der = match PrivateKeyDer::try_from(key.as_slice())? {
        PrivateKeyDer::Pkcs1(_) => PrivateKeyDer::Pkcs1(key.clone().into()),
        PrivateKeyDer::Pkcs8(_) => PrivateKeyDer::Pkcs8(key.clone().into()),
        PrivateKeyDer::Sec1(_) => PrivateKeyDer::Sec1(key.clone().into()),
        _ => {
            // 处理未来可能添加的变体
            return Err("不支持的私钥格式".into());
        }
    };

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], static_key_der)?;
    server_config.alpn_protocols = vec![b"acme-tls/1".to_vec(), b"http/1.1".to_vec()];

    if let Some(redis_url_str) = &args.redis_url {
        let redis_url_owned = redis_url_str.clone(); // Clone the String
        tokio::spawn(schedule_renewal(
            "./acmex_cache/cert.pem",
            Some(redis_url_owned),
        ));
    } else {
        tokio::spawn(schedule_renewal("./acmex_cache/cert.pem", None));
    }

    let app = Router::new()
        .route("/", get(hello_world))
        .route("/metrics", get(metrics))
        .route("/certificates/apply", post(apply_cert))
        .with_state(Arc::new(client))
        .layer(axum::Extension(registry));

    let listener =
        TcpListener::bind(SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), args.port)).await?;
    axum::serve(listener, app).await.unwrap();

    Ok(())
}
