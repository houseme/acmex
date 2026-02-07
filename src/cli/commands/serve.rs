#[cfg(feature = "redis")]
use crate::RedisStorage;
use crate::config::Config;
/// Serve command implementation
use crate::error::Result;
use crate::notifications::{WebhookConfig, WebhookFormat, WebhookManager};
use crate::scheduler::AdvancedRenewalScheduler;
use crate::server::start_server;
use crate::storage::{CertificateStore, FileStorage, MemoryStorage, StorageBackend};
use std::net::SocketAddr;
use std::sync::Arc;

/// Handle serve command
pub async fn handle_serve(addr: String, config_path: Option<String>) -> Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| crate::error::AcmeError::configuration(format!("Invalid address: {}", e)))?;

    let mut config = Config::default();
    // Load config if provided
    if let Some(path) = config_path {
        tracing::info!("Loading config from: {}", path);
        config = Config::from_file(std::path::Path::new(&path))?;
    }

    let config = Arc::new(config);

    // Initialize storage backend
    let storage: Arc<dyn StorageBackend> = match config.storage.backend.as_str() {
        "memory" => Arc::new(MemoryStorage::new()),
        "redis" => {
            #[cfg(feature = "redis")]
            {
                if let Some(redis_config) = &config.storage.redis {
                    Arc::new(RedisStorage::new(&redis_config.url)?)
                } else {
                    return Err(crate::error::AcmeError::configuration(
                        "Redis configuration missing".to_string(),
                    ));
                }
            }
            #[cfg(not(feature = "redis"))]
            {
                return Err(crate::error::AcmeError::configuration(
                    "Redis feature not enabled".to_string(),
                ));
            }
        }
        _ => {
            let path = config
                .storage
                .file
                .as_ref()
                .map(|f| f.path.as_str())
                .unwrap_or(".acmex");
            Arc::new(FileStorage::new(path))
        }
    };

    // Initialize certificate store
    let cert_store = CertificateStore::new(storage.clone());

    // Initialize ACME client
    let mut acme_config = crate::client::AcmeConfig::new(&config.acme.directory)
        .with_tos_agreed(config.acme.tos_agreed);
    for contact in &config.acme.contact {
        if contact.starts_with("mailto:") {
            acme_config = acme_config.with_contact(crate::types::Contact::email(&contact[7..]));
        }
    }
    let client = crate::client::AcmeClient::new(acme_config)?;

    // Initialize Advanced Renewal Scheduler
    let (scheduler, _task_tx) = AdvancedRenewalScheduler::new(
        client.clone(),
        cert_store,
        config.renewal.concurrency as usize,
    );
    let scheduler = Arc::new(scheduler);

    // Start scheduler in background
    let scheduler_clone = scheduler.clone();
    tokio::spawn(async move {
        scheduler_clone.run().await;
    });

    // Initialize webhook manager
    let webhook_config = WebhookConfig {
        name: "default".to_string(),
        url: "http://localhost:8080/webhook".to_string(), // Default or from config
        events: vec![],
        format: WebhookFormat::Json,
        auth_token: None,
        timeout_secs: 10,
        max_retries: 3,
    };

    let webhook_manager = Arc::new(WebhookManager::new(vec![webhook_config]));

    // Start server
    start_server(
        addr,
        config,
        Some(Arc::new(client)),
        Some(storage),
        webhook_manager,
        Some(scheduler),
    )
    .await?;

    Ok(())
}
