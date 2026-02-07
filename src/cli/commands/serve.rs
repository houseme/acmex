/// Serve command implementation
use crate::error::Result;
use crate::notifications::{WebhookConfig, WebhookFormat, WebhookManager};
use crate::server::start_server;
use std::net::SocketAddr;
use std::sync::Arc;

/// Handle serve command
pub async fn handle_serve(addr: String, config_path: Option<String>) -> Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|e| crate::error::AcmeError::configuration(format!("Invalid address: {}", e)))?;

    // Load config if provided
    if let Some(path) = config_path {
        tracing::info!("Loading config from: {}", path);
        // TODO: Load config
    }

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
    start_server(addr, None, webhook_manager).await?;

    Ok(())
}
