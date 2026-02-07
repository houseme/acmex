use acmex::config::Config;
use acmex::notifications::WebhookManager;
use acmex::prelude::*;
use acmex::server::start_server;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // 1. Setup minimal configuration
    let addr = SocketAddr::from(([127, 0, 0, 1], 8080));
    let config = Arc::new(Config::default()); // Load your actual config here

    // 2. Setup dependencies
    // Usually these are initialized based on config
    let acme_config = AcmeConfig::lets_encrypt_staging();
    let client = Arc::new(AcmeClient::new(acme_config)?);

    let webhook_manager = Arc::new(WebhookManager::new(vec![]));

    // We can use MemoryStorage for this example server
    let storage: Arc<dyn acmex::storage::StorageBackend> =
        Arc::new(acmex::storage::MemoryStorage::new());

    println!("Starting AcmeX API server on http://{}", addr);
    println!("Try running: curl http://{}/health", addr);

    // 3. Start the server (this blocks)
    start_server(
        addr,
        config,
        Some(client),
        Some(storage),
        webhook_manager,
        None, // Optional: RenewalScheduler
    )
    .await?;

    Ok(())
}
