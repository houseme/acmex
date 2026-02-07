use acmex::client::CertificateBundle;
use acmex::prelude::*;
use acmex::renewal::RenewalHook;
use acmex::scheduler::AdvancedRenewalScheduler;
use acmex::storage::{CertificateStore, MemoryStorage};

struct MyRenewalHook;

impl RenewalHook for MyRenewalHook {
    fn before_renewal(&self, domains: &[String]) {
        println!("🚀 Starting renewal process for domains: {:?}", domains);
    }

    fn after_renewal(&self, domains: &[String], _bundle: &CertificateBundle) {
        println!("✅ Successfully renewed domains: {:?}", domains);
        // Here you could reload your Nginx/HAProxy configuration
    }

    fn on_error(&self, domains: &[String], error: &AcmeError) {
        eprintln!(
            "❌ Renewal failed for domains: {:?}. Error: {}",
            domains, error
        );
    }
}

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // 1. Setup Storage
    let storage = Arc::new(MemoryStorage::new());
    let cert_store = CertificateStore::new(storage);

    // 2. Setup Client
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("ops@example.com"))
        .with_tos_agreed(true);
    let client = AcmeClient::new(config)?;

    // 3. Initialize Advanced Scheduler
    let concurrency = 5;
    let (scheduler, task_tx) = AdvancedRenewalScheduler::new(client, cert_store, concurrency);

    // Add custom hooks
    let scheduler = Arc::new(scheduler.with_hook(Arc::new(MyRenewalHook)));

    // 4. Start scheduler in background
    let s_clone = scheduler.clone();
    tokio::spawn(async move {
        s_clone.run().await;
    });

    // 5. Enqueue a manual renewal task
    println!("Enqueuing manual renewal task...");
    task_tx
        .send(acmex::scheduler::renewal_scheduler::RenewalTask {
            domains: vec!["example.org".to_string()],
            priority: acmex::scheduler::renewal_scheduler::Priority::Urgent,
            retry_count: 0,
        })
        .await
        .map_err(|e| format!("Send error: {}", e))?;

    // Keep running for a bit to see the output
    tokio::time::sleep(Duration::from_secs(5)).await;
    println!("Scheduler example finished (demo mode).");

    Ok(())
}
