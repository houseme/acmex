use acmex::challenge::{ChallengeSolverRegistry, Dns01Solver};
use acmex::dns::providers::cloudflare::{CloudFlareConfig, CloudFlareDnsProvider};
use acmex::prelude::*;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // 1. Setup Client
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("owner@example.com"))
        .with_tos_agreed(true);
    let mut client = AcmeClient::new(config)?;

    // 2. Configure DNS Provider
    // In a real scenario, use environment variables or a config file
    let api_token = std::env::var("CLOUDFLARE_API_TOKEN")
        .expect("CLOUDFLARE_API_TOKEN environment variable not set");

    let cf_config = CloudFlareConfig {
        api_token,
        zone_id: std::env::var("CLOUDFLARE_ZONE_ID").unwrap_or_default(),
    };
    let cf_provider = CloudFlareDnsProvider::new(cf_config);

    // 3. Register Solver in Registry
    let mut registry = ChallengeSolverRegistry::new();
    let dns_solver = Dns01Solver::new(Arc::new(cf_provider), "example.com".to_string());
    registry.register(dns_solver);

    // 4. Issue Certificate
    println!("Requesting wildcard certificate *.example.com via DNS-01...");
    let domains = vec!["example.com".to_string(), "*.example.com".to_string()];

    match client.issue_certificate(domains, &mut registry).await {
        Ok(bundle) => {
            println!("Success! Wildcard certificate obtained.");
            println!("Primary Domain: {}", bundle.domains[0]);
        }
        Err(e) => {
            eprintln!("DNS-01 issuance failed: {}", e);
        }
    }

    Ok(())
}
