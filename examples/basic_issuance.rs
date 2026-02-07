use acmex::challenge::{ChallengeSolverRegistry, Http01Solver};
use acmex::prelude::*;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn Error>> {
    // 1. Setup Configuration
    // Using Let's Encrypt Staging for development/testing
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    // 2. Initialize Client
    let mut client = AcmeClient::new(config)?;

    // 3. Register Account
    println!("Registering account...");
    client.register_account().await?;
    println!("Account registered successfully.");

    // 4. Setup Challenge Solvers
    // For HTTP-01, you typically need a server listening on port 80 or
    // a way to present the token to your web server.
    let mut registry = ChallengeSolverRegistry::new();
    let http_solver = Http01Solver::default(); // Uses built-in HTTP server if configured
    registry.register(http_solver);

    // 5. Issue Certificate
    println!("Requesting certificate for example.com...");
    let domains = vec!["example.com".to_string()];

    // Note: This call will block until all challenges are solved and the cert is issued
    match client.issue_certificate(domains, &mut registry).await {
        Ok(bundle) => {
            println!("Certificate issued successfully!");
            println!("Certificate PEM:\n{}", bundle.certificate_pem);

            // Save to files
            // bundle.save_to_files("cert.pem", "key.pem")?;
        }
        Err(e) => {
            eprintln!("Failed to issue certificate: {}", e);
        }
    }

    Ok(())
}
