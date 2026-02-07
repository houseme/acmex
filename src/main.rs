/// Simple example of using acmex as a library
use acmex::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create a configuration for Let's Encrypt staging
    let config = AcmeConfig::lets_encrypt_staging()
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    println!("ACME Config:");
    println!("  Directory URL: {}", config.directory_url);
    println!("  Contacts: {:?}", config.contacts);
    println!("  TOS Agreed: {}", config.terms_of_service_agreed);

    // Example usage:
    // 1. Create HTTP client
    let http_client = reqwest::Client::new();

    // 2. Get directory
    let dir_manager =
        acmex::protocol::DirectoryManager::new(&config.directory_url, http_client.clone());
    let directory = dir_manager.get().await?;

    println!("\nACME Directory endpoints:");
    println!("  New Nonce: {}", directory.new_nonce);
    println!("  New Account: {}", directory.new_account);
    println!("  New Order: {}", directory.new_order);

    // 3. Generate key pair
    let key_pair = KeyPair::generate()?;
    println!("\nKey pair generated successfully");

    // 4. Create nonce manager
    let nonce_manager =
        acmex::protocol::NonceManager::new(&directory.new_nonce, http_client.clone());

    // 5. Create account manager
    let account_manager =
        AccountManager::new(&key_pair, &nonce_manager, &dir_manager, &http_client)?;

    println!("\nAccount manager created successfully");
    println!("JWK: {:?}", account_manager.get_jwk());

    println!("\nv0.1.0 - Core ACME Protocol Implementation");
    println!("Successfully demonstrated basic ACME operations!");

    Ok(())
}
