use crate::account::{AccountManager, KeyPair};
use crate::error::Result;
use crate::order::CertificateRevocation;
use crate::protocol::{DirectoryManager, NonceManager};
use crate::storage::{CertificateStore, FileStorage, StorageBackend};
use crate::types::RevocationReason;
use std::fs;
use std::path::Path;
use tracing::info;

/// Handle certificate list command
pub async fn handle_cert_list() -> Result<()> {
    info!("Listing certificates...");

    // Default storage path for listing
    let storage_path = ".acmex";
    if !Path::new(storage_path).exists() {
        println!(
            "No certificates found (storage directory {} does not exist).",
            storage_path
        );
        return Ok(());
    }

    let storage = FileStorage::new(storage_path);
    let keys = storage.list("cert:").await?;

    if keys.is_empty() {
        println!("No certificates found.");
        return Ok(());
    }

    println!("{:<30} | {:<10} | {:<20}", "Domains", "Status", "Created");
    println!("{:-<30}-|-{:-<10}-|-{:-<20}", "", "", "");

    for key in keys {
        if let Some(data) = storage.load(&key).await? {
            // Attempt to deserialize as CertificateBundle if possible
            if let Ok(bundle) = serde_json::from_slice::<crate::client::CertificateBundle>(&data) {
                println!(
                    "{:<30} | {:<10} | {:<20}",
                    bundle.domains.join(", "),
                    "Valid", // Simplified status
                    "N/A"    // Simplified date
                );
            } else {
                println!(
                    "{:<30} | {:<10} | {:<20}",
                    key.replace("cert:", ""),
                    "Unknown",
                    "N/A"
                );
            }
        }
    }

    Ok(())
}

/// Handle certificate revocation
pub async fn handle_cert_revoke(
    cert_path: String,
    reason_str: Option<String>,
    key_path: String,
) -> Result<()> {
    info!("Revoking certificate: {}", cert_path);

    // 1. Load certificate
    let cert_der = pem::parse(fs::read(cert_path)?)
        .map_err(|e| crate::error::AcmeError::Certificate(e.to_string()))?
        .contents()
        .to_vec();

    // 2. Load account key
    let key_pem = fs::read_to_string(key_path)?;
    let key_pair = KeyPair::from_pem(&key_pem)?;

    // 3. Initialize ACME protocol components
    let http_client = reqwest::Client::new();
    let dir_url = "https://acme-v02.api.letsencrypt.org/directory"; // Default to prod for revocation usually
    let dir_manager = DirectoryManager::new(dir_url, http_client.clone());
    let directory = dir_manager.get().await?;
    let nonce_manager = NonceManager::new(&directory.new_nonce, http_client.clone());

    // 4. Create account manager
    let account_manager =
        AccountManager::new(&key_pair, &nonce_manager, &dir_manager, &http_client)?;

    // 5. Build and execute revocation
    let mut revocation = CertificateRevocation::new(&account_manager, "dummy_id", cert_der);

    if let Some(r) = reason_str {
        let reason = match r.to_lowercase().as_str() {
            "key-compromise" => RevocationReason::KeyCompromise,
            "ca-compromise" => RevocationReason::CaCompromise,
            "affiliation-changed" => RevocationReason::AffiliationChanged,
            "superseded" => RevocationReason::Superseded,
            "cessation-of-operation" => RevocationReason::CessationOfOperation,
            _ => RevocationReason::Unspecified,
        };
        revocation = revocation.with_reason(reason);
    }

    revocation.revoke().await?;
    info!("Successfully revoked certificate.");

    Ok(())
}
