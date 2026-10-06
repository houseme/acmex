/// Account management commands
use crate::account::{AccountManager, KeyPair, KeyRollover};
use crate::error::{AcmeError, Result};
use crate::protocol::{DirectoryManager, NonceManager};
use crate::types::Contact;
use tracing::info;

/// Handle account registration
pub async fn handle_register(email: String, prod: bool, key_path: String) -> Result<()> {
    info!("Registering new account for {}", email);

    // 1. Generate key pair
    let key_pair = KeyPair::generate()?;

    // 2. Setup client components
    let acme_url = if prod {
        "https://acme-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    };

    let http_client = reqwest::Client::new();
    let dir_mgr = DirectoryManager::new(acme_url, http_client.clone());
    let directory = dir_mgr.get().await?;
    let nonce_mgr = NonceManager::new(&directory.new_nonce, http_client.clone());

    let account_mgr = AccountManager::new(&key_pair, &nonce_mgr, &dir_mgr, &http_client)?;

    // 3. Register
    let contact = Contact::email(email);
    let account = account_mgr.register(vec![contact], true).await?;

    info!("Account registered: {}", account.id);
    println!("✅ Account registered successfully");
    println!("   ID: {}", account.id);
    println!("   Status: {}", account.status);

    // 4. Save key
    key_pair.save_to_file(&key_path)?;
    println!("   Key saved to: {}", key_path);

    Ok(())
}

/// Handle account update
pub async fn handle_update(key_path: String, email: String, prod: bool) -> Result<()> {
    info!("Updating account contact to {}", email);

    // 1. Load key
    let key_pair = KeyPair::load_from_file(&key_path)?;

    // 2. Setup client components
    let acme_url = if prod {
        "https://acme-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    };

    let http_client = reqwest::Client::new();
    let dir_mgr = DirectoryManager::new(acme_url, http_client.clone());
    let directory = dir_mgr.get().await?;
    let nonce_mgr = NonceManager::new(&directory.new_nonce, http_client.clone());

    let account_mgr = AccountManager::new(&key_pair, &nonce_mgr, &dir_mgr, &http_client)?;

    // 3. Get account ID (need to register/lookup first to get ID)
    // In a real implementation, we'd store the account ID or look it up
    // For now, we'll re-register which returns the existing account
    let contact = Contact::email(email.clone());
    let account = account_mgr.register(vec![contact.clone()], true).await?;

    // 4. Update
    let updated = account_mgr
        .update_contacts(&account.id, vec![contact])
        .await?;

    info!("Account updated: {}", updated.id);
    println!("✅ Account updated successfully");
    println!("   ID: {}", updated.id);
    println!("   Contacts: {:?}", updated.contact);

    Ok(())
}

/// Handle account deactivation
pub async fn handle_deactivate(key_path: String, prod: bool) -> Result<()> {
    info!("Deactivating account");

    // 1. Load key
    let key_pair = KeyPair::load_from_file(&key_path)?;

    // 2. Setup client components
    let acme_url = if prod {
        "https://acme-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    };

    let http_client = reqwest::Client::new();
    let dir_mgr = DirectoryManager::new(acme_url, http_client.clone());
    let directory = dir_mgr.get().await?;
    let nonce_mgr = NonceManager::new(&directory.new_nonce, http_client.clone());

    let account_mgr = AccountManager::new(&key_pair, &nonce_mgr, &dir_mgr, &http_client)?;

    // 3. Get account ID
    // Re-register to get ID (safe operation, returns existing account)
    let account = account_mgr.register(vec![], true).await?;

    // 4. Deactivate
    account_mgr.deactivate(&account.id).await?;

    info!("Account deactivated: {}", account.id);
    println!("✅ Account deactivated successfully");

    Ok(())
}

/// Handle key rotation
pub async fn handle_rotate_key(key_path: String, new_key_path: String, prod: bool) -> Result<()> {
    info!("Rotating account key");

    // 1. Load old key
    let key_pair = KeyPair::load_from_file(&key_path)?;

    // 2. Setup client components
    let acme_url = if prod {
        "https://acme-v02.api.letsencrypt.org/directory"
    } else {
        "https://acme-staging-v02.api.letsencrypt.org/directory"
    };

    let http_client = reqwest::Client::new();
    let dir_mgr = DirectoryManager::new(acme_url, http_client.clone());
    let directory = dir_mgr.get().await?;
    let nonce_mgr = NonceManager::new(&directory.new_nonce, http_client.clone());

    let account_mgr = AccountManager::new(&key_pair, &nonce_mgr, &dir_mgr, &http_client)?;

    // 3. Get account ID
    let account = account_mgr.register(vec![], true).await?;

    // 4. Perform rollover
    let rollover = KeyRollover::new(&account_mgr)?;
    let updated_account = rollover.execute(&account.id).await?;

    // 5. Save new key
    rollover.new_key_pair().save_to_file(&new_key_path)?;

    info!("Account key rotated: {}", updated_account.id);
    println!("✅ Account key rotated successfully");
    println!("   New key saved to: {}", new_key_path);

    Ok(())
}

/// Triggers the safe account-key rollover exposed by the API v1 control
/// plane. The server owns the account secret store and shares its backend
/// with the workflow worker, so this CLI never reads or writes private keys.
pub async fn handle_rollover_account_key(
    account_id: String,
    api_base: String,
    api_key: Option<String>,
) -> Result<()> {
    let key = api_key
        .or_else(|| std::env::var("ACMEX_API_KEY").ok())
        .ok_or_else(|| AcmeError::invalid_input("provide --api-key or set ACMEX_API_KEY"))?;
    let base = api_base.trim_end_matches('/');
    let response = reqwest::Client::new()
        .post(format!("{base}/accounts/{account_id}/key-rollover"))
        .header("X-API-Key", key)
        .send()
        .await
        .map_err(|err| AcmeError::transport(format!("API request failed: {err}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| AcmeError::transport(format!("API response read failed: {err}")))?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value["detail"]
                    .as_str()
                    .or_else(|| value["title"].as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        return Err(AcmeError::transport(format!(
            "API returned {status}: {detail}"
        )));
    }
    let view: serde_json::Value = serde_json::from_slice(&body)?;
    println!(
        "Account key rollover completed: account={} ca={} key_id={}",
        view["account_id"].as_str().unwrap_or("-"),
        view["ca_id"].as_str().unwrap_or("-"),
        view["key_id"].as_str().unwrap_or("-")
    );
    Ok(())
}
