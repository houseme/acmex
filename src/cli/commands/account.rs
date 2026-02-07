/// Account management commands
use crate::account::{AccountManager, KeyPair, KeyRollover};
use crate::error::Result;
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
