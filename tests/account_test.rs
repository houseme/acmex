mod common;

use acmex::prelude::*;
use common::MockAcmeServer;

#[tokio::test]
async fn test_full_account_lifecycle() -> Result<()> {
    let mut mock_server = MockAcmeServer::new().await;
    let _m_dir = mock_server.mock_directory().await;
    let _m_nonce = mock_server.mock_new_nonce().await;
    let _m_account = mock_server.mock_new_account().await;

    // 1. Setup client
    let config = AcmeConfig::new(format!("{}/directory", mock_server.url()))
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;

    // 2. Register account
    client.register_account().await?;

    // 3. Verify status
    // (In a real test we'd check more properties)
    tracing::info!("Account registered successfully at mock server");

    Ok(())
}

#[tokio::test]
async fn lookup_existing_account_uses_location_as_account_id() -> Result<()> {
    let mut mock_server = MockAcmeServer::new().await;
    let _m_dir = mock_server.mock_directory().await;
    let _m_nonce = mock_server.mock_new_nonce().await;
    let _m_account = mock_server.mock_existing_account().await;

    let http_client = reqwest::Client::new();
    let directory_manager = DirectoryManager::new(
        format!("{}/directory", mock_server.url()),
        http_client.clone(),
    );
    let directory = directory_manager.get().await?;
    let nonce_manager = NonceManager::new(&directory.new_nonce, http_client.clone());
    let key_pair = KeyPair::generate()?;
    let account_manager =
        AccountManager::new(&key_pair, &nonce_manager, &directory_manager, &http_client)?;

    let account = account_manager.lookup_existing_account().await?;

    assert_eq!(account.id, format!("{}/account/1", mock_server.url()));
    assert_eq!(account.status, "valid");
    Ok(())
}

#[tokio::test]
async fn lookup_existing_account_reports_ca_problem_before_location_header() -> Result<()> {
    let mut mock_server = MockAcmeServer::new().await;
    let _m_dir = mock_server.mock_directory().await;
    let _m_nonce = mock_server.mock_new_nonce().await;
    let _m_account = mock_server
        .server
        .mock("POST", "/new-account")
        .with_status(400)
        .with_header("content-type", "application/problem+json")
        .with_body(
            serde_json::json!({
                "type": "urn:ietf:params:acme:error:accountDoesNotExist",
                "detail": "No account exists for this key"
            })
            .to_string(),
        )
        .expect(1)
        .create_async()
        .await;

    let http_client = reqwest::Client::new();
    let directory_manager = DirectoryManager::new(
        format!("{}/directory", mock_server.url()),
        http_client.clone(),
    );
    let directory = directory_manager.get().await?;
    let nonce_manager = NonceManager::new(&directory.new_nonce, http_client.clone());
    let key_pair = KeyPair::generate()?;
    let account_manager =
        AccountManager::new(&key_pair, &nonce_manager, &directory_manager, &http_client)?;

    let err = account_manager
        .lookup_existing_account()
        .await
        .expect_err("missing account should return the CA problem body");
    let message = err.to_string();

    assert!(message.contains("accountDoesNotExist"), "got: {message}");
    assert!(
        !message.contains("Missing location header"),
        "got: {message}"
    );
    Ok(())
}
