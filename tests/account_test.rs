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
    let config = AcmeConfig::new(&format!("{}/directory", mock_server.url()))
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
