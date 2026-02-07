mod common;

use acmex::prelude::*;
use common::MockAcmeServer;
use serde_json::json;

#[tokio::test]
async fn test_certificate_order_flow() -> Result<()> {
    let mut mock_server = MockAcmeServer::new().await;
    let url = mock_server.url();

    // Setup mocks for a full issuance flow
    let _m_dir = mock_server.mock_directory().await;
    let _m_nonce = mock_server.mock_new_nonce().await;
    let _m_account = mock_server.mock_new_account().await;

    // Mock new order
    let _m_order = mock_server
        .server
        .mock("POST", "/new-order")
        .with_status(201)
        .with_header("location", &format!("{}/order/1", url))
        .with_body(
            json!({
                "status": "pending",
                "expires": "2026-02-10T00:00:00Z",
                "identifiers": [{"type": "dns", "value": "example.com"}],
                "authorizations": [format!("{}/authz/1", url)],
                "finalize": format!("{}/order/1/finalize", url)
            })
            .to_string(),
        )
        .create_async()
        .await;

    // 1. Setup client
    let config = AcmeConfig::new(&format!("{}/directory", url))
        .with_contact(Contact::email("admin@example.com"))
        .with_tos_agreed(true);

    let mut client = AcmeClient::new(config)?;
    client.register_account().await?;

    // 2. Create order
    let order = client.create_order(vec!["example.com".to_string()]).await?;
    assert_eq!(order.status, "pending");

    Ok(())
}
