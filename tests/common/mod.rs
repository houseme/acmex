use mockito::Server;
use serde_json::json;

pub struct MockAcmeServer {
    pub server: mockito::ServerGuard,
}

impl MockAcmeServer {
    pub async fn new() -> Self {
        let server = Server::new_async().await;
        Self { server }
    }

    pub fn url(&self) -> String {
        self.server.url()
    }

    pub async fn mock_directory(&mut self) -> mockito::Mock {
        let url = self.url();
        self.server
            .mock("GET", "/directory")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "newNonce": format!("{}/new-nonce", url),
                    "newAccount": format!("{}/new-account", url),
                    "newOrder": format!("{}/new-order", url),
                    "revokeCert": format!("{}/revoke-cert", url),
                    "keyChange": format!("{}/key-change", url),
                    "meta": {
                        "termsOfService": "https://example.com/tos"
                    }
                })
                .to_string(),
            )
            .create_async()
            .await
    }

    pub async fn mock_new_nonce(&mut self) -> mockito::Mock {
        self.server
            .mock("HEAD", "/new-nonce")
            .with_status(200)
            .with_header("replay-nonce", "test-nonce-123")
            .create_async()
            .await
    }

    pub async fn mock_new_account(&mut self) -> mockito::Mock {
        self.server
            .mock("POST", "/new-account")
            .with_status(201)
            .with_header("location", &format!("{}/account/1", self.url()))
            .with_body(
                json!({
                    "status": "valid",
                    "contact": ["mailto:admin@example.com"],
                    "orders": format!("{}/account/1/orders", self.url())
                })
                .to_string(),
            )
            .create_async()
            .await
    }
}
