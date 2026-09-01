/// Renew certificate command.
use crate::application::{
    ActorContext, ApplicationServiceBuilder, CertificateApplication, RenewCertificate,
};
use crate::config::{FileRepositoryConfig, RepositorySettings};
use crate::error::Result;
use tracing::info;

/// Renew existing certificate
pub async fn handle_renew(domains: Vec<String>, force: bool, storage_path: String) -> Result<()> {
    if domains.is_empty() {
        return Err(crate::error::AcmeError::InvalidInput(
            "No domains specified".to_string(),
        ));
    }

    info!("Starting certificate renewal for domains: {:?}", domains);
    println!("🔄 Renewing certificate for domains: {:?}", domains);
    println!("   Repository directory: {}", storage_path);

    let config = crate::config::Config {
        repository: RepositorySettings {
            backend: "file".to_string(),
            file: Some(FileRepositoryConfig { path: storage_path }),
            ..RepositorySettings::default()
        },
        ..crate::config::Config::default()
    };
    let (service, _repositories) = ApplicationServiceBuilder::from_config(&config)
        .await?
        .build()?;
    let operation = service
        .renew(RenewCertificate {
            context: ActorContext::default(),
            lineage_id: None,
            identifiers: domains.clone(),
            force,
            idempotency_key: format!("cli-renew-{}", domains.join(",")),
        })
        .await?;

    println!("✓ Renewal operation: {}", operation.id);
    println!("Renewal execution is handled by the workflow worker and can be polled via API v1.");
    info!(operation = %operation.id, "certificate renewal operation submitted");
    Ok(())
}
