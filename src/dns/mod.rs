/// DNS provider implementations for ACME DNS-01 challenge.
/// This module contains various DNS provider implementations that allow
/// automatic creation and deletion of TXT records required for domain validation.
pub mod providers;

// Re-exports with feature gates for easier access to specific providers.
#[cfg(feature = "dns-alibaba")]
pub use providers::AlibabaCloudDnsProvider;
#[cfg(feature = "dns-azure")]
pub use providers::AzureDnsProvider;
#[cfg(feature = "dns-godaddy")]
pub use providers::GodaddyDnsProvider;
#[cfg(feature = "dns-google")]
pub use providers::GoogleCloudDnsProvider;
#[cfg(feature = "dns-cloudflare")]
pub use providers::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use providers::DigitalOceanDnsProvider;
#[cfg(feature = "dns-linode")]
pub use providers::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use providers::Route53DnsProvider;
#[cfg(feature = "dns-tencent")]
pub use providers::TencentCloudDnsProvider;
#[cfg(feature = "dns-huawei")]
pub use providers::HuaweiCloudDnsProvider;
#[cfg(feature = "dns-cloudns")]
pub use providers::ClouDnsProvider;
