/// Built-in DNS providers
pub mod alibaba;
pub mod azure;
pub mod cloudflare;
pub mod cloudns;
pub mod digitalocean;
pub mod godaddy;
pub mod google;
pub mod huawei;
pub mod linode;
pub mod route53;
pub mod tencent;

// Re-exports with feature gates
#[cfg(feature = "dns-alibaba")]
pub use alibaba::AlibabaCloudDnsProvider;
#[cfg(feature = "dns-azure")]
pub use azure::AzureDnsProvider;
#[cfg(feature = "dns-cloudflare")]
pub use cloudflare::CloudFlareDnsProvider;
#[cfg(feature = "dns-cloudns")]
pub use cloudns::ClouDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use digitalocean::DigitalOceanDnsProvider;
#[cfg(feature = "dns-godaddy")]
pub use godaddy::GodaddyDnsProvider;
#[cfg(feature = "dns-google")]
pub use google::GoogleCloudDnsProvider;
#[cfg(feature = "dns-huawei")]
pub use huawei::HuaweiCloudDnsProvider;
#[cfg(feature = "dns-linode")]
pub use linode::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use route53::Route53DnsProvider;
#[cfg(feature = "dns-tencent")]
pub use tencent::TencentCloudDnsProvider;
