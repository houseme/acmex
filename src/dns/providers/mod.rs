/// Built-in DNS providers
pub mod alibaba;
pub mod azure;
pub mod godaddy;
pub mod google;
pub mod tencent;

#[cfg(feature = "dns-cloudflare")]
pub mod cloudflare;
#[cfg(feature = "dns-digitalocean")]
pub mod digitalocean;
#[cfg(feature = "dns-linode")]
pub mod linode;
#[cfg(feature = "dns-route53")]
pub mod route53;

// New providers - with feature gates
#[cfg(feature = "dns-alibaba")]
pub use alibaba::AlibabaCloudDnsProvider;
#[cfg(feature = "dns-azure")]
pub use azure::AzureDnsProvider;
#[cfg(feature = "dns-godaddy")]
pub use godaddy::GodaddyDnsProvider;
#[cfg(feature = "dns-google")]
pub use google::GoogleCloudDnsProvider;
#[cfg(feature = "dns-tencent")]
pub use tencent::TencentCloudDnsProvider;

#[cfg(feature = "dns-cloudflare")]
pub use cloudflare::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use digitalocean::DigitalOceanDnsProvider;
#[cfg(feature = "dns-linode")]
pub use linode::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use route53::Route53DnsProvider;
