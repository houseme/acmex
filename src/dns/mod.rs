/// DNS provider implementations
pub mod providers;

#[cfg(feature = "dns-cloudflare")]
pub use providers::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use providers::DigitalOceanDnsProvider;
#[cfg(feature = "dns-linode")]
pub use providers::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use providers::Route53DnsProvider;
