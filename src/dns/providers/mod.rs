/// Built-in DNS providers
#[cfg(feature = "dns-cloudflare")]
pub mod cloudflare;
#[cfg(feature = "dns-digitalocean")]
pub mod digitalocean;
#[cfg(feature = "dns-linode")]
pub mod linode;
#[cfg(feature = "dns-route53")]
pub mod route53;

#[cfg(feature = "dns-cloudflare")]
pub use cloudflare::CloudFlareDnsProvider;
#[cfg(feature = "dns-digitalocean")]
pub use digitalocean::DigitalOceanDnsProvider;
#[cfg(feature = "dns-linode")]
pub use linode::LinodeDnsProvider;
#[cfg(feature = "dns-route53")]
pub use route53::Route53DnsProvider;
