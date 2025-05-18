use async_trait::async_trait;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::{config::ResolverConfig, Resolver};
use std::error::Error;
use tokio::time::{sleep, Duration};
use tracing::info;

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<(), Box<dyn Error>>;
    async fn remove_txt_record(&self, domain: &str, value: &str) -> Result<(), Box<dyn Error>>;
}

pub struct MockDnsProvider;

#[async_trait]
impl DnsProvider for MockDnsProvider {
    async fn add_txt_record(&self, domain: &str, value: &str) -> Result<(), Box<dyn Error>> {
        info!("添加 TXT 记录：{} -> {}", domain, value);
        Ok(())
    }

    async fn remove_txt_record(&self, domain: &str, value: &str) -> Result<(), Box<dyn Error>> {
        info!("删除 TXT 记录：{} -> {}", domain, value);
        Ok(())
    }
}

pub async fn check_dns_propagation(domain: &str, value: &str) -> Result<(), Box<dyn Error>> {
    let resolver = Resolver::builder_with_config(
        ResolverConfig::default(),
        TokioConnectionProvider::default(),
    )
    .build();
    let max_attempts = 12; // 60 秒，5 秒间隔
    for _ in 0..max_attempts {
        match resolver.txt_lookup(domain).await {
            Ok(response) => {
                if response.iter().any(|r| r.to_string().contains(value)) {
                    info!("DNS TXT 记录已传播：{} -> {}", domain, value);
                    return Ok(());
                }
            }
            Err(e) => tracing::warn!("DNS 查询失败：{}", e),
        }
        sleep(Duration::from_secs(5)).await;
    }
    Err("DNS TXT 记录传播超时".into())
}
