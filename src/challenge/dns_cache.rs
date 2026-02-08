use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
/// DNS query caching implementation
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::error::Result;

/// Cached DNS record
#[derive(Debug, Clone)]
struct CachedRecord<T> {
    /// Record value
    value: T,
    /// Expiration time
    expires_at: Instant,
}

impl<T> CachedRecord<T> {
    /// Create a new cached record
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    /// Check if record is expired
    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// DNS cache
pub struct DnsCache {
    /// A records cache
    a_records: Arc<RwLock<HashMap<String, CachedRecord<Vec<IpAddr>>>>>,
    /// AAAA records cache
    aaaa_records: Arc<RwLock<HashMap<String, CachedRecord<Vec<IpAddr>>>>>,
    /// TXT records cache
    txt_records: Arc<RwLock<HashMap<String, CachedRecord<Vec<String>>>>>,
    /// Default TTL
    default_ttl: Duration,
}

impl Default for DnsCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(60))
    }
}

impl DnsCache {
    /// Create a new DNS cache
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            a_records: Arc::new(RwLock::new(HashMap::new())),
            aaaa_records: Arc::new(RwLock::new(HashMap::new())),
            txt_records: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
        }
    }

    /// Get A records
    pub async fn get_a(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let cache = self.a_records.read().await;
        if let Some(record) = cache.get(domain)
            && !record.is_expired() {
                return Some(record.value.clone());
            }
        None
    }

    /// Set A records
    pub async fn set_a(&self, domain: &str, ips: Vec<IpAddr>, ttl: Option<Duration>) {
        let mut cache = self.a_records.write().await;
        cache.insert(
            domain.to_string(),
            CachedRecord::new(ips, ttl.unwrap_or(self.default_ttl)),
        );
    }

    /// Get AAAA records
    pub async fn get_aaaa(&self, domain: &str) -> Option<Vec<IpAddr>> {
        let cache = self.aaaa_records.read().await;
        if let Some(record) = cache.get(domain)
            && !record.is_expired() {
                return Some(record.value.clone());
            }
        None
    }

    /// Set AAAA records
    pub async fn set_aaaa(&self, domain: &str, ips: Vec<IpAddr>, ttl: Option<Duration>) {
        let mut cache = self.aaaa_records.write().await;
        cache.insert(
            domain.to_string(),
            CachedRecord::new(ips, ttl.unwrap_or(self.default_ttl)),
        );
    }

    /// Get TXT records
    pub async fn get_txt(&self, domain: &str) -> Option<Vec<String>> {
        let cache = self.txt_records.read().await;
        if let Some(record) = cache.get(domain)
            && !record.is_expired() {
                return Some(record.value.clone());
            }
        None
    }

    /// Set TXT records
    pub async fn set_txt(&self, domain: &str, txts: Vec<String>, ttl: Option<Duration>) {
        let mut cache = self.txt_records.write().await;
        cache.insert(
            domain.to_string(),
            CachedRecord::new(txts, ttl.unwrap_or(self.default_ttl)),
        );
    }

    /// Clear expired records
    pub async fn cleanup(&self) {
        let mut a_cache = self.a_records.write().await;
        a_cache.retain(|_, v| !v.is_expired());

        let mut aaaa_cache = self.aaaa_records.write().await;
        aaaa_cache.retain(|_, v| !v.is_expired());

        let mut txt_cache = self.txt_records.write().await;
        txt_cache.retain(|_, v| !v.is_expired());
    }
}

/// DNS resolver with caching
pub struct CachingDnsResolver {
    /// Underlying resolver (using hickory-resolver)
    resolver: hickory_resolver::TokioResolver,
    /// Cache
    cache: DnsCache,
}

impl CachingDnsResolver {
    /// Create a new caching resolver
    pub fn new() -> Result<Self> {
        let resolver = hickory_resolver::TokioResolver::builder_with_config(
            ResolverConfig::new(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            cache: DnsCache::default(),
        })
    }

    /// Resolve A records
    pub async fn resolve_a(&self, domain: &str) -> Result<Vec<IpAddr>> {
        if let Some(ips) = self.cache.get_a(domain).await {
            return Ok(ips);
        }

        let response =
            self.resolver.lookup_ip(domain).await.map_err(|e| {
                crate::error::AcmeError::transport(format!("DNS lookup failed: {}", e))
            })?;

        let ips: Vec<IpAddr> = response.iter().collect();
        self.cache.set_a(domain, ips.clone(), None).await;

        Ok(ips)
    }

    /// Resolve TXT records
    pub async fn resolve_txt(&self, domain: &str) -> Result<Vec<String>> {
        if let Some(txts) = self.cache.get_txt(domain).await {
            return Ok(txts);
        }

        let response = self.resolver.txt_lookup(domain).await.map_err(|e| {
            crate::error::AcmeError::transport(format!("DNS TXT lookup failed: {}", e))
        })?;

        let txts: Vec<String> = response.iter().map(|txt| txt.to_string()).collect();

        self.cache.set_txt(domain, txts.clone(), None).await;

        Ok(txts)
    }
}
