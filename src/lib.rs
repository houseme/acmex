use crate::account::{load_or_create_account_key, register_account};
use crate::cache::{Cache, FileCache};
use crate::challenge::{ChallengeType, handle_challenge};
use crate::dns::DnsProvider;
use crate::order::{create_order, fetch_order, finalize_order};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::info;

#[cfg(feature = "redis")]
use crate::cache::RedisCache;

pub mod account;
pub mod cache;
pub mod challenge;
pub mod dns;
pub mod order;

#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("Network error:{0}")]
    Network(#[from] reqwest::Error),

    #[error("Validation errors:{0}")]
    Validation(String),

    #[error("Limits on the frequency of API calls:{0}")]
    RateLimit(String),

    #[error("Encryption operation error:{0}")]
    Crypto(String),

    #[error("Certificate generation error:{0}")]
    CertError(#[from] rcgen::Error),

    #[error("Other errors:{0}")]
    Other(String),
}

impl From<serde_json::Error> for AcmeError {
    fn from(err: serde_json::Error) -> Self {
        AcmeError::Other(err.to_string())
    }
}

impl From<ring::error::KeyRejected> for AcmeError {
    fn from(err: ring::error::KeyRejected) -> Self {
        AcmeError::Crypto(err.to_string())
    }
}

#[derive(Clone, Serialize)]
pub struct AcmeConfig {
    domains: Vec<String>,
    contact: Vec<String>,
    directory_url: String,
    #[serde(skip)]
    cache: Arc<dyn Cache>,
    prod: bool,
}

impl AcmeConfig {
    pub fn new(domains: Vec<String>) -> Self {
        Self {
            domains,
            contact: vec![],
            directory_url: "letsencrypt".to_string(),
            cache: Arc::new(FileCache::new("./acmex_cache")),
            prod: false,
        }
    }

    pub fn contact(mut self, contact: Vec<String>) -> Self {
        self.contact = contact;
        self
    }

    pub fn directory_url(mut self, url: impl Into<String>) -> Self {
        self.directory_url = url.into();
        self
    }

    pub fn cache(mut self, cache: impl Cache + 'static) -> Self {
        self.cache = Arc::new(cache);
        self
    }

    pub fn prod(mut self, prod: bool) -> Self {
        self.prod = prod;
        self
    }

    #[cfg(feature = "redis")]
    pub fn redis_cache(mut self, redis_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        self.cache = Arc::new(RedisCache::new(redis_url)?);
        Ok(self)
    }
}

pub struct AcmeClient {
    config: AcmeConfig,
    client: reqwest::Client,
}

impl AcmeClient {
    pub fn new(config: AcmeConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    pub async fn provision_certificate(
        &self,
        challenge_type: ChallengeType,
        dns_provider: Option<&dyn DnsProvider>,
    ) -> Result<(Vec<u8>, Vec<u8>), AcmeError> {
        // 1. 连接 ACME 目录并获取必要的端点
        let directory_url = self.get_directory_url();
        info!("连接到 ACME 目录：{}", directory_url);
        let directory = self
            .client
            .get(&directory_url)
            .send()
            .await
            .map_err(AcmeError::Network)?
            .json::<Directory>()
            .await?;

        // 2. 加载或创建账户密钥
        info!("加载或创建账户密钥");
        let account_key = load_or_create_account_key(&self.config.cache).await?;

        // 3. 注册或验证账户
        info!("注册/验证 ACME 账户");
        let account =
            register_account(&self.client, &directory, &account_key, &self.config.contact).await?;

        // 4. 创建证书订单
        info!("创建证书订单：domains={:?}", self.config.domains);
        let order_url = create_order(
            &self.client,
            &directory,
            &account,
            &self.config.domains,
            &account_key,
        )
        .await?;

        // 5. 获取订单详情
        info!("获取订单详情");
        let order = fetch_order(&self.client, &order_url, &account, &account_key).await?;

        // 6. 处理验证挑战
        info!("处理域名验证挑战：{:?}", challenge_type);
        handle_challenge(
            &self.client,
            &order,
            challenge_type,
            dns_provider,
            &account,
            &account_key,
        )
        .await?;

        // 7. 完成订单并获取证书
        info!("完成订单并获取证书");
        let cert = finalize_order(&self.client, &order, &account_key, &self.config.domains).await?;

        info!("证书签发成功");
        Ok((cert.certificate, cert.private_key))
    }

    fn get_directory_url(&self) -> String {
        if self.config.prod {
            match self.config.directory_url.as_str() {
                "letsencrypt" => "https://acme-v02.api.letsencrypt.org/directory".to_string(),
                #[cfg(feature = "google-ca")]
                "google" => "https://dv.acme-v02.api.pki.goog/directory".to_string(),
                #[cfg(feature = "zerossl-ca")]
                "zerossl" => "https://acme.zerossl.com/v2/DV90/directory".to_string(),
                url => url.to_string(),
            }
        } else {
            "https://acme-staging-v02.api.letsencrypt.org/directory".to_string()
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Default)]
pub struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}
