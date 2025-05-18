use crate::account::{Account, create_jws, get_nonce};
use crate::{AcmeError, Directory};
use base64::Engine;
use rcgen::DistinguishedName;
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{error, info};

#[derive(Deserialize)]
pub struct Order {
    pub status: String,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct OrderPayload {
    identifiers: Vec<Identifier>,
}

#[derive(Serialize, Deserialize)]
struct Identifier {
    #[serde(rename = "type")]
    type_: String,
    value: String,
}

#[derive(Serialize, Deserialize)]
pub struct CertResult {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub async fn create_order(
    client: &reqwest::Client,
    directory: &Directory,
    account: &Account,
    domains: &[String],
    account_key: &[u8],
) -> Result<String, AcmeError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        account_key,
        &ring::rand::SystemRandom::new(),
    )?;
    let nonce = get_nonce(client, directory).await?;
    let payload = OrderPayload {
        identifiers: domains
            .iter()
            .map(|d| Identifier {
                type_: "dns".to_string(),
                value: d.to_string(),
            })
            .collect(),
    };
    let jws = create_jws(
        &key_pair,
        &directory.new_order,
        Some(&account.id),
        &nonce,
        &payload,
    )?;

    let response = client
        .post(&directory.new_order)
        .header("Content-Type", "application/jose+json")
        .body(jws)
        .send()
        .await?;

    if response.status().is_success() {
        let order_url = response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| AcmeError::Validation("Missing order URL".into()))?;
        let order: Order = response.json().await?;
        info!("订单创建成功，状态：{}", order.status);
        Ok(order_url)
    } else {
        let err = response.text().await?;
        error!("订单创建失败：{}", err);
        Err(AcmeError::Other(err))
    }
}

pub async fn fetch_order(
    client: &reqwest::Client,
    order_url: &str,
    account: &Account,
    account_key: &[u8],
) -> Result<Order, AcmeError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        account_key,
        &ring::rand::SystemRandom::new(),
    )?;
    let nonce = get_nonce(
        client,
        &Directory {
            new_nonce: order_url.to_string(),
            ..Default::default()
        },
    )
    .await?;
    let payload = json!({});
    let jws = create_jws(&key_pair, order_url, Some(&account.id), &nonce, &payload)?;

    let response = client
        .post(order_url)
        .header("Content-Type", "application/jose+json")
        .body(jws)
        .send()
        .await?;

    if response.status().is_success() {
        let order: Order = response.json().await?;
        info!("订单获取成功：{:?}", order.status);
        Ok(order)
    } else {
        let err = response.text().await?;
        error!("订单获取失败：{}", err);
        Err(AcmeError::Other(err))
    }
}

pub async fn finalize_order(
    client: &reqwest::Client,
    order: &Order,
    account_key: &[u8],
    domains: &[String],
) -> Result<CertResult, AcmeError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        account_key,
        &ring::rand::SystemRandom::new(),
    )?;
    let private_key = EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &ring::rand::SystemRandom::new(),
    )
    .map_err(|_| AcmeError::Other("Failed to generate private key".into()))?
    .as_ref()
    .to_vec();

    let csr = generate_csr(&key_pair, domains)?;
    let nonce = get_nonce(
        client,
        &Directory {
            new_nonce: order.finalize.clone(),
            ..Default::default()
        },
    )
    .await?;
    let payload = json!({ "csr": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&csr) });
    let jws = create_jws(
        &key_pair,
        &order.finalize,
        Some(&order.finalize),
        &nonce,
        &payload,
    )?;

    let response = client
        .post(&order.finalize)
        .header("Content-Type", "application/jose+json")
        .body(jws)
        .send()
        .await?;

    if response.status().is_success() {
        let order: Order = response.json().await?;
        if order.status == "valid" && order.certificate.is_some() {
            let cert = client
                .post(order.certificate.as_ref().unwrap())
                .header("Content-Type", "application/jose+json")
                .body(create_jws(
                    &key_pair,
                    order.certificate.as_ref().unwrap(),
                    Some(&order.finalize),
                    &nonce,
                    &json!({}),
                )?)
                .send()
                .await?
                .bytes()
                .await?;
            info!("证书签发成功");
            Ok(CertResult {
                certificate: cert.to_vec(),
                private_key,
            })
        } else {
            Err(AcmeError::Validation("Order not valid".into()))
        }
    } else {
        let err = response.text().await?;
        error!("订单完成失败：{}", err);
        Err(AcmeError::Other(err))
    }
}

/// 生成 CSR
fn generate_csr(_key_pair: &EcdsaKeyPair, domains: &[String]) -> Result<Vec<u8>, AcmeError> {
    use rcgen::{CertificateParams, KeyPair as RcgenKeyPair};

    // 构造 CSR 参数
    let mut params = CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = DistinguishedName::new();

    // 创建新的 rcgen 密钥对，因为 ring 的 EcdsaKeyPair 无法直接转换为 rcgen 密钥
    // 这里我们必须生成新密钥，而不是复用 ring 的密钥
    let rcgen_key = RcgenKeyPair::generate()?;

    // 生成 Certificate 对象和 CSR
    let cert = params.self_signed(&rcgen_key)?;
    let pem_serialized = cert.pem();
    let pem = pem::parse(&pem_serialized)
        .map_err(|e| AcmeError::Other(format!("pem parse error: {}", e)))?;
    let der_serialized = pem.contents();

    Ok(der_serialized.to_vec())
}
