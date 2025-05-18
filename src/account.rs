use crate::cache::Cache;
use crate::{AcmeError, Directory};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::signature::{EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

/// Represents an ACME account.
pub struct Account {
    pub id: String,
    pub key: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct AccountPayload {
    contact: Vec<String>,
    #[serde(rename = "termsOfServiceAgreed")]
    terms_of_service_agreed: bool,
}

pub async fn load_or_create_account_key(cache: &Arc<dyn Cache>) -> Result<Vec<u8>, AcmeError> {
    let key_id = "account_key";
    if let Some(key) = cache
        .load(key_id)
        .await
        .map_err(|e| AcmeError::Other(e.to_string()))?
    {
        Ok(key)
    } else {
        let key_pair = EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .expect("Failed to generate key pair");
        let key = key_pair.as_ref().to_vec();
        cache
            .store(key_id, &key)
            .await
            .map_err(|e| AcmeError::Other(e.to_string()))?;
        Ok(key)
    }
}

pub async fn register_account(
    client: &reqwest::Client,
    directory: &Directory,
    key: &[u8],
    contact: &[String],
) -> Result<Account, AcmeError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        key,
        &ring::rand::SystemRandom::new(),
    )?;
    let nonce = get_nonce(client, directory).await?;
    let payload = AccountPayload {
        contact: contact.to_vec(),
        terms_of_service_agreed: true,
    };
    let jws = create_jws(&key_pair, &directory.new_account, None, &nonce, &payload)?;

    let response = client
        .post(&directory.new_account)
        .header("Content-Type", "application/jose+json")
        .body(jws)
        .send()
        .await?;

    if response.status().is_success() {
        let account: serde_json::Value = response.json().await?;
        let id = account["kid"]
            .as_str()
            .ok_or_else(|| AcmeError::Validation("Missing account ID".into()))?
            .to_string();
        info!("账户注册成功：{}", id);
        Ok(Account {
            id,
            key: key.to_vec(),
        })
    } else {
        let err = response.text().await?;
        error!("账户注册失败：{}", err);
        Err(AcmeError::Other(err))
    }
}

pub async fn get_nonce(
    client: &reqwest::Client,
    nonce_url: &Directory,
) -> Result<String, AcmeError> {
    println!("获取 nonce:{:?}", nonce_url.new_nonce);
    let response = client.head("".to_string()).send().await?;
    response
        .headers()
        .get("replay-nonce")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| AcmeError::Validation("Missing nonce".into()))
}

pub fn create_jws<T: Serialize>(
    key_pair: &EcdsaKeyPair,
    url: &str,
    kid: Option<&str>,
    nonce: &str,
    payload: &T,
) -> Result<String, AcmeError> {
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload)?);
    let mut protected = serde_json::Map::new();
    protected.insert("alg".to_string(), json!("ES256"));
    protected.insert("nonce".to_string(), json!(nonce));
    protected.insert("url".to_string(), json!(url));
    if let Some(kid) = kid {
        protected.insert("kid".to_string(), json!(kid));
    } else {
        protected.insert("jwk".to_string(), jwk_from_key_pair(key_pair));
    }
    let protected_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&protected)?);
    let input = format!("{}.{}", protected_b64, payload_b64);
    let signature = key_pair
        .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
        .map_err(|e| AcmeError::Crypto(format!("ring sign error: {e:?}")))?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(signature.as_ref());
    Ok(serde_json::to_string(&json!({
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": signature_b64,
    }))?)
}

fn jwk_from_key_pair(key_pair: &EcdsaKeyPair) -> serde_json::Value {
    let (x, y) = key_pair.public_key().as_ref()[1..].split_at(32);
    json!({
        "crv": "P-256",
        "kty": "EC",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    })
}
