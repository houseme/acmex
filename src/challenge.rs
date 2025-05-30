use crate::account::{Account, create_jws, get_nonce};
use crate::dns::{DnsProvider, check_dns_propagation};
use crate::order::{Order, fetch_order};
use crate::{AcmeError, Directory};
use ring::signature::EcdsaKeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::time::{Duration, sleep};
use tracing::info;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ChallengeType {
    TlsAlpn01,
    Http01,
    Dns01,
}

#[derive(Deserialize, Serialize)]
struct Authorization {
    challenges: Vec<Challenge>,
}

#[derive(Deserialize, Serialize)]
struct Challenge {
    #[serde(rename = "type")]
    type_: String,
    url: String,
    token: String,
}

pub async fn handle_challenge(
    client: &reqwest::Client,
    order: &Order,
    challenge_type: ChallengeType,
    dns_provider: Option<&dyn DnsProvider>,
    account: &Account,
    account_key: &[u8],
) -> Result<(), AcmeError> {
    let key_pair = EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        account_key,
        &ring::rand::SystemRandom::new(),
    )?;

    // 将 for 循环改为 if let，因为循环内有 return 语句导致它最多只执行一次
    if let Some(auth_url) = order.authorizations.first() {
        let nonce = get_nonce(
            client,
            &Directory {
                new_nonce: auth_url.to_string(),
                ..Default::default()
            },
        )
        .await?;
        let jws = create_jws(&key_pair, auth_url, Some(&account.id), &nonce, &json!({}))?;
        let auth: Authorization = client
            .post(auth_url)
            .header("Content-Type", "application/jose+json")
            .body(jws)
            .send()
            .await?
            .json()
            .await?;

        let challenge = auth
            .challenges
            .iter()
            .find(|c| {
                c.type_
                    == match challenge_type {
                        ChallengeType::TlsAlpn01 => "tls-alpn-01",
                        ChallengeType::Http01 => "http-01",
                        ChallengeType::Dns01 => "dns-01",
                    }
            })
            .ok_or_else(|| AcmeError::Validation("Challenge not found".into()))?;

        match challenge_type {
            ChallengeType::TlsAlpn01 => {
                info!("处理 TLS-ALPN-01 挑战：{}", challenge.token);
                // 假设 TLS 配置已设置，实际需在 rustls 中配置 ALPN
                let nonce = get_nonce(
                    client,
                    &Directory {
                        new_nonce: challenge.url.clone(),
                        ..Default::default()
                    },
                )
                .await?;
                let jws = create_jws(
                    &key_pair,
                    &challenge.url,
                    Some(&account.id),
                    &nonce,
                    &json!({}),
                )?;
                client
                    .post(&challenge.url)
                    .header("Content-Type", "application/jose+json")
                    .body(jws)
                    .send()
                    .await?;
            }
            ChallengeType::Http01 => {
                info!("处理 HTTP-01 挑战：{}", challenge.token);
                // 假设 HTTP 服务器已设置，实际需提供 /.well-known/acme-challenge/
                let nonce = get_nonce(
                    client,
                    &Directory {
                        new_nonce: challenge.url.clone(),
                        ..Default::default()
                    },
                )
                .await?;
                let jws = create_jws(
                    &key_pair,
                    &challenge.url,
                    Some(&account.id),
                    &nonce,
                    &json!({}),
                )?;
                client
                    .post(&challenge.url)
                    .header("Content-Type", "application/jose+json")
                    .body(jws)
                    .send()
                    .await?;
            }
            ChallengeType::Dns01 => {
                if let Some(provider) = dns_provider {
                    info!("处理 DNS-01 挑战：{}", challenge.token);
                    let txt_value = format!("{}.{}", challenge.token, account.id); // 简化，实际需计算 key authorization
                    provider
                        .add_txt_record("_acme-challenge.example.com", &txt_value)
                        .await
                        .map_err(|e| {
                            AcmeError::Validation(format!("DNS 提供商添加记录失败：{}", e))
                        })?;
                    check_dns_propagation("_acme-challenge.example.com", &txt_value)
                        .await
                        .map_err(|e| AcmeError::Validation(format!("DNS 传播检查失败：{}", e)))?;
                    let nonce = get_nonce(
                        client,
                        &Directory {
                            new_nonce: challenge.url.clone(),
                            ..Default::default()
                        },
                    )
                    .await?;
                    let jws = create_jws(
                        &key_pair,
                        &challenge.url,
                        Some(&account.id),
                        &nonce,
                        &json!({}),
                    )?;
                    client
                        .post(&challenge.url)
                        .header("Content-Type", "application/jose+json")
                        .body(jws)
                        .send()
                        .await?;
                    provider
                        .remove_txt_record("_acme-challenge.example.com", &txt_value)
                        .await
                        .map_err(|e| {
                            AcmeError::Validation(format!("DNS 提供商删除记录失败：{}", e))
                        })?;
                } else {
                    return Err(AcmeError::Validation("DNS-01 需要 DNS 提供商".into()));
                }
            }
        }

        // 轮询挑战状态，使用当前处理的 auth_url 而非硬编码索引
        for _ in 0..10 {
            let order = fetch_order(client, auth_url, account, account_key).await?;
            if order.status == "valid" {
                return Ok(());
            }
            sleep(Duration::from_secs(2)).await;
        }
        Err(AcmeError::Validation("挑战验证超时".into()))
    } else {
        // 如果没有授权 URL，则返回错误
        Err(AcmeError::Validation("未找到授权 URL".into()))
    }
}
