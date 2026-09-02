use crate::error::{AcmeError, Result};

pub async fn handle_status(
    operation_id: String,
    api_base: String,
    api_key: Option<String>,
) -> Result<()> {
    let key = api_key
        .or_else(|| std::env::var("ACMEX_API_KEY").ok())
        .ok_or_else(|| AcmeError::invalid_input("provide --api-key or set ACMEX_API_KEY"))?;
    let base = api_base.trim_end_matches('/');
    let client = reqwest::Client::new();

    let operation: serde_json::Value =
        get_json(&client, &key, &format!("{base}/operations/{operation_id}")).await?;
    println!(
        "Operation {}",
        operation["id"].as_str().unwrap_or(&operation_id)
    );
    println!(
        "  Kind: {}",
        operation["kind"].as_str().unwrap_or("unknown")
    );
    println!(
        "  Status: {}",
        operation["status"].as_str().unwrap_or("unknown")
    );
    println!(
        "  Current step: {}",
        operation["current_step"].as_str().unwrap_or("-")
    );
    println!(
        "  Progress: {:.0}%",
        operation["progress"].as_f64().unwrap_or(0.0) * 100.0
    );
    if let Some(error_code) = operation["error_code"].as_str() {
        println!("  Error: {error_code}");
    }

    let challenges: serde_json::Value = get_json(
        &client,
        &key,
        &format!("{base}/operations/{operation_id}/challenges"),
    )
    .await?;
    let Some(challenges) = challenges.as_array() else {
        return Ok(());
    };
    if challenges.is_empty() {
        return Ok(());
    }

    println!("Challenges");
    for challenge in challenges {
        println!(
            "  {} {} {}",
            challenge["identifier"].as_str().unwrap_or("-"),
            challenge["challenge_type"].as_str().unwrap_or("-"),
            challenge["state"].as_str().unwrap_or("-")
        );
        if let Some(status) = challenge["last_propagation_status"].as_str() {
            println!(
                "    Propagation: {} at {}",
                status,
                challenge["last_propagation_check_at"]
                    .as_str()
                    .unwrap_or("-")
            );
        }
        if let Some(status) = challenge["last_ca_status"].as_str() {
            println!(
                "    CA poll: {} at {}",
                status,
                challenge["last_ca_poll_at"].as_str().unwrap_or("-")
            );
        }
        if let Some(last_error) = challenge["last_error"].as_str() {
            println!("    Last error: {last_error}");
        }
    }

    Ok(())
}

async fn get_json(client: &reqwest::Client, key: &str, url: &str) -> Result<serde_json::Value> {
    let response = client
        .get(url)
        .header("X-API-Key", key)
        .send()
        .await
        .map_err(|err| AcmeError::transport(format!("API request failed: {err}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|err| AcmeError::transport(format!("API response read failed: {err}")))?;
    if !status.is_success() {
        let detail = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|value| {
                value["detail"]
                    .as_str()
                    .or_else(|| value["title"].as_str())
                    .map(str::to_string)
            })
            .unwrap_or_else(|| String::from_utf8_lossy(&body).into_owned());
        return Err(AcmeError::transport(format!(
            "API returned {status}: {detail}"
        )));
    }
    serde_json::from_slice(&body).map_err(Into::into)
}
