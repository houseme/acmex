use crate::error::{AcmeError, Result};
use tracing::info;

/// Handle order list command
pub async fn handle_order_list(api_base: String, api_key: Option<String>) -> Result<()> {
    info!("Listing ACME orders...");
    let key = api_key
        .or_else(|| std::env::var("ACMEX_API_KEY").ok())
        .ok_or_else(|| AcmeError::invalid_input("provide --api-key or set ACMEX_API_KEY"))?;
    let base = api_base.trim_end_matches('/');
    let operations = get_json(&reqwest::Client::new(), &key, &format!("{base}/operations")).await?;
    print_operation_list(&operations);
    Ok(())
}

/// Handle order show command
pub async fn handle_order_show(
    order_id: String,
    api_base: String,
    api_key: Option<String>,
) -> Result<()> {
    info!("Showing details for order: {}", order_id);
    let key = api_key
        .or_else(|| std::env::var("ACMEX_API_KEY").ok())
        .ok_or_else(|| AcmeError::invalid_input("provide --api-key or set ACMEX_API_KEY"))?;
    let base = api_base.trim_end_matches('/');
    let operation = get_json(
        &reqwest::Client::new(),
        &key,
        &format!("{base}/operations/{order_id}"),
    )
    .await?;
    print_operation_detail(&operation, &order_id);
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

fn print_operation_list(operations: &serde_json::Value) {
    let Some(items) = operations.as_array() else {
        println!("No operations found.");
        return;
    };
    if items.is_empty() {
        println!("No operations found.");
        return;
    }

    println!(
        "{:<28} | {:<8} | {:<12} | {:<18}",
        "Operation", "Kind", "Status", "Current step"
    );
    println!("{:-<28}-|-{:-<8}-|-{:-<12}-|-{:-<18}", "", "", "", "");
    for operation in items {
        println!(
            "{:<28} | {:<8} | {:<12} | {:<18}",
            operation["id"].as_str().unwrap_or("-"),
            operation["kind"].as_str().unwrap_or("-"),
            operation["status"].as_str().unwrap_or("-"),
            operation["current_step"].as_str().unwrap_or("-")
        );
    }
}

fn print_operation_detail(operation: &serde_json::Value, fallback_id: &str) {
    println!(
        "Operation {}",
        operation["id"].as_str().unwrap_or(fallback_id)
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
    if let Some(retry_at) = operation["retry_at"].as_str() {
        println!("  Retry at: {retry_at}");
    }
    if let Some(error_code) = operation["error_code"].as_str() {
        println!("  Error: {error_code}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_list_accepts_v1_projection() {
        let operations = serde_json::json!([
            {
                "id": "op_test",
                "kind": "issue",
                "status": "waiting",
                "current_step": "WaitOrder"
            }
        ]);
        print_operation_list(&operations);
    }

    #[test]
    fn operation_detail_accepts_missing_optional_fields() {
        let operation = serde_json::json!({
            "id": "op_test",
            "kind": "revoke",
            "status": "succeeded",
            "progress": 1.0
        });
        print_operation_detail(&operation, "op_fallback");
    }
}
