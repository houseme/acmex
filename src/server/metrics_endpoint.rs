//! Prometheus scrape endpoint (roadmap T11).
//!
//! Serves the shared [`MetricsRegistry`] text exposition on a dedicated
//! listener (default `127.0.0.1:9090`, see `MetricsSettings`). The endpoint
//! is intentionally separate from the management API: scrapers should not
//! need API credentials, and the API server should not serve unauthenticated
//! routes.

use std::sync::Arc;

use axum::Router;
use axum::routing::get;

use crate::metrics::SharedMetrics;

/// The scrape router: `GET /metrics` in Prometheus text format.
pub fn metrics_router(metrics: SharedMetrics) -> Router {
    Router::new().route(
        "/metrics",
        get(move || {
            let metrics = metrics.clone();
            async move { metrics.gather_text() }
        }),
    )
}

/// Serves `/metrics` until the process exits.
pub async fn serve_metrics(
    addr: std::net::SocketAddr,
    metrics: SharedMetrics,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("metrics endpoint listening on http://{addr}/metrics");
    axum::serve(listener, metrics_router(metrics))
        .await
        .map_err(|e| std::io::Error::other(e.to_string()))
}

/// Spawns the metrics listener when `[metrics] enabled = true` in the
/// configuration. Bind failures are logged but do not take down the API
/// server: scraping is additive, not load-bearing.
pub fn spawn_from_config(
    config: &crate::config::Config,
    metrics: Arc<crate::metrics::MetricsRegistry>,
) {
    let Some(settings) = &config.metrics else {
        tracing::debug!("no [metrics] section; metrics endpoint disabled");
        return;
    };
    if !settings.enabled {
        return;
    }
    let Ok(addr) = settings.listen_addr.parse::<std::net::SocketAddr>() else {
        tracing::error!(
            listen_addr = %settings.listen_addr,
            "invalid [metrics].listen_addr; metrics endpoint disabled"
        );
        return;
    };
    tokio::spawn(async move {
        if let Err(err) = serve_metrics(addr, metrics).await {
            tracing::error!("metrics endpoint failed: {err}");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metrics_endpoint_exposes_registered_series() {
        let metrics = Arc::new(crate::metrics::MetricsRegistry::new());
        metrics.requests_total.inc();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task =
            tokio::spawn(async move { axum::serve(listener, metrics_router(metrics)).await.ok() });
        // Small yield so the server accepts connections.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let body = reqwest::get(format!("http://{addr}/metrics"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(body.contains("acmex_requests_total 1"), "{body}");
        task.abort();
        let _ = task.await;
    }
}
