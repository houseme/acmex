//! Daemon mode — a self-contained renewal service in one process.
//!
//! The daemon runs the same production pipeline as `acmex serve`, minus the
//! HTTP API:
//!
//! 1. a **workflow worker** (`server::worker`) executes every queued
//!    operation (renewals, deployments, cleanups) through the real CA
//!    backend, presenters and sinks;
//! 2. a **renewal controller scan** runs every `check_interval` seconds:
//!    each lineage is evaluated (ARI window first, lifetime-fraction
//!    fallback second) and due renewals become durable operations the
//!    worker then executes.
//!
//! Both loops stop on SIGINT/SIGTERM. Legacy arguments (`--domains`,
//! `--renew-before-days`) are accepted for compatibility but superseded by
//! the repository-backed scan, which covers every lineage — the daemon
//! prints a notice when they are used.

use std::sync::Arc;
use std::time::Duration;

use tokio::signal;
use tracing::{error, info, warn};

use crate::application::ApplicationServiceBuilder;
use crate::config::Config;
use crate::metrics::MetricsRegistry;
use crate::renewal::{ControllerRenewalScheduler, RenewalController, RenewalControllerConfig};
use crate::scheduler::RenewalScheduler;
use crate::server::worker::{self, WorkflowWorkerSettings};

/// Loads the daemon configuration: an explicit `--config` file, or the
/// defaults (staging-safe) when none is given.
fn load_config(path: Option<&str>) -> crate::error::Result<Config> {
    match path {
        Some(path) => {
            info!(config = path, "loading daemon configuration");
            Config::from_file(std::path::Path::new(path))
        }
        None => Ok(Config::default()),
    }
}

/// Run daemon for automatic certificate renewal.
#[allow(clippy::too_many_arguments)]
pub async fn handle_daemon(
    domains: Vec<String>,
    storage_path: String,
    check_interval_secs: u64,
    renew_before_days: u64,
    notify_email: Option<String>,
    config_path: Option<String>,
) -> crate::error::Result<()> {
    if !domains.is_empty() {
        println!(
            "ℹ️  --domains is superseded by repository-backed scanning (all lineages are evaluated)"
        );
    }
    if renew_before_days != 30 {
        println!("ℹ️  --renew-before-days is superseded by ARI/lifetime-fallback policy");
    }
    let _ = storage_path;
    if let Some(email) = &notify_email {
        println!(
            "ℹ️  notifications for {email} follow the configured webhooks ([notifications.webhook])"
        );
    }

    let config = load_config(config_path.as_deref())?;
    let check_interval = Duration::from_secs(check_interval_secs.max(1));

    println!("🚀 AcmeX renewal daemon");
    println!("   CA: {} ({})", config.acme.ca, config.acme.ca_environment);
    println!("   Scan interval: {check_interval_secs}s");
    println!("   Ctrl+C to stop");

    // Shared state: repositories + application service + metrics.
    let (service, repositories) = ApplicationServiceBuilder::from_config(&config)
        .await?
        .build()?;
    let metrics: Arc<MetricsRegistry> = Arc::new(MetricsRegistry::new());
    crate::server::metrics_endpoint::spawn_from_config(&config, metrics.clone());

    // 1. Workflow worker: executes operations (renewals, deployments).
    let worker_settings = WorkflowWorkerSettings {
        http01_listen: config
            .challenge
            .http01
            .as_ref()
            .map(|http| http.listen_addr.clone()),
        ..Default::default()
    };
    let worker_handle = worker::spawn_from_config(
        &config,
        repositories.clone(),
        metrics.clone(),
        worker_settings,
    )
    .await?;
    println!("✓ workflow worker running (real CA backend, presenters, sinks)");

    // 2. Renewal scan loop: ARI-first decisions create Renew operations.
    let scheduler: Arc<dyn RenewalScheduler> = {
        let ari = worker::build_ari_provider(&config, metrics.clone());
        let controller = RenewalController::new(
            repositories.clone(),
            service.clone(),
            RenewalControllerConfig::default(),
        )
        .with_ari_provider(ari)
        .with_metrics(metrics.clone());
        Arc::new(ControllerRenewalScheduler::new(controller))
    };
    let scan_handle = tokio::spawn({
        let scheduler = scheduler.clone();
        async move {
            let mut interval = tokio::time::interval(check_interval);
            interval.tick().await; // first tick completes immediately
            loop {
                interval.tick().await;
                if let Err(err) = scheduler.run_once().await {
                    error!(error = %err, "renewal scan failed");
                }
            }
        }
    });
    println!("✓ renewal controller scanning every {check_interval_secs}s");

    // One scan immediately so a freshly started daemon reports due renewals
    // without waiting a full interval.
    if let Err(err) = scheduler.run_once().await {
        warn!(error = %err, "initial renewal scan failed");
    }

    // 3. Wait for shutdown.
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
    let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => println!("\n📛 SIGTERM received, shutting down..."),
        _ = sigint.recv() => println!("\n📛 SIGINT received, shutting down..."),
    }

    worker_handle.abort();
    scan_handle.abort();
    let _ = worker_handle.await;
    let _ = scan_handle.await;
    println!("✅ Daemon stopped");
    Ok(())
}
