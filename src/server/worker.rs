//! Production workflow worker (roadmap T03/T05/T09/T10 runtime wiring).
//!
//! This module is the assembly point where configuration becomes a running
//! issuance pipeline. It builds a [`WorkflowEngine`] whose executors are the
//! *real* implementations — ACME session (JWS, badNonce, Retry-After), DNS
//! propagation quorum, managed keys in a file secret store, strict
//! certificate verification and durable deployment orchestration — and
//! drives it on a fixed interval.
//!
//! # What runs where
//!
//! - `acmex serve` embeds this worker via [`spawn_from_config`]: every
//!   operation accepted by API v1 (`POST /certificate-intents/{id}/issue`,
//!   renewals created by the renewal controller, deploy operations) is
//!   advanced to completion inside the server process.
//! - `acmex obtain --wait` and `acmex daemon` build the *same* engine with
//!   [`build_engine_from_config`] and drive it in the CLI process, so a
//!   one-shot CLI invocation actually executes the whole flow.
//! - Library consumers can reuse [`register_executors`] to assemble an
//!   engine with their own components (custom CA backend, custom presenters,
//!   remote sinks) while keeping the durable step semantics.
//!
//! # Failure philosophy
//!
//! Every dependency that cannot be built from configuration (no DNS
//! provider credentials, HTTP-01 port unavailable, ...) is skipped with an
//! explicit `warn!`. The worker still starts; operations that then need the
//! missing piece fail with a clear classified error instead of being
//! silently simulated. Nothing pretends to succeed.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use acmex::config::Config;
//! use acmex::metrics::MetricsRegistry;
//! use acmex::server::worker::{self, WorkflowWorkerSettings};
//!
//! # async fn example() -> acmex::Result<()> {
//! let config: Config = "acmex.toml".parse().unwrap_or_default();
//! let (service, repositories) =
//!     acmex::application::ApplicationServiceBuilder::from_config(&config)
//!         .await?
//!         .build()?;
//! let metrics = Arc::new(MetricsRegistry::new());
//! let settings = WorkflowWorkerSettings::default();
//! let engine = worker::build_engine_from_config(&config, repositories, metrics, settings).await?;
//! // Advance every ready operation by one step (poll this on an interval,
//! // or use `spawn_from_config` for the self-driving loop):
//! let advanced = engine.run_once().await?;
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

use crate::ca_backend::{AcmeCaBackend, InstrumentedAcmeTransport, ReqwestAcmeTransport};
use crate::challenge::{
    AcknowledgeChallengesStep, ChallengePresenter, ChallengeStepDeps, CleanupChallengesStep,
    CreateOrderStep, EnsureAccountStep, LoadAuthorizationsStep, PrepareChallengesStep,
    PresenterRegistry, WaitAuthorizationsStep, WaitPropagationStep,
};
use crate::config::Config;
use crate::delivery::{DeploymentOrchestrator, FileCertificateSink};
use crate::key::SoftwareKeyProvider;
use crate::metrics::SharedMetrics;
use crate::protocol::Jwk;
use crate::repository::{FileSecretStore, RepositorySet};
use crate::workflow::{
    ActivateDeploymentStep, CompleteStep, CreateCsrStep, DownloadCertificateStep, EngineConfig,
    FinalizeOrderStep, IssuanceStepDeps, PersistVersionStep, PlanStep, ScheduleDeploymentsStep,
    StageDeploymentStep, SubmitRevocationStep, VerifyCertificateStep, VerifyDeploymentStep,
    WaitOrderStep, WorkflowEngine,
};

/// Tuning for the assembled worker.
#[derive(Debug, Clone)]
pub struct WorkflowWorkerSettings {
    /// How often the worker looks for ready operations.
    pub poll_interval: Duration,
    /// Maximum time from challenge prepare to propagation.
    pub propagation_timeout: Duration,
    /// Re-observation interval while waiting for propagation/CA state.
    pub challenge_poll_interval: Duration,
    /// Account contacts used for ACME registration.
    pub account_contacts: Vec<String>,
    /// Whether the terms of service are agreed for registration.
    pub terms_agreed: bool,
    /// External Account Binding used when the CA requires EAB.
    pub external_account_binding: Option<crate::ca_backend::ExternalAccountBindingRef>,
    /// Directory holding the account key and managed certificate keys.
    pub secret_store_dir: std::path::PathBuf,
    /// HTTP-01 listen address (None disables the local HTTP-01 presenter).
    pub http01_listen: Option<String>,
}

impl Default for WorkflowWorkerSettings {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            propagation_timeout: Duration::from_secs(600),
            challenge_poll_interval: Duration::from_secs(15),
            account_contacts: vec![],
            terms_agreed: true,
            external_account_binding: None,
            secret_store_dir: std::path::PathBuf::from(".acmex/secrets"),
            http01_listen: None,
        }
    }
}

/// The secret store directory derived from the configured file storage
/// path (`.acmex/certs` → `.acmex/secrets`).
pub fn default_secret_store_dir(config: &Config) -> std::path::PathBuf {
    let base = config
        .storage
        .file
        .as_ref()
        .map(|file| std::path::PathBuf::from(&file.path))
        .unwrap_or_else(|| std::path::PathBuf::from(".acmex/certs"));
    base.parent()
        .map(|parent| parent.join("secrets"))
        .unwrap_or_else(|| std::path::PathBuf::from(".acmex/secrets"))
}

/// Runtime components the executor set is built from.
pub struct WorkflowWorkerComponents {
    /// The CA backend every ACME step talks to.
    pub backend: Arc<dyn crate::ca_backend::CaBackend>,
    /// The account key's JWK (key authorizations).
    pub account_jwk: Jwk,
    /// Presenters by challenge type.
    pub presenters: PresenterRegistry,
    /// Managed key and CSR source.
    pub key_provider: Arc<dyn crate::key::KeyProvider>,
    /// Deployment orchestration.
    pub orchestrator: DeploymentOrchestrator,
}

/// Registers the full production executor set on an engine.
///
/// Public so tests and custom deployments can assemble the exact same
/// executor set as `spawn_from_config`.
pub fn register_executors(
    engine: &mut WorkflowEngine,
    settings: &WorkflowWorkerSettings,
    components: WorkflowWorkerComponents,
) {
    let WorkflowWorkerComponents {
        backend,
        account_jwk,
        presenters,
        key_provider,
        orchestrator,
    } = components;
    let challenge_deps = Arc::new(ChallengeStepDeps {
        backend: backend.clone(),
        presenters,
        account_jwk,
        allowed_challenges: Default::default(),
        propagation_timeout: settings.propagation_timeout,
        poll_interval: settings.challenge_poll_interval,
    });
    let issuance_deps = Arc::new(IssuanceStepDeps {
        backend,
        key_provider,
        orchestrator,
        poll_interval: settings.challenge_poll_interval,
    });

    // Challenge lifecycle (T05).
    engine.register(Arc::new(
        EnsureAccountStep::new(
            challenge_deps.clone(),
            settings.account_contacts.clone(),
            settings.terms_agreed,
        )
        .with_external_account_binding(settings.external_account_binding.clone()),
    ));
    engine.register(Arc::new(CreateOrderStep::resolving(challenge_deps.clone())));
    engine.register(Arc::new(LoadAuthorizationsStep::new(
        challenge_deps.clone(),
    )));
    engine.register(Arc::new(PrepareChallengesStep::new(challenge_deps.clone())));
    engine.register(Arc::new(WaitPropagationStep::new(challenge_deps.clone())));
    engine.register(Arc::new(AcknowledgeChallengesStep::new(
        challenge_deps.clone(),
    )));
    engine.register(Arc::new(WaitAuthorizationsStep::new(
        challenge_deps.clone(),
    )));
    engine.register(Arc::new(CleanupChallengesStep::new(challenge_deps)));

    // Issuance spine (T03/T07/T09/T10).
    engine.register(Arc::new(PlanStep::new()));
    engine.register(Arc::new(CreateCsrStep::new(issuance_deps.clone())));
    engine.register(Arc::new(FinalizeOrderStep::new(issuance_deps.clone())));
    engine.register(Arc::new(WaitOrderStep::new(issuance_deps.clone())));
    engine.register(Arc::new(DownloadCertificateStep::new(
        issuance_deps.clone(),
    )));
    engine.register(Arc::new(VerifyCertificateStep::new()));
    engine.register(Arc::new(PersistVersionStep::new(issuance_deps.clone())));
    engine.register(Arc::new(ScheduleDeploymentsStep::new(
        issuance_deps.clone(),
    )));

    // Deployment sub-operations and completion/activation gate (T10).
    engine.register(Arc::new(StageDeploymentStep::new(issuance_deps.clone())));
    engine.register(Arc::new(ActivateDeploymentStep::new(issuance_deps.clone())));
    engine.register(Arc::new(VerifyDeploymentStep::new(issuance_deps.clone())));
    engine.register(Arc::new(CompleteStep::new(issuance_deps.clone())));

    // Revocation carries its own spine step.
    engine.register(Arc::new(SubmitRevocationStep::new(issuance_deps)));
}

/// Loads the persistent ACME account key (or creates it on first run).
async fn load_or_create_account_key(
    store: &FileSecretStore,
    ca_label: &str,
) -> crate::error::Result<crate::account::KeyPair> {
    let key_id = format!("account_key_{ca_label}");
    if let Some(pem) = store.get(&key_id).await? {
        return crate::account::KeyPair::from_pem(&String::from_utf8_lossy(&pem))
            .map_err(|err| crate::error::AcmeError::crypto(format!("stored account key: {err}")));
    }
    let key_pair = crate::account::KeyPair::generate()
        .map_err(|err| crate::error::AcmeError::crypto(format!("generate account key: {err}")))?;
    store
        .put(&key_id, key_pair.serialize_pem().as_bytes())
        .await?;
    Ok(key_pair)
}

/// Builds the DNS-01 presenter from `[challenge.dns01]` providers, when any
/// are configured. Returns `None` (with a warning) otherwise.
async fn build_dns_presenter(config: &Config) -> Option<Arc<dyn ChallengePresenter>> {
    let dns01 = config.challenge.dns01.as_ref()?;
    let mut builder = crate::dns::router::ProviderRouterBuilder::new(Box::new(
        crate::dns::spec::EnvFileSecretResolver,
    ));
    let mut any = false;
    for provider in &dns01.providers {
        // Reuse one SecretRef for the primary credential and let `extra`
        // carry additional secret references (factory convention).
        let extra: std::collections::HashMap<String, String> = provider
            .extra
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        builder = builder.provider(crate::dns::spec::DnsProviderSpec {
            id: provider.name.clone(),
            provider_type: provider.name.clone(),
            credential: provider.api_token.clone(),
            zones: Vec::new(),
            zone_suffixes: Vec::new(),
            endpoint: None,
            timeout_secs: 30,
            extra,
        });
        any = true;
    }
    if !any {
        return None;
    }
    let router = match builder.build().await {
        Ok(router) => router,
        Err(err) => {
            tracing::warn!(error = %err, "DNS provider assembly failed; DNS-01 challenges will not be available");
            return None;
        }
    };
    let zone_resolver = match crate::dns::zone::HickoryZoneResolver::from_system() {
        Ok(resolver) => Arc::new(resolver),
        Err(err) => {
            tracing::warn!(error = %err, "DNS resolver unavailable; DNS-01 challenges will not be available");
            return None;
        }
    };
    // Propagation policy comes from `[challenge.dns01.propagation]` when
    // present; otherwise the built-in defaults apply.
    let policy = match &dns01.propagation {
        Some(settings) => settings.to_policy(),
        None => crate::dns::propagation::PropagationPolicyV2::default(),
    };
    let observer = match crate::dns::propagation::HickoryPropagationObserver::new(
        zone_resolver.clone(),
        policy,
    ) {
        Ok(observer) => observer,
        Err(err) => {
            tracing::warn!(error = %err, "propagation observer unavailable; DNS-01 challenges will not be available");
            return None;
        }
    };
    Some(Arc::new(crate::dns::presenter::Dns01Presenter::new(
        Arc::new(router),
        zone_resolver,
        Arc::new(observer),
    )))
}

/// Builds the local HTTP-01 presenter when an address is configured. Bind
/// failures are warnings: HTTP-01 intents then fail with an explicit
/// "no presenter" error instead of binding silently.
async fn build_http_presenter(listen: Option<&str>) -> Option<Arc<dyn ChallengePresenter>> {
    let listen = listen?;
    match listen.parse::<std::net::SocketAddr>() {
        Ok(addr) => {
            match crate::challenge::http01_presenter::Http01Presenter::with_local_listener(addr)
                .await
            {
                Ok(presenter) => Some(Arc::new(presenter)),
                Err(err) => {
                    tracing::warn!(error = %err, listen, "HTTP-01 local listener unavailable");
                    None
                }
            }
        }
        Err(err) => {
            tracing::warn!(listen, error = %err, "invalid http01.listen_addr");
            None
        }
    }
}

/// Builds the key-free RFC 9773 ARI provider used by renewal scanning.
///
/// ARI lookups are unauthenticated GETs, so no account key is needed —
/// only the directory URL and a metrics-instrumented transport. Shared by
/// the embedded server scheduler, the CLI daemon and library consumers so
/// every deployment gets identical ARI semantics (directory discovery
/// cached, 404 → no suggestion, errors fall back to policy windows).
pub fn build_ari_provider(
    config: &Config,
    metrics: SharedMetrics,
) -> Arc<dyn crate::renewal::RenewalInfoProvider> {
    let ca_label = super::api::sanitize_ca_label(&config.acme.ca);
    let transport =
        InstrumentedAcmeTransport::wrap(ca_label, Arc::new(ReqwestAcmeTransport::new()), metrics);
    Arc::new(crate::ca_backend::DirectoryAriProvider::new(
        config.acme.directory.clone(),
        transport,
    ))
}

/// Assembles a fully equipped [`WorkflowEngine`] from configuration.
///
/// This is the shared assembly for the embedded server worker, the CLI
/// (`obtain --wait`, `daemon`) and library consumers. It:
///
/// 1. loads or creates the persistent ACME account key in the secret store
///    (`.acmex/secrets` by default — restarts reuse the same account);
/// 2. wraps the HTTP transport with request/duration/badNonce metrics;
/// 3. builds the presenters that are actually configured (DNS-01 from
///    `[challenge.dns01]`, HTTP-01 from `[challenge.http01].listen_addr`);
/// 4. registers the durable File sink for `[delivery] file targets;
/// 5. registers every production step executor via [`register_executors`].
///
/// The returned engine advances operations when `run_once`/`run_step` is
/// called; pair it with your own driving loop or use
/// [`spawn_from_config`].
pub async fn build_engine_from_config(
    config: &Config,
    repositories: RepositorySet,
    metrics: SharedMetrics,
    settings: WorkflowWorkerSettings,
) -> crate::error::Result<WorkflowEngine> {
    // `[challenge.dns01]` owns the DNS propagation deadline when present;
    // otherwise the caller-provided worker settings apply unchanged.
    let mut settings = settings;
    if let Some(dns01) = config.challenge.dns01.as_ref() {
        settings.propagation_timeout = Duration::from_secs(dns01.propagation_timeout_secs);
    }
    settings.external_account_binding = config.external_account_binding_ref()?;

    let ca_label = super::api::sanitize_ca_label(&config.acme.ca);
    let secret_store = FileSecretStore::new(settings.secret_store_dir.clone());
    let key_pair = Arc::new(load_or_create_account_key(&secret_store, &ca_label).await?);
    let account_jwk = Jwk::new_ed25519(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key_pair.public_key_bytes()),
    );

    let transport = InstrumentedAcmeTransport::wrap(
        ca_label.clone(),
        Arc::new(ReqwestAcmeTransport::new()),
        metrics.clone(),
    );
    let backend: Arc<dyn crate::ca_backend::CaBackend> = Arc::new(AcmeCaBackend::new(
        ca_label,
        config.acme.directory.clone(),
        transport,
        key_pair,
        repositories.clone(),
    ));

    let key_provider: Arc<dyn crate::key::KeyProvider> = Arc::new(SoftwareKeyProvider::new(
        FileSecretStore::new(settings.secret_store_dir.clone()),
    ));

    let mut presenters = PresenterRegistry::new();
    if let Some(dns) = build_dns_presenter(config).await {
        presenters.register(dns);
    } else {
        tracing::warn!("no DNS providers configured; DNS-01 challenges will fail explicitly");
    }
    match build_http_presenter(settings.http01_listen.as_deref()).await {
        Some(http) => presenters.register(http),
        None => tracing::warn!(
            "no HTTP-01 listener configured; HTTP-01 challenges will fail explicitly"
        ),
    }
    // TLS-ALPN-01 has no local multi-route listener yet (KNOWN_LIMITATIONS);
    // intents pinned to tls-alpn-01 fail explicitly at prepare time.

    let mut orchestrator =
        DeploymentOrchestrator::new(repositories.clone()).with_metrics(metrics.clone());
    orchestrator = orchestrator.register_sink(
        crate::domain::DeliveryTargetKind::File,
        Arc::new(FileCertificateSink::new()),
    );

    let mut engine =
        WorkflowEngine::new("server-worker", repositories.clone()).with_config(EngineConfig {
            batch_size: 16,
            ..Default::default()
        });
    engine = engine.with_metrics(metrics);
    register_executors(
        &mut engine,
        &settings,
        WorkflowWorkerComponents {
            backend,
            account_jwk,
            presenters,
            key_provider,
            orchestrator,
        },
    );

    Ok(engine)
}

/// Builds the engine (see [`build_engine_from_config`]) and spawns its
/// self-driving loop: every `poll_interval` the worker advances up to
/// `batch_size` ready operations by one durable step each.
///
/// The task runs until the process exits; pass failures are logged, never
/// fatal — the next tick retries.
pub async fn spawn_from_config(
    config: &Config,
    repositories: RepositorySet,
    metrics: SharedMetrics,
    settings: WorkflowWorkerSettings,
) -> crate::error::Result<tokio::task::JoinHandle<()>> {
    let poll_interval = settings.poll_interval;
    let engine = std::sync::Arc::new(
        build_engine_from_config(config, repositories, metrics, settings).await?,
    );
    Ok(tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        interval.tick().await; // first tick completes immediately
        loop {
            interval.tick().await;
            match engine.run_once().await {
                Ok(0) => {}
                Ok(advanced) => {
                    tracing::debug!(advanced, "workflow worker advanced operations");
                }
                Err(err) => {
                    tracing::error!(error = %err, "workflow worker pass failed");
                }
            }
        }
    }))
}
