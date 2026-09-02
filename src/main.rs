//! The `acmex` binary entry point.
//!
//! The binary is the CLI defined in [`acmex::cli`] (`init`, `obtain`,
//! `renew`, `daemon`, `serve`, `info`, `account`, `order`, `cert`). This
//! file only wires process-level concerns before handing over:
//!
//! * optional OpenTelemetry tracing — enabled when
//!   `OTEL_EXPORTER_OTLP_ENDPOINT` is set; failures degrade to plain
//!   `tracing` output instead of aborting the command;
//! * non-zero exit codes on command failure (with the error printed once).
//!
//! The previous behavior (a hard-coded ACME protocol demo) moved out of the
//! binary — run `acmex info <cert>` or see the library quick start in the
//! crate docs for equivalent examples.

use acmex::cli;

/// Attaches an OTLP tracing layer when an endpoint is configured.
///
/// Returns `true` when OpenTelemetry was initialized. Any exporter failure
/// is downgraded to a warning: a missing collector must not break CLI
/// commands.
fn try_init_open_telemetry() -> bool {
    if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_err() {
        return false;
    }
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::prelude::*;

    let exporter = match opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
    {
        Ok(exporter) => exporter,
        Err(err) => {
            eprintln!("warning: OTLP exporter unavailable, continuing without traces: {err}");
            return false;
        }
    };
    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .build();
    let tracer = provider.tracer("acmex");
    opentelemetry::global::set_tracer_provider(provider);
    // The fmt layer is installed by `cli::init_logging`; adding the OTel
    // layer on top of the global default subscriber keeps both sinks live.
    let fmt_layer = tracing_subscriber::fmt::layer();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .with(tracing_opentelemetry::layer().with_tracer(tracer))
        .try_init();
    true
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // Optional observability first so command logs can also be exported.
    let otel = try_init_open_telemetry();
    if otel {
        eprintln!("OpenTelemetry tracing enabled");
    }

    match cli::run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
