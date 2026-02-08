/// CLI commands and entry point implementation.
/// This module handles command-line argument parsing and dispatches execution
/// to the appropriate command handlers.
use crate::cli::args::{AccountCommands, Cli, Commands};
use clap::Parser;
use tracing_subscriber::EnvFilter;

pub mod args;
pub mod commands;

/// Initializes the logging system for the CLI.
/// Supports dynamic log level configuration via the `log_level` parameter.
pub fn init_logging(log_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level))
        .add_directive(log_level.parse().unwrap_or_default());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .init();

    tracing::debug!("Logging initialized with level: {}", log_level);
}

/// Parses command-line arguments and executes the requested command.
/// This is the main entry point for the AcmeX CLI application.
pub async fn run() -> crate::error::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    tracing::info!("AcmeX CLI starting command: {:?}", cli.command);

    match cli.command {
        Commands::Obtain(args) => {
            tracing::info!("Handling 'obtain' command for domains: {:?}", args.domains);
            commands::handle_obtain(
                args.domains,
                args.email,
                args.challenge,
                args.cert_path,
                args.key_path,
                args.prod,
                args.dns_provider,
            )
            .await?;
        }
        Commands::Renew(args) => {
            tracing::info!("Handling 'renew' command (force: {})", args.force);
            commands::handle_renew(args.domains, args.force, args.storage_path).await?;
        }
        Commands::Order(args) => match args.command {
            args::OrderCommands::List => {
                tracing::info!("Listing ACME orders");
                commands::handle_order_list().await?;
            }
            args::OrderCommands::Show { order_id } => {
                tracing::info!("Showing details for order: {}", order_id);
                commands::handle_order_show(order_id).await?;
            }
        },
        Commands::Cert(args) => match args.command {
            args::CertCommands::List => {
                tracing::info!("Listing managed certificates");
                commands::handle_cert_list().await?;
            }
            args::CertCommands::Revoke { cert, reason, key } => {
                tracing::info!("Revoking certificate: {}", cert);
                commands::handle_cert_revoke(cert, reason, key).await?;
            }
        },
        Commands::Daemon(args) => {
            if let Some(config_path) = args.config {
                tracing::info!("Loading daemon configuration from: {}", config_path);
            }

            tracing::info!("Starting AcmeX renewal daemon");
            commands::handle_daemon(
                args.domains,
                args.storage_path,
                args.check_interval,
                args.renew_before_days,
                args.notify_email,
            )
            .await?;
        }
        Commands::Info(args) => {
            tracing::info!("Displaying info for certificate: {}", args.cert);
            commands::handle_info(args.cert)?;
        }
        Commands::Account(args) => match args.command {
            AccountCommands::Register(a) => {
                tracing::info!("Registering new ACME account with email: {:?}", a.email);
                commands::handle_register(a.email, a.prod, a.key_path).await?;
            }
            AccountCommands::Update(a) => {
                tracing::info!("Updating ACME account contacts");
                commands::handle_update(a.key_path, a.email, a.prod).await?;
            }
            AccountCommands::Deactivate(a) => {
                tracing::info!("Deactivating ACME account");
                commands::handle_deactivate(a.key_path, a.prod).await?;
            }
            AccountCommands::RotateKey(a) => {
                tracing::info!("Rotating ACME account key pair");
                commands::handle_rotate_key(a.key_path, a.new_key_path, a.prod).await?;
            }
        },
        Commands::Serve(args) => {
            tracing::info!("Starting AcmeX REST API server on {}", args.addr);
            commands::handle_serve(args.addr, args.config).await?;
        }
    }

    tracing::info!("Command execution completed successfully");
    Ok(())
}
