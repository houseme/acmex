/// CLI commands implementation
use crate::cli::args::{AccountCommands, Cli, Commands};
use clap::Parser;
use tracing_subscriber::EnvFilter;

pub mod args;
pub mod commands;

/// Initialize CLI logging
pub fn init_logging(log_level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(log_level))
        .add_directive(log_level.parse().unwrap_or_default());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(true)
        .init();
}

/// Parse and execute CLI commands
pub async fn run() -> crate::error::Result<()> {
    let cli = Cli::parse();
    init_logging(&cli.log_level);

    match cli.command {
        Commands::Obtain(args) => {
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
            commands::handle_renew(args.domains, args.force, args.storage_path).await?;
        }
        Commands::Order(args) => match args.command {
            args::OrderCommands::List => {
                commands::handle_order_list().await?;
            }
            args::OrderCommands::Show { order_id } => {
                commands::handle_order_show(order_id).await?;
            }
        },
        Commands::Cert(args) => match args.command {
            args::CertCommands::List => {
                commands::handle_cert_list().await?;
            }
            args::CertCommands::Revoke { cert, reason, key } => {
                commands::handle_cert_revoke(cert, reason, key).await?;
            }
        },
        Commands::Daemon(args) => {
            if let Some(config_path) = args.config {
                tracing::info!("Loading config from: {}", config_path);
                // TODO: Load and parse TOML config
            }

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
            commands::handle_info(args.cert)?;
        }
        Commands::Account(args) => match args.command {
            AccountCommands::Register(a) => {
                commands::handle_register(a.email, a.prod, a.key_path).await?;
            }
            AccountCommands::Update(a) => {
                commands::handle_update(a.key_path, a.email, a.prod).await?;
            }
            AccountCommands::Deactivate(a) => {
                commands::handle_deactivate(a.key_path, a.prod).await?;
            }
            AccountCommands::RotateKey(a) => {
                commands::handle_rotate_key(a.key_path, a.new_key_path, a.prod).await?;
            }
        },
        Commands::Serve(args) => {
            commands::handle_serve(args.addr, args.config).await?;
        }
    }

    Ok(())
}
