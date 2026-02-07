/// CLI argument parsing and configuration
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "acmex")]
#[command(about = "ACME v2 client for obtaining TLS certificates", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Log level (trace, debug, info, warn, error)
    #[arg(global = true, short, long, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Obtain a new certificate
    Obtain(ObtainArgs),

    /// Renew an existing certificate
    Renew(RenewArgs),

    /// Start automatic renewal daemon
    Daemon(DaemonArgs),

    /// Show certificate info
    Info(InfoArgs),
}

#[derive(Parser)]
pub struct ObtainArgs {
    /// Domain(s) to obtain certificate for
    #[arg(short, long, required = true)]
    pub domains: Vec<String>,

    /// Contact email for ACME account
    #[arg(short, long)]
    pub email: String,

    /// Challenge type (http-01, dns-01)
    #[arg(short, long, default_value = "http-01")]
    pub challenge: String,

    /// Output certificate path
    #[arg(short, long, default_value = "certificate.pem")]
    pub cert_path: String,

    /// Output private key path
    #[arg(short, long, default_value = "private_key.pem")]
    pub key_path: String,

    /// Use production Let's Encrypt
    #[arg(long, default_value_t = false)]
    pub prod: bool,

    /// DNS provider (cloudflare, digitalocean, linode, route53)
    #[arg(long)]
    pub dns_provider: Option<String>,
}

#[derive(Parser)]
pub struct RenewArgs {
    /// Domain(s) to renew
    #[arg(short, long, required = true)]
    pub domains: Vec<String>,

    /// Certificate storage directory
    #[arg(short, long, default_value = ".acmex")]
    pub storage_path: String,

    /// Force renewal even if not due
    #[arg(long, default_value_t = false)]
    pub force: bool,
}

#[derive(Parser)]
pub struct DaemonArgs {
    /// Domain(s) to manage
    #[arg(short, long, required = true)]
    pub domains: Vec<String>,

    /// Config file path (TOML format)
    #[arg(short, long)]
    pub config: Option<String>,

    /// Storage directory
    #[arg(short, long, default_value = ".acmex")]
    pub storage_path: String,

    /// Check interval (seconds)
    #[arg(long, default_value = "3600")]
    pub check_interval: u64,

    /// Renew before expiry (days)
    #[arg(long, default_value = "30")]
    pub renew_before_days: u64,

    /// Notification email
    #[arg(long)]
    pub notify_email: Option<String>,
}

#[derive(Parser)]
pub struct InfoArgs {
    /// Certificate file path
    #[arg(short, long, required = true)]
    pub cert: String,
}
