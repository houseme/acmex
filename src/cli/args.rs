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

    /// Account management
    Account(AccountArgs),

    /// Start API server
    Serve(ServeArgs),
}

#[derive(Parser)]
pub struct ObtainArgs {
    /// Domain(s) to obtain certificate for
    #[arg(short, long, required = true)]
    pub domains: Vec<String>,

    /// Contact email for ACME account
    #[arg(short, long)]
    pub email: String,

    /// Challenge type (http-01, dns-01, tls-alpn-01)
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

#[derive(Parser)]
pub struct AccountArgs {
    #[command(subcommand)]
    pub command: AccountCommands,
}

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Register a new account
    Register(AccountRegisterArgs),
    /// Update account contacts
    Update(AccountUpdateArgs),
    /// Deactivate account
    Deactivate(AccountDeactivateArgs),
    /// Rotate account key
    RotateKey(AccountRotateKeyArgs),
}

#[derive(Parser)]
pub struct AccountRegisterArgs {
    /// Contact email
    #[arg(short, long, required = true)]
    pub email: String,

    /// Use production Let's Encrypt
    #[arg(long, default_value_t = false)]
    pub prod: bool,

    /// Output account key path
    #[arg(short, long, default_value = "account_key.pem")]
    pub key_path: String,
}

#[derive(Parser)]
pub struct AccountUpdateArgs {
    /// Account key path
    #[arg(short, long, required = true)]
    pub key_path: String,

    /// New contact email
    #[arg(short, long, required = true)]
    pub email: String,

    /// Use production Let's Encrypt
    #[arg(long, default_value_t = false)]
    pub prod: bool,
}

#[derive(Parser)]
pub struct AccountDeactivateArgs {
    /// Account key path
    #[arg(short, long, required = true)]
    pub key_path: String,

    /// Use production Let's Encrypt
    #[arg(long, default_value_t = false)]
    pub prod: bool,
}

#[derive(Parser)]
pub struct AccountRotateKeyArgs {
    /// Current account key path
    #[arg(short, long, required = true)]
    pub key_path: String,

    /// New account key path (output)
    #[arg(short, long, default_value = "account_key_new.pem")]
    pub new_key_path: String,

    /// Use production Let's Encrypt
    #[arg(long, default_value_t = false)]
    pub prod: bool,
}

#[derive(Parser)]
pub struct ServeArgs {
    /// Listen address
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    pub addr: String,

    /// Config file path
    #[arg(short, long)]
    pub config: Option<String>,
}
