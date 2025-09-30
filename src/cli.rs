use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tracing::{error, info, instrument};

use crate::config::{ServicesConfig, SystemConfig};
use crate::secrets::SecretManager;
use crate::types::Result;

#[derive(Parser)]
#[command(name = "hookshot")]
#[command(about = "A lightweight deployment webhook receiver")]
#[command(long_about = "
A single-binary HTTP service that accepts authenticated deployment requests
from CI systems and executes locally-configured OS command sequences.
")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// System configuration file path
    #[arg(short, long, default_value = "/etc/hookshot/config.toml")]
    pub config: PathBuf,

    /// Services configuration file path
    #[arg(short, long, default_value = "/etc/hookshot/services.toml")]
    pub services: PathBuf,

    /// Override log level
    #[arg(long, value_enum)]
    pub log_level: Option<LogLevel>,

    /// Enable verbose output (sets log level to debug)
    #[arg(short, long)]
    pub verbose: bool,

    /// Run in quiet mode (minimal output)
    #[arg(short, long, conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(ValueEnum, Clone, Debug)]
pub enum LogFormat {
    Json,
    Pretty,
}

#[derive(Subcommand, Clone)]
pub enum Commands {
    /// Run the webhook receiver server (default if no subcommand given)
    Run(RunArgs),
    /// Validate configuration files
    Validate,
    /// Show detailed version and build information
    Version,
    /// Export current state to backup archive
    Export(ExportArgs),
    /// Import state from backup archive
    Import(ImportArgs),
}

#[derive(Args, Clone)]
pub struct RunArgs {
    /// Override listen address (format: "host:port")
    #[arg(long)]
    pub port: Option<String>,

    /// Set bind address (e.g. "127.0.0.1")
    #[arg(long)]
    pub bind: Option<String>,

    /// Set log format
    #[arg(long)]
    pub log_format: Option<LogFormat>,
}

#[derive(Args, Clone)]
pub struct ExportArgs {
    /// Output file path for the backup archive
    pub output_file: PathBuf,
}

#[derive(Args, Clone)]
pub struct ImportArgs {
    /// Input file path of the backup archive to restore
    pub input_file: PathBuf,

    /// Preview what will be restored without making changes
    #[arg(long)]
    pub dry_run: bool,

    /// Force restore even if there are active deployments
    #[arg(long)]
    pub force: bool,
}

impl Cli {
    /// Get effective log level considering verbose/quiet flags
    pub fn effective_log_level(&self) -> LogLevel {
        if self.verbose {
            LogLevel::Debug
        } else if self.quiet {
            LogLevel::Error
        } else {
            self.log_level.clone().unwrap_or(LogLevel::Info)
        }
    }

    /// Convert LogLevel enum to string for logging module
    pub fn log_level_to_str(&self) -> &'static str {
        match self.effective_log_level() {
            LogLevel::Trace => crate::logging::level::TRACE,
            LogLevel::Debug => crate::logging::level::DEBUG,
            LogLevel::Info => crate::logging::level::INFO,
            LogLevel::Warn => crate::logging::level::WARN,
            LogLevel::Error => crate::logging::level::ERROR,
        }
    }

    /// Get log format override from CLI arguments
    pub fn log_format_override(&self) -> Option<&'static str> {
        match &self.command {
            Some(Commands::Run(args)) => args.log_format.as_ref().map(|fmt| match fmt {
                LogFormat::Json => crate::logging::format::JSON,
                LogFormat::Pretty => crate::logging::format::PRETTY,
            }),
            _ => None,
        }
    }
}

/// Run the webhook receiver server
#[instrument(skip(cli, _args, system_config))]
pub async fn run_server(
    cli: Cli,
    _args: RunArgs,
    system_config: Option<SystemConfig>,
) -> Result<()> {
    // Load and validate configuration if not already loaded
    let system_config = if let Some(config) = system_config {
        config
    } else {
        info!("Loading system configuration...");
        let config = SystemConfig::load_from_file(&cli.config)?;
        config.validate().await?;
        config
    };

    info!("Loading services configuration...");
    let services_config = ServicesConfig::load_from_file(&cli.services)?;
    services_config.validate().await?;

    info!(
        config_path = %cli.config.display(),
        services_path = %cli.services.display(),
        "Configuration loaded successfully"
    );

    // Initialize secret manager
    info!("Initializing secret manager...");
    let secret_manager = SecretManager::new(system_config.secrets.clone()).await?;

    // Validate all required secrets are available
    secret_manager.validate_required_secrets().await?;

    info!(
        loaders = ?secret_manager.get_loader_names(),
        "Secret manager initialized successfully"
    );

    info!(
        listen = %system_config.server.listen,
        worker_threads = system_config.server.worker_threads,
        services_count = services_config.service.len(),
        "Starting server"
    );

    // Set up graceful shutdown
    let shutdown_signal = setup_shutdown_signal();
    let secret_manager = Arc::new(secret_manager);

    // Start the HTTP server
    crate::http::start_server(
        system_config,
        services_config,
        secret_manager,
        shutdown_signal,
    )
    .await?;
    Ok(())
}

/// Validate configuration files
#[instrument(skip(cli, system_config))]
pub async fn validate_config(cli: Cli, system_config: Option<SystemConfig>) -> Result<()> {
    info!("Validating configuration files...");

    // Validate system configuration
    let config = if let Some(config) = system_config {
        config
    } else {
        SystemConfig::load_from_file(&cli.config)?
    };

    match config.validate().await {
        Ok(()) => info!(
            config_path = %cli.config.display(),
            "System configuration is valid"
        ),
        Err(e) => {
            error!(
                config_path = %cli.config.display(),
                error = %e,
                "System configuration validation failed"
            );
            return Err(e);
        }
    }

    // Validate services configuration
    match ServicesConfig::load_from_file(&cli.services) {
        Ok(config) => {
            match config.validate().await {
                Ok(()) => {
                    info!(
                        services_path = %cli.services.display(),
                        services_count = config.service.len(),
                        "Services configuration is valid"
                    );

                    // Show service summary with proper spans (demonstrating future service context)
                    for service in &config.service {
                        let _service_span = crate::logging::service_span(&service.name).entered();
                        info!(
                            service_name = service.name,
                            enabled = service.enabled,
                            "Service configuration loaded"
                        );
                    }
                }
                Err(e) => {
                    error!(
                        services_path = %cli.services.display(),
                        error = %e,
                        "Services configuration validation failed"
                    );
                    return Err(e);
                }
            }
        }
        Err(e) => {
            error!(
                services_path = %cli.services.display(),
                error = %e,
                "Failed to load services configuration"
            );
            return Err(e);
        }
    }

    // Validate secret configuration
    info!("Validating secret configuration...");
    match SecretManager::new(config.secrets.clone()).await {
        Ok(secret_manager) => match secret_manager.validate_required_secrets().await {
            Ok(()) => info!("Secret configuration is valid"),
            Err(e) => {
                error!(
                    error = %e,
                    "Secret validation failed"
                );
                return Err(e);
            }
        },
        Err(e) => {
            error!(
                error = %e,
                "Failed to initialize secret manager"
            );
            return Err(e);
        }
    }

    info!("All configuration files are valid");
    Ok(())
}

/// Show version and build information
#[instrument]
pub async fn show_version() -> Result<()> {
    println!("Hookshot {}", env!("CARGO_PKG_VERSION"));
    println!("Description: {}", env!("CARGO_PKG_DESCRIPTION"));
    println!("License: {}", env!("CARGO_PKG_LICENSE"));
    println!();

    println!("Build Information:");
    println!(
        "  Build Profile: {}",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!();

    println!("Runtime Information:");
    println!("  Platform: linux");
    println!("  Architecture: {}", std::env::consts::ARCH);

    Ok(())
}

/// Export current state to backup archive
#[instrument(skip(cli, args))]
pub async fn export_state(cli: Cli, args: ExportArgs) -> Result<()> {
    info!("Starting state export");

    let config_path = &cli.config;
    let services_path = &cli.services;

    // Load system config to get data directory
    let system_config = SystemConfig::load_from_file(config_path)?;
    let data_dir = PathBuf::from(&system_config.storage.data_dir);

    info!(
        output = %args.output_file.display(),
        config = %config_path.display(),
        services = %services_path.display(),
        data_dir = %data_dir.display(),
        "Exporting state"
    );

    // Create the backup
    crate::backup::create_backup(&args.output_file, config_path, services_path, &data_dir)?;

    info!(
        output = %args.output_file.display(),
        "State export completed successfully"
    );

    Ok(())
}

/// Import state from backup archive
#[instrument(skip(cli, args))]
pub async fn import_state(cli: Cli, args: ImportArgs) -> Result<()> {
    info!("Starting state import");

    let config_path = &cli.config;
    let services_path = &cli.services;

    // Load system config to get data directory
    let system_config = SystemConfig::load_from_file(config_path)?;
    let data_dir = PathBuf::from(&system_config.storage.data_dir);

    info!(
        input = %args.input_file.display(),
        config = %config_path.display(),
        services = %services_path.display(),
        data_dir = %data_dir.display(),
        dry_run = args.dry_run,
        force = args.force,
        "Importing state"
    );

    // Initialize state manager to check for active deployments
    let state_manager = crate::state::StateManager::new(&data_dir)?;

    // Create closure for checking active deployments
    let has_active_deployments = || state_manager.has_active_deployments();

    // Restore the backup
    crate::backup::restore_backup(
        &args.input_file,
        config_path,
        services_path,
        &data_dir,
        args.dry_run,
        args.force,
        has_active_deployments,
    )?;

    if args.dry_run {
        info!("Dry run completed - no changes were made");
    } else {
        info!(
            input = %args.input_file.display(),
            "State import completed successfully"
        );
        info!("Service restart recommended to apply changes");
    }

    Ok(())
}

/// Set up graceful shutdown signal handling for Linux
pub async fn setup_shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    tokio::select! {
        _ = ctrl_c => {
            info!("Received Ctrl+C");
        },
        _ = terminate => {
            info!("Received SIGTERM");
        },
    }
}
