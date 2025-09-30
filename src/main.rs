#![allow(dead_code)]
// Used to get build time information
use shadow_rs::shadow;
shadow!(build);

mod backup;
mod cli;
mod config;
mod deployment;
mod execution;
mod http;
mod logging;
mod metrics;
mod notifications;
mod secrets;
mod state;
mod tasks;
mod types;

use clap::Parser;
use tracing::info;

use crate::cli::{Cli, Commands, RunArgs};
use crate::config::SystemConfig;
use crate::types::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // For validate and version commands, try to load config to get better logging setup
    // For run command, always load config for proper logging
    let system_config = match &cli.command {
        Some(Commands::Version) => {
            // Version command doesn't need config
            None
        }
        Some(Commands::Export(_)) | Some(Commands::Import(_)) => {
            // Export/Import commands need config but handle their own error reporting
            SystemConfig::load_from_file(&cli.config).ok()
        }
        _ => {
            // Try to load system config for logging setup, but don't fail if it doesn't exist
            SystemConfig::load_from_file(&cli.config).ok()
        }
    };

    // Initialize logging with config if available
    let log_level_override = if cli.log_level.is_some() || cli.verbose || cli.quiet {
        Some(cli.log_level_to_str())
    } else {
        None
    };

    crate::logging::init(
        log_level_override,
        cli.log_format_override(),
        system_config.as_ref(),
    )?;

    // Initialize metrics registry
    crate::metrics::init_metrics();

    info!("Starting Hookshot");

    // Execute the appropriate command
    match cli.command.clone().unwrap_or(Commands::Run(RunArgs {
        port: None,
        bind: None,
        log_format: None,
    })) {
        Commands::Run(args) => cli::run_server(cli, args, system_config).await,
        Commands::Validate => cli::validate_config(cli, system_config).await,
        Commands::Version => cli::show_version().await,
        Commands::Export(args) => cli::export_state(cli, args).await,
        Commands::Import(args) => cli::import_state(cli, args).await,
    }
}
