//! Logging module for Hookshot deployment receiver
//!
//! This module provides structured logging functionality with support for:
//! - JSON and pretty format output
//! - Configurable log levels via environment or configuration
//! - Deployment and service context spans for structured logging
//! - CLI argument integration for logging preferences
//!
//! # Usage
//!
//! Initialize logging early in your application:
//! ```rust,no_run
//! use hookshot::logging;
//! use hookshot::config::SystemConfig;
//!
//! // Initialize with CLI args and optional config
//! logging::init(&cli_args, system_config.as_ref())?;
//! ```
//!
//! Use context helpers for structured logging:
//! ```rust,no_run
//! use hookshot::logging;
//!
//! // Create deployment context
//! let _span = logging::deployment_span("deploy-001").entered();
//!
//! // Create service context
//! let _span = logging::service_span("web-frontend").entered();
//! ```

use tracing::{info_span, Span};
use tracing_subscriber::{fmt::time::ChronoLocal, EnvFilter};

use crate::config::SystemConfig;
use crate::types::Result;

/// Logging context helpers for structured logging
/// These provide consistent span creation for deployment and service operations
/// Create a deployment context span
/// This will be used when deployment tracking is implemented
pub fn deployment_span(deploy_id: &str) -> Span {
    info_span!("deployment", deploy_id = deploy_id)
}

/// Create a service context span
/// This will be used when service operations are implemented
pub fn service_span(service_name: &str) -> Span {
    info_span!("service", service_name = service_name)
}

/// Create a combined deployment and service context span
pub fn deployment_service_span(deploy_id: &str, service_name: &str) -> Span {
    info_span!(
        "deployment_service",
        deploy_id = deploy_id,
        service_name = service_name
    )
}

/// Add deployment ID to current span context
pub fn add_deployment_context(deploy_id: &str) {
    tracing::Span::current().record("deploy_id", deploy_id);
}

/// Add service name to current span context
pub fn add_service_context(service_name: &str) {
    tracing::Span::current().record("service_name", service_name);
}

/// Log level enum values as strings for configuration
pub mod level {
    pub const TRACE: &str = "trace";
    pub const DEBUG: &str = "debug";
    pub const INFO: &str = "info";
    pub const WARN: &str = "warn";
    pub const ERROR: &str = "error";
}

/// Log format enum values as strings for configuration
pub mod format {
    pub const JSON: &str = "json";
    pub const PRETTY: &str = "pretty";
}

/// Initialize logging with configuration
///
/// This function sets up the global tracing subscriber with the appropriate
/// format and log level based on CLI arguments and optional system configuration.
///
/// # Arguments
///
/// * `log_level_override` - Optional log level from CLI arguments
/// * `log_format_override` - Optional log format from CLI arguments
/// * `system_config` - Optional system configuration for defaults
///
/// # Precedence
///
/// 1. CLI arguments (highest priority)
/// 2. System configuration file
/// 3. Default values (lowest priority)
pub fn init(
    log_level_override: Option<&str>,
    log_format_override: Option<&str>,
    system_config: Option<&SystemConfig>,
) -> Result<()> {
    // Determine effective log level (CLI overrides config)
    let log_level = if let Some(level) = log_level_override {
        level
    } else if let Some(config) = system_config {
        &config.logging.level
    } else {
        level::INFO
    };

    // Determine effective format (CLI overrides config)
    let log_format = if let Some(fmt) = log_format_override {
        fmt
    } else if let Some(config) = system_config {
        &config.logging.format
    } else {
        format::PRETTY
    };

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    // Create a custom time formatter for better readability
    let timer = ChronoLocal::new("%Y-%m-%d %H:%M:%S%.3f".to_string());

    match log_format {
        format::JSON => {
            tracing_subscriber::fmt()
                .json()
                .with_timer(timer)
                .with_env_filter(env_filter)
                .with_target(false)
                .with_current_span(true)
                .with_span_list(false)
                .init();
        }
        format::PRETTY => {
            tracing_subscriber::fmt()
                .pretty()
                .with_timer(timer)
                .with_env_filter(env_filter)
                .with_target(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
        _ => {
            // Default to standard format for unknown formats
            tracing_subscriber::fmt()
                .with_timer(timer)
                .with_env_filter(env_filter)
                .with_target(false)
                .with_file(false)
                .with_line_number(false)
                .init();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_span_creation() {
        let span = deployment_span("test-deploy-001");
        // Test that span is created with correct metadata when subscriber is available
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "deployment");
        }
        // Test that we can enter the span without panic
        let _guard = span.enter();
    }

    #[test]
    fn test_service_span_creation() {
        let span = service_span("test-service");
        // Test that span is created with correct metadata when subscriber is available
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "service");
        }
        // Test that we can enter the span without panic
        let _guard = span.enter();
    }

    #[test]
    fn test_deployment_service_span_creation() {
        let span = deployment_service_span("deploy-001", "web-service");
        // Test that span is created with correct metadata when subscriber is available
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "deployment_service");
        }
        // Test that we can enter the span without panic
        let _guard = span.enter();
    }

    #[test]
    fn test_level_constants() {
        assert_eq!(level::TRACE, "trace");
        assert_eq!(level::DEBUG, "debug");
        assert_eq!(level::INFO, "info");
        assert_eq!(level::WARN, "warn");
        assert_eq!(level::ERROR, "error");
    }

    #[test]
    fn test_format_constants() {
        assert_eq!(format::JSON, "json");
        assert_eq!(format::PRETTY, "pretty");
    }
}
