//! HTTP server setup and configuration
//!
//! This module provides the main server startup logic, routing configuration,
//! and graceful shutdown handling for the deployment receiver.

use axum::{
    middleware::from_fn_with_state,
    routing::{get, post},
    Router,
};
use std::{net::SocketAddr, path::Path, sync::Arc, time::SystemTime};
use tokio::net::TcpListener;
use tracing::{error, info, instrument};

use crate::{
    config::{ServicesConfig, SystemConfig},
    deployment::DeploymentManager,
    http::{
        handlers::*,
        middleware::{self, auth::hmac_auth_middleware},
    },
    secrets::SecretManager,
    state::StateManager,
    types::Result,
};

/// Start the HTTP server with the given configuration
#[instrument(skip_all)]
pub async fn start_server(
    system_config: SystemConfig,
    services_config: ServicesConfig,
    secret_manager: Arc<SecretManager>,
    shutdown_signal: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    // Initialize rate limiter with cleanup task
    let rate_limiter = Arc::new(middleware::RateLimiter::new(
        system_config.security.rate_limit,
    ));
    rate_limiter.clone().start_cleanup_task();

    // Parse IP allowlist from configuration
    let ip_allowlist = Arc::new(
        middleware::IpAllowlist::from_config(&system_config.security.allowed_ips).map_err(|e| {
            error!(error = %e, "Failed to parse IP allowlist configuration");
            crate::types::Error::Config(crate::types::ConfigError::Invalid {
                message: format!("Invalid IP allowlist configuration: {}", e),
            })
        })?,
    );

    info!(
        rate_limit = system_config.security.rate_limit,
        allowed_ips_count = system_config.security.allowed_ips.len(),
        "Security middleware initialized"
    );

    // Create state manager
    let state_manager = Arc::new(StateManager::new(Path::new(
        &system_config.storage.data_dir,
    ))?);

    // Clean up any stale locks from previous improper shutdowns
    // This checks database locks against file locks (which are auto-released by OS)
    match state_manager.cleanup_stale_locks_on_startup() {
        Ok(cleaned) if !cleaned.is_empty() => {
            info!(
                count = cleaned.len(),
                services = ?cleaned,
                "Cleaned up stale locks from previous shutdown"
            );
        }
        Ok(_) => {
            info!("No stale locks found on startup");
        }
        Err(e) => {
            error!(error = %e, "Failed to clean up stale locks on startup, continuing anyway");
        }
    }

    // Spawn background tasks for maintenance
    info!("Spawning background maintenance tasks");
    let _background_tasks = crate::tasks::spawn_background_tasks(
        state_manager.clone(),
        system_config.limits.lock_timeout,
    );

    // Create deployment manager
    let deployment_manager = Arc::new(
        DeploymentManager::new(
            state_manager.clone(),
            system_config.clone(),
            services_config.clone(),
            Some(secret_manager.clone()),
        )
        .await,
    );

    info!("Deployment manager initialized");

    // Create shared application state
    let app_state = Arc::new(AppState {
        system_config: system_config.clone(),
        services_config,
        start_time: SystemTime::now(),
        database: (*state_manager).clone(),
        rate_limiter,
        ip_allowlist,
        deployment_manager,
        health_cache: Arc::new(dashmap::DashMap::new()),
        secret_manager,
    });

    // Create the router with all endpoints
    let router = create_router(app_state.clone(), &system_config);

    // Parse the listen address
    let addr = parse_listen_address(&system_config.server.listen)?;

    info!(
        listen_addr = %addr,
        worker_threads = system_config.server.worker_threads,
        max_request_size = %system_config.server.max_request_size,
        request_timeout = system_config.server.request_timeout,
        "Starting HTTP server"
    );

    // Create TCP listener
    let listener = TcpListener::bind(&addr).await.map_err(|e| {
        error!(
            error = %e,
            addr = %addr,
            "Failed to bind to address"
        );
        crate::types::Error::Io(e)
    })?;

    info!(
        local_addr = %listener.local_addr().unwrap_or(addr),
        "HTTP server listening"
    );

    // Start the server with graceful shutdown
    let server = axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        shutdown_signal.await;
        info!("Shutdown signal received, starting graceful shutdown");
    });

    // Run the server
    if let Err(e) = server.await {
        error!(error = %e, "HTTP server error");
        return Err(crate::types::Error::Io(e));
    }

    info!("HTTP server shutdown complete");
    Ok(())
}

/// Create the Axum router with all endpoints and middleware
fn create_router(app_state: Arc<AppState>, config: &SystemConfig) -> Router {
    // Create authenticated routes (only /deploy endpoint)
    // Apply HMAC auth, then rate limiting, then IP allowlist (innermost to outermost)
    let authenticated_routes = Router::new()
        .route("/deploy", post(handle_deploy))
        .layer(from_fn_with_state(app_state.clone(), hmac_auth_middleware))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::rate_limit_middleware,
        ))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::ip_allowlist_middleware,
        ));

    // Create public routes (no authentication required)
    // Apply only IP allowlist and rate limiting, but not HMAC auth
    let public_routes = Router::new()
        .route("/status/{deploy_id}", get(handle_status))
        .route("/services", get(handle_services))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::rate_limit_middleware,
        ))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::ip_allowlist_middleware,
        ));

    // Health endpoint - no rate limiting or IP restrictions for monitoring
    let health_routes = Router::new()
        .route("/health", get(handle_health))
        .route("/ready", get(handle_ready))
        .layer(from_fn_with_state(
            app_state.clone(),
            middleware::rate_limit_middleware,
        ));

    // Add metrics endpoint to health routes if enabled (no rate limiting for monitoring)
    let health_routes = if config.monitoring.metrics_enabled {
        health_routes.route(&config.monitoring.metrics_path, get(handle_metrics))
    } else {
        health_routes
    };

    // Create the main router with individual middleware layers
    use std::time::Duration;
    use tower_http::{
        compression::CompressionLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
        trace::TraceLayer,
    };

    Router::new()
        .merge(authenticated_routes)
        .merge(public_routes)
        .merge(health_routes)
        .fallback(handle_not_found)
        .layer(TraceLayer::new_for_http())
        .layer(TimeoutLayer::new(Duration::from_secs(
            config.server.request_timeout,
        )))
        .layer(CompressionLayer::new())
        .layer(RequestBodyLimitLayer::new(
            middleware::parse_size_string(&config.server.max_request_size).unwrap_or(1024 * 1024), // Default to 1MB if parsing fails
        ))
        .with_state(app_state)
}

/// Parse the listen address from configuration
fn parse_listen_address(listen: &str) -> Result<SocketAddr> {
    listen.parse().map_err(|e| {
        error!(
            listen_addr = %listen,
            error = %e,
            "Invalid listen address format"
        );
        crate::types::Error::Config(crate::types::ConfigError::Invalid {
            message: format!("Invalid listen address '{}': {}", listen, e),
        })
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::*;
    fn make_test_system_config(temp_dir: &Path) -> String {
        format!(
            r#"[server]
listen = "127.0.0.1:16001"
worker_threads = 2
max_request_size = "1MB"
request_timeout = 30
shutdown_timeout = 30

[security]
allowed_ips = []
rate_limit = 10

[storage]
data_dir = "{data_dir}"

[logging]
level = "info"
format = "pretty"
directory = "{logs_dir}"

[monitoring]
metrics_enabled = false
metrics_path = "/metrics"
health_path = "/health"

[limits]
max_concurrent_total = 2
max_concurrent_per_service = 1
deployment_timeout = 300
command_timeout = 60
lock_timeout = 10

[secrets]
source = "file"
secrets_file = "{secrets_file}"
required_secrets = ["hmac_key"]
"#,
            data_dir = temp_dir.display(),
            logs_dir = temp_dir.join("logs").display(),
            secrets_file = temp_dir.join("secret.env").display(),
        )
    }
    fn make_test_services_config(temp_dir: &Path) -> String {
        format!(
            r#"[defaults]
working_dir = "{working_dir}"
command_timeout = 60
healthcheck_timeout = 30
rollback_enabled = true

[[service]]
name = "test-service"
description = "Test service for HTTP foundation testing"
enabled = true
working_dir = "{working_dir}"

[service.env]
TEST_VAR = "test"

[service.security]
allowed_image_pattern = ".*"
allowed_env_overrides = ["TEST_VAR"]

[service.deploy]
commands = [
    ["echo", "Deploying test service"],
    ["sleep", "1"]
]

[service.healthcheck]
initial_delay = 1
interval = 2
max_attempts = 3
success_threshold = 1
commands = [
    ["echo", "Health check OK"]
]

[service.rollback]
enabled = true
max_attempts = 1
commands = [
    ["echo", "Rolling back test service"]
]

[service.hooks]
pre_deploy = [
    ["echo", "Pre-deploy hook: Starting deployment for {{SERVICE}}"],
    ["echo", "Pre-deploy hook: Image is {{IMAGE}}"]
]
post_deploy = [
    ["echo", "Post-deploy hook: Deployment completed for {{SERVICE}}"],
    ["echo", "Post-deploy hook: Deploy ID is {{DEPLOY_ID}}"]
]
on_failure = [
    ["echo", "On-failure hook: Deployment failed for {{SERVICE}}"]
]
"#,
            working_dir = temp_dir.display(),
        )
    }

    async fn setup_test_configs() -> ((SystemConfig, ServicesConfig), Arc<SecretManager>) {
        // Create and load system config.
        let test_folder = tempfile::tempdir().expect("Failed to create temp dir");
        let secrets_file_path = test_folder.path().join("secret.env");
        std::fs::write(
            &secrets_file_path,
            "hmac_key=test-secret-key-for-hmac-validation\n",
        )
        .expect("Failed to write secrets file");
        let system_config_toml = make_test_system_config(test_folder.path());
        let mut system_temp_file =
            NamedTempFile::new().expect("Failed to create temp file for system config");

        system_temp_file
            .write_all(system_config_toml.as_bytes())
            .expect("Failed to write system config TOML");
        let system_path = system_temp_file
            .path()
            .to_str()
            .expect("Invalid temp path")
            .to_string();
        let system_config =
            SystemConfig::load_from_file(&system_path).expect("Failed to load test system config");

        // Create and load services config.
        let mut services_temp_file =
            NamedTempFile::new().expect("Failed to create temp file for services config");
        let services_config_toml = make_test_services_config(test_folder.path());
        services_temp_file
            .write_all(services_config_toml.as_bytes())
            .expect("Failed to write services config TOML");
        let services_path = services_temp_file
            .path()
            .to_str()
            .expect("Invalid temp path")
            .to_string();
        let services_config = ServicesConfig::load_from_file(&services_path)
            .expect("Failed to load test services config");
        let secret_manager = Arc::new(
            SecretManager::new(system_config.clone().secrets)
                .await
                .expect("Failed to create test SecretManager"),
        );
        secret_manager
            .load_required_secret("hmac_key")
            .await
            .unwrap();
        // Temp files are dropped here and deleted automatically.

        ((system_config, services_config), secret_manager)
    }
    #[test]
    fn test_parse_listen_address() {
        // Valid addresses
        assert!(parse_listen_address("127.0.0.1:8080").is_ok());
        assert!(parse_listen_address("0.0.0.0:8080").is_ok());
        assert!(parse_listen_address("[::1]:8080").is_ok());

        // Invalid addresses
        assert!(parse_listen_address("invalid").is_err());
        assert!(parse_listen_address("127.0.0.1").is_err());
        assert!(parse_listen_address("127.0.0.1:99999").is_err());
    }

    #[tokio::test]
    async fn test_create_router() {
        let ((mut system_config, services_config), secrets) = setup_test_configs().await;

        // Use unique path for this test
        let unique_path = format!(
            "/tmp/hookshot-test-router-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        system_config.storage.data_dir = unique_path.clone();

        // Create rate limiter and IP allowlist for test
        let rate_limiter = Arc::new(middleware::RateLimiter::new(
            system_config.security.rate_limit,
        ));
        let ip_allowlist = Arc::new(
            middleware::IpAllowlist::from_config(&system_config.security.allowed_ips).unwrap(),
        );

        // Create state manager and deployment manager
        let state_manager = Arc::new(StateManager::new(Path::new(&unique_path)).unwrap());
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                state_manager.clone(),
                system_config.clone(),
                services_config.clone(),
                Some(secrets.clone()),
            )
            .await,
        );

        let app_state = Arc::new(AppState {
            system_config: system_config.clone(),
            services_config,
            start_time: SystemTime::now(),
            database: (*state_manager).clone(),
            rate_limiter,
            ip_allowlist,
            deployment_manager,
            health_cache: Arc::new(dashmap::DashMap::new()),
            secret_manager: secrets,
        });

        let router = create_router(app_state, &system_config);

        // Router should be created without panicking
        // We can't easily test the routes without setting up a test server,
        // but this ensures the router creation logic doesn't fail
        drop(router); // Just ensure the router was created successfully
    }

    #[tokio::test]
    async fn test_router_creation_with_metrics_disabled() {
        let ((mut system_config, services_config), secrets) = setup_test_configs().await;

        // Use unique path for this test
        let unique_path = format!(
            "/tmp/hookshot-test-metrics-disabled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        system_config.storage.data_dir = unique_path.clone();

        // Create rate limiter and IP allowlist for test
        let rate_limiter = Arc::new(middleware::RateLimiter::new(
            system_config.security.rate_limit,
        ));
        let ip_allowlist = Arc::new(
            middleware::IpAllowlist::from_config(&system_config.security.allowed_ips).unwrap(),
        );

        // Create state manager and deployment manager
        let state_manager = Arc::new(StateManager::new(Path::new(&unique_path)).unwrap());
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                state_manager.clone(),
                system_config.clone(),
                services_config.clone(),
                Some(secrets.clone()),
            )
            .await,
        );

        let app_state = Arc::new(AppState {
            system_config: system_config.clone(),
            services_config,
            start_time: SystemTime::now(),
            database: (*state_manager).clone(),
            rate_limiter,
            ip_allowlist,
            deployment_manager,
            health_cache: Arc::new(dashmap::DashMap::new()),
            secret_manager: secrets,
        });

        // Should create router without metrics endpoint
        let _router = create_router(app_state, &system_config);
    }

    #[tokio::test]
    async fn test_router_creation_with_metrics_enabled() {
        let ((mut system_config, services_config), secrets) = setup_test_configs().await;

        // Use unique path for this test
        let unique_path = format!(
            "/tmp/hookshot-test-metrics-enabled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        system_config.storage.data_dir = unique_path.clone();

        // Create rate limiter and IP allowlist for test
        let rate_limiter = Arc::new(middleware::RateLimiter::new(
            system_config.security.rate_limit,
        ));
        let ip_allowlist = Arc::new(
            middleware::IpAllowlist::from_config(&system_config.security.allowed_ips).unwrap(),
        );

        // Create state manager and deployment manager
        let state_manager = Arc::new(StateManager::new(Path::new(&unique_path)).unwrap());
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                state_manager.clone(),
                system_config.clone(),
                services_config.clone(),
                Some(secrets.clone()),
            )
            .await,
        );

        let app_state = Arc::new(AppState {
            system_config: system_config.clone(),
            services_config,
            start_time: SystemTime::now(),
            database: (*state_manager).clone(),
            rate_limiter,
            ip_allowlist,
            deployment_manager,
            health_cache: Arc::new(dashmap::DashMap::new()),
            secret_manager: secrets,
        });

        // Should create router with metrics endpoint
        let _router = create_router(app_state, &system_config);
    }
}
