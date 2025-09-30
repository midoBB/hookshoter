//! HTTP endpoint handlers for the deployment API
//!
//! This module implements the actual HTTP endpoint handlers that process
//! incoming requests and return appropriate responses.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use dashmap::DashMap;
use std::{collections::BTreeMap, sync::Arc, time::SystemTime};
use tracing::{info, warn};

use std::ffi::OsString;
use std::process::Command;

use crate::{
    build,
    config::{ServicesConfig, SystemConfig},
    deployment::DeploymentManager,
    http::{
        middleware::{IpAllowlist, RateLimiter},
        responses::*,
    },
    secrets::SecretManager,
    state::StateManager,
    types::{DeploymentStatus, HealthStatus},
};
use anyhow::{anyhow, Result};

/// Application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    pub system_config: SystemConfig,
    pub services_config: ServicesConfig,
    pub start_time: SystemTime,
    pub database: StateManager,
    pub rate_limiter: Arc<RateLimiter>,
    pub ip_allowlist: Arc<IpAllowlist>,
    pub deployment_manager: Arc<DeploymentManager>,
    pub health_cache: Arc<DashMap<String, (HealthResponse, SystemTime)>>,
    pub secret_manager: Arc<SecretManager>,
}

/// POST /deploy - Accept deployment requests
pub async fn handle_deploy(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeployRequest>,
) -> impl IntoResponse {
    info!(
        deploy_id = ?request.deploy_id,
        service = %request.service,
        image = %request.image,
        dry_run = request.dry_run,
        "Received deployment request"
    );

    // Basic request validation
    if request.service.is_empty() {
        warn!("Empty service name in deploy request");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Service name cannot be empty".to_string(),
                code: "VALIDATION_ERROR".to_string(),
                details: None,
                timestamp: Utc::now().to_rfc3339(),
            }),
        )
            .into_response();
    }

    if request.image.is_empty() {
        warn!("Empty image in deploy request");
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Image cannot be empty".to_string(),
                code: "VALIDATION_ERROR".to_string(),
                details: None,
                timestamp: Utc::now().to_rfc3339(),
            }),
        )
            .into_response();
    }

    // Check if service exists in configuration (basic check before executing)
    let service_exists = state
        .services_config
        .service
        .iter()
        .any(|s| s.name == request.service && s.enabled);

    if !service_exists {
        warn!(service = %request.service, "Service not found or disabled");
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("Service '{}' not found or disabled", request.service),
                code: "SERVICE_NOT_FOUND".to_string(),
                details: None,
                timestamp: Utc::now().to_rfc3339(),
            }),
        )
            .into_response();
    }

    // Execute the deployment using DeploymentManager
    // For now, assume triggered_by comes from a future auth middleware
    // In production, this would be extracted from the request context
    let triggered_by = "http-api".to_string();

    match state
        .deployment_manager
        .execute_deployment(request.clone(), triggered_by)
        .await
    {
        Ok(deployment) => {
            let response = DeployResponse {
                deploy_id: deployment.deploy_id.clone(),
                service: deployment.service.clone(),
                status: deployment.status.clone(),
                image: deployment.image.clone(),
                started_at: chrono::DateTime::from_timestamp(deployment.started_at, 0)
                    .unwrap_or_else(chrono::Utc::now)
                    .to_rfc3339(),
                completed_at: deployment.completed_at.map(|ts| {
                    chrono::DateTime::from_timestamp(ts, 0)
                        .unwrap_or_else(chrono::Utc::now)
                        .to_rfc3339()
                }),
                duration_seconds: deployment.duration_ms.map(|ms| ms / 1000),
                status_url: format!("/status/{}", deployment.deploy_id),
                log_url: format!("/logs/{}", deployment.deploy_id),
            };

            info!(
                deploy_id = %deployment.deploy_id,
                service = %deployment.service,
                status = ?deployment.status,
                "Deployment completed"
            );

            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            warn!(error = %e, "Deployment failed");
            e.into_response()
        }
    }
}

/// GET /health - Health check endpoint
/// Caches responses for `status_cache_seconds` to reduce load from frequent polling
pub async fn handle_health(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let cache_key = "health";
    let cache_ttl = state.system_config.monitoring.status_cache_seconds;

    // Check if we have a valid cached response
    if let Some(entry) = state.health_cache.get(cache_key) {
        let (cached_response, cached_at) = entry.value();
        let elapsed = SystemTime::now()
            .duration_since(*cached_at)
            .unwrap_or_default();

        if elapsed.as_secs() < cache_ttl {
            // Cache hit - return cached response
            return Ok(Json(cached_response.clone()));
        }
        // Cache expired, continue to generate fresh response
    }

    // Cache miss or expired - perform actual health checks
    async fn has_disk_space(path: &std::path::Path) -> Result<bool> {
        // take ownership of the path so we can move it into the spawn_blocking closure
        let path_os: OsString = path.as_os_str().to_owned();

        // run `df` in a blocking thread
        let output = tokio::task::spawn_blocking(move || -> Result<std::process::Output> {
            // df --output=avail -B1 -- <path>
            let out = Command::new("df")
                .arg("--output=avail")
                .arg("-B1")
                .arg("--")
                .arg(path_os)
                .output()
                .map_err(|e| anyhow!("failed to spawn `df`: {}", e))?;
            Ok(out)
        })
        .await
        .map_err(|e| anyhow!("spawn_blocking join error: {}", e))??;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("`df` failed: {} - {}", output.status, stderr));
        }

        // `df` output is textual; use lossy conversion to handle any odd bytes robustly
        let stdout = String::from_utf8_lossy(&output.stdout);

        // df prints a header line "Avail" and then one or more filesystems; take the last non-empty line
        let last_line = stdout
            .lines()
            .rev()
            .find(|l| !l.trim().is_empty())
            .ok_or_else(|| anyhow!("unexpected `df` output: {:?}", stdout))?;

        let avail_bytes: u64 = last_line
            .trim()
            .parse()
            .map_err(|e| anyhow!("failed to parse available bytes from `df`: {}", e))?;

        Ok(avail_bytes > 0)
    }
    let uptime = state.start_time.elapsed().unwrap_or_default().as_secs();

    let response = HealthResponse {
        status: "healthy".to_string(),
        version: build::PKG_VERSION.to_string(),
        build: build::BUILD_TIME.to_string(),
        uptime_seconds: uptime,
        deployment_queue: QueueStatus {
            pending: 0,
            active: 0,
            workers: state.system_config.server.worker_threads,
        },
        database: DatabaseStatus {
            connected: state.database.get_db_connection().await.unwrap_or(false),
            size_bytes: state.database.get_db_size().await.unwrap_or(0),
        },
        checks: HealthChecks {
            database: if state.database.get_db_connection().await.unwrap_or(false) {
                "ok".to_string()
            } else {
                "failed".to_string()
            },
            disk_space: if has_disk_space(state.system_config.storage.data_dir.as_ref())
                .await
                .unwrap_or(false)
            {
                "ok".to_string()
            } else {
                "failed".to_string()
            },
            worker_pool: "ok".to_string(),
        },
    };

    // Store the fresh response in cache
    state
        .health_cache
        .insert(cache_key.to_string(), (response.clone(), SystemTime::now()));

    Ok(Json(response))
}

/// GET /metrics - Prometheus metrics endpoint
pub async fn handle_metrics(
    State(_state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    match crate::metrics::gather_metrics() {
        Ok(metrics_text) => Ok((
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
            metrics_text,
        )),
        Err(e) => {
            warn!(error = %e, "Failed to gather Prometheus metrics");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// GET /ready - Kubernetes-style readiness probe
/// Returns 200 OK if the service is ready to handle requests
/// Returns 503 Service Unavailable if the service is not ready
pub async fn handle_ready(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Check critical dependencies
    let db_connected = state.database.get_db_connection().await.unwrap_or(false);

    if db_connected {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                ready: true,
                message: None,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                ready: false,
                message: Some("Database not available".to_string()),
            }),
        )
    }
}

/// GET /status/{deploy_id} - Get deployment status
pub async fn handle_status(
    State(_state): State<Arc<AppState>>,
    Path(deploy_id): Path<String>,
) -> Result<impl IntoResponse, StatusCode> {
    info!(deploy_id = %deploy_id, "Status request received");

    // TODO: Look up deployment in database
    // For now, return a placeholder response
    let response = StatusResponse {
        deploy_id: deploy_id.clone(),
        service: "example-service".to_string(),
        status: DeploymentStatus::Queued,
        progress: ProgressInfo {
            phase: "QUEUED".to_string(),
            steps_completed: 0,
            steps_total: 4,
            current_step: None,
        },
        timings: TimingInfo {
            queued_at: Utc::now().to_rfc3339(),
            started_at: Utc::now().to_rfc3339(),
            completed_at: None,
            duration_ms: None,
            queue_time_ms: Some(0),
            deploy_time_ms: None,
            healthcheck_time_ms: None,
        },
        state_transitions: vec![StateTransitionInfo {
            state: DeploymentStatus::Queued,
            at: Utc::now().to_rfc3339(),
        }],
        commands: vec![],
        logs_url: format!("/logs/{}", deploy_id),
        metadata: BTreeMap::new(),
    };

    Ok(Json(response))
}

/// GET /services - List configured services
pub async fn handle_services(
    State(state): State<Arc<AppState>>,
) -> Result<impl IntoResponse, StatusCode> {
    let services: Vec<ServiceInfo> = state
        .services_config
        .service
        .iter()
        .map(|service| {
            // Get service state from database
            let service_state = state
                .database
                .get_service_state(&service.name)
                .ok()
                .flatten();

            let (current_image, last_deploy, health, stats) =
                if let Some(ref svc_state) = service_state {
                    let current_image = if svc_state.current_image.is_empty() {
                        "unknown".to_string()
                    } else {
                        svc_state.current_image.clone()
                    };

                    let last_deploy = svc_state.last_successful_deploy.as_ref().map(|deploy_id| {
                        LastDeployInfo {
                            deploy_id: deploy_id.clone(),
                            status: DeploymentStatus::Succeeded,
                            completed_at: chrono::Utc::now().to_rfc3339(), // TODO: Get actual timestamp
                        }
                    });

                    let health = svc_state.health_status.clone();

                    let stats = ServiceStats {
                        total_deploys: svc_state.total_deploys,
                        success_rate: if svc_state.total_deploys > 0 {
                            let failures =
                                svc_state.total_rollbacks + svc_state.consecutive_failures as u64;
                            let successes = svc_state.total_deploys.saturating_sub(failures);
                            successes as f64 / svc_state.total_deploys as f64
                        } else {
                            1.0
                        },
                        avg_duration_seconds: 0, // TODO: Calculate from history
                        last_failure: svc_state.last_failed_deploy.as_ref().map(|_| {
                            chrono::Utc::now().to_rfc3339() // TODO: Get actual timestamp
                        }),
                    };

                    (current_image, last_deploy, health, stats)
                } else {
                    (
                        "unknown".to_string(),
                        None,
                        HealthStatus::Unknown,
                        ServiceStats {
                            total_deploys: 0,
                            success_rate: 1.0,
                            avg_duration_seconds: 0,
                            last_failure: None,
                        },
                    )
                };

            // Get lock status
            let locked = service_state.as_ref().map(|s| s.locked).unwrap_or(false);

            ServiceInfo {
                name: service.name.clone(),
                enabled: service.enabled,
                current_image,
                last_deploy,
                health,
                locked,
                stats,
            }
        })
        .collect();

    let response = ServicesResponse { services };
    Ok(Json(response))
}

/// Fallback handler for 404 Not Found
pub async fn handle_not_found() -> impl IntoResponse {
    let error_response = ErrorResponse {
        error: "Endpoint not found".to_string(),
        code: "NOT_FOUND".to_string(),
        details: None,
        timestamp: Utc::now().to_rfc3339(),
    };

    (StatusCode::NOT_FOUND, Json(error_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Note: No longer need explicit service config imports as we load from files
    use http_body_util::BodyExt;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::io::Write as _;

    use std::fs;
    use tempfile::{NamedTempFile, TempDir};

    fn make_test_system_config(temp_dir: &std::path::Path) -> String {
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
    fn make_test_services_config(temp_dir: &std::path::Path) -> String {
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

    fn setup_test_configs() -> (SystemConfig, ServicesConfig, TempDir) {
        // Create and load system config.
        let test_folder = tempfile::tempdir().expect("Failed to create temp dir");

        // Create the secret.env file in the temp directory
        let secrets_file_path = test_folder.path().join("secret.env");
        fs::write(
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

        // Temp files are dropped here and deleted automatically.

        (system_config, services_config, test_folder)
    }

    async fn create_test_state() -> (Arc<AppState>, TempDir) {
        // Load test configuration to avoid permission issues
        let (mut system_config, services_config, temp_dir) = setup_test_configs();

        // Use a unique database path for each test to avoid lock conflicts
        let unique_path = format!(
            "/tmp/hookshot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        system_config.storage.data_dir = unique_path.clone();

        // Create rate limiter and IP allowlist for test
        let rate_limiter = Arc::new(crate::http::middleware::RateLimiter::new(
            system_config.security.rate_limit,
        ));
        let ip_allowlist = Arc::new(
            crate::http::middleware::IpAllowlist::from_config(&system_config.security.allowed_ips)
                .unwrap(),
        );

        // Create state manager and deployment manager
        let state_manager =
            Arc::new(StateManager::new(std::path::Path::new(&unique_path)).unwrap());
        let secret_manager = Arc::new(
            SecretManager::new(system_config.clone().secrets)
                .await
                .expect("Failed to create test SecretManager"),
        );
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                state_manager.clone(),
                system_config.clone(),
                services_config.clone(),
                Some(secret_manager.clone()),
            )
            .await,
        );

        (
            Arc::new(AppState {
                system_config: system_config.clone(),
                services_config,
                start_time: SystemTime::now(),
                database: (*state_manager).clone(),
                rate_limiter,
                ip_allowlist,
                deployment_manager,
                health_cache: Arc::new(DashMap::new()),
                secret_manager,
            }),
            temp_dir,
        )
    }

    #[tokio::test]
    async fn test_handle_health() {
        let (state, _temp_dir) = create_test_state().await;
        let result = handle_health(State(state)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_health_caching() {
        let (state, _temp_dir) = create_test_state().await;

        // First request should populate cache
        let result1 = handle_health(State(state.clone())).await;
        assert!(result1.is_ok());
        let response1 = result1.unwrap().into_response();
        let body1 = response1.into_body().collect().await.unwrap().to_bytes();
        let json1: serde_json::Value = serde_json::from_slice(&body1).unwrap();

        // Verify cache was populated
        assert_eq!(state.health_cache.len(), 1);
        assert!(state.health_cache.contains_key("health"));

        // Second immediate request should return cached result
        let result2 = handle_health(State(state.clone())).await;
        assert!(result2.is_ok());
        let response2 = result2.unwrap().into_response();
        let body2 = response2.into_body().collect().await.unwrap().to_bytes();
        let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();

        // Responses should be identical (from cache)
        assert_eq!(json1["status"], json2["status"]);
        assert_eq!(json1["version"], json2["version"]);
    }

    #[tokio::test]
    async fn test_handle_health_cache_expiry() {
        use std::time::Duration;

        let (mut state, _temp_dir) = create_test_state().await;
        // Set very short cache TTL for testing (1 second)
        Arc::get_mut(&mut state)
            .unwrap()
            .system_config
            .monitoring
            .status_cache_seconds = 1;

        // First request
        let result1 = handle_health(State(state.clone())).await;
        assert!(result1.is_ok());

        // Wait for cache to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second request after expiry should fetch fresh data
        let result2 = handle_health(State(state.clone())).await;
        assert!(result2.is_ok());

        // Cache should still contain entry (updated with fresh data)
        assert_eq!(state.health_cache.len(), 1);
    }

    #[tokio::test]
    async fn test_handle_metrics() {
        let (state, _temp_dir) = create_test_state().await;
        let result = handle_metrics(State(state)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_services() {
        let (state, _temp_dir) = create_test_state().await;
        let result = handle_services(State(state)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_handle_deploy_validation() {
        let (state, _temp_dir) = create_test_state().await;

        // Test empty service name
        let request = DeployRequest {
            deploy_id: None,
            service: "".to_string(),
            image: "test:latest".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: DeployOverrides::default(),
            dry_run: false,
        };

        let response = handle_deploy(State(state.clone()), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test empty image
        let request = DeployRequest {
            deploy_id: None,
            service: "test-service".to_string(),
            image: "".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: DeployOverrides::default(),
            dry_run: false,
        };

        let response = handle_deploy(State(state.clone()), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Test nonexistent service
        let request = DeployRequest {
            deploy_id: None,
            service: "nonexistent-service".to_string(),
            image: "test:latest".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: DeployOverrides::default(),
            dry_run: false,
        };

        let response = handle_deploy(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_handle_deploy_success() {
        let (state, _temp_dir) = create_test_state().await;

        // Test successful deployment request
        let request = DeployRequest {
            deploy_id: Some("custom-deploy-123".to_string()),
            service: "test-service".to_string(),
            image: "registry.example.com/app:v1.2.3".to_string(),
            previous_image: Some("registry.example.com/app:v1.2.2".to_string()),
            metadata: BTreeMap::from([
                ("git_ref".to_string(), "refs/heads/main".to_string()),
                ("git_sha".to_string(), "abc123def456".to_string()),
            ]),
            overrides: DeployOverrides {
                env: HashMap::from([("TEST_VAR".to_string(), "test-value".to_string())]),
            },
            dry_run: false,
        };

        let response = handle_deploy(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["deploy_id"], "custom-deploy-123");
        assert_eq!(body["service"], "test-service");
        assert_eq!(body["image"], "registry.example.com/app:v1.2.3");
        assert_eq!(body["status"], "Succeeded");
        assert_eq!(body["status_url"], "/status/custom-deploy-123");
        assert_eq!(body["log_url"], "/logs/custom-deploy-123");
        assert!(body["started_at"].is_string());
        assert!(body["completed_at"].is_string());
        assert!(body["duration_seconds"].is_number());
    }

    #[tokio::test]
    async fn test_handle_deploy_auto_generate_id() {
        let (state, _temp_dir) = create_test_state().await;

        // Test deployment without deploy_id (should auto-generate)
        let request = DeployRequest {
            deploy_id: None,
            service: "test-service".to_string(),
            image: "registry.example.com/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: DeployOverrides::default(),
            dry_run: false,
        };

        let response = handle_deploy(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert!(body["deploy_id"].as_str().unwrap().starts_with("deploy-"));
        assert_eq!(body["service"], "test-service");
        assert_eq!(body["image"], "registry.example.com/app:v1.0.0");
        assert_eq!(body["status"], "Succeeded");
    }

    #[tokio::test]
    async fn test_handle_status() {
        let (state, _temp_dir) = create_test_state().await;

        let result = handle_status(State(state), Path("test-deploy-123".to_string())).await;
        assert!(result.is_ok());

        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["deploy_id"], "test-deploy-123");
        assert_eq!(body["service"], "example-service");
        assert_eq!(body["status"], "Queued");
        assert_eq!(body["progress"]["phase"], "QUEUED");
        assert_eq!(body["progress"]["steps_completed"], 0);
        assert_eq!(body["progress"]["steps_total"], 4);
        assert!(body["progress"]["current_step"].is_null());
        assert_eq!(body["logs_url"], "/logs/test-deploy-123");
        assert!(body["state_transitions"].is_array());
        assert!(body["commands"].is_array());
        assert!(body["metadata"].is_object());
    }

    #[tokio::test]
    async fn test_handle_status_special_characters() {
        let (state, _temp_dir) = create_test_state().await;

        // Test with deploy_id containing special characters
        let deploy_id = "deploy-2023-12-01T10:30:00.123Z";
        let result = handle_status(State(state), Path(deploy_id.to_string())).await;
        assert!(result.is_ok());

        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["deploy_id"], deploy_id);
    }

    #[tokio::test]
    async fn test_handle_not_found() {
        let result = handle_not_found().await;
        let response = result.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["error"], "Endpoint not found");
        assert_eq!(body["code"], "NOT_FOUND");
        assert!(body["details"].is_null());
        assert!(body["timestamp"].is_string());
    }

    #[tokio::test]
    async fn test_handle_health_response_content() {
        let (state, _temp_dir) = create_test_state().await;
        let result = handle_health(State(state)).await;
        assert!(result.is_ok());

        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["status"], "healthy");
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert!(body["uptime_seconds"].is_number());
        assert_eq!(body["deployment_queue"]["pending"], 0);
        assert_eq!(body["deployment_queue"]["active"], 0);
        assert_eq!(body["deployment_queue"]["workers"], 2); // From test config
        assert_eq!(body["database"]["connected"], true);
        assert!(body["database"]["size_bytes"].is_number());
        // Database structure doesn't include tables field
        assert_eq!(body["checks"]["database"], "ok");
        assert_eq!(body["checks"]["disk_space"], "ok");
        assert_eq!(body["checks"]["worker_pool"], "ok");
    }

    #[tokio::test]
    async fn test_handle_metrics_content() {
        // Initialize metrics registry (normally done in main)
        crate::metrics::init_metrics();

        let (state, _temp_dir) = create_test_state().await;
        let result = handle_metrics(State(state)).await;
        assert!(result.is_ok());

        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        // Check content type header
        let content_type = response.headers().get("content-type").unwrap();
        assert!(content_type.to_str().unwrap().starts_with("text/plain"));

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body_str = std::str::from_utf8(&body).unwrap();

        // Verify that actual Prometheus metrics are being returned
        assert!(!body_str.is_empty(), "Metrics body should not be empty");
        assert!(
            body_str.contains("# HELP") || body_str.contains("# TYPE"),
            "Metrics should contain Prometheus format markers"
        );
        // Should contain at least some of our registered metrics
        assert!(body_str.contains("deployment") || body_str.contains("http_requests"));
    }

    #[tokio::test]
    async fn test_handle_services_response_content() {
        let (state, _temp_dir) = create_test_state().await;
        let result = handle_services(State(state)).await;
        assert!(result.is_ok());

        let response = result.unwrap().into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(body["services"].as_array().unwrap().len(), 1);

        let service = &body["services"][0];
        assert_eq!(service["name"], "test-service");
        assert_eq!(service["enabled"], true);
        assert_eq!(service["current_image"], "unknown");
        assert!(service["last_deploy"].is_null());
        assert_eq!(service["health"], "Unknown");
        assert_eq!(service["locked"], false);
        assert_eq!(service["stats"]["total_deploys"], 0);
        assert_eq!(service["stats"]["success_rate"], 1.0);
        assert_eq!(service["stats"]["avg_duration_seconds"], 0);
        assert!(service["stats"]["last_failure"].is_null());
    }

    #[tokio::test]
    async fn test_handle_deploy_disabled_service() {
        let (mut system_config, mut services_config, _temp_dir) = setup_test_configs();

        // Use a unique database path for this test
        let unique_path = format!(
            "/tmp/hookshot-test-disabled-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        system_config.storage.data_dir = unique_path.clone();

        // Modify the test service to be disabled
        if let Some(service) = services_config.service.get_mut(0) {
            service.enabled = false;
        }

        // Create rate limiter and IP allowlist for test
        let rate_limiter = Arc::new(crate::http::middleware::RateLimiter::new(
            system_config.security.rate_limit,
        ));
        let ip_allowlist = Arc::new(
            crate::http::middleware::IpAllowlist::from_config(&system_config.security.allowed_ips)
                .unwrap(),
        );

        // Create state manager and deployment manager
        let state_manager =
            Arc::new(StateManager::new(std::path::Path::new(&unique_path)).unwrap());
        let secret_manager = Arc::new(
            SecretManager::new(system_config.clone().secrets)
                .await
                .expect("Failed to create test SecretManager"),
        );
        let deployment_manager = Arc::new(
            DeploymentManager::new(
                state_manager.clone(),
                system_config.clone(),
                services_config.clone(),
                Some(secret_manager.clone()),
            )
            .await,
        );

        let state = Arc::new(AppState {
            system_config: system_config.clone(),
            services_config,
            start_time: SystemTime::now(),
            database: (*state_manager).clone(),
            rate_limiter,
            ip_allowlist,
            deployment_manager,
            health_cache: Arc::new(DashMap::new()),
            secret_manager,
        });

        let request = DeployRequest {
            deploy_id: None,
            service: "test-service".to_string(), // Use the test service name
            image: "test:latest".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: DeployOverrides::default(),
            dry_run: false,
        };

        let response = handle_deploy(State(state), Json(request))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
