//! HTTP request and response types for the deployment API
//!
//! This module defines the JSON request/response structures based on the
//! API specification in PROJECT.md.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

use crate::types::{DeploymentStatus, Error, HealthStatus};

/// Deployment request structure from POST /deploy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    /// Deployment ID (optional, auto-generated if absent)
    pub deploy_id: Option<String>,
    /// Service name to deploy
    pub service: String,
    /// Container image to deploy
    pub image: String,
    /// Previous image for rollback (optional but recommended)
    pub previous_image: Option<String>,
    /// Additional metadata about the deployment
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Environment variable overrides
    #[serde(default)]
    pub overrides: DeployOverrides,
    /// Dry run mode - validate without executing
    #[serde(default)]
    pub dry_run: bool,
}

/// Environment and configuration overrides
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeployOverrides {
    /// Environment variable overrides
    #[serde(default)]
    pub env: HashMap<String, String>,
}

/// Successful deployment response
#[derive(Debug, Serialize)]
pub struct DeployResponse {
    pub deploy_id: String,
    pub service: String,
    pub status: DeploymentStatus,
    pub image: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_seconds: Option<u64>,
    pub status_url: String,
    pub log_url: String,
}

/// Deployment response for rollback scenarios
#[derive(Debug, Serialize)]
pub struct DeployRollbackResponse {
    pub deploy_id: String,
    pub service: String,
    pub status: DeploymentStatus,
    pub attempted_image: String,
    pub current_image: String,
    pub error: String,
    pub rollback_reason: String,
    pub started_at: String,
    pub completed_at: String,
    pub duration_seconds: u64,
    pub status_url: String,
    pub log_url: String,
}

/// Deployment failure response
#[derive(Debug, Serialize)]
pub struct DeployFailureResponse {
    pub deploy_id: String,
    pub service: String,
    pub status: DeploymentStatus,
    pub error: String,
    pub failure_stage: String,
    pub failure_detail: String,
    pub requires_intervention: bool,
    pub started_at: String,
    pub failed_at: String,
    pub status_url: String,
    pub log_url: String,
}

/// Health check response
#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub build: String,
    pub uptime_seconds: u64,
    pub deployment_queue: QueueStatus,
    pub database: DatabaseStatus,
    pub checks: HealthChecks,
}

#[derive(Debug, Clone, Serialize)]
pub struct QueueStatus {
    pub pending: u32,
    pub active: u32,
    pub workers: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct DatabaseStatus {
    pub connected: bool,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthChecks {
    pub database: String,
    pub disk_space: String,
    pub worker_pool: String,
}

/// Readiness response for Kubernetes-style readiness checks
#[derive(Debug, Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub message: Option<String>,
}

/// Deployment status response
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub deploy_id: String,
    pub service: String,
    pub status: DeploymentStatus,
    pub progress: ProgressInfo,
    pub timings: TimingInfo,
    pub state_transitions: Vec<StateTransitionInfo>,
    pub commands: Vec<CommandInfo>,
    pub logs_url: String,
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct ProgressInfo {
    pub phase: String,
    pub steps_completed: u32,
    pub steps_total: u32,
    pub current_step: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TimingInfo {
    pub queued_at: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub queue_time_ms: Option<u64>,
    pub deploy_time_ms: Option<u64>,
    pub healthcheck_time_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct StateTransitionInfo {
    pub state: DeploymentStatus,
    pub at: String,
}

#[derive(Debug, Serialize)]
pub struct CommandInfo {
    pub phase: String,
    pub step: String,
    pub status: String,
    pub exit_code: Option<i32>,
    pub duration_ms: u64,
    pub output_preview: String,
}

/// Services list response
#[derive(Debug, Serialize)]
pub struct ServicesResponse {
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub enabled: bool,
    pub current_image: String,
    pub last_deploy: Option<LastDeployInfo>,
    pub health: HealthStatus,
    pub locked: bool,
    pub stats: ServiceStats,
}

#[derive(Debug, Serialize)]
pub struct LastDeployInfo {
    pub deploy_id: String,
    pub status: DeploymentStatus,
    pub completed_at: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceStats {
    pub total_deploys: u64,
    pub success_rate: f64,
    pub avg_duration_seconds: u64,
    pub last_failure: Option<String>,
}

/// Standard error response
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
    pub details: Option<BTreeMap<String, String>>,
    pub timestamp: String,
}

impl ErrorResponse {
    pub fn new(error: &Error) -> Self {
        Self {
            error: error.to_string(),
            code: error_to_code(error),
            details: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn with_details(mut self, details: BTreeMap<String, String>) -> Self {
        self.details = Some(details);
        self
    }
}

/// Convert error types to HTTP status codes and error codes
fn error_to_code(error: &Error) -> String {
    match error {
        Error::Config(_) => "CONFIG_ERROR".to_string(),
        Error::Database(_) => "DATABASE_ERROR".to_string(),
        Error::Execution(_) => "EXECUTION_ERROR".to_string(),
        Error::TemplateExpansion(_) => "TEMPLATE_ERROR".to_string(),
        Error::Backup(_) => "BACKUP_ERROR".to_string(),
        Error::Authentication(_) => "AUTH_ERROR".to_string(),
        Error::ServiceLocked { .. } => "SERVICE_LOCKED".to_string(),
        Error::ConcurrencyLimitExceeded { .. } => "CONCURRENCY_LIMIT_EXCEEDED".to_string(),
        Error::Validation { .. } => "VALIDATION_ERROR".to_string(),
        Error::Io(_) => "IO_ERROR".to_string(),
        Error::Application(_) => "APPLICATION_ERROR".to_string(),
    }
}

/// Convert error types to HTTP status codes
pub fn error_to_status_code(error: &Error) -> StatusCode {
    match error {
        Error::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Execution(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::TemplateExpansion(_) => StatusCode::BAD_REQUEST,
        Error::Backup(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Authentication(_) => StatusCode::UNAUTHORIZED,
        Error::ServiceLocked { .. } => StatusCode::CONFLICT,
        Error::ConcurrencyLimitExceeded { .. } => StatusCode::TOO_MANY_REQUESTS,
        Error::Validation { .. } => StatusCode::BAD_REQUEST,
        Error::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        Error::Application(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// Implement IntoResponse for Error types to automatically convert them to HTTP responses
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status_code = error_to_status_code(&self);
        let error_response = ErrorResponse::new(&self);
        (status_code, Json(error_response)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_request_serialization() {
        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "web-service".to_string(),
            image: "registry:5000/app:v1.0.0".to_string(),
            previous_image: Some("registry:5000/app:v0.9.0".to_string()),
            metadata: BTreeMap::from([
                ("git_ref".to_string(), "refs/heads/main".to_string()),
                ("git_sha".to_string(), "abc123".to_string()),
            ]),
            overrides: DeployOverrides {
                env: HashMap::from([("LOG_LEVEL".to_string(), "debug".to_string())]),
            },
            dry_run: false,
        };

        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("deploy-001"));
        assert!(json.contains("web-service"));
        assert!(json.contains("registry:5000/app:v1.0.0"));
    }

    #[test]
    fn test_error_response_creation() {
        let error = Error::Validation {
            field: "image".to_string(),
            message: "Invalid image format".to_string(),
        };

        let response = ErrorResponse::new(&error);
        assert_eq!(response.code, "VALIDATION_ERROR");
        assert!(response.error.contains("Invalid image format"));
    }

    #[test]
    fn test_error_to_status_code() {
        assert_eq!(
            error_to_status_code(&Error::Authentication("test".to_string())),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            error_to_status_code(&Error::Validation {
                field: "test".to_string(),
                message: "test".to_string()
            }),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            error_to_status_code(&Error::ServiceLocked {
                service: "test".to_string(),
                deploy_id: "test".to_string()
            }),
            StatusCode::CONFLICT
        );
    }
}
