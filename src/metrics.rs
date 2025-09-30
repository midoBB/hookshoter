//! Prometheus metrics collection for the deployment system
//!
//! This module provides a global metrics registry and helper functions
//! to track deployment operations, command execution, and HTTP requests.

use lazy_static::lazy_static;
use prometheus::{
    opts, register_histogram_vec, register_int_counter_vec, register_int_gauge,
    register_int_gauge_vec, Encoder, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry,
    TextEncoder,
};
use tracing::debug;

use crate::types::DeploymentStatus;

lazy_static! {
    /// Global Prometheus registry for all metrics
    pub static ref REGISTRY: Registry = Registry::new();

    /// Total number of deployments by service and status
    /// Labels: service, status (succeeded, failed, rolled_back, rollback_failed)
    pub static ref DEPLOYMENT_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("deployment_total", "Total number of deployments"),
        &["service", "status"]
    )
    .expect("Failed to create deployment_total metric");

    /// Deployment duration in seconds by service and phase
    /// Labels: service, phase (deploy, healthcheck, rollback, total)
    /// Buckets optimized for typical deployment durations (1s to 30min)
    pub static ref DEPLOYMENT_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "deployment_duration_seconds",
        "Time spent in deployment phases",
        &["service", "phase"],
        vec![1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0]
    )
    .expect("Failed to create deployment_duration_seconds metric");

    /// Current number of active deployments per service
    /// Labels: service
    pub static ref DEPLOYMENT_ACTIVE: IntGaugeVec = register_int_gauge_vec!(
        opts!("deployment_active", "Current active deployments"),
        &["service"]
    )
    .expect("Failed to create deployment_active metric");

    /// Total number of rollbacks by service and reason
    /// Labels: service, reason
    pub static ref ROLLBACK_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("rollback_total", "Total number of rollbacks"),
        &["service", "reason"]
    )
    .expect("Failed to create rollback_total metric");

    /// Command execution duration in seconds
    /// Labels: service, phase, command (first element of command array)
    /// Buckets optimized for command execution (100ms to 10min)
    pub static ref COMMAND_EXECUTION_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "command_execution_duration_seconds",
        "Command execution times",
        &["service", "phase", "command"],
        vec![0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0]
    )
    .expect("Failed to create command_execution_duration_seconds metric");

    /// Total number of healthcheck failures
    /// Labels: service
    pub static ref HEALTHCHECK_FAILURES_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("healthcheck_failures_total", "Total number of healthcheck failures"),
        &["service"]
    )
    .expect("Failed to create healthcheck_failures_total metric");

    /// HTTP request duration in seconds
    /// Labels: method, path, status
    /// Buckets optimized for HTTP request times (1ms to 10s)
    pub static ref HTTP_REQUEST_DURATION_SECONDS: HistogramVec = register_histogram_vec!(
        "http_request_duration_seconds",
        "HTTP request latencies",
        &["method", "path", "status"],
        vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
    )
    .expect("Failed to create http_request_duration_seconds metric");

    /// Current deployment queue size
    pub static ref DEPLOYMENT_QUEUE_SIZE: IntGauge = register_int_gauge!(
        opts!("deployment_queue_size", "Current deployment queue depth")
    )
    .expect("Failed to create deployment_queue_size metric");

    /// Total number of HTTP requests
    /// Labels: method, path
    pub static ref HTTP_REQUESTS_TOTAL: IntCounterVec = register_int_counter_vec!(
        opts!("http_requests_total", "Total number of HTTP requests"),
        &["method", "path"]
    )
    .expect("Failed to create http_requests_total metric");
}

/// Initialize metrics registry by registering all metrics
pub fn init_metrics() {
    // Register all metrics with the global registry
    REGISTRY
        .register(Box::new(DEPLOYMENT_TOTAL.clone()))
        .expect("Failed to register deployment_total");
    REGISTRY
        .register(Box::new(DEPLOYMENT_DURATION_SECONDS.clone()))
        .expect("Failed to register deployment_duration_seconds");
    REGISTRY
        .register(Box::new(DEPLOYMENT_ACTIVE.clone()))
        .expect("Failed to register deployment_active");
    REGISTRY
        .register(Box::new(ROLLBACK_TOTAL.clone()))
        .expect("Failed to register rollback_total");
    REGISTRY
        .register(Box::new(COMMAND_EXECUTION_DURATION_SECONDS.clone()))
        .expect("Failed to register command_execution_duration_seconds");
    REGISTRY
        .register(Box::new(HEALTHCHECK_FAILURES_TOTAL.clone()))
        .expect("Failed to register healthcheck_failures_total");
    REGISTRY
        .register(Box::new(HTTP_REQUEST_DURATION_SECONDS.clone()))
        .expect("Failed to register http_request_duration_seconds");
    REGISTRY
        .register(Box::new(DEPLOYMENT_QUEUE_SIZE.clone()))
        .expect("Failed to register deployment_queue_size");
    REGISTRY
        .register(Box::new(HTTP_REQUESTS_TOTAL.clone()))
        .expect("Failed to register http_requests_total");

    debug!("Prometheus metrics registry initialized");
}

/// Record a deployment completion with its final status
pub fn record_deployment_complete(service: &str, status: &DeploymentStatus, duration_ms: u64) {
    let status_label = match status {
        DeploymentStatus::Succeeded => "succeeded",
        DeploymentStatus::Failed => "failed",
        DeploymentStatus::RolledBack => "rolled_back",
        DeploymentStatus::RollbackFailed => "rollback_failed",
        _ => "unknown",
    };

    DEPLOYMENT_TOTAL
        .with_label_values(&[service, status_label])
        .inc();

    // Record total duration
    let duration_seconds = duration_ms as f64 / 1000.0;
    DEPLOYMENT_DURATION_SECONDS
        .with_label_values(&[service, "total"])
        .observe(duration_seconds);

    debug!(
        service = %service,
        status = %status_label,
        duration_ms = duration_ms,
        "Recorded deployment completion metric"
    );
}

/// Record a deployment phase duration
pub fn record_deployment_phase(service: &str, phase: &str, duration_ms: u64) {
    let duration_seconds = duration_ms as f64 / 1000.0;
    DEPLOYMENT_DURATION_SECONDS
        .with_label_values(&[service, phase])
        .observe(duration_seconds);

    debug!(
        service = %service,
        phase = %phase,
        duration_ms = duration_ms,
        "Recorded deployment phase metric"
    );
}

/// Increment active deployment counter for a service
pub fn inc_active_deployments(service: &str) {
    DEPLOYMENT_ACTIVE.with_label_values(&[service]).inc();
}

/// Decrement active deployment counter for a service
pub fn dec_active_deployments(service: &str) {
    DEPLOYMENT_ACTIVE.with_label_values(&[service]).dec();
}

/// Record a rollback with reason
pub fn record_rollback(service: &str, reason: &str) {
    ROLLBACK_TOTAL.with_label_values(&[service, reason]).inc();

    debug!(
        service = %service,
        reason = %reason,
        "Recorded rollback metric"
    );
}

/// Record command execution time
pub fn record_command_execution(service: &str, phase: &str, command_name: &str, duration_ms: u64) {
    let duration_seconds = duration_ms as f64 / 1000.0;
    COMMAND_EXECUTION_DURATION_SECONDS
        .with_label_values(&[service, phase, command_name])
        .observe(duration_seconds);

    debug!(
        service = %service,
        phase = %phase,
        command = %command_name,
        duration_ms = duration_ms,
        "Recorded command execution metric"
    );
}

/// Record a healthcheck failure
pub fn record_healthcheck_failure(service: &str) {
    HEALTHCHECK_FAILURES_TOTAL
        .with_label_values(&[service])
        .inc();

    debug!(
        service = %service,
        "Recorded healthcheck failure metric"
    );
}

/// Record an HTTP request
pub fn record_http_request(method: &str, path: &str, status: u16, duration_seconds: f64) {
    HTTP_REQUESTS_TOTAL.with_label_values(&[method, path]).inc();

    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, path, &status.to_string()])
        .observe(duration_seconds);

    debug!(
        method = %method,
        path = %path,
        status = status,
        duration_seconds = duration_seconds,
        "Recorded HTTP request metric"
    );
}

/// Set the current deployment queue size
pub fn set_queue_size(size: i64) {
    DEPLOYMENT_QUEUE_SIZE.set(size);
}

/// Gather all metrics and encode them in Prometheus text format
pub fn gather_metrics() -> Result<String, String> {
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();

    let mut buffer = Vec::new();
    encoder
        .encode(&metric_families, &mut buffer)
        .map_err(|e| format!("Failed to encode metrics: {}", e))?;

    String::from_utf8(buffer).map_err(|e| format!("Failed to convert metrics to UTF-8: {}", e))
}

/// Guard struct for tracking active deployment metrics
/// Automatically decrements the counter when dropped
pub struct DeploymentMetricsGuard {
    service: String,
}

impl DeploymentMetricsGuard {
    pub fn new(service: String) -> Self {
        inc_active_deployments(&service);
        Self { service }
    }
}

impl Drop for DeploymentMetricsGuard {
    fn drop(&mut self) {
        dec_active_deployments(&self.service);
    }
}

/// Helper to get status label from DeploymentStatus
pub fn deployment_status_label(status: &DeploymentStatus) -> &'static str {
    match status {
        DeploymentStatus::Queued => "queued",
        DeploymentStatus::Validating => "validating",
        DeploymentStatus::Deploying => "deploying",
        DeploymentStatus::HealthChecking => "healthchecking",
        DeploymentStatus::Succeeded => "succeeded",
        DeploymentStatus::Failed => "failed",
        DeploymentStatus::RollingBack => "rolling_back",
        DeploymentStatus::RolledBack => "rolled_back",
        DeploymentStatus::RollbackFailed => "rollback_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_status_labels() {
        assert_eq!(
            deployment_status_label(&DeploymentStatus::Succeeded),
            "succeeded"
        );
        assert_eq!(deployment_status_label(&DeploymentStatus::Failed), "failed");
        assert_eq!(
            deployment_status_label(&DeploymentStatus::RolledBack),
            "rolled_back"
        );
    }

    #[test]
    fn test_metrics_registration() {
        // Test that metrics can be accessed without panicking
        let _ = DEPLOYMENT_TOTAL.clone();
        let _ = DEPLOYMENT_DURATION_SECONDS.clone();
        let _ = DEPLOYMENT_ACTIVE.clone();
        let _ = ROLLBACK_TOTAL.clone();
        let _ = COMMAND_EXECUTION_DURATION_SECONDS.clone();
        let _ = HEALTHCHECK_FAILURES_TOTAL.clone();
        let _ = HTTP_REQUEST_DURATION_SECONDS.clone();
        let _ = DEPLOYMENT_QUEUE_SIZE.clone();
        let _ = HTTP_REQUESTS_TOTAL.clone();
    }

    #[test]
    fn test_record_deployment_complete() {
        // Should not panic
        record_deployment_complete("test-service", &DeploymentStatus::Succeeded, 5000);
        record_deployment_complete("test-service", &DeploymentStatus::Failed, 3000);
    }

    #[test]
    fn test_record_deployment_phase() {
        // Should not panic
        record_deployment_phase("test-service", "deploy", 2000);
        record_deployment_phase("test-service", "healthcheck", 1000);
    }

    #[test]
    fn test_active_deployments() {
        // Should not panic
        inc_active_deployments("test-service");
        dec_active_deployments("test-service");
    }

    #[test]
    fn test_deployment_metrics_guard() {
        let service = "test-service".to_string();
        {
            let _guard = DeploymentMetricsGuard::new(service.clone());
            // Guard increments counter
        }
        // Guard decrements counter on drop
    }

    #[test]
    fn test_record_rollback() {
        // Should not panic
        record_rollback("test-service", "healthcheck_failed");
        record_rollback("test-service", "deploy_failed");
    }

    #[test]
    fn test_record_command_execution() {
        // Should not panic
        record_command_execution("test-service", "deploy", "podman", 1500);
        record_command_execution("test-service", "healthcheck", "curl", 200);
    }

    #[test]
    fn test_record_healthcheck_failure() {
        // Should not panic
        record_healthcheck_failure("test-service");
    }

    #[test]
    fn test_record_http_request() {
        // Should not panic
        record_http_request("POST", "/deploy", 200, 0.5);
        record_http_request("GET", "/health", 200, 0.01);
    }

    #[test]
    fn test_set_queue_size() {
        // Should not panic
        set_queue_size(5);
        set_queue_size(0);
    }

    #[test]
    fn test_gather_metrics() {
        // Initialize metrics registry
        init_metrics();

        // Record some metrics
        record_deployment_complete("test", &DeploymentStatus::Succeeded, 1000);

        // Gather metrics
        let result = gather_metrics();
        assert!(result.is_ok());

        let metrics_text = result.unwrap();
        assert!(metrics_text.contains("deployment_total"));
        assert!(metrics_text.contains("# HELP"));
        assert!(metrics_text.contains("# TYPE"));
    }
}
