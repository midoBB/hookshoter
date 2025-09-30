use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Main error type for the application
#[derive(Error, Debug)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),

    #[error("Execution error: {0}")]
    Execution(#[from] ExecutionError),

    #[error("Template expansion error: {0}")]
    TemplateExpansion(#[from] TemplateExpansionError),

    #[error("Backup error: {0}")]
    Backup(#[from] BackupError),

    #[error("Authentication failed: {0}")]
    Authentication(String),

    #[error("Service {service} is locked by deployment {deploy_id}")]
    ServiceLocked { service: String, deploy_id: String },

    #[error("Concurrency limit exceeded for {limit_type}: {current}/{limit} active deployments")]
    ConcurrencyLimitExceeded {
        limit_type: String,
        limit: u32,
        current: u32,
    },

    #[error("Validation failed: {field}: {message}")]
    Validation { field: String, message: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Application error: {0}")]
    Application(String),
}

/// Configuration-related errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Config file not found: {path}")]
    FileNotFound { path: String },

    #[error("Config file parse error: {0}")]
    ParseError(#[from] toml::de::Error),

    #[error("Invalid configuration: {message}")]
    Invalid { message: String },

    #[error("Missing required field: {field}")]
    MissingField { field: String },
}

/// Execution-related errors
#[derive(Error, Debug)]
pub enum ExecutionError {
    #[error("Command '{command}' failed with exit code {code}")]
    NonZeroExit { command: String, code: i32 },

    #[error("Command '{command}' timed out after {timeout}s")]
    Timeout { command: String, timeout: u64 },

    #[error("Command '{command}' could not be started: {source}")]
    StartFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Template expansion failed: {0}")]
    TemplateExpansion(#[from] TemplateExpansionError),
}

/// Template expansion errors
#[derive(Error, Debug)]
pub enum TemplateExpansionError {
    #[error("Undefined template variable: {variable}")]
    UndefinedVariable { variable: String },

    #[error("Template contains unexpanded variables: {template}")]
    UnexpandedTemplate { template: String },

    #[error("Unsafe value for template variable '{variable}': {value}")]
    UnsafeValue { variable: String, value: String },

    #[error("Template rendering failed: {source}")]
    RenderError {
        #[from]
        source: handlebars::RenderError,
    },
}

/// Database-related errors
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Database connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Database transaction failed: {0}")]
    TransactionFailed(String),

    #[error("Record not found: {key}")]
    RecordNotFound { key: String },

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Database corruption detected: {0}")]
    Corruption(String),
}

/// Backup and restore errors
#[derive(Error, Debug)]
pub enum BackupError {
    #[error("Invalid backup archive format: {0}")]
    InvalidArchive(String),

    #[error("Checksum mismatch for file {file}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        file: String,
        expected: String,
        actual: String,
    },

    #[error("Version incompatibility: backup version {backup_version} cannot be restored to {current_version}")]
    VersionIncompatible {
        backup_version: String,
        current_version: String,
    },

    #[error("Active deployments present, cannot restore (use --force to override)")]
    ActiveDeployments,

    #[error("Backup restoration failed: {0}")]
    RestoreFailed(String),

    #[error("Manifest parsing failed: {0}")]
    ManifestParseFailed(String),

    #[error("Required file missing in backup: {0}")]
    MissingFile(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Type alias for Results
pub type Result<T> = std::result::Result<T, Error>;

/// Deployment status enum representing the state of a deployment
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DeploymentStatus {
    /// Deployment is queued and waiting to start
    #[default]
    Queued,
    /// Deployment is being validated
    Validating,
    /// Deployment commands are executing
    Deploying,
    /// Health checks are running
    HealthChecking,
    /// Deployment completed successfully
    Succeeded,
    /// Deployment failed
    Failed,
    /// Rollback is in progress
    RollingBack,
    /// Rollback completed successfully
    RolledBack,
    /// Rollback failed
    RollbackFailed,
}

/// Health status for services and deployments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HealthStatus {
    #[default]
    Unknown,
    Healthy,
    Unhealthy,
    Degraded,
}

/// Command execution phase
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandPhase {
    Deploy,
    Healthcheck,
    Rollback,
    PreDeploy,
    PostDeploy,
    OnFailure,
}

/// State transition record for tracking deployment progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from_state: DeploymentStatus,
    pub to_state: DeploymentStatus,
    pub timestamp: i64,
    pub reason: Option<String>,
}

/// Result of a command execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub phase: CommandPhase,
    pub step_name: String,
    pub command: Vec<String>,
    pub exit_code: Option<i32>,
    pub stdout: String, // Truncated to reasonable size
    pub stderr: String, // Truncated to reasonable size
    pub started_at: i64,
    pub duration_ms: u64,
    pub timed_out: bool,
    pub retries: u32,
}

/// Complete deployment record with all execution details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentRecord {
    pub deploy_id: String,
    pub service: String,
    pub status: DeploymentStatus,
    pub image: String,
    pub previous_image: Option<String>,
    pub started_at: i64,
    pub completed_at: Option<i64>,
    pub duration_ms: Option<u64>,

    // Execution details
    pub state_transitions: Vec<StateTransition>,
    pub command_results: Vec<CommandResult>,

    // Rollback information
    pub rollback_attempted: bool,
    pub rollback_reason: Option<String>,
    pub rollback_succeeded: Option<bool>,

    // Request metadata
    pub metadata: BTreeMap<String, String>,
    pub triggered_by: String, // IP or identifier
    pub hmac_valid: bool,
}

impl DeploymentRecord {
    /// Create a new deployment record
    pub fn new(deploy_id: String, service: String, image: String, triggered_by: String) -> Self {
        let now = chrono::Utc::now().timestamp();

        Self {
            deploy_id,
            service,
            status: DeploymentStatus::Queued,
            image,
            previous_image: None,
            started_at: now,
            completed_at: None,
            duration_ms: None,
            state_transitions: Vec::new(),
            command_results: Vec::new(),
            rollback_attempted: false,
            rollback_reason: None,
            rollback_succeeded: None,
            metadata: BTreeMap::new(),
            triggered_by,
            hmac_valid: false,
        }
    }

    /// Add a state transition
    pub fn add_state_transition(&mut self, to_state: DeploymentStatus, reason: Option<String>) {
        let transition = StateTransition {
            from_state: self.status.clone(),
            to_state: to_state.clone(),
            timestamp: chrono::Utc::now().timestamp(),
            reason,
        };

        self.state_transitions.push(transition);
        self.status = to_state;
    }

    /// Mark deployment as completed
    pub fn mark_completed(&mut self) {
        let now = chrono::Utc::now().timestamp();
        self.completed_at = Some(now);
        self.duration_ms = Some((now - self.started_at) as u64 * 1000);
    }
}

/// Current state of a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceState {
    pub service: String,
    pub current_image: String,
    pub current_deploy_id: String,

    // History
    pub last_successful_deploy: Option<String>,
    pub last_failed_deploy: Option<String>,
    pub consecutive_failures: u32,
    pub total_deploys: u64,
    pub total_rollbacks: u64,

    // Health
    pub last_health_check: i64,
    pub health_status: HealthStatus,
    pub health_message: Option<String>,

    // State
    pub locked: bool,
    pub locked_by: Option<String>,
    pub locked_at: Option<i64>,
    pub updated_at: i64,
}

impl ServiceState {
    /// Create a new service state
    pub fn new(service: String) -> Self {
        let now = chrono::Utc::now().timestamp();

        Self {
            service,
            current_image: String::new(),
            current_deploy_id: String::new(),
            last_successful_deploy: None,
            last_failed_deploy: None,
            consecutive_failures: 0,
            total_deploys: 0,
            total_rollbacks: 0,
            last_health_check: now,
            health_status: HealthStatus::Unknown,
            health_message: None,
            locked: false,
            locked_by: None,
            locked_at: None,
            updated_at: now,
        }
    }

    /// Lock the service for deployment
    pub fn lock(&mut self, deploy_id: String) -> Result<()> {
        if self.locked {
            return Err(Error::ServiceLocked {
                service: self.service.clone(),
                deploy_id: self
                    .locked_by
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            });
        }

        let now = chrono::Utc::now().timestamp();
        self.locked = true;
        self.locked_by = Some(deploy_id);
        self.locked_at = Some(now);
        self.updated_at = now;

        Ok(())
    }

    /// Unlock the service
    pub fn unlock(&mut self) {
        self.locked = false;
        self.locked_by = None;
        self.locked_at = None;
        self.updated_at = chrono::Utc::now().timestamp();
    }

    /// Update deployment statistics
    pub fn update_deployment_stats(&mut self, deployment: &DeploymentRecord) {
        self.total_deploys += 1;
        self.updated_at = chrono::Utc::now().timestamp();

        match deployment.status {
            DeploymentStatus::Succeeded => {
                self.last_successful_deploy = Some(deployment.deploy_id.clone());
                self.consecutive_failures = 0;
                self.current_image = deployment.image.clone();
                self.current_deploy_id = deployment.deploy_id.clone();
            }
            DeploymentStatus::Failed | DeploymentStatus::RollbackFailed => {
                self.last_failed_deploy = Some(deployment.deploy_id.clone());
                self.consecutive_failures += 1;
            }
            DeploymentStatus::RolledBack => {
                self.total_rollbacks += 1;
                self.last_failed_deploy = Some(deployment.deploy_id.clone());
                self.consecutive_failures += 1;
                // Restore previous image if rollback succeeded
                if let Some(ref previous_image) = deployment.previous_image {
                    self.current_image = previous_image.clone();
                }
            }
            _ => {
                // Other states don't affect final statistics
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deployment_record_creation() {
        let record = DeploymentRecord::new(
            "deploy-001".to_string(),
            "web-service".to_string(),
            "registry:5000/app:v1.0.0".to_string(),
            "192.168.1.100".to_string(),
        );

        assert_eq!(record.deploy_id, "deploy-001");
        assert_eq!(record.service, "web-service");
        assert_eq!(record.status, DeploymentStatus::Queued);
        assert_eq!(record.image, "registry:5000/app:v1.0.0");
        assert_eq!(record.triggered_by, "192.168.1.100");
        assert!(!record.hmac_valid);
        assert!(!record.rollback_attempted);
    }

    #[test]
    fn test_state_transitions() {
        let mut record = DeploymentRecord::new(
            "deploy-001".to_string(),
            "web-service".to_string(),
            "registry:5000/app:v1.0.0".to_string(),
            "192.168.1.100".to_string(),
        );

        record.add_state_transition(
            DeploymentStatus::Deploying,
            Some("Starting deployment".to_string()),
        );
        record.add_state_transition(DeploymentStatus::Succeeded, None);

        assert_eq!(record.status, DeploymentStatus::Succeeded);
        assert_eq!(record.state_transitions.len(), 2);
        assert_eq!(
            record.state_transitions[0].from_state,
            DeploymentStatus::Queued
        );
        assert_eq!(
            record.state_transitions[0].to_state,
            DeploymentStatus::Deploying
        );
        assert_eq!(
            record.state_transitions[1].from_state,
            DeploymentStatus::Deploying
        );
        assert_eq!(
            record.state_transitions[1].to_state,
            DeploymentStatus::Succeeded
        );
    }

    #[test]
    fn test_service_state_locking() {
        let mut state = ServiceState::new("web-service".to_string());

        // Should be able to lock initially
        assert!(state.lock("deploy-001".to_string()).is_ok());
        assert!(state.locked);
        assert_eq!(state.locked_by, Some("deploy-001".to_string()));

        // Should not be able to lock again
        assert!(state.lock("deploy-002".to_string()).is_err());

        // Should be able to unlock
        state.unlock();
        assert!(!state.locked);
        assert_eq!(state.locked_by, None);
    }

    #[test]
    fn test_error_conversion() {
        let config_error = ConfigError::Invalid {
            message: "test error".to_string(),
        };
        let main_error: Error = config_error.into();

        match main_error {
            Error::Config(ConfigError::Invalid { message }) => {
                assert_eq!(message, "test error");
            }
            _ => panic!("Error conversion failed"),
        }
    }
}
