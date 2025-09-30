use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::types::{ConfigError, Result};

/// System configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub monitoring: MonitoringConfig,
    #[serde(default)]
    pub notifications: NotificationsConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_worker_threads")]
    pub worker_threads: u32,
    #[serde(default = "default_max_request_size")]
    pub max_request_size: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout: u64,
    #[serde(default = "default_shutdown_timeout")]
    pub shutdown_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default)]
    pub retention: RetentionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionConfig {
    #[serde(default = "default_successful_deploys_retention")]
    pub successful_deploys: u32,
    #[serde(default = "default_failed_deploys_retention")]
    pub failed_deploys: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_log_directory")]
    pub directory: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitsConfig {
    #[serde(default = "default_max_concurrent_total")]
    pub max_concurrent_total: u32,
    #[serde(default = "default_max_concurrent_per_service")]
    pub max_concurrent_per_service: u32,
    #[serde(default = "default_deployment_timeout")]
    pub deployment_timeout: u64,
    #[serde(default = "default_command_timeout")]
    pub command_timeout: u64,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    #[serde(default = "default_metrics_enabled")]
    pub metrics_enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub metrics_path: String,
    #[serde(default = "default_health_path")]
    pub health_path: String,
    #[serde(default = "default_status_cache_seconds")]
    pub status_cache_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationsConfig {
    #[serde(default = "default_notifications_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub webhook: WebhookConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub on_failure: Option<String>,
    pub on_rollback: Option<String>,
    pub on_success: Option<String>,
    #[serde(default = "default_webhook_timeout")]
    pub timeout: u64,
    #[serde(default = "default_use_secrets")]
    pub use_secrets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    #[serde(default = "default_secrets_source")]
    pub source: SecretSource,
    #[serde(default = "default_sources_priority")]
    pub sources_priority: Vec<String>,
    #[serde(default = "default_secrets_file")]
    pub secrets_file: String,
    #[serde(default = "default_required_secrets")]
    pub required_secrets: Vec<String>,
    #[serde(default = "default_reload_interval")]
    pub reload_interval: u64,
    #[serde(default = "default_secret_prefix")]
    pub secret_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SecretSource {
    Single(String),
    Multiple(Vec<String>),
}

/// Services configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServicesConfig {
    #[serde(default)]
    pub defaults: DefaultsConfig,
    #[serde(default)]
    pub service: Vec<ServiceConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultsConfig {
    #[serde(default = "default_working_dir")]
    pub working_dir: String,
    #[serde(default = "default_command_timeout")]
    pub command_timeout: u64,
    #[serde(default = "default_healthcheck_timeout")]
    pub healthcheck_timeout: u64,
    #[serde(default = "default_rollback_enabled")]
    pub rollback_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub description: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub working_dir: Option<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub security: ServiceSecurity,
    pub deploy: ServiceDeploy,
    #[serde(default)]
    pub healthcheck: ServiceHealthcheck,
    #[serde(default)]
    pub rollback: ServiceRollback,
    #[serde(default)]
    pub hooks: ServiceHooks,
    #[serde(default)]
    pub templates: HashMap<String, String>,
    #[serde(default)]
    pub github: Option<ServiceGitHub>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSecurity {
    pub allowed_image_pattern: String,
    #[serde(default)]
    pub allowed_env_overrides: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDeploy {
    pub commands: Vec<Vec<String>>,
    pub timeout: Option<u64>,
    #[serde(default = "default_retries")]
    pub retries: u32,
    #[serde(default = "default_critical")]
    pub critical: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHealthcheck {
    #[serde(default = "default_initial_delay")]
    pub initial_delay: u64,
    #[serde(default = "default_healthcheck_interval")]
    pub interval: u64,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceRollback {
    #[serde(default = "default_rollback_enabled")]
    pub enabled: bool,
    #[serde(default = "default_rollback_max_attempts")]
    pub max_attempts: u32,
    pub timeout: Option<u64>,
    #[serde(default)]
    pub commands: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceHooks {
    #[serde(default)]
    pub pre_deploy: Vec<Vec<String>>,
    #[serde(default)]
    pub post_deploy: Vec<Vec<String>>,
    #[serde(default)]
    pub on_failure: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ServiceGitHub {
    pub repo: String,
}

impl SystemConfig {
    /// Load system configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let content = std::fs::read_to_string(&path)
            .map_err(|_| ConfigError::FileNotFound { path: path_str })?;

        let config: SystemConfig = toml::from_str(&content).map_err(ConfigError::ParseError)?;
        Ok(config)
    }
}

impl ServicesConfig {
    /// Load services configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_str = path.as_ref().to_string_lossy().to_string();
        let content = std::fs::read_to_string(&path)
            .map_err(|_| ConfigError::FileNotFound { path: path_str })?;

        let config: ServicesConfig = toml::from_str(&content).map_err(ConfigError::ParseError)?;
        Ok(config)
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            allowed_ips: Vec::new(),
            rate_limit: default_rate_limit(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            retention: RetentionConfig::default(),
        }
    }
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            successful_deploys: default_successful_deploys_retention(),
            failed_deploys: default_failed_deploys_retention(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            directory: default_log_directory(),
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_concurrent_total: default_max_concurrent_total(),
            max_concurrent_per_service: default_max_concurrent_per_service(),
            deployment_timeout: default_deployment_timeout(),
            command_timeout: default_command_timeout(),
            lock_timeout: default_lock_timeout(),
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            metrics_enabled: default_metrics_enabled(),
            metrics_path: default_metrics_path(),
            health_path: default_health_path(),
            status_cache_seconds: default_status_cache_seconds(),
        }
    }
}

impl Default for NotificationsConfig {
    fn default() -> Self {
        Self {
            enabled: default_notifications_enabled(),
            webhook: WebhookConfig::default(),
        }
    }
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            on_failure: None,
            on_rollback: None,
            on_success: None,
            timeout: default_webhook_timeout(),
            use_secrets: default_use_secrets(),
        }
    }
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            source: default_secrets_source(),
            sources_priority: default_sources_priority(),
            secrets_file: default_secrets_file(),
            required_secrets: default_required_secrets(),
            reload_interval: default_reload_interval(),
            secret_prefix: default_secret_prefix(),
        }
    }
}

impl Default for SecretSource {
    fn default() -> Self {
        default_secrets_source()
    }
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen: default_listen(),
                worker_threads: default_worker_threads(),
                max_request_size: default_max_request_size(),
                request_timeout: default_request_timeout(),
                shutdown_timeout: default_shutdown_timeout(),
            },
            security: SecurityConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
            limits: LimitsConfig::default(),
            monitoring: MonitoringConfig::default(),
            notifications: NotificationsConfig::default(),
            secrets: SecretsConfig::default(),
        }
    }
}

impl Default for DefaultsConfig {
    fn default() -> Self {
        Self {
            working_dir: default_working_dir(),
            command_timeout: default_command_timeout(),
            healthcheck_timeout: default_healthcheck_timeout(),
            rollback_enabled: default_rollback_enabled(),
        }
    }
}

impl Default for ServiceHealthcheck {
    fn default() -> Self {
        Self {
            initial_delay: default_initial_delay(),
            interval: default_healthcheck_interval(),
            max_attempts: default_max_attempts(),
            success_threshold: default_success_threshold(),
            timeout: None,
            commands: Vec::new(),
        }
    }
}

impl Default for ServiceRollback {
    fn default() -> Self {
        Self {
            enabled: default_rollback_enabled(),
            max_attempts: default_rollback_max_attempts(),
            timeout: None,
            commands: Vec::new(),
        }
    }
}

// Default value functions
fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}

fn default_worker_threads() -> u32 {
    4
}

fn default_request_timeout() -> u64 {
    30
}

fn default_shutdown_timeout() -> u64 {
    300
}

fn default_rate_limit() -> u32 {
    100
}

fn default_data_dir() -> String {
    "/var/lib/hookshot".to_string()
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_format() -> String {
    "json".to_string()
}

fn default_enabled() -> bool {
    true
}

fn default_max_request_size() -> String {
    "1MB".to_string()
}

fn default_successful_deploys_retention() -> u32 {
    100
}

fn default_failed_deploys_retention() -> u32 {
    50
}

fn default_log_directory() -> String {
    "/var/log/hookshot".to_string()
}

fn default_max_concurrent_total() -> u32 {
    10
}

fn default_max_concurrent_per_service() -> u32 {
    1
}

fn default_deployment_timeout() -> u64 {
    1800
}

fn default_command_timeout() -> u64 {
    300
}

fn default_lock_timeout() -> u64 {
    60
}

fn default_metrics_enabled() -> bool {
    true
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

fn default_health_path() -> String {
    "/health".to_string()
}

fn default_status_cache_seconds() -> u64 {
    10
}

fn default_notifications_enabled() -> bool {
    false
}

fn default_webhook_timeout() -> u64 {
    5
}

fn default_use_secrets() -> bool {
    false
}

fn default_working_dir() -> String {
    "/srv".to_string()
}

fn default_healthcheck_timeout() -> u64 {
    60
}

fn default_rollback_enabled() -> bool {
    true
}

fn default_retries() -> u32 {
    0
}

fn default_critical() -> bool {
    true
}

fn default_initial_delay() -> u64 {
    5
}

fn default_healthcheck_interval() -> u64 {
    3
}

fn default_max_attempts() -> u32 {
    20
}

fn default_success_threshold() -> u32 {
    3
}

fn default_rollback_max_attempts() -> u32 {
    2
}

fn default_secrets_source() -> SecretSource {
    SecretSource::Single("auto".to_string())
}

fn default_sources_priority() -> Vec<String> {
    vec!["systemd".to_string(), "file".to_string(), "env".to_string()]
}

fn default_secrets_file() -> String {
    "/etc/hookshot/secrets".to_string()
}

fn default_required_secrets() -> Vec<String> {
    vec!["hmac_key".to_string()]
}

fn default_reload_interval() -> u64 {
    300
}

fn default_secret_prefix() -> String {
    "DEPLOY_RECEIVER_".to_string()
}
