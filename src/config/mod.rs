pub mod types;
mod validators;

// Re-export all public types
pub use types::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::validators::{
        parse_size_string, validate_array_size, validate_concurrency_limits,
        validate_listen_address, validate_network_cidr, validate_positive_timeout,
        validate_regex_pattern, validate_request_size, validate_secret_source,
        validate_service_name_length, validate_timeout_relationships,
    };
    use std::collections::HashMap;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test utilities
    fn create_temp_file(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    // SystemConfig Tests
    #[test]
    fn test_system_config_complete() {
        let config_toml = r#"
[server]
listen = "0.0.0.0:8080"
worker_threads = 8
max_request_size = "2MB"
request_timeout = 60
shutdown_timeout = 600

[security]
allowed_ips = ["10.0.0.0/8", "192.168.1.0/24"]
rate_limit = 200

[storage]
data_dir = "/var/lib/test-receiver"

[storage.retention]
successful_deploys = 200
failed_deploys = 100

[logging]
level = "debug"
format = "pretty"
directory = "/var/log/test-receiver"

[limits]
max_concurrent_total = 20
max_concurrent_per_service = 2
deployment_timeout = 3600
command_timeout = 600
lock_timeout = 120

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"
status_cache_seconds = 15

[notifications]
enabled = true

[notifications.webhook]
on_failure = "https://hooks.slack.com/failure"
on_success = "https://hooks.slack.com/success"
timeout = 10

[secrets]
source = ["env", "file"]
sources_priority = ["file", "env", "systemd"]
secrets_file = "/etc/test/secrets"
required_secrets = ["hmac_key", "webhook_secret"]
reload_interval = 600
secret_prefix = "TEST_"
        "#;

        let config: SystemConfig = toml::from_str(config_toml).unwrap();

        // Server config
        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert_eq!(config.server.worker_threads, 8);
        assert_eq!(config.server.max_request_size, "2MB");
        assert_eq!(config.server.request_timeout, 60);
        assert_eq!(config.server.shutdown_timeout, 600);

        // Security config
        assert_eq!(
            config.security.allowed_ips,
            vec!["10.0.0.0/8", "192.168.1.0/24"]
        );
        assert_eq!(config.security.rate_limit, 200);

        // Storage config
        assert_eq!(config.storage.data_dir, "/var/lib/test-receiver");
        assert_eq!(config.storage.retention.successful_deploys, 200);
        assert_eq!(config.storage.retention.failed_deploys, 100);

        // Logging config
        assert_eq!(config.logging.level, "debug");
        assert_eq!(config.logging.format, "pretty");
        assert_eq!(config.logging.directory, "/var/log/test-receiver");

        // Limits config
        assert_eq!(config.limits.max_concurrent_total, 20);
        assert_eq!(config.limits.max_concurrent_per_service, 2);
        assert_eq!(config.limits.deployment_timeout, 3600);
        assert_eq!(config.limits.command_timeout, 600);
        assert_eq!(config.limits.lock_timeout, 120);

        // Monitoring config
        assert!(config.monitoring.metrics_enabled);
        assert_eq!(config.monitoring.metrics_path, "/metrics");
        assert_eq!(config.monitoring.health_path, "/health");
        assert_eq!(config.monitoring.status_cache_seconds, 15);

        // Notifications config
        assert!(config.notifications.enabled);
        assert_eq!(
            config.notifications.webhook.on_failure,
            Some("https://hooks.slack.com/failure".to_string())
        );
        assert_eq!(
            config.notifications.webhook.on_success,
            Some("https://hooks.slack.com/success".to_string())
        );
        assert_eq!(config.notifications.webhook.timeout, 10);

        // Secrets config
        match config.secrets.source {
            SecretSource::Multiple(sources) => {
                assert_eq!(sources, vec!["env", "file"]);
            }
            _ => panic!("Expected multiple sources"),
        }
        assert_eq!(
            config.secrets.sources_priority,
            vec!["file", "env", "systemd"]
        );
        assert_eq!(config.secrets.secrets_file, "/etc/test/secrets");
        assert_eq!(
            config.secrets.required_secrets,
            vec!["hmac_key", "webhook_secret"]
        );
        assert_eq!(config.secrets.reload_interval, 600);
        assert_eq!(config.secrets.secret_prefix, "TEST_");
    }

    #[test]
    fn test_system_config_minimal() {
        let config_toml = r#"
[server]
listen = "127.0.0.1:8080"
        "#;

        let config: SystemConfig = toml::from_str(config_toml).unwrap();

        // Server config (only listen specified)
        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert_eq!(config.server.worker_threads, 4); // default
        assert_eq!(config.server.max_request_size, "1MB"); // default

        // All other configs should use defaults
        assert_eq!(config.security.rate_limit, 100); // default
        assert_eq!(config.storage.data_dir, "/var/lib/hookshot"); // default
        assert_eq!(config.logging.level, "info"); // default
        assert_eq!(config.limits.max_concurrent_total, 10); // default
        assert!(config.monitoring.metrics_enabled); // default
        assert!(!config.notifications.enabled); // default

        // Secrets defaults
        match config.secrets.source {
            SecretSource::Single(source) => {
                assert_eq!(source, "auto");
            }
            _ => panic!("Expected single source"),
        }
        assert_eq!(config.secrets.required_secrets, vec!["hmac_key"]);
    }

    #[test]
    fn test_secrets_config_polymorphic_source() {
        // Test string source
        let config_toml = r#"
source = "env"
        "#;

        let config: SecretsConfig = toml::from_str(config_toml).unwrap();
        match config.source {
            SecretSource::Single(source) => assert_eq!(source, "env"),
            _ => panic!("Expected single source"),
        }

        // Test array source
        let config_toml = r#"
source = ["systemd", "file", "env"]
        "#;

        let config: SecretsConfig = toml::from_str(config_toml).unwrap();
        match config.source {
            SecretSource::Multiple(sources) => {
                assert_eq!(sources, vec!["systemd", "file", "env"]);
            }
            _ => panic!("Expected multiple sources"),
        }
    }

    // ServicesConfig Tests
    #[test]
    fn test_services_config_complete() {
        let services_toml = r#"
[defaults]
working_dir = "/srv/apps"
command_timeout = 180
healthcheck_timeout = 90
rollback_enabled = true

[[service]]
name = "web-app"
description = "Frontend web application"
enabled = true
working_dir = "/srv/web-app"

[service.env]
NODE_ENV = "production"
PORT = "3000"
LOG_LEVEL = "info"

[service.security]
allowed_image_pattern = "^registry\\.local/web-app:(v\\d+\\.\\d+\\.\\d+|sha-[a-f0-9]{40})$"
allowed_env_overrides = ["LOG_LEVEL", "DEBUG", "FEATURE_FLAGS"]

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "run", "--rm", "--entrypoint=/bin/true", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "web-app.service"]
]
timeout = 300
retries = 1
critical = true

[service.healthcheck]
initial_delay = 10
interval = 5
max_attempts = 15
success_threshold = 2
commands = [
    ["curl", "-fsS", "http://127.0.0.1:3000/health"],
    ["systemctl", "--user", "is-active", "web-app.service"]
]

[service.rollback]
enabled = true
max_attempts = 3
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "web-app.service"]
]

[service.hooks]
pre_deploy = [["echo", "Starting deployment"]]
post_deploy = [["echo", "Deployment completed"]]
on_failure = [["echo", "Deployment failed"]]

[service.templates]
backup_tag = "rollback-{{DEPLOY_ID}}"
container_name = "{{SERVICE}}-{{TIMESTAMP}}"
        "#;

        let config: ServicesConfig = toml::from_str(services_toml).unwrap();

        // Defaults
        assert_eq!(config.defaults.working_dir, "/srv/apps");
        assert_eq!(config.defaults.command_timeout, 180);
        assert_eq!(config.defaults.healthcheck_timeout, 90);
        assert!(config.defaults.rollback_enabled);

        // Service
        assert_eq!(config.service.len(), 1);
        let service = &config.service[0];

        assert_eq!(service.name, "web-app");
        assert_eq!(
            service.description,
            Some("Frontend web application".to_string())
        );
        assert!(service.enabled);
        assert_eq!(service.working_dir, Some("/srv/web-app".to_string()));

        // Environment
        assert_eq!(service.env.get("NODE_ENV"), Some(&"production".to_string()));
        assert_eq!(service.env.get("PORT"), Some(&"3000".to_string()));
        assert_eq!(service.env.get("LOG_LEVEL"), Some(&"info".to_string()));

        // Security
        assert_eq!(
            service.security.allowed_image_pattern,
            "^registry\\.local/web-app:(v\\d+\\.\\d+\\.\\d+|sha-[a-f0-9]{40})$"
        );
        assert_eq!(
            service.security.allowed_env_overrides,
            vec!["LOG_LEVEL", "DEBUG", "FEATURE_FLAGS"]
        );

        // Deploy
        assert_eq!(service.deploy.commands.len(), 3);
        assert_eq!(
            service.deploy.commands[0],
            vec!["podman", "pull", "{{IMAGE}}"]
        );
        assert_eq!(service.deploy.timeout, Some(300));
        assert_eq!(service.deploy.retries, 1);
        assert!(service.deploy.critical);

        // Healthcheck
        assert_eq!(service.healthcheck.initial_delay, 10);
        assert_eq!(service.healthcheck.interval, 5);
        assert_eq!(service.healthcheck.max_attempts, 15);
        assert_eq!(service.healthcheck.success_threshold, 2);
        assert_eq!(service.healthcheck.commands.len(), 2);

        // Rollback
        assert!(service.rollback.enabled);
        assert_eq!(service.rollback.max_attempts, 3);
        assert_eq!(service.rollback.commands.len(), 2);

        // Hooks
        assert_eq!(service.hooks.pre_deploy.len(), 1);
        assert_eq!(service.hooks.post_deploy.len(), 1);
        assert_eq!(service.hooks.on_failure.len(), 1);

        // Templates
        assert_eq!(
            service.templates.get("backup_tag"),
            Some(&"rollback-{{DEPLOY_ID}}".to_string())
        );
        assert_eq!(
            service.templates.get("container_name"),
            Some(&"{{SERVICE}}-{{TIMESTAMP}}".to_string())
        );
    }

    #[test]
    fn test_services_config_minimal() {
        let services_toml = r#"
[[service]]
name = "simple-app"

[service.security]
allowed_image_pattern = "^localhost/simple-app:.*$"

[service.deploy]
commands = [["echo", "deploying"]]
        "#;

        let config: ServicesConfig = toml::from_str(services_toml).unwrap();

        // Defaults should be applied
        assert_eq!(config.defaults.working_dir, "/srv");
        assert_eq!(config.defaults.command_timeout, 300);

        let service = &config.service[0];
        assert_eq!(service.name, "simple-app");
        assert_eq!(service.description, None);
        assert!(service.enabled); // default
        assert_eq!(service.working_dir, None);
        assert!(service.env.is_empty()); // default

        // Required fields
        assert_eq!(
            service.security.allowed_image_pattern,
            "^localhost/simple-app:.*$"
        );
        assert_eq!(service.deploy.commands, vec![vec!["echo", "deploying"]]);

        // Defaults applied
        assert_eq!(service.healthcheck.initial_delay, 5);
        assert!(service.rollback.enabled);
        assert!(service.hooks.pre_deploy.is_empty());
    }

    #[test]
    fn test_services_config_multiple_services() {
        let services_toml = r#"
[[service]]
name = "frontend"

[service.security]
allowed_image_pattern = "^registry/frontend:.*$"

[service.deploy]
commands = [["echo", "deploying frontend"]]

[[service]]
name = "backend"

[service.security]
allowed_image_pattern = "^registry/backend:.*$"

[service.deploy]
commands = [["echo", "deploying backend"]]
        "#;

        let config: ServicesConfig = toml::from_str(services_toml).unwrap();
        assert_eq!(config.service.len(), 2);
        assert_eq!(config.service[0].name, "frontend");
        assert_eq!(config.service[1].name, "backend");
    }

    // File Loading Tests
    #[test]
    fn test_load_valid_system_config() {
        let config_toml = r#"
[server]
listen = "127.0.0.1:8080"
worker_threads = 4

[security]
rate_limit = 100
        "#;

        let file = create_temp_file(config_toml);
        let config = SystemConfig::load_from_file(file.path()).unwrap();

        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert_eq!(config.server.worker_threads, 4);
        assert_eq!(config.security.rate_limit, 100);
    }

    #[test]
    fn test_load_missing_file() {
        let result = SystemConfig::load_from_file("/nonexistent/path/config.toml");
        match result {
            Err(crate::types::Error::Config(crate::types::ConfigError::FileNotFound { path })) => {
                assert_eq!(path, "/nonexistent/path/config.toml");
            }
            _ => panic!("Expected FileNotFound error"),
        }
    }

    #[test]
    fn test_load_invalid_toml() {
        let invalid_toml = r#"
[server
listen = "127.0.0.1:8080"  // missing closing bracket
        "#;

        let file = create_temp_file(invalid_toml);
        let result = SystemConfig::load_from_file(file.path());

        match result {
            Err(crate::types::Error::Config(crate::types::ConfigError::ParseError(_))) => {
                // Expected parse error
            }
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_load_invalid_structure() {
        let config_toml = r#"
[server]
listen = "127.0.0.1:8080"
worker_threads = "not_a_number"
        "#;

        let file = create_temp_file(config_toml);
        let result = SystemConfig::load_from_file(file.path());

        match result {
            Err(crate::types::Error::Config(crate::types::ConfigError::ParseError(_))) => {
                // Expected parse error due to type mismatch
            }
            _ => panic!("Expected ParseError for type mismatch"),
        }
    }

    // Validation Tests
    #[tokio::test]
    async fn test_system_config_validation_success() {
        let mut config = SystemConfig {
            server: ServerConfig {
                listen: "127.0.0.1:8080".to_string(),
                worker_threads: 4,
                max_request_size: "1MB".to_string(),
                request_timeout: 30,
                shutdown_timeout: 300,
            },
            ..Default::default()
        };
        // Use /tmp for paths to avoid validation errors
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        assert!(config.validate().await.is_ok());
    }

    #[tokio::test]
    async fn test_system_config_validation_zero_worker_threads() {
        let mut config = SystemConfig {
            server: ServerConfig {
                listen: "127.0.0.1:8080".to_string(),
                worker_threads: 0,
                max_request_size: "1MB".to_string(),
                request_timeout: 30,
                shutdown_timeout: 300,
            },
            ..Default::default()
        };
        // Use /tmp for paths to avoid validation errors
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, message }) => {
                assert_eq!(field, "server.worker_threads");
                assert!(message.contains("below minimum"));
            }
            _ => panic!("Expected validation error for zero worker threads"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_success() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();
        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        assert!(config.validate().await.is_ok());
    }

    #[tokio::test]
    async fn test_services_config_validation_empty_name() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();
        config.service.push(ServiceConfig {
            name: "".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, message }) => {
                assert_eq!(field, "service[0].name");
                assert_eq!(message, "service name cannot be empty");
            }
            _ => panic!("Expected validation error for empty service name"),
        }
    }

    // Default Value Tests
    #[test]
    fn test_all_default_functions() {
        let config = SystemConfig::default();
        assert_eq!(config.server.listen, "127.0.0.1:8080");
        assert_eq!(config.server.worker_threads, 4);
        assert_eq!(config.server.max_request_size, "1MB");
        assert_eq!(config.server.request_timeout, 30);
        assert_eq!(config.server.shutdown_timeout, 300);
        assert_eq!(config.security.rate_limit, 100);
        assert_eq!(config.storage.data_dir, "/var/lib/hookshot");
        assert_eq!(config.storage.retention.successful_deploys, 100);
        assert_eq!(config.storage.retention.failed_deploys, 50);
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.logging.format, "json");
        assert_eq!(config.logging.directory, "/var/log/hookshot");
        assert_eq!(config.limits.max_concurrent_total, 10);
        assert_eq!(config.limits.max_concurrent_per_service, 1);
        assert_eq!(config.limits.deployment_timeout, 1800);
        assert_eq!(config.limits.command_timeout, 300);
        assert_eq!(config.limits.lock_timeout, 60);
        assert!(config.monitoring.metrics_enabled);
        assert_eq!(config.monitoring.metrics_path, "/metrics");
        assert_eq!(config.monitoring.health_path, "/health");
        assert_eq!(config.monitoring.status_cache_seconds, 10);
        assert!(!config.notifications.enabled);
        assert_eq!(config.notifications.webhook.timeout, 5);

        let services_config = ServicesConfig::default();
        assert_eq!(services_config.defaults.working_dir, "/srv");
        assert_eq!(services_config.defaults.healthcheck_timeout, 60);
        assert!(services_config.defaults.rollback_enabled);
        assert!(services_config.service.is_empty());

        let secrets_config = SecretsConfig::default();
        match secrets_config.source {
            SecretSource::Single(source) => assert_eq!(source, "auto"),
            _ => panic!("Expected single source"),
        }
        assert_eq!(secrets_config.required_secrets, vec!["hmac_key"]);
        assert_eq!(secrets_config.reload_interval, 300);
        assert_eq!(secrets_config.secret_prefix, "DEPLOY_RECEIVER_");
    }

    #[test]
    fn test_default_trait_implementations() {
        let system_config = SystemConfig::default();
        assert_eq!(system_config.server.listen, "127.0.0.1:8080");
        assert_eq!(system_config.security.rate_limit, 100);
        assert_eq!(system_config.storage.data_dir, "/var/lib/hookshot");

        let services_config = ServicesConfig::default();
        assert_eq!(services_config.defaults.working_dir, "/srv");
        assert!(services_config.service.is_empty());

        let secrets_config = SecretsConfig::default();
        match secrets_config.source {
            SecretSource::Single(source) => assert_eq!(source, "auto"),
            _ => panic!("Expected single source"),
        }
        assert_eq!(secrets_config.required_secrets, vec!["hmac_key"]);
    }

    #[test]
    fn test_serde_default_application() {
        // Test that missing optional fields get default values
        let minimal_toml = r#"
[server]
listen = "127.0.0.1:8080"
        "#;

        let config: SystemConfig = toml::from_str(minimal_toml).unwrap();

        // These fields weren't specified, so should get defaults
        assert_eq!(config.server.worker_threads, 4);
        assert_eq!(config.server.max_request_size, "1MB");
        assert_eq!(config.security.rate_limit, 100);
        assert_eq!(config.storage.data_dir, "/var/lib/hookshot");
        assert_eq!(config.logging.level, "info");
        assert_eq!(config.limits.max_concurrent_total, 10);
        assert!(config.monitoring.metrics_enabled);
        assert!(!config.notifications.enabled);
    }

    // Validation Helper Tests
    #[test]
    fn test_validate_listen_address() {
        assert!(validate_listen_address("127.0.0.1:8080").is_ok());
        assert!(validate_listen_address("0.0.0.0:80").is_ok());
        assert!(validate_listen_address("[::1]:8080").is_ok());

        assert!(validate_listen_address("invalid").is_err());
        assert!(validate_listen_address("127.0.0.1").is_err());
        assert!(validate_listen_address("127.0.0.1:99999").is_err());
        assert!(validate_listen_address(":8080").is_err());
        assert!(validate_listen_address("localhost:3000").is_err()); // hostname resolution not supported in SocketAddr parsing
    }

    #[test]
    fn test_validate_regex_pattern() {
        assert!(validate_regex_pattern("^test.*$", "test_field").is_ok());
        assert!(validate_regex_pattern(".*", "test_field").is_ok());
        assert!(validate_regex_pattern("\\d+", "test_field").is_ok());

        assert!(validate_regex_pattern("[", "test_field").is_err());
        assert!(validate_regex_pattern("(?P<invalid", "test_field").is_err());
        assert!(validate_regex_pattern("*", "test_field").is_err());
    }

    #[test]
    fn test_validate_positive_timeout() {
        assert!(validate_positive_timeout(1, "test_field").is_ok());
        assert!(validate_positive_timeout(60, "test_field").is_ok());
        assert!(validate_positive_timeout(3600, "test_field").is_ok());

        assert!(validate_positive_timeout(0, "test_field").is_err());
    }

    #[test]
    fn test_validate_concurrency_limits() {
        assert!(validate_concurrency_limits(5, "test_field", 1, 10).is_ok());
        assert!(validate_concurrency_limits(1, "test_field", 1, 10).is_ok());
        assert!(validate_concurrency_limits(10, "test_field", 1, 10).is_ok());

        assert!(validate_concurrency_limits(0, "test_field", 1, 10).is_err());
        assert!(validate_concurrency_limits(11, "test_field", 1, 10).is_err());
    }

    // Enhanced SystemConfig Validation Tests
    #[tokio::test]
    async fn test_system_config_enhanced_validation_success() {
        let mut config = SystemConfig::default();
        // Use /tmp which should exist and be writable
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        assert!(config.validate().await.is_ok());
    }

    #[tokio::test]
    async fn test_system_config_validation_invalid_listen_address() {
        let mut config = SystemConfig::default();
        config.server.listen = "invalid-address".to_string();
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "server.listen");
            }
            _ => panic!("Expected validation error for invalid listen address"),
        }
    }

    #[tokio::test]
    async fn test_system_config_validation_invalid_cidr() {
        let mut config = SystemConfig::default();
        config.security.allowed_ips = vec!["invalid-cidr".to_string()];
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "security.allowed_ips[0]");
            }
            _ => panic!("Expected validation error for invalid CIDR"),
        }
    }

    #[tokio::test]
    async fn test_system_config_validation_zero_timeout() {
        let mut config = SystemConfig::default();
        config.server.request_timeout = 0;
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "server.request_timeout");
            }
            _ => panic!("Expected validation error for zero timeout"),
        }
    }

    #[tokio::test]
    async fn test_system_config_validation_excessive_worker_threads() {
        let mut config = SystemConfig::default();
        config.server.worker_threads = 2000; // Exceeds max of 16
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "server.worker_threads");
            }
            _ => panic!("Expected validation error for excessive worker threads"),
        }
    }

    #[tokio::test]
    async fn test_system_config_validation_invalid_log_level() {
        let mut config = SystemConfig::default();
        config.logging.level = "invalid".to_string();
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "logging.level");
            }
            _ => panic!("Expected validation error for invalid log level"),
        }
    }

    #[tokio::test]
    async fn test_system_config_validation_invalid_log_format() {
        let mut config = SystemConfig::default();
        config.logging.format = "invalid".to_string();
        config.storage.data_dir = "/tmp".to_string();
        config.logging.directory = "/tmp".to_string();

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "logging.format");
            }
            _ => panic!("Expected validation error for invalid log format"),
        }
    }

    // Enhanced ServicesConfig Validation Tests
    #[tokio::test]
    async fn test_services_config_enhanced_validation_success() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        assert!(config.validate().await.is_ok());
    }

    #[tokio::test]
    async fn test_services_config_validation_duplicate_names() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        // Add two services with the same name
        for _ in 0..2 {
            config.service.push(ServiceConfig {
                name: "duplicate".to_string(),
                description: None,
                enabled: true,
                working_dir: None,
                env: HashMap::new(),
                security: ServiceSecurity {
                    allowed_image_pattern: "^test:.*$".to_string(),
                    allowed_env_overrides: vec![],
                },
                deploy: ServiceDeploy {
                    commands: vec![vec!["echo".to_string(), "test".to_string()]],
                    timeout: None,
                    retries: 0,
                    critical: true,
                },
                healthcheck: ServiceHealthcheck::default(),
                rollback: ServiceRollback::default(),
                hooks: ServiceHooks::default(),
                templates: HashMap::new(),
                github: None,
            });
        }

        match config.validate().await {
            Err(crate::types::Error::Validation { field, message }) => {
                assert_eq!(field, "service.name");
                assert!(message.contains("duplicate"));
            }
            _ => panic!("Expected validation error for duplicate service names"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_invalid_service_name_chars() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "invalid@name".to_string(), // Contains @ which is not allowed
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, message }) => {
                assert_eq!(field, "service[0].name");
                assert!(message.contains("invalid characters"));
            }
            _ => panic!("Expected validation error for invalid service name characters"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_invalid_regex() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "[invalid-regex".to_string(), // Invalid regex
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].security.allowed_image_pattern");
            }
            _ => panic!("Expected validation error for invalid regex"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_empty_deploy_commands() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![], // Empty commands
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].deploy.commands");
            }
            _ => panic!("Expected validation error for empty deploy commands"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_empty_command() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec![]], // Empty command array
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].deploy.commands[0]");
            }
            _ => panic!("Expected validation error for empty command"),
        }
    }

    #[tokio::test]
    async fn test_services_config_validation_success_threshold_exceeds_max_attempts() {
        let mut config = ServicesConfig::default();
        config.defaults.working_dir = "/tmp".to_string();

        config.service.push(ServiceConfig {
            name: "test-service".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: vec![],
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string(), "test".to_string()]],
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck {
                max_attempts: 5,
                success_threshold: 10, // Greater than max_attempts
                ..ServiceHealthcheck::default()
            },
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        });

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].healthcheck.success_threshold");
            }
            _ => panic!("Expected validation error for success_threshold > max_attempts"),
        }
    }

    // Enhanced validation tests for new helper functions

    #[test]
    fn test_parse_size_string() {
        // Valid sizes
        assert_eq!(parse_size_string("1000").unwrap(), 1000);
        assert_eq!(parse_size_string("1KB").unwrap(), 1024);
        assert_eq!(parse_size_string("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_string("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size_string("2KB").unwrap(), 2048);
        assert_eq!(parse_size_string("500MB").unwrap(), 500 * 1024 * 1024);

        // Case insensitive
        assert_eq!(parse_size_string("1kb").unwrap(), 1024);
        assert_eq!(parse_size_string("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_string("1gb").unwrap(), 1024 * 1024 * 1024);

        // Invalid formats
        assert!(parse_size_string("").is_err());
        assert!(parse_size_string("abc").is_err());
        assert!(parse_size_string("1TB").is_err()); // Not supported
        assert!(parse_size_string("-1KB").is_err()); // Negative
        assert!(parse_size_string("1.5MB").is_err()); // Decimal
    }

    #[test]
    fn test_validate_request_size() {
        // Valid sizes
        assert!(validate_request_size("1MB", "test_field").is_ok());
        assert!(validate_request_size("100MB", "test_field").is_ok());
        assert!(validate_request_size("1024", "test_field").is_ok());

        // Invalid sizes
        assert!(validate_request_size("0", "test_field").is_err());
        assert!(validate_request_size("2GB", "test_field").is_err()); // Too large
        assert!(validate_request_size("invalid", "test_field").is_err());
    }

    #[test]
    fn test_validate_secret_source() {
        // Valid sources
        assert!(
            validate_secret_source(&SecretSource::Single("env".to_string()), "test_field").is_ok()
        );
        assert!(
            validate_secret_source(&SecretSource::Single("file".to_string()), "test_field").is_ok()
        );
        assert!(
            validate_secret_source(&SecretSource::Single("auto".to_string()), "test_field").is_ok()
        );
        assert!(
            validate_secret_source(&SecretSource::Single("systemd".to_string()), "test_field")
                .is_ok()
        );
        assert!(validate_secret_source(
            &SecretSource::Multiple(vec!["env".to_string(), "file".to_string()]),
            "test_field"
        )
        .is_ok());

        // Valid multiple sources
        let valid_sources = vec![
            SecretSource::Single("env".to_string()),
            SecretSource::Single("file".to_string()),
            SecretSource::Multiple(vec!["auto".to_string(), "systemd".to_string()]),
        ];

        for source in valid_sources {
            assert!(validate_secret_source(&source, "test_field").is_ok());
        }

        // Invalid sources
        assert!(
            validate_secret_source(&SecretSource::Single("invalid".to_string()), "test_field")
                .is_err()
        );
        assert!(validate_secret_source(
            &SecretSource::Multiple(vec!["env".to_string(), "invalid".to_string()]),
            "test_field"
        )
        .is_err());
    }

    #[test]
    fn test_validate_array_size() {
        // Valid arrays
        let small_array = vec![1, 2, 3];
        assert!(validate_array_size(&small_array, "test_field", 10).is_ok());

        let empty_array: Vec<i32> = vec![];
        assert!(validate_array_size(&empty_array, "test_field", 10).is_ok());

        // Invalid array (too large)
        let large_array = vec![1; 15];
        assert!(validate_array_size(&large_array, "test_field", 10).is_err());

        // Edge case - exactly at limit
        let limit_array = vec![1; 10];
        assert!(validate_array_size(&limit_array, "test_field", 10).is_ok());
    }

    #[test]
    fn test_validate_network_cidr() {
        // Valid network CIDRs
        assert!(validate_network_cidr("192.168.1.0/24", "test_field").is_ok());
        assert!(validate_network_cidr("10.0.0.0/8", "test_field").is_ok());
        assert!(validate_network_cidr("172.16.0.0/12", "test_field").is_ok());
        assert!(validate_network_cidr("2001:db8::/32", "test_field").is_ok());

        // Invalid host addresses (not network addresses)
        assert!(validate_network_cidr("192.168.1.1/24", "test_field").is_err());
        assert!(validate_network_cidr("10.0.0.1/8", "test_field").is_err());
        assert!(validate_network_cidr("172.16.0.5/12", "test_field").is_err());

        // Invalid CIDR formats
        assert!(validate_network_cidr("192.168.1.0", "test_field").is_err());
        assert!(validate_network_cidr("192.168.1.0/", "test_field").is_err());
        assert!(validate_network_cidr("invalid", "test_field").is_err());
        assert!(validate_network_cidr("192.168.1.0/33", "test_field").is_err());
    }

    #[test]
    fn test_validate_service_name_length() {
        // Valid names
        assert!(validate_service_name_length("short", "test_field").is_ok());
        assert!(
            validate_service_name_length("exactly-32-character-service-nm", "test_field").is_ok()
        );

        // Invalid names (too long)
        assert!(validate_service_name_length(
            "this-service-name-is-way-too-long-and-exceeds-the-32-character-limit",
            "test_field"
        )
        .is_err());

        // Edge case - empty name (should be caught by other validation)
        assert!(validate_service_name_length("", "test_field").is_err());
    }

    #[tokio::test]
    async fn test_system_config_enhanced_validation() {
        // Test worker_threads range (should be 1-16, not 1-1024)
        let config = SystemConfig {
            server: ServerConfig {
                listen: "127.0.0.1:8080".to_string(),
                worker_threads: 20, // Too high
                max_request_size: "1MB".to_string(),
                request_timeout: 30,
                shutdown_timeout: 10,
            },
            ..SystemConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "server.worker_threads");
            }
            _ => panic!("Expected validation error for worker_threads > 16"),
        }

        // Test max_request_size validation
        let config = SystemConfig {
            server: ServerConfig {
                listen: "127.0.0.1:8080".to_string(),
                worker_threads: 4,
                max_request_size: "3GB".to_string(), // Too large
                request_timeout: 30,
                shutdown_timeout: 10,
            },
            ..SystemConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "server.max_request_size");
            }
            _ => panic!("Expected validation error for max_request_size > 1GB"),
        }

        // Test enhanced CIDR validation (host vs network)
        let config = SystemConfig {
            security: SecurityConfig {
                allowed_ips: vec!["192.168.1.1/24".to_string()], // Host address, not network
                ..SecurityConfig::default()
            },
            ..SystemConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "security.allowed_ips[0]");
            }
            _ => panic!("Expected validation error for host CIDR instead of network CIDR"),
        }

        // Test array size limits for security
        let large_ip_list: Vec<String> = (0..105).map(|i| format!("10.0.{}.0/24", i)).collect();
        let config = SystemConfig {
            security: SecurityConfig {
                allowed_ips: large_ip_list, // Too many IPs
                ..SecurityConfig::default()
            },
            ..SystemConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "security.allowed_ips");
            }
            _ => panic!("Expected validation error for too many allowed IPs"),
        }
    }

    #[tokio::test]
    async fn test_services_config_enhanced_validation() {
        // Test service name length validation
        let config = ServicesConfig {
            service: vec![ServiceConfig {
                name: "this-service-name-is-way-too-long-and-exceeds-the-32-character-limit"
                    .to_string(),
                description: None,
                enabled: true,
                working_dir: None,
                env: HashMap::new(),
                security: ServiceSecurity {
                    allowed_image_pattern: "^test:.*$".to_string(),
                    allowed_env_overrides: Vec::new(),
                },
                deploy: ServiceDeploy {
                    commands: vec![vec!["echo".to_string(), "test".to_string()]],
                    timeout: None,
                    retries: 0,
                    critical: false,
                },
                healthcheck: ServiceHealthcheck {
                    initial_delay: 5,
                    interval: 30,
                    max_attempts: 10,
                    success_threshold: 2,
                    timeout: None,
                    commands: Vec::new(),
                },
                rollback: ServiceRollback {
                    enabled: true,
                    max_attempts: 3,
                    timeout: None,
                    commands: Vec::new(),
                },
                hooks: ServiceHooks::default(),
                templates: HashMap::new(),
                github: None,
            }],
            ..ServicesConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].name");
            }
            _ => panic!("Expected validation error for service name too long"),
        }

        // Test array size limits for service arrays
        let large_commands: Vec<Vec<String>> = (0..25).map(|i| vec![format!("cmd{}", i)]).collect();
        let config = ServicesConfig {
            service: vec![ServiceConfig {
                name: "test".to_string(),
                description: None,
                enabled: true,
                working_dir: None,
                env: HashMap::new(),
                security: ServiceSecurity {
                    allowed_image_pattern: "^test:.*$".to_string(),
                    allowed_env_overrides: Vec::new(),
                },
                deploy: ServiceDeploy {
                    commands: large_commands, // Too many commands
                    timeout: None,
                    retries: 0,
                    critical: false,
                },
                healthcheck: ServiceHealthcheck {
                    initial_delay: 5,
                    interval: 30,
                    max_attempts: 10,
                    success_threshold: 2,
                    timeout: None,
                    commands: Vec::new(),
                },
                rollback: ServiceRollback {
                    enabled: true,
                    max_attempts: 3,
                    timeout: None,
                    commands: Vec::new(),
                },
                hooks: ServiceHooks::default(),
                templates: HashMap::new(),
                github: None,
            }],
            ..ServicesConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].deploy.commands");
            }
            _ => panic!("Expected validation error for too many deploy commands"),
        }

        // Test environment overrides array size limit
        let large_env_overrides: Vec<String> = (0..55).map(|i| format!("VAR{}", i)).collect();
        let config = ServicesConfig {
            service: vec![ServiceConfig {
                name: "test".to_string(),
                description: None,
                enabled: true,
                working_dir: None,
                env: HashMap::new(),
                security: ServiceSecurity {
                    allowed_image_pattern: "^test:.*$".to_string(),
                    allowed_env_overrides: large_env_overrides, // Too many env vars
                },
                deploy: ServiceDeploy {
                    commands: vec![vec!["echo".to_string(), "test".to_string()]],
                    timeout: None,
                    retries: 0,
                    critical: false,
                },
                healthcheck: ServiceHealthcheck {
                    initial_delay: 5,
                    interval: 30,
                    max_attempts: 10,
                    success_threshold: 2,
                    timeout: None,
                    commands: Vec::new(),
                },
                rollback: ServiceRollback {
                    enabled: true,
                    max_attempts: 3,
                    timeout: None,
                    commands: Vec::new(),
                },
                hooks: ServiceHooks::default(),
                templates: HashMap::new(),
                github: None,
            }],
            ..ServicesConfig::default()
        };

        match config.validate().await {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].security.allowed_env_overrides");
            }
            _ => panic!("Expected validation error for too many environment overrides"),
        }
    }

    #[test]
    fn test_validate_timeout_relationships() {
        // Test valid timeout relationships
        let service = ServiceConfig {
            name: "test".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: Vec::new(),
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string()]],
                timeout: Some(300),
                retries: 0,
                critical: false,
            },
            healthcheck: ServiceHealthcheck {
                initial_delay: 5,
                interval: 30,
                max_attempts: 10,
                success_threshold: 2,
                timeout: Some(45), // Less than 2x interval (60)
                commands: Vec::new(),
            },
            rollback: ServiceRollback {
                enabled: true,
                max_attempts: 3,
                timeout: Some(120),
                commands: Vec::new(),
            },
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        };

        assert!(validate_timeout_relationships(&service, 0).is_ok());

        // Test invalid relationship: healthcheck.timeout > 2x interval
        let service = ServiceConfig {
            name: "test".to_string(),
            description: None,
            enabled: true,
            working_dir: None,
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: "^test:.*$".to_string(),
                allowed_env_overrides: Vec::new(),
            },
            deploy: ServiceDeploy {
                commands: vec![vec!["echo".to_string()]],
                timeout: None,
                retries: 0,
                critical: false,
            },
            healthcheck: ServiceHealthcheck {
                initial_delay: 5,
                interval: 30,
                max_attempts: 10,
                success_threshold: 2,
                timeout: Some(120), // Greater than 2x interval (60)
                commands: Vec::new(),
            },
            rollback: ServiceRollback {
                enabled: true,
                max_attempts: 3,
                timeout: None,
                commands: Vec::new(),
            },
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        };

        match validate_timeout_relationships(&service, 0) {
            Err(crate::types::Error::Validation { field, .. }) => {
                assert_eq!(field, "service[0].healthcheck.timeout");
            }
            _ => panic!("Expected validation error for healthcheck timeout > 2x interval"),
        }
    }
}
