use regex::Regex;
use std::net::{IpAddr, SocketAddr};

use super::types::{SecretSource, ServiceConfig, ServicesConfig, SystemConfig};
use crate::types::Result;

// Validation helper functions

/// Validate listen address format (host:port)
pub(crate) fn validate_listen_address(addr: &str) -> Result<()> {
    addr.parse::<SocketAddr>()
        .map_err(|_| crate::types::Error::Validation {
            field: "server.listen".to_string(),
            message: format!("Invalid listen address format '{}'. Expected format: 'host:port' (e.g., '127.0.0.1:8080')", addr),
        })?;
    Ok(())
}

/// Validate regex pattern
pub(crate) fn validate_regex_pattern(pattern: &str, field: &str) -> Result<()> {
    Regex::new(pattern).map_err(|e| crate::types::Error::Validation {
        field: field.to_string(),
        message: format!("Invalid regex pattern '{}': {}", pattern, e),
    })?;
    Ok(())
}

/// Validate path accessibility
async fn validate_path_accessible(path: &str, field: &str, check_writable: bool) -> Result<()> {
    // Check if path exists
    if !tokio::fs::try_exists(path)
        .await
        .map_err(|e| crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Cannot access path '{}': {}", path, e),
        })?
    {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Path '{}' does not exist", path),
        });
    }

    // Check if it's a directory
    let metadata =
        tokio::fs::metadata(path)
            .await
            .map_err(|e| crate::types::Error::Validation {
                field: field.to_string(),
                message: format!("Cannot read metadata for path '{}': {}", path, e),
            })?;

    if !metadata.is_dir() {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Path '{}' is not a directory", path),
        });
    }

    // Check write permissions if required
    if check_writable {
        // Try to create a temporary file to test write permissions
        let test_file = format!("{}/._test_write_{}", path, std::process::id());
        match tokio::fs::File::create(&test_file).await {
            Ok(_) => {
                // Clean up test file
                let _ = tokio::fs::remove_file(&test_file).await;
            }
            Err(e) => {
                return Err(crate::types::Error::Validation {
                    field: field.to_string(),
                    message: format!("Path '{}' is not writable: {}", path, e),
                });
            }
        }
    }

    Ok(())
}

/// Validate positive timeout value
pub(crate) fn validate_positive_timeout(value: u64, field: &str) -> Result<()> {
    if value == 0 {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: "Timeout must be greater than 0".to_string(),
        });
    }
    Ok(())
}

/// Validate concurrency limits
pub(crate) fn validate_concurrency_limits(
    value: u32,
    field: &str,
    min: u32,
    max: u32,
) -> Result<()> {
    if value < min {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Value {} is below minimum allowed value {}", value, min),
        });
    }
    if value > max {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Value {} exceeds maximum allowed value {}", value, max),
        });
    }
    Ok(())
}

/// Parse size string with units (KB, MB, GB) into bytes
pub(crate) fn parse_size_string(size: &str) -> Result<u64> {
    let size = size.trim().to_uppercase();

    if size.ends_with("KB") {
        let number = size.strip_suffix("KB").unwrap().trim();
        let bytes = number
            .parse::<u64>()
            .map_err(|_| crate::types::Error::Validation {
                field: "size".to_string(),
                message: format!("Invalid number in size '{}'", size),
            })?;
        Ok(bytes * 1024)
    } else if size.ends_with("MB") {
        let number = size.strip_suffix("MB").unwrap().trim();
        let bytes = number
            .parse::<u64>()
            .map_err(|_| crate::types::Error::Validation {
                field: "size".to_string(),
                message: format!("Invalid number in size '{}'", size),
            })?;
        Ok(bytes * 1024 * 1024)
    } else if size.ends_with("GB") {
        let number = size.strip_suffix("GB").unwrap().trim();
        let bytes = number
            .parse::<u64>()
            .map_err(|_| crate::types::Error::Validation {
                field: "size".to_string(),
                message: format!("Invalid number in size '{}'", size),
            })?;
        Ok(bytes * 1024 * 1024 * 1024)
    } else {
        // Try parsing as plain bytes
        size.parse::<u64>()
            .map_err(|_| crate::types::Error::Validation {
                field: "size".to_string(),
                message: format!("Invalid size format '{}'. Expected format: number + unit (KB/MB/GB) or plain bytes", size),
            })
    }
}

/// Validate request size string and ensure reasonable limits
pub(crate) fn validate_request_size(size: &str, field: &str) -> Result<()> {
    let bytes = parse_size_string(size).map_err(|mut e| {
        if let crate::types::Error::Validation {
            field: ref mut field_ref,
            ..
        } = e
        {
            *field_ref = field.to_string();
        }
        e
    })?;

    // Minimum 1KB, maximum 100MB to prevent DoS
    const MIN_SIZE: u64 = 1024; // 1KB
    const MAX_SIZE: u64 = 100 * 1024 * 1024; // 100MB

    if bytes < MIN_SIZE {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Request size {} bytes is below minimum {} (1KB)",
                bytes, MIN_SIZE
            ),
        });
    }

    if bytes > MAX_SIZE {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Request size {} bytes exceeds maximum {} (100MB)",
                bytes, MAX_SIZE
            ),
        });
    }

    Ok(())
}

/// Validate secret source values
pub(crate) fn validate_secret_source(source: &SecretSource, field: &str) -> Result<()> {
    const VALID_SOURCES: &[&str] = &["auto", "env", "file", "systemd"];

    match source {
        SecretSource::Single(s) => {
            if !VALID_SOURCES.contains(&s.as_str()) {
                return Err(crate::types::Error::Validation {
                    field: field.to_string(),
                    message: format!(
                        "Invalid secret source '{}'. Must be one of: {}",
                        s,
                        VALID_SOURCES.join(", ")
                    ),
                });
            }
        }
        SecretSource::Multiple(sources) => {
            for (i, s) in sources.iter().enumerate() {
                if !VALID_SOURCES.contains(&s.as_str()) {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}[{}]", field, i),
                        message: format!(
                            "Invalid secret source '{}'. Must be one of: {}",
                            s,
                            VALID_SOURCES.join(", ")
                        ),
                    });
                }
            }
        }
    }

    Ok(())
}

/// Validate array size to prevent DoS
pub(crate) fn validate_array_size<T>(arr: &[T], field: &str, max_size: usize) -> Result<()> {
    if arr.len() > max_size {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Array size {} exceeds maximum allowed size {}",
                arr.len(),
                max_size
            ),
        });
    }
    Ok(())
}

/// Enhanced CIDR validation that checks if IP is a network address
pub(crate) fn validate_network_cidr(cidr: &str, field: &str) -> Result<()> {
    if cidr.is_empty() {
        return Ok(()); // Empty is valid (means no restriction)
    }

    // Parse CIDR notation
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Invalid CIDR notation '{}'. Expected format: 'IP/prefix' (e.g., '192.168.1.0/24')",
                cidr
            ),
        });
    }

    // Validate IP address
    let ip: IpAddr = parts[0]
        .parse()
        .map_err(|_| crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Invalid IP address '{}' in CIDR '{}'", parts[0], cidr),
        })?;

    // Validate prefix length
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Invalid prefix length '{}' in CIDR '{}'", parts[1], cidr),
        })?;

    // Check prefix length bounds based on IP version
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Prefix length {} exceeds maximum {} for IP version in CIDR '{}'",
                prefix, max_prefix, cidr
            ),
        });
    }

    // For IPv4, validate that the IP is actually a network address
    if let IpAddr::V4(ipv4) = ip {
        if prefix < 32 {
            let ip_u32 = u32::from(ipv4);
            let network_mask = !((1u32 << (32 - prefix)) - 1);
            let network_addr = ip_u32 & network_mask;

            if ip_u32 != network_addr {
                let network_ip = std::net::Ipv4Addr::from(network_addr);
                return Err(crate::types::Error::Validation {
                    field: field.to_string(),
                    message: format!(
                        "IP '{}' is not a network address for prefix /{}. Did you mean '{}/{}'?",
                        ipv4, prefix, network_ip, prefix
                    ),
                });
            }
        }
    }

    // For IPv6, similar validation (simplified for now)
    if let IpAddr::V6(_ipv6) = ip {
        if prefix < 128 {
            // For IPv6, we could implement similar network validation
            // but it's more complex due to 128-bit addresses
            // For now, we'll accept any IPv6 address but this could be enhanced
        }
    }

    Ok(())
}

/// Validate timeout relationships for a service
pub(crate) fn validate_timeout_relationships(
    service: &ServiceConfig,
    service_index: usize,
) -> Result<()> {
    let service_prefix = format!("service[{}]", service_index);

    // Check healthcheck timeout relationships
    let healthcheck_total_time = service.healthcheck.initial_delay
        + (service.healthcheck.interval * service.healthcheck.max_attempts as u64);

    // Healthcheck interval should be reasonable relative to max attempts
    if service.healthcheck.interval * service.healthcheck.max_attempts as u64 > 3600 {
        return Err(crate::types::Error::Validation {
            field: format!("{}.healthcheck", service_prefix),
            message: format!("Total healthcheck time ({} seconds) exceeds reasonable limit (3600 seconds). Consider reducing interval or max_attempts",
                service.healthcheck.interval * service.healthcheck.max_attempts as u64),
        });
    }

    // Initial delay should not be larger than total healthcheck time
    if service.healthcheck.initial_delay > healthcheck_total_time / 2 {
        return Err(crate::types::Error::Validation {
            field: format!("{}.healthcheck.initial_delay", service_prefix),
            message: format!("Initial delay ({} seconds) is too large relative to total healthcheck time ({} seconds)",
                service.healthcheck.initial_delay, healthcheck_total_time),
        });
    }

    // If service has custom timeouts, validate they are reasonable
    if let Some(deploy_timeout) = service.deploy.timeout {
        if deploy_timeout > 7200 {
            // 2 hours max
            return Err(crate::types::Error::Validation {
                field: format!("{}.deploy.timeout", service_prefix),
                message: format!(
                    "Deploy timeout {} seconds exceeds reasonable maximum (7200 seconds)",
                    deploy_timeout
                ),
            });
        }
    }

    if let Some(healthcheck_timeout) = service.healthcheck.timeout {
        // Healthcheck timeout should be reasonable but can be longer than interval
        if healthcheck_timeout > service.healthcheck.interval * 2 {
            return Err(crate::types::Error::Validation {
                field: format!("{}.healthcheck.timeout", service_prefix),
                message: format!("Healthcheck timeout ({} seconds) is too large relative to interval ({} seconds). Should not exceed 2x interval",
                    healthcheck_timeout, service.healthcheck.interval),
            });
        }
    }

    Ok(())
}

/// Validate service name length (32 character limit per spec)
pub(crate) fn validate_service_name_length(name: &str, field: &str) -> Result<()> {
    const MAX_LENGTH: usize = 32;

    if name.is_empty() {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: "Service name cannot be empty".to_string(),
        });
    }

    if name.len() > MAX_LENGTH {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("Service name '{}' exceeds maximum length of {} characters (current: {} characters)",
                name, MAX_LENGTH, name.len()),
        });
    }

    Ok(())
}

/// Validate GitHub repository format (owner/repo)
pub(crate) fn validate_github_repo_format(repo: &str, field: &str) -> Result<()> {
    if repo.is_empty() {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: "GitHub repository cannot be empty".to_string(),
        });
    }

    let parts: Vec<&str> = repo.split('/').collect();
    if parts.len() != 2 {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "Invalid GitHub repository format '{}'. Expected format: 'owner/repo' (e.g., 'myorg/my-app')",
                repo
            ),
        });
    }

    let (owner, repo_name) = (parts[0], parts[1]);

    // Validate owner and repo name are not empty
    if owner.is_empty() || repo_name.is_empty() {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!("GitHub repository '{}' has empty owner or repo name", repo),
        });
    }

    // Validate characters (GitHub allows alphanumeric, hyphen, underscore, and period)
    let is_valid_char = |c: char| c.is_alphanumeric() || c == '-' || c == '_' || c == '.';

    if !owner.chars().all(is_valid_char) {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "GitHub repository owner '{}' contains invalid characters. Only alphanumeric, hyphen, underscore, and period are allowed",
                owner
            ),
        });
    }

    if !repo_name.chars().all(is_valid_char) {
        return Err(crate::types::Error::Validation {
            field: field.to_string(),
            message: format!(
                "GitHub repository name '{}' contains invalid characters. Only alphanumeric, hyphen, underscore, and period are allowed",
                repo_name
            ),
        });
    }

    Ok(())
}

impl SystemConfig {
    /// Validate the configuration
    pub async fn validate(&self) -> Result<()> {
        // Validate server configuration
        validate_listen_address(&self.server.listen)?;
        validate_concurrency_limits(
            self.server.worker_threads,
            "server.worker_threads",
            1,
            16, // Updated to spec range 1-16
        )?;
        validate_request_size(&self.server.max_request_size, "server.max_request_size")?;
        validate_positive_timeout(self.server.request_timeout, "server.request_timeout")?;
        validate_positive_timeout(self.server.shutdown_timeout, "server.shutdown_timeout")?;

        // Validate security configuration
        validate_array_size(&self.security.allowed_ips, "security.allowed_ips", 100)?; // Max 100 IPs
        for (i, cidr) in self.security.allowed_ips.iter().enumerate() {
            validate_network_cidr(cidr, &format!("security.allowed_ips[{}]", i))?;
            // Use enhanced CIDR validation
        }
        validate_concurrency_limits(self.security.rate_limit, "security.rate_limit", 1, 10000)?;

        // Validate storage configuration - check paths exist and are writable
        validate_path_accessible(&self.storage.data_dir, "storage.data_dir", true).await?;
        validate_concurrency_limits(
            self.storage.retention.successful_deploys,
            "storage.retention.successful_deploys",
            1,
            10000,
        )?;
        validate_concurrency_limits(
            self.storage.retention.failed_deploys,
            "storage.retention.failed_deploys",
            1,
            10000,
        )?;

        // Validate logging configuration
        if !matches!(
            self.logging.level.as_str(),
            "trace" | "debug" | "info" | "warn" | "error"
        ) {
            return Err(crate::types::Error::Validation {
                field: "logging.level".to_string(),
                message: format!(
                    "Invalid log level '{}'. Must be one of: trace, debug, info, warn, error",
                    self.logging.level
                ),
            });
        }

        if !matches!(self.logging.format.as_str(), "json" | "pretty") {
            return Err(crate::types::Error::Validation {
                field: "logging.format".to_string(),
                message: format!(
                    "Invalid log format '{}'. Must be one of: json, pretty",
                    self.logging.format
                ),
            });
        }

        validate_path_accessible(&self.logging.directory, "logging.directory", true).await?;

        // Validate limits configuration
        validate_concurrency_limits(
            self.limits.max_concurrent_total,
            "limits.max_concurrent_total",
            1,
            1000,
        )?;
        validate_concurrency_limits(
            self.limits.max_concurrent_per_service,
            "limits.max_concurrent_per_service",
            1,
            100,
        )?;
        validate_positive_timeout(self.limits.deployment_timeout, "limits.deployment_timeout")?;
        validate_positive_timeout(self.limits.command_timeout, "limits.command_timeout")?;
        validate_positive_timeout(self.limits.lock_timeout, "limits.lock_timeout")?;

        // Validate monitoring configuration
        validate_positive_timeout(
            self.monitoring.status_cache_seconds,
            "monitoring.status_cache_seconds",
        )?;

        // Validate notifications webhook timeouts
        validate_positive_timeout(
            self.notifications.webhook.timeout,
            "notifications.webhook.timeout",
        )?;

        // Validate secrets configuration
        validate_secret_source(&self.secrets.source, "secrets.source")?;
        validate_array_size(
            &self.secrets.sources_priority,
            "secrets.sources_priority",
            10,
        )?; // Max 10 sources
        validate_array_size(
            &self.secrets.required_secrets,
            "secrets.required_secrets",
            50,
        )?; // Max 50 required secrets
        validate_positive_timeout(self.secrets.reload_interval, "secrets.reload_interval")?;

        Ok(())
    }
}

impl ServicesConfig {
    /// Validate the services configuration
    pub async fn validate(&self) -> Result<()> {
        // Validate defaults
        validate_path_accessible(&self.defaults.working_dir, "defaults.working_dir", false).await?;
        validate_positive_timeout(self.defaults.command_timeout, "defaults.command_timeout")?;
        validate_positive_timeout(
            self.defaults.healthcheck_timeout,
            "defaults.healthcheck_timeout",
        )?;

        // Check for duplicate service names
        let mut service_names = std::collections::HashSet::new();
        for service in &self.service {
            if !service_names.insert(&service.name) {
                return Err(crate::types::Error::Validation {
                    field: "service.name".to_string(),
                    message: format!("Duplicate service name '{}'", service.name),
                });
            }
        }

        // Check for duplicate GitHub repository mappings
        let mut github_repos = std::collections::HashMap::new();
        for service in &self.service {
            if let Some(ref github) = service.github {
                if let Some(existing_service) = github_repos.insert(&github.repo, &service.name) {
                    return Err(crate::types::Error::Validation {
                        field: "service.github.repo".to_string(),
                        message: format!(
                            "Duplicate GitHub repository '{}' mapped to both '{}' and '{}'",
                            github.repo, existing_service, service.name
                        ),
                    });
                }
            }
        }

        // Validate each service
        for (i, service) in self.service.iter().enumerate() {
            let service_prefix = format!("service[{}]", i);

            // Validate service name
            if service.name.is_empty() {
                return Err(crate::types::Error::Validation {
                    field: format!("{}.name", service_prefix),
                    message: "service name cannot be empty".to_string(),
                });
            }

            // Validate service name length (32 character limit per specification)
            validate_service_name_length(&service.name, &format!("{}.name", service_prefix))?;

            // Validate service name format (no special characters that could cause issues)
            if !service
                .name
                .chars()
                .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                return Err(crate::types::Error::Validation {
                    field: format!("{}.name", service_prefix),
                    message: format!("Service name '{}' contains invalid characters. Only alphanumeric, hyphen, and underscore are allowed", service.name),
                });
            }

            // Validate working directory if specified
            if let Some(ref working_dir) = service.working_dir {
                validate_path_accessible(
                    working_dir,
                    &format!("{}.working_dir", service_prefix),
                    false,
                )
                .await?;
            }

            // Validate security configuration
            validate_regex_pattern(
                &service.security.allowed_image_pattern,
                &format!("{}.security.allowed_image_pattern", service_prefix),
            )?;

            // Validate array sizes for security (DoS prevention)
            validate_array_size(
                &service.security.allowed_env_overrides,
                &format!("{}.security.allowed_env_overrides", service_prefix),
                50, // Max 50 environment variables
            )?;

            // Validate deploy configuration
            if service.deploy.commands.is_empty() {
                return Err(crate::types::Error::Validation {
                    field: format!("{}.deploy.commands", service_prefix),
                    message: "Deploy commands cannot be empty".to_string(),
                });
            }

            // Validate deploy commands array size for security
            validate_array_size(
                &service.deploy.commands,
                &format!("{}.deploy.commands", service_prefix),
                20, // Max 20 deploy commands
            )?;

            for (cmd_i, command) in service.deploy.commands.iter().enumerate() {
                if command.is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.deploy.commands[{}]", service_prefix, cmd_i),
                        message: "Command cannot be empty".to_string(),
                    });
                }
                if command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.deploy.commands[{}]", service_prefix, cmd_i),
                        message: "Command executable cannot be empty".to_string(),
                    });
                }
            }

            if let Some(timeout) = service.deploy.timeout {
                validate_positive_timeout(timeout, &format!("{}.deploy.timeout", service_prefix))?;
            }

            validate_concurrency_limits(
                service.deploy.retries,
                &format!("{}.deploy.retries", service_prefix),
                0,
                10,
            )?;

            // Validate healthcheck configuration
            validate_positive_timeout(
                service.healthcheck.initial_delay,
                &format!("{}.healthcheck.initial_delay", service_prefix),
            )?;
            validate_positive_timeout(
                service.healthcheck.interval,
                &format!("{}.healthcheck.interval", service_prefix),
            )?;
            validate_concurrency_limits(
                service.healthcheck.max_attempts,
                &format!("{}.healthcheck.max_attempts", service_prefix),
                1,
                100,
            )?;
            validate_concurrency_limits(
                service.healthcheck.success_threshold,
                &format!("{}.healthcheck.success_threshold", service_prefix),
                1,
                service.healthcheck.max_attempts,
            )?;

            if let Some(timeout) = service.healthcheck.timeout {
                validate_positive_timeout(
                    timeout,
                    &format!("{}.healthcheck.timeout", service_prefix),
                )?;
            }

            // Validate healthcheck commands array size for security
            validate_array_size(
                &service.healthcheck.commands,
                &format!("{}.healthcheck.commands", service_prefix),
                10, // Max 10 healthcheck commands
            )?;

            // Validate healthcheck commands if present
            for (cmd_i, command) in service.healthcheck.commands.iter().enumerate() {
                if command.is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.healthcheck.commands[{}]", service_prefix, cmd_i),
                        message: "Healthcheck command cannot be empty".to_string(),
                    });
                }
                if command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.healthcheck.commands[{}]", service_prefix, cmd_i),
                        message: "Healthcheck command executable cannot be empty".to_string(),
                    });
                }
            }

            // Validate rollback configuration
            validate_concurrency_limits(
                service.rollback.max_attempts,
                &format!("{}.rollback.max_attempts", service_prefix),
                1,
                10,
            )?;

            if let Some(timeout) = service.rollback.timeout {
                validate_positive_timeout(
                    timeout,
                    &format!("{}.rollback.timeout", service_prefix),
                )?;
            }

            // Validate rollback commands array size for security
            validate_array_size(
                &service.rollback.commands,
                &format!("{}.rollback.commands", service_prefix),
                10, // Max 10 rollback commands
            )?;

            // Validate rollback commands if present
            for (cmd_i, command) in service.rollback.commands.iter().enumerate() {
                if command.is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.rollback.commands[{}]", service_prefix, cmd_i),
                        message: "Rollback command cannot be empty".to_string(),
                    });
                }
                if command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.rollback.commands[{}]", service_prefix, cmd_i),
                        message: "Rollback command executable cannot be empty".to_string(),
                    });
                }
            }

            // Validate hook commands array sizes for security
            validate_array_size(
                &service.hooks.pre_deploy,
                &format!("{}.hooks.pre_deploy", service_prefix),
                10, // Max 10 pre-deploy hooks
            )?;
            validate_array_size(
                &service.hooks.post_deploy,
                &format!("{}.hooks.post_deploy", service_prefix),
                10, // Max 10 post-deploy hooks
            )?;
            validate_array_size(
                &service.hooks.on_failure,
                &format!("{}.hooks.on_failure", service_prefix),
                10, // Max 10 on-failure hooks
            )?;

            // Validate hook commands
            for (cmd_i, command) in service.hooks.pre_deploy.iter().enumerate() {
                if command.is_empty() || command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.hooks.pre_deploy[{}]", service_prefix, cmd_i),
                        message: "Pre-deploy hook command cannot be empty".to_string(),
                    });
                }
            }

            for (cmd_i, command) in service.hooks.post_deploy.iter().enumerate() {
                if command.is_empty() || command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.hooks.post_deploy[{}]", service_prefix, cmd_i),
                        message: "Post-deploy hook command cannot be empty".to_string(),
                    });
                }
            }

            for (cmd_i, command) in service.hooks.on_failure.iter().enumerate() {
                if command.is_empty() || command[0].is_empty() {
                    return Err(crate::types::Error::Validation {
                        field: format!("{}.hooks.on_failure[{}]", service_prefix, cmd_i),
                        message: "On-failure hook command cannot be empty".to_string(),
                    });
                }
            }

            // Validate GitHub configuration if present
            if let Some(ref github) = service.github {
                validate_github_repo_format(
                    &github.repo,
                    &format!("{}.github.repo", service_prefix),
                )?;
            }

            // Validate timeout relationships within the service
            validate_timeout_relationships(service, i)?;
        }

        Ok(())
    }
}
