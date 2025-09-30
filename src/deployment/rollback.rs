//! Rollback system for reverting failed deployments
//!
//! This module implements the rollback workflow that runs when a deployment
//! fails either during command execution or health check verification.

use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::types::{ServiceConfig, ServiceRollback};
use crate::execution::executor::{execute_with_retry_and_context, CommandExecutor, ExecutionStep};
use crate::execution::templates::ExecutionContext;
use crate::metrics;
use crate::types::{CommandPhase, CommandResult, Error, Result};

use super::healthcheck;

/// Execute rollback for a failed deployment
///
/// This function implements the rollback workflow:
/// 1. Check if rollback is enabled and previous_image is available
/// 2. Execute rollback commands with retry logic
/// 3. Optionally run health checks to verify rollback success
/// 4. Return all command results and health check results
///
/// # Arguments
/// * `executor` - The command executor to use for running rollback commands
/// * `service_config` - Service configuration with rollback settings
/// * `context` - Execution context with template variables (must include PREVIOUS_IMAGE)
/// * `service_name` - Name of the service being rolled back (for logging)
/// * `rollback_reason` - Reason for triggering rollback
///
/// # Returns
/// * `Ok(Vec<CommandResult>)` - All rollback command results on success
/// * `Err(Error)` - If rollback fails or is not configured
pub async fn execute_rollback(
    executor: &CommandExecutor,
    service_config: &ServiceConfig,
    context: &ExecutionContext,
    service_name: &str,
    rollback_reason: &str,
) -> Result<Vec<CommandResult>> {
    info!(
        service = %service_name,
        reason = %rollback_reason,
        "Starting rollback process"
    );

    // Check if rollback is enabled
    if !service_config.rollback.enabled {
        warn!(
            service = %service_name,
            "Rollback is disabled in service configuration"
        );
        return Err(Error::Application(
            "Rollback is disabled for this service".to_string(),
        ));
    }

    // Check if rollback commands are configured
    if service_config.rollback.commands.is_empty() {
        warn!(
            service = %service_name,
            "No rollback commands configured"
        );
        return Err(Error::Application(
            "No rollback commands configured for this service".to_string(),
        ));
    }

    // Verify previous_image is available in context
    if !context.has_variable("PREVIOUS_IMAGE") {
        error!(
            service = %service_name,
            "Cannot rollback: no previous image available"
        );
        return Err(Error::Application(
            "Cannot rollback: no previous image specified in deployment request".to_string(),
        ));
    }

    info!(
        service = %service_name,
        command_count = service_config.rollback.commands.len(),
        max_attempts = service_config.rollback.max_attempts,
        "Rollback configuration validated"
    );

    // Create executor with rollback timeout if specified
    let rollback_executor = if let Some(timeout) = service_config.rollback.timeout {
        let mut exec = executor.clone();
        exec.timeout = Duration::from_secs(timeout);
        exec
    } else {
        executor.clone()
    };

    let mut all_results = Vec::new();

    // Execute rollback with retry logic at the sequence level
    for attempt in 1..=service_config.rollback.max_attempts {
        info!(
            service = %service_name,
            attempt = attempt,
            max_attempts = service_config.rollback.max_attempts,
            "Executing rollback attempt"
        );

        // Execute all rollback commands sequentially
        match execute_rollback_commands(
            &rollback_executor,
            &service_config.rollback,
            context,
            service_name,
            attempt,
        )
        .await
        {
            Ok(mut results) => {
                info!(
                    service = %service_name,
                    attempt = attempt,
                    command_count = results.len(),
                    "Rollback commands completed successfully"
                );

                all_results.append(&mut results);

                // If health checks are configured, run them to verify rollback
                if !service_config.healthcheck.commands.is_empty() {
                    info!(
                        service = %service_name,
                        "Running health checks to verify rollback"
                    );

                    match healthcheck::execute_health_checks(
                        &rollback_executor,
                        &service_config.healthcheck,
                        context,
                        service_name,
                    )
                    .await
                    {
                        Ok(mut health_results) => {
                            info!(
                                service = %service_name,
                                health_check_count = health_results.len(),
                                "Rollback health checks passed"
                            );
                            all_results.append(&mut health_results);
                            return Ok(all_results);
                        }
                        Err(e) => {
                            error!(
                                service = %service_name,
                                attempt = attempt,
                                error = %e,
                                "Rollback health checks failed"
                            );

                            // If this was the last attempt, return error
                            if attempt == service_config.rollback.max_attempts {
                                return Err(Error::Application(format!(
                                    "Rollback commands succeeded but health checks failed: {}",
                                    e
                                )));
                            }

                            // Otherwise, retry the entire rollback sequence
                            warn!(
                                service = %service_name,
                                attempt = attempt,
                                "Retrying rollback due to health check failure"
                            );
                            continue;
                        }
                    }
                } else {
                    // No health checks configured - rollback is successful
                    info!(
                        service = %service_name,
                        "Rollback completed successfully (no health checks configured)"
                    );
                    return Ok(all_results);
                }
            }
            Err(e) => {
                error!(
                    service = %service_name,
                    attempt = attempt,
                    max_attempts = service_config.rollback.max_attempts,
                    error = %e,
                    "Rollback attempt failed"
                );

                // If this was the last attempt, return the error
                if attempt == service_config.rollback.max_attempts {
                    return Err(Error::Application(format!(
                        "Rollback failed after {} attempts: {}",
                        service_config.rollback.max_attempts, e
                    )));
                }

                // Wait before retrying (simple linear backoff)
                if attempt < service_config.rollback.max_attempts {
                    let retry_delay = 5; // 5 seconds between rollback attempts
                    debug!(
                        service = %service_name,
                        delay_seconds = retry_delay,
                        "Waiting before next rollback attempt"
                    );
                    tokio::time::sleep(Duration::from_secs(retry_delay)).await;
                }
            }
        }
    }

    // Should not reach here, but return error just in case
    Err(Error::Application(
        "Rollback failed: exhausted all retry attempts".to_string(),
    ))
}

/// Execute all rollback commands sequentially
///
/// All commands must succeed for this function to return Ok.
/// If any command fails, the function returns Err immediately.
async fn execute_rollback_commands(
    executor: &CommandExecutor,
    rollback_config: &ServiceRollback,
    context: &ExecutionContext,
    service_name: &str,
    attempt: u32,
) -> Result<Vec<CommandResult>> {
    let mut results = Vec::new();

    for (idx, command) in rollback_config.commands.iter().enumerate() {
        let step_name = format!("rollback_attempt_{}_cmd_{}", attempt, idx + 1);

        info!(
            service = %service_name,
            attempt = attempt,
            command_index = idx + 1,
            command_count = rollback_config.commands.len(),
            command = ?command,
            "Executing rollback command"
        );

        // Create execution step (no per-command retries - retries happen at sequence level)
        let step = ExecutionStep::new(step_name.clone(), command.clone())
            .with_retries(0, 0)
            .with_critical(true);

        // Execute the command with template expansion
        match execute_with_retry_and_context(executor, &step, context, CommandPhase::Rollback).await
        {
            Ok(result) => {
                info!(
                    service = %service_name,
                    attempt = attempt,
                    command_index = idx + 1,
                    duration_ms = result.duration_ms,
                    "Rollback command succeeded"
                );

                // Record command execution metric
                let command_name = result
                    .command
                    .first()
                    .map(|s| s.as_str())
                    .unwrap_or("unknown");
                metrics::record_command_execution(
                    service_name,
                    "rollback",
                    command_name,
                    result.duration_ms,
                );

                results.push(result);
            }
            Err(e) => {
                error!(
                    service = %service_name,
                    attempt = attempt,
                    command_index = idx + 1,
                    error = %e,
                    "Rollback command failed"
                );
                return Err(e);
            }
        }
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{ServiceHealthcheck, ServiceRollback};
    use std::collections::HashMap;

    fn create_test_rollback_config(enabled: bool, max_attempts: u32) -> ServiceRollback {
        ServiceRollback {
            enabled,
            max_attempts,
            timeout: Some(30),
            commands: vec![
                vec![
                    "echo".to_string(),
                    "Rolling back to {{PREVIOUS_IMAGE}}".to_string(),
                ],
                vec!["echo".to_string(), "Rollback complete".to_string()],
            ],
        }
    }

    fn create_test_service_config(rollback_config: ServiceRollback) -> ServiceConfig {
        ServiceConfig {
            name: "test-service".to_string(),
            description: Some("Test service".to_string()),
            enabled: true,
            working_dir: Some("/tmp".to_string()),
            env: HashMap::new(),
            security: crate::config::types::ServiceSecurity {
                allowed_image_pattern: ".*".to_string(),
                allowed_env_overrides: Vec::new(),
            },
            deploy: crate::config::types::ServiceDeploy {
                commands: Vec::new(),
                timeout: None,
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: rollback_config,
            hooks: crate::config::types::ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        }
    }

    fn create_test_executor() -> CommandExecutor {
        CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp")
    }

    fn create_test_context_with_previous_image() -> ExecutionContext {
        ExecutionContext::new()
            .with_built_in_variables(
                "registry:5000/app:v2.0.0".to_string(),
                "test-service".to_string(),
                "deploy-001".to_string(),
                "/srv/app".to_string(),
            )
            .with_previous_image(Some("registry:5000/app:v1.0.0".to_string()))
    }

    fn create_test_context_without_previous_image() -> ExecutionContext {
        ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v2.0.0".to_string(),
            "test-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        )
    }

    #[tokio::test]
    async fn test_rollback_success() {
        let executor = create_test_executor();
        let rollback_config = create_test_rollback_config(true, 2);
        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 2); // Two rollback commands
        assert!(results.iter().all(|r| r.exit_code == Some(0)));
        assert!(results.iter().all(|r| r.phase == CommandPhase::Rollback));
    }

    #[tokio::test]
    async fn test_rollback_disabled() {
        let executor = create_test_executor();
        let rollback_config = create_test_rollback_config(false, 2);
        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("disabled"));
    }

    #[tokio::test]
    async fn test_rollback_no_previous_image() {
        let executor = create_test_executor();
        let rollback_config = create_test_rollback_config(true, 2);
        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_without_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("no previous image"));
    }

    #[tokio::test]
    async fn test_rollback_no_commands() {
        let executor = create_test_executor();
        let mut rollback_config = create_test_rollback_config(true, 2);
        rollback_config.commands = Vec::new(); // No commands
        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error.to_string().contains("No rollback commands"));
    }

    #[tokio::test]
    async fn test_rollback_command_failure() {
        let executor = create_test_executor();
        let mut rollback_config = create_test_rollback_config(true, 2);
        rollback_config.commands = vec![
            vec!["echo".to_string(), "step 1".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()], // This fails
            vec!["echo".to_string(), "step 3".to_string()],
        ];
        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Rollback failed after 2 attempts"));
    }

    #[tokio::test]
    async fn test_rollback_with_health_checks() {
        let executor = create_test_executor();
        let rollback_config = create_test_rollback_config(true, 2);
        let mut service_config = create_test_service_config(rollback_config);

        // Add health check configuration
        service_config.healthcheck = ServiceHealthcheck {
            initial_delay: 0,
            interval: 0,
            max_attempts: 2,
            success_threshold: 1,
            timeout: Some(10),
            commands: vec![vec!["echo".to_string(), "health check passed".to_string()]],
        };

        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_ok());
        let results = result.unwrap();
        // 2 rollback commands + 1 health check command = 3 total
        assert_eq!(results.len(), 3);

        // First two should be rollback phase
        assert_eq!(results[0].phase, CommandPhase::Rollback);
        assert_eq!(results[1].phase, CommandPhase::Rollback);

        // Last one should be health check phase
        assert_eq!(results[2].phase, CommandPhase::Healthcheck);
    }

    #[tokio::test]
    async fn test_rollback_health_check_failure() {
        let executor = create_test_executor();
        let rollback_config = create_test_rollback_config(true, 2);
        let mut service_config = create_test_service_config(rollback_config);

        // Add failing health check
        service_config.healthcheck = ServiceHealthcheck {
            initial_delay: 0,
            interval: 0,
            max_attempts: 1,
            success_threshold: 1,
            timeout: Some(10),
            commands: vec![vec![
                "sh".to_string(),
                "-c".to_string(),
                "exit 1".to_string(),
            ]],
        };

        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(
            error.to_string().contains("health checks failed")
                || error.to_string().contains("Rollback failed")
        );
    }

    #[tokio::test]
    async fn test_rollback_template_expansion() {
        let executor = create_test_executor();
        let mut rollback_config = create_test_rollback_config(true, 1);
        rollback_config.commands = vec![vec![
            "echo".to_string(),
            "Rollback to {{PREVIOUS_IMAGE}} from {{IMAGE}}".to_string(),
        ]];

        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);

        // Check that template was expanded
        let stdout = &results[0].stdout;
        assert!(stdout.contains("registry:5000/app:v1.0.0")); // PREVIOUS_IMAGE
        assert!(stdout.contains("registry:5000/app:v2.0.0")); // IMAGE
    }

    #[tokio::test]
    async fn test_rollback_retry_logic() {
        let executor = create_test_executor();
        let mut rollback_config = create_test_rollback_config(true, 3);

        // Use a command that always fails to test retry logic
        rollback_config.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];

        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        // Verify that it tried max_attempts times
        let error = result.unwrap_err();
        assert!(error.to_string().contains("after 3 attempts"));
    }

    #[tokio::test]
    async fn test_rollback_timeout_handling() {
        let executor = create_test_executor();
        let mut rollback_config = create_test_rollback_config(true, 1);
        rollback_config.timeout = Some(1); // 1 second timeout
        rollback_config.commands = vec![vec!["sleep".to_string(), "5".to_string()]]; // Sleep longer than timeout

        let service_config = create_test_service_config(rollback_config);
        let context = create_test_context_with_previous_image();

        let result = execute_rollback(
            &executor,
            &service_config,
            &context,
            "test-service",
            "deployment failed",
        )
        .await;

        assert!(result.is_err());
        // Should fail due to timeout
    }
}
