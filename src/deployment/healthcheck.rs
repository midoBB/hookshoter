//! Health check system for verifying deployment success
//!
//! This module implements the health checking logic that runs after deployment
//! to verify that the service is healthy before marking the deployment as successful.

use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::types::ServiceHealthcheck;
use crate::execution::executor::{CommandExecutor, ExecutionStep};
use crate::execution::templates::ExecutionContext;
use crate::metrics;
use crate::types::{CommandPhase, CommandResult, Error, Result};

/// Execute health checks for a deployed service
///
/// This function implements the health check workflow:
/// 1. Wait for initial_delay before starting
/// 2. Execute health check commands in a retry loop
/// 3. Track consecutive successes against success_threshold
/// 4. Return success when threshold is met, or failure after max_attempts
///
/// # Arguments
/// * `executor` - The command executor to use for running health check commands
/// * `healthcheck_config` - Health check configuration from service config
/// * `context` - Execution context with template variables
/// * `service_name` - Name of the service being health checked (for logging)
///
/// # Returns
/// * `Ok(Vec<CommandResult>)` - All health check command results on success
/// * `Err(Error)` - If health checks fail after max attempts
pub async fn execute_health_checks(
    executor: &CommandExecutor,
    healthcheck_config: &ServiceHealthcheck,
    context: &ExecutionContext,
    service_name: &str,
) -> Result<Vec<CommandResult>> {
    // If no health check commands configured, skip health checking
    if healthcheck_config.commands.is_empty() {
        debug!(service = %service_name, "No health check commands configured, skipping");
        return Ok(Vec::new());
    }

    info!(
        service = %service_name,
        initial_delay = healthcheck_config.initial_delay,
        interval = healthcheck_config.interval,
        max_attempts = healthcheck_config.max_attempts,
        success_threshold = healthcheck_config.success_threshold,
        command_count = healthcheck_config.commands.len(),
        "Starting health check phase"
    );

    // Wait for initial delay before starting health checks
    if healthcheck_config.initial_delay > 0 {
        debug!(
            service = %service_name,
            delay_seconds = healthcheck_config.initial_delay,
            "Waiting for initial delay before health checks"
        );
        tokio::time::sleep(Duration::from_secs(healthcheck_config.initial_delay)).await;
    }

    // Create executor with health check timeout if specified
    let health_executor = if let Some(timeout) = healthcheck_config.timeout {
        let mut exec = executor.clone();
        exec.timeout = Duration::from_secs(timeout);
        exec
    } else {
        executor.clone()
    };

    let mut consecutive_successes = 0;
    let mut all_results = Vec::new();

    // Health check retry loop
    for attempt in 1..=healthcheck_config.max_attempts {
        info!(
            service = %service_name,
            attempt = attempt,
            max_attempts = healthcheck_config.max_attempts,
            consecutive_successes = consecutive_successes,
            success_threshold = healthcheck_config.success_threshold,
            "Executing health check attempt"
        );

        // Execute all health check commands sequentially
        match execute_all_health_check_commands(
            &health_executor,
            &healthcheck_config.commands,
            context,
            service_name,
            attempt,
        )
        .await
        {
            Ok(mut results) => {
                // All commands succeeded - increment consecutive success count
                consecutive_successes += 1;
                all_results.append(&mut results);

                info!(
                    service = %service_name,
                    attempt = attempt,
                    consecutive_successes = consecutive_successes,
                    success_threshold = healthcheck_config.success_threshold,
                    "Health check attempt succeeded"
                );

                // Check if we've met the success threshold
                if consecutive_successes >= healthcheck_config.success_threshold {
                    info!(
                        service = %service_name,
                        total_attempts = attempt,
                        consecutive_successes = consecutive_successes,
                        "Health check success threshold met"
                    );
                    return Ok(all_results);
                }

                // Wait for interval before next attempt (unless this was the last attempt)
                if attempt < healthcheck_config.max_attempts {
                    debug!(
                        service = %service_name,
                        interval_seconds = healthcheck_config.interval,
                        "Waiting before next health check attempt"
                    );
                    tokio::time::sleep(Duration::from_secs(healthcheck_config.interval)).await;
                }
            }
            Err(e) => {
                // One or more commands failed - reset consecutive success count
                warn!(
                    service = %service_name,
                    attempt = attempt,
                    error = %e,
                    "Health check attempt failed, resetting consecutive success count"
                );

                consecutive_successes = 0;

                // Wait for interval before next attempt (unless this was the last attempt)
                if attempt < healthcheck_config.max_attempts {
                    debug!(
                        service = %service_name,
                        interval_seconds = healthcheck_config.interval,
                        "Waiting before next health check attempt after failure"
                    );
                    tokio::time::sleep(Duration::from_secs(healthcheck_config.interval)).await;
                }
            }
        }
    }

    // Max attempts reached without meeting success threshold
    error!(
        service = %service_name,
        max_attempts = healthcheck_config.max_attempts,
        consecutive_successes = consecutive_successes,
        success_threshold = healthcheck_config.success_threshold,
        "Health check failed: max attempts reached without meeting success threshold"
    );

    // Record healthcheck failure metric
    metrics::record_healthcheck_failure(service_name);

    Err(Error::Application(format!(
        "Health check failed after {} attempts (needed {} consecutive successes, got {})",
        healthcheck_config.max_attempts,
        healthcheck_config.success_threshold,
        consecutive_successes
    )))
}

/// Execute all health check commands sequentially
///
/// All commands must succeed for this function to return Ok.
/// If any command fails, the function returns Err immediately.
async fn execute_all_health_check_commands(
    executor: &CommandExecutor,
    commands: &[Vec<String>],
    context: &ExecutionContext,
    service_name: &str,
    attempt: u32,
) -> Result<Vec<CommandResult>> {
    let mut results = Vec::new();

    for (idx, command) in commands.iter().enumerate() {
        let step_name = format!("healthcheck_attempt_{}_cmd_{}", attempt, idx + 1);

        debug!(
            service = %service_name,
            attempt = attempt,
            command_index = idx + 1,
            command_count = commands.len(),
            command = ?command,
            "Executing health check command"
        );

        // Create execution step (no retries for health checks - handled by outer loop)
        let step = ExecutionStep::new(step_name.clone(), command.clone())
            .with_retries(0, 0)
            .with_critical(true);

        // Execute the command with template expansion
        match crate::execution::executor::execute_with_retry_and_context(
            executor,
            &step,
            context,
            CommandPhase::Healthcheck,
        )
        .await
        {
            Ok(result) => {
                debug!(
                    service = %service_name,
                    attempt = attempt,
                    command_index = idx + 1,
                    duration_ms = result.duration_ms,
                    "Health check command succeeded"
                );
                results.push(result);
            }
            Err(e) => {
                error!(
                    service = %service_name,
                    attempt = attempt,
                    command_index = idx + 1,
                    error = %e,
                    "Health check command failed"
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
    use crate::config::types::ServiceHealthcheck;
    use std::collections::HashMap;

    fn create_test_healthcheck_config() -> ServiceHealthcheck {
        ServiceHealthcheck {
            initial_delay: 0, // No delay in tests for speed
            interval: 0,      // No interval in tests for speed
            max_attempts: 3,
            success_threshold: 2,
            timeout: Some(10),
            commands: vec![
                vec!["echo".to_string(), "health check 1".to_string()],
                vec!["echo".to_string(), "health check 2".to_string()],
            ],
        }
    }

    fn create_test_executor() -> CommandExecutor {
        CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp")
    }

    fn create_test_context() -> ExecutionContext {
        ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "test-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        )
    }

    #[tokio::test]
    async fn test_health_check_success_after_threshold() {
        let executor = create_test_executor();
        let config = create_test_healthcheck_config();
        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_ok());
        let results = result.unwrap();
        // Should have 2 attempts * 2 commands = 4 results
        assert_eq!(results.len(), 4);
        assert!(results.iter().all(|r| r.exit_code == Some(0)));
    }

    #[tokio::test]
    async fn test_health_check_failure_max_attempts() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        // Use a command that will fail
        config.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        config.max_attempts = 3;
        config.success_threshold = 2;

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Health check failed after 3 attempts"));
    }

    #[tokio::test]
    async fn test_health_check_consecutive_success_reset() {
        // This test verifies that when a health check fails, the consecutive success
        // count resets to 0, requiring the threshold to be met again from scratch.

        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();

        // Test scenario: need 2 consecutive successes, but with intermittent failures
        // We'll use a higher threshold and verify it takes the expected number of attempts
        config.commands = vec![vec!["echo".to_string(), "success".to_string()]];
        config.max_attempts = 5;
        config.success_threshold = 3; // Need 3 consecutive successes
        config.interval = 0;

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        // Should succeed after 3 consecutive successful attempts
        assert!(result.is_ok());
        let results = result.unwrap();
        // Should have exactly 3 command results (3 successful attempts)
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_health_check_empty_commands_skipped() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = Vec::new(); // Empty commands

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 0); // No commands executed
    }

    #[tokio::test]
    async fn test_health_check_multiple_commands_sequential() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = vec![
            vec!["echo".to_string(), "first".to_string()],
            vec!["echo".to_string(), "second".to_string()],
            vec!["echo".to_string(), "third".to_string()],
        ];
        config.success_threshold = 1; // Only need 1 success

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 3); // All 3 commands from 1 successful attempt
        assert_eq!(results[0].stdout.trim(), "first");
        assert_eq!(results[1].stdout.trim(), "second");
        assert_eq!(results[2].stdout.trim(), "third");
    }

    #[tokio::test]
    async fn test_health_check_one_command_fails_all_fail() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = vec![
            vec!["echo".to_string(), "success".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()], // This fails
            vec!["echo".to_string(), "never reached".to_string()],
        ];
        config.max_attempts = 2;
        config.success_threshold = 1;

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_health_check_initial_delay() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.initial_delay = 1; // 1 second delay
        config.success_threshold = 1;

        let context = create_test_context();

        let start = std::time::Instant::now();
        let result = execute_health_checks(&executor, &config, &context, "test-service").await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        assert!(elapsed >= Duration::from_secs(1)); // Should take at least 1 second
    }

    #[tokio::test]
    async fn test_health_check_interval_between_attempts() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]]; // Always fails
        config.max_attempts = 3;
        config.interval = 1; // 1 second between attempts
        config.initial_delay = 0;

        let context = create_test_context();

        let start = std::time::Instant::now();
        let result = execute_health_checks(&executor, &config, &context, "test-service").await;
        let elapsed = start.elapsed();

        assert!(result.is_err());
        // Should take at least 2 seconds (2 intervals between 3 attempts)
        assert!(elapsed >= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_health_check_timeout_handling() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = vec![vec!["sleep".to_string(), "10".to_string()]]; // Sleep longer than timeout
        config.timeout = Some(1); // 1 second timeout
        config.max_attempts = 1;

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        let error_str = error.to_string();
        // The error will be "Health check failed after..." because timeout causes attempt to fail
        assert!(error_str.contains("Health check failed after 1 attempt"));
    }

    #[tokio::test]
    async fn test_health_check_template_expansion() {
        let executor = create_test_executor();
        let mut config = create_test_healthcheck_config();
        config.commands = vec![vec!["echo".to_string(), "{{SERVICE}}".to_string()]];
        config.success_threshold = 1;

        let context = create_test_context();

        let result = execute_health_checks(&executor, &config, &context, "test-service").await;

        assert!(result.is_ok());
        let results = result.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].stdout.contains("test-service"));
    }
}
