use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use super::templates::ExecutionContext;
use crate::types::{CommandPhase, CommandResult, ExecutionError, Result};

/// Maximum size for captured stdout/stderr to prevent memory issues
const MAX_OUTPUT_SIZE: usize = 10 * 1024; // 10KB per stream

/// Grace period for SIGTERM before SIGKILL on timeout
const TERMINATION_GRACE_PERIOD: Duration = Duration::from_secs(5);

/// Default retry delay in seconds
const DEFAULT_RETRY_DELAY: u64 = 2;

/// Command executor handles running individual commands with proper timeout,
/// environment variables, and working directory configuration
#[derive(Debug, Clone)]
pub struct CommandExecutor {
    /// Maximum time to wait for command completion
    pub timeout: Duration,
    /// Environment variables to set for the command
    pub env: HashMap<String, String>,
    /// Working directory for command execution
    pub working_dir: String,
}

impl CommandExecutor {
    /// Create a new command executor with the specified configuration
    pub fn new<P: AsRef<Path>>(
        timeout: Duration,
        env: HashMap<String, String>,
        working_dir: P,
    ) -> Self {
        Self {
            timeout,
            env,
            working_dir: working_dir.as_ref().to_string_lossy().to_string(),
        }
    }

    /// Execute a single command with template expansion, timeout and capture output
    pub async fn execute_with_context(
        &self,
        command: &[String],
        context: &ExecutionContext,
        phase: CommandPhase,
        step_name: &str,
    ) -> Result<CommandResult> {
        // Expand templates in command arguments
        let expanded_command = context.expand_command(command)?;

        debug!(
            original_command = ?command,
            expanded_command = ?expanded_command,
            "Expanded command templates"
        );

        self.execute(&expanded_command, phase, step_name).await
    }

    /// Execute a single command with timeout and capture output (without template expansion)
    pub async fn execute(
        &self,
        command: &[String],
        phase: CommandPhase,
        step_name: &str,
    ) -> Result<CommandResult> {
        if command.is_empty() {
            return Err(ExecutionError::StartFailed {
                command: "<empty>".to_string(),
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Command cannot be empty",
                ),
            }
            .into());
        }

        let executable = &command[0];
        let args = if command.len() > 1 {
            &command[1..]
        } else {
            &[]
        };

        debug!(
            command = ?command,
            working_dir = %self.working_dir,
            timeout_secs = self.timeout.as_secs(),
            "Executing command"
        );

        let start_time = Instant::now();
        let started_at = chrono::Utc::now().timestamp();

        // Set up the command
        let mut cmd = Command::new(executable);
        cmd.args(args)
            .envs(&self.env)
            .current_dir(&self.working_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null()); // Ensure no stdin interaction

        // Execute with timeout
        let execution_result = timeout(self.timeout, cmd.output()).await;

        let duration = start_time.elapsed();
        let duration_ms = duration.as_millis() as u64;

        match execution_result {
            Ok(Ok(output)) => {
                let exit_code = output.status.code();

                // Truncate output to prevent memory issues
                let stdout = truncate_output(output.stdout);
                let stderr = truncate_output(output.stderr);

                debug!(
                    command = ?command,
                    exit_code = exit_code,
                    duration_ms = duration_ms,
                    stdout_len = stdout.len(),
                    stderr_len = stderr.len(),
                    "Command completed"
                );

                // Check for non-zero exit code
                if let Some(code) = exit_code {
                    if code != 0 {
                        warn!(
                            command = ?command,
                            exit_code = code,
                            stderr = %stderr,
                            "Command failed with non-zero exit code"
                        );
                        return Err(ExecutionError::NonZeroExit {
                            command: command.join(" "),
                            code,
                        }
                        .into());
                    }
                }

                Ok(CommandResult {
                    phase,
                    step_name: step_name.to_string(),
                    command: command.to_vec(),
                    exit_code,
                    stdout,
                    stderr,
                    started_at,
                    duration_ms,
                    timed_out: false,
                    retries: 0,
                })
            }
            Ok(Err(io_error)) => {
                error!(
                    command = ?command,
                    error = %io_error,
                    "Failed to execute command"
                );
                Err(ExecutionError::StartFailed {
                    command: command.join(" "),
                    source: io_error,
                }
                .into())
            }
            Err(_timeout_error) => {
                warn!(
                    command = ?command,
                    timeout_secs = self.timeout.as_secs(),
                    duration_ms = duration_ms,
                    "Command timed out"
                );

                Err(ExecutionError::Timeout {
                    command: command.join(" "),
                    timeout: self.timeout.as_secs(),
                }
                .into())
            }
        }
    }
}

/// Configuration for command execution with retries
#[derive(Debug, Clone)]
pub struct ExecutionStep {
    pub name: String,
    pub command: Vec<String>,
    pub retries: u32,
    pub retry_delay: u64,
    pub critical: bool,
    pub timeout: Option<Duration>,
}

impl ExecutionStep {
    pub fn new(name: String, command: Vec<String>) -> Self {
        Self {
            name,
            command,
            retries: 0,
            retry_delay: DEFAULT_RETRY_DELAY,
            critical: true,
            timeout: None,
        }
    }

    pub fn with_retries(mut self, retries: u32, delay: u64) -> Self {
        self.retries = retries;
        self.retry_delay = delay;
        self
    }

    pub fn with_critical(mut self, critical: bool) -> Self {
        self.critical = critical;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

/// Execute a command with template expansion and retry logic
pub async fn execute_with_retry_and_context(
    executor: &CommandExecutor,
    step: &ExecutionStep,
    context: &ExecutionContext,
    phase: CommandPhase,
) -> Result<CommandResult> {
    let mut last_error: Option<crate::types::Error> = None;

    // Use step-specific timeout if provided, otherwise use executor default
    let effective_executor = if let Some(step_timeout) = step.timeout {
        let mut exec = executor.clone();
        exec.timeout = step_timeout;
        exec
    } else {
        executor.clone()
    };

    for attempt in 0..=step.retries {
        if attempt > 0 {
            let delay = calculate_retry_delay(attempt, step.retry_delay);
            info!(
                step = %step.name,
                attempt = attempt + 1,
                max_attempts = step.retries + 1,
                delay_secs = delay,
                "Retrying command after failure"
            );
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        match effective_executor
            .execute_with_context(&step.command, context, phase.clone(), &step.name)
            .await
        {
            Ok(mut result) => {
                result.retries = attempt;
                info!(
                    step = %step.name,
                    attempt = attempt + 1,
                    duration_ms = result.duration_ms,
                    "Command succeeded"
                );
                return Ok(result);
            }
            Err(e) => {
                error!(
                    step = %step.name,
                    attempt = attempt + 1,
                    max_attempts = step.retries + 1,
                    error = %e,
                    critical = step.critical,
                    "Command attempt failed"
                );

                last_error = Some(e);

                // For critical commands, fail immediately after first attempt
                if step.critical && attempt == 0 {
                    break;
                }
            }
        }
    }

    // All attempts failed
    let final_error = last_error
        .unwrap_or_else(|| crate::types::Error::Application("Unknown execution error".to_string()));

    error!(
        step = %step.name,
        attempts = step.retries + 1,
        critical = step.critical,
        "All command execution attempts failed"
    );

    Err(final_error)
}

/// Execute a command with retry logic and exponential backoff (legacy function without template expansion)
pub async fn execute_with_retry(
    executor: &CommandExecutor,
    step: &ExecutionStep,
    phase: CommandPhase,
) -> Result<CommandResult> {
    let mut last_error: Option<crate::types::Error> = None;

    // Use step-specific timeout if provided, otherwise use executor default
    let effective_executor = if let Some(step_timeout) = step.timeout {
        let mut exec = executor.clone();
        exec.timeout = step_timeout;
        exec
    } else {
        executor.clone()
    };

    for attempt in 0..=step.retries {
        if attempt > 0 {
            let delay = calculate_retry_delay(attempt, step.retry_delay);
            info!(
                step = %step.name,
                attempt = attempt + 1,
                max_attempts = step.retries + 1,
                delay_secs = delay,
                "Retrying command after failure"
            );
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }

        match effective_executor
            .execute(&step.command, phase.clone(), &step.name)
            .await
        {
            Ok(mut result) => {
                result.retries = attempt;
                info!(
                    step = %step.name,
                    attempt = attempt + 1,
                    duration_ms = result.duration_ms,
                    "Command succeeded"
                );
                return Ok(result);
            }
            Err(e) => {
                error!(
                    step = %step.name,
                    attempt = attempt + 1,
                    max_attempts = step.retries + 1,
                    error = %e,
                    critical = step.critical,
                    "Command attempt failed"
                );

                last_error = Some(e);

                // For critical commands, fail immediately after first attempt
                if step.critical && attempt == 0 {
                    break;
                }
            }
        }
    }

    // All attempts failed
    let final_error = last_error
        .unwrap_or_else(|| crate::types::Error::Application("Unknown execution error".to_string()));

    error!(
        step = %step.name,
        attempts = step.retries + 1,
        critical = step.critical,
        "All command execution attempts failed"
    );

    Err(final_error)
}

/// Calculate retry delay with exponential backoff
fn calculate_retry_delay(attempt: u32, base_delay: u64) -> u64 {
    // Exponential backoff: delay * 2^(attempt-1), capped at 60 seconds
    let delay = base_delay * (2_u64.pow(attempt.saturating_sub(1)));
    delay.min(60)
}

/// Truncate command output to prevent memory issues
fn truncate_output(output: Vec<u8>) -> String {
    let output_str = String::from_utf8_lossy(&output);
    if output_str.len() > MAX_OUTPUT_SIZE {
        let truncated = &output_str[..MAX_OUTPUT_SIZE];
        format!("{}... [truncated at {} bytes]", truncated, MAX_OUTPUT_SIZE)
    } else {
        output_str.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::super::templates::ExecutionContext;
    use super::*;
    use std::collections::HashMap;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_successful_command_execution() {
        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp");

        let result = executor
            .execute(
                &["echo".to_string(), "hello world".to_string()],
                CommandPhase::Deploy,
                "test_echo",
            )
            .await
            .unwrap();

        assert_eq!(result.phase, CommandPhase::Deploy);
        assert_eq!(result.step_name, "test_echo");
        assert_eq!(result.command, vec!["echo", "hello world"]);
        assert_eq!(result.exit_code, Some(0));
        assert_eq!(result.stdout.trim(), "hello world");
        assert!(!result.timed_out);
        assert_eq!(result.retries, 0);
    }

    #[tokio::test]
    async fn test_command_execution_with_template_context() {
        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp");

        let context = ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "web-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        );

        let command = vec!["echo".to_string(), "{{SERVICE}}".to_string()];

        let result = executor
            .execute_with_context(&command, &context, CommandPhase::Deploy, "test_template")
            .await
            .unwrap();

        assert_eq!(result.phase, CommandPhase::Deploy);
        assert_eq!(result.step_name, "test_template");
        assert!(result.stdout.contains("web-service"));
    }

    #[tokio::test]
    async fn test_command_with_non_zero_exit() {
        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp");

        let result = executor
            .execute(
                &["sh".to_string(), "-c".to_string(), "exit 1".to_string()],
                CommandPhase::Deploy,
                "test_exit",
            )
            .await;

        match result {
            Err(crate::types::Error::Execution(ExecutionError::NonZeroExit { command, code })) => {
                assert!(command.contains("sh -c exit 1"));
                assert_eq!(code, 1);
            }
            _ => panic!("Expected NonZeroExit error, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_command_timeout() {
        let executor = CommandExecutor::new(
            Duration::from_millis(100), // Very short timeout
            HashMap::new(),
            "/tmp",
        );

        let result = executor
            .execute(
                &["sleep".to_string(), "1".to_string()], // Sleep longer than timeout
                CommandPhase::Deploy,
                "test_timeout",
            )
            .await;

        match result {
            Err(crate::types::Error::Execution(ExecutionError::Timeout { command, timeout })) => {
                assert!(command.contains("sleep 1"));
                assert_eq!(timeout, 0); // Timeout was less than 1 second
            }
            _ => panic!("Expected Timeout error, got: {:?}", result),
        }
    }

    #[tokio::test]
    async fn test_command_with_environment_variables() {
        let mut env = HashMap::new();
        env.insert("TEST_VAR".to_string(), "test_value".to_string());

        let executor = CommandExecutor::new(Duration::from_secs(10), env, "/tmp");

        let result = executor
            .execute(
                &[
                    "sh".to_string(),
                    "-c".to_string(),
                    "echo $TEST_VAR".to_string(),
                ],
                CommandPhase::Deploy,
                "test_env",
            )
            .await
            .unwrap();

        assert_eq!(result.stdout.trim(), "test_value");
    }

    #[tokio::test]
    async fn test_command_with_working_directory() {
        let temp_dir = tempdir().unwrap();
        let temp_path = temp_dir.path();

        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), temp_path);

        let result = executor
            .execute(&["pwd".to_string()], CommandPhase::Deploy, "test_pwd")
            .await
            .unwrap();

        assert_eq!(result.stdout.trim(), temp_path.to_string_lossy());
    }

    #[tokio::test]
    async fn test_empty_command() {
        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp");

        let result = executor
            .execute(&[], CommandPhase::Deploy, "test_empty")
            .await;

        assert!(matches!(
            result,
            Err(crate::types::Error::Execution(
                ExecutionError::StartFailed { .. }
            ))
        ));
    }

    #[tokio::test]
    async fn test_retry_logic_with_template_context() {
        let executor = CommandExecutor::new(Duration::from_secs(10), HashMap::new(), "/tmp");

        let context = ExecutionContext::new().with_built_in_variables(
            "registry:5000/app:v1.0.0".to_string(),
            "web-service".to_string(),
            "deploy-001".to_string(),
            "/srv/app".to_string(),
        );

        // Test template expansion in command execution
        let step = ExecutionStep::new(
            "template_expansion_test".to_string(),
            vec!["echo".to_string(), "Hello {{DEPLOY_ID}}".to_string()],
        )
        .with_retries(0, 0)
        .with_critical(false);

        let result =
            execute_with_retry_and_context(&executor, &step, &context, CommandPhase::Deploy)
                .await
                .unwrap();

        assert_eq!(result.retries, 0);
        assert_eq!(result.exit_code, Some(0));
        assert!(result.stdout.contains("deploy-001"));
    }

    #[test]
    fn test_calculate_retry_delay() {
        assert_eq!(calculate_retry_delay(1, 2), 2); // 2 * 2^0 = 2
        assert_eq!(calculate_retry_delay(2, 2), 4); // 2 * 2^1 = 4
        assert_eq!(calculate_retry_delay(3, 2), 8); // 2 * 2^2 = 8
        assert_eq!(calculate_retry_delay(10, 2), 60); // Capped at 60
    }

    #[test]
    fn test_truncate_output() {
        let small_output = b"hello world".to_vec();
        assert_eq!(truncate_output(small_output), "hello world");

        let large_output = "x".repeat(MAX_OUTPUT_SIZE + 100).into_bytes();
        let result = truncate_output(large_output);
        assert!(result.contains("truncated"));
        assert!(result.len() > MAX_OUTPUT_SIZE); // Includes truncation message
    }

    #[test]
    fn test_execution_step_builder() {
        let step = ExecutionStep::new(
            "test".to_string(),
            vec!["echo".to_string(), "hello".to_string()],
        )
        .with_retries(3, 5)
        .with_critical(false)
        .with_timeout(Duration::from_secs(30));

        assert_eq!(step.name, "test");
        assert_eq!(step.retries, 3);
        assert_eq!(step.retry_delay, 5);
        assert!(!step.critical);
        assert_eq!(step.timeout, Some(Duration::from_secs(30)));
    }
}
