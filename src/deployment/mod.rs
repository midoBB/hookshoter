//! Deployment workflow orchestration
//!
//! This module implements the core deployment workflow that coordinates
//! command execution, state management, and error handling throughout
//! the deployment lifecycle.

mod healthcheck;
mod rollback;

use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::types::{ServiceConfig, ServicesConfig, SystemConfig};
use crate::execution::executor::{execute_with_retry_and_context, CommandExecutor, ExecutionStep};
use crate::execution::templates::ExecutionContext;
use crate::http::responses::DeployRequest;
use crate::metrics;
use crate::notifications::NotificationManager;
use crate::secrets::SecretManager;
use crate::state::{ConcurrencyGuard, ConcurrencyTracker, StateManager};
use crate::types::{
    CommandPhase, CommandResult, DeploymentRecord, DeploymentStatus, Error, Result, ServiceState,
};

/// DeploymentManager orchestrates the complete deployment lifecycle
pub struct DeploymentManager {
    state_manager: Arc<StateManager>,
    system_config: SystemConfig,
    services_config: ServicesConfig,
    concurrency_tracker: ConcurrencyTracker,
    notification_manager: Option<Arc<NotificationManager>>,
}

impl DeploymentManager {
    /// Create a new DeploymentManager
    pub async fn new(
        state_manager: Arc<StateManager>,
        system_config: SystemConfig,
        services_config: ServicesConfig,
        secret_manager: Option<Arc<SecretManager>>,
    ) -> Self {
        let concurrency_tracker = ConcurrencyTracker::new(
            system_config.limits.max_concurrent_total,
            system_config.limits.max_concurrent_per_service,
        );

        // Initialize notification manager if enabled
        let notification_manager = if system_config.notifications.enabled {
            match NotificationManager::new(system_config.clone(), secret_manager).await {
                Ok(manager) => {
                    info!("Notification manager initialized successfully");
                    Some(Arc::new(manager))
                }
                Err(e) => {
                    warn!(error = %e, "Failed to initialize notification manager, notifications disabled");
                    None
                }
            }
        } else {
            debug!("Notifications disabled in configuration");
            None
        };

        Self {
            state_manager,
            system_config,
            services_config,
            concurrency_tracker,
            notification_manager,
        }
    }

    /// Get the concurrency tracker for this deployment manager
    pub fn concurrency_tracker(&self) -> &ConcurrencyTracker {
        &self.concurrency_tracker
    }

    /// Handle deployment failure by attempting rollback and executing failure hooks
    ///
    /// This helper function consolidates the rollback logic for both deployment command
    /// failures and health check failures to avoid code duplication.
    #[allow(clippy::too_many_arguments)]
    async fn handle_deployment_failure(
        &self,
        deployment: &mut DeploymentRecord,
        deploy_id: &str,
        service_name: &str,
        service_config: &ServiceConfig,
        executor: &CommandExecutor,
        context: &ExecutionContext,
        rollback_reason: String,
        has_previous_image: bool,
    ) -> Result<()> {
        // Record the failure
        deployment.add_state_transition(DeploymentStatus::Failed, Some(rollback_reason.clone()));
        self.state_manager.update_deployment(deployment)?;

        // Attempt rollback if enabled and previous_image is available
        if service_config.rollback.enabled && has_previous_image {
            // Mark that we're attempting rollback
            deployment.rollback_attempted = true;
            deployment.rollback_reason = Some(rollback_reason.clone());

            info!(
                deploy_id = %deploy_id,
                service = %service_name,
                "Attempting rollback after deployment failure"
            );

            deployment.add_state_transition(
                DeploymentStatus::RollingBack,
                Some("Starting rollback due to deployment failure".to_string()),
            );
            self.state_manager.update_deployment(deployment)?;

            // Execute rollback
            match rollback::execute_rollback(
                executor,
                service_config,
                context,
                service_name,
                &rollback_reason,
            )
            .await
            {
                Ok(rollback_results) => {
                    info!(
                        deploy_id = %deploy_id,
                        service = %service_name,
                        "Rollback completed successfully"
                    );

                    deployment.rollback_succeeded = Some(true);
                    deployment.command_results.extend(rollback_results);
                    deployment.add_state_transition(
                        DeploymentStatus::RolledBack,
                        Some("Rollback completed successfully".to_string()),
                    );

                    // Record rollback metric
                    metrics::record_rollback(service_name, &rollback_reason);

                    // Send rollback notification
                    if let Some(ref notifier) = self.notification_manager {
                        notifier.notify_rollback(deployment.clone());
                    }
                }
                Err(rollback_error) => {
                    error!(
                        deploy_id = %deploy_id,
                        service = %service_name,
                        error = %rollback_error,
                        "Rollback failed"
                    );

                    deployment.rollback_succeeded = Some(false);
                    deployment.add_state_transition(
                        DeploymentStatus::RollbackFailed,
                        Some(format!("Rollback failed: {}", rollback_error)),
                    );
                }
            }
        } else {
            info!(
                deploy_id = %deploy_id,
                service = %service_name,
                rollback_enabled = service_config.rollback.enabled,
                has_previous_image = has_previous_image,
                "Skipping rollback (disabled or no previous image)"
            );
        }

        // Execute on_failure hooks (regardless of rollback status)
        match self
            .execute_hooks(
                &service_config.hooks.on_failure,
                CommandPhase::OnFailure,
                context,
                service_config,
            )
            .await
        {
            Ok(hook_results) => {
                // Add hook results to deployment record
                deployment.command_results.extend(hook_results);
            }
            Err(hook_error) => {
                warn!(
                    deploy_id = %deploy_id,
                    error = %hook_error,
                    "Failed to execute on_failure hooks (non-fatal)"
                );
            }
        }

        deployment.mark_completed();
        self.state_manager.update_deployment(deployment)?;

        // Record deployment failure metrics
        if let Some(duration_ms) = deployment.duration_ms {
            metrics::record_deployment_complete(service_name, &deployment.status, duration_ms);
            self.record_phase_metrics(deployment);
        }

        // Update service state
        let mut service_state = self
            .state_manager
            .get_service_state(service_name)?
            .unwrap_or_else(|| ServiceState::new(service_name.to_string()));
        service_state.update_deployment_stats(deployment);
        self.state_manager.update_service_state(&service_state)?;

        // Send failure notification if rollback was not successful or not attempted
        // (Successful rollback sends its own notification above)
        if deployment.status == DeploymentStatus::Failed
            || deployment.status == DeploymentStatus::RollbackFailed
        {
            if let Some(ref notifier) = self.notification_manager {
                notifier.notify_failure(deployment.clone());
            }
        }

        Ok(())
    }

    /// Generate a unique deployment ID
    pub fn generate_deploy_id() -> String {
        format!(
            "deploy-{}-{:03}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            chrono::Utc::now().timestamp_millis() % 1000
        )
    }

    /// Calculate and record phase duration metrics from state transitions
    fn record_phase_metrics(&self, deployment: &DeploymentRecord) {
        let transitions = &deployment.state_transitions;
        if transitions.is_empty() {
            return;
        }

        // Find timestamps for different phases
        let mut deploy_start: Option<i64> = None;
        let mut deploy_end: Option<i64> = None;
        let mut healthcheck_start: Option<i64> = None;
        let mut healthcheck_end: Option<i64> = None;
        let mut rollback_start: Option<i64> = None;
        let mut rollback_end: Option<i64> = None;

        for transition in transitions {
            match transition.to_state {
                DeploymentStatus::Deploying if deploy_start.is_none() => {
                    deploy_start = Some(transition.timestamp);
                }
                DeploymentStatus::HealthChecking if healthcheck_start.is_none() => {
                    healthcheck_start = Some(transition.timestamp);
                    deploy_end = Some(transition.timestamp);
                }
                DeploymentStatus::Succeeded if healthcheck_start.is_some() => {
                    healthcheck_end = Some(transition.timestamp);
                }
                DeploymentStatus::RollingBack if rollback_start.is_none() => {
                    rollback_start = Some(transition.timestamp);
                }
                DeploymentStatus::RolledBack | DeploymentStatus::RollbackFailed
                    if rollback_start.is_some() =>
                {
                    rollback_end = Some(transition.timestamp);
                }
                _ => {}
            }
        }

        // Record deploy phase duration
        if let (Some(start), Some(end)) = (deploy_start, deploy_end) {
            let duration_ms = ((end - start) * 1000) as u64;
            metrics::record_deployment_phase(&deployment.service, "deploy", duration_ms);
        }

        // Record healthcheck phase duration
        if let (Some(start), Some(end)) = (healthcheck_start, healthcheck_end) {
            let duration_ms = ((end - start) * 1000) as u64;
            metrics::record_deployment_phase(&deployment.service, "healthcheck", duration_ms);
        }

        // Record rollback phase duration
        if let (Some(start), Some(end)) = (rollback_start, rollback_end) {
            let duration_ms = ((end - start) * 1000) as u64;
            metrics::record_deployment_phase(&deployment.service, "rollback", duration_ms);
        }
    }

    /// Validate a deployment request against service configuration
    pub fn validate_deployment_request(
        &self,
        request: &DeployRequest,
        service_config: &ServiceConfig,
    ) -> Result<()> {
        info!(
            service = %request.service,
            image = %request.image,
            "Validating deployment request"
        );

        // Validate image against allowed pattern
        let image_pattern = regex::Regex::new(&service_config.security.allowed_image_pattern)
            .map_err(|e| Error::Validation {
                field: "allowed_image_pattern".to_string(),
                message: format!("Invalid regex pattern: {}", e),
            })?;

        if !image_pattern.is_match(&request.image) {
            return Err(Error::Validation {
                field: "image".to_string(),
                message: format!(
                    "Image '{}' does not match allowed pattern '{}'",
                    request.image, service_config.security.allowed_image_pattern
                ),
            });
        }

        // Validate previous_image if provided
        if let Some(ref previous_image) = request.previous_image {
            if !image_pattern.is_match(previous_image) {
                return Err(Error::Validation {
                    field: "previous_image".to_string(),
                    message: format!(
                        "Previous image '{}' does not match allowed pattern '{}'",
                        previous_image, service_config.security.allowed_image_pattern
                    ),
                });
            }
        }

        // Validate environment variable overrides
        for env_key in request.overrides.env.keys() {
            if !service_config
                .security
                .allowed_env_overrides
                .contains(env_key)
            {
                return Err(Error::Validation {
                    field: "overrides.env".to_string(),
                    message: format!(
                        "Environment variable '{}' is not in allowed overrides list",
                        env_key
                    ),
                });
            }
        }

        info!(service = %request.service, "Deployment request validation passed");
        Ok(())
    }

    /// Find a service configuration by name
    fn find_service_config(&self, service_name: &str) -> Result<&ServiceConfig> {
        self.services_config
            .service
            .iter()
            .find(|s| s.name == service_name && s.enabled)
            .ok_or_else(|| Error::Validation {
                field: "service".to_string(),
                message: format!("Service '{}' not found or disabled", service_name),
            })
    }

    /// Execute deployment hooks
    ///
    /// Hooks are executed sequentially and their results are logged.
    /// By default, hook failures are non-fatal (logged as warnings).
    async fn execute_hooks(
        &self,
        hooks: &[Vec<String>],
        phase: CommandPhase,
        context: &ExecutionContext,
        service_config: &ServiceConfig,
    ) -> Result<Vec<CommandResult>> {
        if hooks.is_empty() {
            debug!(phase = ?phase, "No hooks configured for this phase");
            return Ok(Vec::new());
        }

        info!(
            phase = ?phase,
            hook_count = hooks.len(),
            "Executing {} hooks",
            hooks.len()
        );

        let mut hook_results = Vec::new();

        // Create executor for hooks
        let working_dir = service_config
            .working_dir
            .as_ref()
            .unwrap_or(&self.services_config.defaults.working_dir)
            .clone();

        let hook_timeout = Duration::from_secs(self.system_config.limits.command_timeout);
        let executor = CommandExecutor::new(hook_timeout, service_config.env.clone(), &working_dir);

        // Execute each hook sequentially
        for (idx, hook_command) in hooks.iter().enumerate() {
            let hook_name = format!("{:?}_hook_{}", phase, idx + 1);

            info!(
                phase = ?phase,
                hook_index = idx + 1,
                hook_name = %hook_name,
                command = ?hook_command,
                "Executing hook"
            );

            // Create execution step for the hook (non-critical by default)
            let step = ExecutionStep::new(hook_name.clone(), hook_command.clone())
                .with_retries(0, 2)
                .with_critical(false);

            match execute_with_retry_and_context(&executor, &step, context, phase.clone()).await {
                Ok(result) => {
                    info!(
                        phase = ?phase,
                        hook_index = idx + 1,
                        hook_name = %hook_name,
                        duration_ms = result.duration_ms,
                        "Hook executed successfully"
                    );
                    hook_results.push(result);
                }
                Err(e) => {
                    // Hook failures are non-fatal by default
                    warn!(
                        phase = ?phase,
                        hook_index = idx + 1,
                        hook_name = %hook_name,
                        error = %e,
                        "Hook execution failed (non-fatal)"
                    );
                    // Continue with other hooks even if this one failed
                }
            }
        }

        info!(
            phase = ?phase,
            successful = hook_results.len(),
            total = hooks.len(),
            "Completed hook execution"
        );

        Ok(hook_results)
    }

    /// Execute a deployment end-to-end
    pub async fn execute_deployment(
        &self,
        request: DeployRequest,
        triggered_by: String,
    ) -> Result<DeploymentRecord> {
        // Generate deploy_id if not provided
        let deploy_id = request
            .deploy_id
            .clone()
            .unwrap_or_else(Self::generate_deploy_id);

        info!(
            deploy_id = %deploy_id,
            service = %request.service,
            image = %request.image,
            "Starting deployment execution"
        );

        // Create metrics guard to track active deployment
        let _metrics_guard = metrics::DeploymentMetricsGuard::new(request.service.clone());

        // Find service configuration
        let service_config = self.find_service_config(&request.service)?;

        // Create initial deployment record
        let mut deployment = DeploymentRecord::new(
            deploy_id.clone(),
            request.service.clone(),
            request.image.clone(),
            triggered_by,
        );

        // Determine previous_image: use explicit value from request, or fall back to
        // the last successful image from service state
        deployment.previous_image = match request.previous_image {
            Some(ref img) => {
                debug!(
                    service = %request.service,
                    previous_image = %img,
                    "Using explicitly provided previous_image"
                );
                Some(img.clone())
            }
            None => {
                // Query service state to get the last successful image
                match self.state_manager.get_service_state(&request.service)? {
                    Some(service_state) if !service_state.current_image.is_empty() => {
                        info!(
                            service = %request.service,
                            current_image = %service_state.current_image,
                            "No previous_image provided; using last successful image from service state"
                        );
                        Some(service_state.current_image.clone())
                    }
                    _ => {
                        info!(
                            service = %request.service,
                            "No previous_image provided and no deployment history found; rollback will not be available"
                        );
                        None
                    }
                }
            }
        };

        deployment.metadata = request.metadata.clone();
        deployment.hmac_valid = true; // Assume HMAC was validated by middleware

        // Record initial state
        self.state_manager.record_deployment(&deployment)?;

        // Check concurrency limits before attempting to lock
        info!(
            service = %request.service,
            deploy_id = %deploy_id,
            "Checking concurrency limits"
        );

        if let Err(e) = self
            .concurrency_tracker
            .try_acquire(&request.service, &deploy_id)
        {
            error!(
                service = %request.service,
                deploy_id = %deploy_id,
                error = %e,
                "Concurrency limit exceeded"
            );
            deployment.add_state_transition(
                DeploymentStatus::Failed,
                Some(format!("Concurrency limit exceeded: {}", e)),
            );
            deployment.mark_completed();
            self.state_manager.update_deployment(&deployment)?;
            return Err(e);
        }

        // Create concurrency guard to ensure slot is released on exit
        let _concurrency_guard = ConcurrencyGuard::new(
            self.concurrency_tracker.clone(),
            request.service.clone(),
            deploy_id.clone(),
        );

        // Try to acquire combined file and database lock with timeout checking
        info!(service = %request.service, "Attempting to acquire service locks");
        let _lock_guard = match self.state_manager.try_lock_service_combined(
            &request.service,
            &deploy_id,
            Some(self.system_config.limits.lock_timeout),
        ) {
            Ok(guard) => guard,
            Err(e) => {
                error!(service = %request.service, error = %e, "Failed to acquire service locks");
                deployment.add_state_transition(
                    DeploymentStatus::Failed,
                    Some(format!("Failed to acquire service locks: {}", e)),
                );
                deployment.mark_completed();
                self.state_manager.update_deployment(&deployment)?;
                return Err(e);
            }
        };

        // ServiceLockGuard will automatically release both locks on drop

        // Transition to Validating state
        deployment.add_state_transition(
            DeploymentStatus::Validating,
            Some("Validating deployment request".to_string()),
        );
        self.state_manager.update_deployment(&deployment)?;

        // Validate the deployment request
        if let Err(e) = self.validate_deployment_request(&request, service_config) {
            error!(
                deploy_id = %deploy_id,
                error = %e,
                "Deployment validation failed"
            );
            deployment.add_state_transition(
                DeploymentStatus::Failed,
                Some(format!("Validation failed: {}", e)),
            );
            deployment.mark_completed();
            self.state_manager.update_deployment(&deployment)?;
            return Err(e);
        }

        // Build execution context with template variables
        let working_dir = service_config
            .working_dir
            .as_ref()
            .unwrap_or(&self.services_config.defaults.working_dir)
            .clone();

        let mut env = service_config.env.clone();
        env.extend(request.overrides.env.clone());

        let context = ExecutionContext::new()
            .with_built_in_variables(
                request.image.clone(),
                request.service.clone(),
                deploy_id.clone(),
                working_dir.clone(),
            )
            .with_previous_image(deployment.previous_image.clone())
            .with_custom_variables(service_config)
            .with_runtime_variables(
                request
                    .metadata
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect(),
            );

        // Execute pre_deploy hooks
        debug!("Executing pre_deploy hooks");
        match self
            .execute_hooks(
                &service_config.hooks.pre_deploy,
                CommandPhase::PreDeploy,
                &context,
                service_config,
            )
            .await
        {
            Ok(hook_results) => {
                // Add hook results to deployment record
                deployment.command_results.extend(hook_results);
                self.state_manager.update_deployment(&deployment)?;
            }
            Err(e) => {
                warn!(error = %e, "Pre-deploy hooks failed (non-fatal)");
                // Don't fail deployment on hook errors - they're non-fatal by default
            }
        }

        // Transition to Deploying state
        deployment.add_state_transition(
            DeploymentStatus::Deploying,
            Some("Executing deployment commands".to_string()),
        );
        self.state_manager.update_deployment(&deployment)?;

        // Create command executor
        let command_timeout = service_config
            .deploy
            .timeout
            .map(Duration::from_secs)
            .unwrap_or_else(|| Duration::from_secs(self.system_config.limits.command_timeout));

        let executor = CommandExecutor::new(command_timeout, env.clone(), &working_dir);

        // Execute deployment commands sequentially
        info!(
            deploy_id = %deploy_id,
            command_count = service_config.deploy.commands.len(),
            "Executing deployment commands"
        );

        for (idx, command) in service_config.deploy.commands.iter().enumerate() {
            let step_name = format!("deploy_step_{}", idx + 1);
            info!(
                deploy_id = %deploy_id,
                step = %step_name,
                command = ?command,
                "Executing deployment command"
            );

            let step = ExecutionStep::new(step_name.clone(), command.clone())
                .with_retries(service_config.deploy.retries, 2)
                .with_critical(service_config.deploy.critical);

            match execute_with_retry_and_context(&executor, &step, &context, CommandPhase::Deploy)
                .await
            {
                Ok(result) => {
                    info!(
                        deploy_id = %deploy_id,
                        step = %step_name,
                        duration_ms = result.duration_ms,
                        "Deployment command succeeded"
                    );

                    // Record command execution metric
                    let command_name = result
                        .command
                        .first()
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    metrics::record_command_execution(
                        &request.service,
                        "deploy",
                        command_name,
                        result.duration_ms,
                    );

                    deployment.command_results.push(result);
                    self.state_manager.update_deployment(&deployment)?;
                }
                Err(e) => {
                    error!(
                        deploy_id = %deploy_id,
                        step = %step_name,
                        error = %e,
                        "Deployment command failed"
                    );

                    // Handle failure with rollback logic
                    let rollback_reason =
                        format!("Deployment command '{}' failed: {}", step_name, e);
                    let has_previous_image = deployment.previous_image.is_some();
                    self.handle_deployment_failure(
                        &mut deployment,
                        &deploy_id,
                        &request.service,
                        service_config,
                        &executor,
                        &context,
                        rollback_reason,
                        has_previous_image,
                    )
                    .await?;

                    return Err(e);
                }
            }
        }

        // Execute post_deploy hooks
        debug!("Executing post_deploy hooks");
        match self
            .execute_hooks(
                &service_config.hooks.post_deploy,
                CommandPhase::PostDeploy,
                &context,
                service_config,
            )
            .await
        {
            Ok(hook_results) => {
                // Add hook results to deployment record
                deployment.command_results.extend(hook_results);
                self.state_manager.update_deployment(&deployment)?;
            }
            Err(e) => {
                warn!(error = %e, "Post-deploy hooks failed (non-fatal)");
                // Don't fail deployment on hook errors - they're non-fatal by default
            }
        }

        // Execute health checks if configured
        if !service_config.healthcheck.commands.is_empty() {
            info!(
                deploy_id = %deploy_id,
                service = %request.service,
                "Starting health check phase"
            );

            // Transition to HealthChecking state
            deployment.add_state_transition(
                DeploymentStatus::HealthChecking,
                Some("Executing health checks".to_string()),
            );
            self.state_manager.update_deployment(&deployment)?;

            // Execute health checks
            match healthcheck::execute_health_checks(
                &executor,
                &service_config.healthcheck,
                &context,
                &request.service,
            )
            .await
            {
                Ok(health_results) => {
                    info!(
                        deploy_id = %deploy_id,
                        service = %request.service,
                        checks_passed = health_results.len(),
                        "Health checks passed"
                    );

                    // Append health check results to deployment record
                    deployment.command_results.extend(health_results);
                }
                Err(e) => {
                    error!(
                        deploy_id = %deploy_id,
                        service = %request.service,
                        error = %e,
                        "Health checks failed"
                    );

                    // Handle failure with rollback logic
                    let rollback_reason = format!("Health checks failed: {}", e);
                    let has_previous_image = deployment.previous_image.is_some();
                    self.handle_deployment_failure(
                        &mut deployment,
                        &deploy_id,
                        &request.service,
                        service_config,
                        &executor,
                        &context,
                        rollback_reason,
                        has_previous_image,
                    )
                    .await?;

                    return Err(e);
                }
            }
        } else {
            debug!(
                deploy_id = %deploy_id,
                service = %request.service,
                "No health checks configured, skipping health check phase"
            );
        }

        // Transition to Succeeded state
        deployment.add_state_transition(
            DeploymentStatus::Succeeded,
            Some("Deployment completed successfully".to_string()),
        );
        deployment.mark_completed();

        // Update service state with deployment statistics
        let mut service_state = self
            .state_manager
            .get_service_state(&request.service)?
            .unwrap_or_else(|| ServiceState::new(request.service.clone()));
        service_state.update_deployment_stats(&deployment);

        // Atomically update both deployment and service state
        self.state_manager
            .update_deployment_and_service_state(&deployment, &service_state)?;

        info!(
            deploy_id = %deploy_id,
            service = %request.service,
            duration_ms = deployment.duration_ms,
            "Deployment completed successfully"
        );

        // Record deployment completion metrics
        if let Some(duration_ms) = deployment.duration_ms {
            metrics::record_deployment_complete(&request.service, &deployment.status, duration_ms);

            // Calculate and record phase durations from state transitions
            self.record_phase_metrics(&deployment);
        }

        // Send success notification
        if let Some(ref notifier) = self.notification_manager {
            notifier.notify_success(deployment.clone());
        }

        Ok(deployment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        DefaultsConfig, ServiceDeploy, ServiceHealthcheck, ServiceHooks, ServiceRollback,
        ServiceSecurity,
    };
    use std::collections::BTreeMap;
    use std::collections::HashMap;
    use tempfile::tempdir;

    fn create_test_system_config() -> SystemConfig {
        SystemConfig::default()
    }

    fn create_test_service_config(name: &str) -> ServiceConfig {
        ServiceConfig {
            name: name.to_string(),
            description: Some("Test service".to_string()),
            enabled: true,
            working_dir: Some("/tmp".to_string()),
            env: HashMap::new(),
            security: ServiceSecurity {
                allowed_image_pattern: r"^registry\.test:5000/.*:.*$".to_string(),
                allowed_env_overrides: vec!["LOG_LEVEL".to_string(), "DEBUG".to_string()],
            },
            deploy: ServiceDeploy {
                commands: vec![
                    vec!["echo".to_string(), "deploying {{IMAGE}}".to_string()],
                    vec!["echo".to_string(), "deployment complete".to_string()],
                ],
                timeout: Some(30),
                retries: 0,
                critical: true,
            },
            healthcheck: ServiceHealthcheck::default(),
            rollback: ServiceRollback::default(),
            hooks: ServiceHooks::default(),
            templates: HashMap::new(),
            github: None,
        }
    }

    fn create_test_services_config() -> ServicesConfig {
        ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![create_test_service_config("test-service")],
        }
    }

    async fn create_test_deployment_manager(state_manager: Arc<StateManager>) -> DeploymentManager {
        DeploymentManager::new(
            state_manager,
            create_test_system_config(),
            create_test_services_config(),
            None,
        )
        .await
    }

    #[test]
    fn test_generate_deploy_id() {
        let id1 = DeploymentManager::generate_deploy_id();
        // Sleep a tiny bit to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(2));
        let id2 = DeploymentManager::generate_deploy_id();

        assert!(id1.starts_with("deploy-"));
        assert!(id2.starts_with("deploy-"));
        // IDs should be different when generated at different times
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn test_validate_deployment_request_valid() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager).await;

        let service_config = create_test_service_config("test-service");
        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v0.9.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides {
                env: HashMap::from([("LOG_LEVEL".to_string(), "debug".to_string())]),
            },
            dry_run: false,
        };

        let result = manager.validate_deployment_request(&request, &service_config);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_validate_deployment_request_invalid_image() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager).await;

        let service_config = create_test_service_config("test-service");
        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "docker.io/nginx:latest".to_string(), // Doesn't match pattern
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager.validate_deployment_request(&request, &service_config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation { field, .. } => {
                assert_eq!(field, "image");
            }
            e => panic!("Expected Validation error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_validate_deployment_request_invalid_env_override() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager).await;

        let service_config = create_test_service_config("test-service");
        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides {
                env: HashMap::from([("UNAUTHORIZED_VAR".to_string(), "value".to_string())]),
            },
            dry_run: false,
        };

        let result = manager.validate_deployment_request(&request, &service_config);
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::Validation { field, .. } => {
                assert_eq!(field, "overrides.env");
            }
            e => panic!("Expected Validation error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_find_service_config() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager).await;

        let result = manager.find_service_config("test-service");
        assert!(result.is_ok());

        let not_found = manager.find_service_config("nonexistent-service");
        assert!(not_found.is_err());
    }

    #[tokio::test]
    async fn test_execute_deployment_success() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v0.9.0".to_string()),
            metadata: BTreeMap::from([("git_sha".to_string(), "abc123".to_string())]),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request.clone(), "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();
        assert_eq!(deployment.deploy_id, "deploy-001");
        assert_eq!(deployment.status, DeploymentStatus::Succeeded);
        assert!(deployment.completed_at.is_some());
        assert!(deployment.duration_ms.is_some());
        assert!(!deployment.command_results.is_empty());

        // Verify service is unlocked
        let service_state = state_manager
            .get_service_state("test-service")
            .unwrap()
            .unwrap();
        assert!(!service_state.locked);
        assert_eq!(service_state.current_image, "registry.test:5000/app:v1.0.0");
        assert_eq!(service_state.total_deploys, 1);
    }

    #[tokio::test]
    async fn test_execute_deployment_service_locked() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        // Lock the service manually
        state_manager
            .try_lock_service("test-service", "other-deploy")
            .unwrap();

        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ServiceLocked { service, .. } => {
                assert_eq!(service, "test-service");
            }
            e => panic!("Expected ServiceLocked error, got: {:?}", e),
        }
    }

    #[tokio::test]
    async fn test_execute_deployment_validation_failure() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "invalid:image".to_string(), // Doesn't match pattern
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_err());

        // Verify service is unlocked after validation failure
        let service_state = state_manager
            .get_service_state("test-service")
            .unwrap()
            .unwrap();
        assert!(!service_state.locked);
    }

    #[tokio::test]
    async fn test_rollback_on_deployment_command_failure() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with rollback enabled
        let mut service_config = create_test_service_config("rollback-test-service");
        service_config.deploy.commands = vec![
            vec!["echo".to_string(), "step 1".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()], // This fails
        ];
        service_config.rollback.enabled = true;
        service_config.rollback.commands = vec![vec![
            "echo".to_string(),
            "rolling back to {{PREVIOUS_IMAGE}}".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-rollback-001".to_string()),
            service: "rollback-test-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v1.0.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        // Deployment should fail, but rollback should succeed
        assert!(result.is_err());

        // Check deployment record
        let deployment = state_manager
            .get_deployment("rollback-test-service", "deploy-rollback-001")
            .unwrap()
            .unwrap();

        assert_eq!(deployment.status, DeploymentStatus::RolledBack);
        assert!(deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, Some(true));
        assert!(deployment.rollback_reason.is_some());

        // Verify rollback commands were executed
        let rollback_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::Rollback)
            .collect();
        assert!(!rollback_results.is_empty());

        // Verify service state
        let service_state = state_manager
            .get_service_state("rollback-test-service")
            .unwrap()
            .unwrap();
        assert!(!service_state.locked);
        assert_eq!(service_state.total_rollbacks, 1);
        // After rollback, current_image should be restored to previous_image
        assert_eq!(service_state.current_image, "registry.test:5000/app:v1.0.0");
    }

    #[tokio::test]
    async fn test_rollback_on_health_check_failure() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with health checks but NO health checks after rollback
        let mut service_config = create_test_service_config("healthcheck-rollback-service");
        service_config.deploy.commands = vec![vec!["echo".to_string(), "deployed".to_string()]];

        // Health checks that will fail for the new deployment
        service_config.healthcheck.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        service_config.healthcheck.max_attempts = 2;
        service_config.healthcheck.success_threshold = 1;
        service_config.healthcheck.interval = 0;

        // Rollback is enabled with commands
        service_config.rollback.enabled = true;
        service_config.rollback.commands = vec![vec![
            "echo".to_string(),
            "health check failed, rolling back".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-health-rollback-001".to_string()),
            service: "healthcheck-rollback-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v1.0.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        // Deployment should fail due to health check
        assert!(result.is_err());

        // Check deployment record
        let deployment = state_manager
            .get_deployment("healthcheck-rollback-service", "deploy-health-rollback-001")
            .unwrap()
            .unwrap();

        // The rollback will also fail because health checks are still configured
        // and they will fail again during rollback verification
        // This is actually correct behavior - if health checks fail after rollback,
        // the rollback itself has failed
        assert_eq!(deployment.status, DeploymentStatus::RollbackFailed);
        assert!(deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, Some(false));
        assert!(deployment
            .rollback_reason
            .as_ref()
            .unwrap()
            .contains("Health check"));

        // Verify service state - RollbackFailed doesn't increment total_rollbacks
        let service_state = state_manager
            .get_service_state("healthcheck-rollback-service")
            .unwrap()
            .unwrap();
        assert_eq!(service_state.total_rollbacks, 0);
    }

    #[tokio::test]
    async fn test_successful_rollback_without_health_checks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with no health checks configured
        // This tests successful rollback when deployment commands fail
        let mut service_config = create_test_service_config("rollback-no-healthcheck-service");

        // Deploy command will fail
        service_config.deploy.commands = vec![
            vec!["echo".to_string(), "step 1".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()],
        ];

        // No health checks configured
        service_config.healthcheck.commands = vec![];

        // Rollback is enabled
        service_config.rollback.enabled = true;
        service_config.rollback.commands = vec![vec![
            "echo".to_string(),
            "rolling back successfully".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-rollback-nocheck-001".to_string()),
            service: "rollback-no-healthcheck-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v1.0.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        // Deployment should fail (deploy command failed)
        assert!(result.is_err());

        // But rollback should succeed (no health checks to fail)
        let deployment = state_manager
            .get_deployment(
                "rollback-no-healthcheck-service",
                "deploy-rollback-nocheck-001",
            )
            .unwrap()
            .unwrap();

        assert_eq!(deployment.status, DeploymentStatus::RolledBack);
        assert!(deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, Some(true));

        // Verify rollback commands were executed
        let rollback_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::Rollback)
            .collect();
        assert!(!rollback_results.is_empty());

        // Verify service state
        let service_state = state_manager
            .get_service_state("rollback-no-healthcheck-service")
            .unwrap()
            .unwrap();
        assert_eq!(service_state.total_rollbacks, 1);
        assert_eq!(service_state.current_image, "registry.test:5000/app:v1.0.0");
    }

    #[tokio::test]
    async fn test_rollback_disabled() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with rollback disabled
        let mut service_config = create_test_service_config("no-rollback-service");
        service_config.deploy.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        service_config.rollback.enabled = false;

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-no-rollback-001".to_string()),
            service: "no-rollback-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v1.0.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_err());

        // Check deployment record - should not have attempted rollback
        let deployment = state_manager
            .get_deployment("no-rollback-service", "deploy-no-rollback-001")
            .unwrap()
            .unwrap();

        assert_eq!(deployment.status, DeploymentStatus::Failed);
        assert!(!deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, None);

        // Verify service state does not track rollback
        let service_state = state_manager
            .get_service_state("no-rollback-service")
            .unwrap()
            .unwrap();
        assert_eq!(service_state.total_rollbacks, 0);
    }

    #[tokio::test]
    async fn test_rollback_failure() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with rollback that will fail
        let mut service_config = create_test_service_config("rollback-fail-service");
        service_config.deploy.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        service_config.rollback.enabled = true;
        service_config.rollback.max_attempts = 2;
        service_config.rollback.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]]; // Rollback command fails

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-rollback-fail-001".to_string()),
            service: "rollback-fail-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v1.0.0".to_string()),
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_err());

        // Check deployment record
        let deployment = state_manager
            .get_deployment("rollback-fail-service", "deploy-rollback-fail-001")
            .unwrap()
            .unwrap();

        assert_eq!(deployment.status, DeploymentStatus::RollbackFailed);
        assert!(deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, Some(false));
    }

    #[tokio::test]
    async fn test_rollback_without_previous_image() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        let mut service_config = create_test_service_config("no-previous-image-service");
        service_config.deploy.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        service_config.rollback.enabled = true;

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-no-prev-001".to_string()),
            service: "no-previous-image-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: None, // No previous image
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_err());

        // Check deployment record - should not have attempted rollback
        let deployment = state_manager
            .get_deployment("no-previous-image-service", "deploy-no-prev-001")
            .unwrap()
            .unwrap();

        assert_eq!(deployment.status, DeploymentStatus::Failed);
        assert!(!deployment.rollback_attempted);
    }

    #[tokio::test]
    async fn test_pre_deploy_hooks_execute() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with pre_deploy hooks
        let mut service_config = create_test_service_config("hooks-test-service");
        service_config.hooks.pre_deploy = vec![
            vec!["echo".to_string(), "Pre-deploy hook 1".to_string()],
            vec![
                "echo".to_string(),
                "Pre-deploy hook 2 for {{SERVICE}}".to_string(),
            ],
        ];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-hooks-001".to_string()),
            service: "hooks-test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();

        // Check that pre_deploy hooks were executed
        let pre_deploy_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::PreDeploy)
            .collect();

        assert_eq!(pre_deploy_results.len(), 2);
        assert!(pre_deploy_results[0].step_name.contains("PreDeploy_hook_1"));
        assert!(pre_deploy_results[1].step_name.contains("PreDeploy_hook_2"));
        assert_eq!(pre_deploy_results[0].exit_code, Some(0));
        assert_eq!(pre_deploy_results[1].exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_post_deploy_hooks_execute() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with post_deploy hooks
        let mut service_config = create_test_service_config("post-hooks-test-service");
        service_config.hooks.post_deploy = vec![
            vec![
                "echo".to_string(),
                "Post-deploy hook for {{DEPLOY_ID}}".to_string(),
            ],
            vec!["echo".to_string(), "Post-deploy completed".to_string()],
        ];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-post-hooks-001".to_string()),
            service: "post-hooks-test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();

        // Check that post_deploy hooks were executed
        let post_deploy_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::PostDeploy)
            .collect();

        assert_eq!(post_deploy_results.len(), 2);
        assert!(post_deploy_results[0]
            .step_name
            .contains("PostDeploy_hook_1"));
        assert!(post_deploy_results[1]
            .step_name
            .contains("PostDeploy_hook_2"));
        assert_eq!(post_deploy_results[0].exit_code, Some(0));
        assert_eq!(post_deploy_results[1].exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_on_failure_hooks_execute() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with deployment that fails and on_failure hooks
        let mut service_config = create_test_service_config("failure-hooks-test-service");
        service_config.deploy.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]];
        service_config.rollback.enabled = false; // Disable rollback for this test
        service_config.hooks.on_failure = vec![
            vec![
                "echo".to_string(),
                "Failure hook for {{SERVICE}}".to_string(),
            ],
            vec!["echo".to_string(), "Deployment failed".to_string()],
        ];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-failure-hooks-001".to_string()),
            service: "failure-hooks-test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        // Deployment should fail
        assert!(result.is_err());

        // Check deployment record
        let deployment = state_manager
            .get_deployment("failure-hooks-test-service", "deploy-failure-hooks-001")
            .unwrap()
            .unwrap();

        // Check that on_failure hooks were executed
        let failure_hook_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::OnFailure)
            .collect();

        assert_eq!(failure_hook_results.len(), 2);
        assert!(failure_hook_results[0]
            .step_name
            .contains("OnFailure_hook_1"));
        assert!(failure_hook_results[1]
            .step_name
            .contains("OnFailure_hook_2"));
    }

    #[tokio::test]
    async fn test_hooks_with_template_variables() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with hooks that use template variables
        let mut service_config = create_test_service_config("template-hooks-service");
        service_config.hooks.pre_deploy = vec![vec![
            "echo".to_string(),
            "Deploying {{IMAGE}} for {{SERVICE}} ({{DEPLOY_ID}})".to_string(),
        ]];
        service_config.hooks.post_deploy = vec![vec![
            "echo".to_string(),
            "Completed deployment {{DEPLOY_ID}}".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-template-001".to_string()),
            service: "template-hooks-service".to_string(),
            image: "registry.test:5000/myapp:v2.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();

        // Check that hooks executed and templates were expanded
        let pre_deploy_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::PreDeploy)
            .collect();

        assert_eq!(pre_deploy_results.len(), 1);
        assert!(pre_deploy_results[0]
            .stdout
            .contains("registry.test:5000/myapp:v2.0.0"));
        assert!(pre_deploy_results[0]
            .stdout
            .contains("template-hooks-service"));
        assert!(pre_deploy_results[0].stdout.contains("deploy-template-001"));

        let post_deploy_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::PostDeploy)
            .collect();

        assert_eq!(post_deploy_results.len(), 1);
        assert!(post_deploy_results[0]
            .stdout
            .contains("deploy-template-001"));
    }

    #[tokio::test]
    async fn test_hook_failure_is_non_fatal() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with a failing pre_deploy hook
        let mut service_config = create_test_service_config("non-fatal-hook-service");
        service_config.hooks.pre_deploy = vec![
            vec!["echo".to_string(), "Good hook".to_string()],
            vec!["sh".to_string(), "-c".to_string(), "exit 1".to_string()], // This fails
            vec!["echo".to_string(), "Another good hook".to_string()],
        ];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-non-fatal-001".to_string()),
            service: "non-fatal-hook-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        // Deployment should succeed despite hook failure
        assert!(result.is_ok());
        let deployment = result.unwrap();
        assert_eq!(deployment.status, DeploymentStatus::Succeeded);

        // Check that successful hooks were executed (failing hook won't be in results)
        let pre_deploy_results: Vec<_> = deployment
            .command_results
            .iter()
            .filter(|r| r.phase == CommandPhase::PreDeploy)
            .collect();

        // Should have 2 successful hooks (the failing one is not added to results)
        assert_eq!(pre_deploy_results.len(), 2);
    }

    #[tokio::test]
    async fn test_all_hooks_execute_in_order() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with all three types of hooks
        let mut service_config = create_test_service_config("all-hooks-service");
        service_config.hooks.pre_deploy = vec![vec![
            "echo".to_string(),
            "Pre-deploy for {{SERVICE}}".to_string(),
        ]];
        service_config.hooks.post_deploy = vec![vec![
            "echo".to_string(),
            "Post-deploy for {{SERVICE}}".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let request = DeployRequest {
            deploy_id: Some("deploy-all-hooks-001".to_string()),
            service: "all-hooks-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();

        // Verify order: PreDeploy hooks -> Deploy commands -> PostDeploy hooks
        let phases: Vec<_> = deployment
            .command_results
            .iter()
            .map(|r| r.phase.clone())
            .collect();

        // Find first occurrence of each phase
        let pre_deploy_idx = phases.iter().position(|p| *p == CommandPhase::PreDeploy);
        let deploy_idx = phases.iter().position(|p| *p == CommandPhase::Deploy);
        let post_deploy_idx = phases.iter().position(|p| *p == CommandPhase::PostDeploy);

        assert!(pre_deploy_idx.is_some());
        assert!(deploy_idx.is_some());
        assert!(post_deploy_idx.is_some());

        // Verify ordering
        assert!(pre_deploy_idx.unwrap() < deploy_idx.unwrap());
        assert!(deploy_idx.unwrap() < post_deploy_idx.unwrap());
    }

    #[tokio::test]
    async fn test_automatic_previous_image_fallback() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        // First deployment - establish a successful deployment with an image
        let first_request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let first_result = manager
            .execute_deployment(first_request, "127.0.0.1".to_string())
            .await;

        assert!(first_result.is_ok());
        let first_deployment = first_result.unwrap();
        assert_eq!(first_deployment.status, DeploymentStatus::Succeeded);

        // Second deployment - WITHOUT providing previous_image
        let second_request = DeployRequest {
            deploy_id: Some("deploy-002".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: None, // Not provided - should use fallback
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let second_result = manager
            .execute_deployment(second_request, "127.0.0.1".to_string())
            .await;

        assert!(second_result.is_ok());
        let second_deployment = second_result.unwrap();

        // Verify that previous_image was automatically set to the first deployment's image
        assert_eq!(
            second_deployment.previous_image,
            Some("registry.test:5000/app:v1.0.0".to_string())
        );
        assert_eq!(second_deployment.status, DeploymentStatus::Succeeded);
    }

    #[tokio::test]
    async fn test_automatic_previous_image_fallback_with_rollback() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create service config with rollback enabled
        let mut service_config = create_test_service_config("rollback-fallback-service");
        service_config.rollback.enabled = true;
        service_config.rollback.commands = vec![vec![
            "echo".to_string(),
            "rolling back to {{PREVIOUS_IMAGE}}".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![service_config],
        };

        let manager = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        // First deployment - establish a successful deployment
        let first_request = DeployRequest {
            deploy_id: Some("deploy-fallback-001".to_string()),
            service: "rollback-fallback-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let first_result = manager
            .execute_deployment(first_request, "127.0.0.1".to_string())
            .await;

        assert!(first_result.is_ok());

        // Second deployment - WITHOUT previous_image, and it FAILS (triggers rollback)
        let mut failing_service_config = create_test_service_config("rollback-fallback-service");
        failing_service_config.deploy.commands = vec![vec![
            "sh".to_string(),
            "-c".to_string(),
            "exit 1".to_string(),
        ]]; // This will fail
        failing_service_config.rollback.enabled = true;
        failing_service_config.rollback.commands = vec![vec![
            "echo".to_string(),
            "rolling back to {{PREVIOUS_IMAGE}}".to_string(),
        ]];

        let services_config = ServicesConfig {
            defaults: DefaultsConfig::default(),
            service: vec![failing_service_config],
        };

        let manager2 = DeploymentManager::new(
            state_manager.clone(),
            create_test_system_config(),
            services_config,
            None,
        )
        .await;

        let second_request = DeployRequest {
            deploy_id: Some("deploy-fallback-002".to_string()),
            service: "rollback-fallback-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: None, // Not provided - should use fallback for rollback
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let second_result = manager2
            .execute_deployment(second_request, "127.0.0.1".to_string())
            .await;

        // Deployment should fail, but rollback should succeed using fallback previous_image
        assert!(second_result.is_err());

        let deployment = state_manager
            .get_deployment("rollback-fallback-service", "deploy-fallback-002")
            .unwrap()
            .unwrap();

        // Verify automatic fallback was used
        assert_eq!(
            deployment.previous_image,
            Some("registry.test:5000/app:v1.0.0".to_string())
        );
        assert!(deployment.rollback_attempted);
        assert_eq!(deployment.rollback_succeeded, Some(true));
        assert_eq!(deployment.status, DeploymentStatus::RolledBack);
    }

    #[tokio::test]
    async fn test_previous_image_explicit_overrides_fallback() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        // First deployment - establish history
        let first_request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None,
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        manager
            .execute_deployment(first_request, "127.0.0.1".to_string())
            .await
            .unwrap();

        // Second deployment - WITH explicit previous_image (should override fallback)
        let second_request = DeployRequest {
            deploy_id: Some("deploy-002".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v2.0.0".to_string(),
            previous_image: Some("registry.test:5000/app:v0.9.0".to_string()), // Explicit
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let second_result = manager
            .execute_deployment(second_request, "127.0.0.1".to_string())
            .await;

        assert!(second_result.is_ok());
        let second_deployment = second_result.unwrap();

        // Verify that explicit previous_image was used (not the fallback)
        assert_eq!(
            second_deployment.previous_image,
            Some("registry.test:5000/app:v0.9.0".to_string())
        );
    }

    #[tokio::test]
    async fn test_no_previous_image_when_no_history() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());
        let manager = create_test_deployment_manager(state_manager.clone()).await;

        // First deployment for a brand new service (no history)
        let request = DeployRequest {
            deploy_id: Some("deploy-001".to_string()),
            service: "test-service".to_string(),
            image: "registry.test:5000/app:v1.0.0".to_string(),
            previous_image: None, // No previous_image provided
            metadata: BTreeMap::new(),
            overrides: crate::http::responses::DeployOverrides::default(),
            dry_run: false,
        };

        let result = manager
            .execute_deployment(request, "127.0.0.1".to_string())
            .await;

        assert!(result.is_ok());
        let deployment = result.unwrap();

        // Verify that previous_image is None (no fallback available)
        assert_eq!(deployment.previous_image, None);
        assert_eq!(deployment.status, DeploymentStatus::Succeeded);
    }
}
