//! Notification system for deployment events
//!
//! This module provides webhook notification capabilities for deployment events.
//! Currently supports Discord webhooks, with architecture designed for future
//! extension to other platforms (Slack, Telegram, email, etc.).

mod discord;
mod sender;

use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::types::SystemConfig;
use crate::config::WebhookConfig;
use crate::secrets::SecretManager;
use crate::types::{DeploymentRecord, Result};

use discord::DiscordWebhookPayload;
pub use discord::NotificationEvent;
use sender::WebhookSender;

/// Notification manager that handles sending deployment notifications
pub struct NotificationManager {
    sender: WebhookSender,
    config: SystemConfig,
}

impl NotificationManager {
    /// Create a new NotificationManager
    pub async fn new(
        mut config: SystemConfig,
        secret_manager: Option<Arc<SecretManager>>,
    ) -> Result<Self> {
        // If use_secrets is true, load webhook URLs from secrets
        if config.notifications.webhook.use_secrets {
            if let Some(ref manager) = secret_manager {
                config.notifications.webhook =
                    Self::load_webhooks_from_secrets(&config.notifications.webhook, manager)
                        .await?;
            } else {
                warn!("use_secrets is true but no SecretManager provided, using config values");
            }
        }

        let timeout = config.notifications.webhook.timeout;
        let sender = WebhookSender::new(timeout)?;

        Ok(Self { sender, config })
    }

    /// Load webhook URLs from secrets
    async fn load_webhooks_from_secrets(
        webhook_config: &crate::config::types::WebhookConfig,
        secret_manager: &SecretManager,
    ) -> Result<crate::config::types::WebhookConfig> {
        let mut new_config = WebhookConfig::default();

        // Load on_failure
        if let Ok(Some(secret)) = secret_manager
            .load_secret("notifications.webhook.on_failure")
            .await
        {
            new_config.on_failure = Some(secret.expose().to_string());
            debug!("Loaded on_failure webhook URL from secrets");
        }

        // Load on_rollback
        if let Ok(Some(secret)) = secret_manager
            .load_secret("notifications.webhook.on_rollback")
            .await
        {
            new_config.on_rollback = Some(secret.expose().to_string());
            debug!("Loaded on_rollback webhook URL from secrets");
        }

        // Load on_success
        if let Ok(Some(secret)) = secret_manager
            .load_secret("notifications.webhook.on_success")
            .await
        {
            new_config.on_success = Some(secret.expose().to_string());
            debug!("Loaded on_success webhook URL from secrets");
        }

        new_config.use_secrets = webhook_config.use_secrets;
        new_config.timeout = webhook_config.timeout;

        Ok(new_config)
    }

    /// Check if notifications are enabled
    pub fn is_enabled(&self) -> bool {
        self.config.notifications.enabled
    }

    /// Send a deployment success notification
    ///
    /// This is a non-blocking operation that spawns a background task to send the notification.
    /// Notification failures are logged but do not affect the deployment result.
    pub fn notify_success(&self, deployment: DeploymentRecord) {
        if !self.is_enabled() {
            debug!("Notifications disabled, skipping success notification");
            return;
        }

        if let Some(ref webhook_url) = self.config.notifications.webhook.on_success {
            let url = webhook_url.clone();
            let sender = self.sender.clone();

            info!(
                deploy_id = %deployment.deploy_id,
                service = %deployment.service,
                "Sending success notification"
            );

            // Spawn background task to send notification
            tokio::spawn(async move {
                let payload = discord::build_notification(NotificationEvent::Success, &deployment);

                if let Err(e) = Self::send_notification(&sender, &url, &payload).await {
                    error!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        error = %e,
                        "Failed to send success notification"
                    );
                } else {
                    debug!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        "Success notification sent"
                    );
                }
            });
        } else {
            debug!("No webhook URL configured for success notifications");
        }
    }

    /// Send a deployment failure notification
    ///
    /// This is a non-blocking operation that spawns a background task to send the notification.
    /// Notification failures are logged but do not affect the deployment result.
    pub fn notify_failure(&self, deployment: DeploymentRecord) {
        if !self.is_enabled() {
            debug!("Notifications disabled, skipping failure notification");
            return;
        }

        if let Some(ref webhook_url) = self.config.notifications.webhook.on_failure {
            let url = webhook_url.clone();
            let sender = self.sender.clone();

            info!(
                deploy_id = %deployment.deploy_id,
                service = %deployment.service,
                "Sending failure notification"
            );

            // Spawn background task to send notification
            tokio::spawn(async move {
                let payload = discord::build_notification(NotificationEvent::Failure, &deployment);

                if let Err(e) = Self::send_notification(&sender, &url, &payload).await {
                    error!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        error = %e,
                        "Failed to send failure notification"
                    );
                } else {
                    debug!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        "Failure notification sent"
                    );
                }
            });
        } else {
            debug!("No webhook URL configured for failure notifications");
        }
    }

    /// Send a deployment rollback notification
    ///
    /// This is a non-blocking operation that spawns a background task to send the notification.
    /// Notification failures are logged but do not affect the deployment result.
    pub fn notify_rollback(&self, deployment: DeploymentRecord) {
        if !self.is_enabled() {
            debug!("Notifications disabled, skipping rollback notification");
            return;
        }

        if let Some(ref webhook_url) = self.config.notifications.webhook.on_rollback {
            let url = webhook_url.clone();
            let sender = self.sender.clone();

            info!(
                deploy_id = %deployment.deploy_id,
                service = %deployment.service,
                "Sending rollback notification"
            );

            // Spawn background task to send notification
            tokio::spawn(async move {
                let payload = discord::build_notification(NotificationEvent::Rollback, &deployment);

                if let Err(e) = Self::send_notification(&sender, &url, &payload).await {
                    error!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        error = %e,
                        "Failed to send rollback notification"
                    );
                } else {
                    debug!(
                        deploy_id = %deployment.deploy_id,
                        service = %deployment.service,
                        "Rollback notification sent"
                    );
                }
            });
        } else {
            debug!("No webhook URL configured for rollback notifications");
        }
    }

    /// Internal helper to send notification with error handling
    async fn send_notification(
        sender: &WebhookSender,
        url: &str,
        payload: &DiscordWebhookPayload,
    ) -> Result<()> {
        sender.send(url, payload).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{NotificationsConfig, WebhookConfig};
    use crate::types::DeploymentStatus;
    use std::collections::BTreeMap;

    fn create_test_config(enabled: bool) -> SystemConfig {
        SystemConfig {
            notifications: NotificationsConfig {
                enabled,
                webhook: WebhookConfig {
                    on_success: Some("https://discord.com/api/webhooks/test/success".to_string()),
                    on_failure: Some("https://discord.com/api/webhooks/test/failure".to_string()),
                    on_rollback: Some("https://discord.com/api/webhooks/test/rollback".to_string()),
                    timeout: 5,
                    use_secrets: false,
                },
            },
            ..Default::default()
        }
    }

    fn create_test_deployment() -> DeploymentRecord {
        DeploymentRecord {
            deploy_id: "deploy-test-001".to_string(),
            service: "test-service".to_string(),
            status: DeploymentStatus::Succeeded,
            image: "registry:5000/app:v1.0.0".to_string(),
            previous_image: None,
            started_at: chrono::Utc::now().timestamp(),
            completed_at: Some(chrono::Utc::now().timestamp()),
            duration_ms: Some(90000),
            state_transitions: Vec::new(),
            command_results: Vec::new(),
            rollback_attempted: false,
            rollback_reason: None,
            rollback_succeeded: None,
            metadata: BTreeMap::new(),
            triggered_by: "test".to_string(),
            hmac_valid: true,
        }
    }

    #[tokio::test]
    async fn test_notification_manager_creation() {
        let config = create_test_config(true);
        let manager = NotificationManager::new(config, None).await;
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_is_enabled() {
        let enabled_config = create_test_config(true);
        let manager = NotificationManager::new(enabled_config, None).await.unwrap();
        assert!(manager.is_enabled());

        let disabled_config = create_test_config(false);
        let manager = NotificationManager::new(disabled_config, None)
            .await
            .unwrap();
        assert!(!manager.is_enabled());
    }

    #[tokio::test]
    async fn test_notify_success_when_disabled() {
        let config = create_test_config(false);
        let manager = NotificationManager::new(config, None).await.unwrap();
        let deployment = create_test_deployment();

        // Should not panic when disabled
        manager.notify_success(deployment);
    }

    #[tokio::test]
    async fn test_notify_failure_when_disabled() {
        let config = create_test_config(false);
        let manager = NotificationManager::new(config, None).await.unwrap();
        let mut deployment = create_test_deployment();
        deployment.status = DeploymentStatus::Failed;

        // Should not panic when disabled
        manager.notify_failure(deployment);
    }

    #[tokio::test]
    async fn test_notify_rollback_when_disabled() {
        let config = create_test_config(false);
        let manager = NotificationManager::new(config, None).await.unwrap();
        let mut deployment = create_test_deployment();
        deployment.status = DeploymentStatus::RolledBack;

        // Should not panic when disabled
        manager.notify_rollback(deployment);
    }

    #[tokio::test]
    async fn test_notification_manager_with_no_webhook_urls() {
        let mut config = SystemConfig::default();
        config.notifications.enabled = true;
        config.notifications.webhook.on_success = None;
        config.notifications.webhook.on_failure = None;
        config.notifications.webhook.on_rollback = None;

        let manager = NotificationManager::new(config, None).await.unwrap();
        let deployment = create_test_deployment();

        // Should not panic when no URLs configured
        manager.notify_success(deployment);
    }

    #[tokio::test]
    async fn test_notification_manager_loads_from_secrets() {
        use std::sync::Arc;
        use tempfile::NamedTempFile;
        use std::io::Write;

        // Create temp secrets file
        let mut secrets_file = NamedTempFile::new().unwrap();
        writeln!(secrets_file, "notifications.webhook.on_failure=https://hooks.slack.com/services/SECRET/FAIL").unwrap();
        writeln!(secrets_file, "notifications.webhook.on_rollback=https://hooks.slack.com/services/SECRET/ROLLBACK").unwrap();
        writeln!(secrets_file, "notifications.webhook.on_success=https://hooks.slack.com/services/SECRET/SUCCESS").unwrap();
        writeln!(secrets_file, "hmac_key=TEST_HMAC_KEY").unwrap();
        secrets_file.flush().unwrap();

        // Create config with use_secrets enabled
        let mut config = SystemConfig::default();
        config.notifications.enabled = true;
        config.notifications.webhook.use_secrets = true;
        config.notifications.webhook.on_failure = Some("https://original.com/fail".to_string());
        config.secrets.source = crate::config::types::SecretSource::Single("file".to_string());
        config.secrets.secrets_file = secrets_file.path().to_string_lossy().to_string();
        config.secrets.required_secrets = vec!["hmac_key".to_string(), "notifications.webhook.on_failure".to_string(), "notifications.webhook.on_rollback".to_string(), "notifications.webhook.on_success".to_string()];

        // Create secret manager
        let secret_manager = Arc::new(crate::secrets::SecretManager::new(config.secrets.clone()).await.unwrap());
        let _ = secret_manager.validate_required_secrets().await;

        // Create notification manager - should load from secrets
        let manager = NotificationManager::new(config.clone(), Some(secret_manager))
            .await
            .unwrap();

        // Verify that secrets were loaded
        assert_eq!(
            manager.config.notifications.webhook.on_failure,
            Some("https://hooks.slack.com/services/SECRET/FAIL".to_string())
        );
        assert_eq!(
            manager.config.notifications.webhook.on_rollback,
            Some("https://hooks.slack.com/services/SECRET/ROLLBACK".to_string())
        );
        assert_eq!(
            manager.config.notifications.webhook.on_success,
            Some("https://hooks.slack.com/services/SECRET/SUCCESS".to_string())
        );
    }

    #[tokio::test]
    async fn test_notification_manager_use_secrets_false_ignores_secrets() {
        use std::sync::Arc;
        use tempfile::NamedTempFile;
        use std::io::Write;

        // Create temp secrets file
        let mut secrets_file = NamedTempFile::new().unwrap();
        writeln!(secrets_file, "notifications.webhook.on_failure=https://hooks.slack.com/services/SECRET/FAIL").unwrap();
        writeln!(secrets_file, "hmac_key=TEST_HMAC_KEY").unwrap();
        secrets_file.flush().unwrap();

        // Create config with use_secrets disabled
        let mut config = SystemConfig::default();
        config.notifications.enabled = true;
        config.notifications.webhook.use_secrets = false;
        config.notifications.webhook.on_failure = Some("https://original.com/fail".to_string());
        config.secrets.source = crate::config::types::SecretSource::Single("file".to_string());
        config.secrets.secrets_file = secrets_file.path().to_string_lossy().to_string();

        // Create secret manager
        let secret_manager = Arc::new(crate::secrets::SecretManager::new(config.secrets.clone()).await.unwrap());

        // Create notification manager - should use config values, not secrets
        let manager = NotificationManager::new(config.clone(), Some(secret_manager))
            .await
            .unwrap();

        // Verify that config values were used, not secrets
        assert_eq!(
            manager.config.notifications.webhook.on_failure,
            Some("https://original.com/fail".to_string())
        );
    }

    #[tokio::test]
    async fn test_notification_manager_no_secret_manager_with_use_secrets_true() {
        // Create config with use_secrets enabled but no secret manager
        let mut config = SystemConfig::default();
        config.notifications.enabled = true;
        config.notifications.webhook.use_secrets = true;
        config.notifications.webhook.on_failure = Some("https://original.com/fail".to_string());

        // Create notification manager without secret manager
        let manager = NotificationManager::new(config.clone(), None).await.unwrap();

        // Should fall back to config values and log a warning
        assert_eq!(
            manager.config.notifications.webhook.on_failure,
            Some("https://original.com/fail".to_string())
        );
    }
}
