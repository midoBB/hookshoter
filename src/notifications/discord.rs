//! Discord webhook payload structures and formatting
//!
//! This module implements Discord-specific webhook message formatting
//! with rich embeds for deployment notifications.

use serde::{Deserialize, Serialize};

use crate::types::DeploymentRecord;

/// Discord webhook payload structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordWebhookPayload {
    pub embeds: Vec<DiscordEmbed>,
}

/// Discord embed structure for rich formatting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordEmbed {
    pub title: String,
    pub description: Option<String>,
    pub color: u32,
    pub fields: Vec<DiscordField>,
    pub timestamp: String,
    pub footer: Option<DiscordFooter>,
}

/// Discord embed field
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub inline: bool,
}

/// Discord embed footer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscordFooter {
    pub text: String,
}

/// Notification event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationEvent {
    Success,
    Failure,
    Rollback,
}

impl NotificationEvent {
    /// Get the Discord embed color for this event type
    pub fn color(&self) -> u32 {
        match self {
            NotificationEvent::Success => 3066993,   // Green (#2ECC71)
            NotificationEvent::Failure => 15158332,  // Red (#E74C3C)
            NotificationEvent::Rollback => 16776960, // Orange (#FFA500)
        }
    }

    /// Get the emoji prefix for this event type
    pub fn emoji(&self) -> &'static str {
        match self {
            NotificationEvent::Success => "✅",
            NotificationEvent::Failure => "❌",
            NotificationEvent::Rollback => "🔄",
        }
    }

    /// Get the event name
    pub fn name(&self) -> &'static str {
        match self {
            NotificationEvent::Success => "Deployment Succeeded",
            NotificationEvent::Failure => "Deployment Failed",
            NotificationEvent::Rollback => "Deployment Rolled Back",
        }
    }
}

/// Build a Discord webhook payload for a deployment notification
pub fn build_notification(
    event: NotificationEvent,
    deployment: &DeploymentRecord,
) -> DiscordWebhookPayload {
    let title = format!("{} {}: {}", event.emoji(), event.name(), deployment.service);

    let description = match event {
        NotificationEvent::Success => {
            format!("Deployed `{}`", deployment.image)
        }
        NotificationEvent::Failure => {
            format!("Failed to deploy `{}`", deployment.image)
        }
        NotificationEvent::Rollback => {
            let prev = deployment
                .previous_image
                .as_deref()
                .unwrap_or("previous version");
            format!("Rolled back from `{}` to `{}`", deployment.image, prev)
        }
    };

    let mut fields = vec![
        DiscordField {
            name: "Deploy ID".to_string(),
            value: deployment.deploy_id.clone(),
            inline: true,
        },
        DiscordField {
            name: "Status".to_string(),
            value: format!("{:?}", deployment.status),
            inline: true,
        },
    ];

    // Add duration if available
    if let Some(duration_ms) = deployment.duration_ms {
        let duration_secs = duration_ms / 1000;
        fields.push(DiscordField {
            name: "Duration".to_string(),
            value: format_duration(duration_secs),
            inline: true,
        });
    }

    // Add image info
    fields.push(DiscordField {
        name: "Image".to_string(),
        value: format!("`{}`", deployment.image),
        inline: false,
    });

    // Add previous image for rollback
    if event == NotificationEvent::Rollback {
        if let Some(ref prev_image) = deployment.previous_image {
            fields.push(DiscordField {
                name: "Restored Image".to_string(),
                value: format!("`{}`", prev_image),
                inline: false,
            });
        }
    }

    // Add triggered by
    fields.push(DiscordField {
        name: "Triggered By".to_string(),
        value: deployment.triggered_by.clone(),
        inline: true,
    });

    // Add error/rollback info for failures
    if event == NotificationEvent::Failure || event == NotificationEvent::Rollback {
        if let Some(ref reason) = deployment.rollback_reason {
            fields.push(DiscordField {
                name: "Reason".to_string(),
                value: truncate_text(reason, 1024),
                inline: false,
            });
        }
    }

    // Add metadata if present
    if !deployment.metadata.is_empty() {
        let metadata_str = deployment
            .metadata
            .iter()
            .map(|(k, v)| format!("**{}**: {}", k, v))
            .collect::<Vec<_>>()
            .join("\n");

        if !metadata_str.is_empty() {
            fields.push(DiscordField {
                name: "Metadata".to_string(),
                value: truncate_text(&metadata_str, 1024),
                inline: false,
            });
        }
    }

    let timestamp = chrono::DateTime::from_timestamp(deployment.started_at, 0)
        .unwrap_or_else(chrono::Utc::now)
        .to_rfc3339();

    let embed = DiscordEmbed {
        title,
        description: Some(description),
        color: event.color(),
        fields,
        timestamp,
        footer: Some(DiscordFooter {
            text: "Hookshot Deployment".to_string(),
        }),
    };

    DiscordWebhookPayload {
        embeds: vec![embed],
    }
}

/// Format duration in a human-readable way
fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        format!("{}m {}s", mins, secs)
    } else {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        format!("{}h {}m", hours, mins)
    }
}

/// Truncate text to a maximum length
fn truncate_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        text.to_string()
    } else {
        format!("{}...", &text[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::DeploymentStatus;
    use std::collections::BTreeMap;

    fn create_test_deployment() -> DeploymentRecord {
        DeploymentRecord {
            deploy_id: "deploy-20250930-001".to_string(),
            service: "web-frontend".to_string(),
            status: DeploymentStatus::Succeeded,
            image: "registry.local:8443/app:v2.0.0".to_string(),
            previous_image: Some("registry.local:8443/app:v1.0.0".to_string()),
            started_at: 1727702400,
            completed_at: Some(1727702490),
            duration_ms: Some(90000),
            state_transitions: Vec::new(),
            command_results: Vec::new(),
            rollback_attempted: false,
            rollback_reason: None,
            rollback_succeeded: None,
            metadata: BTreeMap::from([
                ("git_sha".to_string(), "abc123".to_string()),
                ("git_ref".to_string(), "refs/heads/main".to_string()),
            ]),
            triggered_by: "github-actions".to_string(),
            hmac_valid: true,
        }
    }

    #[test]
    fn test_notification_event_colors() {
        assert_eq!(NotificationEvent::Success.color(), 3066993);
        assert_eq!(NotificationEvent::Failure.color(), 15158332);
        assert_eq!(NotificationEvent::Rollback.color(), 16776960);
    }

    #[test]
    fn test_notification_event_emojis() {
        assert_eq!(NotificationEvent::Success.emoji(), "✅");
        assert_eq!(NotificationEvent::Failure.emoji(), "❌");
        assert_eq!(NotificationEvent::Rollback.emoji(), "🔄");
    }

    #[test]
    fn test_build_success_notification() {
        let deployment = create_test_deployment();
        let payload = build_notification(NotificationEvent::Success, &deployment);

        assert_eq!(payload.embeds.len(), 1);
        let embed = &payload.embeds[0];

        assert!(embed.title.contains("✅"));
        assert!(embed.title.contains("Deployment Succeeded"));
        assert!(embed.title.contains("web-frontend"));
        assert_eq!(embed.color, 3066993);
        assert!(embed.description.is_some());
        assert!(embed
            .description
            .as_ref()
            .unwrap()
            .contains("registry.local:8443/app:v2.0.0"));

        // Check fields
        assert!(embed.fields.iter().any(|f| f.name == "Deploy ID"));
        assert!(embed.fields.iter().any(|f| f.name == "Duration"));
        assert!(embed.fields.iter().any(|f| f.name == "Image"));
        assert!(embed.fields.iter().any(|f| f.name == "Triggered By"));
        assert!(embed.fields.iter().any(|f| f.name == "Metadata"));
    }

    #[test]
    fn test_build_failure_notification() {
        let mut deployment = create_test_deployment();
        deployment.status = DeploymentStatus::Failed;
        deployment.rollback_reason = Some("Health check failed".to_string());

        let payload = build_notification(NotificationEvent::Failure, &deployment);

        let embed = &payload.embeds[0];
        assert!(embed.title.contains("❌"));
        assert!(embed.title.contains("Deployment Failed"));
        assert_eq!(embed.color, 15158332);
        assert!(embed.fields.iter().any(|f| f.name == "Reason"));
    }

    #[test]
    fn test_build_rollback_notification() {
        let mut deployment = create_test_deployment();
        deployment.status = DeploymentStatus::RolledBack;
        deployment.rollback_attempted = true;
        deployment.rollback_reason = Some("Deployment command failed".to_string());
        deployment.rollback_succeeded = Some(true);

        let payload = build_notification(NotificationEvent::Rollback, &deployment);

        let embed = &payload.embeds[0];
        assert!(embed.title.contains("🔄"));
        assert!(embed.title.contains("Deployment Rolled Back"));
        assert_eq!(embed.color, 16776960);
        assert!(embed.fields.iter().any(|f| f.name == "Restored Image"));
        assert!(embed.fields.iter().any(|f| f.name == "Reason"));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(30), "30s");
        assert_eq!(format_duration(90), "1m 30s");
        assert_eq!(format_duration(3661), "1h 1m");
    }

    #[test]
    fn test_truncate_text() {
        assert_eq!(truncate_text("short", 100), "short");
        assert_eq!(
            truncate_text("a".repeat(100).as_str(), 50),
            format!("{}...", "a".repeat(47))
        );
    }

    #[test]
    fn test_payload_serialization() {
        let deployment = create_test_deployment();
        let payload = build_notification(NotificationEvent::Success, &deployment);

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("embeds"));
        assert!(json.contains("title"));
        assert!(json.contains("color"));
        assert!(json.contains("fields"));
    }
}
