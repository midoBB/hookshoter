//! HTTP webhook sender with retry and timeout logic
//!
//! This module handles the actual HTTP POST requests to webhook URLs
//! with configurable retries and timeouts.

use reqwest::Client;
use serde::Serialize;
use std::time::Duration;
use tracing::{debug, info, warn};

use crate::types::Result;

/// Webhook sender with retry and timeout capabilities
#[derive(Clone)]
pub struct WebhookSender {
    client: Client,
    timeout: Duration,
    max_retries: u32,
}

impl WebhookSender {
    /// Create a new WebhookSender with specified timeout
    pub fn new(timeout_seconds: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .build()
            .map_err(|e| {
                crate::types::Error::Application(format!("Failed to create HTTP client: {}", e))
            })?;

        Ok(Self {
            client,
            timeout: Duration::from_secs(timeout_seconds),
            max_retries: 3,
        })
    }

    /// Send a webhook notification with retry logic
    ///
    /// This method sends an HTTP POST request to the specified URL with the given payload.
    /// It will retry up to `max_retries` times with exponential backoff on failure.
    ///
    /// Retry schedule: 1s, 2s, 4s
    pub async fn send<T: Serialize>(&self, url: &str, payload: &T) -> Result<()> {
        let mut last_error = None;

        for attempt in 0..self.max_retries {
            if attempt > 0 {
                let delay = Duration::from_secs(1u64 << (attempt - 1)); // Exponential: 1s, 2s, 4s
                debug!(
                    url = %url,
                    attempt = attempt + 1,
                    delay_ms = delay.as_millis(),
                    "Retrying webhook notification after delay"
                );
                tokio::time::sleep(delay).await;
            }

            match self.send_once(url, payload).await {
                Ok(()) => {
                    if attempt > 0 {
                        info!(
                            url = %url,
                            attempt = attempt + 1,
                            "Webhook notification succeeded after retry"
                        );
                    } else {
                        debug!(url = %url, "Webhook notification sent successfully");
                    }
                    return Ok(());
                }
                Err(e) => {
                    warn!(
                        url = %url,
                        attempt = attempt + 1,
                        error = %e,
                        "Webhook notification attempt failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        // All retries exhausted
        Err(last_error.unwrap_or_else(|| {
            crate::types::Error::Application(
                "Webhook notification failed: unknown error".to_string(),
            )
        }))
    }

    /// Send a single webhook request without retry
    async fn send_once<T: Serialize>(&self, url: &str, payload: &T) -> Result<()> {
        let response = self
            .client
            .post(url)
            .json(payload)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    crate::types::Error::Application(format!(
                        "Webhook notification timed out after {}s",
                        self.timeout.as_secs()
                    ))
                } else if e.is_connect() {
                    crate::types::Error::Application(format!(
                        "Failed to connect to webhook URL: {}",
                        e
                    ))
                } else {
                    crate::types::Error::Application(format!(
                        "Webhook notification request failed: {}",
                        e
                    ))
                }
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if status.is_client_error() {
            Err(crate::types::Error::Application(format!(
                "Webhook notification failed with client error: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )))
        } else if status.is_server_error() {
            Err(crate::types::Error::Application(format!(
                "Webhook notification failed with server error: {} {}",
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )))
        } else {
            Err(crate::types::Error::Application(format!(
                "Webhook notification returned unexpected status: {}",
                status.as_u16()
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_webhook_sender_creation() {
        let sender = WebhookSender::new(5);
        assert!(sender.is_ok());

        let sender = sender.unwrap();
        assert_eq!(sender.timeout, Duration::from_secs(5));
        assert_eq!(sender.max_retries, 3);
    }

    #[tokio::test]
    async fn test_send_to_invalid_url() {
        let sender = WebhookSender::new(1).unwrap();
        let payload = json!({"test": "data"});

        let result = sender
            .send(
                "http://invalid-domain-that-does-not-exist-12345.com",
                &payload,
            )
            .await;
        assert!(result.is_err());
    }

    // Note: Testing actual webhook delivery requires a mock HTTP server
    // For now, we're just testing the structure and error handling
}
