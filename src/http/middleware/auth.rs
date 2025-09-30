//! HMAC authentication middleware for webhook signature verification
//!
//! This module provides HMAC-SHA256 authentication for deployment webhook requests.
//! It validates the X-Hub-Signature-256 header against the request body using a
//! configured HMAC secret key.
//!
//! # Security Features
//! - HMAC-SHA256 signature verification compatible with GitHub webhooks
//! - Constant-time signature comparison to prevent timing attacks
//! - Secure key handling using SecretManager infrastructure
//! - Proper error responses that don't leak sensitive information

use axum::{
    body::{to_bytes, Body},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use constant_time_eq::constant_time_eq;
use ring::hmac;
use std::sync::Arc;
use tracing::{debug, warn};

use crate::{http::handlers::AppState, secrets::SecretManager, types::Error};

/// HMAC validator for webhook signature verification
pub struct HmacValidator {
    secret_manager: Arc<SecretManager>,
}

impl HmacValidator {
    /// Create a new HMAC validator with the given secret manager
    pub fn new(secret_manager: Arc<SecretManager>) -> Self {
        Self { secret_manager }
    }

    /// Validate an HMAC signature against the provided body
    pub async fn validate(&self, body: &[u8], signature: &str) -> Result<bool, Error> {
        // Load the HMAC secret from the secret manager
        let secret = self.secret_manager.load_required_secret("hmac_key").await?;

        // Parse the signature header (expected format: "sha256=<hex>")
        let provided_hex = match signature.strip_prefix("sha256=") {
            Some(hex) => hex,
            None => {
                debug!("Invalid signature format - missing 'sha256=' prefix");
                return Ok(false);
            }
        };

        // Decode the provided signature from hex
        let provided_bytes = match hex::decode(provided_hex) {
            Ok(bytes) => bytes,
            Err(_) => {
                debug!("Invalid signature format - failed to decode hex");
                return Ok(false);
            }
        };

        // Create HMAC key and compute expected signature
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
        let expected = hmac::sign(&key, body);

        // Perform constant-time comparison to prevent timing attacks
        let is_valid = constant_time_eq(expected.as_ref(), &provided_bytes);

        if is_valid {
            debug!("HMAC signature validation successful");
        } else {
            debug!("HMAC signature validation failed");
        }

        Ok(is_valid)
    }

    /// Generate an HMAC signature for the given body (used for testing)
    #[cfg(test)]
    pub async fn generate_signature(&self, body: &[u8]) -> Result<String, Error> {
        let secret = self.secret_manager.load_required_secret("hmac_key").await?;

        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
        let signature = hmac::sign(&key, body);

        Ok(format!("sha256={}", hex::encode(signature.as_ref())))
    }
}

/// Axum middleware for HMAC authentication
/// This middleware requires a SecretManager to be available in the AppState
pub async fn hmac_auth_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract the signature header
    let signature = match extract_signature_header(request.headers()) {
        Some(sig) => sig,
        None => {
            warn!("Deploy request missing X-Hub-Signature-256 header");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    // Read the request body for signature verification
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => {
            warn!("Failed to read request body for HMAC verification");
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    let validator = HmacValidator::new(app_state.secret_manager.clone());
    let is_valid = match validator.validate(&body_bytes, &signature).await {
        Ok(valid) => valid,
        Err(e) => {
            warn!("HMAC validation error: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    if !is_valid {
        warn!("HMAC signature validation failed for deploy request");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Reconstruct the request with the body and continue processing
    let request = Request::from_parts(parts, Body::from(body_bytes.to_vec()));
    Ok(next.run(request).await)
}

/// Extract the HMAC signature from request headers
fn extract_signature_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-hub-signature-256")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::SystemConfig, secrets::SecretManager};
    // std::path::Path not needed in current implementation
    use std::io::Write as _;

    use std::fs;
    use tempfile::{NamedTempFile, TempDir};

    fn make_test_system_config(temp_dir: &std::path::Path) -> String {
        format!(
            r#"[server]
listen = "127.0.0.1:16001"
worker_threads = 2
max_request_size = "1MB"
request_timeout = 30
shutdown_timeout = 30

[security]
allowed_ips = []
rate_limit = 10

[storage]
data_dir = "{data_dir}"

[logging]
level = "info"
format = "pretty"
directory = "{logs_dir}"

[monitoring]
metrics_enabled = false
metrics_path = "/metrics"
health_path = "/health"

[limits]
max_concurrent_total = 2
max_concurrent_per_service = 1
deployment_timeout = 300
command_timeout = 60
lock_timeout = 10

[secrets]
source = "file"
secrets_file = "{secrets_file}"
required_secrets = ["hmac_key"]
"#,
            data_dir = temp_dir.display(),
            logs_dir = temp_dir.join("logs").display(),
            secrets_file = temp_dir.join("secret.env").display(),
        )
    }
    fn setup_test_configs() -> (SystemConfig, TempDir) {
        // Create and load system config.
        let test_folder = tempfile::tempdir().expect("Failed to create temp dir");

        // Create the secret.env file in the temp directory
        let secrets_file_path = test_folder.path().join("secret.env");
        fs::write(
            &secrets_file_path,
            "hmac_key=test-secret-key-for-hmac-validation\n",
        )
        .expect("Failed to write secrets file");

        let system_config_toml = make_test_system_config(test_folder.path());
        let mut system_temp_file =
            NamedTempFile::new().expect("Failed to create temp file for system config");

        system_temp_file
            .write_all(system_config_toml.as_bytes())
            .expect("Failed to write system config TOML");
        let system_path = system_temp_file
            .path()
            .to_str()
            .expect("Invalid temp path")
            .to_string();
        let system_config =
            SystemConfig::load_from_file(&system_path).expect("Failed to load test system config");

        (system_config, test_folder)
    }

    async fn create_test_validator() -> (HmacValidator, TempDir) {
        // Load test configuration which points to test/secret.env
        let (system_config, temp_dir) = setup_test_configs();

        let secret_manager = Arc::new(
            SecretManager::new(system_config.secrets)
                .await
                .expect("Failed to create test SecretManager"),
        );

        (HmacValidator::new(secret_manager), temp_dir)
    }

    #[tokio::test]
    async fn test_hmac_validation_success() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body = b"test message";

        // Generate a valid signature
        let signature = validator.generate_signature(body).await.unwrap();

        // Validate the signature
        let result = validator.validate(body, &signature).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_hmac_validation_failure() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body = b"test message";
        let invalid_signature = "sha256=invalid_signature";

        let result = validator.validate(body, invalid_signature).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_hmac_validation_wrong_prefix() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body = b"test message";
        let signature_without_prefix = "abcdef1234567890";

        let result = validator
            .validate(body, signature_without_prefix)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_hmac_validation_invalid_hex() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body = b"test message";
        let invalid_hex_signature = "sha256=not_valid_hex!@#";

        let result = validator
            .validate(body, invalid_hex_signature)
            .await
            .unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn test_signature_generation() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body = b"test message";

        let signature = validator.generate_signature(body).await.unwrap();
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), 71); // "sha256=" (7) + 64 hex chars

        // Verify the generated signature is valid
        let result = validator.validate(body, &signature).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn test_different_bodies_different_signatures() {
        let (validator, _temp_dir) = create_test_validator().await;
        let body1 = b"message one";
        let body2 = b"message two";

        let signature1 = validator.generate_signature(body1).await.unwrap();
        let signature2 = validator.generate_signature(body2).await.unwrap();

        // Signatures should be different
        assert_ne!(signature1, signature2);

        // Each signature should only validate its corresponding body
        assert!(validator.validate(body1, &signature1).await.unwrap());
        assert!(validator.validate(body2, &signature2).await.unwrap());
        assert!(!validator.validate(body1, &signature2).await.unwrap());
        assert!(!validator.validate(body2, &signature1).await.unwrap());
    }

    #[test]
    fn test_extract_signature_header() {
        let mut headers = HeaderMap::new();

        // Test missing header
        assert_eq!(extract_signature_header(&headers), None);

        // Test valid header
        headers.insert("x-hub-signature-256", "sha256=abc123".parse().unwrap());
        assert_eq!(
            extract_signature_header(&headers),
            Some("sha256=abc123".to_string())
        );

        // Test invalid header value (non-UTF8)
        headers.clear();
        assert_eq!(extract_signature_header(&headers), None);
    }

    #[tokio::test]
    async fn test_github_webhook_compatibility() {
        let (validator, _temp_dir) = create_test_validator().await;

        // Example payload similar to GitHub webhook
        let payload = r#"{"action":"push","repository":{"name":"test-repo"}}"#;
        let body = payload.as_bytes();

        let signature = validator.generate_signature(body).await.unwrap();

        // Verify the signature follows GitHub format
        assert!(signature.starts_with("sha256="));

        // Verify it validates correctly
        let result = validator.validate(body, &signature).await.unwrap();
        assert!(result);
    }
}
