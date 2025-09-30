//! Multi-source secret loading system
//!
//! This module provides a flexible secret loading system that can retrieve secrets
//! from multiple sources including environment variables, files, and systemd credentials.
//!
//! # Features
//! - Multiple secret sources with configurable priority
//! - Environment variable loading with prefix transformation
//! - Key=value file parsing with comment support
//! - Systemd credentials directory support
//! - Auto-detection of available sources
//! - Secret reloading capability
//! - Secure logging that masks secret values

pub mod loader;
pub mod manager;
pub mod storage;

pub use loader::{EnvVarSecretLoader, FileSecretLoader, SecretLoader, SystemdCredentialsLoader};
pub use manager::SecretManager;
pub use storage::{SecretStore, SecureString, StorageError};

use crate::types::Error;

/// Errors specific to secret loading operations
#[derive(thiserror::Error, Debug)]
pub enum SecretError {
    #[error("Secret '{0}' not found in any configured source")]
    SecretNotFound(String),

    #[error("Required secret '{0}' is missing")]
    RequiredSecretMissing(String),

    #[error("Secret source '{0}' is not available")]
    SourceNotAvailable(String),

    #[error("Failed to parse secrets file '{0}': {1}")]
    FileParseError(String, String),

    #[error("Secret key transformation failed: {0}")]
    KeyTransformError(String),

    #[error("Secret reload failed: {0}")]
    ReloadError(String),

    #[error("Storage error: {0}")]
    Storage(#[from] StorageError),
}

impl From<SecretError> for Error {
    fn from(err: SecretError) -> Self {
        Error::Application(err.to_string())
    }
}

/// Transform environment variable names to secret keys
/// Example: DEPLOY_RECEIVER_HMAC_SECRET -> hmac_secret
pub fn transform_env_key(env_key: &str, prefix: &str) -> Option<String> {
    if !env_key.starts_with(prefix) {
        return None;
    }

    let key = env_key.strip_prefix(prefix)?;
    Some(key.trim_start_matches('_').to_lowercase())
}

/// Mask secret value for logging purposes
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        "[empty]".to_string()
    } else if value.len() <= 8 {
        "*".repeat(value.len())
    } else {
        format!("{}***{}", &value[..2], &value[value.len() - 2..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transform_env_key() {
        assert_eq!(
            transform_env_key("DEPLOY_RECEIVER_HMAC_SECRET", "DEPLOY_RECEIVER"),
            Some("hmac_secret".to_string())
        );
        assert_eq!(
            transform_env_key("DEPLOY_RECEIVER_API_KEY", "DEPLOY_RECEIVER"),
            Some("api_key".to_string())
        );
        assert_eq!(transform_env_key("OTHER_SECRET", "DEPLOY_RECEIVER"), None);
        assert_eq!(
            transform_env_key("DEPLOY_RECEIVER", "DEPLOY_RECEIVER"),
            Some("".to_string())
        );
    }

    #[test]
    fn test_mask_secret() {
        assert_eq!(mask_secret(""), "[empty]");
        assert_eq!(mask_secret("short"), "*****");
        assert_eq!(mask_secret("verylongsecretkey"), "ve***ey");
        assert_eq!(mask_secret("12345678"), "********");
        assert_eq!(mask_secret("123456789"), "12***89");
    }
}
