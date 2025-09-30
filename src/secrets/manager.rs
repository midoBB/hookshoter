//! Secret manager that orchestrates multiple secret loaders with secure storage

use tracing::{debug, info, trace, warn};

use super::{
    EnvVarSecretLoader, FileSecretLoader, SecretError, SecretLoader, SecretStore, SecureString,
    SystemdCredentialsLoader,
};
use crate::config::{SecretSource, SecretsConfig};
use crate::types::Result;

/// Manages multiple secret sources with secure storage
pub struct SecretManager {
    config: SecretsConfig,
    secure_store: SecretStore,
}

impl SecretManager {
    /// Create a new SecretManager from configuration
    pub async fn new(config: SecretsConfig) -> Result<Self> {
        let loaders = Self::create_loaders(&config).await?;

        // Initialize secure storage for secrets
        let secure_store = SecretStore::new().map_err(SecretError::Storage)?;

        let manager = Self {
            config: config.clone(),
            secure_store,
        };

        // Load all secrets from all sources at startup
        manager.load_all_secrets(&loaders).await?;

        info!(
            "SecretManager initialized with {} loaders and loaded all secrets",
            loaders.len()
        );
        Ok(manager)
    }

    /// Create loaders based on configuration
    async fn create_loaders(config: &SecretsConfig) -> Result<Vec<Box<dyn SecretLoader>>> {
        let mut loaders: Vec<Box<dyn SecretLoader>> = Vec::new();

        let sources = match &config.source {
            SecretSource::Single(source) => {
                if source == "auto" {
                    Self::auto_detect_sources().await
                } else {
                    vec![source.clone()]
                }
            }
            SecretSource::Multiple(sources) => sources.clone(),
        };

        // Create loaders in priority order
        for source_name in &config.sources_priority {
            if !sources.contains(source_name) {
                continue;
            }

            let loader: Box<dyn SecretLoader> = match source_name.as_str() {
                "env" => Box::new(EnvVarSecretLoader::new(config.secret_prefix.clone())),
                "file" => {
                    let mut loader = Box::new(FileSecretLoader::new(config.secrets_file.clone()));
                    if loader.is_available().await {
                        loader.reload().await?;
                    }
                    loader
                }
                "systemd" => Box::new(SystemdCredentialsLoader::new()),
                _ => {
                    warn!("Unknown secret source: {}", source_name);
                    continue;
                }
            };

            if loader.is_available().await {
                debug!("Added secret loader: {}", loader.name());
                loaders.push(loader);
            } else {
                debug!("Secret loader '{}' is not available, skipping", source_name);
            }
        }

        if loaders.is_empty() {
            return Err(SecretError::SourceNotAvailable("no sources available".to_string()).into());
        }

        Ok(loaders)
    }

    /// Auto-detect available secret sources
    async fn auto_detect_sources() -> Vec<String> {
        let mut sources = Vec::new();

        // Check systemd credentials
        if SystemdCredentialsLoader::new().is_available().await {
            sources.push("systemd".to_string());
        }

        // Environment variables are always available
        sources.push("env".to_string());

        debug!("Auto-detected secret sources: {:?}", sources);
        sources
    }

    /// Strip configured prefix from secret key
    fn strip_prefix(&self, key: &str) -> String {
        if self.config.secret_prefix.is_empty() {
            key.to_string()
        } else if let Some(stripped) = key.strip_prefix(&self.config.secret_prefix) {
            stripped.to_string()
        } else {
            key.to_string()
        }
    }

    /// Load all secrets from all sources and store them securely at startup
    async fn load_all_secrets(&self, loaders: &[Box<dyn SecretLoader>]) -> Result<()> {
        // Track all secrets we've loaded to avoid duplicates
        let mut loaded_secrets = std::collections::HashSet::new();

        // Try all loaders in priority order
        for loader in loaders {
            // For each loader, we need to get all secrets it can provide
            // Since the loader interface only supports loading specific keys,
            // we'll need to try loading the required secrets from config
            for required_secret in &self.config.required_secrets {
                if loaded_secrets.contains(required_secret) {
                    continue; // Already loaded from higher priority source
                }

                match loader.load_secret(required_secret).await {
                    Ok(Some(value)) => {
                        // Strip prefix from key before storing
                        let storage_key = self.strip_prefix(required_secret);
                        if let Err(e) = self.secure_store.store_secret(&storage_key, &value) {
                            warn!("Failed to store secret '{}': {}", storage_key, e);
                        } else {
                            loaded_secrets.insert(required_secret.clone());
                            debug!(
                                "Loaded secret '{}' from {} loader, stored as '{}'",
                                required_secret,
                                loader.name(),
                                storage_key
                            );
                        }
                    }
                    Ok(None) => {
                        trace!(
                            "Secret '{}' not found in {} loader",
                            required_secret,
                            loader.name()
                        );
                    }
                    Err(e) => {
                        warn!(
                            "Error loading secret '{}' from {} loader: {}",
                            required_secret,
                            loader.name(),
                            e
                        );
                    }
                }
            }
        }

        // Check that all required secrets were loaded
        for required_secret in &self.config.required_secrets {
            if !loaded_secrets.contains(required_secret) {
                return Err(SecretError::RequiredSecretMissing(required_secret.clone()).into());
            }
        }

        info!(
            "Successfully loaded {} secrets at startup",
            loaded_secrets.len()
        );
        Ok(())
    }

    /// Load a secret by key from secure storage
    pub async fn load_secret(&self, key: &str) -> Result<Option<SecureString>> {
        // Keys are stored with prefix stripped, so we don't need to strip again here
        // Users should reference secrets by their stripped names
        match self.secure_store.get_secret(key) {
            Ok(secure_string) => {
                trace!("Retrieved secret for key '{}'", key);
                Ok(Some(secure_string))
            }
            Err(super::StorageError::SecretNotFound(_)) => {
                trace!("Secret '{}' not found in storage", key);
                Ok(None)
            }
            Err(e) => {
                warn!("Error accessing secret '{}': {}", key, e);
                Err(SecretError::Storage(e).into())
            }
        }
    }

    /// Load a required secret, returning an error if not found
    pub async fn load_required_secret(&self, key: &str) -> Result<SecureString> {
        match self.load_secret(key).await? {
            Some(secure_string) => {
                debug!(
                    "Loaded required secret '{}' (length: {} bytes)",
                    key,
                    secure_string.len()
                );
                Ok(secure_string)
            }
            None => Err(SecretError::RequiredSecretMissing(key.to_string()).into()),
        }
    }

    /// Validate that all required secrets are available
    pub async fn validate_required_secrets(&self) -> Result<()> {
        let mut missing = Vec::new();

        for key in &self.config.required_secrets {
            if self.load_secret(key).await?.is_none() {
                missing.push(key.clone());
            }
        }

        if !missing.is_empty() {
            return Err(SecretError::RequiredSecretMissing(missing.join(", ")).into());
        }

        info!(
            "All {} required secrets are available",
            self.config.required_secrets.len()
        );
        Ok(())
    }

    /// Get names of configured secret sources for logging
    pub fn get_loader_names(&self) -> Vec<String> {
        match &self.config.source {
            crate::config::SecretSource::Single(source) => {
                if source == "auto" {
                    self.config.sources_priority.clone()
                } else {
                    vec![source.clone()]
                }
            }
            crate::config::SecretSource::Multiple(sources) => sources.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::io::Write;
    use tempfile::NamedTempFile;

    async fn create_test_config(secrets_file: Option<String>) -> SecretsConfig {
        SecretsConfig {
            source: SecretSource::Multiple(vec!["env".to_string(), "file".to_string()]),
            sources_priority: vec!["file".to_string(), "env".to_string()],
            secrets_file: secrets_file.unwrap_or_else(|| "/tmp/nonexistent".to_string()),
            required_secrets: vec![], // Start with empty, tests will add specific secrets
            reload_interval: 60,
            secret_prefix: "TEST_PREFIX".to_string(),
        }
    }

    #[tokio::test]
    async fn test_secret_manager_creation() {
        let config = create_test_config(None).await;
        // This should succeed because no required secrets are set
        assert!(SecretManager::new(config).await.is_ok());
    }

    #[tokio::test]
    async fn test_secret_loading_priority() {
        // Create a temporary secrets file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "test_secret=file_value").unwrap();
        temp_file.flush().unwrap();

        // Set environment variable (lower priority)
        unsafe {
            env::set_var("TEST_PREFIX_TEST_SECRET", "env_value");
        }
        let mut config =
            create_test_config(Some(temp_file.path().to_string_lossy().to_string())).await;
        config.required_secrets.push("test_secret".to_string());
        let manager = SecretManager::new(config).await.unwrap();

        // Should get file value (higher priority) loaded at startup
        let result = manager.load_secret("test_secret").await.unwrap();
        assert!(result.is_some());
        let secure_string = result.unwrap();
        assert_eq!(secure_string.expose(), "file_value");

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_TEST_SECRET");
        }
    }

    #[tokio::test]
    async fn test_required_secret_validation() {
        // Set the required secret
        unsafe {
            env::set_var("TEST_PREFIX_TEST_SECRET", "test_value");
        }

        let mut config = create_test_config(None).await;
        config.required_secrets.push("test_secret".to_string());
        let manager = SecretManager::new(config).await.unwrap();

        // Should pass validation since required secret is available
        assert!(manager.validate_required_secrets().await.is_ok());

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_TEST_SECRET");
        }
    }

    #[tokio::test]
    async fn test_secret_retrieval() {
        unsafe {
            env::set_var("TEST_PREFIX_RETRIEVAL_SECRET", "retrieval_value");
        }
        let mut config = create_test_config(None).await;
        config.required_secrets.push("retrieval_secret".to_string());
        let manager = SecretManager::new(config).await.unwrap();

        // First load
        let result1 = manager.load_secret("retrieval_secret").await.unwrap();
        assert!(result1.is_some());
        let secure_string1 = result1.unwrap();
        assert_eq!(secure_string1.expose(), "retrieval_value");

        // Second load should return same value
        let result2 = manager.load_secret("retrieval_secret").await.unwrap();
        assert!(result2.is_some());
        let secure_string2 = result2.unwrap();
        assert_eq!(secure_string2.expose(), "retrieval_value");

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_RETRIEVAL_SECRET");
        }
    }

    #[tokio::test]
    async fn test_auto_detection() {
        let sources = SecretManager::auto_detect_sources().await;

        // Should always detect env
        assert!(sources.contains(&"env".to_string()));

        // May or may not detect systemd depending on environment
        assert!(!sources.is_empty());
    }

    #[tokio::test]
    async fn test_secure_storage_integration() {
        unsafe {
            env::set_var("TEST_PREFIX_SECURE_SECRET", "secure_test_value");
        }

        let mut config = create_test_config(None).await;
        config.required_secrets.push("secure_secret".to_string());
        let manager = SecretManager::new(config).await.unwrap();

        // Load secret - should be stored securely
        let result = manager.load_secret("secure_secret").await.unwrap();
        assert!(result.is_some());
        let secure_string = result.unwrap();
        assert_eq!(secure_string.expose(), "secure_test_value");
        assert_eq!(secure_string.len(), 17);

        // Load the secret again
        let _result2 = manager.load_secret("secure_secret").await.unwrap();

        // Test required secret loading
        let required_result = manager.load_required_secret("secure_secret").await.unwrap();
        assert_eq!(required_result.expose(), "secure_test_value");

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_SECURE_SECRET");
        }
    }

    #[tokio::test]
    async fn test_secure_string_properties() {
        unsafe {
            env::set_var("TEST_PREFIX_PROPS_SECRET", "test_properties");
        }

        let mut config = create_test_config(None).await;
        config.required_secrets.push("props_secret".to_string());
        let manager = SecretManager::new(config).await.unwrap();

        let result = manager.load_secret("props_secret").await.unwrap();
        assert!(result.is_some());
        let secure_string = result.unwrap();

        // Test SecureString properties
        assert!(!secure_string.is_empty());
        assert_eq!(secure_string.len(), 15);

        // Verify debug output doesn't expose secret
        let debug_output = format!("{:?}", secure_string);
        assert!(debug_output.contains("[REDACTED"));
        assert!(!debug_output.contains("test_properties"));

        // Verify display output doesn't expose secret
        let display_output = format!("{}", secure_string);
        assert_eq!(display_output, "[REDACTED]");

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_PROPS_SECRET");
        }
    }

    #[tokio::test]
    async fn test_nonexistent_secret() {
        let config = create_test_config(None).await;
        let manager = SecretManager::new(config).await.unwrap();

        // Try to load a secret that doesn't exist
        let result = manager.load_secret("nonexistent_secret").await.unwrap();
        assert!(result.is_none());

        // Try to load required secret that doesn't exist
        let required_result = manager.load_required_secret("nonexistent_secret").await;
        assert!(required_result.is_err());
    }

    #[tokio::test]
    async fn test_prefix_stripping_with_file() {
        // Create a temporary secrets file with prefixed keys
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "secret.minio.MINIO_ACCESS_KEY=access123").unwrap();
        writeln!(temp_file, "secret.minio.MINIO_SECRET_KEY=secret456").unwrap();
        temp_file.flush().unwrap();

        let mut config =
            create_test_config(Some(temp_file.path().to_string_lossy().to_string())).await;
        config.secret_prefix = "secret.minio.".to_string();
        config.required_secrets.push("secret.minio.MINIO_ACCESS_KEY".to_string());
        config.required_secrets.push("secret.minio.MINIO_SECRET_KEY".to_string());

        let manager = SecretManager::new(config).await.unwrap();

        // Secrets should be stored with stripped names
        let result = manager.load_secret("MINIO_ACCESS_KEY").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose(), "access123");

        let result = manager.load_secret("MINIO_SECRET_KEY").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose(), "secret456");

        // Original prefixed names should not work
        let result = manager.load_secret("secret.minio.MINIO_ACCESS_KEY").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_empty_prefix_no_stripping() {
        // Create a temporary secrets file
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "MY_SECRET=value123").unwrap();
        temp_file.flush().unwrap();

        let mut config =
            create_test_config(Some(temp_file.path().to_string_lossy().to_string())).await;
        config.secret_prefix = "".to_string();
        config.required_secrets.push("MY_SECRET".to_string());

        let manager = SecretManager::new(config).await.unwrap();

        // Secret should be stored with original name (no stripping)
        let result = manager.load_secret("MY_SECRET").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose(), "value123");
    }

    #[tokio::test]
    async fn test_prefix_stripping_no_match() {
        // Create a temporary secrets file with keys that don't match prefix
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "OTHER_SECRET=value999").unwrap();
        temp_file.flush().unwrap();

        let mut config =
            create_test_config(Some(temp_file.path().to_string_lossy().to_string())).await;
        config.secret_prefix = "secret.minio.".to_string();
        config.required_secrets.push("OTHER_SECRET".to_string());

        let manager = SecretManager::new(config).await.unwrap();

        // Secret should be stored with original name (prefix doesn't match)
        let result = manager.load_secret("OTHER_SECRET").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().expose(), "value999");
    }
}
