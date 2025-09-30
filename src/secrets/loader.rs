//! Secret loader implementations for different sources

use std::collections::HashMap;
use std::env;
use std::path::Path;
use tokio::fs;
use tracing::{debug, trace, warn};

use super::SecretError;
use crate::types::Result;

/// Trait for loading secrets from various sources
#[async_trait::async_trait]
pub trait SecretLoader: Send + Sync {
    /// Load a secret by key, returning None if not found
    async fn load_secret(&self, key: &str) -> Result<Option<String>>;

    /// Check if this loader source is available
    async fn is_available(&self) -> bool;

    /// Reload secrets from source (for file-based loaders)
    async fn reload(&mut self) -> Result<()>;

    /// Get the name of this loader for logging
    fn name(&self) -> &'static str;
}

/// Environment variable secret loader
pub struct EnvVarSecretLoader {
    prefix: String,
}

impl EnvVarSecretLoader {
    pub fn new(prefix: String) -> Self {
        Self { prefix }
    }
}

#[async_trait::async_trait]
impl SecretLoader for EnvVarSecretLoader {
    async fn load_secret(&self, key: &str) -> Result<Option<String>> {
        // Try direct key first
        if let Ok(value) = env::var(key) {
            trace!("Found secret '{}' directly from environment", key);
            return Ok(Some(value));
        }

        // Try with prefix
        let prefixed_key = if self.prefix.is_empty() {
            key.to_uppercase()
        } else {
            format!("{}_{}", self.prefix, key.to_uppercase())
        };

        match env::var(&prefixed_key) {
            Ok(value) => {
                trace!(
                    "Found secret '{}' as '{}' from environment",
                    key, prefixed_key
                );
                Ok(Some(value))
            }
            Err(env::VarError::NotPresent) => {
                trace!(
                    "Secret '{}' not found in environment (tried '{}' and '{}')",
                    key, key, prefixed_key
                );
                Ok(None)
            }
            Err(env::VarError::NotUnicode(_)) => Err(SecretError::KeyTransformError(format!(
                "Environment variable '{}' contains invalid UTF-8",
                prefixed_key
            ))
            .into()),
        }
    }

    async fn is_available(&self) -> bool {
        true // Environment variables are always available
    }

    async fn reload(&mut self) -> Result<()> {
        // Environment variables don't need reloading
        Ok(())
    }

    fn name(&self) -> &'static str {
        "env"
    }
}

/// File-based secret loader for key=value format
pub struct FileSecretLoader {
    file_path: String,
    secrets: HashMap<String, String>,
    last_modified: Option<std::time::SystemTime>,
}

impl FileSecretLoader {
    pub fn new(file_path: String) -> Self {
        Self {
            file_path,
            secrets: HashMap::new(),
            last_modified: None,
        }
    }

    /// Parse key=value file format with comment support
    async fn parse_secrets_file(&self) -> Result<HashMap<String, String>> {
        let content = fs::read_to_string(&self.file_path).await.map_err(|e| {
            SecretError::FileParseError(
                self.file_path.clone(),
                format!("Failed to read file: {}", e),
            )
        })?;

        let mut secrets = HashMap::new();

        for (line_num, line) in content.lines().enumerate() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse key=value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim().to_string();
                let value = value.trim().to_string();

                if key.is_empty() {
                    warn!(
                        "Empty key found in secrets file '{}' at line {}",
                        self.file_path,
                        line_num + 1
                    );
                    continue;
                }

                secrets.insert(key, value);
            } else {
                warn!(
                    "Invalid line format in secrets file '{}' at line {}: {}",
                    self.file_path,
                    line_num + 1,
                    line
                );
            }
        }

        debug!(
            "Parsed {} secrets from file '{}'",
            secrets.len(),
            self.file_path
        );
        Ok(secrets)
    }

    /// Check if file has been modified since last load
    async fn is_file_modified(&self) -> Result<bool> {
        let metadata = fs::metadata(&self.file_path).await.map_err(|e| {
            SecretError::FileParseError(
                self.file_path.clone(),
                format!("Failed to read file metadata: {}", e),
            )
        })?;

        let modified = metadata.modified().map_err(|e| {
            SecretError::FileParseError(
                self.file_path.clone(),
                format!("Failed to get file modification time: {}", e),
            )
        })?;

        Ok(self.last_modified.is_none_or(|last| modified > last))
    }
}

#[async_trait::async_trait]
impl SecretLoader for FileSecretLoader {
    async fn load_secret(&self, key: &str) -> Result<Option<String>> {
        if let Some(value) = self.secrets.get(key) {
            trace!("Found secret '{}' in file '{}'", key, self.file_path);
            Ok(Some(value.clone()))
        } else {
            trace!("Secret '{}' not found in file '{}'", key, self.file_path);
            Ok(None)
        }
    }

    async fn is_available(&self) -> bool {
        Path::new(&self.file_path).exists()
    }

    async fn reload(&mut self) -> Result<()> {
        if !self.is_available().await {
            return Err(SecretError::SourceNotAvailable(format!("file:{}", self.file_path)).into());
        }

        // Check if file has been modified
        if !self.is_file_modified().await? {
            trace!(
                "Secrets file '{}' has not been modified, skipping reload",
                self.file_path
            );
            return Ok(());
        }

        self.secrets = self.parse_secrets_file().await?;

        // Update last modified time
        let metadata = fs::metadata(&self.file_path).await.map_err(|e| {
            SecretError::ReloadError(format!("Failed to read file metadata after reload: {}", e))
        })?;
        self.last_modified = Some(metadata.modified().map_err(|e| {
            SecretError::ReloadError(format!(
                "Failed to get file modification time after reload: {}",
                e
            ))
        })?);

        debug!(
            "Reloaded {} secrets from file '{}'",
            self.secrets.len(),
            self.file_path
        );
        Ok(())
    }

    fn name(&self) -> &'static str {
        "file"
    }
}

/// Systemd credentials directory loader
pub struct SystemdCredentialsLoader {
    credentials_dir: Option<String>,
}

impl SystemdCredentialsLoader {
    pub fn new() -> Self {
        let credentials_dir = env::var("CREDENTIALS_DIRECTORY").ok();
        Self { credentials_dir }
    }

    async fn load_credential_file(&self, key: &str) -> Result<Option<String>> {
        let Some(ref dir) = self.credentials_dir else {
            return Ok(None);
        };

        let file_path = format!("{}/{}", dir, key);

        match fs::read_to_string(&file_path).await {
            Ok(content) => {
                let value = content.trim().to_string();
                trace!("Found secret '{}' in systemd credentials", key);
                Ok(Some(value))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                trace!("Secret '{}' not found in systemd credentials", key);
                Ok(None)
            }
            Err(e) => Err(SecretError::FileParseError(
                file_path,
                format!("Failed to read credential file: {}", e),
            )
            .into()),
        }
    }
}

impl Default for SystemdCredentialsLoader {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecretLoader for SystemdCredentialsLoader {
    async fn load_secret(&self, key: &str) -> Result<Option<String>> {
        self.load_credential_file(key).await
    }

    async fn is_available(&self) -> bool {
        if let Some(ref dir) = self.credentials_dir {
            Path::new(dir).is_dir()
        } else {
            false
        }
    }

    async fn reload(&mut self) -> Result<()> {
        // Systemd credentials don't need reloading as they're managed by systemd
        Ok(())
    }

    fn name(&self) -> &'static str {
        "systemd"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_env_var_loader() {
        let loader = EnvVarSecretLoader::new("TEST_PREFIX".to_string());

        // Set test environment variable
        unsafe {
            env::set_var("TEST_PREFIX_SECRET_KEY", "test_value");
        }

        let result = loader.load_secret("secret_key").await.unwrap();
        assert_eq!(result, Some("test_value".to_string()));

        let result = loader.load_secret("nonexistent").await.unwrap();
        assert_eq!(result, None);

        // Clean up
        unsafe {
            env::remove_var("TEST_PREFIX_SECRET_KEY");
        }
    }

    #[tokio::test]
    async fn test_file_loader() {
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "# This is a comment").unwrap();
        writeln!(temp_file, "secret1=value1").unwrap();
        writeln!(temp_file).unwrap(); // Empty line
        writeln!(temp_file, "secret2 = value2 ").unwrap(); // With spaces
        writeln!(temp_file, "# Another comment").unwrap();
        writeln!(temp_file, "secret3=value with spaces").unwrap();
        temp_file.flush().unwrap();

        let mut loader = FileSecretLoader::new(temp_file.path().to_string_lossy().to_string());
        loader.reload().await.unwrap();

        assert_eq!(
            loader.load_secret("secret1").await.unwrap(),
            Some("value1".to_string())
        );
        assert_eq!(
            loader.load_secret("secret2").await.unwrap(),
            Some("value2".to_string())
        );
        assert_eq!(
            loader.load_secret("secret3").await.unwrap(),
            Some("value with spaces".to_string())
        );
        assert_eq!(loader.load_secret("nonexistent").await.unwrap(), None);
    }

    #[tokio::test]
    async fn test_systemd_loader() {
        let loader = SystemdCredentialsLoader::new();

        // Without CREDENTIALS_DIRECTORY set, should not be available
        assert!(!loader.is_available().await);

        let result = loader.load_secret("test").await.unwrap();
        assert_eq!(result, None);
    }
}
