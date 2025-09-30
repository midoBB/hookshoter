//! Secure in-memory secret storage with memory protection
//!
//! This module provides secure storage for secrets in memory using best practices
//! to prevent exposure through memory dumps, swap files, or debugging tools.
//!
//! # Features
//! - Automatic memory zeroization on drop
//! - Memory locking to prevent swapping
//! - Encrypted storage with ChaCha20Poly1305
//! - SecureString type for safe secret handling

use crate::types::Error;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use parking_lot::Mutex;
use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Errors specific to secure storage operations
#[derive(thiserror::Error, Debug)]
pub enum StorageError {
    #[error("Encryption failed")]
    EncryptionError,

    #[error("Secret '{0}' not found")]
    SecretNotFound(String),

    #[error("Memory lock failed: {0}")]
    MemoryLockFailed(String),
}

impl From<StorageError> for Error {
    fn from(err: StorageError) -> Self {
        Error::Application(err.to_string())
    }
}

/// Memory protection utilities using the region crate
pub struct MemoryProtection;

impl MemoryProtection {
    /// Lock memory pages to prevent swapping to disk
    pub fn lock_memory(data: &[u8]) -> Result<region::LockGuard, StorageError> {
        region::lock(data.as_ptr(), data.len())
            .map_err(|e| StorageError::MemoryLockFailed(format!("Failed to lock memory: {}", e)))
    }

    /// Disable core dumps for the current process
    #[cfg(target_os = "linux")]
    pub fn disable_core_dumps() -> Result<(), StorageError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        // Set core dump size limit to 0
        if let Ok(mut file) = OpenOptions::new()
            .write(true)
            .open("/proc/self/coredump_filter")
        {
            let _ = file.write_all(b"0");
        }

        // Also try to set rlimit
        unsafe {
            let rlimit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &rlimit);
        }

        Ok(())
    }
}

/// Simple encrypted secret storage
#[derive(Clone)]
struct EncryptedSecret {
    ciphertext: Vec<u8>,
    nonce: [u8; 12],
}

/// Secure string that zeros memory on drop and prevents accidental exposure
pub struct SecureString {
    data: Vec<u8>,
    #[allow(dead_code)]
    guard: Option<region::LockGuard>,
}

impl SecureString {
    /// Create a new secure string with memory protection
    pub fn new(data: String) -> Result<Self, StorageError> {
        let bytes = data.into_bytes();
        let guard = MemoryProtection::lock_memory(&bytes).ok();

        Ok(Self { data: bytes, guard })
    }

    /// Expose the string data (use with caution)
    pub fn expose(&self) -> &str {
        // SAFETY: We created this from a valid UTF-8 string
        unsafe { std::str::from_utf8_unchecked(&self.data) }
    }

    /// Get the length without exposing the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the string is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureString([REDACTED {} bytes])", self.data.len())
    }
}

impl std::fmt::Display for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

/// Simple secure secret store
pub struct SecretStore {
    cipher: ChaCha20Poly1305,
    secrets: Arc<Mutex<HashMap<String, EncryptedSecret>>>,
}

impl SecretStore {
    /// Create a new secret store with security initialization
    pub fn new() -> Result<Self, StorageError> {
        // Disable core dumps for security
        MemoryProtection::disable_core_dumps()?;

        let master_key_bytes = ChaCha20Poly1305::generate_key(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&master_key_bytes);

        Ok(Self {
            cipher,
            secrets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Store a secret securely
    pub fn store_secret(&self, key: &str, secret: &str) -> Result<(), StorageError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, secret.as_bytes())
            .map_err(|_| StorageError::EncryptionError)?;

        let encrypted_secret = EncryptedSecret {
            ciphertext,
            nonce: nonce.into(),
        };

        let mut secrets = self.secrets.lock();
        secrets.insert(key.to_string(), encrypted_secret);

        tracing::debug!(secret_key = %key, "Secret stored successfully");
        Ok(())
    }

    /// Retrieve a secret
    pub fn get_secret(&self, key: &str) -> Result<SecureString, StorageError> {
        let secrets = self.secrets.lock();

        let encrypted_secret = secrets
            .get(key)
            .ok_or_else(|| StorageError::SecretNotFound(key.to_string()))?;

        let nonce = Nonce::from_slice(&encrypted_secret.nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, encrypted_secret.ciphertext.as_ref())
            .map_err(|_| StorageError::EncryptionError)?;

        let secret_string =
            String::from_utf8(plaintext).map_err(|_| StorageError::EncryptionError)?;

        tracing::debug!(secret_key = %key, "Secret retrieved successfully");

        SecureString::new(secret_string)
    }
}

/// Utility functions for secure operations
pub struct SecureUtils;

impl SecureUtils {
    /// Constant-time comparison for security-sensitive operations
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        let mut result = 0u8;
        for (byte_a, byte_b) in a.iter().zip(b.iter()) {
            result |= byte_a ^ byte_b;
        }
        result == 0
    }

    /// Generate a cryptographically secure random token
    pub fn generate_secure_token(length: usize) -> String {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        let mut rng = rand::thread_rng();
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Validate HMAC signature using constant-time comparison
    pub fn validate_hmac_signature(expected: &[u8], provided: &[u8]) -> bool {
        Self::constant_time_compare(expected, provided)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string_creation() {
        let secure_str = SecureString::new("test_secret".to_string()).unwrap();
        assert_eq!(secure_str.expose(), "test_secret");
        assert_eq!(secure_str.len(), 11);
        assert!(!secure_str.is_empty());
    }

    #[test]
    fn test_secure_string_debug_redaction() {
        let secure_str = SecureString::new("secret".to_string()).unwrap();
        let debug_str = format!("{:?}", secure_str);
        assert!(debug_str.contains("[REDACTED"));
        assert!(!debug_str.contains("secret"));
    }

    #[test]
    fn test_secret_store_basic_operations() {
        let store = SecretStore::new().unwrap();

        // Store a secret
        store.store_secret("test_key", "test_value").unwrap();

        // Retrieve the secret
        let retrieved = store.get_secret("test_key").unwrap();
        assert_eq!(retrieved.expose(), "test_value");
    }

    #[test]
    fn test_secret_not_found() {
        let store = SecretStore::new().unwrap();

        // Try to get non-existent secret
        let result = store.get_secret("nonexistent");
        assert!(matches!(result, Err(StorageError::SecretNotFound(_))));
    }

    #[test]
    fn test_constant_time_comparison() {
        let a = b"secret123";
        let b = b"secret123";
        let c = b"secret124";

        assert!(SecureUtils::constant_time_compare(a, b));
        assert!(!SecureUtils::constant_time_compare(a, c));
        assert!(!SecureUtils::constant_time_compare(a, b"different_length"));
    }

    #[test]
    fn test_secure_token_generation() {
        let token1 = SecureUtils::generate_secure_token(32);
        let token2 = SecureUtils::generate_secure_token(32);

        assert_eq!(token1.len(), 32);
        assert_eq!(token2.len(), 32);
        assert_ne!(token1, token2); // Should be different
        assert!(token1.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_hmac_validation() {
        let key = b"test_key";
        let data = b"test_data";

        // This is a simplified test - in real usage you'd use proper HMAC
        assert!(SecureUtils::validate_hmac_signature(key, key));
        assert!(!SecureUtils::validate_hmac_signature(key, data));
    }
}
