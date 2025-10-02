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

/// Protected cipher wrapper with memory security
struct ProtectedCipher {
    key: Vec<u8>,
    #[allow(dead_code)]
    guard: Option<region::LockGuard>,
}

impl ProtectedCipher {
    /// Create a new protected cipher with memory locking
    fn new() -> Result<Self, StorageError> {
        let key_bytes = ChaCha20Poly1305::generate_key(&mut OsRng);
        let key = key_bytes.to_vec();
        let guard = MemoryProtection::lock_memory(&key).ok();

        Ok(Self { key, guard })
    }

    /// Encrypt data using the protected key
    fn encrypt(&self, nonce: &Nonce, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| StorageError::EncryptionError)?;

        cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| StorageError::EncryptionError)
    }

    /// Decrypt data using the protected key
    fn decrypt(&self, nonce: &Nonce, ciphertext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| StorageError::EncryptionError)?;

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| StorageError::EncryptionError)
    }
}

impl std::fmt::Debug for ProtectedCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ProtectedCipher([REDACTED {} bytes])", self.key.len())
    }
}

impl Drop for ProtectedCipher {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for ProtectedCipher {}

/// Simple secure secret store
pub struct SecretStore {
    cipher: ProtectedCipher,
    secrets: Arc<Mutex<HashMap<String, EncryptedSecret>>>,
}

impl SecretStore {
    /// Create a new secret store with security initialization
    pub fn new() -> Result<Self, StorageError> {
        // Disable core dumps for security
        MemoryProtection::disable_core_dumps()?;

        let cipher = ProtectedCipher::new()?;

        Ok(Self {
            cipher,
            secrets: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Store a secret securely
    pub fn store_secret(&self, key: &str, secret: &str) -> Result<(), StorageError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self.cipher.encrypt(&nonce, secret.as_bytes())?;

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
            .decrypt(nonce, encrypted_secret.ciphertext.as_ref())?;

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
    fn test_hmac_validation() {
        let key = b"test_key";
        let data = b"test_data";

        // This is a simplified test - in real usage you'd use proper HMAC
        assert!(SecureUtils::validate_hmac_signature(key, key));
        assert!(!SecureUtils::validate_hmac_signature(key, data));
    }

    #[test]
    fn test_protected_cipher_encryption_decryption() {
        let cipher = ProtectedCipher::new().unwrap();
        let plaintext = b"sensitive data";
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        // Encrypt
        let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap();
        assert_ne!(ciphertext.as_slice(), plaintext);

        // Decrypt
        let decrypted = cipher.decrypt(&nonce, &ciphertext).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn test_protected_cipher_debug_redaction() {
        let cipher = ProtectedCipher::new().unwrap();
        let debug_str = format!("{:?}", cipher);
        assert!(debug_str.contains("[REDACTED"));
        assert!(debug_str.contains("32 bytes")); // ChaCha20Poly1305 key is 32 bytes
    }

    #[test]
    fn test_protected_cipher_zeroization() {
        use std::ptr;

        let cipher = ProtectedCipher::new().unwrap();
        let key_ptr = cipher.key.as_ptr();
        let key_len = cipher.key.len();

        // Create a copy to check later (this is just for testing)
        let mut key_copy = vec![0u8; key_len];
        unsafe {
            ptr::copy_nonoverlapping(key_ptr, key_copy.as_mut_ptr(), key_len);
        }

        // Verify the key is not all zeros initially
        assert!(!key_copy.iter().all(|&b| b == 0));

        // Drop the cipher
        drop(cipher);

        // Note: We can't directly verify memory was zeroed because it's deallocated
        // This test mainly ensures the Drop implementation compiles and runs
        // In a real scenario, you'd use tools like valgrind or memory inspection
    }

    #[test]
    fn test_secret_store_with_protected_cipher() {
        let store = SecretStore::new().unwrap();

        // Store multiple secrets
        store.store_secret("key1", "value1").unwrap();
        store.store_secret("key2", "value2").unwrap();

        // Retrieve and verify
        let secret1 = store.get_secret("key1").unwrap();
        let secret2 = store.get_secret("key2").unwrap();

        assert_eq!(secret1.expose(), "value1");
        assert_eq!(secret2.expose(), "value2");
    }

    #[test]
    fn test_cipher_memory_lock_attempt() {
        // This test verifies that memory locking is attempted
        // Even if it fails (e.g., insufficient permissions), the code should handle it gracefully
        let cipher = ProtectedCipher::new().unwrap();

        // The guard field exists, which means memory locking was attempted
        // We can't guarantee it succeeded (depends on OS permissions),
        // but we can verify the code doesn't panic
        assert_eq!(cipher.key.len(), 32); // ChaCha20Poly1305 key size
    }

    #[test]
    fn test_cipher_different_keys_produce_different_ciphertexts() {
        let cipher1 = ProtectedCipher::new().unwrap();
        let cipher2 = ProtectedCipher::new().unwrap();

        let plaintext = b"same plaintext";
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext1 = cipher1.encrypt(&nonce, plaintext).unwrap();
        let ciphertext2 = cipher2.encrypt(&nonce, plaintext).unwrap();

        // Different keys should produce different ciphertexts
        assert_ne!(ciphertext1, ciphertext2);
    }
}
