//! File-based locking using flock(2) via fs2 crate
//!
//! This module provides OS-level file locks that complement the database locks.
//! File locks are automatically released on process termination, providing
//! protection against stale locks from crashed processes.

use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::types::{DatabaseError, Result};

/// Manages file-based locks for services
#[derive(Clone)]
pub struct FileLockManager {
    /// Directory where lock files are stored
    lock_dir: PathBuf,
}

impl FileLockManager {
    /// Create a new FileLockManager with locks stored in the specified directory
    pub fn new(data_dir: &Path) -> Result<Self> {
        let lock_dir = data_dir.join("locks");

        // Create the locks directory if it doesn't exist
        fs::create_dir_all(&lock_dir).map_err(|e| {
            DatabaseError::ConnectionFailed(format!(
                "Failed to create locks directory at {:?}: {}",
                lock_dir, e
            ))
        })?;

        info!(lock_dir = ?lock_dir, "Initialized file lock manager");

        Ok(Self { lock_dir })
    }

    /// Get the path to a service's lock file
    fn lock_file_path(&self, service: &str) -> PathBuf {
        self.lock_dir.join(format!("{}.lock", service))
    }

    /// Attempt to acquire an exclusive file lock for a service (non-blocking)
    ///
    /// Returns Ok(FileLock) if the lock was acquired, or an error if:
    /// - The lock is already held by another process
    /// - Filesystem doesn't support locks
    /// - I/O errors occur
    pub fn try_acquire_lock(&self, service: &str) -> Result<FileLock> {
        let lock_path = self.lock_file_path(service);

        debug!(
            service = %service,
            lock_path = ?lock_path,
            "Attempting to acquire file lock"
        );

        // Open or create the lock file
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&lock_path)
            .map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open lock file for service '{}': {}",
                    service, e
                ))
            })?;

        // Try to acquire exclusive lock (non-blocking)
        match file.try_lock_exclusive() {
            Ok(()) => {
                info!(
                    service = %service,
                    lock_path = ?lock_path,
                    "File lock acquired"
                );

                Ok(FileLock {
                    service: service.to_string(),
                    file: Some(file),
                    lock_path,
                })
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Lock is held by another process
                Err(DatabaseError::TransactionFailed(format!(
                    "Service '{}' is locked by another process (file lock held)",
                    service
                ))
                .into())
            }
            Err(e) => {
                // Other error (filesystem doesn't support locks, etc.)
                Err(DatabaseError::TransactionFailed(format!(
                    "Failed to acquire file lock for service '{}': {}",
                    service, e
                ))
                .into())
            }
        }
    }

    /// Clean up stale lock files
    ///
    /// This removes lock files that exist but are not locked by any process.
    /// Should be called periodically to clean up after crashes.
    pub fn cleanup_stale_locks(&self) -> Result<Vec<String>> {
        debug!(lock_dir = ?self.lock_dir, "Cleaning up stale lock files");

        let entries = fs::read_dir(&self.lock_dir).map_err(|e| {
            DatabaseError::TransactionFailed(format!(
                "Failed to read locks directory {:?}: {}",
                self.lock_dir, e
            ))
        })?;

        let mut cleaned = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();

            // Only process .lock files
            if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                continue;
            }

            // Extract service name from filename
            let service_name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(name) => name,
                None => {
                    warn!(path = ?path, "Invalid lock file name");
                    continue;
                }
            };

            // Try to acquire lock - if we can, it means the file is stale
            match self.try_acquire_and_check_stale(&path, service_name) {
                Ok(true) => {
                    // Lock was stale, remove it
                    match fs::remove_file(&path) {
                        Ok(()) => {
                            info!(
                                service = %service_name,
                                path = ?path,
                                "Removed stale lock file"
                            );
                            cleaned.push(service_name.to_string());
                        }
                        Err(e) if e.kind() == ErrorKind::NotFound => {
                            // Already removed, that's fine
                            debug!(path = ?path, "Lock file already removed");
                        }
                        Err(e) => {
                            warn!(
                                service = %service_name,
                                path = ?path,
                                error = %e,
                                "Failed to remove stale lock file"
                            );
                        }
                    }
                }
                Ok(false) => {
                    // Lock is held by another process, not stale
                    debug!(service = %service_name, "Lock file is in use");
                }
                Err(e) => {
                    warn!(
                        service = %service_name,
                        error = %e,
                        "Failed to check lock file"
                    );
                }
            }
        }

        Ok(cleaned)
    }

    /// Try to acquire a lock to check if it's stale, then release it
    ///
    /// Returns Ok(true) if the lock was stale (successfully acquired and released)
    /// Returns Ok(false) if the lock is held by another process
    fn try_acquire_and_check_stale(&self, path: &Path, service: &str) -> Result<bool> {
        let file = match OpenOptions::new().write(true).open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                // File was already removed
                return Ok(true);
            }
            Err(e) => {
                return Err(DatabaseError::TransactionFailed(format!(
                    "Failed to open lock file for '{}': {}",
                    service, e
                ))
                .into());
            }
        };

        match file.try_lock_exclusive() {
            Ok(()) => {
                // We got the lock, so it was stale
                // Unlock it before returning
                let _ = file.unlock();
                Ok(true)
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                // Lock is held, not stale
                Ok(false)
            }
            Err(e) => Err(DatabaseError::TransactionFailed(format!(
                "Failed to check lock for '{}': {}",
                service, e
            ))
            .into()),
        }
    }

    /// Get all currently locked services (files with active locks)
    pub fn get_locked_services(&self) -> Result<Vec<String>> {
        let entries = fs::read_dir(&self.lock_dir).map_err(|e| {
            DatabaseError::TransactionFailed(format!(
                "Failed to read locks directory {:?}: {}",
                self.lock_dir, e
            ))
        })?;

        let mut locked_services = Vec::new();

        for entry in entries {
            let entry = entry.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();

            // Only process .lock files
            if path.extension().and_then(|s| s.to_str()) != Some("lock") {
                continue;
            }

            let service_name = match path.file_stem().and_then(|s| s.to_str()) {
                Some(name) => name,
                None => continue,
            };

            // Check if the lock is actually held
            match self.try_acquire_and_check_stale(&path, service_name) {
                Ok(false) => {
                    // Lock is held
                    locked_services.push(service_name.to_string());
                }
                Ok(true) => {
                    // Lock was stale, already released
                }
                Err(e) => {
                    warn!(service = %service_name, error = %e, "Failed to check lock status");
                }
            }
        }

        Ok(locked_services)
    }
}

/// RAII guard that holds a file lock and automatically releases it on drop
pub struct FileLock {
    service: String,
    file: Option<File>,
    lock_path: PathBuf,
}

impl FileLock {
    /// Get the service name for this lock
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Manually unlock the file (usually not needed, handled by Drop)
    pub fn unlock(mut self) -> Result<()> {
        if let Some(file) = self.file.take() {
            file.unlock().map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to unlock file for service '{}': {}",
                    self.service, e
                ))
            })?;

            debug!(
                service = %self.service,
                lock_path = ?self.lock_path,
                "File lock released manually"
            );
        }
        Ok(())
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            match file.unlock() {
                Ok(()) => {
                    debug!(
                        service = %self.service,
                        lock_path = ?self.lock_path,
                        "File lock released (Drop)"
                    );
                }
                Err(e) => {
                    warn!(
                        service = %self.service,
                        lock_path = ?self.lock_path,
                        error = %e,
                        "Failed to unlock file during drop"
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_file_lock_manager_creation() {
        let temp_dir = tempdir().unwrap();
        let _manager = FileLockManager::new(temp_dir.path()).unwrap();

        // Check that locks directory was created
        let lock_dir = temp_dir.path().join("locks");
        assert!(lock_dir.exists());
        assert!(lock_dir.is_dir());
    }

    #[test]
    fn test_acquire_and_release_lock() {
        let temp_dir = tempdir().unwrap();
        let manager = FileLockManager::new(temp_dir.path()).unwrap();

        // Acquire lock
        let lock = manager.try_acquire_lock("test-service").unwrap();
        assert_eq!(lock.service(), "test-service");

        // Lock file should exist
        let lock_path = temp_dir.path().join("locks").join("test-service.lock");
        assert!(lock_path.exists());

        // Try to acquire again - should fail
        let result = manager.try_acquire_lock("test-service");
        assert!(result.is_err());

        // Release lock
        drop(lock);

        // Should be able to acquire again
        let lock2 = manager.try_acquire_lock("test-service").unwrap();
        assert_eq!(lock2.service(), "test-service");
    }

    #[test]
    fn test_multiple_services() {
        let temp_dir = tempdir().unwrap();
        let manager = FileLockManager::new(temp_dir.path()).unwrap();

        // Acquire locks for different services
        let lock_a = manager.try_acquire_lock("service-a").unwrap();
        let lock_b = manager.try_acquire_lock("service-b").unwrap();

        assert_eq!(lock_a.service(), "service-a");
        assert_eq!(lock_b.service(), "service-b");

        // Both lock files should exist
        let locks_dir = temp_dir.path().join("locks");
        assert!(locks_dir.join("service-a.lock").exists());
        assert!(locks_dir.join("service-b.lock").exists());

        drop(lock_a);
        drop(lock_b);
    }

    #[test]
    fn test_cleanup_stale_locks() {
        let temp_dir = tempdir().unwrap();
        let manager = FileLockManager::new(temp_dir.path()).unwrap();

        // Create and release a lock
        let lock = manager.try_acquire_lock("stale-service").unwrap();
        drop(lock);

        // Lock file should still exist (we don't auto-delete)
        let lock_path = temp_dir.path().join("locks").join("stale-service.lock");
        assert!(lock_path.exists());

        // Cleanup should find and report it
        let cleaned = manager.cleanup_stale_locks().unwrap();
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0], "stale-service");

        // Lock file should be removed
        assert!(!lock_path.exists());
    }

    #[test]
    fn test_get_locked_services() {
        let temp_dir = tempdir().unwrap();
        let manager = FileLockManager::new(temp_dir.path()).unwrap();

        // No locks initially
        let locked = manager.get_locked_services().unwrap();
        assert!(locked.is_empty());

        // Acquire some locks
        let lock_a = manager.try_acquire_lock("service-a").unwrap();
        let lock_b = manager.try_acquire_lock("service-b").unwrap();

        let locked = manager.get_locked_services().unwrap();
        assert_eq!(locked.len(), 2);
        assert!(locked.contains(&"service-a".to_string()));
        assert!(locked.contains(&"service-b".to_string()));

        // Release one
        drop(lock_a);

        let locked = manager.get_locked_services().unwrap();
        assert_eq!(locked.len(), 1);
        assert!(locked.contains(&"service-b".to_string()));

        drop(lock_b);
    }

    #[test]
    fn test_manual_unlock() {
        let temp_dir = tempdir().unwrap();
        let manager = FileLockManager::new(temp_dir.path()).unwrap();

        let lock = manager.try_acquire_lock("test-service").unwrap();

        // Manually unlock
        lock.unlock().unwrap();

        // Should be able to acquire again
        let lock2 = manager.try_acquire_lock("test-service").unwrap();
        assert_eq!(lock2.service(), "test-service");
    }
}
