pub mod concurrency;
pub mod filelock;

use std::path::Path;
use std::sync::Arc;
use std::{collections::HashMap, path::PathBuf};

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use tracing::{debug, error, info, warn};

use crate::types::{DatabaseError, DeploymentRecord, DeploymentStatus, Result, ServiceState};

pub use concurrency::{ConcurrencyGuard, ConcurrencyTracker};
pub use filelock::{FileLock, FileLockManager};

// Table definitions for redb
const DEPLOYMENTS: TableDefinition<&str, Vec<u8>> = TableDefinition::new("deployments");
const SERVICE_STATE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("service_state");

/// Type alias for service lock information: (service_name, locked, locked_by, locked_at)
pub type ServiceLockInfo = (String, bool, Option<String>, Option<i64>);

/// Combined lock guard that holds both file and database locks
///
/// This RAII guard ensures both locks are released when dropped, with proper
/// ordering (database lock released before file lock).
pub struct ServiceLockGuard {
    service: String,
    state_manager: StateManager,
    file_lock: Option<FileLock>,
}

impl ServiceLockGuard {
    /// Create a new ServiceLockGuard
    fn new(service: String, state_manager: StateManager, file_lock: FileLock) -> Self {
        Self {
            service,
            state_manager,
            file_lock: Some(file_lock),
        }
    }

    /// Get the service name
    pub fn service(&self) -> &str {
        &self.service
    }
}

impl Drop for ServiceLockGuard {
    fn drop(&mut self) {
        // Release database lock first
        if let Err(e) = self.state_manager.unlock_service(&self.service) {
            warn!(
                service = %self.service,
                error = %e,
                "Failed to release database lock in ServiceLockGuard drop"
            );
        }

        // File lock will be released automatically when file_lock is dropped
        if let Some(file_lock) = self.file_lock.take() {
            drop(file_lock);
        }
    }
}

/// StateManager handles all database operations for deployment records and service state
#[derive(Clone)]
pub struct StateManager {
    db: Arc<Database>,
    path: PathBuf,
    file_lock_manager: FileLockManager,
}

impl StateManager {
    /// Create a new StateManager with a database at the given path
    pub fn new(data_dir: &Path) -> Result<Self> {
        // Ensure the data directory exists
        std::fs::create_dir_all(data_dir)?;

        let db_path = data_dir.join("state.redb");

        let db = Database::create(&db_path).map_err(|e| {
            DatabaseError::ConnectionFailed(format!("Failed to create database: {}", e))
        })?;

        // Initialize tables
        let write_txn = db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            // Open tables to ensure they exist
            let _ = write_txn.open_table(DEPLOYMENTS).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
            })?;
            let _ = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit initialization: {}", e))
        })?;

        // Initialize file lock manager
        let file_lock_manager = FileLockManager::new(data_dir)?;

        Ok(StateManager {
            db: Arc::new(db),
            path: data_dir.to_path_buf(),
            file_lock_manager,
        })
    }
    pub async fn get_db_size(&self) -> Result<u64> {
        let db_path = self.path.join("state.redb");
        let metadata = tokio::fs::metadata(db_path).await?;
        let size = metadata.len();
        Ok(size)
    }

    pub async fn get_db_connection(&self) -> Result<bool> {
        let db_path = self.path.join("state.redb");
        let metadata = tokio::fs::metadata(db_path).await?;
        Ok(metadata.is_file())
    }

    /// Record a new deployment
    pub fn record_deployment(&self, record: &DeploymentRecord) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(DEPLOYMENTS).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
            })?;

            let key = format!("{}:{}", record.service, record.deploy_id);
            let value = serde_json::to_vec(record).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "Failed to serialize deployment record: {}",
                    e
                ))
            })?;

            table.insert(key.as_str(), value).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to insert deployment record: {}",
                    e
                ))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit deployment record: {}", e))
        })?;

        Ok(())
    }

    /// Get a deployment record by service and deploy_id
    pub fn get_deployment(
        &self,
        service: &str,
        deploy_id: &str,
    ) -> Result<Option<DeploymentRecord>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(DEPLOYMENTS).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
        })?;

        let key = format!("{}:{}", service, deploy_id);

        match table.get(key.as_str()) {
            Ok(Some(access_guard)) => {
                let value = access_guard.value();
                let record: DeploymentRecord = serde_json::from_slice(&value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "Failed to deserialize deployment record: {}",
                        e
                    ))
                })?;
                Ok(Some(record))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DatabaseError::TransactionFailed(format!(
                "Failed to get deployment record: {}",
                e
            ))
            .into()),
        }
    }

    /// Update an existing deployment record
    pub fn update_deployment(&self, record: &DeploymentRecord) -> Result<()> {
        // Same as record_deployment since we're using upsert semantics
        self.record_deployment(record)
    }

    /// Get the current state of a service
    pub fn get_service_state(&self, service: &str) -> Result<Option<ServiceState>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(SERVICE_STATE).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open service_state table: {}", e))
        })?;

        match table.get(service) {
            Ok(Some(access_guard)) => {
                let value = access_guard.value();
                let state: ServiceState = serde_json::from_slice(&value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "Failed to deserialize service state: {}",
                        e
                    ))
                })?;
                Ok(Some(state))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(DatabaseError::TransactionFailed(format!(
                "Failed to get service state: {}",
                e
            ))
            .into()),
        }
    }

    /// Update the state of a service
    pub fn update_service_state(&self, state: &ServiceState) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;

            let value = serde_json::to_vec(state).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to serialize service state: {}", e))
            })?;

            table.insert(state.service.as_str(), value).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to insert service state: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit service state: {}", e))
        })?;

        Ok(())
    }

    /// Attempt to acquire both file and database locks for a service
    ///
    /// This is the recommended method for acquiring service locks as it provides
    /// both filesystem-level protection (via flock) and database-level tracking.
    ///
    /// Returns a ServiceLockGuard that will automatically release both locks on drop.
    pub fn try_lock_service_combined(
        &self,
        service: &str,
        deploy_id: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<ServiceLockGuard> {
        info!(
            service = %service,
            deploy_id = %deploy_id,
            "Attempting to acquire combined file and database lock"
        );

        // Step 1: Acquire file lock first (fail fast if OS-level lock is held)
        let file_lock = self.file_lock_manager.try_acquire_lock(service)?;

        // Step 2: Try to acquire database lock
        match self.try_lock_service_with_timeout(service, deploy_id, timeout_seconds) {
            Ok(true) => {
                // Both locks acquired successfully
                info!(
                    service = %service,
                    deploy_id = %deploy_id,
                    "Successfully acquired combined lock"
                );

                Ok(ServiceLockGuard::new(
                    service.to_string(),
                    self.clone(),
                    file_lock,
                ))
            }
            Ok(false) => {
                // Database lock failed (already locked)
                // File lock will be auto-released when file_lock is dropped
                drop(file_lock);

                Err(crate::types::Error::ServiceLocked {
                    service: service.to_string(),
                    deploy_id: deploy_id.to_string(),
                })
            }
            Err(e) => {
                // Database lock error
                // File lock will be auto-released when file_lock is dropped
                drop(file_lock);
                Err(e)
            }
        }
    }

    /// Attempt to lock a service for deployment (atomic test-and-set)
    ///
    /// Automatically cleans up stale locks if timeout is provided
    ///
    /// NOTE: This method only acquires the database lock. Use `try_lock_service_combined`
    /// for acquiring both file and database locks.
    pub fn try_lock_service(&self, service: &str, deploy_id: &str) -> Result<bool> {
        self.try_lock_service_with_timeout(service, deploy_id, None)
    }

    /// Attempt to lock a service with optional timeout checking for stale locks
    pub fn try_lock_service_with_timeout(
        &self,
        service: &str,
        deploy_id: &str,
        timeout_seconds: Option<u64>,
    ) -> Result<bool> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;

            // Get current state or create new one
            let mut state = match table.get(service) {
                Ok(Some(access_guard)) => {
                    let value = access_guard.value();
                    {
                        let state: ServiceState = serde_json::from_slice(&value).map_err(|e| {
                            DatabaseError::Serialization(format!(
                                "Failed to deserialize service state: {}",
                                e
                            ))
                        })?;
                        state
                    }
                }
                Ok(None) => ServiceState::new(service.to_string()),
                Err(e) => {
                    return Err(DatabaseError::TransactionFailed(format!(
                        "Failed to get service state: {}",
                        e
                    ))
                    .into())
                }
            };

            // Check if already locked
            if state.locked {
                // If timeout is specified, check if the lock is stale
                if let Some(timeout) = timeout_seconds {
                    if let Some(locked_at) = state.locked_at {
                        let now = chrono::Utc::now().timestamp();
                        let elapsed = (now - locked_at) as u64;

                        if elapsed > timeout {
                            // Lock is stale, force unlock it
                            warn!(
                                service = %service,
                                locked_by = ?state.locked_by,
                                elapsed_seconds = elapsed,
                                "Cleaning up stale lock during lock acquisition"
                            );
                            state.unlock();
                        } else {
                            // Lock is still valid
                            return Ok(false);
                        }
                    } else {
                        // Lock exists but no timestamp (shouldn't happen)
                        return Ok(false);
                    }
                } else {
                    // No timeout checking, lock is held
                    return Ok(false);
                }
            }

            // Lock the service
            state.lock(deploy_id.to_string())?;

            // Save the updated state
            let value = serde_json::to_vec(&state).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to serialize service state: {}", e))
            })?;

            table.insert(service, value).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to insert service state: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit service lock: {}", e))
        })?;

        Ok(true)
    }

    /// Unlock a service
    pub fn unlock_service(&self, service: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;

            // Get current state
            let mut state = match table.get(service) {
                Ok(Some(access_guard)) => {
                    let value = access_guard.value();
                    {
                        let state: ServiceState = serde_json::from_slice(&value).map_err(|e| {
                            DatabaseError::Serialization(format!(
                                "Failed to deserialize service state: {}",
                                e
                            ))
                        })?;
                        state
                    }
                }
                Ok(None) => {
                    // Service doesn't exist, nothing to unlock
                    return Ok(());
                }
                Err(e) => {
                    return Err(DatabaseError::TransactionFailed(format!(
                        "Failed to get service state: {}",
                        e
                    ))
                    .into())
                }
            };

            // Unlock the service
            state.unlock();

            // Save the updated state
            let value = serde_json::to_vec(&state).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to serialize service state: {}", e))
            })?;

            table.insert(service, value).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to insert service state: {}", e))
            })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit service unlock: {}", e))
        })?;

        Ok(())
    }

    /// Check if a service lock is stale based on timeout
    pub fn is_lock_stale(&self, service: &str, timeout_seconds: u64) -> Result<bool> {
        let state = self.get_service_state(service)?;

        if let Some(state) = state {
            if state.locked {
                if let Some(locked_at) = state.locked_at {
                    let now = chrono::Utc::now().timestamp();
                    let elapsed = (now - locked_at) as u64;
                    return Ok(elapsed > timeout_seconds);
                }
            }
        }

        Ok(false)
    }

    /// Force unlock a service (admin operation, bypasses normal checks)
    pub fn force_unlock_service(&self, service: &str) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            let mut table = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;

            // Get current state
            let mut state: ServiceState = match table.get(service) {
                Ok(Some(access_guard)) => {
                    let value = access_guard.value();
                    serde_json::from_slice(&value).map_err(|e| {
                        DatabaseError::Serialization(format!(
                            "Failed to deserialize service state: {}",
                            e
                        ))
                    })?
                }
                Ok(None) => {
                    // Service doesn't exist, nothing to unlock
                    return Ok(());
                }
                Err(e) => {
                    return Err(DatabaseError::TransactionFailed(format!(
                        "Failed to get service state: {}",
                        e
                    ))
                    .into())
                }
            };

            if state.locked {
                info!(
                    service = %service,
                    locked_by = ?state.locked_by,
                    "Force unlocking service"
                );
                state.unlock();

                // Save the updated state
                let value = serde_json::to_vec(&state).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "Failed to serialize service state: {}",
                        e
                    ))
                })?;

                table.insert(service, value).map_err(|e| {
                    DatabaseError::TransactionFailed(format!(
                        "Failed to insert service state: {}",
                        e
                    ))
                })?;
            }
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to commit force unlock: {}", e))
        })?;

        Ok(())
    }

    /// Get reference to the file lock manager
    pub fn file_lock_manager(&self) -> &FileLockManager {
        &self.file_lock_manager
    }

    /// Clean up stale database locks on startup by checking against file locks
    ///
    /// This is called during initialization to handle locks left over from
    /// improper shutdowns. Since file locks are automatically released by the OS,
    /// any database lock without a corresponding file lock is definitely stale.
    pub fn cleanup_stale_locks_on_startup(&self) -> Result<Vec<String>> {
        info!("Performing startup cleanup of stale locks");

        let mut cleaned = Vec::new();

        // Get all services with database locks
        let db_locks = self.get_all_service_locks()?;

        for (service, locked, locked_by, locked_at) in db_locks {
            if !locked {
                continue; // Not locked, nothing to clean
            }

            // Check if file lock exists and is actually held
            // If the file lock doesn't exist or isn't held, the database lock is stale
            let file_lock_held = match self.file_lock_manager.try_acquire_lock(&service) {
                Ok(lock) => {
                    // We successfully acquired it, meaning it was NOT held
                    // (stale database lock). Release it immediately.
                    drop(lock);
                    false
                }
                Err(_) => {
                    // Failed to acquire, meaning it IS held by another process
                    true
                }
            };

            if !file_lock_held {
                // Database lock exists but file lock doesn't - definitely stale
                warn!(
                    service = %service,
                    locked_by = ?locked_by,
                    locked_at = ?locked_at,
                    "Found stale database lock on startup (no file lock), cleaning up"
                );

                match self.force_unlock_service(&service) {
                    Ok(()) => {
                        info!(service = %service, "Cleaned up stale database lock on startup");
                        cleaned.push(service);
                    }
                    Err(e) => {
                        error!(
                            service = %service,
                            error = %e,
                            "Failed to clean up stale database lock on startup"
                        );
                    }
                }
            }
        }

        if !cleaned.is_empty() {
            info!(
                count = cleaned.len(),
                services = ?cleaned,
                "Startup cleanup completed - removed stale database locks"
            );
        } else {
            info!("Startup cleanup completed - no stale locks found");
        }

        Ok(cleaned)
    }

    /// Clean up all stale locks across all services (both database and file locks)
    pub fn cleanup_stale_locks(&self, timeout_seconds: u64) -> Result<Vec<String>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(SERVICE_STATE).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open service_state table: {}", e))
        })?;

        // Collect stale locks
        let mut stale_services = Vec::new();
        let now = chrono::Utc::now().timestamp();

        let iter = table.iter().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to create table iterator: {}", e))
        })?;

        for item in iter {
            let (_key_guard, value_guard) = item.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to iterate table: {}", e))
            })?;

            let value = value_guard.value();
            let state: ServiceState = serde_json::from_slice(&value).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to deserialize service state: {}", e))
            })?;

            if state.locked {
                if let Some(locked_at) = state.locked_at {
                    let elapsed = (now - locked_at) as u64;
                    if elapsed > timeout_seconds {
                        debug!(
                            service = %state.service,
                            locked_by = ?state.locked_by,
                            elapsed_seconds = elapsed,
                            "Found stale lock"
                        );
                        stale_services.push(state.service.clone());
                    }
                }
            }
        }

        drop(table);
        drop(read_txn);

        // Unlock stale services (database locks)
        let mut cleaned = Vec::new();
        for service in stale_services {
            match self.force_unlock_service(&service) {
                Ok(()) => {
                    info!(service = %service, "Cleaned up stale database lock");
                    cleaned.push(service.clone());
                }
                Err(e) => {
                    warn!(service = %service, error = %e, "Failed to clean up stale database lock");
                }
            }
        }

        // Also clean up stale file locks
        match self.file_lock_manager.cleanup_stale_locks() {
            Ok(file_cleaned) => {
                for service in file_cleaned {
                    info!(service = %service, "Cleaned up stale file lock");
                    // Add to cleaned list if not already there
                    if !cleaned.contains(&service) {
                        cleaned.push(service);
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to clean up stale file locks");
            }
        }

        Ok(cleaned)
    }

    /// Get all services with their lock status
    pub fn get_all_service_locks(&self) -> Result<Vec<ServiceLockInfo>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(SERVICE_STATE).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open service_state table: {}", e))
        })?;

        let mut locks = Vec::new();

        let iter = table.iter().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to create table iterator: {}", e))
        })?;

        for item in iter {
            let (_key_guard, value_guard) = item.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to iterate table: {}", e))
            })?;

            let value = value_guard.value();
            let state: ServiceState = serde_json::from_slice(&value).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to deserialize service state: {}", e))
            })?;

            locks.push((
                state.service.clone(),
                state.locked,
                state.locked_by.clone(),
                state.locked_at,
            ));
        }

        Ok(locks)
    }

    /// Get deployment history for a service
    pub fn get_deployment_history(
        &self,
        service: &str,
        limit: Option<usize>,
    ) -> Result<Vec<DeploymentRecord>> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(DEPLOYMENTS).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
        })?;

        let prefix = format!("{}:", service);
        let mut deployments = Vec::new();

        // Iterate through all records and filter by service prefix
        let iter = table.iter().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to create table iterator: {}", e))
        })?;

        for item in iter {
            let (key_guard, value_guard) = item.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to iterate table: {}", e))
            })?;

            let key = key_guard.value();
            if key.starts_with(&prefix) {
                let value = value_guard.value();
                let record: DeploymentRecord = serde_json::from_slice(&value).map_err(|e| {
                    DatabaseError::Serialization(format!(
                        "Failed to deserialize deployment record: {}",
                        e
                    ))
                })?;
                deployments.push(record);
            }
        }

        // Sort by started_at timestamp (newest first)
        deployments.sort_by(|a, b| b.started_at.cmp(&a.started_at));

        // Apply limit if specified
        if let Some(limit) = limit {
            deployments.truncate(limit);
        }

        Ok(deployments)
    }

    /// Get deployments by status for a service
    pub fn get_deployments_by_status(
        &self,
        service: &str,
        status: DeploymentStatus,
    ) -> Result<Vec<DeploymentRecord>> {
        let deployments = self.get_deployment_history(service, None)?;
        Ok(deployments
            .into_iter()
            .filter(|d| d.status == status)
            .collect())
    }

    /// Clean up old deployment records according to retention policies
    pub fn cleanup_old_records(&self, successful_limit: usize, failed_limit: usize) -> Result<()> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(DEPLOYMENTS).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
        })?;

        // Collect all deployments grouped by service
        let mut service_deployments: HashMap<String, Vec<DeploymentRecord>> = HashMap::new();

        let iter = table.iter().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to create table iterator: {}", e))
        })?;

        for item in iter {
            let (_, value_guard) = item.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to iterate table: {}", e))
            })?;

            let value = value_guard.value();
            let record: DeploymentRecord = serde_json::from_slice(&value).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "Failed to deserialize deployment record: {}",
                    e
                ))
            })?;

            service_deployments
                .entry(record.service.clone())
                .or_default()
                .push(record);
        }

        drop(table);
        drop(read_txn);

        // For each service, determine which records to keep and which to delete
        let mut keys_to_delete = Vec::new();

        for (service, mut deployments) in service_deployments {
            // Sort by timestamp (newest first)
            deployments.sort_by(|a, b| b.started_at.cmp(&a.started_at));

            // Separate by status
            let mut successful = Vec::new();
            let mut failed = Vec::new();

            for deployment in deployments {
                match deployment.status {
                    DeploymentStatus::Succeeded => successful.push(deployment),
                    DeploymentStatus::Failed | DeploymentStatus::RollbackFailed => {
                        failed.push(deployment)
                    }
                    _ => {
                        // Keep in-progress deployments
                        continue;
                    }
                }
            }

            // Mark old successful deployments for deletion
            if successful.len() > successful_limit {
                for deployment in successful.into_iter().skip(successful_limit) {
                    keys_to_delete.push(format!("{}:{}", service, deployment.deploy_id));
                }
            }

            // Mark old failed deployments for deletion
            if failed.len() > failed_limit {
                for deployment in failed.into_iter().skip(failed_limit) {
                    keys_to_delete.push(format!("{}:{}", service, deployment.deploy_id));
                }
            }
        }

        // Delete the old records
        if !keys_to_delete.is_empty() {
            let write_txn = self.db.begin_write().map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to begin write transaction: {}",
                    e
                ))
            })?;

            {
                let mut table = write_txn.open_table(DEPLOYMENTS).map_err(|e| {
                    DatabaseError::TransactionFailed(format!(
                        "Failed to open deployments table: {}",
                        e
                    ))
                })?;

                for key in keys_to_delete {
                    table.remove(key.as_str()).map_err(|e| {
                        DatabaseError::TransactionFailed(format!(
                            "Failed to remove deployment record: {}",
                            e
                        ))
                    })?;
                }
            }

            write_txn.commit().map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to commit cleanup: {}", e))
            })?;
        }

        Ok(())
    }

    /// Update both deployment record and service state in a single transaction
    pub fn update_deployment_and_service_state(
        &self,
        deployment: &DeploymentRecord,
        service_state: &ServiceState,
    ) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin write transaction: {}", e))
        })?;

        {
            // Update deployment record
            let mut deployments_table = write_txn.open_table(DEPLOYMENTS).map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
            })?;

            let deployment_key = format!("{}:{}", deployment.service, deployment.deploy_id);
            let deployment_value = serde_json::to_vec(deployment).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "Failed to serialize deployment record: {}",
                    e
                ))
            })?;

            deployments_table
                .insert(deployment_key.as_str(), deployment_value)
                .map_err(|e| {
                    DatabaseError::TransactionFailed(format!(
                        "Failed to insert deployment record: {}",
                        e
                    ))
                })?;

            // Update service state
            let mut state_table = write_txn.open_table(SERVICE_STATE).map_err(|e| {
                DatabaseError::TransactionFailed(format!(
                    "Failed to open service_state table: {}",
                    e
                ))
            })?;

            let state_value = serde_json::to_vec(service_state).map_err(|e| {
                DatabaseError::Serialization(format!("Failed to serialize service state: {}", e))
            })?;

            state_table
                .insert(service_state.service.as_str(), state_value)
                .map_err(|e| {
                    DatabaseError::TransactionFailed(format!(
                        "Failed to insert service state: {}",
                        e
                    ))
                })?;
        }

        write_txn.commit().map_err(|e| {
            DatabaseError::TransactionFailed(format!(
                "Failed to commit deployment and state update: {}",
                e
            ))
        })?;

        Ok(())
    }

    /// Check if there are any active deployments (for backup safety checks)
    pub fn has_active_deployments(&self) -> Result<bool> {
        let read_txn = self.db.begin_read().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to begin read transaction: {}", e))
        })?;

        let table = read_txn.open_table(DEPLOYMENTS).map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to open deployments table: {}", e))
        })?;

        let iter = table.iter().map_err(|e| {
            DatabaseError::TransactionFailed(format!("Failed to create table iterator: {}", e))
        })?;

        for item in iter {
            let (_key_guard, value_guard) = item.map_err(|e| {
                DatabaseError::TransactionFailed(format!("Failed to iterate table: {}", e))
            })?;

            let value = value_guard.value();
            let record: DeploymentRecord = serde_json::from_slice(&value).map_err(|e| {
                DatabaseError::Serialization(format!(
                    "Failed to deserialize deployment record: {}",
                    e
                ))
            })?;

            // Check if deployment is in an active state
            match record.status {
                DeploymentStatus::Queued
                | DeploymentStatus::Validating
                | DeploymentStatus::Deploying
                | DeploymentStatus::HealthChecking
                | DeploymentStatus::RollingBack => {
                    info!(
                        service = %record.service,
                        deploy_id = %record.deploy_id,
                        status = ?record.status,
                        "Found active deployment"
                    );
                    return Ok(true);
                }
                _ => {}
            }
        }

        Ok(false)
    }

    /// Get the database path
    pub fn get_db_path(&self) -> PathBuf {
        self.path.join("state.redb")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tempfile::tempdir;

    fn create_test_deployment(service: &str, deploy_id: &str) -> DeploymentRecord {
        DeploymentRecord::new(
            deploy_id.to_string(),
            service.to_string(),
            "registry:5000/app:v1.0.0".to_string(),
            "127.0.0.1".to_string(),
        )
    }

    #[test]
    fn test_state_manager_creation() {
        let temp_dir = tempdir().unwrap();
        let _state_manager = StateManager::new(temp_dir.path()).unwrap();
        assert!(temp_dir.path().join("state.redb").exists());
    }

    #[test]
    fn test_deployment_record_crud() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        let mut deployment = create_test_deployment("test-service", "deploy-001");

        // Test record deployment
        state_manager.record_deployment(&deployment).unwrap();

        // Test get deployment
        let retrieved = state_manager
            .get_deployment("test-service", "deploy-001")
            .unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.deploy_id, "deploy-001");
        assert_eq!(retrieved.service, "test-service");

        // Test update deployment
        deployment.add_state_transition(DeploymentStatus::Succeeded, None);
        state_manager.update_deployment(&deployment).unwrap();

        let updated = state_manager
            .get_deployment("test-service", "deploy-001")
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, DeploymentStatus::Succeeded);

        // Test non-existent deployment
        let non_existent = state_manager
            .get_deployment("test-service", "deploy-999")
            .unwrap();
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_service_state_management() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        let mut service_state = ServiceState::new("test-service".to_string());
        service_state.current_image = "registry:5000/app:v1.0.0".to_string();

        // Test update service state
        state_manager.update_service_state(&service_state).unwrap();

        // Test get service state
        let retrieved = state_manager.get_service_state("test-service").unwrap();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.service, "test-service");
        assert_eq!(retrieved.current_image, "registry:5000/app:v1.0.0");

        // Test non-existent service
        let non_existent = state_manager.get_service_state("non-existent").unwrap();
        assert!(non_existent.is_none());
    }

    #[test]
    fn test_service_locking() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Test successful lock
        let locked = state_manager
            .try_lock_service("test-service", "deploy-001")
            .unwrap();
        assert!(locked);

        // Test lock already held
        let locked_again = state_manager
            .try_lock_service("test-service", "deploy-002")
            .unwrap();
        assert!(!locked_again);

        // Test unlock
        state_manager.unlock_service("test-service").unwrap();

        // Test lock after unlock
        let locked_after_unlock = state_manager
            .try_lock_service("test-service", "deploy-003")
            .unwrap();
        assert!(locked_after_unlock);
    }

    #[test]
    fn test_deployment_history() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Create multiple deployments for the same service
        for i in 1..=5 {
            let mut deployment =
                create_test_deployment("test-service", &format!("deploy-{:03}", i));
            deployment.started_at = Utc::now().timestamp() - (5 - i) as i64; // Older timestamps for earlier deployments
            state_manager.record_deployment(&deployment).unwrap();
        }

        // Create deployment for different service
        let other_deployment = create_test_deployment("other-service", "deploy-001");
        state_manager.record_deployment(&other_deployment).unwrap();

        // Test get deployment history
        let history = state_manager
            .get_deployment_history("test-service", None)
            .unwrap();
        assert_eq!(history.len(), 5);

        // Should be sorted by newest first
        assert_eq!(history[0].deploy_id, "deploy-005");
        assert_eq!(history[4].deploy_id, "deploy-001");

        // Test with limit
        let limited_history = state_manager
            .get_deployment_history("test-service", Some(3))
            .unwrap();
        assert_eq!(limited_history.len(), 3);
        assert_eq!(limited_history[0].deploy_id, "deploy-005");
    }

    #[test]
    fn test_deployments_by_status() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Create deployments with different statuses
        let mut deployment1 = create_test_deployment("test-service", "deploy-001");
        deployment1.add_state_transition(DeploymentStatus::Succeeded, None);
        state_manager.record_deployment(&deployment1).unwrap();

        let mut deployment2 = create_test_deployment("test-service", "deploy-002");
        deployment2.add_state_transition(DeploymentStatus::Failed, None);
        state_manager.record_deployment(&deployment2).unwrap();

        let mut deployment3 = create_test_deployment("test-service", "deploy-003");
        deployment3.add_state_transition(DeploymentStatus::Succeeded, None);
        state_manager.record_deployment(&deployment3).unwrap();

        // Test get successful deployments
        let successful = state_manager
            .get_deployments_by_status("test-service", DeploymentStatus::Succeeded)
            .unwrap();
        assert_eq!(successful.len(), 2);

        // Test get failed deployments
        let failed = state_manager
            .get_deployments_by_status("test-service", DeploymentStatus::Failed)
            .unwrap();
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].deploy_id, "deploy-002");
    }

    #[test]
    fn test_cleanup_old_records() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Create multiple successful deployments
        for i in 1..=5 {
            let mut deployment =
                create_test_deployment("test-service", &format!("success-{:03}", i));
            deployment.add_state_transition(DeploymentStatus::Succeeded, None);
            deployment.started_at = Utc::now().timestamp() - (5 - i) as i64;
            state_manager.record_deployment(&deployment).unwrap();
        }

        // Create multiple failed deployments
        for i in 1..=3 {
            let mut deployment =
                create_test_deployment("test-service", &format!("failed-{:03}", i));
            deployment.add_state_transition(DeploymentStatus::Failed, None);
            deployment.started_at = Utc::now().timestamp() - (3 - i) as i64;
            state_manager.record_deployment(&deployment).unwrap();
        }

        // Cleanup - keep 2 successful and 1 failed
        state_manager.cleanup_old_records(2, 1).unwrap();

        let successful = state_manager
            .get_deployments_by_status("test-service", DeploymentStatus::Succeeded)
            .unwrap();
        assert_eq!(successful.len(), 2);

        let failed = state_manager
            .get_deployments_by_status("test-service", DeploymentStatus::Failed)
            .unwrap();
        assert_eq!(failed.len(), 1);

        // Should keep the newest ones
        assert!(successful.iter().any(|d| d.deploy_id == "success-005"));
        assert!(successful.iter().any(|d| d.deploy_id == "success-004"));
        assert!(failed.iter().any(|d| d.deploy_id == "failed-003"));
    }

    #[test]
    fn test_combined_file_and_database_lock() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Acquire combined lock
        let guard = state_manager
            .try_lock_service_combined("test-service", "deploy-001", None)
            .unwrap();

        assert_eq!(guard.service(), "test-service");

        // Verify database lock is held
        let service_state = state_manager.get_service_state("test-service").unwrap();
        assert!(service_state.is_some());
        assert!(service_state.unwrap().locked);

        // Verify file lock exists
        let lock_file = temp_dir.path().join("locks").join("test-service.lock");
        assert!(lock_file.exists());

        // Try to acquire again - should fail (both locks held)
        let result = state_manager.try_lock_service_combined("test-service", "deploy-002", None);
        assert!(result.is_err());

        // Release locks
        drop(guard);

        // Verify database lock is released
        let service_state = state_manager.get_service_state("test-service").unwrap();
        assert!(service_state.is_some());
        assert!(!service_state.unwrap().locked);

        // Should be able to acquire again
        let guard2 = state_manager
            .try_lock_service_combined("test-service", "deploy-003", None)
            .unwrap();
        assert_eq!(guard2.service(), "test-service");
    }

    #[test]
    fn test_combined_lock_failure_releases_file_lock() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Manually lock database (but not file lock)
        state_manager
            .try_lock_service("test-service", "deploy-001")
            .unwrap();

        // Try to acquire combined lock - should fail at database lock
        let result = state_manager.try_lock_service_combined("test-service", "deploy-002", None);
        assert!(result.is_err());

        // File lock should have been released (not held)
        // Verify by trying to acquire file lock directly
        let file_lock = state_manager
            .file_lock_manager()
            .try_acquire_lock("test-service")
            .unwrap();

        assert_eq!(file_lock.service(), "test-service");
    }

    #[test]
    fn test_cleanup_includes_file_locks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Create and release a file lock (leaving stale file)
        let file_lock = state_manager
            .file_lock_manager()
            .try_acquire_lock("stale-service")
            .unwrap();
        drop(file_lock);

        // Lock file should exist
        let lock_file = temp_dir.path().join("locks").join("stale-service.lock");
        assert!(lock_file.exists());

        // Run cleanup
        let cleaned = state_manager.cleanup_stale_locks(300).unwrap();

        // Should have cleaned up the file lock
        assert!(!lock_file.exists());
        assert!(cleaned.contains(&"stale-service".to_string()));
    }

    #[test]
    fn test_file_lock_manager_access() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Can access file lock manager
        let file_lock_manager = state_manager.file_lock_manager();

        // Can use it to acquire locks
        let lock = file_lock_manager.try_acquire_lock("test-service").unwrap();
        assert_eq!(lock.service(), "test-service");
    }

    #[test]
    fn test_startup_cleanup_removes_stale_db_locks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Simulate a crash: acquire database lock but no file lock
        // (In real scenario, file lock would be auto-released by OS on crash)
        state_manager
            .try_lock_service("crashed-service", "deploy-001")
            .unwrap();

        // Verify database lock is held
        let service_state = state_manager
            .get_service_state("crashed-service")
            .unwrap()
            .unwrap();
        assert!(service_state.locked);

        // Run startup cleanup
        let cleaned = state_manager.cleanup_stale_locks_on_startup().unwrap();

        // Should have cleaned up the stale lock
        assert_eq!(cleaned.len(), 1);
        assert_eq!(cleaned[0], "crashed-service");

        // Verify database lock is now released
        let service_state = state_manager
            .get_service_state("crashed-service")
            .unwrap()
            .unwrap();
        assert!(!service_state.locked);
    }

    #[test]
    fn test_startup_cleanup_preserves_valid_locks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // Acquire both file and database locks (valid, active deployment)
        let _guard = state_manager
            .try_lock_service_combined("active-service", "deploy-001", None)
            .unwrap();

        // Run startup cleanup
        let cleaned = state_manager.cleanup_stale_locks_on_startup().unwrap();

        // Should NOT have cleaned up the valid lock
        assert!(cleaned.is_empty());

        // Verify lock is still held
        let service_state = state_manager
            .get_service_state("active-service")
            .unwrap()
            .unwrap();
        assert!(service_state.locked);
    }

    #[test]
    fn test_startup_cleanup_no_locks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        // No locks exist
        let cleaned = state_manager.cleanup_stale_locks_on_startup().unwrap();

        // Should have cleaned nothing
        assert!(cleaned.is_empty());
    }

    #[test]
    fn test_atomic_deployment_and_state_update() {
        let temp_dir = tempdir().unwrap();
        let state_manager = StateManager::new(temp_dir.path()).unwrap();

        let deployment = create_test_deployment("test-service", "deploy-001");
        let mut service_state = ServiceState::new("test-service".to_string());
        service_state.current_image = "registry:5000/app:v1.0.0".to_string();

        // Test atomic update
        state_manager
            .update_deployment_and_service_state(&deployment, &service_state)
            .unwrap();

        // Verify both were updated
        let retrieved_deployment = state_manager
            .get_deployment("test-service", "deploy-001")
            .unwrap();
        assert!(retrieved_deployment.is_some());

        let retrieved_state = state_manager.get_service_state("test-service").unwrap();
        assert!(retrieved_state.is_some());
        assert_eq!(
            retrieved_state.unwrap().current_image,
            "registry:5000/app:v1.0.0"
        );
    }
}
