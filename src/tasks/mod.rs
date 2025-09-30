//! Background tasks for maintenance operations
//!
//! This module provides background tasks that run periodically to perform
//! maintenance operations like cleaning up stale locks.

use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, error, info};

use crate::state::StateManager;

/// Configuration for the stale lock cleanup task
#[derive(Debug, Clone)]
pub struct StaleLocksCleanupConfig {
    /// How often to run the cleanup (in seconds)
    pub interval_seconds: u64,
    /// Lock timeout threshold (in seconds)
    pub lock_timeout_seconds: u64,
}

impl Default for StaleLocksCleanupConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 60,      // Run every minute
            lock_timeout_seconds: 300, // 5 minutes
        }
    }
}

/// Start a background task to periodically clean up stale locks
pub fn spawn_stale_locks_cleanup_task(
    state_manager: Arc<StateManager>,
    config: StaleLocksCleanupConfig,
) -> tokio::task::JoinHandle<()> {
    info!(
        interval_seconds = config.interval_seconds,
        lock_timeout_seconds = config.lock_timeout_seconds,
        "Starting stale locks cleanup background task"
    );

    tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(config.interval_seconds));

        loop {
            tick.tick().await;

            debug!("Running stale locks cleanup");

            match state_manager.cleanup_stale_locks(config.lock_timeout_seconds) {
                Ok(cleaned) => {
                    if !cleaned.is_empty() {
                        info!(
                            count = cleaned.len(),
                            services = ?cleaned,
                            "Cleaned up stale locks"
                        );
                    } else {
                        debug!("No stale locks found");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to clean up stale locks");
                }
            }
        }
    })
}

/// Start all background tasks
pub fn spawn_background_tasks(
    state_manager: Arc<StateManager>,
    lock_timeout_seconds: u64,
) -> Vec<tokio::task::JoinHandle<()>> {
    let mut handles = Vec::new();

    // Spawn stale locks cleanup task
    let config = StaleLocksCleanupConfig {
        interval_seconds: 60,
        lock_timeout_seconds,
    };
    let handle = spawn_stale_locks_cleanup_task(state_manager.clone(), config);
    handles.push(handle);

    info!(
        task_count = handles.len(),
        "Background tasks spawned successfully"
    );

    handles
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::StateManager;
    use tempfile::tempdir;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_stale_locks_cleanup_task() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        // Create a service state with an old lock
        let deploy_id = "test-deploy-123";
        state_manager
            .try_lock_service("test-service", deploy_id)
            .unwrap();

        // Manually set the lock to be old (simulate by unlocking and re-locking with old timestamp)
        // In a real test, we'd wait for the actual timeout, but for unit tests
        // we'll just verify the cleanup function works

        let config = StaleLocksCleanupConfig {
            interval_seconds: 1,     // Short interval for testing
            lock_timeout_seconds: 1, // Very short timeout for testing
        };

        let handle = spawn_stale_locks_cleanup_task(state_manager.clone(), config);

        // Wait for a couple of cleanup cycles
        sleep(Duration::from_secs(3)).await;

        // Stop the task
        handle.abort();

        // The task should have run at least once
        // (We can't easily verify the cleanup worked without manipulating timestamps)
    }

    #[tokio::test]
    async fn test_spawn_background_tasks() {
        let temp_dir = tempdir().unwrap();
        let state_manager = Arc::new(StateManager::new(temp_dir.path()).unwrap());

        let handles = spawn_background_tasks(state_manager, 300);

        // Should have spawned at least one task
        assert!(!handles.is_empty());

        // Clean up
        for handle in handles {
            handle.abort();
        }
    }
}
