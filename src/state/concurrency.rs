//! Concurrency tracking for deployment operations
//!
//! This module provides thread-safe tracking of active deployments to enforce
//! global and per-service concurrency limits.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tracing::{debug, warn};

use crate::types::{Error, Result};

/// ConcurrencyTracker manages active deployment counts and enforces limits
#[derive(Clone)]
pub struct ConcurrencyTracker {
    /// Global count of active deployments across all services
    global_active: Arc<AtomicU32>,
    /// Per-service active deployment counts: service_name -> count
    per_service_active: Arc<DashMap<String, u32>>,
    /// Maximum allowed concurrent deployments globally
    max_concurrent_total: u32,
    /// Maximum allowed concurrent deployments per service
    max_concurrent_per_service: u32,
}

impl ConcurrencyTracker {
    /// Create a new ConcurrencyTracker with the specified limits
    pub fn new(max_concurrent_total: u32, max_concurrent_per_service: u32) -> Self {
        Self {
            global_active: Arc::new(AtomicU32::new(0)),
            per_service_active: Arc::new(DashMap::new()),
            max_concurrent_total,
            max_concurrent_per_service,
        }
    }

    /// Attempt to acquire a deployment slot for the specified service
    ///
    /// Returns Ok(()) if the slot was acquired, or an error if limits would be exceeded
    pub fn try_acquire(&self, service: &str, deploy_id: &str) -> Result<()> {
        // Check global limit first
        let global_count = self.global_active.load(Ordering::SeqCst);
        if global_count >= self.max_concurrent_total {
            warn!(
                service = %service,
                deploy_id = %deploy_id,
                global_active = global_count,
                max_concurrent_total = self.max_concurrent_total,
                "Global concurrency limit reached"
            );
            return Err(Error::ConcurrencyLimitExceeded {
                limit_type: "global".to_string(),
                limit: self.max_concurrent_total,
                current: global_count,
            });
        }

        // Check per-service limit
        let service_count = self
            .per_service_active
            .get(service)
            .map(|entry| *entry.value())
            .unwrap_or(0);

        if service_count >= self.max_concurrent_per_service {
            warn!(
                service = %service,
                deploy_id = %deploy_id,
                service_active = service_count,
                max_concurrent_per_service = self.max_concurrent_per_service,
                "Per-service concurrency limit reached"
            );
            return Err(Error::ConcurrencyLimitExceeded {
                limit_type: format!("service '{}'", service),
                limit: self.max_concurrent_per_service,
                current: service_count,
            });
        }

        // Acquire the slot
        self.global_active.fetch_add(1, Ordering::SeqCst);
        self.per_service_active
            .entry(service.to_string())
            .and_modify(|count| *count += 1)
            .or_insert(1);

        let new_global = self.global_active.load(Ordering::SeqCst);
        let new_service = self
            .per_service_active
            .get(service)
            .map(|e| *e.value())
            .unwrap_or(0);

        debug!(
            service = %service,
            deploy_id = %deploy_id,
            global_active = new_global,
            service_active = new_service,
            "Deployment slot acquired"
        );

        Ok(())
    }

    /// Release a deployment slot for the specified service
    pub fn release(&self, service: &str, deploy_id: &str) {
        // Decrement global count
        let prev_global = self.global_active.fetch_sub(1, Ordering::SeqCst);
        if prev_global == 0 {
            warn!(
                service = %service,
                deploy_id = %deploy_id,
                "Attempted to release deployment slot when global count was already 0"
            );
            // Restore the count
            self.global_active.fetch_add(1, Ordering::SeqCst);
            return;
        }

        // Decrement per-service count
        if let Some(mut entry) = self.per_service_active.get_mut(service) {
            if *entry.value() > 0 {
                *entry.value_mut() -= 1;
                let new_count = *entry.value();

                // Remove the entry if count reaches 0 to avoid memory growth
                if new_count == 0 {
                    drop(entry);
                    self.per_service_active.remove(service);
                }
            } else {
                warn!(
                    service = %service,
                    deploy_id = %deploy_id,
                    "Attempted to release deployment slot when service count was already 0"
                );
            }
        } else {
            warn!(
                service = %service,
                deploy_id = %deploy_id,
                "Attempted to release deployment slot for service with no active deployments"
            );
        }

        let new_global = self.global_active.load(Ordering::SeqCst);
        let new_service = self
            .per_service_active
            .get(service)
            .map(|e| *e.value())
            .unwrap_or(0);

        debug!(
            service = %service,
            deploy_id = %deploy_id,
            global_active = new_global,
            service_active = new_service,
            "Deployment slot released"
        );
    }

    /// Get the current global active deployment count
    pub fn get_global_active(&self) -> u32 {
        self.global_active.load(Ordering::SeqCst)
    }

    /// Get the current active deployment count for a specific service
    pub fn get_service_active(&self, service: &str) -> u32 {
        self.per_service_active
            .get(service)
            .map(|entry| *entry.value())
            .unwrap_or(0)
    }

    /// Get all services with active deployments
    pub fn get_all_active_services(&self) -> Vec<(String, u32)> {
        self.per_service_active
            .iter()
            .map(|entry| (entry.key().clone(), *entry.value()))
            .collect()
    }

    /// Get the maximum allowed global concurrent deployments
    pub fn get_max_concurrent_total(&self) -> u32 {
        self.max_concurrent_total
    }

    /// Get the maximum allowed per-service concurrent deployments
    pub fn get_max_concurrent_per_service(&self) -> u32 {
        self.max_concurrent_per_service
    }

    /// Check if there's capacity for a new deployment without acquiring
    pub fn has_capacity(&self, service: &str) -> bool {
        let global_count = self.global_active.load(Ordering::SeqCst);
        if global_count >= self.max_concurrent_total {
            return false;
        }

        let service_count = self.get_service_active(service);
        service_count < self.max_concurrent_per_service
    }
}

/// RAII guard that automatically releases a concurrency slot when dropped
pub struct ConcurrencyGuard {
    tracker: ConcurrencyTracker,
    service: String,
    deploy_id: String,
    released: bool,
}

impl ConcurrencyGuard {
    /// Create a new guard that will release the slot on drop
    pub fn new(tracker: ConcurrencyTracker, service: String, deploy_id: String) -> Self {
        Self {
            tracker,
            service,
            deploy_id,
            released: false,
        }
    }

    /// Manually release the guard early (usually not needed due to Drop)
    pub fn release(mut self) {
        if !self.released {
            self.tracker.release(&self.service, &self.deploy_id);
            self.released = true;
        }
    }
}

impl Drop for ConcurrencyGuard {
    fn drop(&mut self) {
        if !self.released {
            self.tracker.release(&self.service, &self.deploy_id);
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concurrency_tracker_creation() {
        let tracker = ConcurrencyTracker::new(10, 2);
        assert_eq!(tracker.get_global_active(), 0);
        assert_eq!(tracker.get_max_concurrent_total(), 10);
        assert_eq!(tracker.get_max_concurrent_per_service(), 2);
    }

    #[test]
    fn test_acquire_and_release() {
        let tracker = ConcurrencyTracker::new(10, 2);

        // Acquire a slot
        assert!(tracker.try_acquire("service-a", "deploy-1").is_ok());
        assert_eq!(tracker.get_global_active(), 1);
        assert_eq!(tracker.get_service_active("service-a"), 1);

        // Release the slot
        tracker.release("service-a", "deploy-1");
        assert_eq!(tracker.get_global_active(), 0);
        assert_eq!(tracker.get_service_active("service-a"), 0);
    }

    #[test]
    fn test_global_concurrency_limit() {
        let tracker = ConcurrencyTracker::new(2, 5);

        // Acquire up to limit
        assert!(tracker.try_acquire("service-a", "deploy-1").is_ok());
        assert!(tracker.try_acquire("service-b", "deploy-2").is_ok());

        // Should fail when limit reached
        let result = tracker.try_acquire("service-c", "deploy-3");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ConcurrencyLimitExceeded {
                limit_type,
                limit,
                current,
            } => {
                assert_eq!(limit_type, "global");
                assert_eq!(limit, 2);
                assert_eq!(current, 2);
            }
            _ => panic!("Expected ConcurrencyLimitExceeded error"),
        }

        // Release one and try again
        tracker.release("service-a", "deploy-1");
        assert!(tracker.try_acquire("service-c", "deploy-3").is_ok());
    }

    #[test]
    fn test_per_service_concurrency_limit() {
        let tracker = ConcurrencyTracker::new(10, 2);

        // Acquire up to per-service limit
        assert!(tracker.try_acquire("service-a", "deploy-1").is_ok());
        assert!(tracker.try_acquire("service-a", "deploy-2").is_ok());

        // Should fail when per-service limit reached
        let result = tracker.try_acquire("service-a", "deploy-3");
        assert!(result.is_err());
        match result.unwrap_err() {
            Error::ConcurrencyLimitExceeded {
                limit_type,
                limit,
                current,
            } => {
                assert_eq!(limit_type, "service 'service-a'");
                assert_eq!(limit, 2);
                assert_eq!(current, 2);
            }
            _ => panic!("Expected ConcurrencyLimitExceeded error"),
        }

        // Other services should still work
        assert!(tracker.try_acquire("service-b", "deploy-4").is_ok());
    }

    #[test]
    fn test_multiple_services() {
        let tracker = ConcurrencyTracker::new(10, 2);

        // Acquire slots for multiple services
        assert!(tracker.try_acquire("service-a", "deploy-1").is_ok());
        assert!(tracker.try_acquire("service-a", "deploy-2").is_ok());
        assert!(tracker.try_acquire("service-b", "deploy-3").is_ok());

        assert_eq!(tracker.get_global_active(), 3);
        assert_eq!(tracker.get_service_active("service-a"), 2);
        assert_eq!(tracker.get_service_active("service-b"), 1);

        // Check all active services
        let active_services = tracker.get_all_active_services();
        assert_eq!(active_services.len(), 2);
    }

    #[test]
    fn test_has_capacity() {
        let tracker = ConcurrencyTracker::new(2, 1);

        assert!(tracker.has_capacity("service-a"));

        // Fill up service-a
        tracker.try_acquire("service-a", "deploy-1").unwrap();
        assert!(!tracker.has_capacity("service-a"));

        // service-b still has capacity
        assert!(tracker.has_capacity("service-b"));

        // Fill up global
        tracker.try_acquire("service-b", "deploy-2").unwrap();
        assert!(!tracker.has_capacity("service-c"));
    }

    #[test]
    fn test_concurrency_guard() {
        let tracker = ConcurrencyTracker::new(10, 2);

        {
            tracker.try_acquire("service-a", "deploy-1").unwrap();
            let _guard = ConcurrencyGuard::new(
                tracker.clone(),
                "service-a".to_string(),
                "deploy-1".to_string(),
            );

            assert_eq!(tracker.get_global_active(), 1);
            assert_eq!(tracker.get_service_active("service-a"), 1);
        } // guard dropped here

        // Should be released automatically
        assert_eq!(tracker.get_global_active(), 0);
        assert_eq!(tracker.get_service_active("service-a"), 0);
    }

    #[test]
    fn test_manual_guard_release() {
        let tracker = ConcurrencyTracker::new(10, 2);

        tracker.try_acquire("service-a", "deploy-1").unwrap();
        let guard = ConcurrencyGuard::new(
            tracker.clone(),
            "service-a".to_string(),
            "deploy-1".to_string(),
        );

        assert_eq!(tracker.get_global_active(), 1);

        // Manually release
        guard.release();

        assert_eq!(tracker.get_global_active(), 0);
        assert_eq!(tracker.get_service_active("service-a"), 0);
    }

    #[test]
    fn test_over_release_protection() {
        let tracker = ConcurrencyTracker::new(10, 2);

        // Try to release without acquiring
        tracker.release("service-a", "deploy-1");

        // Should not go negative
        assert_eq!(tracker.get_global_active(), 0);
        assert_eq!(tracker.get_service_active("service-a"), 0);
    }
}
