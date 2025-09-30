//! Rate limiting middleware using token bucket algorithm
//!
//! This module provides per-IP rate limiting to prevent DoS attacks and
//! request flooding. It uses a token bucket algorithm for smooth rate
//! limiting with burst capacity.
//!
//! # Features
//! - Token bucket algorithm per IP address
//! - Configurable rate limit (requests per minute)
//! - Automatic cleanup of stale entries
//! - Thread-safe concurrent access
//! - Retry-After header in 429 responses

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::{debug, warn};

use crate::http::handlers::AppState;

/// Token bucket for rate limiting
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
    last_access: Instant,
}

impl TokenBucket {
    /// Create a new token bucket
    fn new(capacity: f64, refill_rate: f64) -> Self {
        let now = Instant::now();
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: now,
            last_access: now,
        }
    }

    /// Refill tokens based on elapsed time
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        let new_tokens = elapsed * self.refill_rate;

        self.tokens = (self.tokens + new_tokens).min(self.capacity);
        self.last_refill = now;
        self.last_access = now;
    }

    /// Try to consume one token
    fn try_consume(&mut self) -> bool {
        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Get time until next token is available
    fn time_until_next_token(&self) -> Duration {
        if self.tokens >= 1.0 {
            return Duration::ZERO;
        }

        let tokens_needed = 1.0 - self.tokens;
        let seconds = tokens_needed / self.refill_rate;
        Duration::from_secs_f64(seconds.ceil())
    }

    /// Check if this bucket is stale (not accessed recently)
    fn is_stale(&self, threshold: Duration) -> bool {
        Instant::now().duration_since(self.last_access) > threshold
    }
}

/// Rate limiter state
pub struct RateLimiter {
    buckets: Arc<DashMap<IpAddr, TokenBucket>>,
    rate_limit: u32,
    refill_rate: f64,
}

impl RateLimiter {
    /// Create a new rate limiter with the given rate limit (requests per minute)
    pub fn new(rate_limit: u32) -> Self {
        let refill_rate = rate_limit as f64 / 60.0; // convert to per second
        Self {
            buckets: Arc::new(DashMap::new()),
            rate_limit,
            refill_rate,
        }
    }

    /// Check if a request from the given IP should be allowed
    pub fn check_rate_limit(&self, ip: IpAddr) -> Result<(), Duration> {
        let mut entry = self
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.rate_limit as f64, self.refill_rate));

        if entry.try_consume() {
            Ok(())
        } else {
            let retry_after = entry.time_until_next_token();
            Err(retry_after)
        }
    }

    /// Start a background task to clean up stale entries
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(60)).await;
                self.cleanup_stale_entries();
            }
        });
    }

    /// Remove stale entries (not accessed for more than 5 minutes)
    fn cleanup_stale_entries(&self) {
        let threshold = Duration::from_secs(300); // 5 minutes
        let mut removed = 0;

        self.buckets.retain(|_ip, bucket| {
            let keep = !bucket.is_stale(threshold);
            if !keep {
                removed += 1;
            }
            keep
        });

        if removed > 0 {
            debug!("Rate limiter: cleaned up {} stale entries", removed);
        }
    }

    /// Get the number of active buckets
    #[cfg(test)]
    pub fn active_buckets(&self) -> usize {
        self.buckets.len()
    }
}

/// Extract client IP from request, considering proxy headers
fn extract_client_ip(request: &Request) -> Option<IpAddr> {
    // First, try X-Forwarded-For header (for requests through proxies)
    if let Some(forwarded_for) = request.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded_for.to_str() {
            // X-Forwarded-For can contain multiple IPs, take the first (original client)
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }
    }

    // Fallback to connection info from socket
    if let Some(ConnectInfo(addr)) = request.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(addr.ip());
    }

    None
}

/// Axum middleware for rate limiting
pub async fn rate_limit_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    // Extract client IP
    let client_ip = match extract_client_ip(&request) {
        Some(ip) => ip,
        None => {
            warn!("Could not determine client IP address for rate limiting");
            // If we can't determine IP, allow the request but log the issue
            return Ok(next.run(request).await);
        }
    };

    // Use the rate limiter from app state (shared across all requests)
    let rate_limiter = &app_state.rate_limiter;

    // Check rate limit
    match rate_limiter.check_rate_limit(client_ip) {
        Ok(()) => {
            debug!(client_ip = %client_ip, "Rate limit check passed");
            Ok(next.run(request).await)
        }
        Err(retry_after) => {
            warn!(
                client_ip = %client_ip,
                uri = %request.uri(),
                method = %request.method(),
                retry_after_secs = retry_after.as_secs(),
                "Request rate limited"
            );

            // Create 429 response with Retry-After header
            let mut headers = HeaderMap::new();
            headers.insert(
                "retry-after",
                retry_after.as_secs().to_string().parse().unwrap(),
            );
            headers.insert("content-type", "application/json".parse().unwrap());

            let body = serde_json::json!({
                "error": "Too many requests",
                "code": "RATE_LIMIT_EXCEEDED",
                "retry_after_seconds": retry_after.as_secs(),
            })
            .to_string();

            Err((StatusCode::TOO_MANY_REQUESTS, headers, body))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_bucket_creation() {
        let bucket = TokenBucket::new(10.0, 1.0);
        assert_eq!(bucket.tokens, 10.0);
        assert_eq!(bucket.capacity, 10.0);
        assert_eq!(bucket.refill_rate, 1.0);
    }

    #[test]
    fn test_token_bucket_consume() {
        let mut bucket = TokenBucket::new(5.0, 1.0);

        // Should be able to consume up to capacity
        assert!(bucket.try_consume());
        assert!(bucket.tokens >= 3.9 && bucket.tokens <= 4.1); // Allow for minor refill
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.try_consume());
        assert!(bucket.tokens < 1.0); // Should be close to 0

        // Should fail when empty (or very close to empty)
        assert!(!bucket.try_consume());
    }

    #[tokio::test]
    async fn test_token_bucket_refill() {
        let mut bucket = TokenBucket::new(10.0, 10.0); // 10 tokens per second

        // Consume all tokens
        for _ in 0..10 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());

        // Wait for refill
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Should have ~5 tokens after 0.5 seconds
        bucket.refill();
        assert!(bucket.tokens >= 4.5 && bucket.tokens <= 5.5);
        assert!(bucket.try_consume());
    }

    #[test]
    fn test_token_bucket_max_capacity() {
        let mut bucket = TokenBucket::new(5.0, 1.0);

        // Don't consume anything, just refill
        std::thread::sleep(Duration::from_secs(10));
        bucket.refill();

        // Should not exceed capacity
        assert_eq!(bucket.tokens, 5.0);
    }

    #[test]
    fn test_token_bucket_time_until_next() {
        let mut bucket = TokenBucket::new(5.0, 2.0); // 2 tokens per second

        // Consume all tokens
        for _ in 0..5 {
            bucket.try_consume();
        }

        let wait_time = bucket.time_until_next_token();
        // Should need to wait some time for next token (at most 0.5 seconds for 1 token at 2 tokens/sec)
        // But due to the refill that happens during consumption, it may be less
        assert!(wait_time.as_secs_f64() >= 0.0 && wait_time.as_secs_f64() <= 1.0);

        // Verify that we actually need to wait (i.e., we don't have a full token)
        assert!(bucket.tokens < 1.0);
    }

    #[test]
    fn test_rate_limiter_creation() {
        let limiter = RateLimiter::new(100);
        assert_eq!(limiter.rate_limit, 100);
        assert_eq!(limiter.refill_rate, 100.0 / 60.0);
    }

    #[test]
    fn test_rate_limiter_per_ip() {
        let limiter = RateLimiter::new(5);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // IP1 can make 5 requests
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip1).is_ok());
        }
        assert!(limiter.check_rate_limit(ip1).is_err());

        // IP2 should still have its own budget
        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip2).is_ok());
        }
        assert!(limiter.check_rate_limit(ip2).is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refill() {
        let limiter = RateLimiter::new(10); // 10 per minute = 1 per 6 seconds
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Consume all tokens
        for _ in 0..10 {
            assert!(limiter.check_rate_limit(ip).is_ok());
        }
        assert!(limiter.check_rate_limit(ip).is_err());

        // Wait for some refill
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Should have refilled some tokens (10/60 per second * 0.5 seconds ≈ 0.08 tokens)
        // Since we need >= 1 token, still should fail
        assert!(limiter.check_rate_limit(ip).is_err());

        // Wait longer
        tokio::time::sleep(Duration::from_secs(6)).await;

        // Should have at least 1 token now
        assert!(limiter.check_rate_limit(ip).is_ok());
    }

    #[test]
    fn test_rate_limiter_cleanup() {
        let limiter = RateLimiter::new(100);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        // Create entries
        limiter.check_rate_limit(ip1).unwrap();
        limiter.check_rate_limit(ip2).unwrap();
        assert_eq!(limiter.active_buckets(), 2);

        // Manually mark one as stale by modifying the bucket
        if let Some(mut entry) = limiter.buckets.get_mut(&ip1) {
            entry.last_access = Instant::now() - Duration::from_secs(400);
        }

        // Run cleanup
        limiter.cleanup_stale_entries();

        // Should have removed the stale entry
        assert_eq!(limiter.active_buckets(), 1);
        assert!(limiter.buckets.contains_key(&ip2));
        assert!(!limiter.buckets.contains_key(&ip1));
    }

    #[test]
    fn test_token_bucket_burst_capacity() {
        let limiter = RateLimiter::new(60); // 60 per minute = 1 per second
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Should be able to burst up to the full capacity immediately
        for i in 0..60 {
            let result = limiter.check_rate_limit(ip);
            assert!(result.is_ok(), "Request {} should succeed", i);
        }

        // 61st request should fail
        assert!(limiter.check_rate_limit(ip).is_err());
    }

    #[test]
    fn test_rate_limiter_retry_after() {
        let limiter = RateLimiter::new(10); // 10 per minute
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Exhaust the bucket
        for _ in 0..10 {
            limiter.check_rate_limit(ip).unwrap();
        }

        // Next request should be rate limited with retry-after
        let result = limiter.check_rate_limit(ip);
        assert!(result.is_err());

        let retry_after = result.unwrap_err();
        // Should be approximately 6 seconds (60 seconds / 10 requests)
        assert!(retry_after.as_secs() >= 5 && retry_after.as_secs() <= 7);
    }
}
