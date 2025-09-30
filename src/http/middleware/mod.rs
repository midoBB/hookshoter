//! HTTP middleware for the deployment receiver
//!
//! This module provides various middleware layers for the HTTP server including:
//! - Request timeout handling
//! - Request body size limits
//! - Compression/decompression
//! - Distributed tracing
//! - HMAC authentication for webhooks
//! - IP allowlist filtering
//! - Rate limiting

pub mod auth;
pub mod ip_allowlist;
pub mod rate_limit;

use axum::extract::Request;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::info_span;

use crate::config::SystemConfig;

// Re-export middleware functions
pub use ip_allowlist::{ip_allowlist_middleware, IpAllowlist};
pub use rate_limit::{rate_limit_middleware, RateLimiter};

/// Create the middleware stack for the HTTP server
pub fn create_middleware_stack(
    config: &SystemConfig,
) -> ServiceBuilder<impl tower::Layer<axum::routing::Router>> {
    ServiceBuilder::new()
        // Logging and tracing layer (outermost)
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request| {
                info_span!(
                    "http_request",
                    method = %request.method(),
                    uri = %request.uri(),
                    version = ?request.version(),
                    user_agent = request
                        .headers()
                        .get("user-agent")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown"),
                    request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("unknown")
                )
            }),
        )
        // Request timeout
        .layer(TimeoutLayer::new(Duration::from_secs(
            config.server.request_timeout,
        )))
        // Compression
        .layer(CompressionLayer::new())
        // Request body size limit (innermost)
        .layer(RequestBodyLimitLayer::new(
            parse_size_string(&config.server.max_request_size).unwrap_or(1024 * 1024), // Default to 1MB if parsing fails
        ))
}

/// Parse size strings like "1MB", "500KB", "2GB" into bytes
pub fn parse_size_string(size_str: &str) -> Result<usize, String> {
    let size_str = size_str.trim().to_uppercase();

    if size_str.is_empty() {
        return Err("Empty size string".to_string());
    }

    // Check for unit suffixes
    if let Some(number_part) = size_str.strip_suffix("GB") {
        return parse_number(number_part).map(|n| n * 1024 * 1024 * 1024);
    }

    if let Some(number_part) = size_str.strip_suffix("MB") {
        return parse_number(number_part).map(|n| n * 1024 * 1024);
    }

    if let Some(number_part) = size_str.strip_suffix("KB") {
        return parse_number(number_part).map(|n| n * 1024);
    }

    if let Some(number_part) = size_str.strip_suffix("B") {
        return parse_number(number_part);
    }

    // No suffix, assume bytes
    parse_number(&size_str)
}

/// Parse the numeric part of a size string
fn parse_number(number_str: &str) -> Result<usize, String> {
    number_str
        .parse::<usize>()
        .map_err(|_| format!("Invalid number: {}", number_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size_string() {
        assert_eq!(parse_size_string("1024").unwrap(), 1024);
        assert_eq!(parse_size_string("1KB").unwrap(), 1024);
        assert_eq!(parse_size_string("1MB").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_string("1GB").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_size_string("2MB").unwrap(), 2 * 1024 * 1024);
        assert_eq!(parse_size_string("512KB").unwrap(), 512 * 1024);

        // Test case insensitive
        assert_eq!(parse_size_string("1mb").unwrap(), 1024 * 1024);
        assert_eq!(parse_size_string("1Mb").unwrap(), 1024 * 1024);

        // Test with whitespace
        assert_eq!(parse_size_string(" 1MB ").unwrap(), 1024 * 1024);

        // Test bytes suffix
        assert_eq!(parse_size_string("1024B").unwrap(), 1024);

        // Test error cases
        assert!(parse_size_string("").is_err());
        assert!(parse_size_string("invalid").is_err());
        assert!(parse_size_string("1XB").is_err());
    }

    #[test]
    fn test_parse_number() {
        assert_eq!(parse_number("123").unwrap(), 123);
        assert_eq!(parse_number("0").unwrap(), 0);
        assert!(parse_number("abc").is_err());
        assert!(parse_number("").is_err());
    }
}
