//! IP allowlist middleware for access control
//!
//! This module provides IP-based access control using CIDR range matching.
//! It validates the client IP address against a configured allowlist and
//! rejects requests from unauthorized sources.
//!
//! # Security Features
//! - CIDR range matching for flexible network-based rules
//! - Support for both IPv4 and IPv6
//! - Empty allowlist = allow all (permissive default)
//! - X-Forwarded-For header support for proxied requests
//! - Proper logging of rejected requests

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tracing::{debug, warn};

use crate::http::handlers::AppState;

/// Parsed IP allowlist with CIDR networks
#[derive(Clone, Debug)]
pub struct IpAllowlist {
    networks: Vec<IpNet>,
    allow_all: bool,
}

impl IpAllowlist {
    /// Create a new IP allowlist from configuration
    pub fn from_config(allowed_ips: &[String]) -> Result<Self, String> {
        // Empty list means allow all
        if allowed_ips.is_empty() {
            return Ok(Self {
                networks: Vec::new(),
                allow_all: true,
            });
        }

        let mut networks = Vec::new();
        for ip_str in allowed_ips {
            let network = ip_str
                .parse::<IpNet>()
                .map_err(|e| format!("Invalid CIDR notation '{}': {}", ip_str, e))?;
            networks.push(network);
        }

        Ok(Self {
            networks,
            allow_all: false,
        })
    }

    /// Check if an IP address is allowed
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        if self.allow_all {
            return true;
        }

        self.networks.iter().any(|network| network.contains(&ip))
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

/// Axum middleware for IP allowlist enforcement
pub async fn ip_allowlist_middleware(
    State(app_state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Use the pre-parsed allowlist from app state
    let allowlist = &app_state.ip_allowlist;
    if allowlist.allow_all {
        debug!("IP allowlist is empty, allowing all requests");
        return Ok(next.run(request).await);
    }

    // Extract client IP
    let client_ip = match extract_client_ip(&request) {
        Some(ip) => ip,
        None => {
            warn!("Could not determine client IP address");
            return Err(StatusCode::FORBIDDEN);
        }
    };

    // Check if IP is allowed
    if !allowlist.is_allowed(client_ip) {
        warn!(
            client_ip = %client_ip,
            uri = %request.uri(),
            method = %request.method(),
            "Request blocked: IP not in allowlist"
        );
        return Err(StatusCode::FORBIDDEN);
    }

    debug!(client_ip = %client_ip, "IP allowlist check passed");

    // Continue processing the request
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_allowlist_empty_allows_all() {
        let allowlist = IpAllowlist::from_config(&[]).unwrap();
        assert!(allowlist.allow_all);
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(allowlist.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(allowlist.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_single_ip() {
        let allowlist = IpAllowlist::from_config(&["192.168.1.1/32".to_string()]).unwrap();
        assert!(!allowlist.allow_all);
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("192.168.1.2".parse().unwrap()));
        assert!(!allowlist.is_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_cidr_range() {
        let allowlist = IpAllowlist::from_config(&["192.168.1.0/24".to_string()]).unwrap();
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(allowlist.is_allowed("192.168.1.100".parse().unwrap()));
        assert!(allowlist.is_allowed("192.168.1.254".parse().unwrap()));
        assert!(!allowlist.is_allowed("192.168.2.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_multiple_ranges() {
        let allowlist = IpAllowlist::from_config(&[
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
        ])
        .unwrap();

        // First range
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(allowlist.is_allowed("192.168.1.254".parse().unwrap()));

        // Second range
        assert!(allowlist.is_allowed("10.0.0.1".parse().unwrap()));
        assert!(allowlist.is_allowed("10.255.255.254".parse().unwrap()));

        // Third range
        assert!(allowlist.is_allowed("172.16.0.1".parse().unwrap()));
        assert!(allowlist.is_allowed("172.31.255.254".parse().unwrap()));

        // Outside ranges
        assert!(!allowlist.is_allowed("192.168.2.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("11.0.0.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("172.32.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_ipv6() {
        let allowlist =
            IpAllowlist::from_config(&["2001:db8::/32".to_string(), "::1/128".to_string()])
                .unwrap();

        assert!(allowlist.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(allowlist.is_allowed("2001:db8:1234:5678::1".parse().unwrap()));
        assert!(allowlist.is_allowed("::1".parse().unwrap())); // localhost

        assert!(!allowlist.is_allowed("2001:db9::1".parse().unwrap()));
        assert!(!allowlist.is_allowed("fe80::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_invalid_cidr() {
        let result = IpAllowlist::from_config(&["invalid".to_string()]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid CIDR notation"));

        let result = IpAllowlist::from_config(&["192.168.1.1".to_string()]);
        assert!(result.is_err());

        let result = IpAllowlist::from_config(&["192.168.1.1/33".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn test_ip_allowlist_mixed_ipv4_ipv6() {
        let allowlist =
            IpAllowlist::from_config(&["192.168.1.0/24".to_string(), "2001:db8::/32".to_string()])
                .unwrap();

        // IPv4
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("192.168.2.1".parse().unwrap()));

        // IPv6
        assert!(allowlist.is_allowed("2001:db8::1".parse().unwrap()));
        assert!(!allowlist.is_allowed("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_localhost() {
        let allowlist =
            IpAllowlist::from_config(&["127.0.0.0/8".to_string(), "::1/128".to_string()]).unwrap();

        assert!(allowlist.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(allowlist.is_allowed("127.0.0.2".parse().unwrap()));
        assert!(allowlist.is_allowed("127.255.255.254".parse().unwrap()));
        assert!(allowlist.is_allowed("::1".parse().unwrap()));

        assert!(!allowlist.is_allowed("128.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ip_allowlist_shorthand_notation() {
        // Test that /32 can be omitted for single IPs
        let result = IpAllowlist::from_config(&["192.168.1.1".to_string()]);
        assert!(result.is_err()); // ipnet requires explicit CIDR notation

        // But explicit /32 works
        let allowlist = IpAllowlist::from_config(&["192.168.1.1/32".to_string()]).unwrap();
        assert!(allowlist.is_allowed("192.168.1.1".parse().unwrap()));
        assert!(!allowlist.is_allowed("192.168.1.2".parse().unwrap()));
    }
}
