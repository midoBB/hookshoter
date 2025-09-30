//! HTTP server module for Hookshot deployment receiver
//!
//! This module provides the HTTP API server functionality including:
//! - Axum-based web server with routing
//! - Request/response handling for deployment operations
//! - Middleware for security, timeouts, and request processing
//! - Graceful shutdown handling
//!
//! The server exposes the following endpoints:
//! - POST /deploy - Accept deployment requests
//! - GET /health - Health check endpoint
//! - GET /metrics - Prometheus metrics (when enabled)
//! - GET /status/{deploy_id} - Deployment status lookup
//! - GET /services - List configured services

pub mod handlers;
pub mod middleware;
pub mod responses;
pub mod server;

pub use server::start_server;
