# Generic Deploy Webhook Receiver - Technical Specification v1.0

## Executive Summary

A lightweight, single-binary HTTP service written in Rust that accepts authenticated deployment requests from CI systems and executes locally-configured OS command sequences for deploy, healthcheck, and rollback operations. The receiver treats any non-zero exit code as failure and provides automatic rollback capabilities with comprehensive logging and observability.

**Key Characteristics:**
- Single static binary (~10MB) with embedded database
- Zero runtime dependencies
- Crash-safe with automatic state recovery
- Intentionally generic - not coupled to any specific deployment technology

## Goals & Non-goals

### Goals
- **Run arbitrary configured OS processes** for deploy, healthcheck, and rollback (argv-form commands).
- Treat **any non-zero exit** as failure and trigger rollback policy if configured.
- Keep the service **stateless** for deployment records & current-image; rely on an external system for previous-image retrieval and authoritative state.
- Be **small**, auditable, and runnable as a single binary on the host.
- Secure (HMAC-signed requests, network restrictions, least privilege).
- Configurable per-service command sequences, timeouts, retries, and environment.
- Provide observability (logs, metrics endpoint).

### Non-Goals
- Full distributed orchestration (multi-node coordination, canarying across nodes).
- Storing authoritative deployment history or cluster state (external system required).
- Running commands supplied by request body — all executable sequences are read from local configuration only (no arbitrary execution from CI payloads).

## Core Architecture

### Design Principles

- **Simplicity First**: Single static binary, minimal dependencies, clear failure semantics
- **Security by Default**: HMAC authentication, no arbitrary command execution, principle of least privilege
- **Operational Excellence**: Idempotent operations, comprehensive logging, observable state transitions
- **Generic Implementation**: Not tied to specific container runtimes or service managers
- **Fast Acknowledgment**: Webhook returns immediately after validation, deployment runs async

### System Components
- **HTTP API**: accepts `POST /deploy` and a few read-only endpoints (`/health`, `/metrics`, optional short-lived `/status/<id>` while process running — not persisted).
- **Config loader**: reads a local config file (YAML) that maps `service` → sequences for `deploy`, `healthcheck`, `rollback` plus execution metadata.
- **Executor**: runs configured commands in a controlled environment (argv-style), with per-command timeouts and kill semantics.
- **Logger**: streams each deploy's stdout/stderr to an append-only file or external log system. Log retention is configurable and rotation is recommended.
- **Metrics exporter**: Prometheus `/metrics` endpoint exposing counters and durations (optional).
```
┌─────────────┐     HTTPS/HMAC      ┌──────────────────┐
│   CI/CD     │────────────────────>│  HTTP Handler    │
│  (GitHub    │                     │   (actix-web)    │
│  Actions)   │                     └────────┬─────────┘
└─────────────┘                              │
                                             ▼
                                    ┌──────────────────┐
                                    │  Request Router  │
                                    │   & Validator    │
                                    └────────┬─────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    ▼                        ▼                        ▼
          ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐
          │ Config Provider  │    │  State Manager   │    │ Command Executor │
          │   (YAML/TOML)    │    │      (redb)      │    │  (tokio::process)│
          └──────────────────┘    └──────────────────┘    └──────────────────┘
```


## Configuration Model

### Dual Configuration Files

The system uses two separate TOML configuration files for clear separation of concerns:

1. **System Configuration** (`/etc/deploy-receiver/config.toml`) - Runtime settings
2. **Services Configuration** (`/etc/deploy-receiver/services.toml`) - Deployment definitions

### System Configuration (`config.toml`)

```toml
# Deploy Receiver System Configuration
# This file controls the receiver runtime behavior

[server]
listen = "127.0.0.1:8080"  # Use Tailscale/private network
worker_threads = 4          # Number of deployment worker threads
max_request_size = "1MB"
request_timeout = 30        # seconds
shutdown_timeout = 300      # seconds to wait for active deploys on shutdown

[security]
allowed_ips = []           # Empty = allow all, or ["10.0.0.0/8", "192.168.1.0/24"]
rate_limit = 100           # Max requests per minute per IP

[storage]
data_dir = "/var/lib/deploy-receiver"

# State retention policies
[storage.retention]
successful_deploys = 100    # Keep last N successful deploys per service
failed_deploys = 50         # Keep last N failed deploys per service

[logging]
level = "info"             # trace, debug, info, warn, error
format = "json"            # json or pretty
directory = "/var/log/deploy-receiver"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"
status_cache_seconds = 10   # Cache /health responses

[limits]
max_concurrent_total = 10   # Global concurrent deployment limit
max_concurrent_per_service = 1
deployment_timeout = 1800   # 30 minutes global timeout
command_timeout = 300       # 5 minutes default per command
lock_timeout = 60          # Seconds to wait for service lock

[notifications]
enabled = false

# Optional webhook notifications
[notifications.webhook]
on_failure = "https://hooks.slack.com/services/..."
on_rollback = "https://hooks.slack.com/services/..."
on_success = "https://hooks.slack.com/services/..."
timeout = 5
```

### Services Configuration (`services.toml`)

```toml
# Deploy Receiver Service Definitions
# This file defines what commands to run for each deployable service

# Global defaults inherited by all services (can be overridden per-service)
[defaults]
working_dir = "/srv"
command_timeout = 120
healthcheck_timeout = 60
rollback_enabled = true

# Service definitions - array of tables allows multiple services
[[service]]
name = "web-frontend"
description = "Next.js frontend application"
enabled = true
working_dir = "/srv/web-frontend"

[service.env]
NODE_ENV = "production"
PORT = "3000"

[service.security]
# Image validation pattern (regex syntax)
allowed_image_pattern = '^registry\.local:8443/web-frontend:(v\d+\.\d+\.\d+|sha-[a-f0-9]{7,40})$'
allowed_env_overrides = ["LOG_LEVEL", "FEATURE_FLAGS", "DEBUG"]

# Deployment phase - commands run sequentially
[services.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "run", "--rm", "--entrypoint=/bin/true", "{{IMAGE}}"],  # smoke test
    ["systemctl", "--user", "restart", "mysite.service"],
]
# Health checking phase
[service.healthcheck]
initial_delay = 5          # Wait before first check
interval = 3               # Seconds between checks
max_attempts = 20          # Total attempts before giving up
success_threshold = 3      # Consecutive successes required
commands = [
    ["curl", "-fsS", "--retry", "3", "http://127.0.0.1:3000/health"],
]


# Rollback phase - only runs if deploy or healthcheck fails
[service.rollback]
enabled = true
max_attempts = 2
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "mysite.service"],
]


# Hooks for external integrations
[service.hooks]
pre_deploy = []            # Commands to run before deploy
post_deploy = []           # Commands to run after successful deploy
on_failure = []            # Commands to run on failure

# Custom template variables for this service
[service.templates]
container_name = "{{SERVICE}}-{{TIMESTAMP}}"
backup_tag = "rollback-{{DEPLOY_ID}}"

# Example of another service
[[service]]
name = "api-service"
description = "Go REST API backend"
enabled = true
working_dir = "/srv/api-service"

[service.env]
GO_ENV = "production"
PORT = "8080"
DATABASE_URL = "postgres://user:pass@localhost:5432/app"

[service.security]
# Image validation ensures only semver releases or commit SHAs are allowed
allowed_image_pattern = '^registry\.local:8443/api-service:(v\d+\.\d+\.\d+|sha-[a-f0-9]{40})$'
allowed_env_overrides = ["LOG_LEVEL", "TRACE_ENABLED"]

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "run", "--rm", "--entrypoint=/bin/true", "{{IMAGE}}"],  # smoke test
    ["systemctl", "--user", "restart", "api-service.service"],
]

[service.healthcheck]
initial_delay = 10
interval = 5
max_attempts = 15
success_threshold = 2
commands = [
    ["curl", "-fsS", "http://127.0.0.1:8080/ready"],
]

[service.rollback]
enabled = true
max_attempts = 3
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "api-service.service"],
]

[service.hooks]
pre_deploy = [["echo", "Starting deploy for api-service"]]
post_deploy = [["echo", "Deployment complete for api-service"]]
on_failure = [["echo", "Deployment failed for api-service"]]

```

## Cli Design

```rust
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "deploy-receiver")]
#[command(about = "A lightweight deployment webhook receiver")]
#[command(long_about = "
A single-binary HTTP service that accepts authenticated deployment requests
from CI systems and executes locally-configured OS command sequences.
")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// System configuration file path
    #[arg(short, long, default_value = "/etc/deploy-receiver/config.toml")]
    config: PathBuf,

    /// Services configuration file path
    #[arg(short, long, default_value = "/etc/deploy-receiver/services.toml")]
    services: PathBuf,

    /// Override log level
    #[arg(long, value_enum)]
    log_level: Option<LogLevel>,

    /// Enable verbose output (sets log level to debug)
    #[arg(short, long)]
    verbose: bool,

    /// Run in quiet mode (minimal output)
    #[arg(short, long, conflicts_with = "verbose")]
    quiet: bool,
}

#[derive(ValueEnum, Clone, Debug)]
enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}
#[derive(ValueEnum, Clone, Debug)]
enum LogFormat {
    Json,
    Pretty,
}


#[derive(Subcommand)]
enum Commands {
    /// Run the webhook receiver server (default if no subcommand given)
    Run(RunArgs),
    /// Validate configuration files
    Validate,
    /// Show detailed version and build information
    Version,
}

#[derive(Args)]
struct RunArgs {
    /// Override listen address (format: "host:port")
    #[arg(long)]
    port: Option<String>,

    #[arg(long)]
    bind: Option<String>, // Set bind address (e.g. "127.0.0.1")
    #[arg(long)]
    logFormat: Option<LogFormat>,
}

/// Get effective log level considering verbose/quiet flags
pub fn effective_log_level(&self) -> LogLevel {
  if self.verbose {
      LogLevel::Debug
  } else if self.quiet {
      LogLevel::Error
  } else {
      self.log_level.clone().unwrap_or(LogLevel::Info)
  }
}

```
## Database Schema (redb)

### Deployment State Machine

```
┌─────────┐
│ PENDING │──────────┐
└────┬────┘          │
     │               ▼
     ▼         ┌──────────┐
┌───────────┐  │ REJECTED │
│ DEPLOYING │  └──────────┘
└────┬──────┘
     │
     ├─────────────────┐
     ▼                 ▼
┌──────────────┐  ┌─────────────────┐
│HEALTHCHECKING│  │ DEPLOY_FAILED   │
└────┬─────────┘  └────────┬────────┘
     │                     │
     ├──────┐              ▼
     ▼      │         ┌────────────┐
┌──────────┐│         │ ROLLING    │
│SUCCEEDED ││         │   BACK     │
└──────────┘│         └────┬───────┘
            │              │
            ▼              ├────────┐
      ┌─────────────┐      ▼        ▼
      │HEALTH_FAILED│ ┌────────┐ ┌──────────────┐
      └─────────────┘ │ROLLED  │ │ROLLBACK      │
                      │BACK    │ │FAILED        │
                      └────────┘ └──────────────┘
```


### Table Definitions

```rust
use redb::{Database, TableDefinition, ReadableTable};
use serde::{Serialize, Deserialize};

// Table definitions with type safety
const DEPLOYMENTS: TableDefinition<&str, Vec<u8>> = TableDefinition::new("deployments");
const SERVICE_STATE: TableDefinition<&str, Vec<u8>> = TableDefinition::new("service_state");

// Key patterns:
// deployments: "{service}:{deploy_id}" -> DeploymentRecord
// service_state: "{service}" -> ServiceState

#[derive(Serialize, Deserialize, Clone)]
struct DeploymentRecord {
    deploy_id: String,
    service: String,
    status: DeploymentStatus,
    image: String,
    previous_image: Option<String>,
    started_at: i64,  // Unix timestamp
    completed_at: Option<i64>,
    duration_ms: Option<u64>,
    // Execution details
    state_transitions: Vec<StateTransition>,
    command_results: Vec<CommandResult>,

    // Rollback information
    rollback_attempted: bool,
    rollback_reason: Option<String>,
    rollback_succeeded: Option<bool>,

    // Request metadata
    metadata: BTreeMap<String, String>,
    triggered_by: String,  // IP or identifier
    hmac_valid: bool,
}

#[derive(Serialize, Deserialize)]
struct ServiceState {
    service: String,
    current_image: String,
    current_deploy_id: String,

    // History
    last_successful_deploy: Option<String>,
    last_failed_deploy: Option<String>,
    consecutive_failures: u32,
    total_deploys: u64,
    total_rollbacks: u64,

    // Health
    last_health_check: i64,
    health_status: HealthStatus,
    health_message: Option<String>,

    // State
    locked: bool,
    locked_by: Option<String>,
    locked_at: Option<i64>,
    updated_at: i64,
}
#[derive(Serialize, Deserialize)]
struct StateTransition {
    from_state: DeploymentStatus,
    to_state: DeploymentStatus,
    timestamp: i64,
    reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CommandResult {
    phase: CommandPhase,  // Deploy, Healthcheck, Rollback
    step_name: String,
    command: Vec<String>,
    exit_code: Option<i32>,
    stdout: String,  // Truncated to 10KB
    stderr: String,  // Truncated to 10KB
    started_at: i64,
    duration_ms: u64,
    timed_out: bool,
    retries: u32,
}

#[derive(Serialize, Deserialize)]
enum DeploymentStatus {
    Queued,
    Validating,
    Deploying,
    HealthChecking,
    Succeeded,
    Failed,
    RollingBack,
    RolledBack,
    RollbackFailed,
}
```

### Database Operations

```rust
impl StateManager {
    fn new(path: &Path) -> Result<Self> {
        let db = Database::builder()
            .set_cache_size(50 * 1024 * 1024)  // 50MB cache
            .create(path)?;

        Ok(StateManager { db: Arc::new(db) })
    }

    async fn record_deployment(&self, record: DeploymentRecord) -> Result<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(DEPLOYMENTS)?;
            let key = format!("{}:{}", record.service, record.deploy_id);
            let value = bincode::serialize(&record)?;
            table.insert(&key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    async fn get_service_state(&self, service: &str) -> Result<Option<ServiceState>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(SERVICE_STATE)?;

        match table.get(service)? {
            Some(data) => Ok(Some(bincode::deserialize(&data.value())?)),
            None => Ok(None),
        }
    }

    // Atomic test-and-set for deployment locking
    async fn try_lock_service(&self, service: &str, deploy_id: &str) -> Result<bool> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(SERVICE_STATE)?;
            let mut state = match table.get(service)? {
                Some(data) => bincode::deserialize(&data.value())?,
                None => ServiceState::new(service),
            };

            if state.locked {
                return Ok(false);  // Already locked
            }

            state.locked = true;
            state.locked_by = Some(deploy_id.to_string());
            state.locked_at = Some(Utc::now().timestamp());

            table.insert(service, bincode::serialize(&state)?)?;
        }
        write_txn.commit()?;
        Ok(true)
    }
}
```

## HTTP API Specification

### Request Flow

```
Client Request → HMAC Validation → Request Parsing → Schema Validation
    → Service Validation → Lock Acquisition → Queue Deployment → Return 202 Accepted
```

### Core Endpoints

#### `POST /deploy`

Initiates a deployment.

**Request Headers**:
```
Content-Type: application/json
X-Hub-Signature-256: sha256=<signature>
X-Request-ID: <optional-correlation-id>
```

**Request Body**:
```json
{
  "deploy_id": "deploy-20250927-0001",  // optional, auto-generated if absent
  "service": "mysite",
  "image": "registry.local:8443/mysite:sha-abc123",
  "previous_image": "registry.local:8443/mysite:sha-xyz789",  // optional but recommended
  "metadata": {
    "git_ref": "refs/heads/main",
    "git_sha": "abc123def456",
    "triggered_by": "github-actions",
    "pull_request": null
  },
  "overrides": {
    "env": {
      "FEATURE_FLAGS": "new_ui=true",
      "LOG_LEVEL": "debug"
    }
  },
  "dry_run": false  // optional, validates without executing
}
```

**Response (200 OK - Success)**:
```json
{
  "deploy_id": "deploy-20250927-0001",
  "service": "mysite",
  "status": "SUCCEEDED",
  "image": "registry.local:8443/mysite:sha-abc123",
  "started_at": "2025-09-27T20:00:00Z",
  "completed_at": "2025-09-27T20:01:30Z",
  "duration_seconds": 90,
  "status_url": "/status/deploy-20250927-0001",
  "log_url": "/logs/deploy-20250927-0001"
}
```

**Response (200 OK - Rolled Back)**:
```json
{
  "deploy_id": "deploy-20250927-0002",
  "service": "mysite",
  "status": "ROLLED_BACK",
  "attempted_image": "registry.local:8443/mysite:sha-bad999",
  "current_image": "registry.local:8443/mysite:sha-abc123",
  "error": "Healthcheck failed: connection refused",
  "rollback_reason": "healthcheck_timeout",
  "started_at": "2025-09-27T21:00:00Z",
  "completed_at": "2025-09-27T21:03:00Z",
  "duration_seconds": 180,
  "status_url": "/status/deploy-20250927-0002",
  "log_url": "/logs/deploy-20250927-0002"
}
```

**Response (500 - Failed)**:
```json
{
  "deploy_id": "deploy-20250927-0003",
  "service": "mysite",
  "status": "FAILED",
  "error": "Deployment failed and rollback unsuccessful",
  "failure_stage": "rollback",
  "failure_detail": "systemctl restart failed: exit code 1",
  "requires_intervention": true,
  "started_at": "2025-09-27T22:00:00Z",
  "failed_at": "2025-09-27T22:05:00Z",
  "status_url": "/status/deploy-20250927-0003",
  "log_url": "/logs/deploy-20250927-0003"
}
```

#### `GET /status/{deploy_id}`

Returns detailed deployment status.

**Response (200 OK)**:
```json
{
  "deploy_id": "deploy-2025-09-27-001",
  "service": "web-frontend",
  "status": "SUCCEEDED",
  "progress": {
    "phase": "COMPLETED",
    "steps_completed": 4,
    "steps_total": 4,
    "current_step": null
  },
  "timings": {
    "queued_at": "2025-09-27T20:00:00.123Z",
    "started_at": "2025-09-27T20:00:00.456Z",
    "completed_at": "2025-09-27T20:01:30.789Z",
    "duration_ms": 90333,
    "queue_time_ms": 333,
    "deploy_time_ms": 45000,
    "healthcheck_time_ms": 45000
  },
  "state_transitions": [
    {"state": "QUEUED", "at": "2025-09-27T20:00:00.123Z"},
    {"state": "DEPLOYING", "at": "2025-09-27T20:00:00.456Z"},
    {"state": "HEALTHCHECKING", "at": "2025-09-27T20:00:45.456Z"},
    {"state": "SUCCEEDED", "at": "2025-09-27T20:01:30.789Z"}
  ],
  "commands": [
    {
      "phase": "deploy",
      "step": "pull_image",
      "status": "success",
      "exit_code": 0,
      "duration_ms": 15000,
      "output_preview": "Pulling registry.local:8443/web-frontend:sha-abc123..."
    }
  ],
  "logs_url": "/logs/deploy-2025-09-27-001",
  "metadata": {
    "git_ref": "refs/heads/main",
    "git_sha": "abc123def456"
  }
}
```

#### `GET /health`

Health check endpoint.

**Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "build": "2025-09-27T15:00:00Z",
  "uptime_seconds": 3600,
  "deployment_queue": {
    "pending": 0,
    "active": 1,
    "workers": 4
  },
  "database": {
    "connected": true,
    "size_bytes": 52428800,
    "tables": 5
  },
  "checks": {
    "database": "ok",
    "disk_space": "ok",
    "worker_pool": "ok"
  }
}
```

#### `GET /metrics`

Prometheus metrics endpoint.

```prometheus
# HELP deployment_total Total number of deployments
# TYPE deployment_total counter
deployment_total{service="web-frontend",status="success"} 142
deployment_total{service="web-frontend",status="failed"} 3
deployment_total{service="web-frontend",status="rolled_back"} 2

# HELP deployment_duration_seconds Time spent in deployment phases
# TYPE deployment_duration_seconds histogram
deployment_duration_seconds_bucket{service="web-frontend",phase="deploy",le="30"} 140
deployment_duration_seconds_bucket{service="web-frontend",phase="deploy",le="60"} 142
deployment_duration_seconds_bucket{service="web-frontend",phase="deploy",le="120"} 145

# HELP deployment_queue_size Current deployment queue depth
# TYPE deployment_queue_size gauge
deployment_queue_size 0

# HELP deployment_active Current active deployments
# TYPE deployment_active gauge
deployment_active{service="web-frontend"} 1

# HELP http_request_duration_seconds HTTP request latencies
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="POST",path="/deploy",le="0.005"} 450
http_request_duration_seconds_bucket{method="POST",path="/deploy",le="0.01"} 455
```

#### `GET /services`

Lists configured services and their current state.

**Response (200 OK)**:
```json
{
  "services": [
    {
      "name": "web-frontend",
      "enabled": true,
      "current_image": "registry.local:8443/web-frontend:sha-abc123",
      "last_deploy": {
        "deploy_id": "deploy-2025-09-27-001",
        "status": "SUCCEEDED",
        "completed_at": "2025-09-27T20:01:30Z"
      },
      "health": "healthy",
      "locked": false,
      "stats": {
        "total_deploys": 145,
        "success_rate": 0.979,
        "avg_duration_seconds": 87,
        "last_failure": "2025-09-25T14:30:00Z"
      }
    }
  ]
}
```

## Command Execution Engine

### Locking Strategy

Per-service deployment locks using filesystem-based advisory locks:

```rust
// Pseudo-code for lock acquisition
impl ServiceLock {
    async fn acquire(&self, timeout: Duration) -> Result<LockGuard> {
        let lock_path = format!("{}/locks/{}.lock", state_dir, service_name);
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)?;

        // Use flock with timeout
        tokio::time::timeout(timeout, async {
            file.lock_exclusive()?;
            Ok(LockGuard { file, path: lock_path })
        }).await?
    }
}
```

## Command Execution

## Semantics

- Argv-style execution: commands are run as arrays of argv values (no shell) unless allow_shell is explicitly enabled for a service. Example: ["/usr/bin/podman", "pull", "{{IMAGE}}"].
- Timeouts: each command has a command_timeout_seconds. On timeout: send SIGTERM, wait grace period, then SIGKILL.
- Retries & backoff: healthcheck commands can be retried with backoff; deploy commands default to single attempt (configurable).
- Failure semantics: any non-zero exit code from a deploy command aborts the deploy and triggers rollback (if configured). Any non-zero exit from a rollback command marks the overall deploy FAILED and requires manual intervention.
- Stdout / Stderr: stream both to a per-deploy log file AND to an in-memory buffer used for the immediate API response (trim large output).
- Exit codes: propagate the last non-zero exit in the API error response to aid debugging.

### Execution Engine

Commands are executed using `tokio::process` with comprehensive monitoring:

```rust
struct CommandExecutor {
    timeout: Duration,
    env: HashMap<String, String>,
    working_dir: PathBuf,
}

impl CommandExecutor {
    async fn execute(&self, command: &[String]) -> CommandResult {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..])
           .envs(&self.env)
           .current_dir(&self.working_dir)
           .stdout(Stdio::piped())
           .stderr(Stdio::piped());

        // Execute with timeout
        let output = timeout(self.timeout, cmd.output()).await??;

        CommandResult {
            command: command.to_vec(),
            exit_code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            duration: elapsed,
            timed_out: false,
        }
    }
}
```

### Retry Logic

```rust
pub async fn execute_with_retry(
    executor: &CommandExecutor,
    step: &DeployStep,
) -> Result<CommandResult> {
    let mut last_error = None;

    for attempt in 0..=step.retries {
        if attempt > 0 {
            info!("Retrying step {} (attempt {}/{})", step.name, attempt, step.retries);
            sleep(Duration::from_secs(step.retry_delay)).await;
        }

        match executor.execute_step(step, context).await {
            Ok(result) if result.exit_code == Some(0) => {
                return Ok(result);
            }
            Ok(result) => {
                last_error = Some(ExecutionError::NonZeroExit(result.clone()));
                if step.critical {
                    return Err(last_error.unwrap());
                }
            }
            Err(e) => {
                last_error = Some(e);
                if step.critical {
                    return Err(last_error.unwrap());
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| ExecutionError::Unknown))
}
```

## Security Implementation

### HMAC Authentication

```rust
use ring::hmac;
use constant_time_eq::constant_time_eq;

pub struct HmacValidator {
    key: hmac::Key,
}

impl HmacValidator {
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
        }
    }

    pub fn validate(&self, body: &[u8], signature: &str) -> bool {
        // Parse signature header
        let provided = match signature.strip_prefix("sha256=") {
            Some(hex) => hex,
            None => return false,
        };

        // Decode hex
        let provided_bytes = match hex::decode(provided) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // Compute expected signature
        let expected = hmac::sign(&self.key, body);

        // Constant-time comparison
        constant_time_eq(expected.as_ref(), &provided_bytes)
    }
}

// Axum middleware
pub async fn hmac_auth(
    State(validator): State<Arc<HmacValidator>>,
    headers: HeaderMap,
    body: Body,
) -> Result<Body, Response> {
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            Response::builder()
                .status(401)
                .body("Missing signature".into())
                .unwrap()
        })?;

    let bytes = hyper::body::to_bytes(body).await.map_err(|_| {
        Response::builder()
            .status(400)
            .body("Invalid body".into())
            .unwrap()
    })?;

    if !validator.validate(&bytes, signature) {
        return Err(Response::builder()
            .status(401)
            .body("Invalid signature".into())
            .unwrap());
    }

    Ok(Body::from(bytes))
}
```
### Template Engine

Safe template substitution using a whitelist approach:

```rust
fn expand_templates(input: &str, context: &TemplateContext) -> Result<String> {
    let mut result = input.to_string();

    for (key, value) in &context.variables {
        // Validate value against allowed pattern
        if !is_safe_template_value(value) {
            return Err(Error::UnsafeTemplateValue(key.clone()));
        }

        let placeholder = format!("{{{{{}}}}}", key);
        result = result.replace(&placeholder, value);
    }

    // Ensure no unexpanded templates remain
    if result.contains("{{") {
        return Err(Error::UnexpandedTemplate);
    }

    Ok(result)
}
```
## Observability

### Metrics

Key metrics exposed via Prometheus:

- `deploy_total{service,status}` - Counter of deployments
- `deploy_duration_seconds{service,phase}` - Histogram of phase durations
- `deploy_in_progress{service}` - Gauge of active deployments
- `rollback_total{service,reason}` - Counter of rollbacks
- `command_execution_duration_seconds{service,command}` - Command execution times
- `healthcheck_failures_total{service}` - Failed healthcheck counter
- `http_request_duration_seconds{method,endpoint,status}` - HTTP handler metrics

### Structured Logging

Using `tracing` for structured logs:

```rust
#[instrument(skip(body, secret))]
async fn handle_deploy(
    body: Bytes,
    signature: String,
    secret: &[u8],
) -> Result<Response> {
    let span = info_span!("deploy",
        deploy_id = field::Empty,
        service = field::Empty
    );

    // Parse and validate
    let request: DeployRequest = serde_json::from_slice(&body)?;
    span.record("deploy_id", &request.deploy_id);
    span.record("service", &request.service);

    info!("Processing deploy request");
    // ...
}
```



## Operational Procedures

### Systemd Service

```ini
# /etc/systemd/system/deploy-receiver.service
[Unit]
Description=Deploy Webhook Receiver
Documentation=https://github.com/org/deploy-receiver
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=deploy-receiver
Group=deploy-receiver
WorkingDirectory=/var/lib/deploy-receiver

ExecStart=/usr/local/bin/deploy-receiver --config /etc/deploy-receiver/config.toml
ExecReload=/bin/kill -USR1 $MAINPID

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/deploy-receiver /var/log/deploy-receiver /run/deploy-receiver
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Resource limits
LimitNOFILE=65536
LimitNPROC=256
MemoryLimit=512M
CPUQuota=200%

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Health monitoring
WatchdogSec=30
TimeoutStartSec=10
TimeoutStopSec=300  # Wait for active deploys

[Install]
WantedBy=multi-user.target
```

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_expansion() {
        let context = ExecutionContext {
            templates: hashmap! {
                "IMAGE".to_string() => "registry:app:v1".to_string(),
                "SERVICE".to_string() => "web".to_string(),
            },
            ..Default::default()
        };

        let command = vec!["docker".to_string(), "pull".to_string(), "{{IMAGE}}".to_string()];
        let expanded = expand_templates(&command, &context).unwrap();

        assert_eq!(expanded, vec!["docker", "pull", "registry:app:v1"]);
    }

    #[tokio::test]
    async fn test_hmac_validation() {
        let validator = HmacValidator::new(b"test-secret");
        let body = b"test body";
        let signature = "sha256=f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

        assert!(validator.validate(body, signature));
        assert!(!validator.validate(body, "sha256=invalid"));
    }
}
```


## Rust implementation notes (crates, patterns, static binary)

### Build target & static linking

- **Target** : x86_64-unknown-linux-musl — produces a single statically linked ELF binary.

- Use musl toolchain and ensure crates used are compatible with musl (avoid crates that pull in system glibc-only dependencies).

## Dependencies

```toml
# Cargo.toml
[dependencies]
# Web framework
axum = "0.7"
hyper = { version = "1.0", features = ["full"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["trace", "compression"] }

# Async runtime
tokio = { version = "1.35", features = ["full"] }

# Database
redb = "2.0"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"

# Security
ring = "0.17"
constant_time_eq = "0.3"
hex = "0.4"

# Logging & Monitoring
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
prometheus = "0.13"

# Utilities
anyhow = "1.0"
thiserror = "1.0"
chrono = "0.4"
regex = "1.10"  # Image pattern validation
uuid = { version = "1.5", features = ["v7", "serde"] }
handlebars = "4.3" # for templating
clap = { version = "4.1", features = ["derive"] } # For CLI parsing
```

## Questions for Clarification

### Target Users & Use Cases

Q1: Who is the primary target user for this deployment receiver?

Small to medium engineering teams (5-50 developers) running self-hosted infrastructure who need a lightweight alternative to complex orchestration platforms like Kubernetes or enterprise CI/CD solutions.

Q2: What are the most common deployment scenarios we should optimize for in the MVP?

Single-host deployments of containerized web services (APIs, frontends) using systemd + Podman/Docker, triggered by GitHub Actions or GitLab CI. Focus on the 80% use case of "pull new container, restart service, verify health."

Q3: What size/complexity of infrastructure should the MVP target?

1-10 services per host, with deployments happening several times per week but not requiring sub-second response times. Prioritize reliability over high throughput.

Integration & Ecosystem

Q4: Which CI/CD systems should we prioritize for integration examples and documentation?

GitHub Actions (primary), GitLab CI (secondary). Provide clear webhook setup examples and HMAC secret configuration for these platforms.

Q5: Which container runtimes and service managers should be supported in MVP documentation?

Podman + systemd (primary target for security-conscious teams), Docker. Include example service configurations for both.

Q6: Should the MVP include any authentication beyond HMAC signatures?

No. HMAC + IP allowlisting + TLS is sufficient for MVP.

User Experience & Onboarding

Q7: How should users initially configure and test their first service deployment?

Users should be able to create a config based on the examples in the repo, run `deploy-receiver validate` to check syntax, then start the service and trigger a test deployment via curl or a simple GitHub Actions workflow. Provide clear error messages and logs to guide troubleshooting.

Q8: What should happen when a deployment fails and requires manual intervention?

Clear error messages in API response + detailed logs with actionable troubleshooting steps.

Q9: How should users monitor and troubleshoot ongoing deployments?

Structured JSON logs with correlation IDs, /health and /metrics endpoints for monitoring integration. For MVP, logs are sufficient - no web UI needed or planeed.

Business Requirements

Q10: What security compliance requirements must the MVP meet?

Basic security hardening (principle of least privilege, no arbitrary command execution, secure defaults).

Q11: What level of support/documentation is expected for MVP launch?

Self-service documentation with examples, troubleshooting guide. No formal SLA or enterprise support for MVP as this is an internal tool.

Scope & Feature Prioritization

Q12: Which features from the specification are must-have vs nice-to-have for MVP?

Must-have: Core deployment flow, HMAC auth, basic health checks, rollback on failure, structured logging, systemd integration
Nice-to-have: Metrics endpoint, notification webhooks, advanced templating.

Q14: Should the MVP support rollbacks to arbitrary previous versions, or only immediate rollback?

Only immediate rollback to the last known good image for MVP. This covers 90% of use cases and keeps the state model simple. Defer "rollback to any previous version" to post-MVP.

Q15: How should the MVP handle configuration changes and service updates?

Require restart for configuration changes in MVP (simple and reliable).


## Feature Scope
Features out of mvp:
- backup/restore
- notification webhooks
- perf targets
- templating engine with whitelist

