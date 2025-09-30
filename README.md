# Hookshot

A lightweight, single-binary HTTP service written in Rust that accepts authenticated deployment requests from CI systems and executes locally-configured OS command sequences for deploy, healthcheck, and rollback operations.

[![License: MPL-2.0](https://img.shields.io/badge/License-MPL--2.0-blue.svg)](https://opensource.org/licenses/MPL-2.0)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

## Features

- **Single Static Binary**: Zero runtime dependencies, ~10MB binary with embedded database
- **Secure by Default**: HMAC-SHA256 authentication, IP allowlisting, no arbitrary command execution
- **Automatic Rollback**: Rolls back to previous version on deployment or healthcheck failure
- **Backup and Restore**: Complete state export/import for disaster recovery
- **Flexible Configuration**: TOML-based configuration with template expansion support
- **Observability**: Structured JSON logging, Prometheus metrics, comprehensive health checks
- **Concurrent Deployment Control**: Per-service and global concurrency limits
- **State Management**: Crash-safe embedded database with deployment history
- **Generic Design**: Works with any deployment technology (containers, binaries, scripts)

## Quick Start

### Installation

#### From Source
```bash
git clone https://github.com/midoBB/hookshoter
cd hookshot
make release
sudo cp target/x86_64-unknown-linux-musl/release/hookshot /usr/local/bin/
```

#### Binary Download
```bash
# Download the latest release
wget https://github.com/midoBB/hookshoter/releases/latest/download/hookshot
chmod +x hookshot
sudo mv hookshot /usr/local/bin/
```

### Basic Configuration

Create system configuration at `/etc/hookshot/config.toml`:

```toml
[server]
listen = "127.0.0.1:8080"
worker_threads = 4

[security]
allowed_ips = []  # Empty = allow all (use with caution)
rate_limit = 100

[storage]
data_dir = "/var/lib/hookshot"

[secrets]
source = "file"
secrets_file = "/etc/hookshot/secrets"
required_secrets = ["hmac_key"]

[logging]
level = "info"
format = "json"

[limits]
max_concurrent_total = 10
max_concurrent_per_service = 1
```

Create secrets file at `/etc/hookshot/secrets`:

```bash
# Generate a secure HMAC key
HMAC_KEY=$(openssl rand -hex 32)
echo "hmac_key=$HMAC_KEY" | sudo tee /etc/hookshot/secrets
sudo chmod 600 /etc/hookshot/secrets
```

Create services configuration at `/etc/hookshot/services.toml`:

```toml
[[service]]
name = "my-app"
description = "My application service"
enabled = true

[service.security]
allowed_image_pattern = '^registry\.example\.com/my-app:.*$'

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app.service"]
]

[service.healthcheck]
initial_delay = 5
interval = 3
max_attempts = 10
success_threshold = 2
commands = [
    ["curl", "-fsS", "http://127.0.0.1:8080/health"]
]

[service.rollback]
enabled = true
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app.service"]
]
```

### Validate Configuration

```bash
hookshot validate
```

### Create Initial Backup

```bash
# Create a backup before starting
hookshot export /var/backups/hookshot-initial.tar.gz

# Test restore preview
hookshot import /var/backups/hookshot-initial.tar.gz --dry-run
```

### Start the Server

```bash
hookshot run
```

Or as a systemd service:

```bash
sudo systemctl enable --now hookshot
```

### Trigger a Deployment

```bash
# Calculate HMAC signature
PAYLOAD='{"service":"my-app","image":"registry.example.com/my-app:v1.0.0"}'
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')

# Send deployment request
curl -X POST http://127.0.0.1:8080/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

## Documentation

- **[Quick Start Guide](docs/QUICKSTART.md)** - Step-by-step setup and first deployment
- **[Configuration Reference](docs/CONFIGURATION.md)** - Complete configuration guide
- **[API Documentation](docs/API.md)** - HTTP API reference and webhook format
- **[Deployment Guide](docs/DEPLOYMENT.md)** - Production deployment instructions
- **[Backup & Restore Guide](docs/BACKUP_RESTORE.md)** - Disaster recovery and state management
- **[Troubleshooting](docs/TROUBLESHOOTING.md)** - Common issues and solutions

## Usage Examples

### Deploy from GitHub Actions

```yaml
name: Deploy
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to production
        env:
          DEPLOY_URL: ${{ secrets.DEPLOY_URL }}
          HMAC_SECRET: ${{ secrets.HMAC_SECRET }}
        run: |
          PAYLOAD=$(jq -nc \
            --arg service "my-app" \
            --arg image "registry.example.com/my-app:${{ github.sha }}" \
            --arg git_ref "${{ github.ref }}" \
            --arg git_sha "${{ github.sha }}" \
            '{service: $service, image: $image, metadata: {git_ref: $git_ref, git_sha: $git_sha}}')

          SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

          curl -X POST "$DEPLOY_URL/deploy" \
            -H "Content-Type: application/json" \
            -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
            -d "$PAYLOAD"
```

### Check Service Status

```bash
# Get deployment status
curl http://127.0.0.1:8080/status/deploy-20250130-001

# List all services
curl http://127.0.0.1:8080/services

# Health check
curl http://127.0.0.1:8080/health

# Prometheus metrics
curl http://127.0.0.1:8080/metrics
```

## Architecture

```
┌─────────────┐     HTTPS/HMAC      ┌──────────────────┐
│   CI/CD     │────────────────────>│  HTTP Handler    │
│  (GitHub    │                     │   (Axum/Tokio)   │
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
          │   (TOML)         │    │      (redb)      │    │  (tokio::process)│
          └──────────────────┘    └──────────────────┘    └──────────────────┘
```

### Key Components

- **HTTP API**: Axum-based async web framework handling all endpoints
- **State Manager**: Embedded redb database with per-service locking
- **Command Executor**: Safe command execution with timeout handling
- **Secret Manager**: Multi-source secret loading (env, file, systemd)
- **Metrics Collector**: Prometheus metrics for monitoring
- **Notification System**: Webhook notifications for deployment events

## Development

### Prerequisites

- Rust 1.75 or later
- musl toolchain for static builds: `rustup target add x86_64-unknown-linux-musl`
- cargo-nextest for testing: `cargo install cargo-nextest`

### Build Commands

```bash
make build          # Debug build
make release        # Optimized release build with musl
make test           # Run tests
make lint           # Run clippy
make fmt            # Format code
make dev            # Build + test + lint
```

### Running Tests

```bash
make test           # Run all tests with nextest
cargo nextest run   # Direct nextest invocation
```

### Project Structure

```
hookshot/
.
├── src
│   ├── backup/
│   ├── config/
│   ├── deployment/
│   ├── execution/
│   ├── http/
│   ├── notifications/
│   ├── secrets/
│   ├── state/
│   ├── tasks/
│   ├── cli.rs
│   ├── error.rs
│   ├── logging.rs
│   ├── main.rs
│   ├── metrics.rs
│   └── types.rs
├── build.rs
├── Cargo.lock
├── Cargo.toml
├── Makefile
└── README.md

```

## Security

### Security Model

- **HMAC Authentication**: All deployment requests require HMAC-SHA256 signatures
- **No Arbitrary Execution**: All commands are pre-configured locally, no CI-provided commands
- **Image Validation**: Regex-based allowlists for container images
- **IP Allowlisting**: Optional IP-based access control
- **Rate Limiting**: Per-IP rate limiting to prevent abuse
- **Secure Secrets**: Memory-protected secret storage with encryption at rest

### Security Best Practices

1. Use strong, randomly generated HMAC keys (32+ bytes)
2. Enable IP allowlisting to restrict access to known CI systems
3. Use restrictive image patterns (e.g., specific registries and tag formats)
4. Run with minimal privileges using systemd hardening
5. Keep secrets in secure storage (systemd credentials, encrypted files)
6. Regularly rotate HMAC keys
7. Monitor metrics for unusual activity

## Monitoring

### Prometheus Metrics

Hookshot exposes metrics at `/metrics`:

- `deployment_total` - Total deployments by service and status
- `deployment_duration_seconds` - Deployment phase durations
- `deployment_active` - Currently active deployments
- `rollback_total` - Total rollbacks by service and reason
- `command_execution_duration_seconds` - Command execution times
- `http_requests_total` - HTTP request counters

### Example Prometheus Configuration

```yaml
scrape_configs:
  - job_name: 'hookshot'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

## Development Workflow

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make changes and add tests
3. Run formatters and linters: `make fmt && make lint`
4. Run tests: `make test`
5. Commit with clear messages
6. Push and create a pull request

## License

This project is licensed under the Mozilla Public License 2.0 - see the LICENSE file for details.

## Support

- **Documentation**: See the [docs/](docs/) directory for detailed guides
- **Examples**: Check [examples/](examples/) for configuration templates

## Roadmap

- [x] Built-in backup/restore functionality
- [ ] Advanced templating with custom functions
- [ ] GitLab CI native integration
