# Quick Start Guide

This guide will walk you through setting up Hookshot and deploying your first service in under 15 minutes.

## Prerequisites

- Linux system (x86_64)
- Rust 1.75+ (for building from source) or download pre-built binary
- Podman or Docker (for container deployments)
- systemd (optional, for service management)

## Step 1: Install Hookshot

### Option A: Build from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/hookshot
cd hookshot

# Build optimized release binary
make release

# Install to /usr/local/bin
sudo cp target/x86_64-unknown-linux-musl/release/hookshot /usr/local/bin/
sudo chmod +x /usr/local/bin/hookshot

# Verify installation
hookshot version
```

### Option B: Download Pre-built Binary

```bash
# Download latest release
wget https://github.com/yourusername/hookshot/releases/latest/download/hookshot
chmod +x hookshot
sudo mv hookshot /usr/local/bin/

# Verify installation
hookshot version
```

## Step 2: Create Configuration Directories

```bash
# Create configuration directory
sudo mkdir -p /etc/hookshot

# Create data directory
sudo mkdir -p /var/lib/hookshot

# Create log directory
sudo mkdir -p /var/log/hookshot

# Set permissions (replace 'youruser' with your username)
sudo chown -R youruser:youruser /etc/hookshot
sudo chown -R youruser:youruser /var/lib/hookshot
sudo chown -R youruser:youruser /var/log/hookshot
```

## Step 3: Create System Configuration

Create `/etc/hookshot/config.toml`:

```toml
[server]
listen = "127.0.0.1:8080"
worker_threads = 4
max_request_size = "1MB"
request_timeout = 30
shutdown_timeout = 300

[security]
# Leave empty for testing, add your CI server IPs for production
allowed_ips = []
rate_limit = 100

[storage]
data_dir = "/var/lib/hookshot"

[storage.retention]
successful_deploys = 100
failed_deploys = 50

[secrets]
source = "file"
secrets_file = "/etc/hookshot/secrets"
required_secrets = ["hmac_key"]

[logging]
level = "info"
format = "pretty"  # Use "json" in production
directory = "/var/log/hookshot"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"
status_cache_seconds = 10

[limits]
max_concurrent_total = 10
max_concurrent_per_service = 1
deployment_timeout = 1800
command_timeout = 300
lock_timeout = 60

[notifications]
enabled = false
```

## Step 4: Generate HMAC Secret

```bash
# Generate a secure random HMAC key
HMAC_KEY=$(openssl rand -hex 32)

# Create secrets file
echo "hmac_key=$HMAC_KEY" | sudo tee /etc/hookshot/secrets
sudo chmod 600 /etc/hookshot/secrets

# Save the HMAC key for later use in CI
echo "Save this HMAC key for your CI system: $HMAC_KEY"
```

## Step 5: Create Services Configuration

Create `/etc/hookshot/services.toml`:

```toml
# Global defaults for all services
[defaults]
working_dir = "/tmp"
command_timeout = 120
healthcheck_timeout = 60
rollback_enabled = true

# Example service configuration
[[service]]
name = "hello-world"
description = "Simple test service"
enabled = true
working_dir = "/tmp"

[service.env]
SERVICE_NAME = "hello-world"

[service.security]
# Allow any image for testing (be more restrictive in production)
allowed_image_pattern = '.*'
allowed_env_overrides = ["DEBUG", "LOG_LEVEL"]

[service.deploy]
commands = [
    ["echo", "Deploying {{IMAGE}} for service {{SERVICE}}"],
    ["echo", "Deploy ID: {{DEPLOY_ID}}"],
    ["sleep", "2"]  # Simulate deployment work
]

[service.healthcheck]
initial_delay = 1
interval = 2
max_attempts = 3
success_threshold = 1
commands = [
    ["echo", "Health check passed for {{SERVICE}}"]
]

[service.rollback]
enabled = true
max_attempts = 1
commands = [
    ["echo", "Rolling back to {{PREVIOUS_IMAGE}}"],
    ["sleep", "1"]
]

[service.hooks]
pre_deploy = [
    ["echo", "Pre-deploy: Starting deployment for {{SERVICE}}"]
]
post_deploy = [
    ["echo", "Post-deploy: Deployment completed successfully"]
]
on_failure = [
    ["echo", "On-failure: Deployment failed for {{SERVICE}}"]
]
```

## Step 6: Validate Configuration

```bash
hookshot validate

# You should see:
# INFO Validating configuration files...
# INFO System configuration is valid
# INFO Services configuration is valid
# INFO All configuration files are valid
```

## Step 7: Start Hookshot

### Option A: Run Directly (for testing)

```bash
hookshot run

# You should see:
# INFO Starting server listen=127.0.0.1:8080 services_count=1
```

### Option B: Run as systemd Service

Create `/etc/systemd/system/hookshot.service`:

```ini
[Unit]
Description=Hookshot Deployment Webhook Receiver
Documentation=https://github.com/yourusername/hookshot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=youruser
Group=yourgroup
WorkingDirectory=/var/lib/hookshot
ExecStart=/usr/local/bin/hookshot run
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hookshot /var/log/hookshot
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable hookshot
sudo systemctl start hookshot

# Check status
sudo systemctl status hookshot
```

## Step 8: Test Health Check

```bash
curl http://127.0.0.1:8080/health | jq

# Expected output:
# {
#   "status": "healthy",
#   "version": "0.0.1",
#   "uptime_seconds": 5,
#   "deployment_queue": {
#     "pending": 0,
#     "active": 0,
#     "workers": 4
#   },
#   "database": {
#     "connected": true,
#     "size_bytes": 8192
#   },
#   "checks": {
#     "database": "ok",
#     "disk_space": "ok",
#     "worker_pool": "ok"
#   }
# }
```

## Step 9: Trigger Your First Deployment

```bash
# Read the HMAC key we generated earlier
HMAC_KEY=$(grep hmac_key /etc/hookshot/secrets | cut -d'=' -f2)

# Create deployment payload
PAYLOAD='{
  "service": "hello-world",
  "image": "test-image:v1.0.0",
  "metadata": {
    "triggered_by": "manual",
    "environment": "test"
  }
}'

# Generate HMAC signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')

# Send deployment request
curl -X POST http://127.0.0.1:8080/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD" | jq

# Expected output:
# {
#   "deploy_id": "deploy-20250130-...",
#   "service": "hello-world",
#   "status": "Succeeded",
#   "image": "test-image:v1.0.0",
#   "started_at": "2025-01-30T...",
#   "completed_at": "2025-01-30T...",
#   "duration_seconds": 3,
#   "status_url": "/status/deploy-20250130-...",
#   "log_url": "/logs/deploy-20250130-..."
# }
```

## Step 10: View Service Status

```bash
# List all services
curl http://127.0.0.1:8080/services | jq

# Expected output:
# {
#   "services": [
#     {
#       "name": "hello-world",
#       "enabled": true,
#       "current_image": "test-image:v1.0.0",
#       "last_deploy": {
#         "deploy_id": "deploy-20250130-...",
#         "status": "Succeeded",
#         "completed_at": "2025-01-30T..."
#       },
#       "health": "Healthy",
#       "locked": false,
#       "stats": {
#         "total_deploys": 1,
#         "success_rate": 1.0,
#         "avg_duration_seconds": 3,
#         "last_failure": null
#       }
#     }
#   ]
# }
```

## Step 11: Create Your First Backup

Before making any further changes, create a backup of your configuration and state:

```bash
# Create a backup
hookshot export /var/backups/hookshot-initial.tar.gz

# Verify backup was created
ls -lh /var/backups/hookshot-initial.tar.gz

# Test restore preview (dry-run)
hookshot import /var/backups/hookshot-initial.tar.gz --dry-run
```

The backup includes:
- Complete deployment history
- System configuration (`config.toml`)
- Services configuration (`services.toml`)
- Secrets file (if accessible)

**💡 Tip**: Always create a backup before:
- Upgrading Hookshot
- Changing service configurations
- Modifying system settings
- Major deployment operations

For automated backups, see the [Backup & Restore Guide](BACKUP_RESTORE.md).

## Next Steps

### Configure a Real Service

Now that you have a working setup, configure a real service. Here's an example for a containerized web application:

Create a new service in `/etc/hookshot/services.toml`:

```toml
[[service]]
name = "my-web-app"
description = "Production web application"
enabled = true
working_dir = "/srv/my-web-app"

[service.env]
NODE_ENV = "production"
PORT = "3000"

[service.security]
# Only allow images from your registry with semantic versioning
allowed_image_pattern = '^registry\.example\.com/my-web-app:v\d+\.\d+\.\d+$'
allowed_env_overrides = ["LOG_LEVEL", "DEBUG"]

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "inspect", "{{IMAGE}}"],  # Verify image exists
    ["systemctl", "--user", "restart", "my-web-app.service"]
]

[service.healthcheck]
initial_delay = 10
interval = 5
max_attempts = 12
success_threshold = 2
commands = [
    ["curl", "-fsS", "--max-time", "10", "http://127.0.0.1:3000/health"]
]

[service.rollback]
enabled = true
max_attempts = 2
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "my-web-app.service"]
]
```

### Integrate with CI/CD

See the [examples/github-actions](../examples/github-actions/) directory for complete CI/CD integration examples.

### Set Up Monitoring

Add Prometheus scraping for metrics:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'hookshot'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

### Enable Security Features

Update `/etc/hookshot/config.toml` for production:

```toml
[security]
# Restrict to your CI server IPs
allowed_ips = [
    "192.168.1.0/24",      # Internal network
    "203.0.113.50/32"      # CI server
]
rate_limit = 100

[logging]
format = "json"  # Structured logging for production
level = "info"
```

## Common Issues

### Port Already in Use

```bash
# Check what's using port 8080
sudo lsof -i :8080

# Change the port in config.toml
[server]
listen = "127.0.0.1:9090"
```

### Permission Denied on Data Directory

```bash
# Fix permissions
sudo chown -R youruser:youruser /var/lib/hookshot
sudo chmod 755 /var/lib/hookshot
```

### HMAC Signature Mismatch

- Ensure there are no extra spaces or newlines in your payload
- Verify you're using the same HMAC key
- Check that the payload is exactly what's being signed

```bash
# Debug HMAC calculation
echo -n "$PAYLOAD" | xxd  # View exact bytes
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY"
```

### Service Not Found

- Verify service name matches exactly (case-sensitive)
- Check that `enabled = true` in services.toml
- Run `hookshot validate` to check configuration

## Helper Script

Create a deployment helper script `deploy.sh`:

```bash
#!/bin/bash
set -euo pipefail

# Configuration
HOOKSHOT_URL="http://127.0.0.1:8080"
HMAC_KEY=$(grep hmac_key /etc/hookshot/secrets | cut -d'=' -f2)

# Parse arguments
SERVICE="${1:?Usage: $0 <service> <image> [previous_image]}"
IMAGE="${2:?Usage: $0 <service> <image> [previous_image]}"
PREVIOUS_IMAGE="${3:-}"

# Build payload
if [ -n "$PREVIOUS_IMAGE" ]; then
  PAYLOAD=$(jq -nc \
    --arg service "$SERVICE" \
    --arg image "$IMAGE" \
    --arg previous "$PREVIOUS_IMAGE" \
    '{service: $service, image: $image, previous_image: $previous}')
else
  PAYLOAD=$(jq -nc \
    --arg service "$SERVICE" \
    --arg image "$IMAGE" \
    '{service: $service, image: $image}')
fi

# Calculate signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY" | awk '{print $2}')

# Deploy
echo "Deploying $SERVICE with image $IMAGE..."
curl -X POST "$HOOKSHOT_URL/deploy" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD" | jq

echo "Deployment request sent successfully!"
```

Usage:

```bash
chmod +x deploy.sh
./deploy.sh hello-world test-image:v2.0.0 test-image:v1.0.0
```

## What's Next?

- Read the [Configuration Reference](CONFIGURATION.md) for all configuration options
- Check out [API Documentation](API.md) for complete API details
- Review [Deployment Guide](DEPLOYMENT.md) for production best practices
- See [Troubleshooting](TROUBLESHOOTING.md) for common issues and solutions
- Explore [examples/](../examples/) for real-world configurations

## Getting Help

- Check the [Troubleshooting Guide](TROUBLESHOOTING.md)
- Review logs in `/var/log/hookshot/`
- Enable debug logging: `log_level = "debug"` in config.toml
- Open an issue on GitHub