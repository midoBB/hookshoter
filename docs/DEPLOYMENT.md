# Production Deployment Guide

This guide covers deploying Hookshot in a production environment with security hardening, monitoring, and operational best practices.

## Prerequisites

- Linux server (Ubuntu 22.04 LTS, Debian 12, or similar)
- Root or sudo access
- Dedicated user account for Hookshot
- systemd for process management
- Reverse proxy (nginx or Caddy recommended)
- TLS certificate (Let's Encrypt)

## Production Architecture

```
┌─────────────────┐
│   Internet      │
└────────┬────────┘
         │ HTTPS (443)
         ▼
┌─────────────────────┐
│  Reverse Proxy      │  ← Nginx/Caddy with TLS
│  (nginx/Caddy)      │
└────────┬────────────┘
         │ HTTP (127.0.0.1:8080)
         ▼
┌─────────────────────┐
│  Hookshot           │  ← Systemd service, restricted user
│  (127.0.0.1:8080)   │
└────────┬────────────┘
         │
         ├──► redb (embedded database)
         ├──► Deployment commands (podman, systemctl)
         └──► Prometheus metrics
```

## Step 1: Server Preparation

### Create Dedicated User

```bash
# Create hookshot user (no login shell for security)
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hookshot

# Create directory structure
sudo mkdir -p /opt/hookshot
sudo mkdir -p /etc/hookshot
sudo mkdir -p /var/lib/hookshot
sudo mkdir -p /var/log/hookshot

# Set ownership
sudo chown hookshot:hookshot /opt/hookshot
sudo chown hookshot:hookshot /etc/hookshot
sudo chown hookshot:hookshot /var/lib/hookshot
sudo chown hookshot:hookshot /var/log/hookshot

# Set permissions
sudo chmod 755 /opt/hookshot
sudo chmod 750 /etc/hookshot
sudo chmod 750 /var/lib/hookshot
sudo chmod 750 /var/log/hookshot
```

### Install Binary

```bash
# Download latest release
wget https://github.com/yourusername/hookshot/releases/latest/download/hookshot -O /tmp/hookshot

# Verify checksum (recommended)
wget https://github.com/yourusername/hookshot/releases/latest/download/hookshot.sha256
sha256sum -c hookshot.sha256

# Install binary
sudo mv /tmp/hookshot /opt/hookshot/hookshot
sudo chown hookshot:hookshot /opt/hookshot/hookshot
sudo chmod 755 /opt/hookshot/hookshot

# Create symlink for convenience
sudo ln -s /opt/hookshot/hookshot /usr/local/bin/hookshot
```

## Step 2: Configuration

### System Configuration

Create `/etc/hookshot/config.toml`:

```toml
[server]
listen = "127.0.0.1:8080"  # Only listen on localhost
worker_threads = 8  # Adjust based on server specs
max_request_size = "1MB"
request_timeout = 60
shutdown_timeout = 300

[security]
# Restrict to your CI/CD server IPs
allowed_ips = [
    "203.0.113.50/32",   # GitHub Actions runner
    "198.51.100.0/24",   # Internal CI network
]
rate_limit = 200

[storage]
data_dir = "/var/lib/hookshot"

[storage.retention]
successful_deploys = 200
failed_deploys = 100

[secrets]
source = "file"
secrets_file = "/etc/hookshot/secrets"
required_secrets = ["hmac_key"]
reload_interval = 300

[logging]
level = "info"  # Use "warn" for less verbose logging
format = "json"  # Structured logging for log aggregation
directory = "/var/log/hookshot"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"
status_cache_seconds = 30

[limits]
max_concurrent_total = 12
max_concurrent_per_service = 1
deployment_timeout = 2400  # 40 minutes
command_timeout = 600      # 10 minutes
lock_timeout = 120

[notifications]
enabled = true

[notifications.webhook]
use_secrets = false
on_failure = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
on_rollback = "https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
timeout = 10
```

### Secrets Management

**Option 1: File-based (Simple)**

```bash
# Generate HMAC key
HMAC_KEY=$(openssl rand -hex 32)

# Create secrets file
sudo tee /etc/hookshot/secrets > /dev/null <<EOF
# HMAC key for webhook authentication
hmac_key=$HMAC_KEY
EOF

# Secure the file
sudo chown hookshot:hookshot /etc/hookshot/secrets
sudo chmod 400 /etc/hookshot/secrets
```

**Option 2: systemd Credentials (Recommended)**

```bash
# Store secret with systemd-creds (systemd 250+)
echo -n "$HMAC_KEY" | sudo systemd-creds encrypt --name=hmac_key - /etc/credstore/hookshot.hmac_key

# Update config.toml
[secrets]
source = "systemd"
required_secrets = ["hmac_key"]
```

### Services Configuration

Create `/etc/hookshot/services.toml` with your production services:

```toml
[defaults]
working_dir = "/srv"
command_timeout = 300
healthcheck_timeout = 120
rollback_enabled = true

[[service]]
name = "web-frontend"
description = "Production web frontend"
enabled = true
working_dir = "/srv/web-frontend"

[service.env]
NODE_ENV = "production"
PORT = "3000"

[service.security]
allowed_image_pattern = '^registry\.example\.com/web-frontend:(v\d+\.\d+\.\d+)$'
allowed_env_overrides = ["LOG_LEVEL"]

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "inspect", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "web-frontend.service"]
]

[service.healthcheck]
initial_delay = 15
interval = 5
max_attempts = 24
success_threshold = 3
commands = [
    ["curl", "-fsS", "--max-time", "10", "http://127.0.0.1:3000/health"]
]

[service.rollback]
enabled = true
max_attempts = 3
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "web-frontend.service"]
]

[service.hooks]
pre_deploy = [
    ["echo", "Starting deployment of {{SERVICE}} at {{DATETIME}}"]
]
post_deploy = [
    ["echo", "Successfully deployed {{SERVICE}} version {{IMAGE}}"]
]
```

### Validate Configuration

```bash
sudo -u hookshot hookshot --config /etc/hookshot/config.toml \
                          --services /etc/hookshot/services.toml \
                          validate
```

## Step 3: systemd Service

Create `/etc/systemd/system/hookshot.service`:

```ini
[Unit]
Description=Hookshot Deployment Webhook Receiver
Documentation=https://github.com/yourusername/hookshot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=hookshot
Group=hookshot
WorkingDirectory=/var/lib/hookshot

ExecStart=/opt/hookshot/hookshot run
ExecReload=/bin/kill -USR1 $MAINPID

# Restart policy
Restart=always
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=3

# Resource limits
LimitNOFILE=65536
LimitNPROC=512
MemoryLimit=1G
CPUQuota=200%

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/hookshot /var/log/hookshot /run/hookshot
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hookshot

# Health monitoring
WatchdogSec=30
TimeoutStartSec=30
TimeoutStopSec=300  # Wait for active deploys to complete

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable on boot
sudo systemctl enable hookshot

# Start service
sudo systemctl start hookshot

# Check status
sudo systemctl status hookshot

# View logs
sudo journalctl -u hookshot -f
```

## Step 4: Reverse Proxy Setup

### Option A: Nginx

Create `/etc/nginx/sites-available/hookshot`:

```nginx
# Upstream hookshot backend
upstream hookshot {
    server 127.0.0.1:8080 fail_timeout=0;
    keepalive 32;
}

# Rate limiting
limit_req_zone $binary_remote_addr zone=hookshot_ratelimit:10m rate=10r/s;

# Redirect HTTP to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name deploy.example.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name deploy.example.com;

    # TLS configuration
    ssl_certificate /etc/letsencrypt/live/deploy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/deploy.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Logging
    access_log /var/log/nginx/hookshot-access.log;
    error_log /var/log/nginx/hookshot-error.log;

    # Client limits
    client_max_body_size 1M;
    client_body_timeout 60s;

    # Apply rate limiting
    limit_req zone=hookshot_ratelimit burst=20 nodelay;

    # Proxy to hookshot
    location / {
        proxy_pass http://hookshot;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";

        # Timeouts for long-running deployments
        proxy_connect_timeout 60s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # Health check (no rate limit)
    location /health {
        proxy_pass http://hookshot;
        limit_req off;
    }

    # Metrics (restrict access)
    location /metrics {
        # Only allow from monitoring server
        allow 192.168.1.0/24;
        deny all;

        proxy_pass http://hookshot;
        limit_req off;
    }
}
```

Enable the site:

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/hookshot /etc/nginx/sites-enabled/

# Test configuration
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

### Option B: Caddy

Create `/etc/caddy/Caddyfile`:

```caddy
deploy.example.com {
    # Automatic HTTPS via Let's Encrypt

    # Rate limiting
    rate_limit {
        zone dynamic {
            key {remote_host}
            events 100
            window 1m
        }
    }

    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        X-XSS-Protection "1; mode=block"
    }

    # Logging
    log {
        output file /var/log/caddy/hookshot-access.log
    }

    # Proxy to hookshot
    reverse_proxy 127.0.0.1:8080 {
        header_up X-Real-IP {remote_host}
        header_up X-Forwarded-For {remote_host}
    }

    # Restrict metrics endpoint
    @metrics path /metrics
    handle @metrics {
        @internal_only {
            remote_ip 192.168.1.0/24
        }
        handle @internal_only {
            reverse_proxy 127.0.0.1:8080
        }
        respond 403
    }
}
```

Reload Caddy:

```bash
sudo systemctl reload caddy
```

## Step 5: Monitoring Setup

### Prometheus Configuration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'hookshot'
    static_configs:
      - targets: ['deploy.example.com:443']
    metrics_path: '/metrics'
    scheme: https
    scrape_interval: 30s
    scrape_timeout: 10s
```

### Grafana Dashboard

Import or create a dashboard with key metrics:

- Deployment success rate
- Deployment duration (p50, p95, p99)
- Active deployments
- Rollback frequency
- HTTP request rates and latencies

Sample PromQL queries:

```promql
# Deployment success rate (last 24h)
rate(deployment_total{status="success"}[24h]) / rate(deployment_total[24h])

# Average deployment duration
rate(deployment_duration_seconds_sum[5m]) / rate(deployment_duration_seconds_count[5m])

# Active deployments
sum(deployment_active)

# Rollback rate
rate(rollback_total[1h])
```

### Alerting Rules

Create `hookshot-alerts.yml`:

```yaml
groups:
  - name: hookshot
    interval: 60s
    rules:
      - alert: HookshotDown
        expr: up{job="hookshot"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Hookshot is down"
          description: "Hookshot has been down for more than 5 minutes"

      - alert: HighDeploymentFailureRate
        expr: |
          rate(deployment_total{status=~"failed|rollback_failed"}[1h]) /
          rate(deployment_total[1h]) > 0.1
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "High deployment failure rate"
          description: "More than 10% of deployments are failing"

      - alert: DeploymentStuck
        expr: deployment_active > 0
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Deployment appears stuck"
          description: "A deployment has been running for over 1 hour"

      - alert: RollbackFailed
        expr: increase(rollback_total{status="rollback_failed"}[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Rollback failed"
          description: "A deployment rollback has failed - manual intervention required"
```

## Step 6: Log Aggregation

### Centralized Logging with Loki

Configure Promtail to ship logs:

```yaml
# /etc/promtail/config.yml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://loki:3100/loki/api/v1/push

scrape_configs:
  - job_name: hookshot
    journal:
      max_age: 12h
      labels:
        job: hookshot
        host: ${HOSTNAME}
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
        regex: 'hookshot.service'
```

### Log Rotation

Create `/etc/logrotate.d/hookshot`:

```
/var/log/hookshot/*.log {
    daily
    rotate 14
    compress
    delaycompress
    notifempty
    create 0644 hookshot hookshot
    sharedscripts
    postrotate
        systemctl reload hookshot
    endscript
}
```

## Step 7: Backup and Disaster Recovery

Hookshot includes built-in backup and restore functionality for complete state management and disaster recovery.

### Automated Daily Backups

Create a backup script at `/usr/local/bin/hookshot-backup.sh`:

```bash
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/var/backups/hookshot"
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/hookshot-state-$DATE.tar.gz"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
/usr/local/bin/hookshot export "$BACKUP_FILE"

# Verify backup exists
if [ ! -f "$BACKUP_FILE" ]; then
    echo "ERROR: Backup failed" >&2
    exit 1
fi

# Clean up old backups
find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/hookshot-backup.sh
```

### Schedule with Systemd Timer

See [examples/backup/systemd-timer/](../examples/backup/systemd-timer/) for complete timer configuration, or use cron:

```bash
# Run daily at 2 AM
echo "0 2 * * * /usr/local/bin/hookshot-backup.sh >> /var/log/hookshot-backup.log 2>&1" | sudo crontab -
```

### Off-Site Backup Storage

Sync backups to remote storage:

```bash
#!/bin/bash
# /usr/local/bin/hookshot-offsite-sync.sh

BACKUP_DIR="/var/backups/hookshot"
REMOTE_HOST="backup-server.example.com"
REMOTE_DIR="/backup/hookshot/"

# Sync to remote server
rsync -avz --delete \
    "$BACKUP_DIR/" \
    "backup@$REMOTE_HOST:$REMOTE_DIR"
```

Or use S3/object storage:

```bash
#!/bin/bash
# Sync to S3
aws s3 sync /var/backups/hookshot/ \
    s3://my-backups/hookshot/ \
    --storage-class STANDARD_IA \
    --server-side-encryption AES256
```

### Backup Before Upgrades

Always create a backup before upgrading:

```bash
# Create pre-upgrade backup
sudo hookshot export /var/backups/hookshot/pre-upgrade-$(date +%Y%m%d-%H%M%S).tar.gz

# Stop service
sudo systemctl stop hookshot

# Upgrade binary
sudo wget https://github.com/yourusername/hookshot/releases/latest/download/hookshot \
    -O /usr/local/bin/hookshot
sudo chmod +x /usr/local/bin/hookshot

# Start service and verify
sudo systemctl start hookshot
sudo systemctl status hookshot
```

### Disaster Recovery Testing

Test restore procedures quarterly:

```bash
# Test on staging server
hookshot import /backup/production-latest.tar.gz --dry-run
hookshot import /backup/production-latest.tar.gz
hookshot validate
```

### Multi-Tier Backup Strategy

Production-grade backup strategy:

1. **Local Daily** (7 days retention): `/var/backups/hookshot/`
2. **Remote Weekly** (4 weeks retention): Off-site server or S3
3. **Monthly Archive** (12 months retention): Cold storage

See the [Backup & Restore Guide](BACKUP_RESTORE.md) for complete documentation.

## Step 8: Security Hardening

### Firewall Configuration

```bash
# UFW example
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# iptables example
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8080 -j DROP
```

### SELinux / AppArmor

Create AppArmor profile `/etc/apparmor.d/opt.hookshot.hookshot`:

```
#include <tunables/global>

/opt/hookshot/hookshot {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /opt/hookshot/hookshot mr,
  /etc/hookshot/** r,
  /var/lib/hookshot/** rw,
  /var/log/hookshot/** rw,

  # Allow execution of deployment commands
  /usr/bin/podman ix,
  /usr/bin/systemctl ix,
  /usr/bin/curl ix,

  # Network
  network inet stream,
  network inet6 stream,

  # Deny everything else
  deny /** wx,
}
```

Enable profile:

```bash
sudo apparmor_parser -r /etc/apparmor.d/opt.hookshot.hookshot
```

### Regular Security Updates

```bash
# Automated security updates (Ubuntu/Debian)
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

## Step 9: Disaster Recovery

### Recovery Procedures

**Service Down**:
```bash
# Check status
sudo systemctl status hookshot

# View logs
sudo journalctl -u hookshot -n 100

# Restart
sudo systemctl restart hookshot
```

**Database Corruption**:
```bash
# Stop service
sudo systemctl stop hookshot

# Restore from backup
sudo cp /var/backups/hookshot/database-latest.redb /var/lib/hookshot/database.redb
sudo chown hookshot:hookshot /var/lib/hookshot/database.redb

# Start service
sudo systemctl start hookshot
```

**Complete System Failure**:
1. Provision new server
2. Install Hookshot following this guide
3. Restore configuration from backup
4. Restore database from backup
5. Update DNS/load balancer to point to new server

## Operational Procedures

### Rolling Updates

```bash
# Download new version
wget https://github.com/yourusername/hookshot/releases/download/v0.2.0/hookshot -O /tmp/hookshot

# Stop accepting new deployments (manual coordination)
# Wait for active deployments to complete
while [ $(curl -s http://localhost:8080/health | jq '.deployment_queue.active') -gt 0 ]; do
    echo "Waiting for deployments to complete..."
    sleep 10
done

# Stop service
sudo systemctl stop hookshot

# Backup current binary
sudo cp /opt/hookshot/hookshot /opt/hookshot/hookshot.bak

# Install new version
sudo mv /tmp/hookshot /opt/hookshot/hookshot
sudo chown hookshot:hookshot /opt/hookshot/hookshot
sudo chmod 755 /opt/hookshot/hookshot

# Start service
sudo systemctl start hookshot

# Verify
curl http://localhost:8080/health
```

### Configuration Changes

```bash
# Edit configuration
sudo nano /etc/hookshot/config.toml

# Validate
sudo -u hookshot hookshot validate

# Reload (when supported) or restart
sudo systemctl restart hookshot
```

## Performance Tuning

### System Limits

```bash
# /etc/security/limits.conf
hookshot soft nofile 65536
hookshot hard nofile 65536
hookshot soft nproc 4096
hookshot hard nproc 4096
```

### Database Optimization

```toml
# Adjust retention to balance history vs performance
[storage.retention]
successful_deploys = 100  # Reduce if database is large
failed_deploys = 50
```

### Worker Thread Tuning

```toml
[server]
# Increase for high-concurrency workloads
worker_threads = 16  # Start with 2x CPU cores

[limits]
max_concurrent_total = 20  # Adjust based on capacity
```

## Compliance and Auditing

### Audit Logging

All deployments are logged with:
- Timestamp
- Service name
- Image deployed
- Triggered by (IP address)
- Success/failure status
- Full command output

Access audit logs:

```bash
# Search deployment history
sudo journalctl -u hookshot | grep "deploy_id"

# Export for compliance
sudo journalctl -u hookshot --since "2025-01-01" --until "2025-01-31" -o json > audit-jan-2025.json
```

### GDPR Considerations

Hookshot stores:
- IP addresses (for rate limiting and audit)
- Deployment metadata (configurable)

To minimize data retention:

```toml
[storage.retention]
successful_deploys = 30  # Keep only 30 days
failed_deploys = 30
```

## Checklist for Production Readiness

- [ ] Dedicated user account created
- [ ] Strong HMAC secret generated and secured
- [ ] Configuration validated
- [ ] systemd service configured with security hardening
- [ ] Reverse proxy with TLS configured
- [ ] IP allowlisting configured
- [ ] Monitoring and alerting set up
- [ ] Log aggregation configured
- [ ] Backup strategy implemented
- [ ] Disaster recovery procedures documented
- [ ] Performance tuning completed
- [ ] Security hardening applied (firewall, AppArmor/SELinux)
- [ ] Team trained on operational procedures
- [ ] Runbooks created for common issues

## Support

For production issues:

1. Check [Troubleshooting Guide](TROUBLESHOOTING.md)
2. Review logs: `sudo journalctl -u hookshot -n 100`
3. Check metrics: `curl http://localhost:8080/metrics`
4. Open GitHub issue with details