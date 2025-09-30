# Backup and Restore Guide

This guide covers Hookshot's built-in backup and restore functionality for disaster recovery and state management.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Creating Backups](#creating-backups)
- [Restoring from Backups](#restoring-from-backups)
- [Backup Strategies](#backup-strategies)
- [Disaster Recovery](#disaster-recovery)
- [Archive Format](#archive-format)
- [Automation](#automation)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

## Overview

Hookshot includes built-in backup and restore functionality that captures the complete system state in a single compressed archive file. This enables:

- **Disaster Recovery**: Quickly restore service after hardware failure or data corruption
- **Environment Migration**: Move Hookshot between servers while preserving history
- **Configuration Testing**: Test configuration changes with easy rollback
- **Pre-Deployment Safety**: Create restore points before major changes
- **Compliance**: Maintain historical records for audit purposes

### What Gets Backed Up

A Hookshot backup archive contains:

- **Database** (`state.redb`): Complete deployment history, service states, and locks
- **System Configuration** (`config.toml`): Server settings, security rules, and limits
- **Services Configuration** (`services.toml`): All service deployment definitions
- **Secrets File** (if found): HMAC keys and other sensitive credentials
- **Manifest**: Archive metadata, checksums, and version information

### What Doesn't Get Backed Up

The backup **does not** include:

- Application containers or binaries being deployed
- External services (databases, message queues, etc.)
- Reverse proxy configuration (nginx, Caddy)
- Systemd unit files
- Log files
- Temporary files or caches

## Quick Start

### Create Your First Backup

```bash
# Create a backup in the current directory
hookshot export hookshot-backup.tar.gz

# Create a backup in a specific location
hookshot export /backup/hookshot-$(date +%Y%m%d).tar.gz
```

### Preview a Restore

```bash
# See what would be restored without making changes
hookshot import /backup/hookshot-backup.tar.gz --dry-run
```

### Restore from Backup

```bash
# Stop the service first (recommended)
sudo systemctl stop hookshot

# Restore the backup
hookshot import /backup/hookshot-backup.tar.gz

# Restart the service
sudo systemctl start hookshot
```

## Creating Backups

### Basic Export

```bash
hookshot export <output-file>
```

**Example**:
```bash
hookshot export /var/backups/hookshot/state-20250130.tar.gz
```

### Export Behavior

- **Non-Intrusive**: Export can run while the service is active
- **Atomic**: Creates a consistent snapshot of the current state
- **Compressed**: Uses gzip compression for efficient storage
- **Validated**: Generates SHA256 checksums for all files
- **Fast**: Typically completes in < 1 second for normal deployments

### Export Output

```
INFO Starting state export
INFO Added database to backup
INFO Added system config to backup
INFO Added services config to backup
INFO Added secrets file to backup
INFO Backup created successfully, output=/backup/state.tar.gz, files=4, size_bytes=125847
```

### Backup File Naming

The recommended naming convention includes timestamps:

```bash
# Date-based naming
hookshot export /backup/hookshot-$(date +%Y%m%d).tar.gz
# Output: hookshot-20250130.tar.gz

# Full timestamp naming
hookshot export /backup/hookshot-$(date +%Y%m%d-%H%M%S).tar.gz
# Output: hookshot-20250130-143022.tar.gz

# Environment-based naming
hookshot export /backup/production-hookshot-$(date +%Y%m%d).tar.gz
# Output: production-hookshot-20250130.tar.gz
```

### Configuration File Paths

By default, Hookshot uses:
- System config: `/etc/hookshot/config.toml`
- Services config: `/etc/hookshot/services.toml`

To export with custom paths:

```bash
hookshot --config /custom/path/config.toml \
         --services /custom/path/services.toml \
         export /backup/state.tar.gz
```

### Backup Size Considerations

Typical backup sizes:
- **Minimal setup** (1-2 services, no deployments): ~10 KB
- **Small deployment** (5 services, 100 deployments): ~100 KB
- **Medium deployment** (20 services, 1000 deployments): ~1 MB
- **Large deployment** (50 services, 10000 deployments): ~10 MB

The embedded database (redb) uses efficient storage, so backup sizes remain manageable even with extensive deployment history.

## Restoring from Backups

### Basic Import

```bash
hookshot import <input-file> [--dry-run] [--force]
```

### Dry Run Mode

**Always test with --dry-run first** to preview what will be restored:

```bash
hookshot import /backup/state.tar.gz --dry-run
```

**Output**:
```
INFO Backup validated successfully, version=0.0.1, created_at=1738252822, files=4
INFO DRY RUN MODE - No changes will be made
INFO The following files would be restored:
INFO   state.redb -> /var/lib/hookshot/state.redb
INFO   config.toml -> /etc/hookshot/config.toml
INFO   services.toml -> /etc/hookshot/services.toml
INFO   secrets -> /etc/hookshot/secrets
INFO DRY RUN COMPLETE - No changes were made
```

### Normal Restore

```bash
# Recommended: Stop service first
sudo systemctl stop hookshot

# Restore backup
hookshot import /backup/state.tar.gz

# Restart service
sudo systemctl start hookshot
```

### Force Mode

By default, imports are blocked if there are active deployments. Use `--force` to override:

```bash
hookshot import /backup/state.tar.gz --force
```

**⚠️ Warning**: Force mode can cause data loss if deployments are in progress. Use only in disaster recovery scenarios.

### Safety Mechanisms

#### 1. **Active Deployment Detection**

```
ERROR Active deployments present, cannot restore (use --force to override)
```

The system checks for in-progress deployments before restoring. This prevents:
- Lost deployment state for running deployments
- Corruption from concurrent database access
- Inconsistent service states

#### 2. **Version Compatibility Checking**

```
ERROR Version incompatibility: backup version 1.0.0 cannot be restored to 0.5.0
```

Restores are blocked if major versions don't match. This prevents:
- Database schema incompatibilities
- Configuration format mismatches
- Feature availability issues

#### 3. **Checksum Validation**

```
ERROR Checksum mismatch for file state.redb: expected abc123..., got def456...
```

All files are verified using SHA256 before restoration:
- Detects corrupted archives
- Ensures data integrity
- Prevents partial restores

#### 4. **Automatic Backups**

Before overwriting files, the restore process creates `.bak` backups:

```
/etc/hookshot/config.toml -> /etc/hookshot/config.toml.bak
/etc/hookshot/services.toml -> /etc/hookshot/services.toml.bak
/var/lib/hookshot/state.redb -> /var/lib/hookshot/state.redb.bak
```

These can be used to roll back if the restore causes issues.

### Post-Restore Verification

After restoring, verify the system:

```bash
# Validate configuration
hookshot validate

# Check service status
systemctl status hookshot

# Verify services are configured
curl http://127.0.0.1:8080/services

# Check health
curl http://127.0.0.1:8080/health
```

## Backup Strategies

### Daily Automated Backups

Create a daily backup script at `/usr/local/bin/hookshot-backup.sh`:

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

# Verify backup
if [ -f "$BACKUP_FILE" ]; then
    echo "Backup created: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"
else
    echo "ERROR: Backup failed" >&2
    exit 1
fi

# Clean up old backups (keep last 30 days)
find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed successfully"
```

Make it executable:
```bash
sudo chmod +x /usr/local/bin/hookshot-backup.sh
```

### Scheduled Backups with Cron

```bash
# Edit crontab
sudo crontab -e

# Add daily backup at 2 AM
0 2 * * * /usr/local/bin/hookshot-backup.sh >> /var/log/hookshot-backup.log 2>&1
```

### Scheduled Backups with Systemd Timer

See [examples/backup/systemd-timer/](../examples/backup/systemd-timer/) for complete systemd timer configuration.

### Pre-Deployment Backups

Create a backup before each deployment:

```bash
#!/bin/bash
# pre-deploy-backup.sh

BACKUP_DIR="/var/backups/hookshot/pre-deploy"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SERVICE_NAME="$1"

mkdir -p "$BACKUP_DIR"
hookshot export "$BACKUP_DIR/pre-deploy-${SERVICE_NAME}-${TIMESTAMP}.tar.gz"
```

### Multi-Tier Backup Strategy

A production-ready strategy includes:

1. **Local Daily Backups** (7 days retention)
   - Quick access for recent restores
   - Stored on same server

2. **Weekly Off-Site Backups** (4 weeks retention)
   - Stored on different server/datacenter
   - Protection against hardware failure

3. **Monthly Archive Backups** (12 months retention)
   - Long-term compliance and audit trail
   - Stored in cold storage (S3 Glacier, etc.)

Example automation:

```bash
#!/bin/bash
DAILY_DIR="/var/backups/hookshot/daily"
WEEKLY_DIR="/mnt/nfs/backups/hookshot/weekly"
MONTHLY_DIR="/mnt/s3/backups/hookshot/monthly"

DATE=$(date +%Y%m%d)
DAY_OF_WEEK=$(date +%u)  # 1-7 (Monday-Sunday)
DAY_OF_MONTH=$(date +%d)

# Always create daily backup
hookshot export "$DAILY_DIR/hookshot-$DATE.tar.gz"

# Copy to weekly on Sundays
if [ "$DAY_OF_WEEK" -eq 7 ]; then
    cp "$DAILY_DIR/hookshot-$DATE.tar.gz" "$WEEKLY_DIR/"
fi

# Copy to monthly on 1st of month
if [ "$DAY_OF_MONTH" -eq 01 ]; then
    cp "$DAILY_DIR/hookshot-$DATE.tar.gz" "$MONTHLY_DIR/"
fi
```

## Disaster Recovery

### Complete System Loss Scenario

If the Hookshot server is completely lost:

#### 1. **Provision New Server**

```bash
# Install Hookshot binary
wget https://github.com/yourusername/hookshot/releases/latest/download/hookshot
sudo mv hookshot /usr/local/bin/
sudo chmod +x /usr/local/bin/hookshot

# Create directory structure
sudo mkdir -p /etc/hookshot
sudo mkdir -p /var/lib/hookshot
sudo mkdir -p /var/log/hookshot
```

#### 2. **Restore from Backup**

```bash
# Copy backup to new server
scp backup-server:/backups/hookshot-latest.tar.gz /tmp/

# Create minimal temporary config for restore
sudo tee /etc/hookshot/config.toml > /dev/null <<EOF
[server]
listen = "127.0.0.1:8080"

[storage]
data_dir = "/var/lib/hookshot"

[logging]
level = "info"
format = "json"
EOF

# Restore backup (overwrites temporary config)
sudo hookshot import /tmp/hookshot-latest.tar.gz --force
```

#### 3. **Verify and Start Service**

```bash
# Validate configuration
hookshot validate

# Install and start systemd service
sudo cp /path/to/hookshot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hookshot

# Verify service is running
systemctl status hookshot
curl http://127.0.0.1:8080/health
```

### Partial Data Loss Scenario

If only the database is corrupted:

```bash
# Stop service
sudo systemctl stop hookshot

# Backup corrupted database
sudo mv /var/lib/hookshot/state.redb /var/lib/hookshot/state.redb.corrupted

# Extract just the database from backup
cd /tmp
tar -xzf /backup/hookshot-latest.tar.gz
cd hookshot-state-*/
sudo cp state.redb /var/lib/hookshot/
sudo chown hookshot:hookshot /var/lib/hookshot/state.redb

# Restart service
sudo systemctl start hookshot
```

### Configuration Rollback

If a configuration change breaks the service:

```bash
# Stop service
sudo systemctl stop hookshot

# Restore configuration files from backup
hookshot import /backup/pre-change-backup.tar.gz --dry-run  # Preview
hookshot import /backup/pre-change-backup.tar.gz            # Execute

# Or manually restore .bak files
sudo cp /etc/hookshot/config.toml.bak /etc/hookshot/config.toml
sudo cp /etc/hookshot/services.toml.bak /etc/hookshot/services.toml

# Restart service
sudo systemctl start hookshot
```

## Archive Format

### Archive Structure

```
hookshot-state-20250130-143022.tar.gz
└── hookshot-state-20250130-143022/
    ├── manifest.json       # Archive metadata
    ├── state.redb          # Embedded database
    ├── config.toml         # System configuration
    ├── services.toml       # Services configuration
    └── secrets             # Secrets file (optional)
```

### Manifest Format

The `manifest.json` contains:

```json
{
  "version": "1.0",
  "created_at": 1738252822,
  "hookshot_version": "0.0.1",
  "files": {
    "state.redb": {
      "path": "state.redb",
      "checksum": "a3b2c1d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890",
      "size": 98304
    },
    "config.toml": {
      "path": "config.toml",
      "checksum": "f1e2d3c4b5a67890fedcba0987654321fedcba0987654321fedcba0987654321",
      "size": 1024
    },
    "services.toml": {
      "path": "services.toml",
      "checksum": "1a2b3c4d5e6f7890abcdef1234567890abcdef1234567890abcdef1234567890",
      "size": 2048
    },
    "secrets": {
      "path": "secrets",
      "checksum": "9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
      "size": 128
    }
  }
}
```

### Manual Archive Inspection

```bash
# Extract archive to temporary directory
mkdir /tmp/backup-inspect
tar -xzf hookshot-backup.tar.gz -C /tmp/backup-inspect

# View manifest
cat /tmp/backup-inspect/hookshot-state-*/manifest.json | jq

# Check configuration without restoring
cat /tmp/backup-inspect/hookshot-state-*/config.toml

# Verify checksums
cd /tmp/backup-inspect/hookshot-state-*/
sha256sum -c <(jq -r '.files[] | "\(.checksum)  \(.path)"' manifest.json)
```

## Automation

### Off-Site Backup with rsync

```bash
#!/bin/bash
# /usr/local/bin/hookshot-offsite-backup.sh

LOCAL_BACKUP="/var/backups/hookshot/hookshot-$(date +%Y%m%d).tar.gz"
REMOTE_USER="backup"
REMOTE_HOST="backup-server.example.com"
REMOTE_DIR="/backup/hookshot/"

# Create local backup
hookshot export "$LOCAL_BACKUP"

# Sync to remote server
rsync -avz --progress "$LOCAL_BACKUP" \
    "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}"

# Clean up local backup (keep remote only)
# rm "$LOCAL_BACKUP"  # Uncomment if desired
```

### S3/Object Storage Backup

```bash
#!/bin/bash
# /usr/local/bin/hookshot-s3-backup.sh

BACKUP_FILE="/tmp/hookshot-$(date +%Y%m%d-%H%M%S).tar.gz"
S3_BUCKET="s3://my-backups/hookshot/"

# Create backup
hookshot export "$BACKUP_FILE"

# Upload to S3
aws s3 cp "$BACKUP_FILE" "$S3_BUCKET" \
    --storage-class STANDARD_IA \
    --server-side-encryption AES256

# Clean up local file
rm "$BACKUP_FILE"

echo "Backup uploaded to $S3_BUCKET"
```

### Monitoring Backup Success

Add monitoring to your backup script:

```bash
#!/bin/bash

BACKUP_FILE="/var/backups/hookshot/hookshot-$(date +%Y%m%d).tar.gz"
WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

if hookshot export "$BACKUP_FILE"; then
    # Success notification
    curl -X POST "$WEBHOOK_URL" -H 'Content-Type: application/json' -d '{
        "text": "✅ Hookshot backup succeeded: '"$BACKUP_FILE"'"
    }'
else
    # Failure notification
    curl -X POST "$WEBHOOK_URL" -H 'Content-Type: application/json' -d '{
        "text": "❌ Hookshot backup FAILED"
    }'
    exit 1
fi
```

## Troubleshooting

### Backup Creation Fails

**Problem**: Permission denied when creating backup

```
ERROR I/O error: Permission denied (os error 13)
```

**Solution**:
```bash
# Ensure directories are readable
sudo chmod 755 /etc/hookshot
sudo chmod 644 /etc/hookshot/*.toml

# Ensure database is readable
sudo chmod 644 /var/lib/hookshot/state.redb

# Or run as appropriate user
sudo -u hookshot hookshot export /backup/state.tar.gz
```

### Import Blocked by Active Deployments

**Problem**:
```
ERROR Active deployments present, cannot restore (use --force to override)
```

**Solution 1**: Wait for deployments to complete
```bash
# Check deployment status
curl http://127.0.0.1:8080/services | jq

# Wait and retry
sleep 60
hookshot import /backup/state.tar.gz
```

**Solution 2**: Force import (destructive)
```bash
# Stop service first to prevent conflicts
sudo systemctl stop hookshot

# Force import
hookshot import /backup/state.tar.gz --force

# Restart service
sudo systemctl start hookshot
```

### Version Incompatibility

**Problem**:
```
ERROR Version incompatibility: backup version 2.0.0 cannot be restored to 1.5.0
```

**Solution**: Upgrade Hookshot to matching version
```bash
# Check current version
hookshot version

# Check backup version
tar -xzOf backup.tar.gz '*/manifest.json' | jq -r '.hookshot_version'

# Upgrade Hookshot to match backup version
wget https://github.com/yourusername/hookshot/releases/download/v2.0.0/hookshot
sudo mv hookshot /usr/local/bin/
sudo systemctl restart hookshot
```

### Checksum Mismatch

**Problem**:
```
ERROR Checksum mismatch for file state.redb: expected abc123, got def456
```

**Cause**: Corrupted backup archive

**Solution**:
```bash
# Try re-downloading backup
scp backup-server:/backups/hookshot-latest.tar.gz /tmp/

# Verify archive integrity
gzip -t /tmp/hookshot-latest.tar.gz

# If corrupted, restore from alternate backup
hookshot import /backup/hookshot-previous-day.tar.gz
```

### Secrets Not Included in Backup

**Problem**: Secrets file not found in backup

**Cause**: Secrets file in non-standard location

**Solution**: Manually specify secrets location or add after restore
```bash
# Option 1: Manually copy secrets
sudo cp /old/location/secrets /etc/hookshot/secrets
sudo chmod 600 /etc/hookshot/secrets
sudo chown hookshot:hookshot /etc/hookshot/secrets

# Option 2: Restore secrets from password manager
echo "hmac_key=$(retrieve-from-vault)" | sudo tee /etc/hookshot/secrets
```

### Database Corruption After Restore

**Problem**: Service fails to start after restore with database error

**Solution**:
```bash
# Check database integrity
redb-check /var/lib/hookshot/state.redb

# If corrupted, try backup file
sudo cp /var/lib/hookshot/state.redb.bak /var/lib/hookshot/state.redb

# Or restore from older backup
hookshot import /backup/hookshot-$(date -d '1 day ago' +%Y%m%d).tar.gz
```

## Best Practices

### 1. **Regular Backup Schedule**

- Minimum: Daily automated backups
- Recommended: Daily local + weekly off-site
- Critical systems: Continuous replication

### 2. **Test Restores Regularly**

```bash
# Monthly restore test
hookshot import /backup/latest.tar.gz --dry-run

# Quarterly full restore test on staging
# (Actual restore on non-production system)
```

### 3. **Backup Before Changes**

Always create a backup before:
- Upgrading Hookshot
- Modifying system configuration
- Adding/removing services
- Major deployment waves

### 4. **Secure Backup Storage**

- Encrypt backups at rest (especially if containing secrets)
- Restrict backup file permissions: `chmod 600`
- Store off-site in case of site-wide failure
- Use separate authentication for backup storage

### 5. **Retention Policies**

Recommended retention:
- Daily backups: 7 days
- Weekly backups: 4 weeks
- Monthly backups: 12 months
- Yearly backups: 3-7 years (compliance dependent)

### 6. **Monitor Backup Health**

- Alert on backup failures
- Monitor backup sizes (detect abnormal growth)
- Track backup duration
- Verify backup integrity regularly

### 7. **Document Recovery Procedures**

Maintain runbook with:
- Backup locations and access credentials
- Recovery time objectives (RTO)
- Recovery point objectives (RPO)
- Step-by-step restore procedures
- Contact information for escalation

### 8. **Separate Backup Infrastructure**

- Don't store backups only on same server
- Use different storage backend (NFS, S3, etc.)
- Implement backup monitoring separate from main system

## See Also

- [Deployment Guide](DEPLOYMENT.md) - Production deployment with backup integration
- [Configuration Reference](CONFIGURATION.md) - Storage and data directory configuration
- [Troubleshooting Guide](TROUBLESHOOTING.md) - Additional backup-related issues
