# Troubleshooting Guide

This guide covers common issues, debugging techniques, and solutions for Hookshot.

## Table of Contents

- [Configuration Issues](#configuration-issues)
- [Authentication Problems](#authentication-problems)
- [Deployment Failures](#deployment-failures)
- [Performance Issues](#performance-issues)
- [Database Problems](#database-problems)
- [Network and Connectivity](#network-and-connectivity)
- [Debugging Techniques](#debugging-techniques)
- [FAQ](#faq)

## Configuration Issues

### Configuration File Not Found

**Symptom**:
```
Error: Config file not found: /etc/hookshot/config.toml
```

**Solution**:
```bash
# Check if file exists
ls -la /etc/hookshot/config.toml

# If missing, create it
sudo mkdir -p /etc/hookshot
sudo cp examples/config.toml /etc/hookshot/

# Or specify custom path
hookshot --config /path/to/config.toml run
```

### Configuration Validation Errors

**Symptom**:
```
ERROR Services configuration validation failed
Error: Invalid configuration: allowed_image_pattern
```

**Solution**:

1. Run validation command for details:
```bash
hookshot validate
```

2. Check regex syntax:
```bash
# Test regex patterns
echo "registry.example.com/app:v1.0.0" | grep -P '^registry\.example\.com/app:v\d+\.\d+\.\d+$'
```

3. Common regex mistakes:
```toml
# Wrong: Unescaped dots
allowed_image_pattern = '^registry.example.com/app:.*$'

# Correct: Escaped dots
allowed_image_pattern = '^registry\.example\.com/app:.*$'
```

### Permission Denied on Data Directory

**Symptom**:
```
Error: Permission denied (os error 13)
Database error: Failed to create database at /var/lib/hookshot/database.redb
```

**Solution**:
```bash
# Check current permissions
ls -ld /var/lib/hookshot

# Fix ownership
sudo chown -R $(whoami):$(whoami) /var/lib/hookshot

# Fix permissions
chmod 755 /var/lib/hookshot
chmod 644 /var/lib/hookshot/*.redb
```

### Port Already in Use

**Symptom**:
```
Error: Address already in use (os error 98)
Failed to bind to 127.0.0.1:8080
```

**Solution**:
```bash
# Find what's using the port
sudo lsof -i :8080
sudo netstat -tulpn | grep :8080

# Kill the process if needed
sudo kill <PID>

# Or change port in config.toml
[server]
listen = "127.0.0.1:9090"
```

## Authentication Problems

### HMAC Signature Mismatch

**Symptom**:
```json
{
  "error": "Invalid HMAC signature",
  "code": "AUTHENTICATION_ERROR"
}
```

**Common Causes**:

1. **Extra whitespace in payload**:
```bash
# Wrong: Has trailing newline
PAYLOAD='{"service":"app"}\n'

# Correct: No trailing newline
PAYLOAD='{"service":"app"}'
```

2. **Wrong secret key**:
```bash
# Verify you're using the correct key
grep hmac_key /etc/hookshot/secrets
```

3. **Payload modified after signing**:
```bash
# Sign exactly what you send
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY"
```

**Debugging**:
```bash
# Enable debug logging to see what server receives
[logging]
level = "debug"

# Test signature generation
PAYLOAD='{"service":"test","image":"test:v1"}'
echo "Payload bytes:"
echo -n "$PAYLOAD" | xxd

echo "Signature:"
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_KEY"
```

### Missing HMAC Header

**Symptom**:
```json
{
  "error": "Missing signature",
  "code": "AUTHENTICATION_ERROR"
}
```

**Solution**:
```bash
# Ensure header is included
curl -X POST http://127.0.0.1:8080/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \  # This line required
  -d "$PAYLOAD"
```

### IP Address Blocked

**Symptom**:
```json
{
  "error": "Access denied from IP address",
  "code": "ACCESS_DENIED"
}
```

**Solution**:
```toml
# Check allowed_ips configuration
[security]
allowed_ips = [
    "192.168.1.0/24",  # Add your IP range
]

# Or allow all (NOT recommended for production)
allowed_ips = []
```

## Deployment Failures

### Service Not Found

**Symptom**:
```json
{
  "error": "Service 'my-app' not found or disabled",
  "code": "SERVICE_NOT_FOUND"
}
```

**Solution**:
```bash
# List configured services
curl http://127.0.0.1:8080/services | jq '.services[].name'

# Check service configuration
grep -A 5 'name = "my-app"' /etc/hookshot/services.toml

# Ensure enabled = true
[[service]]
name = "my-app"
enabled = true  # Must be true
```

### Image Pattern Validation Failed

**Symptom**:
```
Deployment failed: Image does not match allowed pattern
```

**Solution**:
```bash
# Check allowed pattern
grep allowed_image_pattern /etc/hookshot/services.toml

# Test pattern match
echo "registry.example.com/app:v1.0.0" | grep -P '^registry\.example\.com/app:v\d+\.\d+\.\d+$'

# Adjust pattern to be more permissive (during testing only)
allowed_image_pattern = '.*'  # Allow any image
```

### Command Execution Timeout

**Symptom**:
```
Command 'podman pull' timed out after 300s
```

**Solution**:
```toml
# Increase timeout for slow operations
[limits]
command_timeout = 600  # 10 minutes

# Or per-service
[service.deploy]
timeout = 600
commands = [
    ["podman", "pull", "{{IMAGE}}"]
]
```

### Health Check Failures

**Symptom**:
```
Healthcheck failed: connection refused
Deployment rolled back
```

**Solutions**:

1. **Increase initial delay**:
```toml
[service.healthcheck]
initial_delay = 15  # Wait longer for service to start
```

2. **Verify health check command**:
```bash
# Test health check manually
curl -fsS http://127.0.0.1:3000/health

# Check service logs
journalctl -u my-app.service -f
```

3. **Adjust success threshold**:
```toml
[service.healthcheck]
max_attempts = 20
success_threshold = 2  # Require only 2 consecutive successes
```

### Rollback Failed

**Symptom**:
```json
{
  "status": "RollbackFailed",
  "requires_intervention": true,
  "failure_detail": "systemctl restart failed: exit code 1"
}
```

**Immediate Action**:
```bash
# Check service status
systemctl status my-app.service

# View service logs
journalctl -u my-app.service -n 50

# Manual recovery
systemctl restart my-app.service

# Verify previous image is available
podman images | grep my-app
```

**Prevention**:
```toml
# Always include previous_image in requests
{
  "service": "my-app",
  "image": "registry.example.com/my-app:v2.0.0",
  "previous_image": "registry.example.com/my-app:v1.9.0"  # Required for rollback
}
```

### Concurrency Limit Exceeded

**Symptom**:
```json
{
  "error": "Concurrency limit exceeded for service: 1/1 active deployments",
  "code": "CONCURRENCY_LIMIT_EXCEEDED"
}
```

**Solution**:
```bash
# Wait for current deployment to complete
curl http://127.0.0.1:8080/services | jq '.services[] | select(.locked == true)'

# Or increase limit (use with caution)
[limits]
max_concurrent_per_service = 2  # Allow 2 concurrent deploys per service
```

## Performance Issues

### Slow Deployments

**Symptom**: Deployments taking much longer than expected

**Diagnosis**:
```bash
# Check deployment timing
curl http://127.0.0.1:8080/status/deploy-123 | jq '.timings'

# Review metrics
curl http://127.0.0.1:8080/metrics | grep deployment_duration
```

**Solutions**:

1. **Container pull optimization**:
```toml
[service.deploy]
commands = [
    # Use --pull=missing to skip if image exists
    ["podman", "pull", "--pull=missing", "{{IMAGE}}"],
]
```

2. **Parallel operations** (advanced):
```toml
# Split independent operations across multiple commands
[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    # These run sequentially, consider pre-pulling
]
```

3. **Reduce health check overhead**:
```toml
[service.healthcheck]
interval = 5  # Increase interval between checks
max_attempts = 10  # Reduce attempts
```

### High Memory Usage

**Symptom**: Hookshot consuming excessive memory

**Diagnosis**:
```bash
# Check memory usage
ps aux | grep hookshot

# Monitor database size
du -h /var/lib/hookshot/database.redb
```

**Solutions**:
```toml
# Reduce retention
[storage.retention]
successful_deploys = 50  # Keep fewer records
failed_deploys = 25

# Add systemd memory limit
[Service]
MemoryLimit=512M
```

### Database Growing Large

**Symptom**: `/var/lib/hookshot/database.redb` consuming significant disk space

**Solution**:
```bash
# Check database size
du -h /var/lib/hookshot/database.redb

# Reduce retention policy
[storage.retention]
successful_deploys = 50
failed_deploys = 25

# Cleanup old records (planned feature)
# For now, restart clears some space after applying new retention
sudo systemctl restart hookshot
```

## Database Problems

### Database Lock Timeout

**Symptom**:
```
Error: Database transaction failed: Lock timeout
```

**Solution**:
```bash
# Check for stale processes
ps aux | grep hookshot

# Kill stale processes
sudo killall hookshot

# Remove lock files if needed (only when service is stopped)
sudo systemctl stop hookshot
rm /var/lib/hookshot/locks/*.lock
sudo systemctl start hookshot
```

### Database Corruption

**Symptom**:
```
Error: Database corruption detected
Failed to read deployment record
```

**Recovery**:
```bash
# Stop service
sudo systemctl stop hookshot

# Backup corrupted database
sudo cp /var/lib/hookshot/database.redb /var/lib/hookshot/database.redb.bak

# Remove corrupted database (will be recreated)
sudo rm /var/lib/hookshot/database.redb

# Restart service
sudo systemctl start hookshot

# Note: Deployment history will be lost
```

### Service Lock Stuck

**Symptom**:
```json
{
  "error": "Service web-app is locked by deployment deploy-123",
  "code": "SERVICE_LOCKED"
}
```

**Solution**:
```bash
# Check service status
curl http://127.0.0.1:8080/services | jq '.services[] | select(.name == "web-app")'

# If deployment is genuinely stuck, restart Hookshot
sudo systemctl restart hookshot

# Stale locks are automatically cleaned up after lock_timeout seconds
[limits]
lock_timeout = 60  # Automatically release after 60 seconds
```

## Network and Connectivity

### Cannot Reach Hookshot from CI

**Symptom**: CI system cannot connect to Hookshot

**Diagnosis**:
```bash
# Check if Hookshot is listening
sudo netstat -tulpn | grep hookshot
sudo lsof -i :8080

# Test connectivity from CI server
curl http://hookshot-server:8080/health
```

**Solutions**:

1. **Wrong listen address**:
```toml
# Binding to localhost only
[server]
listen = "127.0.0.1:8080"  # Only accessible locally

# Bind to all interfaces
[server]
listen = "0.0.0.0:8080"  # Accessible from network (use with IP allowlist!)
```

2. **Firewall blocking**:
```bash
# Check firewall rules
sudo iptables -L -n | grep 8080
sudo firewall-cmd --list-all

# Allow port (example)
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

3. **Use reverse proxy** (recommended):
```nginx
# nginx configuration
server {
    listen 443 ssl;
    server_name deploy.example.com;

    ssl_certificate /etc/letsencrypt/live/deploy.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/deploy.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Rate Limit Issues

**Symptom**:
```json
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED"
}
```

**Solution**:
```toml
# Increase rate limit
[security]
rate_limit = 200  # Allow 200 requests per minute per IP

# Or disable for testing (not recommended)
rate_limit = 0  # No limit
```

## Debugging Techniques

### Enable Debug Logging

```toml
[logging]
level = "debug"  # Show all debug messages
format = "pretty"  # Human-readable format
```

Restart Hookshot and check logs:
```bash
sudo systemctl restart hookshot
sudo journalctl -u hookshot -f
```

### View Detailed Logs

```bash
# View recent logs
sudo journalctl -u hookshot -n 100

# Follow logs in real-time
sudo journalctl -u hookshot -f

# Filter by severity
sudo journalctl -u hookshot -p err

# View logs for specific deployment
sudo journalctl -u hookshot | grep "deploy-20250130-001"

# Export logs to file
sudo journalctl -u hookshot --since "1 hour ago" > /tmp/hookshot-debug.log
```

### Test Individual Commands

```bash
# Test deployment commands manually
cd /srv/my-app
podman pull registry.example.com/my-app:v1.0.0
systemctl --user status my-app.service

# Test health check commands
curl -fsS http://127.0.0.1:3000/health
echo $?  # Should be 0 for success
```

### Validate JSON Payloads

```bash
# Validate JSON syntax
echo "$PAYLOAD" | jq .

# Format JSON for readability
echo "$PAYLOAD" | jq . -C

# Check specific fields
echo "$PAYLOAD" | jq '.service, .image'
```

### Monitor Metrics

```bash
# View all metrics
curl http://127.0.0.1:8080/metrics

# Filter specific metrics
curl http://127.0.0.1:8080/metrics | grep deployment_

# Monitor deployment rate
watch -n 5 'curl -s http://127.0.0.1:8080/metrics | grep deployment_total'
```

### Trace Requests

```bash
# Use X-Request-ID for tracing
REQUEST_ID="debug-$(date +%s)"

curl -X POST http://127.0.0.1:8080/deploy \
  -H "X-Request-ID: $REQUEST_ID" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"

# Search logs for request ID
sudo journalctl -u hookshot | grep "$REQUEST_ID"
```

## Backup and Restore Issues

### Backup Creation Fails with Permission Denied

**Symptom**:
```
ERROR I/O error: Permission denied (os error 13)
```

**Solution**:
```bash
# Ensure configuration files are readable
sudo chmod 755 /etc/hookshot
sudo chmod 644 /etc/hookshot/*.toml

# Ensure database is readable
sudo chmod 644 /var/lib/hookshot/state.redb

# Or run as hookshot user
sudo -u hookshot hookshot export /backup/state.tar.gz

# Or ensure backup directory is writable
sudo mkdir -p /var/backups/hookshot
sudo chown $USER:$USER /var/backups/hookshot
```

### Import Blocked by Active Deployments

**Symptom**:
```
ERROR Active deployments present, cannot restore (use --force to override)
```

**Solution 1**: Wait for deployments to complete
```bash
# Check for active deployments
curl http://127.0.0.1:8080/services | jq '.services[] | select(.locked == true)'

# Wait and retry
sleep 60
hookshot import /backup/state.tar.gz
```

**Solution 2**: Stop service and force restore
```bash
# Stop the service completely
sudo systemctl stop hookshot

# Force import (safe when service is stopped)
hookshot import /backup/state.tar.gz --force

# Restart service
sudo systemctl start hookshot
```

### Version Incompatibility Error

**Symptom**:
```
ERROR Version incompatibility: backup version 2.0.0 cannot be restored to 1.5.0
```

**Solution**:
```bash
# Check backup version
tar -xzOf backup.tar.gz '*/manifest.json' | jq -r '.hookshot_version'

# Check current version
hookshot version

# Upgrade Hookshot to match backup version
wget https://github.com/yourusername/hookshot/releases/download/v2.0.0/hookshot
sudo mv hookshot /usr/local/bin/
sudo systemctl restart hookshot

# Retry import
hookshot import /backup/state.tar.gz
```

### Checksum Mismatch After Restore

**Symptom**:
```
ERROR Checksum mismatch for file state.redb: expected abc123, got def456
```

**Cause**: Corrupted backup archive

**Solution**:
```bash
# Verify archive integrity
gzip -t /backup/state.tar.gz

# If corrupted, try alternate backup
hookshot import /backup/state-previous-day.tar.gz

# If no other backup, check off-site backups
scp backup-server:/backups/hookshot-latest.tar.gz /tmp/
hookshot import /tmp/hookshot-latest.tar.gz
```

### Secrets File Not Included in Backup

**Symptom**: Backup restores but service fails to start due to missing secrets

**Solution**:
```bash
# Manually restore secrets from secure storage
# Option 1: From password manager
echo "hmac_key=YOUR_KEY_FROM_VAULT" | sudo tee /etc/hookshot/secrets
sudo chmod 600 /etc/hookshot/secrets

# Option 2: Copy from another source
scp secure-server:/secure/secrets /etc/hookshot/secrets

# Option 3: Regenerate and update CI systems
HMAC_KEY=$(openssl rand -hex 32)
echo "hmac_key=$HMAC_KEY" | sudo tee /etc/hookshot/secrets
# Update CI/CD systems with new HMAC key
```

### Dry-Run Shows Files But Import Fails

**Symptom**: `--dry-run` succeeds but actual import fails

**Solution**:
```bash
# Check available disk space
df -h /var/lib/hookshot /etc/hookshot

# Check file permissions for destination directories
ls -la /var/lib/hookshot
ls -la /etc/hookshot

# Ensure parent directories exist and are writable
sudo mkdir -p /var/lib/hookshot /etc/hookshot
sudo chown hookshot:hookshot /var/lib/hookshot /etc/hookshot

# Try import again
hookshot import /backup/state.tar.gz
```

### Backup Size Unexpectedly Large

**Symptom**: Backup file is much larger than expected

**Solution**:
```bash
# Check database size
du -h /var/lib/hookshot/state.redb

# Review retention settings in config.toml
grep -A 5 "\[storage.retention\]" /etc/hookshot/config.toml

# Clean up old deployment records
# Edit config.toml to reduce retention:
[storage.retention]
successful_deploys = 50  # Reduce from 100
failed_deploys = 25      # Reduce from 50

# Restart hookshot to apply cleanup
sudo systemctl restart hookshot
```

### Restore Corrupts Running Service

**Symptom**: Service becomes unstable after restore

**Solution**:
```bash
# ALWAYS stop service before restore
sudo systemctl stop hookshot

# Restore from backup
hookshot import /backup/state.tar.gz

# Validate configuration
hookshot validate

# Start service
sudo systemctl start hookshot

# Verify service health
curl http://127.0.0.1:8080/health
```

### Cannot Find Backup Files

**Symptom**: Backup directory is empty or backup command succeeds but file not found

**Solution**:
```bash
# Check if backup was created with different path
find /var -name "hookshot-state-*.tar.gz" 2>/dev/null

# Check backup script logs
tail -f /var/log/hookshot-backup.log

# Verify systemd timer ran
systemctl list-timers hookshot-backup.timer
journalctl -u hookshot-backup.service -n 50

# Check backup directory permissions
ls -la /var/backups/hookshot/
```

For complete backup and restore documentation, see the [Backup & Restore Guide](BACKUP_RESTORE.md).

## FAQ

### Q: Can I run multiple deployments for the same service simultaneously?

**A**: By default, no. The `max_concurrent_per_service` limit is set to 1 to prevent race conditions. You can increase it, but ensure your deployment commands are idempotent.

### Q: What happens if Hookshot crashes during a deployment?

**A**: The deployment will be marked as failed on restart. Service locks are automatically cleaned up after `lock_timeout` seconds. However, the partially-deployed service may be in an inconsistent state and require manual intervention.

### Q: How do I rotate HMAC keys?

**A**:
1. Generate new key: `openssl rand -hex 32`
2. Update `/etc/hookshot/secrets` with both old and new keys (temporarily)
3. Update CI systems to use new key
4. Remove old key from secrets file after migration
5. Note: Current implementation supports only one key; implement key rotation carefully

### Q: Can I use Hookshot with GitLab CI / Jenkins / other CI systems?

**A**: Yes! Any CI system that can make HTTP POST requests with custom headers can integrate with Hookshot. See the [examples/](../examples/) directory for templates.

### Q: How do I deploy non-containerized applications?

**A**: Configure deployment commands for your specific use case:

```toml
[service.deploy]
commands = [
    ["wget", "-O", "/tmp/app-{{DEPLOY_ID}}", "{{DOWNLOAD_URL}}"],
    ["sudo", "systemctl", "stop", "my-app"],
    ["sudo", "cp", "/tmp/app-{{DEPLOY_ID}}", "/usr/local/bin/my-app"],
    ["sudo", "systemctl", "start", "my-app"]
]
```

### Q: What happens if the network fails during deployment?

**A**: Commands will time out based on `command_timeout`. The deployment will fail and trigger rollback if configured.

### Q: Can I test deployments without actually deploying?

**A**: Yes, use the `dry_run` parameter:

```json
{
  "service": "my-app",
  "image": "test:v1.0.0",
  "dry_run": true
}
```

### Q: How do I backup deployment history?

**A**: Backup the database file:

```bash
sudo systemctl stop hookshot
sudo cp /var/lib/hookshot/database.redb /backup/location/
sudo systemctl start hookshot
```

### Q: Can I customize the deployment ID format?

**A**: Yes, provide a custom `deploy_id` in your request:

```json
{
  "deploy_id": "release-2025-01-30-001",
  "service": "my-app",
  "image": "registry.example.com/my-app:v1.0.0"
}
```

### Q: What's the maximum payload size?

**A**: Configurable via `max_request_size` (default: 1MB). Adjust if needed:

```toml
[server]
max_request_size = "5MB"
```

### Q: How do I update Hookshot without downtime?

**A**: Hookshot doesn't support zero-downtime updates. Plan a maintenance window:

1. Stop accepting new deployments
2. Wait for active deployments to complete
3. Stop Hookshot
4. Update binary
5. Start Hookshot

## Getting More Help

If you're still experiencing issues:

1. **Enable debug logging** and capture full output
2. **Check GitHub Issues** for similar problems
3. **Provide details** when opening an issue:
   - Hookshot version (`hookshot version`)
   - Full error message and logs
   - Configuration files (redact secrets!)
   - Steps to reproduce
4. **Review the documentation**:
   - [Configuration Reference](CONFIGURATION.md)
   - [API Documentation](API.md)
   - [Deployment Guide](DEPLOYMENT.md)