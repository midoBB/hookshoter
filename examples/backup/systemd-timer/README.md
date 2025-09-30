# Hookshot Systemd Timer for Automated Backups

This directory contains systemd unit files for automated daily backups of Hookshot.

## Files

- `hookshot-backup.service` - Service unit that runs the backup script
- `hookshot-backup.timer` - Timer unit that schedules the backup service
- `../backup-cron.sh` - The actual backup script

## Installation

### 1. Install the Backup Script

```bash
# Copy the backup script
sudo cp ../backup-cron.sh /usr/local/bin/hookshot-backup.sh
sudo chmod +x /usr/local/bin/hookshot-backup.sh

# Test the script manually
sudo /usr/local/bin/hookshot-backup.sh
```

### 2. Install Systemd Units

```bash
# Copy service and timer files
sudo cp hookshot-backup.service /etc/systemd/system/
sudo cp hookshot-backup.timer /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload
```

### 3. Configure (Optional)

Edit the service file to customize settings:

```bash
sudo systemctl edit hookshot-backup.service
```

Add your custom environment variables:

```ini
[Service]
Environment="HOOKSHOT_BACKUP_DIR=/custom/backup/path"
Environment="HOOKSHOT_BACKUP_RETENTION=60"
Environment="HOOKSHOT_BACKUP_WEBHOOK=https://hooks.slack.com/services/YOUR/WEBHOOK"
```

### 4. Enable and Start the Timer

```bash
# Enable timer to start on boot
sudo systemctl enable hookshot-backup.timer

# Start the timer now
sudo systemctl start hookshot-backup.timer

# Check timer status
sudo systemctl status hookshot-backup.timer

# List all timers and see when next backup will run
systemctl list-timers hookshot-backup.timer
```

## Usage

### Check Timer Status

```bash
# View timer status
systemctl status hookshot-backup.timer

# See when the next backup will run
systemctl list-timers hookshot-backup.timer
```

Output example:
```
NEXT                        LEFT          LAST                        PASSED  UNIT                      ACTIVATES
Wed 2025-01-31 02:00:00 UTC 4h 23min left Tue 2025-01-30 02:00:00 UTC 19h ago hookshot-backup.timer     hookshot-backup.service
```

### View Backup Logs

```bash
# View recent backup logs
sudo journalctl -u hookshot-backup.service -n 50

# Follow backup logs in real-time
sudo journalctl -u hookshot-backup.service -f

# View logs from specific date
sudo journalctl -u hookshot-backup.service --since "2025-01-30"

# View detailed backup log file
sudo tail -f /var/log/hookshot-backup.log
```

### Manually Trigger a Backup

```bash
# Run backup service immediately (won't affect timer schedule)
sudo systemctl start hookshot-backup.service

# Check the status
sudo systemctl status hookshot-backup.service
```

### Modify Backup Schedule

The default schedule is daily at 2:00 AM. To change it:

```bash
# Edit the timer
sudo systemctl edit hookshot-backup.timer
```

Add your custom schedule:

```ini
[Timer]
# Run every 6 hours
OnCalendar=00/6:00:00

# Or run twice daily at specific times
OnCalendar=*-*-* 02:00:00
OnCalendar=*-*-* 14:00:00

# Or run weekly on Sunday at 3 AM
OnCalendar=Sun *-*-* 03:00:00
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart hookshot-backup.timer
```

### Disable Automated Backups

```bash
# Stop and disable the timer
sudo systemctl stop hookshot-backup.timer
sudo systemctl disable hookshot-backup.timer
```

## Monitoring

### Set Up Backup Monitoring

Add monitoring for backup failures:

```bash
# Check if last backup succeeded
if systemctl is-failed hookshot-backup.service; then
    echo "Last backup failed!"
    # Send alert
fi
```

### Prometheus Monitoring

Create a script to export backup metrics:

```bash
#!/bin/bash
# /usr/local/bin/hookshot-backup-metrics.sh

BACKUP_DIR="/var/backups/hookshot"
METRICS_FILE="/var/lib/node_exporter/textfile_collector/hookshot_backup.prom"

# Get last backup time
LAST_BACKUP=$(find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" -type f -printf '%T@\n' | sort -n | tail -1)
LAST_BACKUP_SECONDS=${LAST_BACKUP%.*}

# Get backup count
BACKUP_COUNT=$(find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" -type f | wc -l)

# Get total backup size
TOTAL_SIZE=$(du -sb "$BACKUP_DIR" | cut -f1)

# Write metrics
cat > "$METRICS_FILE" <<EOF
# HELP hookshot_backup_last_success_timestamp_seconds Timestamp of last successful backup
# TYPE hookshot_backup_last_success_timestamp_seconds gauge
hookshot_backup_last_success_timestamp_seconds $LAST_BACKUP_SECONDS

# HELP hookshot_backup_count Total number of backup files
# TYPE hookshot_backup_count gauge
hookshot_backup_count $BACKUP_COUNT

# HELP hookshot_backup_total_size_bytes Total size of all backups in bytes
# TYPE hookshot_backup_total_size_bytes gauge
hookshot_backup_total_size_bytes $TOTAL_SIZE
EOF
```

Add to cron:
```bash
*/5 * * * * /usr/local/bin/hookshot-backup-metrics.sh
```

## Troubleshooting

### Timer Not Running

```bash
# Check if timer is enabled
systemctl is-enabled hookshot-backup.timer

# Check for errors
journalctl -u hookshot-backup.timer -n 50
```

### Backup Service Fails

```bash
# Check service logs
sudo journalctl -u hookshot-backup.service -n 50

# Check backup script permissions
ls -l /usr/local/bin/hookshot-backup.sh

# Test backup script manually
sudo /usr/local/bin/hookshot-backup.sh
```

### Insufficient Disk Space

```bash
# Check available disk space
df -h /var/backups/hookshot

# Manually clean up old backups
find /var/backups/hookshot -name "hookshot-state-*.tar.gz" -mtime +30 -delete

# Reduce retention period
sudo systemctl edit hookshot-backup.service
# Set: Environment="HOOKSHOT_BACKUP_RETENTION=14"
```

## Advanced Configuration

### Multiple Backup Destinations

Create additional timer units for different destinations:

```bash
# Copy and modify for S3 backup
sudo cp hookshot-backup.service /etc/systemd/system/hookshot-backup-s3.service
sudo cp hookshot-backup.timer /etc/systemd/system/hookshot-backup-s3.timer

# Edit to use different script or settings
sudo systemctl edit hookshot-backup-s3.service
```

### Email Notifications on Failure

Configure systemd to send email on failure:

```bash
sudo systemctl edit hookshot-backup.service
```

Add:

```ini
[Unit]
OnFailure=status-email-admin@%n.service
```

Then create the email service (requires `mail` command):

```bash
sudo cat > /etc/systemd/system/status-email-admin@.service <<'EOF'
[Unit]
Description=Send status email for %i

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'systemctl status %i | mail -s "Backup Failure: %i" admin@example.com'
User=root
Group=systemd-journal
EOF

sudo systemctl daemon-reload
```

## See Also

- [Backup & Restore Guide](../../../docs/BACKUP_RESTORE.md)
- [Deployment Guide](../../../docs/DEPLOYMENT.md)
- [Systemd Timer Documentation](https://www.freedesktop.org/software/systemd/man/systemd.timer.html)
