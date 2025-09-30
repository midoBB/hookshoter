#!/bin/bash
#
# Automated Hookshot Backup Script
#
# This script creates daily backups of Hookshot's complete state and manages retention.
# It can be run via cron or systemd timer for automated backups.
#
# Usage:
#   ./backup-cron.sh
#
# Cron Example:
#   0 2 * * * /usr/local/bin/hookshot-backup.sh >> /var/log/hookshot-backup.log 2>&1
#

set -euo pipefail

# Configuration
BACKUP_DIR="${HOOKSHOT_BACKUP_DIR:-/var/backups/hookshot}"
RETENTION_DAYS="${HOOKSHOT_BACKUP_RETENTION:-30}"
HOOKSHOT_BIN="${HOOKSHOT_BIN:-/usr/local/bin/hookshot}"
LOG_FILE="${HOOKSHOT_BACKUP_LOG:-/var/log/hookshot-backup.log}"

# Notification settings (optional)
WEBHOOK_URL="${HOOKSHOT_BACKUP_WEBHOOK:-}"  # Slack/Discord webhook for notifications
EMAIL_TO="${HOOKSHOT_BACKUP_EMAIL:-}"        # Email address for notifications

# Timestamp for backup file
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DATE=$(date +%Y%m%d)
BACKUP_FILE="$BACKUP_DIR/hookshot-state-$DATE.tar.gz"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR: $1"

    # Send notification if configured
    if [ -n "$WEBHOOK_URL" ]; then
        curl -X POST "$WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"❌ Hookshot backup FAILED: $1\"}" \
            2>/dev/null || true
    fi

    if [ -n "$EMAIL_TO" ]; then
        echo "Hookshot backup failed: $1" | mail -s "Hookshot Backup Failure" "$EMAIL_TO" 2>/dev/null || true
    fi

    exit 1
}

# Success notification
success_notification() {
    local size=$1
    local duration=$2

    log "✓ Backup completed successfully: $BACKUP_FILE ($size, took ${duration}s)"

    if [ -n "$WEBHOOK_URL" ]; then
        curl -X POST "$WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"✅ Hookshot backup succeeded: $size, took ${duration}s\"}" \
            2>/dev/null || true
    fi
}

# Main backup process
main() {
    local start_time=$(date +%s)

    log "Starting Hookshot backup process"

    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DIR" ]; then
        log "Creating backup directory: $BACKUP_DIR"
        mkdir -p "$BACKUP_DIR" || error_exit "Failed to create backup directory"
    fi

    # Check if hookshot binary exists
    if [ ! -x "$HOOKSHOT_BIN" ]; then
        error_exit "Hookshot binary not found or not executable: $HOOKSHOT_BIN"
    fi

    # If backup for today already exists, add timestamp to filename
    if [ -f "$BACKUP_FILE" ]; then
        log "Backup for today already exists, using timestamped filename"
        BACKUP_FILE="$BACKUP_DIR/hookshot-state-$TIMESTAMP.tar.gz"
    fi

    # Create the backup
    log "Creating backup: $BACKUP_FILE"
    if ! "$HOOKSHOT_BIN" export "$BACKUP_FILE" >> "$LOG_FILE" 2>&1; then
        error_exit "Backup export command failed"
    fi

    # Verify backup file exists
    if [ ! -f "$BACKUP_FILE" ]; then
        error_exit "Backup file was not created: $BACKUP_FILE"
    fi

    # Get backup file size
    BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)

    # Verify backup integrity (quick check)
    if ! gzip -t "$BACKUP_FILE" 2>/dev/null; then
        error_exit "Backup file is corrupted (gzip test failed)"
    fi

    # Calculate duration
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Clean up old backups
    log "Cleaning up backups older than $RETENTION_DAYS days"
    find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" -mtime +$RETENTION_DAYS -delete || \
        log "Warning: Failed to clean up old backups"

    # Count remaining backups
    local backup_count=$(find "$BACKUP_DIR" -name "hookshot-state-*.tar.gz" | wc -l)
    log "Total backups in $BACKUP_DIR: $backup_count"

    # Success
    success_notification "$BACKUP_SIZE" "$duration"
}

# Run main function
main "$@"
