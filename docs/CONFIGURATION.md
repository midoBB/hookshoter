# Configuration Reference Guide

## Overview

The Deploy Receiver uses two separate TOML configuration files:
- **System Configuration** (`config.toml`): Runtime behavior and global settings
- **Services Configuration** (`services.toml`): Per-service deployment definitions

## System Configuration (`config.toml`)

### Server Configuration

```toml
[server]
# Network binding configuration
listen = "127.0.0.1:8080"              # IP:PORT or just :PORT
worker_threads = 4                      # Deployment worker thread pool size
max_request_size = "1MB"               # Maximum HTTP request body size
request_timeout = 30                   # HTTP request timeout (seconds)
shutdown_timeout = 300                 # Graceful shutdown timeout (seconds)
```

#### `listen`
- **Type**: String
- **Default**: `"127.0.0.1:8080"`
- **Format**: `"host:port"` or `":port"`
- **Purpose**: Defines the network interface and port for the HTTP server
- **Security**: Use `127.0.0.1` for localhost-only access, `0.0.0.0` for all interfaces
- **Examples**:
  - `"127.0.0.1:8080"` - Localhost only
  - `"0.0.0.0:8080"` - All interfaces (use with caution)
  - `":8080"` - All interfaces on port 8080

#### `worker_threads`
- **Type**: Integer
- **Default**: `4`
- **Range**: `1-16`
- **Purpose**: Number of concurrent deployment workers
- **Sizing**: Typically 1-2x CPU cores, consider I/O wait time
- **Impact**: Higher values = more concurrent deployments but more resource usage

#### `max_request_size`
- **Type**: String (with unit)
- **Default**: `"1MB"`
- **Units**: `"KB"`, `"MB"`, `"GB"`
- **Purpose**: Prevents DoS via large request bodies
- **Recommendation**: `"1MB"` sufficient for most deployment payloads

### Secrets Loading

```toml
[secrets]
# Secret loading configuration
source = "auto"                        # auto, env, file, systemd, or array for multiple
sources_priority = ["systemd", "file", "env"]  # Order to try sources (first wins)
secrets_file = "/etc/hookshot/secrets"  # Path to secrets file (key=value format)
required_secrets = ["hmac_key"]        # Secrets that must be present for startup
reload_interval = 300                   # Reload file-based secrets every N seconds (0 = disabled)
secret_prefix = "DEPLOY_RECEIVER_"     # Prefix for environment variables
```

#### `source`

-   **Type**: String enum or array
-   **Values**: `"auto"`, `"env"`, `"file"`, `"systemd"`, or array like `["systemd", "env"]`
-   **Default**: `"auto"`
-   **Purpose**: Defines where to load secrets from
-   **Auto mode**: Tries sources in order defined by `sources_priority`

#### `sources_priority`

-   **Type**: Array of strings
-   **Default**: `["systemd", "file", "env"]`
-   **Purpose**: Order to try secret sources when using auto mode
-   **Note**: First successful source wins

#### `secrets_file`

-   **Type**: String (path)
-   **Default**: `"/etc/hookshot/secrets"`
-   **Format**: Key=value pairs, one per line, # for comments
-   Example content:

```ini
# HMAC key for webhook authentication
  hmac_key=d7e8f9a0b1c2d3e4f5g6h7i8j9k0l1m2

  # Notification webhook URL
  slack_webhook=https://hooks.slack.com/services/XXX
```

#### `required_secrets`

-   **Type**: Array of strings
-   **Default**: `["hmac_key"]`
-   **Purpose**: List of secrets that must be present for the application to start
-   **Note**: Missing required secrets cause startup failure

#### `reload_interval`

-   **Type**: Integer (seconds)
-   **Default**: `300` (5 minutes)
-   **Purpose**: How often to check file-based secrets for changes
-   **Note**: Set to `0` to disable reloading

#### `secret_prefix`

-   **Type**: String
-   **Default**: `"DEPLOY_RECEIVER_"`
-   **Purpose**: Prefix for environment variable names
-   **Example**: `DEPLOY_RECEIVER_HMAC_KEY` maps to `hmac_key`

### Security Configuration

```toml
[security]
# Network access control
allowed_ips = []                       # Empty = allow all, ["CIDR", ...]
rate_limit = 100                       # Requests per minute per IP
```

#### `allowed_ips`
- **Type**: Array of strings
- **Default**: `[]` (allow all)
- **Format**: CIDR notation (`"192.168.1.0/24"`)
- **Purpose**: IP-based access control
- **Examples**:
  ```toml
  allowed_ips = [
      "10.0.0.0/8",          # Private network
      "192.168.1.0/24",      # Local subnet
      "203.0.113.5/32"       # Specific CI server
  ]
  ```

#### `rate_limit`
- **Type**: Integer
- **Default**: `100`
- **Units**: Requests per minute per IP
- **Purpose**: Prevent DoS attacks
- **Recommendation**: `100` for normal CI usage, adjust based on deployment frequency

### Storage Configuration

```toml
[storage]
# Database and file storage
data_dir = "/var/lib/hookshot"   # Database and state directory

[storage.retention]
successful_deploys = 100               # Keep last N successful deploys per service
failed_deploys = 50                    # Keep last N failed deploys per service
```

#### `data_dir`
- **Type**: String (path)
- **Default**: `"/var/lib/hookshot"`
- **Purpose**: Base directory for database and persistent state
- **Permissions**: Must be writable by hookshot user
- **Contents**: `state.redb` (database), lock files, temporary state
- **Backup**: This directory is included in `hookshot export` backups
- **Important**: Ensure this path is accessible during backup operations (see [Backup & Restore Guide](BACKUP_RESTORE.md))

#### `retention.successful_deploys`
- **Type**: Integer
- **Default**: `100`
- **Purpose**: Limit database growth by keeping only recent successful deployments
- **Storage**: ~1KB per deployment record
- **Recommendation**: 50-200 based on deployment frequency and debugging needs

#### `retention.failed_deploys`
- **Type**: Integer
- **Default**: `50`
- **Purpose**: Keep failed deployment history for troubleshooting
- **Note**: Failed deployments often contain critical debugging information

### Logging Configuration

```toml
[logging]
level = "info"                         # trace, debug, info, warn, error
format = "json"                        # json or pretty
directory = "/var/log/hookshot" # Log file directory

[logging.rotation]
max_size = "100MB"                     # Rotate when log reaches this size
max_files = 10                         # Keep this many rotated log files
```

#### `level`
- **Type**: String enum
- **Values**: `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`
- **Default**: `"info"`
- **Purpose**: Control logging verbosity
- **Production**: Use `"info"` or `"warn"`
- **Debug**: Use `"debug"` or `"trace"`

#### `format`
- **Type**: String enum
- **Values**: `"json"`, `"pretty"`
- **Default**: `"json"`
- **Purpose**: Log output format
- **Production**: Use `"json"` for structured logging and log aggregation
- **Development**: Use `"pretty"` for human-readable logs

### Monitoring Configuration

```toml
[monitoring]
metrics_enabled = true                 # Enable Prometheus metrics endpoint
metrics_path = "/metrics"              # Metrics endpoint path
health_path = "/health"                # Health check endpoint path
status_cache_seconds = 10              # Cache health check responses
```

#### `metrics_enabled`
- **Type**: Boolean
- **Default**: `true`
- **Purpose**: Enable/disable Prometheus metrics collection
- **Note**: Minimal performance impact when enabled

#### `metrics_path`
- **Type**: String
- **Default**: `"/metrics"`
- **Purpose**: HTTP path for Prometheus metrics endpoint
- **Security**: Consider using non-standard path for security through obscurity

### Limits Configuration

```toml
[limits]
# Concurrency limits
max_concurrent_total = 10              # Global concurrent deployment limit
max_concurrent_per_service = 1         # Per-service concurrent deployment limit

# Timeout limits
deployment_timeout = 1800              # Global deployment timeout (seconds)
command_timeout = 300                  # Default per-command timeout (seconds)
lock_timeout = 60                      # Service lock acquisition timeout
```

#### `max_concurrent_total`
- **Type**: Integer
- **Default**: `10`
- **Range**: `1-50`
- **Purpose**: Prevent resource exhaustion from too many simultaneous deployments
- **Sizing**: Consider available CPU, memory, and I/O capacity

#### `max_concurrent_per_service`
- **Type**: Integer
- **Default**: `1`
- **Recommendation**: Keep at `1` to prevent deployment race conditions
- **Advanced**: Set to `2-3` only if deployments are fully idempotent

#### `deployment_timeout`
- **Type**: Integer (seconds)
- **Default**: `1800` (30 minutes)
- **Purpose**: Maximum wall-clock time for entire deployment workflow
- **Includes**: Deploy + health check + rollback time
- **Sizing**: Should accommodate your slowest expected deployment

#### `command_timeout`
- **Type**: Integer (seconds)
- **Default**: `300` (5 minutes)
- **Purpose**: Default timeout for individual commands
- **Override**: Can be overridden per-service or per-command
- **Typical values**:
  - Container pulls: 30-300 seconds
  - Service restarts: 10-60 seconds
  - Health checks: 5-30 seconds

### Notifications Configuration

```toml
[notifications]
enabled = false                        # Enable webhook notifications

[notifications.webhook]
use_secrets = false                    # Load webhook URLs from secrets manager
on_failure = "https://hooks.slack.com/services/..."
on_rollback = "https://hooks.slack.com/services/..."
on_success = "https://hooks.slack.com/services/..."  # Optional
timeout = 5                            # Webhook timeout (seconds)
```

#### `use_secrets`
- **Type**: Boolean
- **Default**: `false`
- **Purpose**: When enabled, webhook URLs are loaded from the secrets manager instead of the configuration file
- **Security**: Allows storing webhook URLs in secure secret storage rather than plain text configuration
- **Secret Keys**: When `use_secrets = true`, the following secret keys are loaded:
  - `notifications.webhook.on_failure`
  - `notifications.webhook.on_rollback`
  - `notifications.webhook.on_success` (optional)
- **Fallback**: If a secret is not found, the corresponding config value is used as fallback

## Services Configuration (`services.toml`)

### Global Defaults

```toml
[defaults]
working_dir = "/srv"                   # Default working directory
command_timeout = 120                  # Default command timeout
healthcheck_timeout = 60               # Default health check timeout
rollback_enabled = true                # Enable rollback by default
```

### Service Definition Structure

```toml
[[service]]
name = "service-name"                  # Unique service identifier
description = "Human readable description"
enabled = true                         # Enable/disable this service
working_dir = "/srv/service-name"      # Service-specific working directory

# Environment variables for all commands
[service.env]
NODE_ENV = "production"
PORT = "3000"
DATABASE_URL = "postgres://..."

# Security configuration
[service.security]
allowed_image_pattern = '^registry\.example\.com/service-name:(v\d+\.\d+\.\d+|sha-[a-f0-9]{40})$'
allowed_env_overrides = ["LOG_LEVEL", "FEATURE_FLAGS"]

# GitHub webhook integration (optional)
[service.github]
repo = "myorg/service-name"

# Deployment phase
[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "service-name.service"]
]

# Health checking phase
[service.healthcheck]
initial_delay = 5                      # Wait before first check
interval = 3                           # Seconds between checks
max_attempts = 20                      # Total attempts before giving up
success_threshold = 3                  # Consecutive successes required
commands = [
    ["curl", "-fsS", "http://127.0.0.1:3000/health"]
]

# Rollback phase
[service.rollback]
enabled = true
max_attempts = 2
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "service-name.service"]
]

# Lifecycle hooks
[service.hooks]
pre_deploy = []                        # Before deployment starts
post_deploy = []                       # After successful deployment
on_failure = []                        # On any failure

# Custom template variables
[service.templates]
container_name = "{{SERVICE}}-{{TIMESTAMP}}"
backup_tag = "rollback-{{DEPLOY_ID}}"
```

### Service Fields Reference

#### Core Service Configuration

##### `name`
- **Type**: String
- **Required**: Yes
- **Format**: Alphanumeric, hyphens, underscores only
- **Max Length**: 32 characters
- **Purpose**: Unique service identifier
- **Example**: `"web-frontend"`, `"api-service"`

##### `description`
- **Type**: String
- **Required**: No
- **Purpose**: Human-readable service description
- **Example**: `"Next.js frontend application"`

##### `enabled`
- **Type**: Boolean
- **Default**: `true`
- **Purpose**: Enable/disable service deployments
- **Use case**: Temporarily disable services during maintenance

##### `working_dir`
- **Type**: String (path)
- **Default**: Inherited from `[defaults]`
- **Purpose**: Command execution directory
- **Security**: Must be within allowed paths
- **Example**: `"/srv/web-frontend"`

#### Environment Configuration

##### `[service.env]`
- **Type**: Key-value pairs
- **Purpose**: Environment variables for all commands
- **Security**: Avoid secrets in configuration files
- **Example**:
  ```toml
  [service.env]
  NODE_ENV = "production"
  LOG_LEVEL = "info"
  METRICS_PORT = "9090"
  ```

#### Security Configuration

##### `allowed_image_pattern`
- **Type**: String (regex)
- **Required**: Yes
- **Purpose**: Whitelist allowed container images
- **Format**: Valid Rust regex pattern
- **Security**: Prevents deployment of unauthorized images
- **Examples**:
  ```toml
  # Semver tags only
  allowed_image_pattern = '^registry\.internal/app:(v\d+\.\d+\.\d+)$'

  # Semver or commit SHA
  allowed_image_pattern = '^registry\.internal/app:(v\d+\.\d+\.\d+|sha-[a-f0-9]{40})$'

  # Multiple registries
  allowed_image_pattern = '^(registry\.internal|ghcr\.io/myorg)/app:.*$'
  ```

##### `allowed_env_overrides`
- **Type**: Array of strings
- **Default**: `[]` (no overrides allowed)
- **Purpose**: Whitelist environment variables that can be overridden via API
- **Security**: Prevents injection of sensitive variables
- **Example**:
  ```toml
  allowed_env_overrides = [
      "LOG_LEVEL",
      "DEBUG",
      "FEATURE_FLAGS",
      "TRACE_ENABLED"
  ]
  ```

#### GitHub Integration Configuration

##### `[service.github]`
Optional GitHub repository mapping for webhook routing.

- **Type**: Optional subsection
- **Purpose**: Maps GitHub repositories to service names for direct webhook integration
- **Fields**:
  - `repo`: GitHub repository in `owner/repo` format

**Example**:
```toml
[service.github]
repo = "myorg/web-frontend"
```

##### `repo`
- **Type**: String
- **Required**: Yes (if `[service.github]` section is present)
- **Format**: `"owner/repo"` (e.g., `"myorg/my-app"`)
- **Validation**:
  - Must contain exactly one forward slash
  - Owner and repo names must not be empty
  - Only alphanumeric characters, hyphens, underscores, and periods are allowed
  - Each repository can only be mapped to one service
- **Purpose**: Identifies the GitHub repository that triggers deployments for this service
- **Examples**:
  ```toml
  # Basic repository mapping
  [service.github]
  repo = "acme-corp/web-frontend"

  # Organization with multiple words (using hyphens)
  [service.github]
  repo = "my-org/api-service"

  # Repository with periods
  [service.github]
  repo = "myorg/service.name"
  ```

**Notes**:
- Repository names are case-sensitive and must match exactly as they appear on GitHub
- Duplicate repository mappings across services will cause validation errors
- This configuration is used by GitHub webhook handlers to route deployment requests to the correct service
- If no GitHub configuration is provided, the service can still be deployed via the API using the service name directly

#### Deployment Configuration

##### `[service.deploy]`
Commands executed sequentially during deployment.

**Structure**:
```toml
[service.deploy]
commands = [
    ["command", "arg1", "arg2"],
    ["another-command", "{{TEMPLATE_VAR}}"]
]
timeout = 300                          # Override default timeout
retries = 0                            # Number of retries (default: 0)
critical = true                        # Fail deployment if command fails
```

**Common Patterns**:
```toml
# Container deployment
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["podman", "run", "--rm", "--entrypoint=/bin/true", "{{IMAGE}}"],  # Smoke test
    ["systemctl", "--user", "restart", "myapp.service"]
]

# Binary deployment
commands = [
    ["wget", "-O", "/tmp/app-{{DEPLOY_ID}}", "{{DOWNLOAD_URL}}"],
    ["chmod", "+x", "/tmp/app-{{DEPLOY_ID}}"],
    ["sudo", "systemctl", "stop", "myapp"],
    ["sudo", "cp", "/tmp/app-{{DEPLOY_ID}}", "/usr/local/bin/myapp"],
    ["sudo", "systemctl", "start", "myapp"]
]
```

#### Health Check Configuration

##### `[service.healthcheck]`

**Fields**:
- `initial_delay`: Seconds to wait before first health check
- `interval`: Seconds between health check attempts
- `max_attempts`: Maximum number of health check attempts
- `success_threshold`: Consecutive successful checks required
- `timeout`: Timeout for individual health check commands
- `commands`: Array of commands to execute for health checking

**Examples**:
```toml
# HTTP health check
[service.healthcheck]
initial_delay = 10
interval = 5
max_attempts = 12
success_threshold = 2
commands = [
    ["curl", "-fsS", "--max-time", "10", "http://127.0.0.1:8080/health"]
]

# TCP port check
[service.healthcheck]
commands = [
    ["nc", "-z", "127.0.0.1", "8080"]
]

# Application-specific check
[service.healthcheck]
commands = [
    ["./health-check.sh"],
    ["systemctl", "--user", "is-active", "myapp.service"]
]
```

#### Rollback Configuration

##### `[service.rollback]`

**Fields**:
- `enabled`: Enable automatic rollback on deployment failure
- `max_attempts`: Maximum rollback retry attempts
- `timeout`: Timeout for rollback commands
- `commands`: Commands to execute for rollback

**Examples**:
```toml
# Container rollback
[service.rollback]
enabled = true
max_attempts = 3
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "myapp.service"]
]

# Symlink rollback
[service.rollback]
enabled = true
commands = [
    ["ln", "-sfn", "{{PREVIOUS_VERSION_PATH}}", "/srv/myapp/current"],
    ["systemctl", "--user", "restart", "myapp.service"]
]
```

#### Lifecycle Hooks

##### `[service.hooks]`

**Hook Types**:
- `pre_deploy`: Execute before deployment starts
- `post_deploy`: Execute after successful deployment
- `on_failure`: Execute on any deployment failure

**Examples**:
```toml
[service.hooks]
pre_deploy = [
    ["echo", "Starting deployment of {{SERVICE}} version {{IMAGE}}"],
    ["./backup-database.sh"]
]

post_deploy = [
    ["echo", "Deployment successful"],
    ["./cleanup-old-versions.sh"],
    ["curl", "-X", "POST", "{{WEBHOOK_URL}}", "-d", "Deployment completed"]
]

on_failure = [
    ["echo", "Deployment failed for {{SERVICE}}"],
    ["./alert-team.sh", "{{DEPLOY_ID}}", "{{ERROR_MESSAGE}}"]
]
```

### Template Variables

Available template variables in commands:

#### Built-in Variables
- `{{IMAGE}}`: Requested container image
- `{{PREVIOUS_IMAGE}}`: Previous container image (for rollbacks)
- `{{SERVICE}}`: Service name
- `{{DEPLOY_ID}}`: Unique deployment identifier
- `{{TIMESTAMP}}`: Unix timestamp
- `{{DATE}}`: ISO 8601 date (YYYY-MM-DD)
- `{{DATETIME}}`: ISO 8601 datetime

#### Custom Variables
Define custom template variables in the `[service.templates]` section:

```toml
[service.templates]
container_name = "{{SERVICE}}-{{TIMESTAMP}}"
backup_path = "/backups/{{SERVICE}}/{{DATE}}"
config_file = "/etc/{{SERVICE}}/{{ENVIRONMENT}}.conf"
```

Use custom variables in commands:
```toml
commands = [
    ["podman", "run", "--name", "{{container_name}}", "{{IMAGE}}"],
    ["cp", "config.toml", "{{config_file}}"]
]
```

## Configuration Examples

### Minimal Configuration

**`config.toml`**:
```toml
[server]
listen = "127.0.0.1:8080"

[storage]
data_dir = "/var/lib/hookshot"
```

**`services.toml`**:
```toml
[[service]]
name = "simple-app"
enabled = true

[service.security]
allowed_image_pattern = '^localhost/simple-app:.*$'

[service.deploy]
commands = [["echo", "Deployed {{IMAGE}}"]]

[service.healthcheck]
commands = [["echo", "healthy"]]
```

### Production Configuration

**`config.toml`**:
```toml
[server]
listen = "127.0.0.1:8080"
worker_threads = 8
request_timeout = 60
shutdown_timeout = 300

[security]
allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
rate_limit = 200

[storage]
data_dir = "/var/lib/hookshot"

[storage.retention]
successful_deploys = 200
failed_deploys = 100

[logging]
level = "info"
format = "json"
directory = "/var/log/hookshot"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"

[limits]
max_concurrent_total = 12
max_concurrent_per_service = 1
deployment_timeout = 2400
command_timeout = 600

[notifications]
enabled = true

[notifications.webhook]
on_failure = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
on_rollback = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
timeout = 10
```

## Configuration Validation

### Validation Rules

The system validates configuration on startup:

1. **Network Configuration**: Valid IP addresses and ports
2. **Path Configuration**: Accessible directories with proper permissions
3. **Regex Patterns**: Valid regular expressions in `allowed_image_pattern`
4. **Time Values**: Positive integers for timeouts and intervals
5. **Resource Limits**: Reasonable values for concurrency and memory limits

### Validation Command

```bash
# Validate configuration files
hookshot validate

# Validate specific files
hookshot --config /path/to/config.toml --services /path/to/services.toml validate
```

### Common Validation Errors

1. **Invalid Listen Address**: `"invalid:port:format"`
2. **Inaccessible Directory**: Permission denied on `data_dir`
3. **Invalid Regex**: Syntax error in `allowed_image_pattern`
4. **Circular Dependencies**: Service depends on itself
5. **Resource Limits**: Negative or zero timeout values

## Best Practices

### Security Best Practices

1. **Use IP Allowlisting**: Restrict access to known CI/CD systems
2. **Strong HMAC Secrets**: Use 32+ byte random secrets
3. **Restrictive Image Patterns**: Only allow trusted registries and tags
4. **Minimal Environment Overrides**: Only allow safe environment variables
5. **Regular Secret Rotation**: Change HMAC secrets periodically

### Performance Best Practices

1. **Right-size Worker Threads**: 1-2x CPU cores for typical workloads
2. **Appropriate Timeouts**: Balance responsiveness vs. deployment complexity
3. **Log Rotation**: Prevent disk space issues with log retention
4. **Database Cleanup**: Configure appropriate retention policies

### Operational Best Practices

1. **Monitor Metrics**: Set up Prometheus scraping and alerting
2. **Structured Logging**: Use JSON format for log aggregation
3. **Health Checks**: Implement comprehensive service health checks
4. **Graceful Shutdowns**: Use appropriate shutdown timeouts
5. **Configuration Management**: Version control configuration files
