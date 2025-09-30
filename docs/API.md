# HTTP API Reference

## Overview

Hookshot provides a RESTful HTTP API for triggering deployments and monitoring service status. All deployment requests require HMAC-SHA256 authentication.

**Base URL**: Configured via `server.listen` in `config.toml` (default: `http://127.0.0.1:8080`)

## Authentication

### HMAC-SHA256 Signature

All `POST /deploy` requests must include an HMAC signature in the `X-Hub-Signature-256` header.

#### Signature Format

```
X-Hub-Signature-256: sha256=<hex_encoded_signature>
```

#### Generating Signatures

**Bash**:
```bash
PAYLOAD='{"service":"my-app","image":"registry.example.com/my-app:v1.0.0"}'
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

curl -X POST http://127.0.0.1:8080/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

**Python**:
```python
import hmac
import hashlib
import json
import requests

payload = {
    "service": "my-app",
    "image": "registry.example.com/my-app:v1.0.0"
}

payload_bytes = json.dumps(payload).encode('utf-8')
signature = hmac.new(
    hmac_secret.encode('utf-8'),
    payload_bytes,
    hashlib.sha256
).hexdigest()

response = requests.post(
    'http://127.0.0.1:8080/deploy',
    json=payload,
    headers={'X-Hub-Signature-256': f'sha256={signature}'}
)
```

**Node.js**:
```javascript
const crypto = require('crypto');
const axios = require('axios');

const payload = {
  service: 'my-app',
  image: 'registry.example.com/my-app:v1.0.0'
};

const payloadString = JSON.stringify(payload);
const signature = crypto
  .createHmac('sha256', hmacSecret)
  .update(payloadString)
  .digest('hex');

await axios.post('http://127.0.0.1:8080/deploy', payload, {
  headers: {
    'Content-Type': 'application/json',
    'X-Hub-Signature-256': `sha256=${signature}`
  }
});
```

## Endpoints

### POST /deploy

Initiates a deployment for a configured service.

#### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | Must be `application/json` |
| `X-Hub-Signature-256` | Yes | HMAC-SHA256 signature of request body |
| `X-Request-ID` | No | Optional correlation ID for tracking |

#### Request Body

```json
{
  "deploy_id": "deploy-20250130-0001",
  "service": "my-app",
  "image": "registry.example.com/my-app:v1.2.3",
  "previous_image": "registry.example.com/my-app:v1.2.2",
  "metadata": {
    "git_ref": "refs/heads/main",
    "git_sha": "abc123def456",
    "triggered_by": "github-actions",
    "pull_request": "42"
  },
  "overrides": {
    "env": {
      "LOG_LEVEL": "debug",
      "FEATURE_FLAGS": "new_ui=true"
    }
  },
  "dry_run": false
}
```

#### Request Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `deploy_id` | string | No | Unique deployment identifier (auto-generated if omitted) |
| `service` | string | Yes | Service name as defined in `services.toml` |
| `image` | string | Yes | Container image or version to deploy |
| `previous_image` | string | No | Previous image for rollback (recommended) |
| `metadata` | object | No | Arbitrary key-value metadata about the deployment |
| `overrides` | object | No | Configuration overrides (must be in `allowed_env_overrides`) |
| `overrides.env` | object | No | Environment variable overrides |
| `dry_run` | boolean | No | Validate request without executing (default: false) |

#### Response: Success (200 OK)

Deployment completed successfully:

```json
{
  "deploy_id": "deploy-20250130-0001",
  "service": "my-app",
  "status": "Succeeded",
  "image": "registry.example.com/my-app:v1.2.3",
  "started_at": "2025-01-30T20:00:00Z",
  "completed_at": "2025-01-30T20:01:30Z",
  "duration_seconds": 90,
  "status_url": "/status/deploy-20250130-0001",
  "log_url": "/logs/deploy-20250130-0001"
}
```

#### Response: Rolled Back (200 OK)

Deployment failed and rollback succeeded:

```json
{
  "deploy_id": "deploy-20250130-0002",
  "service": "my-app",
  "status": "RolledBack",
  "attempted_image": "registry.example.com/my-app:v1.3.0",
  "current_image": "registry.example.com/my-app:v1.2.3",
  "error": "Healthcheck failed: connection refused",
  "rollback_reason": "healthcheck_timeout",
  "started_at": "2025-01-30T21:00:00Z",
  "completed_at": "2025-01-30T21:03:00Z",
  "duration_seconds": 180,
  "status_url": "/status/deploy-20250130-0002",
  "log_url": "/logs/deploy-20250130-0002"
}
```

#### Response: Failed (500 Internal Server Error)

Deployment and rollback both failed:

```json
{
  "deploy_id": "deploy-20250130-0003",
  "service": "my-app",
  "status": "RollbackFailed",
  "error": "Deployment failed and rollback unsuccessful",
  "failure_stage": "rollback",
  "failure_detail": "systemctl restart failed: exit code 1",
  "requires_intervention": true,
  "started_at": "2025-01-30T22:00:00Z",
  "failed_at": "2025-01-30T22:05:00Z",
  "status_url": "/status/deploy-20250130-0003",
  "log_url": "/logs/deploy-20250130-0003"
}
```

#### Error Responses

**400 Bad Request** - Invalid request:
```json
{
  "error": "Service name cannot be empty",
  "code": "VALIDATION_ERROR",
  "details": null,
  "timestamp": "2025-01-30T20:00:00Z"
}
```

**401 Unauthorized** - Invalid or missing HMAC signature:
```json
{
  "error": "Invalid HMAC signature",
  "code": "AUTHENTICATION_ERROR",
  "details": null,
  "timestamp": "2025-01-30T20:00:00Z"
}
```

**404 Not Found** - Service not found or disabled:
```json
{
  "error": "Service 'unknown-service' not found or disabled",
  "code": "SERVICE_NOT_FOUND",
  "details": null,
  "timestamp": "2025-01-30T20:00:00Z"
}
```

**429 Too Many Requests** - Rate limit exceeded:
```json
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "details": "100 requests per minute allowed",
  "timestamp": "2025-01-30T20:00:00Z"
}
```

**503 Service Unavailable** - Concurrency limit reached:
```json
{
  "error": "Concurrency limit exceeded for service: 1/1 active deployments",
  "code": "CONCURRENCY_LIMIT_EXCEEDED",
  "details": null,
  "timestamp": "2025-01-30T20:00:00Z"
}
```

---

### GET /status/{deploy_id}

Retrieve detailed status for a specific deployment.

#### Path Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `deploy_id` | string | Unique deployment identifier |

#### Response: Success (200 OK)

```json
{
  "deploy_id": "deploy-20250130-001",
  "service": "my-app",
  "status": "Succeeded",
  "progress": {
    "phase": "COMPLETED",
    "steps_completed": 4,
    "steps_total": 4,
    "current_step": null
  },
  "timings": {
    "queued_at": "2025-01-30T20:00:00.123Z",
    "started_at": "2025-01-30T20:00:00.456Z",
    "completed_at": "2025-01-30T20:01:30.789Z",
    "duration_ms": 90333,
    "queue_time_ms": 333,
    "deploy_time_ms": 45000,
    "healthcheck_time_ms": 45000
  },
  "state_transitions": [
    {"state": "Queued", "at": "2025-01-30T20:00:00.123Z"},
    {"state": "Deploying", "at": "2025-01-30T20:00:00.456Z"},
    {"state": "HealthChecking", "at": "2025-01-30T20:00:45.456Z"},
    {"state": "Succeeded", "at": "2025-01-30T20:01:30.789Z"}
  ],
  "commands": [
    {
      "phase": "deploy",
      "step": "pull_image",
      "status": "success",
      "exit_code": 0,
      "duration_ms": 15000,
      "output_preview": "Pulling registry.example.com/my-app:v1.2.3..."
    },
    {
      "phase": "deploy",
      "step": "restart_service",
      "status": "success",
      "exit_code": 0,
      "duration_ms": 5000,
      "output_preview": "Restarted my-app.service"
    }
  ],
  "logs_url": "/logs/deploy-20250130-001",
  "metadata": {
    "git_ref": "refs/heads/main",
    "git_sha": "abc123def456"
  }
}
```

#### Deployment Status Values

| Status | Description |
|--------|-------------|
| `Queued` | Deployment is waiting to start |
| `Validating` | Request is being validated |
| `Deploying` | Deployment commands are executing |
| `HealthChecking` | Health checks are running |
| `Succeeded` | Deployment completed successfully |
| `Failed` | Deployment failed |
| `RollingBack` | Rollback is in progress |
| `RolledBack` | Rollback completed successfully |
| `RollbackFailed` | Rollback failed, manual intervention required |

---

### GET /health

Health check endpoint for monitoring and load balancers.

#### Response: Success (200 OK)

```json
{
  "status": "healthy",
  "version": "0.0.1",
  "build": "2025-01-30T15:00:00Z",
  "uptime_seconds": 3600,
  "deployment_queue": {
    "pending": 0,
    "active": 1,
    "workers": 4
  },
  "database": {
    "connected": true,
    "size_bytes": 52428800
  },
  "checks": {
    "database": "ok",
    "disk_space": "ok",
    "worker_pool": "ok"
  }
}
```

#### Health Check Fields

| Field | Description |
|-------|-------------|
| `status` | Overall health status (`healthy` or `unhealthy`) |
| `version` | Application version |
| `build` | Build timestamp |
| `uptime_seconds` | Seconds since server started |
| `deployment_queue.pending` | Queued deployments waiting to start |
| `deployment_queue.active` | Currently executing deployments |
| `deployment_queue.workers` | Total worker threads available |
| `database.connected` | Database connectivity status |
| `database.size_bytes` | Database file size in bytes |
| `checks.*` | Individual health check results (`ok` or `failed`) |

#### Caching

Health responses are cached for `status_cache_seconds` (default: 10) to reduce load from frequent polling.

---

### GET /ready

Kubernetes-style readiness probe. Returns 200 if ready to accept requests, 503 if not ready.

#### Response: Ready (200 OK)

```json
{
  "ready": true,
  "message": null
}
```

#### Response: Not Ready (503 Service Unavailable)

```json
{
  "ready": false,
  "message": "Database not available"
}
```

---

### GET /metrics

Prometheus metrics endpoint.

#### Response: Success (200 OK)

**Content-Type**: `text/plain; version=0.0.4; charset=utf-8`

```prometheus
# HELP deployment_total Total number of deployments
# TYPE deployment_total counter
deployment_total{service="my-app",status="success"} 142
deployment_total{service="my-app",status="failed"} 3
deployment_total{service="my-app",status="rolled_back"} 2

# HELP deployment_duration_seconds Time spent in deployment phases
# TYPE deployment_duration_seconds histogram
deployment_duration_seconds_bucket{service="my-app",phase="deploy",le="30"} 140
deployment_duration_seconds_bucket{service="my-app",phase="deploy",le="60"} 142
deployment_duration_seconds_bucket{service="my-app",phase="deploy",le="120"} 145
deployment_duration_seconds_sum{service="my-app",phase="deploy"} 4250.5
deployment_duration_seconds_count{service="my-app",phase="deploy"} 145

# HELP deployment_active Current active deployments
# TYPE deployment_active gauge
deployment_active{service="my-app"} 1

# HELP rollback_total Total number of rollbacks
# TYPE rollback_total counter
rollback_total{service="my-app",reason="healthcheck_failed"} 2

# HELP http_requests_total Total HTTP requests
# TYPE http_requests_total counter
http_requests_total{method="POST",path="/deploy",status="200"} 450
http_requests_total{method="GET",path="/health",status="200"} 12045

# HELP http_request_duration_seconds HTTP request latencies
# TYPE http_request_duration_seconds histogram
http_request_duration_seconds_bucket{method="POST",path="/deploy",le="0.005"} 450
http_request_duration_seconds_bucket{method="POST",path="/deploy",le="0.01"} 455
http_request_duration_seconds_sum{method="POST",path="/deploy"} 2.5
http_request_duration_seconds_count{method="POST",path="/deploy"} 455
```

#### Available Metrics

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `deployment_total` | counter | `service`, `status` | Total deployments by status |
| `deployment_duration_seconds` | histogram | `service`, `phase` | Deployment phase durations |
| `deployment_active` | gauge | `service` | Currently active deployments |
| `rollback_total` | counter | `service`, `reason` | Total rollbacks |
| `command_execution_duration_seconds` | histogram | `service`, `command` | Command execution times |
| `healthcheck_failures_total` | counter | `service` | Failed healthchecks |
| `http_requests_total` | counter | `method`, `path`, `status` | HTTP request counters |
| `http_request_duration_seconds` | histogram | `method`, `path` | HTTP request latencies |

---

### GET /services

List all configured services and their current state.

#### Response: Success (200 OK)

```json
{
  "services": [
    {
      "name": "my-app",
      "enabled": true,
      "current_image": "registry.example.com/my-app:v1.2.3",
      "last_deploy": {
        "deploy_id": "deploy-20250130-001",
        "status": "Succeeded",
        "completed_at": "2025-01-30T20:01:30Z"
      },
      "health": "Healthy",
      "locked": false,
      "stats": {
        "total_deploys": 145,
        "success_rate": 0.979,
        "avg_duration_seconds": 87,
        "last_failure": "2025-01-28T14:30:00Z"
      }
    },
    {
      "name": "api-service",
      "enabled": true,
      "current_image": "registry.example.com/api:v2.1.0",
      "last_deploy": {
        "deploy_id": "deploy-20250130-015",
        "status": "Succeeded",
        "completed_at": "2025-01-30T19:45:00Z"
      },
      "health": "Healthy",
      "locked": true,
      "stats": {
        "total_deploys": 89,
        "success_rate": 1.0,
        "avg_duration_seconds": 62,
        "last_failure": null
      }
    }
  ]
}
```

#### Service Health Values

| Value | Description |
|-------|-------------|
| `Unknown` | No recent health check data |
| `Healthy` | Service is functioning normally |
| `Unhealthy` | Service is failing health checks |
| `Degraded` | Service is partially functional |

---

## Webhook Payload Format

For CI/CD integration, construct deployment payloads as follows:

### GitHub Actions Example

```yaml
- name: Deploy
  env:
    DEPLOY_URL: ${{ secrets.DEPLOY_URL }}
    HMAC_SECRET: ${{ secrets.HMAC_SECRET }}
  run: |
    PAYLOAD=$(jq -nc \
      --arg service "my-app" \
      --arg image "registry.example.com/my-app:sha-${{ github.sha }}" \
      --arg previous "registry.example.com/my-app:sha-${{ github.event.before }}" \
      --arg git_ref "${{ github.ref }}" \
      --arg git_sha "${{ github.sha }}" \
      --arg actor "${{ github.actor }}" \
      '{
        service: $service,
        image: $image,
        previous_image: $previous,
        metadata: {
          git_ref: $git_ref,
          git_sha: $git_sha,
          triggered_by: $actor,
          workflow: "${{ github.workflow }}",
          run_id: "${{ github.run_id }}"
        }
      }')

    SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

    curl -X POST "$DEPLOY_URL/deploy" \
      -H "Content-Type: application/json" \
      -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
      -H "X-Request-ID: gh-${{ github.run_id }}" \
      -d "$PAYLOAD"
```

### GitLab CI Example

```yaml
deploy:
  stage: deploy
  script:
    - |
      PAYLOAD=$(jq -nc \
        --arg service "$CI_PROJECT_NAME" \
        --arg image "$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA" \
        --arg previous "$CI_REGISTRY_IMAGE:$CI_COMMIT_BEFORE_SHA" \
        --arg ref "$CI_COMMIT_REF_NAME" \
        --arg sha "$CI_COMMIT_SHA" \
        --arg user "$GITLAB_USER_LOGIN" \
        '{
          service: $service,
          image: $image,
          previous_image: $previous,
          metadata: {
            git_ref: $ref,
            git_sha: $sha,
            triggered_by: $user,
            pipeline_id: "'$CI_PIPELINE_ID'",
            job_id: "'$CI_JOB_ID'"
          }
        }')

      SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

      curl -X POST "$DEPLOY_URL/deploy" \
        -H "Content-Type: application/json" \
        -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
        -H "X-Request-ID: gl-$CI_PIPELINE_ID" \
        -d "$PAYLOAD"
```

## Rate Limiting

Rate limiting is applied per source IP address:

- **Default**: 100 requests per minute per IP
- **Configurable**: Set `security.rate_limit` in `config.toml`
- **Response**: HTTP 429 with `Retry-After` header

```json
{
  "error": "Rate limit exceeded",
  "code": "RATE_LIMIT_EXCEEDED",
  "details": "100 requests per minute allowed",
  "timestamp": "2025-01-30T20:00:00Z"
}
```

## IP Allowlisting

When `security.allowed_ips` is configured, requests from non-allowed IPs are rejected:

```json
{
  "error": "Access denied from IP address",
  "code": "ACCESS_DENIED",
  "details": "203.0.113.5 not in allowlist",
  "timestamp": "2025-01-30T20:00:00Z"
}
```

## Error Handling

All errors follow a consistent format:

```json
{
  "error": "Human-readable error message",
  "code": "MACHINE_READABLE_CODE",
  "details": "Additional context (optional)",
  "timestamp": "2025-01-30T20:00:00Z"
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request parameters |
| `AUTHENTICATION_ERROR` | 401 | Invalid or missing HMAC signature |
| `ACCESS_DENIED` | 403 | IP address not in allowlist |
| `SERVICE_NOT_FOUND` | 404 | Service doesn't exist or is disabled |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `CONCURRENCY_LIMIT_EXCEEDED` | 503 | Max concurrent deployments reached |
| `SERVICE_LOCKED` | 503 | Service is locked by another deployment |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

## Best Practices

1. **Always include `previous_image`**: Enables successful rollbacks
2. **Use meaningful `deploy_id`**: Include timestamps or CI build numbers
3. **Add rich metadata**: Git refs, PR numbers, and triggering user for audit trails
4. **Monitor metrics**: Set up Prometheus scraping and alerting
5. **Handle all response codes**: Implement retry logic for 503 errors
6. **Use `X-Request-ID` header**: For request tracing across systems
7. **Validate before deploying**: Use `dry_run: true` to test configurations