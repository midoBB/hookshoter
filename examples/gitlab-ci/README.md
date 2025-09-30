# GitLab CI/CD Integration

This directory contains examples for integrating Hookshot with GitLab CI/CD.

## Setup

### 1. Add CI/CD Variables

Go to your GitLab project → Settings → CI/CD → Variables, and add:

| Variable Name | Description | Protected | Masked |
|---------------|-------------|-----------|--------|
| `HOOKSHOT_URL` | Your Hookshot deployment URL | ✅ | ❌ |
| `HOOKSHOT_HMAC_SECRET` | HMAC key from `/etc/hookshot/secrets` | ✅ | ✅ |
| `CI_REGISTRY_USER` | Container registry username | ✅ | ❌ |
| `CI_REGISTRY_PASSWORD` | Container registry password/token | ✅ | ✅ |

Example values:
- `HOOKSHOT_URL`: `https://deploy.example.com`
- `HOOKSHOT_HMAC_SECRET`: `your-hmac-key-here`

### 2. Add Pipeline Configuration

Copy `.gitlab-ci.yml` to the root of your repository.

### 3. Configure Service in Hookshot

Ensure your services are configured in `/etc/hookshot/services.toml`:

```toml
# Staging environment
[[service]]
name = "my-app-staging"
enabled = true

[service.security]
allowed_image_pattern = '^registry\.example\.com/my-app:.*$'

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app-staging.service"]
]

[service.healthcheck]
commands = [
    ["curl", "-fsS", "http://127.0.0.1:8080/health"]
]

# Production environment
[[service]]
name = "my-app"
enabled = true

[service.security]
allowed_image_pattern = '^registry\.example\.com/my-app:v\d+\.\d+\.\d+$'

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app.service"]
]

[service.healthcheck]
initial_delay = 10
commands = [
    ["curl", "-fsS", "http://127.0.0.1:3000/health"]
]

[service.rollback]
enabled = true
commands = [
    ["podman", "pull", "{{PREVIOUS_IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app.service"]
]
```

### 4. Allow GitLab Runner IP Ranges

Add GitLab runner IP addresses to Hookshot allowlist:

```toml
# /etc/hookshot/config.toml
[security]
allowed_ips = [
    "192.168.1.0/24",  # Your GitLab runners
]
```

## Pipeline Stages

The example pipeline includes four stages:

1. **Build**: Builds and pushes container image
2. **Test**: Runs automated tests
3. **Deploy to Staging**: Automatically deploys `develop` branch to staging
4. **Deploy to Production**: Manually triggered deployment to production

## Deployment Flows

### Staging Deployment

```
develop branch push → build → test → deploy:staging (automatic)
```

Commits to `develop` branch automatically deploy to staging after passing tests.

### Production Deployment

```
main branch push / tag push → build → test → deploy:production (manual)
```

Deployments to production require manual approval via GitLab UI.

### Rollback

```
Manual trigger → rollback:production (with ROLLBACK_TO_IMAGE variable)
```

Rollback requires setting the `ROLLBACK_TO_IMAGE` CI/CD variable.

## Advanced Configuration

### Environment-Specific Variables

Define environment-specific variables in GitLab:

```yaml
deploy:staging:
  variables:
    SERVICE_NAME: my-app-staging
    DEPLOYMENT_TIMEOUT: 300

deploy:production:
  variables:
    SERVICE_NAME: my-app
    DEPLOYMENT_TIMEOUT: 600
```

### Deployment Protection

Add protected environments in GitLab:

Settings → CI/CD → Protected Environments → Add Protected Environment

- Environment name: `production`
- Allowed to deploy: Maintainers only
- Approval required: Yes

### Matrix Deployments

Deploy multiple services in parallel:

```yaml
deploy:production:
  parallel:
    matrix:
      - SERVICE: [web-frontend, api-backend, worker]
  script:
    - |
      PAYLOAD=$(jq -nc \
        --arg service "$SERVICE" \
        --arg image "$REGISTRY/$SERVICE:$IMAGE_TAG" \
        '{service: $service, image: $image}')
      # ... rest of deployment script
```

### Scheduled Deployments

Create a scheduled pipeline in GitLab:

CI/CD → Schedules → New schedule

- Description: "Nightly deployment"
- Interval: `0 2 * * *` (2 AM daily)
- Target branch: `main`
- Variables: Set any required variables

### Deployment Verification

Add a verification stage after deployment:

```yaml
verify:production:
  stage: verify
  script:
    - |
      echo "Running smoke tests..."
      curl -f https://example.com/health || exit 1
      curl -f https://example.com/api/version || exit 1
      echo "✅ Verification passed"
  dependencies:
    - deploy:production
  only:
    - main
```

## Debugging

### Test Deployment Locally

```bash
# Set variables
export HOOKSHOT_URL="https://deploy.example.com"
export HOOKSHOT_HMAC_SECRET="your-secret-here"
export IMAGE="registry.example.com/my-app:v1.0.0"

# Create payload
PAYLOAD=$(jq -nc \
  --arg service "my-app" \
  --arg image "$IMAGE" \
  '{service: $service, image: $image}')

# Calculate signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HOOKSHOT_HMAC_SECRET" | awk '{print $2}')

# Test deployment
curl -X POST "$HOOKSHOT_URL/deploy" \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD" | jq .
```

### View Pipeline Logs

GitLab CI/CD → Pipelines → Select pipeline → View job logs

Look for:
- Deployment payload
- HMAC signature calculation
- HTTP response from Hookshot
- Deployment status

### Common Issues

**HTTP 401 Unauthorized**:
```bash
# Verify HMAC secret matches
grep hmac_key /etc/hookshot/secrets

# Test signature calculation
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET"
```

**HTTP 403 Forbidden**:
```bash
# Check GitLab runner IP
curl -s https://ifconfig.me

# Verify IP is in Hookshot allowlist
grep allowed_ips /etc/hookshot/config.toml
```

**HTTP 404 Not Found**:
```bash
# Verify service name
curl -s https://deploy.example.com/services | jq '.services[].name'

# Check service is enabled
grep -A 5 'name = "my-app"' /etc/hookshot/services.toml
```

**Pipeline Fails on HMAC Calculation**:
```yaml
# Ensure jq and openssl are installed in the image
before_script:
  - apk add --no-cache jq openssl  # For Alpine-based images
  # or
  - apt-get update && apt-get install -y jq openssl  # For Debian-based
```

## Rollback Procedure

### Manual Rollback via UI

1. Go to CI/CD → Pipelines
2. Click "Run pipeline"
3. Select job: `rollback:production`
4. Add variable: `ROLLBACK_TO_IMAGE` = `registry.example.com/my-app:v1.2.3`
5. Click "Run pipeline"

### Automatic Rollback on Test Failure

Add a post-deployment test stage:

```yaml
test:production:
  stage: verify
  script:
    - npm run test:production
  dependencies:
    - deploy:production

rollback:auto:
  stage: verify
  script:
    # Automatically rollback if tests fail
    - |
      CURRENT=$(curl -s "$HOOKSHOT_URL/services" | jq -r '.services[] | select(.name == "my-app") | .current_image')
      # Deploy previous version
      # ... rollback script
  when: on_failure
  dependencies:
    - deploy:production
    - test:production
```

## Security Best Practices

1. **Use Protected Variables**: Mark `HOOKSHOT_HMAC_SECRET` as protected and masked
2. **Limit Runner Access**: Use specific runners for production deployments
3. **Enable IP Allowlisting**: Restrict Hookshot to GitLab runner IPs
4. **Protected Branches**: Only allow deployments from protected branches
5. **Manual Approval**: Require manual trigger for production deployments
6. **Audit Logs**: Review GitLab audit logs regularly
7. **Rotate Secrets**: Update HMAC secrets periodically

## Resources

- [GitLab CI/CD Documentation](https://docs.gitlab.com/ee/ci/)
- [GitLab Environments and Deployments](https://docs.gitlab.com/ee/ci/environments/)
- [Hookshot API Documentation](../../docs/API.md)
- [Hookshot Configuration Guide](../../docs/CONFIGURATION.md)