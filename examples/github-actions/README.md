# GitHub Actions Integration

This directory contains examples for integrating Hookshot with GitHub Actions.

## Setup

### 1. Add Secrets to GitHub Repository

Go to your repository settings → Secrets and variables → Actions, and add:

| Secret Name | Description | Example |
|-------------|-------------|---------|
| `HOOKSHOT_URL` | Your Hookshot deployment URL | `https://deploy.example.com` |
| `HOOKSHOT_HMAC_SECRET` | HMAC key from `/etc/hookshot/secrets` | `your-hmac-key-here` |
| `REGISTRY_USERNAME` | Container registry username | `deployer` |
| `REGISTRY_PASSWORD` | Container registry password/token | `your-registry-token` |

### 2. Add Workflow File

Copy `deploy.yml` to `.github/workflows/deploy.yml` in your repository.

### 3. Configure Service in Hookshot

Ensure your service is configured in `/etc/hookshot/services.toml`:

```toml
[[service]]
name = "my-app"
enabled = true

[service.security]
allowed_image_pattern = '^registry\.example\.com/my-app:.*$'

[service.deploy]
commands = [
    ["podman", "pull", "{{IMAGE}}"],
    ["systemctl", "--user", "restart", "my-app.service"]
]

[service.healthcheck]
commands = [
    ["curl", "-fsS", "http://127.0.0.1:8080/health"]
]
```

### 4. Allow GitHub Actions IP Ranges

Add GitHub Actions IP ranges to Hookshot allowlist:

```toml
# /etc/hookshot/config.toml
[security]
allowed_ips = [
    # GitHub Actions IP ranges (as of 2025)
    # See: https://api.github.com/meta (hooks)
    "192.30.252.0/22",
    "185.199.108.0/22",
    "140.82.112.0/20",
    "143.55.64.0/20",
]
```

Or use a reverse proxy with GitHub IP verification.

## Workflow Triggers

The example workflow triggers on:

- **Push to main branch**: Deploys to production
- **Git tags (v*)**: Deploys semantic versioned releases
- **Manual trigger**: Allows selecting staging or production

## Customization

### Deploy to Multiple Environments

```yaml
deploy-staging:
  if: github.ref == 'refs/heads/develop'
  steps:
    - name: Deploy to staging
      env:
        SERVICE_NAME: my-app-staging
      run: |
        # Same deployment script but with staging service

deploy-production:
  if: github.ref == 'refs/heads/main'
  needs: deploy-staging
  steps:
    - name: Deploy to production
      env:
        SERVICE_NAME: my-app
      run: |
        # Production deployment
```

### Add Deployment Approval

```yaml
deploy:
  environment:
    name: production
    url: https://example.com
  # GitHub will require manual approval before running
```

### Rollback on Test Failure

```yaml
deploy:
  # ... deployment steps ...

integration-tests:
  needs: deploy
  steps:
    - name: Run tests
      run: |
        npm run test:integration

    - name: Rollback on failure
      if: failure()
      run: |
        # Trigger rollback deployment
        PAYLOAD=$(jq -nc \
          --arg service "my-app" \
          --arg image "$PREVIOUS_IMAGE" \
          '{service: $service, image: $image}')

        SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

        curl -X POST "$DEPLOY_URL/deploy" \
          -H "Content-Type: application/json" \
          -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
          -d "$PAYLOAD"
```

## Debugging

### Test HMAC Signature Locally

```bash
# Set variables
HMAC_SECRET="your-secret-here"
PAYLOAD='{"service":"my-app","image":"registry.example.com/my-app:v1.0.0"}'

# Calculate signature
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

# Test deployment
curl -X POST https://deploy.example.com/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

### View Deployment Logs in Actions

The workflow outputs deployment response and status, visible in the GitHub Actions logs.

### Common Issues

**HTTP 401 Unauthorized**:
- Verify HMAC_SECRET matches `/etc/hookshot/secrets`
- Ensure payload is exactly what's being signed (no extra whitespace)

**HTTP 403 Forbidden**:
- Check GitHub Actions IP ranges in Hookshot allowlist
- Verify reverse proxy configuration

**HTTP 404 Not Found**:
- Confirm service name matches services.toml
- Ensure service is enabled

**HTTP 503 Service Unavailable**:
- Another deployment may be in progress (check concurrency limits)
- Hookshot may be down (check health endpoint)

## Advanced Usage

### Matrix Deployments

Deploy multiple services in parallel:

```yaml
deploy:
  strategy:
    matrix:
      service: [web-frontend, api-backend, worker-service]
  steps:
    - name: Deploy ${{ matrix.service }}
      env:
        SERVICE_NAME: ${{ matrix.service }}
      run: |
        # Deployment script
```

### Conditional Deployments

```yaml
- name: Check if deployment needed
  id: check
  run: |
    # Check if code changed
    if git diff --name-only ${{ github.event.before }} ${{ github.sha }} | grep -E '^(src|package.json)'; then
      echo "deploy=true" >> $GITHUB_OUTPUT
    fi

- name: Deploy
  if: steps.check.outputs.deploy == 'true'
  run: |
    # Deploy only if code changed
```

## Security Best Practices

1. **Never commit HMAC secrets** to the repository
2. **Use GitHub Secrets** for all sensitive values
3. **Enable IP allowlisting** in Hookshot
4. **Use HTTPS** for Hookshot endpoint
5. **Rotate secrets regularly** (update both GitHub and Hookshot)
6. **Limit workflow permissions** using `permissions:` key
7. **Review deployment logs** for suspicious activity

## Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [GitHub Actions IP Ranges](https://api.github.com/meta)
- [Hookshot API Documentation](../../docs/API.md)
- [Hookshot Configuration Guide](../../docs/CONFIGURATION.md)