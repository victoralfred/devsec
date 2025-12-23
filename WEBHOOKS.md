# DevSec Webhooks Guide

This guide explains how webhooks work in DevSec, including CI/CD integration, alerting, and common use cases.

---

## Overview

DevSec uses webhooks in two directions:

1. **Incoming Webhooks**: Receive events from CI/CD systems (GitHub, GitLab) to trigger pipeline execution
2. **Outgoing Webhooks**: Send notifications and status updates to external systems

```
┌─────────────────┐     Incoming Event      ┌─────────────────┐
│   CI/CD System  │ ───────────────────────▶│     DevSec      │
│ GitHub/GitLab   │                         │   (Pipeline)    │
└─────────────────┘                         └────────┬────────┘
        ▲                                            │
        │         Status Updates                     │
        └────────────────────────────────────────────┘
                                                     │
                  Outgoing Alerts                    │
        ┌────────────────────────────────────────────┘
        ▼
┌─────────────────┐
│  Slack/Webhook  │
│   Endpoints     │
└─────────────────┘
```

---

## How It Works

### DevSec is NOT a Background Server

DevSec is a **CLI tool** that runs pipelines on-demand. It does not run as a persistent background service listening for webhooks. Instead:

1. **CI/CD systems** (GitHub Actions, GitLab CI) trigger DevSec when events occur
2. **DevSec runs** the security pipeline
3. **DevSec reports back** status updates via API calls or webhooks

### Typical Flow

```
1. Developer pushes code to GitHub/GitLab
2. CI/CD workflow starts
3. CI/CD runs: devsec pipeline run pipeline.yaml .
4. DevSec executes security scans
5. DevSec updates commit status via GitHub/GitLab API
6. DevSec sends alerts to Slack/webhooks
7. CI/CD workflow completes
```

---

## CI/CD Provider Integration

DevSec automatically detects and integrates with CI/CD providers.

### Provider Detection

DevSec auto-detects the provider from environment variables:

| Environment Variable | Provider |
|---------------------|----------|
| `GITHUB_ACTIONS=true` | GitHub |
| `GITLAB_CI=true` | GitLab |
| `GITHUB_RUN_ID` set | GitHub |
| `CI_PROJECT_ID` set | GitLab |
| None of the above | Webhook (generic) |

### GitHub Actions Integration

DevSec uses the GitHub API to update commit statuses and check runs.

**Environment Variables:**
```bash
GITHUB_TOKEN=ghp_xxxx          # GitHub token with repo permissions
GITHUB_REPOSITORY=owner/repo   # Repository in owner/repo format
GITHUB_SHA=abc123              # Commit SHA to update
```

**What DevSec Does:**
- Creates check runs on the commit
- Updates check status (pending → running → success/failure)
- Posts commit status with scan results

**Example GitHub Actions Workflow:**
```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write          # Required for check runs
      statuses: write        # Required for commit status
      security-events: write # Required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Install DevSec
        run: |
          curl -sSL https://get.devsec.io | sh
          sudo mv devsec /usr/local/bin/

      - name: Run Security Pipeline
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          devsec pipeline run examples/pipelines/cicd.yaml .

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: security-results.sarif
```

### GitLab CI Integration

DevSec uses the GitLab API to update commit statuses.

**Environment Variables:**
```bash
GITLAB_TOKEN=glpat-xxxx       # GitLab access token
CI_PROJECT_PATH=group/project # Project path
CI_COMMIT_SHA=abc123          # Commit SHA
CI_API_V4_URL=https://gitlab.com/api/v4  # API URL (auto-set)
```

**Example GitLab CI Configuration:**
```yaml
# .gitlab-ci.yml
security-scan:
  stage: test
  image: ubuntu:22.04
  variables:
    GITLAB_TOKEN: $GITLAB_API_TOKEN
  before_script:
    - curl -sSL https://get.devsec.io | sh
    - mv devsec /usr/local/bin/
  script:
    - devsec pipeline run examples/pipelines/cicd.yaml .
  artifacts:
    paths:
      - security-results.json
    reports:
      sast: security-results.json
    when: always
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Generic Webhook Provider

For custom CI/CD systems, DevSec can send status updates to any HTTP endpoint.

**Environment Variables:**
```bash
DEVSEC_WEBHOOK_URL=https://api.example.com/webhook
DEVSEC_WEBHOOK_SECRET=your-secret-key  # For HMAC signing
```

**Webhook Payload Format:**
```json
{
  "type": "status_update",
  "run_id": "run-12345",
  "pipeline_ref": "security-pipeline",
  "status": "success",
  "description": "Security scan completed",
  "start_time": "2025-12-23T10:00:00Z",
  "end_time": "2025-12-23T10:05:00Z",
  "duration": "5m0s",
  "stages": [
    {
      "name": "secrets",
      "status": "success",
      "duration": "30s"
    },
    {
      "name": "vulnerabilities",
      "status": "success",
      "duration": "2m30s"
    }
  ]
}
```

**HMAC Signature:**
When a secret is configured, DevSec signs payloads with HMAC-SHA256:
```
X-Webhook-Signature: sha256=<hex-encoded-signature>
```

**Verify Signature (Example in Go):**
```go
func verifySignature(payload []byte, signature, secret string) bool {
    // Remove "sha256=" prefix
    sig := strings.TrimPrefix(signature, "sha256=")

    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    expected := hex.EncodeToString(mac.Sum(nil))

    return hmac.Equal([]byte(expected), []byte(sig))
}
```

---

## Alerting Webhooks

DevSec can send security alerts to various destinations.

### Slack Notifications

Send alerts to Slack channels via incoming webhooks.

**Setup:**
1. Create a Slack app at https://api.slack.com/apps
2. Enable "Incoming Webhooks"
3. Add webhook to your workspace
4. Copy the webhook URL

**Configuration:**
```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T00/B00/xxx
```

**Pipeline with Slack Notification:**
```yaml
# pipeline.yaml
name: security-with-alerts
stages:
  - name: scan
    kind: scan
    config:
      scanner: gitleaks,trivy

  - name: notify
    kind: custom
    config:
      command: |
        curl -X POST -H 'Content-type: application/json' \
          --data '{"text":"Security scan completed for $PWD"}' \
          "$SLACK_WEBHOOK_URL"
    depends_on: [scan]
    continue_on: always
```

**Alert Payload:**
```json
{
  "attachments": [{
    "color": "#ff0000",
    "title": ":warning: Security Alert",
    "text": "Critical vulnerabilities detected",
    "fields": [
      {"title": "Severity", "value": "critical", "short": true},
      {"title": "Findings", "value": "5 findings detected", "short": true}
    ],
    "footer": "DevSec | security-scan"
  }]
}
```

### Generic Webhook Alerts

Send alerts to any HTTP endpoint.

**Configuration:**
```bash
export ALERT_WEBHOOK_URL=https://api.example.com/alerts
export ALERT_WEBHOOK_SECRET=your-hmac-secret
```

**Alert Payload:**
```json
{
  "version": "1.0",
  "source": "devsec",
  "timestamp": "2025-12-23T10:05:00Z",
  "alert": {
    "id": "alert-12345",
    "type": "security",
    "severity": "critical",
    "title": "Critical Vulnerabilities Detected",
    "message": "Found 5 critical vulnerabilities in dependencies",
    "source": "security-pipeline",
    "findings": [
      {
        "id": "CVE-2024-1234",
        "severity": "critical",
        "title": "Remote Code Execution in library-x",
        "file": "go.mod"
      }
    ],
    "metadata": {
      "repository": "owner/repo",
      "branch": "main",
      "commit": "abc123"
    }
  }
}
```

---

## Use Cases

### Use Case 1: GitHub PR Security Gate

Block PRs with critical vulnerabilities.

```yaml
# .github/workflows/pr-security.yml
name: PR Security Gate

on:
  pull_request:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      checks: write
      pull-requests: write

    steps:
      - uses: actions/checkout@v4

      - name: Run Security Scan
        id: security
        run: |
          devsec pipeline run examples/pipelines/cicd.yaml . \
            --output results.json
        continue-on-error: true

      - name: Check Results
        run: |
          if [ -f results.json ]; then
            CRITICAL=$(jq '.findings | map(select(.severity == "critical")) | length' results.json)
            if [ "$CRITICAL" -gt 0 ]; then
              echo "::error::Found $CRITICAL critical vulnerabilities"
              exit 1
            fi
          fi

      - name: Comment on PR
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '⚠️ Security scan found critical vulnerabilities. Please review and fix before merging.'
            })
```

### Use Case 2: Scheduled Security Audit

Run weekly security audits with Slack notifications.

```yaml
# .github/workflows/weekly-audit.yml
name: Weekly Security Audit

on:
  schedule:
    - cron: '0 9 * * 1'  # Every Monday at 9 AM
  workflow_dispatch:      # Manual trigger

jobs:
  audit:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Run Compliance Audit
        run: |
          devsec pipeline run examples/pipelines/compliance-audit.yaml .

      - name: Send Slack Report
        env:
          SLACK_WEBHOOK_URL: ${{ secrets.SLACK_WEBHOOK_URL }}
        run: |
          SUMMARY=$(cat audit/soc2-evidence.md | head -50)
          curl -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"Weekly Security Audit Complete\",\"attachments\":[{\"text\":\"$SUMMARY\"}]}" \
            "$SLACK_WEBHOOK_URL"

      - name: Upload Reports
        uses: actions/upload-artifact@v4
        with:
          name: audit-reports
          path: audit/
```

### Use Case 3: Custom Webhook Integration

Integrate with internal security dashboard.

```yaml
# pipeline-with-webhook.yaml
name: security-with-dashboard
version: "1.0.0"

stages:
  - name: scan
    kind: scan
    config:
      scanner: gitleaks,semgrep,trivy,osv
    timeout: 15m

  - name: policy
    kind: policy
    config:
      fail_on: high
    depends_on: [scan]

  - name: report
    kind: report
    config:
      format: json
      output: findings.json
    depends_on: [policy]
    continue_on: always

  - name: notify-dashboard
    kind: custom
    config:
      command: |
        # Send results to internal dashboard
        FINDINGS=$(cat findings.json)
        SIGNATURE=$(echo -n "$FINDINGS" | openssl dgst -sha256 -hmac "$DASHBOARD_SECRET" | cut -d' ' -f2)

        curl -X POST "$DASHBOARD_URL/api/security/findings" \
          -H "Content-Type: application/json" \
          -H "X-Signature-256: sha256=$SIGNATURE" \
          -H "X-Repository: $GITHUB_REPOSITORY" \
          -H "X-Commit: $GITHUB_SHA" \
          -d "$FINDINGS"
    depends_on: [report]
    continue_on: always
```

**Run with environment variables:**
```bash
export DASHBOARD_URL=https://security-dashboard.internal.com
export DASHBOARD_SECRET=your-hmac-secret

devsec pipeline run pipeline-with-webhook.yaml .
```

### Use Case 4: Multi-Channel Alerting

Send alerts to multiple destinations based on severity.

```yaml
# multi-alert-pipeline.yaml
name: multi-channel-alerts
version: "1.0.0"

stages:
  - name: scan
    kind: scan
    config:
      scanner: gitleaks,trivy
    timeout: 10m

  - name: policy
    kind: policy
    config:
      fail_on: critical
    depends_on: [scan]

  - name: report
    kind: report
    config:
      format: json
      output: findings.json
    depends_on: [scan]
    continue_on: always

  # Always notify Slack
  - name: slack-notify
    kind: custom
    config:
      command: |
        COUNT=$(jq '.findings | length' findings.json 2>/dev/null || echo "0")
        curl -X POST -H 'Content-type: application/json' \
          --data "{\"text\":\"Security scan completed: $COUNT findings\"}" \
          "$SLACK_WEBHOOK_URL"
    depends_on: [report]
    continue_on: always

  # PagerDuty for critical only
  - name: pagerduty-critical
    kind: custom
    config:
      command: |
        CRITICAL=$(jq '[.findings[] | select(.severity == "critical")] | length' findings.json)
        if [ "$CRITICAL" -gt 0 ]; then
          curl -X POST https://events.pagerduty.com/v2/enqueue \
            -H "Content-Type: application/json" \
            -d '{
              "routing_key": "'$PAGERDUTY_KEY'",
              "event_action": "trigger",
              "payload": {
                "summary": "Critical security vulnerabilities detected",
                "severity": "critical",
                "source": "devsec"
              }
            }'
        fi
    depends_on: [report]
    continue_on: always

  # Jira ticket for high severity
  - name: jira-ticket
    kind: custom
    config:
      command: |
        HIGH=$(jq '[.findings[] | select(.severity == "high")] | length' findings.json)
        if [ "$HIGH" -gt 0 ]; then
          curl -X POST "$JIRA_URL/rest/api/2/issue" \
            -H "Content-Type: application/json" \
            -H "Authorization: Basic $JIRA_AUTH" \
            -d '{
              "fields": {
                "project": {"key": "SEC"},
                "summary": "High severity vulnerabilities detected",
                "issuetype": {"name": "Bug"},
                "priority": {"name": "High"}
              }
            }'
        fi
    depends_on: [report]
    continue_on: always
```

---

## Webhook Security

### HMAC Signature Verification

Always verify webhook signatures to prevent tampering:

```python
# Python example
import hmac
import hashlib

def verify_signature(payload: bytes, signature: str, secret: str) -> bool:
    if not signature.startswith('sha256='):
        return False

    expected = hmac.new(
        secret.encode(),
        payload,
        hashlib.sha256
    ).hexdigest()

    provided = signature[7:]  # Remove 'sha256=' prefix

    return hmac.compare_digest(expected, provided)
```

```javascript
// Node.js example
const crypto = require('crypto');

function verifySignature(payload, signature, secret) {
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('hex');

  return crypto.timingSafeEqual(
    Buffer.from(signature),
    Buffer.from(expected)
  );
}
```

### Best Practices

1. **Always use HTTPS** for webhook URLs
2. **Rotate secrets** regularly
3. **Validate payloads** before processing
4. **Set timeouts** to prevent hanging connections
5. **Implement retry logic** for failed deliveries
6. **Log all webhook activity** for auditing

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| No status update on GitHub | Missing token permissions | Add `checks: write` and `statuses: write` |
| Webhook delivery failed | Invalid URL or network issue | Check URL and firewall rules |
| Signature verification failed | Wrong secret or encoding | Verify secret matches on both ends |
| Slack message not appearing | Invalid webhook URL | Regenerate webhook URL in Slack |

### Debug Mode

Enable debug logging to troubleshoot webhook issues:

```bash
DEVSEC_LOG_LEVEL=debug devsec pipeline run pipeline.yaml .
```

### Test Webhook Endpoint

Test your webhook endpoint with curl:

```bash
# Test without signature
curl -X POST https://your-endpoint.com/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"test","message":"Hello from DevSec"}'

# Test with signature
PAYLOAD='{"type":"test"}'
SECRET="your-secret"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

curl -X POST https://your-endpoint.com/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

---

## API Reference

### Status Types

| Status | Description |
|--------|-------------|
| `pending` | Pipeline queued |
| `running` | Pipeline executing |
| `success` | Pipeline completed successfully |
| `failure` | Pipeline failed (security issues found) |
| `error` | Pipeline error (execution problem) |
| `canceled` | Pipeline was canceled |

### Event Types

| Event | Description |
|-------|-------------|
| `push` | Code push to branch |
| `pull_request` | Pull/merge request event |
| `tag` | Tag push event |
| `schedule` | Scheduled pipeline run |
| `manual` | Manually triggered |

---

*Documentation generated: 2025-12-23*
