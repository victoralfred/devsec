# DevSec Setup Guide

This guide covers the installation and configuration of DevSec and its dependencies.

## Prerequisites

- Go 1.21 or higher
- Git
- One or more of the following scanners (based on your needs):
  - Gitleaks (for secret detection)
  - Semgrep (for SAST)
  - Trivy (for vulnerability scanning)

## Installing External Tools

### Gitleaks (Secret Detection)

Gitleaks detects secrets, passwords, and API keys in your codebase.

**macOS (Homebrew):**
```bash
brew install gitleaks
```

**Linux (Binary):**
```bash
# Download latest release
GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep tag_name | cut -d '"' -f 4)
wget https://github.com/gitleaks/gitleaks/releases/download/${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION#v}_linux_x64.tar.gz
tar -xzf gitleaks_*.tar.gz
sudo mv gitleaks /usr/local/bin/
rm gitleaks_*.tar.gz
```

**Verify installation:**
```bash
gitleaks version
```

### Semgrep (SAST)

Semgrep performs static application security testing with pattern-based scanning.

**Python pip (Recommended):**
```bash
pip install semgrep
```

**macOS (Homebrew):**
```bash
brew install semgrep
```

**Verify installation:**
```bash
semgrep --version
```

### Trivy (Vulnerability Scanner)

Trivy scans for vulnerabilities in dependencies and container images.

**macOS (Homebrew):**
```bash
brew install trivy
```

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

**Linux (RHEL/CentOS):**
```bash
sudo rpm -ivh https://github.com/aquasecurity/trivy/releases/download/v0.50.0/trivy_0.50.0_Linux-64bit.rpm
```

**Verify installation:**
```bash
trivy version
```

## Building DevSec

### From Source

```bash
# Clone repository
git clone https://github.com/victoralfred/devsec.git
cd devsec/source

# Download dependencies
go mod download

# Build binary
make build

# Install to PATH
sudo mv bin/devsec /usr/local/bin/

# Verify installation
devsec version
```

### Build with Version Information

```bash
VERSION=1.0.0
GIT_COMMIT=$(git rev-parse --short HEAD)
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

go build -ldflags "-X github.com/victoralfred/devsec/internal/cli.Version=$VERSION \
                   -X github.com/victoralfred/devsec/internal/cli.GitCommit=$GIT_COMMIT \
                   -X github.com/victoralfred/devsec/internal/cli.BuildDate=$BUILD_DATE" \
         -o bin/devsec ./cmd/devsec
```

## Development Setup

### Install Development Tools

```bash
# Install linter and security scanner
make tools

# Or manually:
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### Run Quality Checks

```bash
# Run all checks (lint, security, test)
make check

# Run individual checks
make lint      # golangci-lint
make security  # gosec
make test      # go test

# Run tests with coverage
make coverage

# Format code
make fmt
```

### Project Structure

```
devsec/source/
├── cmd/devsec/       # CLI entry point
├── internal/         # Internal packages
├── bin/              # Build output
├── Makefile          # Build targets
├── go.mod            # Go modules
└── go.sum            # Dependencies checksum
```

## Configuration

### Configuration File

Create `devsec.yaml` in your project root:

```yaml
# Log level: debug, info, warn, error
log_level: info

# Working directory for scans
work_dir: .

# Scanner configuration
scanners:
  gitleaks:
    enabled: true
    timeout: 5m
    # Custom config file (optional)
    config_file: .gitleaks.toml

  semgrep:
    enabled: true
    timeout: 10m
    # Ruleset configuration
    config:
      - p/security-audit
      - p/owasp-top-ten

  trivy:
    enabled: true
    timeout: 10m
    # Scan types
    scan_types:
      - vuln
      - secret
      - config

# Policy configuration
policy:
  # Directory containing Rego policies
  policies_dir: ./policies

  # Fail pipeline on critical findings
  fail_on_critical: true

  # Fail pipeline on high findings
  fail_on_high: false

  # Warn on medium findings
  warn_on_medium: true

# Compliance configuration
compliance:
  # Enabled frameworks
  frameworks:
    - soc2
    - iso27001

  # Include evidence in reports
  include_evidence: true

# Reporting configuration
reporting:
  # Output directory for reports
  output_dir: ./reports

  # Report formats
  formats:
    - json
    - markdown
    - sarif

# Pipeline configuration
pipeline:
  # Maximum parallel stages
  max_workers: 4

  # Default timeout per stage
  default_timeout: 10m

  # Fail fast on first error
  fail_fast: true
```

### Environment Variables

Override configuration with environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DEVSEC_LOG_LEVEL` | Log level | info |
| `DEVSEC_WORK_DIR` | Working directory | . |
| `DEVSEC_CONFIG` | Config file path | devsec.yaml |
| `DEVSEC_POLICY_DIR` | Policy directory | ./policies |
| `DEVSEC_POLICY_FAIL_ON_CRITICAL` | Fail on critical | true |
| `DEVSEC_POLICY_FAIL_ON_HIGH` | Fail on high | false |
| `DEVSEC_PIPELINE_MAX_WORKERS` | Max parallel workers | 4 |
| `DEVSEC_PIPELINE_TIMEOUT` | Pipeline timeout | 30m |
| `DEVSEC_REPORT_DIR` | Report output directory | ./reports |

### Scanner-Specific Configuration

#### Gitleaks Configuration

Create `.gitleaks.toml` in your project root:

```toml
[extend]
# Extend default rules
useDefault = true

[allowlist]
# Paths to ignore
paths = [
    '''vendor/''',
    '''node_modules/''',
    '''.git/''',
]

# Regex patterns to ignore
regexes = [
    '''EXAMPLE_.*''',
]

[[rules]]
# Custom rule example
id = "custom-api-key"
description = "Custom API Key"
regex = '''(?i)custom[_-]?api[_-]?key[_-]?=\s*['"]?([a-zA-Z0-9]{32,})['"]?'''
secretGroup = 1
```

#### Semgrep Configuration

Create `.semgrep.yaml` in your project root:

```yaml
rules:
  - id: custom-sql-injection
    pattern: |
      db.Query($SQL)
    message: Potential SQL injection
    languages: [go]
    severity: ERROR
```

## Pipeline Configuration

### Basic Pipeline

Create `devsec.yaml` or `pipeline.yaml`:

```yaml
name: security-scan
version: "1.0.0"
timeout: 30m
fail_fast: true

stages:
  - name: secrets
    kind: scan
    config:
      scanner: gitleaks
    timeout: 5m

  - name: sast
    kind: scan
    config:
      scanner: semgrep
    depends_on: [secrets]
    timeout: 10m

  - name: vulnerabilities
    kind: scan
    config:
      scanner: trivy
    depends_on: [secrets]
    timeout: 10m
```

### Full Pipeline with Compliance

```yaml
name: full-security-pipeline
version: "1.0.0"
timeout: 60m
fail_fast: true

metadata:
  description: Complete security pipeline
  author: security-team

stages:
  - name: secrets
    kind: scan
    config:
      scanner: gitleaks
    timeout: 5m

  - name: sast
    kind: scan
    config:
      scanner: semgrep
    depends_on: [secrets]
    timeout: 10m

  - name: vulnerabilities
    kind: scan
    config:
      scanner: trivy
    depends_on: [secrets]
    timeout: 10m

  - name: dependencies
    kind: scan
    config:
      scanner: osv
    depends_on: [secrets]
    timeout: 5m

  - name: policy-check
    kind: policy
    config:
      policy_dir: policies
      fail_on: high
    depends_on: [sast, vulnerabilities, dependencies]

  - name: compliance
    kind: compliance
    config:
      frameworks: soc2,iso27001
    depends_on: [policy-check]

  - name: report
    kind: report
    config:
      format: markdown
      output: security-report.md
    depends_on: [compliance]
    continue_on: always
```

### CI/CD Pipeline (Fast)

```yaml
name: cicd-security-check
version: "1.0.0"
timeout: 15m
fail_fast: true

metadata:
  description: Fast security checks for CI/CD
  trigger: pull_request

stages:
  - name: quick-scan
    kind: scan
    config:
      scanner: gitleaks
    timeout: 2m

  - name: security-check
    kind: scan
    config:
      scanner: semgrep
    depends_on: [quick-scan]
    timeout: 5m

  - name: policy-gate
    kind: policy
    config:
      fail_on: critical
    depends_on: [security-check]
```

## Kubernetes and Helm Setup (Optional)

### Kubernetes Configuration

Ensure kubectl is configured:

```bash
# Check cluster connection
kubectl cluster-info

# Verify namespace access
kubectl get namespaces
```

### Helm Client Setup

```bash
# Install Helm
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Verify installation
helm version
```

## Metrics and Alerting Setup (Optional)

### Prometheus Metrics

DevSec exposes metrics on `/metrics` endpoint:

```bash
# Start metrics server (in your application)
devsec serve --metrics-port 9090
```

Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'devsec'
    static_configs:
      - targets: ['localhost:9090']
```

### Slack Notifications

Configure Slack webhook in your environment:

```bash
export DEVSEC_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
export DEVSEC_SLACK_CHANNEL="#security-alerts"
```

### Custom Webhook

```bash
export DEVSEC_WEBHOOK_URL="https://your-webhook.example.com/alerts"
export DEVSEC_WEBHOOK_SECRET="your-hmac-secret"
```

## Verification

Verify your installation is complete:

```bash
# Check devsec version
devsec version

# Check scanners
gitleaks version
semgrep --version
trivy version

# Run a test scan
devsec scan secrets .

# Generate pipeline template
devsec pipeline generate basic

# Validate pipeline
devsec pipeline validate devsec.yaml
```

## Troubleshooting

### Scanner Binary Not Found

If you see "executable not found" errors:

```bash
# Check if scanner is in PATH
which gitleaks
which semgrep
which trivy

# Add to PATH if needed
export PATH=$PATH:/usr/local/bin
```

### Permission Issues

```bash
# Fix binary permissions
chmod +x /usr/local/bin/devsec
chmod +x /usr/local/bin/gitleaks
```

### Timeout Errors

Increase timeouts for large codebases:

```bash
# Command line
devsec scan sast . --timeout 30m

# Or in configuration
scanners:
  semgrep:
    timeout: 30m
```

### Memory Issues

For large projects, limit scanner concurrency:

```bash
# Limit parallel stages
devsec pipeline run --parallel 2

# Or in configuration
pipeline:
  max_workers: 2
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
export DEVSEC_LOG_LEVEL=debug
devsec scan secrets . -v
```
