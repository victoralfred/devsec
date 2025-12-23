# DevSec

MLSecOps pipeline tool for security scanning, policy enforcement, and compliance.

## Overview

DevSec is a comprehensive security pipeline tool that automates security scanning, policy enforcement, and compliance assessment for CI/CD pipelines. It integrates multiple security scanners, provides OPA-based policy evaluation, and maps findings to compliance frameworks.

## Features

- **Security Scanning**: Integrated scanners for secrets, vulnerabilities, and code security
  - Gitleaks for secret detection
  - Semgrep for SAST (Static Application Security Testing)
  - Trivy for container and dependency vulnerabilities
  - OSV for open source vulnerability scanning

- **Policy Engine**: OPA-based policy evaluation with Rego
  - Custom policy definitions
  - Policy validation and documentation generation
  - Configurable severity thresholds

- **Compliance Mapping**: Map findings to compliance frameworks
  - SOC 2 Trust Services Criteria
  - ISO/IEC 27001:2022
  - GDPR

- **ML Validation**: Machine learning security and validation
  - Framework detection (TensorFlow, PyTorch, scikit-learn, etc.)
  - Model file identification
  - Model card generation
  - Data validation and drift detection
  - Fairness and bias analysis

- **Supply Chain Security**: Software supply chain integrity
  - SBOM generation (SPDX, CycloneDX)
  - Artifact signing with ECDSA-P256
  - SLSA provenance attestations
  - In-toto attestation format

- **Pipeline Orchestration**: YAML-based pipeline execution
  - Sequential and parallel stage execution
  - Stage dependencies with automatic ordering
  - Multiple stage types: scan, policy, report, compliance, custom

- **Observability**: Monitoring and alerting
  - Structured logging
  - Prometheus metrics
  - Slack and webhook notifications

## Quick Start

```bash
# Install devsec
make build
sudo mv bin/devsec /usr/local/bin/

# Scan for secrets
devsec scan secrets .

# Scan for vulnerabilities
devsec scan vulnerabilities .

# Run full security pipeline
devsec pipeline run
```

For detailed installation instructions, see [SETUP.md](SETUP.md).

For CI/CD integration and webhook configuration, see [WEBHOOKS.md](WEBHOOKS.md).

## CLI Reference

### Root Commands

| Command | Description |
|---------|-------------|
| `devsec version` | Print version information |
| `devsec --help` | Show help for available commands |

### Scanning Commands

| Command | Description |
|---------|-------------|
| `devsec scan secrets [path]` | Scan for secrets using Gitleaks |
| `devsec scan sast [path]` | SAST scanning with Semgrep |
| `devsec scan vulnerabilities [path]` | Vulnerability scan with Trivy |
| `devsec scan dependencies [path]` | Dependency check with OSV |

**Common Flags:**
- `-f, --format`: Output format (text, json)
- `-o, --output`: Output file path
- `-t, --timeout`: Scan timeout duration
- `-v, --verbose`: Verbose output

### Policy Commands

| Command | Description |
|---------|-------------|
| `devsec policy check` | Evaluate findings against security policy |
| `devsec policy validate [path]` | Validate Rego policy files |
| `devsec policy docs [path]` | Generate policy documentation |

**Policy Check Flags:**
- `-p, --policy`: Custom Rego policy file
- `-s, --strict`: Enable strict mode (warn on medium)
- `-i, --findings`: JSON file with findings to check

### Compliance Commands

| Command | Description |
|---------|-------------|
| `devsec compliance assess [path]` | Run compliance assessment |
| `devsec compliance report [scan-file]` | Generate compliance report |
| `devsec compliance coverage [scan-file]` | Show compliance coverage statistics |
| `devsec compliance gaps [scan-file]` | Show compliance gaps |
| `devsec compliance controls list` | List compliance controls |

**Compliance Flags:**
- `-F, --frameworks`: Frameworks (comma-separated: soc2, iso27001, gdpr)
- `-f, --format`: Output format (json, markdown, text)

### ML Commands

| Command | Description |
|---------|-------------|
| `devsec ml detect [path]` | Detect ML frameworks and model files |
| `devsec ml model-card [path]` | Generate a model card template |
| `devsec ml validate [data-file]` | Validate ML data against a schema |
| `devsec ml drift [baseline] [current]` | Detect data drift between datasets |
| `devsec ml fairness [data-file]` | Analyze model fairness across groups |
| `devsec ml bias [data-file]` | Detect potential biases in data |

**ML Flags:**
- `-f, --format`: Output format (text, json, csv, html, junit, sarif)
- `-s, --schema`: Schema file for validation
- `-a, --attributes`: Protected attributes (comma-separated)

### Supply Chain Commands

| Command | Description |
|---------|-------------|
| `devsec sbom [path]` | Generate Software Bill of Materials |
| `devsec sign artifact [file]` | Sign an artifact file |
| `devsec sign verify [file]` | Verify an artifact signature |
| `devsec sign genkey` | Generate a new signing key pair |
| `devsec attestation generate [files...]` | Generate SLSA provenance attestation |
| `devsec attestation verify [attestation]` | Verify an attestation envelope |
| `devsec attestation inspect [attestation]` | Inspect an attestation |

**SBOM Flags:**
- `-f, --format`: Output format (spdx, cyclonedx)

**Sign Flags:**
- `-k, --key`: Private key file (PEM format)
- `--pub-key`: Public key file

### Pipeline Commands

| Command | Description |
|---------|-------------|
| `devsec pipeline run [pipeline-file] [path]` | Execute a security pipeline |
| `devsec pipeline validate [pipeline-file]` | Validate a pipeline definition |
| `devsec pipeline generate [template]` | Generate a pipeline template |

**Pipeline Flags:**
- `-p, --parallel`: Max parallel stages (0 = auto)
- `--dry-run`: Validate and show execution plan
- `-T, --template`: Template type (basic, full, parallel, cicd)

## Configuration

### Configuration File

Create a `devsec.yaml` file in your project root:

```yaml
log_level: info
work_dir: .

scanners:
  gitleaks:
    enabled: true
    timeout: 5m
  semgrep:
    enabled: true
    timeout: 10m
  trivy:
    enabled: true
    timeout: 10m

policy:
  policies_dir: ./policies
  fail_on_critical: true
  fail_on_high: false

reporting:
  output_dir: ./reports
  formats:
    - json
    - markdown
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEVSEC_LOG_LEVEL` | Log level (debug, info, warn, error) | info |
| `DEVSEC_WORK_DIR` | Working directory | . |
| `DEVSEC_POLICY_FAIL_ON_CRITICAL` | Fail on critical findings | true |
| `DEVSEC_PIPELINE_MAX_WORKERS` | Max parallel workers | auto |

### Pipeline Definition

Create a pipeline file (e.g., `pipeline.yaml`):

```yaml
name: security-pipeline
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

  - name: policy-check
    kind: policy
    config:
      fail_on: high
    depends_on: [sast, vulnerabilities]

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

### Example Pipelines

Ready-to-use pipeline configurations are available in [`examples/pipelines/`](examples/pipelines/):

| Pipeline | Description |
|----------|-------------|
| [basic.yaml](examples/pipelines/basic.yaml) | Minimal secret detection |
| [full.yaml](examples/pipelines/full.yaml) | Complete security pipeline |
| [cicd.yaml](examples/pipelines/cicd.yaml) | Fast CI/CD integration |
| [parallel.yaml](examples/pipelines/parallel.yaml) | Maximum parallelism |
| [compliance-audit.yaml](examples/pipelines/compliance-audit.yaml) | Compliance evidence |
| [custom.yaml](examples/pipelines/custom.yaml) | Custom integrations |
| [ml-security.yaml](examples/pipelines/ml-security.yaml) | ML project security |

Example policies are in [`examples/policies/`](examples/policies/).

## Use Cases

### CI/CD Integration

Run security checks on every commit:

```bash
# Quick scan for secrets (block commits with secrets)
devsec scan secrets . --format json --output secrets.json
if [ $? -ne 0 ]; then
  echo "Secrets detected! Blocking commit."
  exit 1
fi

# Full security pipeline
devsec pipeline run --timeout 15m
```

### Pre-deployment Checks

Gate deployments on security results:

```bash
# Run policy check with strict mode
devsec scan sast . --output findings.json
devsec policy check --findings findings.json --strict

# Check for critical vulnerabilities
devsec scan vulnerabilities . --format json | jq '.[] | select(.severity == "critical")'
```

### Compliance Audits

Generate evidence for auditors:

```bash
# Run compliance assessment
devsec compliance assess . --frameworks soc2,iso27001 --format markdown --output compliance-report.md

# Generate coverage statistics
devsec compliance coverage scan-results.json

# Identify compliance gaps
devsec compliance gaps scan-results.json --format markdown --output gaps.md
```

### ML Model Security

Validate ML pipelines:

```bash
# Detect ML frameworks and models
devsec ml detect ./ml-project --format json --output ml-detection.json

# Generate model card
devsec ml model-card ./ml-project --output model-card.md

# Check for data drift
devsec ml drift baseline-data.json current-data.json --threshold 0.1

# Analyze fairness
devsec ml fairness predictions.json --protected gender --format html --output fairness-report.html
```

## Architecture

```
devsec/
├── cmd/devsec/          # CLI entry point
├── internal/
│   ├── cli/             # Command implementations
│   ├── scanner/         # Security scanners
│   │   ├── gitleaks/    # Secret detection
│   │   ├── semgrep/     # SAST
│   │   ├── trivy/       # Vulnerability scanning
│   │   └── osv/         # Dependency vulnerabilities
│   ├── policy/          # OPA policy engine
│   ├── compliance/      # Compliance mapping
│   ├── ml/              # ML validation
│   ├── sbom/            # SBOM generation
│   ├── signing/         # Artifact signing
│   ├── attestation/     # SLSA attestations
│   ├── pipeline/        # Pipeline orchestration
│   ├── gates/           # Deployment gates
│   ├── kubernetes/      # Kubernetes integration
│   ├── helm/            # Helm integration
│   ├── logging/         # Structured logging
│   ├── metrics/         # Prometheus metrics
│   ├── alerting/        # Notifications
│   └── model/           # Data models
└── bin/                 # Build output
```

## Development

```bash
# Install development tools
make tools

# Run tests
make test

# Run linter
make lint

# Run security scanner
make security

# Run all checks
make check

# Build binary
make build
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes following the code style
4. Ensure all checks pass: `make check`
5. Submit a pull request

Quality gate requirements:
- All tests pass
- golangci-lint passes
- gosec passes
- No direct os file I/O (use gowritter)

## License

This project is licensed under the MIT License.
