# DevSec Pipeline Examples

Example pipeline configurations for common security scanning scenarios.

## Available Pipelines

| Pipeline | Description | Use Case |
|----------|-------------|----------|
| [basic.yaml](basic.yaml) | Minimal secret detection | Quick scans, testing |
| [full.yaml](full.yaml) | Complete security pipeline | Comprehensive security |
| [cicd.yaml](cicd.yaml) | Fast fail-fast pipeline | CI/CD integration |
| [parallel.yaml](parallel.yaml) | Maximum parallelism | Large codebases |
| [compliance-audit.yaml](compliance-audit.yaml) | Compliance evidence | Audits, SOC2/ISO/GDPR |
| [custom.yaml](custom.yaml) | Custom integrations | Notifications, scripts |
| [ml-security.yaml](ml-security.yaml) | ML project security | Machine learning |

## Quick Start

```bash
# Run basic scan
devsec pipeline run examples/pipelines/basic.yaml .

# Run full pipeline
devsec pipeline run examples/pipelines/full.yaml .

# Validate without executing
devsec pipeline run examples/pipelines/full.yaml . --dry-run

# Run with parallel stages
devsec pipeline run examples/pipelines/parallel.yaml . --parallel 4
```

## Pipeline Comparison

### Execution Time vs Coverage

```
basic.yaml          [====]                    ~5 min   | Low coverage
cicd.yaml           [========]                ~10 min  | Medium coverage
parallel.yaml       [==========]              ~12 min  | High coverage (fast)
full.yaml           [==============]          ~30 min  | Full coverage
compliance-audit.yaml [==================]    ~45 min  | Full + compliance
ml-security.yaml    [====================]    ~45 min  | Full + ML validation
```

### Stage Dependencies

**basic.yaml:**
```
secrets
```

**cicd.yaml:**
```
secrets ──────┐
vulnerabilities ├──▶ security-gate ──▶ ci-report
dependencies ──┘
```

**full.yaml:**
```
secrets ─────┬──▶ sast ────────────┐
             ├──▶ vulnerabilities ──┼──▶ policy-check ──▶ compliance ──┬──▶ report
             └──▶ dependencies ─────┘                                   └──▶ markdown-report
```

## Customization

### Modify Scanner Selection

```yaml
stages:
  - name: scan
    kind: scan
    config:
      # Single scanner
      scanner: gitleaks

      # Multiple scanners (comma-separated)
      scanner: gitleaks,semgrep,trivy,osv
```

### Change Policy Threshold

```yaml
stages:
  - name: policy
    kind: policy
    config:
      fail_on: critical  # Only fail on critical (default: high)
      # Options: critical, high, medium, low
```

### Add Custom Stage

```yaml
stages:
  - name: my-custom-step
    kind: custom
    config:
      command: ./scripts/my-script.sh
      timeout: 5m
    depends_on:
      - scan
```

## CI/CD Integration

### GitHub Actions

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Security Pipeline
        run: devsec pipeline run examples/pipelines/cicd.yaml .
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-results
          path: security-results.json
```

### GitLab CI

```yaml
security:
  stage: test
  script:
    - devsec pipeline run examples/pipelines/cicd.yaml .
  artifacts:
    paths:
      - security-results.json
    when: always
```

### Jenkins

```groovy
pipeline {
    stages {
        stage('Security') {
            steps {
                sh 'devsec pipeline run examples/pipelines/cicd.yaml .'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-results.json'
                }
            }
        }
    }
}
```

## Requirements

- devsec binary installed
- Scanner binaries (gitleaks, semgrep, trivy) in PATH
- Policy files in `./policies/` directory (for policy stages)

## See Also

- [Pipeline Guide](/home/voseghale/projects/documentations/devsec-pipeline-guide.md)
- [README.md](../../README.md)
