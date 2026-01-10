# Claude Instructions for DevSec

This file provides context for AI assistants working with the DevSec codebase.

## Project Overview

DevSec is an MLSecOps security pipeline tool written in Go. It provides automated security scanning, policy enforcement, compliance mapping, and ML validation for CI/CD pipelines.

## Architecture

```
devsec/
├── cmd/devsec/          # CLI entry point
├── internal/
│   ├── cli/             # Cobra command implementations
│   ├── scanner/         # Security scanners (gitleaks, semgrep, trivy, osv)
│   ├── policy/          # OPA policy engine
│   ├── compliance/      # Compliance framework mapping
│   ├── ml/              # ML validation and fairness analysis
│   ├── sbom/            # SBOM generation
│   ├── signing/         # Artifact signing
│   ├── attestation/     # SLSA attestations
│   ├── pipeline/        # Pipeline orchestration
│   ├── model/           # Data models
│   └── logging/         # Structured logging
└── examples/            # Example pipelines and policies
```

## Coding Guidelines

### File I/O
- **NEVER use direct `os` file I/O** (`os.Open`, `os.Create`, `os.ReadFile`, `os.WriteFile`, `os.Remove`, `os.Mkdir`)
- **ALWAYS use `github.com/victoralfred/gowritter`** for all file operations
- Exception: `internal/logging/` may use direct I/O for log files

### Code Style
- Follow Go idioms and best practices
- Use structured logging with `internal/logging`
- Keep functions small and focused
- Write table-driven tests

### Testing
- All packages must have tests
- Minimum 40% code coverage required
- Use `go test -race` for race detection
- Run `make check` before committing

### Security
- Run `gosec` on all code
- No hardcoded secrets
- Validate all external input
- Use context for timeouts

## Common Commands

```bash
# Build
make build

# Test
make test

# Lint
make lint

# Security scan
make security

# All checks
make check

# Run CLI
./bin/devsec --help
```

## Key Packages

| Package | Purpose |
|---------|---------|
| `internal/cli` | CLI commands using Cobra |
| `internal/scanner` | Security scanner integrations |
| `internal/policy` | OPA policy evaluation |
| `internal/compliance` | SOC2, ISO27001, GDPR mapping |
| `internal/ml` | ML framework detection, fairness |
| `internal/pipeline` | YAML pipeline execution |

## External Dependencies

- **gitleaks** - Secret detection
- **semgrep** - SAST scanning
- **trivy** - Vulnerability scanning
- **OPA** - Policy evaluation

## Do Not

- Introduce breaking changes to CLI flags
- Add dependencies without justification
- Skip security checks (`gosec`, `golangci-lint`)
- Use `--no-verify` on git commits
- Commit generated files or binaries
