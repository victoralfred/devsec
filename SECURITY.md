# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in DevSec, please report it responsibly.

### How to Report

1. **Do NOT** create a public GitHub issue for security vulnerabilities
2. Email the maintainers directly or use [GitHub Security Advisories](https://github.com/victoralfred/devsec/security/advisories)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: We will acknowledge receipt within 48 hours
- **Assessment**: We will assess the vulnerability and determine severity
- **Updates**: We will keep you informed of our progress
- **Resolution**: We aim to resolve critical issues within 7 days
- **Credit**: We will credit reporters in release notes (unless anonymity is requested)

## Security Practices

### In Development

- All code is scanned with `gosec` for security issues
- Dependencies are monitored for vulnerabilities
- No secrets are committed to the repository
- All external input is validated

### In CI/CD

- Security scans run on every commit
- Dependencies are checked for known vulnerabilities
- Binaries are built with security flags

### For Users

- Always use the latest version
- Verify checksums when downloading releases
- Review policies before deploying to production
- Follow least-privilege principles for scanner access

## Security Features

DevSec includes security features to help secure your CI/CD:

- **Secret Detection**: Scan for leaked credentials
- **SAST**: Static application security testing
- **Vulnerability Scanning**: Dependency and container vulnerabilities
- **Policy Enforcement**: OPA-based security policies
- **SBOM Generation**: Software bill of materials
- **Artifact Signing**: Cryptographic signing of artifacts

## Dependency Security

We use:
- Dependabot for dependency updates
- OSV for vulnerability scanning
- Trivy for container scanning

## Contact

For security concerns, contact the maintainers through:
- [GitHub Security Advisories](https://github.com/victoralfred/devsec/security/advisories)
- Direct email to repository maintainers
