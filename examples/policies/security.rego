# Security Policy for DevSec Pipeline
# This policy evaluates security findings and enforces thresholds.
#
# Usage:
#   Copy this file to your project's ./policies/ directory
#   Reference it in pipeline stages with policy_dir config

package devsec.security

import future.keywords.if
import future.keywords.in

# Default deny - findings must pass all rules
default allow := false

# Allow if no critical or high severity findings
allow if {
    count(critical_findings) == 0
    count(high_findings) == 0
}

# Critical findings (must be zero)
critical_findings[finding] {
    finding := input.findings[_]
    finding.severity == "critical"
}

# High severity findings
high_findings[finding] {
    finding := input.findings[_]
    finding.severity == "high"
}

# Medium severity findings (warning only)
medium_findings[finding] {
    finding := input.findings[_]
    finding.severity == "medium"
}

# Secret detection rule - always fail on secrets
deny[msg] {
    finding := input.findings[_]
    finding.type == "secret"
    msg := sprintf("Secret detected: %s in %s", [finding.title, finding.file])
}

# Vulnerability rule - fail on critical CVEs
deny[msg] {
    finding := input.findings[_]
    finding.type == "vulnerability"
    finding.severity == "critical"
    msg := sprintf("Critical vulnerability: %s (%s)", [finding.title, finding.cve])
}

# SAST rule - fail on injection vulnerabilities
deny[msg] {
    finding := input.findings[_]
    finding.type == "sast"
    contains(lower(finding.title), "injection")
    msg := sprintf("Injection vulnerability: %s in %s:%d", [finding.title, finding.file, finding.line])
}

# Summary output
summary := {
    "total_findings": count(input.findings),
    "critical": count(critical_findings),
    "high": count(high_findings),
    "medium": count(medium_findings),
    "passed": allow,
}
