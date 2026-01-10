# Compliance Policy for DevSec Pipeline
# Enforces compliance requirements for SOC2, ISO 27001, and GDPR.
#
# Usage:
#   Copy this file to your project's ./policies/ directory

package devsec.compliance

import rego.v1

# SOC2 Trust Services Criteria checks
soc2_violations contains msg if {
    some finding in input.findings
    finding.severity in ["critical", "high"]
    finding.cwe != ""
    msg := sprintf("SOC2 CC6.1 violation: %s (CWE-%s)", [finding.title, finding.cwe])
}

# ISO 27001 control checks
iso27001_violations contains msg if {
    some finding in input.findings
    finding.type == "secret"
    msg := sprintf("ISO 27001 A.9.4.3 violation: Secret in source code - %s", [finding.title])
}

iso27001_violations contains msg if {
    some finding in input.findings
    finding.type == "vulnerability"
    finding.severity == "critical"
    msg := sprintf("ISO 27001 A.12.6.1 violation: Critical vulnerability - %s", [finding.title])
}

# GDPR checks (data protection)
gdpr_violations contains msg if {
    some finding in input.findings
    contains(lower(finding.title), "pii")
    msg := sprintf("GDPR Article 32 violation: PII exposure risk - %s", [finding.title])
}

gdpr_violations contains msg if {
    some finding in input.findings
    contains(lower(finding.title), "encryption")
    finding.severity in ["critical", "high"]
    msg := sprintf("GDPR Article 32 violation: Encryption issue - %s", [finding.title])
}

# Aggregate compliance status
compliance_status := {
    "soc2": {
        "passed": count(soc2_violations) == 0,
        "violations": count(soc2_violations),
    },
    "iso27001": {
        "passed": count(iso27001_violations) == 0,
        "violations": count(iso27001_violations),
    },
    "gdpr": {
        "passed": count(gdpr_violations) == 0,
        "violations": count(gdpr_violations),
    },
}

# Overall compliance pass/fail
default compliant := false

compliant if {
    count(soc2_violations) == 0
    count(iso27001_violations) == 0
    count(gdpr_violations) == 0
}
