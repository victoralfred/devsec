# Strict Security Policy
# This policy blocks high/critical findings and warns on medium severity.

package devsec

default decision := {"allow": true, "deny": false, "warnings": [], "metadata": {}}

# Block on critical findings
decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	count(critical_findings) > 0
	d := {
		"allow": false,
		"deny": true,
		"warnings": [sprintf("BLOCKED: %d critical finding(s) must be fixed", [count(critical_findings)])],
		"metadata": {"blocked_by": "critical", "severity": "critical"},
	}
}

# Block on high findings (when no critical)
decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	high_findings := [f | some f in input.findings; f.severity == "high"]
	count(critical_findings) == 0
	count(high_findings) > 0
	d := {
		"allow": false,
		"deny": true,
		"warnings": [sprintf("BLOCKED: %d high severity finding(s) must be fixed", [count(high_findings)])],
		"metadata": {"blocked_by": "high", "severity": "high"},
	}
}

# Warn on medium findings (when no high/critical)
decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	high_findings := [f | some f in input.findings; f.severity == "high"]
	medium_findings := [f | some f in input.findings; f.severity == "medium"]
	count(critical_findings) == 0
	count(high_findings) == 0
	count(medium_findings) > 0
	d := {
		"allow": true,
		"deny": false,
		"warnings": [sprintf("Warning: %d medium severity finding(s) should be reviewed", [count(medium_findings)])],
		"metadata": {"warning_severity": "medium"},
	}
}
