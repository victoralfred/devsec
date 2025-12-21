# Block Critical Findings Policy
# This policy denies if any critical severity findings are present.

package devsec

default decision := {"allow": true, "deny": false, "warnings": [], "metadata": {}}

decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	count(critical_findings) > 0
	d := {
		"allow": false,
		"deny": true,
		"warnings": [sprintf("Found %d critical finding(s)", [count(critical_findings)])],
		"metadata": {"blocked_by": "critical_findings", "count": sprintf("%d", [count(critical_findings)])},
	}
}
