# Block High and Critical Findings Policy
# This policy denies if any high or critical severity findings are present.

package devsec

default decision := {"allow": true, "deny": false, "warnings": [], "metadata": {}}

decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	high_findings := [f | some f in input.findings; f.severity == "high"]
	total := count(critical_findings) + count(high_findings)
	total > 0
	d := {
		"allow": false,
		"deny": true,
		"warnings": [sprintf("Found %d critical and %d high severity finding(s)", [count(critical_findings), count(high_findings)])],
		"metadata": {
			"blocked_by": "high_critical_findings",
			"critical_count": sprintf("%d", [count(critical_findings)]),
			"high_count": sprintf("%d", [count(high_findings)]),
		},
	}
}
