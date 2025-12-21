# Warn on Secrets Policy
# This policy allows but warns when secrets are detected (scanner == "gitleaks").

package devsec

default decision := {"allow": true, "deny": false, "warnings": [], "metadata": {}}

decision := d if {
	secret_findings := [f | some f in input.findings; f.scanner == "gitleaks"]
	count(secret_findings) > 0
	d := {
		"allow": true,
		"deny": false,
		"warnings": [sprintf("Warning: %d secret(s) detected - review before deployment", [count(secret_findings)])],
		"metadata": {"secret_count": sprintf("%d", [count(secret_findings)])},
	}
}
