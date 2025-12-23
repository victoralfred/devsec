# Example Security Policies

OPA Rego policies for DevSec pipeline policy evaluation.

## Files

| Policy | Description |
|--------|-------------|
| [security.rego](security.rego) | General security policy with severity thresholds |
| [compliance.rego](compliance.rego) | Compliance framework policies (SOC2, ISO 27001, GDPR) |

## Usage

Copy policies to your project:

```bash
mkdir -p ./policies
cp examples/policies/*.rego ./policies/
```

Reference in pipeline:

```yaml
stages:
  - name: policy
    kind: policy
    config:
      policy_dir: ./policies
      fail_on: high
```

## Policy Structure

### security.rego

- Blocks on critical/high severity findings
- Specific rules for secrets, vulnerabilities, and injection flaws
- Provides summary with counts per severity

### compliance.rego

- SOC2 Trust Services Criteria (CC6.1)
- ISO 27001 controls (A.9.4.3, A.12.6.1)
- GDPR Article 32 (data protection)
- Aggregate compliance status per framework

## Customization

### Change Severity Threshold

```rego
# Allow medium findings
allow if {
    count(critical_findings) == 0
    count(high_findings) == 0
    # Remove: count(medium_findings) == 0
}
```

### Add Custom Rule

```rego
# Block specific CVE
deny[msg] {
    finding := input.findings[_]
    finding.cve == "CVE-2021-44228"  # Log4Shell
    msg := "Log4Shell vulnerability detected"
}
```

### Exempt Specific Paths

```rego
# Skip test files
allow if {
    finding := input.findings[_]
    contains(finding.file, "_test.go")
}
```

## Testing Policies

```bash
# Validate policy syntax
devsec policy validate ./policies/

# Test with sample findings
devsec policy check --policy ./policies/security.rego --findings sample-findings.json
```

## See Also

- [OPA Rego Documentation](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [DevSec Policy Commands](../../README.md#policy-commands)
