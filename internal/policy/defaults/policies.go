// Package defaults provides embedded default security policies.
package defaults

import _ "embed"

// BlockCritical blocks any critical severity findings.
//
//go:embed block_critical.rego
var BlockCritical string

// BlockHighAndCritical blocks any high or critical severity findings.
//
//go:embed block_high_critical.rego
var BlockHighAndCritical string

// WarnOnSecrets warns but allows when secrets are found.
//
//go:embed warn_secrets.rego
var WarnOnSecrets string

// StrictSecurity blocks all high/critical findings and warns on medium.
//
//go:embed strict_security.rego
var StrictSecurity string
