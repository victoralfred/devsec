package policy

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

func TestGenerateDocumentation(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy := `# Strict Security Policy
# Description: Blocks high/critical findings and warns on medium
# Version: 1.0.0
# Author: Security Team

package devsec

# Default decision allows if no blocking conditions
default decision := {"allow": true, "deny": false}

# Block on critical findings
decision := d if {
	critical_findings := [f | some f in input.findings; f.severity == "critical"]
	count(critical_findings) > 0
	d := {"allow": false, "deny": true}
}
`
	err = sp.WriteFile("strict.rego", []byte(policy), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	doc, docErr := engine.GenerateDocumentation(ctx, filepath.Join(tmpDir, "strict.rego"))
	if docErr != nil {
		t.Fatalf("GenerateDocumentation() error = %v", docErr)
	}

	if doc.Package != "devsec" {
		t.Errorf("expected package 'devsec', got '%s'", doc.Package)
	}

	if doc.Title != "Strict Security Policy" {
		t.Errorf("expected title 'Strict Security Policy', got '%s'", doc.Title)
	}

	if doc.Version != "1.0.0" {
		t.Errorf("expected version '1.0.0', got '%s'", doc.Version)
	}

	if doc.Author != "Security Team" {
		t.Errorf("expected author 'Security Team', got '%s'", doc.Author)
	}

	if len(doc.Rules) == 0 {
		t.Error("expected at least one rule")
	}
}

func TestGenerateDocumentationFromContent(t *testing.T) {
	engine := New()
	ctx := context.Background()

	policy := `# Test Policy
package devsec
default decision := {"allow": true}
`

	doc, err := engine.GenerateDocumentationFromContent(ctx, "test.rego", policy)
	if err != nil {
		t.Fatalf("GenerateDocumentationFromContent() error = %v", err)
	}

	if doc.Package != "devsec" {
		t.Errorf("expected package 'devsec', got '%s'", doc.Package)
	}

	if doc.Title != "Test Policy" {
		t.Errorf("expected title 'Test Policy', got '%s'", doc.Title)
	}
}

func TestGenerateDocumentationInvalidPolicy(t *testing.T) {
	engine := New()
	ctx := context.Background()

	invalidPolicy := `package devsec
invalid syntax {{{`

	_, err := engine.GenerateDocumentationFromContent(ctx, "invalid.rego", invalidPolicy)
	if err == nil {
		t.Error("expected error for invalid policy")
	}
}

func TestFormatDocumentation(t *testing.T) {
	engine := New()
	ctx := context.Background()

	policy := `# Example Policy
# Description: An example security policy
# Version: 2.0.0
# Author: Test Author

package devsec

# Allow by default
default decision := {"allow": true, "deny": false}

# Block critical findings
decision := d if {
	count([f | some f in input.findings; f.severity == "critical"]) > 0
	d := {"allow": false, "deny": true}
}
`

	doc, err := engine.GenerateDocumentationFromContent(ctx, "example.rego", policy)
	if err != nil {
		t.Fatalf("GenerateDocumentationFromContent() error = %v", err)
	}

	formatted := FormatDocumentation(doc)

	if formatted == "" {
		t.Error("expected non-empty formatted documentation")
	}

	expectedStrings := []string{
		"# Example Policy",
		"Package",
		"devsec",
		"Version",
		"2.0.0",
		"Author",
		"Test Author",
		"## Rules",
		"`decision`",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(formatted, expected) {
			t.Errorf("formatted documentation should contain %q", expected)
		}
	}
}

func TestFormatDocumentationJSON(t *testing.T) {
	engine := New()
	ctx := context.Background()

	policy := `# JSON Test
package devsec
default decision := {"allow": true}
`

	doc, err := engine.GenerateDocumentationFromContent(ctx, "json-test.rego", policy)
	if err != nil {
		t.Fatalf("GenerateDocumentationFromContent() error = %v", err)
	}

	jsonStr, jsonErr := FormatDocumentationJSON(doc)
	if jsonErr != nil {
		t.Fatalf("FormatDocumentationJSON() error = %v", jsonErr)
	}

	if jsonStr == "" {
		t.Error("expected non-empty JSON output")
	}

	expectedStrings := []string{
		`"name"`,
		`"package"`,
		`"devsec"`,
		`"rules"`,
		`"decision"`,
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(jsonStr, expected) {
			t.Errorf("JSON output should contain %q", expected)
		}
	}
}

func TestGenerateDirectoryDocs(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safe path: %v", err)
	}

	policy1 := `# Policy One
package devsec
default decision := {"allow": true}
`
	policy2 := `# Policy Two
package devsec
default decision := {"allow": false}
`

	err = sp.WriteFile("policy1.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy1: %v", err)
	}

	err = sp.WriteFile("policy2.rego", []byte(policy2), 0o644)
	if err != nil {
		t.Fatalf("failed to write policy2: %v", err)
	}

	// Also write a test file that should be skipped.
	err = sp.WriteFile("policy_test.rego", []byte(policy1), 0o644)
	if err != nil {
		t.Fatalf("failed to write test policy: %v", err)
	}

	engine := New()
	ctx := context.Background()

	docs, docsErr := engine.GenerateDirectoryDocs(ctx, tmpDir)
	if docsErr != nil {
		t.Fatalf("GenerateDirectoryDocs() error = %v", docsErr)
	}

	if len(docs) != 2 {
		t.Errorf("expected 2 docs, got %d", len(docs))
	}
}

func TestGenerateDirectoryDocsEmpty(t *testing.T) {
	tmpDir := t.TempDir()

	engine := New()
	ctx := context.Background()

	docs, err := engine.GenerateDirectoryDocs(ctx, tmpDir)
	if err != nil {
		t.Fatalf("GenerateDirectoryDocs() error = %v", err)
	}

	if len(docs) != 0 {
		t.Errorf("expected 0 docs for empty directory, got %d", len(docs))
	}
}

func TestGenerateDirectoryDocsNotFound(t *testing.T) {
	engine := New()
	ctx := context.Background()

	_, err := engine.GenerateDirectoryDocs(ctx, "/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
}

func TestGenerateDocumentationFileNotFound(t *testing.T) {
	engine := New()
	ctx := context.Background()

	_, err := engine.GenerateDocumentation(ctx, "/nonexistent/path/policy.rego")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestGenerateDocumentationContextCancellation(t *testing.T) {
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := engine.GenerateDocumentation(ctx, "/tmp/policy.rego")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestExtractHeaderAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantTitle   string
		wantDesc    string
		wantVersion string
		wantAuthor  string
	}{
		{
			name: "full annotations",
			content: `# Policy Title
# Description: Full description here
# Version: 1.0.0
# Author: Test Author

package devsec`,
			wantTitle:   "Policy Title",
			wantDesc:    "Full description here",
			wantVersion: "1.0.0",
			wantAuthor:  "Test Author",
		},
		{
			name: "title only",
			content: `# Simple Title

package devsec`,
			wantTitle: "Simple Title",
		},
		{
			name:    "no comments",
			content: `package devsec`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := &Doc{}
			doc.extractHeaderAnnotations(tt.content)

			if doc.Title != tt.wantTitle {
				t.Errorf("title = %q, want %q", doc.Title, tt.wantTitle)
			}
			if doc.Description != tt.wantDesc {
				t.Errorf("description = %q, want %q", doc.Description, tt.wantDesc)
			}
			if doc.Version != tt.wantVersion {
				t.Errorf("version = %q, want %q", doc.Version, tt.wantVersion)
			}
			if doc.Author != tt.wantAuthor {
				t.Errorf("author = %q, want %q", doc.Author, tt.wantAuthor)
			}
		})
	}
}

func TestExtractCommentDescription(t *testing.T) {
	content := `package devsec

# This is a description
# on multiple lines
decision := true
`
	desc := extractCommentDescription(content, 5)
	if !strings.Contains(desc, "description") {
		t.Errorf("expected description to contain 'description', got %q", desc)
	}
}

func TestExtractAnnotation(t *testing.T) {
	tests := []struct {
		name    string
		comment string
		prefix  string
		want    string
	}{
		{"version found", "Version: 1.0.0", "Version:", "1.0.0"},
		{"author found", "Author: John Doe", "Author:", "John Doe"},
		{"prefix not found", "Something else", "Version:", ""},
		{"empty value", "Version:", "Version:", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAnnotation(tt.comment, tt.prefix)
			if got != tt.want {
				t.Errorf("extractAnnotation(%q, %q) = %q, want %q", tt.comment, tt.prefix, got, tt.want)
			}
		})
	}
}
