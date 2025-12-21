// Package policy provides OPA-based policy evaluation for security findings.
package policy

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/victoralfred/gowritter/safepath"
)

const (
	// MaxDocs is the maximum number of policy docs to generate to prevent DoS.
	MaxDocs = 1000
)

// Doc represents documentation for a policy.
type Doc struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	Package     string          `json:"package"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	Version     string          `json:"version,omitempty"`
	Author      string          `json:"author,omitempty"`
	Annotations []AnnotationDoc `json:"annotations,omitempty"`
	Rules       []RuleDoc       `json:"rules"`
}

// RuleDoc represents documentation for a rule.
type RuleDoc struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Examples    []string `json:"examples,omitempty"`
	Default     bool     `json:"default"`
}

// AnnotationDoc represents a policy annotation.
type AnnotationDoc struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// GenerateDocumentation generates documentation for a policy file.
func (e *Engine) GenerateDocumentation(ctx context.Context, policyPath string) (Doc, error) {
	doc := Doc{
		Path:        policyPath,
		GeneratedAt: time.Now().UTC(),
		Rules:       make([]RuleDoc, 0),
		Annotations: make([]AnnotationDoc, 0),
	}

	// Check context.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return doc, fmt.Errorf("context canceled: %w", ctxErr)
	}

	// Validate path
	if policyPath == "" {
		return doc, fmt.Errorf("policy path cannot be empty")
	}
	if strings.Contains(policyPath, "..") {
		return doc, fmt.Errorf("policy path contains invalid characters: %s", policyPath)
	}

	// Read the policy file.
	absPath, err := filepath.Abs(policyPath)
	if err != nil {
		return doc, fmt.Errorf("failed to resolve path: %w", err)
	}

	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)
	doc.Name = strings.TrimSuffix(filename, ".rego")

	sp, spErr := safepath.New(dir)
	if spErr != nil {
		return doc, fmt.Errorf("directory not accessible: %w", spErr)
	}

	data, readErr := sp.ReadFile(filename)
	if readErr != nil {
		return doc, fmt.Errorf("failed to read file: %w", readErr)
	}

	return e.GenerateDocumentationFromContent(ctx, absPath, string(data))
}

// GenerateDocumentationFromContent generates documentation from policy content.
func (e *Engine) GenerateDocumentationFromContent(_ context.Context, name, content string) (Doc, error) {
	doc := Doc{
		Path:        name,
		Name:        filepath.Base(name),
		GeneratedAt: time.Now().UTC(),
		Rules:       make([]RuleDoc, 0),
		Annotations: make([]AnnotationDoc, 0),
	}

	// Parse the policy.
	module, parseErr := ast.ParseModule(name, content)
	if parseErr != nil {
		return doc, fmt.Errorf("failed to parse policy: %w", parseErr)
	}

	// Extract package name (skip "data" prefix which is OPA internal root).
	if module.Package != nil && module.Package.Path != nil {
		parts := make([]string, 0, len(module.Package.Path))
		for _, p := range module.Package.Path {
			// Get the string value, removing quotes if present.
			val := p.Value.String()
			val = strings.Trim(val, `"`)
			// Skip the OPA "data" root reference.
			if val == "data" && len(parts) == 0 {
				continue
			}
			parts = append(parts, val)
		}
		doc.Package = strings.Join(parts, ".")
	}

	// Extract policy-level annotations from comments.
	doc.extractHeaderAnnotations(content)

	// Extract rules and their documentation.
	for _, rule := range module.Rules {
		ruleDoc := RuleDoc{
			Name:    string(rule.Head.Name),
			Default: rule.Default,
		}

		// Extract description from rule annotations.
		if len(rule.Annotations) > 0 {
			for _, ann := range rule.Annotations {
				if ann.Description != "" {
					ruleDoc.Description = ann.Description
				}
			}
		}

		// Try to extract description from comment above rule.
		if ruleDoc.Description == "" && rule.Location != nil {
			ruleDoc.Description = extractCommentDescription(content, rule.Location.Row)
		}

		doc.Rules = append(doc.Rules, ruleDoc)
	}

	return doc, nil
}

// extractHeaderAnnotations extracts annotations from the policy header comments.
func (doc *Doc) extractHeaderAnnotations(content string) {
	lines := strings.Split(content, "\n")

	// Look for annotations in header comments before the package statement.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Stop at package statement.
		if strings.HasPrefix(trimmed, "package ") {
			break
		}

		// Skip empty lines and non-comment lines.
		if !strings.HasPrefix(trimmed, "#") {
			continue
		}

		comment := strings.TrimPrefix(trimmed, "#")
		comment = strings.TrimSpace(comment)

		// Check for annotation patterns.
		if title := extractAnnotation(comment, "Title:"); title != "" {
			doc.Title = title
		} else if desc := extractAnnotation(comment, "Description:"); desc != "" {
			doc.Description = desc
		} else if version := extractAnnotation(comment, "Version:"); version != "" {
			doc.Version = version
		} else if author := extractAnnotation(comment, "Author:"); author != "" {
			doc.Author = author
		} else if !strings.Contains(comment, ":") && doc.Title == "" && comment != "" {
			// Use first non-annotation comment as title.
			doc.Title = comment
		}
	}
}

// extractAnnotation extracts a value from a comment annotation.
func extractAnnotation(comment, prefix string) string {
	if strings.HasPrefix(comment, prefix) {
		return strings.TrimSpace(strings.TrimPrefix(comment, prefix))
	}
	return ""
}

// extractCommentDescription extracts description from comment lines above a rule.
func extractCommentDescription(content string, ruleLine int) string {
	lines := strings.Split(content, "\n")
	if ruleLine <= 1 || ruleLine > len(lines) {
		return ""
	}

	// Look at the line(s) above the rule.
	var comments []string
	for i := ruleLine - 2; i >= 0; i-- {
		trimmed := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(trimmed, "#"):
			comment := strings.TrimPrefix(trimmed, "#")
			comment = strings.TrimSpace(comment)
			comments = append([]string{comment}, comments...)
		case trimmed == "":
			continue
		default:
			i = -1 // break out of loop
		}
	}

	return strings.Join(comments, " ")
}

// FormatDocumentation formats a Doc as markdown.
func FormatDocumentation(doc Doc) string {
	var builder strings.Builder
	builder.Grow(2048)

	// Title.
	title := doc.Title
	if title == "" {
		title = doc.Name
	}
	builder.WriteString("# " + title + "\n\n")

	// Metadata table.
	builder.WriteString("| Property | Value |\n")
	builder.WriteString("|----------|-------|\n")
	builder.WriteString(fmt.Sprintf("| Package | `%s` |\n", doc.Package))
	builder.WriteString(fmt.Sprintf("| File | `%s` |\n", filepath.Base(doc.Path)))
	if doc.Version != "" {
		builder.WriteString(fmt.Sprintf("| Version | %s |\n", doc.Version))
	}
	if doc.Author != "" {
		builder.WriteString(fmt.Sprintf("| Author | %s |\n", doc.Author))
	}
	builder.WriteString("\n")

	// Description.
	if doc.Description != "" {
		builder.WriteString("## Description\n\n")
		builder.WriteString(doc.Description + "\n\n")
	}

	// Rules.
	if len(doc.Rules) > 0 {
		builder.WriteString("## Rules\n\n")
		for _, rule := range doc.Rules {
			builder.WriteString("### `" + rule.Name + "`\n\n")
			if rule.Default {
				builder.WriteString("*Default rule*\n\n")
			}
			if rule.Description != "" {
				builder.WriteString(rule.Description + "\n\n")
			}
		}
	}

	// Footer.
	builder.WriteString("---\n\n")
	builder.WriteString(fmt.Sprintf("*Generated at: %s*\n", doc.GeneratedAt.Format(time.RFC3339)))

	return builder.String()
}

// FormatDocumentationJSON formats a Doc as JSON string.
func FormatDocumentationJSON(doc Doc) (string, error) {
	// Use simple formatting to avoid import.
	var builder strings.Builder
	builder.Grow(1024)

	builder.WriteString("{\n")
	builder.WriteString(fmt.Sprintf("  \"name\": %q,\n", doc.Name))
	builder.WriteString(fmt.Sprintf("  \"path\": %q,\n", doc.Path))
	builder.WriteString(fmt.Sprintf("  \"package\": %q,\n", doc.Package))

	if doc.Title != "" {
		builder.WriteString(fmt.Sprintf("  \"title\": %q,\n", doc.Title))
	}
	if doc.Description != "" {
		builder.WriteString(fmt.Sprintf("  \"description\": %q,\n", doc.Description))
	}
	if doc.Version != "" {
		builder.WriteString(fmt.Sprintf("  \"version\": %q,\n", doc.Version))
	}
	if doc.Author != "" {
		builder.WriteString(fmt.Sprintf("  \"author\": %q,\n", doc.Author))
	}

	builder.WriteString("  \"rules\": [\n")
	for i, rule := range doc.Rules {
		builder.WriteString("    {\n")
		builder.WriteString(fmt.Sprintf("      \"name\": %q,\n", rule.Name))
		builder.WriteString(fmt.Sprintf("      \"default\": %t", rule.Default))
		if rule.Description != "" {
			builder.WriteString(fmt.Sprintf(",\n      \"description\": %q", rule.Description))
		}
		builder.WriteString("\n    }")
		if i < len(doc.Rules)-1 {
			builder.WriteString(",")
		}
		builder.WriteString("\n")
	}
	builder.WriteString("  ],\n")

	builder.WriteString(fmt.Sprintf("  \"generated_at\": %q\n", doc.GeneratedAt.Format(time.RFC3339)))
	builder.WriteString("}\n")

	return builder.String(), nil
}

// GenerateDirectoryDocs generates documentation for all policies in a directory.
func (e *Engine) GenerateDirectoryDocs(ctx context.Context, dirPath string) ([]Doc, error) {
	docs := make([]Doc, 0, 100) // Pre-allocate with capacity

	// Validate path
	if dirPath == "" {
		return docs, fmt.Errorf("directory path cannot be empty")
	}
	if strings.Contains(dirPath, "..") {
		return docs, fmt.Errorf("directory path contains invalid characters: %s", dirPath)
	}

	absPath, err := filepath.Abs(dirPath)
	if err != nil {
		return docs, fmt.Errorf("failed to resolve directory path: %w", err)
	}

	sp, spErr := safepath.New(absPath)
	if spErr != nil {
		return docs, fmt.Errorf("directory not accessible: %w", spErr)
	}

	entries, readErr := sp.ReadDir(".")
	if readErr != nil {
		return docs, fmt.Errorf("failed to read directory: %w", readErr)
	}

	regoPattern := regexp.MustCompile(`\.rego$`)
	testPattern := regexp.MustCompile(`_test\.rego$`)

	for _, entry := range entries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return docs, fmt.Errorf("context canceled: %w", ctxErr)
		}

		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !regoPattern.MatchString(name) {
			continue
		}
		if testPattern.MatchString(name) {
			continue
		}

		// Check limit
		if len(docs) >= MaxDocs {
			return docs, fmt.Errorf("documentation limit exceeded: %d (max %d)", len(docs), MaxDocs)
		}

		policyPath := filepath.Join(absPath, name)
		doc, docErr := e.GenerateDocumentation(ctx, policyPath)
		if docErr != nil {
			continue // Skip files that fail to parse.
		}

		docs = append(docs, doc)
	}

	return docs, nil
}
