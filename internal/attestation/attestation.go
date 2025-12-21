// Package attestation provides SLSA provenance and in-toto attestation support.
package attestation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/victoralfred/devsec/internal/signing"
	"github.com/victoralfred/gowritter/safepath"
)

// PredicateType represents the type of attestation predicate.
type PredicateType string

const (
	// PredicateSLSAProvenance represents SLSA provenance predicate.
	PredicateSLSAProvenance PredicateType = "https://slsa.dev/provenance/v1"
	// PredicateVulnScan represents vulnerability scan predicate.
	PredicateVulnScan PredicateType = "https://devsec.dev/attestations/vuln-scan/v1"
	// PredicateSBOM represents SBOM predicate.
	PredicateSBOM PredicateType = "https://spdx.dev/Document"
)

// StatementType is the in-toto statement type.
const StatementType = "https://in-toto.io/Statement/v1"

// Statement represents an in-toto attestation statement.
// Fields ordered for optimal memory alignment.
type Statement struct {
	Predicate     interface{}   `json:"predicate"`
	Type          string        `json:"_type"`
	PredicateType PredicateType `json:"predicateType"`
	Subject       []Subject     `json:"subject"`
}

// Subject represents a subject in an attestation.
type Subject struct {
	Digest map[string]string `json:"digest"`
	Name   string            `json:"name"`
}

// SLSAProvenance represents a SLSA v1.0 provenance predicate.
// Fields ordered for optimal memory alignment.
type SLSAProvenance struct {
	RunDetails      RunDetails      `json:"runDetails"`
	BuildDefinition BuildDefinition `json:"buildDefinition"`
}

// BuildDefinition contains the build definition.
// Fields ordered for optimal memory alignment.
type BuildDefinition struct {
	ExternalParameters   map[string]interface{} `json:"externalParameters,omitempty"`
	InternalParameters   map[string]interface{} `json:"internalParameters,omitempty"`
	BuildType            string                 `json:"buildType"`
	ResolvedDependencies []ResourceDescriptor   `json:"resolvedDependencies,omitempty"`
}

// RunDetails contains details about the build run.
// Fields ordered for optimal memory alignment.
type RunDetails struct {
	Metadata Metadata `json:"metadata,omitempty"`
	Builder  Builder  `json:"builder"`
}

// Builder identifies the build system.
type Builder struct {
	ID string `json:"id"`
}

// Metadata contains build metadata.
// Fields ordered for optimal memory alignment.
type Metadata struct {
	StartedOn    *time.Time `json:"startedOn,omitempty"`
	FinishedOn   *time.Time `json:"finishedOn,omitempty"`
	InvocationID string     `json:"invocationId,omitempty"`
}

// ResourceDescriptor describes a resource.
// Fields ordered for optimal memory alignment.
type ResourceDescriptor struct {
	Digest      map[string]string `json:"digest,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Name        string            `json:"name,omitempty"`
}

// VulnScanPredicate represents a vulnerability scan attestation predicate.
// Fields ordered for optimal memory alignment.
type VulnScanPredicate struct {
	Metadata ScanMetadata `json:"metadata"`
	Scanner  ScannerInfo  `json:"scanner"`
	Summary  ScanSummary  `json:"summary"`
}

// ScanMetadata contains scan metadata.
// Fields ordered for optimal memory alignment.
type ScanMetadata struct {
	ScanStartedOn  time.Time `json:"scanStartedOn"`
	ScanFinishedOn time.Time `json:"scanFinishedOn"`
}

// ScannerInfo contains scanner information.
type ScannerInfo struct {
	URI     string `json:"uri"`
	Version string `json:"version"`
}

// ScanSummary contains scan results summary.
type ScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
}

// Envelope wraps a statement with its signature (DSSE format).
// Fields ordered for optimal memory alignment.
type Envelope struct {
	Payload     string              `json:"payload"`
	PayloadType string              `json:"payloadType"`
	Signatures  []EnvelopeSignature `json:"signatures"`
}

// EnvelopeSignature contains a signature in DSSE format.
type EnvelopeSignature struct {
	Sig       string `json:"sig"`
	KeyID     string `json:"keyid,omitempty"`
	PublicKey string `json:"publicKey,omitempty"`
}

// Generator generates attestations.
type Generator struct {
	builderID   string
	toolVersion string
}

// NewGenerator creates a new attestation generator.
func NewGenerator(builderID, toolVersion string) *Generator {
	return &Generator{
		builderID:   builderID,
		toolVersion: toolVersion,
	}
}

// GenerateProvenance generates a SLSA provenance attestation.
func (g *Generator) GenerateProvenance(ctx context.Context, subjects []Subject, opts ...ProvenanceOption) (*Statement, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Validate subjects
	if len(subjects) == 0 {
		return nil, fmt.Errorf("subjects cannot be empty")
	}

	now := time.Now().UTC()
	prov := &SLSAProvenance{
		BuildDefinition: BuildDefinition{
			BuildType:          "https://devsec.dev/DevSecBuild/v1",
			ExternalParameters: make(map[string]interface{}),
			InternalParameters: map[string]interface{}{
				"platform": runtime.GOOS + "/" + runtime.GOARCH,
			},
		},
		RunDetails: RunDetails{
			Builder: Builder{
				ID: g.builderID,
			},
			Metadata: Metadata{
				StartedOn:  &now,
				FinishedOn: &now,
			},
		},
	}

	// Apply options.
	for _, opt := range opts {
		opt(prov)
	}

	return &Statement{
		Type:          StatementType,
		PredicateType: PredicateSLSAProvenance,
		Subject:       subjects,
		Predicate:     prov,
	}, nil
}

// ProvenanceOption configures provenance generation.
type ProvenanceOption func(*SLSAProvenance)

// WithBuildType sets the build type.
func WithBuildType(buildType string) ProvenanceOption {
	return func(p *SLSAProvenance) {
		p.BuildDefinition.BuildType = buildType
	}
}

// WithDependencies adds resolved dependencies.
func WithDependencies(deps []ResourceDescriptor) ProvenanceOption {
	return func(p *SLSAProvenance) {
		p.BuildDefinition.ResolvedDependencies = deps
	}
}

// WithInvocationID sets the invocation ID.
func WithInvocationID(id string) ProvenanceOption {
	return func(p *SLSAProvenance) {
		p.RunDetails.Metadata.InvocationID = id
	}
}

// WithExternalParameters sets external parameters.
func WithExternalParameters(params map[string]interface{}) ProvenanceOption {
	return func(p *SLSAProvenance) {
		p.BuildDefinition.ExternalParameters = params
	}
}

// GenerateVulnScanAttestation generates a vulnerability scan attestation.
func (g *Generator) GenerateVulnScanAttestation(ctx context.Context, subjects []Subject, summary ScanSummary, scannerURI, scannerVersion string) (*Statement, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	now := time.Now().UTC()
	predicate := &VulnScanPredicate{
		Scanner: ScannerInfo{
			URI:     scannerURI,
			Version: scannerVersion,
		},
		Metadata: ScanMetadata{
			ScanStartedOn:  now,
			ScanFinishedOn: now,
		},
		Summary: summary,
	}

	return &Statement{
		Type:          StatementType,
		PredicateType: PredicateVulnScan,
		Subject:       subjects,
		Predicate:     predicate,
	}, nil
}

// CreateSubjectFromFile creates a subject from a file.
func CreateSubjectFromFile(ctx context.Context, filePath string) (*Subject, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Validate file path
	if filePath == "" {
		return nil, fmt.Errorf("file path cannot be empty")
	}
	if strings.Contains(filePath, "..") {
		return nil, fmt.Errorf("file path contains invalid characters: %s", filePath)
	}

	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	content, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	hash := sha256.Sum256(content)

	return &Subject{
		Name: filename,
		Digest: map[string]string{
			"sha256": hex.EncodeToString(hash[:]),
		},
	}, nil
}

// CreateSubjectFromContent creates a subject from content.
func CreateSubjectFromContent(name string, content []byte) *Subject {
	hash := sha256.Sum256(content)
	return &Subject{
		Name: name,
		Digest: map[string]string{
			"sha256": hex.EncodeToString(hash[:]),
		},
	}
}

// SignStatement signs a statement and creates a DSSE envelope.
func SignStatement(ctx context.Context, stmt *Statement, signer *signing.Signer) (*Envelope, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Validate inputs
	if stmt == nil {
		return nil, fmt.Errorf("statement cannot be nil")
	}
	if signer == nil {
		return nil, fmt.Errorf("signer cannot be nil")
	}

	// Serialize statement to JSON.
	payload, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}

	// Sign the payload.
	sig, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, fmt.Errorf("sign statement: %w", err)
	}

	return &Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodeBase64(payload),
		Signatures: []EnvelopeSignature{
			{
				Sig:       sig.Value,
				KeyID:     sig.KeyID,
				PublicKey: sig.PublicKey,
			},
		},
	}, nil
}

// VerifyEnvelope verifies a DSSE envelope.
func VerifyEnvelope(ctx context.Context, env *Envelope, verifier *signing.Verifier) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Validate inputs
	if env == nil {
		return fmt.Errorf("envelope cannot be nil")
	}
	if verifier == nil {
		return fmt.Errorf("verifier cannot be nil")
	}
	if len(env.Signatures) == 0 {
		return fmt.Errorf("envelope must contain at least one signature")
	}

	// Decode payload.
	if env.Payload == "" {
		return fmt.Errorf("envelope payload cannot be empty")
	}
	payload, err := decodeBase64(env.Payload)
	if err != nil {
		return fmt.Errorf("decode payload: %w", err)
	}

	// Verify each signature.
	for _, envSig := range env.Signatures {
		// Add public key as trusted if provided in envelope.
		if envSig.PublicKey != "" {
			if addErr := verifier.AddTrustedKey(envSig.KeyID, envSig.PublicKey); addErr != nil {
				return fmt.Errorf("add trusted key: %w", addErr)
			}
		}

		sig := &signing.Signature{
			Value:     envSig.Sig,
			KeyID:     envSig.KeyID,
			PublicKey: envSig.PublicKey,
		}

		if verifyErr := verifier.Verify(ctx, payload, sig); verifyErr != nil {
			return fmt.Errorf("signature verification failed: %w", verifyErr)
		}
	}

	return nil
}

// ExtractStatement extracts the statement from an envelope.
func ExtractStatement(env *Envelope) (*Statement, error) {
	if env == nil {
		return nil, fmt.Errorf("envelope cannot be nil")
	}
	if env.Payload == "" {
		return nil, fmt.Errorf("envelope payload cannot be empty")
	}

	payload, err := decodeBase64(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	if len(payload) == 0 {
		return nil, fmt.Errorf("decoded payload is empty")
	}

	var stmt Statement
	if err := json.Unmarshal(payload, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}

	return &stmt, nil
}

// WriteAttestation writes an attestation envelope to a file.
func WriteAttestation(ctx context.Context, path string, env *Envelope) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return sp.WriteFile(filename, data, 0o644)
}

// ReadAttestation reads an attestation envelope from a file.
func ReadAttestation(ctx context.Context, path string) (*Envelope, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var env Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	return &env, nil
}

// WriteStatement writes an unsigned statement to a file.
func WriteStatement(ctx context.Context, path string, stmt *Statement) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	data, err := json.MarshalIndent(stmt, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal statement: %w", err)
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return sp.WriteFile(filename, data, 0o644)
}

// ReadStatement reads an unsigned statement from a file.
func ReadStatement(ctx context.Context, path string) (*Statement, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var stmt Statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return nil, fmt.Errorf("unmarshal statement: %w", err)
	}

	return &stmt, nil
}

// GetBuilderID returns the default builder ID.
func GetBuilderID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return fmt.Sprintf("https://devsec.dev/builder/%s/%s-%s", hostname, runtime.GOOS, runtime.GOARCH)
}

// encodeBase64 encodes bytes to base64 URL encoding without padding.
func encodeBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 URL encoding without padding.
func decodeBase64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
