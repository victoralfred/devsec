package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/victoralfred/devsec/internal/signing"
)

func TestNewGenerator(t *testing.T) {
	gen := NewGenerator("test-builder", "1.0.0")
	if gen == nil {
		t.Fatal("expected generator, got nil")
	}
	if gen.builderID != "test-builder" {
		t.Errorf("expected builderID 'test-builder', got %q", gen.builderID)
	}
	if gen.toolVersion != "1.0.0" {
		t.Errorf("expected toolVersion '1.0.0', got %q", gen.toolVersion)
	}
}

func TestGenerateProvenance(t *testing.T) {
	ctx := context.Background()
	gen := NewGenerator("test-builder", "1.0.0")

	subjects := []Subject{
		{
			Name: "test-artifact",
			Digest: map[string]string{
				"sha256": "abc123",
			},
		},
	}

	stmt, err := gen.GenerateProvenance(ctx, subjects)
	if err != nil {
		t.Fatalf("GenerateProvenance failed: %v", err)
	}

	if stmt.Type != StatementType {
		t.Errorf("expected Type %q, got %q", StatementType, stmt.Type)
	}
	if stmt.PredicateType != PredicateSLSAProvenance {
		t.Errorf("expected PredicateType %q, got %q", PredicateSLSAProvenance, stmt.PredicateType)
	}
	if len(stmt.Subject) != 1 {
		t.Errorf("expected 1 subject, got %d", len(stmt.Subject))
	}

	prov, ok := stmt.Predicate.(*SLSAProvenance)
	if !ok {
		t.Fatal("expected predicate to be *SLSAProvenance")
	}
	if prov.RunDetails.Builder.ID != "test-builder" {
		t.Errorf("expected builder ID 'test-builder', got %q", prov.RunDetails.Builder.ID)
	}
}

func TestGenerateProvenanceWithOptions(t *testing.T) {
	ctx := context.Background()
	gen := NewGenerator("test-builder", "1.0.0")

	subjects := []Subject{
		{Name: "test", Digest: map[string]string{"sha256": "abc"}},
	}

	deps := []ResourceDescriptor{
		{URI: "pkg:golang/example.com/dep@v1.0.0", Name: "dep"},
	}

	stmt, err := gen.GenerateProvenance(ctx, subjects,
		WithBuildType("https://custom.build/v1"),
		WithDependencies(deps),
		WithInvocationID("inv-123"),
		WithExternalParameters(map[string]interface{}{"target": "linux/amd64"}),
	)
	if err != nil {
		t.Fatalf("GenerateProvenance failed: %v", err)
	}

	prov, ok := stmt.Predicate.(*SLSAProvenance)
	if !ok {
		t.Fatal("expected predicate to be *SLSAProvenance")
	}

	if prov.BuildDefinition.BuildType != "https://custom.build/v1" {
		t.Errorf("expected custom build type, got %q", prov.BuildDefinition.BuildType)
	}
	if len(prov.BuildDefinition.ResolvedDependencies) != 1 {
		t.Errorf("expected 1 dependency, got %d", len(prov.BuildDefinition.ResolvedDependencies))
	}
	if prov.RunDetails.Metadata.InvocationID != "inv-123" {
		t.Errorf("expected invocationID 'inv-123', got %q", prov.RunDetails.Metadata.InvocationID)
	}
	if prov.BuildDefinition.ExternalParameters["target"] != "linux/amd64" {
		t.Error("expected external parameter 'target' to be set")
	}
}

func TestGenerateProvenanceContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gen := NewGenerator("test-builder", "1.0.0")
	subjects := []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}}

	_, err := gen.GenerateProvenance(ctx, subjects)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestGenerateVulnScanAttestation(t *testing.T) {
	ctx := context.Background()
	gen := NewGenerator("test-builder", "1.0.0")

	subjects := []Subject{
		{Name: "test-image", Digest: map[string]string{"sha256": "abc123"}},
	}

	summary := ScanSummary{
		Critical: 0,
		High:     2,
		Medium:   5,
		Low:      10,
		Info:     3,
		Total:    20,
	}

	stmt, err := gen.GenerateVulnScanAttestation(ctx, subjects, summary, "https://trivy.dev", "0.50.0")
	if err != nil {
		t.Fatalf("GenerateVulnScanAttestation failed: %v", err)
	}

	if stmt.PredicateType != PredicateVulnScan {
		t.Errorf("expected PredicateType %q, got %q", PredicateVulnScan, stmt.PredicateType)
	}

	pred, ok := stmt.Predicate.(*VulnScanPredicate)
	if !ok {
		t.Fatal("expected predicate to be *VulnScanPredicate")
	}
	if pred.Scanner.URI != "https://trivy.dev" {
		t.Errorf("expected scanner URI 'https://trivy.dev', got %q", pred.Scanner.URI)
	}
	if pred.Summary.Total != 20 {
		t.Errorf("expected total 20, got %d", pred.Summary.Total)
	}
}

func TestGenerateVulnScanContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	gen := NewGenerator("test-builder", "1.0.0")
	subjects := []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}}
	summary := ScanSummary{}

	_, err := gen.GenerateVulnScanAttestation(ctx, subjects, summary, "uri", "1.0")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestCreateSubjectFromContent(t *testing.T) {
	content := []byte("hello world")
	subject := CreateSubjectFromContent("test.txt", content)

	if subject.Name != "test.txt" {
		t.Errorf("expected name 'test.txt', got %q", subject.Name)
	}
	if subject.Digest["sha256"] == "" {
		t.Error("expected sha256 digest to be set")
	}
	// SHA256 of "hello world"
	expected := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if subject.Digest["sha256"] != expected {
		t.Errorf("expected digest %q, got %q", expected, subject.Digest["sha256"])
	}
}

func TestCreateSubjectFromFile(t *testing.T) {
	ctx := context.Background()

	// Create temp file.
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	content := []byte("test content for hashing")
	if err := os.WriteFile(testFile, content, 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	subject, err := CreateSubjectFromFile(ctx, testFile)
	if err != nil {
		t.Fatalf("CreateSubjectFromFile failed: %v", err)
	}

	if subject.Name != "test.txt" {
		t.Errorf("expected name 'test.txt', got %q", subject.Name)
	}
	if subject.Digest["sha256"] == "" {
		t.Error("expected sha256 digest")
	}
}

func TestCreateSubjectFromFileNotExists(t *testing.T) {
	ctx := context.Background()
	_, err := CreateSubjectFromFile(ctx, "/nonexistent/file.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestCreateSubjectFromFileContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := CreateSubjectFromFile(ctx, "/some/file")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestSignStatement(t *testing.T) {
	ctx := context.Background()

	// Create a signer.
	signer, err := signing.NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	stmt := &Statement{
		Type:          StatementType,
		PredicateType: PredicateSLSAProvenance,
		Subject: []Subject{
			{Name: "test", Digest: map[string]string{"sha256": "abc123"}},
		},
		Predicate: map[string]interface{}{"test": "value"},
	}

	env, err := SignStatement(ctx, stmt, signer)
	if err != nil {
		t.Fatalf("SignStatement failed: %v", err)
	}

	if env.PayloadType != "application/vnd.in-toto+json" {
		t.Errorf("expected payload type 'application/vnd.in-toto+json', got %q", env.PayloadType)
	}
	if env.Payload == "" {
		t.Error("expected non-empty payload")
	}
	if len(env.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(env.Signatures))
	}
}

func TestSignStatementContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	signer, _ := signing.NewSigner()
	stmt := &Statement{Type: StatementType}

	_, err := SignStatement(ctx, stmt, signer)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestVerifyEnvelope(t *testing.T) {
	ctx := context.Background()

	// Create and sign a statement.
	signer, err := signing.NewSigner()
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}

	stmt := &Statement{
		Type:          StatementType,
		PredicateType: PredicateSLSAProvenance,
		Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		Predicate:     map[string]interface{}{"test": true},
	}

	env, err := SignStatement(ctx, stmt, signer)
	if err != nil {
		t.Fatalf("SignStatement failed: %v", err)
	}

	// Verify the envelope.
	verifier := signing.NewVerifier()
	if verifyErr := VerifyEnvelope(ctx, env, verifier); verifyErr != nil {
		t.Errorf("VerifyEnvelope failed: %v", verifyErr)
	}
}

func TestVerifyEnvelopeInvalidSignature(t *testing.T) {
	ctx := context.Background()

	env := &Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodeBase64([]byte(`{"test":"data"}`)),
		Signatures: []EnvelopeSignature{
			{Sig: "invalid-signature", KeyID: "invalid-key"},
		},
	}

	verifier := signing.NewVerifier()
	err := VerifyEnvelope(ctx, env, verifier)
	if err == nil {
		t.Error("expected error for invalid signature")
	}
}

func TestVerifyEnvelopeContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := &Envelope{}
	verifier := signing.NewVerifier()

	err := VerifyEnvelope(ctx, env, verifier)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestExtractStatement(t *testing.T) {
	original := &Statement{
		Type:          StatementType,
		PredicateType: PredicateSLSAProvenance,
		Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc123"}}},
		Predicate:     map[string]interface{}{"key": "value"},
	}

	payload, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal statement: %v", err)
	}

	env := &Envelope{
		Payload: encodeBase64(payload),
	}

	stmt, err := ExtractStatement(env)
	if err != nil {
		t.Fatalf("ExtractStatement failed: %v", err)
	}

	if stmt.Type != original.Type {
		t.Errorf("expected Type %q, got %q", original.Type, stmt.Type)
	}
	if stmt.PredicateType != original.PredicateType {
		t.Errorf("expected PredicateType %q, got %q", original.PredicateType, stmt.PredicateType)
	}
}

func TestExtractStatementInvalidPayload(t *testing.T) {
	env := &Envelope{
		Payload: "not-valid-base64!!!",
	}

	_, err := ExtractStatement(env)
	if err == nil {
		t.Error("expected error for invalid base64 payload")
	}
}

func TestWriteAndReadAttestation(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	attestPath := filepath.Join(tmpDir, "attest.json")

	original := &Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     encodeBase64([]byte(`{"test":"data"}`)),
		Signatures: []EnvelopeSignature{
			{Sig: "signature", KeyID: "key123"},
		},
	}

	// Write.
	if err := WriteAttestation(ctx, attestPath, original); err != nil {
		t.Fatalf("WriteAttestation failed: %v", err)
	}

	// Read.
	loaded, err := ReadAttestation(ctx, attestPath)
	if err != nil {
		t.Fatalf("ReadAttestation failed: %v", err)
	}

	if loaded.PayloadType != original.PayloadType {
		t.Errorf("expected PayloadType %q, got %q", original.PayloadType, loaded.PayloadType)
	}
	if loaded.Payload != original.Payload {
		t.Errorf("expected Payload %q, got %q", original.Payload, loaded.Payload)
	}
	if len(loaded.Signatures) != 1 {
		t.Errorf("expected 1 signature, got %d", len(loaded.Signatures))
	}
}

func TestWriteAttestationContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	env := &Envelope{}
	err := WriteAttestation(ctx, "/tmp/test.json", env)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestReadAttestationNotExists(t *testing.T) {
	ctx := context.Background()
	_, err := ReadAttestation(ctx, "/nonexistent/attest.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestReadAttestationContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ReadAttestation(ctx, "/some/path.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestWriteAndReadStatement(t *testing.T) {
	ctx := context.Background()

	tmpDir := t.TempDir()
	stmtPath := filepath.Join(tmpDir, "stmt.json")

	original := &Statement{
		Type:          StatementType,
		PredicateType: PredicateSLSAProvenance,
		Subject:       []Subject{{Name: "test", Digest: map[string]string{"sha256": "abc"}}},
		Predicate:     map[string]interface{}{"key": "value"},
	}

	// Write.
	if err := WriteStatement(ctx, stmtPath, original); err != nil {
		t.Fatalf("WriteStatement failed: %v", err)
	}

	// Read.
	loaded, err := ReadStatement(ctx, stmtPath)
	if err != nil {
		t.Fatalf("ReadStatement failed: %v", err)
	}

	if loaded.Type != original.Type {
		t.Errorf("expected Type %q, got %q", original.Type, loaded.Type)
	}
	if loaded.PredicateType != original.PredicateType {
		t.Errorf("expected PredicateType %q, got %q", original.PredicateType, loaded.PredicateType)
	}
}

func TestWriteStatementContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	stmt := &Statement{}
	err := WriteStatement(ctx, "/tmp/test.json", stmt)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestReadStatementNotExists(t *testing.T) {
	ctx := context.Background()
	_, err := ReadStatement(ctx, "/nonexistent/stmt.json")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestReadStatementContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ReadStatement(ctx, "/some/path.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

func TestGetBuilderID(t *testing.T) {
	builderID := GetBuilderID()
	if builderID == "" {
		t.Error("expected non-empty builder ID")
	}
	// Should contain the devsec prefix.
	if len(builderID) < 30 {
		t.Errorf("builder ID seems too short: %q", builderID)
	}
}

func TestBase64EncodeDecode(t *testing.T) {
	original := []byte("test data for encoding")

	encoded := encodeBase64(original)
	if encoded == "" {
		t.Error("expected non-empty encoded string")
	}

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("decodeBase64 failed: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("expected %q, got %q", string(original), string(decoded))
	}
}

func TestDecodeBase64Invalid(t *testing.T) {
	_, err := decodeBase64("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestPredicateTypes(t *testing.T) {
	tests := []struct {
		predType PredicateType
		expected string
	}{
		{PredicateSLSAProvenance, "https://slsa.dev/provenance/v1"},
		{PredicateVulnScan, "https://devsec.dev/attestations/vuln-scan/v1"},
		{PredicateSBOM, "https://spdx.dev/Document"},
	}

	for _, tt := range tests {
		if string(tt.predType) != tt.expected {
			t.Errorf("expected %q, got %q", tt.expected, string(tt.predType))
		}
	}
}

func TestStatementType(t *testing.T) {
	if StatementType != "https://in-toto.io/Statement/v1" {
		t.Errorf("unexpected StatementType: %q", StatementType)
	}
}

func TestMetadataTimestamps(t *testing.T) {
	now := time.Now().UTC()
	meta := Metadata{
		StartedOn:    &now,
		FinishedOn:   &now,
		InvocationID: "test-123",
	}

	if meta.StartedOn == nil {
		t.Error("expected StartedOn to be set")
	}
	if meta.FinishedOn == nil {
		t.Error("expected FinishedOn to be set")
	}
	if meta.InvocationID != "test-123" {
		t.Errorf("expected InvocationID 'test-123', got %q", meta.InvocationID)
	}
}

func TestResourceDescriptor(t *testing.T) {
	rd := ResourceDescriptor{
		URI:  "pkg:golang/example.com/pkg@v1.0.0",
		Name: "pkg",
		Digest: map[string]string{
			"sha256": "abc123",
		},
		Annotations: map[string]string{
			"source": "go.mod",
		},
	}

	if rd.URI != "pkg:golang/example.com/pkg@v1.0.0" {
		t.Errorf("unexpected URI: %q", rd.URI)
	}
	if rd.Name != "pkg" {
		t.Errorf("unexpected Name: %q", rd.Name)
	}
	if rd.Digest["sha256"] != "abc123" {
		t.Error("expected sha256 digest")
	}
	if rd.Annotations["source"] != "go.mod" {
		t.Error("expected annotation 'source'")
	}
}

func TestScanSummary(t *testing.T) {
	summary := ScanSummary{
		Critical: 1,
		High:     2,
		Medium:   3,
		Low:      4,
		Info:     5,
		Total:    15,
	}

	expectedTotal := summary.Critical + summary.High + summary.Medium + summary.Low + summary.Info
	if summary.Total != expectedTotal {
		t.Errorf("total mismatch: expected %d, got %d", expectedTotal, summary.Total)
	}
}

func TestEnvelopeSignatureFields(t *testing.T) {
	sig := EnvelopeSignature{
		Sig:   "base64-signature",
		KeyID: "key-12345",
	}

	if sig.Sig != "base64-signature" {
		t.Errorf("unexpected Sig: %q", sig.Sig)
	}
	if sig.KeyID != "key-12345" {
		t.Errorf("unexpected KeyID: %q", sig.KeyID)
	}
}

func TestGeneratorFields(t *testing.T) {
	gen := &Generator{
		builderID:   "builder-1",
		toolVersion: "2.0.0",
	}

	if gen.builderID != "builder-1" {
		t.Errorf("unexpected builderID: %q", gen.builderID)
	}
	if gen.toolVersion != "2.0.0" {
		t.Errorf("unexpected toolVersion: %q", gen.toolVersion)
	}
}

func TestScanMetadata(t *testing.T) {
	now := time.Now().UTC()
	later := now.Add(5 * time.Minute)

	meta := ScanMetadata{
		ScanStartedOn:  now,
		ScanFinishedOn: later,
	}

	if meta.ScanStartedOn.IsZero() {
		t.Error("expected ScanStartedOn to be set")
	}
	if !meta.ScanFinishedOn.After(meta.ScanStartedOn) {
		t.Error("expected ScanFinishedOn to be after ScanStartedOn")
	}
}

func TestScannerInfo(t *testing.T) {
	info := ScannerInfo{
		URI:     "https://scanner.example.com",
		Version: "1.2.3",
	}

	if info.URI != "https://scanner.example.com" {
		t.Errorf("unexpected URI: %q", info.URI)
	}
	if info.Version != "1.2.3" {
		t.Errorf("unexpected Version: %q", info.Version)
	}
}

func TestBuilderStruct(t *testing.T) {
	builder := Builder{ID: "https://builder.example.com/v1"}
	if builder.ID != "https://builder.example.com/v1" {
		t.Errorf("unexpected builder ID: %q", builder.ID)
	}
}

func TestSubjectStruct(t *testing.T) {
	subject := Subject{
		Name: "artifact.tar.gz",
		Digest: map[string]string{
			"sha256": "abc123def456",
			"sha512": "789xyz",
		},
	}

	if subject.Name != "artifact.tar.gz" {
		t.Errorf("unexpected name: %q", subject.Name)
	}
	if len(subject.Digest) != 2 {
		t.Errorf("expected 2 digests, got %d", len(subject.Digest))
	}
}
