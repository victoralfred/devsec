package signing

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/pem"
	"path/filepath"
	"testing"

	"github.com/victoralfred/gowritter/safepath"
)

// TestGenerateKeyPair tests key pair generation.
func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	if kp.PublicKey == "" {
		t.Error("expected non-empty public key")
	}
	if kp.PrivateKey == "" {
		t.Error("expected non-empty private key")
	}
	if kp.KeyID == "" {
		t.Error("expected non-empty key ID")
	}
	if kp.Algorithm != "ECDSA-P256-SHA256" {
		t.Errorf("expected algorithm ECDSA-P256-SHA256, got %s", kp.Algorithm)
	}
	if kp.privateKey == nil {
		t.Error("expected non-nil private key")
	}
}

// TestNewSigner tests signer creation.
func TestNewSigner(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	if signer.keyPair == nil {
		t.Error("expected non-nil key pair")
	}
}

// TestNewSignerWithKeyPair tests signer with custom key pair.
func TestNewSignerWithKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	signer, err := NewSigner(WithKeyPair(kp))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	if signer.keyPair.KeyID != kp.KeyID {
		t.Error("expected same key pair")
	}
}

// TestNewSignerWithAnnotations tests signer with annotations.
func TestNewSignerWithAnnotations(t *testing.T) {
	annotations := map[string]string{
		"author": "test",
		"env":    "development",
	}

	signer, err := NewSigner(WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	if len(signer.annotations) != 2 {
		t.Errorf("expected 2 annotations, got %d", len(signer.annotations))
	}
}

// TestSign tests signing content.
func TestSign(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("test content to sign")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if sig.Value == "" {
		t.Error("expected non-empty signature value")
	}
	if sig.Type != SignatureTypeCosign {
		t.Errorf("expected type cosign, got %s", sig.Type)
	}
	if sig.PublicKey == "" {
		t.Error("expected non-empty public key in signature")
	}
	if sig.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp")
	}
}

// TestSignContextCancellation tests context cancellation.
func TestSignContextCancellation(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Sign(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestVerify tests signature verification.
func TestVerify(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("test content to verify")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	err = verifier.Verify(ctx, content, sig)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// TestVerifyWithTrustedKey tests verification with trusted key.
func TestVerifyWithTrustedKey(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("test content")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	err = verifier.AddTrustedKey(sig.KeyID, sig.PublicKey)
	if err != nil {
		t.Fatalf("AddTrustedKey() error = %v", err)
	}

	// Clear embedded public key to force use of trusted key.
	sigCopy := *sig
	sigCopy.PublicKey = ""

	err = verifier.Verify(ctx, content, &sigCopy)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

// TestVerifyTamperedContent tests verification with tampered content.
func TestVerifyTamperedContent(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("original content")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	tamperedContent := []byte("tampered content")

	err = verifier.Verify(ctx, tamperedContent, sig)
	if err == nil {
		t.Error("expected verification to fail for tampered content")
	}
}

// TestVerifyInvalidSignature tests verification with invalid signature.
func TestVerifyInvalidSignature(t *testing.T) {
	content := []byte("test content")
	ctx := context.Background()

	// Create a valid key pair for the signature metadata.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	sig := &Signature{
		Value:     base64.StdEncoding.EncodeToString([]byte("invalid signature")),
		Type:      SignatureTypeCosign,
		Algorithm: kp.Algorithm,
		KeyID:     kp.KeyID,
		PublicKey: kp.PublicKey,
	}

	verifier := NewVerifier()
	err = verifier.Verify(ctx, content, sig)
	if err == nil {
		t.Error("expected verification to fail for invalid signature")
	}
}

// TestVerifyNoPublicKey tests verification with no public key.
func TestVerifyNoPublicKey(t *testing.T) {
	content := []byte("test content")
	ctx := context.Background()

	sig := &Signature{
		Value: "test",
		Type:  SignatureTypeCosign,
	}

	verifier := NewVerifier()
	err := verifier.Verify(ctx, content, sig)
	if err == nil {
		t.Error("expected error for missing public key")
	}
}

// TestSignFile tests file signing.
func TestSignFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	content := []byte("file content to sign")
	err = sp.WriteFile("test.txt", content, 0o644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	artifact, err := signer.SignFile(ctx, filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("SignFile() error = %v", err)
	}

	if artifact.ArtifactURI == "" {
		t.Error("expected non-empty artifact URI")
	}
	if artifact.ContentHash == "" {
		t.Error("expected non-empty content hash")
	}
	if artifact.Signature.Value == "" {
		t.Error("expected non-empty signature")
	}
}

// TestVerifyFile tests file verification.
func TestVerifyFile(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	content := []byte("file content to verify")
	err = sp.WriteFile("test.txt", content, 0o644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	artifact, err := signer.SignFile(ctx, filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("SignFile() error = %v", err)
	}

	verifier := NewVerifier()
	err = verifier.VerifyFile(ctx, artifact)
	if err != nil {
		t.Fatalf("VerifyFile() error = %v", err)
	}
}

// TestVerifyFileHashMismatch tests file verification with hash mismatch.
func TestVerifyFileHashMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	sp, err := safepath.New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create safepath: %v", err)
	}

	content := []byte("original content")
	err = sp.WriteFile("test.txt", content, 0o644)
	if err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	artifact, err := signer.SignFile(ctx, filepath.Join(tmpDir, "test.txt"))
	if err != nil {
		t.Fatalf("SignFile() error = %v", err)
	}

	// Modify the file after signing.
	err = sp.WriteFile("test.txt", []byte("modified content"), 0o644)
	if err != nil {
		t.Fatalf("failed to modify test file: %v", err)
	}

	verifier := NewVerifier()
	err = verifier.VerifyFile(ctx, artifact)
	if err == nil {
		t.Error("expected verification to fail for modified file")
	}
}

// TestSaveAndLoadKeyPair tests saving and loading key pairs.
func TestSaveAndLoadKeyPair(t *testing.T) {
	tmpDir := t.TempDir()

	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	ctx := context.Background()
	privPath := filepath.Join(tmpDir, "private.pem")
	pubPath := filepath.Join(tmpDir, "public.pem")

	err = kp.SaveKeyPair(ctx, privPath, pubPath)
	if err != nil {
		t.Fatalf("SaveKeyPair() error = %v", err)
	}

	loaded, err := LoadKeyPair(ctx, privPath, pubPath)
	if err != nil {
		t.Fatalf("LoadKeyPair() error = %v", err)
	}

	if loaded.KeyID != kp.KeyID {
		t.Error("key ID mismatch after load")
	}
	if loaded.Algorithm != kp.Algorithm {
		t.Error("algorithm mismatch after load")
	}
}

// TestAddTrustedKeyFromSignature tests adding key from signature.
func TestAddTrustedKeyFromSignature(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	sig, err := signer.Sign(ctx, []byte("test"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	err = verifier.AddTrustedKeyFromSignature(sig)
	if err != nil {
		t.Fatalf("AddTrustedKeyFromSignature() error = %v", err)
	}

	if len(verifier.trustedKeys) != 1 {
		t.Errorf("expected 1 trusted key, got %d", len(verifier.trustedKeys))
	}
}

// TestAddTrustedKeyFromSignatureNoKey tests error when no key in signature.
func TestAddTrustedKeyFromSignatureNoKey(t *testing.T) {
	sig := &Signature{
		Value: "test",
	}

	verifier := NewVerifier()
	err := verifier.AddTrustedKeyFromSignature(sig)
	if err == nil {
		t.Error("expected error for signature without public key")
	}
}

// TestCreateBundle tests bundle creation.
func TestCreateBundle(t *testing.T) {
	sig := &Signature{
		Value:     "test-signature",
		Type:      SignatureTypeCosign,
		Algorithm: "ECDSA-P256-SHA256",
	}

	bundle := CreateBundle(sig, []byte("content"))
	if bundle.MediaType == "" {
		t.Error("expected non-empty media type")
	}
	if bundle.Signature.Value != sig.Value {
		t.Error("signature mismatch in bundle")
	}
}

// TestWriteAndReadSignature tests signature file I/O.
func TestWriteAndReadSignature(t *testing.T) {
	tmpDir := t.TempDir()
	sigPath := filepath.Join(tmpDir, "signature.json")

	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	sig, err := signer.Sign(ctx, []byte("test content"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	err = WriteSignature(ctx, sigPath, sig)
	if err != nil {
		t.Fatalf("WriteSignature() error = %v", err)
	}

	loaded, err := ReadSignature(ctx, sigPath)
	if err != nil {
		t.Fatalf("ReadSignature() error = %v", err)
	}

	if loaded.Value != sig.Value {
		t.Error("signature value mismatch after load")
	}
	if loaded.Type != sig.Type {
		t.Error("signature type mismatch after load")
	}
}

// TestComputeDigest tests digest computation.
func TestComputeDigest(t *testing.T) {
	content := []byte("test content")
	digest := ComputeDigest(content)

	if digest == "" {
		t.Error("expected non-empty digest")
	}
	if len(digest) != 64 {
		t.Errorf("expected 64 char digest, got %d", len(digest))
	}

	// Same content should produce same digest.
	digest2 := ComputeDigest(content)
	if digest != digest2 {
		t.Error("expected same digest for same content")
	}
}

// TestVerifyWithResult tests verification with result.
func TestVerifyWithResult(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("test content")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	result := verifier.VerifyWithResult(ctx, content, sig)

	if !result.Verified {
		t.Error("expected verification to succeed")
	}
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
	if result.KeyID != sig.KeyID {
		t.Error("key ID mismatch in result")
	}
}

// TestVerifyWithResultFailure tests verification failure result.
func TestVerifyWithResultFailure(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	content := []byte("test content")
	ctx := context.Background()

	sig, err := signer.Sign(ctx, content)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	verifier := NewVerifier()
	result := verifier.VerifyWithResult(ctx, []byte("different content"), sig)

	if result.Verified {
		t.Error("expected verification to fail")
	}
	if result.Error == "" {
		t.Error("expected error message in result")
	}
}

// TestNewSignatureEnvelope tests envelope creation.
func TestNewSignatureEnvelope(t *testing.T) {
	sig := &Signature{
		Value: "test-sig",
		Type:  SignatureTypeCosign,
	}

	envelope := NewSignatureEnvelope(sig, "application/json", "abc123")

	if envelope.PayloadType != "application/json" {
		t.Errorf("expected payload type application/json, got %s", envelope.PayloadType)
	}
	if envelope.PayloadHash != "abc123" {
		t.Errorf("expected payload hash abc123, got %s", envelope.PayloadHash)
	}
}

// TestAddTrustedKeyInvalidPEM tests adding invalid PEM key.
func TestAddTrustedKeyInvalidPEM(t *testing.T) {
	verifier := NewVerifier()
	err := verifier.AddTrustedKey("test", "not a valid pem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestAddTrustedKeyNonECDSA tests adding non-ECDSA key.
func TestAddTrustedKeyNonECDSA(t *testing.T) {
	// Create a fake RSA-like PEM (just for testing error path).
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not a valid key"),
	}
	fakePEM := string(pem.EncodeToMemory(block))

	verifier := NewVerifier()
	err := verifier.AddTrustedKey("test", fakePEM)
	if err == nil {
		t.Error("expected error for invalid key data")
	}
}

// TestResolvePublicKeyUnknownKeyID tests unknown key ID error.
func TestResolvePublicKeyUnknownKeyID(t *testing.T) {
	sig := &Signature{
		KeyID: "unknown-key-id",
	}

	verifier := NewVerifier()
	ctx := context.Background()

	err := verifier.Verify(ctx, []byte("test"), sig)
	if err == nil {
		t.Error("expected error for unknown key ID")
	}
}

// TestLoadKeyPairContextCancellation tests context cancellation.
func TestLoadKeyPairContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := LoadKeyPair(ctx, "/fake/private.pem", "/fake/public.pem")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestSaveKeyPairContextCancellation tests context cancellation.
func TestSaveKeyPairContextCancellation(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = kp.SaveKeyPair(ctx, "/fake/private.pem", "/fake/public.pem")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestEphemeralKeyGeneration tests that new signers get unique keys.
func TestEphemeralKeyGeneration(t *testing.T) {
	signer1, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	signer2, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	if signer1.keyPair.KeyID == signer2.keyPair.KeyID {
		t.Error("expected different key IDs for different signers")
	}
}

// TestSignatureWithAnnotations tests annotations in signature.
func TestSignatureWithAnnotations(t *testing.T) {
	annotations := map[string]string{
		"purpose": "testing",
		"version": "1.0.0",
	}

	signer, err := NewSigner(WithAnnotations(annotations))
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()
	sig, err := signer.Sign(ctx, []byte("test"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if len(sig.Annotations) != 2 {
		t.Errorf("expected 2 annotations, got %d", len(sig.Annotations))
	}
	if sig.Annotations["purpose"] != "testing" {
		t.Error("expected purpose annotation")
	}
}

// TestVerifyContextCancellation tests context cancellation during verify.
func TestVerifyContextCancellation(t *testing.T) {
	sig := &Signature{
		Value:     "test",
		PublicKey: "test",
	}

	verifier := NewVerifier()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := verifier.Verify(ctx, []byte("test"), sig)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestParsePublicKeyInvalid tests parsing invalid public key.
func TestParsePublicKeyInvalid(t *testing.T) {
	_, err := parsePublicKey("not a valid pem")
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

// TestParsePublicKeyNonECDSA tests parsing non-ECDSA public key.
func TestParsePublicKeyNonECDSA(t *testing.T) {
	// Create a fake PEM with invalid key data.
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("invalid key data"),
	}
	fakePEM := string(pem.EncodeToMemory(block))

	_, err := parsePublicKey(fakePEM)
	if err == nil {
		t.Error("expected error for invalid key")
	}
}

// TestDigestAlgorithm tests digest algorithm.
func TestDigestAlgorithm(t *testing.T) {
	alg := DigestAlgorithm()
	if alg.String() != "SHA-256" {
		t.Errorf("expected SHA-256, got %s", alg.String())
	}
}

// TestSignerWithNilKeyPair tests signing with nil key.
func TestSignerWithNilKeyPair(t *testing.T) {
	signer := &Signer{
		keyPair: nil,
	}

	ctx := context.Background()
	_, err := signer.Sign(ctx, []byte("test"))
	if err == nil {
		t.Error("expected error for nil key pair")
	}
}

// TestLoadKeyPairInvalidPath tests loading from invalid path.
func TestLoadKeyPairInvalidPath(t *testing.T) {
	ctx := context.Background()
	_, err := LoadKeyPair(ctx, "/nonexistent/private.pem", "/nonexistent/public.pem")
	if err == nil {
		t.Error("expected error for nonexistent files")
	}
}

// TestWriteSignatureContextCancellation tests context cancellation.
func TestWriteSignatureContextCancellation(t *testing.T) {
	sig := &Signature{Value: "test"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := WriteSignature(ctx, "/fake/path.json", sig)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestReadSignatureContextCancellation tests context cancellation.
func TestReadSignatureContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ReadSignature(ctx, "/fake/path.json")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestSignFileContextCancellation tests context cancellation.
func TestSignFileContextCancellation(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.SignFile(ctx, "/fake/file.txt")
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestVerifyFileContextCancellation tests context cancellation.
func TestVerifyFileContextCancellation(t *testing.T) {
	artifact := &SignedArtifact{
		ArtifactURI: "/fake/file.txt",
	}

	verifier := NewVerifier()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := verifier.VerifyFile(ctx, artifact)
	if err == nil {
		t.Error("expected error for canceled context")
	}
}

// TestDifferentContentDifferentSignature tests signatures differ for different content.
func TestDifferentContentDifferentSignature(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}

	ctx := context.Background()

	sig1, err := signer.Sign(ctx, []byte("content 1"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	sig2, err := signer.Sign(ctx, []byte("content 2"))
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	if sig1.Value == sig2.Value {
		t.Error("expected different signatures for different content")
	}
}

// TestKeyPairHasPrivateKey tests that generated key pair has usable private key.
func TestKeyPairHasPrivateKey(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	// Verify private key can sign.
	privateKey := kp.privateKey
	if privateKey == nil {
		t.Fatal("expected non-nil private key")
	}

	// Verify it's a valid P-256 key.
	if privateKey.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

// TestResolvePublicKeyWithEmbeddedKey tests embedded key resolution.
func TestResolvePublicKeyWithEmbeddedKey(t *testing.T) {
	// Use GenerateKeyPair to get a properly encoded key.
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}

	sig := &Signature{
		KeyID:     "known-key",
		PublicKey: kp.PublicKey,
	}

	verifier := NewVerifier()
	// Don't add the key to trusted keys - should use embedded key.

	pubKey, err := verifier.resolvePublicKey(sig)
	if err != nil {
		t.Fatalf("resolvePublicKey() error = %v", err)
	}

	if pubKey == nil {
		t.Error("expected non-nil public key")
	}
}
