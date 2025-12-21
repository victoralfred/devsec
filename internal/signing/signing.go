// Package signing provides artifact signing and verification using Sigstore.
package signing

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/victoralfred/gowritter/safepath"
)

// SignatureType represents the type of signature.
type SignatureType string

const (
	// SignatureTypeCosign represents a Cosign-style signature.
	SignatureTypeCosign SignatureType = "cosign"
	// SignatureTypeKeyless represents a keyless (Fulcio) signature.
	SignatureTypeKeyless SignatureType = "keyless"
)

// Signature represents a cryptographic signature.
// Fields ordered for optimal memory alignment.
type Signature struct {
	Timestamp   time.Time         `json:"timestamp"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Value       string            `json:"signature"`
	PublicKey   string            `json:"public_key,omitempty"`
	Certificate string            `json:"certificate,omitempty"`
	Type        SignatureType     `json:"type"`
	Algorithm   string            `json:"algorithm"`
	KeyID       string            `json:"key_id,omitempty"`
}

// SignedArtifact represents an artifact with its signature.
// Fields ordered for optimal memory alignment.
type SignedArtifact struct {
	Signature   Signature `json:"signature"`
	ContentHash string    `json:"content_hash"`
	ArtifactURI string    `json:"artifact_uri"`
}

// Bundle represents a Sigstore bundle containing signature and verification material.
// Fields ordered for optimal memory alignment.
type Bundle struct {
	Signature            Signature `json:"signature"`
	RekorLogEntry        string    `json:"rekor_log_entry,omitempty"`
	MediaType            string    `json:"mediaType"`
	VerificationMaterial string    `json:"verification_material,omitempty"`
}

// KeyPair represents a signing key pair.
// Fields ordered for optimal memory alignment.
type KeyPair struct {
	CreatedAt  time.Time
	privateKey *ecdsa.PrivateKey
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key,omitempty"`
	KeyID      string `json:"key_id"`
	Algorithm  string `json:"algorithm"`
}

// Signer provides artifact signing functionality.
type Signer struct {
	keyPair     *KeyPair
	annotations map[string]string
}

// SignerOption configures a Signer.
type SignerOption func(*Signer)

// WithKeyPair sets the key pair for signing.
func WithKeyPair(kp *KeyPair) SignerOption {
	return func(s *Signer) {
		s.keyPair = kp
	}
}

// WithAnnotations sets annotations to include in signatures.
func WithAnnotations(annotations map[string]string) SignerOption {
	return func(s *Signer) {
		s.annotations = annotations
	}
}

// NewSigner creates a new Signer with the given options.
func NewSigner(opts ...SignerOption) (*Signer, error) {
	s := &Signer{
		annotations: make(map[string]string),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Generate ephemeral key pair if none provided.
	if s.keyPair == nil {
		kp, err := GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate key pair: %w", err)
		}
		s.keyPair = kp
	}

	return s, nil
}

// GenerateKeyPair generates a new ECDSA P-256 key pair.
func GenerateKeyPair() (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ecdsa key: %w", err)
	}

	// Encode public key.
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	// Encode private key.
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Generate key ID from public key hash.
	keyHash := sha256.Sum256(pubBytes)
	keyID := hex.EncodeToString(keyHash[:8])

	return &KeyPair{
		privateKey: privateKey,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
		KeyID:      keyID,
		Algorithm:  "ECDSA-P256-SHA256",
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// LoadKeyPair loads a key pair from PEM-encoded files.
func LoadKeyPair(ctx context.Context, privateKeyPath, publicKeyPath string) (*KeyPair, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Load private key.
	privDir := filepath.Dir(privateKeyPath)
	privFile := filepath.Base(privateKeyPath)

	sp, err := safepath.New(privDir)
	if err != nil {
		return nil, fmt.Errorf("create safepath for private key: %w", err)
	}

	privPEM, err := sp.ReadFile(privFile)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	// Load public key.
	pubDir := filepath.Dir(publicKeyPath)
	pubFile := filepath.Base(publicKeyPath)

	spPub, err := safepath.New(pubDir)
	if err != nil {
		return nil, fmt.Errorf("create safepath for public key: %w", err)
	}

	pubPEM, err := spPub.ReadFile(pubFile)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}

	// Parse private key.
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Generate key ID from public key.
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	keyHash := sha256.Sum256(pubBytes)
	keyID := hex.EncodeToString(keyHash[:8])

	return &KeyPair{
		privateKey: privateKey,
		PublicKey:  string(pubPEM),
		PrivateKey: string(privPEM),
		KeyID:      keyID,
		Algorithm:  "ECDSA-P256-SHA256",
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// SaveKeyPair saves a key pair to PEM-encoded files.
func (kp *KeyPair) SaveKeyPair(ctx context.Context, privateKeyPath, publicKeyPath string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Save private key.
	privDir := filepath.Dir(privateKeyPath)
	privFile := filepath.Base(privateKeyPath)

	sp, err := safepath.New(privDir)
	if err != nil {
		return fmt.Errorf("create safepath for private key: %w", err)
	}

	err = sp.WriteFile(privFile, []byte(kp.PrivateKey), 0o600)
	if err != nil {
		return fmt.Errorf("write private key: %w", err)
	}

	// Save public key.
	pubDir := filepath.Dir(publicKeyPath)
	pubFile := filepath.Base(publicKeyPath)

	spPub, err := safepath.New(pubDir)
	if err != nil {
		return fmt.Errorf("create safepath for public key: %w", err)
	}

	err = spPub.WriteFile(pubFile, []byte(kp.PublicKey), 0o644)
	if err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	return nil
}

// Sign signs the given content and returns a signature.
func (s *Signer) Sign(ctx context.Context, content []byte) (*Signature, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if s.keyPair == nil || s.keyPair.privateKey == nil {
		return nil, errors.New("no signing key available")
	}

	// Compute SHA-256 hash of content.
	hash := sha256.Sum256(content)

	// Sign the hash.
	signature, err := ecdsa.SignASN1(rand.Reader, s.keyPair.privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("sign content: %w", err)
	}

	return &Signature{
		Value:       base64.StdEncoding.EncodeToString(signature),
		Type:        SignatureTypeCosign,
		Algorithm:   s.keyPair.Algorithm,
		KeyID:       s.keyPair.KeyID,
		PublicKey:   s.keyPair.PublicKey,
		Timestamp:   time.Now().UTC(),
		Annotations: s.annotations,
	}, nil
}

// SignFile signs a file and returns a signed artifact.
func (s *Signer) SignFile(ctx context.Context, filePath string) (*SignedArtifact, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Read file content.
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

	// Sign content.
	sig, err := s.Sign(ctx, content)
	if err != nil {
		return nil, err
	}

	// Compute content hash.
	hash := sha256.Sum256(content)

	return &SignedArtifact{
		ArtifactURI: filePath,
		ContentHash: hex.EncodeToString(hash[:]),
		Signature:   *sig,
	}, nil
}

// CreateBundle creates a Sigstore bundle from a signature.
func CreateBundle(sig *Signature, content []byte) *Bundle {
	return &Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
		Signature: *sig,
	}
}

// Verifier provides signature verification functionality.
type Verifier struct {
	trustedKeys map[string]*ecdsa.PublicKey
}

// NewVerifier creates a new Verifier.
func NewVerifier() *Verifier {
	return &Verifier{
		trustedKeys: make(map[string]*ecdsa.PublicKey),
	}
}

// AddTrustedKey adds a trusted public key for verification.
func (v *Verifier) AddTrustedKey(keyID, publicKeyPEM string) error {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return errors.New("failed to decode public key PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not ECDSA")
	}

	v.trustedKeys[keyID] = pubKey
	return nil
}

// AddTrustedKeyFromSignature adds the public key from a signature as trusted.
func (v *Verifier) AddTrustedKeyFromSignature(sig *Signature) error {
	if sig.PublicKey == "" {
		return errors.New("signature does not contain public key")
	}
	return v.AddTrustedKey(sig.KeyID, sig.PublicKey)
}

// Verify verifies a signature against content.
func (v *Verifier) Verify(ctx context.Context, content []byte, sig *Signature) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Get public key.
	pubKey, err := v.resolvePublicKey(sig)
	if err != nil {
		return err
	}

	// Decode signature.
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Value)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Compute hash.
	hash := sha256.Sum256(content)

	// Verify signature.
	if !ecdsa.VerifyASN1(pubKey, hash[:], sigBytes) {
		return errors.New("signature verification failed")
	}

	return nil
}

// resolvePublicKey resolves the public key from a signature.
func (v *Verifier) resolvePublicKey(sig *Signature) (*ecdsa.PublicKey, error) {
	switch {
	case sig.KeyID != "":
		pubKey, ok := v.trustedKeys[sig.KeyID]
		if ok {
			return pubKey, nil
		}
		// Try to use embedded public key.
		if sig.PublicKey != "" {
			return parsePublicKey(sig.PublicKey)
		}
		return nil, fmt.Errorf("unknown key ID: %s", sig.KeyID)

	case sig.PublicKey != "":
		return parsePublicKey(sig.PublicKey)

	default:
		return nil, errors.New("no public key available for verification")
	}
}

// VerifyFile verifies a signed artifact.
func (v *Verifier) VerifyFile(ctx context.Context, artifact *SignedArtifact) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Read file content.
	dir := filepath.Dir(artifact.ArtifactURI)
	filename := filepath.Base(artifact.ArtifactURI)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	content, err := sp.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	// Verify content hash.
	hash := sha256.Sum256(content)
	if hex.EncodeToString(hash[:]) != artifact.ContentHash {
		return errors.New("content hash mismatch")
	}

	// Verify signature.
	return v.Verify(ctx, content, &artifact.Signature)
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(publicKeyPEM string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to decode public key PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}

	pubKey, ok := pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ECDSA")
	}

	return pubKey, nil
}

// VerificationResult represents the result of signature verification.
// Fields ordered for optimal memory alignment.
type VerificationResult struct {
	Timestamp   time.Time `json:"timestamp"`
	ArtifactURI string    `json:"artifact_uri"`
	KeyID       string    `json:"key_id"`
	Algorithm   string    `json:"algorithm"`
	Error       string    `json:"error,omitempty"`
	Verified    bool      `json:"verified"`
}

// VerifyWithResult verifies and returns a detailed result.
func (v *Verifier) VerifyWithResult(ctx context.Context, content []byte, sig *Signature) *VerificationResult {
	result := &VerificationResult{
		Timestamp: time.Now().UTC(),
		KeyID:     sig.KeyID,
		Algorithm: sig.Algorithm,
	}

	err := v.Verify(ctx, content, sig)
	if err != nil {
		result.Verified = false
		result.Error = err.Error()
	} else {
		result.Verified = true
	}

	return result
}

// SignatureEnvelope wraps a signature with its payload for storage.
// Fields ordered for optimal memory alignment.
type SignatureEnvelope struct {
	Signature   Signature `json:"signature"`
	PayloadHash string    `json:"payload_hash"`
	PayloadType string    `json:"payload_type"`
}

// NewSignatureEnvelope creates a new signature envelope.
func NewSignatureEnvelope(sig *Signature, payloadType, payloadHash string) *SignatureEnvelope {
	return &SignatureEnvelope{
		Signature:   *sig,
		PayloadType: payloadType,
		PayloadHash: payloadHash,
	}
}

// WriteSignature writes a signature to a file.
func WriteSignature(ctx context.Context, path string, sig *Signature) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	data, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signature: %w", err)
	}

	dir := filepath.Dir(path)
	filename := filepath.Base(path)

	sp, err := safepath.New(dir)
	if err != nil {
		return fmt.Errorf("create safepath: %w", err)
	}

	return sp.WriteFile(filename, data, 0o644)
}

// ReadSignature reads a signature from a file.
func ReadSignature(ctx context.Context, path string) (*Signature, error) {
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
		return nil, fmt.Errorf("read signature file: %w", err)
	}

	var sig Signature
	if err := json.Unmarshal(data, &sig); err != nil {
		return nil, fmt.Errorf("unmarshal signature: %w", err)
	}

	return &sig, nil
}

// ComputeDigest computes the SHA-256 digest of content.
func ComputeDigest(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

// DigestAlgorithm returns the digest algorithm identifier.
func DigestAlgorithm() crypto.Hash {
	return crypto.SHA256
}
