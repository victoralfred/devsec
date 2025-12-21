package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/signing"
	"github.com/victoralfred/gowritter/safepath"
)

var (
	signOutput      string
	signKeyFile     string
	signPubKeyFile  string
	signTimeout     time.Duration
	signAnnotations []string
	verifySigFile   string
	verifyTimeout   time.Duration
	genkeyOutput    string
	genkeyTimeout   time.Duration
)

// NewSignCmd creates the sign command.
func NewSignCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign and verify artifacts",
		Long: `Sign artifacts using ECDSA-P256 keys or verify existing signatures.

Supports:
  - Key-based signing with PEM-encoded ECDSA keys
  - Ephemeral key generation for one-time signing
  - Signature verification with public keys
  - File integrity verification with content hashing`,
	}

	cmd.AddCommand(NewSignArtifactCmd())
	cmd.AddCommand(NewVerifyCmd())
	cmd.AddCommand(NewGenKeyCmd())

	return cmd
}

// NewSignArtifactCmd creates the sign artifact subcommand.
func NewSignArtifactCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "artifact [file]",
		Short: "Sign an artifact file",
		Long: `Sign an artifact file using ECDSA-P256 keys.

If no key file is specified, an ephemeral key pair is generated.
The signature is written to a .sig file alongside the artifact.`,
		Args: cobra.ExactArgs(1),
		RunE: runSignArtifact,
	}

	cmd.Flags().StringVarP(&signOutput, "output", "o", "", "output signature file (default: <file>.sig)")
	cmd.Flags().StringVarP(&signKeyFile, "key", "k", "", "private key file (PEM format)")
	cmd.Flags().StringVar(&signPubKeyFile, "pub-key", "", "public key file (required with --key)")
	cmd.Flags().DurationVarP(&signTimeout, "timeout", "t", 1*time.Minute, "signing timeout")
	cmd.Flags().StringArrayVarP(&signAnnotations, "annotation", "a", nil, "annotations (key=value)")

	return cmd
}

func runSignArtifact(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), signTimeout)
	defer cancel()

	// Parse annotations.
	annotations := parseAnnotations(signAnnotations)

	// Create signer.
	var opts []signing.SignerOption
	opts = append(opts, signing.WithAnnotations(annotations))

	if signKeyFile != "" {
		if signPubKeyFile == "" {
			return fmt.Errorf("--pub-key is required when using --key")
		}
		kp, loadErr := signing.LoadKeyPair(ctx, signKeyFile, signPubKeyFile)
		if loadErr != nil {
			return fmt.Errorf("failed to load key pair: %w", loadErr)
		}
		opts = append(opts, signing.WithKeyPair(kp))
	}

	signer, err := signing.NewSigner(opts...)
	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	// Sign the file.
	artifact, err := signer.SignFile(ctx, absPath)
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	// Determine output path.
	outputPath := signOutput
	if outputPath == "" {
		outputPath = absPath + ".sig"
	}

	// Write signature.
	if err := signing.WriteSignature(ctx, outputPath, &artifact.Signature); err != nil {
		return fmt.Errorf("failed to write signature: %w", err)
	}

	cmd.Printf("Signed: %s\n", absPath)
	cmd.Printf("Signature: %s\n", outputPath)
	cmd.Printf("Content Hash: %s\n", artifact.ContentHash)
	cmd.Printf("Key ID: %s\n", artifact.Signature.KeyID)

	return nil
}

// NewVerifyCmd creates the verify subcommand.
func NewVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [file]",
		Short: "Verify an artifact signature",
		Long: `Verify an artifact's signature.

The signature file is expected to be at <file>.sig unless specified.
Verification checks both the cryptographic signature and content hash.`,
		Args: cobra.ExactArgs(1),
		RunE: runVerify,
	}

	cmd.Flags().StringVarP(&verifySigFile, "signature", "s", "", "signature file (default: <file>.sig)")
	cmd.Flags().DurationVarP(&verifyTimeout, "timeout", "t", 1*time.Minute, "verification timeout")

	return cmd
}

func runVerify(cmd *cobra.Command, args []string) error {
	filePath := args[0]

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()

	// Determine signature path.
	sigPath := verifySigFile
	if sigPath == "" {
		sigPath = absPath + ".sig"
	}

	absSigPath, err := filepath.Abs(sigPath)
	if err != nil {
		return fmt.Errorf("failed to resolve signature path: %w", err)
	}

	// Read signature.
	sig, err := signing.ReadSignature(ctx, absSigPath)
	if err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	// Read file content for verification.
	content, err := readFileContent(absPath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Verify the signature.
	verifier := signing.NewVerifier()
	result := verifier.VerifyWithResult(ctx, content, sig)

	if !result.Verified {
		cmd.Printf("Verification FAILED: %s\n", result.Error)
		cmd.Printf("File: %s\n", absPath)
		cmd.Printf("Signature: %s\n", absSigPath)
		return fmt.Errorf("verification failed: %s", result.Error)
	}

	cmd.Printf("Verification PASSED\n")
	cmd.Printf("File: %s\n", absPath)
	cmd.Printf("Signature: %s\n", absSigPath)
	cmd.Printf("Content Hash: %s\n", signing.ComputeDigest(content))
	cmd.Printf("Key ID: %s\n", result.KeyID)
	cmd.Printf("Algorithm: %s\n", result.Algorithm)

	return nil
}

// NewGenKeyCmd creates the genkey subcommand.
func NewGenKeyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "genkey",
		Short: "Generate a new signing key pair",
		Long: `Generate a new ECDSA-P256 key pair for signing.

The private key is written to the specified file with restricted permissions (0600).
The public key is written alongside it with .pub extension.`,
		RunE: runGenKey,
	}

	cmd.Flags().StringVarP(&genkeyOutput, "output", "o", "devsec.key", "output key file (public key will be <file>.pub)")
	cmd.Flags().DurationVarP(&genkeyTimeout, "timeout", "t", 1*time.Minute, "generation timeout")

	return cmd
}

func runGenKey(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), genkeyTimeout)
	defer cancel()

	// Generate key pair.
	kp, err := signing.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Determine output paths.
	privPath := genkeyOutput
	pubPath := genkeyOutput + ".pub"

	absPrivPath, err := filepath.Abs(privPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	absPubPath, err := filepath.Abs(pubPath)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %w", err)
	}

	// Save key pair.
	if err := kp.SaveKeyPair(ctx, absPrivPath, absPubPath); err != nil {
		return fmt.Errorf("failed to save key pair: %w", err)
	}

	cmd.Printf("Generated key pair:\n")
	cmd.Printf("  Private key: %s\n", absPrivPath)
	cmd.Printf("  Public key:  %s\n", absPubPath)
	cmd.Printf("  Key ID:      %s\n", kp.KeyID)
	cmd.Printf("  Algorithm:   %s\n", kp.Algorithm)

	return nil
}

// parseAnnotations parses annotation flags into a map.
func parseAnnotations(annotations []string) map[string]string {
	result := make(map[string]string)
	for _, a := range annotations {
		for i := 0; i < len(a); i++ {
			if a[i] == '=' {
				result[a[:i]] = a[i+1:]
				break
			}
		}
	}
	return result
}

// readFileContent reads the content of a file using safepath.
func readFileContent(filePath string) ([]byte, error) {
	dir := filepath.Dir(filePath)
	filename := filepath.Base(filePath)

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, fmt.Errorf("create safepath: %w", err)
	}

	return sp.ReadFile(filename)
}
