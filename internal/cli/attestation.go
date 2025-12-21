package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/victoralfred/devsec/internal/attestation"
	"github.com/victoralfred/devsec/internal/signing"
)

var (
	attestGenOutput     string
	attestGenKeyFile    string
	attestGenPubKeyFile string
	attestGenTimeout    time.Duration
	attestGenBuildType  string
	attestVerifyTimeout time.Duration
	attestInspectRaw    bool
)

// NewAttestationCmd creates the attestation command.
func NewAttestationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attestation",
		Short: "Generate and verify attestations",
		Long: `Generate and verify SLSA provenance and in-toto attestations.

Supports:
  - SLSA v1.0 provenance generation
  - Vulnerability scan attestations
  - DSSE envelope signing and verification
  - In-toto statement format`,
	}

	cmd.AddCommand(NewAttestGenCmd())
	cmd.AddCommand(NewAttestVerifyCmd())
	cmd.AddCommand(NewAttestInspectCmd())

	return cmd
}

// NewAttestGenCmd creates the attestation generate subcommand.
func NewAttestGenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate [files...]",
		Short: "Generate a SLSA provenance attestation",
		Long: `Generate a SLSA v1.0 provenance attestation for the specified files.

The attestation includes:
  - Subject digests (SHA256) for each file
  - Build metadata (builder ID, timestamps)
  - Platform information

If a key file is provided, the attestation is signed (DSSE envelope).
Otherwise, an unsigned statement is written.`,
		Args: cobra.MinimumNArgs(1),
		RunE: runAttestGen,
	}

	cmd.Flags().StringVarP(&attestGenOutput, "output", "o", "", "output attestation file (required)")
	cmd.Flags().StringVarP(&attestGenKeyFile, "key", "k", "", "private key file for signing (PEM format)")
	cmd.Flags().StringVar(&attestGenPubKeyFile, "pub-key", "", "public key file (required with --key)")
	cmd.Flags().DurationVarP(&attestGenTimeout, "timeout", "t", 2*time.Minute, "generation timeout")
	cmd.Flags().StringVar(&attestGenBuildType, "build-type", "", "custom build type URI")

	_ = cmd.MarkFlagRequired("output")

	return cmd
}

func runAttestGen(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), attestGenTimeout)
	defer cancel()

	// Create subjects from input files.
	subjects := make([]attestation.Subject, 0, len(args))
	for _, filePath := range args {
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return fmt.Errorf("resolve path %s: %w", filePath, err)
		}

		subject, err := attestation.CreateSubjectFromFile(ctx, absPath)
		if err != nil {
			return fmt.Errorf("create subject from %s: %w", filePath, err)
		}
		subjects = append(subjects, *subject)
	}

	// Create generator.
	builderID := attestation.GetBuilderID()
	gen := attestation.NewGenerator(builderID, Version)

	// Build options.
	var opts []attestation.ProvenanceOption
	if attestGenBuildType != "" {
		opts = append(opts, attestation.WithBuildType(attestGenBuildType))
	}

	// Generate provenance.
	stmt, err := gen.GenerateProvenance(ctx, subjects, opts...)
	if err != nil {
		return fmt.Errorf("generate provenance: %w", err)
	}

	// Determine output path.
	absOutput, err := filepath.Abs(attestGenOutput)
	if err != nil {
		return fmt.Errorf("resolve output path: %w", err)
	}

	// If key provided, sign the attestation.
	if attestGenKeyFile != "" {
		if attestGenPubKeyFile == "" {
			return fmt.Errorf("--pub-key is required when using --key")
		}

		kp, loadErr := signing.LoadKeyPair(ctx, attestGenKeyFile, attestGenPubKeyFile)
		if loadErr != nil {
			return fmt.Errorf("load key pair: %w", loadErr)
		}

		signer, signerErr := signing.NewSigner(signing.WithKeyPair(kp))
		if signerErr != nil {
			return fmt.Errorf("create signer: %w", signerErr)
		}

		env, signErr := attestation.SignStatement(ctx, stmt, signer)
		if signErr != nil {
			return fmt.Errorf("sign attestation: %w", signErr)
		}

		if writeErr := attestation.WriteAttestation(ctx, absOutput, env); writeErr != nil {
			return fmt.Errorf("write attestation: %w", writeErr)
		}

		cmd.Printf("Generated signed attestation: %s\n", absOutput)
		cmd.Printf("Builder ID: %s\n", builderID)
		cmd.Printf("Subjects: %d\n", len(subjects))
		cmd.Printf("Key ID: %s\n", kp.KeyID)
	} else {
		if writeErr := attestation.WriteStatement(ctx, absOutput, stmt); writeErr != nil {
			return fmt.Errorf("write statement: %w", writeErr)
		}

		cmd.Printf("Generated unsigned attestation: %s\n", absOutput)
		cmd.Printf("Builder ID: %s\n", builderID)
		cmd.Printf("Subjects: %d\n", len(subjects))
		cmd.Printf("Note: Use --key to sign the attestation\n")
	}

	return nil
}

// NewAttestVerifyCmd creates the attestation verify subcommand.
func NewAttestVerifyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [attestation]",
		Short: "Verify an attestation envelope",
		Long: `Verify a signed attestation envelope.

Verification checks:
  - Cryptographic signature validity
  - Payload integrity
  - Public key embedded in signature`,
		Args: cobra.ExactArgs(1),
		RunE: runAttestVerify,
	}

	cmd.Flags().DurationVarP(&attestVerifyTimeout, "timeout", "t", 1*time.Minute, "verification timeout")

	return cmd
}

func runAttestVerify(cmd *cobra.Command, args []string) error {
	attestPath := args[0]

	absPath, err := filepath.Abs(attestPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), attestVerifyTimeout)
	defer cancel()

	// Read attestation envelope.
	env, err := attestation.ReadAttestation(ctx, absPath)
	if err != nil {
		return fmt.Errorf("read attestation: %w", err)
	}

	// Create verifier.
	verifier := signing.NewVerifier()

	// Verify envelope.
	if verifyErr := attestation.VerifyEnvelope(ctx, env, verifier); verifyErr != nil {
		cmd.Printf("Verification FAILED: %s\n", verifyErr)
		cmd.Printf("Attestation: %s\n", absPath)
		return fmt.Errorf("verification failed: %w", verifyErr)
	}

	// Extract statement for display.
	stmt, err := attestation.ExtractStatement(env)
	if err != nil {
		return fmt.Errorf("extract statement: %w", err)
	}

	cmd.Printf("Verification PASSED\n")
	cmd.Printf("Attestation: %s\n", absPath)
	cmd.Printf("Statement Type: %s\n", stmt.Type)
	cmd.Printf("Predicate Type: %s\n", stmt.PredicateType)
	cmd.Printf("Subjects: %d\n", len(stmt.Subject))

	return nil
}

// NewAttestInspectCmd creates the attestation inspect subcommand.
func NewAttestInspectCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect [attestation]",
		Short: "Inspect an attestation",
		Long: `Inspect an attestation file and display its contents.

Works with both signed envelopes and unsigned statements.`,
		Args: cobra.ExactArgs(1),
		RunE: runAttestInspect,
	}

	cmd.Flags().BoolVarP(&attestInspectRaw, "raw", "r", false, "show raw JSON output")

	return cmd
}

func runAttestInspect(cmd *cobra.Command, args []string) error {
	attestPath := args[0]

	absPath, err := filepath.Abs(attestPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Try reading as envelope first.
	env, err := attestation.ReadAttestation(ctx, absPath)
	if err == nil {
		return inspectEnvelope(cmd, env, absPath)
	}

	// Try reading as unsigned statement.
	stmt, stmtErr := attestation.ReadStatement(ctx, absPath)
	if stmtErr != nil {
		return fmt.Errorf("read attestation (tried envelope and statement): %w", stmtErr)
	}

	return inspectStatement(cmd, stmt, absPath, false)
}

func inspectEnvelope(cmd *cobra.Command, env *attestation.Envelope, path string) error {
	if attestInspectRaw {
		data, err := json.MarshalIndent(env, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal envelope: %w", err)
		}
		cmd.Println(string(data))
		return nil
	}

	cmd.Printf("Attestation: %s\n", path)
	cmd.Printf("Format: Signed Envelope (DSSE)\n")
	cmd.Printf("Payload Type: %s\n", env.PayloadType)
	cmd.Printf("Signatures: %d\n", len(env.Signatures))

	for i, sig := range env.Signatures {
		cmd.Printf("  [%d] Key ID: %s\n", i, sig.KeyID)
	}

	// Extract and display statement.
	stmt, err := attestation.ExtractStatement(env)
	if err != nil {
		return fmt.Errorf("extract statement: %w", err)
	}

	return inspectStatement(cmd, stmt, "", true)
}

func inspectStatement(cmd *cobra.Command, stmt *attestation.Statement, path string, nested bool) error {
	if attestInspectRaw && !nested {
		data, err := json.MarshalIndent(stmt, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal statement: %w", err)
		}
		cmd.Println(string(data))
		return nil
	}

	if !nested {
		cmd.Printf("Attestation: %s\n", path)
		cmd.Printf("Format: Unsigned Statement\n")
	}

	cmd.Printf("Statement Type: %s\n", stmt.Type)
	cmd.Printf("Predicate Type: %s\n", stmt.PredicateType)
	cmd.Printf("Subjects:\n")

	for i, subj := range stmt.Subject {
		cmd.Printf("  [%d] %s\n", i, subj.Name)
		for algo, hash := range subj.Digest {
			cmd.Printf("      %s: %s\n", algo, hash)
		}
	}

	return nil
}
