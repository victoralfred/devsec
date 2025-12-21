package ml

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	// Verify all sentinel errors are defined and non-empty.
	sentinels := []error{
		ErrEmptyPath,
		ErrNoSchema,
		ErrEmptyData,
		ErrMismatchedLength,
		ErrInvalidDataType,
		ErrNilModelCard,
		ErrUnsupportedFormat,
		ErrFileTooLarge,
		ErrMaxDepthExceeded,
		ErrMaxFilesExceeded,
		ErrScanTimeout,
	}

	for _, err := range sentinels {
		if err == nil {
			t.Error("sentinel error should not be nil")
		}
		if err.Error() == "" {
			t.Error("sentinel error message should not be empty")
		}
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that wrapped errors can be unwrapped.
	wrapped := fmt.Errorf("context: %w", ErrEmptyPath)

	if !errors.Is(wrapped, ErrEmptyPath) {
		t.Error("errors.Is should detect wrapped ErrEmptyPath")
	}

	wrapped = fmt.Errorf("invalid type: %w: got string", ErrInvalidDataType)
	if !errors.Is(wrapped, ErrInvalidDataType) {
		t.Error("errors.Is should detect wrapped ErrInvalidDataType")
	}
}

func TestErrorUniqueness(t *testing.T) {
	// Ensure all sentinel errors are unique.
	sentinels := []error{
		ErrEmptyPath,
		ErrNoSchema,
		ErrEmptyData,
		ErrMismatchedLength,
		ErrInvalidDataType,
		ErrNilModelCard,
		ErrUnsupportedFormat,
		ErrFileTooLarge,
		ErrMaxDepthExceeded,
		ErrMaxFilesExceeded,
		ErrScanTimeout,
	}

	seen := make(map[string]bool)
	for _, err := range sentinels {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %s", msg)
		}
		seen[msg] = true
	}
}

func TestDetectorEmptyPathError(t *testing.T) {
	ctx := context.Background()
	d := NewDetector()
	_, err := d.Detect(ctx, "")

	if !errors.Is(err, ErrEmptyPath) {
		t.Errorf("expected ErrEmptyPath, got %v", err)
	}
}

func TestValidatorNoSchemaError(t *testing.T) {
	ctx := context.Background()
	v := NewDataValidator(nil)
	_, err := v.Validate(ctx, nil)

	if !errors.Is(err, ErrNoSchema) {
		t.Errorf("expected ErrNoSchema, got %v", err)
	}
}

func TestDriftDetectorEmptyDataError(t *testing.T) {
	ctx := context.Background()
	d := NewDriftDetector(0.1)
	_, err := d.DetectDrift(ctx, []map[string]interface{}{}, []map[string]interface{}{{"a": 1}})

	if !errors.Is(err, ErrEmptyData) {
		t.Errorf("expected ErrEmptyData, got %v", err)
	}
}

func TestFairnessCheckerMismatchedLengthError(t *testing.T) {
	ctx := context.Background()
	c := NewFairnessChecker("group")
	_, err := c.CheckFairness(ctx, []interface{}{true}, []interface{}{true, false}, []interface{}{"A"})

	if !errors.Is(err, ErrMismatchedLength) {
		t.Errorf("expected ErrMismatchedLength, got %v", err)
	}
}

func TestBiasDetectorInvalidDataTypeError(t *testing.T) {
	ctx := context.Background()
	d := NewBiasDetector()
	_, err := d.DetectBias(ctx, "invalid", []string{"gender"})

	if !errors.Is(err, ErrInvalidDataType) {
		t.Errorf("expected ErrInvalidDataType, got %v", err)
	}
}

func TestModelCardNilError(t *testing.T) {
	ctx := context.Background()
	err := WriteModelCard(ctx, "/tmp/test.json", nil, "json")

	if !errors.Is(err, ErrNilModelCard) {
		t.Errorf("expected ErrNilModelCard, got %v", err)
	}
}

func TestModelCardUnsupportedFormatError(t *testing.T) {
	ctx := context.Background()
	card := &ModelCard{}
	err := WriteModelCard(ctx, "/tmp/test.txt", card, "invalid")

	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("expected ErrUnsupportedFormat, got %v", err)
	}
}
