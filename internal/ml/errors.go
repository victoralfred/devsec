// Package ml provides ML-specific validation and detection capabilities.
package ml

import "errors"

// Sentinel errors for the ML package.
// These errors can be checked using errors.Is() for programmatic error handling.
var (
	// ErrEmptyPath indicates that a required path argument was empty.
	ErrEmptyPath = errors.New("path cannot be empty")

	// ErrNoSchema indicates that no schema was provided for validation.
	ErrNoSchema = errors.New("schema is not set")

	// ErrEmptyData indicates that the provided data is empty.
	ErrEmptyData = errors.New("data cannot be empty")

	// ErrMismatchedLength indicates that array arguments have different lengths.
	ErrMismatchedLength = errors.New("array lengths do not match")

	// ErrInvalidDataType indicates that the provided data type is not supported.
	ErrInvalidDataType = errors.New("unsupported data type")

	// ErrNilModelCard indicates that a nil model card was provided.
	ErrNilModelCard = errors.New("model card cannot be nil")

	// ErrUnsupportedFormat indicates that the requested output format is not supported.
	ErrUnsupportedFormat = errors.New("unsupported format")

	// ErrFileTooLarge indicates that a file exceeds the configured size limit.
	ErrFileTooLarge = errors.New("file exceeds size limit")

	// ErrMaxDepthExceeded indicates that the maximum directory depth was reached.
	ErrMaxDepthExceeded = errors.New("maximum directory depth exceeded")

	// ErrMaxFilesExceeded indicates that the maximum number of files to scan was reached.
	ErrMaxFilesExceeded = errors.New("maximum file count exceeded")

	// ErrScanTimeout indicates that the scan operation timed out.
	ErrScanTimeout = errors.New("scan operation timed out")
)
