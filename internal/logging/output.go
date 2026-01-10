package logging

import (
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/victoralfred/gowritter/safepath"
)

// FileWriter is a thread-safe file writer using safepath.
type FileWriter struct {
	sp       *safepath.SafePath
	file     io.WriteCloser
	filename string
	mu       sync.Mutex
}

// NewFileWriter creates a new file writer for the given path.
// The path must be an absolute path or will be resolved relative to cwd.
func NewFileWriter(path string) (*FileWriter, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(absPath)
	filename := filepath.Base(absPath)

	// Ensure directory exists.
	if mkdirErr := os.MkdirAll(dir, 0o750); mkdirErr != nil {
		return nil, mkdirErr
	}

	sp, err := safepath.New(dir)
	if err != nil {
		return nil, err
	}

	// Create or open the file for appending.
	file, err := sp.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}

	return &FileWriter{
		sp:       sp,
		filename: filename,
		file:     file,
	}, nil
}

// Write implements io.Writer.
func (w *FileWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, os.ErrClosed
	}

	return w.file.Write(p)
}

// Close closes the file writer.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

// Sync flushes the file to disk if supported.
func (w *FileWriter) Sync() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return os.ErrClosed
	}

	if syncer, ok := w.file.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}

	return nil
}

// MultiWriter writes to multiple outputs.
type MultiWriter struct {
	writers []io.Writer
	mu      sync.Mutex
}

// NewMultiWriter creates a writer that writes to all provided writers.
func NewMultiWriter(writers ...io.Writer) *MultiWriter {
	return &MultiWriter{
		writers: writers,
	}
}

// Write implements io.Writer.
func (w *MultiWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for _, writer := range w.writers {
		n, err = writer.Write(p)
		if err != nil {
			return n, err
		}
	}

	return len(p), nil
}

// Add adds a writer to the multi-writer.
func (w *MultiWriter) Add(writer io.Writer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.writers = append(w.writers, writer)
}

// Close closes all writers that implement io.Closer, except standard streams.
func (w *MultiWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var lastErr error
	for _, writer := range w.writers {
		// Skip closing standard streams (stdout, stderr, stdin).
		if writer == os.Stdout || writer == os.Stderr || writer == os.Stdin {
			continue
		}
		if closer, ok := writer.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// NullWriter discards all writes.
type NullWriter struct{}

// Write implements io.Writer and discards all data.
func (NullWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

// NewFileLogger creates a logger that writes to a file.
func NewFileLogger(path string, opts ...Option) (*JSONLogger, *FileWriter, error) {
	fw, err := NewFileWriter(path)
	if err != nil {
		return nil, nil, err
	}

	// Prepend file output option.
	allOpts := append([]Option{WithOutput(fw)}, opts...)
	logger := New(allOpts...)

	return logger, fw, nil
}

// NewDualLogger creates a logger that writes to both stdout and a file.
func NewDualLogger(path string, opts ...Option) (*JSONLogger, *MultiWriter, error) {
	fw, err := NewFileWriter(path)
	if err != nil {
		return nil, nil, err
	}

	mw := NewMultiWriter(os.Stdout, fw)

	// Prepend multi-writer output option.
	allOpts := append([]Option{WithOutput(mw)}, opts...)
	logger := New(allOpts...)

	return logger, mw, nil
}
