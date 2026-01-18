package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLevel_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		expected string
		level    Level
	}{
		{"debug", LevelDebug},
		{"info", LevelInfo},
		{"warn", LevelWarn},
		{"error", LevelError},
		{"unknown", Level(99)},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			t.Parallel()
			if got := tt.level.String(); got != tt.expected {
				t.Errorf("Level.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestParseLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected Level
		wantErr  bool
	}{
		{"debug", LevelDebug, false},
		{"DEBUG", LevelDebug, false},
		{"info", LevelInfo, false},
		{"INFO", LevelInfo, false},
		{"warn", LevelWarn, false},
		{"WARN", LevelWarn, false},
		{"warning", LevelWarn, false},
		{"WARNING", LevelWarn, false},
		{"error", LevelError, false},
		{"ERROR", LevelError, false},
		{"invalid", LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			got, err := ParseLevel(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLevel() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.expected {
				t.Errorf("ParseLevel() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestJSONLogger_Basic(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelDebug))

	logger.Debug("debug message")
	logger.Info("info message")
	logger.Warn("warn message")
	logger.Error("error message", errors.New("test error"))

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	if len(lines) != 4 {
		t.Fatalf("expected 4 log lines, got %d", len(lines))
	}

	// Verify each line is valid JSON.
	for i, line := range lines {
		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
			continue
		}

		if entry.Timestamp == "" {
			t.Errorf("line %d missing timestamp", i)
		}
	}
}

func TestJSONLogger_LevelFiltering(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelWarn))

	logger.Debug("debug")
	logger.Info("info")
	logger.Warn("warn")
	logger.Error("error", nil)

	output := buf.String()
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// Should only have warn and error.
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines, got %d: %s", len(lines), output)
	}
}

func TestJSONLogger_WithFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo))

	childLogger := logger.WithFields(Fields{"component": "test"})
	childLogger.Info("with fields")

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Fields["component"] != "test" {
		t.Errorf("expected component=test, got %v", entry.Fields["component"])
	}
}

func TestJSONLogger_WithCorrelationID(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo))

	childLogger := logger.WithCorrelationID("test-correlation-123")
	childLogger.Info("with correlation")

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.CorrelationID != "test-correlation-123" {
		t.Errorf("expected correlation_id=test-correlation-123, got %v", entry.CorrelationID)
	}
}

func TestJSONLogger_WithCaller(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo), WithCaller(true))

	logger.Info("with caller")

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Caller == "" {
		t.Error("expected caller to be set")
	}

	if !strings.Contains(entry.Caller, "logging_test.go") {
		t.Errorf("expected caller to contain logging_test.go, got %v", entry.Caller)
	}
}

func TestJSONLogger_ErrorField(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo))

	testErr := errors.New("test error message")
	logger.Error("error occurred", testErr)

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Error != "test error message" {
		t.Errorf("expected error='test error message', got %v", entry.Error)
	}
}

func TestJSONLogger_InlineFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo))

	logger.Info("with inline fields", Fields{"key1": "value1"}, Fields{"key2": 42})

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Fields["key1"] != "value1" {
		t.Errorf("expected key1=value1, got %v", entry.Fields["key1"])
	}

	// JSON numbers are float64.
	if entry.Fields["key2"] != float64(42) {
		t.Errorf("expected key2=42, got %v", entry.Fields["key2"])
	}
}

func TestJSONLogger_SetLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelError))

	logger.Info("should not appear")
	if buf.Len() != 0 {
		t.Error("expected no output with level=error")
	}

	logger.SetLevel(LevelInfo)
	logger.Info("should appear")
	if buf.Len() == 0 {
		t.Error("expected output after setting level=info")
	}
}

func TestJSONLogger_SetOutput(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	logger := New(WithOutput(&buf1), WithLevel(LevelInfo))

	logger.Info("to buf1")
	if buf1.Len() == 0 {
		t.Error("expected output to buf1")
	}

	logger.SetOutput(&buf2)
	logger.Info("to buf2")
	if buf2.Len() == 0 {
		t.Error("expected output to buf2")
	}
}

func TestJSONLogger_Concurrent(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(WithOutput(&buf), WithLevel(LevelInfo))

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			logger.Info("concurrent message", Fields{"n": n})
		}(i)
	}

	wg.Wait()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 100 {
		t.Errorf("expected 100 log lines, got %d", len(lines))
	}
}

func TestDefaultLogger(t *testing.T) {
	// Do NOT run in parallel - modifies global Default.

	// Save and restore default logger.
	original := Default
	defer func() { Default = original }()

	var buf bytes.Buffer
	Default = New(WithOutput(&buf), WithLevel(LevelInfo))

	Info("default info")

	if buf.Len() == 0 {
		t.Error("expected output from default logger")
	}
}

func TestFromContext_NoLogger(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	logger := FromContext(ctx)

	if logger == nil {
		t.Error("expected non-nil logger")
	}
}

func TestFromContext_WithLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	customLogger := New(WithOutput(&buf), WithLevel(LevelInfo))

	ctx := WithLogger(context.Background(), customLogger)
	logger := FromContext(ctx)

	logger.Info("from context")

	if buf.Len() == 0 {
		t.Error("expected output from custom logger")
	}
}

func TestFromContext_NilContext(t *testing.T) {
	t.Parallel()

	logger := FromContext(context.TODO())

	if logger == nil {
		t.Error("expected non-nil logger for nil context")
	}
}

func TestCorrelationID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// No correlation ID initially.
	if id := CorrelationIDFromContext(ctx); id != "" {
		t.Errorf("expected empty correlation ID, got %v", id)
	}

	// Add correlation ID.
	ctx = WithCorrelationIDContext(ctx, "test-id-123")
	if id := CorrelationIDFromContext(ctx); id != "test-id-123" {
		t.Errorf("expected test-id-123, got %v", id)
	}
}

func TestNewCorrelationID(t *testing.T) {
	t.Parallel()

	id1 := NewCorrelationID()
	id2 := NewCorrelationID()

	if id1 == "" {
		t.Error("expected non-empty correlation ID")
	}

	if id1 == id2 {
		t.Error("expected unique correlation IDs")
	}

	// Should be 16 hex characters (8 bytes).
	if len(id1) != 16 {
		t.Errorf("expected 16 character ID, got %d", len(id1))
	}
}

func TestWithNewCorrelationID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	newCtx, id := WithNewCorrelationID(ctx)

	if id == "" {
		t.Error("expected non-empty correlation ID")
	}

	if CorrelationIDFromContext(newCtx) != id {
		t.Error("correlation ID not in context")
	}
}

func TestContextLogger(t *testing.T) {
	// Do NOT run in parallel - modifies global Default.

	// Save and restore default logger.
	original := Default
	defer func() { Default = original }()

	var buf bytes.Buffer
	Default = New(WithOutput(&buf), WithLevel(LevelInfo))

	ctx := context.Background()
	logger, newCtx := ContextLogger(ctx)

	logger.Info("context logger message")

	// Should have correlation ID.
	id := CorrelationIDFromContext(newCtx)
	if id == "" {
		t.Error("expected correlation ID in context")
	}

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.CorrelationID != id {
		t.Errorf("expected correlation_id=%s, got %v", id, entry.CorrelationID)
	}
}

func TestContextLoggerFunctions(t *testing.T) {
	// Do NOT run in parallel - modifies global Default.

	// Save and restore default logger.
	original := Default
	defer func() { Default = original }()

	var buf bytes.Buffer
	Default = New(WithOutput(&buf), WithLevel(LevelDebug))

	ctx := context.Background()

	CtxDebug(ctx, "debug")
	CtxInfo(ctx, "info")
	CtxWarn(ctx, "warn")
	CtxError(ctx, "error", errors.New("test"))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Errorf("expected 4 log lines, got %d", len(lines))
	}
}

func TestNullWriter(t *testing.T) {
	t.Parallel()

	nw := NullWriter{}
	n, err := nw.Write([]byte("test data"))

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if n != 9 {
		t.Errorf("expected 9, got %d", n)
	}
}

func TestMultiWriter(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	mw := NewMultiWriter(&buf1, &buf2)

	data := []byte("test message")
	n, err := mw.Write(data)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if n != len(data) {
		t.Errorf("expected %d, got %d", len(data), n)
	}

	if buf1.String() != "test message" {
		t.Errorf("buf1: expected 'test message', got %v", buf1.String())
	}

	if buf2.String() != "test message" {
		t.Errorf("buf2: expected 'test message', got %v", buf2.String())
	}
}

func TestMultiWriter_Add(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	mw := NewMultiWriter(&buf1)

	_, _ = mw.Write([]byte("first"))
	mw.Add(&buf2)
	_, _ = mw.Write([]byte("second"))

	if buf1.String() != "firstsecond" {
		t.Errorf("buf1: expected 'firstsecond', got %v", buf1.String())
	}

	if buf2.String() != "second" {
		t.Errorf("buf2: expected 'second', got %v", buf2.String())
	}
}

func TestFileWriter(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "test.log")

	fw, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create file writer: %v", err)
	}

	data := []byte("test log entry\n")
	n, err := fw.Write(data)

	if err != nil {
		t.Errorf("write error: %v", err)
	}

	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	// Sync and close.
	if syncErr := fw.Sync(); syncErr != nil {
		t.Errorf("sync error: %v", syncErr)
	}

	if closeErr := fw.Close(); closeErr != nil {
		t.Errorf("close error: %v", closeErr)
	}

	// Verify file contents.
	content, err := os.ReadFile(logPath) //#nosec G304 -- Test file path.
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if string(content) != "test log entry\n" {
		t.Errorf("expected 'test log entry\\n', got %v", string(content))
	}
}

func TestFileWriter_Append(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "append.log")

	// First write.
	fw1, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create file writer: %v", err)
	}
	_, _ = fw1.Write([]byte("first\n"))
	_ = fw1.Close()

	// Second write (should append).
	fw2, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create file writer: %v", err)
	}
	_, _ = fw2.Write([]byte("second\n"))
	_ = fw2.Close()

	// Verify contents.
	content, err := os.ReadFile(logPath) //#nosec G304 -- Test file path.
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if string(content) != "first\nsecond\n" {
		t.Errorf("expected 'first\\nsecond\\n', got %v", string(content))
	}
}

func TestFileWriter_ClosedWrite(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "closed.log")

	fw, err := NewFileWriter(logPath)
	if err != nil {
		t.Fatalf("failed to create file writer: %v", err)
	}

	_ = fw.Close()

	_, err = fw.Write([]byte("after close"))
	if err != os.ErrClosed {
		t.Errorf("expected os.ErrClosed, got %v", err)
	}
}

func TestNewFileLogger(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "logger.log")

	logger, fw, err := NewFileLogger(logPath, WithLevel(LevelInfo))
	if err != nil {
		t.Fatalf("failed to create file logger: %v", err)
	}
	defer func() { _ = fw.Close() }()

	logger.Info("file logger message")
	_ = fw.Sync()

	content, err := os.ReadFile(logPath) //#nosec G304 -- Test file path.
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var entry Entry
	if err := json.Unmarshal(bytes.TrimSpace(content), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Message != "file logger message" {
		t.Errorf("expected message='file logger message', got %v", entry.Message)
	}
}

func TestNewDualLogger(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "dual.log")

	logger, mw, err := NewDualLogger(logPath, WithLevel(LevelInfo))
	if err != nil {
		t.Fatalf("failed to create dual logger: %v", err)
	}
	defer func() { _ = mw.Close() }()

	logger.Info("dual logger message")

	content, err := os.ReadFile(logPath) //#nosec G304 -- Test file path.
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	var entry Entry
	if err := json.Unmarshal(bytes.TrimSpace(content), &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.Message != "dual logger message" {
		t.Errorf("expected message='dual logger message', got %v", entry.Message)
	}
}

func TestFromContext_WithCorrelationID(t *testing.T) {
	// Do NOT run in parallel - modifies global Default.

	// Save and restore default logger.
	original := Default
	defer func() { Default = original }()

	var buf bytes.Buffer
	Default = New(WithOutput(&buf), WithLevel(LevelInfo))

	ctx := WithCorrelationIDContext(context.Background(), "ctx-correlation")
	logger := FromContext(ctx)

	logger.Info("test message")

	var entry Entry
	if err := json.Unmarshal(buf.Bytes()[:len(buf.Bytes())-1], &entry); err != nil {
		t.Fatalf("failed to parse JSON: %v", err)
	}

	if entry.CorrelationID != "ctx-correlation" {
		t.Errorf("expected correlation_id=ctx-correlation, got %v", entry.CorrelationID)
	}
}

func TestCorrelationIDFromContext_NilContext(t *testing.T) {
	t.Parallel()

	id := CorrelationIDFromContext(context.TODO())

	if id != "" {
		t.Errorf("expected empty string for nil context, got %v", id)
	}
}
