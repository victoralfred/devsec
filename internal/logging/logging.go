// Package logging provides structured JSON logging with levels and correlation IDs.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"time"
)

// Level represents the severity of a log message.
type Level int

const (
	// LevelDebug is for verbose debugging information.
	LevelDebug Level = iota
	// LevelInfo is for general informational messages.
	LevelInfo
	// LevelWarn is for warning messages.
	LevelWarn
	// LevelError is for error messages.
	LevelError
)

// String returns the string representation of the level.
func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

// ParseLevel parses a string into a Level.
func ParseLevel(s string) (Level, error) {
	switch s {
	case "debug", "DEBUG":
		return LevelDebug, nil
	case "info", "INFO":
		return LevelInfo, nil
	case "warn", "WARN", "warning", "WARNING":
		return LevelWarn, nil
	case "error", "ERROR":
		return LevelError, nil
	default:
		return LevelInfo, fmt.Errorf("unknown log level: %s", s)
	}
}

// Entry represents a single log entry.
type Entry struct {
	time          time.Time // Internal, not serialized.
	Fields        Fields    `json:"fields,omitempty"`
	Message       string    `json:"message"`
	Level         string    `json:"level"`
	Timestamp     string    `json:"timestamp"`
	CorrelationID string    `json:"correlation_id,omitempty"`
	Caller        string    `json:"caller,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// Fields represents structured log fields.
type Fields map[string]interface{}

// Logger is the interface for structured logging.
type Logger interface {
	// Debug logs a debug message.
	Debug(msg string, fields ...Fields)
	// Info logs an info message.
	Info(msg string, fields ...Fields)
	// Warn logs a warning message.
	Warn(msg string, fields ...Fields)
	// Error logs an error message.
	Error(msg string, err error, fields ...Fields)
	// WithFields returns a new logger with additional fields.
	WithFields(fields Fields) Logger
	// WithCorrelationID returns a new logger with a correlation ID.
	WithCorrelationID(id string) Logger
	// SetLevel sets the minimum log level.
	SetLevel(level Level)
	// SetOutput sets the output writer.
	SetOutput(w io.Writer)
}

// JSONLogger implements Logger with JSON output.
type JSONLogger struct {
	output        io.Writer
	fields        Fields
	correlationID string
	mu            sync.Mutex
	level         Level
	includeCaller bool
}

// Option configures a JSONLogger.
type Option func(*JSONLogger)

// WithLevel sets the minimum log level.
func WithLevel(level Level) Option {
	return func(l *JSONLogger) {
		l.level = level
	}
}

// WithOutput sets the output writer.
func WithOutput(w io.Writer) Option {
	return func(l *JSONLogger) {
		l.output = w
	}
}

// WithCaller enables caller information in logs.
func WithCaller(enabled bool) Option {
	return func(l *JSONLogger) {
		l.includeCaller = enabled
	}
}

// WithCorrelation sets the initial correlation ID.
func WithCorrelation(id string) Option {
	return func(l *JSONLogger) {
		l.correlationID = id
	}
}

// New creates a new JSONLogger with the given options.
func New(opts ...Option) *JSONLogger {
	l := &JSONLogger{
		output: os.Stdout,
		level:  LevelInfo,
		fields: make(Fields),
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// Debug logs a debug message.
func (l *JSONLogger) Debug(msg string, fields ...Fields) {
	l.log(LevelDebug, msg, nil, fields...)
}

// Info logs an info message.
func (l *JSONLogger) Info(msg string, fields ...Fields) {
	l.log(LevelInfo, msg, nil, fields...)
}

// Warn logs a warning message.
func (l *JSONLogger) Warn(msg string, fields ...Fields) {
	l.log(LevelWarn, msg, nil, fields...)
}

// Error logs an error message.
func (l *JSONLogger) Error(msg string, err error, fields ...Fields) {
	l.log(LevelError, msg, err, fields...)
}

// WithFields returns a new logger with additional fields.
func (l *JSONLogger) WithFields(fields Fields) Logger {
	newFields := make(Fields, len(l.fields)+len(fields))
	for k, v := range l.fields {
		newFields[k] = v
	}
	for k, v := range fields {
		newFields[k] = v
	}

	return &JSONLogger{
		output:        l.output,
		level:         l.level,
		fields:        newFields,
		correlationID: l.correlationID,
		includeCaller: l.includeCaller,
	}
}

// WithCorrelationID returns a new logger with a correlation ID.
func (l *JSONLogger) WithCorrelationID(id string) Logger {
	return &JSONLogger{
		output:        l.output,
		level:         l.level,
		fields:        l.fields,
		correlationID: id,
		includeCaller: l.includeCaller,
	}
}

// SetLevel sets the minimum log level.
func (l *JSONLogger) SetLevel(level Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetOutput sets the output writer.
func (l *JSONLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// log writes a log entry.
func (l *JSONLogger) log(level Level, msg string, err error, fields ...Fields) {
	if level < l.level {
		return
	}

	entry := Entry{
		Message:       msg,
		Level:         level.String(),
		Timestamp:     time.Now().UTC().Format(time.RFC3339Nano),
		CorrelationID: l.correlationID,
		time:          time.Now(),
	}

	if err != nil {
		entry.Error = err.Error()
	}

	if l.includeCaller {
		entry.Caller = l.getCaller()
	}

	// Merge fields.
	allFields := make(Fields, len(l.fields))
	for k, v := range l.fields {
		allFields[k] = v
	}
	for _, f := range fields {
		for k, v := range f {
			allFields[k] = v
		}
	}
	if len(allFields) > 0 {
		entry.Fields = allFields
	}

	l.write(entry)
}

// write serializes and writes the entry.
func (l *JSONLogger) write(entry Entry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		// Fallback to simple format if JSON fails.
		_, _ = fmt.Fprintf(l.output, `{"level":"%s","message":"log marshal error: %v"}`+"\n", entry.Level, err)
		return
	}

	_, _ = l.output.Write(data)
	_, _ = l.output.Write([]byte("\n"))
}

// getCaller returns the file:line of the caller.
func (l *JSONLogger) getCaller() string {
	// Skip: runtime.Caller(0)=getCaller, 1=log, 2=Debug/Info/Warn/Error, 3=user code.
	_, file, line, ok := runtime.Caller(3)
	if !ok {
		return "unknown"
	}

	// Get just the filename, not full path.
	short := file
	for i := len(file) - 1; i > 0; i-- {
		if file[i] == '/' {
			short = file[i+1:]
			break
		}
	}

	return fmt.Sprintf("%s:%d", short, line)
}

// Default is the default logger instance.
var Default = New()

// Debug logs a debug message using the default logger.
func Debug(msg string, fields ...Fields) {
	Default.Debug(msg, fields...)
}

// Info logs an info message using the default logger.
func Info(msg string, fields ...Fields) {
	Default.Info(msg, fields...)
}

// Warn logs a warning message using the default logger.
func Warn(msg string, fields ...Fields) {
	Default.Warn(msg, fields...)
}

// Error logs an error message using the default logger.
func Error(msg string, err error, fields ...Fields) {
	Default.Error(msg, err, fields...)
}

// SetLevel sets the level for the default logger.
func SetLevel(level Level) {
	Default.SetLevel(level)
}

// SetOutput sets the output for the default logger.
func SetOutput(w io.Writer) {
	Default.SetOutput(w)
}
