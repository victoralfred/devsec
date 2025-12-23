package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

// contextKey is a type for context keys.
type contextKey int

const (
	// LoggerKey is the context key for the logger.
	loggerKey contextKey = iota
	// CorrelationIDKey is the context key for the correlation ID.
	correlationIDKey
)

// FromContext retrieves the logger from context.
// If no logger is found, returns the default logger.
func FromContext(ctx context.Context) Logger {
	if ctx == nil {
		return Default
	}

	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}

	// Check for correlation ID and attach it to default logger.
	if id := CorrelationIDFromContext(ctx); id != "" {
		return Default.WithCorrelationID(id)
	}

	return Default
}

// WithLogger adds a logger to the context.
func WithLogger(ctx context.Context, logger Logger) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

// CorrelationIDFromContext retrieves the correlation ID from context.
func CorrelationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}

	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}

	return ""
}

// WithCorrelationIDContext adds a correlation ID to the context.
func WithCorrelationIDContext(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, correlationIDKey, id)
}

// NewCorrelationID generates a new random correlation ID.
func NewCorrelationID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to empty if random fails.
		return ""
	}
	return hex.EncodeToString(b)
}

// WithNewCorrelationID creates a context with a new correlation ID
// and returns both the context and the ID.
func WithNewCorrelationID(ctx context.Context) (newCtx context.Context, correlationID string) {
	correlationID = NewCorrelationID()
	newCtx = WithCorrelationIDContext(ctx, correlationID)
	return newCtx, correlationID
}

// ContextLogger creates a logger from context with correlation ID attached.
// If no correlation ID exists in context, a new one is generated.
func ContextLogger(ctx context.Context) (Logger, context.Context) {
	id := CorrelationIDFromContext(ctx)
	if id == "" {
		ctx, id = WithNewCorrelationID(ctx)
	}

	logger := FromContext(ctx).WithCorrelationID(id)
	ctx = WithLogger(ctx, logger)

	return logger, ctx
}

// CtxDebug logs a debug message using the logger from context.
func CtxDebug(ctx context.Context, msg string, fields ...Fields) {
	FromContext(ctx).Debug(msg, fields...)
}

// CtxInfo logs an info message using the logger from context.
func CtxInfo(ctx context.Context, msg string, fields ...Fields) {
	FromContext(ctx).Info(msg, fields...)
}

// CtxWarn logs a warning message using the logger from context.
func CtxWarn(ctx context.Context, msg string, fields ...Fields) {
	FromContext(ctx).Warn(msg, fields...)
}

// CtxError logs an error message using the logger from context.
func CtxError(ctx context.Context, msg string, err error, fields ...Fields) {
	FromContext(ctx).Error(msg, err, fields...)
}
