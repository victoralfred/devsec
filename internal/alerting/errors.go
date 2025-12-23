package alerting

import (
	"errors"
	"fmt"
)

// Sentinel errors for the alerting package.
var (
	// ErrNilContext is returned when context is nil.
	ErrNilContext = errors.New("context cannot be nil")

	// ErrNotifierDisabled is returned when a notifier is disabled.
	ErrNotifierDisabled = errors.New("notifier is disabled")

	// ErrInvalidWebhookURL is returned when webhook URL is invalid.
	ErrInvalidWebhookURL = errors.New("invalid webhook URL")

	// ErrInvalidSlackToken is returned when Slack token is invalid.
	ErrInvalidSlackToken = errors.New("invalid Slack token")

	// ErrInvalidChannel is returned when channel is invalid.
	ErrInvalidChannel = errors.New("invalid channel")

	// ErrSendFailed is returned when sending a notification fails.
	ErrSendFailed = errors.New("failed to send notification")

	// ErrTimeout is returned when a notification times out.
	ErrTimeout = errors.New("notification timed out")

	// ErrRateLimited is returned when rate limited by the service.
	ErrRateLimited = errors.New("rate limited")

	// ErrNoNotifiers is returned when no notifiers are configured.
	ErrNoNotifiers = errors.New("no notifiers configured")

	// ErrEmptyAlert is returned when alert is empty.
	ErrEmptyAlert = errors.New("alert cannot be empty")
)

// NotifyError wraps errors with notification context.
type NotifyError struct {
	Err      error
	Notifier string
	AlertID  string
	Op       string
}

// Error implements the error interface.
func (e *NotifyError) Error() string {
	if e.AlertID != "" {
		return fmt.Sprintf("%s: %s [notifier=%s, alert=%s]", e.Op, e.Err.Error(), e.Notifier, e.AlertID)
	}
	return fmt.Sprintf("%s: %s [notifier=%s]", e.Op, e.Err.Error(), e.Notifier)
}

// Unwrap returns the underlying error.
func (e *NotifyError) Unwrap() error {
	return e.Err
}

// NewNotifyError creates a new NotifyError.
func NewNotifyError(op, notifier, alertID string, err error) *NotifyError {
	return &NotifyError{
		Op:       op,
		Notifier: notifier,
		AlertID:  alertID,
		Err:      err,
	}
}

// IsTimeout checks if the error is a timeout error.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsRateLimited checks if the error is a rate limit error.
func IsRateLimited(err error) bool {
	return errors.Is(err, ErrRateLimited)
}

// IsSendFailed checks if the error is a send failure.
func IsSendFailed(err error) bool {
	return errors.Is(err, ErrSendFailed)
}
