package alerting

import (
	"context"
	"sync"
	"time"
)

// ManagerConfig holds configuration for the notification manager.
type ManagerConfig struct {
	MinSeverity     Severity
	DefaultTimeout  time.Duration
	ContinueOnError bool
}

// ManagerOption configures ManagerConfig.
type ManagerOption func(*ManagerConfig)

// WithManagerTimeout sets the default timeout.
func WithManagerTimeout(d time.Duration) ManagerOption {
	return func(c *ManagerConfig) {
		c.DefaultTimeout = d
	}
}

// WithContinueOnError sets whether to continue on error.
func WithContinueOnError(cont bool) ManagerOption {
	return func(c *ManagerConfig) {
		c.ContinueOnError = cont
	}
}

// WithMinSeverity sets the minimum severity.
func WithMinSeverity(s Severity) ManagerOption {
	return func(c *ManagerConfig) {
		c.MinSeverity = s
	}
}

// Manager manages multiple notifiers and routes alerts.
type Manager struct {
	notifiers []Notifier
	config    ManagerConfig
	mu        sync.RWMutex
}

// NewManager creates a new notification manager.
func NewManager(opts ...ManagerOption) *Manager {
	config := ManagerConfig{
		DefaultTimeout:  30 * time.Second,
		ContinueOnError: true,
		MinSeverity:     SeverityInfo,
	}

	for _, opt := range opts {
		opt(&config)
	}

	return &Manager{
		config:    config,
		notifiers: make([]Notifier, 0),
	}
}

// AddNotifier adds a notifier to the manager.
func (m *Manager) AddNotifier(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers = append(m.notifiers, n)
}

// RemoveNotifier removes a notifier by name.
func (m *Manager) RemoveNotifier(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	filtered := make([]Notifier, 0, len(m.notifiers))
	for _, n := range m.notifiers {
		if n.Name() != name {
			filtered = append(filtered, n)
		}
	}
	m.notifiers = filtered
}

// GetNotifier returns a notifier by name.
func (m *Manager) GetNotifier(name string) Notifier {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, n := range m.notifiers {
		if n.Name() == name {
			return n
		}
	}
	return nil
}

// Notifiers returns all registered notifiers.
func (m *Manager) Notifiers() []Notifier {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]Notifier, len(m.notifiers))
	copy(result, m.notifiers)
	return result
}

// Send sends an alert to all enabled notifiers.
func (m *Manager) Send(ctx context.Context, alert Alert) []NotifyResult {
	m.mu.RLock()
	notifiers := make([]Notifier, len(m.notifiers))
	copy(notifiers, m.notifiers)
	m.mu.RUnlock()

	if len(notifiers) == 0 {
		return []NotifyResult{{
			Notifier:  "manager",
			AlertID:   alert.ID,
			Success:   false,
			Error:     ErrNoNotifiers.Error(),
			Timestamp: time.Now().UTC(),
		}}
	}

	// Check minimum severity.
	if !m.meetsMinSeverity(alert.Severity) {
		return nil
	}

	results := make([]NotifyResult, 0, len(notifiers))

	for _, n := range notifiers {
		if !n.IsEnabled() {
			continue
		}

		result := NotifyResult{
			Notifier:  n.Name(),
			AlertID:   alert.ID,
			Timestamp: time.Now().UTC(),
		}

		if err := n.Send(ctx, alert); err != nil {
			result.Success = false
			result.Error = err.Error()

			if !m.config.ContinueOnError {
				results = append(results, result)
				return results
			}
		} else {
			result.Success = true
		}

		results = append(results, result)
	}

	return results
}

// SendAsync sends an alert asynchronously to all notifiers.
func (m *Manager) SendAsync(ctx context.Context, alert Alert) <-chan NotifyResult {
	resultCh := make(chan NotifyResult, len(m.notifiers))

	go func() {
		defer close(resultCh)

		m.mu.RLock()
		notifiers := make([]Notifier, len(m.notifiers))
		copy(notifiers, m.notifiers)
		m.mu.RUnlock()

		if len(notifiers) == 0 {
			resultCh <- NotifyResult{
				Notifier:  "manager",
				AlertID:   alert.ID,
				Success:   false,
				Error:     ErrNoNotifiers.Error(),
				Timestamp: time.Now().UTC(),
			}
			return
		}

		// Check minimum severity.
		if !m.meetsMinSeverity(alert.Severity) {
			return
		}

		var wg sync.WaitGroup

		for _, n := range notifiers {
			if !n.IsEnabled() {
				continue
			}

			wg.Add(1)
			go func(notifier Notifier) {
				defer wg.Done()

				result := NotifyResult{
					Notifier:  notifier.Name(),
					AlertID:   alert.ID,
					Timestamp: time.Now().UTC(),
				}

				if err := notifier.Send(ctx, alert); err != nil {
					result.Success = false
					result.Error = err.Error()
				} else {
					result.Success = true
				}

				resultCh <- result
			}(n)
		}

		wg.Wait()
	}()

	return resultCh
}

// SendBatch sends multiple alerts to all notifiers.
func (m *Manager) SendBatch(ctx context.Context, alerts []Alert) []NotifyResult {
	var allResults []NotifyResult

	for i := range alerts {
		results := m.Send(ctx, alerts[i])
		allResults = append(allResults, results...)
	}

	return allResults
}

// meetsMinSeverity checks if the severity meets the minimum threshold.
func (m *Manager) meetsMinSeverity(s Severity) bool {
	severityOrder := map[Severity]int{
		SeverityCritical: 5,
		SeverityHigh:     4,
		SeverityMedium:   3,
		SeverityLow:      2,
		SeverityInfo:     1,
	}

	alertLevel := severityOrder[s]
	minLevel := severityOrder[m.config.MinSeverity]

	return alertLevel >= minLevel
}

// EnabledCount returns the number of enabled notifiers.
func (m *Manager) EnabledCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, n := range m.notifiers {
		if n.IsEnabled() {
			count++
		}
	}
	return count
}

// Close closes all notifiers that implement io.Closer.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var lastErr error
	for _, n := range m.notifiers {
		if closer, ok := n.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				lastErr = err
			}
		}
	}

	m.notifiers = nil
	return lastErr
}
