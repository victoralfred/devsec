// Package alerting provides notification capabilities for the devsec pipeline.
package alerting

import (
	"fmt"
	"sync"
)

// NotifierFactory creates notifier instances from configuration.
type NotifierFactory func(config map[string]interface{}) (Notifier, error)

// NotifierRegistry manages notifier types and their factories.
// It allows consumers to register custom notifier types and create instances.
type NotifierRegistry struct {
	factories map[string]NotifierFactory
	mu        sync.RWMutex
}

// NewNotifierRegistry creates a new empty notifier registry.
func NewNotifierRegistry() *NotifierRegistry {
	return &NotifierRegistry{
		factories: make(map[string]NotifierFactory),
	}
}

// Register adds a notifier factory to the registry.
// The name is case-sensitive.
// Returns an error if the name is empty or already registered.
func (r *NotifierRegistry) Register(name string, factory NotifierFactory) error {
	if name == "" {
		return fmt.Errorf("notifier name cannot be empty")
	}
	if factory == nil {
		return fmt.Errorf("notifier factory cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		return fmt.Errorf("notifier %q already registered", name)
	}

	r.factories[name] = factory
	return nil
}

// MustRegister registers a notifier factory and panics on error.
// Useful for registering built-in notifiers at package initialization.
func (r *NotifierRegistry) MustRegister(name string, factory NotifierFactory) {
	if err := r.Register(name, factory); err != nil {
		panic(fmt.Sprintf("failed to register notifier %q: %v", name, err))
	}
}

// Get returns the factory for the given notifier name.
// Returns false if the notifier is not registered.
func (r *NotifierRegistry) Get(name string) (NotifierFactory, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	factory, ok := r.factories[name]
	return factory, ok
}

// Has checks if a notifier is registered.
func (r *NotifierRegistry) Has(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, ok := r.factories[name]
	return ok
}

// Create creates a notifier instance by name with the given configuration.
// Returns an error if the notifier is not registered or creation fails.
func (r *NotifierRegistry) Create(name string, config map[string]interface{}) (Notifier, error) {
	factory, ok := r.Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown notifier type: %s", name)
	}

	notifier, err := factory(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create notifier %q: %w", name, err)
	}

	return notifier, nil
}

// Names returns all registered notifier names.
func (r *NotifierRegistry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.factories))
	for name := range r.factories {
		names = append(names, name)
	}
	return names
}

// Unregister removes a notifier from the registry.
// Returns true if the notifier was found and removed.
func (r *NotifierRegistry) Unregister(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.factories[name]; exists {
		delete(r.factories, name)
		return true
	}
	return false
}

// DefaultRegistry returns a registry with built-in notifiers registered.
// Built-in notifiers include: slack, webhook.
func DefaultRegistry() *NotifierRegistry {
	registry := NewNotifierRegistry()

	// Register Slack notifier factory.
	registry.MustRegister("slack", func(config map[string]interface{}) (Notifier, error) {
		webhookURL, _ := config["webhook_url"].(string)
		if webhookURL == "" {
			return nil, fmt.Errorf("webhook_url is required for slack notifier")
		}

		var opts []SlackOption

		if channel, ok := config["channel"].(string); ok && channel != "" {
			opts = append(opts, WithSlackChannel(channel))
		}
		if username, ok := config["username"].(string); ok && username != "" {
			opts = append(opts, WithSlackUsername(username))
		}
		if icon, ok := config["icon_emoji"].(string); ok && icon != "" {
			opts = append(opts, WithSlackIcon(icon))
		}
		if enabled, ok := config["enabled"].(bool); ok {
			opts = append(opts, WithSlackEnabled(enabled))
		}

		return NewSlackNotifier(webhookURL, opts...)
	})

	// Register Webhook notifier factory.
	registry.MustRegister("webhook", func(config map[string]interface{}) (Notifier, error) {
		webhookURL, _ := config["url"].(string)
		if webhookURL == "" {
			return nil, fmt.Errorf("url is required for webhook notifier")
		}

		var opts []WebhookOption

		if secret, ok := config["secret"].(string); ok && secret != "" {
			opts = append(opts, WithWebhookSecret(secret))
		}
		if method, ok := config["method"].(string); ok && method != "" {
			opts = append(opts, WithWebhookMethod(method))
		}
		if headers, ok := config["headers"].(map[string]string); ok {
			opts = append(opts, WithWebhookHeaders(headers))
		}
		if enabled, ok := config["enabled"].(bool); ok {
			opts = append(opts, WithWebhookEnabled(enabled))
		}

		return NewWebhookNotifier(webhookURL, opts...)
	})

	return registry
}

// globalRegistry is the default registry used when none is specified.
var globalRegistry = DefaultRegistry()

// GlobalRegistry returns the global default notifier registry.
// This registry is initialized with all built-in notifiers.
func GlobalRegistry() *NotifierRegistry {
	return globalRegistry
}
