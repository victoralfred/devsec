package metrics

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ServerConfig holds configuration for the metrics server.
type ServerConfig struct {
	// Address to listen on (e.g., ":9090" or "127.0.0.1:9090").
	Address string

	// Path for metrics endpoint (default: "/metrics").
	Path string

	// ReadTimeout for HTTP server.
	ReadTimeout time.Duration

	// WriteTimeout for HTTP server.
	WriteTimeout time.Duration

	// ShutdownTimeout for graceful shutdown.
	ShutdownTimeout time.Duration
}

// DefaultServerConfig returns the default server configuration.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Address:         ":9090",
		Path:            "/metrics",
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
		ShutdownTimeout: 5 * time.Second,
	}
}

// ServerOption configures ServerConfig.
type ServerOption func(*ServerConfig)

// WithAddress sets the server address.
func WithAddress(addr string) ServerOption {
	return func(c *ServerConfig) {
		c.Address = addr
	}
}

// WithPath sets the metrics endpoint path.
func WithPath(path string) ServerOption {
	return func(c *ServerConfig) {
		c.Path = path
	}
}

// WithReadTimeout sets the read timeout.
func WithReadTimeout(d time.Duration) ServerOption {
	return func(c *ServerConfig) {
		c.ReadTimeout = d
	}
}

// WithWriteTimeout sets the write timeout.
func WithWriteTimeout(d time.Duration) ServerOption {
	return func(c *ServerConfig) {
		c.WriteTimeout = d
	}
}

// WithShutdownTimeout sets the shutdown timeout.
func WithShutdownTimeout(d time.Duration) ServerOption {
	return func(c *ServerConfig) {
		c.ShutdownTimeout = d
	}
}

// Server serves Prometheus metrics over HTTP.
type Server struct {
	metrics *Metrics
	server  *http.Server
	config  ServerConfig
	mu      sync.RWMutex
	running bool
}

// NewServer creates a new metrics server.
func NewServer(metrics *Metrics, opts ...ServerOption) *Server {
	config := DefaultServerConfig()
	for _, opt := range opts {
		opt(&config)
	}

	return &Server{
		metrics: metrics,
		config:  config,
	}
}

// Start starts the metrics server.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return ErrServerAlreadyRunning
	}

	mux := http.NewServeMux()

	// Metrics endpoint with custom registry.
	handler := promhttp.HandlerFor(s.metrics.Registry(), promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
	mux.Handle(s.config.Path, handler)

	// Health endpoint.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Ready endpoint.
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Ready"))
	})

	s.server = &http.Server{
		Addr:         s.config.Address,
		Handler:      mux,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	listener, err := net.Listen("tcp", s.config.Address)
	if err != nil {
		return err
	}

	s.running = true

	go func() {
		if serveErr := s.server.Serve(listener); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			s.mu.Lock()
			s.running = false
			s.mu.Unlock()
		}
	}()

	return nil
}

// Stop gracefully stops the metrics server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	// Create shutdown context with timeout if not provided.
	shutdownCtx := ctx
	if s.config.ShutdownTimeout > 0 {
		var cancel context.CancelFunc
		shutdownCtx, cancel = context.WithTimeout(ctx, s.config.ShutdownTimeout)
		defer cancel()
	}

	err := s.server.Shutdown(shutdownCtx)
	s.running = false
	return err
}

// IsRunning returns whether the server is running.
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}

// Address returns the configured address.
func (s *Server) Address() string {
	return s.config.Address
}

// Path returns the metrics endpoint path.
func (s *Server) Path() string {
	return s.config.Path
}
