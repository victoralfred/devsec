package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/victoralfred/gowritter/safepath"
	"gopkg.in/yaml.v3"
)

// Loader limits for DoS prevention.
const (
	MaxFileSize = 1 << 20 // 1 MB
)

// Loader loads pipeline definitions from YAML files.
type Loader struct{}

// NewLoader creates a new pipeline loader.
func NewLoader() *Loader {
	return &Loader{}
}

// Load loads a pipeline from a YAML file.
func (l *Loader) Load(ctx context.Context, path string) (*Pipeline, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if path == "" {
		return nil, ErrEmptyPath
	}

	// Check context cancellation before proceeding.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Clean the path to prevent path traversal.
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	filename := filepath.Base(cleanPath)

	// Check file size before reading.
	info, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, NewLoadError(cleanPath, "file not found", ErrFileNotFound)
		}
		return nil, NewLoadError(cleanPath, "failed to stat file", err)
	}

	if info.Size() > MaxFileSize {
		return nil, NewLoadError(cleanPath, "file too large", ErrFileTooLarge)
	}

	// Create safepath for file reading.
	sp, err := safepath.New(dir)
	if err != nil {
		return nil, NewLoadError(cleanPath, "failed to create safe path", err)
	}

	// Read file content using safepath.
	data, err := sp.ReadFile(filename)
	if err != nil {
		return nil, NewLoadError(cleanPath, "failed to read file", err)
	}

	// Parse YAML.
	return l.parse(data, cleanPath)
}

// LoadFromBytes loads a pipeline from YAML bytes.
func (l *Loader) LoadFromBytes(ctx context.Context, data []byte) (*Pipeline, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}

	if len(data) == 0 {
		return nil, NewLoadError("", "empty content", ErrInvalidYAML)
	}

	if len(data) > MaxFileSize {
		return nil, NewLoadError("", "content too large", ErrFileTooLarge)
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	return l.parse(data, "")
}

// parse parses YAML data into a Pipeline.
func (l *Loader) parse(data []byte, path string) (*Pipeline, error) {
	// Unmarshal YAML into raw struct for duration parsing.
	var raw rawPipeline
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, NewLoadError(path, "invalid YAML", err)
	}

	// Convert to Pipeline.
	pipeline, err := raw.toPipeline()
	if err != nil {
		return nil, NewLoadError(path, "conversion failed", err)
	}

	// Validate the pipeline.
	if err := pipeline.Validate(); err != nil {
		return nil, NewLoadError(path, "validation failed", err)
	}

	return pipeline, nil
}

// rawPipeline is the raw YAML representation of a pipeline.
// Used to handle duration parsing from strings.
type rawPipeline struct {
	Metadata map[string]string `yaml:"metadata,omitempty"`
	Name     string            `yaml:"name"`
	Version  string            `yaml:"version,omitempty"`
	Timeout  string            `yaml:"timeout,omitempty"`
	Stages   []rawStage        `yaml:"stages"`
	Parallel bool              `yaml:"parallel,omitempty"`
	FailFast bool              `yaml:"fail_fast,omitempty"`
}

// rawStage is the raw YAML representation of a stage.
type rawStage struct {
	Config     map[string]string `yaml:"config,omitempty"`
	Name       string            `yaml:"name"`
	Kind       string            `yaml:"kind"`
	Timeout    string            `yaml:"timeout,omitempty"`
	ContinueOn string            `yaml:"continue_on,omitempty"`
	DependsOn  []string          `yaml:"depends_on,omitempty"`
	Parallel   bool              `yaml:"parallel,omitempty"`
	FailFast   bool              `yaml:"fail_fast,omitempty"`
}

// toPipeline converts rawPipeline to Pipeline.
func (r *rawPipeline) toPipeline() (*Pipeline, error) {
	p := &Pipeline{
		Metadata: r.Metadata,
		Name:     r.Name,
		Version:  r.Version,
		Parallel: r.Parallel,
		FailFast: r.FailFast,
	}

	// Parse pipeline timeout.
	if r.Timeout != "" {
		timeout, err := time.ParseDuration(r.Timeout)
		if err != nil {
			return nil, NewValidationError("timeout", "invalid duration format", err)
		}
		p.Timeout = timeout
	}

	// Convert stages.
	p.Stages = make([]Stage, 0, len(r.Stages))
	for i := range r.Stages {
		stage, err := r.Stages[i].toStage()
		if err != nil {
			return nil, err
		}
		p.Stages = append(p.Stages, *stage)
	}

	return p, nil
}

// toStage converts rawStage to Stage.
func (r *rawStage) toStage() (*Stage, error) {
	s := &Stage{
		Config:     r.Config,
		Name:       r.Name,
		Kind:       StageKind(r.Kind),
		DependsOn:  r.DependsOn,
		ContinueOn: ContinueCondition(r.ContinueOn),
		Parallel:   r.Parallel,
		FailFast:   r.FailFast,
	}

	// Parse stage timeout.
	if r.Timeout != "" {
		timeout, err := time.ParseDuration(r.Timeout)
		if err != nil {
			return nil, NewValidationError("stages.timeout", "invalid duration format", err)
		}
		s.Timeout = timeout
	}

	return s, nil
}

// DefaultPipelineNames returns common pipeline file names to search for.
func DefaultPipelineNames() []string {
	return []string{
		"devsec.yaml",
		"devsec.yml",
		"pipeline.yaml",
		"pipeline.yml",
		".devsec.yaml",
		".devsec.yml",
	}
}

// FindPipeline searches for a pipeline file in the given directory.
func (l *Loader) FindPipeline(ctx context.Context, dir string) (string, error) {
	if ctx == nil {
		return "", ErrNilContext
	}

	if dir == "" {
		dir = "."
	}

	// Clean the directory path.
	cleanDir := filepath.Clean(dir)

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	default:
	}

	// Search for pipeline files.
	for _, name := range DefaultPipelineNames() {
		path := filepath.Join(cleanDir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", NewLoadError(cleanDir, "no pipeline file found", ErrFileNotFound)
}

// Save saves a pipeline to a YAML file.
func (l *Loader) Save(ctx context.Context, pipeline *Pipeline, path string) error {
	if ctx == nil {
		return ErrNilContext
	}

	if pipeline == nil {
		return ErrNilPipeline
	}

	if path == "" {
		return ErrEmptyPath
	}

	// Validate before saving.
	if err := pipeline.Validate(); err != nil {
		return err
	}

	// Check context cancellation.
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Convert to raw format for proper YAML output.
	raw := pipelineToRaw(pipeline)

	// Marshal to YAML.
	data, err := yaml.Marshal(raw)
	if err != nil {
		return NewLoadError(path, "failed to marshal pipeline", err)
	}

	// Clean the path.
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)
	filename := filepath.Base(cleanPath)

	// Create safepath for file writing.
	sp, err := safepath.New(dir)
	if err != nil {
		return NewLoadError(cleanPath, "failed to create safe path", err)
	}

	// Write using safepath.
	if err := sp.WriteFile(filename, data, 0o600); err != nil {
		return NewLoadError(cleanPath, "failed to write file", err)
	}

	return nil
}

// pipelineToRaw converts Pipeline to rawPipeline for YAML output.
func pipelineToRaw(p *Pipeline) *rawPipeline {
	raw := &rawPipeline{
		Metadata: p.Metadata,
		Name:     p.Name,
		Version:  p.Version,
		Parallel: p.Parallel,
		FailFast: p.FailFast,
	}

	if p.Timeout > 0 {
		raw.Timeout = p.Timeout.String()
	}

	raw.Stages = make([]rawStage, 0, len(p.Stages))
	for i := range p.Stages {
		raw.Stages = append(raw.Stages, stageToRaw(&p.Stages[i]))
	}

	return raw
}

// stageToRaw converts Stage to rawStage for YAML output.
func stageToRaw(s *Stage) rawStage {
	raw := rawStage{
		Config:     s.Config,
		Name:       s.Name,
		Kind:       string(s.Kind),
		DependsOn:  s.DependsOn,
		ContinueOn: string(s.ContinueOn),
		Parallel:   s.Parallel,
		FailFast:   s.FailFast,
	}

	if s.Timeout > 0 {
		raw.Timeout = s.Timeout.String()
	}

	return raw
}
