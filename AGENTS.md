# AI Coding Agents Guide for DevSec

This document provides instructions for AI coding agents working on DevSec.

## Quick Context

- **Language**: Go 1.23+
- **Build**: `make build`
- **Test**: `make test`
- **Lint**: `make lint`
- **Entry Point**: `cmd/devsec/main.go`

## Before Making Changes

1. Read relevant source files first
2. Understand existing patterns in the codebase
3. Check for existing tests
4. Run `make check` to verify current state

## Making Changes

### Adding a New Command

1. Create command file in `internal/cli/`
2. Register in `internal/cli/root.go`
3. Add tests in `internal/cli/*_test.go`
4. Update `README.md` CLI reference

### Adding a New Scanner

1. Create package in `internal/scanner/<name>/`
2. Implement `Scanner` interface from `internal/scanner/scanner.go`
3. Register in scanner factory
4. Add CLI command if needed

### Adding Compliance Controls

1. Add controls to `internal/compliance/controls.go`
2. Map to findings in `internal/compliance/mapper.go`
3. Update framework coverage tests

## File I/O Requirement

```go
// WRONG - Do not use
file, err := os.Create("output.txt")

// CORRECT - Use gowritter
import "github.com/victoralfred/gowritter/safepath"
sp, _ := safepath.New("/safe/dir")
file, _ := sp.Create("output.txt")
```

## Testing Requirements

- Write table-driven tests
- Use subtests for organization
- Mock external dependencies
- Minimum 40% coverage

## Commit Guidelines

- Clear, descriptive messages
- Reference issues if applicable
- All checks must pass
- No `--no-verify`

## Quality Gates

Before submitting changes:

```bash
make check      # Runs all checks
make test       # Unit tests with race detection
make lint       # golangci-lint
make security   # gosec security scan
```

## Common Patterns

### Error Handling
```go
if err != nil {
    return fmt.Errorf("operation failed: %w", err)
}
```

### Logging
```go
import "github.com/victoralfred/devsec/internal/logging"

log := logging.New()
log.Info("message", "key", "value")
```

### CLI Commands
```go
var exampleCmd = &cobra.Command{
    Use:   "example",
    Short: "Short description",
    RunE: func(cmd *cobra.Command, args []string) error {
        // Implementation
        return nil
    },
}
```

## Resources

- [README.md](README.md) - Project overview
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [examples/](examples/) - Example configurations
