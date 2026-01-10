# Contributing to DevSec

Thank you for your interest in contributing to DevSec! This document provides guidelines and information for contributors.

## Getting Started

### Prerequisites

- Go 1.23 or later
- Make
- Git

### Development Setup

```bash
# Clone the repository
git clone https://github.com/victoralfred/devsec.git
cd devsec

# Install development tools
make tools

# Build
make build

# Run tests
make test
```

## How to Contribute

### Reporting Bugs

1. Check existing [issues](https://github.com/victoralfred/devsec/issues) first
2. Create a new issue using the bug report template
3. Include:
   - DevSec version (`devsec version`)
   - Operating system and architecture
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Check existing [issues](https://github.com/victoralfred/devsec/issues) and [discussions](https://github.com/victoralfred/devsec/discussions)
2. Create a feature request issue or start a discussion
3. Describe the use case and proposed solution

### Submitting Changes

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run all checks: `make check`
5. Commit with clear messages
6. Push to your fork
7. Create a Pull Request

## Development Guidelines

### Code Style

- Follow Go idioms and [Effective Go](https://golang.org/doc/effective_go)
- Use `gofmt` for formatting (handled by `make lint`)
- Keep functions focused and small
- Write descriptive variable and function names

### File I/O

**Important**: Do not use direct `os` file operations. Use `github.com/victoralfred/gowritter` instead.

```go
// Wrong
os.ReadFile("path")

// Correct
import "github.com/victoralfred/gowritter/safepath"
sp, _ := safepath.New(dir)
data, _ := sp.ReadFile("path")
```

### Testing

- Write tests for all new functionality
- Use table-driven tests
- Aim for meaningful coverage (minimum 40%)
- Include both positive and negative test cases

```go
func TestExample(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "test", "expected", false},
        {"empty input", "", "", true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := Example(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
            }
            if got != tt.want {
                t.Errorf("got = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Commit Messages

- Use clear, descriptive messages
- Start with a verb (add, fix, update, remove)
- Reference issues when applicable

```
fix secret detection for base64-encoded values

- Handle multi-line base64 strings
- Add test cases for edge cases
- Fixes #123
```

### Pull Request Process

1. Update documentation if needed
2. Add tests for new functionality
3. Ensure all checks pass (`make check`)
4. Request review from maintainers
5. Address review feedback

## Quality Requirements

All contributions must pass:

- `make test` - Unit tests with race detection
- `make lint` - golangci-lint checks
- `make security` - gosec security scan
- No decrease in code coverage

## Project Structure

```
devsec/
├── cmd/devsec/       # CLI entry point
├── internal/         # Internal packages
│   ├── cli/          # Command implementations
│   ├── scanner/      # Security scanners
│   ├── policy/       # OPA policy engine
│   ├── compliance/   # Compliance mapping
│   └── ...
├── examples/         # Example configurations
└── docs/             # Documentation
```

## Getting Help

- [GitHub Discussions](https://github.com/victoralfred/devsec/discussions) - Questions and ideas
- [GitHub Issues](https://github.com/victoralfred/devsec/issues) - Bug reports and feature requests

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
