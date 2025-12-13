// Package main provides the entry point for the devsec CLI.
package main

import (
	"fmt"
	"os"

	"github.com/victoralfred/devsec/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
