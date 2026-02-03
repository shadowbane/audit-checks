package main

import (
	"fmt"
	"os"

	"github.com/shadowbane/audit-checks/pkg/cli"
)

// Version information (can be set during build)
var (
	Version   = "dev"
	BuildTime = "unknown"
	BuildOS   = "unknown"
	BuildArch = "unknown"
)

func main() {
	// Set version information in CLI package
	cli.SetVersion(Version, BuildTime, BuildOS, BuildArch)

	// Create CLI with arguments (skip the program name)
	c := cli.New(os.Args[1:])

	// Run CLI
	if err := c.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
