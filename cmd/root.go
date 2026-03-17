package cmd

import (
	"os"

	"github.com/spf13/cobra"
	"github.com/tttturtle-russ/clawsan/internal/scanner"
)

// Version is injected at build time via ldflags: -X github.com/tttturtle-russ/clawsan/cmd.Version=v0.0.1
var Version = "0.0.1"

var rootCmd = &cobra.Command{
	Use:     "clawsan",
	Short:   "Scan your OpenClaw installation for security vulnerabilities",
	Version: Version,
}

func Execute() {
	scanner.Version = Version
	rootCmd.Version = Version
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
