package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/yourusername/clawsanitizer/internal/output"
	"github.com/yourusername/clawsanitizer/internal/scanner"
)

var scanPath string
var scanJSON bool

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan an OpenClaw installation for security vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Path resolution precedence:
		// 1. Start with default
		resolvedPath := "~/.openclaw/"

		// 2. If positional arg given, use it
		if len(args) > 0 {
			resolvedPath = args[0]
		}

		// 3. If --path flag was explicitly set, override with flag value
		if scanPath != "" {
			resolvedPath = scanPath
		}

		// 4. Expand tilde
		if strings.HasPrefix(resolvedPath, "~/") {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
				os.Exit(2)
			}
			resolvedPath = filepath.Join(homeDir, resolvedPath[2:])
		} else if resolvedPath == "~" {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error: could not determine home directory: %v\n", err)
				os.Exit(2)
			}
			resolvedPath = homeDir
		}

		// 5. Check if resolved path exists
		_, err := os.Stat(resolvedPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "Error: path not found: %s\n", resolvedPath)
			} else {
				fmt.Fprintf(os.Stderr, "Error: cannot access path: %s\n", resolvedPath)
			}
			os.Exit(2)
		}

		result, err := scanner.Scan(resolvedPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: scan failed: %v\n", err)
			os.Exit(2)
		}

		if scanJSON {
			if err := output.PrintJSON(*result); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(2)
			}
			os.Exit(0)
		}

		output.PrintFindings(result.Findings)
		output.PrintSummary(*result)

		if len(result.Findings) > 0 {
			os.Exit(1)
		}
		os.Exit(0)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.Flags().StringVar(&scanPath, "path", "", "path to OpenClaw installation")
	scanCmd.Flags().BoolVar(&scanJSON, "json", false, "output results as JSON")
}
