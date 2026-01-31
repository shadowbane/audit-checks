package cli

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"go.uber.org/zap"
)

// CLI handles command-line interface
type CLI struct {
	args    []string
	verbose bool
}

// New creates a new CLI instance
func New(args []string) *CLI {
	return &CLI{args: args}
}

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Run         func(args []string) error
}

// ParseCommand parses the command from args
func (c *CLI) ParseCommand() (cmd string, args []string) {
	if len(c.args) == 0 {
		return "run", []string{}
	}

	// Check if first arg is a flag
	if strings.HasPrefix(c.args[0], "-") {
		return "run", c.args
	}

	return c.args[0], c.args[1:]
}

// Run executes the CLI
func (c *CLI) Run() error {
	cmd, args := c.ParseCommand()

	switch cmd {
	case "setup":
		return RunSetup(args)
	case "run":
		return RunAudit(args)
	case "app":
		return RunApp(args)
	case "help", "-h", "--help":
		c.PrintHelp()
		return nil
	case "version", "-v", "--version":
		c.PrintVersion()
		return nil
	default:
		fmt.Printf("Unknown command: %s\n\n", cmd)
		c.PrintHelp()
		os.Exit(1)
		return nil
	}
}

// PrintHelp prints the help message
func (c *CLI) PrintHelp() {
	fmt.Printf("audit-checks version %s (built %s)\n", Version, BuildTime)
	fmt.Println(`Security audit tool for npm and composer projects

Usage:
  audit-checks [command] [flags]

Commands:
  run           Run security audit on configured apps (default)
  setup         Initialize database and configuration
  app           Manage apps (add, list, remove, enable, disable)
  help          Show this help message
  version       Show version information

Run Flags:
  --app, -a         Run audit for specific app only
  --dry-run         Run without sending notifications
  --verbose, -v     Enable verbose logging
  --report-only     Generate reports without notifications
  --json-output     Output results as JSON to stdout

App Subcommands:
  app add           Add a new app to audit
  app list          List all configured apps
  app remove        Remove an app
  app enable        Enable an app
  app disable       Disable an app

Examples:
  audit-checks                          # Run audit for all enabled apps
  audit-checks run --app myapp          # Run audit for specific app
  audit-checks setup                    # Initialize database
  audit-checks app add                  # Add a new app interactively
  audit-checks app add --name myapp --path /path/to/app --type npm
  audit-checks app list                 # List all apps
  audit-checks app remove myapp         # Remove an app
  audit-checks app enable myapp         # Enable an app
  audit-checks app disable myapp        # Disable an app

Environment Variables:
  APP_ENV               Application environment (default: production)
  LOG_LEVEL             Log level: debug, info, warn, error (default: info)
  LOG_DIRECTORY         Log files directory (default: ./storage/logs)
  DB_SQLITE_PATH        SQLite database path (default: ./storage/audit.db)
  RESEND_API_KEY        Resend API key for email notifications
  RESEND_FROM_EMAIL     From email address for notifications
  TELEGRAM_BOT_TOKEN    Telegram bot token
  TELEGRAM_ENABLED      Enable Telegram notifications (default: false)
  GEMINI_API_KEY        Google Gemini API key
  GEMINI_ENABLED        Enable Gemini AI analysis (default: false)
  GEMINI_MODEL          Gemini model to use (default: gemini-2.5-flash)
  SEVERITY_THRESHOLD    Minimum severity to report: critical, high, moderate, low (default: moderate)
  REPORT_FORMATS        Comma-separated report formats: json, markdown (default: json,markdown)
  REPORT_OUTPUT_DIR     Report output directory (default: ./storage/reports)
  MAX_CONCURRENT        Maximum concurrent audits (default: 3)
  RETRY_ATTEMPTS        Number of retry attempts on failure (default: 3)
`)
}

// PrintVersion prints version information
func (c *CLI) PrintVersion() {
	fmt.Printf("audit-checks version %s (built %s)\n", Version, BuildTime)
}

// Version and build information (set by main.go)
var (
	Version   = "dev"
	BuildTime = "unknown"
)

// SetVersion sets the version information
func SetVersion(version, buildTime string) {
	Version = version
	BuildTime = buildTime
}

// Helper functions for interactive prompts

// Prompt asks for user input
func Prompt(message string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	input, err := reader.ReadString('\n')
	if err != nil {
		zap.S().Errorf("Failed to read input: %v", err)
		return ""
	}
	return strings.TrimSpace(input)
}

// PromptWithDefault asks for user input with a default value
func PromptWithDefault(message, defaultValue string) string {
	if defaultValue != "" {
		message = fmt.Sprintf("%s [%s]: ", message, defaultValue)
	} else {
		message = message + ": "
	}

	input := Prompt(message)
	if input == "" {
		return defaultValue
	}
	return input
}

// PromptYesNo asks for a yes/no confirmation
func PromptYesNo(message string, defaultYes bool) bool {
	suffix := " (y/N): "
	if defaultYes {
		suffix = " (Y/n): "
	}

	input := strings.ToLower(Prompt(message + suffix))

	if input == "" {
		return defaultYes
	}

	return input == "y" || input == "yes"
}

// PromptSelect asks user to select from options
func PromptSelect(message string, options []string, defaultIndex int) int {
	fmt.Println(message)
	for i, opt := range options {
		marker := "  "
		if i == defaultIndex {
			marker = "> "
		}
		fmt.Printf("%s%d. %s\n", marker, i+1, opt)
	}

	for {
		input := Prompt(fmt.Sprintf("Enter choice (1-%d) [%d]: ", len(options), defaultIndex+1))
		if input == "" {
			return defaultIndex
		}

		var choice int
		if _, err := fmt.Sscanf(input, "%d", &choice); err == nil {
			if choice >= 1 && choice <= len(options) {
				return choice - 1
			}
		}
		fmt.Println("Invalid choice, please try again.")
	}
}

// ParseRunFlags parses flags for the run command
func ParseRunFlags(args []string) (targetApp string, dryRun bool, verbose bool, reportOnly bool, jsonOutput bool) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)

	fs.StringVar(&targetApp, "app", "", "Run audit for specific app only")
	targetAppShort := fs.String("a", "", "Run audit for specific app only (shorthand)")
	fs.BoolVar(&dryRun, "dry-run", false, "Run without sending notifications")
	fs.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	verboseShort := fs.Bool("v", false, "Enable verbose logging (shorthand)")
	fs.BoolVar(&reportOnly, "report-only", false, "Generate reports without notifications")
	fs.BoolVar(&jsonOutput, "json-output", false, "Output results as JSON to stdout")

	_ = fs.Parse(args)

	// Handle shorthand flags
	if *targetAppShort != "" {
		targetApp = *targetAppShort
	}
	if *verboseShort {
		verbose = true
	}

	return
}
