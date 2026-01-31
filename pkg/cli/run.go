package cli

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/shadowbane/audit-checks/pkg/application"
	"github.com/shadowbane/audit-checks/pkg/config"
	"go.uber.org/zap"
)

// RunAudit runs the audit command
func RunAudit(args []string) error {
	// Parse flags
	targetApp, dryRun, verbose, reportOnly, jsonOutput := ParseRunFlags(args)

	// Set verbose logging if requested
	if verbose {
		_ = os.Setenv("LOG_LEVEL", "debug")
	}

	// Load configuration
	cfg := config.Get()

	// Apply CLI flags to config
	cfg.TargetApp = targetApp
	cfg.DryRun = dryRun
	cfg.Verbose = verbose
	cfg.ReportOnly = reportOnly
	cfg.JSONOutput = jsonOutput

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		zap.S().Fatalf("Failed to create directories: %v", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		zap.S().Info("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Initialize application
	app, err := application.New(cfg)
	if err != nil {
		zap.S().Fatalf("Failed to initialize application: %v", err)
	}
	defer app.Close()

	// Run audit
	if err := app.Run(ctx); err != nil {
		zap.S().Errorf("Audit error: %v", err)
		os.Exit(2)
	}

	// Exit with appropriate code
	if app.HasVulnerabilities() {
		os.Exit(1) // Vulnerabilities found
	}

	return nil
}
