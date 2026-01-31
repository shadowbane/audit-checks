package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/shadowbane/audit-checks/pkg/config"
	"github.com/shadowbane/audit-checks/pkg/config/dblogger"
	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// RunSetup runs the setup command
func RunSetup(args []string) error {
	fmt.Println("=== Audit Checks Setup ===")
	fmt.Println()

	// Load config (initializes logger)
	cfg := config.Get()

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	fmt.Printf("Database path: %s\n", cfg.DBSQLitePath)
	fmt.Printf("Log directory: %s\n", cfg.LogDirectory)
	fmt.Printf("Report output: %s\n", cfg.Settings.ReportOutputDir)
	fmt.Println()

	// Check if database already exists
	dbExists := false
	if _, err := os.Stat(cfg.DBSQLitePath); err == nil {
		dbExists = true
		fmt.Println("Database already exists.")
		if !PromptYesNo("Do you want to continue with migration?", true) {
			fmt.Println("Setup cancelled.")
			return nil
		}
	}

	// Initialize database
	gormConfig := &gorm.Config{
		Logger: &dblogger.ZapLogger{
			Config: gormlogger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  dblogger.LogLevelToGormLevel(cfg.GetDBLogLevel()),
				IgnoreRecordNotFoundError: true,
				ParameterizedQueries:      true,
			},
		},
	}

	db, err := gorm.Open(sqlite.Open(cfg.DBSQLitePath), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	fmt.Println("Running database migrations...")
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	fmt.Println("Migrations completed successfully.")

	// Close database
	sqlDB, _ := db.DB()
	if sqlDB != nil {
		sqlDB.Close()
	}

	fmt.Println()

	// Offer to add an app if database is new
	if !dbExists {
		if PromptYesNo("Would you like to add an app to audit now?", true) {
			return addAppInteractive(cfg)
		}
	}

	fmt.Println()
	fmt.Println("Setup completed successfully!")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Add apps to audit: audit-checks app add")
	fmt.Println("  2. Configure environment variables in .env")
	fmt.Println("  3. Run audits: audit-checks run")
	fmt.Println()

	return nil
}

// addAppInteractive adds an app interactively during setup
func addAppInteractive(cfg *config.Config) error {
	fmt.Println()
	fmt.Println("=== Add New App ===")
	fmt.Println()

	// Get app details
	name := PromptWithDefault("App name", "")
	if name == "" {
		return fmt.Errorf("app name is required")
	}

	path := PromptWithDefault("App path", "")
	if path == "" {
		return fmt.Errorf("app path is required")
	}

	// Validate path exists
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", path)
	}

	// Select type
	typeOptions := []string{"auto (detect automatically)", "npm", "composer"}
	typeIndex := PromptSelect("Select app type", typeOptions, 0)
	appType := "auto"
	if typeIndex > 0 {
		appType = typeOptions[typeIndex]
	}

	// Email notifications
	var emailNotifications []string
	if PromptYesNo("Add email notifications?", false) {
		email := PromptWithDefault("Email address (comma-separated for multiple)", "")
		if email != "" {
			for _, e := range splitAndTrim(email) {
				emailNotifications = append(emailNotifications, e)
			}
		}
	}

	// Telegram notifications
	telegramEnabled := PromptYesNo("Enable Telegram notifications?", false)

	// Create app in database
	gormConfig := &gorm.Config{
		Logger: &dblogger.ZapLogger{
			Config: gormlogger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  dblogger.LogLevelToGormLevel(cfg.GetDBLogLevel()),
				IgnoreRecordNotFoundError: true,
				ParameterizedQueries:      true,
			},
		},
	}

	db, err := gorm.Open(sqlite.Open(cfg.DBSQLitePath), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	app := &models.App{
		Name:               name,
		Path:               path,
		Type:               appType,
		EmailNotifications: emailNotifications,
		TelegramEnabled:    telegramEnabled,
		Enabled:            true,
	}

	if err := db.Create(app).Error; err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}

	zap.S().Infof("App created: %s (ID: %s)", name, app.ID)
	fmt.Printf("\nApp '%s' added successfully!\n", name)

	// Ask if user wants to add another
	if PromptYesNo("Add another app?", false) {
		return addAppInteractive(cfg)
	}

	return nil
}

// splitAndTrim splits a string by comma and trims whitespace
func splitAndTrim(s string) []string {
	var result []string
	for _, part := range splitString(s, ",") {
		trimmed := trimString(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// splitString splits string by separator
func splitString(s, sep string) []string {
	if s == "" {
		return nil
	}
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
		}
	}
	result = append(result, s[start:])
	return result
}

// trimString trims whitespace from string
func trimString(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
