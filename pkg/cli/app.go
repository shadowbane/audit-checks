package cli

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/shadowbane/audit-checks/pkg/config"
	"github.com/shadowbane/audit-checks/pkg/config/dblogger"
	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// RunApp runs the app management subcommands
func RunApp(args []string) error {
	if len(args) == 0 {
		printAppHelp()
		return nil
	}

	subcmd := args[0]
	subargs := args[1:]

	switch subcmd {
	case "add":
		return runAppAdd(subargs)
	case "edit", "update":
		return runAppEdit(subargs)
	case "list", "ls":
		return runAppList(subargs)
	case "remove", "rm":
		return runAppRemove(subargs)
	case "enable":
		return runAppEnable(subargs)
	case "disable":
		return runAppDisable(subargs)
	case "show":
		return runAppShow(subargs)
	case "help":
		printAppHelp()
		return nil
	default:
		fmt.Printf("Unknown app subcommand: %s\n\n", subcmd)
		printAppHelp()
		os.Exit(1)
		return nil
	}
}

func printAppHelp() {
	fmt.Println(`app - Manage apps to audit

Usage:
  audit-checks app [subcommand] [flags]

Subcommands:
  add          Add a new app to audit
  edit, update Edit an existing app
  list, ls     List all configured apps
  show         Show details of a specific app
  remove, rm   Remove an app
  enable       Enable an app
  disable      Disable an app

Add Flags:
  --name        App name (required)
  --path        App path (required)
  --type        App type: auto, npm, composer, or "npm,composer" for both (default: auto)
  --email       Email notifications (comma-separated)
  --telegram    Telegram chat IDs (comma-separated)
  --ignore      Ignore list (comma-separated CVEs or packages)

Edit Flags:
  --path        New app path
  --type        New app type: auto, npm, composer, or "npm,composer" for both
  --email       Email notifications (comma-separated, use "" to clear)
  --telegram    Telegram chat IDs (comma-separated, use "" to clear)
  --ignore      Ignore list (comma-separated, use "" to clear)

Examples:
  audit-checks app add                            # Interactive mode
  audit-checks app add --name myapp --path /path  # With flags
  audit-checks app edit myapp --type composer     # Change app type
  audit-checks app edit myapp --path /new/path    # Change app path
  audit-checks app list                           # List all apps
  audit-checks app show myapp                     # Show app details
  audit-checks app remove myapp                   # Remove an app
  audit-checks app enable myapp                   # Enable an app
  audit-checks app disable myapp                  # Disable an app
`)
}

// getDB returns a database connection
func getDB(cfg *config.Config) (*gorm.DB, error) {
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

	return gorm.Open(sqlite.Open(cfg.DBSQLitePath), gormConfig)
}

func runAppAdd(args []string) error {
	fs := flag.NewFlagSet("app add", flag.ExitOnError)

	name := fs.String("name", "", "App name")
	path := fs.String("path", "", "App path")
	appType := fs.String("type", "auto", "App type: auto, npm, composer")
	email := fs.String("email", "", "Email notifications (comma-separated)")
	telegram := fs.String("telegram", "", "Telegram chat IDs (comma-separated)")
	ignore := fs.String("ignore", "", "Ignore list (comma-separated)")

	_ = fs.Parse(args)

	// Load config (initializes logger)
	cfg := config.Get()

	// If no flags provided, run interactive mode
	if *name == "" && *path == "" {
		return addAppInteractive(cfg)
	}

	// Validate required fields
	if *name == "" {
		return fmt.Errorf("--name is required")
	}
	if *path == "" {
		return fmt.Errorf("--path is required")
	}

	// Validate path exists
	if _, err := os.Stat(*path); os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", *path)
	}

	// Validate type(s) - supports comma-separated like "npm,composer"
	if err := validateTypes(*appType); err != nil {
		return err
	}

	// Parse notifications
	var emailNotifications, telegramNotifications, ignoreList []string
	if *email != "" {
		emailNotifications = splitAndTrim(*email)
	}
	if *telegram != "" {
		telegramNotifications = splitAndTrim(*telegram)
	}
	if *ignore != "" {
		ignoreList = splitAndTrim(*ignore)
	}

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Check if app already exists
	var existing models.App
	if err := db.Where("name = ?", *name).First(&existing).Error; err == nil {
		return fmt.Errorf("app '%s' already exists", *name)
	}

	// Create app
	app := &models.App{
		Name:                  *name,
		Path:                  *path,
		Type:                  *appType,
		EmailNotifications:    emailNotifications,
		TelegramNotifications: telegramNotifications,
		IgnoreList:            ignoreList,
		Enabled:               true,
	}

	if err := db.Create(app).Error; err != nil {
		return fmt.Errorf("failed to create app: %w", err)
	}

	zap.S().Infof("App created: %s (ID: %s)", *name, app.ID)
	fmt.Printf("App '%s' added successfully!\n", *name)

	return nil
}

func runAppList(args []string) error {
	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Get all apps
	var apps []models.App
	if err := db.Order("name").Find(&apps).Error; err != nil {
		return fmt.Errorf("failed to list apps: %w", err)
	}

	if len(apps) == 0 {
		fmt.Println("No apps configured.")
		fmt.Println("Use 'audit-checks app add' to add an app.")
		return nil
	}

	fmt.Printf("\n%-20s %-10s %-10s %-40s\n", "NAME", "TYPE", "STATUS", "PATH")
	fmt.Println(strings.Repeat("-", 85))

	for _, app := range apps {
		status := "enabled"
		if !app.Enabled {
			status = "disabled"
		}
		// Truncate path if too long
		path := app.Path
		if len(path) > 40 {
			path = "..." + path[len(path)-37:]
		}
		fmt.Printf("%-20s %-10s %-10s %-40s\n", app.Name, app.Type, status, path)
	}

	fmt.Printf("\nTotal: %d apps\n", len(apps))

	return nil
}

func runAppShow(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("app name is required")
	}
	name := args[0]

	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Get app
	var app models.App
	if err := db.Where("name = ?", name).First(&app).Error; err != nil {
		return fmt.Errorf("app '%s' not found", name)
	}

	status := "enabled"
	if !app.Enabled {
		status = "disabled"
	}

	fmt.Println()
	fmt.Printf("Name:      %s\n", app.Name)
	fmt.Printf("ID:        %s\n", app.ID)
	fmt.Printf("Path:      %s\n", app.Path)
	fmt.Printf("Type:      %s\n", app.Type)
	fmt.Printf("Status:    %s\n", status)
	fmt.Printf("Created:   %s\n", app.CreatedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Updated:   %s\n", app.UpdatedAt.Format("2006-01-02 15:04:05"))

	if len(app.EmailNotifications) > 0 {
		fmt.Printf("Email:     %s\n", strings.Join(app.EmailNotifications, ", "))
	}
	if len(app.TelegramNotifications) > 0 {
		fmt.Printf("Telegram:  %s\n", strings.Join(app.TelegramNotifications, ", "))
	}
	if len(app.IgnoreList) > 0 {
		fmt.Printf("Ignore:    %s\n", strings.Join(app.IgnoreList, ", "))
	}

	fmt.Println()

	return nil
}

func runAppRemove(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("app name is required")
	}
	name := args[0]

	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Check if app exists
	var app models.App
	if err := db.Where("name = ?", name).First(&app).Error; err != nil {
		return fmt.Errorf("app '%s' not found", name)
	}

	// Confirm deletion
	if !PromptYesNo(fmt.Sprintf("Are you sure you want to remove app '%s'?", name), false) {
		fmt.Println("Cancelled.")
		return nil
	}

	// Delete app
	if err := db.Delete(&app).Error; err != nil {
		return fmt.Errorf("failed to remove app: %w", err)
	}

	zap.S().Infof("App removed: %s", name)
	fmt.Printf("App '%s' removed successfully.\n", name)

	return nil
}

func runAppEnable(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("app name is required")
	}
	name := args[0]

	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Update app
	result := db.Model(&models.App{}).Where("name = ?", name).Update("enabled", true)
	if result.Error != nil {
		return fmt.Errorf("failed to enable app: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("app '%s' not found", name)
	}

	zap.S().Infof("App enabled: %s", name)
	fmt.Printf("App '%s' enabled.\n", name)

	return nil
}

func runAppDisable(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("app name is required")
	}
	name := args[0]

	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Update app
	result := db.Model(&models.App{}).Where("name = ?", name).Update("enabled", false)
	if result.Error != nil {
		return fmt.Errorf("failed to disable app: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("app '%s' not found", name)
	}

	zap.S().Infof("App disabled: %s", name)
	fmt.Printf("App '%s' disabled.\n", name)

	return nil
}

func runAppEdit(args []string) error {
	// Extract app name first (first non-flag argument)
	name, flagArgs := extractAppName(args)
	if name == "" {
		return fmt.Errorf("app name is required: audit-checks app edit <name> [flags]")
	}

	fs := flag.NewFlagSet("app edit", flag.ExitOnError)

	path := fs.String("path", "", "New app path")
	appType := fs.String("type", "", "New app type: auto, npm, composer")
	email := fs.String("email", "", "Email notifications (comma-separated, use \"\" to clear)")
	telegram := fs.String("telegram", "", "Telegram chat IDs (comma-separated, use \"\" to clear)")
	ignore := fs.String("ignore", "", "Ignore list (comma-separated, use \"\" to clear)")

	_ = fs.Parse(flagArgs)

	// Load config (initializes logger)
	cfg := config.Get()

	// Connect to database
	db, err := getDB(cfg)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer func() {
		sqlDB, _ := db.DB()
		if sqlDB != nil {
			sqlDB.Close()
		}
	}()

	// Get existing app
	var app models.App
	if err := db.Where("name = ?", name).First(&app).Error; err != nil {
		return fmt.Errorf("app '%s' not found", name)
	}

	// Track if any changes made
	changes := make([]string, 0)

	// Update path if provided
	if *path != "" {
		if _, err := os.Stat(*path); os.IsNotExist(err) {
			return fmt.Errorf("path does not exist: %s", *path)
		}
		app.Path = *path
		changes = append(changes, "path")
	}

	// Update type if provided
	if *appType != "" {
		if err := validateTypes(*appType); err != nil {
			return err
		}
		app.Type = *appType
		changes = append(changes, "type")
	}

	// Update email notifications if flag was explicitly set
	if isFlagSet(fs, "email") {
		if *email == "" {
			app.EmailNotifications = []string{}
		} else {
			app.EmailNotifications = splitAndTrim(*email)
		}
		changes = append(changes, "email")
	}

	// Update telegram notifications if flag was explicitly set
	if isFlagSet(fs, "telegram") {
		if *telegram == "" {
			app.TelegramNotifications = []string{}
		} else {
			app.TelegramNotifications = splitAndTrim(*telegram)
		}
		changes = append(changes, "telegram")
	}

	// Update ignore list if flag was explicitly set
	if isFlagSet(fs, "ignore") {
		if *ignore == "" {
			app.IgnoreList = []string{}
		} else {
			app.IgnoreList = splitAndTrim(*ignore)
		}
		changes = append(changes, "ignore")
	}

	if len(changes) == 0 {
		fmt.Println("No changes specified. Use flags like --type, --path, --email, --telegram, --ignore")
		return nil
	}

	// Save changes
	if err := db.Save(&app).Error; err != nil {
		return fmt.Errorf("failed to update app: %w", err)
	}

	zap.S().Infof("App updated: %s (changed: %s)", name, strings.Join(changes, ", "))
	fmt.Printf("App '%s' updated successfully (changed: %s).\n", name, strings.Join(changes, ", "))

	return nil
}

// isFlagSet checks if a flag was explicitly set
func isFlagSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// extractAppName extracts the app name (first non-flag arg) from args
// Returns the name and remaining flag args
func extractAppName(args []string) (string, []string) {
	var name string
	var flagArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			// It's a flag
			flagArgs = append(flagArgs, arg)
			// Check if next arg is the flag's value (not another flag)
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") && !strings.Contains(arg, "=") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else if name == "" {
			// First non-flag argument is the app name
			name = arg
		}
		i++
	}

	return name, flagArgs
}

// validateTypes validates app type(s) - supports comma-separated like "npm,composer"
func validateTypes(typeStr string) error {
	validTypes := map[string]bool{"auto": true, "npm": true, "composer": true}

	types := splitAndTrim(typeStr)
	for _, t := range types {
		if !validTypes[t] {
			return fmt.Errorf("invalid type: %s (must be auto, npm, composer, or comma-separated combination)", t)
		}
	}

	// Can't combine "auto" with specific types
	if len(types) > 1 {
		for _, t := range types {
			if t == "auto" {
				return fmt.Errorf("cannot combine 'auto' with specific types")
			}
		}
	}

	return nil
}
