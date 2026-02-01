package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/shadowbane/audit-checks/pkg/auditor"
	"github.com/shadowbane/audit-checks/pkg/config"
	"github.com/shadowbane/audit-checks/pkg/models"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

// LaravelApp represents a discovered Laravel application
type LaravelApp struct {
	Name    string // From APP_NAME or directory name
	Path    string // Absolute path
	HasEnv  bool   // Whether .env exists
	HasName bool   // Whether APP_NAME was found
}

// runAppScan runs the app scan subcommand
func runAppScan(args []string) error {
	fs := flag.NewFlagSet("app scan", flag.ExitOnError)

	scanPath := fs.String("path", "", "Directory to scan for Laravel apps (required)")
	appType := fs.String("type", "auto", "App type for added apps: auto, npm, composer")
	addAll := fs.Bool("all", false, "Add all found apps without prompting")

	_ = fs.Parse(args)

	// Validate required flags
	if *scanPath == "" {
		return fmt.Errorf("--path is required")
	}

	// Validate path exists
	absPath, err := filepath.Abs(*scanPath)
	if err != nil {
		return fmt.Errorf("invalid path: %w", err)
	}

	info, err := os.Stat(absPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("path does not exist: %s", absPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory: %s", absPath)
	}

	// Validate type
	if err := validateTypes(*appType); err != nil {
		return err
	}

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

	fmt.Println("\n=== Laravel App Scanner ===")
	fmt.Printf("\nScanning %s for Laravel applications...\n", absPath)

	// Scan for Laravel apps
	apps, err := scanForLaravelApps(absPath)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if len(apps) == 0 {
		fmt.Println("\nNo Laravel apps found.")
		return nil
	}

	// Filter out apps that already exist in database
	apps, skipped := filterExistingApps(db, apps)

	if len(apps) == 0 {
		fmt.Println("\nAll found apps already exist in database.")
		return nil
	}

	// Display found apps
	displayDiscoveredApps(apps, skipped)

	// Get selection
	var selectedIndices []int
	if *addAll {
		// Select all apps
		selectedIndices = make([]int, len(apps))
		for i := range apps {
			selectedIndices[i] = i
		}
	} else {
		selectedIndices, err = promptAppSelection(apps)
		if err != nil {
			return err
		}
		if selectedIndices == nil {
			fmt.Println("\nCancelled.")
			return nil
		}
	}

	if len(selectedIndices) == 0 {
		fmt.Println("\nNo apps selected.")
		return nil
	}

	// Add selected apps
	selectedApps := make([]LaravelApp, len(selectedIndices))
	for i, idx := range selectedIndices {
		selectedApps[i] = apps[idx]
	}

	added, err := addAppsToDatabase(db, selectedApps, *appType)
	if err != nil {
		return fmt.Errorf("failed to add apps: %w", err)
	}

	fmt.Printf("\nSuccessfully added %d apps.\n", added)

	return nil
}

// scanForLaravelApps scans immediate subdirectories for Laravel applications (one level deep)
func scanForLaravelApps(rootPath string) ([]LaravelApp, error) {
	var apps []LaravelApp

	// Read immediate subdirectories only
	entries, err := os.ReadDir(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		// Skip non-directories and hidden directories
		if !entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		subPath := filepath.Join(rootPath, entry.Name())

		// Check if this directory is a Laravel app
		if isLaravelApp(subPath) {
			name, hasEnv, hasName := readLaravelEnv(subPath)
			apps = append(apps, LaravelApp{
				Name:    name,
				Path:    subPath,
				HasEnv:  hasEnv,
				HasName: hasName,
			})
		}
	}

	return apps, nil
}

// isLaravelApp checks if a directory contains a Laravel application
func isLaravelApp(path string) bool {
	return auditor.FileExists(auditor.JoinPath(path, "artisan"))
}

// readLaravelEnv reads the APP_NAME from a Laravel app's .env file
func readLaravelEnv(appPath string) (name string, hasEnv bool, hasName bool) {
	envPath := filepath.Join(appPath, ".env")

	// Default to directory name
	name = filepath.Base(appPath)

	if !auditor.FileExists(envPath) {
		return name, false, false
	}

	// Use isolated Viper instance
	v := viper.New()
	v.SetConfigFile(envPath)
	v.SetConfigType("env")

	if err := v.ReadInConfig(); err != nil {
		return name, true, false
	}

	appName := v.GetString("APP_NAME")
	if appName == "" {
		return name, true, false
	}

	return appName, true, true
}

// displayDiscoveredApps shows a table of discovered apps
func displayDiscoveredApps(apps []LaravelApp, skipped int) {
	fmt.Printf("\nFound %d Laravel applications:\n\n", len(apps))

	// Calculate column widths
	maxNameLen := 20
	for _, app := range apps {
		if len(app.Name) > maxNameLen {
			maxNameLen = len(app.Name)
		}
	}
	if maxNameLen > 40 {
		maxNameLen = 40
	}

	// Header
	fmt.Printf("  %-4s %-*s %-50s %s\n", "#", maxNameLen, "NAME", "PATH", "STATUS")
	fmt.Println(strings.Repeat("-", 4+maxNameLen+50+15+6))

	// Rows
	for i, app := range apps {
		name := app.Name
		if len(name) > maxNameLen {
			name = name[:maxNameLen-3] + "..."
		}

		path := app.Path
		if len(path) > 50 {
			path = "..." + path[len(path)-47:]
		}

		status := "OK"
		if !app.HasEnv {
			status = "(no .env)"
		} else if !app.HasName {
			status = "(no APP_NAME)"
		}

		fmt.Printf("  %-4d %-*s %-50s %s\n", i+1, maxNameLen, name, path, status)
	}

	if skipped > 0 {
		fmt.Printf("\nNote: %d app(s) already exist in database (skipped)\n", skipped)
	}
}

// filterExistingApps removes apps that already exist in the database (by path)
func filterExistingApps(db *gorm.DB, apps []LaravelApp) ([]LaravelApp, int) {
	var filtered []LaravelApp
	var skipped int

	for _, app := range apps {
		var existing models.App
		if err := db.Where("path = ?", app.Path).First(&existing).Error; err != nil {
			// Not found, include it
			filtered = append(filtered, app)
		} else {
			skipped++
		}
	}

	return filtered, skipped
}

// promptAppSelection prompts user to select apps to add
// Returns selected indices, or nil if user cancelled
func promptAppSelection(apps []LaravelApp) ([]int, error) {
	maxRetries := 10
	retries := 0

	for {
		input := Prompt("\nEnter apps to add (comma-separated numbers, 'all', or 'q' to quit): ")
		input = strings.TrimSpace(strings.ToLower(input))

		// Handle empty input (EOF or error)
		if input == "" {
			retries++
			if retries >= maxRetries {
				return nil, fmt.Errorf("too many empty inputs, aborting")
			}
			continue
		}
		retries = 0 // Reset on valid input

		if input == "q" || input == "quit" {
			return nil, nil
		}

		if input == "all" {
			indices := make([]int, len(apps))
			for i := range apps {
				indices[i] = i
			}
			return indices, nil
		}

		// Parse comma-separated numbers
		parts := strings.Split(input, ",")
		var indices []int
		var invalid []string

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}

			num, err := strconv.Atoi(part)
			if err != nil || num < 1 || num > len(apps) {
				invalid = append(invalid, part)
				continue
			}
			indices = append(indices, num-1) // Convert to 0-indexed
		}

		if len(invalid) > 0 {
			fmt.Printf("Invalid selection: %s. Please enter numbers between 1 and %d.\n",
				strings.Join(invalid, ", "), len(apps))
			continue
		}

		if len(indices) == 0 {
			fmt.Println("No valid selection. Please try again.")
			continue
		}

		// Remove duplicates
		seen := make(map[int]bool)
		var unique []int
		for _, idx := range indices {
			if !seen[idx] {
				seen[idx] = true
				unique = append(unique, idx)
			}
		}

		return unique, nil
	}
}

// addAppsToDatabase adds selected apps to the database
func addAppsToDatabase(db *gorm.DB, apps []LaravelApp, appType string) (int, error) {
	fmt.Printf("\nAdding %d apps...\n", len(apps))

	var added int
	for _, app := range apps {
		// Check if name already exists, prompt for new name if needed
		finalName, err := resolveNameConflict(db, app.Name, app.Path)
		if err != nil {
			fmt.Printf("  ! Skipped: %s (%v)\n", app.Name, err)
			continue
		}
		if finalName == "" {
			fmt.Printf("  - Skipped: %s\n", app.Name)
			continue
		}

		newApp := &models.App{
			Name:    finalName,
			Path:    app.Path,
			Type:    appType,
			Enabled: true,
		}

		if err := db.Create(newApp).Error; err != nil {
			fmt.Printf("  ! Failed to add: %s (%v)\n", finalName, err)
			continue
		}

		zap.S().Infof("App created via scan: %s (ID: %s)", finalName, newApp.ID)
		fmt.Printf("  + Added: %s\n", finalName)
		added++
	}

	return added, nil
}

// resolveNameConflict checks if name exists and prompts user for a new name if needed
// Returns empty string if user chooses to skip, or the final name to use
func resolveNameConflict(db *gorm.DB, name string, path string) (string, error) {
	var existing models.App
	if err := db.Where("name = ?", name).First(&existing).Error; err != nil {
		// Name doesn't exist, use it
		return name, nil
	}

	// Name exists, prompt user
	fmt.Printf("\n  Name '%s' already exists in database.\n", name)
	fmt.Printf("  Path: %s\n", path)

	// Suggest a default based on directory name
	dirName := filepath.Base(path)
	suggested := dirName
	if dirName == name {
		suggested = fmt.Sprintf("%s-2", name)
	}

	for {
		input := PromptWithDefault("  Enter new name (or 's' to skip)", suggested)
		input = strings.TrimSpace(input)

		if input == "" {
			input = suggested
		}

		if strings.ToLower(input) == "s" || strings.ToLower(input) == "skip" {
			return "", nil
		}

		// Check if new name also exists
		if err := db.Where("name = ?", input).First(&existing).Error; err != nil {
			// Name is available
			return input, nil
		}

		fmt.Printf("  Name '%s' also exists. Please choose another.\n", input)
	}
}
