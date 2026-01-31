package config

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/shadowbane/audit-checks/pkg/models"
	"github.com/shadowbane/go-logger"
	"github.com/spf13/viper"
)

// Config holds all application configuration (from environment variables only)
type Config struct {
	// Environment variables
	AppEnv           string
	LogLevel         string
	LogDirectory     string
	DBSQLitePath     string
	DBLogLevel       string
	ResendAPIKey     string
	ResendFromEmail  string
	TelegramBotToken string
	TelegramGroupID  int64
	TelegramEnabled  bool
	GeminiAPIKey     string
	GeminiEnabled    bool
	GeminiModel      string

	// Settings (from env vars with defaults)
	Settings Settings

	// CLI flags (set after loading)
	TargetApp  string
	DryRun     bool
	Verbose    bool
	ReportOnly bool
	JSONOutput bool

	// Apps loaded from database (populated by application)
	Apps []models.AppConfig
}

// Settings holds the settings (from env vars with defaults)
type Settings struct {
	SeverityThreshold string
	ReportFormats     []string
	ReportOutputDir   string
	MaxConcurrent     int
	RetryAttempts     int
}

// Get loads configuration from environment variables
func Get() *Config {

	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	if _, err := os.Stat(".env"); err == nil {
		viper.SetConfigFile(".env")
		_ = viper.ReadInConfig()
	}

	cfg := &Config{}

	// Load environment variables
	cfg.loadEnvVars()

	// Set defaults for log level and directory if not set
	if os.Getenv("LOG_LEVEL") == "" {
		_ = os.Setenv("LOG_LEVEL", cfg.getDefaultLogLevel())
	}
	if os.Getenv("LOG_DIRECTORY") == "" {
		_ = os.Setenv("LOG_DIRECTORY", "./storage/logs")
	}
	if os.Getenv("LOG_FILE_ENABLED") == "" {
		_ = os.Setenv("LOG_FILE_ENABLED", viper.GetString("LOG_FILE_ENABLED"))
	}
	if os.Getenv("LOG_MAX_SIZE") == "" {
		_ = os.Setenv("LOG_MAX_SIZE", viper.GetString("LOG_MAX_SIZE"))
	}
	if os.Getenv("LOG_MAX_BACKUPS") == "" {
		_ = os.Setenv("LOG_MAX_BACKUPS", viper.GetString("LOG_MAX_BACKUPS"))
	}
	if os.Getenv("LOG_MAX_AGE") == "" {
		_ = os.Setenv("LOG_MAX_AGE", viper.GetString("LOG_MAX_AGE"))
	}

	// Initialize logger
	logger.Init(logger.LoadEnvForLogger())

	// Set defaults for settings
	cfg.setDefaults()

	return cfg
}

// loadEnvVars loads configuration from environment variables via Viper
// Priority: OS env vars > .env file > defaults
func (c *Config) loadEnvVars() {
	// Set defaults
	viper.SetDefault("APP_ENV", "production")
	viper.SetDefault("LOG_LEVEL", "info")
	viper.SetDefault("LOG_DIRECTORY", "./storage/logs")
	viper.SetDefault("DB_SQLITE_PATH", "./storage/audit.db")
	viper.SetDefault("DB_LOG_LEVEL", "warn")
	viper.SetDefault("TELEGRAM_ENABLED", false)
	viper.SetDefault("TELEGRAM_GROUP_ID", 0)
	viper.SetDefault("GEMINI_ENABLED", false)
	viper.SetDefault("GEMINI_MODEL", "gemini-2.5-flash")
	viper.SetDefault("SEVERITY_THRESHOLD", models.SeverityModerate)
	viper.SetDefault("REPORT_OUTPUT_DIR", "./storage/reports")
	viper.SetDefault("MAX_CONCURRENT", 3)
	viper.SetDefault("RETRY_ATTEMPTS", 3)
	viper.SetDefault("REPORT_FORMATS", "json,markdown")

	// Load from Viper (OS env > .env > defaults)
	c.AppEnv = viper.GetString("APP_ENV")
	c.LogLevel = viper.GetString("LOG_LEVEL")
	c.LogDirectory = viper.GetString("LOG_DIRECTORY")
	c.DBSQLitePath = viper.GetString("DB_SQLITE_PATH")
	c.DBLogLevel = viper.GetString("DB_LOG_LEVEL")
	c.ResendAPIKey = viper.GetString("RESEND_API_KEY")
	c.ResendFromEmail = viper.GetString("RESEND_FROM_EMAIL")
	c.TelegramBotToken = viper.GetString("TELEGRAM_BOT_TOKEN")
	c.TelegramGroupID = viper.GetInt64("TELEGRAM_GROUP_ID")
	c.TelegramEnabled = viper.GetBool("TELEGRAM_ENABLED")
	c.GeminiAPIKey = viper.GetString("GEMINI_API_KEY")
	c.GeminiEnabled = viper.GetBool("GEMINI_ENABLED")
	c.GeminiModel = viper.GetString("GEMINI_MODEL")

	// Settings from Viper
	c.Settings.SeverityThreshold = viper.GetString("SEVERITY_THRESHOLD")
	c.Settings.ReportOutputDir = viper.GetString("REPORT_OUTPUT_DIR")
	c.Settings.MaxConcurrent = viper.GetInt("MAX_CONCURRENT")
	c.Settings.RetryAttempts = viper.GetInt("RETRY_ATTEMPTS")

	// Parse report formats
	formats := viper.GetString("REPORT_FORMATS")
	c.Settings.ReportFormats = strings.Split(formats, ",")
	for i, f := range c.Settings.ReportFormats {
		c.Settings.ReportFormats[i] = strings.TrimSpace(f)
	}
}

// setDefaults sets default values for settings
func (c *Config) setDefaults() {
	if c.Settings.SeverityThreshold == "" {
		c.Settings.SeverityThreshold = models.SeverityModerate
	}

	if len(c.Settings.ReportFormats) == 0 {
		c.Settings.ReportFormats = []string{"json", "markdown"}
	}

	if c.Settings.ReportOutputDir == "" {
		c.Settings.ReportOutputDir = "./storage/reports"
	}

	if c.Settings.MaxConcurrent <= 0 {
		c.Settings.MaxConcurrent = 3
	}

	if c.Settings.RetryAttempts <= 0 {
		c.Settings.RetryAttempts = 3
	}
}

// EnsureDirectories creates necessary directories
func (c *Config) EnsureDirectories() error {
	// Ensure report output directory exists
	if err := os.MkdirAll(c.Settings.ReportOutputDir, 0755); err != nil {
		return err
	}

	// Ensure log directory exists
	if err := os.MkdirAll(c.LogDirectory, 0755); err != nil {
		return err
	}

	// Ensure database directory exists
	dbDir := filepath.Dir(c.DBSQLitePath)
	if err := os.MkdirAll(dbDir, 0755); err != nil {
		return err
	}

	return nil
}

// SetApps sets the apps from database
func (c *Config) SetApps(apps []models.AppConfig) {
	c.Apps = apps
}

// GetEnabledApps returns only the enabled apps
func (c *Config) GetEnabledApps() []models.AppConfig {
	var enabled []models.AppConfig
	for _, app := range c.Apps {
		if app.Enabled {
			enabled = append(enabled, app)
		}
	}
	return enabled
}

// GetApp returns a specific app by name
func (c *Config) GetApp(name string) (*models.AppConfig, error) {
	for _, app := range c.Apps {
		if app.Name == name {
			return &app, nil
		}
	}
	return nil, nil
}

// ShouldNotify checks if a severity level should trigger notifications
func (c *Config) ShouldNotify(severity string) bool {
	return models.MeetsSeverityThreshold(severity, c.Settings.SeverityThreshold)
}

// IsGeminiEnabled returns true if Gemini is enabled and API key is set
func (c *Config) IsGeminiEnabled() bool {
	return c.GeminiEnabled && c.GeminiAPIKey != ""
}

// IsEmailEnabled returns true if email notifications are configured
func (c *Config) IsEmailEnabled() bool {
	return c.ResendAPIKey != "" && c.ResendFromEmail != ""
}

// IsTelegramEnabled returns true if Telegram notifications are configured
func (c *Config) IsTelegramEnabled() bool {
	return c.TelegramEnabled && c.TelegramBotToken != "" && c.TelegramGroupID != 0
}

// IsDevelopment returns true if running in development environment
func (c *Config) IsDevelopment() bool {
	return c.AppEnv == "development" || c.AppEnv == "dev" || c.AppEnv == "local"
}

// getDefaultLogLevel returns the default log level based on environment
func (c *Config) getDefaultLogLevel() string {
	switch c.AppEnv {
	case "local", "development", "dev", "debug", "testing":
		return "debug"
	default:
		return "info"
	}
}

// GetDBLogLevel returns the database log level
func (c *Config) GetDBLogLevel() string {
	return strings.ToUpper(c.DBLogLevel)
}
