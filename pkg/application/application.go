package application

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/shadowbane/audit-checks/pkg/analyzer"
	"github.com/shadowbane/audit-checks/pkg/auditor"
	"github.com/shadowbane/audit-checks/pkg/config"
	"github.com/shadowbane/audit-checks/pkg/config/dblogger"
	"github.com/shadowbane/audit-checks/pkg/exithandler"
	"github.com/shadowbane/audit-checks/pkg/models"
	"github.com/shadowbane/audit-checks/pkg/notifier"
	"github.com/shadowbane/audit-checks/pkg/reporter"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Application is the main application container
type Application struct {
	Config          *config.Config
	DB              *gorm.DB
	AuditorRegistry *auditor.Registry
	ReporterManager *reporter.Manager
	NotifierManager *notifier.Manager
	GeminiAnalyzer  *analyzer.GeminiAnalyzer
	ExitHandler     *exithandler.ExitHandler

	// State
	results            []*models.AuditResult
	hasVulnerabilities bool
	mu                 sync.Mutex
}

// New creates a new Application instance
func New(cfg *config.Config) (*Application, error) {
	app := &Application{
		Config:      cfg,
		ExitHandler: exithandler.New(),
		results:     make([]*models.AuditResult, 0),
	}

	// Initialize database
	if err := app.initDatabase(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Load apps from database
	if err := app.loadApps(); err != nil {
		return nil, fmt.Errorf("failed to load apps: %w", err)
	}

	// Initialize auditors
	app.initAuditors()

	// Initialize reporters
	app.initReporters()

	// Initialize notifiers
	if err := app.initNotifiers(); err != nil {
		return nil, fmt.Errorf("failed to initialize notifiers: %w", err)
	}

	// Initialize Gemini analyzer
	if err := app.initGemini(); err != nil {
		zap.S().Warnf("Failed to initialize Gemini analyzer: %v", err)
	}

	return app, nil
}

// initDatabase initializes the SQLite database
func (a *Application) initDatabase() error {
	gormConfig := &gorm.Config{
		Logger: &dblogger.ZapLogger{
			Config: gormlogger.Config{
				SlowThreshold:             time.Second,
				LogLevel:                  dblogger.LogLevelToGormLevel(a.Config.GetDBLogLevel()),
				IgnoreRecordNotFoundError: true,
				ParameterizedQueries:      true,
			},
		},
	}

	zap.S().Debugf("Connecting to SQLite database at %s", a.Config.DBSQLitePath)

	db, err := gorm.Open(sqlite.Open(a.Config.DBSQLitePath), gormConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	// Run migrations
	if err := db.AutoMigrate(models.AllModels()...); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	// SQLite works best with a single connection for write operations
	sqlDB, err := db.DB()
	if err == nil {
		sqlDB.SetMaxOpenConns(1)
	}

	a.DB = db
	zap.S().Infof("Database initialized at %s", a.Config.DBSQLitePath)

	return nil
}

// loadApps loads apps from the database into config
func (a *Application) loadApps() error {
	var apps []models.App
	if err := a.DB.Find(&apps).Error; err != nil {
		return fmt.Errorf("failed to query apps: %w", err)
	}

	// Convert to AppConfig
	var appConfigs []models.AppConfig
	for _, app := range apps {
		appConfigs = append(appConfigs, app.ToAppConfig())
	}

	// Set apps in config
	a.Config.SetApps(appConfigs)

	zap.S().Infof("Loaded %d apps from database", len(appConfigs))

	return nil
}

// initAuditors registers all auditors
func (a *Application) initAuditors() {
	a.AuditorRegistry = auditor.NewRegistry()
	a.AuditorRegistry.Register(auditor.NewNPMAuditor())
	a.AuditorRegistry.Register(auditor.NewComposerAuditor())

	zap.S().Debugf("Auditors registered: %v", a.AuditorRegistry.Names())
}

// initReporters registers all reporters
func (a *Application) initReporters() {
	a.ReporterManager = reporter.NewManager(a.Config.Settings.ReportOutputDir)
	a.ReporterManager.Register(reporter.NewJSONReporter())
	a.ReporterManager.Register(reporter.NewMarkdownReporter())

	zap.S().Debugf("Reporters registered: %v", a.ReporterManager.Formats())
}

// initNotifiers initializes notification services
func (a *Application) initNotifiers() error {
	a.NotifierManager = notifier.NewManager(a.Config.DryRun)

	// Email notifier
	emailNotifier := notifier.NewEmailNotifier(
		a.Config.ResendAPIKey,
		a.Config.ResendFromEmail,
	)
	a.NotifierManager.Register(emailNotifier)

	// Telegram notifier
	telegramNotifier, err := notifier.NewTelegramNotifier(
		a.Config.TelegramBotToken,
		a.Config.TelegramGroupID,
		a.Config.TelegramEnabled,
	)
	if err != nil {
		zap.S().Warnf("Failed to initialize Telegram notifier: %v", err)
	} else {
		a.NotifierManager.Register(telegramNotifier)
	}

	zap.S().Debugf("Notifiers registered: %v", a.NotifierManager.EnabledNotifiers())

	return nil
}

// initGemini initializes the Gemini analyzer
func (a *Application) initGemini() error {
	ctx := context.Background()
	zap.S().Debugf("Initializing Gemini analyzer")

	geminiAnalyzer, err := analyzer.NewGeminiAnalyzer(
		ctx,
		a.Config.GeminiAPIKey,
		a.Config.GeminiModel,
		a.Config.IsGeminiEnabled(),
	)
	if err != nil {
		return err
	}
	a.GeminiAnalyzer = geminiAnalyzer

	if geminiAnalyzer.Enabled() {
		zap.S().Info("Gemini analyzer enabled")
	}

	return nil
}

// Run executes the audit process
func (a *Application) Run(ctx context.Context) error {
	zap.S().Info("Starting security audit")

	// Get apps to audit
	apps := a.getAppsToAudit()
	if len(apps) == 0 {
		zap.S().Warn("No apps to audit. Use 'audit-checks app add' to add apps.")
		return nil
	}

	zap.S().Infof("Auditing %d apps", len(apps))

	// Audit apps concurrently
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, a.Config.Settings.MaxConcurrent)
	errChan := make(chan error, len(apps))

	for _, app := range apps {
		wg.Add(1)
		go func(appConfig models.AppConfig) {
			defer wg.Done()

			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			if err := a.auditApp(ctx, appConfig); err != nil {
				zap.S().Errorf("Failed to audit app=%s error=%v",
					appConfig.Name,
					err,
				)
				errChan <- fmt.Errorf("audit failed for %s: %w", appConfig.Name, err)
			}
		}(app)
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	// Generate summary report
	if len(a.results) > 0 {
		if err := a.generateSummary(); err != nil {
			zap.S().Errorf("Failed to generate summary: %v", err)
		}
	}

	// Output JSON if requested
	if a.Config.JSONOutput {
		a.outputJSON()
	}

	if len(errs) > 0 {
		return fmt.Errorf("audit completed with errors: %v", errs)
	}

	zap.S().Infof("Security audit completed apps=%d vulnerabilities_found=%t",
		len(a.results),
		a.hasVulnerabilities,
	)

	return nil
}

// getAppsToAudit returns the list of apps to audit
func (a *Application) getAppsToAudit() []models.AppConfig {
	if a.Config.TargetApp != "" {
		app, err := a.Config.GetApp(a.Config.TargetApp)
		if err != nil || app == nil {
			zap.S().Errorf("Target app not found: %s", a.Config.TargetApp)
			return nil
		}
		return []models.AppConfig{*app}
	}

	return a.Config.GetEnabledApps()
}

// auditApp audits a single application (may run multiple auditors)
func (a *Application) auditApp(ctx context.Context, appConfig models.AppConfig) error {
	zap.S().Infof("Auditing app=%s path=%s", appConfig.Name, appConfig.Path)

	// Get all applicable auditors
	auditors, err := a.AuditorRegistry.GetAuditorsForApp(appConfig)
	if err != nil {
		return fmt.Errorf("failed to get auditors: %w", err)
	}

	zap.S().Infof("Running %d auditor(s) for app=%s: %v", len(auditors), appConfig.Name, auditorNames(auditors))

	// Create combined report for this app
	combinedReport := models.NewCombinedAppReport(appConfig.Name, appConfig.Path)

	// Run each auditor and collect results
	var errs []error
	for _, aud := range auditors {
		report, filePaths, err := a.runSingleAudit(ctx, appConfig, aud)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", aud.Name(), err))
			continue
		}
		if report != nil {
			combinedReport.AddReport(report, filePaths)
		}
	}

	// Send ONE combined notification if vulnerabilities found and not report-only mode
	if combinedReport.HasVulnerabilities() && !a.Config.ReportOnly {
		notifyResult, err := a.NotifierManager.NotifyAllCombined(ctx, combinedReport, appConfig.Notifications)
		if err != nil {
			zap.S().Errorf("Failed to send notifications: %v", err)
		}

		// Save Telegram topic ID if it was created/updated
		if notifyResult != nil && notifyResult.TelegramTopicID > 0 {
			if notifyResult.TelegramTopicID != appConfig.Notifications.TelegramTopicID {
				if err := a.DB.Model(&models.App{}).Where("name = ?", appConfig.Name).
					Update("telegram_topic_id", notifyResult.TelegramTopicID).Error; err != nil {
					zap.S().Errorf("Failed to save Telegram topic ID: %v", err)
				} else {
					zap.S().Debugf("Saved Telegram topic ID=%d for app=%s", notifyResult.TelegramTopicID, appConfig.Name)
				}
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("audit errors: %v", errs)
	}

	return nil
}

// auditorNames returns the names of auditors
func auditorNames(auditors []auditor.Auditor) []string {
	names := make([]string, len(auditors))
	for i, a := range auditors {
		names[i] = a.Name()
	}
	return names
}

// runSingleAudit runs a single auditor for an app.
// Returns the report and generated file paths (does NOT send notifications).
func (a *Application) runSingleAudit(ctx context.Context, appConfig models.AppConfig, aud auditor.Auditor) (*models.Report, []string, error) {
	// Run audit with retry
	var result *models.AuditResult
	var err error
	for attempt := 1; attempt <= a.Config.Settings.RetryAttempts; attempt++ {
		result, err = aud.Audit(ctx, appConfig)
		if err == nil {
			break
		}

		zap.S().Warnf("Audit attempt failed app=%s auditor=%s attempt=%d error=%v",
			appConfig.Name,
			aud.Name(),
			attempt,
			err,
		)

		if attempt < a.Config.Settings.RetryAttempts {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}

	if err != nil {
		return nil, nil, fmt.Errorf("all audit attempts failed: %w", err)
	}

	// Filter by severity threshold
	result.Vulnerabilities = auditor.FilterVulnerabilities(
		result.Vulnerabilities,
		a.Config.Settings.SeverityThreshold,
	)
	result.UpdateCounts()

	// Run Gemini analysis if enabled and vulnerabilities found
	var aiAnalysis *models.AIAnalysis
	if a.GeminiAnalyzer != nil && a.GeminiAnalyzer.Enabled() && result.HasVulnerabilities() {
		analysis, err := a.GeminiAnalyzer.Analyze(ctx, result)
		if err != nil {
			zap.S().Warnf("Gemini analysis failed: %v", err)
		} else {
			aiAnalysis = analysis
			if analysis != nil {
				result.AISummary = analysis.Summary
			}
		}
	}

	// Store in database
	if err := a.DB.Create(result).Error; err != nil {
		zap.S().Errorf("Failed to store audit result: %v", err)
	}

	// Create report
	report := models.NewReport(result, aiAnalysis)

	// Generate report files
	filePaths, err := a.ReporterManager.GenerateFormats(report, a.Config.Settings.ReportFormats)
	if err != nil {
		zap.S().Errorf("Failed to generate reports: %v", err)
	}

	// Update state
	a.mu.Lock()
	a.results = append(a.results, result)
	if result.HasVulnerabilities() {
		a.hasVulnerabilities = true
	}
	a.mu.Unlock()

	return report, filePaths, nil
}

// generateSummary creates a summary report across all apps
func (a *Application) generateSummary() error {
	summary := models.NewAuditSummary(a.results)

	return a.ReporterManager.GenerateSummaryReport(summary, a.Config.Settings.ReportFormats)
}

// outputJSON outputs results as JSON to stdout
func (a *Application) outputJSON() {
	summary := models.NewAuditSummary(a.results)
	jsonData, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		zap.S().Errorf("Failed to marshal JSON output: %v", err)
		return
	}
	fmt.Println(string(jsonData))
}

// HasVulnerabilities returns true if any vulnerabilities were found
func (a *Application) HasVulnerabilities() bool {
	return a.hasVulnerabilities
}

// Close cleans up resources
func (a *Application) Close() error {
	if a.GeminiAnalyzer != nil {
		if err := a.GeminiAnalyzer.Close(); err != nil {
			zap.S().Warnf("Failed to close Gemini analyzer: %v", err)
		}
	}

	if a.DB != nil {
		sqlDB, err := a.DB.DB()
		if err == nil {
			sqlDB.Close()
		}
	}

	return nil
}
