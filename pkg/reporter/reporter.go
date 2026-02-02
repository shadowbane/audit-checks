package reporter

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
)

// Reporter defines the interface for report generators
type Reporter interface {
	// Format returns the report format name (e.g., "json", "markdown")
	Format() string

	// Extension returns the file extension (e.g., ".json", ".md")
	Extension() string

	// Generate creates the report content
	Generate(report *models.Report) ([]byte, error)
}

// Manager manages report generation and output
type Manager struct {
	reporters map[string]Reporter
	outputDir string
	mu        sync.RWMutex
}

// NewManager creates a new report manager
func NewManager(outputDir string) *Manager {
	return &Manager{
		reporters: make(map[string]Reporter),
		outputDir: outputDir,
	}
}

// Register adds a reporter to the manager
func (m *Manager) Register(r Reporter) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reporters[r.Format()] = r
}

// Get returns a reporter by format name
func (m *Manager) Get(format string) (Reporter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.reporters[format]
	return r, ok
}

// Formats returns all available report formats
func (m *Manager) Formats() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	formats := make([]string, 0, len(m.reporters))
	for format := range m.reporters {
		formats = append(formats, format)
	}
	return formats
}

// GenerateAll generates reports in all registered formats.
// Returns a slice of generated file paths.
func (m *Manager) GenerateAll(report *models.Report) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filePaths []string

	for format, reporter := range m.reporters {
		filePath, err := m.generateAndSave(report, reporter)
		if err != nil {
			zap.S().Errorf("Failed to generate report format=%s app=%s error=%v",
				format,
				report.AppName,
				err,
			)
			return filePaths, err
		}
		filePaths = append(filePaths, filePath)
	}

	return filePaths, nil
}

// GenerateFormats generates reports only for specified formats.
// Returns a slice of generated file paths.
func (m *Manager) GenerateFormats(report *models.Report, formats []string) ([]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var filePaths []string

	for _, format := range formats {
		reporter, ok := m.reporters[format]
		if !ok {
			zap.S().Warnf("Unknown report format: %s", format)
			continue
		}

		filePath, err := m.generateAndSave(report, reporter)
		if err != nil {
			zap.S().Errorf("Failed to generate report format=%s app=%s error=%v",
				format,
				report.AppName,
				err,
			)
			return filePaths, err
		}
		filePaths = append(filePaths, filePath)
	}

	return filePaths, nil
}

// generateAndSave generates a report and saves it to disk.
// Returns the generated file path.
func (m *Manager) generateAndSave(report *models.Report, reporter Reporter) (string, error) {
	content, err := reporter.Generate(report)
	if err != nil {
		return "", fmt.Errorf("failed to generate %s report: %w", reporter.Format(), err)
	}

	filename := m.buildFilename(report.AppName, report.AuditorType, reporter.Extension())
	filePath := filepath.Join(m.outputDir, filename)

	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return "", fmt.Errorf("failed to write report file: %w", err)
	}

	zap.S().Infof("Report generated format=%s app=%s auditor=%s file=%s",
		reporter.Format(),
		report.AppName,
		report.AuditorType,
		filePath,
	)

	return filePath, nil
}

// buildFilename creates a filename for the report
// Format: {appName}-{auditorType}-{timestamp}{extension}
func (m *Manager) buildFilename(appName, auditorType, extension string) string {
	timestamp := time.Now().UTC().Format("2006-01-02-150405")
	if auditorType != "" {
		return fmt.Sprintf("%s-%s-%s%s", appName, auditorType, timestamp, extension)
	}
	return fmt.Sprintf("%s-%s%s", appName, timestamp, extension)
}

// GenerateSummaryReport generates a summary report across all apps
func (m *Manager) GenerateSummaryReport(summary *models.AuditSummary, formats []string) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, format := range formats {
		reporter, ok := m.reporters[format]
		if !ok {
			continue
		}

		// Check if reporter supports summary reports
		if summaryReporter, ok := reporter.(SummaryReporter); ok {
			content, err := summaryReporter.GenerateSummary(summary)
			if err != nil {
				zap.S().Errorf("Failed to generate summary report format=%s error=%v",
					format,
					err,
				)
				continue
			}

			filename := m.buildFilename("summary", "", reporter.Extension())
			filePath := filepath.Join(m.outputDir, filename)

			if err := os.WriteFile(filePath, content, 0644); err != nil {
				zap.S().Errorf("Failed to write summary report format=%s error=%v",
					format,
					err,
				)
				continue
			}

			zap.S().Infof("Summary report generated format=%s file=%s",
				format,
				filePath,
			)
		}
	}

	return nil
}

// SummaryReporter is an optional interface for reporters that support summary reports
type SummaryReporter interface {
	GenerateSummary(summary *models.AuditSummary) ([]byte, error)
}
