package models

import (
	"database/sql/driver"
	"encoding/json"
	"errors"
	"time"

	"github.com/shadowbane/audit-checks/pkg/helpers"
	"gorm.io/gorm"
)

// Severity levels for vulnerabilities
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityModerate = "moderate"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// SeverityOrder maps severity to numeric value for comparison
var SeverityOrder = map[string]int{
	SeverityCritical: 4,
	SeverityHigh:     3,
	SeverityModerate: 2,
	SeverityLow:      1,
	SeverityInfo:     0,
}

// MeetsSeverityThreshold checks if a severity meets the threshold
func MeetsSeverityThreshold(severity, threshold string) bool {
	return SeverityOrder[severity] >= SeverityOrder[threshold]
}

// StringArray is a custom type for storing string arrays as JSON in SQLite
type StringArray []string

// Scan implements the sql.Scanner interface
func (s *StringArray) Scan(value interface{}) error {
	if value == nil {
		*s = []string{}
		return nil
	}

	bytes, ok := value.([]byte)
	if !ok {
		str, ok := value.(string)
		if !ok {
			return errors.New("failed to unmarshal StringArray value")
		}
		bytes = []byte(str)
	}

	if len(bytes) == 0 {
		*s = []string{}
		return nil
	}

	return json.Unmarshal(bytes, s)
}

// Value implements the driver.Valuer interface
func (s StringArray) Value() (driver.Value, error) {
	if s == nil {
		return "[]", nil
	}
	return json.Marshal(s)
}

// App represents an application to audit (stored in database)
type App struct {
	ID                 string      `gorm:"primaryKey;size:26" json:"id"`
	Name               string      `gorm:"uniqueIndex;size:255;not null" json:"name"`
	Path               string      `gorm:"size:1024;not null" json:"path"`
	Type               string      `gorm:"size:50;default:auto" json:"type"` // npm, composer, auto
	EmailNotifications StringArray `gorm:"type:text" json:"email_notifications"`
	TelegramEnabled    bool        `gorm:"default:false" json:"telegram_enabled"`
	TelegramTopicID    int         `gorm:"default:0" json:"telegram_topic_id"`
	IgnoreList         StringArray `gorm:"type:text" json:"ignore_list"`
	Enabled            bool        `gorm:"default:true" json:"enabled"`
	CreatedAt          time.Time   `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt          time.Time   `gorm:"autoUpdateTime" json:"updated_at"`
}

// BeforeCreate hook to generate ULID
func (a *App) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = helpers.MustNewULID()
	}
	return nil
}

// ToAppConfig converts App to AppConfig for backward compatibility
func (a *App) ToAppConfig() AppConfig {
	return AppConfig{
		Name: a.Name,
		Path: a.Path,
		Type: a.Type,
		Notifications: NotificationConfig{
			Email:           a.EmailNotifications,
			TelegramEnabled: a.TelegramEnabled,
			TelegramTopicID: a.TelegramTopicID,
			AppName:         a.Name,
		},
		Enabled:    a.Enabled,
		IgnoreList: a.IgnoreList,
	}
}

// NotificationConfig holds notification settings for an app
type NotificationConfig struct {
	Email           []string `json:"email"`
	TelegramEnabled bool     `json:"telegram_enabled"`
	TelegramTopicID int      `json:"telegram_topic_id"`
	AppName         string   `json:"app_name"`
}

// AppConfig represents configuration for an app to audit (in-memory)
type AppConfig struct {
	Name          string             `json:"name"`
	Path          string             `json:"path"`
	Type          string             `json:"type"` // npm, composer, auto
	Notifications NotificationConfig `json:"notifications"`
	Enabled       bool               `json:"enabled"`
	IgnoreList    []string           `json:"ignore_list,omitempty"` // CVEs or package names to ignore
}

// Setting represents a configuration setting stored in database
type Setting struct {
	Key       string    `gorm:"primaryKey;size:255" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `gorm:"autoUpdateTime" json:"updated_at"`
}

// AuditResult represents a single audit run result (GORM model)
type AuditResult struct {
	ID                   string          `gorm:"primaryKey;size:26" json:"id"`
	AppName              string          `gorm:"index;size:255" json:"app_name"`
	AppPath              string          `gorm:"size:1024" json:"app_path"`
	AuditorType          string          `gorm:"size:50" json:"auditor_type"`
	TotalVulnerabilities int             `json:"total_vulnerabilities"`
	CriticalCount        int             `json:"critical_count"`
	HighCount            int             `json:"high_count"`
	ModerateCount        int             `json:"moderate_count"`
	LowCount             int             `json:"low_count"`
	RawOutput            string          `gorm:"type:text" json:"raw_output,omitempty"`
	AISummary            string          `gorm:"type:text" json:"ai_summary,omitempty"`
	CreatedAt            time.Time       `gorm:"autoCreateTime" json:"created_at"`
	Vulnerabilities      []Vulnerability `gorm:"foreignKey:AuditResultID" json:"vulnerabilities,omitempty"`
}

// BeforeCreate hook to generate ULID
func (a *AuditResult) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = helpers.MustNewULID()
	}
	return nil
}

// UpdateCounts updates the severity counts based on vulnerabilities
func (a *AuditResult) UpdateCounts() {
	a.CriticalCount = 0
	a.HighCount = 0
	a.ModerateCount = 0
	a.LowCount = 0
	a.TotalVulnerabilities = len(a.Vulnerabilities)

	for _, v := range a.Vulnerabilities {
		switch v.Severity {
		case SeverityCritical:
			a.CriticalCount++
		case SeverityHigh:
			a.HighCount++
		case SeverityModerate:
			a.ModerateCount++
		case SeverityLow:
			a.LowCount++
		}
	}
}

// HasVulnerabilities returns true if any vulnerabilities were found
func (a *AuditResult) HasVulnerabilities() bool {
	return a.TotalVulnerabilities > 0
}

// Vulnerability represents a single vulnerability (GORM model)
type Vulnerability struct {
	ID                 string    `gorm:"primaryKey;size:26" json:"id"`
	AuditResultID      string    `gorm:"index;size:26" json:"audit_result_id"`
	PackageName        string    `gorm:"size:255" json:"package_name"`
	Severity           string    `gorm:"index;size:20" json:"severity"`
	CVEID              string    `gorm:"column:cve_id;size:50" json:"cve_id,omitempty"`
	Title              string    `gorm:"size:512" json:"title"`
	Description        string    `gorm:"type:text" json:"description,omitempty"`
	Recommendation     string    `gorm:"type:text" json:"recommendation,omitempty"`
	VulnerableVersions string    `gorm:"column:vulnerable_versions;size:255" json:"vulnerable_versions,omitempty"`
	PatchedVersions    string    `gorm:"size:255" json:"patched_versions,omitempty"`
	URL                string    `gorm:"size:1024" json:"url,omitempty"`
	CreatedAt          time.Time `gorm:"autoCreateTime" json:"created_at"`
}

// BeforeCreate hook to generate ULID
func (v *Vulnerability) BeforeCreate(tx *gorm.DB) error {
	if v.ID == "" {
		v.ID = helpers.MustNewULID()
	}
	return nil
}

// AIAnalysis represents the Gemini analysis response
type AIAnalysis struct {
	Summary        string   `json:"summary"`
	Priority       []string `json:"priority"`
	Remediation    []string `json:"remediation"`
	RiskAssessment string   `json:"risk_assessment"`
}

// Report represents a complete audit report
type Report struct {
	AppName         string          `json:"app_name"`
	AppPath         string          `json:"app_path"`
	AuditorType     string          `json:"auditor_type"`
	AuditResult     *AuditResult    `json:"audit_result"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	AIAnalysis      *AIAnalysis     `json:"ai_analysis,omitempty"`
	GeneratedAt     time.Time       `json:"generated_at"`
}

// Summary represents a summary of counts
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
}

// NewReport creates a new Report from an AuditResult
func NewReport(result *AuditResult, analysis *AIAnalysis) *Report {
	return &Report{
		AppName:         result.AppName,
		AppPath:         result.AppPath,
		AuditorType:     result.AuditorType,
		AuditResult:     result,
		Vulnerabilities: result.Vulnerabilities,
		AIAnalysis:      analysis,
		GeneratedAt:     time.Now(),
	}
}

// GetSummary returns the summary counts from audit result
func (r *Report) GetSummary() Summary {
	return Summary{
		Total:    r.AuditResult.TotalVulnerabilities,
		Critical: r.AuditResult.CriticalCount,
		High:     r.AuditResult.HighCount,
		Moderate: r.AuditResult.ModerateCount,
		Low:      r.AuditResult.LowCount,
	}
}

// CombinedAppReport represents combined audit results from multiple auditors for a single app
type CombinedAppReport struct {
	AppName     string    `json:"app_name"`
	AppPath     string    `json:"app_path"`
	Reports     []*Report `json:"reports"`
	ReportFiles []string  `json:"report_files"`
	GeneratedAt time.Time `json:"generated_at"`
}

// NewCombinedAppReport creates a new CombinedAppReport
func NewCombinedAppReport(appName, appPath string) *CombinedAppReport {
	return &CombinedAppReport{
		AppName:     appName,
		AppPath:     appPath,
		Reports:     make([]*Report, 0),
		ReportFiles: make([]string, 0),
		GeneratedAt: time.Now(),
	}
}

// AddReport adds a report to the combined report
func (c *CombinedAppReport) AddReport(report *Report, filePaths []string) {
	c.Reports = append(c.Reports, report)
	c.ReportFiles = append(c.ReportFiles, filePaths...)
}

// GetCombinedSummary returns the combined summary counts from all reports
func (c *CombinedAppReport) GetCombinedSummary() Summary {
	summary := Summary{}
	for _, r := range c.Reports {
		s := r.GetSummary()
		summary.Total += s.Total
		summary.Critical += s.Critical
		summary.High += s.High
		summary.Moderate += s.Moderate
		summary.Low += s.Low
	}
	return summary
}

// HasVulnerabilities returns true if any report has vulnerabilities
func (c *CombinedAppReport) HasVulnerabilities() bool {
	for _, r := range c.Reports {
		if r.AuditResult.HasVulnerabilities() {
			return true
		}
	}
	return false
}

// AuditSummary represents a summary across all audited apps
type AuditSummary struct {
	TotalApps            int            `json:"total_apps"`
	AppsWithVulns        int            `json:"apps_with_vulnerabilities"`
	TotalVulnerabilities int            `json:"total_vulnerabilities"`
	CriticalCount        int            `json:"critical_count"`
	HighCount            int            `json:"high_count"`
	ModerateCount        int            `json:"moderate_count"`
	LowCount             int            `json:"low_count"`
	Results              []*AuditResult `json:"results"`
	GeneratedAt          time.Time      `json:"generated_at"`
}

// NewAuditSummary creates a summary from multiple audit results
func NewAuditSummary(results []*AuditResult) *AuditSummary {
	summary := &AuditSummary{
		TotalApps:   len(results),
		Results:     results,
		GeneratedAt: time.Now(),
	}

	for _, r := range results {
		if r.HasVulnerabilities() {
			summary.AppsWithVulns++
		}
		summary.TotalVulnerabilities += r.TotalVulnerabilities
		summary.CriticalCount += r.CriticalCount
		summary.HighCount += r.HighCount
		summary.ModerateCount += r.ModerateCount
		summary.LowCount += r.LowCount
	}

	return summary
}

// AllModels returns all models for auto-migration
func AllModels() []interface{} {
	return []interface{}{
		&App{},
		&Setting{},
		&AuditResult{},
		&Vulnerability{},
	}
}
