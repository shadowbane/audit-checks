package reporter

import (
	"encoding/json"

	"github.com/shadowbane/audit-checks/pkg/models"
)

// JSONReporter generates JSON reports
type JSONReporter struct{}

// NewJSONReporter creates a new JSONReporter
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

// Format returns "json"
func (r *JSONReporter) Format() string {
	return "json"
}

// Extension returns ".json"
func (r *JSONReporter) Extension() string {
	return ".json"
}

// jsonReport is the structure for JSON output
type jsonReport struct {
	AppName         string             `json:"app_name"`
	AppPath         string             `json:"app_path"`
	AuditorType     string             `json:"auditor_type"`
	GeneratedAt     string             `json:"generated_at"`
	Summary         jsonSummary        `json:"summary"`
	Vulnerabilities []jsonVuln         `json:"vulnerabilities"`
	AIAnalysis      *models.AIAnalysis `json:"ai_analysis,omitempty"`
}

type jsonSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Moderate int `json:"moderate"`
	Low      int `json:"low"`
}

type jsonVuln struct {
	PackageName        string `json:"package_name"`
	Severity           string `json:"severity"`
	CVEID              string `json:"cve_id,omitempty"`
	Title              string `json:"title"`
	Description        string `json:"description,omitempty"`
	Recommendation     string `json:"recommendation,omitempty"`
	VulnerableVersions string `json:"vulnerable_versions,omitempty"`
	PatchedVersions    string `json:"patched_versions,omitempty"`
	URL                string `json:"url,omitempty"`
}

// Generate creates a JSON report
func (r *JSONReporter) Generate(report *models.Report) ([]byte, error) {
	output := jsonReport{
		AppName:     report.AppName,
		AppPath:     report.AppPath,
		AuditorType: report.AuditorType,
		GeneratedAt: report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
		Summary: jsonSummary{
			Total:    report.AuditResult.TotalVulnerabilities,
			Critical: report.AuditResult.CriticalCount,
			High:     report.AuditResult.HighCount,
			Moderate: report.AuditResult.ModerateCount,
			Low:      report.AuditResult.LowCount,
		},
		Vulnerabilities: make([]jsonVuln, 0, len(report.Vulnerabilities)),
		AIAnalysis:      report.AIAnalysis,
	}

	for _, v := range report.Vulnerabilities {
		output.Vulnerabilities = append(output.Vulnerabilities, jsonVuln{
			PackageName:        v.PackageName,
			Severity:           v.Severity,
			CVEID:              v.CVEID,
			Title:              v.Title,
			Description:        v.Description,
			Recommendation:     v.Recommendation,
			VulnerableVersions: v.VulnerableVersions,
			PatchedVersions:    v.PatchedVersions,
			URL:                v.URL,
		})
	}

	return json.MarshalIndent(output, "", "  ")
}

// jsonSummaryReport is the structure for summary JSON output
type jsonSummaryReport struct {
	GeneratedAt          string           `json:"generated_at"`
	TotalApps            int              `json:"total_apps"`
	AppsWithVulns        int              `json:"apps_with_vulnerabilities"`
	TotalVulnerabilities int              `json:"total_vulnerabilities"`
	Summary              jsonSummary      `json:"summary"`
	Apps                 []jsonAppSummary `json:"apps"`
}

type jsonAppSummary struct {
	AppName     string      `json:"app_name"`
	AuditorType string      `json:"auditor_type"`
	Summary     jsonSummary `json:"summary"`
}

// GenerateSummary creates a summary JSON report
func (r *JSONReporter) GenerateSummary(summary *models.AuditSummary) ([]byte, error) {
	output := jsonSummaryReport{
		GeneratedAt:          summary.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
		TotalApps:            summary.TotalApps,
		AppsWithVulns:        summary.AppsWithVulns,
		TotalVulnerabilities: summary.TotalVulnerabilities,
		Summary: jsonSummary{
			Total:    summary.TotalVulnerabilities,
			Critical: summary.CriticalCount,
			High:     summary.HighCount,
			Moderate: summary.ModerateCount,
			Low:      summary.LowCount,
		},
		Apps: make([]jsonAppSummary, 0, len(summary.Results)),
	}

	for _, result := range summary.Results {
		output.Apps = append(output.Apps, jsonAppSummary{
			AppName:     result.AppName,
			AuditorType: result.AuditorType,
			Summary: jsonSummary{
				Total:    result.TotalVulnerabilities,
				Critical: result.CriticalCount,
				High:     result.HighCount,
				Moderate: result.ModerateCount,
				Low:      result.LowCount,
			},
		})
	}

	return json.MarshalIndent(output, "", "  ")
}
