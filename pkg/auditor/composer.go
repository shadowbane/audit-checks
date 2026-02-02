package auditor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
)

// ComposerAuditor implements the Auditor interface for Composer (PHP) projects
type ComposerAuditor struct{}

// NewComposerAuditor creates a new ComposerAuditor
func NewComposerAuditor() *ComposerAuditor {
	return &ComposerAuditor{}
}

// Name returns "composer"
func (a *ComposerAuditor) Name() string {
	return "composer"
}

// Detect checks for composer.json or composer.lock
func (a *ComposerAuditor) Detect(path string) bool {
	return FileExists(JoinPath(path, "composer.json")) || FileExists(JoinPath(path, "composer.lock"))
}

// Audit runs composer audit and parses the results
func (a *ComposerAuditor) Audit(ctx context.Context, app models.AppConfig) (*models.AuditResult, error) {
	zap.S().Infof("Running composer audit for app=%s path=%s", app.Name, app.Path)

	// Check if composer is available
	if _, err := exec.LookPath("composer"); err != nil {
		return nil, fmt.Errorf("composer not found in PATH: %w", err)
	}

	// Check if composer.json exists (lock file is optional for newer composer versions)
	if !FileExists(JoinPath(app.Path, "composer.json")) {
		return nil, fmt.Errorf("composer.json not found in %s", app.Path)
	}

	// Warn if lock file is missing
	if !FileExists(JoinPath(app.Path, "composer.lock")) {
		zap.S().Warnf("composer.lock not found in %s, auditing from composer.json only", app.Path)
	}

	// Run composer audit
	cmd := exec.CommandContext(ctx, "composer", "audit", "--format=json", "--no-interaction")
	cmd.Dir = app.Path

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// composer audit returns non-zero exit code when vulnerabilities are found
	// Exit codes:
	//   0 = No vulnerabilities found
	//   1 = Vulnerabilities found (security advisories)
	//   2 = Error running audit
	//   3 = Vulnerabilities found AND abandoned packages detected
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			// Exit codes 1 and 3 mean vulnerabilities/abandoned packages found, which is expected
			if exitCode != 1 && exitCode != 3 {
				// Build error message from available output
				errMsg := strings.TrimSpace(stderr.String())
				if errMsg == "" {
					errMsg = strings.TrimSpace(stdout.String())
				}
				if errMsg == "" {
					errMsg = fmt.Sprintf("exit code %d", exitCode)
				}
				return nil, fmt.Errorf("composer audit failed (exit %d): %s", exitCode, errMsg)
			}
		} else {
			return nil, fmt.Errorf("failed to run composer audit: %w", err)
		}
	}

	// Parse the output
	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		// No output likely means no vulnerabilities
		zap.S().Debugf("composer audit returned empty output for app=%s", app.Name)
		return &models.AuditResult{
			Vulnerabilities: []models.Vulnerability{},
			AuditorType:     a.Name(),
			AppName:         app.Name,
			AppPath:         app.Path,
		}, nil
	}

	result, err := a.parseOutput(output, app)
	if err != nil {
		zap.S().Debugf("composer audit raw output: %s", output)
		return nil, fmt.Errorf("failed to parse composer audit output: %w", err)
	}

	result.RawOutput = output
	result.AuditorType = a.Name()
	result.AppName = app.Name
	result.AppPath = app.Path

	zap.S().Infof("composer audit completed for app=%s total=%d critical=%d high=%d",
		app.Name,
		result.TotalVulnerabilities,
		result.CriticalCount,
		result.HighCount,
	)

	return result, nil
}

// composerAuditOutput represents the composer audit JSON output structure
type composerAuditOutput struct {
	Advisories json.RawMessage `json:"advisories,omitempty"` // Can be [] or {} depending on content
	Abandoned  json.RawMessage `json:"abandoned,omitempty"`  // Can be [] or {} depending on content
}

type composerAdvisory struct {
	AdvisoryID       string   `json:"advisoryId"`
	PackageName      string   `json:"packageName"`
	AffectedVersions string   `json:"affectedVersions"`
	Title            string   `json:"title"`
	CVE              string   `json:"cve"`
	Link             string   `json:"link"`
	ReportedAt       string   `json:"reportedAt"`
	Sources          []source `json:"sources"`
	Severity         string   `json:"severity,omitempty"`
}

type source struct {
	Name     string `json:"name"`
	RemoteID string `json:"remoteId"`
	Advisory string `json:"advisory,omitempty"`
}

// parseOutput parses composer audit JSON output
func (a *ComposerAuditor) parseOutput(output string, app models.AppConfig) (*models.AuditResult, error) {
	// Handle empty output (no vulnerabilities)
	if strings.TrimSpace(output) == "" || output == "{}" || output == "[]" {
		return &models.AuditResult{
			Vulnerabilities: []models.Vulnerability{},
		}, nil
	}

	var auditOutput composerAuditOutput
	if err := json.Unmarshal([]byte(output), &auditOutput); err != nil {
		// Try parsing as empty array
		var emptyArr []interface{}
		if json.Unmarshal([]byte(output), &emptyArr) == nil && len(emptyArr) == 0 {
			return &models.AuditResult{
				Vulnerabilities: []models.Vulnerability{},
			}, nil
		}
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	result := &models.AuditResult{
		Vulnerabilities: make([]models.Vulnerability, 0),
	}

	// Parse advisories - can be [] (empty array) or map[string][]advisory
	var advisoriesMap map[string][]composerAdvisory
	if len(auditOutput.Advisories) > 0 {
		// Try parsing as map first
		if err := json.Unmarshal(auditOutput.Advisories, &advisoriesMap); err != nil {
			// If it fails, it might be an empty array - that's ok
			var emptyArr []interface{}
			if json.Unmarshal(auditOutput.Advisories, &emptyArr) != nil {
				return nil, fmt.Errorf("failed to parse advisories: %w", err)
			}
			// Empty array means no advisories
			advisoriesMap = make(map[string][]composerAdvisory)
		}
	}

	// Process advisories
	for pkgName, advisories := range advisoriesMap {
		for _, advisory := range advisories {
			severity := determineSeverity(advisory)
			recommendation := buildComposerRecommendation(pkgName, advisory)

			vulnerability := models.Vulnerability{
				PackageName:        pkgName,
				Severity:           severity,
				CVEID:              advisory.CVE,
				Title:              advisory.Title,
				Description:        fmt.Sprintf("Advisory: %s", advisory.AdvisoryID),
				Recommendation:     recommendation,
				VulnerableVersions: advisory.AffectedVersions,
				PatchedVersions:    "", // Composer doesn't provide this directly
				URL:                advisory.Link,
			}

			result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
		}
	}

	// Filter ignored vulnerabilities
	result.Vulnerabilities = FilterIgnored(result.Vulnerabilities, app.IgnoreList)

	// Update counts
	result.UpdateCounts()

	return result, nil
}

// determineSeverity determines the severity level for a composer advisory
func determineSeverity(advisory composerAdvisory) string {
	// If severity is provided, use it
	if advisory.Severity != "" {
		return normalizeSeverity(advisory.Severity)
	}

	// Otherwise, try to determine from sources or default to moderate
	for _, src := range advisory.Sources {
		if strings.Contains(strings.ToLower(src.Name), "critical") {
			return models.SeverityCritical
		}
		if strings.Contains(strings.ToLower(src.Name), "high") {
			return models.SeverityHigh
		}
	}

	// Check title for severity hints
	titleLower := strings.ToLower(advisory.Title)
	if strings.Contains(titleLower, "remote code execution") ||
		strings.Contains(titleLower, "rce") ||
		strings.Contains(titleLower, "sql injection") {
		return models.SeverityCritical
	}
	if strings.Contains(titleLower, "xss") ||
		strings.Contains(titleLower, "cross-site") ||
		strings.Contains(titleLower, "authentication bypass") {
		return models.SeverityHigh
	}

	// Default to moderate
	return models.SeverityModerate
}

// buildComposerRecommendation creates a recommendation message for composer packages
func buildComposerRecommendation(pkgName string, advisory composerAdvisory) string {
	var rec strings.Builder

	rec.WriteString(fmt.Sprintf("Update %s to a patched version. ", pkgName))
	rec.WriteString(fmt.Sprintf("Affected versions: %s. ", advisory.AffectedVersions))
	rec.WriteString("Run 'composer update ")
	rec.WriteString(pkgName)
	rec.WriteString("' to update the package. ")

	if advisory.Link != "" {
		rec.WriteString(fmt.Sprintf("See %s for more details.", advisory.Link))
	}

	return rec.String()
}
