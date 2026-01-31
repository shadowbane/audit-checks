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

// NPMAuditor implements the Auditor interface for npm projects
type NPMAuditor struct{}

// NewNPMAuditor creates a new NPMAuditor
func NewNPMAuditor() *NPMAuditor {
	return &NPMAuditor{}
}

// Name returns "npm"
func (a *NPMAuditor) Name() string {
	return "npm"
}

// Detect checks for package.json or package-lock.json
func (a *NPMAuditor) Detect(path string) bool {
	return FileExists(JoinPath(path, "package.json")) || FileExists(JoinPath(path, "package-lock.json"))
}

// Audit runs npm audit and parses the results
func (a *NPMAuditor) Audit(ctx context.Context, app models.AppConfig) (*models.AuditResult, error) {
	zap.S().Infof("Running npm audit for app=%s path=%s", app.Name, app.Path)

	// Check if npm is available
	if _, err := exec.LookPath("npm"); err != nil {
		return nil, fmt.Errorf("npm not found in PATH: %w", err)
	}

	// Check if package.json exists
	if !FileExists(JoinPath(app.Path, "package.json")) {
		return nil, fmt.Errorf("package.json not found in %s", app.Path)
	}

	// Warn if lock file is missing (npm audit needs it, but will generate one)
	if !FileExists(JoinPath(app.Path, "package-lock.json")) {
		zap.S().Warnf("package-lock.json not found in %s, npm audit may fail or generate one", app.Path)
	}

	// Run npm audit
	cmd := exec.CommandContext(ctx, "npm", "audit", "--json")
	cmd.Dir = app.Path

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// npm audit returns non-zero exit code when vulnerabilities are found
	// This is expected behavior, so we don't treat it as an error
	err := cmd.Run()
	if err != nil {
		// Check if it's just because vulnerabilities were found (exit code 1)
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode := exitErr.ExitCode()
			// npm audit returns 1 when vulnerabilities found, which is fine
			if exitCode > 1 {
				// Build error message from available output
				errMsg := strings.TrimSpace(stderr.String())
				if errMsg == "" {
					errMsg = strings.TrimSpace(stdout.String())
				}
				if errMsg == "" {
					errMsg = fmt.Sprintf("exit code %d", exitCode)
				}
				return nil, fmt.Errorf("npm audit failed (exit %d): %s", exitCode, errMsg)
			}
		} else {
			return nil, fmt.Errorf("failed to run npm audit: %w", err)
		}
	}

	// Parse the output
	output := stdout.String()
	if strings.TrimSpace(output) == "" {
		// No output likely means no vulnerabilities
		zap.S().Debugf("npm audit returned empty output for app=%s", app.Name)
		return &models.AuditResult{
			Vulnerabilities: []models.Vulnerability{},
			AuditorType:     a.Name(),
			AppName:         app.Name,
			AppPath:         app.Path,
		}, nil
	}

	result, err := a.parseOutput(output, app)
	if err != nil {
		zap.S().Debugf("npm audit raw output: %s", output)
		return nil, fmt.Errorf("failed to parse npm audit output: %w", err)
	}

	result.RawOutput = output
	result.AuditorType = a.Name()
	result.AppName = app.Name
	result.AppPath = app.Path

	zap.S().Infof("npm audit completed for app=%s total=%d critical=%d high=%d",
		app.Name,
		result.TotalVulnerabilities,
		result.CriticalCount,
		result.HighCount,
	)

	return result, nil
}

// npmAuditOutput represents the npm audit JSON output structure
type npmAuditOutput struct {
	AuditReportVersion int                         `json:"auditReportVersion"`
	Vulnerabilities    map[string]npmVulnerability `json:"vulnerabilities"`
	Metadata           npmMetadata                 `json:"metadata"`
}

type npmVulnerability struct {
	Name         string      `json:"name"`
	Severity     string      `json:"severity"`
	IsDirect     bool        `json:"isDirect"`
	Via          []any       `json:"via"`
	Effects      []string    `json:"effects"`
	Range        string      `json:"range"`
	Nodes        []string    `json:"nodes"`
	FixAvailable interface{} `json:"fixAvailable"`
}

type npmVia struct {
	Source     int      `json:"source"`
	Name       string   `json:"name"`
	Dependency string   `json:"dependency"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Severity   string   `json:"severity"`
	CWE        []string `json:"cwe"`
	CVSS       struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vectorString"`
	} `json:"cvss"`
	Range string `json:"range"`
}

type npmMetadata struct {
	Vulnerabilities struct {
		Info     int `json:"info"`
		Low      int `json:"low"`
		Moderate int `json:"moderate"`
		High     int `json:"high"`
		Critical int `json:"critical"`
		Total    int `json:"total"`
	} `json:"vulnerabilities"`
	Dependencies struct {
		Prod     int `json:"prod"`
		Dev      int `json:"dev"`
		Optional int `json:"optional"`
		Peer     int `json:"peer"`
		Total    int `json:"total"`
	} `json:"dependencies"`
}

// parseOutput parses npm audit JSON output
func (a *NPMAuditor) parseOutput(output string, app models.AppConfig) (*models.AuditResult, error) {
	var auditOutput npmAuditOutput
	if err := json.Unmarshal([]byte(output), &auditOutput); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %w", err)
	}

	result := &models.AuditResult{
		Vulnerabilities: make([]models.Vulnerability, 0),
	}

	// Process vulnerabilities
	for pkgName, vuln := range auditOutput.Vulnerabilities {
		// Extract details from "via" field
		var title, description, url, cveID, patchedVersions string

		for _, v := range vuln.Via {
			// Via can be either a string (package name) or an object
			switch via := v.(type) {
			case map[string]interface{}:
				if t, ok := via["title"].(string); ok {
					title = t
				}
				if u, ok := via["url"].(string); ok {
					url = u
					// Extract CVE from URL if present
					if strings.Contains(url, "CVE-") {
						parts := strings.Split(url, "/")
						for _, p := range parts {
							if strings.HasPrefix(p, "CVE-") {
								cveID = p
								break
							}
						}
					}
				}
				if r, ok := via["range"].(string); ok && description == "" {
					description = fmt.Sprintf("Vulnerable versions: %s", r)
				}
			case string:
				// This is just a reference to another package
				if description == "" {
					description = fmt.Sprintf("Vulnerability via dependency: %s", via)
				}
			}
		}

		// Determine patched versions from fixAvailable
		if fix, ok := vuln.FixAvailable.(map[string]interface{}); ok {
			if version, ok := fix["version"].(string); ok {
				patchedVersions = version
			}
		} else if vuln.FixAvailable == true {
			patchedVersions = "Fix available (run npm audit fix)"
		}

		// Build recommendation
		recommendation := buildNpmRecommendation(pkgName, vuln, patchedVersions)

		vulnerability := models.Vulnerability{
			PackageName:        pkgName,
			Severity:           normalizeSeverity(vuln.Severity),
			CVEID:              cveID,
			Title:              title,
			Description:        description,
			Recommendation:     recommendation,
			VulnerableVersions: vuln.Range,
			PatchedVersions:    patchedVersions,
			URL:                url,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, vulnerability)
	}

	// Filter ignored vulnerabilities
	result.Vulnerabilities = FilterIgnored(result.Vulnerabilities, app.IgnoreList)

	// Update counts
	result.UpdateCounts()

	return result, nil
}

// buildNpmRecommendation creates a recommendation message
func buildNpmRecommendation(pkgName string, vuln npmVulnerability, patchedVersions string) string {
	var rec strings.Builder

	if patchedVersions != "" {
		rec.WriteString(fmt.Sprintf("Update %s to version %s. ", pkgName, patchedVersions))
	}

	if vuln.FixAvailable != nil && vuln.FixAvailable != false {
		rec.WriteString("Run 'npm audit fix' to automatically update. ")
	} else {
		rec.WriteString("No automatic fix available. Manual intervention required. ")
	}

	if vuln.IsDirect {
		rec.WriteString("This is a direct dependency.")
	} else {
		rec.WriteString("This is a transitive dependency.")
	}

	return rec.String()
}

// normalizeSeverity normalizes severity strings to standard values
func normalizeSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "moderate", "medium":
		return models.SeverityModerate
	case "low":
		return models.SeverityLow
	default:
		return models.SeverityInfo
	}
}
