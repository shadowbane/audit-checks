package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/shadowbane/audit-checks/pkg/models"
)

const (
	resendAPIURL = "https://api.resend.com/emails"
)

// EmailNotifier sends notifications via email using Resend API
type EmailNotifier struct {
	apiKey    string
	fromEmail string
	enabled   bool
	client    *http.Client
}

// NewEmailNotifier creates a new EmailNotifier
func NewEmailNotifier(apiKey, fromEmail string) *EmailNotifier {
	enabled := apiKey != "" && fromEmail != ""

	return &EmailNotifier{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		enabled:   enabled,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns "email"
func (n *EmailNotifier) Name() string {
	return "email"
}

// Enabled returns true if the notifier is configured
func (n *EmailNotifier) Enabled() bool {
	return n.enabled
}

// Send sends an email notification
func (n *EmailNotifier) Send(ctx context.Context, report *models.Report, recipients []string) error {
	if !n.enabled {
		return fmt.Errorf("email notifier is not enabled")
	}

	if len(recipients) == 0 {
		return nil
	}

	subject := n.buildSubject(report)
	htmlBody, err := n.buildHTMLBody(report)
	if err != nil {
		return fmt.Errorf("failed to build email body: %w", err)
	}

	payload := resendPayload{
		From:    n.fromEmail,
		To:      recipients,
		Subject: subject,
		HTML:    htmlBody,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", resendAPIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+n.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp resendErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err == nil {
			return fmt.Errorf("resend API error: %s", errResp.Message)
		}
		return fmt.Errorf("resend API error: status %d", resp.StatusCode)
	}

	return nil
}

// resendPayload is the request payload for Resend API
type resendPayload struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// resendErrorResponse is the error response from Resend API
type resendErrorResponse struct {
	StatusCode int    `json:"statusCode"`
	Message    string `json:"message"`
	Name       string `json:"name"`
}

// buildSubject creates the email subject
func (n *EmailNotifier) buildSubject(report *models.Report) string {
	total := report.AuditResult.TotalVulnerabilities
	critical := report.AuditResult.CriticalCount
	high := report.AuditResult.HighCount

	var severity string
	if critical > 0 {
		severity = "CRITICAL"
	} else if high > 0 {
		severity = "HIGH"
	} else {
		severity = "MODERATE"
	}

	return fmt.Sprintf("[%s] Security Alert: %s - %d vulnerabilities found",
		severity, report.AppName, total)
}

// emailTemplate is the HTML template for email body
var emailTemplate = template.Must(template.New("email").Funcs(template.FuncMap{
	"upper": strings.ToUpper,
	"severityColor": func(s string) string {
		switch s {
		case "critical":
			return "#dc3545"
		case "high":
			return "#fd7e14"
		case "moderate":
			return "#ffc107"
		case "low":
			return "#28a745"
		default:
			return "#6c757d"
		}
	},
}).Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .header h1 { margin: 0 0 10px 0; color: #212529; }
        .summary { display: flex; gap: 10px; flex-wrap: wrap; margin: 20px 0; }
        .severity-badge { padding: 8px 16px; border-radius: 4px; color: white; font-weight: bold; }
        .critical { background: #dc3545; }
        .high { background: #fd7e14; }
        .moderate { background: #ffc107; color: #212529; }
        .low { background: #28a745; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }
        th { background: #f8f9fa; }
        .vuln-item { margin: 15px 0; padding: 15px; border: 1px solid #dee2e6; border-radius: 8px; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .vuln-title { font-weight: bold; font-size: 16px; }
        .ai-section { background: #e7f3ff; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .footer { text-align: center; color: #6c757d; font-size: 12px; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Audit Alert</h1>
            <p><strong>App:</strong> {{.AppName}}</p>
            <p><strong>Auditor:</strong> {{.AuditorType}}</p>
            <p><strong>Date:</strong> {{.GeneratedAt}}</p>
        </div>

        <h2>Summary</h2>
        <div class="summary">
            {{if gt .Summary.Critical 0}}<span class="severity-badge critical">{{.Summary.Critical}} Critical</span>{{end}}
            {{if gt .Summary.High 0}}<span class="severity-badge high">{{.Summary.High}} High</span>{{end}}
            {{if gt .Summary.Moderate 0}}<span class="severity-badge moderate">{{.Summary.Moderate}} Moderate</span>{{end}}
            {{if gt .Summary.Low 0}}<span class="severity-badge low">{{.Summary.Low}} Low</span>{{end}}
        </div>
        <p><strong>Total:</strong> {{.Summary.Total}} vulnerabilities</p>

        {{if .AIAnalysis}}
        <div class="ai-section">
            <h3>AI Analysis</h3>
            <p>{{.AIAnalysis.Summary}}</p>
            {{if .AIAnalysis.Priority}}
            <p><strong>Priority Fix Order:</strong></p>
            <ol>
            {{range .AIAnalysis.Priority}}
                <li>{{.}}</li>
            {{end}}
            </ol>
            {{end}}
        </div>
        {{end}}

        <h2>Vulnerabilities</h2>
        {{range .Vulnerabilities}}
        <div class="vuln-item">
            <div class="vuln-header">
                <span class="vuln-title">{{.PackageName}}</span>
                <span class="severity-badge" style="background: {{.Severity | severityColor}}">{{.Severity | upper}}</span>
            </div>
            <p><strong>{{.Title}}</strong></p>
            {{if .CVEID}}<p><strong>CVE:</strong> {{.CVEID}}</p>{{end}}
            {{if .VulnerableVersions}}<p><strong>Affected:</strong> {{.VulnerableVersions}}</p>{{end}}
            {{if .PatchedVersions}}<p><strong>Fixed:</strong> {{.PatchedVersions}}</p>{{end}}
            {{if .Recommendation}}<p><strong>Recommendation:</strong> {{.Recommendation}}</p>{{end}}
        </div>
        {{end}}

        <div class="footer">
            <p>Generated by Audit Checks</p>
        </div>
    </div>
</body>
</html>
`))

// emailData holds data for the email template
type emailData struct {
	AppName     string
	AuditorType string
	GeneratedAt string
	Summary     struct {
		Total    int
		Critical int
		High     int
		Moderate int
		Low      int
	}
	Vulnerabilities []models.Vulnerability
	AIAnalysis      *models.AIAnalysis
}

// buildHTMLBody creates the HTML body for the email
func (n *EmailNotifier) buildHTMLBody(report *models.Report) (string, error) {
	data := emailData{
		AppName:         report.AppName,
		AuditorType:     report.AuditorType,
		GeneratedAt:     report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
		Vulnerabilities: report.Vulnerabilities,
		AIAnalysis:      report.AIAnalysis,
	}
	data.Summary.Total = report.AuditResult.TotalVulnerabilities
	data.Summary.Critical = report.AuditResult.CriticalCount
	data.Summary.High = report.AuditResult.HighCount
	data.Summary.Moderate = report.AuditResult.ModerateCount
	data.Summary.Low = report.AuditResult.LowCount

	var buf bytes.Buffer
	if err := emailTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}
