package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/google/generative-ai-go/genai"
	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
	"google.golang.org/api/option"
)

// GeminiAnalyzer provides AI-powered vulnerability analysis using Google Gemini
type GeminiAnalyzer struct {
	client    *genai.Client
	model     *genai.GenerativeModel
	modelName string
	enabled   bool
}

// NewGeminiAnalyzer creates a new GeminiAnalyzer
func NewGeminiAnalyzer(ctx context.Context, apiKey string, modelName string, enabled bool) (*GeminiAnalyzer, error) {
	if !enabled || apiKey == "" {
		return &GeminiAnalyzer{
			enabled: false,
		}, nil
	}

	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	zap.S().Infof("Using Gemini model: %s", modelName)
	model := client.GenerativeModel(modelName)
	model.SetTemperature(0.2)
	model.SetTopK(40)
	model.SetTopP(0.95)

	// Configure for JSON output
	model.ResponseMIMEType = "application/json"

	return &GeminiAnalyzer{
		client:    client,
		model:     model,
		modelName: modelName,
		enabled:   true,
	}, nil
}

// Enabled returns true if the analyzer is enabled
func (g *GeminiAnalyzer) Enabled() bool {
	return g.enabled
}

// Analyze sends vulnerability data to Gemini for enhanced analysis
func (g *GeminiAnalyzer) Analyze(ctx context.Context, result *models.AuditResult) (*models.AIAnalysis, error) {
	if !g.enabled {
		return nil, nil
	}

	if len(result.Vulnerabilities) == 0 {
		return &models.AIAnalysis{
			Summary:        "No vulnerabilities found.",
			Priority:       []string{},
			Remediation:    []string{},
			RiskAssessment: "No security risks identified.",
		}, nil
	}

	zap.S().Infof("Sending vulnerabilities to Gemini for analysis app=%s count=%d",
		result.AppName,
		len(result.Vulnerabilities),
	)

	prompt, err := g.buildPrompt(result)
	if err != nil {
		return nil, fmt.Errorf("failed to build prompt: %w", err)
	}

	resp, err := g.model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return nil, fmt.Errorf("failed to generate content: %w", err)
	}

	analysis, err := g.parseResponse(resp)
	if err != nil {
		zap.S().Warnf("Failed to parse Gemini response, using fallback: %v", err)
		return g.fallbackAnalysis(result), nil
	}

	zap.S().Infof("Gemini analysis completed for app=%s", result.AppName)
	return analysis, nil
}

// Close closes the Gemini client
func (g *GeminiAnalyzer) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// promptData holds data for the prompt template
type promptData struct {
	AppName         string
	AuditorType     string
	Vulnerabilities []models.Vulnerability
}

// promptTemplate is the template for Gemini prompts
var promptTemplate = template.Must(template.New("prompt").Parse(`
You are a security analyst reviewing vulnerabilities found in a {{.AuditorType}} project named "{{.AppName}}".

Analyze these vulnerabilities and provide a JSON response with the following structure:
{
  "summary": "A plain-language summary (2-3 sentences) explaining the security situation for non-technical stakeholders",
  "priority": ["package1", "package2", ...],
  "remediation": ["command1", "command2", ...],
  "risk_assessment": "Business risk explanation including potential impact if vulnerabilities are exploited"
}

Guidelines:
- summary: Be concise but informative. Mention the most severe issues.
- priority: List package names in order of fix priority (most critical/exploitable first)
- remediation: Provide specific commands to fix each vulnerability (e.g., "npm update lodash@4.17.21")
- risk_assessment: Explain the business impact in terms non-technical stakeholders can understand

Vulnerabilities found:
{{range .Vulnerabilities}}
- Package: {{.PackageName}}
  Severity: {{.Severity}}
  CVE: {{if .CVEID}}{{.CVEID}}{{else}}N/A{{end}}
  Title: {{.Title}}
  Vulnerable Versions: {{.VulnerableVersions}}
  Patched Versions: {{if .PatchedVersions}}{{.PatchedVersions}}{{else}}Unknown{{end}}
{{end}}

Respond ONLY with valid JSON. Do not include any markdown formatting or explanation outside the JSON.
`))

// buildPrompt creates the prompt for Gemini
func (g *GeminiAnalyzer) buildPrompt(result *models.AuditResult) (string, error) {
	data := promptData{
		AppName:         result.AppName,
		AuditorType:     result.AuditorType,
		Vulnerabilities: result.Vulnerabilities,
	}

	var buf bytes.Buffer
	if err := promptTemplate.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// parseResponse parses the Gemini response into AIAnalysis
func (g *GeminiAnalyzer) parseResponse(resp *genai.GenerateContentResponse) (*models.AIAnalysis, error) {
	if len(resp.Candidates) == 0 {
		return nil, fmt.Errorf("no candidates in response")
	}

	candidate := resp.Candidates[0]
	if candidate.Content == nil || len(candidate.Content.Parts) == 0 {
		return nil, fmt.Errorf("no content in candidate")
	}

	// Extract text from response
	var responseText string
	for _, part := range candidate.Content.Parts {
		if text, ok := part.(genai.Text); ok {
			responseText += string(text)
		}
	}

	if responseText == "" {
		return nil, fmt.Errorf("empty response text")
	}

	// Clean up the response (remove markdown code blocks if present)
	responseText = strings.TrimSpace(responseText)
	responseText = strings.TrimPrefix(responseText, "```json")
	responseText = strings.TrimPrefix(responseText, "```")
	responseText = strings.TrimSuffix(responseText, "```")
	responseText = strings.TrimSpace(responseText)

	var analysis models.AIAnalysis
	if err := json.Unmarshal([]byte(responseText), &analysis); err != nil {
		return nil, fmt.Errorf("failed to parse JSON response: %w (response: %s)", err, responseText)
	}

	return &analysis, nil
}

// fallbackAnalysis creates a basic analysis when Gemini fails
func (g *GeminiAnalyzer) fallbackAnalysis(result *models.AuditResult) *models.AIAnalysis {
	// Build priority list based on severity
	priority := make([]string, 0)
	seen := make(map[string]bool)

	// Add critical first, then high, etc.
	for _, severity := range []string{models.SeverityCritical, models.SeverityHigh, models.SeverityModerate, models.SeverityLow} {
		for _, v := range result.Vulnerabilities {
			if v.Severity == severity && !seen[v.PackageName] {
				priority = append(priority, v.PackageName)
				seen[v.PackageName] = true
			}
		}
	}

	// Build remediation commands
	remediation := make([]string, 0)
	for _, v := range result.Vulnerabilities {
		if v.Recommendation != "" && len(remediation) < 10 {
			remediation = append(remediation, v.Recommendation)
		}
	}

	// Build summary
	summary := fmt.Sprintf("Found %d vulnerabilities: %d critical, %d high, %d moderate, %d low.",
		result.TotalVulnerabilities,
		result.CriticalCount,
		result.HighCount,
		result.ModerateCount,
		result.LowCount,
	)

	if result.CriticalCount > 0 {
		summary += " Immediate attention required for critical vulnerabilities."
	}

	// Build risk assessment
	riskAssessment := "Security vulnerabilities were detected that could potentially be exploited by attackers. "
	if result.CriticalCount > 0 || result.HighCount > 0 {
		riskAssessment += "High-severity issues may allow unauthorized access, data theft, or system compromise. Prioritize fixing these issues immediately."
	} else {
		riskAssessment += "The identified issues are moderate to low severity but should still be addressed to maintain security posture."
	}

	return &models.AIAnalysis{
		Summary:        summary,
		Priority:       priority,
		Remediation:    remediation,
		RiskAssessment: riskAssessment,
	}
}
