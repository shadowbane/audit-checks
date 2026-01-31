package auditor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/shadowbane/audit-checks/pkg/models"
)

// Auditor defines the interface for security auditors
type Auditor interface {
	// Name returns the auditor name (e.g., "npm", "composer")
	Name() string

	// Detect checks if the project at path uses this package manager
	Detect(path string) bool

	// Audit runs the security audit and returns results
	Audit(ctx context.Context, app models.AppConfig) (*models.AuditResult, error)
}

// Registry manages available auditors
type Registry struct {
	auditors map[string]Auditor
	mu       sync.RWMutex
}

// NewRegistry creates a new auditor registry
func NewRegistry() *Registry {
	return &Registry{
		auditors: make(map[string]Auditor),
	}
}

// Register adds an auditor to the registry
func (r *Registry) Register(a Auditor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.auditors[a.Name()] = a
}

// Get returns an auditor by name
func (r *Registry) Get(name string) (Auditor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.auditors[name]
	return a, ok
}

// Detect finds the appropriate auditor for a project path (returns first match)
func (r *Registry) Detect(path string) Auditor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, a := range r.auditors {
		if a.Detect(path) {
			return a
		}
	}
	return nil
}

// DetectAll finds all applicable auditors for a project path
func (r *Registry) DetectAll(path string) []Auditor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var auditors []Auditor
	for _, a := range r.auditors {
		if a.Detect(path) {
			auditors = append(auditors, a)
		}
	}
	return auditors
}

// GetAuditorForApp returns the appropriate auditor for an app config (single)
func (r *Registry) GetAuditorForApp(app models.AppConfig) (Auditor, error) {
	auditors, err := r.GetAuditorsForApp(app)
	if err != nil {
		return nil, err
	}
	if len(auditors) == 0 {
		return nil, fmt.Errorf("no auditors found for: %s", app.Path)
	}
	return auditors[0], nil
}

// GetAuditorsForApp returns all applicable auditors for an app config
func (r *Registry) GetAuditorsForApp(app models.AppConfig) ([]Auditor, error) {
	// If type is specified (not auto), parse it
	if app.Type != "" && app.Type != "auto" {
		var auditors []Auditor
		// Support comma-separated types like "npm,composer"
		types := splitTypes(app.Type)
		for _, t := range types {
			a, ok := r.Get(t)
			if !ok {
				return nil, fmt.Errorf("unknown auditor type: %s", t)
			}
			auditors = append(auditors, a)
		}
		return auditors, nil
	}

	// Otherwise, auto-detect all applicable auditors
	auditors := r.DetectAll(app.Path)
	if len(auditors) == 0 {
		return nil, fmt.Errorf("could not detect package manager for: %s", app.Path)
	}
	return auditors, nil
}

// splitTypes splits comma-separated types and trims whitespace
func splitTypes(s string) []string {
	var result []string
	for _, part := range splitByComma(s) {
		trimmed := trimWhitespace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func splitByComma(s string) []string {
	var result []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}

func trimWhitespace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// All returns all registered auditors
func (r *Registry) All() []Auditor {
	r.mu.RLock()
	defer r.mu.RUnlock()

	auditors := make([]Auditor, 0, len(r.auditors))
	for _, a := range r.auditors {
		auditors = append(auditors, a)
	}
	return auditors
}

// Names returns the names of all registered auditors
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.auditors))
	for name := range r.auditors {
		names = append(names, name)
	}
	return names
}

// Helper functions for auditors

// FileExists checks if a file exists at the given path
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// JoinPath joins path components
func JoinPath(base string, parts ...string) string {
	return filepath.Join(append([]string{base}, parts...)...)
}

// FilterVulnerabilities filters vulnerabilities by severity threshold
func FilterVulnerabilities(vulns []models.Vulnerability, threshold string) []models.Vulnerability {
	var filtered []models.Vulnerability
	for _, v := range vulns {
		if models.MeetsSeverityThreshold(v.Severity, threshold) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

// IsIgnored checks if a vulnerability should be ignored
func IsIgnored(vuln models.Vulnerability, ignoreList []string) bool {
	for _, ignore := range ignoreList {
		if vuln.CVEID == ignore || vuln.PackageName == ignore {
			return true
		}
	}
	return false
}

// FilterIgnored removes ignored vulnerabilities
func FilterIgnored(vulns []models.Vulnerability, ignoreList []string) []models.Vulnerability {
	if len(ignoreList) == 0 {
		return vulns
	}

	var filtered []models.Vulnerability
	for _, v := range vulns {
		if !IsIgnored(v, ignoreList) {
			filtered = append(filtered, v)
		}
	}
	return filtered
}
