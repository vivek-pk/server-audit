package report

import "time"

// Severity levels for findings.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Finding represents a single security issue.
type Finding struct {
	CheckType   string `json:"check_type"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// Report is the top-level structure sent to the webhook.
type Report struct {
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	Findings  []Finding `json:"findings"`
}

// ValidSeverity returns true if s is a known severity level.
func ValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}
