package formatter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"security-scanner/internal/report"
)

// FormatReport marshals a report into JSON bytes.
func FormatReport(r report.Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// NewReport creates a Report with the current hostname and timestamp.
func NewReport(findings []report.Finding) (report.Report, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	return report.Report{
		Hostname:  hostname,
		Timestamp: time.Now().UTC(),
		Findings:  findings,
	}, nil
}

// FormatFinding creates a JSON representation of a single finding (for debug/logging).
func FormatFinding(f report.Finding) (string, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return "", fmt.Errorf("marshal finding: %w", err)
	}
	return string(b), nil
}
