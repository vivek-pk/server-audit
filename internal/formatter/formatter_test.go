package formatter

import (
	"testing"
	"time"

	"security-scanner/internal/report"
)

func TestFormatReport(t *testing.T) {
	r := report.Report{
		Hostname:  "test-host",
		Timestamp: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []report.Finding{
			{CheckType: "kernel", Severity: report.SeverityHigh, Title: "Update available"},
		},
	}
	b, err := FormatReport(r)
	if err != nil {
		t.Fatalf("format report: %v", err)
	}
	if len(b) == 0 {
		t.Error("expected non-empty output")
	}
}

func TestNewReport(t *testing.T) {
	f := []report.Finding{{CheckType: "ssh", Severity: report.SeverityInfo, Title: "OK"}}
	r, err := NewReport(f)
	if err != nil {
		t.Fatalf("new report: %v", err)
	}
	if r.Hostname == "" {
		t.Error("expected non-empty hostname")
	}
	if len(r.Findings) != 1 {
		t.Errorf("findings count = %d, want 1", len(r.Findings))
	}
}
