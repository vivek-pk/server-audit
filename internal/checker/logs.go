package checker

import (
	"context"
	"os/exec"
	"strconv"
	"strings"

	"security-scanner/internal/report"
)

// LogChecker audits system logs for security anomalies.
type LogChecker struct{}

func (l *LogChecker) Name() string { return "logs" }

func (l *LogChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Try journalctl first (systemd)
	if _, err := exec.LookPath("journalctl"); err == nil {
		out, err := runCommand(ctx, "journalctl", "-q", "--since", "1 hour ago", "-u", "sshd", "--no-pager")
		if err == nil {
			authFailures := countOccurrences(out, "authentication failure") + countOccurrences(out, "Failed password")
			if authFailures > 5 {
				findings = append(findings, report.Finding{
					CheckType:   "logs",
					Severity:    report.SeverityHigh,
					Title:       "High number of authentication failures",
					Description: "Detected " + strconv.Itoa(authFailures) + " SSH authentication failures in the last hour.",
					Remediation: "Investigate source IPs (check 'journalctl -u sshd'), consider enabling fail2ban or tightening firewall rules.",
				})
			}
		}
	}

	// Fallback to /var/log/auth.log
	if _, err := exec.LookPath("grep"); err == nil {
		out, err := runCommand(ctx, "grep", "-c", "authentication failure", "/var/log/auth.log")
		if err == nil {
			count := strings.TrimSpace(out)
			n, _ := strconv.Atoi(count)
			if n > 10 {
				findings = append(findings, report.Finding{
					CheckType:   "logs",
					Severity:    report.SeverityMedium,
					Title:       "Auth log shows repeated failures",
					Description: "/var/log/auth.log contains " + count + " authentication failure entries.",
					Remediation: "Review auth logs, check for brute-force attempts, and consider using fail2ban.",
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "logs",
			Severity:    report.SeverityInfo,
			Title:       "Log audit completed",
			Description: "No significant authentication failures or anomalies detected in recent logs.",
			Remediation: "Continue monitoring logs and set up alerting for repeated failures.",
		})
	}

	return findings, nil
}

func countOccurrences(text, substr string) int {
	count := 0
	for {
		idx := strings.Index(text, substr)
		if idx == -1 {
			break
		}
		count++
		text = text[idx+len(substr):]
	}
	return count
}
