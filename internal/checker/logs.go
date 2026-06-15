package checker

import (
	"context"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"security-scanner/internal/report"
)

// LogChecker audits system logs for security anomalies.
type LogChecker struct{}

func (l *LogChecker) Name() string { return "logs" }

func (l *LogChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding
	var logData string
	var source string

	// Try journalctl first (systemd)
	if _, err := exec.LookPath("journalctl"); err == nil {
		out, err := runCommand(ctx, "journalctl", "-q", "--since", "1 hour ago", "-u", "sshd", "--no-pager")
		if err == nil && strings.TrimSpace(out) != "" {
			logData = out
			source = "journalctl"
		}
	}

	// Fallback to /var/log/auth.log
	if logData == "" {
		if _, err := exec.LookPath("grep"); err == nil {
			out, err := runCommand(ctx, "grep", "sshd", "/var/log/auth.log")
			if err == nil && strings.TrimSpace(out) != "" {
				logData = out
				source = "auth.log"
			}
		}
	}

	if logData == "" {
		return []report.Finding{infoFinding("logs", "No SSH log data available from journalctl or /var/log/auth.log.")}, nil
	}

	// Analyze failed attempts
	failedIPs := extractFailedAttempts(logData)
	if len(failedIPs) > 0 {
		findings = append(findings, analyzeFailedIPs(failedIPs, source)...)
	}

	// Analyze successful logins
	successes := extractSuccessfulLogins(logData)
	if len(successes) > 0 {
		findings = append(findings, analyzeSuccessfulLogins(successes, failedIPs)...)
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "logs",
			Severity:    report.SeverityInfo,
			Title:       "Log audit completed",
			Description: "No significant authentication failures or anomalies detected in recent " + source + ".",
			Remediation: "Continue monitoring logs and set up alerting for repeated failures.",
		})
	}

	return findings, nil
}

// loginAttempt represents a parsed log entry.
type loginAttempt struct {
	user   string
	ip     string
	method string
	line   string
}

// ipRegex matches IPv4 addresses.
var ipRegex = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

func extractFailedAttempts(logData string) map[string]int {
	ips := make(map[string]int)
	lines := strings.Split(logData, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "Failed password") && !strings.Contains(line, "authentication failure") {
			continue
		}
		matches := ipRegex.FindAllString(line, -1)
		for _, ip := range matches {
			ips[ip]++
		}
	}
	return ips
}

func analyzeFailedIPs(ips map[string]int, source string) []report.Finding {
	var findings []report.Finding

	// Sort IPs by failure count
	type ipCount struct {
		ip    string
		count int
	}
	var sorted []ipCount
	var totalFailures int
	for ip, count := range ips {
		sorted = append(sorted, ipCount{ip, count})
		totalFailures += count
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].count > sorted[j].count
	})

	// Report top offenders (IPs with > 3 failures)
	var topOffenders []string
	for _, ic := range sorted {
		if ic.count > 3 {
			topOffenders = append(topOffenders, ic.ip+" ("+strconv.Itoa(ic.count)+" attempts)")
		}
	}

	if len(topOffenders) > 0 {
		findings = append(findings, report.Finding{
			CheckType:   "logs",
			Severity:    report.SeverityHigh,
			Title:       "Brute force attack detected",
			Description: "Detected " + strconv.Itoa(totalFailures) + " failed SSH attempts from " + strconv.Itoa(len(sorted)) + " unique IP(s). Top offenders: " + strings.Join(topOffenders, ", ") + ". Source: " + source + ".",
			Remediation: "Block offending IPs via fail2ban, firewall rules, or consider disabling password authentication.",
		})
	} else if totalFailures > 5 {
		findings = append(findings, report.Finding{
			CheckType:   "logs",
			Severity:    report.SeverityMedium,
			Title:       "Multiple authentication failures",
			Description: "Detected " + strconv.Itoa(totalFailures) + " failed SSH attempts distributed across multiple IPs. Source: " + source + ".",
			Remediation: "Review auth logs and verify no unauthorized access attempts are succeeding.",
		})
	}

	return findings
}

func extractSuccessfulLogins(logData string) []loginAttempt {
	var attempts []loginAttempt
	lines := strings.Split(logData, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "Accepted") {
			continue
		}
		matches := ipRegex.FindAllString(line, -1)
		if len(matches) == 0 {
			continue
		}
		ip := matches[len(matches)-1] // last IP is usually the source

		var user, method string
		fields := strings.Fields(line)
		for i, f := range fields {
			if f == "for" && i+1 < len(fields) {
				user = fields[i+1]
			}
			if f == "from" && i+1 < len(fields) {
				// ip already extracted via regex
			}
		}
		// Determine auth method
		if strings.Contains(line, "password") {
			method = "password"
		} else if strings.Contains(line, "publickey") {
			method = "publickey"
		} else {
			method = "unknown"
		}

		attempts = append(attempts, loginAttempt{
			user:   user,
			ip:     ip,
			method: method,
			line:   line,
		})
	}
	return attempts
}

func analyzeSuccessfulLogins(successes []loginAttempt, failedIPs map[string]int) []report.Finding {
	var findings []report.Finding

	for _, s := range successes {
		// Check for root login
		if s.user == "root" {
			findings = append(findings, report.Finding{
				CheckType:   "logs",
				Severity:    report.SeverityCritical,
				Title:       "Root login successful",
				Description: "Successful root login detected from " + s.ip + " via " + s.method + ".",
				Remediation: "Audit why root SSH login was permitted. Disable root login in sshd_config if not required. Rotate credentials if suspicious.",
			})
		}

		// Check for password-based login (potential brute force success)
		if s.method == "password" {
			findings = append(findings, report.Finding{
				CheckType:   "logs",
				Severity:    report.SeverityHigh,
				Title:       "Password-based login successful",
				Description: "Successful password login for user '" + s.user + "' from " + s.ip + ".",
				Remediation: "Verify this login was authorized. If not, rotate the user's password and check for unauthorized access.",
			})
		}

		// Check if this IP had many failures before succeeding (potential brute force success)
		if failedCount, ok := failedIPs[s.ip]; ok && failedCount > 3 {
			findings = append(findings, report.Finding{
				CheckType:   "logs",
				Severity:    report.SeverityCritical,
				Title:       "Possible brute force success",
				Description: "IP " + s.ip + " had " + strconv.Itoa(failedCount) + " failed attempts followed by a successful login for user '" + s.user + "'.",
				Remediation: "Immediately investigate this IP. Rotate the affected user's credentials and consider blocking the source IP.",
			})
		}
	}

	return findings
}
