package checker

import (
	"bufio"
	"context"
	"os"
	"strings"

	"security-scanner/internal/report"
)

// UserChecker audits user accounts and groups.
type UserChecker struct{}

func (u *UserChecker) Name() string { return "users" }

func (u *UserChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Check for empty passwords or unlocked system accounts
	shadowFile, err := os.Open("/etc/shadow")
	if err != nil {
		return append(findings, infoFinding("users", "Cannot read /etc/shadow: "+err.Error())), nil
	}
	defer shadowFile.Close()

	scanner := bufio.NewScanner(shadowFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			continue
		}
		username := parts[0]
		passwordHash := parts[1]

		if passwordHash == "" {
			findings = append(findings, report.Finding{
				CheckType:   "users",
				Severity:    report.SeverityHigh,
				Title:       "Account '" + username + "' has empty password",
				Description: "The user '" + username + "' in /etc/shadow has an empty password hash, allowing passwordless local login.",
				Remediation: "Set a strong password for '" + username + "' or disable the account with 'passwd -l " + username + "'.",
			})
		}

		// Check for locked accounts with empty hash (! or *)
		if passwordHash == "!" || passwordHash == "*" || passwordHash == "!!" {
			continue // properly locked
		}

		// Check for weak hashes or known bad values
		if strings.HasPrefix(passwordHash, "!") && len(passwordHash) > 1 {
			// Account locked but has password hash (may be unlocked later)
			continue
		}
	}

	// Check for duplicate UIDs (esp UID 0)
	passwdFile, err := os.Open("/etc/passwd")
	if err != nil {
		return append(findings, infoFinding("users", "Cannot read /etc/passwd: "+err.Error())), nil
	}
	defer passwdFile.Close()

	uidCounts := make(map[string][]string) // uid -> list of usernames
	scanner = bufio.NewScanner(passwdFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		username := parts[0]
		uid := parts[2]
		uidCounts[uid] = append(uidCounts[uid], username)
	}

	for uid, users := range uidCounts {
		if len(users) > 1 {
			severity := report.SeverityMedium
			if uid == "0" {
				severity = report.SeverityCritical
			}
			findings = append(findings, report.Finding{
				CheckType:   "users",
				Severity:    severity,
				Title:       "Duplicate UID " + uid + " detected",
				Description: "Users sharing UID " + uid + ": " + strings.Join(users, ", ") + ".",
				Remediation: "Ensure each user has a unique UID. UID 0 should be reserved for root only.",
			})
		}
	}

	// Check sudoers for NOPASSWD or ALL privileges
	if _, err := os.Stat("/etc/sudoers"); err == nil {
		findings = append(findings, checkSudoers(ctx)...)
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "users",
			Severity:    report.SeverityInfo,
			Title:       "User audit completed",
			Description: "No critical user account issues detected.",
			Remediation: "Continue periodic user audits.",
		})
	}

	return findings, nil
}

func checkSudoers(ctx context.Context) []report.Finding {
	var findings []report.Finding
	data, err := os.ReadFile("/etc/sudoers")
	if err != nil {
		return []report.Finding{infoFinding("users", "Cannot read /etc/sudoers: "+err.Error())}
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "NOPASSWD") {
			findings = append(findings, report.Finding{
				CheckType:   "users",
				Severity:    report.SeverityMedium,
				Title:       "NOPASSWD sudo rule detected",
				Description: "Line in /etc/sudoers allows sudo without password: " + line,
				Remediation: "Remove NOPASSWD where possible and require password authentication for privileged commands.",
			})
		}
	}
	return findings
}
