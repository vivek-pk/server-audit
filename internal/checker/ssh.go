package checker

import (
	"context"
	"os"
	"strings"

	"security-scanner/internal/report"
)

// SSHChecker audits SSH server configuration.
type SSHChecker struct{}

func (s *SSHChecker) Name() string { return "ssh" }

func (s *SSHChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Common sshd_config locations
	configPaths := []string{"/etc/ssh/sshd_config", "/etc/sshd_config", "/usr/local/etc/ssh/sshd_config"}
	var configPath string
	for _, p := range configPaths {
		if _, err := os.Stat(p); err == nil {
			configPath = p
			break
		}
	}

	if configPath == "" {
		return []report.Finding{infoFinding("ssh", "sshd_config not found in standard locations.")}, nil
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return []report.Finding{infoFinding("ssh", "Cannot read sshd_config: "+err.Error())}, nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := fields[0]
		val := fields[1]

		switch key {
		case "PermitRootLogin":
			if strings.EqualFold(val, "yes") {
				findings = append(findings, report.Finding{
					CheckType:   "ssh",
					Severity:    report.SeverityCritical,
					Title:       "SSH root login permitted",
					Description: "PermitRootLogin is set to 'yes' in " + configPath + ".",
					Remediation: "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in sshd_config and restart sshd.",
				})
			}
		case "PasswordAuthentication":
			if strings.EqualFold(val, "yes") {
				findings = append(findings, report.Finding{
					CheckType:   "ssh",
					Severity:    report.SeverityMedium,
					Title:       "SSH password authentication enabled",
					Description: "PasswordAuthentication is set to 'yes' in " + configPath + ".",
					Remediation: "Set 'PasswordAuthentication no' and use key-based authentication instead.",
				})
			}
		case "Protocol":
			if val == "1" {
				findings = append(findings, report.Finding{
					CheckType:   "ssh",
					Severity:    report.SeverityCritical,
					Title:       "SSH protocol 1 in use",
					Description: "SSH protocol version 1 is insecure and should not be used.",
					Remediation: "Set 'Protocol 2' in sshd_config.",
				})
			}
		case "PermitEmptyPasswords":
			if strings.EqualFold(val, "yes") {
				findings = append(findings, report.Finding{
					CheckType:   "ssh",
					Severity:    report.SeverityCritical,
					Title:       "SSH empty passwords permitted",
					Description: "PermitEmptyPasswords is set to 'yes' in sshd_config.",
					Remediation: "Set 'PermitEmptyPasswords no' in sshd_config.",
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "ssh",
			Severity:    report.SeverityInfo,
			Title:       "SSH configuration audit completed",
			Description: "No critical SSH misconfigurations found in " + configPath + ".",
			Remediation: "Review SSH configuration periodically and keep sshd updated.",
		})
	}

	return findings, nil
}
