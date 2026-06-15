package checker

import (
	"context"
	"os/exec"
	"strings"

	"security-scanner/internal/report"
)

// FirewallChecker audits active firewall rules and listening ports.
type FirewallChecker struct{}

func (f *FirewallChecker) Name() string { return "firewall" }

func (f *FirewallChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Detect firewall tool and check active rules
	hasRules := false
	var firewallType string

	if _, err := exec.LookPath("iptables"); err == nil {
		out, err := runCommand(ctx, "iptables", "-L", "-n")
		if err == nil && len(out) > 0 && !strings.Contains(out, "Chain INPUT (policy ACCEPT)") {
			hasRules = true
			firewallType = "iptables"
		}
	}

	if !hasRules {
		if _, err := exec.LookPath("nft"); err == nil {
			out, err := runCommand(ctx, "nft", "list", "ruleset")
			if err == nil && strings.TrimSpace(out) != "" && !strings.Contains(out, "table ip filter {") {
				// Actually has nft rules
				hasRules = true
				firewallType = "nftables"
			}
		}
	}

	if !hasRules {
		if _, err := exec.LookPath("ufw"); err == nil {
			out, err := runCommand(ctx, "ufw", "status")
			if err == nil && strings.Contains(out, "Status: active") {
				hasRules = true
				firewallType = "ufw"
			}
		}
	}

	if !hasRules {
		findings = append(findings, report.Finding{
			CheckType:   "firewall",
			Severity:    report.SeverityHigh,
			Title:       "No active firewall detected",
			Description: "No active firewall rules found via iptables, nftables, or ufw.",
			Remediation: "Enable and configure a host-based firewall (e.g., ufw, firewalld, or iptables rules).",
		})
	} else {
		findings = append(findings, report.Finding{
			CheckType:   "firewall",
			Severity:    report.SeverityInfo,
			Title:       "Active firewall detected",
			Description: "Firewall type: " + firewallType + ".",
			Remediation: "Review firewall rules regularly to ensure only necessary ports are exposed.",
		})
	}

	// Check listening ports that might be exposed without firewall coverage
	if _, err := exec.LookPath("ss"); err == nil {
		out, err := runCommand(ctx, "ss", "-tlnp")
		if err == nil {
			lines := strings.Split(out, "\n")
			for _, line := range lines[1:] {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 5 {
					localAddr := parts[3]
					if strings.HasPrefix(localAddr, "0.0.0.0:") || strings.HasPrefix(localAddr, "[::]:") {
						port := strings.Split(localAddr, ":")
						portStr := port[len(port)-1]
						findings = append(findings, report.Finding{
							CheckType:   "firewall",
							Severity:    report.SeverityLow,
							Title:       "Listening port " + portStr + " on all interfaces",
							Description: "Service is listening on " + localAddr + " without IP restriction.",
							Remediation: "Bind the service to localhost or specific interfaces if external access is not required.",
						})
					}
				}
			}
		}
	}

	return findings, nil
}
