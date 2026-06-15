package checker

import (
	"context"
	"os/exec"

	"security-scanner/internal/report"
)

// runCommand executes a command with context and returns stdout.
func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}

// detectPackageManager attempts to identify the package manager used on the system.
func detectPackageManager() string {
	managers := []struct {
		cmd  string
		name string
	}{
		{"apt-get", "apt"},
		{"apt", "apt"},
		{"dnf", "dnf"},
		{"yum", "yum"},
		{"pacman", "pacman"},
		{"apk", "apk"},
		{"zypper", "zypper"},
	}
	for _, m := range managers {
		if _, err := exec.LookPath(m.cmd); err == nil {
			return m.name
		}
	}
	return ""
}

// infoFinding creates an INFO-level finding for a given check type.
func infoFinding(checkType, description string) report.Finding {
	return report.Finding{
		CheckType:   checkType,
		Severity:    report.SeverityInfo,
		Title:       checkType + " check skipped",
		Description: description,
		Remediation: "Ensure required tools and files are available.",
	}
}
