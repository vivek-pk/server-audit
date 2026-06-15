package checker

import (
	"context"
	"os"
	"os/exec"
	"strings"

	"security-scanner/internal/report"
)

// ContainerChecker audits Docker and container security.
type ContainerChecker struct{}

func (c *ContainerChecker) Name() string { return "containers" }

func (c *ContainerChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Check Docker socket permissions
	dockerSocket := "/var/run/docker.sock"
	if info, err := os.Stat(dockerSocket); err == nil {
		mode := info.Mode().Perm()
		if mode&0o077 != 0 {
			findings = append(findings, report.Finding{
				CheckType:   "containers",
				Severity:    report.SeverityCritical,
				Title:       "Docker socket is accessible to non-root users",
				Description: "The Docker socket at " + dockerSocket + " has permissions allowing non-root access.",
				Remediation: "Restrict Docker socket permissions or use Docker TLS and user groups carefully.",
			})
		}
	}

	// Check for running privileged containers
	if _, err := exec.LookPath("docker"); err == nil {
		out, err := runCommand(ctx, "docker", "ps", "--format", "{{.Names}}|{{.Image}}|{{.Status}}")
		if err == nil && strings.TrimSpace(out) != "" {
			lines := strings.Split(out, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, "|", 3)
				if len(parts) < 1 {
					continue
				}
				containerName := parts[0]
				// Attempt to inspect for privileged mode
				inspectOut, err := runCommand(ctx, "docker", "inspect", "--format", "{{.HostConfig.Privileged}}", containerName)
				if err == nil && strings.TrimSpace(inspectOut) == "true" {
					findings = append(findings, report.Finding{
						CheckType:   "containers",
						Severity:    report.SeverityHigh,
						Title:       "Privileged container running",
						Description: "Container '" + containerName + "' is running in privileged mode, which grants full host access.",
						Remediation: "Remove privileged flag and use specific capabilities (e.g., --cap-add) instead.",
					})
				}
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "containers",
			Severity:    report.SeverityInfo,
			Title:       "Container audit completed",
			Description: "No critical container security issues detected.",
			Remediation: "Keep Docker and container images updated. Scan images for vulnerabilities.",
		})
	}

	return findings, nil
}
