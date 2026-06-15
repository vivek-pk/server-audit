package checker

import (
	"context"
	"os/exec"
	"strings"

	"security-scanner/internal/report"
)

// KernelChecker audits the running kernel for known issues.
type KernelChecker struct{}

func (k *KernelChecker) Name() string { return "kernel" }

func (k *KernelChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Get running kernel version
	unameOutput, err := runCommand(ctx, "uname", "-r")
	if err != nil {
		return append(findings, infoFinding("kernel", "Unable to determine kernel version: "+err.Error())), nil
	}
	kernelVersion := strings.TrimSpace(unameOutput)

	// Try to detect available security updates using package managers
	pm := detectPackageManager()
	updatesAvailable := false
	var updateDetail string

	switch pm {
	case "apt":
		out, err := runCommand(ctx, "apt", "list", "--upgradable")
		if err == nil && strings.Contains(out, "linux-image") {
			updatesAvailable = true
			updateDetail = "Kernel updates available via apt"
		}
	case "yum", "dnf":
		out, err := runCommand(ctx, pm, "check-update", "kernel")
		if err == nil || (err != nil && strings.Contains(out, "kernel")) {
			// yum check-update exits 100 when updates are available
			updatesAvailable = true
			updateDetail = "Kernel updates available via " + pm
		}
	case "pacman":
		out, err := runCommand(ctx, "pacman", "-Qu", "linux")
		if err == nil && strings.TrimSpace(out) != "" {
			updatesAvailable = true
			updateDetail = "Kernel updates available via pacman"
		}
	case "apk":
		out, err := runCommand(ctx, "apk", "version", "linux-lts")
		if err == nil && strings.Contains(out, "<") {
			updatesAvailable = true
			updateDetail = "Kernel updates available via apk"
		}
	default:
		// Try generic approach
		if _, err := exec.LookPath("apt"); err == nil {
			out, err2 := runCommand(ctx, "apt", "list", "--upgradable")
			if err2 == nil && strings.Contains(out, "linux-image") {
				updatesAvailable = true
				updateDetail = "Kernel updates available via apt"
			}
		}
	}

	if updatesAvailable {
		findings = append(findings, report.Finding{
			CheckType:   "kernel",
			Severity:    report.SeverityHigh,
			Title:       "Kernel security updates available",
			Description: "The running kernel (" + kernelVersion + ") has pending security updates. " + updateDetail + "...",
			Remediation: "Update the kernel using your package manager and reboot the system.",
		})
	} else {
		findings = append(findings, report.Finding{
			CheckType:   "kernel",
			Severity:    report.SeverityInfo,
			Title:       "Kernel version checked",
			Description: "Running kernel: " + kernelVersion + ". No pending kernel updates detected via available package manager.",
			Remediation: "Keep the system updated regularly.",
		})
	}

	return findings, nil
}
