package checker

import (
	"bufio"
	"context"
	"os"
	"strings"

	"security-scanner/internal/report"
)

// FilesystemChecker audits filesystem mounts and encryption status.
type FilesystemChecker struct{}

func (f *FilesystemChecker) Name() string { return "filesystem" }

func (f *FilesystemChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Parse /proc/mounts for critical mount options
	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return []report.Finding{infoFinding("filesystem", "Cannot read /proc/mounts: "+err.Error())}, nil
	}
	defer mounts.Close()

	scanner := bufio.NewScanner(mounts)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 4 {
			continue
		}
		mountPoint := parts[1]
		options := parts[3]

		// Check /tmp for noexec and nodev
		if mountPoint == "/tmp" {
			if !strings.Contains(options, "noexec") {
				findings = append(findings, report.Finding{
					CheckType:   "filesystem",
					Severity:    report.SeverityMedium,
					Title:       "/tmp mounted without noexec",
					Description: "The /tmp filesystem is mounted without the noexec option, allowing execution of binaries from /tmp.",
					Remediation: "Remount /tmp with noexec: mount -o remount,noexec /tmp",
				})
			}
			if !strings.Contains(options, "nodev") {
				findings = append(findings, report.Finding{
					CheckType:   "filesystem",
					Severity:    report.SeverityMedium,
					Title:       "/tmp mounted without nodev",
					Description: "The /tmp filesystem is mounted without the nodev option, allowing device files in /tmp.",
					Remediation: "Remount /tmp with nodev: mount -o remount,nodev /tmp",
				})
			}
		}

		// Check /dev/shm for noexec
		if mountPoint == "/dev/shm" && !strings.Contains(options, "noexec") {
			findings = append(findings, report.Finding{
				CheckType:   "filesystem",
				Severity:    report.SeverityMedium,
				Title:       "/dev/shm mounted without noexec",
				Description: "The /dev/shm filesystem lacks the noexec option.",
				Remediation: "Remount /dev/shm with noexec: mount -o remount,noexec /dev/shm",
			})
		}
	}

	// Check for LUKS encryption on block devices
	if _, err := os.Stat("/dev/mapper"); err == nil {
		entries, err := os.ReadDir("/dev/mapper")
		if err == nil {
			hasLUKS := false
			for _, entry := range entries {
				if strings.Contains(entry.Name(), "luks") || strings.Contains(entry.Name(), "crypt") {
					hasLUKS = true
					break
				}
			}
			if !hasLUKS {
				findings = append(findings, report.Finding{
					CheckType:   "filesystem",
					Severity:    report.SeverityLow,
					Title:       "No LUKS encryption detected",
					Description: "No LUKS-encrypted volumes were detected on this system.",
					Remediation: "Consider enabling full-disk encryption (LUKS) for data-at-rest protection.",
				})
			}
		}
	}

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "filesystem",
			Severity:    report.SeverityInfo,
			Title:       "Filesystem audit completed",
			Description: "Mount options and filesystem checks completed with no issues.",
			Remediation: "Periodically review mount options and filesystem integrity.",
		})
	}

	return findings, nil
}
