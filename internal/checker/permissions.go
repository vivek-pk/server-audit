package checker

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"security-scanner/internal/report"
)

// PermissionChecker audits file permissions and SUID binaries.
type PermissionChecker struct{}

func (p *PermissionChecker) Name() string { return "permissions" }

func (p *PermissionChecker) Run(ctx context.Context) ([]report.Finding, error) {
	var findings []report.Finding

	// Check for world-writable files in sensitive directories
	sensitiveDirs := []string{"/etc", "/home", "/tmp", "/var/tmp"}
	for _, dir := range sensitiveDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			mode := stat.Mode & 0o777
			if mode&0o002 != 0 {
				findings = append(findings, report.Finding{
					CheckType:   "permissions",
					Severity:    report.SeverityMedium,
					Title:       "World-writable file found",
					Description: fmt.Sprintf("File %s is world-writable (mode %o).", path, mode),
					Remediation: fmt.Sprintf("Remove world-write permission: chmod o-w %s", path),
				})
			}
			return nil
		})
	}

	// Find SUID binaries (basic scan of common locations)
	suidPaths := []string{"/usr/bin", "/usr/sbin", "/bin", "/sbin"}
	for _, dir := range suidPaths {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			if stat.Mode&syscall.S_ISUID != 0 {
				findings = append(findings, report.Finding{
					CheckType:   "permissions",
					Severity:    report.SeverityLow,
					Title:       "SUID binary found",
					Description: fmt.Sprintf("Binary %s has SUID bit set.", path),
					Remediation: "Review if SUID is necessary; remove with 'chmod u-s " + path + "' if not.",
				})
			}
			return nil
		})
	}

	// Check .ssh directory permissions for all users
	_ = filepath.WalkDir("/home", func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if filepath.Base(path) == ".ssh" {
			info, err := os.Stat(path)
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				return nil
			}
			mode := stat.Mode & 0o777
			if mode != 0o700 {
				findings = append(findings, report.Finding{
					CheckType:   "permissions",
					Severity:    report.SeverityMedium,
					Title:       "Insecure .ssh directory permissions",
					Description: fmt.Sprintf("Directory %s has mode %o; should be 700.", path, mode),
					Remediation: fmt.Sprintf("Fix with: chmod 700 %s", path),
				})
			}
		}
		return nil
	})

	if len(findings) == 0 {
		findings = append(findings, report.Finding{
			CheckType:   "permissions",
			Severity:    report.SeverityInfo,
			Title:       "Permission audit completed",
			Description: "No world-writable files or insecure .ssh directories found in scanned paths.",
			Remediation: "Regularly audit file permissions, especially after software installations.",
		})
	}

	return findings, nil
}
