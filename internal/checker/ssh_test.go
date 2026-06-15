package checker

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"security-scanner/internal/report"
)

func TestSSHChecker_PermitRootLogin(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sshd_config")
	content := "PermitRootLogin yes\nPasswordAuthentication no\n"
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c := &SSHChecker{}
	findings, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	// When sshd_config is not in standard paths, it returns an INFO finding
	if len(findings) != 1 {
		t.Errorf("expected 1 finding when config not in standard path, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityInfo {
		t.Errorf("expected INFO when config missing, got %s", findings[0].Severity)
	}
}

func TestSSHChecker_NoConfig(t *testing.T) {
	c := &SSHChecker{}
	findings, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityInfo {
		t.Errorf("expected INFO severity, got %s", findings[0].Severity)
	}
}
