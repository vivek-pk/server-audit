package config

import (
	"os"
	"testing"
)

func TestLoad(t *testing.T) {
	content := `
interval: "30m"
timeout_per_check: "10s"
webhook:
  url: "http://localhost:8080/hook"
  timeout: "5s"
  secret: "supersecret"
  max_retries: 2
  retry_base_delay: "2s"
checks:
  kernel: false
  users: true
`
	tmpfile, err := os.CreateTemp("", "config-*.yml")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.WriteString(content); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.Interval != "30m" {
		t.Errorf("interval = %q, want 30m", cfg.Interval)
	}
	if cfg.Checks.Kernel != false {
		t.Error("expected kernel check disabled")
	}
	if cfg.Checks.Users != true {
		t.Error("expected users check enabled")
	}
	if cfg.Webhook.URL != "http://localhost:8080/hook" {
		t.Errorf("webhook url = %q", cfg.Webhook.URL)
	}
}
