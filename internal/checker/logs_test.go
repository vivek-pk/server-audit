package checker

import (
	"testing"

	"security-scanner/internal/report"
)

func TestExtractFailedAttempts(t *testing.T) {
	logData := `Jun 15 10:00:00 server sshd[1234]: Failed password for root from 192.168.1.100 port 54321 ssh2
Jun 15 10:01:00 server sshd[1235]: Failed password for admin from 192.168.1.100 port 54322 ssh2
Jun 15 10:02:00 server sshd[1236]: Failed password for root from 10.0.0.5 port 54323 ssh2
Jun 15 10:03:00 server sshd[1237]: authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.100`

	ips := extractFailedAttempts(logData)
	if len(ips) != 2 {
		t.Fatalf("expected 2 unique IPs, got %d", len(ips))
	}
	if ips["192.168.1.100"] != 3 {
		t.Errorf("expected 3 failures from 192.168.1.100, got %d", ips["192.168.1.100"])
	}
	if ips["10.0.0.5"] != 1 {
		t.Errorf("expected 1 failure from 10.0.0.5, got %d", ips["10.0.0.5"])
	}
}

func TestAnalyzeFailedIPs_TopOffenders(t *testing.T) {
	ips := map[string]int{
		"192.168.1.100": 15,
		"10.0.0.5":      2,
		"172.16.0.1":    7,
	}
	findings := analyzeFailedIPs(ips, "journalctl")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityHigh {
		t.Errorf("expected HIGH severity, got %s", findings[0].Severity)
	}
	if !contains(findings[0].Description, "192.168.1.100") {
		t.Error("expected 192.168.1.100 in description")
	}
	if !contains(findings[0].Description, "172.16.0.1") {
		t.Error("expected 172.16.0.1 in description")
	}
	// 10.0.0.5 should NOT be included since it only has 2 failures
	if contains(findings[0].Description, "10.0.0.5") {
		t.Error("10.0.0.5 should not be listed as top offender (only 2 failures)")
	}
}

func TestAnalyzeFailedIPs_Medium(t *testing.T) {
	ips := map[string]int{
		"192.168.1.10": 2,
		"192.168.1.11": 2,
		"192.168.1.12": 2,
	}
	findings := analyzeFailedIPs(ips, "auth.log")

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != report.SeverityMedium {
		t.Errorf("expected MEDIUM severity, got %s", findings[0].Severity)
	}
}

func TestExtractSuccessfulLogins(t *testing.T) {
	logData := `Jun 15 10:00:00 server sshd[1234]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2
Jun 15 10:01:00 server sshd[1235]: Accepted password for root from 10.0.0.1 port 54322 ssh2
Jun 15 10:02:00 server sshd[1236]: Accepted publickey for bob from 192.168.1.50 port 54323 ssh2`

	attempts := extractSuccessfulLogins(logData)
	if len(attempts) != 3 {
		t.Fatalf("expected 3 successful logins, got %d", len(attempts))
	}

	if attempts[0].user != "alice" || attempts[0].method != "publickey" || attempts[0].ip != "192.168.1.50" {
		t.Errorf("unexpected attempt[0]: %+v", attempts[0])
	}
	if attempts[1].user != "root" || attempts[1].method != "password" || attempts[1].ip != "10.0.0.1" {
		t.Errorf("unexpected attempt[1]: %+v", attempts[1])
	}
}

func TestAnalyzeSuccessfulLogins_Root(t *testing.T) {
	successes := []loginAttempt{
		{user: "root", ip: "10.0.0.1", method: "publickey"},
	}
	findings := analyzeSuccessfulLogins(successes, nil)

	foundRoot := false
	for _, f := range findings {
		if f.Title == "Root login successful" {
			foundRoot = true
			if f.Severity != report.SeverityCritical {
				t.Errorf("expected CRITICAL for root login, got %s", f.Severity)
			}
		}
	}
	if !foundRoot {
		t.Error("expected root login finding")
	}
}

func TestAnalyzeSuccessfulLogins_Password(t *testing.T) {
	successes := []loginAttempt{
		{user: "admin", ip: "10.0.0.5", method: "password"},
	}
	findings := analyzeSuccessfulLogins(successes, nil)

	foundPassword := false
	for _, f := range findings {
		if f.Title == "Password-based login successful" {
			foundPassword = true
			if f.Severity != report.SeverityHigh {
				t.Errorf("expected HIGH for password login, got %s", f.Severity)
			}
		}
	}
	if !foundPassword {
		t.Error("expected password login finding")
	}
}

func TestAnalyzeSuccessfulLogins_BruteForceSuccess(t *testing.T) {
	successes := []loginAttempt{
		{user: "admin", ip: "192.168.1.100", method: "password"},
	}
	failedIPs := map[string]int{
		"192.168.1.100": 10,
	}
	findings := analyzeSuccessfulLogins(successes, failedIPs)

	foundBrute := false
	for _, f := range findings {
		if f.Title == "Possible brute force success" {
			foundBrute = true
			if f.Severity != report.SeverityCritical {
				t.Errorf("expected CRITICAL for brute force success, got %s", f.Severity)
			}
		}
	}
	if !foundBrute {
		t.Error("expected brute force success finding")
	}
}

func TestAnalyzeSuccessfulLogins_NoCorrelation(t *testing.T) {
	successes := []loginAttempt{
		{user: "admin", ip: "192.168.1.100", method: "password"},
	}
	failedIPs := map[string]int{
		"192.168.1.100": 2,
	}
	findings := analyzeSuccessfulLogins(successes, failedIPs)

	for _, f := range findings {
		if f.Title == "Possible brute force success" {
			t.Error("should NOT flag brute force success with only 2 prior failures")
		}
	}
}

func contains(s, substr string) bool {
	return len(substr) <= len(s) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
