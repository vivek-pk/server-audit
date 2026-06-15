package sender

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-scanner/internal/report"
)

func TestSendWithSignature(t *testing.T) {
	secret := "test-secret"
	var receivedSig string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Signature")
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := New(server.URL, secret, 5*time.Second, 1*time.Second, 1)
	r := report.Report{Hostname: "h1", Findings: []report.Finding{}}
	if err := s.Send(r); err != nil {
		t.Fatalf("send: %v", err)
	}

	if receivedSig == "" {
		t.Fatal("expected X-Signature header")
	}

	payload, _ := json.Marshal(r)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expectedSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	if receivedSig != expectedSig {
		t.Errorf("signature mismatch: got %s, want %s", receivedSig, expectedSig)
	}
}

func TestSendRetry(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	s := New(server.URL, "", 5*time.Second, 10*time.Millisecond, 2)
	r := report.Report{Hostname: "h1", Findings: []report.Finding{}}
	if err := s.Send(r); err != nil {
		t.Fatalf("send: %v", err)
	}
	if attempts != 2 {
		t.Errorf("attempts = %d, want 2", attempts)
	}
}
