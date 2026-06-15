package sender

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"security-scanner/internal/report"
)

// Sender delivers reports to a webhook endpoint.
type Sender struct {
	URL            string
	Secret         string
	Timeout        time.Duration
	MaxRetries     int
	RetryBaseDelay time.Duration
}

// New creates a Sender from configuration values.
func New(url, secret string, timeout, retryBaseDelay time.Duration, maxRetries int) *Sender {
	return &Sender{
		URL:            url,
		Secret:         secret,
		Timeout:        timeout,
		MaxRetries:     maxRetries,
		RetryBaseDelay: retryBaseDelay,
	}
}

// Send delivers the report to the configured webhook.
func (s *Sender) Send(r report.Report) error {
	if s.URL == "" {
		return fmt.Errorf("webhook URL is empty")
	}

	payload, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt <= s.MaxRetries; attempt++ {
		if attempt > 0 {
			delay := s.RetryBaseDelay * time.Duration(1<<attempt)
			time.Sleep(delay)
		}

		lastErr = s.trySend(payload)
		if lastErr == nil {
			return nil
		}
	}
	return fmt.Errorf("webhook delivery failed after %d retries: %w", s.MaxRetries, lastErr)
}

func (s *Sender) trySend(payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if s.Secret != "" {
		sig := hmacSHA256(payload, s.Secret)
		req.Header.Set("X-Signature", "sha256="+sig)
	}

	client := &http.Client{Timeout: s.Timeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 || resp.StatusCode == 429 {
		return fmt.Errorf("server error %d", resp.StatusCode)
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("client error %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func hmacSHA256(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
