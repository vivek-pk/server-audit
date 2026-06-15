package scheduler

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"security-scanner/internal/checker"
	"security-scanner/internal/config"
	"security-scanner/internal/formatter"
	"security-scanner/internal/report"
	"security-scanner/internal/sender"
)

// Scheduler orchestrates security checks and report delivery.
type Scheduler struct {
	cfg      config.Config
	checkers []checker.Checker
	sender   *sender.Sender
	logger   *slog.Logger
}

// New creates a Scheduler from the given configuration.
func New(cfg config.Config) (*Scheduler, error) {
	all := checker.Registry()
	enabled := checker.EnabledFromConfig(cfg.Checks)
	selected := checker.FilterEnabled(all, enabled)

	webhookTimeout, err := cfg.WebhookTimeout()
	if err != nil {
		return nil, fmt.Errorf("invalid webhook timeout: %w", err)
	}
	retryDelay, err := cfg.RetryBaseDelay()
	if err != nil {
		return nil, fmt.Errorf("invalid retry base delay: %w", err)
	}

	return &Scheduler{
		cfg:      cfg,
		checkers: selected,
		sender:   sender.New(cfg.Webhook.URL, cfg.Webhook.Secret, webhookTimeout, retryDelay, cfg.Webhook.MaxRetries),
		logger:   slog.Default(),
	}, nil
}

// Run starts the scheduler loop and blocks until a signal is received.
func (s *Scheduler) Run() error {
	interval, err := s.cfg.ParseInterval()
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}
	timeout, err := s.cfg.ParseTimeout()
	if err != nil {
		return fmt.Errorf("invalid timeout: %w", err)
	}

	// Run immediately on startup
	if err := s.tick(timeout); err != nil {
		s.logger.Error("initial scan failed", "error", err)
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				s.logger.Info("received SIGHUP, config reload not yet implemented")
			case syscall.SIGINT, syscall.SIGTERM:
				s.logger.Info("shutting down")
				return nil
			}
		case <-ticker.C:
			if err := s.tick(timeout); err != nil {
				s.logger.Error("scan failed", "error", err)
			}
		}
	}
}

func (s *Scheduler) tick(timeout time.Duration) error {
	s.logger.Info("starting security scan")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var findings []report.Finding
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, c := range s.checkers {
		wg.Add(1)
		go func(ch checker.Checker) {
			defer wg.Done()
			res, err := ch.Run(ctx)
			if err != nil {
				s.logger.Error("checker failed", "checker", ch.Name(), "error", err)
				mu.Lock()
				findings = append(findings, report.Finding{
					CheckType:   ch.Name(),
					Severity:    report.SeverityInfo,
					Title:       ch.Name() + " check failed",
					Description: err.Error(),
					Remediation: "Check system compatibility and permissions.",
				})
				mu.Unlock()
				return
			}
			mu.Lock()
			findings = append(findings, res...)
			mu.Unlock()
		}(c)
	}

	wg.Wait()

	r, err := formatter.NewReport(findings)
	if err != nil {
		return fmt.Errorf("creating report: %w", err)
	}

	data, err := formatter.FormatReport(r)
	if err != nil {
		return fmt.Errorf("formatting report: %w", err)
	}
	s.logger.Debug("report generated", "findings", len(findings))
	_ = data

	if err := s.sender.Send(r); err != nil {
		return fmt.Errorf("sending report: %w", err)
	}
	s.logger.Info("scan complete", "findings", len(findings))
	return nil
}
