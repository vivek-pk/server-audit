package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"security-scanner/internal/config"
	"security-scanner/internal/scheduler"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "", "Path to configuration file")
	flag.Parse()

	if configPath == "" {
		configPath = os.Getenv("SECURITY_SCANNER_CONFIG")
	}
	if configPath == "" {
		for _, p := range []string{"/etc/security-scanner/config.yml", "config.yml"} {
			if _, err := os.Stat(p); err == nil {
				configPath = p
				break
			}
		}
	}
	if configPath == "" {
		fmt.Fprintln(os.Stderr, "Error: no config file specified (use --config or set SECURITY_SCANNER_CONFIG)")
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("failed to load config", "path", configPath, "error", err)
		os.Exit(1)
	}

	logger.Info("starting security scanner", "config", configPath)

	s, err := scheduler.New(cfg)
	if err != nil {
		logger.Error("failed to create scheduler", "error", err)
		os.Exit(1)
	}

	if err := s.Run(); err != nil {
		logger.Error("scheduler exited with error", "error", err)
		os.Exit(1)
	}
}
