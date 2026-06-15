package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds the complete application configuration.
type Config struct {
	Interval        string        `yaml:"interval"`
	TimeoutPerCheck string        `yaml:"timeout_per_check"`
	Webhook         WebhookConfig `yaml:"webhook"`
	Checks          ChecksConfig  `yaml:"checks"`
}

// WebhookConfig holds webhook delivery settings.
type WebhookConfig struct {
	URL            string `yaml:"url"`
	Timeout        string `yaml:"timeout"`
	Secret         string `yaml:"secret"`
	MaxRetries     int    `yaml:"max_retries"`
	RetryBaseDelay string `yaml:"retry_base_delay"`
}

// ChecksConfig toggles individual security checks.
type ChecksConfig struct {
	Kernel      bool `yaml:"kernel"`
	Users       bool `yaml:"users"`
	Permissions bool `yaml:"permissions"`
	SSH         bool `yaml:"ssh"`
	Firewall    bool `yaml:"firewall"`
	Logs        bool `yaml:"logs"`
	Filesystem  bool `yaml:"filesystem"`
	Containers  bool `yaml:"containers"`
}

// Default returns a Config with sensible defaults.
func Default() Config {
	return Config{
		Interval:        "1h",
		TimeoutPerCheck: "30s",
		Webhook: WebhookConfig{
			URL:            "",
			Timeout:        "30s",
			Secret:         "",
			MaxRetries:     3,
			RetryBaseDelay: "5s",
		},
		Checks: ChecksConfig{
			Kernel:      true,
			Users:       true,
			Permissions: true,
			SSH:         true,
			Firewall:    true,
			Logs:        true,
			Filesystem:  true,
			Containers:  true,
		},
	}
}

// Load reads configuration from the provided path.
func Load(path string) (Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("reading config file: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config file: %w", err)
	}
	return cfg, nil
}

// ParseDuration parses the interval string into a time.Duration.
func (c Config) ParseInterval() (time.Duration, error) {
	return time.ParseDuration(c.Interval)
}

// ParseTimeout parses the per-check timeout.
func (c Config) ParseTimeout() (time.Duration, error) {
	return time.ParseDuration(c.TimeoutPerCheck)
}

// WebhookTimeout parses the webhook delivery timeout.
func (c Config) WebhookTimeout() (time.Duration, error) {
	return time.ParseDuration(c.Webhook.Timeout)
}

// RetryBaseDelay parses the retry base delay.
func (c Config) RetryBaseDelay() (time.Duration, error) {
	return time.ParseDuration(c.Webhook.RetryBaseDelay)
}
