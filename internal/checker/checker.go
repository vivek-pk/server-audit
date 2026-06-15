package checker

import (
	"context"

	"security-scanner/internal/config"
	"security-scanner/internal/report"
)

// Checker is the interface implemented by all security checkers.
type Checker interface {
	Name() string
	Run(ctx context.Context) ([]report.Finding, error)
}

// Registry holds all available checkers.
func Registry() []Checker {
	return []Checker{
		&KernelChecker{},
		&UserChecker{},
		&PermissionChecker{},
		&SSHChecker{},
		&FirewallChecker{},
		&LogChecker{},
		&FilesystemChecker{},
		&ContainerChecker{},
	}
}

// FilterEnabled returns only the checkers enabled in the config.
func FilterEnabled(all []Checker, enabled map[string]bool) []Checker {
	var out []Checker
	for _, c := range all {
		if enabled[c.Name()] {
			out = append(out, c)
		}
	}
	return out
}

// EnabledFromConfig converts config.ChecksConfig into the map used by FilterEnabled.
func EnabledFromConfig(cfg config.ChecksConfig) map[string]bool {
	return map[string]bool{
		"kernel":      cfg.Kernel,
		"users":       cfg.Users,
		"permissions": cfg.Permissions,
		"ssh":         cfg.SSH,
		"firewall":    cfg.Firewall,
		"logs":        cfg.Logs,
		"filesystem":  cfg.Filesystem,
		"containers":  cfg.Containers,
	}
}
