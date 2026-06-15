# Security Scanner

A Go background daemon that periodically audits a Linux server for security misconfigurations and reports findings to a generic HTTP webhook in JSON format.

## Features

- **8 Security Check Modules:**
  - Kernel vulnerability detection
  - User & group audits (empty passwords, duplicate UIDs, sudoers)
  - File permissions (world-writable files, SUID binaries, `.ssh` permissions)
  - SSH configuration checks
  - Firewall & network rules status
  - Log anomaly detection
  - Filesystem integrity (mount options, encryption)
  - Container security (Docker socket, privileged containers)
- Configurable via YAML file
- Webhook delivery with optional HMAC-SHA256 signature
- Exponential backoff retry on webhook failures
- systemd service support
- Graceful shutdown on SIGINT/SIGTERM

## Build

```bash
make build
```

## Quick Install (curl | bash)

Run the interactive installer on any Linux server:

```bash
curl -fsSL https://raw.githubusercontent.com/your-org/security-scanner/main/install.sh | sudo bash
```

The installer will:
1. Download the latest pre-built binary (or build from source if needed)
2. Prompt for your webhook URL, scan interval, and which checks to enable
3. Install the systemd service
4. Start the daemon

### Install from Local Source

If you don't have a GitHub release yet:

```bash
# Clone the repo, then run the installer locally
git clone https://github.com/your-org/security-scanner.git
cd security-scanner
sudo bash install.sh --local
```

## Manual Install (Make)

```bash
# Requires root privileges
sudo make install
```

This installs:
- Binary to `/usr/local/bin/security-scanner`
- Config to `/etc/security-scanner/config.yml`
- systemd service file and enables/starts the service

## Uninstall

```bash
sudo make uninstall
```

## Configuration

Edit `/etc/security-scanner/config.yml`:

```yaml
interval: "1h"
timeout_per_check: "30s"

webhook:
  url: "https://hooks.example.com/security"
  timeout: "30s"
  secret: "your-hmac-secret"
  max_retries: 3
  retry_base_delay: "5s"

checks:
  kernel: true
  users: true
  permissions: true
  ssh: true
  firewall: true
  logs: true
  filesystem: true
  containers: true
```

## Webhook Payload Format

```json
{
  "hostname": "prod-web-01",
  "timestamp": "2026-06-15T14:30:00Z",
  "findings": [
    {
      "check_type": "users",
      "severity": "HIGH",
      "title": "Account 'backup' has empty password",
      "description": "...",
      "remediation": "..."
    }
  ]
}
```

## Testing

```bash
make test
```

## License

MIT
