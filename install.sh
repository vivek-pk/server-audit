#!/usr/bin/env bash
set -euo pipefail

# Security Scanner Installer Script
# Usage: curl -fsSL https://example.com/install.sh | sudo bash
#        or: curl -fsSL https://example.com/install.sh | bash

BINARY_NAME="security-scanner"
INSTALL_PATH="/usr/local/bin"
CONFIG_DIR="/etc/security-scanner"
SERVICE_DIR="/etc/systemd/system"
SERVICE_NAME="security-scanner.service"

# GitHub repo (change these to your actual repo)
GITHUB_OWNER="vivek-pk"
GITHUB_REPO="server-audit"
GITHUB_RELEASE="latest"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root or with sufficient privileges
check_privileges() {
    if [[ $EUID -ne 0 ]]; then
        if command -v sudo >/dev/null 2>&1; then
            log_warn "This script needs root privileges. Re-running with sudo..."
            exec sudo bash "$0" "$@"
        else
            log_error "This script must be run as root or with sudo."
            exit 1
        fi
    fi
}

# Detect OS and architecture
detect_platform() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        i386|i686) ARCH="386" ;;
        armv7l) ARCH="arm" ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac

    case "$OS" in
        linux) ;;
        *)
            log_error "Unsupported OS: $OS. This tool is designed for Linux servers."
            exit 1
            ;;
    esac

    log_info "Detected platform: $OS/$ARCH"
}

# Download file with curl or wget
download() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$output" "$url"
    else
        log_error "Neither curl nor wget is installed."
        exit 1
    fi
}

# Try to download pre-built binary from GitHub releases using the /latest/download/ redirect URL.
download_binary() {
    local binary_url="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"
    local tmp_binary="/tmp/${BINARY_NAME}"

    log_info "Attempting to download pre-built binary..."
    log_info "URL: $binary_url"

    if download "$binary_url" "$tmp_binary" 2>/dev/null; then
        chmod +x "$tmp_binary"
        PREBUILT_BINARY="$tmp_binary"
        log_success "Downloaded pre-built binary."
        return 0
    else
        log_warn "Pre-built binary not found. Will build from source."
        return 1
    fi
}

# Build from source
build_from_source() {
    log_info "Building from source..."

    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is not installed and no pre-built binary was found."
        log_info "Install Go first, or provide a pre-built binary."
        exit 1
    fi

    local go_version
    go_version=$(go version | awk '{print $3}' | sed 's/go//')
    log_info "Go version: $go_version"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    log_info "Cloning repository..."
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 "https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}.git" "$tmpdir/repo" 2>/dev/null || true
    fi

    # If git clone failed, try to find source locally or download tarball
    if [[ ! -d "$tmpdir/repo/cmd" ]]; then
        log_info "Attempting to download source tarball..."
        local tarball_url="https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/archive/refs/heads/main.tar.gz"
        if download "$tarball_url" "$tmpdir/source.tar.gz" 2>/dev/null; then
            tar -xzf "$tmpdir/source.tar.gz" -C "$tmpdir"
            local extracted_dir
            extracted_dir=$(find "$tmpdir" -maxdepth 1 -type d | tail -n 1)
            cp -r "$extracted_dir""/.repo" "$tmpdir/repo" 2>/dev/null || mv "$extracted_dir" "$tmpdir/repo"
        fi
    fi

    # If we still don't have source, check if we're running from within the source tree
    if [[ ! -d "$tmpdir/repo/cmd" ]]; then
        local script_dir
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
        if [[ -d "$script_dir/cmd/scanner" ]]; then
            log_info "Using local source directory: $script_dir"
            cp -r "$script_dir/." "$tmpdir/repo"
        fi
    fi

    if [[ ! -d "$tmpdir/repo/cmd/scanner" ]]; then
        log_error "Could not locate source code. Cannot build."
        exit 1
    fi

    cd "$tmpdir/repo"
    go mod download 2>/dev/null || true
    go build -ldflags="-s -w" -o "${tmpdir}/${BINARY_NAME}" ./cmd/scanner

    if [[ ! -f "${tmpdir}/${BINARY_NAME}" ]]; then
        log_error "Build failed."
        exit 1
    fi

    PREBUILT_BINARY="${tmpdir}/${BINARY_NAME}"
    log_success "Built binary successfully."
}

# Prompt for webhook configuration
prompt_webhook_config() {
    echo ""
    log_info "Webhook Configuration"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    # Default webhook URL
    local default_url="https://hooks.example.com/security"
    read -rp "Webhook URL [$default_url]: " webhook_url
    webhook_url="${webhook_url:-$default_url}"

    # Check interval
    local default_interval="1h"
    read -rp "Scan interval [$default_interval]: " interval
    interval="${interval:-$default_interval}"

    # Secret
    read -rsp "Webhook secret for HMAC signature (optional, press Enter to skip): " webhook_secret
    echo ""

    # Timeout
    local default_timeout="30s"
    read -rp "Webhook timeout [$default_timeout]: " timeout
    timeout="${timeout:-$default_timeout}"

    # Which checks to enable
    echo ""
    log_info "Which checks should be enabled? (all are enabled by default)"

    local check_kernel="true"
    local check_users="true"
    local check_permissions="true"
    local check_ssh="true"
    local check_firewall="true"
    local check_logs="true"
    local check_filesystem="true"
    local check_containers="true"

    read -rp "Enable kernel checks? [Y/n]: " ans
    [[ "${ans:-Y}" =~ ^[Nn]$ ]] && check_kernel="false"

    read -rp "Enable user checks? [Y/n]: " ans
    [[ "${ans:-Y}" =~ ^[Nn]$ ]] && check_users="false"

    read -rp "Enable SSH checks? [Y/n]: " ans
    [[ "${ans:-Y}" =~ ^[Nn]$ ]] && check_ssh="false"

    read -rp "Enable firewall checks? [Y/n]: " ans
    [[ "${ans:-Y}" =~ ^[Nn]$ ]] && check_firewall="false"

    read -rp "Enable container checks? [Y/n]: " ans
    [[ "${ans:-Y}" =~ ^[Nn]$ ]] && check_containers="false"

    # Write config
    mkdir -p "$CONFIG_DIR"
    cat > "${CONFIG_DIR}/config.yml" <<EOF
interval: "${interval}"
timeout_per_check: "30s"

webhook:
  url: "${webhook_url}"
  timeout: "${timeout}"
  secret: "${webhook_secret}"
  max_retries: 3
  retry_base_delay: "5s"

checks:
  kernel: ${check_kernel}
  users: ${check_users}
  permissions: ${check_permissions}
  ssh: ${check_ssh}
  firewall: ${check_firewall}
  logs: ${check_logs}
  filesystem: ${check_filesystem}
  containers: ${check_containers}
EOF

    chmod 600 "${CONFIG_DIR}/config.yml"
    log_success "Configuration written to ${CONFIG_DIR}/config.yml"
}

# Install systemd service
install_service() {
    log_info "Installing systemd service..."

    cat > "${SERVICE_DIR}/${SERVICE_NAME}" <<EOF
[Unit]
Description=Linux Security Scanner Daemon
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_PATH}/${BINARY_NAME} --config ${CONFIG_DIR}/config.yml
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    log_success "Systemd service installed and enabled."
}

# Start the service
start_service() {
    log_info "Starting security scanner daemon..."
    systemctl start "$SERVICE_NAME"

    sleep 2

    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_success "Service is running!"
    else
        log_error "Service failed to start. Check logs:"
        echo "  journalctl -u ${SERVICE_NAME} --no-pager -n 50"
        exit 1
    fi
}

# Print usage info
print_usage() {
    echo ""
    log_info "Installation complete. Useful commands:"
    echo ""
    echo "  Check status:     systemctl status ${SERVICE_NAME}"
    echo "  View logs:        journalctl -u ${SERVICE_NAME} -f"
    echo "  Restart:          systemctl restart ${SERVICE_NAME}"
    echo "  Edit config:      nano ${CONFIG_DIR}/config.yml"
    echo "  Uninstall:        ${INSTALL_PATH}/${BINARY_NAME} is not directly uninstallable via script yet; stop with: systemctl stop ${SERVICE_NAME}"
    echo ""
    log_info "The scanner will send reports to: $(grep -A1 'url:' ${CONFIG_DIR}/config.yml | tail -n1 | awk '{print $2}')"
    echo ""
}

cleanup_old() {
    log_info "Cleaning up old installation if present..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    rm -f "${INSTALL_PATH}/${BINARY_NAME}"
    rm -f "${SERVICE_DIR}/${SERVICE_NAME}"
    systemctl daemon-reload 2>/dev/null || true
}

main() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Linux Security Scanner Installer"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    # Check if the user passed --help
    if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        echo "Usage: curl -fsSL <url> | sudo bash"
        echo ""
        echo "Options:"
        echo "  --local       Build from local source instead of downloading"
        exit 0
    fi

    check_privileges
    detect_platform

    # Check for local build flag or if we cannot download
    local build_local=false
    if [[ "${1:-}" == "--local" ]]; then
        build_local=true
    fi

    cleanup_old

    if [[ "$build_local" == "false" ]]; then
        if ! download_binary; then
            build_from_source
        fi
    else
        build_from_source
    fi

    # Install binary
    install -Dm755 "$PREBUILT_BINARY" "${INSTALL_PATH}/${BINARY_NAME}"
    log_success "Binary installed to ${INSTALL_PATH}/${BINARY_NAME}"

    # Prompt for config
    prompt_webhook_config

    # Install and start service
    install_service
    start_service

    print_usage
}

main "$@"
