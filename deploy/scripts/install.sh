#!/bin/bash
# install.sh — Install NetGuardia on a fresh system.
#
# Usage:
#   install.sh                          # Download from GitHub Release
#   install.sh --local /path/to/binary  # Use a pre-built local binary
#
set -euo pipefail

# ── Helpers ──────────────────────────────────────────────────────────────────
info()  { printf '\033[1;34m[INFO]\033[0m  %s\n' "$*"; }
warn()  { printf '\033[1;33m[WARN]\033[0m  %s\n' "$*"; }
fatal() { printf '\033[1;31m[FATAL]\033[0m %s\n' "$*" >&2; exit 1; }

# ── Defaults ─────────────────────────────────────────────────────────────────
LOCAL_BINARY=""
INSTALL_DIR="/opt/netguardia"
BIN_DIR="${INSTALL_DIR}/bin"
DATA_DIR="/var/lib/netguardia"
LOG_DIR="/var/log/netguardia"
SERVICE_USER="netguardia"
SERVICE_GROUP="netguardia"
GITHUB_REPO="dalaw2/NetGuardia"

# ── Parse arguments ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local)
            [[ -z "${2:-}" ]] && fatal "--local requires a path to the binary"
            LOCAL_BINARY="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--local /path/to/binary]"
            exit 0
            ;;
        *)
            fatal "Unknown argument: $1"
            ;;
    esac
done

# ── Validate local binary (if provided) ─────────────────────────────────────
if [[ -n "${LOCAL_BINARY}" ]]; then
    [[ -f "${LOCAL_BINARY}" ]] || fatal "Local binary not found: ${LOCAL_BINARY}"
    [[ -x "${LOCAL_BINARY}" ]] || fatal "Local binary is not executable: ${LOCAL_BINARY}"
    info "Using local binary: ${LOCAL_BINARY}"
fi

# ── Must be root ─────────────────────────────────────────────────────────────
[[ "$(id -u)" -eq 0 ]] || fatal "This script must be run as root"

# ── Install runtime dependencies (SQLCipher needs OpenSSL) ──────────────────
if command -v apt-get &>/dev/null; then
    info "Refreshing apt package metadata"
    DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null 2>&1 || warn "Could not refresh apt metadata"
    info "Installing runtime dependencies (libssl)"
    DEBIAN_FRONTEND=noninteractive apt-get install -y libssl3 >/dev/null 2>&1 || warn "Could not install libssl3"
elif command -v dnf &>/dev/null; then
    info "Installing runtime dependencies (openssl-libs)"
    dnf install -y openssl-libs >/dev/null 2>&1 || warn "Could not install openssl-libs"
fi

# ── Create system user ───────────────────────────────────────────────────────
if ! id "${SERVICE_USER}" &>/dev/null; then
    info "Creating system user: ${SERVICE_USER}"
    useradd --system --no-create-home --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

# ── Create directories ───────────────────────────────────────────────────────
info "Creating directories"
mkdir -p "${BIN_DIR}" "${DATA_DIR}" "${LOG_DIR}"
chown "${SERVICE_USER}:${SERVICE_GROUP}" "${DATA_DIR}" "${LOG_DIR}"

# ── Obtain the binary ────────────────────────────────────────────────────────
if [[ -n "${LOCAL_BINARY}" ]]; then
    # --local mode: skip download and checksum entirely
    info "Installing local binary to ${BIN_DIR}/net-guardia"
    install -m 0755 "${LOCAL_BINARY}" "${BIN_DIR}/net-guardia"
else
    # Download from GitHub Release
    info "Fetching latest release from GitHub (${GITHUB_REPO})"
    LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
        | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [[ -n "${LATEST_TAG}" ]] || fatal "Could not determine latest release tag"
    info "Latest release: ${LATEST_TAG}"

    DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}/net-guardia-linux-amd64"
    CHECKSUMS_URL="https://github.com/${GITHUB_REPO}/releases/download/${LATEST_TAG}/SHA256SUMS"

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "${TMPDIR}"' EXIT

    info "Downloading binary"
    curl -fSL -o "${TMPDIR}/net-guardia" "${DOWNLOAD_URL}"

    info "Downloading SHA256SUMS"
    if ! curl -fSL -o "${TMPDIR}/SHA256SUMS" "${CHECKSUMS_URL}"; then
        fatal "SHA256SUMS file not found in release — aborting"
    fi

    info "Verifying checksum"
    (cd "${TMPDIR}" && sha256sum -c SHA256SUMS)

    install -m 0755 "${TMPDIR}/net-guardia" "${BIN_DIR}/net-guardia"
fi

# ── Install systemd unit ─────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${DEPLOY_DIR}/netguardia.service" ]]; then
    info "Installing systemd unit"
    install -m 0644 "${DEPLOY_DIR}/netguardia.service" /etc/systemd/system/netguardia.service
    systemctl daemon-reload
    systemctl enable netguardia.service
else
    warn "netguardia.service not found at ${DEPLOY_DIR}/netguardia.service — skipping"
fi

# ── Install logrotate config ─────────────────────────────────────────────────
if [[ -f "${DEPLOY_DIR}/logrotate.conf" ]]; then
    info "Installing logrotate config"
    install -m 0644 "${DEPLOY_DIR}/logrotate.conf" /etc/logrotate.d/netguardia
else
    warn "logrotate.conf not found — skipping"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
info "NetGuardia installed successfully"
info "  Binary:  ${BIN_DIR}/net-guardia"
info "  Data:    ${DATA_DIR}"
info "  Logs:    ${LOG_DIR}"
info "  Service: systemctl start netguardia"
