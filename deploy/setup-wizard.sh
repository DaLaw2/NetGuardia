#!/usr/bin/env bash
#
# NetGuardia Interactive Setup Wizard
# Uses whiptail (falls back to dialog) for interactive configuration.
#
set -euo pipefail

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
readonly LOG_DIR="/var/log/netguardia"
readonly LOG_FILE="${LOG_DIR}/setup.log"
readonly CONFIG_DIR="/opt/netguardia"
readonly CONFIG_FILE="${CONFIG_DIR}/config.toml"
readonly PASSWORD_FLAG="${CONFIG_DIR}/.admin_password_set"
readonly BACKTITLE="NetGuardia Setup Wizard"

DIALOG=""
INGRESS_NIC=""
EGRESS_NIC=""
NET_MODE=""
STATIC_IP=""
STATIC_MASK=""
STATIC_GW=""
ADMIN_PASS=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${ts}] $*" >> "${LOG_FILE}"
}

die() {
    log "FATAL: $*"
    if [[ -n "${DIALOG}" ]]; then
        "${DIALOG}" --backtitle "${BACKTITLE}" --title "Error" \
            --msgbox "Setup failed:\n\n$*\n\nSee ${LOG_FILE} for details." 12 60
    else
        echo "FATAL: $*" >&2
    fi
    exit 1
}

ensure_root() {
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This script must be run as root."
    fi
}

init_logging() {
    mkdir -p "${LOG_DIR}"
    touch "${LOG_FILE}"
    chmod 0640 "${LOG_FILE}"
    log "=== NetGuardia setup wizard started ==="
}

detect_dialog() {
    if command -v whiptail &>/dev/null; then
        DIALOG="whiptail"
    elif command -v dialog &>/dev/null; then
        DIALOG="dialog"
    else
        die "Neither whiptail nor dialog is installed. Install whiptail and retry."
    fi
    log "Using dialog frontend: ${DIALOG}"
}

# ---------------------------------------------------------------------------
# Step 1 & 2: Detect and select NICs
# ---------------------------------------------------------------------------
get_interfaces() {
    local -a ifaces=()
    for iface in /sys/class/net/*; do
        local name
        name="$(basename "${iface}")"
        [[ "${name}" == "lo" ]] && continue
        ifaces+=("${name}")
    done

    if [[ ${#ifaces[@]} -lt 2 ]]; then
        die "At least 2 network interfaces are required (found ${#ifaces[@]}). Connect additional NICs and retry."
    fi

    # Build menu items: "name description"
    local -a menu_items=()
    for name in "${ifaces[@]}"; do
        local mac state
        mac="$(cat "/sys/class/net/${name}/address" 2>/dev/null || echo "unknown")"
        state="$(cat "/sys/class/net/${name}/operstate" 2>/dev/null || echo "unknown")"
        menu_items+=("${name}" "MAC=${mac}  state=${state}")
    done

    # Select ingress NIC
    INGRESS_NIC=$("${DIALOG}" --backtitle "${BACKTITLE}" \
        --title "Step 1: Select Ingress (External) NIC" \
        --menu "Choose the network interface facing the untrusted/external network:" \
        20 70 10 "${menu_items[@]}" 3>&1 1>&2 2>&3) || die "Ingress NIC selection cancelled."
    log "Ingress NIC selected: ${INGRESS_NIC}"

    # Build egress menu (exclude the chosen ingress NIC)
    local -a egress_items=()
    for ((i = 0; i < ${#menu_items[@]}; i += 2)); do
        [[ "${menu_items[i]}" == "${INGRESS_NIC}" ]] && continue
        egress_items+=("${menu_items[i]}" "${menu_items[i+1]}")
    done

    EGRESS_NIC=$("${DIALOG}" --backtitle "${BACKTITLE}" \
        --title "Step 2: Select Egress (Internal) NIC" \
        --menu "Choose the network interface facing the trusted/internal network:" \
        20 70 10 "${egress_items[@]}" 3>&1 1>&2 2>&3) || die "Egress NIC selection cancelled."
    log "Egress NIC selected: ${EGRESS_NIC}"
}

# ---------------------------------------------------------------------------
# Step 3: Configure network mode
# ---------------------------------------------------------------------------
configure_network() {
    NET_MODE=$("${DIALOG}" --backtitle "${BACKTITLE}" \
        --title "Step 3: Network Configuration" \
        --menu "How should the management IP be configured?" \
        12 60 2 \
        "dhcp"   "Automatic (DHCP)" \
        "static" "Manual (Static IP)" \
        3>&1 1>&2 2>&3) || die "Network configuration cancelled."

    log "Network mode: ${NET_MODE}"

    if [[ "${NET_MODE}" == "static" ]]; then
        STATIC_IP=$("${DIALOG}" --backtitle "${BACKTITLE}" \
            --title "Static IP Address" \
            --inputbox "Enter the management IP address (e.g. 192.168.1.10):" \
            10 60 "" 3>&1 1>&2 2>&3) || die "Static IP entry cancelled."

        STATIC_MASK=$("${DIALOG}" --backtitle "${BACKTITLE}" \
            --title "Subnet Mask" \
            --inputbox "Enter the subnet prefix length (e.g. 24):" \
            10 60 "24" 3>&1 1>&2 2>&3) || die "Subnet mask entry cancelled."

        STATIC_GW=$("${DIALOG}" --backtitle "${BACKTITLE}" \
            --title "Default Gateway" \
            --inputbox "Enter the default gateway (e.g. 192.168.1.1):" \
            10 60 "" 3>&1 1>&2 2>&3) || die "Gateway entry cancelled."

        log "Static config: ip=${STATIC_IP}/${STATIC_MASK} gw=${STATIC_GW}"
    fi
}

# ---------------------------------------------------------------------------
# Step 4: Set admin password flag
# ---------------------------------------------------------------------------
set_admin_password() {
    while true; do
        ADMIN_PASS=$("${DIALOG}" --backtitle "${BACKTITLE}" \
            --title "Step 4: Admin Password" \
            --passwordbox "Set the initial admin password (min 8 characters):" \
            10 60 "" 3>&1 1>&2 2>&3) || die "Password entry cancelled."

        if [[ ${#ADMIN_PASS} -lt 8 ]]; then
            "${DIALOG}" --backtitle "${BACKTITLE}" --title "Invalid Password" \
                --msgbox "Password must be at least 8 characters. Please try again." 8 50
            continue
        fi

        local confirm
        confirm=$("${DIALOG}" --backtitle "${BACKTITLE}" \
            --title "Confirm Password" \
            --passwordbox "Re-enter the admin password:" \
            10 60 "" 3>&1 1>&2 2>&3) || die "Password confirmation cancelled."

        if [[ "${ADMIN_PASS}" != "${confirm}" ]]; then
            "${DIALOG}" --backtitle "${BACKTITLE}" --title "Mismatch" \
                --msgbox "Passwords do not match. Please try again." 8 50
            continue
        fi

        break
    done

    # Write flag file; actual password is set on first web login.
    echo "password_pending" > "${PASSWORD_FLAG}"
    chmod 0600 "${PASSWORD_FLAG}"
    log "Admin password flag written to ${PASSWORD_FLAG}"
}

# ---------------------------------------------------------------------------
# Step 5: Generate config.toml
# ---------------------------------------------------------------------------
generate_config() {
    log "Generating ${CONFIG_FILE}"
    mkdir -p "${CONFIG_DIR}"

    local bind_port=8080

    cat > "${CONFIG_FILE}" <<TOML
[Http]
http_server_bind_port = ${bind_port}
jwt_expiry_hours = 24

[Network]
ingress_ifname = "${INGRESS_NIC}"
egress_ifname = "${EGRESS_NIC}"
combined_queue_count = 16
channel_size = 4096
fill_queue_size = 4096
comp_queue_size = 4096
tx_queue_size = 4096
rx_queue_size = 4096
frame_size = 4096
frame_count = 4096
refresh_interval = 5

[Inference]
deep_autoencoder_name = "deep_autoencoder.onnx"
classifier_name = "classifier.onnx"
models_config_name = "inference_config.json"
max_concurrent_flows = 10000
min_packets_for_inference = 5
inference_interval_secs = 5
aggregator_window_secs = 30
inference_batch_size = 200
traffic_logging_mode = true
traffic_log_csv_path = "traffic_log.csv"

[Misc]
geoip_db_name = "net-guardia/static/geo/GeoLite2-City.mmdb"
database_path = "net-guardia.db"
license_file = "license.key"

[Pipeline]
ingress = ["access_control", "rate_limit", "service"]
egress = []
TOML

    # Append static network config as a comment block for reference
    if [[ "${NET_MODE}" == "static" ]]; then
        cat >> "${CONFIG_FILE}" <<TOML

# Management network (static)
# ip   = "${STATIC_IP}/${STATIC_MASK}"
# gateway = "${STATIC_GW}"
TOML
    fi

    chmod 0644 "${CONFIG_FILE}"
    log "Config written to ${CONFIG_FILE}"
}

# ---------------------------------------------------------------------------
# Step 6: Start systemd service
# ---------------------------------------------------------------------------
start_service() {
    log "Enabling and starting netguardia.service"
    systemctl daemon-reload
    systemctl enable netguardia.service
    systemctl start netguardia.service

    # Brief wait then check status
    sleep 2
    if systemctl is-active --quiet netguardia.service; then
        log "netguardia.service is active"
    else
        die "netguardia.service failed to start. Check 'journalctl -u netguardia' for details."
    fi
}

# ---------------------------------------------------------------------------
# Step 7: Display dashboard URL
# ---------------------------------------------------------------------------
show_dashboard_url() {
    local mgmt_ip
    if [[ "${NET_MODE}" == "static" ]]; then
        mgmt_ip="${STATIC_IP}"
    else
        # Try to resolve the current IP on the egress interface
        mgmt_ip=$(ip -4 addr show "${EGRESS_NIC}" 2>/dev/null \
            | grep -oP 'inet \K[0-9.]+' | head -1)
        if [[ -z "${mgmt_ip}" ]]; then
            mgmt_ip="<this-host-ip>"
        fi
    fi

    local url="http://${mgmt_ip}:8080"

    "${DIALOG}" --backtitle "${BACKTITLE}" \
        --title "Setup Complete" \
        --msgbox "NetGuardia is running!\n\nDashboard: ${url}\n\nLog in with the admin account.\nYou will set your password on first login.\n\nSetup log: ${LOG_FILE}" \
        14 60

    log "Setup complete. Dashboard URL: ${url}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    ensure_root
    init_logging
    detect_dialog

    get_interfaces
    configure_network
    set_admin_password
    generate_config
    start_service
    show_dashboard_url

    log "=== NetGuardia setup wizard finished ==="
}

main "$@"
