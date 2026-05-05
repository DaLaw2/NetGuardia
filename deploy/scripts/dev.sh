#!/usr/bin/env bash
# Build the NetGuardia development containers and inline veth topology.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$DEPLOY_DIR/.." && pwd)"
BASE_COMPOSE_FILE="$DEPLOY_DIR/compose/podman-compose.yml"
COMPOSE_FILE="/tmp/netguardia-compose-$$.yml"
COMPOSE_PROJECT="compose"
LOG_FILE="/tmp/netguardia-dev-$(date +%Y%m%d-%H%M%S).log"

VERBOSE=0
CLEANUP_FIRST=1
RT=""
declare -a RT_CMD=()
declare -a COMPOSE_CMD=()

info() {
    printf '[INFO] %s\n' "$*"
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

fatal() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<EOF
Usage: sudo bash deploy/scripts/dev.sh [--verbose] [--no-cleanup]

Options:
  --verbose     Print compose build/up output in addition to writing the log.
  --no-cleanup  Skip the default preflight cleanup of old containers/veth links.
  -h, --help    Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --verbose)
                VERBOSE=1
                shift
                ;;
            --no-cleanup)
                CLEANUP_FIRST=0
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                fatal "Unknown argument: $1"
                ;;
        esac
    done
}

cleanup_netns_links() {
    rm -f \
        /var/run/netns/external \
        /var/run/netns/internal \
        /var/run/netns/router \
        /var/run/netns/netguardia
}

cleanup_temp_files() {
    cleanup_netns_links
    rm -f "$COMPOSE_FILE"
}

trap cleanup_temp_files EXIT

require_root() {
    [[ "$(id -u)" -eq 0 ]] || fatal "dev.sh must run as root. Use: sudo bash deploy/scripts/dev.sh"
}

require_linux_host() {
    [[ "$(uname -s)" == "Linux" ]] || fatal "dev.sh supports Linux hosts only."
    if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
        fatal "WSL2 is not supported for this XDP/AF_XDP development topology."
    fi
}

package_manager() {
    if command -v dnf >/dev/null 2>&1; then
        printf 'dnf'
    elif command -v apt-get >/dev/null 2>&1; then
        printf 'apt-get'
    elif command -v zypper >/dev/null 2>&1; then
        printf 'zypper'
    elif command -v pacman >/dev/null 2>&1; then
        printf 'pacman'
    fi
}

package_for_command() {
    local manager="$1"
    local command_name="$2"

    case "$manager:$command_name" in
        dnf:ip) printf 'iproute' ;;
        dnf:ping) printf 'iputils' ;;
        dnf:ethtool) printf 'ethtool' ;;
        dnf:curl) printf 'curl' ;;
        dnf:ln|dnf:mkdir|dnf:rm|dnf:uname) printf 'coreutils' ;;
        apt-get:ip) printf 'iproute2' ;;
        apt-get:ping) printf 'iputils-ping' ;;
        apt-get:ethtool) printf 'ethtool' ;;
        apt-get:curl) printf 'curl' ;;
        apt-get:ln|apt-get:mkdir|apt-get:rm|apt-get:uname) printf 'coreutils' ;;
        zypper:ip) printf 'iproute2' ;;
        zypper:ping) printf 'iputils' ;;
        zypper:ethtool) printf 'ethtool' ;;
        zypper:curl) printf 'curl' ;;
        zypper:ln|zypper:mkdir|zypper:rm|zypper:uname) printf 'coreutils' ;;
        pacman:ip) printf 'iproute2' ;;
        pacman:ping) printf 'iputils' ;;
        pacman:ethtool) printf 'ethtool' ;;
        pacman:curl) printf 'curl' ;;
        pacman:ln|pacman:mkdir|pacman:rm|pacman:uname) printf 'coreutils' ;;
    esac
}

append_unique() {
    local value="$1"
    shift
    local existing

    for existing in "$@"; do
        [[ "$existing" == "$value" ]] && return 1
    done
    return 0
}

install_packages() {
    local manager="$1"
    shift

    case "$manager" in
        dnf)
            dnf install -y "$@"
            ;;
        apt-get)
            DEBIAN_FRONTEND=noninteractive apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
            ;;
        zypper)
            zypper --non-interactive install "$@"
            ;;
        pacman)
            pacman -Sy --noconfirm "$@"
            ;;
        *)
            return 1
            ;;
    esac
}

manual_install_command() {
    local manager="$1"
    shift

    case "$manager" in
        dnf) printf 'dnf install -y %s\n' "$*" ;;
        apt-get) printf 'apt-get update && apt-get install -y %s\n' "$*" ;;
        zypper) printf 'zypper --non-interactive install %s\n' "$*" ;;
        pacman) printf 'pacman -Sy --noconfirm %s\n' "$*" ;;
        *) printf 'Install packages manually: %s\n' "$*" ;;
    esac
}

check_host_tools() {
    local required_commands=(ip ping ethtool curl ln mkdir rm uname)
    local missing_commands=()
    local packages=()
    local command_name manager package answer

    for command_name in "${required_commands[@]}"; do
        if ! command -v "$command_name" >/dev/null 2>&1; then
            missing_commands+=("$command_name")
        fi
    done

    if ((${#missing_commands[@]} == 0)); then
        info "Host tools OK"
        return 0
    fi

    manager="$(package_manager || true)"
    [[ -n "$manager" ]] || fatal "Missing host commands: ${missing_commands[*]}. No supported package manager found."

    for command_name in "${missing_commands[@]}"; do
        package="$(package_for_command "$manager" "$command_name")"
        [[ -n "$package" ]] || fatal "No package mapping for missing command '$command_name' on $manager."
        if append_unique "$package" "${packages[@]}"; then
            packages+=("$package")
        fi
    done

    warn "Missing host commands: ${missing_commands[*]}"
    warn "Package manager: $manager"
    warn "Packages to install: ${packages[*]}"

    if [[ ! -t 0 ]]; then
        manual_install_command "$manager" "${packages[@]}" >&2
        fatal "Non-interactive shell; refusing to install packages without consent."
    fi

    read -r -p "Install missing packages? [y/N] " answer
    case "$answer" in
        y|Y|yes|YES)
            install_packages "$manager" "${packages[@]}"
            ;;
        *)
            manual_install_command "$manager" "${packages[@]}" >&2
            fatal "Required host packages were not installed."
            ;;
    esac
}

runtime_install_hint() {
    cat >&2 <<'EOF'
Install a supported container runtime first.

Examples:
  dnf install -y podman podman-compose
  apt-get install -y podman podman-compose
  apt-get install -y docker.io docker-compose-plugin
EOF
}

check_docker_supported() {
    local context security_options operating_system

    context="$(docker context show 2>/dev/null || true)"
    if [[ "$context" == "desktop-linux" ]]; then
        fatal "Docker Desktop is not supported for this XDP/netns topology."
    fi

    operating_system="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
    if [[ "$operating_system" == *"Docker Desktop"* ]]; then
        fatal "Docker Desktop is not supported for this XDP/netns topology."
    fi

    security_options="$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)"
    if grep -qi rootless <<<"$security_options"; then
        fatal "Rootless Docker is not supported for this privileged XDP/netns topology."
    fi
}

detect_runtime() {
    if command -v podman-compose >/dev/null 2>&1 && command -v podman >/dev/null 2>&1; then
        RT="podman"
        RT_CMD=(podman)
        COMPOSE_CMD=(podman-compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE")
    elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
        check_docker_supported
        RT="docker"
        RT_CMD=(docker)
        COMPOSE_CMD=(docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE")
    else
        runtime_install_hint
        fatal "No supported runtime found. Need podman + podman-compose or docker + docker compose."
    fi

    info "Runtime: $RT"
}

generate_compose_file() {
    local yaml_deploy
    local yaml_root

    [[ -f "$BASE_COMPOSE_FILE" ]] || fatal "Compose file not found: $BASE_COMPOSE_FILE"
    yaml_deploy="${DEPLOY_DIR//\'/\'\'}"
    yaml_root="${ROOT_DIR//\'/\'\'}"

    : >"$COMPOSE_FILE"
    while IFS= read -r line; do
        case "$line" in
            "      context: ..")
                printf "      context: '%s'\n" "$yaml_deploy" >>"$COMPOSE_FILE"
                ;;
            "      - /home/dalaw2/NetGuardia:/root/NetGuardia:z")
                printf "      - '%s:/root/NetGuardia:z'\n" "$yaml_root" >>"$COMPOSE_FILE"
                ;;
            *)
                printf '%s\n' "$line" >>"$COMPOSE_FILE"
                ;;
        esac
    done <"$BASE_COMPOSE_FILE"
}

run_logged() {
    local label="$1"
    shift

    info "$label"
    if ((VERBOSE)); then
        "$@" 2>&1 | tee -a "$LOG_FILE"
    elif [[ -t 1 ]]; then
        run_with_spinner "$label" "$@"
    elif ! "$@" >>"$LOG_FILE" 2>&1; then
        warn "$label failed. Last log lines:"
        tail -n 80 "$LOG_FILE" >&2 || true
        fatal "Full log: $LOG_FILE"
    fi
}

run_with_spinner() {
    local label="$1"
    shift
    local pid status

    "$@" >>"$LOG_FILE" 2>&1 &
    pid=$!
    spinner "$pid" "$label"
    set +e
    wait "$pid"
    status=$?
    set -e
    clear_spinner_line
    if ((status != 0)); then
        warn "$label failed. Last log lines:"
        tail -n 80 "$LOG_FILE" >&2 || true
        fatal "Full log: $LOG_FILE"
    fi
}

spinner() {
    local pid="$1"
    local label="$2"
    local frames='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    local frame
    local started_at=$SECONDS

    while kill -0 "$pid" 2>/dev/null; do
        frame="${frames:i++%${#frames}:1}"
        printf '\r%s %s... %02ds' "$frame" "$label" "$((SECONDS - started_at))"
        sleep 0.12
    done
}

clear_spinner_line() {
    printf '\r\033[K'
}

runtime_rm_containers() {
    "${RT_CMD[@]}" rm -f netguardia router external internal >/dev/null 2>&1 || true
}

delete_host_link() {
    local link_name="$1"
    ip link del "$link_name" >/dev/null 2>&1 || true
}

preflight_cleanup() {
    ((CLEANUP_FIRST)) || return 0

    info "Cleaning old development topology"
    runtime_rm_containers
    cleanup_netns_links
    delete_host_link ext-eth0
    delete_host_link rtr-ext
    delete_host_link rtr-int
    delete_host_link ng-ext
    delete_host_link int-eth0
    delete_host_link ng-int
}

container_pid() {
    "${RT_CMD[@]}" inspect --format '{{.State.Pid}}' "$1"
}

link_netns() {
    local container="$1"
    local pid

    pid="$(container_pid "$container")"
    [[ -n "$pid" && "$pid" != "0" ]] || fatal "Container '$container' is not running."
    ln -sf "/proc/$pid/ns/net" "/var/run/netns/$container"
}

link_container_namespaces() {
    mkdir -p /var/run/netns
    link_netns external
    link_netns internal
    link_netns router
    link_netns netguardia
}

netns() {
    ip netns exec "$@"
}

disable_offload() {
    local namespace="$1"
    local interface="$2"

    netns "$namespace" ethtool -K "$interface" tx off rx off >/dev/null 2>&1 || true
}

create_topology() {
    info "Creating inline veth topology"

    ip link add ext-eth0 type veth peer name rtr-ext
    ip link set ext-eth0 netns external
    ip link set rtr-ext netns router

    netns external ip link set lo up
    netns external ip link set ext-eth0 up
    netns external ip addr add 10.10.1.2/24 dev ext-eth0
    for i in 3 4 5 6 7; do
        netns external ip addr add "10.10.1.$i/24" dev ext-eth0
    done
    netns external ip route replace default via 10.10.1.1

    netns router ip link set lo up
    netns router ip link set rtr-ext up
    netns router ip addr add 10.10.1.1/24 dev rtr-ext

    ip link add rtr-int type veth peer name ng-ext
    ip link set rtr-int netns router
    ip link set ng-ext netns netguardia

    ip link add int-eth0 type veth peer name ng-int
    ip link set int-eth0 netns internal
    ip link set ng-int netns netguardia

    netns router ip link set rtr-int up
    netns router ip addr add 10.10.2.1/24 dev rtr-int
    netns router sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

    netns internal ip link set lo up
    netns internal ip link set int-eth0 up
    netns internal ip addr add 10.10.2.2/24 dev int-eth0
    for i in 3 4 5 6; do
        netns internal ip addr add "10.10.2.$i/24" dev int-eth0
    done
    netns internal ip route replace default via 10.10.2.1

    netns netguardia ip link set ng-ext up
    netns netguardia ip link set ng-int up

    disable_offload router rtr-int
    disable_offload router rtr-ext
    disable_offload internal int-eth0
    disable_offload external ext-eth0
    disable_offload netguardia ng-ext
    disable_offload netguardia ng-int
}

write_interface_mapping() {
    cat >/tmp/netguardia_interfaces.txt <<'IEOF'
# NetGuardia interface mapping - realistic inline deployment
# Router handles L3 (10.10.1.0/24 <-> 10.10.2.0/24)
# NetGuardia inline on 10.10.2.0/24 (no IP, no bridge)
#   ng-ext - XDP ingress (router side, attached to rtr-int peer)
#   ng-int - XDP egress  (internal side, attached to int-eth0 peer)
# XSK forwards packets: ng-ext RX -> ng-int TX and ng-int RX -> ng-ext TX
# Management: eth0 (10.10.3.10)
IEOF
    "${RT_CMD[@]}" cp /tmp/netguardia_interfaces.txt netguardia:/root/NetGuardia/interfaces.txt >/dev/null 2>&1 || true
}

connectivity_check() {
    local external_router="FAIL"

    if netns external ping -c 1 -W 2 10.10.1.1 >/dev/null 2>&1; then
        external_router="OK"
    fi

    info "Connectivity: external -> router: $external_router"
}

print_summary() {
    cat <<EOF

NetGuardia development topology is ready.

  Mgmt:    http://<host-ip>:8080

  external (10.10.1.{2-7}) -> router -> ng-ext
  ng-ext <-> net-guardia XSK <-> ng-int
  ng-int -> internal (10.10.2.{2-6})
EOF
}

main() {
    parse_args "$@"
    require_root
    require_linux_host
    check_host_tools
    generate_compose_file
    detect_runtime
    preflight_cleanup

    : >"$LOG_FILE"
    info "Compose log: $LOG_FILE"
    run_logged "Building containers" "${COMPOSE_CMD[@]}" build
    run_logged "Starting containers" "${COMPOSE_CMD[@]}" up -d

    info "Containers running"
    "${RT_CMD[@]}" ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || "${RT_CMD[@]}" ps

    link_container_namespaces
    create_topology
    write_interface_mapping
    connectivity_check
    print_summary
}

main "$@"
