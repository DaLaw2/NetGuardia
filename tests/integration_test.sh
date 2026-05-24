#!/usr/bin/env bash
# NetGuardia eBPF end-to-end gate.
# Builds the dev topology with deploy/scripts/dev.sh, starts net-guardia,
# exercises real packet paths, and shuts the data plane down with SIGINT.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEV_SCRIPT="$ROOT_DIR/deploy/scripts/dev.sh"
NG_API="http://10.10.3.10:8080"
ADMIN_USER="admin"
ADMIN_PASSWORD="E2eAdmin20040421!"
CSRF_TOKEN=""
COOKIE_JAR="/tmp/netguardia-e2e-cookies.txt"
RUN_LOG="${RUN_LOG:-/tmp/netguardia-ebpf-e2e.log}"
START_TIMEOUT_SECS="${START_TIMEOUT_SECS:-240}"
POLL_INTERVAL_SECS=2

SUDO_PASSWORD=""
RUNTIME=""
NG_PID=""
SETUP_TOKEN=""
TOKEN=""
PASS=0
FAIL=0
declare -a FAILURES=()

read -rsp "sudo password: " SUDO_PASSWORD
echo

run_sudo() {
    printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$@"
}

detect_runtime() {
    if run_sudo podman container exists netguardia >/dev/null 2>&1; then
        RUNTIME="podman"
    elif run_sudo docker container inspect netguardia >/dev/null 2>&1; then
        RUNTIME="docker"
    elif command -v podman >/dev/null 2>&1; then
        RUNTIME="podman"
    elif command -v docker >/dev/null 2>&1; then
        RUNTIME="docker"
    else
        echo "No supported container runtime found" >&2
        return 1
    fi
}

container_exec() {
    run_sudo "$RUNTIME" exec "$@"
}

ng_exec() {
    container_exec netguardia bash -lc "$1"
}

external_exec() {
    container_exec external bash -lc "$1"
}

internal_exec() {
    container_exec internal bash -lc "$1"
}

router_exec() {
    container_exec router bash -lc "$1"
}

container_pid() {
    run_sudo "$RUNTIME" inspect --format '{{.State.Pid}}' "$1"
}

host_netns_exec() {
    local container="$1"
    shift
    local pid
    pid="$(container_pid "$container")"
    run_sudo nsenter -t "$pid" -n "$@"
}

pass() {
    echo "  PASS $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL $1"
    FAIL=$((FAIL + 1))
    FAILURES+=("$1")
}

check() {
    local name="$1"
    shift
    if "$@"; then
        pass "$name"
    else
        fail "$name"
    fi
}

api_raw() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    local auth_args=()

    if [[ -n "$TOKEN" ]]; then
        auth_args=(-b "$COOKIE_JAR")
        case "$method" in
            POST|PUT|DELETE|PATCH)
                auth_args+=(-H "X-CSRF-Token: $CSRF_TOKEN")
                ;;
        esac
    fi

    if [[ -n "$body" ]]; then
        ng_exec "curl -fsS --max-time 20 -X '$method' '${NG_API}${path}' -H 'Content-Type: application/json' ${auth_args[*]@Q} -d '$body'"
    else
        ng_exec "curl -fsS --max-time 20 -X '$method' '${NG_API}${path}' ${auth_args[*]@Q}"
    fi
}

api_expect_ok() {
    local method="$1"
    local path="$2"
    local body="${3:-}"
    api_raw "$method" "$path" "$body" >/dev/null
}

api_ignore() {
    api_expect_ok "$@" >/dev/null 2>&1 || true
}

json_field() {
    local field="$1"
    python3 -c 'import json,sys; data=json.load(sys.stdin); print(data.get(sys.argv[1], ""))' "$field"
}

drop_counter() {
    local field="$1"
    api_raw GET /api/stats/drops | json_field "$field"
}

counter_increased() {
    local field="$1"
    local before="$2"
    local after
    after="$(drop_counter "$field")"
    [[ "$after" =~ ^[0-9]+$ ]] && (( after > before ))
}

counter_unchanged() {
    local field="$1"
    local before="$2"
    local after
    after="$(drop_counter "$field")"
    [[ "$after" =~ ^[0-9]+$ ]] && (( after == before ))
}

wait_for_log() {
    local pattern="$1"
    local deadline=$((SECONDS + START_TIMEOUT_SECS))
    while (( SECONDS < deadline )); do
        if grep -q "$pattern" "$RUN_LOG" 2>/dev/null; then
            return 0
        fi
        sleep "$POLL_INTERVAL_SECS"
    done
    return 1
}

wait_for_http() {
    local deadline=$((SECONDS + START_TIMEOUT_SECS))
    while (( SECONDS < deadline )); do
        if ng_exec "curl -fsS --max-time 2 '${NG_API}/api/setup/status' >/dev/null"; then
            return 0
        fi
        sleep "$POLL_INTERVAL_SECS"
    done
    return 1
}

load_setup_token() {
    local deadline=$((SECONDS + START_TIMEOUT_SECS))
    while (( SECONDS < deadline )); do
        SETUP_TOKEN="$(sed -n 's/.*Setup token: //p' "$RUN_LOG" 2>/dev/null | tail -n 1)"
        if [[ -n "$SETUP_TOKEN" ]]; then
            return 0
        fi
        sleep "$POLL_INTERVAL_SECS"
    done
    return 1
}

find_net_guardia_pids() {
    # shellcheck disable=SC2016 # The script is evaluated inside the container.
    ng_exec 'for p in /proc/[0-9]*/cmdline; do
        cmd=$(tr "\0" " " < "$p" 2>/dev/null || true)
        case "$cmd" in
            "target/release/net-guardia "*|"target/release/net-guardia")
                pid=${p#/proc/}; echo "${pid%/cmdline}"
                ;;
        esac
    done'
}

kill_existing_net_guardia() {
    local pids
    pids="$(find_net_guardia_pids || true)"
    if [[ -n "$pids" ]]; then
        ng_exec "kill -INT $pids || true"
        sleep 3
    fi
}

detach_xdp_links() {
    ng_exec "ip link set dev ng-ext xdp off 2>/dev/null || true; ip link set dev ng-int xdp off 2>/dev/null || true"
}

remove_pinned_xsk_maps() {
    ng_exec "rm -f /sys/fs/bpf/INGRESS_XSKS_MAP /sys/fs/bpf/EGRESS_XSKS_MAP"
}

cleanup_runtime_state() {
    run_sudo rm -f "$ROOT_DIR"/net-guardia.db "$ROOT_DIR"/net-guardia.db-shm "$ROOT_DIR"/net-guardia.db-wal
    remove_pinned_xsk_maps || true
}

cleanup_api_state() {
    [[ -z "$TOKEN" ]] && return 0
    api_ignore DELETE /api/acl/ipv4/source/blacklist '"10.10.1.5:0"'
    api_ignore DELETE /api/acl/ipv4/source/whitelist '"10.10.1.5:0"'
    api_ignore DELETE /api/acl/ipv6/source/blacklist '"[fd00:1::5]:0"'
    api_ignore DELETE /api/filter/http/ipv4 '["10.10.2.2:80",["GET"]]'
    api_ignore DELETE /api/filter/ssh/ipv4 '"10.10.2.2:22"'
    api_ignore DELETE /api/filter/ssh/blacklist/ipv4 '"10.10.1.5"'
    api_ignore DELETE /api/filter/ssh/whitelist/ipv4 '"10.10.1.2"'
    api_ignore POST /api/filter/ssh/whitelist/disable
    api_ignore DELETE /api/filter/dns/blacklist '{"domains":["evil.example.com"]}'
    api_ignore DELETE /api/acl/geo/unblock '{"country_codes":["US","AU","DE","NL","GB","JP","TW"]}'
    router_exec "for ip in 8.8.8.8 8.8.4.4 1.1.1.1 9.9.9.9 80.249.99.148 51.140.0.1 133.242.0.1 1.34.0.1; do ip addr del \"\$ip/32\" dev rtr-int 2>/dev/null || true; done" || true
    api_ignore PUT /api/rate-limit/config '{"packet_rate":10000,"syn_rate":100,"udp_rate":5000,"dns_rate":200,"window_ns":1000000000}'
}

shutdown_net_guardia() {
    local pids
    local had_inner_process=0
    pids="$(find_net_guardia_pids || true)"
    if [[ -n "$pids" ]]; then
        had_inner_process=1
        ng_exec "kill -INT $pids || true"
        local deadline=$((SECONDS + 30))
        while (( SECONDS < deadline )); do
            [[ -z "$(find_net_guardia_pids || true)" ]] && break
            sleep 1
        done
    fi
    if [[ -n "$NG_PID" ]]; then
        if kill -0 "$NG_PID" 2>/dev/null; then
            kill -INT "$NG_PID" 2>/dev/null || true
            local host_deadline=$((SECONDS + 15))
            while (( SECONDS < host_deadline )); do
                kill -0 "$NG_PID" 2>/dev/null || break
                sleep 1
            done
            if kill -0 "$NG_PID" 2>/dev/null \
                && (( had_inner_process == 0 )) \
                && ! ng_exec "bpftool net show | grep -Eq 'ng-ext|ng-int|net_guardia'"
            then
                kill -TERM "$NG_PID" 2>/dev/null || true
            fi
        fi
        if kill -0 "$NG_PID" 2>/dev/null; then
            echo "  WARN net-guardia host runner still alive after SIGINT; leaving final failure to cleanup checks" >&2
        else
            wait "$NG_PID" 2>/dev/null || true
        fi
        NG_PID=""
    fi
}

assert_clean_shutdown() {
    local pids
    pids="$(find_net_guardia_pids || true)"
    [[ -z "$pids" ]] || return 1
    ! ng_exec "bpftool net show | grep -Eq 'ng-ext|ng-int|net_guardia|xdp.*id'"
}

cleanup() {
    set +e
    cleanup_api_state
    shutdown_net_guardia
    assert_clean_shutdown >/dev/null 2>&1 || true
}

trap cleanup EXIT

setup_ipv6_topology() {
    external_exec "ip -6 addr add fd00:1::2/64 dev ext-eth0 2>/dev/null || true; ip -6 addr add fd00:1::5/64 dev ext-eth0 2>/dev/null || true; ip -6 route replace default via fd00:1::1"
    router_exec "ip -6 addr add fd00:1::1/64 dev rtr-ext 2>/dev/null || true; ip -6 addr add fd00:2::1/64 dev rtr-int 2>/dev/null || true"
    host_netns_exec router sh -c "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"
    internal_exec "ip -6 addr add fd00:2::2/64 dev int-eth0 2>/dev/null || true; ip -6 route replace default via fd00:2::1"
}

start_internal_http() {
    internal_exec "ssh-keygen -A >/dev/null 2>&1 || true; /usr/sbin/sshd 2>/dev/null || true; pkill -f 'python3 -m http.server 80' 2>/dev/null || true; cd /var/www/html && nohup python3 -m http.server 80 >/tmp/ng-http.log 2>&1 &"
}

start_net_guardia() {
    : > "$RUN_LOG"
    (
        cd "$ROOT_DIR"
        printf '%s\n' "$SUDO_PASSWORD" | sudo -S -p '' "$RUNTIME" exec -i netguardia cargo run --release --bin net-guardia
    ) >"$RUN_LOG" 2>&1 &
    NG_PID=$!
}

complete_setup_if_needed() {
    local status
    status="$(ng_exec "curl -fsS --max-time 5 '${NG_API}/api/setup/status'")"
    if grep -q '"setup_complete":true' <<<"$status"; then
        return 0
    fi

    [[ -n "$SETUP_TOKEN" ]] || load_setup_token
    ng_exec "curl -fsS --max-time 20 -X POST '${NG_API}/api/setup/complete' -H 'Content-Type: application/json' -H 'X-Setup-Token: ${SETUP_TOKEN}' -d '{\"ingress_interface\":\"ng-ext\",\"egress_interface\":\"ng-int\",\"admin_password\":\"${ADMIN_PASSWORD}\",\"http_port\":8080}'" >/dev/null
    wait_for_log "Full system initialization complete"
}

login() {
    local body csrf_token
    ng_exec "rm -f '$COOKIE_JAR'"
    body="$(ng_exec "curl -fsS --max-time 20 -c '$COOKIE_JAR' -X POST '${NG_API}/api/auth/login' -H 'Content-Type: application/json' -d '{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASSWORD}\"}'")"
    csrf_token="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("csrf_token", ""))' <<<"$body")"
    [[ -n "$csrf_token" ]]
    CSRF_TOKEN="$csrf_token"
    TOKEN="cookie-session"
}

scapy_send_ipv4_options_tcp() {
    external_exec "python3 - <<'PY'
from scapy.all import IP, TCP, Raw, send, conf
conf.verb = 0
pkt = IP(src='10.10.1.2', dst='10.10.2.2', options=b'\x01\x01\x00\x00')/TCP(sport=45678, dport=80, flags='PA')/Raw(b'GET / HTTP/1.0\r\n\r\n')
send(pkt, count=3, inter=0.05)
PY"
}

scapy_send_invalid_ipv4() {
    internal_exec "python3 - <<'PY'
from scapy.all import Ether, sendp, conf
conf.verb = 0
# Ethernet + IPv4 version/IHL byte with invalid IHL=4, sent directly into ng-int.
pkt = Ether(type=0x0800) / bytes([0x44,0,0,20,0,0,0,0,64,6,0,0,10,10,1,2,10,10,2,2])
sendp(pkt, iface='int-eth0', count=3, inter=0.05)
PY"
}

tcp_connect_from_external() {
    local src_ip="$1"
    local dst="$2"
    external_exec "timeout 5 curl -fsS --interface '$src_ip' '$dst' >/dev/null"
}

ping4_from_external() {
    local src_ip="$1"
    local dst_ip="$2"
    external_exec "ping -c 2 -W 3 -I '$src_ip' '$dst_ip' >/dev/null 2>&1"
}

ping6_from_external() {
    local src_ip="$1"
    local dst_ip="$2"
    external_exec "ping -6 -c 2 -W 3 -I '$src_ip' '$dst_ip' >/dev/null 2>&1"
}

expect_blocked() {
    if "$@"; then
        return 1
    fi
    return 0
}

send_burst() {
    local kind="$1"
    external_exec "python3 - '$kind' <<'PY'
import sys
from scapy.all import IP, ICMP, TCP, UDP, DNS, DNSQR, send, conf
conf.verb = 0
kind = sys.argv[1]
if kind == 'packet':
    pkt = IP(src='10.10.1.5', dst='10.10.2.2')/ICMP()
elif kind == 'syn':
    pkt = IP(src='10.10.1.5', dst='10.10.2.2')/TCP(sport=41000, dport=22, flags='S')
elif kind == 'udp':
    pkt = IP(src='10.10.1.5', dst='10.10.2.2')/UDP(sport=41000, dport=9999)/b'x'
elif kind == 'dns':
    pkt = IP(src='10.10.1.5', dst='10.10.2.2')/UDP(sport=41000, dport=53)/DNS(rd=1, qd=DNSQR(qname='rate.example.com'))
else:
    raise SystemExit(2)
send(pkt, count=20, inter=0.01)
PY"
}

send_dns_query() {
    local domain="$1"
    external_exec "python3 - '$domain' <<'PY'
import sys
from scapy.all import IP, UDP, DNS, DNSQR, send, conf
conf.verb = 0
domain = sys.argv[1]
pkt = IP(src='10.10.1.5', dst='10.10.2.2')/UDP(sport=53000, dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
send(pkt, count=5, inter=0.05)
PY"
}

send_geo_packet() {
    local source_ip="$1"
    router_exec "ip addr add '$source_ip/32' dev rtr-int 2>/dev/null || true; ping -c 5 -W 1 -I '$source_ip' 10.10.2.2 >/dev/null 2>&1 || true"
}

geo_block_prefixes() {
    local country="$1"
    local response
    response="$(api_raw PUT /api/acl/geo/block '{"country_codes":["'"$country"'"]}')"
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("total_prefixes", 0))' <<<"$response"
}

geo_unblock_country() {
    local country="$1"
    api_expect_ok DELETE /api/acl/geo/unblock '{"country_codes":["'"$country"'"]}'
}

geo_block_counter_increases() {
    local candidate country source_ip prefixes before
    local candidates=(
        "US 8.8.8.8"
        "US 8.8.4.4"
        "AU 1.1.1.1"
        "DE 9.9.9.9"
        "NL 80.249.99.148"
        "GB 51.140.0.1"
        "JP 133.242.0.1"
        "TW 1.34.0.1"
    )

    for candidate in "${candidates[@]}"; do
        country="${candidate%% *}"
        source_ip="${candidate#* }"
        geo_unblock_country "$country" >/dev/null 2>&1 || true
        if ! prefixes="$(geo_block_prefixes "$country" 2>/dev/null)"; then
            geo_unblock_country "$country" >/dev/null 2>&1 || true
            continue
        fi
        if ! [[ "$prefixes" =~ ^[0-9]+$ ]] || (( prefixes == 0 )); then
            geo_unblock_country "$country" >/dev/null 2>&1 || true
            continue
        fi

        before="$(drop_counter geo_block)"
        send_geo_packet "$source_ip"
        sleep 1
        if counter_increased geo_block "$before"; then
            geo_unblock_country "$country" >/dev/null 2>&1 || true
            return 0
        fi
        geo_unblock_country "$country" >/dev/null 2>&1 || true
    done

    return 1
}

run_rate_limit_case() {
    local name="$1"
    local field="$2"
    local config="$3"
    local burst_kind="$4"
    local before
    before="$(drop_counter "$field")"
    api_expect_ok PUT /api/rate-limit/config "$config"
    sleep 1
    send_burst "$burst_kind"
    sleep 1
    check "$name" counter_increased "$field" "$before"
    api_expect_ok PUT /api/rate-limit/config '{"packet_rate":10000,"syn_rate":100,"udp_rate":5000,"dns_rate":200,"window_ns":1000000000}'
}

echo "=========================================="
echo "  NetGuardia eBPF E2E Gate"
echo "=========================================="

echo "--- Environment setup ---"
run_sudo "$DEV_SCRIPT"
detect_runtime
kill_existing_net_guardia
detach_xdp_links
cleanup_runtime_state
setup_ipv6_topology
start_internal_http

echo "--- Starting net-guardia ---"
start_net_guardia
check "setup/status becomes reachable" wait_for_http
check "setup completion starts full system" complete_setup_if_needed
check "ng-ext XDP attach logged" wait_for_log "XDP attached to ng-ext"
check "ng-int XDP attach logged" wait_for_log "XDP attached to ng-int"
check "XSK queue starts" wait_for_log "Queue pair 0 started successfully"
check "full system initialized" wait_for_log "Full system initialization complete"
check "login succeeds" login

echo "--- XSK forwarding ---"
check "IPv4 external to internal ICMP" ping4_from_external 10.10.1.2 10.10.2.2
check "IPv4 internal to external ICMP" internal_exec "ping -c 2 -W 3 10.10.1.2 >/dev/null 2>&1"
check "IPv4 external to internal HTTP" tcp_connect_from_external 10.10.1.2 http://10.10.2.2/
check "IPv6 external to internal ICMP" ping6_from_external fd00:1::2 fd00:2::2

echo "--- Parser packet path ---"
check "IPv4 IHL=6 TCP packet path does not detach" scapy_send_ipv4_options_tcp
sleep 1
check "Invalid IPv4 packet does not detach XDP" scapy_send_invalid_ipv4
check "XDP links remain attached after parser probes" ng_exec "bpftool net show | grep -Eq 'ng-ext|ng-int'"

echo "--- ACL ---"
acl_before="$(drop_counter acl_blacklist)"
api_expect_ok PUT /api/acl/ipv4/source/blacklist '"10.10.1.5:0"'
check "IPv4 source blacklist drops traffic" expect_blocked ping4_from_external 10.10.1.5 10.10.2.2
check "ACL blacklist counter increases" counter_increased acl_blacklist "$acl_before"
api_expect_ok PUT /api/acl/ipv4/source/whitelist '"10.10.1.5:0"'
check "Whitelist overrides blacklist" ping4_from_external 10.10.1.5 10.10.2.2
api_expect_ok DELETE /api/acl/ipv4/source/whitelist '"10.10.1.5:0"'
check "Blacklist resumes after whitelist removal" expect_blocked ping4_from_external 10.10.1.5 10.10.2.2
api_expect_ok DELETE /api/acl/ipv4/source/blacklist '"10.10.1.5:0"'
acl6_before="$(drop_counter acl_blacklist)"
api_expect_ok PUT /api/acl/ipv6/source/blacklist '"[fd00:1::5]:0"'
check "IPv6 source blacklist drops traffic" expect_blocked ping6_from_external fd00:1::5 fd00:2::2
check "IPv6 ACL counter increases" counter_increased acl_blacklist "$acl6_before"
api_expect_ok DELETE /api/acl/ipv6/source/blacklist '"[fd00:1::5]:0"'

echo "--- Protocol filter ---"
proto_before="$(drop_counter protocol_filter)"
api_expect_ok PUT /api/filter/http/ipv4 '["10.10.2.2:80",["GET"]]'
check "HTTP GET is allowed" external_exec "timeout 5 curl -fsS -X GET http://10.10.2.2/ >/dev/null"
check "HTTP POST is dropped" expect_blocked external_exec "timeout 5 curl -fsS -X POST http://10.10.2.2/ >/dev/null"
check "Protocol filter counter increases for POST" counter_increased protocol_filter "$proto_before"
api_expect_ok DELETE /api/filter/http/ipv4 '["10.10.2.2:80",["GET"]]'

proto_ssh_before="$(drop_counter protocol_filter)"
api_expect_ok PUT /api/filter/ssh/ipv4 '"10.10.2.2:22"'
api_expect_ok PUT /api/filter/ssh/blacklist/ipv4 '"10.10.1.5"'
check "SSH blacklist drops TCP connect" expect_blocked external_exec "timeout 5 nc -z -s 10.10.1.5 10.10.2.2 22"
check "SSH blacklist counter increases" counter_increased protocol_filter "$proto_ssh_before"
api_expect_ok DELETE /api/filter/ssh/blacklist/ipv4 '"10.10.1.5"'
api_expect_ok POST /api/filter/ssh/whitelist/enable
api_expect_ok PUT /api/filter/ssh/whitelist/ipv4 '"10.10.1.2"'
check "SSH whitelist allows listed source" external_exec "timeout 5 nc -z -s 10.10.1.2 10.10.2.2 22"
check "SSH whitelist blocks unlisted source" expect_blocked external_exec "timeout 5 nc -z -s 10.10.1.5 10.10.2.2 22"
api_expect_ok POST /api/filter/ssh/whitelist/disable
api_expect_ok DELETE /api/filter/ssh/whitelist/ipv4 '"10.10.1.2"'
api_expect_ok DELETE /api/filter/ssh/ipv4 '"10.10.2.2:22"'

echo "--- Rate limit ---"
run_rate_limit_case "Packet rate limit bucket" rate_limit_pkt '{"packet_rate":2,"syn_rate":1000,"udp_rate":1000,"dns_rate":1000,"window_ns":2000000000}' packet
run_rate_limit_case "SYN rate limit bucket" rate_limit_syn '{"packet_rate":1000,"syn_rate":2,"udp_rate":1000,"dns_rate":1000,"window_ns":2000000000}' syn
run_rate_limit_case "UDP rate limit bucket" rate_limit_udp '{"packet_rate":1000,"syn_rate":1000,"udp_rate":2,"dns_rate":1000,"window_ns":2000000000}' udp
run_rate_limit_case "DNS rate limit bucket" rate_limit_dns '{"packet_rate":1000,"syn_rate":1000,"udp_rate":1000,"dns_rate":2,"window_ns":2000000000}' dns

echo "--- DNS blacklist ---"
dns_before="$(drop_counter dns_blacklist)"
api_expect_ok PUT /api/filter/dns/blacklist '{"domains":["evil.example.com"]}'
send_dns_query evil.example.com
sleep 1
check "DNS blacklist counter increases" counter_increased dns_blacklist "$dns_before"
dns_allowed_before="$(drop_counter dns_blacklist)"
send_dns_query allowed.example.com
sleep 1
check "Non-blacklisted DNS does not increase DNS blacklist drops" counter_unchanged dns_blacklist "$dns_allowed_before"
api_expect_ok DELETE /api/filter/dns/blacklist '{"domains":["evil.example.com"]}'

echo "--- GeoIP block ---"
check "GeoIP block counter increases" geo_block_counter_increases

echo "--- Graceful shutdown ---"
cleanup_api_state
shutdown_net_guardia
check "No residual XDP link or net-guardia process" assert_clean_shutdown

trap - EXIT

echo "=========================================="
echo "  eBPF E2E result: $PASS passed / $FAIL failed"
echo "=========================================="
if (( FAIL > 0 )); then
    printf 'Failures:\n'
    printf '  - %s\n' "${FAILURES[@]}"
    echo "Run log: $RUN_LOG"
    exit 1
fi

echo "Run log: $RUN_LOG"
