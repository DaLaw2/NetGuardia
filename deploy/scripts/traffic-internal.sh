#!/bin/bash
# Internal network traffic generator
# Simulates internal hosts sending traffic toward the external network
# Also runs services (HTTP, SSH) for external to connect to

EXTERNAL_IP="10.10.1.2"
SELF_BASE="10.10.2"

echo "[internal] Traffic generator started"

# Start HTTP server on all interfaces
httpd -D FOREGROUND &
HTTPD_PID=$!

# Start a simple SSH listener (for connection pattern generation)
ssh-keygen -A 2>/dev/null
/usr/sbin/sshd 2>/dev/null || true

# Wait for network to be ready
sleep 3
until ping -c 1 -W 1 $EXTERNAL_IP &>/dev/null; do
    echo "[internal] Waiting for external connectivity..."
    sleep 2
done
echo "[internal] External network reachable"

# --- Benign outbound traffic ---

http_outbound() {
    while true; do
        for src in 2 3 4; do
            local ip="${SELF_BASE}.${src}"
            curl -s --interface $ip -o /dev/null -m 3 http://${EXTERNAL_IP}/ 2>/dev/null
            curl -s --interface $ip -o /dev/null -m 3 -X POST -d "query=test" http://${EXTERNAL_IP}/ 2>/dev/null
        done
        sleep $((RANDOM % 4 + 2))
    done
}

dns_outbound() {
    while true; do
        for src in 2 5; do
            local ip="${SELF_BASE}.${src}"
            echo -ne '\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01' | \
                nc -u -w 1 -s $ip $EXTERNAL_IP 53 2>/dev/null || true
        done
        sleep $((RANDOM % 5 + 3))
    done
}

udp_outbound() {
    while true; do
        for src in 3 4 6; do
            local ip="${SELF_BASE}.${src}"
            echo "internal-udp-$(date +%s)" | nc -u -w 1 -s $ip $EXTERNAL_IP $((RANDOM % 5000 + 5000)) 2>/dev/null || true
        done
        sleep $((RANDOM % 4 + 2))
    done
}

tcp_outbound() {
    while true; do
        for src in 2 5 6; do
            local ip="${SELF_BASE}.${src}"
            timeout 2 bash -c "echo 'ping' | nc -w 1 -s $ip $EXTERNAL_IP $((RANDOM % 1000 + 3000))" 2>/dev/null || true
        done
        sleep $((RANDOM % 5 + 3))
    done
}

icmp_outbound() {
    while true; do
        for src in 2 3; do
            local ip="${SELF_BASE}.${src}"
            ping -c 1 -W 1 -I $ip $EXTERNAL_IP >/dev/null 2>&1 || true
        done
        sleep $((RANDOM % 6 + 4))
    done
}

# Launch all traffic generators
http_outbound &
dns_outbound &
udp_outbound &
tcp_outbound &
icmp_outbound &

echo "[internal] All traffic generators + services running"
echo "[internal] Services: HTTP(:80), SSH(:22)"
wait
