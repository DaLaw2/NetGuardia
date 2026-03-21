#!/bin/bash
# External network traffic generator
# Simulates external hosts sending traffic toward the internal network

INTERNAL_IP="10.10.2.2"
SELF_BASE="10.10.1"

echo "[external] Traffic generator started"

# Wait for network and routing to be ready
sleep 5
until ping -c 1 -W 1 $INTERNAL_IP &>/dev/null; do
    echo "[external] Waiting for internal connectivity..."
    sleep 2
done
echo "[external] Internal network reachable"

# --- Benign traffic functions ---

http_traffic() {
    while true; do
        for src in 2 3 4; do
            local ip="${SELF_BASE}.${src}"
            # Various HTTP methods
            curl -s --interface $ip -o /dev/null -m 3 http://${INTERNAL_IP}/ 2>/dev/null
            curl -s --interface $ip -o /dev/null -m 3 -X POST -d "data=test" http://${INTERNAL_IP}/ 2>/dev/null
            curl -s --interface $ip -o /dev/null -m 3 -X HEAD http://${INTERNAL_IP}/ 2>/dev/null
            curl -s --interface $ip -o /dev/null -m 3 -X OPTIONS http://${INTERNAL_IP}/ 2>/dev/null
        done
        sleep $((RANDOM % 3 + 1))
    done
}

ssh_traffic() {
    while true; do
        for src in 2 5; do
            local ip="${SELF_BASE}.${src}"
            # SSH connection attempts (will fail but generates TCP SYN to port 22)
            timeout 2 bash -c "echo | nc -w 1 -s $ip $INTERNAL_IP 22" 2>/dev/null || true
        done
        sleep $((RANDOM % 5 + 3))
    done
}

dns_traffic() {
    while true; do
        for src in 2 3 6; do
            local ip="${SELF_BASE}.${src}"
            # UDP packets to port 53 (DNS-like)
            echo -ne '\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | \
                nc -u -w 1 -s $ip $INTERNAL_IP 53 2>/dev/null || true
        done
        sleep $((RANDOM % 4 + 2))
    done
}

udp_traffic() {
    while true; do
        for src in 2 4 7; do
            local ip="${SELF_BASE}.${src}"
            for port in 5000 5001 8000 9090; do
                echo "udp-payload-$(date +%s)" | nc -u -w 1 -s $ip $INTERNAL_IP $port 2>/dev/null || true
            done
        done
        sleep $((RANDOM % 3 + 2))
    done
}

tcp_traffic() {
    while true; do
        for src in 3 5 6; do
            local ip="${SELF_BASE}.${src}"
            for port in 3000 4000 6379 5432; do
                timeout 2 bash -c "echo 'hello' | nc -w 1 -s $ip $INTERNAL_IP $port" 2>/dev/null || true
            done
        done
        sleep $((RANDOM % 4 + 2))
    done
}

icmp_traffic() {
    while true; do
        for src in 2 3 4 5; do
            local ip="${SELF_BASE}.${src}"
            ping -c 2 -W 1 -I $ip $INTERNAL_IP >/dev/null 2>&1 || true
        done
        sleep $((RANDOM % 5 + 3))
    done
}

# --- Attack-like traffic (low intensity, for ML training) ---

syn_scan() {
    while true; do
        sleep $((RANDOM % 30 + 30))
        src="${SELF_BASE}.$((RANDOM % 3 + 5))"
        echo "[external] SYN scan burst from $src"
        # Quick port scan pattern
        for port in 22 80 443 8080 3306 5432 6379 8443 9090 27017; do
            timeout 1 bash -c "echo | nc -w 1 -s $src $INTERNAL_IP $port" 2>/dev/null || true
        done
    done
}

udp_burst() {
    while true; do
        sleep $((RANDOM % 60 + 45))
        src="${SELF_BASE}.$((RANDOM % 3 + 5))"
        echo "[external] UDP burst from $src"
        for i in $(seq 1 50); do
            echo "flood-$i" | nc -u -w 0 -s $src $INTERNAL_IP $((RANDOM % 10000 + 1024)) 2>/dev/null || true
        done
    done
}

# Launch all traffic generators in background
http_traffic &
ssh_traffic &
dns_traffic &
udp_traffic &
tcp_traffic &
icmp_traffic &
syn_scan &
udp_burst &

echo "[external] All traffic generators running"
wait
