#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$DEPLOY_DIR/compose/podman-compose.yml"

if command -v podman-compose &>/dev/null; then
    COMPOSE="podman-compose -f $COMPOSE_FILE"
    RT="podman"
elif command -v docker &>/dev/null && docker compose version &>/dev/null 2>&1; then
    COMPOSE="docker compose -f $COMPOSE_FILE"
    RT="docker"
else
    echo "ERROR: No container runtime found"
    exit 1
fi

echo "=== Runtime: $RT ==="
echo "=== Kernel: $(uname -r) ==="
echo ""

echo "=== Building containers ==="
$COMPOSE build

echo "=== Starting containers ==="
$COMPOSE up -d

echo ""
echo "=== Containers running ==="
$RT ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null || $RT ps

get_pid() {
    $RT inspect --format '{{.State.Pid}}' "$1"
}

mkdir -p /var/run/netns

EXT_PID=$(get_pid external)
INT_PID=$(get_pid internal)
RTR_PID=$(get_pid router)
NG_PID=$(get_pid netguardia)
ln -sf /proc/$EXT_PID/ns/net /var/run/netns/external
ln -sf /proc/$INT_PID/ns/net /var/run/netns/internal
ln -sf /proc/$RTR_PID/ns/net /var/run/netns/router
ln -sf /proc/$NG_PID/ns/net /var/run/netns/netguardia

# ============================================================
# Segment 1: external <-> router (10.10.1.0/24)
# Direct connection, no inspection needed
# ============================================================
echo ""
echo "=== Segment 1: external <-> router (10.10.1.0/24) ==="

ip link add ext-eth0 type veth peer name rtr-ext
ip link set ext-eth0 netns external
ip link set rtr-ext netns router

ip netns exec external ip link set lo up
ip netns exec external ip link set ext-eth0 up
ip netns exec external ip addr add 10.10.1.2/24 dev ext-eth0
for i in 3 4 5 6 7; do
    ip netns exec external ip addr add 10.10.1.${i}/24 dev ext-eth0
done
ip netns exec external ip route add default via 10.10.1.1

ip netns exec router ip link set lo up
ip netns exec router ip link set rtr-ext up
ip netns exec router ip addr add 10.10.1.1/24 dev rtr-ext

echo "  external: ext-eth0 10.10.1.{2-7}/24, gw 10.10.1.1"
echo "  router:   rtr-ext  10.10.1.1/24"

# ============================================================
# Segment 2: router <-> netguardia <-> internal (10.10.2.0/24)
# NetGuardia inline: XDP on ng-ext (router side) and ng-int (internal side)
# No bridges, no inline veth pair — direct XSK forwarding
# ============================================================
echo ""
echo "=== Segment 2: router <-> [NetGuardia] <-> internal (10.10.2.0/24) ==="

# router <-> netguardia: ng-ext is the netguardia side
ip link add rtr-int type veth peer name ng-ext
ip link set rtr-int netns router
ip link set ng-ext netns netguardia

# netguardia <-> internal: ng-int is the netguardia side
ip link add int-eth0 type veth peer name ng-int
ip link set int-eth0 netns internal
ip link set ng-int netns netguardia

# Router internal side
ip netns exec router ip link set rtr-int up
ip netns exec router ip addr add 10.10.2.1/24 dev rtr-int
ip netns exec router sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

# Internal container
ip netns exec internal ip link set lo up
ip netns exec internal ip link set int-eth0 up
ip netns exec internal ip addr add 10.10.2.2/24 dev int-eth0
for i in 3 4 5 6; do
    ip netns exec internal ip addr add 10.10.2.${i}/24 dev int-eth0
done
ip netns exec internal ip route add default via 10.10.2.1

# NetGuardia interfaces (no IP, transparent)
ip netns exec netguardia ip link set ng-ext up
ip netns exec netguardia ip link set ng-int up

# Disable checksum offload on ALL veth endpoints.
# AF_XDP TX bypasses the kernel stack, so checksums are not computed.
# Without this, TCP packets forwarded through XSK have bad checksums and get dropped.
ip netns exec router ethtool -K rtr-int tx off rx off 2>/dev/null || true
ip netns exec router ethtool -K rtr-ext tx off rx off 2>/dev/null || true
ip netns exec internal ethtool -K int-eth0 tx off rx off 2>/dev/null || true
ip netns exec external ethtool -K ext-eth0 tx off rx off 2>/dev/null || true
ip netns exec netguardia ethtool -K ng-ext tx off rx off 2>/dev/null || true
ip netns exec netguardia ethtool -K ng-int tx off rx off 2>/dev/null || true

echo "  router:      rtr-int (10.10.2.1) <-> ng-ext (XDP ingress)"
echo "  netguardia:  ng-ext <-> [XSK forwarding] <-> ng-int"
echo "  internal:    int-eth0 (10.10.2.{2-6}) <-> ng-int (XDP egress)"
echo "  checksum offload disabled on all veth endpoints"

# ============================================================
# Verify
# ============================================================
echo ""
echo "=== Interfaces inside netguardia ==="
ip netns exec netguardia ip -br link show

echo ""
echo "=== Testing connectivity ==="

echo -n "  external -> router: "
ip netns exec external ping -c 1 -W 2 10.10.1.1 >/dev/null 2>&1 && echo "OK" || echo "FAIL"

# Without net-guardia, traffic between router and internal won't pass
# because ng-ext/ng-int are just veth endpoints with no forwarding
echo -n "  router -> internal: "
ip netns exec router ping -c 1 -W 2 10.10.2.2 >/dev/null 2>&1 && echo "OK" || echo "FAIL (expected - needs net-guardia)"

cat > /tmp/netguardia_interfaces.txt << IEOF
# NetGuardia interface mapping - realistic inline deployment
# Router handles L3 (10.10.1.0/24 <-> 10.10.2.0/24)
# NetGuardia inline on 10.10.2.0/24 (no IP, no bridge)
#   ng-ext - XDP ingress (router side, attached to rtr-int peer)
#   ng-int - XDP egress  (internal side, attached to int-eth0 peer)
# XSK forwards packets: ng-ext RX -> ng-int TX and ng-int RX -> ng-ext TX
# Management: eth0 (10.10.3.10)
IEOF
$RT cp /tmp/netguardia_interfaces.txt netguardia:/root/NetGuardia/interfaces.txt 2>/dev/null || true

rm -f /var/run/netns/external /var/run/netns/internal /var/run/netns/router /var/run/netns/netguardia

echo ""
echo "=========================================="
echo "  NetGuardia realistic inline deployment!"
echo ""
echo "    external (10.10.1.{2-7})"
echo "        |"
echo "    [router] 10.10.1.1 <-> 10.10.2.1"
echo "        |  rtr-int"
echo "        |"
echo "      ng-ext  (no IP) <- XDP ingress"
echo "        |"
echo "   [net-guardia XSK]"
echo "        |"
echo "      ng-int  (no IP) <- XDP egress"
echo "        |"
echo "        |  int-eth0"
echo "    internal (10.10.2.{2-6})"
echo ""
echo "  All 10.10.2.0/24 traffic requires net-guardia!"
echo "  Mgmt: 10.10.3.10"
echo "  SSH:  ssh -p 2222 root@<host-ip>"
echo "  Web:  http://<host-ip>:8080"
echo "=========================================="
