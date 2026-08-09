#!/usr/bin/env bash
# End-to-end Phase 6 integration test in isolated network namespaces.
#
# The DHCP test server runs in its own netns and the native DHCP client in a
# second netns; the two are joined by a veth pair, so nothing touches any host
# interface, namespace, port (67/68), or routing table. This also avoids the
# host dnsmasq that owns wildcard port 67 on virbr0.
#
# Requires: root (for ip/netns), a debug build with examples.
#
# Usage: sudo scripts/integration-netns.sh
set -euo pipefail

CLIENT_NS="nmdclient"
SERVER_NS="nmddhcp"
CLIENT_VETH="nmdc0"
SERVER_VETH="nmds0"
SERVER_ADDR="10.99.0.1"
CLIENT_ADDR="10.99.0.50"
BIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/target/debug/examples"

cleanup() {
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
}
trap cleanup EXIT

cleanup
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"
ip link add "$CLIENT_VETH" type veth peer name "$SERVER_VETH"
ip link set "$CLIENT_VETH" netns "$CLIENT_NS"
ip link set "$SERVER_VETH" netns "$SERVER_NS"

ip netns exec "$CLIENT_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip link set "$CLIENT_VETH" up
# An unaddressed DHCP client cannot yet route back to the server, so loose
# reverse-path filtering (rp_filter=2) drops the broadcast OFFER. Disable it.
ip netns exec "$CLIENT_NS" sysctl -w "net.ipv4.conf.$CLIENT_VETH.rp_filter=0" >/dev/null
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$SERVER_NS" ip link set "$SERVER_VETH" up
ip netns exec "$SERVER_NS" ip addr add "${SERVER_ADDR}/24" dev "$SERVER_VETH"

echo "== starting DHCP test server inside netns $SERVER_NS (${SERVER_ADDR}:67)"
ip netns exec "$SERVER_NS" "$BIN_DIR/dhcp_test_server" "$SERVER_VETH" >/tmp/nmd_dhcp_server.log 2>&1 &
SERVER_PID=$!
sleep 0.5

echo "== running DHCP client inside netns $CLIENT_NS"
ip netns exec "$CLIENT_NS" "$BIN_DIR/nmd_dhcp_client" "$CLIENT_VETH" 10 | tee /tmp/nmd_dhcp_result.txt
grep -q "DHCP OK" /tmp/nmd_dhcp_result.txt
grep -q "address=10.99.0.50/24" /tmp/nmd_dhcp_result.txt

echo "== verifying lease matches the address the kernel assigned"
ASSIGNED=$(ip netns exec "$CLIENT_NS" ip -4 addr show "$CLIENT_VETH" | grep -o 'inet [0-9./]*' | awk '{print $2}')
[ "$ASSIGNED" = "${CLIENT_ADDR}/24" ] || { echo "kernel address mismatch: $ASSIGNED"; exit 1; }

# nmd_dhcp_client left its lease applied; clear the interface so the engine
# demos start from a pristine state (and the engine's own DHCP acquisition
# does not collide with the already-assigned address).
ip netns exec "$CLIENT_NS" ip -4 addr flush dev "$CLIENT_VETH"
ip netns exec "$CLIENT_NS" ip -4 route flush dev "$CLIENT_VETH"

# The engine writes /etc/resolv.conf, but the netns inherits the host's
# NetworkManager-owned file. Run the demos in a private mount namespace with
# an empty tmpfs over /etc so the DNS manager can take ownership without the
# host resolv.conf being touched.
engine_demo() {
    local mode="$1"
    ip netns exec "$CLIENT_NS" unshare -m --propagation private sh -c \
        'mount -t tmpfs tmpfs /etc && : > /etc/resolv.conf && exec "$1" "$2" "$3"' \
        _ "$BIN_DIR/nmd_ip_engine_demo" "$CLIENT_VETH" "$mode"
}

echo "== exercising LinuxIpEngine manual activation/teardown in netns $CLIENT_NS"
engine_demo manual | tee /tmp/nmd_engine_manual.txt
grep -q "IP ENGINE manual OK" /tmp/nmd_engine_manual.txt

echo "== exercising LinuxIpEngine DHCP activation/teardown in netns $CLIENT_NS"
engine_demo auto | tee /tmp/nmd_engine_auto.txt
grep -q "IP ENGINE auto OK" /tmp/nmd_engine_auto.txt

kill "$SERVER_PID" 2>/dev/null || true
wait "$SERVER_PID" 2>/dev/null || true

echo "== exercising rtnetlink ipconfigurator in netns $CLIENT_NS"
ip netns exec "$CLIENT_NS" "$BIN_DIR/nmd_ipconfig_probe" "$CLIENT_VETH"

echo "INTEGRATION NETNS TEST PASSED"
