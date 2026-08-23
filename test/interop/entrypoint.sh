#!/bin/sh
# Entrypoint for the interop client container: optionally injects synthetic
# loss and reordering on the container's egress interface (client-to-server
# direction, 01-04-PLAN.md Task 1 — the server-to-client direction is
# injected independently by test/interop/server/main.go's PacketConn
# decorator), starts a packet capture on the tunnel port in the background,
# runs the real OpenVPN client in the foreground, and stops the capture on
# exit so it is flushed and complete — including on a failing run, so a
# failing CI run leaves a debuggable artifact (Task 2's requirement).
set -eu

CAPTURE_DIR="${CAPTURE_DIR:-/captures}"
CAPTURE_FILE="${CAPTURE_DIR}/interop.pcap"
CONFIG="${OVPN_CONFIG:-/pki/client.conf}"

# NETEM_ENABLED gates client-to-server loss/reorder injection so the same
# image serves both the clean and lossy scenarios (01-04-PLAN.md Task 1).
# NETEM_LOSS_PCT/NETEM_REORDER_PCT default to the middle of the required
# 5-10% band when netem is enabled but a percentage wasn't explicitly set.
# This container already carries NET_ADMIN and iproute2 for the real
# OpenVPN client's own tun device — netem needs nothing beyond that.
if [ "${NETEM_ENABLED:-0}" = "1" ]; then
	IFACE=$(ip route show default | awk '{print $5; exit}')
	if [ -z "$IFACE" ]; then
		echo "entrypoint: NETEM_ENABLED=1 but could not determine the default egress interface" >&2
		exit 1
	fi
	LOSS_PCT="${NETEM_LOSS_PCT:-7}"
	REORDER_PCT="${NETEM_REORDER_PCT:-7}"
	# delay 10ms is required for netem's `reorder` clause to have any effect
	# (reorder only reorders packets relative to ones held back by delay);
	# reorder's second percentage (50%) is the reference's own documented
	# "correlation" default, not a protocol-derived value.
	tc qdisc add dev "$IFACE" root netem delay 10ms loss "${LOSS_PCT}%" reorder "${REORDER_PCT}%" 50%
	echo "entrypoint: netem active on $IFACE: loss=${LOSS_PCT}% reorder=${REORDER_PCT}%"
fi

mkdir -p "$CAPTURE_DIR"

tcpdump -i any -w "$CAPTURE_FILE" -U udp port 1194 &
TCPDUMP_PID=$!

cleanup() {
	# Send SIGTERM and wait so tcpdump flushes its output file before the
	# container exits; without this, the pcap global/record headers can be
	# left in a partially-written state.
	kill "$TCPDUMP_PID" 2>/dev/null || true
	wait "$TCPDUMP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Give tcpdump a moment to attach before the client starts sending.
sleep 1

set +e
openvpn --config "$CONFIG"
OVPN_EXIT=$?
set -e

exit "$OVPN_EXIT"
