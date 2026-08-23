#!/bin/sh
# Entrypoint for the interop client container: starts a packet capture on
# the tunnel port in the background, runs the real OpenVPN client in the
# foreground, and stops the capture on exit so it is flushed and complete —
# including on a failing run, so a failing CI run leaves a debuggable
# artifact (Task 2's requirement).
set -eu

CAPTURE_DIR="${CAPTURE_DIR:-/captures}"
CAPTURE_FILE="${CAPTURE_DIR}/interop.pcap"
CONFIG="${OVPN_CONFIG:-/pki/client.conf}"

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
