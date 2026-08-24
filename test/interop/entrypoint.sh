#!/bin/sh
# Entrypoint for the interop client container: optionally injects synthetic
# loss and reordering on the container's egress interface (client-to-server
# direction, 01-04-PLAN.md Task 1 — the server-to-client direction is
# injected independently by test/interop/server/main.go's PacketConn
# decorator), starts a packet capture on the tunnel port in the background,
# runs the real OpenVPN client in the background, pings the server's pushed
# tunnel IP once tun0 is up (02-03-PLAN.md Task 1 — proves Session.Read/
# Write carry a genuine encrypted round trip, not merely that the
# handshake completed), and stops the capture on exit so it is flushed and
# complete — including on a failing run, so a failing CI run leaves a
# debuggable artifact (01-04-PLAN.md Task 2's requirement).
set -eu

# TUNNEL_SERVER_IP is the server's own reserved tunnel address — base+1 of
# test/interop/server/main.go's hardcoded 10.8.0.0/24 tunnel network
# (ippool.go's serverIP: "base+1, the first host address"). Under
# `topology subnet` (pushed unconditionally, RESEARCH Pattern 6) the
# client's own route to the whole /24 already covers it, so no extra route
# is pushed or needed — the client just pings an address inside its own
# pushed subnet.
TUNNEL_SERVER_IP="${TUNNEL_SERVER_IP:-10.8.0.1}"
PING_COUNT="${PING_COUNT:-4}"

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
	# left in a partially-written state. OVPN_PID may not be set yet if
	# cleanup fires before the client starts (e.g. a signal during the
	# initial sleep below).
	kill "$TCPDUMP_PID" 2>/dev/null || true
	wait "$TCPDUMP_PID" 2>/dev/null || true
	if [ -n "${OVPN_PID:-}" ]; then
		kill "$OVPN_PID" 2>/dev/null || true
		wait "$OVPN_PID" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

# Give tcpdump a moment to attach before the client starts sending.
sleep 1

# Run the real OpenVPN client in the background (not foreground, unlike
# before 02-03-PLAN.md Task 1) so this script can drive a ping through the
# tunnel once it comes up, then wait for the client process itself to exit
# (normally via the SIGTERM cleanup above, when the server container exits
# and docker compose's --abort-on-container-exit tears this one down too).
openvpn --config "$CONFIG" &
OVPN_PID=$!

# Wait for tun0 to come up with an address (real client-side proof of
# "Initialization Sequence Completed"), bounded so a broken handshake fails
# this ping step fast rather than hanging until the outer test's own
# timeout; the client's own log/exit-code coverage is unaffected either
# way — this loop only gates the ping-through-the-tunnel step below.
i=0
while [ "$i" -lt 30 ]; do
	if ip addr show tun0 2>/dev/null | grep -q 'inet '; then
		break
	fi
	i=$((i + 1))
	sleep 1
done

if ip addr show tun0 2>/dev/null | grep -q 'inet '; then
	echo "entrypoint: tun0 is up, pinging server tunnel IP $TUNNEL_SERVER_IP through it"
	# -i 0.2 (the fastest interval iputils-ping permits a non-root caller;
	# this container runs as root anyway, per docker-compose.yml's own
	# comment on the client service, so even smaller intervals would be
	# permitted, but 0.2 is already comfortably fast) keeps the whole ping
	# well under test/interop/server/main.go's postHandshakeSurvival
	# window, so the server doesn't exit — ending the compose run via
	# --abort-on-container-exit — before this prints its summary line.
	if ping -c "$PING_COUNT" -i 0.2 -W 2 "$TUNNEL_SERVER_IP"; then
		echo "entrypoint: ping to $TUNNEL_SERVER_IP succeeded"
	else
		echo "entrypoint: ping to $TUNNEL_SERVER_IP failed (see ping output above)"
	fi
else
	echo "entrypoint: tun0 never came up within the wait window; skipping ping"
fi

set +e
wait "$OVPN_PID"
OVPN_EXIT=$?
set -e

exit "$OVPN_EXIT"
