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
# PING_COUNT/interval: 02-04-PLAN.md Task 1 widened this from 4 packets at a
# 0.2s interval to 10 packets at a 1s interval (~10s total) so the lossy
# scenario's ping spans several of docker-compose.lossy.yml's loss events
# rather than completing inside a single short window — a multi-second ping
# is what makes "at least one reply returned" (the lossy scenario's tolerant
# assertion, VRFY-03) a meaningful proof of tunnel survival rather than a
# coin flip on whichever single packet happened to survive.
PING_COUNT="${PING_COUNT:-10}"

# HTTP_PORT is the tunnelweb example site's port over the netstack's TCP
# listener (test/interop/server/main.go's -http-port, 03-06-PLAN.md Task 1).
# The probes below curl it through the tunnel at $TUNNEL_SERVER_IP.
HTTP_PORT="${HTTP_PORT:-8080}"
# UDP_PORT is the netstack UDP echo service's port (test/interop/server/
# main.go's -udp-port, 03-06-PLAN.md Task 2).
UDP_PORT="${UDP_PORT:-9999}"

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
	# -i 1 (one request per second) over PING_COUNT requests spans several
	# seconds of the lossy scenario's loss/reorder events (02-04-PLAN.md
	# Task 1) rather than completing inside one short burst, while staying
	# well under test/interop/server/main.go's 20s postHandshakeSurvival
	# window, so the server doesn't exit — ending the compose run via
	# --abort-on-container-exit — before this prints its summary line.
	# -W 2 bounds the per-reply wait so a dropped echo is retried on the
	# next second's request rather than stalling the whole sequence.
	if ping -c "$PING_COUNT" -i 1 -W 2 "$TUNNEL_SERVER_IP"; then
		echo "entrypoint: ping to $TUNNEL_SERVER_IP succeeded"
	else
		echo "entrypoint: ping to $TUNNEL_SERVER_IP failed (see ping output above)"
	fi
else
	echo "entrypoint: tun0 never came up within the wait window; skipping ping"
fi

# Probe block (03-06-PLAN.md): every probe below emits one structured line,
#   entrypoint: PROBE <name> result=<ok|fail> <key>=<value>...
# so test/interop/interop_test.go's parser needs no new regexp when a later
# task adds another probe. Every curl/nc invocation is guarded against
# set -eu (a bare non-zero exit would abort this script and lose the
# cleanup/wait path below that flushes the pcap).
#
# http_landing (Task 1): curl the tunnelweb landing page through the tunnel
# and check for its locked <h1> text (UI-SPEC §1). --retry/--retry-all-errors
# gives the lossy scenario's synthetic loss room to succeed on a later
# attempt rather than failing on the first dropped/reordered segment.
LANDING_BODY=$(curl -s --max-time 10 --retry 2 --retry-all-errors "http://$TUNNEL_SERVER_IP:$HTTP_PORT/" 2>/dev/null || true)
if [ -n "$LANDING_BODY" ] && printf '%s' "$LANDING_BODY" | grep -q '<h1>govpn tunnelweb</h1>'; then
	echo "entrypoint: PROBE http_landing result=ok marker=found"
	echo "entrypoint: landing page probe succeeded"
else
	echo "entrypoint: PROBE http_landing result=fail reason=marker_not_found"
	echo "entrypoint: landing page probe failed (see body above, if any)"
fi

# udp_echo (Task 2): send a fixed payload to the server's netstack UDP echo
# service and check the reply carries the server's udpEchoMarker prefix
# (test/interop/server/main.go's runUDPEcho). UDP has no retransmission by
# design, and the lossy scenario injects 5-10% loss on top, so this tries up
# to 3 attempts before giving up — interop_test.go's assertion tolerates a
# fail here only on the lossy scenario (both choices commented there).
#
# nc -u -w <N> blocks for the FULL N seconds even after it has already
# received a reply — UDP is connectionless, so nc has no EOF signal telling
# it "no more data is coming" and simply waits out its own idle timer
# (confirmed empirically against a real UDP echo server before choosing this
# value). A 1-second timeout keeps each attempt's unavoidable block short —
# a reply on this local Docker bridge network arrives in single-digit
# milliseconds, so 1 second is generous headroom, not a tight race — while
# keeping the probe-driven survival window's settle delay
# (test/interop/server/main.go's probeSettleDelay) small enough to still
# finish faster than the old fixed window.
UDP_PROBE_PAYLOAD="govpn-udp-probe"
udp_ok=0
attempt=1
while [ "$attempt" -le 3 ]; do
	UDP_REPLY=$(printf '%s' "$UDP_PROBE_PAYLOAD" | nc -u -w 1 "$TUNNEL_SERVER_IP" "$UDP_PORT" 2>/dev/null || true)
	if printf '%s' "$UDP_REPLY" | grep -qF "govpn-udp-echo:${UDP_PROBE_PAYLOAD}"; then
		udp_ok=1
		break
	fi
	attempt=$((attempt + 1))
done
if [ "$udp_ok" -eq 1 ]; then
	echo "entrypoint: PROBE udp_echo result=ok"
	echo "entrypoint: UDP echo probe succeeded"
else
	echo "entrypoint: PROBE udp_echo result=fail reason=no_echo_after_3_attempts"
	echo "entrypoint: UDP echo probe failed after 3 attempts"
fi

# http_status (Task 2): curl /status and check for the locked "tunnel:
# active" indicator text (UI-SPEC §2).
STATUS_BODY=$(curl -s --max-time 10 --retry 2 --retry-all-errors "http://$TUNNEL_SERVER_IP:$HTTP_PORT/status" 2>/dev/null || true)
if [ -n "$STATUS_BODY" ] && printf '%s' "$STATUS_BODY" | grep -q 'tunnel: active'; then
	echo "entrypoint: PROBE http_status result=ok"
	echo "entrypoint: status page probe succeeded"
else
	echo "entrypoint: PROBE http_status result=fail reason=marker_not_found"
	echo "entrypoint: status page probe failed"
fi

# http_echo (Task 2): POST a fixed message to /echo and check for the
# populated-state rendering of that exact string (UI-SPEC §4) — the
# strongest single proof in this run, since a request body and a response
# body both cross the netstack's TCP in one exchange.
ECHO_PROBE_MSG="govpn-echo-probe-msg"
ECHO_BODY=$(curl -s --max-time 10 --retry 2 --retry-all-errors -d "msg=$ECHO_PROBE_MSG" "http://$TUNNEL_SERVER_IP:$HTTP_PORT/echo" 2>/dev/null || true)
if [ -n "$ECHO_BODY" ] && printf '%s' "$ECHO_BODY" | grep -qF "You sent: $ECHO_PROBE_MSG"; then
	echo "entrypoint: PROBE http_echo result=ok"
	echo "entrypoint: echo POST probe succeeded"
else
	echo "entrypoint: PROBE http_echo result=fail reason=marker_not_found"
	echo "entrypoint: echo POST probe failed"
fi

# http_headers (Task 2): curl /headers and check for the "{N} headers
# received" heading fragment (UI-SPEC §5).
HEADERS_BODY=$(curl -s --max-time 10 --retry 2 --retry-all-errors "http://$TUNNEL_SERVER_IP:$HTTP_PORT/headers" 2>/dev/null || true)
if [ -n "$HEADERS_BODY" ] && printf '%s' "$HEADERS_BODY" | grep -q 'headers received'; then
	echo "entrypoint: PROBE http_headers result=ok"
	echo "entrypoint: headers page probe succeeded"
else
	echo "entrypoint: PROBE http_headers result=fail reason=marker_not_found"
	echo "entrypoint: headers page probe failed"
fi

# outside_tunnel (Task 3): a direct curl at the server container's own
# Docker-network alias (govpn-interop-server, which this client container
# already resolves) on the same HTTP port must FAIL — the tunnelweb site
# binds no OS TCP socket for HTTP at all; its only listener lives inside the
# netstack's own 4-tuple table, reachable only via a packet arriving on an
# attached Session. result=ok means the connection was refused or timed out
# (the correct, desired outcome, proving the site is unreachable outside
# the tunnel); result=fail means a response actually came back. The sense
# is deliberately inverted from every other probe above — commented clearly
# because a probe whose SUCCESS is a command's FAILURE is exactly the kind
# of code a later reader "fixes" by accident.
if curl -s --max-time 3 "http://govpn-interop-server:$HTTP_PORT/" >/dev/null 2>&1; then
	echo "entrypoint: PROBE outside_tunnel result=fail reason=response_received"
	echo "entrypoint: outside-tunnel probe failed: the server responded to a direct connection outside the tunnel"
else
	echo "entrypoint: PROBE outside_tunnel result=ok"
	echo "entrypoint: outside-tunnel probe succeeded: direct connection to the server container was refused or timed out"
fi

set +e
wait "$OVPN_PID"
OVPN_EXIT=$?
set -e

exit "$OVPN_EXIT"
