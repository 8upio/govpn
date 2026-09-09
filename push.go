// This file (push.go) implements the PUSH_REQUEST/PUSH_REPLY control
// exchange: plain, NUL-terminated ASCII control strings exchanged over the
// same tls.Conn Key Method 2 already established, distinct from KM2's own
// length-prefixed field framing (forward.c:374-394
// send_control_channel_string_dowork writes strlen(str)+1 bytes and
// nothing else).
//
// Reference: /Users/svenloth/dev/openvpn-reference (release/2.6)
//   - push.c:41                push_reply_cmd literal "PUSH_REPLY"
//   - push.c:567,1089          client's "PUSH_REQUEST" literal
//   - push.c:629-643           prepare_push_reply
//   - push.c:663-666           cipher pushed only when peer signals NCP
//     support (tls_peer_supports_ncp, ssl_ncp.c:76-92) — implemented below
//     via peerSupportsNCP (05-03-PLAN.md; formerly RESEARCH.md "Assumption
//     A2", which is retired now that real IV_CIPHERS/IV_NCP parsing exists.
//     The observable consequence for every real OpenVPN 2.6 client is nil:
//     such a client always signals NCP support, so this gate is always
//     true in practice — only a genuinely pre-NCP synthetic test client can
//     ever observe the token omitted)
//   - push.c:775-837           send_push_reply
//   - helper.c:496-558         helper_keepalive: keepalive N M expands to
//     local `ping N`/`ping-restart 2*M` and PUSHED `ping N`/`ping-restart
//     M` — the pushed second value is M, not 2*M
//   - options.c:6097-6110      ifconfig parsing: under topology subnet the
//     second ifconfig parameter is the netmask, not a point-to-point peer
//     address
package ovpn

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// maxControlStringLen bounds readControlString's search for a NUL
// terminator (T-02-09): no control string this phase cares about
// (PUSH_REQUEST, 13 bytes) is ever remotely close to this size, so a
// client streaming bytes with no NUL is rejected well before it can force
// unbounded buffer growth on the server.
const maxControlStringLen = 1024

// readControlString reads bytes from r up to and including the next 0x00
// byte, returning the string with the terminator stripped. It returns an
// error, without having consumed more than max bytes past its own call, if
// no terminator appears within max bytes — this framing is deliberately
// different from Key Method 2's length-prefixed fields (see this file's
// package doc): PUSH_REQUEST/PUSH_REPLY are plain NUL-terminated ASCII
// with no length prefix at all, so the only bound available is a byte cap
// enforced by this function itself.
func readControlString(r *bufio.Reader, max int) (string, error) {
	buf := make([]byte, 0, 32)
	for len(buf) < max {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 0 {
			return string(buf), nil
		}
		buf = append(buf, b)
	}
	return "", fmt.Errorf("ovpn: control string exceeds %d bytes without a NUL terminator", max)
}

// writeControlString writes s to w followed by exactly one 0x00 byte and
// nothing else (forward.c:374-394's own on-wire shape).
func writeControlString(w io.Writer, s string) error {
	_, err := w.Write(append([]byte(s), 0))
	return err
}

// durationToPushedSeconds converts d to whole seconds for a pushed `ping`/
// `ping-restart` directive, floored at 1: a sub-second test override (or a
// pathological embedder Config value) must still produce a valid,
// non-zero directive rather than `ping 0`, which a real client would
// reject or misinterpret.
func durationToPushedSeconds(d time.Duration) int {
	secs := int(d / time.Second)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// buildPushReply assembles the server's PUSH_REPLY payload for clientIP
// (drawn from network by the caller's ipPool), peerID, cipher,
// peerSupportsNCP, and the server-authoritative ping/ping-restart values
// (seconds, already resolved by the caller from Config.PingInterval/
// Config.ReapWindow — see durationToPushedSeconds), in the exact option
// order and content a real OpenVPN 2.6 server transmits (Pattern 6, D-03
// "minimal reference defaults only"): ifconfig under subnet topology,
// topology subnet, peer-id, the data-channel cipher (only when
// peerSupportsNCP — push.c:663-666), and the keepalive helper's own pushed
// expansion (ping N / ping-restart M — NOT the doubled local value of 2*N,
// and NOT the literal "keepalive N M" token). Nothing else is pushed: no
// route, no redirect-gateway, no dhcp-option, no compression (D-03; routes
// are Phase 3). The returned slice ends with exactly one 0x00 byte and is
// written to the wire unmodified — no length prefix (Pattern 6).
//
// cipher is never defaulted here: by the time this function is reached,
// the caller (performPushExchange) already holds a negotiated canonical
// cipher name (T-05-05) — silently substituting "AES-256-GCM" for an empty
// value would hide exactly the wiring bug an empty cipher represents,
// rather than surfacing it. performPushExchange itself fails loudly before
// ever calling this function if the session has no negotiated cipher.
func buildPushReply(clientIP net.IP, network *net.IPNet, peerID uint32, cipher string, peerSupportsNCP bool, pingSeconds, pingRestartSeconds int) []byte {
	netmask := net.IP(normalizeIPv4Mask(network.Mask)).String()

	opts := []string{
		"PUSH_REPLY",
		fmt.Sprintf("ifconfig %s %s", clientIP.String(), netmask),
		"topology subnet",
		fmt.Sprintf("peer-id %d", peerID),
	}
	if peerSupportsNCP {
		// push.c:663-666: "We avoid pushing the cipher to clients not
		// supporting NCP to avoid error messages in their logs." Every real
		// OpenVPN 2.6 client always signals NCP support (peerSupportsNCP,
		// cipher.go), so this branch is always taken in practice — only a
		// genuinely pre-NCP synthetic test client can ever observe it
		// skipped.
		opts = append(opts, fmt.Sprintf("cipher %s", cipher))
	}
	opts = append(opts,
		// pingSeconds/pingRestartSeconds are derived by the caller
		// (performPushExchange) from the SAME Server.pingInterval/
		// Server.reapWindow fields session.go's keepalive goroutine and
		// idle-reap timer read — the pushed and enforced schedules cannot
		// drift apart, the same structural guarantee the old fixed
		// pingIntervalSeconds constant and "ping-restart 60" literal used
		// to provide, now derived from Config instead of hardcoded.
		fmt.Sprintf("ping %d", pingSeconds),
		fmt.Sprintf("ping-restart %d", pingRestartSeconds),
	)
	reply := strings.Join(opts, ",")
	return append([]byte(reply), 0)
}
