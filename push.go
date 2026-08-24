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
//     support (always true for a real 2.6 client — RESEARCH.md Assumption
//     A2)
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

// buildPushReply assembles the server's PUSH_REPLY payload for clientIP
// (drawn from network by the caller's ipPool) and peerID, in the exact
// option order and content a real OpenVPN 2.6 server transmits (Pattern 6,
// D-03 "minimal reference defaults only"): ifconfig under subnet topology,
// topology subnet, peer-id, the fixed data-channel cipher, and the
// keepalive helper's own pushed expansion (ping 10 / ping-restart 60 — NOT
// the doubled local value of 120, and NOT the literal "keepalive 10 60"
// token). Nothing else is pushed: no route, no redirect-gateway, no
// dhcp-option, no compression (D-03; routes are Phase 3). The returned
// slice ends with exactly one 0x00 byte and is written to the wire
// unmodified — no length prefix (Pattern 6).
func buildPushReply(clientIP net.IP, network *net.IPNet, peerID uint32, cipher string) []byte {
	if cipher == "" {
		cipher = "AES-256-GCM"
	}
	netmask := net.IP(network.Mask).String()

	opts := []string{
		"PUSH_REPLY",
		fmt.Sprintf("ifconfig %s %s", clientIP.String(), netmask),
		"topology subnet",
		fmt.Sprintf("peer-id %d", peerID),
		fmt.Sprintf("cipher %s", cipher),
		"ping 10",
		"ping-restart 60",
	}
	reply := strings.Join(opts, ",")
	return append([]byte(reply), 0)
}
