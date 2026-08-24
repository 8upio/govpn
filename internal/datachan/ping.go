// This file (ping.go) implements the 16-byte keepalive ping magic (DATA-03):
// recognizing it on the decrypted plaintext (see datachan.go's Open, which
// completes the tracer's own minimal guard from Task 1) and sealing it for
// emission (Wrapper.SealPing, datachan.go).
//
// Magic bytes / PingSize: src/openvpn/ping.c:42-45, src/openvpn/ping.h:38
// (pinned reference checkout /Users/svenloth/dev/openvpn-reference, branch
// release/2.6, commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686). A ping is
// encrypted through exactly the same AEAD path as any other data packet
// (ping.c:74-90, "We will treat the ping like any other outgoing packet,
// encrypt, sign, etc.") — it is not a distinct wire opcode, and the check
// below runs on the decrypted plaintext, after the AEAD tag has already
// verified.
//
// Detecting a dead peer and tearing the session down on a missing ping
// (the reference's own ping-restart) is SESS-05, Phase 4's scope — this
// package only emits pings and absorbs them; it does not act on their
// absence.
package datachan

import "bytes"

// PingSize: ping.h:38 (PING_STRING_SIZE = 16).
const PingSize = 16

// pingMagic: ping.c:42-45, written out explicitly rather than derived.
var pingMagic = [PingSize]byte{
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48,
}

// IsPing reports whether plaintext is exactly the 16-byte ping keepalive
// magic. The magic is not a secret, so a plain length-then-bytes.Equal
// comparison is sufficient — deliberately not
// subtle.ConstantTimeCompare, so a future reader does not "fix" this into
// a constant-time comparison that buys nothing here.
func IsPing(plaintext []byte) bool {
	return len(plaintext) == PingSize && bytes.Equal(plaintext, pingMagic[:])
}
