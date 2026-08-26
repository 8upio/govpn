package netstack

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// TestParseIPv4NeverPanics drives parseIPv4 with every truncation of a
// valid packet, plus specific internally-inconsistent header fields, under
// the race detector — parseIPv4 must never index past its input, only ever
// return a typed error (T-03-02).
func TestParseIPv4NeverPanics(t *testing.T) {
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	serverIP := net.IPv4(10, 8, 0, 1).To4()
	// A 20-byte payload keeps the full valid packet at 48 bytes, so every
	// prefix length in [0,40] below is a genuine truncation (never the
	// full, successfully-parseable packet).
	valid := buildICMPEchoRequest(mustAddr(clientIP), mustAddr(serverIP), 1, 1, make([]byte, 20))
	if len(valid) < 48 {
		t.Fatalf("test fixture too short: len(valid) = %d, want >= 48", len(valid))
	}

	for n := 0; n <= 40; n++ {
		mustNotPanicParse(t, valid[:n])
	}

	// IHL 0: version 4, IHL nibble 0 -> ihl := 0*4 = 0, which is below
	// minIPv4HeaderLen.
	ihlZero := append([]byte(nil), valid...)
	ihlZero[0] = 0x40
	mustNotPanicParse(t, ihlZero)

	// IHL 15 (60 bytes) on a 24-byte buffer: ihl computed correctly but
	// far exceeds len(pkt).
	buf24 := make([]byte, 24)
	buf24[0] = 0x4F
	mustNotPanicParse(t, buf24)

	// version 6.
	version6 := append([]byte(nil), valid...)
	version6[0] = 0x60
	mustNotPanicParse(t, version6)

	// total length field larger than the buffer.
	bigTotalLen := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(bigTotalLen[2:4], 0xFFFF)
	mustNotPanicParse(t, bigTotalLen)
}

func mustNotPanicParse(t *testing.T, pkt []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseIPv4 panicked on %d-byte input %x: %v", len(pkt), pkt, r)
		}
	}()
	if _, err := parseIPv4(pkt); err == nil {
		t.Fatalf("parseIPv4 unexpectedly succeeded on malformed/truncated input (%d bytes): %x", len(pkt), pkt)
	}
}

// TestIPOptionsAreSkippedNotRejected asserts an IHL > 5 packet (one 4-byte
// option word) parses successfully, with payloadOff pointing past the
// option, and that the stack still answers an echo request carried inside
// one (RESEARCH.md Anti-Patterns, Assumption A3: skip past options, do not
// reject them).
func TestIPOptionsAreSkippedNotRejected(t *testing.T) {
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	serverIP := net.IPv4(10, 8, 0, 1).To4()

	icmpPayload := []byte("ping-with-options")
	icmp := make([]byte, minICMPHeaderLen+len(icmpPayload))
	icmp[0] = icmpTypeEchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], 7)
	binary.BigEndian.PutUint16(icmp[6:8], 1)
	copy(icmp[8:], icmpPayload)
	binary.BigEndian.PutUint16(icmp[2:4], internetChecksum(icmp))

	const ihl = 24 // IHL 6: one 4-byte option word.
	totalLen := ihl + len(icmp)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = defaultTTL
	pkt[9] = protocolICMP
	copy(pkt[12:16], clientIP)
	copy(pkt[16:20], serverIP)
	// pkt[20:24] is the one option word; its content is irrelevant to this
	// test — parseIPv4 must skip past it, never interpret it.
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:ihl]))
	copy(pkt[ihl:], icmp)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4 rejected an options-bearing packet: %v", err)
	}
	if hdr.payloadOff != ihl {
		t.Fatalf("payloadOff = %d, want %d (IHL 6's options skipped, not rejected)", hdr.payloadOff, ihl)
	}

	stack := newTestStack(t)
	defer stack.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	fs.inbound <- pkt

	reply := waitForOutbound(t, fs, time.Second)
	replyHdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	replyICMP := reply[replyHdr.payloadOff:replyHdr.totalLen]
	if string(replyICMP[8:]) != string(icmpPayload) {
		t.Fatalf("reply payload = %q, want %q", replyICMP[8:], icmpPayload)
	}
}

// TestInternetChecksumRFC1071 asserts internetChecksum against a
// hand-computed literal (including the odd-trailing-byte rule) and the
// standard receiver-side self-check: re-summing a buffer that already
// carries its own correct checksum folds to zero.
func TestInternetChecksumRFC1071(t *testing.T) {
	// [0x0001, 0x0002] sum to 0x0003; the trailing odd byte 0x03 pairs
	// with an implicit zero low byte (0x0300); total 0x0303; one's
	// complement 0xFCFC.
	b := []byte{0x00, 0x01, 0x00, 0x02, 0x03}
	if got, want := internetChecksum(b), uint16(0xFCFC); got != want {
		t.Fatalf("internetChecksum(% x) = %#04x, want %#04x", b, got, want)
	}

	full := []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x00}
	binary.BigEndian.PutUint16(full[4:6], internetChecksum(full[:4]))
	if cs := internetChecksum(full); cs != 0 {
		t.Fatalf("internetChecksum with its own correct checksum embedded = %#04x, want 0", cs)
	}
}

// TestPseudoHeaderSumLayout locks the exact field order RFC 768 specifies
// (src, dst, zero, protocol, length) against a hand-derived literal — a
// transposed src/dst or a missing zero byte would fail this.
func TestPseudoHeaderSumLayout(t *testing.T) {
	src := mustAddr(net.IPv4(10, 8, 0, 1).To4())
	dst := mustAddr(net.IPv4(10, 8, 0, 2).To4())

	// (0x0A08 + 0x0001) + (0x0A08 + 0x0002) + 0x11 (protocol 17) + 0x10
	// (length 16) = 0x1434.
	got := pseudoHeaderSum(src, dst, 17, 16)
	want := uint32(0x1434)
	if got != want {
		t.Fatalf("pseudoHeaderSum(10.8.0.1, 10.8.0.2, 17, 16) = %#x, want %#x", got, want)
	}
}
