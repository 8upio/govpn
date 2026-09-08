package netstack

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
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
	valid := netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(clientIP), netstacktest.MustAddr(serverIP), 1, 1, make([]byte, 20))
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
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	fs.Inject(pkt)

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
	src := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	dst := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())

	// (0x0A08 + 0x0001) + (0x0A08 + 0x0002) + 0x11 (protocol 17) + 0x10
	// (length 16) = 0x1434.
	got := pseudoHeaderSum(src, dst, 17, 16)
	want := uint32(0x1434)
	if got != want {
		t.Fatalf("pseudoHeaderSum(10.8.0.1, 10.8.0.2, 17, 16) = %#x, want %#x", got, want)
	}
}

// TestParseIPv4FragmentFields asserts the three fragment fields parseIPv4
// now populates on EVERY parse — a complete datagram reports id 0, MF
// clear and offset 0 (and isFragment() false), a fragment reports the id
// and MF it carries plus an offset scaled from the on-wire 8-byte units
// into BYTES, which is the unit every call site in this package uses.
func TestParseIPv4FragmentFields(t *testing.T) {
	client := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	server := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())

	whole := buildIPv4(nil, client, server, protocolUDP, make([]byte, 16))
	hdr, err := parseIPv4(whole)
	if err != nil {
		t.Fatalf("parseIPv4(whole datagram): %v", err)
	}
	if hdr.id != 0 || hdr.moreFragments || hdr.fragOffset != 0 {
		t.Fatalf("whole datagram parsed as id=%d mf=%v off=%d, want 0/false/0", hdr.id, hdr.moreFragments, hdr.fragOffset)
	}
	if hdr.isFragment() {
		t.Fatal("isFragment() = true for a complete datagram")
	}

	// On the wire the offset field holds 1480/8 = 185; parseIPv4 must
	// report it back in bytes.
	frag := netstacktest.BuildFragment(client, server, protocolUDP, 0xBEEF, 1480, true, make([]byte, 16))
	hdr, err = parseIPv4(frag)
	if err != nil {
		t.Fatalf("parseIPv4(fragment): %v", err)
	}
	if hdr.id != 0xBEEF {
		t.Errorf("id = %#04x, want 0xBEEF", hdr.id)
	}
	if !hdr.moreFragments {
		t.Error("moreFragments = false, want true")
	}
	if hdr.fragOffset != 1480 {
		t.Errorf("fragOffset = %d, want 1480 (bytes, not 8-byte units)", hdr.fragOffset)
	}
	if !hdr.isFragment() {
		t.Error("isFragment() = false for a fragment")
	}

	// A final fragment (MF clear, non-zero offset) is still a fragment.
	last := netstacktest.BuildFragment(client, server, protocolUDP, 0xBEEF, 2960, false, make([]byte, 5))
	hdr, err = parseIPv4(last)
	if err != nil {
		t.Fatalf("parseIPv4(final fragment): %v", err)
	}
	if hdr.moreFragments || !hdr.isFragment() || hdr.fragOffset != 2960 {
		t.Fatalf("final fragment parsed as mf=%v off=%d isFragment=%v, want false/2960/true", hdr.moreFragments, hdr.fragOffset, hdr.isFragment())
	}
}

// TestParseIPv4RejectsBadFragmentGeometry asserts the three geometry rules
// parseIPv4 enforces before any fragment is ever buffered (RFC 791 §3.2):
// a fragment carries data, a non-final fragment's data length is a
// multiple of 8, and no fragment claims bytes past the 65535 a Total
// Length field can address.
func TestParseIPv4RejectsBadFragmentGeometry(t *testing.T) {
	client := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	server := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())

	tests := []struct {
		name        string
		offsetBytes int
		mf          bool
		payloadLen  int
	}{
		// 65528 + 20 = 65548, past the largest datagram RFC 791's
		// 16-bit Total Length field can express.
		{"offset plus length past 65535", 65528, false, 20},
		{"MF set with a payload length not a multiple of 8", 0, true, 13},
		{"MF set with an empty payload", 0, true, 0},
		{"non-zero offset with an empty payload", 1480, false, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := netstacktest.BuildFragment(client, server, protocolUDP, 1, tt.offsetBytes, tt.mf, make([]byte, tt.payloadLen))
			if _, err := parseIPv4(pkt); !errors.Is(err, errBadFragment) {
				t.Fatalf("parseIPv4 = %v, want errBadFragment", err)
			}
		})
	}
}

// TestParseIPv4FragmentWordsNeverPanic sweeps the identification and
// flags/fragment-offset words parseIPv4 now reads — including the maximum
// expressible offset — through the same never-panic discipline the rest of
// the header already gets (T-03-02). Unlike mustNotPanicParse, a parse here
// may legitimately SUCCEED (a valid fragment is no longer an error); only a
// panic fails the test.
func TestParseIPv4FragmentWordsNeverPanic(t *testing.T) {
	client := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())
	server := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	valid := buildIPv4(nil, client, server, protocolUDP, make([]byte, 24))

	for _, word := range []uint16{
		0x0000,
		flagMoreFragments,
		flagDontFragment,
		fragOffsetMask,                     // the maximum offset, 8191*8 = 65528
		flagMoreFragments | fragOffsetMask, // MF at the maximum offset
		0xFFFF,                             // every flag bit plus the maximum offset
		1, 2, 5, 185,
	} {
		for _, id := range []uint16{0, 1, 0xFFFF} {
			pkt := append([]byte(nil), valid...)
			binary.BigEndian.PutUint16(pkt[4:6], id)
			binary.BigEndian.PutUint16(pkt[6:8], word)
			mustNotPanicParseAny(t, pkt)

			// The same mutations on a truncated buffer, where a missing
			// length check would index out of range.
			for _, n := range []int{20, 21, 27, 33} {
				short := append([]byte(nil), pkt[:n]...)
				mustNotPanicParseAny(t, short)
			}
		}
	}
}

func mustNotPanicParseAny(t *testing.T, pkt []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseIPv4 panicked on %d-byte input %x: %v", len(pkt), pkt, r)
		}
	}()
	_, _ = parseIPv4(pkt)
}

// TestFragmentIPv4 asserts fragmentIPv4 produces RFC-791-conformant
// fragments of a 4000-byte datagram at a 1500-byte MTU — three fragments
// at offsets 0/1480/2960, MF set on all but the last, one shared
// identification, none larger than the MTU, every non-final payload a
// multiple of 8, and every header checksum self-consistent — and then
// closes the loop by feeding all three back through a reassembler and
// recovering the original payload byte-for-byte.
func TestFragmentIPv4(t *testing.T) {
	server := netstacktest.MustAddr(net.IPv4(10, 8, 0, 1).To4())
	client := netstacktest.MustAddr(net.IPv4(10, 8, 0, 2).To4())

	payload := make([]byte, 4000-minIPv4HeaderLen)
	for i := range payload {
		payload[i] = byte(i)
	}
	pkt := buildIPv4(nil, server, client, protocolUDP, payload)
	if len(pkt) != 4000 {
		t.Fatalf("test fixture is %d bytes, want 4000", len(pkt))
	}
	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4(fixture): %v", err)
	}

	const mtu = 1500
	frags := fragmentIPv4(hdr, pkt, mtu, 0x1234)
	if len(frags) != 3 {
		t.Fatalf("fragmentIPv4 produced %d fragments, want 3", len(frags))
	}

	wantOffsets := []int{0, 1480, 2960}
	wantMF := []bool{true, true, false}
	for i, frag := range frags {
		if len(frag) > mtu {
			t.Errorf("fragment %d is %d bytes, larger than the %d MTU", i, len(frag), mtu)
		}
		fh, err := parseIPv4(frag)
		if err != nil {
			t.Fatalf("parseIPv4(fragment %d): %v", i, err)
		}
		if fh.fragOffset != wantOffsets[i] {
			t.Errorf("fragment %d offset = %d, want %d", i, fh.fragOffset, wantOffsets[i])
		}
		if fh.moreFragments != wantMF[i] {
			t.Errorf("fragment %d MF = %v, want %v", i, fh.moreFragments, wantMF[i])
		}
		if fh.id != 0x1234 {
			t.Errorf("fragment %d id = %#04x, want 0x1234 (all fragments share one identification)", i, fh.id)
		}
		if fh.totalLen != len(frag) {
			t.Errorf("fragment %d Total Length = %d, want %d", i, fh.totalLen, len(frag))
		}
		if cs := internetChecksum(frag[:fh.ihl]); cs != 0 {
			t.Errorf("fragment %d header checksum does not fold to zero (got %#04x)", i, cs)
		}
		if data := fh.totalLen - fh.ihl; wantMF[i] && data%8 != 0 {
			t.Errorf("non-final fragment %d carries %d payload bytes, not a multiple of 8", i, data)
		}
	}

	// Round trip: the fragments this stack emits must be exactly the
	// fragments its own reassembler accepts.
	var r reassembler
	now := time.Unix(0, 0)
	var got []byte
	for i, frag := range frags {
		fh, err := parseIPv4(frag)
		if err != nil {
			t.Fatalf("parseIPv4(fragment %d): %v", i, err)
		}
		datagram, out, _ := r.add(now, fh, frag)
		if i < len(frags)-1 {
			if out != reasmBuffered {
				t.Fatalf("fragment %d outcome = %v, want reasmBuffered", i, out)
			}
			continue
		}
		if out != reasmComplete {
			t.Fatalf("final fragment outcome = %v, want reasmComplete", out)
		}
		got = datagram
	}
	gotHdr, err := parseIPv4(got)
	if err != nil {
		t.Fatalf("parseIPv4(round-tripped datagram): %v", err)
	}
	if gotHdr.isFragment() {
		t.Error("round-tripped datagram still parses as a fragment")
	}
	if gotHdr.totalLen != len(pkt) {
		t.Errorf("round-tripped Total Length = %d, want %d", gotHdr.totalLen, len(pkt))
	}
	if gotHdr.src != server || gotHdr.dst != client || gotHdr.protocol != protocolUDP {
		t.Errorf("round-tripped addressing = %v -> %v proto %d, want %v -> %v proto %d", gotHdr.src, gotHdr.dst, gotHdr.protocol, server, client, protocolUDP)
	}
	if cs := internetChecksum(got[:gotHdr.ihl]); cs != 0 {
		t.Errorf("round-tripped header checksum does not fold to zero (got %#04x)", cs)
	}
	// The identification deliberately survives reassembly (it is the
	// fragments' own, not the original's 0) — the PAYLOAD is what must
	// come back untouched.
	if !bytes.Equal(got[gotHdr.payloadOff:gotHdr.totalLen], payload) {
		t.Fatal("round-tripped payload is not byte-identical to the original")
	}
}
