// reassembly_test.go drives reassembler.add directly — no Stack, no
// attachment, no clock but the time.Time each call is handed — so every
// RFC 815 rule, every per-session bound and the lazy expiry sweep are
// asserted against the algorithm itself rather than through the stack that
// happens to call it.
package netstack

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

var (
	reasmSrc = mustAddr(net.IPv4(10, 8, 0, 2).To4())
	reasmDst = mustAddr(net.IPv4(10, 8, 0, 1).To4())
)

// addFrag parses frag and offers it to r, failing the test if the fragment
// this test just built is not one parseIPv4 accepts — a test fixture with
// invalid geometry would otherwise silently assert nothing.
func addFrag(t *testing.T, r *reassembler, now time.Time, frag []byte) ([]byte, reasmOutcome, int) {
	t.Helper()
	hdr, err := parseIPv4(frag)
	if err != nil {
		t.Fatalf("parseIPv4(test fragment): %v", err)
	}
	return r.add(now, hdr, frag)
}

// assertReassembled checks that datagram is a well-formed, fully
// reassembled IPv4 packet carrying want: MF/DF/offset all cleared, Total
// Length rewritten to the real length, a header checksum that folds to
// zero, and the exact payload bytes.
func assertReassembled(t *testing.T, datagram, want []byte) {
	t.Helper()

	hdr, err := parseIPv4(datagram)
	if err != nil {
		t.Fatalf("parseIPv4(reassembled datagram): %v", err)
	}
	if hdr.isFragment() {
		t.Errorf("reassembled datagram still parses as a fragment (mf=%v off=%d)", hdr.moreFragments, hdr.fragOffset)
	}
	if word := binary.BigEndian.Uint16(datagram[6:8]); word != 0 {
		t.Errorf("flags/fragment-offset word = %#04x, want 0 (MF, DF and offset all cleared)", word)
	}
	if hdr.totalLen != len(datagram) {
		t.Errorf("Total Length = %d, want %d", hdr.totalLen, len(datagram))
	}
	if hdr.totalLen != minIPv4HeaderLen+len(want) {
		t.Errorf("reassembled length = %d, want %d", hdr.totalLen, minIPv4HeaderLen+len(want))
	}
	if cs := internetChecksum(datagram[:hdr.ihl]); cs != 0 {
		t.Errorf("reassembled header checksum does not fold to zero (got %#04x)", cs)
	}
	if got := datagram[hdr.payloadOff:hdr.totalLen]; !bytes.Equal(got, want) {
		t.Errorf("reassembled payload = % x, want % x", got, want)
	}
}

// threeFragments splits a 24-byte payload into three 8-byte fragments of
// one datagram, in ascending offset order.
func threeFragments(id uint16) (payload []byte, frags [][]byte) {
	payload = []byte("AAAAAAAABBBBBBBBCCCCCCCC")
	frags = [][]byte{
		buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, id, 0, true, payload[0:8]),
		buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, id, 8, true, payload[8:16]),
		buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, id, 16, false, payload[16:24]),
	}
	return payload, frags
}

// TestReassemblyArrivalOrderIndependent asserts the central RFC 815
// property: the same three fragments produce the identical datagram no
// matter what order they arrive in — in order, exactly reversed, or
// interleaved with the final fragment in the middle.
func TestReassemblyArrivalOrderIndependent(t *testing.T) {
	orders := map[string][]int{
		"in order":    {0, 1, 2},
		"reversed":    {2, 1, 0},
		"interleaved": {1, 2, 0},
	}

	for name, order := range orders {
		t.Run(name, func(t *testing.T) {
			payload, frags := threeFragments(0x0042)
			var r reassembler
			now := time.Unix(1000, 0)

			var datagram []byte
			for i, idx := range order {
				out, outcome, expired := addFrag(t, &r, now, frags[idx])
				if expired != 0 {
					t.Fatalf("fragment %d: expired = %d, want 0", idx, expired)
				}
				if i < len(order)-1 {
					if outcome != reasmBuffered {
						t.Fatalf("fragment %d (arrival %d) outcome = %v, want reasmBuffered", idx, i, outcome)
					}
					continue
				}
				if outcome != reasmComplete {
					t.Fatalf("last fragment %d outcome = %v, want reasmComplete", idx, outcome)
				}
				datagram = out
			}

			assertReassembled(t, datagram, payload)

			if len(r.bufs) != 0 || r.bytes != 0 {
				t.Fatalf("after completion: %d buffers holding %d bytes, want 0/0", len(r.bufs), r.bytes)
			}
		})
	}
}

// TestReassemblyDuplicateFragment asserts a byte-identical duplicate is
// reported as such and — the part that matters — does not corrupt the
// buffer: the datagram still completes normally afterwards.
func TestReassemblyDuplicateFragment(t *testing.T) {
	payload, frags := threeFragments(7)
	var r reassembler
	now := time.Unix(1000, 0)

	if _, outcome, _ := addFrag(t, &r, now, frags[0]); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}
	if _, outcome, _ := addFrag(t, &r, now, frags[0]); outcome != reasmDuplicate {
		t.Fatalf("duplicate fragment outcome = %v, want reasmDuplicate", outcome)
	}

	if _, outcome, _ := addFrag(t, &r, now, frags[1]); outcome != reasmBuffered {
		t.Fatalf("second fragment outcome = %v, want reasmBuffered", outcome)
	}
	datagram, outcome, _ := addFrag(t, &r, now, frags[2])
	if outcome != reasmComplete {
		t.Fatalf("final fragment outcome = %v, want reasmComplete after a duplicate", outcome)
	}
	assertReassembled(t, datagram, payload)
}

// TestReassemblyPermissiveOverlap asserts this file's stated overlap
// policy: an overlapping fragment is accepted, its bytes overwrite what was
// buffered underneath, and the datagram completes.
func TestReassemblyPermissiveOverlap(t *testing.T) {
	var r reassembler
	now := time.Unix(1000, 0)

	// Bytes 0..15, MF set.
	firstPayload := []byte("XXXXXXXXXXXXXXXX")
	// Bytes 8..23, final — its 8 overlapping bytes must win over the
	// first fragment's.
	secondPayload := []byte("YYYYYYYYZZZZZZZZ")

	if _, outcome, _ := addFrag(t, &r, now, buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 9, 0, true, firstPayload)); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}
	datagram, outcome, _ := addFrag(t, &r, now, buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 9, 8, false, secondPayload))
	if outcome != reasmComplete {
		t.Fatalf("overlapping final fragment outcome = %v, want reasmComplete", outcome)
	}

	want := append(append([]byte(nil), firstPayload[0:8]...), secondPayload...)
	assertReassembled(t, datagram, want)
}

// TestReassemblyConflictsDropTheDatagram asserts the two genuine
// inconsistencies — a second final fragment declaring a different total
// length, and data landing beyond an already-known end — discard the whole
// buffer and return every one of its bytes to the budget, rather than
// leaving state whose contents depend on arrival order.
func TestReassemblyConflictsDropTheDatagram(t *testing.T) {
	tests := []struct {
		name   string
		second []byte
	}{
		{
			// A final fragment at 0..7 says the datagram is 8 bytes;
			// the first said 16.
			name:   "second final fragment declares a different total length",
			second: buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 3, 0, false, []byte("00000000")),
		},
		{
			// Bytes 16..23 lie past the known 16-byte end.
			name:   "data beyond an already-known end",
			second: buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 3, 16, true, []byte("11111111")),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r reassembler
			now := time.Unix(1000, 0)

			// Establishes totalLen = 16 while leaving bytes 0..7 missing.
			first := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 3, 8, false, []byte("FINALFIN"))
			if _, outcome, _ := addFrag(t, &r, now, first); outcome != reasmBuffered {
				t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
			}

			if _, outcome, _ := addFrag(t, &r, now, tt.second); outcome != reasmConflict {
				t.Fatalf("conflicting fragment outcome = %v, want reasmConflict", outcome)
			}
			if len(r.bufs) != 0 {
				t.Errorf("after a conflict: %d buffers remain, want 0", len(r.bufs))
			}
			if r.bytes != 0 {
				t.Errorf("after a conflict: %d bytes still accounted, want 0", r.bytes)
			}
		})
	}
}

// TestReassemblyLazyExpiry asserts the timeout is enforced without a timer
// or a goroutine: a buffer older than reassemblyTimeout is swept away by
// the NEXT add, whichever datagram that add belongs to, and reported in the
// expired return so the caller can count it.
func TestReassemblyLazyExpiry(t *testing.T) {
	var r reassembler
	start := time.Unix(1000, 0)

	_, frags := threeFragments(11)
	if _, outcome, _ := addFrag(t, &r, start, frags[0]); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}

	// One second before the deadline: a fragment for a SECOND datagram
	// sweeps nothing.
	other := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 12, 0, true, []byte("EARLYFRG"))
	if _, _, expired := addFrag(t, &r, start.Add(reassemblyTimeout-time.Second), other); expired != 0 {
		t.Fatalf("expired = %d one second before the deadline, want 0", expired)
	}

	// Past the FIRST datagram's deadline only: a fragment for a third
	// datagram sweeps exactly that one. The second datagram's own
	// deadline runs from ITS first fragment, so it survives — deadlines
	// are per datagram and are never extended by other traffic.
	third := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 13, 0, true, []byte("LATEFRAG"))
	_, _, expired := addFrag(t, &r, start.Add(reassemblyTimeout+time.Second), third)
	if expired != 1 {
		t.Fatalf("expired = %d, want 1 (counted per datagram dropped)", expired)
	}
	if len(r.bufs) != 2 {
		t.Fatalf("%d buffers remain, want 2 (the not-yet-stale one plus the sweeper)", len(r.bufs))
	}
	if r.bytes != 16 {
		t.Fatalf("%d bytes accounted, want 16 (the swept buffer's bytes were returned)", r.bytes)
	}
}

// TestReassemblyTimeoutIsNeverExtended asserts the deadline is fixed when a
// datagram's FIRST fragment arrives: dripping further fragments into the
// same buffer does not push it out, so an attacker cannot hold state open
// indefinitely by sending one fragment every 29 seconds.
func TestReassemblyTimeoutIsNeverExtended(t *testing.T) {
	var r reassembler
	start := time.Unix(1000, 0)

	_, frags := threeFragments(31)
	if _, outcome, _ := addFrag(t, &r, start, frags[0]); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}
	if _, outcome, _ := addFrag(t, &r, start.Add(reassemblyTimeout-time.Second), frags[1]); outcome != reasmBuffered {
		t.Fatalf("second fragment outcome = %v, want reasmBuffered", outcome)
	}

	// Had the second fragment extended the deadline, nothing would be
	// swept here.
	sweeper := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 32, 0, true, []byte("SWEEPFRG"))
	if _, _, expired := addFrag(t, &r, start.Add(reassemblyTimeout+time.Second), sweeper); expired != 1 {
		t.Fatalf("expired = %d, want 1 — the deadline was extended by a later fragment", expired)
	}
}

// TestReassemblyBufferCap asserts maxReassemblyBuffersPerSession: the
// 17th distinct datagram allocates nothing.
func TestReassemblyBufferCap(t *testing.T) {
	var r reassembler
	now := time.Unix(1000, 0)

	for i := 0; i < maxReassemblyBuffersPerSession; i++ {
		frag := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, uint16(i), 0, true, []byte("01234567"))
		if _, outcome, _ := addFrag(t, &r, now, frag); outcome != reasmBuffered {
			t.Fatalf("datagram %d outcome = %v, want reasmBuffered", i, outcome)
		}
	}

	overflow := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, uint16(maxReassemblyBuffersPerSession), 0, true, []byte("01234567"))
	if _, outcome, _ := addFrag(t, &r, now, overflow); outcome != reasmBoundExceeded {
		t.Fatalf("datagram %d outcome = %v, want reasmBoundExceeded", maxReassemblyBuffersPerSession, outcome)
	}
	if len(r.bufs) != maxReassemblyBuffersPerSession {
		t.Fatalf("%d buffers, want %d — the refused fragment must not allocate", len(r.bufs), maxReassemblyBuffersPerSession)
	}
}

// TestReassemblyByteCap asserts maxReassemblyBytesPerSession is charged by
// REACHED BUFFER LENGTH, not by bytes written: four 8-byte fragments, each
// at offset 65520, cost ~65 KiB apiece and exhaust the 256 KiB budget, so
// the fifth is refused. A sparse-fragment attacker is capped by exactly the
// same number as a dense one.
func TestReassemblyByteCap(t *testing.T) {
	var r reassembler
	now := time.Unix(1000, 0)

	const sparseOffset = 65520
	for i := 0; i < 4; i++ {
		frag := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, uint16(i), sparseOffset, true, []byte("01234567"))
		if _, outcome, _ := addFrag(t, &r, now, frag); outcome != reasmBuffered {
			t.Fatalf("sparse datagram %d outcome = %v, want reasmBuffered", i, outcome)
		}
	}
	if want := 4 * (sparseOffset + 8); r.bytes != want {
		t.Fatalf("accounted bytes = %d, want %d (charged by reached buffer length)", r.bytes, want)
	}

	fifth := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 4, sparseOffset, true, []byte("01234567"))
	if _, outcome, _ := addFrag(t, &r, now, fifth); outcome != reasmBoundExceeded {
		t.Fatalf("fifth sparse datagram outcome = %v, want reasmBoundExceeded", outcome)
	}
	if want := 4 * (sparseOffset + 8); r.bytes != want {
		t.Fatalf("accounted bytes = %d after the refusal, want %d unchanged", r.bytes, want)
	}
}

// TestReassemblyDiscardAll asserts the teardown seam: discardAll frees
// every buffer and permanently closes the reassembler, so a fragment
// arriving after an attachment is torn down allocates nothing.
func TestReassemblyDiscardAll(t *testing.T) {
	var r reassembler
	now := time.Unix(1000, 0)

	_, frags := threeFragments(21)
	if _, outcome, _ := addFrag(t, &r, now, frags[0]); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}

	r.discardAll()
	if len(r.bufs) != 0 || r.bytes != 0 {
		t.Fatalf("after discardAll: %d buffers holding %d bytes, want 0/0", len(r.bufs), r.bytes)
	}

	if _, outcome, _ := addFrag(t, &r, now, frags[1]); outcome != reasmClosed {
		t.Fatalf("add after discardAll = %v, want reasmClosed", outcome)
	}
	if len(r.bufs) != 0 || r.bytes != 0 {
		t.Fatalf("a fragment after discardAll allocated state: %d buffers, %d bytes", len(r.bufs), r.bytes)
	}

	// discardAll is idempotent — attachment.stop() may run more than once.
	r.discardAll()
}

// TestReassemblyCustomBufferLimit asserts a reassembler constructed with a
// non-zero maxBufs enforces THAT bound instead of
// maxReassemblyBuffersPerSession, exercising WithReassemblyLimits'
// MaxDatagramsPerAttachment end to end at the reassembler layer.
func TestReassemblyCustomBufferLimit(t *testing.T) {
	r := reassembler{maxBufs: 2}
	now := time.Unix(1000, 0)

	for i := 0; i < 2; i++ {
		frag := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, uint16(i), 0, true, []byte("01234567"))
		if _, outcome, _ := addFrag(t, &r, now, frag); outcome != reasmBuffered {
			t.Fatalf("datagram %d outcome = %v, want reasmBuffered", i, outcome)
		}
	}

	// A default-limit reassembler would accept a third and even a
	// sixteenth concurrent half-reassembled datagram; this one, limited
	// to 2, must refuse the third.
	third := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 2, 0, true, []byte("01234567"))
	if _, outcome, _ := addFrag(t, &r, now, third); outcome != reasmBoundExceeded {
		t.Fatalf("third datagram outcome = %v, want reasmBoundExceeded with maxBufs=2", outcome)
	}

	// The default-limit reassembler accepts up to maxReassemblyBuffersPerSession
	// (16) — confirm the custom-limit one is strictly tighter than that
	// default, not merely coincidentally rejecting this one fragment.
	var defaultR reassembler
	for i := 0; i < 16; i++ {
		frag := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, uint16(100+i), 0, true, []byte("01234567"))
		if _, outcome, _ := addFrag(t, &defaultR, now, frag); outcome != reasmBuffered {
			t.Fatalf("default-limit datagram %d outcome = %v, want reasmBuffered (default accepts 16)", i, outcome)
		}
	}
}

// TestReassemblyCustomTimeout asserts a reassembler constructed with a
// non-zero timeout is swept using THAT duration instead of
// reassemblyTimeout, exercising WithReassemblyLimits' Timeout end to end.
func TestReassemblyCustomTimeout(t *testing.T) {
	shortTimeout := 5 * time.Second
	r := reassembler{timeout: shortTimeout}
	start := time.Unix(1000, 0)

	first := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 1, 0, true, []byte("01234567"))
	if _, outcome, _ := addFrag(t, &r, start, first); outcome != reasmBuffered {
		t.Fatalf("first fragment outcome = %v, want reasmBuffered", outcome)
	}

	// Past the CUSTOM (short) timeout but well inside the default 30s
	// reassemblyTimeout: a fragment for a second datagram must sweep the
	// first, proving the shortened timeout — not the package default —
	// is what's enforced.
	sweeper := buildFragmentForTest(reasmSrc, reasmDst, protocolUDP, 2, 0, true, []byte("SWEEPFRG"))
	_, _, expired := addFrag(t, &r, start.Add(shortTimeout+time.Second), sweeper)
	if expired != 1 {
		t.Fatalf("expired = %d, want 1 — the shortened timeout was not enforced", expired)
	}
}

// TestReassemblyZeroValueUsesDefaults asserts a zero-value reassembler
// (reassembly_test.go's own construction pattern, used by every other test
// in this file) resolves to the three package-constant defaults, exactly
// as it did before maxBufs/maxBytes/timeout existed.
func TestReassemblyZeroValueUsesDefaults(t *testing.T) {
	var r reassembler
	maxBufs, maxBytes, timeout := r.resolveLimits()
	if maxBufs != maxReassemblyBuffersPerSession {
		t.Fatalf("resolveLimits maxBufs = %d, want %d (default)", maxBufs, maxReassemblyBuffersPerSession)
	}
	if maxBytes != maxReassemblyBytesPerSession {
		t.Fatalf("resolveLimits maxBytes = %d, want %d (default)", maxBytes, maxReassemblyBytesPerSession)
	}
	if timeout != reassemblyTimeout {
		t.Fatalf("resolveLimits timeout = %v, want %v (default)", timeout, reassemblyTimeout)
	}
}
