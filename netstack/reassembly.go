// reassembly.go implements RFC 815's hole-descriptor reassembly algorithm
// ("IP Datagram Reassembly Algorithms", rfc-editor.org/rfc/rfc815) over the
// in-tunnel IPv4 fragments of ONE attached session, bounded by three fixed
// per-session limits so a hostile client's fragments can never grow this
// stack's state without bound. Nothing here knows about Stack or stats: add
// returns an outcome and deliver maps that outcome onto exactly one counter.
//
// Overlap policy is RFC 815 PERMISSIVE: an overlapping fragment is accepted
// and its bytes overwrite whatever was buffered underneath. That is safe
// here in a way it is not for a general-purpose gateway stack, for three
// reasons:
//
//   - the source-IP ACL in Stack.deliver runs strictly BEFORE add, so the
//     only party that can ever write into a session's reassembly buffer is
//     that session itself — there is no second writer whose view a
//     conflicting overlap could shadow;
//   - there is no middlebox downstream reassembling the same bytes with a
//     different policy, so the classic overlap-evasion attack (send one
//     view to the IDS, another to the host) has no second reassembler to
//     disagree with;
//   - parseIPv4 validates fragment geometry before any buffering, and every
//     write below is a bounds-checked Go slice operation, so the Teardrop
//     class of attack (negative/wrapping offsets, oversized copies) cannot
//     reach memory here at all.
//
// Only genuine inconsistencies discard a datagram: a second final (MF=0)
// fragment declaring a different total length, or data landing beyond an
// already-known total length. Those are ambiguity, not overlap, and there
// is no correct reassembly of them.
//
//   - fragmentation fields, 8-byte offset units: RFC 791 §3.1-3.2
//   - hole descriptor list: RFC 815
//   - reassembly timeout guidance (and this file's deliberate deviation
//     from it): RFC 1122 §3.3.2
package netstack

import (
	"encoding/binary"
	"net/netip"
	"sync"
	"time"
)

const (
	// maxReassemblyBuffersPerSession caps how many distinct datagrams one
	// session may have half-reassembled at once. 16 is the same order of
	// magnitude as this stack's existing per-session TCP caps
	// (maxHalfOpenPerSession 8, maxLiveConnsPerSession 64,
	// tcp_timer.go): enough for any real client's in-flight SIP/RTP
	// traffic, small enough that the O(n) expiry sweep below stays free.
	maxReassemblyBuffersPerSession = 16

	// maxReassemblyBytesPerSession caps the bytes one session's
	// half-reassembled datagrams may hold: 4 maximum-size IPv4 datagrams.
	// This is a PER-AUTHENTICATED-SESSION bound, not a system-wide one —
	// one client's fragment flood cannot starve another's.
	maxReassemblyBytesPerSession = 256 * 1024

	// reassemblyTimeout is how long a partially-reassembled datagram
	// lives before it is discarded. 30 s is Linux's own net.ipv4.
	// ipfrag_time default, a deliberate deviation from RFC 1122 §3.3.2's
	// 60-120 s guidance chosen to halve the window in which state can be
	// held. The deadline is fixed when the FIRST fragment of a datagram
	// arrives and is NEVER extended by later fragments, so an attacker
	// cannot keep a buffer alive indefinitely by dripping one fragment
	// into it every 29 seconds.
	reassemblyTimeout = 30 * time.Second

	// holeOpenEnd is the `last` value of the initial hole: "end unknown".
	// The largest byte offset any datagram can have is maxIPv4Datagram-1
	// (RFC 791 §3.1's Total Length is 16 bits and offsets are 0-based), so
	// this hole means "everything from 0 to the largest offset that could
	// possibly exist" until an MF=0 fragment reveals the real end.
	holeOpenEnd = maxIPv4Datagram - 1
)

// reassemblyKey is RFC 791 §3.2's own reassembly identity: fragments are
// gathered by (source, destination, protocol, identification), never by
// identification alone.
type reassemblyKey struct {
	src      netip.Addr
	dst      netip.Addr
	protocol uint8
	id       uint16
}

// hole is one RFC 815 hole descriptor: an inclusive [first, last] byte
// range of the datagram that has not been received yet.
type hole struct {
	first int
	last  int
}

// reassemblyBuffer is one datagram under reassembly.
type reassemblyBuffer struct {
	// header is a copy of the offset-0 fragment's ihl header bytes, nil
	// until that fragment arrives. The datagram cannot be completed
	// without it — it is the only fragment whose header describes the
	// whole datagram's options.
	header []byte

	// data holds the payload bytes received so far. Its LENGTH is the
	// highest byte end seen, and it is that length — not the number of
	// bytes actually written — that is charged against the byte budget.
	data []byte

	// holes is the RFC 815 hole list, kept sorted and disjoint. Empty
	// means every byte below totalLen has arrived.
	holes []hole

	// totalLen is the datagram's full payload length, -1 until an MF=0
	// fragment reveals it.
	totalLen int

	// expires is the fixed deadline set from the first fragment.
	expires time.Time
}

// reassembler is one attached session's whole reassembly state. The zero
// value is ready to use: bufs is created lazily on the first add, so an
// attachment that never sees a fragment allocates nothing at all.
type reassembler struct {
	mu     sync.Mutex
	bufs   map[reassemblyKey]*reassemblyBuffer
	bytes  int
	closed bool
}

// reasmOutcome is what add did with a fragment. deliver maps each of these
// onto exactly one Stats counter.
type reasmOutcome int

const (
	// reasmBuffered: the fragment was stored; the datagram is incomplete.
	reasmBuffered reasmOutcome = iota

	// reasmComplete: the fragment completed the datagram, which is
	// returned.
	reasmComplete

	// reasmDuplicate: the fragment covered no missing byte range.
	reasmDuplicate

	// reasmConflict: the fragment contradicted what was already known
	// about the datagram; the whole buffer was discarded.
	reasmConflict

	// reasmBoundExceeded: accepting the fragment would have exceeded a
	// per-session bound.
	reasmBoundExceeded

	// reasmClosed: discardAll has run — the session is going away.
	reasmClosed
)

// add offers one fragment to the reassembler and reports what happened.
// now is the caller's injected clock reading (Stack.deliver passes
// s.clock.Now()) — this file never touches the wall clock itself, which is
// what makes its expiry behavior assertable against a fake clock.
//
// hdr must already have been validated by parseIPv4 and must satisfy
// hdr.isFragment(). expired reports how many DATAGRAMS this call swept away
// as timed out, so the caller can count them.
//
// On reasmComplete the returned datagram is a freshly allocated, fully
// reassembled IPv4 packet with its Total Length rewritten, its
// flags/fragment-offset word zeroed (so MF, DF and the offset are all
// clear and the result can never be fed back into this reassembler) and a
// recomputed header checksum.
func (r *reassembler) add(now time.Time, hdr ipv4Header, pkt []byte) (datagram []byte, out reasmOutcome, expired int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil, reasmClosed, 0
	}

	// Lazy expiry: no goroutine and no timer. With at most
	// maxReassemblyBuffersPerSession entries an O(n) sweep on every
	// fragment is cheaper than a timer would be to arm and cancel. The
	// consequence, accepted deliberately: a session that sends one
	// fragment and then goes quiet holds that buffer's bytes until its
	// next fragment or until its attachment is torn down (discardAll).
	// Bounded either way.
	for k, b := range r.bufs {
		if !now.Before(b.expires) {
			r.dropLocked(k, b)
			expired++
		}
	}

	payload := pkt[hdr.payloadOff:hdr.totalLen]
	first := hdr.fragOffset
	last := first + len(payload) - 1

	key := reassemblyKey{src: hdr.src, dst: hdr.dst, protocol: hdr.protocol, id: hdr.id}
	b := r.bufs[key]
	if b == nil {
		if len(r.bufs) >= maxReassemblyBuffersPerSession {
			return nil, reasmBoundExceeded, expired
		}
		if r.bufs == nil {
			r.bufs = make(map[reassemblyKey]*reassemblyBuffer)
		}
		b = &reassemblyBuffer{
			holes:    []hole{{first: 0, last: holeOpenEnd}},
			totalLen: -1,
			expires:  now.Add(reassemblyTimeout),
		}
		r.bufs[key] = b
	}

	// Consistency, before a single byte is touched. Data beyond an
	// already-known end, or a second final fragment declaring a different
	// end, is an ambiguity no reassembly can resolve: discard the whole
	// datagram rather than keeping a buffer whose contents depend on
	// arrival order.
	if b.totalLen >= 0 && last >= b.totalLen {
		r.dropLocked(key, b)
		return nil, reasmConflict, expired
	}
	if !hdr.moreFragments {
		if b.totalLen >= 0 && b.totalLen != last+1 {
			r.dropLocked(key, b)
			return nil, reasmConflict, expired
		}
		b.totalLen = last + 1
	}

	// Byte cap, charged by REACHED BUFFER LENGTH rather than by bytes
	// actually written: an 8-byte fragment at offset 65000 costs 65 KiB,
	// exactly as a dense 65 KiB datagram would, so a sparse-fragment
	// attacker is capped by the same number as a dense one. The fragment
	// is discarded; the buffer survives and expires on its own.
	grow := last + 1 - len(b.data)
	if grow < 0 {
		grow = 0
	}
	if r.bytes+grow > maxReassemblyBytesPerSession {
		return nil, reasmBoundExceeded, expired
	}

	// RFC 815 steps 1-8: replace every hole this fragment intersects with
	// the up-to-two remainder holes around it.
	var newHoles []hole
	intersects := false
	for _, h := range b.holes {
		if !hdr.moreFragments && h.first > last {
			// This fragment is the last one: no hole can exist beyond
			// its end (RFC 815 step 7's "if more fragments" condition,
			// read from the other side).
			continue
		}
		if last < h.first || first > h.last {
			newHoles = append(newHoles, h)
			continue
		}
		intersects = true
		if first > h.first {
			newHoles = append(newHoles, hole{first: h.first, last: first - 1})
		}
		if last < h.last && hdr.moreFragments {
			newHoles = append(newHoles, hole{first: last + 1, last: h.last})
		}
	}
	b.holes = newHoles

	// Copy the payload unconditionally, intersecting or not: newer bytes
	// win over buffered ones. That IS the permissive overlap policy this
	// file's header comment justifies.
	if last+1 > len(b.data) {
		grown := make([]byte, last+1)
		copy(grown, b.data)
		r.bytes += len(grown) - len(b.data)
		b.data = grown
	}
	copy(b.data[first:], payload)
	if first == 0 {
		b.header = append([]byte(nil), pkt[:hdr.ihl]...)
	}

	if !intersects {
		// The fragment covered no missing range: a pure duplicate. The
		// buffer stays exactly as it was (its bytes were already
		// accounted) and the datagram can still complete later.
		return nil, reasmDuplicate, expired
	}

	if len(b.holes) != 0 || b.totalLen < 0 || b.header == nil || b.totalLen > len(b.data) {
		return nil, reasmBuffered, expired
	}

	if len(b.header)+b.totalLen > maxIPv4Datagram {
		// Only reachable with IP options: a payload that exactly fills a
		// 65535-byte datagram plus an options-bearing header would not
		// fit its own Total Length field. Treat it as the inconsistency
		// it is.
		r.dropLocked(key, b)
		return nil, reasmConflict, expired
	}

	out2 := make([]byte, 0, len(b.header)+b.totalLen)
	out2 = append(out2, b.header...)
	out2 = append(out2, b.data[:b.totalLen]...)

	binary.BigEndian.PutUint16(out2[2:4], uint16(len(out2)))
	binary.BigEndian.PutUint16(out2[6:8], 0)
	out2[10], out2[11] = 0, 0
	binary.BigEndian.PutUint16(out2[10:12], internetChecksum(out2[:len(b.header)]))

	r.dropLocked(key, b)
	return out2, reasmComplete, expired
}

// dropLocked deletes b from the buffer map and returns its bytes to the
// budget. r.mu must be held.
func (r *reassembler) dropLocked(key reassemblyKey, b *reassemblyBuffer) {
	r.bytes -= len(b.data)
	delete(r.bufs, key)
}

// discardAll drops every buffer, zeroes the byte budget and permanently
// closes the reassembler: every later add returns reasmClosed. Called from
// attachment.stop(), the single teardown seam Detach, Close and
// detachAttachment all funnel through.
func (r *reassembler) discardAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	r.bufs = nil
	r.bytes = 0
}
