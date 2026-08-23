// Package reliable is a Go port of the OpenVPN control-channel reliability
// layer: ACK bookkeeping, packet-ID windows, retransmission scheduling and
// strictly in-order delivery on top of unreliable UDP.
//
// Every constant and heuristic below is traceable to the pinned OpenVPN
// reference checkout (/Users/svenloth/dev/openvpn-reference, branch
// release/2.6, commit c9b790f5b9e8ebca5da38c22f479c31bb8d33686):
//
//   - window/capacity/fast-retransmit constants: src/openvpn/reliable.h:44-56
//     (RELIABLE_ACK_SIZE, RELIABLE_CAPACITY, N_ACK_RETRANSMIT)
//   - send/receive window sizes: src/openvpn/ssl_pkt.h:70-71
//     (TLS_RELIABLE_N_SEND_BUFFERS=6, TLS_RELIABLE_N_REC_BUFFERS=12)
//   - retransmit timeout default and exponential backoff:
//     src/openvpn/options.c:876 (o->tls_timeout = 2), src/openvpn/reliable.c:
//     662-699 (reliable_send: best->timeout *= 2 on every (re)send, and the
//     n_acks >= N_ACK_RETRANSMIT fast-retransmit path)
//   - handshake window default: src/openvpn/options.c:880
//     (o->handshake_window = 60)
//   - packet-ID range/replay/wraparound checks: src/openvpn/reliable.c:42-95
//     (subtract_pid, reliable_pid_in_range1/2, reliable_pid_min),
//     src/openvpn/reliable.c:487-532 (reliable_not_replay,
//     reliable_wont_break_sequentiality)
//   - ACK purge and fast-retransmit counter: src/openvpn/reliable.c:407-445
//     (reliable_send_purge)
//   - in-order delivery: src/openvpn/reliable.c:617-631 (
//     reliable_get_entry_sequenced), 818-833 (reliable_mark_deleted)
//
// The reliability-layer packet ID (PacketID, a plain uint32) is
// intentionally a distinct Go type from internal/tlscrypt's own 8-byte
// packet ID (sequence + timestamp). This package never imports
// internal/tlscrypt, and the two packet-ID spaces are never compared or
// assigned to each other — confusing them is flagged in 01-RESEARCH.md as
// the single easiest way to build something that looks correct and
// silently is not.
package reliable

import (
	"sync"
	"time"
)

const (
	// AckSize: reliable.h:44 (RELIABLE_ACK_SIZE) — the maximum number of
	// packet IDs that can be piggybacked in one ack record.
	AckSize = 8

	// Capacity: reliable.h:49 (RELIABLE_CAPACITY) — the maximum number of
	// entries a reliable{} struct can hold.
	Capacity = 12

	// NSendBuffers: ssl_pkt.h:70 (TLS_RELIABLE_N_SEND_BUFFERS) — the
	// send-side window size ("also window size for reliability layer").
	NSendBuffers = 6

	// NRecBuffers: ssl_pkt.h:71 (TLS_RELIABLE_N_REC_BUFFERS) — the
	// receive-side window size.
	NRecBuffers = 12

	// NAckRetransmit: reliable.h:53 (N_ACK_RETRANSMIT) — an unacknowledged
	// entry is resent early, independent of its timeout, once this many
	// later packets have been acknowledged.
	NAckRetransmit = 3

	// TLSTimeout: options.c:876 (--tls-timeout default) — the initial
	// per-entry retransmit timeout. Doubles on every (re)send
	// (reliable.c:690, best->timeout *= 2).
	TLSTimeout = 2 * time.Second

	// HandshakeWindow: options.c:880 (--hand-window default) — the hard
	// ceiling on total handshake time before the session is torn down.
	HandshakeWindow = 60 * time.Second
)

// PacketID is the control-channel reliability layer's own 4-byte packet ID
// (packet_id_type, short form). See the package doc for why this must never
// be confused with internal/tlscrypt's own, differently-sized packet ID.
type PacketID uint32

// Clock abstracts wall-clock time so retransmit/backoff behavior can be
// driven from an injected fake clock in tests instead of real sleeps.
type Clock interface {
	Now() time.Time
}

// SystemClock is the default Clock, backed by time.Now.
type SystemClock struct{}

// Now implements Clock.
func (SystemClock) Now() time.Time { return time.Now() }

// subtractPID mirrors subtract_pid (reliable.c:44-48): test - base, while
// allowing for base or test wraparound. test is assumed to be "higher" than
// base in the wraparound-aware sense used throughout this file.
func subtractPID(test, base PacketID) uint32 {
	return uint32(test - base)
}

// pidInRange1 mirrors reliable_pid_in_range1 (reliable.c:53-59): verifies
// that test-base < extent, while allowing for base or test wraparound.
func pidInRange1(test, base PacketID, extent uint32) bool {
	return subtractPID(test, base) < extent
}

// pidInRange2 mirrors reliable_pid_in_range2 (reliable.c:64-85): verifies
// that test < base+extent, while allowing for base or test wraparound.
func pidInRange2(test, base PacketID, extent uint32) bool {
	b := uint32(base)
	t := uint32(test)
	if b+extent >= b {
		return t < b+extent
	}
	return (t + 0x80000000) < (b+0x80000000)+extent
}

// pidMin mirrors reliable_pid_min (reliable.c:90-95): verifies that p1 < p2,
// while allowing for p1 or p2 wraparound.
func pidMin(p1, p2 PacketID) bool {
	return !pidInRange1(p1, p2, 0x80000000)
}

// entry mirrors struct reliable_entry (reliable.h:74-85). payload holds the
// exact bytes to (re)send for a send-side entry, or the delivered bytes for
// a receive-side entry — Go slices need no preallocated buffer size or
// offset the way the reference's fixed C buffers do.
type entry struct {
	active   bool
	timeout  time.Duration
	nextTry  time.Time
	packetID PacketID
	nAcks    int // reliable_entry.n_acks: acks received for later packets
	payload  []byte
}

// Reliable is a Go port of struct reliable (reliable.h:91-99): the storage
// for one VPN tunnel's control channel in ONE direction. A caller owns two
// instances per connection — one sized NSendBuffers for outgoing entries
// (Next/MarkActive/SetPayload/Ack/Due), one sized NRecBuffers for incoming
// entries (Put/Get) — mirroring the reference's separate send_reliable and
// rec_reliable per tls_session.
type Reliable struct {
	clock Clock

	mu   sync.Mutex
	size int

	// initialTimeout: rel->initial_timeout, applied to every entry's
	// timeout when it is (re)marked active outgoing.
	initialTimeout time.Duration

	// packetID: rel->packet_id. On the send side, the next ID to assign to
	// a newly-marked-active outgoing entry. On the receive side, the
	// lowest ID not yet consumed by Get (the "already consumed" floor
	// used by Put's replay check).
	packetID PacketID

	entries [Capacity]entry
}

// New builds a Reliable with the given array size (reliable_init,
// reliable.c:357-373), using clock to drive retransmit timing. If clock is
// nil, SystemClock is used. size must be in (0, Capacity].
func New(clock Clock, size int) *Reliable {
	if clock == nil {
		clock = SystemClock{}
	}
	if size <= 0 || size > Capacity {
		panic("reliable: size out of range")
	}
	return &Reliable{clock: clock, size: size, initialTimeout: TLSTimeout}
}

// ---------------------------------------------------------------------
// Send-side: Next, MarkActive, SetPayload, Ack, Due, Empty.
// ---------------------------------------------------------------------

// Next returns a free entry index for a new outgoing packet, honoring the
// output-sequenced ordering check (reliable_get_buf_output_sequenced,
// reliable.c:582-615): if the window's minimum active packet ID is more
// than size behind the next ID to be assigned, no free entry is returned
// even if one is physically free — this is what makes a Write blocking on
// a full 6-entry send window actually mean something: the window can't
// silently grow past what the peer's own receive window (NRecBuffers) can
// hold.
func (r *Reliable) Next() (idx int, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	minDefined := false
	var minID PacketID
	for i := 0; i < r.size; i++ {
		e := &r.entries[i]
		if e.active {
			if !minDefined || pidMin(e.packetID, minID) {
				minDefined = true
				minID = e.packetID
			}
		}
	}
	if minDefined && !pidInRange1(r.packetID, minID, uint32(r.size)) {
		return 0, false
	}
	for i := 0; i < r.size; i++ {
		if !r.entries[i].active {
			return i, true
		}
	}
	return 0, false
}

// MarkActive assigns the next monotonically increasing packet ID to the
// entry at idx (previously returned by Next) and marks it active
// (reliable_mark_active_outgoing, reliable.c:791-815): the entry's timeout
// is set to the reliable's initial timeout and it is marked due
// immediately (next_try = 0 in the reference; here, the zero time.Time,
// which is always considered "due" by Due).
func (r *Reliable) MarkActive(idx int) PacketID {
	r.mu.Lock()
	defer r.mu.Unlock()

	e := &r.entries[idx]
	e.packetID = r.packetID
	r.packetID++
	e.active = true
	e.nAcks = 0
	e.timeout = r.initialTimeout
	e.nextTry = time.Time{}
	return e.packetID
}

// SetPayload stores the exact wire bytes to (re)send for the entry at idx.
// It is separate from MarkActive because building those bytes (piggybacked
// ACKs, session IDs) requires the packet ID MarkActive assigns.
func (r *Reliable) SetPayload(idx int, payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[idx].payload = payload
}

// Ack purges acknowledged entries and bumps the fast-retransmit counter on
// any still-active entry with a lower packet ID (reliable_send_purge,
// reliable.c:408-445): an ACK for a higher packet ID means either the ACKs
// arrived out of order or the lower packet was lost, so the counter is used
// by Due to trigger an early resend once NAckRetransmit later packets have
// been acknowledged — independent of the entry's own timeout.
func (r *Reliable) Ack(ids []PacketID) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, pid := range ids {
		for i := 0; i < r.size; i++ {
			e := &r.entries[i]
			if !e.active {
				continue
			}
			if e.packetID == pid {
				e.active = false
			} else if e.packetID < pid {
				e.nAcks++
			}
		}
	}
}

// Due returns the active entry with the lowest packet ID that is ready for
// (re)send — either its per-entry timeout has elapsed or NAckRetransmit
// later packets have already been ACKed (reliable_send, reliable.c:
// 662-699). Calling Due applies the reference's exponential backoff: the
// returned entry's timeout doubles and its due time is pushed out by the
// (now-doubled) interval, and its fast-retransmit counter resets to 0.
func (r *Reliable) Due() (payload []byte, id PacketID, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	nowT := r.clock.Now()
	var best *entry
	for i := 0; i < r.size; i++ {
		e := &r.entries[i]
		if !e.active {
			continue
		}
		if e.nAcks >= NAckRetransmit || !nowT.Before(e.nextTry) {
			if best == nil || pidMin(e.packetID, best.packetID) {
				best = e
			}
		}
	}
	if best == nil {
		return nil, 0, false
	}
	best.nextTry = nowT.Add(best.timeout)
	best.timeout *= 2
	best.nAcks = 0
	return best.payload, best.packetID, true
}

// Empty reports whether no entries are active (reliable_empty,
// reliable.c:392-405).
func (r *Reliable) Empty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := 0; i < r.size; i++ {
		if r.entries[i].active {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------
// Receive-side: Put, Get.
// ---------------------------------------------------------------------

// PutResult classifies the outcome of Put.
type PutResult int

const (
	// PutRejected: id is at or below the lowest already-consumed ID, or
	// would need more buffer slots than the window's capacity allows
	// before its gap is filled — the caller must not acknowledge it.
	PutRejected PutResult = iota

	// PutAccepted: id was newly stored. The caller should acknowledge it
	// and may now be able to drain more in-order data via Get.
	PutAccepted

	// PutDuplicate: id matches a currently-active, not-yet-consumed entry
	// — a legitimate retransmission. The caller should acknowledge it
	// again (to help the peer stop retransmitting) but there is nothing
	// new to store or deliver.
	PutDuplicate
)

// Put stores an incoming packet's payload under packet ID id, applying the
// reference's replay and sequentiality checks before it is stored
// (reliable_not_replay, reliable.c:487-512; reliable_wont_break_sequentiality,
// reliable.c:514-532):
//
//   - an ID at or below the lowest not-yet-consumed ID is rejected (it is
//     genuinely too old to matter — either already delivered or long since
//     superseded)
//   - an ID matching a currently-active (not-yet-consumed) entry is a
//     legitimate retransmission: accepted once as PutAccepted, and any
//     further retransmission of the same still-active ID reports
//     PutDuplicate rather than being stored a second time
//   - an ID that would need more buffer slots than the window's capacity
//     allows before the gap between it and the lowest not-yet-consumed ID
//     is filled is rejected, so a peer cannot force unbounded buffering by
//     sending a far-future ID (T-01-13)
func (r *Reliable) Put(id PacketID, payload []byte) PutResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	if pidMin(id, r.packetID) {
		return PutRejected
	}
	for i := 0; i < r.size; i++ {
		e := &r.entries[i]
		if e.active && e.packetID == id {
			return PutDuplicate
		}
	}
	if !pidInRange2(id, r.packetID, uint32(r.size)) {
		return PutRejected
	}
	for i := 0; i < r.size; i++ {
		e := &r.entries[i]
		if !e.active {
			e.active = true
			e.packetID = id
			e.nAcks = 0
			e.payload = payload
			return PutAccepted
		}
	}
	// No free entry: every slot is legitimately occupied by an
	// in-window, not-yet-consumed ID. This mirrors reliable_can_get
	// returning false; the caller's own window-size sizing (NRecBuffers)
	// makes this unreachable once pidInRange2 above has already passed,
	// but is kept as a defensive fallback rather than a panic.
	return PutRejected
}

// Get removes and returns, in order, the next sequential active entry
// (reliable_get_entry_sequenced + reliable_mark_deleted, reliable.c:
// 618-631, 818-833): Get returns ok=false once the entry for the current
// lowest not-yet-consumed ID hasn't arrived yet, so repeated calls after
// each Put drain exactly the in-order prefix that has arrived so far —
// concatenating those payloads in the order Get returns them reproduces
// the original ordered byte stream with no separate reassembly step.
func (r *Reliable) Get() (payload []byte, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i := 0; i < r.size; i++ {
		e := &r.entries[i]
		if e.active && e.packetID == r.packetID {
			e.active = false
			r.packetID = e.packetID + 1
			return e.payload, true
		}
	}
	return nil, false
}

// ---------------------------------------------------------------------
// AckSet: pending ACKs to piggyback on outgoing packets.
// ---------------------------------------------------------------------

// AckSet accumulates packet IDs of received packets that are pending
// acknowledgment to the peer, mirroring struct reliable_ack (reliable.h:
// 61-65) and reliable_ack_acknowledge_packet_id (reliable.c:131-145).
//
// Unlike the reference's fixed RELIABLE_ACK_SIZE=8 storage (which relies on
// a separate ack_mru structure for redundant re-acking once full — an
// optimization out of scope for Phase 1), AckSet accumulates without a
// storage cap and only caps how many IDs Drain hands out per outgoing
// packet, per the ACK piggyback policy (ssl.c:3146-3177, RESEARCH Pattern
// 3): "an outgoing packet piggybacks up to 8 pending ACKs plus the peer
// session ID; with more than 8 pending, the remainder stay queued for the
// next packet."
type AckSet struct {
	mu  sync.Mutex
	ids []PacketID
}

// Add records id for later acknowledgment. It is a no-op if id is already
// pending.
func (a *AckSet) Add(id PacketID) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, existing := range a.ids {
		if existing == id {
			return
		}
	}
	a.ids = append(a.ids, id)
}

// Drain removes and returns up to AckSize pending IDs — the maximum that
// fits in one ack record — leaving any remainder queued for the next
// outgoing packet.
func (a *AckSet) Drain() []PacketID {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := len(a.ids)
	if n > AckSize {
		n = AckSize
	}
	out := append([]PacketID(nil), a.ids[:n]...)
	a.ids = a.ids[n:]
	return out
}

// Peek reports whether any IDs are pending without draining them.
func (a *AckSet) Peek() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.ids) > 0
}
