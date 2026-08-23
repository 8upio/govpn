package reliable

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/8upio/govpn/internal/tlscrypt"
)

// fakeClock is an injectable Clock a test fully controls, so retransmit and
// backoff behavior can be asserted deterministically in milliseconds
// instead of driving real 2/4/8-second sleeps.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Unix(0, 0)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

var _ Clock = (*fakeClock)(nil)

// TestRetransmitBackoff asserts the observed resend intervals are 2s, then
// 4s, then 8s on the injected clock (reliable_send, reliable.c:662-699:
// best->timeout *= 2 on every (re)send).
func TestRetransmitBackoff(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NSendBuffers)

	idx, ok := r.Next()
	if !ok {
		t.Fatal("expected a free send slot")
	}
	id := r.MarkActive(idx)
	r.SetPayload(idx, []byte("payload"))

	// Marked active outgoing: due immediately (next_try = 0 in the
	// reference).
	if _, gotID, ok := r.Due(); !ok || gotID != id {
		t.Fatal("expected the freshly-marked entry due immediately")
	}

	// Not due again until TLSTimeout (2s) elapses.
	clock.Advance(TLSTimeout - time.Millisecond)
	if _, _, ok := r.Due(); ok {
		t.Fatal("entry became due before its initial 2s timeout elapsed")
	}
	clock.Advance(time.Millisecond)
	if _, gotID, ok := r.Due(); !ok || gotID != id {
		t.Fatal("expected the first retransmit at 2s")
	}

	// Timeout has now doubled to 4s.
	clock.Advance(4*time.Second - time.Millisecond)
	if _, _, ok := r.Due(); ok {
		t.Fatal("entry became due before its doubled 4s timeout elapsed")
	}
	clock.Advance(time.Millisecond)
	if _, gotID, ok := r.Due(); !ok || gotID != id {
		t.Fatal("expected the second retransmit at 2s+4s")
	}

	// Timeout has now doubled again to 8s.
	clock.Advance(8*time.Second - time.Millisecond)
	if _, _, ok := r.Due(); ok {
		t.Fatal("entry became due before its doubled 8s timeout elapsed")
	}
	clock.Advance(time.Millisecond)
	if _, gotID, ok := r.Due(); !ok || gotID != id {
		t.Fatal("expected the third retransmit at 2s+4s+8s")
	}
}

// TestFastRetransmitAfterThreeLaterAcks asserts that once NAckRetransmit
// (3) later packets have been acknowledged, the still-unacknowledged
// earlier packet is resent immediately, independent of its own timeout
// (reliable_send_purge / reliable_send, reliable.c:407-445,662-699).
func TestFastRetransmitAfterThreeLaterAcks(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NSendBuffers)

	var ids [4]PacketID
	for i := range ids {
		idx, ok := r.Next()
		if !ok {
			t.Fatalf("expected a free send slot for entry %d", i)
		}
		ids[i] = r.MarkActive(idx)
		r.SetPayload(idx, []byte{byte(i)})
	}

	// Drain every entry's initial "due immediately" state so none of them
	// is due by timeout alone, isolating the fast-retransmit path below.
	for i := range ids {
		if _, _, ok := r.Due(); !ok {
			t.Fatalf("expected entry %d due on the initial drain pass", i)
		}
	}
	if _, _, ok := r.Due(); ok {
		t.Fatal("no entry should be due immediately after the initial drain")
	}

	// Acknowledge the three LATER packets (ids[1..3]) but not ids[0].
	r.Ack(ids[1:])

	// ids[0] is now the only active entry, and it must be due purely
	// because 3 later packets were acknowledged (n_acks == NAckRetransmit)
	// — its own timeout has not elapsed.
	_, gotID, ok := r.Due()
	if !ok {
		t.Fatal("expected ids[0] due via fast retransmit (3 later packets acked)")
	}
	if gotID != ids[0] {
		t.Fatalf("Due returned id %d, want ids[0]=%d", gotID, ids[0])
	}
}

// TestSendWindowBlocksAtSix asserts that with all NSendBuffers (6) slots
// occupied and none acknowledged, a seventh Next reports no free slot
// rather than overwriting an unacknowledged entry — this is what makes a
// seventh Write block/defer at the ctrlconn.Conn layer instead of
// clobbering the send window.
func TestSendWindowBlocksAtSix(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NSendBuffers)

	for i := 0; i < NSendBuffers; i++ {
		idx, ok := r.Next()
		if !ok {
			t.Fatalf("expected a free send slot for entry %d", i)
		}
		r.MarkActive(idx)
	}

	if _, ok := r.Next(); ok {
		t.Fatal("expected Next to report no free slot with all 6 entries unacknowledged")
	}

	// Acknowledging the lowest entry frees a slot again.
	r.Ack([]PacketID{0})
	if _, ok := r.Next(); !ok {
		t.Fatal("expected a free slot after acknowledging the lowest entry")
	}
}

// TestRejectsReplayAndOutOfWindow asserts the receive-side replay and
// sequentiality checks (reliable_not_replay / reliable_wont_break_
// sequentiality, reliable.c:487-532): an ID at or below the lowest
// already-consumed ID is rejected, a legitimate retransmission of an
// un-consumed ID is accepted once (reported as a duplicate on the second
// arrival, not stored twice), and an ID that would need more buffer slots
// than the window's capacity allows is rejected.
func TestRejectsReplayAndOutOfWindow(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NRecBuffers)

	if got := r.Put(0, []byte("a")); got != PutAccepted {
		t.Fatalf("Put(0) = %v, want PutAccepted", got)
	}
	if got := r.Put(0, []byte("a-retransmit")); got != PutDuplicate {
		t.Fatalf("Put(0) again while still active = %v, want PutDuplicate", got)
	}

	payload, ok := r.Get()
	if !ok || string(payload) != "a" {
		t.Fatalf("Get() = %q, %v, want %q, true", payload, ok, "a")
	}

	// ID 0 is now at or below the lowest already-consumed ID.
	if got := r.Put(0, nil); got != PutRejected {
		t.Fatalf("Put(0) after consumption = %v, want PutRejected", got)
	}

	// An ID far beyond what NRecBuffers can hold before the gap is filled
	// breaks sequentiality and is rejected — a peer cannot force unbounded
	// buffering by sending a far-future ID (T-01-13).
	if got := r.Put(PacketID(NRecBuffers+100), nil); got != PutRejected {
		t.Fatalf("Put(far-future id) = %v, want PutRejected", got)
	}
}

// TestOrderedDelivery asserts that IDs delivered out of order (3, 1, 2)
// are only ever consumed in order (1, 2, 3 after 0 arrives) — Get returns
// ok=false until the entry for the current lowest not-yet-consumed ID has
// actually arrived.
func TestOrderedDelivery(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NRecBuffers)

	if got := r.Put(3, []byte("3")); got != PutAccepted {
		t.Fatalf("Put(3) = %v, want PutAccepted", got)
	}
	if got := r.Put(1, []byte("1")); got != PutAccepted {
		t.Fatalf("Put(1) = %v, want PutAccepted", got)
	}
	if got := r.Put(2, []byte("2")); got != PutAccepted {
		t.Fatalf("Put(2) = %v, want PutAccepted", got)
	}

	// ID 0 hasn't arrived yet: nothing is deliverable, even though 1, 2, 3
	// are all buffered.
	if _, ok := r.Get(); ok {
		t.Fatal("Get delivered a payload before ID 0 arrived")
	}

	if got := r.Put(0, []byte("0")); got != PutAccepted {
		t.Fatalf("Put(0) = %v, want PutAccepted", got)
	}

	want := []string{"0", "1", "2", "3"}
	var got []string
	for {
		payload, ok := r.Get()
		if !ok {
			break
		}
		got = append(got, string(payload))
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// TestPacketIDWraparound exercises the reference's wraparound-safe range
// checks (subtract_pid / reliable_pid_in_range1/2 / reliable_pid_min,
// reliable.c:42-95) across the actual 32-bit packet-ID wrap boundary: IDs
// just before the wrap are consumed normally, ID 0 immediately after the
// wrap is correctly treated as "ahead" rather than an ancient replay, and
// the just-consumed pre-wrap ID is correctly rejected as stale once the
// window has moved past it via the wrap.
func TestPacketIDWraparound(t *testing.T) {
	clock := newFakeClock()
	r := New(clock, NRecBuffers)
	r.packetID = 0xFFFFFFFE // walk the window right up to the wrap boundary

	if got := r.Put(0xFFFFFFFE, []byte("a")); got != PutAccepted {
		t.Fatalf("Put(0xFFFFFFFE) = %v, want PutAccepted", got)
	}
	if _, ok := r.Get(); !ok {
		t.Fatal("expected to consume 0xFFFFFFFE")
	}
	if r.packetID != 0xFFFFFFFF {
		t.Fatalf("packetID after consuming 0xFFFFFFFE = %#x, want 0xFFFFFFFF", uint32(r.packetID))
	}

	if got := r.Put(0xFFFFFFFF, []byte("b")); got != PutAccepted {
		t.Fatalf("Put(0xFFFFFFFF) = %v, want PutAccepted", got)
	}
	if _, ok := r.Get(); !ok {
		t.Fatal("expected to consume 0xFFFFFFFF")
	}
	if r.packetID != 0 {
		t.Fatalf("packetID after consuming 0xFFFFFFFF = %#x, want 0 (wrapped)", uint32(r.packetID))
	}

	// Post-wrap: ID 0 is correctly treated as ahead of the (now-wrapped)
	// base, not as an ancient replay.
	if got := r.Put(0, []byte("c")); got != PutAccepted {
		t.Fatalf("Put(0) post-wrap = %v, want PutAccepted", got)
	}

	// The previous, already-consumed pre-wrap ID (0xFFFFFFFF) is correctly
	// rejected as stale now that the window has moved past it via the wrap.
	if got := r.Put(0xFFFFFFFF, []byte("stale")); got != PutRejected {
		t.Fatalf("Put(0xFFFFFFFF) after wrap = %v, want PutRejected", got)
	}
}

// TestAckPiggybackCapAndAckOnlyPacket asserts the ACK piggyback policy
// (01-RESEARCH.md Pattern 3 / ssl.c:3146-3177): an outgoing packet
// piggybacks up to AckSize (8) pending ACKs; with more than 8 pending, the
// remainder stays queued for the next Drain (the next outgoing packet);
// Peek reports whether ACKs are pending without draining them — the exact
// signal ctrlconn.Conn.flushAckOnly uses to decide whether to emit a
// dedicated ACK-only packet when nothing else is queued to carry them.
func TestAckPiggybackCapAndAckOnlyPacket(t *testing.T) {
	var acks AckSet

	for i := 0; i < AckSize+3; i++ {
		acks.Add(PacketID(i))
	}

	first := acks.Drain()
	if len(first) != AckSize {
		t.Fatalf("first Drain returned %d ids, want %d (AckSize)", len(first), AckSize)
	}
	for i, id := range first {
		if id != PacketID(i) {
			t.Fatalf("first Drain()[%d] = %d, want %d (FIFO order)", i, id, i)
		}
	}

	if !acks.Peek() {
		t.Fatal("expected 3 remaining ids still pending after the first Drain")
	}
	second := acks.Drain()
	if len(second) != 3 {
		t.Fatalf("second Drain returned %d ids, want 3", len(second))
	}

	// With nothing left pending, Peek reports false.
	if acks.Peek() {
		t.Fatal("expected no ids pending after draining everything")
	}

	// Adding an already-pending id is a no-op — no duplicate acks queued.
	acks.Add(42)
	acks.Add(42)
	if got := acks.Drain(); len(got) != 1 {
		t.Fatalf("Drain after duplicate Add = %v, want exactly one id", got)
	}
}

// TestReliabilityAndTLSCryptWindowsAreIndependent asserts the reliability
// packet-ID window and the tls-crypt packet-ID window advance
// independently: a tls-crypt-layer retransmission carries a new tls-crypt
// sequence number for the SAME reliability packet ID, and the reliability
// layer treats it as a duplicate while the tls-crypt layer accepts it as
// fresh (01-RESEARCH.md Pitfall 1). This is the one test in this package
// that imports internal/tlscrypt — reliable.go itself never does (see its
// package doc and grep -c 'tlscrypt\.' internal/reliable/reliable.go == 0).
func TestReliabilityAndTLSCryptWindowsAreIndependent(t *testing.T) {
	key := make([]byte, 256)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate tls-crypt key: %v", err)
	}
	sender, err := tlscrypt.NewWrapper(key, true)
	if err != nil {
		t.Fatalf("sender wrapper: %v", err)
	}
	receiver, err := tlscrypt.NewWrapper(key, false)
	if err != nil {
		t.Fatalf("receiver wrapper: %v", err)
	}

	header := make([]byte, 0, 9)
	header = append(header, 0x20) // arbitrary opcode<<3|key-id byte
	header = append(header, make([]byte, 8)...)

	const reliabilityID PacketID = 7
	plaintext := []byte("reliability packet id 7, sent twice")

	// Two separate tls-crypt Wrap calls for the SAME reliability-layer
	// packet ID above — Wrap's own monotonic sequence counter advances on
	// every call regardless of what's inside the plaintext; tlscrypt has
	// no notion of the reliability packet ID at all.
	wireA, err := sender.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("first Wrap: %v", err)
	}
	wireB, err := sender.Wrap(nil, header, plaintext)
	if err != nil {
		t.Fatalf("second Wrap: %v", err)
	}

	// The tls-crypt layer treats both as fresh: its own independent
	// packet-id/replay window advanced between the two Wrap calls.
	if _, _, err := receiver.Unwrap(nil, wireA); err != nil {
		t.Fatalf("tls-crypt rejected the first transmission: %v", err)
	}
	if _, _, err := receiver.Unwrap(nil, wireB); err != nil {
		t.Fatalf("tls-crypt rejected the second transmission (independent sequence number): %v", err)
	}

	// Meanwhile the reliability layer's OWN window, keyed purely on
	// reliabilityID (a distinct type and value space from tls-crypt's own
	// packet ID), treats the exact same reliability-layer packet ID
	// arriving twice as a duplicate, not two fresh packets — the
	// reliability layer never learns, and never needs to learn, that two
	// different tls-crypt sequence numbers were involved.
	clock := newFakeClock()
	r := New(clock, NRecBuffers)
	if got := r.Put(reliabilityID, plaintext); got != PutAccepted {
		t.Fatalf("first Put(reliabilityID) = %v, want PutAccepted", got)
	}
	if got := r.Put(reliabilityID, plaintext); got != PutDuplicate {
		t.Fatalf("second Put(reliabilityID) = %v, want PutDuplicate (tls-crypt saw it as fresh, reliability correctly saw a duplicate)", got)
	}
}
