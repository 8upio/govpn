package netstack

import (
	"bytes"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func testServerIP() net.IP {
	return net.IPv4(10, 8, 0, 1).To4()
}

func newTestStack(t *testing.T, opts ...Option) *Stack {
	t.Helper()
	s, err := New(testServerIP(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func waitForOutbound(t *testing.T, fs *fakeSession, timeout time.Duration) []byte {
	t.Helper()
	select {
	case pkt := <-fs.outbound:
		return pkt
	case <-time.After(timeout):
		t.Fatal("timed out waiting for an outbound packet")
		return nil
	}
}

func assertNoOutbound(t *testing.T, fs *fakeSession, wait time.Duration) {
	t.Helper()
	select {
	case pkt := <-fs.outbound:
		t.Fatalf("expected no outbound packet, got %d bytes", len(pkt))
	case <-time.After(wait):
	}
}

// TestICMPEchoEndToEnd is Task 1's end-to-end fast check: attach a fake
// session and prove a real ICMP echo request comes back as a correct echo
// reply, in milliseconds, with no Docker (D-12). The exhaustive
// drop/spoof/fragment matrix lives in the other tests in this file plus
// ipv4_test.go/icmp_test.go (Task 2).
func TestICMPEchoEndToEnd(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	req := buildICMPEchoRequest(mustAddr(clientIP), mustAddr(testServerIP()), 1, 1, []byte("hello, tunnel"))
	fs.inbound <- req

	reply := waitForOutbound(t, fs, time.Second)

	hdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	if hdr.src != mustAddr(testServerIP()) {
		t.Errorf("reply source = %v, want server IP %v", hdr.src, mustAddr(testServerIP()))
	}
	if hdr.dst != mustAddr(clientIP) {
		t.Errorf("reply destination = %v, want client IP %v", hdr.dst, mustAddr(clientIP))
	}

	icmpMsg := reply[hdr.payloadOff:hdr.totalLen]
	if icmpMsg[0] != icmpTypeEchoReply {
		t.Errorf("reply ICMP type = %d, want %d (echo reply)", icmpMsg[0], icmpTypeEchoReply)
	}
	reqICMP := req[minIPv4HeaderLen:]
	if string(icmpMsg[4:]) != string(reqICMP[4:]) {
		t.Errorf("reply identifier/sequence/payload = %q, want %q (echoed unchanged)", icmpMsg[4:], reqICMP[4:])
	}
	if cs := internetChecksum(icmpMsg); cs != 0 {
		t.Errorf("reply ICMP checksum does not fold to zero (got %#04x)", cs)
	}

	stats := stack.Stats()
	if stats.ICMPEchoRequests != 1 {
		t.Errorf("Stats().ICMPEchoRequests = %d, want 1", stats.ICMPEchoRequests)
	}
	if stats.ICMPEchoReplies != 1 {
		t.Errorf("Stats().ICMPEchoReplies = %d, want 1", stats.ICMPEchoReplies)
	}
}

// TestReadLoopRecoversFromShortBuffer (WR-04): a decrypted IP packet
// larger than readBufferSize (2048) — which Session.Read's documented
// contract retains and reports as an error, per its own doc comment
// (session.go:305-334), rather than a genuine session failure — must not
// permanently and silently detach the attachment. readLoop must instead
// grow its buffer once and retry, successfully delivering the oversized
// packet, and keeping the route (and the read loop) alive for whatever
// traffic follows. Without WR-04's fix, this test's first echo request
// would detach the attachment before ever reaching deliver, and the
// second (small) echo request below would time out.
func TestReadLoopRecoversFromShortBuffer(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// A payload comfortably larger than readBufferSize but well under
	// maxReadRetryBufferSize — the "non-conforming or hostile client
	// exceeds the advisory tun-mtu" scenario WR-04 is about.
	bigPayload := bytes.Repeat([]byte{0x7a}, readBufferSize+500)
	req := buildICMPEchoRequest(mustAddr(clientIP), mustAddr(testServerIP()), 1, 1, bigPayload)
	fs.inbound <- req

	reply := waitForOutbound(t, fs, time.Second)
	hdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	icmpMsg := reply[hdr.payloadOff:hdr.totalLen]
	if icmpMsg[0] != icmpTypeEchoReply {
		t.Fatalf("reply ICMP type = %d, want %d (echo reply) — the oversized request was not delivered", icmpMsg[0], icmpTypeEchoReply)
	}

	if got := stack.Stats().ShortReadBufferGrown; got < 1 {
		t.Fatalf("Stats().ShortReadBufferGrown = %d, want at least 1", got)
	}

	// The route must still be alive: a subsequent, ordinary-sized request
	// on the SAME attachment still gets a reply.
	stack.mu.RLock()
	_, exists := stack.routes[mustAddr(clientIP)]
	stack.mu.RUnlock()
	if !exists {
		t.Fatal("route was removed after an oversized (but recoverable) packet — the attachment was wrongly detached")
	}
	fs.inbound <- buildICMPEchoRequest(mustAddr(clientIP), mustAddr(testServerIP()), 2, 1, []byte("still alive"))
	waitForOutbound(t, fs, time.Second)
}

func TestAttachDetachRouting(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fsA := newFakeSession()
	fsB := newFakeSession()
	ipA := net.IPv4(10, 8, 0, 2).To4()
	ipB := net.IPv4(10, 8, 0, 3).To4()

	if err := stack.Attach(fsA, ipA); err != nil {
		t.Fatalf("Attach A: %v", err)
	}
	if err := stack.Attach(fsB, ipB); err != nil {
		t.Fatalf("Attach B: %v", err)
	}

	fsA.inbound <- buildICMPEchoRequest(mustAddr(ipA), mustAddr(testServerIP()), 1, 1, nil)
	replyA := waitForOutbound(t, fsA, time.Second)
	hdrA, err := parseIPv4(replyA)
	if err != nil {
		t.Fatalf("parseIPv4(replyA): %v", err)
	}
	if hdrA.dst != mustAddr(ipA) {
		t.Fatalf("session A's reply is addressed to %v, want %v", hdrA.dst, mustAddr(ipA))
	}
	assertNoOutbound(t, fsB, 50*time.Millisecond)

	fsB.inbound <- buildICMPEchoRequest(mustAddr(ipB), mustAddr(testServerIP()), 2, 1, nil)
	replyB := waitForOutbound(t, fsB, time.Second)
	hdrB, err := parseIPv4(replyB)
	if err != nil {
		t.Fatalf("parseIPv4(replyB): %v", err)
	}
	if hdrB.dst != mustAddr(ipB) {
		t.Fatalf("session B's reply is addressed to %v, want %v", hdrB.dst, mustAddr(ipB))
	}

	if err := stack.Attach(newFakeSession(), ipA); !errors.Is(err, ErrDuplicateAttach) {
		t.Fatalf("Attach(duplicate ipA) = %v, want ErrDuplicateAttach", err)
	}
	if err := stack.Attach(newFakeSession(), testServerIP()); !errors.Is(err, ErrAttachServerIP) {
		t.Fatalf("Attach(server IP) = %v, want ErrAttachServerIP", err)
	}

	if !stack.Detach(ipA) {
		t.Fatal("Detach(ipA) = false, want true")
	}
	if stack.Detach(ipA) {
		t.Fatal("second Detach(ipA) = true, want false")
	}

	fsA.inbound <- buildICMPEchoRequest(mustAddr(ipA), mustAddr(testServerIP()), 3, 1, nil)
	assertNoOutbound(t, fsA, 50*time.Millisecond)
}

// TestDetachOnSessionReadError asserts D-02's sole detach trigger: closing
// a fake session's Read path (making it return io.EOF) makes the stack's
// route disappear and the read-loop goroutine exit, observed via a
// channel wait on the attachment's own stopCh (closed by
// detachAttachment), never a sleep-based poll.
func TestDetachOnSessionReadError(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[mustAddr(ip)]
	stack.mu.RUnlock()
	if a == nil {
		t.Fatal("no attachment found immediately after Attach")
	}

	if err := fs.Close(); err != nil {
		t.Fatalf("fs.Close: %v", err)
	}

	select {
	case <-a.stopCh:
	case <-time.After(time.Second):
		t.Fatal("read-loop goroutine did not exit within 1s of Session.Read returning an error")
	}

	stack.mu.RLock()
	_, exists := stack.routes[mustAddr(ip)]
	stack.mu.RUnlock()
	if exists {
		t.Fatal("route was not removed after the session's Read returned an error")
	}
}

// TestSingleReaderPerSession asserts Attach starts exactly one goroutine
// per attached session that calls Session.Read (session.go:305-313's
// single-reader contract) — via both an overlap check and a distinct
// goroutine-identity count (see fakeSession's doc comment).
func TestSingleReaderPerSession(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for i := 0; i < 50; i++ {
		fs.inbound <- buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, uint16(i), nil)
		waitForOutbound(t, fs, time.Second)
	}

	fs.readMu.Lock()
	overlapped := fs.readOverlapped
	distinct := len(fs.readerIDs)
	fs.readMu.Unlock()

	if overlapped {
		t.Fatal("Session.Read was called concurrently from more than one goroutine")
	}
	if distinct != 1 {
		t.Fatalf("Session.Read was called from %d distinct goroutines, want exactly 1", distinct)
	}
}

func TestSourceIPSpoofDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	otherClient := net.IPv4(10, 8, 0, 3).To4()
	fs.inbound <- buildICMPEchoRequest(mustAddr(otherClient), mustAddr(testServerIP()), 1, 1, nil)
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().SpoofedSourceDropped; got != 1 {
		t.Fatalf("Stats().SpoofedSourceDropped = %d, want 1 (claiming another client's IP)", got)
	}

	fs.inbound <- buildICMPEchoRequest(mustAddr(testServerIP()), mustAddr(testServerIP()), 2, 1, nil)
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().SpoofedSourceDropped; got != 2 {
		t.Fatalf("Stats().SpoofedSourceDropped = %d, want 2 (claiming the server's own IP)", got)
	}
}

func TestNonServerDestinationDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	wrongDst := net.IPv4(10, 8, 0, 7).To4()
	fs.inbound <- buildICMPEchoRequest(mustAddr(ip), mustAddr(wrongDst), 1, 1, nil)
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().WrongDestinationDropped; got != 1 {
		t.Fatalf("Stats().WrongDestinationDropped = %d, want 1", got)
	}
}

func TestFragmentDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	pkt1 := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, nil)
	setFlagsFragOffsetForTest(pkt1, flagMoreFragments)
	fs.inbound <- pkt1
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().FragmentsDropped; got != 1 {
		t.Fatalf("Stats().FragmentsDropped = %d, want 1 after MF flag set", got)
	}

	pkt2 := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 2, 1, nil)
	setFlagsFragOffsetForTest(pkt2, 5)
	fs.inbound <- pkt2
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().FragmentsDropped; got != 2 {
		t.Fatalf("Stats().FragmentsDropped = %d, want 2 after a non-zero fragment offset", got)
	}
}

func setFlagsFragOffsetForTest(pkt []byte, v uint16) {
	pkt[6] = byte(v >> 8)
	pkt[7] = byte(v)
}

func TestOutboundSourceIPFailClosed(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[mustAddr(ip)]
	stack.mu.RUnlock()

	badICMP := []byte{icmpTypeEchoReply, 0, 0, 0, 0, 0, 0, 0}
	badICMP[2], badICMP[3] = 0, 0
	binaryPutChecksum(badICMP)
	// Source == client IP, not the server's own tunnel IP: this must never
	// reach the wire (D-04).
	badPkt := buildIPv4(nil, mustAddr(ip), mustAddr(ip), protocolICMP, badICMP)

	err := stack.writePacket(a, badPkt)
	if !errors.Is(err, ErrOutboundSourceMismatch) {
		t.Fatalf("writePacket(wrong source) = %v, want ErrOutboundSourceMismatch", err)
	}

	select {
	case <-fs.outbound:
		t.Fatal("a packet reached the fake session's outbound channel despite the outbound source-IP mismatch")
	default:
	}

	if got := stack.Stats().OutboundSourceDropped; got != 1 {
		t.Fatalf("Stats().OutboundSourceDropped = %d, want 1", got)
	}
}

func binaryPutChecksum(icmp []byte) {
	cs := internetChecksum(icmp)
	icmp[2] = byte(cs >> 8)
	icmp[3] = byte(cs)
}

// TestUnhandledProtocolDropped asserts the documented wave-1 baseline
// (this plan registers neither a UDP nor a TCP handler, so both protocols
// are counted and dropped) — wave 2 changes this once plan 03-02/03-03
// register their handlers.
func TestUnhandledProtocolDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	udpPkt := buildIPv4(nil, mustAddr(ip), mustAddr(testServerIP()), protocolUDP, []byte("hello"))
	fs.inbound <- udpPkt
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().UnhandledProtocolDropped; got != 1 {
		t.Fatalf("Stats().UnhandledProtocolDropped = %d, want 1 after a UDP packet with no registered handler", got)
	}

	tcpPkt := buildIPv4(nil, mustAddr(ip), mustAddr(testServerIP()), protocolTCP, []byte("hello"))
	fs.inbound <- tcpPkt
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().UnhandledProtocolDropped; got != 2 {
		t.Fatalf("Stats().UnhandledProtocolDropped = %d, want 2 after a TCP packet with no registered handler", got)
	}
}

// fakeClock is a manually-advanced Clock for deterministic timer tests —
// mirrors internal/reliable's own injected-Clock precedent
// (internal/reliable/reliable.go:79-89) in spirit, extended with a Timer
// that actually fires when the clock is advanced past its deadline (not
// merely a Now() comparison), since plan 03-03's TCP retransmit/TIME_WAIT
// timers must be driven without real sleeps.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{
		clock:  c,
		fireAt: c.now.Add(d),
		ch:     make(chan time.Time, 1),
		active: true,
	}
	c.timers = append(c.timers, t)
	return t
}

// Advance moves the fake clock forward by d, firing (in no particular
// order) every active timer whose deadline has now passed.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	var toFire []*fakeTimer
	for _, ft := range c.timers {
		ft.mu.Lock()
		if ft.active && !ft.fireAt.After(now) {
			ft.active = false
			toFire = append(toFire, ft)
		}
		ft.mu.Unlock()
	}
	c.mu.Unlock()

	for _, ft := range toFire {
		select {
		case ft.ch <- now:
		default:
		}
	}
}

type fakeTimer struct {
	clock  *fakeClock
	mu     sync.Mutex
	fireAt time.Time
	ch     chan time.Time
	active bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.ch }

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := t.active
	t.active = true
	t.fireAt = t.clock.Now().Add(d)
	return wasActive
}

func (t *fakeTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := t.active
	t.active = false
	return wasActive
}

func TestFakeClockDrivesTimer(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	timer := clock.NewTimer(1 * time.Second)

	select {
	case <-timer.C():
		t.Fatal("timer fired before the fake clock ever advanced")
	case <-time.After(20 * time.Millisecond):
	}

	clock.Advance(500 * time.Millisecond)
	select {
	case <-timer.C():
		t.Fatal("timer fired before its full duration had elapsed on the fake clock")
	case <-time.After(20 * time.Millisecond):
	}

	clock.Advance(600 * time.Millisecond)
	select {
	case <-timer.C():
	case <-time.After(time.Second):
		t.Fatal("timer did not fire after the fake clock advanced past its duration")
	}
}
