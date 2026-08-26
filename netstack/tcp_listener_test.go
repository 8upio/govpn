package netstack

import (
	"net"
	"sync"
	"testing"
	"time"
)

// demuxOf returns stack's TCP demux, failing the test if ListenTCP has
// never been called on it.
func demuxOf(t *testing.T, stack *Stack) *tcpDemux {
	t.Helper()
	stack.mu.RLock()
	d, ok := stack.tcpHandler.(*tcpDemux)
	stack.mu.RUnlock()
	if !ok {
		t.Fatal("demuxOf: no TCP demux registered on this Stack")
	}
	return d
}

// connOf looks up the live *tcpConn for key, failing the test if none
// exists — a same-package test helper for asserting internal teardown
// state (timerDone) that no exported API exposes.
func connOf(t *testing.T, d *tcpDemux, key fourTuple) *tcpConn {
	t.Helper()
	d.mu.Lock()
	c, ok := d.conns[key]
	d.mu.Unlock()
	if !ok {
		t.Fatalf("connOf: no connection for key %+v", key)
	}
	return c
}

// drainOutbound reads and discards exactly n packets from fs.outbound,
// failing the test if fewer than n arrive within timeout — used where
// several connections share one fakeSession and this test only cares
// about the count (e.g. one RST per aborted backlog/half-open connection),
// not which connection produced which packet.
func drainOutbound(t *testing.T, fs *fakeSession, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for i := 0; i < n; i++ {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			t.Fatalf("drainOutbound: only drained %d/%d packets before timing out", i, n)
		}
		select {
		case <-fs.outbound:
		case <-time.After(remaining):
			t.Fatalf("drainOutbound: only drained %d/%d packets before timing out", i, n)
		}
	}
}

// TestTCPRSTForClosedPort: a SYN to a port with no listener draws an RST
// whose sequence is 0 and whose ack is the offending segment's sequence +
// 1 with the ACK flag set (RFC 9293 SS3.5.2's rule for a segment without
// ACK), and no connection state is created.
func TestTCPRSTForClosedPort(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	// Register a demux without actually listening on the port under test,
	// by listening on a different port first.
	ln, err := stack.ListenTCP(9999)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080) // port 8080 has no listener

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
	rst := client.recvRaw(time.Second)
	if rst.flags != flagRST|flagACK {
		t.Fatalf("RST flags = %#x, want RST|ACK", rst.flags)
	}
	if rst.seq != 0 {
		t.Fatalf("RST seq = %d, want 0", rst.seq)
	}
	if rst.ack != client.isn+1 {
		t.Fatalf("RST ack = %d, want %d (offending SYN's seq+1)", rst.ack, client.isn+1)
	}

	d := demuxOf(t, stack)
	d.mu.Lock()
	_, exists := d.conns[fourTuple{remoteIP: client.localIP, remotePort: client.localPort, localPort: client.remotePort}]
	d.mu.Unlock()
	if exists {
		t.Fatal("connection state was created for a SYN to a closed port")
	}
}

// TestTCPRSTForUnknownConnection: a data segment for a 4-tuple with no
// connection draws an RST whose sequence is the offending segment's ack
// number and which does not set the ACK flag (SS3.5.2's rule for a segment
// carrying ACK).
func TestTCPRSTForUnknownConnection(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	// A data-bearing ACK for a connection this stack has never heard of.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: 5000, ack: 9000, flags: flagACK, window: 65535, payload: []byte("x")})
	rst := client.recvRaw(time.Second)
	if rst.flags&flagACK != 0 {
		t.Fatalf("RST flags = %#x, must not have ACK set", rst.flags)
	}
	if rst.flags&flagRST == 0 {
		t.Fatalf("RST flags = %#x, want RST set", rst.flags)
	}
	if rst.seq != 9000 {
		t.Fatalf("RST seq = %d, want 9000 (offending segment's ack)", rst.seq)
	}
}

// TestTCPRSTClosesConnection: an inbound RST on an established connection
// makes subsequent Read/Write return an error, releases the 4-tuple, and
// stops every timer for that connection.
func TestTCPRSTClosesConnection(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()

	c, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn := c.(*tcpConn)

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagRST})
	time.Sleep(30 * time.Millisecond)

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read after inbound RST succeeded, want an error")
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("Write after inbound RST succeeded, want an error")
	}

	select {
	case <-conn.timerDone:
	case <-time.After(time.Second):
		t.Fatal("timer goroutine did not exit after an inbound RST")
	}

	// The 4-tuple is free: a brand new handshake on it must succeed.
	client2 := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client2.isn = 55555
	client2.sendRaw(tcpSegment{srcPort: client2.localPort, dstPort: client2.remotePort, seq: client2.isn, flags: flagSYN, window: 65535})
	synack := client2.recvRaw(time.Second)
	if synack.flags != flagSYN|flagACK {
		t.Fatalf("reused 4-tuple SYN drew flags %#x, want a fresh SYN-ACK", synack.flags)
	}
}

// TestTCPBacklogBounded: with the application not calling Accept,
// defaultBacklog connections complete and queue; the next completed
// connection is reset rather than queued unboundedly, and Stats()'s
// backlog-overflow counter increments.
func TestTCPBacklogBounded(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	before := stack.TCPStats().BacklogOverflow

	for i := 0; i < defaultBacklog; i++ {
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(20000+i), testServerIP(), 8080)
		client.connect()
	}

	overflow := newTCPTestClient(t, fs, testClientAddr(), uint16(20000+defaultBacklog), testServerIP(), 8080)
	overflow.sendRaw(tcpSegment{srcPort: overflow.localPort, dstPort: overflow.remotePort, seq: overflow.isn, flags: flagSYN, window: 65535})
	synack := overflow.recvRaw(time.Second)
	overflow.serverISN = synack.seq
	overflow.rcvNext = synack.seq + 1
	overflow.sndNext = overflow.isn + 1
	overflow.sendRaw(tcpSegment{srcPort: overflow.localPort, dstPort: overflow.remotePort, seq: overflow.sndNext, ack: overflow.rcvNext, flags: flagACK, window: 65535})

	rst := overflow.recvRaw(time.Second)
	if rst.flags&flagRST == 0 {
		t.Fatalf("overflow connection got flags %#x, want an RST (backlog full)", rst.flags)
	}
	if got := stack.TCPStats().BacklogOverflow; got <= before {
		t.Fatalf("BacklogOverflow = %d, want it to have increased from %d", got, before)
	}
}

// TestTCPHalfOpenBounded: one session sending maxHalfOpenPerSession+4 SYNs
// without ever completing any handshake results in at most
// maxHalfOpenPerSession half-open connections; the excess SYNs are dropped
// (no SYN-ACK), and the counter increments.
func TestTCPHalfOpenBounded(t *testing.T) {
	// A fixed fake clock (never advanced) guarantees none of the initial
	// half-open connections' SYN-ACK retransmit timers can fire mid-test
	// and pollute the shared fs.outbound channel with a stray segment
	// that tryRecvRaw (which does not filter by port) could misattribute
	// to one of the "excess" clients below.
	clock := newFakeClock(time.Unix(0, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	before := stack.TCPStats().HalfOpenCapHits

	for i := 0; i < maxHalfOpenPerSession; i++ {
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(21000+i), testServerIP(), 8080)
		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
		client.recvRaw(time.Second) // SYN-ACK expected
	}

	for i := 0; i < 4; i++ {
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(21000+maxHalfOpenPerSession+i), testServerIP(), 8080)
		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
		if _, ok := client.tryRecvRaw(100 * time.Millisecond); ok {
			t.Fatalf("excess SYN #%d drew a response, want it silently dropped", i)
		}
	}

	if got := stack.TCPStats().HalfOpenCapHits; got < before+4 {
		t.Fatalf("HalfOpenCapHits = %d, want at least %d", got, before+4)
	}
}

// TestTCPHalfOpenIsPerSession: with two sessions attached, one session
// saturating its own half-open budget does not prevent the other session
// from completing a handshake — the cap isolates clients from each other.
func TestTCPHalfOpenIsPerSession(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fsA := newFakeSession()
	ipA := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fsA, ipA); err != nil {
		t.Fatalf("Attach A: %v", err)
	}
	fsB := newFakeSession()
	ipB := net.IPv4(10, 8, 0, 3).To4()
	if err := stack.Attach(fsB, ipB); err != nil {
		t.Fatalf("Attach B: %v", err)
	}

	for i := 0; i < maxHalfOpenPerSession; i++ {
		clientA := newTCPTestClient(t, fsA, ipA, uint16(22000+i), testServerIP(), 8080)
		clientA.sendRaw(tcpSegment{srcPort: clientA.localPort, dstPort: clientA.remotePort, seq: clientA.isn, flags: flagSYN, window: 65535})
		clientA.recvRaw(time.Second)
	}
	// Session A is now saturated; one more SYN from A must be dropped.
	extraA := newTCPTestClient(t, fsA, ipA, uint16(22000+maxHalfOpenPerSession), testServerIP(), 8080)
	extraA.sendRaw(tcpSegment{srcPort: extraA.localPort, dstPort: extraA.remotePort, seq: extraA.isn, flags: flagSYN, window: 65535})
	if _, ok := extraA.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("session A's extra SYN was not dropped despite a saturated half-open budget")
	}

	// Session B, untouched, must still complete a full handshake.
	clientB := newTCPTestClient(t, fsB, ipB, 34567, testServerIP(), 8080)
	clientB.connect()
	if _, err := acceptWithTimeout(t, ln, time.Second); err != nil {
		t.Fatalf("session B's handshake did not complete: %v", err)
	}
}

// TestTCPHalfOpenTimesOut: a half-open connection that never receives its
// completing ACK is retransmitted per Task 2's backoff and then released
// after maxRetransmits, freeing its slot — the budget is not permanently
// consumed by an abandoned SYN.
func TestTCPHalfOpenTimesOut(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for i := 0; i < maxHalfOpenPerSession; i++ {
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(23000+i), testServerIP(), 8080)
		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
		client.recvRaw(time.Second)
	}

	blocked := newTCPTestClient(t, fs, testClientAddr(), uint16(23000+maxHalfOpenPerSession), testServerIP(), 8080)
	blocked.sendRaw(tcpSegment{srcPort: blocked.localPort, dstPort: blocked.remotePort, seq: blocked.isn, flags: flagSYN, window: 65535})
	if _, ok := blocked.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("half-open budget was not yet saturated")
	}

	// Advance the clock through every half-open connection's own
	// SYN-ACK retransmit backoff and give-up (maxRetransmits+1 fires;
	// every half-open conn shares the same fireAt schedule, having all
	// been armed at t=0).
	for i := 0; i < maxRetransmits+1; i++ {
		clock.Advance(maxRTO + time.Second)
		time.Sleep(20 * time.Millisecond)
	}

	// Each of the maxHalfOpenPerSession abandoned half-opens produced at
	// least one retransmit before giving up with an RST; drain whatever
	// arrived so the channel does not block later reads. We only care
	// about the eventual slot release, not the exact retransmit count.
drainLoop:
	for i := 0; i < 1000; i++ {
		select {
		case <-fs.outbound:
		default:
			break drainLoop
		}
	}

	// The half-open budget must now be free: the previously-blocked SYN
	// succeeds.
	blocked.sendRaw(tcpSegment{srcPort: blocked.localPort, dstPort: blocked.remotePort, seq: blocked.isn, flags: flagSYN, window: 65535})
	synack, ok := blocked.tryRecvRaw(time.Second)
	if !ok || synack.flags != flagSYN|flagACK {
		t.Fatal("half-open slot was not released after the abandoned SYNs gave up")
	}
}

// TestTCPListenerCloseResetsQueued: closing the listener resets
// connections still sitting in the backlog, unblocks a goroutine blocked
// in Accept with an error wrapping net.ErrClosed, and leaves no live
// connection state or timer goroutine behind.
func TestTCPListenerCloseResetsQueued(t *testing.T) {
	// Part 1: connections queued in the backlog (never accepted) are
	// reset when the listener closes.
	t.Run("queuedConnectionsReset", func(t *testing.T) {
		stack := newTestStack(t)
		defer stack.Close()
		ln, err := stack.ListenTCP(8080)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		fs := newFakeSession()
		if err := stack.Attach(fs, testClientAddr()); err != nil {
			t.Fatalf("Attach: %v", err)
		}

		d := demuxOf(t, stack)
		const n = 3
		conns := make([]*tcpConn, 0, n)
		for i := 0; i < n; i++ {
			client := newTCPTestClient(t, fs, testClientAddr(), uint16(24000+i), testServerIP(), 8080)
			client.connect()
			key := fourTuple{remoteIP: client.localIP, remotePort: client.localPort, localPort: client.remotePort}
			conns = append(conns, connOf(t, d, key))
		}

		if err := ln.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		for i, c := range conns {
			select {
			case <-c.timerDone:
			case <-time.After(time.Second):
				t.Fatalf("conn %d: timer goroutine did not exit after listener Close", i)
			}
		}
	})

	// Part 2: a goroutine genuinely blocked in Accept (nothing queued)
	// unblocks with an error wrapping net.ErrClosed once Close is called.
	t.Run("blockedAcceptUnblocks", func(t *testing.T) {
		stack := newTestStack(t)
		defer stack.Close()
		ln, err := stack.ListenTCP(8080)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}

		acceptErrCh := make(chan error, 1)
		go func() {
			_, err := ln.Accept()
			acceptErrCh <- err
		}()
		time.Sleep(20 * time.Millisecond) // let Accept genuinely block

		if err := ln.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		select {
		case err := <-acceptErrCh:
			if err == nil {
				t.Fatal("blocked Accept returned no error after Close")
			}
		case <-time.After(time.Second):
			t.Fatal("Accept did not unblock after Close")
		}
	})
}

// TestTCPDetachDuringConnectionCleansUp: detaching a session with an
// established TCP connection releases the connection's state and stops
// its timers without panicking on a subsequent write attempt.
func TestTCPDetachDuringConnectionCleansUp(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()

	c, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn := c.(*tcpConn)

	if !stack.Detach(testClientAddr()) {
		t.Fatal("Detach reported no attachment removed")
	}

	select {
	case <-conn.timerDone:
	case <-time.After(time.Second):
		t.Fatal("timer goroutine did not exit after Detach")
	}

	// Must not panic on a write attempt after detach.
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("Write after Detach succeeded, want an error")
	}
}

// TestTCPBadAckInSynRcvdResets: an ACK completing the handshake with a
// wrong acknowledgement number draws an RST and destroys the half-open
// state instead of establishing the connection.
func TestTCPBadAckInSynRcvdResets(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
	synack := client.recvRaw(time.Second)
	client.serverISN = synack.seq

	// A completing ACK with a deliberately wrong acknowledgement number.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn + 1, ack: synack.seq + 999, flags: flagACK, window: 65535})
	rst := client.recvRaw(time.Second)
	if rst.flags&flagRST == 0 {
		t.Fatalf("bad-ack response flags = %#x, want RST set", rst.flags)
	}

	// The half-open state must be destroyed, not established: a fresh SYN
	// on the same 4-tuple draws a brand new SYN-ACK rather than being
	// silently absorbed by stale SYN_RCVD state (or, worse, treated as
	// already-established).
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
	synack2 := client.recvRaw(time.Second)
	if synack2.flags != flagSYN|flagACK {
		t.Fatalf("retry SYN drew flags %#x, want a fresh SYN-ACK", synack2.flags)
	}
}

// TestTCPLiveConnCapPerSession (CR-02): one session that completes
// maxLiveConnsPerSession handshakes and never closes any of them — each
// completion releasing its own half-open slot the instant it succeeds, so
// the half-open budget alone never blocks it — hits a separate cap on the
// total number of live (non-CLOSED) connections it may hold at once. A
// further SYN is silently dropped and the LiveConnCapHits counter
// increments, exactly mirroring HalfOpenCapHits' own shape for the
// half-open budget.
func TestTCPLiveConnCapPerSession(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := newFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	before := stack.TCPStats().LiveConnCapHits

	// Left open deliberately, never Close'd: stack.Close() (deferred
	// above) tears every attachment down directly (onAttachmentDetached,
	// no wire I/O) rather than this test driving 64 individual FIN
	// sequences through fs.outbound's small fixed buffer, which nothing
	// here drains.
	for i := 0; i < maxLiveConnsPerSession; i++ {
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(25000+i), testServerIP(), 8080)
		client.connect()
		if _, err := acceptWithTimeout(t, ln, time.Second); err != nil {
			t.Fatalf("handshake #%d did not complete: %v", i, err)
		}
	}

	// Every prior handshake already completed and released its half-open
	// slot (tcp_state.go's handleSegment calls releaseHalfOpen the moment
	// SYN_RCVD resolves) — the half-open budget has room, but the
	// separate live-connection budget does not.
	extra := newTCPTestClient(t, fs, testClientAddr(), uint16(25000+maxLiveConnsPerSession), testServerIP(), 8080)
	extra.sendRaw(tcpSegment{srcPort: extra.localPort, dstPort: extra.remotePort, seq: extra.isn, flags: flagSYN, window: 65535})
	if _, ok := extra.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("SYN beyond maxLiveConnsPerSession drew a response, want it silently dropped")
	}

	if got := stack.TCPStats().LiveConnCapHits; got < before+1 {
		t.Fatalf("LiveConnCapHits = %d, want at least %d", got, before+1)
	}
}

// TestTCPListenerEnqueueCloseRaceLeavesNothingBehind (WR-01) races a
// handshake's completing ACK — processed asynchronously on the stack's own
// read-loop goroutine, where enqueue() is called — against a concurrent
// Close() from the test goroutine, across many trials. The SYN/SYN-ACK
// step runs synchronously BEFORE the race window opens (a half-open
// connection safely sitting in the demux is not what WR-01 is about;
// racing the SYN itself against Close would instead exercise handleSYN's
// own separate, unrelated closed-check, misattributing any flake to the
// wrong fix) — only the completing ACK races Close, isolating exactly the
// enqueue/Close interaction WR-01 fixes.
//
// Before WR-01, enqueue's closed-check and its backlog send were two
// separate steps with l.mu released in between: Close could observe an
// empty backlog and return right as a concurrently-racing enqueue's send
// landed behind it, leaving that connection ESTABLISHED in the demux's
// conns map — neither reachable via Accept (already unblocked via
// closeCh) nor aborted by Close's own drain loop (which had already
// finished). This is a lost update between two lock-protected steps, not
// a data race in the sync/race-detector sense, so the regression signal
// is the FUNCTIONAL assertion below (the demux's conns map must end up
// empty), not `-race` itself; many trials make the race window
// overwhelmingly likely to be hit at least once if the two operations are
// not properly serialized.
//
// The completing-ACK goroutine below only ever calls sendRaw (never
// recvRaw/t.Fatalf) — calling FailNow-family methods from a goroutine
// other than the test's own is unsupported by the testing package.
func TestTCPListenerEnqueueCloseRaceLeavesNothingBehind(t *testing.T) {
	// The race window this closes is narrow (a handful of instructions
	// between releasing l.mu and the backlog send in the pre-fix code) —
	// empirically, several thousand trials are needed to reliably land in
	// it under normal goroutine scheduling. 5000 trials reproduced the
	// pre-fix leak within ~400 trials in local testing and this whole
	// test still runs in low single-digit seconds under -race.
	const trials = 5000
	for trial := 0; trial < trials; trial++ {
		stack := newTestStack(t)
		ln, err := stack.ListenTCP(8080)
		if err != nil {
			t.Fatalf("trial %d: ListenTCP: %v", trial, err)
		}
		fs := newFakeSession()
		if err := stack.Attach(fs, testClientAddr()); err != nil {
			t.Fatalf("trial %d: Attach: %v", trial, err)
		}
		client := newTCPTestClient(t, fs, testClientAddr(), uint16(26000+trial), testServerIP(), 8080)

		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
		synack, ok := client.tryRecvRaw(time.Second)
		if !ok {
			t.Fatalf("trial %d: no SYN-ACK received", trial)
		}
		client.serverISN = synack.seq
		client.rcvNext = synack.seq + 1
		client.sndNext = client.isn + 1

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})
		}()
		go func() {
			defer wg.Done()
			ln.Close()
		}()
		wg.Wait()

		// Drain whatever a well-behaved caller's Accept loop would see —
		// exactly what net/http's own Serve loop does until Accept
		// errors — and close it. The property under test is not "the
		// handshake always wins" (it may legitimately lose the race to
		// Close outright) but "nothing is left ESTABLISHED and
		// unreachable."
		for {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			c.Close()
		}

		// The completing ACK's actual processing (handleSegment, then
		// enqueue/abort) happens asynchronously on the stack's own
		// read-loop goroutine — sendRaw only queues the packet and
		// returns, so wg.Wait() above does not guarantee that processing
		// has finished yet. Poll briefly (bounded, no fixed sleep) rather
		// than asserting immediately: with WR-01's fix this always
		// reaches zero quickly; without it, a leaked connection never
		// clears and the deadline below fires.
		deadline := time.Now().Add(time.Second)
		var remaining int
		for {
			d := demuxOf(t, stack)
			d.mu.Lock()
			remaining = len(d.conns)
			d.mu.Unlock()
			if remaining == 0 || time.Now().After(deadline) {
				break
			}
			time.Sleep(time.Millisecond)
		}
		if remaining != 0 {
			t.Fatalf("trial %d: %d connection(s) still tracked in the demux a full second after Close and an Accept-drain loop — a connection was enqueued after Close's own drain finished (WR-01)", trial, remaining)
		}

		stack.Close()
	}
}
