package netstack

import (
	"net"
	"testing"
	"time"
)

// setupEstablishedConn is a small helper shared by this file's tests: it
// builds a stack on the given clock, listens on port 8080, completes a
// handshake, and returns the accepted conn plus the driving test client.
func setupEstablishedConn(t *testing.T, clock *fakeClock) (*Stack, net.Listener, *tcpConn, *tcpTestClient) {
	t.Helper()
	stack := newTestStack(t, WithClock(clock))
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
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
	return stack, ln, conn, client
}

// TestTCPRetransmitsUnackedData: a segment whose ACK the test client
// withholds is retransmitted once the fake clock advances past initialRTO,
// byte-identical to the original; when the client finally ACKs,
// retransmission stops.
func TestTCPRetransmitsUnackedData(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack, ln, conn, client := setupEstablishedConn(t, clock)
	defer stack.Close()
	defer ln.Close()

	payload := []byte("unacked payload")
	writeDone := make(chan struct{})
	go func() {
		conn.Write(payload)
		close(writeDone)
	}()

	first := client.recvRaw(time.Second)
	if string(first.payload) != string(payload) {
		t.Fatalf("first segment payload = %q, want %q", first.payload, payload)
	}
	<-writeDone

	clock.Advance(initialRTO)
	retransmit := client.recvRaw(time.Second)
	if retransmit.seq != first.seq || string(retransmit.payload) != string(payload) {
		t.Fatalf("retransmit = seq %d payload %q, want seq %d payload %q", retransmit.seq, retransmit.payload, first.seq, payload)
	}

	// Now ACK it: retransmission must stop.
	client.rcvNext = first.seq // unused here, but keep client's own bookkeeping sane
	client.sendRaw(tcpSegment{
		srcPort: client.localPort, dstPort: client.remotePort,
		seq: client.sndNext, ack: first.seq + uint32(len(payload)), flags: flagACK, window: 65535,
	})
	// The ACK is delivered asynchronously (the stack's read-loop
	// goroutine drains fs.inbound) — give it a moment to be processed
	// and disarm the retransmit timer before advancing the clock again,
	// or this assertion would race the ACK's own delivery.
	time.Sleep(50 * time.Millisecond)

	clock.Advance(maxRTO * 2)
	if _, ok := client.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("received another retransmission after the data was ACKed")
	}
}

// TestTCPRTODoubles: successive retransmissions of the same unacknowledged
// data occur at initialRTO, then 2x, then 4x — asserted by advancing the
// fake clock in exact increments and counting emitted segments; the
// interval never exceeds maxRTO.
func TestTCPRTODoubles(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack, ln, conn, client := setupEstablishedConn(t, clock)
	defer stack.Close()
	defer ln.Close()

	payload := []byte("x")
	go conn.Write(payload)
	first := client.recvRaw(time.Second)

	intervals := []time.Duration{initialRTO, 2 * initialRTO, 4 * initialRTO}
	for i, interval := range intervals {
		clock.Advance(interval - time.Nanosecond)
		if _, ok := client.tryRecvRaw(30 * time.Millisecond); ok {
			t.Fatalf("retransmission #%d fired before its full interval elapsed", i+1)
		}
		clock.Advance(time.Nanosecond)
		seg := client.recvRaw(time.Second)
		if seg.seq != first.seq {
			t.Fatalf("retransmission #%d seq = %d, want %d", i+1, seg.seq, first.seq)
		}
	}
}

// TestTCPGivesUpAfterMaxRetransmits: after maxRetransmits unacknowledged
// retransmissions the connection emits an RST, moves to CLOSED, and
// Read/Write return an error — it does not retry forever and the
// retransmit timer goroutine exits (asserted by a done channel, not a
// sleep).
func TestTCPGivesUpAfterMaxRetransmits(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack, ln, conn, client := setupEstablishedConn(t, clock)
	defer stack.Close()
	defer ln.Close()

	go conn.Write([]byte("y"))
	client.recvRaw(time.Second) // initial send

	interval := initialRTO
	for i := 0; i < maxRetransmits; i++ {
		clock.Advance(interval)
		client.recvRaw(time.Second) // each retransmit
		interval = doubleRTO(interval)
	}

	// One more tick past maxRetransmits: give up, RST.
	clock.Advance(interval)
	rst := client.recvRaw(time.Second)
	if rst.flags&flagRST == 0 {
		t.Fatalf("final segment flags = %#x, want RST set", rst.flags)
	}

	select {
	case <-conn.timerDone:
	case <-time.After(time.Second):
		t.Fatal("timer goroutine did not exit (timerDone never closed) after giving up")
	}

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read after giving up on retransmits succeeded, want an error")
	}
	if _, err := conn.Write([]byte("z")); err == nil {
		t.Fatal("Write after giving up on retransmits succeeded, want an error")
	}
}

// TestTCPZeroWindowDoesNotSpin: a client advertising a zero window makes
// the server stop sending and, on each RTO tick of the fake clock, emit
// exactly one probe segment rather than a burst; a subsequent window
// update resumes the stream with no lost or duplicated bytes.
func TestTCPZeroWindowDoesNotSpin(t *testing.T) {
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
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	// Handshake with a zero window from the very start.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 0})
	synack := client.recvRaw(time.Second)
	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 0})

	c, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn := c.(*tcpConn)

	payload := []byte("hello")
	go conn.Write(payload)

	if _, ok := client.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("server sent data despite a zero-window peer")
	}

	// Each tick: exactly one probe segment, never a burst.
	for i := 0; i < 3; i++ {
		clock.Advance(maxRTO)
		seg, ok := client.tryRecvRaw(time.Second)
		if !ok {
			t.Fatalf("probe #%d: no segment received", i+1)
		}
		if len(seg.payload) != 1 {
			t.Fatalf("probe #%d payload = %d bytes, want exactly 1", i+1, len(seg.payload))
		}
		if _, ok := client.tryRecvRaw(50 * time.Millisecond); ok {
			t.Fatalf("probe #%d: a second segment arrived in the same tick (burst)", i+1)
		}
	}

	// Reopen the window AND acknowledge the one persist-probe byte the
	// server has been resending (it always resends from sndUna, so every
	// probe carried the payload's first byte): the rest of the stream
	// must resume with no loss or duplication.
	ackAll := client.serverISN + 1 + 1 // +1 for the SYN, +1 for the probed byte
	client.rcvNext = ackAll
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: ackAll, flags: flagACK, window: 65535})

	got := client.recvData(len(payload)-1, 2*time.Second)
	if string(got) != string(payload[1:]) {
		t.Fatalf("after window reopened, received %q, want %q", got, payload[1:])
	}
}

// TestTCPZeroWindowPersistGivesUpEventually (CR-02): a peer that
// acknowledges each zero-window persist probe one byte at a time — never
// letting sentBytes accumulate past zero, so the ordinary
// sentBytes-greater-than-zero retransmit case (with its own
// maxRetransmits accounting) never gets a chance to match — but never
// reopens its window, would otherwise keep re-triggering the zero-window
// persist branch in onRTOFired forever: that branch is not itself gated by
// maxRetransmits. CR-02's own persistProbeCount closes exactly this gap.
// After maxPersistProbes such probes the connection is reset (RST emitted,
// timerLoop exits, Read fails) instead of persisting indefinitely.
func TestTCPZeroWindowPersistGivesUpEventually(t *testing.T) {
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
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	// Handshake with a zero window from the very start.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 0})
	synack := client.recvRaw(time.Second)
	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 0})

	c, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	conn := c.(*tcpConn)

	// A payload with a few more bytes than maxPersistProbes, so the send
	// buffer never fully drains before the connection is expected to give
	// up (an empty send buffer would stop the persist branch from
	// matching at all, for an unrelated reason — "nothing left to
	// persist," not "gave up").
	payload := make([]byte, maxPersistProbes+5)
	for i := range payload {
		payload[i] = byte(i)
	}
	go conn.Write(payload)
	if _, ok := client.tryRecvRaw(100 * time.Millisecond); ok {
		t.Fatal("server sent data despite a zero-window peer")
	}

	for i := 0; i < maxPersistProbes; i++ {
		clock.Advance(maxRTO)
		probe, ok := client.tryRecvRaw(time.Second)
		if !ok {
			t.Fatalf("probe #%d: no segment received (window never reopened)", i+1)
		}
		if len(probe.payload) != 1 {
			t.Fatalf("probe #%d payload = %d bytes, want exactly 1", i+1, len(probe.payload))
		}
		// ACK the probed byte while keeping the window at zero: the
		// server's sentBytes drops back to 0, so the NEXT RTO tick
		// matches the zero-window persist case again rather than the
		// ordinary sentBytes>0 retransmit case (which would otherwise
		// give up via maxRetransmits, a different and already-bounded
		// path CR-02 does not need to touch).
		client.sendRaw(tcpSegment{
			srcPort: client.localPort, dstPort: client.remotePort,
			seq: client.sndNext, ack: probe.seq + uint32(len(probe.payload)), flags: flagACK, window: 0,
		})
		time.Sleep(20 * time.Millisecond) // let the async read-loop deliver the ACK before advancing again
	}

	// One more tick past maxPersistProbes: give up, RST, rather than yet
	// another probe.
	clock.Advance(maxRTO)
	rst := client.recvRaw(time.Second)
	if rst.flags&flagRST == 0 {
		t.Fatalf("final segment flags = %#x, want RST set", rst.flags)
	}

	select {
	case <-conn.timerDone:
	case <-time.After(time.Second):
		t.Fatal("timer goroutine did not exit (timerDone never closed) after giving up on persist probes")
	}

	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("Read after giving up on persist probes succeeded, want an error")
	}
}
