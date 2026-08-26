// tcp_conn_test.go hardens the deadline path Task 1 wired against the
// exact sequences net/http actually produces — RESEARCH.md Pitfall 1's own
// "Warning signs" paragraph names the failure these tests exist to
// prevent: curl hanging forever instead of erroring, and a harness's HTTP
// probe timing out at the test framework's own outer bound rather than
// failing fast. The load-bearing property under test throughout is
// CLEARABILITY: a deadline firing is a per-call outcome, never terminal to
// the connection.
package netstack

import (
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// establishedTestConn is the shared setup every test below starts from: a
// Stack (with the given clock, or the real SystemClock if clock is nil), a
// listener on port 8080, one attached fake session, a completed handshake,
// and the accepted net.Conn.
func establishedTestConn(t *testing.T, clock *fakeClock) (*Stack, net.Listener, net.Conn, *tcpTestClient) {
	t.Helper()
	var stack *Stack
	if clock != nil {
		stack = newTestStack(t, WithClock(clock))
	} else {
		stack = newTestStack(t)
	}
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

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	return stack, ln, conn, client
}

// assertTimeoutErr fails the test unless err is both a net.Error with
// Timeout() == true and wraps os.ErrDeadlineExceeded — the exact contract
// (*http.conn).readRequest depends on (net/http/server.go:992,
// net/net.go:158-159).
func assertTimeoutErr(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("err = %v (%T), want a net.Error with Timeout() == true", err, err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want errors.Is(err, os.ErrDeadlineExceeded)", err)
	}
}

// TestTCPReadDeadlineTimesOut: SetReadDeadline(now+20ms) on an idle
// established conn makes Read return a net.Error-shaped,
// os.ErrDeadlineExceeded-wrapping timeout in roughly 20ms.
func TestTCPReadDeadlineTimesOut(t *testing.T) {
	stack, ln, conn, _ := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, err := conn.Read(make([]byte, 16))
	elapsed := time.Since(start)

	assertTimeoutErr(t, err)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Read took %v, want roughly 20ms", elapsed)
	}
}

// TestTCPDeadlineDoesNotKillConnection: after a read deadline fires,
// clearing it with SetReadDeadline(time.Time{}) and having the peer send
// data makes Read deliver that data normally — the connection is still
// established and no RST was emitted. This is the keep-alive idle path
// net/http walks on every request.
func TestTCPDeadlineDoesNotKillConnection(t *testing.T) {
	stack, ln, conn, client := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := conn.Read(make([]byte, 16))
	assertTimeoutErr(t, err)

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(clear): %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		client.sendData([]byte("hello"))
	}()
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing deadline: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Fatalf("Read = %q, want %q", buf[:n], "hello")
	}
	<-done

	if n := stack.TCPStats().RSTsSent; n != 0 {
		t.Fatalf("RSTsSent = %d, want 0 (a fired read deadline must not reset the connection)", n)
	}
}

// TestTCPReadDeadlineInThePast: a deadline already in the past makes the
// next Read return the timeout error immediately and does NOT consume
// buffered data — a subsequent read after clearing the deadline still sees
// it.
func TestTCPReadDeadlineInThePast(t *testing.T) {
	stack, ln, conn, client := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	// sendData's own round trip (it waits for the resulting ACK) proves
	// the data has already been appended to the server's receive buffer
	// before this call returns — the ACK is only ever built after
	// handleEstablishedDataLocked appends the payload.
	client.sendData([]byte("buffered"))

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(past): %v", err)
	}
	_, err := conn.Read(make([]byte, 16))
	assertTimeoutErr(t, err)

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(clear): %v", err)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read after clearing the past deadline: %v", err)
	}
	if string(buf[:n]) != "buffered" {
		t.Fatalf("Read = %q, want %q (the timed-out Read must not have consumed it)", buf[:n], "buffered")
	}
}

// TestTCPWriteDeadlineTimesOut: with the peer advertising a zero window so
// Write can never drain what it queues, a write deadline makes Write
// return the timeout error and report the number of bytes actually
// accepted into the send buffer, not a lie.
func TestTCPWriteDeadlineTimesOut(t *testing.T) {
	stack, ln, conn, client := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	// Force the peer's advertised window to zero via a single
	// data-carrying segment, so its own resulting ACK is something to
	// synchronize on (a bare window-only ACK has no reply to wait for).
	client.sendRaw(tcpSegment{
		srcPort: client.localPort,
		dstPort: client.remotePort,
		seq:     client.sndNext,
		ack:     client.rcvNext,
		flags:   flagACK,
		window:  0,
		payload: []byte("x"),
	})
	client.sndNext++
	ack := client.recvRaw(time.Second)
	if ack.ack != client.sndNext {
		t.Fatalf("ack.ack = %d, want %d", ack.ack, client.sndNext)
	}
	// Drain the one byte so it doesn't interfere with later assertions.
	drain := make([]byte, 1)
	if _, err := io.ReadFull(conn, drain); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	big := make([]byte, maxInFlightBytes+1000)
	start := time.Now()
	n, err := conn.Write(big)
	elapsed := time.Since(start)

	assertTimeoutErr(t, err)
	if n != maxInFlightBytes {
		t.Fatalf("Write n = %d, want %d (exactly what fit in the send buffer before blocking)", n, maxInFlightBytes)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("Write took %v, want roughly 30ms", elapsed)
	}
}

// TestTCPDeadlineFromAnotherGoroutine: one goroutine blocked in Read, a
// second calling SetReadDeadline — the blocked call unblocks with the
// timeout error and the race detector reports nothing.
func TestTCPDeadlineFromAnotherGoroutine(t *testing.T) {
	stack, ln, conn, _ := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	errCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 16))
		errCh <- err
	}()

	time.Sleep(20 * time.Millisecond) // give the reader time to block
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-errCh:
		assertTimeoutErr(t, err)
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after SetReadDeadline from another goroutine")
	}
}

// TestTCPSetDeadlineSetsBoth: SetDeadline(t) arms both the read and write
// deadlines; clearing with the zero time clears both.
func TestTCPSetDeadlineSetsBoth(t *testing.T) {
	stack, ln, conn, client := establishedTestConn(t, nil)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	past := time.Now().Add(-time.Second)
	if err := conn.SetDeadline(past); err != nil {
		t.Fatalf("SetDeadline(past): %v", err)
	}

	_, err := conn.Read(make([]byte, 16))
	assertTimeoutErr(t, err)

	_, err = conn.Write([]byte("x"))
	assertTimeoutErr(t, err)

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline(clear): %v", err)
	}
	if _, err := conn.Write([]byte("y")); err != nil {
		t.Fatalf("Write after clearing SetDeadline: %v", err)
	}
	got := client.recvData(1, time.Second)
	if string(got) != "y" {
		t.Fatalf("client received %q, want %q", got, "y")
	}
}

// TestTCPDeadlineAfterClose: SetReadDeadline/SetWriteDeadline on a closed
// conn return an error wrapping net.ErrClosed, and Read after close
// returns promptly rather than blocking on a deadline that will never
// fire.
func TestTCPDeadlineAfterClose(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack, ln, conn, client := establishedTestConn(t, clock)
	defer stack.Close()
	defer ln.Close()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	client.expectServerFINAndClose()

	// expectServerFINAndClose leaves the connection in TIME_WAIT; advance
	// the fake clock past timeWaitDuration to reach CLOSED synchronously
	// (mirrors TestTCPCleanClose's own release pattern in
	// tcp_state_test.go).
	clock.Advance(timeWaitDuration + time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetReadDeadline after close = %v, want an error wrapping net.ErrClosed", err)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetWriteDeadline after close = %v, want an error wrapping net.ErrClosed", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.Read(make([]byte, 16))
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Read after close did not return promptly")
	}
}

// TestTCPDeadlineUsesWallClockNotProtocolClock: with a fake protocol Clock
// installed via WithClock, advancing that fake clock by an hour does NOT
// fire a read deadline set 50ms out in real time; the deadline still fires
// on its own real-time schedule. This is the separation-of-concerns
// prohibition, asserted rather than asserted-in-a-comment: a deadline is
// the caller's contract with net/http, not this package's own internal
// protocol timing (retransmit/TIME_WAIT), and conflating the two would let
// a test clock silently change http.Server's own timeout behavior.
func TestTCPDeadlineUsesWallClockNotProtocolClock(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack, ln, conn, _ := establishedTestConn(t, clock)
	defer stack.Close()
	defer ln.Close()
	defer conn.Close()

	const wallDeadline = 200 * time.Millisecond
	if err := conn.SetReadDeadline(time.Now().Add(wallDeadline)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	readErrCh := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 16))
		readErrCh <- err
	}()

	// A deadline is the caller's contract with net/http, not this
	// package's own internal protocol timing (retransmit/TIME_WAIT) —
	// advancing the injected Clock by an hour must not fire it. If this
	// assertion ever fails after a "tidying" change that unifies the two
	// timing sources, that unification IS the bug: a real http.Server's
	// ReadHeaderTimeout must never be affected by this package's own
	// retransmit clock.
	clock.Advance(time.Hour)

	select {
	case err := <-readErrCh:
		t.Fatalf("Read returned early (%v) after advancing the protocol Clock — the read deadline must run on wall-clock time only", err)
	case <-time.After(wallDeadline / 2):
		// Still blocked well past the fake-clock jump: correct.
	}

	select {
	case err := <-readErrCh:
		assertTimeoutErr(t, err)
	case <-time.After(wallDeadline):
		t.Fatal("Read never timed out on its own wall-clock deadline")
	}
}
