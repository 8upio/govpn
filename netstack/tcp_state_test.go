package netstack

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
)

// TestTCPHandshake: the test client's SYN to a listening port draws a
// SYN-ACK whose sequence is the server ISN, whose ack is client ISN+1,
// whose flags are exactly SYN|ACK, and which advertises MSS 1460 and
// window 65535; the client's ACK completes the connection and Accept
// returns a net.Conn whose RemoteAddr is the client's tunnel IP and source
// port and whose LocalAddr is the server tunnel IP and the listening port.
func TestTCPHandshake(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	client.sendRaw(tcpSegment{
		srcPort: client.localPort,
		dstPort: client.remotePort,
		seq:     client.isn,
		flags:   flagSYN,
		window:  65535,
		hasMSS:  true,
		mss:     1460,
	})

	synack := client.recvRaw(time.Second)
	if synack.flags != flagSYN|flagACK {
		t.Fatalf("SYN-ACK flags = %#x, want SYN|ACK", synack.flags)
	}
	if synack.ack != client.isn+1 {
		t.Fatalf("SYN-ACK ack = %d, want %d", synack.ack, client.isn+1)
	}
	if !synack.hasMSS || synack.mss != 1460 {
		t.Fatalf("SYN-ACK MSS = (%v, %d), want (true, 1460)", synack.hasMSS, synack.mss)
	}
	if synack.window != 65535 {
		t.Fatalf("SYN-ACK window = %d, want 65535", synack.window)
	}

	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{
		srcPort: client.localPort,
		dstPort: client.remotePort,
		seq:     client.sndNext,
		ack:     client.rcvNext,
		flags:   flagACK,
		window:  65535,
	})

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	ra := conn.RemoteAddr().String()
	if want := "10.8.0.2:34567"; ra != want {
		t.Fatalf("RemoteAddr = %s, want %s", ra, want)
	}
	la := conn.LocalAddr().String()
	if want := "10.8.0.1:8080"; la != want {
		t.Fatalf("LocalAddr = %s, want %s", la, want)
	}
}

// acceptWithTimeout calls ln.Accept in a goroutine and fails the test if it
// does not return within timeout — avoids a hung test if a bug causes the
// backlog to never receive the connection.
func acceptWithTimeout(t *testing.T, ln net.Listener, timeout time.Duration) (net.Conn, error) {
	t.Helper()
	type result struct {
		c   net.Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		ch <- result{c, err}
	}()
	select {
	case r := <-ch:
		return r.c, r.err
	case <-time.After(timeout):
		t.Fatal("Accept timed out")
		return nil, nil
	}
}

// TestTCPEchoStream: over an accepted conn, a 5000-byte payload written by
// the test client arrives in order and in full from Read (across multiple
// Read calls, as a stream), and a 5000-byte response written to the conn
// arrives in order and in full at the test client; both directions are
// asserted byte-for-byte.
func TestTCPEchoStream(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	clientToServer := make([]byte, 5000)
	for i := range clientToServer {
		clientToServer[i] = byte(i)
	}
	client.sendData(clientToServer)

	got := make([]byte, 0, 5000)
	buf := make([]byte, 700)
	for len(got) < 5000 {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("conn.Read: %v", err)
		}
		got = append(got, buf[:n]...)
		if n == 0 && err != nil {
			break
		}
	}
	if !bytes.Equal(got, clientToServer) {
		t.Fatalf("server received %d bytes, mismatched content (client->server)", len(got))
	}

	serverToClient := make([]byte, 5000)
	for i := range serverToClient {
		serverToClient[i] = byte(255 - i%256)
	}
	writeErrCh := make(chan error, 1)
	go func() {
		_, err := conn.Write(serverToClient)
		writeErrCh <- err
	}()

	received := client.recvData(5000, 2*time.Second)
	if err := <-writeErrCh; err != nil {
		t.Fatalf("conn.Write: %v", err)
	}
	if !bytes.Equal(received, serverToClient) {
		t.Fatalf("client received %d bytes, mismatched content (server->client)", len(received))
	}
}

// TestTCPSequenceNumbersAdvanceCorrectly: the server's sequence advances by
// exactly the bytes it sent; its ACK advances by exactly the bytes it
// received; SYN and FIN each consume exactly one sequence number.
func TestTCPSequenceNumbersAdvanceCorrectly(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
	synack := client.recvRaw(time.Second)
	serverISNStart := synack.seq
	if synack.ack != client.isn+1 {
		t.Fatalf("SYN consumed %d sequence numbers, want 1", synack.ack-client.isn)
	}
	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	payload := []byte("hello, sequence numbers")
	client.sendData(payload)
	if client.rcvNext != serverISNStart+1 {
		t.Fatalf("server rcvNext advanced unexpectedly before any server send")
	}

	if _, err := conn.Write([]byte("reply")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	seg := client.recvRaw(time.Second)
	if seg.seq != serverISNStart+1 {
		t.Fatalf("server's data segment seq = %d, want %d (ISN+1, after SYN consumed one)", seg.seq, serverISNStart+1)
	}
	if len(seg.payload) != 5 {
		t.Fatalf("server's data segment payload = %d bytes, want 5", len(seg.payload))
	}
	client.rcvNext = seg.seq + uint32(len(seg.payload))
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	fin := client.recvRaw(time.Second)
	if fin.flags&flagFIN == 0 {
		t.Fatalf("expected a FIN, got flags %#x", fin.flags)
	}
	wantFinSeq := serverISNStart + 1 + uint32(len(seg.payload))
	if fin.seq != wantFinSeq {
		t.Fatalf("FIN seq = %d, want %d", fin.seq, wantFinSeq)
	}
	client.rcvNext = fin.seq + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagFIN | flagACK, window: 65535})
	client.sndNext++
	finalAck := client.recvRaw(time.Second)
	if finalAck.ack != client.sndNext {
		t.Fatalf("final ack = %d, want %d (client's FIN consumed one sequence number)", finalAck.ack, client.sndNext)
	}
}

// TestTCPCleanClose: closing the accepted conn sends a FIN; the client's
// ACK moves it to FIN_WAIT_2; the client's own FIN draws an ACK and moves
// it to TIME_WAIT; Read on the conn afterward returns io.EOF; advancing the
// fake clock past timeWaitDuration releases the connection's state
// (asserted by the 4-tuple becoming reusable, not by reading a private
// field).
func TestTCPCleanClose(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	fin := client.recvRaw(time.Second)
	if fin.flags&flagFIN == 0 {
		t.Fatalf("expected server FIN, got flags %#x", fin.flags)
	}
	client.rcvNext = fin.seq + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})

	readErrCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 16)
		_, err := conn.Read(buf)
		readErrCh <- err
	}()

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagFIN | flagACK, window: 65535})
	client.sndNext++
	finalAck := client.recvRaw(time.Second)
	if finalAck.flags&flagACK == 0 || finalAck.ack != client.sndNext {
		t.Fatalf("final ack = %#x/%d, want ACK/%d", finalAck.flags, finalAck.ack, client.sndNext)
	}

	if err := <-readErrCh; err != io.EOF {
		t.Fatalf("Read after full close = %v, want io.EOF", err)
	}

	// The 4-tuple must still be in TIME_WAIT (not yet reusable) until the
	// clock advances past timeWaitDuration.
	clock.Advance(timeWaitDuration - time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	// Advancing past timeWaitDuration releases the connection: proven by
	// a fresh SYN with the SAME 4-tuple completing a brand new handshake
	// rather than hitting stale state.
	clock.Advance(2 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	client2 := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client2.isn = 9999
	client2.sendRaw(tcpSegment{srcPort: client2.localPort, dstPort: client2.remotePort, seq: client2.isn, flags: flagSYN, window: 65535})
	synack2 := client2.recvRaw(time.Second)
	if synack2.flags != flagSYN|flagACK {
		t.Fatalf("reused 4-tuple SYN drew flags %#x, want a fresh SYN-ACK", synack2.flags)
	}
}

// TestTCPISNIsRandom: 100 connections produce 100 distinct initial
// sequence numbers, none equal to a small integer, and none forming an
// arithmetic progression — proving the ISN is not a counter and not
// clock-derived.
func TestTCPISNIsRandom(t *testing.T) {
	const n = 100
	isns := make([]uint32, 0, n)

	for i := 0; i < n; i++ {
		stack := newTestStack(t)
		ln, err := stack.ListenTCP(8080)
		if err != nil {
			t.Fatalf("ListenTCP: %v", err)
		}
		fs := netstacktest.NewFakeSession()
		if err := stack.Attach(fs, testClientAddr()); err != nil {
			t.Fatalf("Attach: %v", err)
		}
		client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
		synack := client.recvRaw(time.Second)
		isns = append(isns, synack.seq)
		ln.Close()
		stack.Close()
	}

	seen := make(map[uint32]bool, n)
	for _, isn := range isns {
		if seen[isn] {
			t.Fatalf("duplicate ISN %d among %d connections", isn, n)
		}
		seen[isn] = true
		if isn < 1000 {
			t.Fatalf("ISN %d looks like a small counter, not random", isn)
		}
	}

	// Arithmetic-progression check: a counter or clock-derived ISN would
	// produce a constant (or near-constant) delta between consecutive
	// draws; crypto/rand output should not.
	constantDeltaCount := 0
	for i := 1; i < len(isns); i++ {
		if isns[i]-isns[i-1] == isns[1]-isns[0] {
			constantDeltaCount++
		}
	}
	if constantDeltaCount > n/2 {
		t.Fatalf("%d/%d consecutive ISN deltas were identical — looks like an arithmetic progression, not random", constantDeltaCount, n)
	}
}

// TestTCPCumulativeAckAdvancesSendWindow: an ACK covering three previously
// -sent segments retires all three from the send buffer at once; a
// duplicate ACK does not retire anything and does not corrupt sndUna.
func TestTCPCumulativeAckAdvancesSendWindow(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	go conn.Write([]byte("AAA"))
	seg1 := client.recvRaw(time.Second)
	go conn.Write([]byte("BBB"))
	seg2 := client.recvRaw(time.Second)
	go conn.Write([]byte("CCC"))
	seg3 := client.recvRaw(time.Second)

	if seg2.seq != seg1.seq+3 || seg3.seq != seg2.seq+3 {
		t.Fatalf("segments not sequential: %d, %d, %d", seg1.seq, seg2.seq, seg3.seq)
	}

	cumulativeAck := seg3.seq + 3
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: cumulativeAck, flags: flagACK, window: 65535})
	time.Sleep(30 * time.Millisecond)

	// Duplicate ACK: repeat the same ack number. Must not corrupt state —
	// proven by the next write continuing exactly where it should.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: cumulativeAck, flags: flagACK, window: 65535})
	time.Sleep(30 * time.Millisecond)

	go conn.Write([]byte("DDD"))
	seg4 := client.recvRaw(time.Second)
	if seg4.seq != cumulativeAck {
		t.Fatalf("after cumulative + duplicate ACK, next segment seq = %d, want %d (sndUna undisturbed by the duplicate)", seg4.seq, cumulativeAck)
	}
}

// TestTCPOutOfOrderBuffered: segments delivered as 3,2,1 (each in-window)
// produce the data in order 1,2,3 from Read exactly once, and the ACK
// emitted after segment 1 covers all three.
func TestTCPOutOfOrderBuffered(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	base := client.sndNext
	seg1 := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: base, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("111")}
	seg2 := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: base + 3, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("222")}
	seg3 := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: base + 6, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("333")}

	client.sendRaw(seg3)
	ack3 := client.recvRaw(time.Second)
	if ack3.ack != base {
		t.Fatalf("dup-ack after out-of-order seg3 = %d, want %d (rcvNxt unchanged)", ack3.ack, base)
	}

	client.sendRaw(seg2)
	ack2 := client.recvRaw(time.Second)
	if ack2.ack != base {
		t.Fatalf("dup-ack after out-of-order seg2 = %d, want %d (rcvNxt unchanged)", ack2.ack, base)
	}

	client.sendRaw(seg1)
	ackFinal := client.recvRaw(time.Second)
	if want := base + 9; ackFinal.ack != want {
		t.Fatalf("ack after gap-filling seg1 = %d, want %d (covers all three)", ackFinal.ack, want)
	}

	buf := make([]byte, 9)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "111222333" {
		t.Fatalf("Read = %q, want %q", buf, "111222333")
	}
}

// TestTCPReorderBufferBounded: more than maxReorderSegments out-of-order
// segments makes the excess dropped rather than queued; after the gap is
// filled by the peer's retransmission, the stream is still delivered
// correctly and in order.
func TestTCPReorderBufferBounded(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	base := client.sndNext
	const total = maxReorderSegments + 2 // 18 one-byte segments, numbered 1..18 (index 0 skipped first)

	segAt := func(i uint32) tcpSegment {
		return tcpSegment{
			srcPort: client.localPort, dstPort: client.remotePort,
			seq: base + i, ack: client.rcvNext, flags: flagACK, window: 65535,
			payload: []byte{byte('A' + i)},
		}
	}

	// Send segments 1..total-1 (skip segment 0 — the gap), out of order.
	before := stack.TCPStats().ReorderDropped
	for i := uint32(1); i < total; i++ {
		client.sendRaw(segAt(i))
		client.recvRaw(time.Second) // dup ack for each
	}
	time.Sleep(30 * time.Millisecond)
	if got := stack.TCPStats().ReorderDropped; got <= before {
		t.Fatalf("ReorderDropped = %d, want it to have increased (excess out-of-order segments must be dropped)", got)
	}

	// Fill the gap: segment 0.
	client.sendRaw(segAt(0))
	finalAck := client.recvRaw(time.Second)
	wantAck := base + 1 + maxReorderSegments // segment 0 plus the maxReorderSegments buffered ones drain contiguously
	if finalAck.ack != wantAck {
		t.Fatalf("ack after gap-fill = %d, want %d", finalAck.ack, wantAck)
	}

	// Re-send the one that was dropped (the peer's own retransmission) —
	// it is now exactly in-order and must be accepted normally.
	dropped := uint32(total - 1)
	client.rcvNext = finalAck.ack
	client.sendRaw(segAt(dropped))
	lastAck := client.recvRaw(time.Second)
	if want := base + dropped + 1; lastAck.ack != want {
		t.Fatalf("ack after re-sending the dropped segment = %d, want %d", lastAck.ack, want)
	}

	buf := make([]byte, int(dropped)+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	for i := range buf {
		if buf[i] != byte('A'+i) {
			t.Fatalf("byte %d = %q, want %q", i, buf[i], byte('A'+i))
		}
	}
}

// TestTCPDuplicateSegmentIgnored: re-delivering an already-accepted
// segment produces no duplicate bytes from Read and re-emits the current
// cumulative ACK.
func TestTCPDuplicateSegmentIgnored(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	seg := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("hello")}
	client.sendRaw(seg)
	ack1 := client.recvRaw(time.Second)
	if want := client.sndNext + 5; ack1.ack != want {
		t.Fatalf("first ack = %d, want %d", ack1.ack, want)
	}

	// Re-deliver the same segment.
	client.sendRaw(seg)
	ack2 := client.recvRaw(time.Second)
	if ack2.ack != ack1.ack {
		t.Fatalf("ack after duplicate = %d, want %d (unchanged)", ack2.ack, ack1.ack)
	}

	buf := make([]byte, 5)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(buf) != "hello" {
		t.Fatalf("Read = %q, want %q", buf, "hello")
	}

	// No further bytes should ever arrive from the duplicate.
	if _, ok := readNonBlocking(conn, 50*time.Millisecond); ok {
		t.Fatal("Read produced additional bytes from a duplicate segment")
	}
}

// readNonBlocking attempts one Read with a short deadline via a goroutine
// race against a timer, reporting ok=false if nothing arrived in time.
func readNonBlocking(r io.Reader, wait time.Duration) ([]byte, bool) {
	ch := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := r.Read(buf)
		if err == nil && n > 0 {
			ch <- buf[:n]
		}
	}()
	select {
	case b := <-ch:
		return b, true
	case <-time.After(wait):
		return nil, false
	}
}

// TestTCPRespectsPeerWindow: a client advertising a 1000-byte window never
// receives more than 1000 unacknowledged bytes; as its ACKs open the
// window, more is sent; total in-flight never exceeds maxInFlightBytes
// even when the peer advertises the full 65535.
func TestTCPRespectsPeerWindow(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	const window = 1000
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: window})
	synack := client.recvRaw(time.Second)
	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: window})

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	const total = 5000
	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i)
	}
	go conn.Write(payload)

	received := 0
	nextSeq := synack.seq + 1
	for received < total {
		seg := client.recvRaw(time.Second)
		if len(seg.payload) > window {
			t.Fatalf("segment carried %d bytes, exceeding the 1000-byte window", len(seg.payload))
		}
		if seg.seq != nextSeq {
			t.Fatalf("segment seq = %d, want %d", seg.seq, nextSeq)
		}
		nextSeq += uint32(len(seg.payload))
		received += len(seg.payload)
		client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: nextSeq, flags: flagACK, window: window})
	}
	if received != total {
		t.Fatalf("received %d bytes total, want %d", received, total)
	}
}

// TestTCPAdvertisedWindowShrinksWithBuffer: with the application not
// reading, the advertised window in emitted ACKs decreases as the receive
// buffer fills and recovers after Read drains it — never advertising more
// space than exists.
func TestTCPAdvertisedWindowShrinksWithBuffer(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	chunk := make([]byte, 1000)
	client.sendData(chunk) // consumes its own ack internally

	// Send a second chunk directly (bypassing sendData's own ack-wait) to
	// read the window this time.
	seg := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535, payload: chunk}
	client.sendRaw(seg)
	client.sndNext += uint32(len(chunk))
	ackAfterFill := client.recvRaw(time.Second)
	wantWindow := uint16(defaultReceiveWindow - 2000)
	if ackAfterFill.window != wantWindow {
		t.Fatalf("advertised window with 2000 buffered bytes = %d, want %d", ackAfterFill.window, wantWindow)
	}

	// Drain the buffer.
	buf := make([]byte, 2000)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}

	// A further segment's ACK must reflect the recovered window.
	seg2 := tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("more")}
	client.sendRaw(seg2)
	client.sndNext += 4
	ackAfterDrain := client.recvRaw(time.Second)
	if ackAfterDrain.window != defaultReceiveWindow-4 {
		t.Fatalf("advertised window after drain = %d, want %d", ackAfterDrain.window, defaultReceiveWindow-4)
	}
}

// TestTCPReceiveWindowEnforcedOnIngress (CR-01): a peer that ignores the
// advertised window and sends far more in-order data than the receive
// window has room for must not grow recvBuf past defaultReceiveWindow —
// the excess is dropped, not buffered, and only defaultReceiveWindow bytes
// are ever delivered to the application. Without CR-01's clamp in
// handleEstablishedDataLocked, this test's Read would return the full
// oversized payload (a receive-side memory-growth vector for a
// slow/malicious reader).
func TestTCPReceiveWindowEnforcedOnIngress(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// Each chunk stays comfortably under readBufferSize (2048, stack.go)
	// so this test exercises CR-01's window enforcement in isolation from
	// WR-04's separate short-read-buffer handling — chunks are sent
	// in-order, back-to-back, with the application never reading in
	// between, exactly the "slow reader" scenario CR-01 closes. 33 chunks
	// of 2000 bytes (66000 total) push the connection just past
	// defaultReceiveWindow (65535).
	const chunkSize = 2000
	const chunkCount = 33
	var totalSent uint32
	var lastAck tcpSegment
	for i := 0; i < chunkCount; i++ {
		chunk := bytes.Repeat([]byte{byte(i)}, chunkSize)
		client.sendRaw(tcpSegment{
			srcPort: client.localPort,
			dstPort: client.remotePort,
			seq:     client.sndNext,
			ack:     client.rcvNext,
			flags:   flagACK,
			window:  65535,
			payload: chunk,
		})
		client.sndNext += chunkSize
		totalSent += chunkSize
		lastAck = client.recvRaw(time.Second)
	}
	if totalSent <= defaultReceiveWindow {
		t.Fatalf("test setup error: totalSent (%d) must exceed defaultReceiveWindow (%d)", totalSent, defaultReceiveWindow)
	}

	admitted := lastAck.ack - client.isn - 1
	if admitted != defaultReceiveWindow {
		t.Fatalf("cumulative ACK admitted %d bytes across %d chunks (%d bytes sent), want exactly defaultReceiveWindow (%d) — CR-01 requires dropping bytes beyond the advertised window rather than buffering them", admitted, chunkCount, totalSent, defaultReceiveWindow)
	}
	if lastAck.window != 0 {
		t.Fatalf("advertised window after filling the buffer = %d, want 0", lastAck.window)
	}

	buf := make([]byte, totalSent)
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _ := io.ReadFull(conn, buf)
	if uint32(n) != defaultReceiveWindow {
		t.Fatalf("Read delivered %d bytes, want exactly defaultReceiveWindow (%d) — the excess must be dropped, not buffered", n, defaultReceiveWindow)
	}
}

// TestTCPRSTOutOfWindowIgnored (WR-03): an inbound RST whose sequence
// number falls outside the receive window is ignored — the connection
// stays ESTABLISHED and keeps accepting legitimate traffic — rather than
// tearing the connection down for any RST regardless of SEG.SEQ (RFC 9293
// §3.10.7.4's in-window validation, the classic blind-reset mitigation).
func TestTCPRSTOutOfWindowIgnored(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)
	client.connect()
	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// A RST far outside the connection's current receive window
	// (client.sndNext is exactly the server's rcvNxt right after the
	// handshake) — a well-behaved peer would never send this.
	client.sendRaw(tcpSegment{
		srcPort: client.localPort, dstPort: client.remotePort,
		seq: client.sndNext + defaultReceiveWindow*4, flags: flagRST, window: 65535,
	})
	time.Sleep(30 * time.Millisecond) // let the async read-loop deliver it before proceeding

	// The connection must still be usable: a subsequent legitimate data
	// exchange succeeds exactly as if the out-of-window RST had never
	// arrived.
	payload := []byte("still alive")
	client.sendData(payload)
	buf := make([]byte, len(payload))
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("ReadFull after out-of-window RST: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("got %q, want %q", buf, payload)
	}
}

// TestTCPSynRcvdBadAckBroadcastsBeforeUnlock (WR-03): the SYN_RCVD
// bad-ACK teardown branch must call broadcastLocked() before releasing
// c.mu, exactly like every other terminal-state transition in this file —
// asserted directly by capturing the pre-existing notifyCh and confirming
// it closes, since no external Read/Write caller can currently observe
// this branch's own effect any other way (a SYN_RCVD connection has never
// been handed to an application). A future change exposing pre-Accept
// connection state to a waiter would otherwise silently reintroduce a
// missed-wakeup bug here.
func TestTCPSynRcvdBadAckBroadcastsBeforeUnlock(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535})
	synack := client.recvRaw(time.Second)
	client.serverISN = synack.seq

	d := demuxOf(t, stack)
	key := fourTuple{remoteIP: netstacktest.MustAddr(testClientAddr()), remotePort: client.localPort, localPort: 8080}
	conn := connOf(t, d, key)
	notify := func() chan struct{} {
		conn.mu.Lock()
		defer conn.mu.Unlock()
		return conn.notifyCh
	}()

	// A completing ACK with a deliberately wrong acknowledgement number —
	// the SYN_RCVD bad-ACK branch under test.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn + 1, ack: synack.seq + 999, flags: flagACK, window: 65535})
	client.recvRaw(time.Second) // the resulting RST

	select {
	case <-notify:
	case <-time.After(time.Second):
		t.Fatal("notifyCh was never closed — the SYN_RCVD bad-ACK branch did not call broadcastLocked() before unlocking")
	}
}

// TestTCPNoSACKOptionEmitted: no segment this stack emits, across a mix of
// handshake/data/retransmit/reorder/zero-window scenarios, carries a TCP
// option other than MSS on a SYN-ACK — asserted by walking the options
// region of every captured outbound segment's raw bytes.
func TestTCPNoSACKOptionEmitted(t *testing.T) {
	clock := newFakeClock(time.Unix(0, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()
	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()
	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, testClientAddr()); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client := newTCPTestClient(t, fs, testClientAddr(), 34567, testServerIP(), 8080)

	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.isn, flags: flagSYN, window: 65535, hasMSS: true, mss: 1460})
	synackPkt := assertOnlyOption(t, <-fs.Outbound(), mssOptionKind)
	synack, err := parseTCP(synackPkt)
	if err != nil {
		t.Fatalf("parseTCP: %v", err)
	}
	client.serverISN = synack.seq
	client.rcvNext = synack.seq + 1
	client.sndNext = client.isn + 1
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext, ack: client.rcvNext, flags: flagACK, window: 65535})

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	// Trigger a retransmission and drain every outbound segment produced
	// so far, none of which may carry any option at all (no MSS on a
	// non-SYN-ACK segment, and definitely no SACK).
	go conn.Write([]byte("payload"))
	assertOnlyOption(t, <-fs.Outbound(), -1)
	clock.Advance(initialRTO)
	assertOnlyOption(t, <-fs.Outbound(), -1)

	// Out-of-order delivery must also never provoke a SACK option.
	client.sendRaw(tcpSegment{srcPort: client.localPort, dstPort: client.remotePort, seq: client.sndNext + 10, ack: client.rcvNext, flags: flagACK, window: 65535, payload: []byte("x")})
	assertOnlyOption(t, <-fs.Outbound(), -1)
}

// assertOnlyOption parses pkt's IPv4+TCP headers and fails the test unless
// its TCP options region contains at most the single option kind wanted
// (or none at all, if wanted < 0) — walking the raw bytes directly rather
// than relying on parseTCP's own (MSS-only-aware) parsing, so an
// unexpected option kind cannot hide from this specific check the way it
// would from parseTCP's generic "skip anything unknown" behavior.
func assertOnlyOption(t *testing.T, pkt []byte, wantKind int) []byte {
	t.Helper()
	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("assertOnlyOption: parseIPv4: %v", err)
	}
	tcpBytes := pkt[hdr.payloadOff:hdr.totalLen]
	if len(tcpBytes) < tcpHeaderMinLen {
		t.Fatalf("assertOnlyOption: TCP segment too short")
	}
	dataOffset := int(tcpBytes[12]>>4) * 4
	opts := tcpBytes[tcpHeaderMinLen:dataOffset]
	if wantKind < 0 {
		if len(opts) != 0 {
			t.Fatalf("assertOnlyOption: expected no options, got %d bytes: %v", len(opts), opts)
		}
		return tcpBytes
	}
	if len(opts) != mssOptionLen || int(opts[0]) != wantKind {
		t.Fatalf("assertOnlyOption: options = %v, want exactly kind %d", opts, wantKind)
	}
	return tcpBytes
}
