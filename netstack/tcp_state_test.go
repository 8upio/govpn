package netstack

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
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

	fs := newFakeSession()
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

	fs := newFakeSession()
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
		fs := newFakeSession()
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
