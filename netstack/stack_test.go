package netstack

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/8upio/govpn/netstack/netstacktest"
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

func waitForOutbound(t *testing.T, fs *netstacktest.FakeSession, timeout time.Duration) []byte {
	t.Helper()
	select {
	case pkt := <-fs.Outbound():
		return pkt
	case <-time.After(timeout):
		t.Fatal("timed out waiting for an outbound packet")
		return nil
	}
}

func assertNoOutbound(t *testing.T, fs *netstacktest.FakeSession, wait time.Duration) {
	t.Helper()
	select {
	case pkt := <-fs.Outbound():
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

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	req := netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP()), 1, 1, []byte("hello, tunnel"))
	fs.Inject(req)

	reply := waitForOutbound(t, fs, time.Second)

	hdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	if hdr.src != netstacktest.MustAddr(testServerIP()) {
		t.Errorf("reply source = %v, want server IP %v", hdr.src, netstacktest.MustAddr(testServerIP()))
	}
	if hdr.dst != netstacktest.MustAddr(clientIP) {
		t.Errorf("reply destination = %v, want client IP %v", hdr.dst, netstacktest.MustAddr(clientIP))
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

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	// A payload comfortably larger than readBufferSize but well under
	// maxReadRetryBufferSize — the "non-conforming or hostile client
	// exceeds the advisory tun-mtu" scenario WR-04 is about.
	bigPayload := bytes.Repeat([]byte{0x7a}, readBufferSize+500)
	req := netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP()), 1, 1, bigPayload)
	fs.Inject(req)

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
	_, exists := stack.routes[netstacktest.MustAddr(clientIP)]
	stack.mu.RUnlock()
	if !exists {
		t.Fatal("route was removed after an oversized (but recoverable) packet — the attachment was wrongly detached")
	}
	fs.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP()), 2, 1, []byte("still alive")))
	waitForOutbound(t, fs, time.Second)
}

func TestAttachDetachRouting(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fsA := netstacktest.NewFakeSession()
	fsB := netstacktest.NewFakeSession()
	ipA := net.IPv4(10, 8, 0, 2).To4()
	ipB := net.IPv4(10, 8, 0, 3).To4()

	if err := stack.Attach(fsA, ipA); err != nil {
		t.Fatalf("Attach A: %v", err)
	}
	if err := stack.Attach(fsB, ipB); err != nil {
		t.Fatalf("Attach B: %v", err)
	}

	fsA.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(ipA), netstacktest.MustAddr(testServerIP()), 1, 1, nil))
	replyA := waitForOutbound(t, fsA, time.Second)
	hdrA, err := parseIPv4(replyA)
	if err != nil {
		t.Fatalf("parseIPv4(replyA): %v", err)
	}
	if hdrA.dst != netstacktest.MustAddr(ipA) {
		t.Fatalf("session A's reply is addressed to %v, want %v", hdrA.dst, netstacktest.MustAddr(ipA))
	}
	assertNoOutbound(t, fsB, 50*time.Millisecond)

	fsB.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(ipB), netstacktest.MustAddr(testServerIP()), 2, 1, nil))
	replyB := waitForOutbound(t, fsB, time.Second)
	hdrB, err := parseIPv4(replyB)
	if err != nil {
		t.Fatalf("parseIPv4(replyB): %v", err)
	}
	if hdrB.dst != netstacktest.MustAddr(ipB) {
		t.Fatalf("session B's reply is addressed to %v, want %v", hdrB.dst, netstacktest.MustAddr(ipB))
	}

	if err := stack.Attach(netstacktest.NewFakeSession(), ipA); !errors.Is(err, ErrDuplicateAttach) {
		t.Fatalf("Attach(duplicate ipA) = %v, want ErrDuplicateAttach", err)
	}
	if err := stack.Attach(netstacktest.NewFakeSession(), testServerIP()); !errors.Is(err, ErrAttachServerIP) {
		t.Fatalf("Attach(server IP) = %v, want ErrAttachServerIP", err)
	}

	if !stack.Detach(ipA) {
		t.Fatal("Detach(ipA) = false, want true")
	}
	if stack.Detach(ipA) {
		t.Fatal("second Detach(ipA) = true, want false")
	}

	fsA.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(ipA), netstacktest.MustAddr(testServerIP()), 3, 1, nil))
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

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[netstacktest.MustAddr(ip)]
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
	_, exists := stack.routes[netstacktest.MustAddr(ip)]
	stack.mu.RUnlock()
	if exists {
		t.Fatal("route was not removed after the session's Read returned an error")
	}
}

// TestSingleReaderPerSession asserts Attach starts exactly one goroutine
// per attached session that calls Session.Read (session.go:305-313's
// single-reader contract) — via both an overlap check and a distinct
// goroutine-identity count (see netstacktest.FakeSession's doc comment).
func TestSingleReaderPerSession(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	for i := 0; i < 50; i++ {
		fs.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(ip), netstacktest.MustAddr(testServerIP()), 1, uint16(i), nil))
		waitForOutbound(t, fs, time.Second)
	}

	obs := fs.ReadObservations()

	if obs.Overlapped {
		t.Fatal("Session.Read was called concurrently from more than one goroutine")
	}
	if obs.DistinctReaders != 1 {
		t.Fatalf("Session.Read was called from %d distinct goroutines, want exactly 1", obs.DistinctReaders)
	}
}

func TestSourceIPSpoofDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	otherClient := net.IPv4(10, 8, 0, 3).To4()
	fs.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(otherClient), netstacktest.MustAddr(testServerIP()), 1, 1, nil))
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().SpoofedSourceDropped; got != 1 {
		t.Fatalf("Stats().SpoofedSourceDropped = %d, want 1 (claiming another client's IP)", got)
	}

	fs.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(testServerIP()), netstacktest.MustAddr(testServerIP()), 2, 1, nil))
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().SpoofedSourceDropped; got != 2 {
		t.Fatalf("Stats().SpoofedSourceDropped = %d, want 2 (claiming the server's own IP)", got)
	}
}

func TestNonServerDestinationDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	wrongDst := net.IPv4(10, 8, 0, 7).To4()
	fs.Inject(netstacktest.BuildICMPEchoRequest(netstacktest.MustAddr(ip), netstacktest.MustAddr(wrongDst), 1, 1, nil))
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().WrongDestinationDropped; got != 1 {
		t.Fatalf("Stats().WrongDestinationDropped = %d, want 1", got)
	}
}

// waitForStat polls stack.Stats() until pred is satisfied or the timeout
// expires, then returns the final snapshot. The stack processes inbound
// packets on its own read-loop goroutine, so a test that asserts a counter
// immediately after feeding a packet would race the loop; this is the
// barrier every fragment test below crosses before reading state.
func waitForStat(t *testing.T, stack *Stack, pred func(Stats) bool, timeout time.Duration) Stats {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		st := stack.Stats()
		if pred(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for a Stats condition; last snapshot: %+v", st)
			return st
		}
		time.Sleep(time.Millisecond)
	}
}

// icmpEchoFragments splits a complete ICMP echo request into n 8-aligned
// fragments of one datagram, in ascending offset order, and returns the
// original ICMP message alongside them.
func icmpEchoFragments(t *testing.T, src, dst netip.Addr, id uint16, chunk int, payload []byte) (icmpMsg []byte, frags [][]byte) {
	t.Helper()
	if chunk%8 != 0 {
		t.Fatalf("icmpEchoFragments: chunk %d is not a multiple of 8", chunk)
	}
	req := netstacktest.BuildICMPEchoRequest(src, dst, 1, 1, payload)
	icmpMsg = req[minIPv4HeaderLen:]

	for off := 0; off < len(icmpMsg); off += chunk {
		end := off + chunk
		if end > len(icmpMsg) {
			end = len(icmpMsg)
		}
		frags = append(frags, netstacktest.BuildFragment(src, dst, protocolICMP, id, off, end < len(icmpMsg), icmpMsg[off:end]))
	}
	return icmpMsg, frags
}

// TestFragmentedICMPEchoReassembled is the inbound end-to-end proof: an
// echo request arriving as three fragments IN REVERSE ORDER is reassembled
// and answered exactly once. PacketsReceived counts the three fragments;
// FragmentsReassembled counts the one datagram they became.
func TestFragmentedICMPEchoReassembled(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())
	icmpMsg, frags := icmpEchoFragments(t, client, server, 0x2222, 16, bytes.Repeat([]byte{0xAB}, 40))
	if len(frags) != 3 {
		t.Fatalf("test fixture produced %d fragments, want 3", len(frags))
	}

	for i := len(frags) - 1; i >= 0; i-- {
		fs.Inject(frags[i])
	}

	reply := waitForOutbound(t, fs, time.Second)
	hdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	replyICMP := reply[hdr.payloadOff:hdr.totalLen]
	if replyICMP[0] != icmpTypeEchoReply {
		t.Fatalf("reply ICMP type = %d, want %d (echo reply)", replyICMP[0], icmpTypeEchoReply)
	}
	if !bytes.Equal(replyICMP[4:], icmpMsg[4:]) {
		t.Fatal("reply identifier/sequence/payload does not echo the reassembled request")
	}

	// Exactly one reply: the two buffered fragments must not each
	// produce one of their own.
	assertNoOutbound(t, fs, 50*time.Millisecond)

	st := stack.Stats()
	if st.FragmentsReassembled != 1 {
		t.Errorf("Stats().FragmentsReassembled = %d, want 1", st.FragmentsReassembled)
	}
	if st.PacketsReceived != 3 {
		t.Errorf("Stats().PacketsReceived = %d, want 3 (fragments are counted individually)", st.PacketsReceived)
	}
	if st.FragmentsDropped != 0 {
		t.Errorf("Stats().FragmentsDropped = %d, want 0", st.FragmentsDropped)
	}
	if st.ICMPEchoReplies != 1 {
		t.Errorf("Stats().ICMPEchoReplies = %d, want 1", st.ICMPEchoReplies)
	}
}

// TestOversizedInboundUDPDatagramReassembled is the Voxio case this whole
// change exists for: a SIP-sized UDP datagram larger than the MTU, sent as
// fragments, must arrive WHOLE at the application's ReadFrom.
func TestOversizedInboundUDPDatagramReassembled(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(5060)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())
	appPayload := bytes.Repeat([]byte("INVITE sip:voxio "), 200) // 3400 bytes
	datagram := buildUDP(nil, client, server, 40000, 5060, appPayload)

	const chunk = 1480
	var sent int
	for off := 0; off < len(datagram); off += chunk {
		end := off + chunk
		if end > len(datagram) {
			end = len(datagram)
		}
		fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 0x3333, off, end < len(datagram), datagram[off:end]))
		sent++
	}
	if sent < 3 {
		t.Fatalf("test fixture produced %d fragments, want at least 3", sent)
	}

	buf := make([]byte, 65535)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], appPayload) {
		t.Fatalf("ReadFrom returned %d bytes, want the %d-byte datagram back whole", n, len(appPayload))
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || !udpAddr.IP.Equal(clientIP) || udpAddr.Port != 40000 {
		t.Fatalf("ReadFrom addr = %v, want %v:40000", addr, clientIP)
	}

	st := stack.Stats()
	if st.FragmentsReassembled != 1 {
		t.Errorf("Stats().FragmentsReassembled = %d, want 1", st.FragmentsReassembled)
	}
	if st.PacketsReceived != uint64(sent) {
		t.Errorf("Stats().PacketsReceived = %d, want %d", st.PacketsReceived, sent)
	}
}

// TestSpoofedFragmentAllocatesNothing is T-FVA-02: the source-IP ACL runs
// strictly BEFORE the reassembler, so a fragment claiming another
// session's IP is dropped without allocating a single buffer.
func TestSpoofedFragmentAllocatesNothing(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[netstacktest.MustAddr(clientIP)]
	stack.mu.RUnlock()

	otherClient := netstacktest.MustAddr(net.IPv4(10, 8, 0, 3).To4())
	fs.Inject(netstacktest.BuildFragment(otherClient, netstacktest.MustAddr(testServerIP()), protocolUDP, 1, 0, true, bytes.Repeat([]byte{0x01}, 16)))

	st := waitForStat(t, stack, func(s Stats) bool { return s.SpoofedSourceDropped == 1 }, time.Second)
	if st.FragmentsDropped != 0 || st.ReassemblyBoundExceeded != 0 {
		t.Errorf("a spoofed fragment was counted as a reassembly outcome: %+v", st)
	}

	a.reasm.mu.Lock()
	bufs, bytesHeld := len(a.reasm.bufs), a.reasm.bytes
	a.reasm.mu.Unlock()
	if bufs != 0 || bytesHeld != 0 {
		t.Fatalf("a spoofed fragment allocated reassembly state: %d buffers, %d bytes", bufs, bytesHeld)
	}
}

// TestMisalignedFragmentIsMalformed: a non-final fragment whose payload is
// not a multiple of 8 never reaches the reassembler — parseIPv4 rejects
// its geometry, so it lands in MalformedDropped, not FragmentsDropped.
func TestMisalignedFragmentIsMalformed(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[netstacktest.MustAddr(clientIP)]
	stack.mu.RUnlock()

	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())
	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 1, 1480, true, make([]byte, 13)))

	st := waitForStat(t, stack, func(s Stats) bool { return s.MalformedDropped == 1 }, time.Second)
	if st.FragmentsDropped != 0 {
		t.Errorf("Stats().FragmentsDropped = %d, want 0 (bad geometry is malformed, not a reassembly drop)", st.FragmentsDropped)
	}

	a.reasm.mu.Lock()
	bufs := len(a.reasm.bufs)
	a.reasm.mu.Unlock()
	if bufs != 0 {
		t.Fatalf("a geometrically invalid fragment allocated %d buffers, want 0", bufs)
	}
}

// TestLoneFragmentTimesOut drives the lazy expiry sweep through the stack
// with a fake clock: a fragment nobody ever completes is discarded 30 s
// later, counted once per DATAGRAM, by whichever fragment happens to
// arrive next.
func TestLoneFragmentTimesOut(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	stack := newTestStack(t, WithClock(clock))
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())
	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 0x4444, 0, true, make([]byte, 16)))
	waitForStat(t, stack, func(s Stats) bool { return s.PacketsReceived == 1 }, time.Second)

	clock.Advance(31 * time.Second)

	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 0x5555, 0, true, make([]byte, 16)))
	st := waitForStat(t, stack, func(s Stats) bool { return s.ReassemblyTimeouts == 1 }, time.Second)
	if st.FragmentsDropped != 0 {
		t.Errorf("Stats().FragmentsDropped = %d, want 0 (a timeout is its own counter)", st.FragmentsDropped)
	}
}

// TestOutboundFragmentation is the outbound half: a 3000-byte UDP payload
// written at a 1500-byte MTU leaves as three correctly-offset,
// correctly-flagged, correctly-checksummed fragments sharing one
// identification — and a real reassembler puts them back together into the
// datagram the caller asked for. WriteTo still reports len(p): from the
// caller's perspective the whole datagram was accepted.
func TestOutboundFragmentation(t *testing.T) {
	stack := newTestStack(t, WithMTU(1500))
	defer stack.Close()

	conn, err := stack.ListenUDP(5060)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	n, err := conn.WriteTo(payload, &net.UDPAddr{IP: clientIP, Port: 40000})
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("WriteTo = %d, want %d (the whole datagram was accepted)", n, len(payload))
	}

	var frags [][]byte
	for i := 0; i < 3; i++ {
		frags = append(frags, waitForOutbound(t, fs, time.Second))
	}
	assertNoOutbound(t, fs, 50*time.Millisecond)

	wantOffsets := []int{0, 1480, 2960}
	var sharedID uint16
	var r reassembler
	var datagram []byte
	for i, frag := range frags {
		if len(frag) > stack.MTU() {
			t.Errorf("fragment %d is %d bytes, larger than the MTU %d", i, len(frag), stack.MTU())
		}
		hdr, err := parseIPv4(frag)
		if err != nil {
			t.Fatalf("parseIPv4(fragment %d): %v", i, err)
		}
		if hdr.fragOffset != wantOffsets[i] {
			t.Errorf("fragment %d offset = %d, want %d", i, hdr.fragOffset, wantOffsets[i])
		}
		if wantMF := i < 2; hdr.moreFragments != wantMF {
			t.Errorf("fragment %d MF = %v, want %v", i, hdr.moreFragments, wantMF)
		}
		if i == 0 {
			sharedID = hdr.id
			if sharedID == 0 {
				t.Error("outbound fragments carry identification 0; an identification must be assigned when fragmenting")
			}
		} else if hdr.id != sharedID {
			t.Errorf("fragment %d id = %#04x, want %#04x (all fragments of one datagram share it)", i, hdr.id, sharedID)
		}
		if cs := internetChecksum(frag[:hdr.ihl]); cs != 0 {
			t.Errorf("fragment %d header checksum does not fold to zero (got %#04x)", i, cs)
		}

		out, outcome, _ := r.add(time.Unix(0, 0), hdr, frag)
		if i < 2 && outcome != reasmBuffered {
			t.Fatalf("fragment %d outcome = %v, want reasmBuffered", i, outcome)
		}
		if i == 2 {
			if outcome != reasmComplete {
				t.Fatalf("final fragment outcome = %v, want reasmComplete", outcome)
			}
			datagram = out
		}
	}

	hdr, err := parseIPv4(datagram)
	if err != nil {
		t.Fatalf("parseIPv4(reassembled): %v", err)
	}
	srcPort, dstPort, data, err := parseUDP(datagram[hdr.payloadOff:hdr.totalLen])
	if err != nil {
		t.Fatalf("parseUDP(reassembled): %v", err)
	}
	if srcPort != 5060 || dstPort != 40000 {
		t.Errorf("reassembled ports = %d -> %d, want 5060 -> 40000", srcPort, dstPort)
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("the reassembled UDP payload is not the payload WriteTo was given")
	}

	if got := stack.Stats().OutboundFragmented; got != 1 {
		t.Fatalf("Stats().OutboundFragmented = %d, want 1 (counted per DATAGRAM, not per fragment)", got)
	}
}

// TestMTUOption asserts WithMTU's contract: a default of 1500, both ends
// of the valid range enforced by New (Option cannot return an error
// itself), and MTU() reporting what was configured.
func TestMTUOption(t *testing.T) {
	if got := newTestStack(t).MTU(); got != defaultMTU {
		t.Errorf("default MTU() = %d, want %d", got, defaultMTU)
	}

	s, err := New(testServerIP(), WithMTU(1000))
	if err != nil {
		t.Fatalf("New(WithMTU(1000)): %v", err)
	}
	if got := s.MTU(); got != 1000 {
		t.Errorf("MTU() = %d, want 1000", got)
	}

	for _, mtu := range []int{minMTU - 1, maxMTU + 1, 0, -1} {
		if _, err := New(testServerIP(), WithMTU(mtu)); !errors.Is(err, ErrInvalidMTU) {
			t.Errorf("New(WithMTU(%d)) = %v, want ErrInvalidMTU", mtu, err)
		}
	}

	// The boundaries themselves are valid.
	for _, mtu := range []int{minMTU, maxMTU} {
		if _, err := New(testServerIP(), WithMTU(mtu)); err != nil {
			t.Errorf("New(WithMTU(%d)) = %v, want success (the bounds are inclusive)", mtu, err)
		}
	}
}

// TestTCPMSSFollowsMTU: the SYN-ACK's advertised MSS is derived from the
// configured MTU (1000 - 20 IPv4 - 20 TCP = 960), which is what keeps TCP
// unfragmented BY CONSTRUCTION — a full-sized response at a sub-1500 MTU
// must produce no outbound fragmentation at all.
func TestTCPMSSFollowsMTU(t *testing.T) {
	stack := newTestStack(t, WithMTU(1000))
	defer stack.Close()

	ln, err := stack.ListenTCP(8080)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	defer ln.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	client := newTCPTestClient(t, fs, clientIP, 34567, testServerIP(), 8080)
	client.connect()

	if want := uint16(960); client.serverMSS != want {
		t.Fatalf("SYN-ACK MSS = %d, want %d (MTU 1000 - 20 IPv4 - 20 TCP)", client.serverMSS, want)
	}
	if got := stack.maxSegmentSize(); got != 960 {
		t.Fatalf("maxSegmentSize() = %d, want 960", got)
	}

	conn, err := acceptWithTimeout(t, ln, time.Second)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer conn.Close()

	response := bytes.Repeat([]byte{0x5A}, 8000)
	go func() {
		_, _ = conn.Write(response)
	}()

	got := client.recvData(len(response), 5*time.Second)
	if !bytes.Equal(got, response) {
		t.Fatal("the client did not receive the response bytes intact")
	}
	if n := stack.Stats().OutboundFragmented; n != 0 {
		t.Fatalf("Stats().OutboundFragmented = %d, want 0 — TCP segmented to the MTU-derived MSS must never need fragmenting", n)
	}
}

// TestDetachWithOpenReassemblyBuffer asserts T-FVA-05: tearing down a
// session with a half-filled reassembly buffer frees that state, never
// panics, and leaves a re-attach on the same IP starting clean.
func TestDetachWithOpenReassemblyBuffer(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	first := stack.routes[netstacktest.MustAddr(clientIP)]
	stack.mu.RUnlock()

	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())
	_, frags := icmpEchoFragments(t, client, server, 0x6666, 16, bytes.Repeat([]byte{0xCD}, 40))
	fs.Inject(frags[0])
	waitForStat(t, stack, func(s Stats) bool { return s.PacketsReceived == 1 }, time.Second)

	first.reasm.mu.Lock()
	held := len(first.reasm.bufs)
	first.reasm.mu.Unlock()
	if held != 1 {
		t.Fatalf("expected 1 half-filled reassembly buffer before detach, got %d", held)
	}

	if !stack.Detach(clientIP) {
		t.Fatal("Detach = false, want true")
	}

	first.reasm.mu.Lock()
	bufs, bytesHeld, closed := len(first.reasm.bufs), first.reasm.bytes, first.reasm.closed
	first.reasm.mu.Unlock()
	if bufs != 0 || bytesHeld != 0 || !closed {
		t.Fatalf("after detach: %d buffers, %d bytes, closed=%v — want 0/0/true", bufs, bytesHeld, closed)
	}

	// Detach runs through the same stopOnce as Close and
	// detachAttachment; calling it again must not panic.
	first.stop()

	// A re-attach on the same IP starts with empty reassembly state and
	// reassembles a fresh datagram normally.
	fs2 := netstacktest.NewFakeSession()
	if err := stack.Attach(fs2, clientIP); err != nil {
		t.Fatalf("re-Attach: %v", err)
	}
	stack.mu.RLock()
	second := stack.routes[netstacktest.MustAddr(clientIP)]
	stack.mu.RUnlock()
	if second == first {
		t.Fatal("re-Attach reused the detached attachment")
	}
	second.reasm.mu.Lock()
	bufs, closed = len(second.reasm.bufs), second.reasm.closed
	second.reasm.mu.Unlock()
	if bufs != 0 || closed {
		t.Fatalf("a re-attached session started with %d buffers, closed=%v — want 0/false", bufs, closed)
	}

	for _, frag := range frags {
		fs2.Inject(frag)
	}
	reply := waitForOutbound(t, fs2, time.Second)
	hdr, err := parseIPv4(reply)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	if reply[hdr.payloadOff] != icmpTypeEchoReply {
		t.Fatal("the re-attached session did not get an echo reply for a freshly fragmented request")
	}
}

func TestOutboundSourceIPFailClosed(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	stack.mu.RLock()
	a := stack.routes[netstacktest.MustAddr(ip)]
	stack.mu.RUnlock()

	badICMP := []byte{icmpTypeEchoReply, 0, 0, 0, 0, 0, 0, 0}
	badICMP[2], badICMP[3] = 0, 0
	binaryPutChecksum(badICMP)
	// Source == client IP, not the server's own tunnel IP: this must never
	// reach the wire (D-04).
	badPkt := buildIPv4(nil, netstacktest.MustAddr(ip), netstacktest.MustAddr(ip), protocolICMP, badICMP)

	err := stack.writePacket(a, badPkt)
	if !errors.Is(err, ErrOutboundSourceMismatch) {
		t.Fatalf("writePacket(wrong source) = %v, want ErrOutboundSourceMismatch", err)
	}

	select {
	case <-fs.Outbound():
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

	fs := netstacktest.NewFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	udpPkt := buildIPv4(nil, netstacktest.MustAddr(ip), netstacktest.MustAddr(testServerIP()), protocolUDP, []byte("hello"))
	fs.Inject(udpPkt)
	assertNoOutbound(t, fs, 50*time.Millisecond)
	if got := stack.Stats().UnhandledProtocolDropped; got != 1 {
		t.Fatalf("Stats().UnhandledProtocolDropped = %d, want 1 after a UDP packet with no registered handler", got)
	}

	tcpPkt := buildIPv4(nil, netstacktest.MustAddr(ip), netstacktest.MustAddr(testServerIP()), protocolTCP, []byte("hello"))
	fs.Inject(tcpPkt)
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

// TestWithReassemblyLimitsValidation asserts New rejects any negative
// ReassemblyLimits field with ErrInvalidReassemblyLimits (Option cannot
// return an error itself, mirroring WithMTU's own New-time validation),
// and accepts the zero value and legitimate positive values.
func TestWithReassemblyLimitsValidation(t *testing.T) {
	bad := []ReassemblyLimits{
		{MaxDatagramsPerAttachment: -1},
		{MaxBytesPerAttachment: -1},
		{Timeout: -time.Second},
	}
	for _, l := range bad {
		if _, err := New(testServerIP(), WithReassemblyLimits(l)); !errors.Is(err, ErrInvalidReassemblyLimits) {
			t.Errorf("New(WithReassemblyLimits(%+v)) = %v, want ErrInvalidReassemblyLimits", l, err)
		}
	}

	if _, err := New(testServerIP(), WithReassemblyLimits(ReassemblyLimits{})); err != nil {
		t.Errorf("New(WithReassemblyLimits(zero value)) = %v, want success", err)
	}
	if _, err := New(testServerIP(), WithReassemblyLimits(ReassemblyLimits{
		MaxDatagramsPerAttachment: 2,
		MaxBytesPerAttachment:     1024,
		Timeout:                   time.Second,
	})); err != nil {
		t.Errorf("New(WithReassemblyLimits(positive values)) = %v, want success", err)
	}
}

// TestWithReassemblyLimitsBufferBound is a Stack-level end-to-end check of
// WithReassemblyLimits' MaxDatagramsPerAttachment: with a limit of 2, a
// third concurrent half-reassembled datagram on one attachment is
// refused, counted in Stats().ReassemblyBoundExceeded, while a
// default-limit stack accepts 16 (asserted at the reassembler layer by
// TestReassemblyCustomBufferLimit in reassembly_test.go; this test proves
// the option actually reaches the attachment).
func TestWithReassemblyLimitsBufferBound(t *testing.T) {
	stack := newTestStack(t, WithReassemblyLimits(ReassemblyLimits{MaxDatagramsPerAttachment: 2}))
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())

	for i := 0; i < 2; i++ {
		fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, uint16(i), 0, true, make([]byte, 16)))
	}
	waitForStat(t, stack, func(s Stats) bool { return s.PacketsReceived == 2 }, time.Second)

	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 2, 0, true, make([]byte, 16)))
	st := waitForStat(t, stack, func(s Stats) bool { return s.ReassemblyBoundExceeded == 1 }, time.Second)
	if st.PacketsReceived != 3 {
		t.Fatalf("Stats().PacketsReceived = %d, want 3", st.PacketsReceived)
	}
}

// TestWithReassemblyLimitsTimeout is a Stack-level end-to-end check of
// WithReassemblyLimits' Timeout: a buffer older than the configured
// (shortened) timeout is swept by the next fragment, driven by fakeClock.
func TestWithReassemblyLimitsTimeout(t *testing.T) {
	clock := newFakeClock(time.Unix(1000, 0))
	shortTimeout := 5 * time.Second
	stack := newTestStack(t, WithClock(clock), WithReassemblyLimits(ReassemblyLimits{Timeout: shortTimeout}))
	defer stack.Close()

	fs := netstacktest.NewFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	client, server := netstacktest.MustAddr(clientIP), netstacktest.MustAddr(testServerIP())

	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 0x6666, 0, true, make([]byte, 16)))
	waitForStat(t, stack, func(s Stats) bool { return s.PacketsReceived == 1 }, time.Second)

	// Past the CUSTOM (short) timeout but well inside the default 30s
	// reassemblyTimeout: proves the shortened timeout, not the package
	// default, is what this attachment enforces.
	clock.Advance(shortTimeout + time.Second)

	fs.Inject(netstacktest.BuildFragment(client, server, protocolUDP, 0x7777, 0, true, make([]byte, 16)))
	waitForStat(t, stack, func(s Stats) bool { return s.ReassemblyTimeouts == 1 }, time.Second)
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

// TestIsAttached covers Stack.IsAttached: true for an attached IP, false
// after Detach, false for the server's own tunnel IP, and false (never a
// panic) for a nil, IPv6, or otherwise malformed argument.
func TestIsAttached(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	ip := net.IPv4(10, 8, 0, 2).To4()
	if stack.IsAttached(ip) {
		t.Fatal("IsAttached = true before Attach, want false")
	}

	fs := netstacktest.NewFakeSession()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if !stack.IsAttached(ip) {
		t.Fatal("IsAttached = false right after Attach, want true")
	}

	if stack.IsAttached(testServerIP()) {
		t.Fatal("IsAttached(server IP) = true, want false")
	}

	if stack.IsAttached(nil) {
		t.Fatal("IsAttached(nil) = true, want false")
	}
	if stack.IsAttached(net.ParseIP("::1")) {
		t.Fatal("IsAttached(IPv6) = true, want false")
	}
	if stack.IsAttached(net.IP{1, 2, 3}) {
		t.Fatal("IsAttached(malformed) = true, want false")
	}

	if !stack.Detach(ip) {
		t.Fatal("Detach = false, want true")
	}
	if stack.IsAttached(ip) {
		t.Fatal("IsAttached = true after Detach, want false")
	}
}

// TestRoutes covers Stack.Routes: empty-stack zero-length result, ascending
// sort order regardless of attach order, and that mutating a returned
// net.IP does not change what a later Routes()/IsAttached call reports
// (the defensive-copy guarantee).
func TestRoutes(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	routes := stack.Routes()
	if len(routes) != 0 {
		t.Fatalf("Routes() on an empty stack = %v, want zero-length", routes)
	}

	ip3 := net.IPv4(10, 8, 0, 4).To4()
	ip1 := net.IPv4(10, 8, 0, 2).To4()
	ip2 := net.IPv4(10, 8, 0, 3).To4()

	// Attach out of order to prove Routes() sorts rather than returning
	// attachment order.
	for _, ip := range []net.IP{ip3, ip1, ip2} {
		if err := stack.Attach(netstacktest.NewFakeSession(), ip); err != nil {
			t.Fatalf("Attach(%v): %v", ip, err)
		}
	}

	routes = stack.Routes()
	if len(routes) != 3 {
		t.Fatalf("Routes() = %v, want 3 entries", routes)
	}
	want := []net.IP{ip1, ip2, ip3}
	for i, ip := range want {
		if !routes[i].Equal(ip) {
			t.Fatalf("Routes()[%d] = %v, want %v (ascending order)", i, routes[i], ip)
		}
	}

	// Defensive-copy guarantee: mutating an element of the returned slice
	// must not be observable in a later Routes() or IsAttached call.
	routes[0][0] = 0xFF
	if !stack.IsAttached(ip1) {
		t.Fatal("IsAttached(ip1) = false after mutating a previously returned Routes() element, want true (mutation must not reach stack state)")
	}
	routesAgain := stack.Routes()
	if !routesAgain[0].Equal(ip1) {
		t.Fatalf("Routes()[0] after mutating a prior result = %v, want unaffected %v", routesAgain[0], ip1)
	}

	if !stack.Detach(ip2) {
		t.Fatal("Detach(ip2) = false, want true")
	}
	routes = stack.Routes()
	if len(routes) != 2 {
		t.Fatalf("Routes() after Detach = %v, want 2 entries", routes)
	}
	for _, ip := range routes {
		if ip.Equal(ip2) {
			t.Fatalf("Routes() after Detach(ip2) still contains ip2: %v", routes)
		}
	}
}
