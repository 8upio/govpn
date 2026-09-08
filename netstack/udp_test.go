package netstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// buildUDPIPv4 builds a complete, checksummed IPv4+UDP datagram from src to
// dst with the given ports and payload — mirrors fakesession_test.go's
// buildICMPEchoRequest, so tests read as intent, not hand-assembled bytes.
func buildUDPIPv4(src, dst netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udpSegment := buildUDP(nil, src, dst, srcPort, dstPort, payload)
	return buildIPv4(nil, src, dst, protocolUDP, udpSegment)
}

// TestUDPRoundTrip is Task 1's tracer slice: a datagram from an attached
// fake session reaches ListenUDP's conn, and a reply written back through
// it reaches that session as a correctly-addressed, correctly-checksummed
// IPv4+UDP packet.
func TestUDPRoundTrip(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(9999)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello from client")
	pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 5000, 9999, payload)
	fs.inbound <- pkt

	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("ReadFrom payload = %q, want %q", buf[:n], payload)
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("ReadFrom addr type = %T, want *net.UDPAddr", addr)
	}
	if !udpAddr.IP.Equal(clientIP) || udpAddr.Port != 5000 {
		t.Fatalf("ReadFrom addr = %v, want %s:5000", udpAddr, clientIP)
	}

	reply := []byte("hello from server")
	if _, err := conn.WriteTo(reply, udpAddr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	out := waitForOutbound(t, fs, time.Second)
	hdr, err := parseIPv4(out)
	if err != nil {
		t.Fatalf("parseIPv4(reply): %v", err)
	}
	if hdr.src != mustAddr(testServerIP()) {
		t.Errorf("reply IPv4 source = %v, want server IP", hdr.src)
	}
	if hdr.dst != mustAddr(clientIP) {
		t.Errorf("reply IPv4 destination = %v, want client IP", hdr.dst)
	}
	if hdr.protocol != protocolUDP {
		t.Errorf("reply IPv4 protocol = %d, want %d (UDP)", hdr.protocol, protocolUDP)
	}
	udpPayload := out[hdr.payloadOff:hdr.totalLen]
	srcPort, dstPort, data, err := parseUDP(udpPayload)
	if err != nil {
		t.Fatalf("parseUDP(reply): %v", err)
	}
	if srcPort != 9999 {
		t.Errorf("reply UDP source port = %d, want 9999", srcPort)
	}
	if dstPort != 5000 {
		t.Errorf("reply UDP destination port = %d, want 5000", dstPort)
	}
	if string(data) != string(reply) {
		t.Errorf("reply UDP payload = %q, want %q", data, reply)
	}
}

// TestUDPConnSatisfiesPacketConn proves ListenUDP's result works through a
// parameter typed exactly net.PacketConn — unmodified, socket-shaped code,
// not merely a *udpConn used directly. The compile-time assertion
// (var _ net.PacketConn = (*udpConn)(nil)) lives in udp.go itself.
func TestUDPConnSatisfiesPacketConn(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	conn, err := stack.ListenUDP(9998)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	roundTripThroughPacketConn(t, conn, fs, clientIP)
}

// roundTripThroughPacketConn's parameter type is net.PacketConn, not
// *udpConn — this is the whole point of the test above.
func roundTripThroughPacketConn(t *testing.T, pc net.PacketConn, fs *fakeSession, clientIP net.IP) {
	t.Helper()
	payload := []byte("via net.PacketConn")
	pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 4000, 9998, payload)
	fs.inbound <- pkt

	buf := make([]byte, 2048)
	if err := pc.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, addr, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}
	if _, err := pc.WriteTo([]byte("ack"), addr); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	waitForOutbound(t, fs, time.Second)
}

// TestUDPChecksumIsPseudoHeaderCorrect re-verifies the pseudo-header
// checksum two ways: folding a re-computation to zero, and comparing
// against a literal expected value for one fixed datagram, so a
// transposed src/dst or a missing zero byte in the pseudo-header fails.
func TestUDPChecksumIsPseudoHeaderCorrect(t *testing.T) {
	src := mustAddr(net.IPv4(10, 8, 0, 1).To4())
	dst := mustAddr(net.IPv4(10, 8, 0, 2).To4())
	payload := []byte("fixed datagram payload")

	datagram := buildUDP(nil, src, dst, 1234, 5678, payload)

	// Literal, independently computed for exactly this
	// src/dst/ports/payload — a transposed src/dst or a missing
	// pseudo-header zero byte would change this value.
	const wantChecksum = 0x9c50
	if got := binary.BigEndian.Uint16(datagram[6:8]); got != wantChecksum {
		t.Fatalf("checksum = %#04x, want literal %#04x", got, wantChecksum)
	}

	// Re-verification: folding the pseudo-header sum together with the
	// transmitted UDP header (checksum field as sent) and payload must
	// fold to zero — the classic Internet-checksum self-verification
	// identity.
	if folded := transportChecksum(src, dst, protocolUDP, datagram); folded != 0 {
		t.Fatalf("checksum re-verification did not fold to zero: got %#04x", folded)
	}
}

// TestUDPComputedZeroChecksumTransmittedAsAllOnes picks a payload whose
// raw computed checksum is 0x0000 and asserts buildUDP transmits 0xFFFF
// instead (RFC 768).
func TestUDPComputedZeroChecksumTransmittedAsAllOnes(t *testing.T) {
	src := mustAddr(net.IPv4(10, 8, 0, 1).To4())
	dst := mustAddr(net.IPv4(10, 8, 0, 2).To4())
	payload := []byte{0xDE, 0xC2} // chosen so the raw computed checksum is 0

	datagram := buildUDP(nil, src, dst, 1111, 2222, payload)
	if got := binary.BigEndian.Uint16(datagram[6:8]); got != 0xFFFF {
		t.Fatalf("checksum = %#04x, want 0xFFFF (RFC 768: a computed 0x0000 is transmitted as all-ones)", got)
	}
}

// TestUDPInboundZeroChecksumAccepted asserts the receive-side half of RFC
// 768's special rule: an on-wire 0x0000 is accepted without verification,
// while a non-zero, wrong checksum is dropped and counted.
func TestUDPInboundZeroChecksumAccepted(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	conn, err := stack.ListenUDP(7000)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	payload := []byte("no checksum here")
	pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 4321, 7000, payload)
	hdr, err := parseIPv4(pkt)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	// Zero the checksum field even though it does not actually verify —
	// RFC 768: an on-wire 0x0000 means "sender computed no checksum" and
	// must be accepted without verification.
	pkt[hdr.payloadOff+6] = 0
	pkt[hdr.payloadOff+7] = 0
	fs.inbound <- pkt

	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}

	demux := stack.udpHandler.(*udpDemux)
	before := demux.badChecksumDropped.Load()

	pkt2 := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 4321, 7000, payload)
	hdr2, err := parseIPv4(pkt2)
	if err != nil {
		t.Fatalf("parseIPv4: %v", err)
	}
	// A non-zero, wrong checksum.
	pkt2[hdr2.payloadOff+6] = 0x12
	pkt2[hdr2.payloadOff+7] = 0x34
	fs.inbound <- pkt2

	if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom delivered a datagram with a wrong non-zero checksum")
	}
	if after := demux.badChecksumDropped.Load(); after != before+1 {
		t.Fatalf("badChecksumDropped = %d, want %d", after, before+1)
	}
}

// TestUDPLocalAddr asserts LocalAddr's shape: the server tunnel IP and the
// listening port, with Network() reporting "udp".
func TestUDPLocalAddr(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(8080)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	addr := conn.LocalAddr()
	if addr.Network() != "udp" {
		t.Errorf("Network() = %q, want %q", addr.Network(), "udp")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr() type = %T, want *net.UDPAddr", addr)
	}
	if !udpAddr.IP.Equal(testServerIP()) || udpAddr.Port != 8080 {
		t.Fatalf("LocalAddr() = %v, want %s:8080", udpAddr, testServerIP())
	}
}

// TestUDPParseNeverPanics drives parseUDP with every prefix length 0-7 of a
// valid datagram, a too-small length field, and an oversized length field —
// all must return a typed error and never panic.
func TestUDPParseNeverPanics(t *testing.T) {
	full := buildUDP(nil, mustAddr(net.IPv4(10, 8, 0, 1).To4()), mustAddr(net.IPv4(10, 8, 0, 2).To4()), 1000, 2000, []byte("payload data"))

	for i := 0; i <= 7; i++ {
		prefix := full[:i]
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseUDP panicked on a %d-byte prefix: %v", i, r)
				}
			}()
			if _, _, _, err := parseUDP(prefix); err == nil {
				t.Fatalf("parseUDP(%d-byte prefix) = nil error, want a typed error", i)
			}
		}()
	}

	tooSmallLength := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(tooSmallLength[4:6], 4)
	if _, _, _, err := parseUDP(tooSmallLength); err == nil {
		t.Fatal("parseUDP with length field < udpHeaderLen = nil error, want a typed error")
	}

	tooLargeLength := append([]byte(nil), full...)
	binary.BigEndian.PutUint16(tooLargeLength[4:6], uint16(len(full)+100))
	if _, _, _, err := parseUDP(tooLargeLength); err == nil {
		t.Fatal("parseUDP with an oversized length field = nil error, want a typed error")
	}
}

// TestUDPArbitraryRuntimePorts opens listeners on several ports at runtime,
// after the stack is already serving traffic, and asserts each receives
// only datagrams addressed to its own port.
func TestUDPArbitraryRuntimePorts(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	ports := []uint16{1, 5060, 30000, 65535}
	conns := make(map[uint16]net.PacketConn)
	for _, p := range ports {
		conn, err := stack.ListenUDP(p)
		if err != nil {
			t.Fatalf("ListenUDP(%d): %v", p, err)
		}
		conns[p] = conn
		defer conn.Close()
	}

	buf := make([]byte, 2048)
	for _, p := range ports {
		payload := []byte(fmt.Sprintf("to port %d", p))
		pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 9000, p, payload)
		fs.inbound <- pkt

		if err := conns[p].SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, _, err := conns[p].ReadFrom(buf)
		if err != nil {
			t.Fatalf("port %d ReadFrom: %v", p, err)
		}
		if string(buf[:n]) != string(payload) {
			t.Fatalf("port %d payload = %q, want %q", p, buf[:n], payload)
		}

		for _, other := range ports {
			if other == p {
				continue
			}
			if err := conns[other].SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			if _, _, err := conns[other].ReadFrom(buf); err == nil {
				t.Fatalf("port %d received a datagram addressed to port %d", other, p)
			}
		}
	}
}

// TestUDPPortInUse asserts the full port-lifecycle contract: a second
// ListenUDP on a bound port fails without disturbing the first listener;
// after Close, the same port is rebindable.
func TestUDPPortInUse(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn1, err := stack.ListenUDP(4444)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	if _, err := stack.ListenUDP(4444); !errors.Is(err, ErrUDPPortInUse) {
		t.Fatalf("second ListenUDP(4444) = %v, want ErrUDPPortInUse", err)
	}

	payload := []byte("still alive")
	pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 1000, 4444, payload)
	fs.inbound <- pkt
	buf := make([]byte, 2048)
	if err := conn1.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n, _, err := conn1.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("payload = %q, want %q", buf[:n], payload)
	}

	if err := conn1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	conn2, err := stack.ListenUDP(4444)
	if err != nil {
		t.Fatalf("ListenUDP(4444) after close = %v, want nil", err)
	}
	defer conn2.Close()

	pkt2 := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 1001, 4444, payload)
	fs.inbound <- pkt2
	if err := conn2.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	n2, _, err := conn2.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom on rebind: %v", err)
	}
	if string(buf[:n2]) != string(payload) {
		t.Fatalf("rebind payload = %q, want %q", buf[:n2], payload)
	}
}

func TestUDPPortZeroRejected(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	if _, err := stack.ListenUDP(0); !errors.Is(err, ErrUDPPortZero) {
		t.Fatalf("ListenUDP(0) = %v, want ErrUDPPortZero", err)
	}
}

// TestUDPNoListenerDropped asserts a datagram to an unbound port produces
// no outbound packet, no panic, and increments the no-listener counter.
func TestUDPNoListenerDropped(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	dummy, err := stack.ListenUDP(1)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer dummy.Close()

	demux := stack.udpHandler.(*udpDemux)
	before := demux.noListenerDropped.Load()

	pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), 1000, 9, []byte("nobody home"))
	fs.inbound <- pkt
	assertNoOutbound(t, fs, 50*time.Millisecond)

	if after := demux.noListenerDropped.Load(); after != before+1 {
		t.Fatalf("noListenerDropped = %d, want %d", after, before+1)
	}
}

// TestUDPMultiSessionRouting attaches three sessions to one shared
// listener and proves no cross-session delivery in either direction.
func TestUDPMultiSessionRouting(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fsA := newFakeSession()
	fsB := newFakeSession()
	fsC := newFakeSession()
	ipA := net.IPv4(10, 8, 0, 2).To4()
	ipB := net.IPv4(10, 8, 0, 3).To4()
	ipC := net.IPv4(10, 8, 0, 4).To4()
	if err := stack.Attach(fsA, ipA); err != nil {
		t.Fatalf("Attach A: %v", err)
	}
	if err := stack.Attach(fsB, ipB); err != nil {
		t.Fatalf("Attach B: %v", err)
	}
	if err := stack.Attach(fsC, ipC); err != nil {
		t.Fatalf("Attach C: %v", err)
	}

	conn, err := stack.ListenUDP(6000)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	sessions := []struct {
		fs   *fakeSession
		ip   net.IP
		port uint16
	}{
		{fsA, ipA, 3001},
		{fsB, ipB, 3002},
		{fsC, ipC, 3003},
	}

	buf := make([]byte, 2048)
	for _, s := range sessions {
		payload := []byte(fmt.Sprintf("from %s", s.ip))
		pkt := buildUDPIPv4(mustAddr(s.ip), mustAddr(testServerIP()), s.port, 6000, payload)
		s.fs.inbound <- pkt

		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom for %s: %v", s.ip, err)
		}
		if string(buf[:n]) != string(payload) {
			t.Fatalf("payload for %s = %q, want %q", s.ip, buf[:n], payload)
		}
		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok || !udpAddr.IP.Equal(s.ip) || udpAddr.Port != int(s.port) {
			t.Fatalf("addr for %s = %v, want %s:%d", s.ip, addr, s.ip, s.port)
		}

		reply := []byte("reply to " + s.ip.String())
		if _, err := conn.WriteTo(reply, udpAddr); err != nil {
			t.Fatalf("WriteTo for %s: %v", s.ip, err)
		}
		out := waitForOutbound(t, s.fs, time.Second)
		hdr, err := parseIPv4(out)
		if err != nil {
			t.Fatalf("parseIPv4: %v", err)
		}
		if hdr.dst != mustAddr(s.ip) {
			t.Fatalf("reply destination = %v, want %v", hdr.dst, mustAddr(s.ip))
		}

		for _, other := range sessions {
			if other.ip.Equal(s.ip) {
				continue
			}
			assertNoOutbound(t, other.fs, 20*time.Millisecond)
		}
	}
}

func TestUDPWriteToUnknownPeer(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(7777)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	addr := &net.UDPAddr{IP: net.IPv4(10, 8, 0, 9).To4(), Port: 1234}
	if _, err := conn.WriteTo([]byte("hi"), addr); !errors.Is(err, ErrUDPNoRoute) {
		t.Fatalf("WriteTo(unattached) = %v, want ErrUDPNoRoute", err)
	}
}

func TestUDPWriteAfterDetach(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(8888)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if !stack.Detach(ip) {
		t.Fatal("Detach = false, want true")
	}

	addr := &net.UDPAddr{IP: ip, Port: 4000}
	if _, err := conn.WriteTo([]byte("hi"), addr); !errors.Is(err, ErrUDPNoRoute) {
		t.Fatalf("WriteTo(detached) = %v, want ErrUDPNoRoute", err)
	}

	pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), 4000, 8888, []byte("post-detach"))
	fs.inbound <- pkt
	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom delivered a datagram fed after Detach")
	}
}

// TestUDPSpoofedSourceNotDelivered asserts the "one session cannot inject
// into another session's flows" property at the UDP layer: the drop
// happens in Stack.deliver's access control, before any UDP dispatch.
func TestUDPSpoofedSourceNotDelivered(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(5555)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	otherIP := net.IPv4(10, 8, 0, 3).To4()
	pkt := buildUDPIPv4(mustAddr(otherIP), mustAddr(testServerIP()), 1000, 5555, []byte("spoofed"))
	fs.inbound <- pkt

	if err := conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 2048)
	if _, _, err := conn.ReadFrom(buf); err == nil {
		t.Fatal("ReadFrom delivered a spoofed-source datagram")
	}

	if got := stack.Stats().SpoofedSourceDropped; got != 1 {
		t.Fatalf("Stats().SpoofedSourceDropped = %d, want 1", got)
	}
}

// TestUDPQueueOverflowDropsNewest fills a listener's queue past its depth
// without reading, and proves (a) the stack's read loop is never blocked —
// an ICMP echo request sent afterward is still answered promptly — and (b)
// the earlier queued datagrams remain readable, in order.
func TestUDPQueueOverflowDropsNewest(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(9090)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	total := udpQueueDepth + 20
	for i := 0; i < total; i++ {
		payload := []byte{byte(i)}
		pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), uint16(2000+i), 9090, payload)
		fs.inbound <- pkt
	}

	req := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, []byte("still alive"))
	fs.inbound <- req
	waitForOutbound(t, fs, time.Second)

	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for i := 0; i < udpQueueDepth; i++ {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom(%d): %v", i, err)
		}
		if n != 1 || buf[0] != byte(i) {
			t.Fatalf("ReadFrom(%d) = %v, want [%d] (in-order delivery of the earlier queued datagrams)", i, buf[:n], byte(i))
		}
	}
}

func TestUDPReadDeadlineTimesOut(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(10001)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	buf := make([]byte, 64)
	_, _, err = conn.ReadFrom(buf)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ReadFrom on an idle conn with a short deadline returned nil error")
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("ReadFrom deadline error = %v, want a net.Error with Timeout() == true", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom deadline error = %v, want errors.Is(err, os.ErrDeadlineExceeded)", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("ReadFrom took %v to time out, want roughly 20ms", elapsed)
	}
}

func TestUDPDeadlineInThePast(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(10002)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), 3000, 10002, []byte("queued"))
	fs.inbound <- pkt
	time.Sleep(20 * time.Millisecond)

	if err := conn.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, _, err := conn.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom(past deadline) = %v, want os.ErrDeadlineExceeded", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(zero): %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom after clearing the deadline: %v", err)
	}
	if string(buf[:n]) != "queued" {
		t.Fatalf("payload = %q, want %q", buf[:n], "queued")
	}
}

func TestUDPDeadlineCleared(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(10003)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 64)
	if _, _, err := conn.ReadFrom(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadFrom before clearing = %v, want os.ErrDeadlineExceeded", err)
	}

	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline(zero): %v", err)
	}

	pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), 3001, 10003, []byte("after clear"))
	fs.inbound <- pkt

	done := make(chan struct{})
	go func() {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Errorf("ReadFrom after clearing deadline: %v", err)
		} else if string(buf[:n]) != "after clear" {
			t.Errorf("payload = %q, want %q", buf[:n], "after clear")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ReadFrom did not return a normally delivered datagram after the deadline was cleared")
	}
}

func TestUDPDeadlineSetFromAnotherGoroutine(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(10004)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := conn.ReadFrom(buf)
		readDone <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	select {
	case err := <-readDone:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("ReadFrom returned %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SetReadDeadline from another goroutine did not unblock the blocked ReadFrom")
	}
}

func TestUDPWriteDeadline(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(10005)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := conn.WriteTo([]byte("hi"), &net.UDPAddr{IP: ip, Port: 4000}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("WriteTo(past write deadline) = %v, want os.ErrDeadlineExceeded", err)
	}
	assertNoOutbound(t, fs, 50*time.Millisecond)
}

func TestUDPCloseUnblocksReader(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	conn, err := stack.ListenUDP(10006)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		_, _, err := conn.ReadFrom(buf)
		readDone <- err
	}()

	time.Sleep(20 * time.Millisecond)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case err := <-readDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the blocked ReadFrom")
	}

	if err := conn.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}

	buf := make([]byte, 64)
	if _, _, err := conn.ReadFrom(buf); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("ReadFrom after Close = %v, want net.ErrClosed", err)
	}
	if _, err := conn.WriteTo([]byte("x"), &net.UDPAddr{IP: net.IPv4(10, 8, 0, 2).To4(), Port: 1}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("WriteTo after Close = %v, want net.ErrClosed", err)
	}
}

// TestUDPConcurrentReadFromAndWriteTo drives 8 WriteTo goroutines and 2
// ReadFrom goroutines concurrently — the stdlib contract that multiple
// goroutines may invoke net.PacketConn methods simultaneously. The race
// detector is the load-bearing assertion here.
func TestUDPConcurrentReadFromAndWriteTo(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	clientIP := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, clientIP); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDP(10007)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()

	const iterations = 200

	// Drain the fake session's outbound channel continuously so the 8
	// WriteTo goroutines below never block on it.
	go func() {
		for range fs.outbound {
		}
	}()

	// Feed `iterations` distinct inbound datagrams so the 2 ReadFrom
	// goroutines below have something to race over.
	go func() {
		for i := 0; i < iterations; i++ {
			payload := []byte{byte(i)}
			pkt := buildUDPIPv4(mustAddr(clientIP), mustAddr(testServerIP()), uint16(20000+i), 10007, payload)
			fs.inbound <- pkt
		}
	}()

	var readCount atomic.Int64
	stopReading := make(chan struct{})
	var readWg sync.WaitGroup
	for r := 0; r < 2; r++ {
		readWg.Add(1)
		go func() {
			defer readWg.Done()
			buf := make([]byte, 64)
			for {
				select {
				case <-stopReading:
					return
				default:
				}
				if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					return
				}
				if _, _, err := conn.ReadFrom(buf); err == nil {
					readCount.Add(1)
				}
			}
		}()
	}

	var writeWg sync.WaitGroup
	for w := 0; w < 8; w++ {
		writeWg.Add(1)
		go func(id int) {
			defer writeWg.Done()
			addr := &net.UDPAddr{IP: clientIP, Port: 30000 + id}
			for i := 0; i < iterations; i++ {
				_, _ = conn.WriteTo([]byte{byte(id), byte(i)}, addr)
			}
		}(w)
	}

	writeWg.Wait()
	time.Sleep(300 * time.Millisecond)
	close(stopReading)
	readWg.Wait()

	if readCount.Load() == 0 {
		t.Fatal("no datagrams were ever read concurrently")
	}
}

// TestListenUDPOptionsValidation asserts ListenUDPOptions' own validation:
// a negative QueueDepth is ErrInvalidUDPQueueDepth, an out-of-range
// DropPolicy is ErrInvalidUDPDropPolicy, and port 0 is still
// ErrUDPPortZero regardless of opts.
func TestListenUDPOptionsValidation(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	if _, err := stack.ListenUDPOptions(9200, UDPOptions{QueueDepth: -1}); !errors.Is(err, ErrInvalidUDPQueueDepth) {
		t.Fatalf("ListenUDPOptions(QueueDepth: -1) = %v, want ErrInvalidUDPQueueDepth", err)
	}
	if _, err := stack.ListenUDPOptions(9200, UDPOptions{DropPolicy: UDPDropPolicy(99)}); !errors.Is(err, ErrInvalidUDPDropPolicy) {
		t.Fatalf("ListenUDPOptions(DropPolicy: 99) = %v, want ErrInvalidUDPDropPolicy", err)
	}
	if _, err := stack.ListenUDPOptions(0, UDPOptions{}); !errors.Is(err, ErrUDPPortZero) {
		t.Fatalf("ListenUDPOptions(0, ...) = %v, want ErrUDPPortZero", err)
	}

	conn, err := stack.ListenUDPOptions(9201, UDPOptions{QueueDepth: 4, DropPolicy: UDPDropOldest})
	if err != nil {
		t.Fatalf("ListenUDPOptions(valid options): %v", err)
	}
	defer conn.Close()
}

// TestUDPDropOldestKeepsNewest asserts UDPDropOldest's ordering contract:
// with a queue depth of 2, four datagrams sent before any ReadFrom leave
// the two NEWEST surviving, in order.
func TestUDPDropOldestKeepsNewest(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	conn, err := stack.ListenUDPOptions(9210, UDPOptions{QueueDepth: 2, DropPolicy: UDPDropOldest})
	if err != nil {
		t.Fatalf("ListenUDPOptions: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 4; i++ {
		payload := []byte{byte(i)}
		pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), uint16(3000+i), 9210, payload)
		fs.inbound <- pkt
	}

	// Barrier: the stack's single read loop processes fs.inbound strictly
	// in order, so waiting for this ICMP reply proves every UDP datagram
	// sent above has already been offered to the demux.
	req := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, []byte("still alive"))
	fs.inbound <- req
	waitForOutbound(t, fs, time.Second)

	buf := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for i, want := range []byte{2, 3} {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom(%d): %v", i, err)
		}
		if n != 1 || buf[0] != want {
			t.Fatalf("ReadFrom(%d) = %v, want [%d] (the two newest datagrams, in order)", i, buf[:n], want)
		}
	}

	if got := stack.UDPStats().QueueFullDropped; got != 2 {
		t.Fatalf("UDPStats().QueueFullDropped = %d, want 2", got)
	}
}

// TestUDPDropNewestKeepsOldestUnchanged asserts the existing default is
// unchanged: both an explicit UDPDropNewest and the zero-value UDPOptions
// keep the two OLDEST datagrams when a queue of depth 2 receives four.
func TestUDPDropNewestKeepsOldestUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts UDPOptions
	}{
		{"explicit UDPDropNewest", UDPOptions{QueueDepth: 2, DropPolicy: UDPDropNewest}},
		{"zero-value UDPOptions", UDPOptions{QueueDepth: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack := newTestStack(t)
			defer stack.Close()

			fs := newFakeSession()
			ip := net.IPv4(10, 8, 0, 2).To4()
			if err := stack.Attach(fs, ip); err != nil {
				t.Fatalf("Attach: %v", err)
			}

			conn, err := stack.ListenUDPOptions(9211, tc.opts)
			if err != nil {
				t.Fatalf("ListenUDPOptions: %v", err)
			}
			defer conn.Close()

			for i := 0; i < 4; i++ {
				payload := []byte{byte(i)}
				pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), uint16(3100+i), 9211, payload)
				fs.inbound <- pkt
			}

			req := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, []byte("still alive"))
			fs.inbound <- req
			waitForOutbound(t, fs, time.Second)

			buf := make([]byte, 2048)
			if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			for i, want := range []byte{0, 1} {
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					t.Fatalf("ReadFrom(%d): %v", i, err)
				}
				if n != 1 || buf[0] != want {
					t.Fatalf("ReadFrom(%d) = %v, want [%d] (the two oldest datagrams, in order)", i, buf[:n], want)
				}
			}
		})
	}
}

// TestUDPStatsQueueFullCountsBothPolicies asserts QueueFullDropped counts
// one per dropped datagram under EITHER drop policy.
func TestUDPStatsQueueFullCountsBothPolicies(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy UDPDropPolicy
	}{
		{"UDPDropNewest", UDPDropNewest},
		{"UDPDropOldest", UDPDropOldest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stack := newTestStack(t)
			defer stack.Close()

			fs := newFakeSession()
			ip := net.IPv4(10, 8, 0, 2).To4()
			if err := stack.Attach(fs, ip); err != nil {
				t.Fatalf("Attach: %v", err)
			}

			conn, err := stack.ListenUDPOptions(9220, UDPOptions{QueueDepth: 2, DropPolicy: tc.policy})
			if err != nil {
				t.Fatalf("ListenUDPOptions: %v", err)
			}
			defer conn.Close()

			for i := 0; i < 5; i++ {
				payload := []byte{byte(i)}
				pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), uint16(3200+i), 9220, payload)
				fs.inbound <- pkt
			}

			req := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, []byte("still alive"))
			fs.inbound <- req
			waitForOutbound(t, fs, time.Second)

			if got := stack.UDPStats().QueueFullDropped; got != 3 {
				t.Fatalf("UDPStats().QueueFullDropped = %d, want 3 (5 sent, queue depth 2)", got)
			}
		})
	}
}

// TestUDPStatsMirrorsInternalCounters asserts UDPStats().NoListenerDropped
// and .BadChecksumDropped reflect the demux's existing internal counters.
func TestUDPStatsMirrorsInternalCounters(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	fs := newFakeSession()
	ip := net.IPv4(10, 8, 0, 2).To4()
	if err := stack.Attach(fs, ip); err != nil {
		t.Fatalf("Attach: %v", err)
	}

	dummy, err := stack.ListenUDP(1)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer dummy.Close()

	// No listener on port 9.
	pkt := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), 1000, 9, []byte("nobody home"))
	fs.inbound <- pkt

	// Bad checksum: build a valid datagram then corrupt its UDP checksum
	// field in place.
	bad := buildUDPIPv4(mustAddr(ip), mustAddr(testServerIP()), 1001, 1, []byte("corrupt"))
	hdr, err := parseIPv4(bad)
	if err != nil {
		t.Fatalf("parseIPv4(test fixture): %v", err)
	}
	udpStart := hdr.payloadOff
	orig0, orig1 := bad[udpStart+6], bad[udpStart+7]
	// Flip the checksum to a value guaranteed to differ from both the
	// original (correct) checksum and the 0x0000 "no checksum" sentinel.
	bad[udpStart+6], bad[udpStart+7] = 0xAB, 0xCD
	if bad[udpStart+6] == orig0 && bad[udpStart+7] == orig1 {
		bad[udpStart+6], bad[udpStart+7] = 0x12, 0x34
	}
	fs.inbound <- bad

	req := buildICMPEchoRequest(mustAddr(ip), mustAddr(testServerIP()), 1, 1, []byte("still alive"))
	fs.inbound <- req
	waitForOutbound(t, fs, time.Second)

	demux := stack.udpHandler.(*udpDemux)
	stats := stack.UDPStats()
	if stats.NoListenerDropped != demux.noListenerDropped.Load() {
		t.Fatalf("UDPStats().NoListenerDropped = %d, want %d (internal counter)", stats.NoListenerDropped, demux.noListenerDropped.Load())
	}
	if stats.NoListenerDropped == 0 {
		t.Fatal("UDPStats().NoListenerDropped = 0, want > 0 after a no-listener datagram")
	}
	if stats.BadChecksumDropped != demux.badChecksumDropped.Load() {
		t.Fatalf("UDPStats().BadChecksumDropped = %d, want %d (internal counter)", stats.BadChecksumDropped, demux.badChecksumDropped.Load())
	}
	if stats.BadChecksumDropped == 0 {
		t.Fatal("UDPStats().BadChecksumDropped = 0, want > 0 after a corrupted-checksum datagram")
	}
}

// TestUDPStatsZeroValueWithoutRegisteringHandler asserts UDPStats() on a
// stack that never called ListenUDP/ListenUDPOptions returns the zero
// value AND does not register a UDP handler as a side effect — unlike
// udpDemuxFor(), which does register one. A read-only accessor that
// mutates the stack would be a bug.
func TestUDPStatsZeroValueWithoutRegisteringHandler(t *testing.T) {
	stack := newTestStack(t)
	defer stack.Close()

	got := stack.UDPStats()
	if got != (UDPStats{}) {
		t.Fatalf("UDPStats() on an untouched stack = %+v, want the zero value", got)
	}

	stack.mu.RLock()
	handler := stack.udpHandler
	stack.mu.RUnlock()
	if handler != nil {
		t.Fatalf("Stack.udpHandler = %v after UDPStats(), want nil — UDPStats must not register a handler", handler)
	}
}
