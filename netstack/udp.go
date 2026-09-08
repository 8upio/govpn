// udp.go implements RFC 768's UDP header parse/build (including its IPv4
// pseudo-header checksum and the protocol's two special-case checksum
// rules) and Stack.ListenUDP's net.PacketConn implementation: a UDP port
// demux keyed by destination port, delivering to per-listener bounded
// queues with the same non-blocking, drop-newest overflow policy
// session.go:365-384 already uses for its own inbound queue.
//
//   - UDP header format, IPv4 pseudo-header layout, and the on-wire 0x0000
//     "sender computed no checksum" rule: RFC 768 (rfc-editor.org/rfc/rfc768)
//   - net.PacketConn's deadline/close contract, including "I/O methods will
//     return an error that wraps os.ErrDeadlineExceeded": /usr/local/go/src/
//     net/net.go (Go 1.26.1 toolchain, read directly during phase research)
package netstack

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// udpHeaderLen is the fixed 8-byte UDP header: source port, destination
	// port, length, checksum (RFC 768).
	udpHeaderLen = 8

	// udpQueueDepth is the per-listener bounded inbound queue depth (D-14).
	// 64 rather than session.go's own per-session 32 (session.go:365-384)
	// because a single UDP listener is a fan-in point for every attached
	// session's traffic to that port, not a per-session queue.
	udpQueueDepth = 64

	// maxUDPPayload is the write-side upper bound on the application
	// payload WriteTo accepts: RFC 768's Length field is 16 bits and
	// covers the 8-byte UDP header plus payload; carried inside a 20-byte,
	// options-free IPv4 packet, the largest payload that still fits a
	// 16-bit IPv4 Total Length field is 65535-20-8 = 65507. A payload up
	// to that size IS genuinely transmittable: writePacket fragments any
	// datagram larger than the configured MTU (WithMTU), so this bound
	// is not about what fits on the wire. A WriteTo exceeding it is a
	// caller bug purely because RFC 768's own Length field is 16 bits
	// and could not describe the datagram at all.
	maxUDPPayload = 65507
)

// Typed errors returned by ListenUDP and udpConn's methods.
var (
	// ErrUDPPortZero is returned by ListenUDP(0): there is no
	// ephemeral-port allocator here, the embedder names the port.
	ErrUDPPortZero = errors.New("netstack: UDP port 0 is not a valid listen port")

	// ErrUDPPortInUse is returned by ListenUDP when port already has a
	// live listener.
	ErrUDPPortInUse = errors.New("netstack: UDP port already in use")

	// ErrUDPNoRoute is returned by WriteTo when no session is currently
	// attached at the destination address (never attached, or detached).
	ErrUDPNoRoute = errors.New("netstack: no attached session for this UDP peer")

	// ErrUDPPayloadTooLarge is returned by WriteTo when len(p) exceeds
	// maxUDPPayload.
	ErrUDPPayloadTooLarge = errors.New("netstack: UDP payload exceeds the maximum UDP datagram size")

	// ErrUDPInvalidAddr is returned by WriteTo when addr is not a
	// *net.UDPAddr, has a nil IP, or is not IPv4 (D-17: IPv4 only).
	ErrUDPInvalidAddr = errors.New("netstack: WriteTo address must be a non-nil IPv4 *net.UDPAddr")

	// errUDPHeaderTooShort / errUDPBadLength are parseUDP's own bounds-check
	// sentinels, in the style of ipv4.go's errTooShort etc. Unexported:
	// deliver's caller (handlePacket) folds a parse failure into the
	// stack's existing malformedDropped counter rather than exposing a
	// distinct UDP-parse error type.
	errUDPHeaderTooShort = errors.New("netstack: buffer too short for a UDP header")
	errUDPBadLength      = errors.New("netstack: UDP length field is out of range for this buffer")
)

// parseUDP parses payload's 8-byte UDP header. Validation, in order, each
// step strictly before the dereference it guards:
//
//  1. len(payload) >= udpHeaderLen
//  2. the 16-bit Length field (payload[4:6]) is >= udpHeaderLen and
//     <= len(payload) — a length field that lies about the datagram's own
//     size is rejected before any slice is taken
//
// data is payload[udpHeaderLen:length]: the UDP payload, excluding the
// 8-byte header. The checksum field (payload[6:8]) is deliberately not
// returned or verified here — handlePacket verifies it, since verification
// needs the IPv4 pseudo-header (src/dst) that parseUDP itself never sees.
func parseUDP(payload []byte) (srcPort, dstPort uint16, data []byte, err error) {
	if len(payload) < udpHeaderLen {
		return 0, 0, nil, errUDPHeaderTooShort
	}
	length := int(binary.BigEndian.Uint16(payload[4:6]))
	if length < udpHeaderLen || length > len(payload) {
		return 0, 0, nil, errUDPBadLength
	}
	srcPort = binary.BigEndian.Uint16(payload[0:2])
	dstPort = binary.BigEndian.Uint16(payload[2:4])
	data = payload[udpHeaderLen:length]
	return srcPort, dstPort, data, nil
}

// buildUDP appends an 8-byte UDP header (source port, destination port,
// length, checksum) followed by payload to dst, and returns the result.
// The checksum is computed with transportChecksum over the pseudo-header
// (src, dstAddr, protocolUDP) plus the UDP header (checksum field zeroed)
// plus payload. RFC 768's special rule is applied explicitly: a computed
// checksum of 0x0000 is transmitted as 0xFFFF, because an on-wire 0x0000
// means "sender computed no checksum" and must not be confused with an
// actual zero result.
func buildUDP(dst []byte, src, dstAddr netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	start := len(dst)
	totalLen := udpHeaderLen + len(payload)

	dst = append(dst, make([]byte, udpHeaderLen)...)
	hdr := dst[start : start+udpHeaderLen]
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(totalLen))
	hdr[6], hdr[7] = 0, 0 // checksum, computed below with this zeroed

	dst = append(dst, payload...)

	segment := dst[start:]
	checksum := transportChecksum(src, dstAddr, protocolUDP, segment)
	if checksum == 0 {
		// RFC 768: "If the computed checksum is zero, it is transmitted
		// as all ones" — an on-wire 0x0000 means "no checksum computed"
		// and must never be produced by a sender that did compute one.
		checksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(dst[start+6:start+8], checksum)

	return dst
}

// udpDatagram is one inbound datagram queued on a udpConn's inbound
// channel: the sender's address and a private copy of its payload.
type udpDatagram struct {
	addr *net.UDPAddr
	data []byte
}

// udpDemux is the stack's UDP port demux (D-03): registered exactly once
// into Stack.udpHandler via registerUDPHandler, on the first ListenUDP
// call. Closing the last listener leaves the (now-empty) demux registered
// rather than unregistering it — a later ListenUDP call never races a
// concurrent inbound UDP packet against re-registration into
// Stack.udpHandler, since the demux (and Stack's dispatch to it) never
// goes away once created.
//
// Deliberate deferral, not an oversight: only single-port binds are
// supported here. A catch-all/port-range demux (for RTP-style dynamic
// port workloads) is held on CONTEXT.md's Deferred Ideas list until a real
// consumer needs it (D-03) — do not add one speculatively.
type udpDemux struct {
	stack *Stack

	mu    sync.RWMutex
	ports map[uint16]*udpConn

	// noListenerDropped / badChecksumDropped are this plan's two new
	// counters (a datagram addressed to a port with no listener, and an
	// inbound datagram whose non-zero on-wire checksum field does not
	// match the computed checksum). A general malformed-header UDP packet
	// instead increments Stack's own existing malformedDropped counter,
	// matching every other protocol's parse-failure path in deliver.
	noListenerDropped  atomic.Uint64
	badChecksumDropped atomic.Uint64
}

var _ protocolHandler = (*udpDemux)(nil)

// handlePacket is Stack.deliver's UDP dispatch target (registered via
// registerUDPHandler): parse the UDP header, verify the checksum per RFC
// 768's rules, look up the destination port, and queue the payload plus
// sender address onto that port's udpConn. A miss on any of parse,
// checksum, or port lookup is dropped silently and counted — in
// particular, a datagram to a closed port produces no ICMP
// port-unreachable of any kind (Deferred Idea, D-03/D-11's sibling
// decision for UDP).
func (d *udpDemux) handlePacket(a *attachment, src, dst netip.Addr, payload []byte) {
	srcPort, dstPort, data, err := parseUDP(payload)
	if err != nil {
		d.stack.stats.malformedDropped.Add(1)
		return
	}

	// RFC 768: an on-wire checksum field of 0x0000 means "sender computed
	// no checksum" and must be accepted without verification. Any other
	// value must match a fresh computation over the pseudo-header plus
	// the received header (checksum field zeroed) plus data.
	wireChecksum := binary.BigEndian.Uint16(payload[6:8])
	if wireChecksum != 0 {
		segment := append([]byte(nil), payload[:udpHeaderLen+len(data)]...)
		segment[6], segment[7] = 0, 0
		computed := transportChecksum(src, dst, protocolUDP, segment)
		if computed == 0 {
			computed = 0xFFFF
		}
		if computed != wireChecksum {
			d.badChecksumDropped.Add(1)
			return
		}
	}

	d.mu.RLock()
	conn := d.ports[dstPort]
	d.mu.RUnlock()
	if conn == nil {
		// No ICMP port-unreachable is generated — Deferred Idea. The
		// omission is deliberate, not a gap: CONTEXT.md's Deferred Ideas
		// list holds ICMP error generation until a later phase.
		d.noListenerDropped.Add(1)
		return
	}

	dgram := udpDatagram{
		addr: &net.UDPAddr{IP: net.IP(src.AsSlice()), Port: int(srcPort)},
		data: append([]byte(nil), data...),
	}
	select {
	case conn.inbound <- dgram:
	default:
		// Queue full: drop the newest datagram (D-14), mirroring
		// session.go:365-384's own congested-link policy. The load-bearing
		// property is that the stack's single read-loop goroutine is
		// never blocked by a slow or absent ReadFrom consumer.
	}
}

// udpDemux (below) returns the Stack's registered UDP demux, creating and
// registering it via registerUDPHandler on first use. See udpDemux's own
// doc comment for why registration, once done, is never undone.
func (s *Stack) udpDemuxFor() *udpDemux {
	s.mu.RLock()
	if d, ok := s.udpHandler.(*udpDemux); ok {
		s.mu.RUnlock()
		return d
	}
	s.mu.RUnlock()

	d := &udpDemux{stack: s, ports: make(map[uint16]*udpConn)}
	if err := s.registerUDPHandler(d); err != nil {
		// Lost the race: another goroutine registered the winning demux
		// between our RUnlock above and this registerUDPHandler call.
		// Use the winner's demux rather than the one we just built.
		s.mu.RLock()
		defer s.mu.RUnlock()
		return s.udpHandler.(*udpDemux)
	}
	return d
}

// ListenUDP opens a UDP listener bound to (the stack's server tunnel IP,
// port) (D-01, D-03). Listeners may be opened at any time after the stack
// is running, on any port. port 0 is rejected (ErrUDPPortZero) — there is
// no ephemeral-port allocator here; the embedder names the port it wants.
// A port already bound by a live listener returns ErrUDPPortInUse rather
// than silently stealing that listener's traffic.
//
// Returning the stdlib net.PacketConn interface type, never the concrete
// *udpConn, is deliberate (D-01): it is what makes "usable by unmodified
// socket-based code" a compiler-checked fact rather than an aspiration —
// see the var _ net.PacketConn assertion on udpConn below.
func (s *Stack) ListenUDP(port uint16) (net.PacketConn, error) {
	if port == 0 {
		return nil, ErrUDPPortZero
	}

	demux := s.udpDemuxFor()

	demux.mu.Lock()
	defer demux.mu.Unlock()
	if _, exists := demux.ports[port]; exists {
		return nil, ErrUDPPortInUse
	}
	conn := newUDPConn(demux, port)
	demux.ports[port] = conn
	return conn, nil
}

// udpConn implements net.PacketConn (D-01): ReadFrom, WriteTo, Close,
// LocalAddr, SetDeadline, SetReadDeadline, SetWriteDeadline. Every method
// is safe to call from any number of goroutines simultaneously, matching
// net.PacketConn's own documented contract.
type udpConn struct {
	demux *udpDemux
	port  uint16

	inbound chan udpDatagram

	closeOnce sync.Once
	closed    chan struct{}

	// readDeadline / writeDeadline are independent deadlineTimer instances
	// (deadline.go, built in plan 03-01): each already guards its own
	// mutable state internally, so no additional lock is needed around
	// calling set/wait/stop on them from multiple goroutines.
	readDeadline  *deadlineTimer
	writeDeadline *deadlineTimer
}

var _ net.PacketConn = (*udpConn)(nil)

func newUDPConn(demux *udpDemux, port uint16) *udpConn {
	return &udpConn{
		demux:         demux,
		port:          port,
		inbound:       make(chan udpDatagram, udpQueueDepth),
		closed:        make(chan struct{}),
		readDeadline:  newDeadlineTimer(),
		writeDeadline: newDeadlineTimer(),
	}
}

// ReadFrom implements net.PacketConn. It copies as many bytes as fit in p
// and returns the copied count with no error even if the queued datagram
// was longer — this is stdlib net.PacketConn semantics (an oversized
// datagram is truncated), unlike Session.Read's retain-and-error contract
// (session.go:305-320). The two Read-shaped APIs in this codebase now
// behave differently on a short buffer; the divergence here is deliberate,
// not an oversight, because ReadFrom's own documented contract requires it.
//
// The read deadline is checked with priority over an already-queued
// datagram: a deadline already in the past must fire immediately without
// consuming anything, even if a datagram is sitting in the queue. The
// deadline's wait channel is re-read (via d.readDeadline.wait()) on every
// call rather than cached, so a concurrent SetReadDeadline from another
// goroutine is always honored, never raced against a stale channel.
func (c *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case <-c.closed:
		return 0, nil, net.ErrClosed
	default:
	}

	select {
	case <-c.readDeadline.wait():
		return 0, nil, errDeadlineExceeded
	default:
	}

	select {
	case dgram := <-c.inbound:
		n := copy(p, dgram.data)
		return n, dgram.addr, nil
	case <-c.closed:
		return 0, nil, net.ErrClosed
	case <-c.readDeadline.wait():
		return 0, nil, errDeadlineExceeded
	}
}

// WriteTo implements net.PacketConn. addr must be a non-nil, IPv4
// *net.UDPAddr (D-17) — anything else is ErrUDPInvalidAddr. The route
// lookup reads the stack's routes map fresh on every call rather than
// caching an attachment inside the conn: a session can Detach at any
// moment, and a stale cached pointer would write into a torn-down session.
// No attached session at addr's IP is ErrUDPNoRoute, not a silent success.
func (c *udpConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-c.writeDeadline.wait():
		return 0, errDeadlineExceeded
	default:
	}

	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return 0, ErrUDPInvalidAddr
	}
	ip4 := udpAddr.IP.To4()
	if ip4 == nil {
		return 0, ErrUDPInvalidAddr
	}
	if len(p) > maxUDPPayload {
		return 0, ErrUDPPayloadTooLarge
	}

	dstAddr := netip.AddrFrom4([4]byte(ip4))
	serverIP := c.demux.stack.serverIP

	c.demux.stack.mu.RLock()
	att, ok := c.demux.stack.routes[dstAddr]
	c.demux.stack.mu.RUnlock()
	if !ok {
		return 0, ErrUDPNoRoute
	}

	datagram := buildUDP(nil, serverIP, dstAddr, c.port, uint16(udpAddr.Port), p)
	pkt := buildIPv4(nil, serverIP, dstAddr, protocolUDP, datagram)

	if err := c.demux.stack.writePacket(att, pkt); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.PacketConn. Idempotent (sync.Once): removes this
// conn's port from the demux table (making the port rebindable by a future
// ListenUDP), stops both deadline timers, and closes the conn's own done
// channel so every in-flight or future ReadFrom/WriteTo returns
// net.ErrClosed without blocking.
func (c *udpConn) Close() error {
	c.closeOnce.Do(func() {
		c.demux.mu.Lock()
		if cur, ok := c.demux.ports[c.port]; ok && cur == c {
			delete(c.demux.ports, c.port)
		}
		c.demux.mu.Unlock()

		c.readDeadline.stop()
		c.writeDeadline.stop()
		close(c.closed)
	})
	return nil
}

// LocalAddr implements net.PacketConn: the server tunnel IP and this
// conn's bound port. The returned *net.UDPAddr's own Network()/String()
// methods already report "udp" and "ip:port" — no separate Addr type is
// needed here.
func (c *udpConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: c.demux.stack.ServerIP(), Port: int(c.port)}
}

// SetDeadline implements net.PacketConn: sets both the read and write
// deadlines to the same value.
func (c *udpConn) SetDeadline(t time.Time) error {
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

// SetReadDeadline implements net.PacketConn. Not a no-op: a deadline that
// passes unblocks a blocked ReadFrom with a net.Error-shaped,
// os.ErrDeadlineExceeded-wrapping timeout, honoring the full contract
// (*http.conn).readRequest and any other stdlib caller relies on.
func (c *udpConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.set(t)
	return nil
}

// SetWriteDeadline implements net.PacketConn. See SetReadDeadline's doc
// comment — the same "not a no-op" contract applies to the write side.
func (c *udpConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.set(t)
	return nil
}
