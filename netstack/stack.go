// Package netstack implements a privilege-free, userspace IPv4 stack that
// terminates OpenVPN tunnel traffic entirely in-process: no TUN device, no
// CAP_NET_ADMIN. It implements exactly the wire formats this project's
// scope requires, verified against their primary specs rather than
// approximated from memory:
//
//   - RFC 791 §3.1 — IPv4 header format, IHL, fragmentation flags
//   - RFC 1071 — Internet checksum (16-bit one's-complement sum)
//   - RFC 792 — ICMP echo request/reply
//   - RFC 768 — UDP header and its IPv4 pseudo-header checksum
//   - RFC 9293 (obsoletes RFC 793) — TCP header and state machine
//
// This package imports nothing from github.com/8upio/govpn (D-01, D-18):
// it declares its own minimal Session interface below — exactly
// io.ReadWriteCloser — so *ovpn.Session satisfies it structurally, with no
// coupling in either direction. A fake, in-memory Session (see
// fakesession_test.go) drives the fast test tier with no Docker (D-12).
package netstack

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// Session is the interface Attach accepts: exactly io.ReadWriteCloser.
// *ovpn.Session already satisfies this interface structurally (see
// session.go:521's own var _ io.ReadWriteCloser assertion) — netstack never
// imports github.com/8upio/govpn.
//
// Read is datagram-shaped: it returns one full, decrypted IP packet per
// call, and is called from exactly one goroutine — the attachment's own
// read loop started by Attach. Session.Read's own doc comment
// (session.go:305-313) documents a single-reader-goroutine contract;
// starting a second reader goroutine on the same Session would violate it.
//
// Write may be called concurrently from any number of goroutines:
// internal/datachan.Wrapper.Seal (the real Session's Write path) holds its
// own mutex, and net.PacketConn.WriteTo is documented safe for concurrent
// use by multiple goroutines — so the netstack's own TCP retransmit-timer
// goroutine, TIME_WAIT timer, and any application-handler goroutine can all
// call Write on the same Session with zero additional locking required
// here (RESEARCH.md Pattern 4).
type Session interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

// protocolHandler is the dispatch seam wave 2's UDP (plan 03-02) and TCP
// (plan 03-03) plans each register into independently, from inside their
// own ListenUDP/ListenTCP constructors, so those two plans can be built in
// the same wave without either editing this file. This plan registers
// neither: with both Stack.udpHandler and Stack.tcpHandler nil, a UDP or
// TCP packet is counted in Stats().UnhandledProtocolDropped and dropped.
// Do not "simplify" this seam away by inlining UDP/TCP handling directly
// into deliver — that would re-couple udp.go and tcp_listener.go through
// this file, defeating the reason it exists.
type protocolHandler interface {
	handlePacket(a *attachment, src, dst netip.Addr, payload []byte)
}

// readBufferSize is the per-attachment read-loop buffer's starting size
// (D-14). Session.Read is datagram-shaped and, per its own documented
// contract (session.go:305-334), returns an error while RETAINING the
// packet if the caller's buffer is too small for it. 2048 covers the
// pushed `tun-mtu 1500` (ovpn.go's serverKM2Options) with headroom for any
// future MTU adjustment — but the pushed MTU is advisory only, never
// enforced upstream of this loop, so a non-conforming or hostile client
// can still hand this stack a larger packet. See maxReadRetryBufferSize
// and readLoop (WR-04) for how that outcome is handled without treating it
// as a fatal, session-wide detach.
const readBufferSize = 2048

// maxReadRetryBufferSize bounds the one-off larger buffer readLoop
// allocates when Session.Read reports its buffer-too-small, retained-
// packet outcome (WR-04). 65535 is the largest IPv4 datagram this stack's
// own parseIPv4 total-length field can express (T-03-01), so growing
// beyond it can never help — a Read that still fails at this size is
// treated as a genuine, terminal session failure, not a sizing problem.
const maxReadRetryBufferSize = 65535

// Typed errors returned by New and Attach.
var (
	// ErrNilServerIP is returned by New when serverIP is nil.
	ErrNilServerIP = errors.New("netstack: server IP must not be nil")

	// ErrNotIPv4Address is returned by New and Attach when the supplied
	// net.IP does not have a usable IPv4 form (D-17: IPv4 only for v1).
	ErrNotIPv4Address = errors.New("netstack: address must be IPv4")

	// ErrInvalidAttachIP is returned by Attach when ip is nil or not a
	// usable IPv4 address.
	ErrInvalidAttachIP = errors.New("netstack: attach IP must be a non-nil IPv4 address")

	// ErrAttachServerIP is returned by Attach when ip equals the stack's
	// own server tunnel IP: a session may not claim to be the server.
	ErrAttachServerIP = errors.New("netstack: a session may not attach as the server's own tunnel IP")

	// ErrDuplicateAttach is returned by Attach when an attachment already
	// exists for ip.
	ErrDuplicateAttach = errors.New("netstack: an attachment already exists for this IP")

	// ErrHandlerAlreadyRegistered is returned by registerUDPHandler /
	// registerTCPHandler when a handler of that kind is already registered.
	ErrHandlerAlreadyRegistered = errors.New("netstack: a protocol handler is already registered")

	// ErrOutboundSourceMismatch is returned by writePacket when the
	// outbound packet's IPv4 source is not the server's own tunnel IP
	// (D-04, fail-closed).
	ErrOutboundSourceMismatch = errors.New("netstack: outbound packet's IPv4 source is not the server tunnel IP")
)

// stats holds the stack's atomic drop/delivery counters. Every silent drop
// path in deliver/writePacket/handleICMP increments exactly one of these —
// this is both the harness's observability surface (test/interop/server's
// PASS line) and the fast tier's assertion surface (stack_test.go).
type stats struct {
	icmpEchoRequests         atomic.Uint64
	icmpEchoReplies          atomic.Uint64
	packetsReceived          atomic.Uint64
	malformedDropped         atomic.Uint64
	fragmentsDropped         atomic.Uint64
	spoofedSourceDropped     atomic.Uint64
	wrongDestinationDropped  atomic.Uint64
	unhandledProtocolDropped atomic.Uint64
	outboundSourceDropped    atomic.Uint64
	shortReadBufferGrown     atomic.Uint64
}

// Stats is a point-in-time snapshot of Stack's drop/delivery counters,
// returned by Stack.Stats().
type Stats struct {
	ICMPEchoRequests         uint64
	ICMPEchoReplies          uint64
	PacketsReceived          uint64
	MalformedDropped         uint64
	FragmentsDropped         uint64
	SpoofedSourceDropped     uint64
	WrongDestinationDropped  uint64
	UnhandledProtocolDropped uint64
	OutboundSourceDropped    uint64
	ShortReadBufferGrown     uint64
}

// attachment is one Attach-ed session's routing state: the session itself,
// its registered tunnel IP, and the stopCh/stopOnce teardown pair mirroring
// session.go's own stopCh/stopOnce discipline (session.go:95-106).
type attachment struct {
	sess Session
	ip   netip.Addr

	stopCh   chan struct{}
	stopOnce sync.Once
}

// stop closes a's stopCh exactly once. Safe to call more than once or
// concurrently.
func (a *attachment) stop() {
	a.stopOnce.Do(func() { close(a.stopCh) })
}

// Stack is a userspace IPv4 stack terminating exactly one server tunnel
// endpoint: sessions Attach to it, IPv4/ICMP/UDP/TCP packets are parsed and
// dispatched, and outbound packets are written back through the owning
// session — all in-process, with no TUN device and no elevated privilege.
type Stack struct {
	serverIP netip.Addr
	clock    Clock

	mu     sync.RWMutex
	routes map[netip.Addr]*attachment

	// udpHandler / tcpHandler are the dispatch seam described on
	// protocolHandler above. Guarded by mu.
	udpHandler protocolHandler
	tcpHandler protocolHandler

	stats stats

	stopCh   chan struct{}
	stopOnce sync.Once
}

// Option configures a Stack at construction time.
type Option func(*Stack)

// WithClock overrides the Stack's Clock (default SystemClock). Plan 03-03's
// TCP retransmit/TIME_WAIT timers are driven from this clock, so tests can
// inject a fake one (see the fakeClock in stack_test.go) without any real
// sleeps.
func WithClock(c Clock) Option {
	return func(s *Stack) { s.clock = c }
}

// New builds a Stack terminating serverIP (the server's own tunnel
// address). serverIP must be a non-nil IPv4 address (D-17: IPv6 is
// rejected, matching Config.Network and the 10.8.0.0/24 harness network).
func New(serverIP net.IP, opts ...Option) (*Stack, error) {
	if serverIP == nil {
		return nil, ErrNilServerIP
	}
	ip4 := serverIP.To4()
	if ip4 == nil {
		return nil, ErrNotIPv4Address
	}

	s := &Stack{
		serverIP: netip.AddrFrom4([4]byte(ip4)),
		clock:    SystemClock{},
		routes:   make(map[netip.Addr]*attachment),
		stopCh:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// ServerIP returns the stack's own tunnel address, as passed to New.
func (s *Stack) ServerIP() net.IP {
	b := s.serverIP.As4()
	return net.IPv4(b[0], b[1], b[2], b[3]).To4()
}

// toIPv4Addr converts ip to a netip.Addr, rejecting nil and non-IPv4
// addresses with ErrInvalidAttachIP.
func toIPv4Addr(ip net.IP) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, ErrInvalidAttachIP
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return netip.Addr{}, ErrInvalidAttachIP
	}
	return netip.AddrFrom4([4]byte(ip4)), nil
}

// registerUDPHandler registers h as the stack's UDP dispatch target,
// called from plan 03-02's ListenUDP. Returns ErrHandlerAlreadyRegistered
// if a UDP handler is already registered.
func (s *Stack) registerUDPHandler(h protocolHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpHandler != nil {
		return ErrHandlerAlreadyRegistered
	}
	s.udpHandler = h
	return nil
}

// registerTCPHandler registers h as the stack's TCP dispatch target,
// called from plan 03-03's ListenTCP. Returns ErrHandlerAlreadyRegistered
// if a TCP handler is already registered.
func (s *Stack) registerTCPHandler(h protocolHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tcpHandler != nil {
		return ErrHandlerAlreadyRegistered
	}
	s.tcpHandler = h
	return nil
}

// Attach registers sess as the owner of tunnel address ip and starts
// exactly ONE goroutine running this attachment's read loop
// (Session.Read's documented single-reader contract, session.go:305-313 —
// starting a second reader goroutine for the same session would violate
// it). ip must be a non-nil IPv4 address, must not equal the stack's own
// server tunnel IP (a session may not claim to be the server), and must
// not already be attached.
func (s *Stack) Attach(sess Session, ip net.IP) error {
	if sess == nil {
		return errors.New("netstack: session must not be nil")
	}
	addr, err := toIPv4Addr(ip)
	if err != nil {
		return err
	}
	if addr == s.serverIP {
		return ErrAttachServerIP
	}

	s.mu.Lock()
	if _, exists := s.routes[addr]; exists {
		s.mu.Unlock()
		return ErrDuplicateAttach
	}
	a := &attachment{
		sess:   sess,
		ip:     addr,
		stopCh: make(chan struct{}),
	}
	s.routes[addr] = a
	s.mu.Unlock()

	go s.readLoop(a)
	return nil
}

// Detach removes the route for ip, if one exists, and closes the
// attachment's stopCh (through its own stopOnce, mirroring session.go's
// stopCh/stopOnce discipline) so the read loop discards any packet it
// receives after this call and exits at its next opportunity — either
// before its next Session.Read call, or immediately after an in-flight
// Session.Read call returns. It does NOT call sess.Close(): the session's
// lifetime belongs to the embedder, not the stack (D-02). If the session
// stays open and never delivers another packet after Detach, its read loop
// goroutine remains blocked inside Session.Read until the embedder
// eventually closes the session — at which point Session.Read returns an
// error and detachAttachment's own idempotent removal below is a
// no-op, since the route was already removed here. Returns whether a route
// was actually removed.
func (s *Stack) Detach(ip net.IP) bool {
	addr, err := toIPv4Addr(ip)
	if err != nil {
		return false
	}

	s.mu.Lock()
	a, ok := s.routes[addr]
	if ok {
		delete(s.routes, addr)
	}
	s.mu.Unlock()

	if !ok {
		return false
	}
	a.stop()
	return true
}

// detachAttachment is readLoop's own detach path: Session.Read returning a
// non-nil error is the SOLE detach trigger (D-02). It removes a's route
// only if a is still the current attachment for its IP — Detach may have
// already raced ahead of it, in which case this is a no-op — and stops a.
func (s *Stack) detachAttachment(a *attachment) {
	s.mu.Lock()
	if cur, ok := s.routes[a.ip]; ok && cur == a {
		delete(s.routes, a.ip)
	}
	s.mu.Unlock()
	a.stop()
}

// readLoop is the exactly-one-goroutine-per-attachment reader Attach
// starts. It loops on a.sess.Read: on any non-nil error it detaches and
// returns (the sole detach trigger, D-02); on success it copies the
// delivered bytes into a fresh slice before dispatch (buf is reused by the
// next iteration — handing the shared backing array to deliver, which may
// hand it onward to a handler goroutine, would be a data race) and calls
// deliver. It checks a.stopCh both before blocking in Read and immediately
// after Read returns successfully, so a concurrent Detach takes effect
// promptly rather than only once the underlying session itself closes.
func (s *Stack) readLoop(a *attachment) {
	buf := make([]byte, readBufferSize)
	for {
		select {
		case <-a.stopCh:
			return
		default:
		}

		n, err := a.sess.Read(buf)
		if err != nil {
			// WR-04: Session.Read's documented contract (session.go:
			// 305-334) returns an error while RETAINING the packet when
			// the caller's buffer is too small, rather than a genuine
			// session failure — treating every non-nil error identically
			// as the sole detach trigger converted that documented,
			// recoverable "retry with a bigger buffer" outcome into an
			// unrecoverable, silent session-routing failure (the pushed
			// tun-mtu is advisory only, never enforced upstream of this
			// loop). Session is a locally-declared structural interface
			// (D-01/D-18) — netstack cannot distinguish this specific
			// error by type without importing the core ovpn module to
			// reach its sentinel, which TestPhase3NetstackDoesNotImportCoreLibrary
			// forbids — so instead of inspecting the error, grow the
			// buffer once (up to maxReadRetryBufferSize, the largest
			// IPv4 datagram this stack can even parse) and retry before
			// treating any error as terminal. A genuinely closed/failed
			// session fails again immediately on retry (Read on a closed
			// session returns io.EOF without blocking), so this costs at
			// most one extra non-blocking call, never a stall.
			if len(buf) < maxReadRetryBufferSize {
				buf = make([]byte, maxReadRetryBufferSize)
				s.stats.shortReadBufferGrown.Add(1)
				continue
			}
			s.detachAttachment(a)
			return
		}

		select {
		case <-a.stopCh:
			return
		default:
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		s.deliver(a, pkt)
	}
}

// deliver parses pkt's IPv4 header and, before any protocol dispatch,
// enforces two access-control rules (V4 Access Control, T-03-01):
//
//  1. the packet's IPv4 source must equal a's registered IP — a session
//     whose packets claim another session's tunnel IP, or the server's
//     own, is spoofing;
//  2. the packet's IPv4 destination must equal the server tunnel IP — this
//     stack is a terminator, not a router, and forwards nothing.
//
// Only then does it switch on the protocol: ICMP is handled inline, UDP
// and TCP are handed to the registered dispatch-seam handler if one
// exists, and everything else (including a parse failure or a dropped
// fragment) is counted in exactly one Stats() counter and dropped.
func (s *Stack) deliver(a *attachment, pkt []byte) {
	s.stats.packetsReceived.Add(1)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		s.stats.malformedDropped.Add(1)
		return
	}

	if hdr.src != a.ip {
		s.stats.spoofedSourceDropped.Add(1)
		return
	}
	if hdr.dst != s.serverIP {
		s.stats.wrongDestinationDropped.Add(1)
		return
	}

	if hdr.isFragment() {
		s.stats.fragmentsDropped.Add(1)
		return
	}

	payload := pkt[hdr.payloadOff:hdr.totalLen]

	switch hdr.protocol {
	case protocolICMP:
		s.handleICMP(a, hdr, payload)
	case protocolUDP:
		s.mu.RLock()
		h := s.udpHandler
		s.mu.RUnlock()
		if h != nil {
			h.handlePacket(a, hdr.src, hdr.dst, payload)
		} else {
			s.stats.unhandledProtocolDropped.Add(1)
		}
	case protocolTCP:
		s.mu.RLock()
		h := s.tcpHandler
		s.mu.RUnlock()
		if h != nil {
			h.handlePacket(a, hdr.src, hdr.dst, payload)
		} else {
			s.stats.unhandledProtocolDropped.Add(1)
		}
	default:
		s.stats.unhandledProtocolDropped.Add(1)
	}
}

// writePacket is the single outbound seam every protocol handler uses to
// send a packet back through a's session. It re-parses pkt and drops it,
// returning ErrOutboundSourceMismatch, if pkt's IPv4 source is not the
// server tunnel IP (D-04, fail-closed) — a bug that builds a reply with the
// wrong source must not reach the wire. On success it calls a.sess.Write;
// Write is documented safe to call concurrently from any goroutine (see
// the Session doc comment above), so no lock is taken here.
func (s *Stack) writePacket(a *attachment, pkt []byte) error {
	hdr, err := parseIPv4(pkt)
	if err != nil {
		return err
	}
	if hdr.src != s.serverIP {
		s.stats.outboundSourceDropped.Add(1)
		return ErrOutboundSourceMismatch
	}
	_, err = a.sess.Write(pkt)
	return err
}

// Stats returns a point-in-time snapshot of the stack's drop/delivery
// counters.
func (s *Stack) Stats() Stats {
	return Stats{
		ICMPEchoRequests:         s.stats.icmpEchoRequests.Load(),
		ICMPEchoReplies:          s.stats.icmpEchoReplies.Load(),
		PacketsReceived:          s.stats.packetsReceived.Load(),
		MalformedDropped:         s.stats.malformedDropped.Load(),
		FragmentsDropped:         s.stats.fragmentsDropped.Load(),
		SpoofedSourceDropped:     s.stats.spoofedSourceDropped.Load(),
		WrongDestinationDropped:  s.stats.wrongDestinationDropped.Load(),
		UnhandledProtocolDropped: s.stats.unhandledProtocolDropped.Load(),
		OutboundSourceDropped:    s.stats.outboundSourceDropped.Load(),
		ShortReadBufferGrown:     s.stats.shortReadBufferGrown.Load(),
	}
}

// Close detaches every attachment and closes the stack's own stopCh
// exactly once. It does not close any attached session — session lifetime
// belongs to the embedder (D-02).
func (s *Stack) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)

		s.mu.Lock()
		routes := s.routes
		s.routes = make(map[netip.Addr]*attachment)
		s.mu.Unlock()

		for _, a := range routes {
			a.stop()
		}
	})
	return nil
}
