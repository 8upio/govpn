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
// netstack/netstacktest's FakeSession) drives the fast test tier with no
// Docker (D-12).
package netstack

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"
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
//
// This buffer only ever has to hold ONE fragment as it arrives on the
// wire, never a whole reassembled datagram: reassembly.go materializes a
// completed datagram into its own freshly allocated slice, well downstream
// of this read loop.
const readBufferSize = 2048

// maxReadRetryBufferSize bounds the one-off larger buffer readLoop
// allocates when Session.Read reports its buffer-too-small, retained-
// packet outcome (WR-04). 65535 is the largest IPv4 datagram this stack's
// own parseIPv4 total-length field can express (T-03-01), so growing
// beyond it can never help — a Read that still fails at this size is
// treated as a genuine, terminal session failure, not a sizing problem.
const maxReadRetryBufferSize = 65535

// MTU bounds for WithMTU. The MTU governs two things and only two things:
// the size above which writePacket fragments an outbound datagram, and the
// MSS this stack advertises in every SYN-ACK (maxSegmentSize).
const (
	// defaultMTU is the `tun-mtu 1500` this project pushes to clients
	// (ovpn.go's serverKM2Options). An embedder that changes neither
	// side keeps the two in step.
	defaultMTU = 1500

	// minMTU is RFC 1122 §3.3.3's EMTU_R — the 576 octets every IPv4
	// host must be able to reassemble, and the floor OpenVPN itself
	// refuses to take `tun-mtu` below.
	minMTU = 576

	// maxMTU is the largest datagram RFC 791 §3.1's Total Length field
	// can express: above this there is nothing left to fragment for.
	maxMTU = maxIPv4Datagram
)

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

	// ErrInvalidMTU is returned by New when WithMTU was given a value
	// outside [minMTU, maxMTU]. Option has no error return, so New is
	// the only place this range check can live.
	ErrInvalidMTU = errors.New("netstack: MTU must be between 576 and 65535")

	// ErrOutboundSourceMismatch is returned by writePacket when the
	// outbound packet's IPv4 source is not the server's own tunnel IP
	// (D-04, fail-closed).
	ErrOutboundSourceMismatch = errors.New("netstack: outbound packet's IPv4 source is not the server tunnel IP")

	// ErrInvalidReassemblyLimits is returned by New when
	// WithReassemblyLimits was given a negative field. Option has no
	// error return, so New is the only place this check can live —
	// exactly the ErrInvalidMTU precedent above.
	ErrInvalidReassemblyLimits = errors.New("netstack: ReassemblyLimits fields must not be negative")
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

	// Fragment counters, appended after the fields above so Stats stays
	// additively compatible (no existing name or position moves).
	fragmentsReassembled    atomic.Uint64
	reassemblyTimeouts      atomic.Uint64
	reassemblyBoundExceeded atomic.Uint64
	outboundFragmented      atomic.Uint64
}

// Stats is a point-in-time snapshot of Stack's drop/delivery counters,
// returned by Stack.Stats().
type Stats struct {
	ICMPEchoRequests uint64
	ICMPEchoReplies  uint64

	// PacketsReceived counts FRAGMENTS, not datagrams: every packet
	// handed to deliver is counted once, so a datagram that arrives as
	// three fragments contributes three here and one to
	// FragmentsReassembled.
	PacketsReceived  uint64
	MalformedDropped uint64

	// FragmentsDropped counts fragments discarded by the reassembler:
	// duplicates, fragments contradicting what is already known about
	// their datagram, and fragments arriving after the attachment was
	// torn down. A fragment with invalid GEOMETRY never reaches the
	// reassembler at all — parseIPv4 rejects it and it lands in
	// MalformedDropped.
	FragmentsDropped         uint64
	SpoofedSourceDropped     uint64
	WrongDestinationDropped  uint64
	UnhandledProtocolDropped uint64
	OutboundSourceDropped    uint64
	ShortReadBufferGrown     uint64

	// FragmentsReassembled counts DATAGRAMS successfully reassembled
	// from inbound fragments.
	FragmentsReassembled uint64

	// ReassemblyTimeouts counts DATAGRAMS discarded because they were
	// still incomplete reassemblyTimeout after their first fragment.
	ReassemblyTimeouts uint64

	// ReassemblyBoundExceeded counts fragments refused because
	// accepting them would have exceeded this session's buffer or byte
	// budget.
	ReassemblyBoundExceeded uint64

	// OutboundFragmented counts DATAGRAMS this stack fragmented on the
	// way out — not the number of fragments emitted.
	OutboundFragmented uint64
}

// attachment is one Attach-ed session's routing state: the session itself,
// its registered tunnel IP, and the stopCh/stopOnce teardown pair mirroring
// session.go's own stopCh/stopOnce discipline (session.go:95-106).
type attachment struct {
	sess Session
	ip   netip.Addr

	stopCh   chan struct{}
	stopOnce sync.Once

	// reasm is this session's own IPv4 reassembly state — per session,
	// never shared, so one client's fragments can neither poison nor
	// starve another's. Its zero value is ready to use and allocates
	// nothing until the first fragment arrives.
	reasm reassembler
}

// stop closes a's stopCh exactly once and discards a's reassembly state.
// Safe to call more than once or concurrently. This is the single teardown
// seam Detach, Close and detachAttachment all funnel through, so no
// half-reassembled datagram can outlive the session that was building it.
// It deliberately bumps no counter: discarding buffers because the session
// went away is not a drop worth alerting on.
func (a *attachment) stop() {
	a.stopOnce.Do(func() {
		close(a.stopCh)
		a.reasm.discardAll()
	})
}

// Stack is a userspace IPv4 stack terminating exactly one server tunnel
// endpoint: sessions Attach to it, IPv4/ICMP/UDP/TCP packets are parsed and
// dispatched, and outbound packets are written back through the owning
// session — all in-process, with no TUN device and no elevated privilege.
type Stack struct {
	serverIP netip.Addr
	clock    Clock

	// mtu is the largest datagram this stack emits unfragmented, and the
	// value maxSegmentSize derives the advertised TCP MSS from. Set once
	// in New (validated there, since Option cannot return an error) and
	// never mutated afterwards, so it needs no lock.
	mtu int

	// reasmLimits overrides the default per-attachment reassembly bounds
	// (see WithReassemblyLimits). Set once in New (validated there, since
	// Option cannot return an error) and never mutated afterwards, so it
	// needs no lock. Attach copies it into each new attachment's
	// reassembler.
	reasmLimits ReassemblyLimits

	// ipID hands out the Identification values fragmentIPv4 stamps on
	// outbound fragments. It starts at 1 and wraps naturally: RFC 6864
	// §4 only requires uniqueness per (source, destination, protocol)
	// within one reassembly window.
	ipID atomic.Uint32

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

// WithMTU overrides the Stack's MTU (default defaultMTU, 1500). It governs
// exactly two things: the size above which an outbound datagram is
// fragmented by writePacket, and the MSS advertised in every SYN-ACK
// (maxSegmentSize), which is what keeps TCP unfragmented by construction.
// mtu must be within [minMTU, maxMTU]; New returns ErrInvalidMTU otherwise,
// since an Option cannot return an error itself.
//
// This is the embedder's choice for what this stack EMITS. It is
// independent of the `tun-mtu 1500` the server pushes to clients, which is
// fixed and advisory.
func WithMTU(mtu int) Option {
	return func(s *Stack) { s.mtu = mtu }
}

// ReassemblyLimits overrides the per-attachment IPv4 fragment-reassembly
// bounds (see reassembly.go's own header comment for the algorithm and
// overlap policy). A zero field means "use the built-in default"
// (maxReassemblyBuffersPerSession, maxReassemblyBytesPerSession,
// reassemblyTimeout respectively), so ReassemblyLimits{} is equivalent to
// never calling WithReassemblyLimits at all.
//
// MaxBytesPerAttachment is a PER-ATTACHMENT byte budget charged by reached
// buffer length, not by bytes actually written (see reassembly.go's add
// for why) — this is how a caller's "max datagram bytes" requirement maps
// onto this stack's existing model.
type ReassemblyLimits struct {
	// MaxDatagramsPerAttachment caps how many distinct datagrams one
	// attached session may have half-reassembled at once.
	MaxDatagramsPerAttachment int

	// MaxBytesPerAttachment caps the bytes one attached session's
	// half-reassembled datagrams may hold in total.
	MaxBytesPerAttachment int

	// Timeout is how long a partially-reassembled datagram lives before
	// it is discarded, fixed when its first fragment arrives.
	Timeout time.Duration
}

// WithReassemblyLimits overrides the default per-attachment reassembly
// bounds for every session Attach-ed to this Stack. Any negative field
// makes New return ErrInvalidReassemblyLimits, since Option cannot return
// an error itself — the same reason WithMTU's range check lives in New.
func WithReassemblyLimits(l ReassemblyLimits) Option {
	return func(s *Stack) { s.reasmLimits = l }
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
		mtu:      defaultMTU,
		routes:   make(map[netip.Addr]*attachment),
		stopCh:   make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	// After the option loop, not inside WithMTU: Option has no error
	// return, so this is the only place the range can be enforced.
	if s.mtu < minMTU || s.mtu > maxMTU {
		return nil, ErrInvalidMTU
	}
	if s.reasmLimits.MaxDatagramsPerAttachment < 0 ||
		s.reasmLimits.MaxBytesPerAttachment < 0 ||
		s.reasmLimits.Timeout < 0 {
		return nil, ErrInvalidReassemblyLimits
	}
	return s, nil
}

// ServerIP returns the stack's own tunnel address, as passed to New.
func (s *Stack) ServerIP() net.IP {
	b := s.serverIP.As4()
	return net.IPv4(b[0], b[1], b[2], b[3]).To4()
}

// MTU returns the stack's configured MTU (see WithMTU): the largest
// datagram it emits without fragmenting, and the basis of the TCP MSS it
// advertises.
func (s *Stack) MTU() int { return s.mtu }

// maxSegmentSize is the MSS this stack advertises in every SYN-ACK,
// derived from the configured MTU: the MTU minus a 20-byte IPv4 header and
// a 20-byte, options-free TCP header. minMTU (576) guarantees the result is
// at least 536, RFC 9293's own floor.
//
// Deriving MSS from the MTU rather than fixing it is what keeps TCP
// unfragmented BY CONSTRUCTION. At an MTU below 1500 a fixed 1460-byte
// segment would split into two fragments on every full-sized send — and a
// path that silently drops fragments would then black-hole the connection
// entirely while small segments kept flowing, exactly the failure mode RFC
// 8900 warns about.
func (s *Stack) maxSegmentSize() uint16 {
	return uint16(s.mtu - minIPv4HeaderLen - tcpHeaderMinLen)
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
		reasm: reassembler{
			maxBufs:  s.reasmLimits.MaxDatagramsPerAttachment,
			maxBytes: s.reasmLimits.MaxBytesPerAttachment,
			timeout:  s.reasmLimits.Timeout,
		},
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

// IsAttached reports whether ip currently has a route: true only for an
// IPv4 address currently registered via Attach and not yet removed by
// Detach or detachAttachment. It never panics on its argument — a nil,
// IPv6, or otherwise malformed ip simply cannot be attached, so
// toIPv4Addr's error is treated as "not attached" rather than propagated.
// The stack's own server tunnel IP is never a routable attachment (Attach
// rejects it with ErrAttachServerIP), so it always reports false too.
func (s *Stack) IsAttached(ip net.IP) bool {
	addr, err := toIPv4Addr(ip)
	if err != nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.routes[addr]
	return ok
}

// Routes returns a point-in-time snapshot of every currently attached IP,
// sorted in ascending address order for deterministic output. It is safe to
// call concurrently with Attach/Detach and with in-flight handshakes and
// teardowns: the map is read once under a brief RLock, then released before
// sorting and materializing the result, so Routes never holds s.mu for
// longer than the lookup itself needs.
//
// Every returned net.IP is a freshly allocated 4-byte defensive copy: a
// caller mutating an element of the returned slice cannot reach or corrupt
// this Stack's own routing state. An empty stack returns a zero-length
// slice, never nil-vs-empty ambiguity a caller would have to special-case.
//
// Routes is the inventory surface (which IPs are attached right now);
// Stack.Stats() is the companion counter surface (how many packets flowed).
// Use Routes when you need identity, Stats when you need a count.
func (s *Stack) Routes() []net.IP {
	s.mu.RLock()
	addrs := make([]netip.Addr, 0, len(s.routes))
	for addr := range s.routes {
		addrs = append(addrs, addr)
	}
	s.mu.RUnlock()

	slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })

	out := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		b := addr.As4()
		ip := make(net.IP, 4)
		copy(ip, b[:])
		out = append(out, ip)
	}
	return out
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
// Only then is the packet dispatched — a complete datagram directly, a
// fragment through this attachment's own reassembler first.
//
// Running both ACL checks strictly BEFORE reasm.add is the security
// property the whole reassembly design rests on (T-FVA-02): a fragment
// whose source is not this session's own registered IP is dropped before
// it can allocate a single byte of buffer state, so one client can neither
// poison nor exhaust another's reassembly buffers.
//
// Note that packetsReceived counts FRAGMENTS, not datagrams: a datagram
// arriving in three fragments is counted three times here and once in
// fragmentsReassembled.
func (s *Stack) deliver(a *attachment, pkt []byte) {
	s.stats.packetsReceived.Add(1)

	hdr, err := parseIPv4(pkt)
	if err != nil {
		// Includes errBadFragment: a fragment whose geometry is invalid
		// is malformed, not a reassembly failure.
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
		datagram, outcome, expired := a.reasm.add(s.clock.Now(), hdr, pkt)
		if expired > 0 {
			s.stats.reassemblyTimeouts.Add(uint64(expired))
		}
		switch outcome {
		case reasmComplete:
			// Re-parse what the reassembler built rather than trusting
			// it: dispatch below indexes with the header's own offsets,
			// so those offsets must describe THIS buffer.
			whole, err := parseIPv4(datagram)
			if err != nil {
				s.stats.malformedDropped.Add(1)
				return
			}
			s.stats.fragmentsReassembled.Add(1)
			s.dispatch(a, whole, datagram)
		case reasmBoundExceeded:
			s.stats.reassemblyBoundExceeded.Add(1)
		case reasmDuplicate, reasmConflict, reasmClosed:
			s.stats.fragmentsDropped.Add(1)
		case reasmBuffered:
			// Nothing to count: the fragment is held, not dropped.
		}
		return
	}

	s.dispatch(a, hdr, pkt)
}

// dispatch switches on a COMPLETE datagram's protocol: ICMP is handled
// inline, UDP and TCP are handed to the registered dispatch-seam handler
// if one exists, and everything else is counted in exactly one Stats()
// counter and dropped. hdr must be the result of parsing pkt.
func (s *Stack) dispatch(a *attachment, hdr ipv4Header, pkt []byte) {
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
//
// A datagram larger than the configured MTU is fragmented (fragmentIPv4)
// and its fragments written in order. Ordering within one datagram is
// guaranteed because they are written from this single goroutine; if a
// Write fails partway, the fragments already sent are simply lost and time
// out in the peer's own reassembly buffer, exactly as with any IP stack.
func (s *Stack) writePacket(a *attachment, pkt []byte) error {
	hdr, err := parseIPv4(pkt)
	if err != nil {
		return err
	}
	if hdr.src != s.serverIP {
		s.stats.outboundSourceDropped.Add(1)
		return ErrOutboundSourceMismatch
	}

	if hdr.totalLen <= s.mtu {
		_, err = a.sess.Write(pkt)
		return err
	}

	id := uint16(s.ipID.Add(1))
	frags := fragmentIPv4(hdr, pkt, s.mtu, id)
	if len(frags) == 0 {
		return errBadFragment
	}
	s.stats.outboundFragmented.Add(1)
	for _, frag := range frags {
		if _, err := a.sess.Write(frag); err != nil {
			return err
		}
	}
	return nil
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
		FragmentsReassembled:     s.stats.fragmentsReassembled.Load(),
		ReassemblyTimeouts:       s.stats.reassemblyTimeouts.Load(),
		ReassemblyBoundExceeded:  s.stats.reassemblyBoundExceeded.Load(),
		OutboundFragmented:       s.stats.outboundFragmented.Load(),
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
