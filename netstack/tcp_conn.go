// tcp_conn.go implements the net.Conn side of a single accepted TCP
// connection: Read/Write/Close/LocalAddr/RemoteAddr/deadlines, and the
// per-connection send/receive state Read and Write operate on. The state
// machine transitions themselves (RFC 9293's LISTEN/SYN_RCVD/ESTABLISHED/...
// table, RST generation) live in tcp_state.go; the retransmit/TIME_WAIT
// timer machinery lives in tcp_timer.go; the net.Listener/4-tuple demux
// lives in tcp_listener.go.
//
// Read delivers from an in-order byte-stream buffer with ordinary
// io.Reader streaming semantics (as many bytes as fit in p, remainder
// retained for the next call) — a deliberate contrast with
// ovpn.Session.Read's datagram-shaped retain-and-error contract
// (session.go:305-313): this is TCP, a byte stream, not one-packet-per-Read.
package netstack

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Typed errors this plan exports (D-14/artifacts list: "typed errors for:
// port already in use, port 0 rejected, connection reset by peer, listener
// closed").
var (
	// ErrTCPPortZero is returned by ListenTCP when port is 0.
	ErrTCPPortZero = errors.New("netstack: TCP port must not be 0")

	// ErrTCPPortInUse is returned by ListenTCP when port already has a
	// listener.
	ErrTCPPortInUse = errors.New("netstack: TCP port already in use")

	// ErrTCPConnReset is the error Read/Write return, wrapped with
	// additional context, once the connection has been reset — by an
	// inbound RST, by exceeding maxRetransmits, or by the owning session
	// being detached.
	ErrTCPConnReset = errors.New("netstack: TCP connection reset by peer")

	// ErrTCPListenerClosed is returned by Accept once the listener has
	// been closed. It wraps net.ErrClosed so callers using
	// errors.Is(err, net.ErrClosed) — the ordinary net.Listener idiom —
	// still work.
	ErrTCPListenerClosed = fmt.Errorf("netstack: TCP listener closed: %w", net.ErrClosed)

	// errTCPWriteAfterClose is returned by Write once Close has already
	// sent this connection's FIN — matches net.Conn's own "use of closed
	// network connection" convention for a local write-side close.
	errTCPWriteAfterClose = fmt.Errorf("netstack: use of closed network connection: %w", net.ErrClosed)

	// errTCPConnClosed is returned by SetDeadline/SetReadDeadline/
	// SetWriteDeadline once the connection has reached its terminal
	// stateClosed (RESEARCH.md's "the stdlib behavior": stdlib's own
	// *net.TCPConn returns an error wrapping net.ErrClosed from these
	// methods on a closed conn, checked via errors.Is(err, net.ErrClosed)).
	errTCPConnClosed = fmt.Errorf("netstack: use of closed network connection: %w", net.ErrClosed)
)

// fourTuple identifies one TCP connection: the server's own IP is always
// the stack's serverIP (D-17, one server tunnel endpoint per Stack), so it
// is not part of the key (RESEARCH.md/plan text: "4-tuple key (client IP,
// client port, server port — the server IP is always the stack's own)").
type fourTuple struct {
	remoteIP   netip.Addr
	remotePort uint16
	localPort  uint16
}

// tcpConn is the net.Conn implementation for one accepted (or half-open)
// TCP connection. Every mutable field is guarded by mu; handleSegment
// (tcp_state.go) and the timer callbacks (tcp_timer.go) always take mu
// before mutating state and release it before calling stack.writePacket —
// "take the connection's own mutex around state reads/writes, never around
// the write itself" (this plan's own action text, mirroring
// session.go's lock-nesting discipline).
type tcpConn struct {
	stack    *Stack
	demux    *tcpDemux
	listener *tcpListener
	a        *attachment
	key      fourTuple

	localAddr  *net.TCPAddr
	remoteAddr *net.TCPAddr

	mu sync.Mutex

	// notifyCh is closed and replaced (broadcastLocked) under mu on every
	// state change a blocked Read or Write cares about — data arrived,
	// send-buffer space freed, an error was set, the peer closed. This is
	// the channel-based equivalent of a sync.Cond's Broadcast, needed
	// because Read/Write must select over this notification alongside a
	// deadline's own wait channel (plan 03-04: sync.Cond.Wait cannot be
	// combined with select, and RESEARCH.md Pitfall 1 requires the
	// deadline to actually unblock a blocked call).
	notifyCh chan struct{}

	state tcpState

	// Send side: outBuf holds every byte from sndUna onward that has not
	// yet been acknowledged — both in-flight (the first sentBytes of it)
	// and queued-but-unsent (the rest). sndNxt is always sndUna+sentBytes,
	// so it is never stored separately.
	sndUna    uint32
	sndWnd    uint32 // the peer's last-advertised window, in bytes
	sndMSS    uint16
	outBuf    []byte
	sentBytes uint32

	// Receive side: rcvNxt is the next expected sequence number; recvBuf
	// holds in-order bytes not yet delivered to Read; reorder holds
	// out-of-order-but-in-window segments, bounded at maxReorderSegments
	// (D-06's bounded out-of-order buffer, T-03-15).
	rcvNxt        uint32
	recvBuf       []byte
	reorder       map[uint32][]byte
	hasPendingFIN bool
	pendingFINSeq uint32
	peerClosed    bool

	finSent  bool
	finAcked bool
	finSeq   uint32

	rtoTimer          Timer
	timerArmed        bool
	retransmitCount   int
	persistProbeCount int // CR-02: bounds RFC 9293 §3.8 zero-window persist retries
	rto               time.Duration
	inTimeWait        bool

	stopTimers       chan struct{}
	stopTimersClosed bool
	timerDone        chan struct{}

	halfOpenCounted bool
	halfOpenIP      netip.Addr

	// liveCounted mirrors halfOpenCounted's own decrement-exactly-once
	// discipline, but for CR-02's separate maxLiveConnsPerSession budget:
	// set once in handleSYN (tcp_listener.go) and released only by
	// removeConn (releaseLiveConn), never by releaseHalfOpen — a
	// completed handshake must not free this budget the way it frees the
	// half-open one.
	liveCounted bool

	err error

	// readDeadline/writeDeadline: plan 03-01's deadlineTimer (deadline.go),
	// one per direction. SetReadDeadline/SetWriteDeadline/SetDeadline drive
	// these directly; Read/Write select over the corresponding wait()
	// channel alongside notifyCh, so a deadline that fires while a call is
	// already blocked actually unblocks it (RESEARCH.md Pitfall 1) rather
	// than only being checked on the next call.
	readDeadline  *deadlineTimer
	writeDeadline *deadlineTimer

	// closeWriteOnce guards CloseWrite's FIN-sending step so it runs
	// exactly once regardless of whether CloseWrite, Close, or both are
	// called, in either order or concurrently — Close itself calls
	// CloseWrite for its own FIN-sending step (see both methods below), so
	// the two can never race each other into sending two FINs.
	closeWriteOnce sync.Once
}

// closeWriter mirrors net/http's own unexported closeWriter interface
// (net/http/server.go:1772-1787: type closeWriter interface { CloseWrite()
// error }) structurally — Go interfaces are satisfied structurally, so this
// local declaration doesn't need to import or reference net/http's
// unexported type for tcpConn to satisfy it. The var assertion below is
// this plan's own compile-time proof that Accept's return value will be
// found by net/http's own type assertion.
type closeWriter interface {
	CloseWrite() error
}

var _ closeWriter = (*tcpConn)(nil)

var _ net.Conn = (*tcpConn)(nil)

// addrToIP converts a netip.Addr (assumed IPv4, as every address in this
// package is — D-17) to a net.IP for net.TCPAddr construction.
func addrToIP(a netip.Addr) net.IP {
	b := a.As4()
	return net.IPv4(b[0], b[1], b[2], b[3]).To4()
}

// randomISN draws a 4-byte initial sequence number from crypto/rand
// (RESEARCH.md A2): every TCP peer this stack ever talks to has already
// passed TLS mutual-cert authentication and AEAD (D-01's Session boundary),
// so RFC 9293's off-path ISN-prediction threat model does not apply inside
// the tunnel — but the ISN must still never be derived from a clock, a
// counter, or any of this codebase's other packet-ID spaces
// (RESEARCH.md Pitfall 4; internal/reliable's PacketID and
// internal/datachan's replay-window counter are both unrelated to this).
func randomISN() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is a catastrophic, system-wide condition
		// (matches this codebase's existing posture toward crypto/rand
		// failures in internal/testpki-style helpers) — there is no
		// sane fallback that would not reintroduce Pitfall 4's exact
		// mistake (deriving from a clock or counter instead).
		panic("netstack: crypto/rand failed while generating a TCP ISN: " + err.Error())
	}
	return binary.BigEndian.Uint32(b[:])
}

// newTCPConn builds a half-open (SYN_RCVD) connection for an inbound SYN.
// clientISN/clientWindow/clientMSS come from the SYN itself; isn is this
// connection's own freshly-drawn server ISN.
func newTCPConn(d *tcpDemux, l *tcpListener, a *attachment, key fourTuple, isn uint32, clientISN uint32, clientWindow uint16, sndMSS uint16) *tcpConn {
	c := &tcpConn{
		stack:    d.stack,
		demux:    d,
		listener: l,
		a:        a,
		key:      key,
		state:    stateSynRcvd,
		sndUna:   isn,
		sndWnd:   uint32(clientWindow),
		sndMSS:   sndMSS,
		rcvNxt:   clientISN + 1,
		reorder:  make(map[uint32][]byte),

		notifyCh: make(chan struct{}),

		readDeadline:  newDeadlineTimer(),
		writeDeadline: newDeadlineTimer(),

		stopTimers: make(chan struct{}),
		timerDone:  make(chan struct{}),

		localAddr:  &net.TCPAddr{IP: d.stack.ServerIP(), Port: int(key.localPort)},
		remoteAddr: &net.TCPAddr{IP: addrToIP(key.remoteIP), Port: int(key.remotePort)},
	}
	// The SYN-ACK's own retransmit clock starts now (armed from
	// creation) — tcp_timer.go's timerLoop/onRTOFired own everything
	// from here.
	c.rtoTimer = d.stack.clock.NewTimer(initialRTO)
	c.timerArmed = true
	c.rto = initialRTO
	return c
}

// Read delivers as many bytes as fit in p from the in-order receive buffer,
// retaining any remainder for a future call (ordinary io.Reader streaming
// semantics — closer to bufio.Reader than to Session.Read, per this file's
// own doc comment). It blocks until data is available, the peer's FIN has
// been fully consumed and the buffer drained (io.EOF), the connection has
// failed (the sticky err set by an inbound RST, exceeding maxRetransmits, or
// the owning session being detached), or the read deadline (if any) passes.
//
// The deadline check runs BEFORE the data check on every iteration
// (including the first): a deadline already in the past returns the timeout
// error immediately without consuming any buffered data — matching real
// net.Conn behavior and TestTCPReadDeadlineInThePast. A deadline expiring
// while Read is already blocked does not touch connection state at all (no
// segment emitted, err left nil, recvBuf untouched) — RESEARCH.md Pitfall 1
// requires this to be a per-call outcome, not a terminal one, since
// net/http sets and clears a header deadline on every keep-alive iteration
// and expects the connection to remain usable afterward.
func (c *tcpConn) Read(p []byte) (int, error) {
	for {
		c.mu.Lock()
		select {
		case <-c.readDeadline.wait():
			c.mu.Unlock()
			return 0, errDeadlineExceeded
		default:
		}
		if len(c.recvBuf) > 0 {
			n := copy(p, c.recvBuf)
			c.recvBuf = c.recvBuf[n:]
			c.mu.Unlock()
			return n, nil
		}
		if c.err != nil {
			err := c.err
			c.mu.Unlock()
			return 0, err
		}
		if c.peerClosed {
			c.mu.Unlock()
			return 0, io.EOF
		}
		// Capture notifyCh and the deadline's wait channel fresh on every
		// iteration — re-reading rather than caching (this plan's own
		// action text): a cached channel would leave this call waiting on
		// a timer a concurrent SetReadDeadline from another goroutine
		// already replaced.
		notify := c.notifyCh
		deadlineCh := c.readDeadline.wait()
		c.mu.Unlock()

		select {
		case <-notify:
			// Loop back: re-check the deadline first, then recvBuf/err/
			// peerClosed under the lock again.
		case <-deadlineCh:
			return 0, errDeadlineExceeded
		}
	}
}

// Write queues p onto the send buffer and emits segments up to
// min(sendMSS, peer window, maxInFlightBytes) (D-07). Queueing itself is
// bounded by sendBufferCap (maxInFlightBytes) rather than by the peer's
// CURRENT window: a send buffer and a transmission window are distinct
// concepts (matching an ordinary socket's SO_SNDBUF vs. the peer's
// advertised window) — decoupling them is what lets Write() still queue
// (and thus have something to zero-window-persist-probe with,
// tcp_timer.go's onRTOFired) even while the peer's window is fully closed.
// Write blocks once the send buffer itself is full rather than buffering p
// without bound (D-07's own "blocks while the window is closed" language,
// read here as bounded by the send buffer, not by the instantaneous
// window), waking on every ACK/window-update via notifyCh.
//
// A write deadline that passes — whether already past on entry or firing
// while this call is blocked queuing — returns the timeout error along
// with the number of bytes ALREADY queued into the send buffer before the
// deadline hit: io.Writer's contract is that n < len(p) accompanies a
// non-nil error, and overstating n here would let a caller (net/http,
// writing a response body) believe bytes were sent that never left the
// buffer.
func (c *tcpConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	select {
	case <-c.writeDeadline.wait():
		c.mu.Unlock()
		return 0, errDeadlineExceeded
	default:
	}
	if c.err != nil {
		err := c.err
		c.mu.Unlock()
		return 0, err
	}
	if c.finSent {
		c.mu.Unlock()
		return 0, errTCPWriteAfterClose
	}

	total := 0
	for total < len(p) {
		for {
			select {
			case <-c.writeDeadline.wait():
				n := total
				c.mu.Unlock()
				return n, errDeadlineExceeded
			default:
			}
			if c.err != nil {
				n := total
				err := c.err
				c.mu.Unlock()
				return n, err
			}
			if uint32(len(c.outBuf)) < maxInFlightBytes {
				break
			}
			notify := c.notifyCh
			deadlineCh := c.writeDeadline.wait()
			c.mu.Unlock()
			select {
			case <-notify:
			case <-deadlineCh:
			}
			c.mu.Lock()
		}

		capacity := maxInFlightBytes - len(c.outBuf)
		remaining := len(p) - total
		if capacity > remaining {
			capacity = remaining
		}
		c.outBuf = append(c.outBuf, p[total:total+capacity]...)
		total += capacity

		var toSend []tcpSegment
		c.sendPendingLocked(&toSend, false)
		c.mu.Unlock()
		if len(toSend) > 0 {
			c.sendSegments(toSend)
		}
		c.mu.Lock()
	}
	c.mu.Unlock()
	return total, nil
}

// allowedInFlightLocked returns the total send-sequence-space budget
// (D-07): the peer's advertised window, capped at maxInFlightBytes even if
// the peer advertises more — no congestion window, just this fixed cap.
func (c *tcpConn) allowedInFlightLocked() uint32 {
	limit := c.sndWnd
	if limit > maxInFlightBytes {
		limit = maxInFlightBytes
	}
	return limit
}

// Close initiates the FIN sequence exactly once (idempotent — repeated
// calls are no-ops after the first, and calling Close after an earlier
// CloseWrite does not emit a second FIN — see CloseWrite's own doc
// comment). It does not wait for the peer's own FIN or for TIME_WAIT to
// elapse; the connection continues its state machine in the background via
// tcp_timer.go's timerLoop.
func (c *tcpConn) Close() error {
	c.mu.Lock()
	if c.state == stateSynRcvd {
		// Never established: tear down without a wire FIN (RFC 9293 has
		// no "close from SYN_RCVD" data-carrying handshake to honor here
		// — nothing was ever delivered to the application). This is the
		// one case CloseWrite itself does not handle, since CloseWrite is
		// only ever meaningful once a connection has reached
		// ESTABLISHED/CLOSE_WAIT.
		c.err = errTCPWriteAfterClose
		c.state = stateClosed
		c.stopTimersLocked()
		c.broadcastLocked()
		c.mu.Unlock()
		c.demux.removeConn(c)
		return nil
	}
	c.mu.Unlock()
	// Every other state's FIN-sending step is CloseWrite's own
	// closeWriteOnce-guarded logic — Close delegates to it so the two can
	// never race each other into sending two FINs.
	return c.CloseWrite()
}

// CloseWrite implements the unexported closeWriter interface net/http's
// (*conn).closeWriteAndWait checks for via a type assertion before falling
// back to a full close (net/http/server.go:1772-1787 — RESEARCH.md
// Pitfall 3). It sends a FIN for the local-to-peer direction only (RFC
// 9293's CLOSE-WAIT/FIN-WAIT half-close) and leaves the read side
// untouched: inbound data and the peer's own FIN continue to be delivered
// to Read exactly as before CloseWrite was called (T-03-xx/D-08's genuine
// half-close, not a full close in disguise).
//
// Guarded by closeWriteOnce so a second call — whether a direct CloseWrite
// or a later Close — is a no-op returning nil rather than emitting a
// second FIN. A Write after CloseWrite already returns errTCPWriteAfterClose
// because sendFINLocked sets finSent, so no separate write-side guard is
// needed here.
func (c *tcpConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.mu.Lock()
		var toSend []tcpSegment
		switch c.state {
		case stateEstablished:
			c.sendFINLocked(&toSend)
			c.state = stateFinWait1
		case stateCloseWait:
			c.sendFINLocked(&toSend)
			c.state = stateLastAck
		default:
			// SYN_RCVD (handled by Close, never meaningful for a bare
			// CloseWrite since no application ever observed this conn
			// pre-Accept), or already closing/closed: nothing to send.
		}
		c.broadcastLocked()
		c.mu.Unlock()
		if len(toSend) > 0 {
			c.sendSegments(toSend)
		}
	})
	return nil
}

// sendFINLocked records this connection's own FIN sequence number (the
// byte position immediately after every currently-queued byte, sent or
// not) and appends the FIN segment to toSend. Called with mu held.
func (c *tcpConn) sendFINLocked(toSend *[]tcpSegment) {
	c.finSeq = c.sndUna + uint32(len(c.outBuf))
	c.finSent = true
	seg := tcpSegment{
		srcPort: c.key.localPort,
		dstPort: c.key.remotePort,
		seq:     c.finSeq,
		ack:     c.rcvNxt,
		flags:   flagFIN | flagACK,
		window:  c.advertisedWindowLocked(),
	}
	*toSend = append(*toSend, seg)
	c.rto = initialRTO
	c.retransmitCount = 0
	c.timerArmed = true
	c.rtoTimer.Reset(c.rto)
}

// LocalAddr returns the server tunnel IP and the listening port.
func (c *tcpConn) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr returns the client's tunnel IP and source port.
func (c *tcpConn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline, SetReadDeadline, SetWriteDeadline drive plan 03-01's
// deadlineTimer (deadline.go) directly — a real net.Error-shaped timeout
// wrapping os.ErrDeadlineExceeded (RESEARCH.md Pitfall 1), never a no-op.
// Safe to call from a goroutine other than the one blocked in Read/Write
// (deadlineTimer.set's own contract — the standard net.Conn
// supervisor-sets-a-deadline-on-a-blocked-reader pattern). Each returns an
// error wrapping net.ErrClosed once the connection has reached stateClosed,
// matching stdlib *net.TCPConn's own behavior — Read/Write after close
// already return promptly via their existing err/peerClosed checks, so
// this closed check exists only so callers of the deadline setters
// themselves see the same "closed" signal stdlib callers expect.
func (c *tcpConn) SetDeadline(t time.Time) error {
	if c.isClosed() {
		return errTCPConnClosed
	}
	c.readDeadline.set(t)
	c.writeDeadline.set(t)
	return nil
}

func (c *tcpConn) SetReadDeadline(t time.Time) error {
	if c.isClosed() {
		return errTCPConnClosed
	}
	c.readDeadline.set(t)
	return nil
}

func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	if c.isClosed() {
		return errTCPConnClosed
	}
	c.writeDeadline.set(t)
	return nil
}

// isClosed reports whether the connection has reached its terminal
// stateClosed.
func (c *tcpConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state == stateClosed
}

// broadcastLocked wakes every goroutine blocked in Read or Write waiting on
// a state change (data arrived, send-buffer space freed, an error was set,
// the peer closed) by closing the current notify channel and installing a
// fresh one for future waiters — the channel-based equivalent of
// sync.Cond.Broadcast, needed because Read/Write select over this
// notification alongside a deadline's own wait channel, and sync.Cond.Wait
// cannot be combined with select. Called with mu held.
func (c *tcpConn) broadcastLocked() {
	close(c.notifyCh)
	c.notifyCh = make(chan struct{})
}

// recvWindowRemainingLocked returns the number of bytes still admissible
// under defaultReceiveWindow, counting both recvBuf (in-order, undelivered
// bytes) and every byte currently held in reorder (out-of-order-but-in-
// window segments) — CR-01: the receive window bounds everything this
// connection is holding on the peer's behalf, not just the in-order
// portion, so admission checks and the advertised window itself must agree
// on what "buffered" means.
func (c *tcpConn) recvWindowRemainingLocked() uint32 {
	used := uint32(len(c.recvBuf))
	for _, buf := range c.reorder {
		used += uint32(len(buf))
	}
	if used >= defaultReceiveWindow {
		return 0
	}
	return defaultReceiveWindow - used
}

// advertisedWindowLocked returns min(defaultReceiveWindow, free space
// remaining across recvBuf and reorder) — the window shrinks honestly as
// an unread buffer fills (D-07's fixed window, made honest rather than a
// constant lie).
func (c *tcpConn) advertisedWindowLocked() uint16 {
	return uint16(c.recvWindowRemainingLocked())
}

// buildACKLocked builds a bare (no payload) cumulative ACK reflecting the
// connection's current send/receive state (D-06: cumulative ACKs only, no
// SACK option ever emitted).
func (c *tcpConn) buildACKLocked() tcpSegment {
	return tcpSegment{
		srcPort: c.key.localPort,
		dstPort: c.key.remotePort,
		seq:     c.sndUna + c.sentBytes,
		ack:     c.rcvNxt,
		flags:   flagACK,
		window:  c.advertisedWindowLocked(),
	}
}

// sendSegments transmits every segment in segs through the stack's single
// outbound seam, one at a time, OUTSIDE any connection lock (this file's
// own "never around the write itself" discipline).
func (c *tcpConn) sendSegments(segs []tcpSegment) {
	for _, seg := range segs {
		c.sendOne(seg)
	}
}

func (c *tcpConn) sendOne(seg tcpSegment) {
	localIP := c.stack.serverIP
	remoteIP := c.key.remoteIP
	tcpBytes := buildTCP(nil, seg, localIP, remoteIP)
	pkt := buildIPv4(nil, localIP, remoteIP, protocolTCP, tcpBytes)
	_ = c.stack.writePacket(c.a, pkt)
}
