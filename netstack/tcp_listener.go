// tcp_listener.go implements Stack.ListenTCP (D-01), the shared TCP
// 4-tuple demux registered into plan 03-01's protocolHandler seam exactly
// once per Stack (so plan 03-02's UDP work and this plan can each build in
// wave 2 without either touching stack.go), and the two denial-of-service
// bounds RESEARCH.md's Open Question #1 calls for: the accept backlog
// (defaultBacklog) and the per-session half-open (SYN_RCVD) cap
// (maxHalfOpenPerSession, T-03-13).
//
// New TCP-specific counters (backlog overflow, half-open cap hits,
// reorder-buffer drops, RSTs sent/received) live in tcpDemuxStats here,
// exposed via Stack.TCPStats — a new method on the existing *Stack type,
// added from this file rather than stack.go, so this plan touches no file
// plan 03-02 touches in the same wave (frontmatter files_modified excludes
// stack.go on purpose).
package netstack

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
)

// tcpDemuxStats holds the demux's own atomic counters — separate from
// Stack's own private stats struct (stack.go), which this plan does not
// modify.
type tcpDemuxStats struct {
	backlogOverflow atomic.Uint64
	halfOpenCapHits atomic.Uint64
	liveConnCapHits atomic.Uint64
	reorderDropped  atomic.Uint64
	rstsSent        atomic.Uint64
	rstsReceived    atomic.Uint64
}

// TCPStats is a point-in-time snapshot of the TCP demux's own drop/RST
// counters, returned by Stack.TCPStats().
type TCPStats struct {
	BacklogOverflow uint64
	HalfOpenCapHits uint64
	LiveConnCapHits uint64
	ReorderDropped  uint64
	RSTsSent        uint64
	RSTsReceived    uint64
}

// TCPStats returns a point-in-time snapshot of the stack's TCP-specific
// counters. It returns a zero-value TCPStats if ListenTCP has never been
// called on this Stack (no demux registered yet).
func (s *Stack) TCPStats() TCPStats {
	s.mu.RLock()
	d, _ := s.tcpHandler.(*tcpDemux)
	s.mu.RUnlock()
	if d == nil {
		return TCPStats{}
	}
	return TCPStats{
		BacklogOverflow: d.stats.backlogOverflow.Load(),
		HalfOpenCapHits: d.stats.halfOpenCapHits.Load(),
		LiveConnCapHits: d.stats.liveConnCapHits.Load(),
		ReorderDropped:  d.stats.reorderDropped.Load(),
		RSTsSent:        d.stats.rstsSent.Load(),
		RSTsReceived:    d.stats.rstsReceived.Load(),
	}
}

// tcpDemux is the single protocolHandler every TCP-carrying packet reaches
// (registered once per Stack, shared across every ListenTCP'd port): it
// looks up a 4-tuple to find a live connection, and on a miss either starts
// a new half-open connection (a SYN to a listening port, bounded by
// maxHalfOpenPerSession) or answers with an RFC 9293 §3.5.2 RST.
type tcpDemux struct {
	stack *Stack

	mu        sync.Mutex
	listeners map[uint16]*tcpListener
	conns     map[fourTuple]*tcpConn
	halfOpen  map[netip.Addr]int // per-session (by remote/attachment IP) half-open count, T-03-13
	liveConns map[netip.Addr]int // per-session live (non-CLOSED) connection count, CR-02

	stats tcpDemuxStats
}

var _ protocolHandler = (*tcpDemux)(nil)

func newTCPDemux(s *Stack) *tcpDemux {
	return &tcpDemux{
		stack:     s,
		listeners: make(map[uint16]*tcpListener),
		conns:     make(map[fourTuple]*tcpConn),
		halfOpen:  make(map[netip.Addr]int),
		liveConns: make(map[netip.Addr]int),
	}
}

// tcpListener is the net.Listener ListenTCP returns: an accept queue of up
// to defaultBacklog completed connections, backed by the shared tcpDemux.
type tcpListener struct {
	stack *Stack
	demux *tcpDemux
	port  uint16

	localAddr *net.TCPAddr

	mu      sync.Mutex
	closed  bool
	backlog chan *tcpConn
	closeCh chan struct{}
}

var _ net.Listener = (*tcpListener)(nil)

// ListenTCP registers (on first call for this Stack) the shared TCP 4-tuple
// demux into plan 03-01's protocolHandler seam, then opens a listener on
// port — D-01's public API shape. port 0 and an already-bound port are
// rejected with typed errors.
func (s *Stack) ListenTCP(port uint16) (net.Listener, error) {
	if port == 0 {
		return nil, ErrTCPPortZero
	}

	s.mu.Lock()
	d, _ := s.tcpHandler.(*tcpDemux)
	if d == nil {
		d = newTCPDemux(s)
		s.tcpHandler = d
	}
	s.mu.Unlock()

	return d.listen(port)
}

func (d *tcpDemux) listen(port uint16) (net.Listener, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, exists := d.listeners[port]; exists {
		return nil, ErrTCPPortInUse
	}

	l := &tcpListener{
		stack:     d.stack,
		demux:     d,
		port:      port,
		localAddr: &net.TCPAddr{IP: d.stack.ServerIP(), Port: int(port)},
		backlog:   make(chan *tcpConn, defaultBacklog),
		closeCh:   make(chan struct{}),
	}
	d.listeners[port] = l
	return l, nil
}

func (d *tcpDemux) removeListener(port uint16) {
	d.mu.Lock()
	delete(d.listeners, port)
	d.mu.Unlock()
}

// removeConn removes c from the demux's connection table (a no-op if c has
// already been removed, or superseded by a newer connection at the same
// 4-tuple) and releases any half-open budget it was still holding.
func (d *tcpDemux) removeConn(c *tcpConn) {
	d.mu.Lock()
	if cur, ok := d.conns[c.key]; ok && cur == c {
		delete(d.conns, c.key)
	}
	d.mu.Unlock()
	d.releaseHalfOpen(c)
	d.releaseLiveConn(c)
}

// releaseHalfOpen decrements c's session's half-open count exactly once,
// the first time it is called for c (guarded by c.halfOpenCounted so a
// connection that later fails again after already being released — e.g.
// removeConn called from two different teardown paths in a race — does not
// double-decrement).
func (d *tcpDemux) releaseHalfOpen(c *tcpConn) {
	c.mu.Lock()
	counted := c.halfOpenCounted
	c.halfOpenCounted = false
	ip := c.halfOpenIP
	c.mu.Unlock()
	if !counted {
		return
	}

	d.mu.Lock()
	if n, ok := d.halfOpen[ip]; ok {
		if n <= 1 {
			delete(d.halfOpen, ip)
		} else {
			d.halfOpen[ip] = n - 1
		}
	}
	d.mu.Unlock()
}

// releaseLiveConn decrements c's session's live-connection count exactly
// once (CR-02), the first time it is called for c — guarded by
// c.liveCounted mirroring releaseHalfOpen's own idempotency discipline.
// Unlike releaseHalfOpen, this is only ever called from removeConn: a
// completed handshake does not free this budget, only the connection's
// final teardown does.
func (d *tcpDemux) releaseLiveConn(c *tcpConn) {
	c.mu.Lock()
	counted := c.liveCounted
	c.liveCounted = false
	ip := c.halfOpenIP
	c.mu.Unlock()
	if !counted {
		return
	}

	d.mu.Lock()
	if n, ok := d.liveConns[ip]; ok {
		if n <= 1 {
			delete(d.liveConns, ip)
		} else {
			d.liveConns[ip] = n - 1
		}
	}
	d.mu.Unlock()
}

// handlePacket implements protocolHandler: it demuxes seg by 4-tuple to a
// live connection, or — on a miss — either starts a new half-open
// connection (SYN to a listening port, within the per-session half-open
// budget) or answers with an RFC 9293 §3.5.2 RST. Never responds to an RST
// with an RST (the classic reset loop).
func (d *tcpDemux) handlePacket(a *attachment, src, dst netip.Addr, payload []byte) {
	seg, err := parseTCP(payload)
	if err != nil {
		d.stack.stats.malformedDropped.Add(1)
		return
	}

	key := fourTuple{remoteIP: src, remotePort: seg.srcPort, localPort: seg.dstPort}

	d.mu.Lock()
	conn, ok := d.conns[key]
	d.mu.Unlock()
	if ok {
		conn.handleSegment(seg)
		return
	}

	if seg.flags&flagRST != 0 {
		return
	}

	if seg.flags&flagSYN != 0 && seg.flags&flagACK == 0 {
		d.mu.Lock()
		l, exists := d.listeners[seg.dstPort]
		d.mu.Unlock()
		if !exists {
			d.sendRST(a, dst, src, seg)
			return
		}
		l.handleSYN(a, src, seg)
		return
	}

	d.sendRST(a, dst, src, seg)
}

// sendRST builds and transmits an RFC 9293 §3.5.2-shaped RST for an
// offending segment addressed to no live connection, through the stack's
// single outbound seam (D-04's fail-closed check applies to it exactly
// like any other outbound packet).
func (d *tcpDemux) sendRST(a *attachment, localIP, remoteIP netip.Addr, seg tcpSegment) {
	rst := buildRSTSegment(seg)
	tcpBytes := buildTCP(nil, rst, localIP, remoteIP)
	pkt := buildIPv4(nil, localIP, remoteIP, protocolTCP, tcpBytes)
	_ = d.stack.writePacket(a, pkt)
	d.stats.rstsSent.Add(1)
}

// handleSYN handles a SYN addressed to l's port with no existing
// connection state: bounded by maxHalfOpenPerSession (per attachment IP,
// T-03-13 — isolating one client's SYN flood from every other attached
// session), it draws a fresh server ISN, creates a half-open connection,
// starts its timer goroutine, and sends the SYN-ACK.
func (l *tcpListener) handleSYN(a *attachment, remoteIP netip.Addr, seg tcpSegment) {
	d := l.demux

	// l.closed is guarded by l.mu (the same lock Close/enqueue use for
	// it), a DIFFERENT lock from d.mu below which guards the demux's own
	// halfOpen/conns maps — reading it under d.mu instead would be a
	// data race with Close's l.mu.Lock() write.
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return
	}

	d.mu.Lock()
	if d.halfOpen[remoteIP] >= maxHalfOpenPerSession {
		d.mu.Unlock()
		d.stats.halfOpenCapHits.Add(1)
		return
	}
	// CR-02: a session that completes handshakes as fast as the
	// half-open budget allows (refilled the instant each one succeeds,
	// tcp_state.go's handleSegment) and never closes them would otherwise
	// accumulate an unbounded number of live connections — check this
	// cap alongside the half-open one, under the same lock, before either
	// counter is incremented.
	if d.liveConns[remoteIP] >= maxLiveConnsPerSession {
		d.mu.Unlock()
		d.stats.liveConnCapHits.Add(1)
		return
	}
	d.halfOpen[remoteIP]++
	d.liveConns[remoteIP]++
	d.mu.Unlock()

	mss := uint16(defaultMSSWhenAbsent)
	if seg.hasMSS {
		mss = seg.mss
		if ourMSS := d.stack.maxSegmentSize(); mss > ourMSS {
			mss = ourMSS
		}
	}

	isn := randomISN()
	key := fourTuple{remoteIP: remoteIP, remotePort: seg.srcPort, localPort: seg.dstPort}
	c := newTCPConn(d, l, a, key, isn, seg.seq, seg.window, mss)
	c.halfOpenCounted = true
	c.halfOpenIP = remoteIP
	c.liveCounted = true

	d.mu.Lock()
	d.conns[key] = c
	d.mu.Unlock()

	c.mu.Lock()
	synack := tcpSegment{
		srcPort: key.localPort,
		dstPort: key.remotePort,
		seq:     c.sndUna,
		ack:     c.rcvNxt,
		flags:   flagSYN | flagACK,
		window:  c.advertisedWindowLocked(),
		hasMSS:  true,
		mss:     d.stack.maxSegmentSize(),
	}
	c.mu.Unlock()

	go c.timerLoop()
	c.sendOne(synack)
}

// enqueue delivers a newly-ESTABLISHED connection into l's accept queue.
// If the queue is already full (defaultBacklog completed connections
// awaiting Accept) or l has been closed, c is reset (aborted) rather than
// queued unboundedly or delivered to a closed listener (T-03-14) — this
// runs on the stack's single per-session read-loop goroutine by way of
// handleSegment, so it must never block.
//
// WR-01: the closed-check and the (non-blocking) backlog send happen
// under the SAME l.mu critical section Close uses to set l.closed —
// previously the check and the send were two separate steps with the
// lock released in between, so Close could observe an empty backlog and
// return right as a concurrent enqueue's check-then-send raced in behind
// it, leaving a connection queued in a channel Close had already finished
// draining and that no future Accept would ever read from again (Accept
// had already unblocked via closeCh). Holding l.mu across both steps
// forces a total order between the two: any enqueue call either completes
// entirely before Close observes/sets l.closed (so Close's subsequent
// drain loop is guaranteed to see it in the backlog), or entirely after
// (so it observes l.closed already true and aborts without sending).
func (l *tcpListener) enqueue(c *tcpConn) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		c.abort()
		return
	}
	select {
	case l.backlog <- c:
		l.mu.Unlock()
	default:
		l.mu.Unlock()
		c.abort()
		l.demux.stats.backlogOverflow.Add(1)
	}
}

// Accept blocks until a completed connection is available or the listener
// is closed.
func (l *tcpListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.backlog:
		if !ok {
			return nil, ErrTCPListenerClosed
		}
		return c, nil
	case <-l.closeCh:
		return nil, ErrTCPListenerClosed
	}
}

// Close removes l from the demux (so a future SYN to this port draws a
// "no listener" RST), unblocks any goroutine blocked in Accept, and resets
// every connection still sitting in the backlog that was never accepted
// (T-03-14/T-03-18).
func (l *tcpListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	l.demux.removeListener(l.port)
	close(l.closeCh)

	for {
		select {
		case c := <-l.backlog:
			c.abort()
		default:
			return nil
		}
	}
}

// Addr returns the listening *net.TCPAddr.
func (l *tcpListener) Addr() net.Addr { return l.localAddr }

// String satisfies fmt.Stringer for nicer test failure output; not part of
// net.Listener.
func (l *tcpListener) String() string {
	return fmt.Sprintf("tcpListener(%s)", l.localAddr)
}
