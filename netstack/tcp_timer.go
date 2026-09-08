// tcp_timer.go implements one retransmit timer per connection, reused
// (via Reset) as the connection's TIME_WAIT timer once it reaches that
// state — deliberately ONE Timer and ONE goroutine per connection rather
// than two, since a connection is never simultaneously retransmitting data
// and sitting in TIME_WAIT. Both are created through the stack's injected
// Clock (netstack/clock.go, plan 03-01) — NO direct use of time.NewTimer,
// time.After, time.Sleep, or time.Now anywhere in the TCP files. That is
// what makes every timer-driven behavior in this plan assertable in
// milliseconds against a fake clock rather than a real sleep.
//
// The retransmit timer's goroutine (timerLoop) writes segments directly
// through Stack.writePacket without funnelling through the per-session read
// loop — RESEARCH.md Pattern 4 verified Session.Write is safe for
// concurrent callers because internal/datachan.Wrapper.Seal holds its own
// mutex. Lock-nesting order, matching session.go's own convention: take
// c.mu around every state read/write, release it before sendSegments'
// I/O — never hold c.mu across a Write call.
package netstack

import "time"

// D-14's named, fixed constants — each cited to its RFC origin or the
// CONTEXT.md/RESEARCH.md decision that scoped it, in
// internal/reliable/reliable.go's own citation-header style.
const (
	// defaultMSS is this stack's DOCUMENTED default MSS — the value
	// Stack.maxSegmentSize returns at defaultMTU: RESEARCH.md
	// Pattern 3 — tun-mtu 1500 (ovpn.go's serverKM2Options) minus 20B
	// IPv4 minus 20B TCP, with no additional VPN-specific subtraction
	// (that overhead is already accounted for below the Session
	// boundary). The MSS actually advertised is derived from the
	// configured MTU (WithMTU), not read from here: see
	// Stack.maxSegmentSize.
	defaultMSS = 1460

	// defaultReceiveWindow is D-07's "~64KB" advertised receive window —
	// also the largest value expressible without the window-scaling
	// option this stack does not implement.
	defaultReceiveWindow = 65535

	// maxInFlightBytes is D-07's fixed in-flight cap: one window's worth,
	// with no congestion window behind it.
	maxInFlightBytes = 65535

	// defaultBacklog is RESEARCH.md Open Question #1's recommended accept
	// backlog depth — the specific number matters less than its being
	// fixed and named (T-03-14).
	defaultBacklog = 16

	// maxHalfOpenPerSession bounds in-tunnel SYN-flood state per
	// attached session (RESEARCH.md Open Question #1 and Security
	// Domain, T-03-13) — enforced PER SESSION, not stack-wide, so one
	// authenticated client cannot exhaust another's budget.
	maxHalfOpenPerSession = 8

	// maxLiveConnsPerSession bounds the number of non-CLOSED (SYN_RCVD
	// through TIME_WAIT) TCP connections one attached session may hold
	// open at once (CR-02) — independent of, and in addition to,
	// maxHalfOpenPerSession: that budget is released the instant a
	// handshake completes (tcp_state.go's handleSegment), so without this
	// separate cap a client could complete handshakes as fast as the
	// half-open budget allows and simply never close them, accumulating
	// an unbounded number of live tcpConns (each backed by its own
	// timerLoop goroutine) over time. Mirrors maxHalfOpenPerSession's own
	// per-attachment-IP scoping style, sized generously above the
	// half-open cap since legitimate long-lived connections (e.g.
	// keep-alive HTTP) are expected to accumulate up to this ceiling in
	// normal operation.
	maxLiveConnsPerSession = 64

	// maxPersistProbes bounds RFC 9293 §3.8's zero-window persist
	// retries (CR-02): past this many consecutive probes with the peer's
	// window still reported closed, the connection is reset rather than
	// probed forever — RFC 9293 does not itself mandate indefinite
	// persistence, and a permanently zero window is indistinguishable
	// from an unresponsive or hostile peer holding the connection (and
	// its timerLoop goroutine) open forever. Reset to zero whenever the
	// peer's window reopens (tcp_state.go's handleAckLocked).
	maxPersistProbes = 20

	// maxReorderSegments bounds the per-connection out-of-order buffer
	// (D-06, T-03-15) — excess out-of-order segments are dropped and
	// re-driven by the peer's own retransmission.
	maxReorderSegments = 16

	// initialRTO is D-06's fixed retransmit timeout, chosen for a
	// tunnel-quality link; doubling (see onRTOFired) covers a slow one.
	// This is a deliberate departure from RFC 6298's SRTT/RTTVAR
	// estimation, which RFC 9293 mandates for general-purpose,
	// Internet-facing TCP — CONTEXT.md scopes this stack to "tunnel-
	// quality links only," where every connection traverses one already-
	// established, homogeneous-quality VPN tunnel.
	initialRTO = 300 * time.Millisecond

	// maxRTO is the backoff ceiling.
	maxRTO = 8 * time.Second

	// maxRetransmits: past this many retransmissions of the same
	// unacknowledged data (or SYN-ACK, or FIN), the connection is reset
	// rather than retried forever (D-06/D-07 — no RFC 6298 Karn's
	// algorithm, no congestion control, just a fixed, named ceiling).
	maxRetransmits = 6

	// timeWaitDuration is D-08's "short-timer TIME_WAIT": a deliberate
	// departure from RFC 9293's conventional 2×MSL (~240s), justified
	// because this connection's path is a single point-to-point
	// encrypted tunnel link with its own replay window below this layer
	// — not a wide-area path needing to absorb stray duplicates.
	timeWaitDuration = 5 * time.Second
)

// sendPendingLocked pushes queued send-buffer bytes onto the wire, up to
// min(sendMSS, peer window, maxInFlightBytes) (D-07). If forceProbe is
// true and the peer's window is fully closed, it sends exactly one
// zero-window persist probe byte instead of returning empty-handed — RFC
// 9293 §3.8's persist behavior, needed so a closed window does not stall
// the connection forever once the peer reopens it. Called with mu held;
// appends any segment to send to *toSend without transmitting it — the
// caller sends it outside the lock.
func (c *tcpConn) sendPendingLocked(toSend *[]tcpSegment, forceProbe bool) {
	limit := c.allowedInFlightLocked()
	if limit == 0 {
		if !forceProbe || c.sentBytes >= uint32(len(c.outBuf)) {
			// Nothing can go out right now, but if data is queued
			// behind a fully-closed window, the persist timer (RFC
			// 9293 §3.8) must still be armed — otherwise nothing
			// would ever wake onRTOFired's zero-window case to probe
			// once the peer reopens the window. A Write() that lands
			// entirely inside a zero window would otherwise stall
			// forever with no timer running at all.
			if uint32(len(c.outBuf)) > c.sentBytes && !c.timerArmed {
				c.timerArmed = true
				c.rto = initialRTO
				c.rtoTimer.Reset(c.rto)
			}
			return
		}
		limit = c.sentBytes + 1
	}

	sentAny := false
	for c.sentBytes < limit && c.sentBytes < uint32(len(c.outBuf)) {
		remainingWindow := limit - c.sentBytes
		remainingData := uint32(len(c.outBuf)) - c.sentBytes
		chunk := remainingWindow
		if remainingData < chunk {
			chunk = remainingData
		}
		if uint32(c.sndMSS) < chunk {
			chunk = uint32(c.sndMSS)
		}
		if chunk == 0 {
			break
		}

		seq := c.sndUna + c.sentBytes
		data := append([]byte(nil), c.outBuf[c.sentBytes:c.sentBytes+chunk]...)
		seg := tcpSegment{
			srcPort: c.key.localPort,
			dstPort: c.key.remotePort,
			seq:     seq,
			ack:     c.rcvNxt,
			flags:   flagACK,
			window:  c.advertisedWindowLocked(),
			payload: data,
		}
		*toSend = append(*toSend, seg)
		c.sentBytes += chunk
		sentAny = true

		if forceProbe {
			break
		}
	}

	if sentAny && !forceProbe {
		c.rto = initialRTO
		c.retransmitCount = 0
		c.timerArmed = true
		c.rtoTimer.Reset(c.rto)
	}
}

// stopTimersLocked stops the retransmit/TIME_WAIT timer and closes
// stopTimers exactly once, signaling timerLoop to exit at its next select.
// Called with mu held from every terminal-state transition (RST received,
// max retransmits exceeded, LAST_ACK's own FIN-ACK, TIME_WAIT release,
// listener/backlog abort, session detach).
func (c *tcpConn) stopTimersLocked() {
	c.rtoTimer.Stop()
	if !c.stopTimersClosed {
		c.stopTimersClosed = true
		close(c.stopTimers)
	}
}

// startTimeWaitLocked repurposes this connection's single Timer as its
// TIME_WAIT timer (D-08's short-timer TIME_WAIT) rather than spawning a
// second goroutine — only one of "retransmitting" and "waiting out
// TIME_WAIT" is ever true for a given connection. Called with mu held.
func (c *tcpConn) startTimeWaitLocked() {
	c.state = stateTimeWait
	c.inTimeWait = true
	c.timerArmed = true
	c.rtoTimer.Reset(timeWaitDuration)
}

// timerLoop is the one goroutine per connection (half-open or established)
// that owns this connection's Timer, started immediately after the
// connection is created (tcp_listener.go's handleSYN). It exits either when
// the connection reaches a terminal state (stopTimers closes) or when the
// owning session is detached (a.stopCh closes) — whichever happens first —
// and signals its own exit by closing timerDone, so tests can assert "no
// timer goroutine left behind" via a done channel rather than a sleep or a
// runtime.NumGoroutine poll.
func (c *tcpConn) timerLoop() {
	defer close(c.timerDone)
	for {
		select {
		case <-c.rtoTimer.C():
			c.onRTOFired()
		case <-c.a.stopCh:
			c.onAttachmentDetached()
			return
		case <-c.stopTimers:
			return
		}
	}
}

// onRTOFired fires on every Timer expiry: TIME_WAIT release, SYN-ACK
// retransmission (SYN_RCVD), data retransmission, FIN retransmission, or a
// zero-window persist probe — whichever applies to the connection's current
// state. Past maxRetransmits it resets the connection (an RST to the peer,
// a sticky error for Read/Write, and full teardown) rather than retrying
// forever (D-06/D-07).
func (c *tcpConn) onRTOFired() {
	c.mu.Lock()

	if c.state == stateClosed {
		c.mu.Unlock()
		return
	}

	if c.inTimeWait {
		c.state = stateClosed
		c.stopTimersLocked()
		c.broadcastLocked()
		c.mu.Unlock()
		c.demux.removeConn(c)
		return
	}

	var toSend []tcpSegment
	giveUp := false

	switch {
	case c.state == stateSynRcvd:
		c.retransmitCount++
		if c.retransmitCount > maxRetransmits {
			giveUp = true
			break
		}
		c.rto = doubleRTO(c.rto)
		c.rtoTimer.Reset(c.rto)
		toSend = append(toSend, tcpSegment{
			srcPort: c.key.localPort,
			dstPort: c.key.remotePort,
			seq:     c.sndUna,
			ack:     c.rcvNxt,
			flags:   flagSYN | flagACK,
			window:  c.advertisedWindowLocked(),
			hasMSS:  true,
			mss:     c.stack.maxSegmentSize(),
		})

	case c.sentBytes > 0:
		c.retransmitCount++
		if c.retransmitCount > maxRetransmits {
			giveUp = true
			break
		}
		chunk := c.sentBytes
		if uint32(c.sndMSS) < chunk {
			chunk = uint32(c.sndMSS)
		}
		data := append([]byte(nil), c.outBuf[:chunk]...)
		c.rto = doubleRTO(c.rto)
		c.rtoTimer.Reset(c.rto)
		toSend = append(toSend, tcpSegment{
			srcPort: c.key.localPort,
			dstPort: c.key.remotePort,
			seq:     c.sndUna,
			ack:     c.rcvNxt,
			flags:   flagACK,
			window:  c.advertisedWindowLocked(),
			payload: data,
		})

	case c.finSent && !c.finAcked:
		c.retransmitCount++
		if c.retransmitCount > maxRetransmits {
			giveUp = true
			break
		}
		c.rto = doubleRTO(c.rto)
		c.rtoTimer.Reset(c.rto)
		toSend = append(toSend, tcpSegment{
			srcPort: c.key.localPort,
			dstPort: c.key.remotePort,
			seq:     c.finSeq,
			ack:     c.rcvNxt,
			flags:   flagFIN | flagACK,
			window:  c.advertisedWindowLocked(),
		})

	case c.sndWnd == 0 && uint32(len(c.outBuf)) > c.sentBytes:
		// Zero-window persist (RFC 9293 §3.8): exactly one probe byte
		// per tick, never a burst — a spin here would saturate the
		// tunnel with a client that is merely slow, not gone. Bounded by
		// maxPersistProbes (CR-02) so a peer that never reopens its
		// window cannot hold this connection (and its timerLoop
		// goroutine) open indefinitely.
		c.persistProbeCount++
		if c.persistProbeCount > maxPersistProbes {
			giveUp = true
			break
		}
		c.sendPendingLocked(&toSend, true)
		c.rtoTimer.Reset(c.rto)

	default:
		c.timerArmed = false
	}

	if giveUp {
		rst := tcpSegment{
			srcPort: c.key.localPort,
			dstPort: c.key.remotePort,
			seq:     c.sndUna + c.sentBytes,
			ack:     c.rcvNxt,
			flags:   flagRST | flagACK,
		}
		c.err = ErrTCPConnReset
		c.state = stateClosed
		c.stopTimersLocked()
		c.broadcastLocked()
		c.mu.Unlock()
		c.demux.removeConn(c)
		c.sendSegments([]tcpSegment{rst})
		c.demux.stats.rstsSent.Add(1)
		return
	}

	c.mu.Unlock()
	if len(toSend) > 0 {
		c.sendSegments(toSend)
	}
}

// doubleRTO doubles d, capped at maxRTO (D-06's fixed backoff, mirroring
// internal/reliable.Due's own best.timeout *= 2 shape).
func doubleRTO(d time.Duration) time.Duration {
	d *= 2
	if d > maxRTO {
		d = maxRTO
	}
	return d
}

// onAttachmentDetached runs when the owning session's attachment is
// detached (Stack.Detach, or the session's own Read returning an error)
// while this connection is still live: it tears the connection down and
// releases its state exactly like an inbound RST would, without attempting
// to write to a session that may already be gone.
func (c *tcpConn) onAttachmentDetached() {
	c.mu.Lock()
	if c.state == stateClosed {
		c.mu.Unlock()
		return
	}
	c.err = ErrTCPConnReset
	c.state = stateClosed
	c.stopTimersLocked()
	c.broadcastLocked()
	c.mu.Unlock()
	c.demux.removeConn(c)
}

// abort tears this connection down locally — used when a completed
// connection cannot be queued into a full accept backlog, or when its
// listener is closed while the connection still sits unaccepted in that
// backlog. It sends an RST so the peer is not left waiting on a connection
// this stack has silently abandoned (D-08: "browsers must not hang").
func (c *tcpConn) abort() {
	c.mu.Lock()
	if c.state == stateClosed {
		c.mu.Unlock()
		return
	}
	rst := tcpSegment{
		srcPort: c.key.localPort,
		dstPort: c.key.remotePort,
		seq:     c.sndUna + c.sentBytes,
		ack:     c.rcvNxt,
		flags:   flagRST | flagACK,
	}
	c.err = ErrTCPConnReset
	c.state = stateClosed
	c.stopTimersLocked()
	c.broadcastLocked()
	c.mu.Unlock()
	c.demux.removeConn(c)
	c.sendSegments([]tcpSegment{rst})
	c.demux.stats.rstsSent.Add(1)
}
