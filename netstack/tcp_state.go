// tcp_state.go implements RFC 9293 §3.5 (connection establishment/RST
// generation) and §3.6 (closing a connection)'s state transitions for one
// tcpConn, plus the §3.5.2 RST-generation rules shared with the demux's
// no-connection paths in tcp_listener.go.
//
// tcpState carries exactly the states D-05 scopes: LISTEN (held by the
// listener itself, not represented here as a tcpConn state), SYN_RCVD,
// ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSING, TIME_WAIT, CLOSE_WAIT,
// LAST_ACK, CLOSED. There is NO SYN_SENT and no active-open handling — this
// is a server-side-accept-only stack (D-05): a reader who knows RFC 9293
// will notice the absence of SYN_SENT and should find this comment next to
// it, not mistake it for an oversight.
package netstack

// tcpState is one connection's position in the (deliberately narrowed)
// state machine.
type tcpState int

const (
	// stateListen is never assigned to a tcpConn — LISTEN is the
	// listener's own state, represented by a *tcpListener existing in
	// tcpDemux.listeners, not by any tcpConn. Kept here only so the state
	// constant block reads as a complete, deliberately-scoped RFC 9293
	// table (D-05's own "no SYN_SENT" comment lives beside this one).
	stateListen tcpState = iota
	stateSynRcvd
	stateEstablished
	stateFinWait1
	stateFinWait2
	stateClosing
	stateTimeWait
	stateCloseWait
	stateLastAck
	stateClosed
)

// seqGT/seqGE report wraparound-safe 32-bit sequence-number comparisons
// (RFC 9293's own convention: compare via signed difference, not `<`/`>`,
// so a sequence space wraparound near 2^32 does not silently misorder).
func seqGT(a, b uint32) bool { return int32(a-b) > 0 }
func seqGE(a, b uint32) bool { return int32(a-b) >= 0 }

// buildRSTSegment implements RFC 9293 §3.5.2's two Reset Generation cases
// for an offending segment addressed to no live connection (or, from
// handleSegment's SYN_RCVD branch below, a handshake-completing ACK with
// the wrong acknowledgement number): if the offending segment carried ACK,
// the RST carries SEG.ACK as its own sequence and does not set ACK; if it
// did not, the RST carries sequence 0 and acknowledges SEG.SEQ+SEG.LEN with
// ACK set. Never call this for an offending segment that is itself an RST
// — that is the classic reset loop (checked by both call sites before
// reaching here).
func buildRSTSegment(offending tcpSegment) tcpSegment {
	rst := tcpSegment{
		srcPort: offending.dstPort,
		dstPort: offending.srcPort,
		flags:   flagRST,
	}
	if offending.flags&flagACK != 0 {
		rst.seq = offending.ack
	} else {
		rst.seq = 0
		rst.ack = offending.seq + offending.segLen()
		rst.flags |= flagACK
	}
	return rst
}

// rstInWindowLocked reports whether an inbound RST's sequence number falls
// within RFC 9293 §3.10.7.4's acceptable range for this connection's own
// receive window (WR-03) — the classic blind-reset mitigation. A zero
// receive window still accepts an RST whose sequence exactly matches
// rcvNxt, mirroring the same "zero window probe" special case RFC 9293
// §3.4's general segment-acceptability test uses for zero-length segments
// against a zero window (an empty range would otherwise reject even the
// single sequence number a well-behaved peer could legitimately reset
// from). Called with mu held.
func (c *tcpConn) rstInWindowLocked(seg tcpSegment) bool {
	wnd := uint32(c.advertisedWindowLocked())
	if wnd == 0 {
		return seg.seq == c.rcvNxt
	}
	return seqGE(seg.seq, c.rcvNxt) && seqGT(c.rcvNxt+wnd, seg.seq)
}

// handleSegment is tcpConn's single entry point for an inbound segment
// already routed to it by the 4-tuple demux (tcp_listener.go). It takes
// c.mu for the whole state evaluation, decides what (if anything) to
// transmit and whether the connection must be torn down, then releases the
// lock before any of that I/O — sendSegments/demux calls never happen while
// c.mu is held.
func (c *tcpConn) handleSegment(seg tcpSegment) {
	c.mu.Lock()

	if seg.flags&flagRST != 0 {
		// WR-03: RFC 9293 §3.10.7.4 requires validating an inbound RST's
		// sequence number falls within the receive window before
		// accepting it (the classic blind-reset mitigation) — this stack
		// previously tore the connection down for ANY inbound RST
		// regardless of SEG.SEQ. Dispatch already restricts a segment's
		// 4-tuple to the session that owns this connection (spoofed
		// source IPs are dropped in Stack.deliver before reaching here),
		// so the practical blast radius was limited to a peer resetting
		// its own connection out of sequence — but it is still a spec
		// deviation worth closing, especially if this code is ever reused
		// behind a less-restrictive dispatch boundary.
		if !c.rstInWindowLocked(seg) {
			c.mu.Unlock()
			return
		}
		c.demux.stats.rstsReceived.Add(1)
		c.err = ErrTCPConnReset
		c.state = stateClosed
		c.stopTimersLocked()
		c.broadcastLocked()
		c.mu.Unlock()
		c.demux.removeConn(c)
		return
	}

	var toSend []tcpSegment
	var enqueueToListener bool
	var removeConn bool

	switch c.state {
	case stateSynRcvd:
		if seg.flags&flagACK == 0 || seg.ack != c.sndUna+1 {
			rst := buildRSTSegment(seg)
			c.state = stateClosed
			c.stopTimersLocked()
			// WR-03: every other terminal-state transition in this file
			// (and in tcp_timer.go) calls broadcastLocked() before
			// unlocking — this branch didn't. Currently harmless (a
			// SYN_RCVD connection has never been handed to an
			// application, so no Read/Write caller can be blocked on
			// notifyCh yet), but a later change exposing pre-Accept
			// connection state to a waiter would otherwise silently
			// reintroduce a missed-wakeup bug here.
			c.broadcastLocked()
			c.mu.Unlock()
			c.demux.removeConn(c)
			c.sendSegments([]tcpSegment{rst})
			c.demux.stats.rstsSent.Add(1)
			return
		}
		c.sndUna = seg.ack
		c.state = stateEstablished
		// The SYN-ACK is now acknowledged; no data is outstanding yet.
		c.rtoTimer.Stop()
		c.timerArmed = false
		c.handleEstablishedDataLocked(seg, &toSend)
		enqueueToListener = true

	case stateEstablished:
		c.handleAckLocked(seg, &toSend)
		if c.handleEstablishedDataLocked(seg, &toSend) {
			c.state = stateCloseWait
		}

	case stateFinWait1:
		c.handleAckLocked(seg, &toSend)
		finConsumed := c.handleEstablishedDataLocked(seg, &toSend)
		switch {
		case finConsumed && c.finAcked:
			c.startTimeWaitLocked()
		case finConsumed:
			c.state = stateClosing
		case c.finAcked:
			c.state = stateFinWait2
		}

	case stateFinWait2:
		c.handleAckLocked(seg, &toSend)
		if c.handleEstablishedDataLocked(seg, &toSend) {
			c.startTimeWaitLocked()
		}

	case stateClosing:
		c.handleAckLocked(seg, &toSend)
		if c.finAcked {
			c.startTimeWaitLocked()
		}

	case stateCloseWait:
		c.handleAckLocked(seg, &toSend)

	case stateLastAck:
		c.handleAckLocked(seg, &toSend)
		if c.finAcked {
			c.state = stateClosed
			c.stopTimersLocked()
			removeConn = true
		}

	case stateTimeWait:
		// A duplicate/retransmitted peer FIN in TIME_WAIT is re-acked,
		// not treated as a new event (RFC 9293 §3.10.7's own TIME-WAIT
		// handling: re-ack and restart nothing else).
		if seg.flags&flagFIN != 0 {
			toSend = append(toSend, c.buildACKLocked())
		}

	case stateClosed:
		// Nothing further to do; a stray segment for an already-closed
		// connection is dropped (its 4-tuple should already be gone
		// from the demux, so this is only reachable via a narrow race).
	}

	c.broadcastLocked()
	c.mu.Unlock()

	if enqueueToListener {
		c.demux.releaseHalfOpen(c)
		c.listener.enqueue(c)
	}
	if removeConn {
		c.demux.removeConn(c)
	}
	if len(toSend) > 0 {
		c.sendSegments(toSend)
	}
}

// handleAckLocked processes the send-side effect of an inbound ACK: it
// retires acknowledged bytes (and, if covered, this connection's own FIN)
// from outBuf, resets the retransmit backoff on any new progress, records
// the peer's newly-advertised window, and attempts to push more queued data
// now that the window may have moved (D-06/D-07). Called with mu held; may
// append to *toSend via sendPendingLocked.
func (c *tcpConn) handleAckLocked(seg tcpSegment, toSend *[]tcpSegment) {
	if seg.flags&flagACK == 0 {
		return
	}
	ackNum := seg.ack

	if c.sentBytes > 0 {
		maxCovered := c.sndUna + c.sentBytes
		if seqGT(ackNum, c.sndUna) {
			covered := ackNum
			if seqGT(covered, maxCovered) {
				covered = maxCovered
			}
			amount := covered - c.sndUna
			if amount > 0 {
				c.outBuf = c.outBuf[amount:]
				c.sentBytes -= amount
				c.sndUna = covered
				c.retransmitCount = 0
				c.rto = initialRTO
				if c.sentBytes == 0 {
					c.rtoTimer.Stop()
					c.timerArmed = false
				} else {
					c.timerArmed = true
					c.rtoTimer.Reset(c.rto)
				}
				c.broadcastLocked()
			}
		}
	}

	if c.finSent && !c.finAcked && seqGE(ackNum, c.finSeq+1) {
		c.finAcked = true
		if c.sentBytes == 0 {
			c.rtoTimer.Stop()
			c.timerArmed = false
		}
	}

	if c.sndWnd == 0 && seg.window > 0 {
		// CR-02: the peer's window reopened — a fresh zero-window
		// episode (if the peer closes it again later) should get its
		// own maxPersistProbes budget, not inherit an already-exhausted
		// one.
		c.persistProbeCount = 0
	}
	c.sndWnd = uint32(seg.window)
	c.sendPendingLocked(toSend, false)
}

// handleEstablishedDataLocked processes the receive-side effect of an
// inbound segment carrying data and/or FIN: in-order bytes are appended to
// recvBuf and rcvNxt advances; out-of-order-but-in-window segments are
// buffered (bounded at maxReorderSegments, T-03-15) and re-driven once the
// gap fills; segments wholly below rcvNxt are duplicates, absorbed with a
// re-ack. Acknowledges every in-order/duplicate/out-of-order data-or-FIN
// segment immediately (this plan's own documented simplification: no
// delayed-ACK timer). Returns whether the peer's FIN was newly consumed
// this call — the caller uses this to drive its own CLOSE_WAIT/CLOSING/
// TIME_WAIT transition. Called with mu held.
func (c *tcpConn) handleEstablishedDataLocked(seg tcpSegment, toSend *[]tcpSegment) (finConsumed bool) {
	dataLen := uint32(len(seg.payload))
	consumesSeq := dataLen > 0 || seg.flags&flagFIN != 0
	if !consumesSeq {
		return false
	}

	switch {
	case seg.seq == c.rcvNxt:
		// CR-01: admission is clamped to what this stack itself last
		// advertised (recvWindowRemainingLocked), not just appended
		// unconditionally — a peer that ignores the advertised window
		// (compromised client, buggy stack, or an application that never
		// drains Read) can otherwise grow recvBuf without bound. Bytes
		// beyond the remaining window are dropped, exactly as if they had
		// never arrived; the peer's own retransmission timer redelivers
		// them once the application drains enough of recvBuf to reopen
		// the window (mirroring how sendPendingLocked already clamps the
		// send side to allowedInFlightLocked()).
		fullyAccepted := dataLen == 0
		if dataLen > 0 {
			avail := c.recvWindowRemainingLocked()
			accept := dataLen
			if accept > avail {
				accept = avail
			}
			if accept > 0 {
				c.recvBuf = append(c.recvBuf, seg.payload[:accept]...)
				c.rcvNxt += accept
			}
			fullyAccepted = accept == dataLen
		}
		// Only drain reordered segments once this segment's own data was
		// fully admitted — draining while this segment was itself
		// truncated for lack of room would immediately re-exceed the
		// same window this branch just enforced.
		if fullyAccepted {
			for {
				data, ok := c.reorder[c.rcvNxt]
				if !ok {
					break
				}
				if uint32(len(data)) > c.recvWindowRemainingLocked() {
					break
				}
				delete(c.reorder, c.rcvNxt)
				c.recvBuf = append(c.recvBuf, data...)
				c.rcvNxt += uint32(len(data))
			}
			if seg.flags&flagFIN != 0 && seg.seq+dataLen == c.rcvNxt {
				c.rcvNxt++
				c.peerClosed = true
				finConsumed = true
			} else if c.hasPendingFIN && c.rcvNxt == c.pendingFINSeq {
				c.rcvNxt++
				c.peerClosed = true
				c.hasPendingFIN = false
				finConsumed = true
			}
		}
		*toSend = append(*toSend, c.buildACKLocked())
		c.broadcastLocked()
		return finConsumed

	case seqGT(seg.seq, c.rcvNxt):
		if _, exists := c.reorder[seg.seq]; !exists {
			if uint32(len(c.reorder)) >= maxReorderSegments || dataLen > c.recvWindowRemainingLocked() {
				c.demux.stats.reorderDropped.Add(1)
				*toSend = append(*toSend, c.buildACKLocked())
				return false
			}
			c.reorder[seg.seq] = append([]byte(nil), seg.payload...)
			if seg.flags&flagFIN != 0 {
				c.hasPendingFIN = true
				c.pendingFINSeq = seg.seq + dataLen
			}
		}
		*toSend = append(*toSend, c.buildACKLocked())
		return false

	default:
		// seg.seq < rcvNxt: a duplicate, wholly or partially already
		// consumed. Absorb it and re-emit the current cumulative ACK
		// so the peer's own retransmission timer stops promptly.
		*toSend = append(*toSend, c.buildACKLocked())
		return false
	}
}

// releaseHalfOpen and removeConn are tcpDemux methods (tcp_listener.go),
// called above once a SYN_RCVD connection resolves (established) or is
// torn down — kept there because they mutate tcpDemux's own maps under
// demux.mu, a lock this file never otherwise touches.
