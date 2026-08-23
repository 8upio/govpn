// Package ctrlconn implements the OpenVPN control channel as a net.Conn:
// outbound crypto/tls ciphertext is fragmented into tls-crypt-wrapped
// control packets driven by a send-side reliable.Reliable window, and
// inbound ciphertext is reassembled from a receive-side reliable.Reliable's
// strictly in-order delivery. Because reassembly is implicit in ordered
// delivery, there is no separate fragmentation header on the wire —
// concatenating in-order payloads IS TLS record reassembly (01-RESEARCH.md
// Pattern 4).
//
// This is the architectural seam the whole phase rests on: putting stdlib
// crypto/tls unmodified on top of Conn via tls.Server(conn, cfg) is the
// project's central bet that OpenVPN's control-channel framing can be
// expressed as an ordinary net.Conn.
package ctrlconn

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/8upio/govpn/internal/reliable"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

const (
	// MaxPayload: 01-RESEARCH.md Pattern 4 — tls-mtu 1250 minus tls-crypt
	// overhead 56 (8-byte packet-id + 32-byte tag + 16-byte block/IV, per
	// tls_crypt_buf_overhead()) minus a 3-byte opcode/length allowance
	// minus ACK_SIZE(RELIABLE_ACK_SIZE=8) 41 bytes (1 + 8-byte session id
	// + 4*8 packet ids) = 1250 - 56 - 3 - 41 = 1150 bytes of control
	// payload per outgoing datagram, at most.
	MaxPayload = 1150
)

// retransmitInterval is how often the background retransmit loop checks
// for send-side entries that have become due. It is unrelated to any
// reference constant — the reference's event loop wakes exactly when the
// earliest entry is due (reliable_send_timeout); polling on a short,
// fixed interval is a simpler, adequately-precise Go equivalent given
// TLSTimeout's 2-second granularity.
const retransmitInterval = 100 * time.Millisecond

// Transport is the subset of net.PacketConn a Conn needs to transmit
// wrapped datagrams to its peer.
type Transport interface {
	WriteTo(p []byte, addr net.Addr) (int, error)
}

// timeoutError implements net.Error for Read/Write deadline expiry.
type timeoutError struct{}

func (timeoutError) Error() string   { return "ctrlconn: i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// sessionAddr is Conn's net.Addr for LocalAddr: the control channel has no
// physical local address of its own (it is demultiplexed by session ID
// over a shared net.PacketConn), so this identifies it by session ID for
// diagnostic purposes only.
type sessionAddr wire.SessionID

func (sessionAddr) Network() string  { return "ovpn-ctrl" }
func (a sessionAddr) String() string { return fmt.Sprintf("ovpn-ctrl:%x", [wire.SessionIDSize]byte(a)) }

// Conn implements net.Conn over one client's OpenVPN control channel. See
// the package doc for the architectural role this plays.
type Conn struct {
	localSID   wire.SessionID
	remoteSID  wire.SessionID
	wrapper    *tlscrypt.Wrapper
	transport  Transport
	remoteAddr net.Addr
	clock      reliable.Clock

	sendRel *reliable.Reliable
	recvRel *reliable.Reliable
	acks    reliable.AckSet

	mu            sync.Mutex
	readBuf       []byte
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time
	readCond      *sync.Cond

	closeCh  chan struct{}
	closeOne sync.Once
}

var _ net.Conn = (*Conn)(nil)

// New builds a Conn for one client session. localSID/remoteSID are this
// side's own and its peer's 8-byte control-channel session IDs. wrapper is
// the session's own tls-crypt state (see internal/tlscrypt's per-session
// Wrapper decision — a Conn never shares a Wrapper across sessions).
// transport is used to send wire-format datagrams to remoteAddr. If clock
// is nil, reliable.SystemClock is used.
func New(localSID, remoteSID wire.SessionID, wrapper *tlscrypt.Wrapper, transport Transport, remoteAddr net.Addr, clock reliable.Clock) *Conn {
	if clock == nil {
		clock = reliable.SystemClock{}
	}
	c := &Conn{
		localSID:   localSID,
		remoteSID:  remoteSID,
		wrapper:    wrapper,
		transport:  transport,
		remoteAddr: remoteAddr,
		clock:      clock,
		sendRel:    reliable.New(clock, reliable.NSendBuffers),
		recvRel:    reliable.New(clock, reliable.NRecBuffers),
		closeCh:    make(chan struct{}),
	}
	c.readCond = sync.NewCond(&c.mu)
	go c.retransmitLoop()
	return c
}

// Deliver feeds a parsed inbound control packet into the connection: it
// purges any of our own outgoing entries the peer just acknowledged
// (reliable.Reliable.Ack) and, for any opcode other than P_ACK_V1 (which
// carries no own packet ID), stores the payload under its packet ID in the
// receive window, draining as much in-order data as has arrived into the
// stream Read consumes. It never blocks and never returns an error — an
// out-of-window or replayed packet is silently dropped, matching the
// reference's fail-open-on-garbage discipline for already
// tls-crypt-authenticated but still untrusted-content control traffic.
//
// Deliver is safe for concurrent use; callers that want strict per-session
// ordering should still serialize their own calls to it (e.g. via a single
// per-session goroutine), since Get()'s in-order draining is only as
// orderly as the sequence of Put calls feeding it.
func (c *Conn) Deliver(cp wire.ControlPacket) {
	c.absorb(cp)
	c.flushAckOnly()
}

// DeliverAndRespond absorbs an inbound packet's ACKs and payload exactly
// like Deliver, but instead of possibly following up with a separate
// ack-only packet, it transmits exactly one control packet of the given
// opcode carrying both those ACKs and payload. It exists for the very
// first packet of a new session (the client's own HARD_RESET_CLIENT_V2):
// the server's HARD_RESET_SERVER_V2 reply IS the ack for that packet, not
// a separate ack-only packet racing an unacked reset — mirroring the
// reference, where the reset reply itself carries the ack array.
func (c *Conn) DeliverAndRespond(cp wire.ControlPacket, opcode wire.Opcode, payload []byte) error {
	c.absorb(cp)
	return c.writeChunk(opcode, payload)
}

// absorb applies an inbound packet's ACKs to the send window and, for any
// opcode other than P_ACK_V1, stores its payload in the receive window,
// draining as much in-order data as has arrived into the stream Read
// consumes. It does not transmit anything — see Deliver and
// DeliverAndRespond for the two ways a caller turns that into outgoing
// traffic.
func (c *Conn) absorb(cp wire.ControlPacket) {
	sendIDs := make([]reliable.PacketID, len(cp.Acks))
	for i, id := range cp.Acks {
		sendIDs[i] = reliable.PacketID(id)
	}
	c.sendRel.Ack(sendIDs)

	if cp.Opcode != wire.OpAckV1 {
		switch c.recvRel.Put(reliable.PacketID(cp.PacketID), cp.Payload) {
		case reliable.PutAccepted, reliable.PutDuplicate:
			c.acks.Add(reliable.PacketID(cp.PacketID))
		case reliable.PutRejected:
			return
		}
	}

	c.mu.Lock()
	for {
		payload, ok := c.recvRel.Get()
		if !ok {
			break
		}
		if len(payload) > 0 {
			c.readBuf = append(c.readBuf, payload...)
		}
	}
	c.mu.Unlock()
	c.readCond.Broadcast()
}

// flushAckOnly emits a dedicated P_ACK_V1 packet (ACK array + peer session
// ID, no own packet ID, no payload) if ACKs are pending — the "nothing else
// queued but ACKs are pending" half of the ACK piggyback policy
// (01-RESEARCH.md Pattern 3 / ssl.c:3146-3177). Any ACKs it drains that a
// concurrently in-flight Write also would have piggybacked are simply not
// duplicated onto that Write's packet — Drain empties the shared queue
// exactly once.
func (c *Conn) flushAckOnly() {
	if !c.acks.Peek() {
		return
	}
	wireBytes, err := c.buildControlPacket(wire.OpAckV1, 0, nil)
	if err != nil {
		return
	}
	_ = c.transmit(wireBytes)
}

// SendReset transmits a reset control packet (e.g.
// wire.OpControlHardResetServerV2) through the same send-side reliability
// window as ordinary data, so it is retransmitted and ACKed exactly like
// any other control packet — resets are not a special case in the
// reference's own reliability layer, only in their effect on protocol
// state above it.
func (c *Conn) SendReset(opcode wire.Opcode) error {
	return c.writeChunk(opcode, nil)
}

// Read implements io.Reader by returning bytes from the in-order delivery
// stream Deliver builds up. It blocks until at least one byte is
// available, the connection is closed (returning io.EOF), or the read
// deadline (SetReadDeadline/SetDeadline) elapses (returning a net.Error
// with Timeout() true).
func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for len(c.readBuf) == 0 {
		if c.closed {
			return 0, io.EOF
		}
		if !c.readDeadline.IsZero() {
			if !c.clock.Now().Before(c.readDeadline) {
				return 0, timeoutError{}
			}
			timer := time.AfterFunc(time.Until(c.readDeadline), c.readCond.Broadcast)
			c.readCond.Wait()
			timer.Stop()
			continue
		}
		c.readCond.Wait()
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write fragments p into chunks of at most MaxPayload bytes and transmits
// each tls-crypt-wrapped, piggybacking up to reliable.AckSize pending ACKs
// on each chunk. If the send window is full, Write blocks (polling at
// retransmitInterval) until a slot frees up via an acknowledgment, the
// connection closes, or the write deadline elapses.
func (c *Conn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxPayload {
			chunk = chunk[:MaxPayload]
		}
		if err := c.writeChunk(wire.OpControlV1, chunk); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

func (c *Conn) writeChunk(opcode wire.Opcode, payload []byte) error {
	idx, err := c.waitForSendSlot()
	if err != nil {
		return err
	}
	id := c.sendRel.MarkActive(idx)
	wireBytes, err := c.buildControlPacket(opcode, id, payload)
	if err != nil {
		return err
	}
	c.sendRel.SetPayload(idx, wireBytes)
	return c.transmit(wireBytes)
}

// waitForSendSlot blocks until reliable.Reliable.Next reports a free,
// output-sequenced send slot, the connection closes (returning
// io.ErrClosedPipe), or the write deadline elapses (returning a
// timeoutError).
func (c *Conn) waitForSendSlot() (int, error) {
	for {
		if idx, ok := c.sendRel.Next(); ok {
			return idx, nil
		}
		c.mu.Lock()
		deadline := c.writeDeadline
		closed := c.closed
		c.mu.Unlock()
		if closed {
			return 0, io.ErrClosedPipe
		}
		if !deadline.IsZero() && !c.clock.Now().Before(deadline) {
			return 0, timeoutError{}
		}
		select {
		case <-c.closeCh:
			return 0, io.ErrClosedPipe
		case <-time.After(retransmitInterval):
		}
	}
}

func (c *Conn) buildControlPacket(opcode wire.Opcode, id reliable.PacketID, payload []byte) ([]byte, error) {
	acks := c.acks.Drain()
	wireAcks := make([]wire.PacketID, len(acks))
	for i, a := range acks {
		wireAcks[i] = wire.PacketID(a)
	}
	cp := wire.ControlPacket{
		Opcode:          opcode,
		KeyID:           0,
		SessionID:       c.localSID,
		Acks:            wireAcks,
		RemoteSessionID: c.remoteSID,
		PacketID:        wire.PacketID(id),
		Payload:         payload,
	}
	plaintext := cp.AppendPlaintext(nil)

	header := wire.AppendHeaderByte(make([]byte, 0, 1+wire.SessionIDSize), opcode, 0)
	header = append(header, c.localSID[:]...)

	return c.wrapper.Wrap(nil, header, plaintext)
}

func (c *Conn) transmit(wireBytes []byte) error {
	_, err := c.transport.WriteTo(wireBytes, c.remoteAddr)
	return err
}

// retransmitLoop periodically resends any send-side entries that have
// become due, applying reliable.Reliable's own exponential backoff (see
// Reliable.Due) each time it does.
func (c *Conn) retransmitLoop() {
	ticker := time.NewTicker(retransmitInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			for {
				payload, _, ok := c.sendRel.Due()
				if !ok {
					break
				}
				_ = c.transmit(payload)
			}
		}
	}
}

// Close is idempotent and safe to call concurrently with Read/Write from
// another goroutine: it stops the retransmit loop and unblocks any blocked
// Read (returning io.EOF) or Write (returning io.ErrClosedPipe).
func (c *Conn) Close() error {
	c.closeOne.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.closeCh)
		c.readCond.Broadcast()
	})
	return nil
}

// LocalAddr returns a diagnostic-only address identifying this side's
// session ID — the control channel has no physical local address of its
// own (see sessionAddr).
func (c *Conn) LocalAddr() net.Addr { return sessionAddr(c.localSID) }

// RemoteAddr returns the peer's UDP address.
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

// SetDeadline sets both the read and write deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	c.readCond.Broadcast()
	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	c.readCond.Broadcast()
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}
