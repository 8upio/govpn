package ovpn

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/keyderiv"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// Session represents an established, TLS-authenticated client connection:
// the value Config.OnSession is invoked with, exactly once per client, and
// only after Key Method 2 and the PUSH_REQUEST/PUSH_REPLY exchange have
// both completed and the data-channel keys and the assigned tunnel IP are
// live (D-08) — not merely after tls.Conn.Handshake() has returned nil.
// The Session handed to OnSession is therefore immediately usable:
// AssignedIP() is already populated.
//
// Session is a full io.ReadWriteCloser for raw, decrypted IP packets:
// Read/Write are datagram-shaped (D-05) — one full IP packet per call, a
// buffer too small for the next packet on Read returns an error rather
// than truncating — backed by the AES-256-GCM data channel
// (internal/datachan). A 16-byte ping keepalive is absorbed entirely
// inside the decrypt path and never reaches Read's caller (D-11). Close
// tears down this session's control channel and releases its tunnel IP
// and peer-id back to the pool.
type Session struct {
	// SessionID is this session's server-assigned 8-byte control-channel
	// session ID.
	SessionID [wire.SessionIDSize]byte

	// RemoteAddr is the client's UDP address.
	RemoteAddr net.Addr

	// PeerCN is the verified client CommonName, read from
	// tls.Conn.ConnectionState().PeerCertificates[0].Subject.CommonName
	// only after Handshake() has returned nil — never from any
	// client-supplied field outside the CA-verified certificate chain
	// (threat T-01-16).
	PeerCN string

	clientSessionID wire.SessionID

	// connState is this session's underlying tls.Conn.ConnectionState(),
	// captured once, right after Handshake() returns nil — see
	// ConnectionState below. Diagnostic-only: Phase 1 pins MinVersion to
	// TLS 1.2 in Config.TLSConfig but does not otherwise act on any of
	// this value's fields.
	connState tls.ConnectionState

	// wrapper is this session's OWN tls-crypt state — an independent
	// send-sequence counter and an independent replay window, allocated
	// fresh per session even though every session shares the same
	// 256-byte key material (see ovpn.go / 01-01-SUMMARY.md's Decisions
	// Made for why a server-wide Wrapper is a correctness bug).
	wrapper *tlscrypt.Wrapper

	// conn is this session's control-channel net.Conn — the
	// tls.Server(conn, cfg) argument.
	conn *ctrlconn.Conn

	// inbound is fed parsed control packets by the Server's demux loop
	// (handleDatagram) and drained by this session's own pump goroutine,
	// which calls conn.Deliver for each one in order — serializing
	// delivery per session even though multiple UDP reads for the same
	// session may be in flight concurrently.
	inbound chan wire.ControlPacket

	// doneCh is closed once the handshake goroutine's call to
	// tlsConn.Handshake() returns, regardless of outcome — used by the
	// handshake-window enforcement goroutine to know it no longer needs
	// to tear the session down on a timeout.
	doneCh chan struct{}

	// key identifies this session in Server.sessions, so the handshake
	// goroutine and the handshake-window timeout can remove it on
	// failure/timeout.
	key sessionKey

	// srv is this session's owning Server, used by Close to remove the
	// session from Server.sessions. It is set once, before the session is
	// published into Server.sessions, and never mutated afterward.
	srv *Server

	// stopCh is closed exactly once (guarded by stopOnce) to signal pump
	// to stop ranging over inbound and to unblock any in-flight send on
	// inbound in handleDatagram. It is never closed directly by anything
	// other than Close's stopOnce.Do, and inbound itself is never closed —
	// closing a channel that another goroutine may still be sending on
	// would panic, so stopCh (selected on both send and receive sides)
	// is the teardown signal instead.
	stopCh chan struct{}

	// stopOnce guards stopCh so repeated or concurrent calls to Close are
	// safe and idempotent.
	stopOnce sync.Once

	// tlsReader is a bufio.Reader wrapping the session's tls.Conn, scoped
	// to runHandshake's Key Method 2 / PUSH_REQUEST continuation (D-15).
	// It is created once, in runHandshake, and retained here so plan
	// 02-02's PUSH_REQUEST/PUSH_REPLY continuation reads from the SAME
	// buffered stream rather than starting a second bufio.Reader over
	// tlsConn — a second reader would lose whatever bytes the first one
	// already pulled into its internal buffer. internal/ctrlconn.Conn
	// itself is not modified by this plan.
	tlsReader *bufio.Reader

	// dataKeys is this session's derived 256-byte Key Method 2 key
	// expansion, per-session like wrapper above, never server-global. It
	// is the single input plan 02-03's internal/datachan.Wrapper will
	// consume. nil until the Key Method 2 exchange completes.
	dataKeys *keyderiv.Key2

	// clientKM is the client's own Key Method 2 pre_master/random1/random2,
	// retained only for diagnostics after DeriveKeys has consumed it.
	clientKM *keyderiv.KeySource

	// serverKM is the server's own Key Method 2 random1/random2 (mirroring
	// clientKM above) — the reference server never populates a pre_master
	// (RESEARCH Pattern 3: the server contributes no pre-master entropy),
	// so this only ever holds random1/random2. Retained only so a
	// debug/test harness can independently re-derive this session's
	// data-channel keys via DebugKeyMethod2Material below (02-04-PLAN.md
	// Task 2, WIRE-03 against live evidence) — the production code path
	// never reads it back.
	serverKM *keyderiv.KeySource

	// pushRequested records whether this session's client has sent its
	// PUSH_REQUEST and been answered with PUSH_REPLY (ovpn.go's
	// performPushExchange). It remains an atomic.Bool, matching plan
	// 02-01's original concurrency contract, even though
	// performPushExchange now sets it from the same goroutine that later
	// calls Config.OnSession — an embedder or the interop harness may
	// still read PushRequestSeen() concurrently from a different
	// goroutine.
	pushRequested atomic.Bool

	// mu guards assignedIP, peerID, and dataWrapper below (WR-03):
	// ovpn.go's performPushExchange (running on this session's own
	// runHandshake goroutine) writes them, while Close — which
	// enforceHandshakeWindow's timeout goroutine can invoke concurrently
	// at any point until sess.doneCh closes, i.e. for the entire duration
	// of performPushExchange — reads them. Without this lock those are an
	// unsynchronized concurrent read/write of the same memory from two
	// goroutines, undefined under the Go memory model. Every other field
	// in this struct has its own, already-established discipline (stopCh/
	// stopOnce, srv.mu for dataSessions/sessions) and does not need this
	// mutex.
	mu sync.Mutex

	// assignedIP is this session's tunnel address, allocated from
	// Config.Network by ovpn.go's performPushExchange and pushed to the
	// client in PUSH_REPLY (D-01). nil until that exchange completes.
	// Released back to Server.pool exactly once, inside Close's
	// stopOnce.Do block (D-02), alongside peerID below. Guarded by mu.
	assignedIP net.IP

	// peerID is this session's 24-bit peer-id, allocated alongside
	// assignedIP from the same Server.pool call and pushed to the client
	// as `peer-id <n>`. Server.dataSessions keys its data-packet routing
	// table on this same value (D-16). Guarded by mu.
	peerID uint32

	// dataWrapper is this session's AES-256-GCM data-channel Wrapper,
	// built from sess.dataKeys.ServerSlots() at the same point assignedIP/
	// peerID are allocated (ovpn.go's performPushExchange) — live before
	// OnSession ever fires (D-08). nil until then; Read/Write on a nil
	// dataWrapper is a bug elsewhere (Read blocks forever, Write errors)
	// since D-08 guarantees a Session handed to an embedder always has one.
	// Guarded by mu.
	dataWrapper *datachan.Wrapper

	// ipInbound is fed decrypted IP packets by handleDataDatagram's decrypt
	// path (ovpn.go) and drained by Read. Sized ipInboundQueueSize (D-14,
	// matching Phase 1's inboundQueueSize): a slow embedder must never
	// block the shared UDP read loop, so a full queue drops the newest
	// packet exactly like inbound above (D-06) — that policy governs
	// arrival, not delivery: once a packet has been pulled off this
	// channel, pendingRead below is what keeps Read from then losing it.
	// Never closed directly — Read selects on stopCh instead, the same
	// discipline pump/inbound already establish.
	ipInbound chan []byte

	// pendingRead holds a decrypted IP packet Read already pulled off
	// ipInbound but could not deliver because the caller's buffer was too
	// small (D-05: Read must not truncate and must not silently discard —
	// "packet retained" is the choice this Session makes, the other
	// D-05-compliant option being "packet dropped with an error"). The
	// next Read call, with any buffer, checks here first. Assumes the
	// single-reader-goroutine convention io.Reader implementations
	// ordinarily rely on; concurrent Read calls on one Session are not
	// supported (mirrors bufio.Reader's own contract).
	pendingRead []byte
}

// closing reports whether Close has already started (or finished) tearing
// this session down, by checking whether stopCh is closed. Used by WR-05's
// fix in ovpn.go (performPushExchange, runHandshake) to detect
// enforceHandshakeWindow's timeout goroutine having raced ahead of the
// bring-up sequence, so state is never published (or handed to
// Config.OnSession) for a session that's already dead. Safe to call from
// any goroutine without additional synchronization — receiving from a
// closed channel is one of the few operations the Go memory model
// guarantees is itself a synchronizing action (see stopCh's own docs; pump,
// Read, and runKeepalive already rely on the identical select-on-stopCh
// pattern with no separate lock).
func (s *Session) closing() bool {
	select {
	case <-s.stopCh:
		return true
	default:
		return false
	}
}

// PushRequestSeen reports whether this session's client has sent its
// PUSH_REQUEST and been answered with a PUSH_REPLY (RESEARCH Pattern 6).
// Exists so an embedder or the interop harness can observe that the real
// client progressed past key negotiation and completed tunnel-IP
// assignment; AssignedIP() below is populated at the same point and is the
// preferred accessor for that same fact.
func (s *Session) PushRequestSeen() bool {
	return s.pushRequested.Load()
}

// AssignedIP returns this session's tunnel address, as allocated from
// Config.Network and pushed to the client in PUSH_REPLY (D-01, D-07). It
// is populated before Config.OnSession is invoked for this session (D-08)
// — calling it earlier, or on a session whose PUSH_REQUEST/PUSH_REPLY
// exchange never completed, returns nil, mirroring ConnectionState's
// documented zero-value behavior. The returned net.IP is a defensive copy:
// mutating it cannot corrupt the allocator's own state.
func (s *Session) AssignedIP() net.IP {
	s.mu.Lock()
	assignedIP := s.assignedIP
	s.mu.Unlock()

	if assignedIP == nil {
		return nil
	}
	ip := make(net.IP, len(assignedIP))
	copy(ip, assignedIP)
	return ip
}

// PeerID returns this session's 24-bit peer-id, allocated alongside
// AssignedIP and pushed to the client as `peer-id <n>`. It is 0 both
// before that exchange completes and for the (valid, distinct) allocated
// peer-id 0 itself — callers that need to distinguish "not yet assigned"
// should check AssignedIP() != nil instead. Added so an external package
// (test/interop/server/main.go's diagnostic PASS line) can report the
// value the pool actually handed out; D-07 fixes AssignedIP/PeerCN/
// ConnectionState as the surface a real embedder needs, and this accessor
// is diagnostic-only in the same spirit as PushRequestSeen above.
func (s *Session) PeerID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peerID
}

// DebugKeyMethod2Material returns this session's raw Key Method 2 seed
// material (the exchanged pre_master/random1/random2 halves, in
// keyderiv.KeySource2's own shape) and the client/server control-channel
// session IDs DeriveKeys consumed to derive dataKeys, so a test harness can
// independently re-run keyderiv.DeriveKeys and confirm byte-identical
// reproduction against a real client's own captured exchange (02-04-PLAN.md
// Task 2's golden-vector verification, WIRE-03 against live evidence, not
// only against the reference's own PRF test vector). ok is false until Key
// Method 2 has completed. This is a debug/test-only accessor — a
// production embedder has no reason to call it, and the library itself
// never reads this material back after performKeyMethod2Exchange has
// already consumed it to derive dataKeys.
func (s *Session) DebugKeyMethod2Material() (src keyderiv.KeySource2, clientSID, serverSID [wire.SessionIDSize]byte, ok bool) {
	if s.clientKM == nil || s.serverKM == nil {
		return keyderiv.KeySource2{}, clientSID, serverSID, false
	}
	return keyderiv.KeySource2{Client: *s.clientKM, Server: *s.serverKM}, s.clientSessionID, s.SessionID, true
}

// DebugDataKeys returns this session's derived per-direction data-channel
// key material from the server's own perspective
// (keyderiv.Key2.ServerSlots), so a test harness can build its own
// internal/datachan.Wrapper to independently decode this session's
// data-channel traffic — e.g. golden-vector export/verification
// (02-04-PLAN.md Task 2). ok is false until Key Method 2 has completed
// (dataKeys != nil). Debug/test-only, mirroring DebugKeyMethod2Material
// above.
func (s *Session) DebugDataKeys() (keys keyderiv.DataKeys, ok bool) {
	if s.dataKeys == nil {
		return keyderiv.DataKeys{}, false
	}
	return s.dataKeys.ServerSlots(), true
}

// Read delivers exactly one raw, decrypted IP packet per call (D-05):
// datagram-shaped, never a stream. If p is too small to hold the next
// packet, Read returns a typed error and RETAINS the packet in
// pendingRead rather than truncating it or discarding it silently — a
// subsequent Read with a large enough buffer still receives it, in full,
// undamaged. (D-05 leaves the choice between "packet retained" and
// "packet dropped with an error" to the implementation; this Session
// retains.) Read blocks until a packet arrives or the Session is closed,
// in which case it returns io.EOF.
func (s *Session) Read(p []byte) (int, error) {
	if s.pendingRead != nil {
		pkt := s.pendingRead
		if len(p) < len(pkt) {
			return 0, fmt.Errorf("ovpn: read buffer (%d bytes) too small for %d-byte packet; packet retained for a future Read", len(p), len(pkt))
		}
		s.pendingRead = nil
		return copy(p, pkt), nil
	}

	select {
	case pkt := <-s.ipInbound:
		if len(p) < len(pkt) {
			s.pendingRead = pkt
			return 0, fmt.Errorf("ovpn: read buffer (%d bytes) too small for %d-byte packet; packet retained for a future Read", len(p), len(pkt))
		}
		return copy(p, pkt), nil
	case <-s.stopCh:
		return 0, io.EOF
	}
}

// Write encrypts p as one P_DATA_V2 packet (D-05: one full IP packet per
// call) and sends it to the client's UDP address over the same
// net.PacketConn the control channel uses. It returns len(p) on success,
// matching io.Writer's contract for a full write.
func (s *Session) Write(p []byte) (int, error) {
	if s.dataWrapper == nil {
		return 0, errors.New("ovpn: data channel not yet established")
	}
	sealed, err := s.dataWrapper.Seal(nil, p)
	if err != nil {
		return 0, fmt.Errorf("ovpn: seal data packet: %w", err)
	}
	if s.srv == nil || s.srv.pc == nil {
		return 0, errors.New("ovpn: session has no transport")
	}
	if _, err := s.srv.pc.WriteTo(sealed, s.RemoteAddr); err != nil {
		return 0, fmt.Errorf("ovpn: write data packet: %w", err)
	}
	return len(p), nil
}

// handleDataPacket decrypts an inbound P_DATA_V2 payload (ovpn.go's
// handleDataDatagram) and, unless it fails to authenticate or is a ping
// (absorbed inside Wrapper.Open — D-11, never surfaced here), delivers it
// into ipInbound using the same non-blocking select+default drop policy
// inbound above already uses (D-06): a slow embedder must never block the
// shared UDP read loop. An authentication failure is dropped silently,
// exactly like a forged control packet — no allocation, no per-attacker
// state (T-02-17).
func (s *Session) handleDataPacket(packet []byte) {
	if s.dataWrapper == nil {
		return
	}
	plaintext, err := s.dataWrapper.Open(nil, packet)
	if err != nil {
		// Includes datachan.ErrPingAbsorbed: a ping is absorbed inside
		// Open, never delivered, and never counts as a delivered IP
		// packet.
		return
	}
	select {
	case s.ipInbound <- plaintext:
	case <-s.stopCh:
	default:
		// Queue full: drop this decrypted packet exactly as a genuinely
		// congested link would (D-06) — never block handleDatagram's
		// per-datagram goroutine.
	}
}

// startKeepalive starts this session's per-session keepalive goroutine
// (D-11): a real time.Ticker at pingInterval feeds runKeepalive below.
// Called once, from ovpn.go's performPushExchange, at the same point the
// data wrapper goes live — alongside the PUSH_REPLY write, before
// OnSession ever fires.
func (s *Session) startKeepalive() {
	ticker := time.NewTicker(pingInterval)
	go func() {
		defer ticker.Stop()
		s.runKeepalive(ticker.C)
	}()
}

// runKeepalive is startKeepalive's own core loop, factored out so tests
// can drive it from an injected tick channel instead of a real
// pingInterval-second ticker — internal/reliable's own injected-Clock
// precedent, applied here as an injected ticker channel (the constructor-
// supplied-channel option 02-03-PLAN.md's own action text names) so
// TestServerEmitsPingOnSchedule/TestPingTimerStopsOnClose run in
// milliseconds, not real 10-second waits. It selects on stopCh and exits
// on Close, the same discipline pump/handleDataPacket already establish —
// no second teardown signal.
//
// This goroutine only EMITS pings; it does not implement ping-restart /
// idle-session reaping (detecting a dead peer from a missing reply) —
// that is SESS-05, Phase 4's scope.
func (s *Session) runKeepalive(tickCh <-chan time.Time) {
	for {
		select {
		case <-tickCh:
			s.emitPing()
		case <-s.stopCh:
			return
		}
	}
}

// emitPing seals and sends one ping keepalive packet directly through
// dataWrapper and srv.pc — deliberately NOT through Session.Write, so a
// server-emitted ping never appears to the embedder as bytes written
// through the public Write path and never affects anything Write's own
// return value represents.
func (s *Session) emitPing() {
	if s.dataWrapper == nil {
		return
	}
	sealed, err := s.dataWrapper.SealPing(nil)
	if err != nil {
		// ErrPacketIDExhausted or similar — nothing more to do; the next
		// tick tries again (and will fail the same way until Phase 4's
		// renegotiation, out of this phase's scope).
		return
	}
	if s.srv == nil || s.srv.pc == nil {
		return
	}
	_, _ = s.srv.pc.WriteTo(sealed, s.RemoteAddr)
}

// ConnectionState returns this session's underlying TLS connection state
// (negotiated version, cipher suite, peer certificate chain, and
// everything else crypto/tls itself exposes) as captured once, immediately
// after Handshake() returned nil. Calling it before OnSession has fired
// for this session returns the zero value.
func (s *Session) ConnectionState() tls.ConnectionState {
	return s.connState
}

// Close tears down this session's control channel: it stops the
// per-session pump goroutine (by closing stopCh, never inbound itself —
// see stopCh's docs), removes this session from its owning Server's
// session table so it can be garbage collected, releases its tunnel IP and
// peer-id back to Server.pool for immediate reuse (D-02) if they were ever
// assigned, and closes the underlying control-channel Conn. Safe to call
// more than once (idempotent — the release happens inside the same
// stopOnce.Do as everything else, so a double Close can never double
// release) and safe to call concurrently.
func (s *Session) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.srv != nil {
			// WR-05: hold mu across BOTH the assignedIP/peerID/dataWrapper
			// snapshot AND the dataSessions routing-entry delete below,
			// nesting s.srv.mu inside mu rather than releasing mu in
			// between (as a pre-WR-05 version of this method did).
			// performPushExchange's own atomic publish (ovpn.go) uses the
			// identical mu-then-srv.mu nesting for the same reason: without
			// it, this snapshot could observe assignedIP/peerID/dataWrapper
			// as not-yet-set (nothing to clean up here), and
			// performPushExchange could then finish publishing everything
			// — including the dataSessions entry — a moment later,
			// pointing at a peer-id this Close call believed was already
			// fully idle. Because stopOnce guarantees this closure body
			// never runs a second time, that publish would never get
			// cleaned up: a permanent leak of the pool IP/peer-id (WR-05
			// consequence 1) and a permanently stale dataSessions entry
			// (WR-05 consequence 2). Holding mu across both steps makes
			// the two sides' critical sections mutually exclusive as a
			// whole, so this snapshot always sees either nothing published
			// yet, or everything published — never a partial state.
			s.mu.Lock()
			assignedIP := s.assignedIP
			peerID := s.peerID
			dataWrapper := s.dataWrapper

			// Remove the dataSessions routing entry BEFORE releasing
			// peerID back to the pool (WR-04): pool.release makes peerID
			// immediately reusable by the next ipPool.allocate() call, so
			// releasing first would open a window where a brand-new
			// session could claim peerID and publish itself into
			// dataSessions before this session's own entry is removed —
			// making the routing-table cleanup below depend on the
			// `existing == s` equality check to save it, rather than being
			// structurally impossible by construction.
			if dataWrapper != nil {
				s.srv.mu.Lock()
				if existing, ok := s.srv.dataSessions[peerID]; ok && existing == s {
					delete(s.srv.dataSessions, peerID)
				}
				s.srv.mu.Unlock()
			}
			s.mu.Unlock()

			if assignedIP != nil && s.srv.pool != nil {
				s.srv.pool.release(assignedIP, peerID)
			}
			s.srv.removeSession(s)
		}
	})
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

var _ io.ReadWriteCloser = (*Session)(nil)
