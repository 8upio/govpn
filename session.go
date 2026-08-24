package ovpn

import (
	"bufio"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/8upio/govpn/internal/ctrlconn"
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
// Session becomes a full io.ReadWriteCloser for raw, decrypted IP packets
// once the AES-256-GCM data channel exists (plan 02-03). This plan
// declares the io.ReadWriteCloser methods so the public shape is stable
// across the phase, but Read/Write are deliberately unimplemented
// placeholders here: there is no data channel yet to read from or write
// to, and pretending otherwise would be scope creep into plan 02-03's
// territory. Close is real — it tears down this session's control channel
// and releases its tunnel IP and peer-id back to the pool.
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

	// pushRequested records whether this session's client has sent its
	// PUSH_REQUEST and been answered with PUSH_REPLY (ovpn.go's
	// performPushExchange). It remains an atomic.Bool, matching plan
	// 02-01's original concurrency contract, even though
	// performPushExchange now sets it from the same goroutine that later
	// calls Config.OnSession — an embedder or the interop harness may
	// still read PushRequestSeen() concurrently from a different
	// goroutine.
	pushRequested atomic.Bool

	// assignedIP is this session's tunnel address, allocated from
	// Config.Network by ovpn.go's performPushExchange and pushed to the
	// client in PUSH_REPLY (D-01). nil until that exchange completes.
	// Released back to Server.pool exactly once, inside Close's
	// stopOnce.Do block (D-02), alongside peerID below.
	assignedIP net.IP

	// peerID is this session's 24-bit peer-id, allocated alongside
	// assignedIP from the same Server.pool call and pushed to the client
	// as `peer-id <n>`. Plan 02-03 keys its data-packet routing table on
	// this same value (D-16).
	peerID uint32
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
	if s.assignedIP == nil {
		return nil
	}
	ip := make(net.IP, len(s.assignedIP))
	copy(ip, s.assignedIP)
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
	return s.peerID
}

// Read is a placeholder: there is no data channel yet to read raw IP
// packets from. It always returns io.EOF. Plan 02-03 replaces this with
// real AES-256-GCM data-channel decryption.
func (s *Session) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// Write is a placeholder: there is no data channel yet to write raw IP
// packets to. Plan 02-03 replaces this with real AES-256-GCM data-channel
// encryption.
func (s *Session) Write(p []byte) (int, error) {
	return 0, errors.New("ovpn: data channel not implemented until plan 02-03")
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
			if s.assignedIP != nil && s.srv.pool != nil {
				s.srv.pool.release(s.assignedIP, s.peerID)
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
