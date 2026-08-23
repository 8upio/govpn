package ovpn

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// Session represents an established, TLS-authenticated client connection:
// the value Config.OnSession is invoked with, exactly once per client, once
// the control channel's TLS handshake has completed
// (tls.Conn.Handshake() returned nil) and never before.
//
// Session becomes a full io.ReadWriteCloser for raw, decrypted IP packets
// once the data channel exists (Key Method 2 and AES-256-GCM data-channel
// crypto, Phase 2 / CTRL-04). This plan declares the io.ReadWriteCloser
// methods so the public shape is stable across the phase, but Read/Write
// are deliberately unimplemented placeholders here: there is no data
// channel yet to read from or write to, and pretending otherwise would be
// scope creep into Phase 2's territory. Close is real — it tears down this
// session's control channel.
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
}

// Read is a placeholder: Phase 1 has no data channel to read raw IP packets
// from. It always returns io.EOF. Phase 2 replaces this with real
// AES-256-GCM data-channel decryption.
func (s *Session) Read(p []byte) (int, error) {
	return 0, io.EOF
}

// Write is a placeholder: Phase 1 has no data channel to write raw IP
// packets to. Phase 2 replaces this with real AES-256-GCM data-channel
// encryption.
func (s *Session) Write(p []byte) (int, error) {
	return 0, errors.New("ovpn: data channel not implemented until phase 2")
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
// session table so it can be garbage collected, and closes the underlying
// control-channel Conn. Safe to call more than once (idempotent) and safe
// to call concurrently.
func (s *Session) Close() error {
	s.stopOnce.Do(func() {
		close(s.stopCh)
		if s.srv != nil {
			s.srv.removeSession(s)
		}
	})
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

var _ io.ReadWriteCloser = (*Session)(nil)
