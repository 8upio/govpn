package ovpn

import (
	"errors"
	"io"
	"net"

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

// Close tears down this session's control channel.
func (s *Session) Close() error {
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

var _ io.ReadWriteCloser = (*Session)(nil)
