// Package ovpn implements the server side of the OpenVPN protocol as an
// embeddable Go library: no wrapper around the openvpn binary, no separate
// process. See the module's PROJECT.md for the full design.
//
// This file (ovpn.go) contains Phase 1's tracer slice: enough of the public
// surface, packet triage, and HARD_RESET_CLIENT_V2/SERVER_V2 exchange to
// prove the wire format and tls-crypt construction end-to-end over a real
// UDP socket. The TLS handshake, control-channel reliability layer, and
// Session's real io.ReadWriteCloser behavior land in later plans of this
// phase (01-03).
package ovpn

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// Config configures a Server.
type Config struct {
	// TLSConfig configures the control-channel TLS handshake (mutual
	// certificate auth, cipher suites). Consumed starting in plan 01-03;
	// this plan declares the field but does not read it.
	TLSConfig *tls.Config

	// TLSCryptKey is the 256 raw bytes of an OpenVPN "Static key V1" tls-crypt
	// key (see ParseStaticKeyV1), shared with every client.
	TLSCryptKey []byte

	// Network is the virtual tunnel-IP range clients are assigned from.
	// Consumed starting in a later plan; declared here for the public
	// surface's shape.
	Network *net.IPNet

	// Cipher names the fixed data-channel cipher (e.g. "AES-256-GCM").
	// Consumed starting in a later plan.
	Cipher string

	// OnSession is invoked once a client's Session is established — once
	// Handshake() returns nil (plan 01-03). It is declared here so Config's
	// shape is stable across the phase, but this plan never invokes it:
	// Phase 1's definition of done is the HARD_RESET exchange, which is a
	// strict subset of a fully established session.
	OnSession func(*Session)
}

// Session represents an established, TLS-authenticated client connection.
// It becomes a full io.ReadWriteCloser for raw, decrypted IP packets in
// plan 01-03; this plan declares only enough of the type to make
// Config.OnSession's signature compile and to key Server's session
// dispatch table.
type Session struct {
	serverSessionID wire.SessionID
	clientSessionID wire.SessionID
	remoteAddr      net.Addr

	// wrapper is this session's OWN tls-crypt state: an independent
	// send-sequence counter and an independent replay window, allocated
	// fresh per session even though every session shares the same 256-byte
	// key material. This mirrors the reference's per-tls_session
	// tls_wrap_ctx (each tls_session gets its own freshly-initialized
	// packet_id state). A single server-wide Wrapper would be wrong: two
	// different clients each start their own tls-crypt sequence counter at
	// 1 independently, so a shared decrypt-side replay window would reject
	// the second client's legitimate first packet as a "replay" of the
	// first client's packet ID 1.
	wrapper *tlscrypt.Wrapper
}

// ParseStaticKeyV1 parses an OpenVPN "Static key V1" PEM-style envelope
// into its 256 raw bytes, suitable for Config.TLSCryptKey.
func ParseStaticKeyV1(data []byte) ([]byte, error) {
	return tlscrypt.ParseStaticKeyV1(data)
}

const (
	// maxDatagramSize: TLS_CHANNEL_BUF_SIZE (mtu.h/common.h) — the hard
	// ceiling on any single control-channel buffer, applied here as an
	// upper sanity bound on raw UDP datagrams even before tls-crypt/wire
	// parsing begins (RESEARCH Security Domain, T-01-01).
	maxDatagramSize = 2048

	// minDatagramSize is the 49-byte tls-crypt prefix (tls_crypt.h
	// TLS_CRYPT_OFF_CT) — nothing shorter than this can possibly be a valid
	// tls-crypt-wrapped packet.
	minDatagramSize = tlscrypt.OffCT
)

// sessionKey identifies a client by the pair the reference dispatches on:
// remote UDP address and 8-byte session ID (tls_pre_decrypt_lite,
// ssl_pkt.c:305-423).
type sessionKey struct {
	addr string
	sid  wire.SessionID
}

// Server is an OpenVPN protocol server. Construct with NewServer and start
// with Serve.
type Server struct {
	cfg Config

	mu       sync.Mutex
	pc       net.PacketConn
	closed   bool
	sessions map[sessionKey]*Session
}

// NewServer builds a Server from cfg. It does not start listening — call
// Serve to begin reading from a net.PacketConn.
func NewServer(cfg Config) *Server {
	return &Server{
		cfg:      cfg,
		sessions: make(map[sessionKey]*Session),
	}
}

// Serve runs the server's UDP read loop over pc until pc is closed or Close
// is called.
//
// It applies cheap triage before allocating any per-session state,
// mirroring tls_pre_decrypt_lite (ssl_pkt.c:305-423): reject datagrams
// shorter than the tls-crypt prefix or longer than TLS_CHANNEL_BUF_SIZE,
// and reject header bytes with an out-of-range opcode — all before ever
// calling Unwrap. Each accepted datagram is then handled on its own
// goroutine, so datagrams belonging to distinct client sessions are
// processed concurrently without blocking the read loop.
func (s *Server) Serve(pc net.PacketConn) error {
	// Fail fast on malformed key material rather than discovering it on the
	// first inbound datagram; NewWrapper's own length check is authoritative,
	// this is just a cheap up-front validation using a throwaway instance.
	if _, err := tlscrypt.NewWrapper(s.cfg.TLSCryptKey, true); err != nil {
		return fmt.Errorf("ovpn: %w", err)
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.pc = pc
	s.mu.Unlock()

	// Sized one byte over the accepted ceiling so an oversized datagram
	// (which the OS would otherwise silently truncate to fit the buffer)
	// is detectable: n > maxDatagramSize means the real datagram exceeded
	// the ceiling and must be rejected, not processed as if it were valid.
	buf := make([]byte, maxDatagramSize+1)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])
		go s.handleDatagram(pc, addr, packet)
	}
}

// Close unblocks Serve's read loop by closing the underlying PacketConn,
// making Serve return.
func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.pc != nil {
		return s.pc.Close()
	}
	return nil
}

func (s *Server) handleDatagram(pc net.PacketConn, addr net.Addr, packet []byte) {
	if len(packet) < minDatagramSize || len(packet) > maxDatagramSize {
		return
	}

	opcode, keyID := wire.ParseHeaderByte(packet[0])
	if !wire.ValidOpcode(opcode) {
		return
	}
	var sid wire.SessionID
	copy(sid[:], packet[1:1+wire.SessionIDSize])

	key := sessionKey{addr: addr.String(), sid: sid}

	s.mu.Lock()
	sess, exists := s.sessions[key]
	s.mu.Unlock()

	if !exists {
		// A hard-reset-client-v2 with key ID 0 from an unknown pair
		// creates a new session; anything else with no matching session
		// has nowhere to be routed and is dropped. Note: no per-session
		// state (Wrapper, Session) is allocated yet at this point — that
		// only happens below, and only after Unwrap+ParseControlPacket
		// both succeed, so a spoofed-source flood of garbage claiming
		// this opcode still cannot allocate unbounded session state
		// (RESEARCH Security Domain, T-01-01).
		if opcode != wire.OpControlHardResetClientV2 || keyID != 0 {
			return
		}
		wrapper, err := tlscrypt.NewWrapper(s.cfg.TLSCryptKey, true)
		if err != nil {
			return
		}
		var serverSID wire.SessionID
		if _, err := rand.Read(serverSID[:]); err != nil {
			return
		}
		sess = &Session{
			serverSessionID: serverSID,
			clientSessionID: sid,
			remoteAddr:      addr,
			wrapper:         wrapper,
		}
	}

	_, plaintext, err := sess.wrapper.Unwrap(nil, packet)
	if err != nil {
		return
	}
	hdr := wire.Header{Opcode: opcode, KeyID: keyID, SessionID: sid}
	cp, err := wire.ParseControlPacket(plaintext, hdr)
	if err != nil {
		return
	}

	if !exists {
		s.mu.Lock()
		if _, raced := s.sessions[key]; !raced {
			s.sessions[key] = sess
		} else {
			// Another goroutine won the race to create this session first;
			// keep using the winner's session/wrapper so both goroutines'
			// replies come from the same, single tls-crypt state.
			sess = s.sessions[key]
		}
		s.mu.Unlock()
	}

	switch {
	case opcode == wire.OpControlHardResetClientV2 && keyID == 0:
		s.handleHardReset(pc, addr, sess, cp)
	default:
		// Every other opcode (renegotiation, control/ack traffic, the real
		// client's post-handshake Key Method 2 data) is out of scope for
		// this plan's tracer slice — the reliability layer and TLS
		// handshake land in plan 01-03. Silently ignoring rather than
		// erroring matches RESEARCH Pitfall 5: the server must not treat
		// the client's own protocol-correct follow-up traffic as a
		// violation just because this plan doesn't process it yet.
	}
}

func (s *Server) handleHardReset(pc net.PacketConn, addr net.Addr, sess *Session, cp wire.ControlPacket) {
	reply := wire.ControlPacket{
		Opcode:          wire.OpControlHardResetServerV2,
		KeyID:           0,
		SessionID:       sess.serverSessionID,
		Acks:            []wire.PacketID{cp.PacketID},
		RemoteSessionID: cp.SessionID,
		PacketID:        0, // reliable{} is zero-cleared at init; the first outgoing control packet ID is 0 (reliable.c struct reliable).
	}

	plaintext := reply.AppendPlaintext(nil)

	header := wire.AppendHeaderByte(make([]byte, 0, 1+wire.SessionIDSize), reply.Opcode, reply.KeyID)
	header = append(header, reply.SessionID[:]...)

	packet, err := sess.wrapper.Wrap(nil, header, plaintext)
	if err != nil {
		return
	}

	_, _ = pc.WriteTo(packet, addr)
}
