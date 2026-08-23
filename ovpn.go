// Package ovpn implements the server side of the OpenVPN protocol as an
// embeddable Go library: no wrapper around the openvpn binary, no separate
// process. See the module's PROJECT.md for the full design.
//
// This file (ovpn.go) wires together internal/wire, internal/tlscrypt,
// internal/reliable and internal/ctrlconn into the public Server/Session
// surface: cheap pre-decrypt UDP triage, per-session tls-crypt
// authentication, the control-channel reliability layer, and — as of this
// plan — a real crypto/tls handshake layered unmodified on top of the
// control-channel net.Conn (internal/ctrlconn). Success is exactly
// tls.Conn.Handshake() returning nil plus a verified peer certificate
// CommonName; the data channel (Key Method 2, AES-256-GCM) is Phase 2.
package ovpn

import (
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/reliable"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// Config configures a Server.
type Config struct {
	// TLSConfig configures the control-channel TLS handshake: mutual
	// certificate auth (ClientAuth, ClientCAs), the server's own
	// certificate, and MinVersion. Consumed starting in this plan — every
	// session's control channel is handed to tls.Server(conn, TLSConfig)
	// unmodified.
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

	// OnSession is invoked exactly once per client, after
	// tls.Conn.Handshake() has returned nil and never before, with a
	// Session whose PeerCN is the verified client CommonName (threat
	// T-01-16).
	OnSession func(*Session)
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

	// inboundQueueSize bounds each session's inbound-datagram channel. It
	// is sized comfortably above reliable.NRecBuffers (12): a slow or
	// stalled handshake goroutine must not make the shared UDP read loop
	// block, so a full queue drops the newest datagram (relying on the
	// reliability layer's own retransmission, exactly as a genuinely lost
	// UDP datagram would) rather than backing up Serve.
	inboundQueueSize = 32
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
	if s.cfg.TLSConfig == nil {
		return errors.New("ovpn: Config.TLSConfig must be set")
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
// making Serve return, and closes every in-flight session's control
// channel so their handshake goroutines and retransmit loops don't leak
// past server shutdown.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	pc := s.pc
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		_ = sess.Close()
	}
	if pc != nil {
		return pc.Close()
	}
	return nil
}

// packetConnTransport adapts a net.PacketConn to ctrlconn.Transport.
type packetConnTransport struct{ pc net.PacketConn }

func (t packetConnTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	return t.pc.WriteTo(p, addr)
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

	justCreated := false
	if !exists {
		// A hard-reset-client-v2 with key ID 0 from an unknown pair
		// creates a new session; anything else with no matching session
		// has nowhere to be routed and is dropped, before any allocation
		// at all.
		if opcode != wire.OpControlHardResetClientV2 || keyID != 0 {
			return
		}
		// A candidate Wrapper+Session pair is constructed here because
		// tls-crypt's Unwrap needs keyed state to even attempt
		// authentication — this is unavoidable regardless of
		// implementation strategy. What matters for T-01-01 (DoS via a
		// spoofed-source flood of garbage claiming this opcode) is that
		// these candidate objects are never persisted into s.sessions
		// below unless Unwrap AND ParseControlPacket both succeed: an
		// unbounded flood of forged HARD_RESET_CLIENT_V2 datagrams can
		// force transient, per-packet allocation (garbage collected
		// immediately, no different in kind from the per-datagram
		// goroutine and buffer copy already made above), but can never
		// grow the server's persistent session table.
		wrapper, err := tlscrypt.NewWrapper(s.cfg.TLSCryptKey, true)
		if err != nil {
			return
		}
		var serverSID wire.SessionID
		if _, err := rand.Read(serverSID[:]); err != nil {
			return
		}
		sess = &Session{
			SessionID:       serverSID,
			RemoteAddr:      addr,
			clientSessionID: sid,
			wrapper:         wrapper,
			key:             key,
			srv:             s,
			inbound:         make(chan wire.ControlPacket, inboundQueueSize),
			doneCh:          make(chan struct{}),
			stopCh:          make(chan struct{}),
		}
		justCreated = true
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
		// sess.conn is constructed (and, transitively, this session's
		// pump/handshake/handshake-window goroutines are only started)
		// while still holding s.mu, strictly before s.sessions[key] = sess
		// makes this session visible to any other goroutine. This is
		// required, not cosmetic: Server.Close() reads s.sessions under
		// s.mu and then reads sess.conn outside the lock — without a
		// happens-before edge running through the SAME lock acquisition
		// that published the map entry, that later unsynchronized read of
		// sess.conn would race with this goroutine's write to it (caught
		// by `go test -race`; see 01-03-SUMMARY.md Deviations).
		s.mu.Lock()
		if existing, raced := s.sessions[key]; raced {
			// Another goroutine won the race to create this session
			// first; keep using the winner's session/wrapper so both
			// goroutines' packets are delivered into the same, single
			// control channel. We never called ctrlconn.New for our
			// candidate, so there is nothing to clean up.
			sess = existing
			justCreated = false
			s.mu.Unlock()
		} else {
			transport := packetConnTransport{pc: pc}
			sess.conn = ctrlconn.New(sess.SessionID, sess.clientSessionID, sess.wrapper, transport, addr, nil)
			s.sessions[key] = sess
			s.mu.Unlock()
		}
	}

	if justCreated {
		go sess.pump()
		go s.runHandshake(sess)
		go s.enforceHandshakeWindow(sess)

		// Absorb the client's own hard reset and reply with
		// HARD_RESET_SERVER_V2 as a single atomic step, synchronously on
		// this goroutine — not through sess.inbound — so the reply IS the
		// ack for the client's packet ID 0 (RESEARCH Pattern 3), never a
		// separate ack-only packet racing an unacked reset.
		_ = sess.conn.DeliverAndRespond(cp, wire.OpControlHardResetServerV2, nil)
		return
	}

	// Every subsequent datagram for an already-established session is fed
	// into this session's own serialized pump, which calls conn.Deliver
	// for each in the order handleDatagram enqueued them.
	select {
	case sess.inbound <- cp:
	case <-sess.stopCh:
		// Session is mid-teardown (Close was called): don't block trying
		// to enqueue into a pump that has already stopped ranging.
	default:
		// Queue full: drop this datagram exactly as a genuinely lost UDP
		// packet would be dropped — the reliability layer's own
		// retransmission (on both sides) is what recovers from this, not
		// a synchronous retry here.
	}
}

// pump serializes delivery of this session's inbound control packets into
// its control-channel Conn, one at a time, in the order handleDatagram
// enqueued them, until stopCh is closed by Session.Close.
func (sess *Session) pump() {
	for {
		select {
		case cp := <-sess.inbound:
			sess.conn.Deliver(cp)
		case <-sess.stopCh:
			return
		}
	}
}

// runHandshake runs crypto/tls, unmodified, over sess's control-channel
// Conn. Success is exactly Handshake() returning nil plus a populated
// verified peer CommonName — not the reference's S_ACTIVE state (which
// additionally requires Key Method 2, Phase 2 scope), and not merely having
// received the client's reset (RESEARCH Pitfall 5). Once Handshake returns
// nil, Config.OnSession is invoked exactly once. TLS application data that
// arrives after that point — the client's own Key Method 2 payload — is the
// client's protocol-correct next step; Session.conn simply buffers it
// unread (see internal/ctrlconn.Conn.Deliver and Read), and this goroutine
// never calls Read again, so it is never disturbed.
func (s *Server) runHandshake(sess *Session) {
	tlsConn := tls.Server(sess.conn, s.cfg.TLSConfig)
	err := tlsConn.Handshake()
	close(sess.doneCh)

	if err != nil {
		_ = sess.Close()
		return
	}

	state := tlsConn.ConnectionState()
	sess.connState = state
	if len(state.PeerCertificates) > 0 {
		sess.PeerCN = state.PeerCertificates[0].Subject.CommonName
	}
	if s.cfg.OnSession != nil {
		s.cfg.OnSession(sess)
	}
}

// enforceHandshakeWindow tears sess down and releases its state if the
// handshake has not completed within reliable.HandshakeWindow (the
// reference's --hand-window default, 60 seconds).
func (s *Server) enforceHandshakeWindow(sess *Session) {
	select {
	case <-sess.doneCh:
		return
	case <-time.After(reliable.HandshakeWindow):
		_ = sess.Close()
	}
}

func (s *Server) removeSession(sess *Session) {
	s.mu.Lock()
	if existing, ok := s.sessions[sess.key]; ok && existing == sess {
		delete(s.sessions, sess.key)
	}
	s.mu.Unlock()
}
