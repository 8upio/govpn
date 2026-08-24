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
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/8upio/govpn/internal/ctrlconn"
	"github.com/8upio/govpn/internal/datachan"
	"github.com/8upio/govpn/internal/keyderiv"
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

	// Network is the virtual tunnel-IP range clients are assigned from
	// (D-01): consumed starting in this plan. Must be an IPv4 *net.IPNet
	// of at least /30 — the server reserves the first host address
	// (base+1) for itself and allocates each connecting client the next
	// free host address sequentially, skipping the network and broadcast
	// addresses. If unset, a session that reaches the PUSH_REQUEST/
	// PUSH_REPLY exchange fails and is closed before Config.OnSession
	// fires.
	Network *net.IPNet

	// Cipher names the fixed data-channel cipher pushed to clients as
	// `cipher <name>` (e.g. "AES-256-GCM"). Consumed starting in this
	// plan; defaults to "AES-256-GCM" when empty.
	Cipher string

	// OnSession is invoked exactly once per client, after Key Method 2 and
	// the PUSH_REQUEST/PUSH_REPLY exchange have both completed and the
	// data-channel keys and the assigned tunnel IP are live (D-08) — not
	// merely after tls.Conn.Handshake() has returned nil. The Session
	// handed to OnSession is therefore immediately usable: Session.
	// AssignedIP() is already populated and PeerCN is the verified client
	// CommonName (threat T-01-16).
	OnSession func(*Session)

	// OnSessionPanic, if set, is invoked when OnSession panics instead of
	// letting the panic take down the embedding process. It receives the
	// Session that was being handed to OnSession, the recovered panic
	// value, and a captured stack trace (runtime/debug.Stack()) so the
	// embedder has a diagnostic trail rather than a session that silently
	// vanishes. OnSessionPanic itself is called from inside the recover
	// path and must not panic.
	OnSessionPanic func(sess *Session, recovered any, stack []byte)
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

	// ipInboundQueueSize bounds each session's inbound raw-IP-packet queue
	// (D-14), matching inboundQueueSize above: a slow or stalled embedder
	// reading from Session.Read must not block the shared UDP read loop, so
	// a full queue drops the newest decrypted IP packet like a congested
	// link (D-06) rather than backing up handleDatagram.
	ipInboundQueueSize = 32

	// dataChannelKeyID is the TLS key slot ID written into every data
	// packet's header. Always 0 in v1: there is no renegotiation
	// (SESS-04, Phase 4), so every session ever has exactly one data-
	// channel key slot.
	dataChannelKeyID = 0

	// pingIntervalSeconds is the fixed v1 keepalive schedule (D-11):
	// push.go's buildPushReply pushes `ping N` using this exact value, and
	// session.go's per-session keepalive goroutine emits its own pings on
	// this exact period — reading both from one constant is what makes the
	// pushed schedule and the emitted schedule structurally unable to
	// drift apart. Not configurable in v1 (RESEARCH.md Deferred Ideas).
	pingIntervalSeconds = 10
	pingInterval        = pingIntervalSeconds * time.Second
)

// serverKM2Options is the options string this server sends in its own Key
// Method 2 message. Per RESEARCH.md Pitfall 4, options_cmp_equal
// (ssl.c:2498) only warns on mismatch (gated on --opt-verify, which this
// project's clients don't set) — a short, honest string describing this
// server's actual fixed configuration is sufficient for interop; there is
// no need to reproduce the reference's exact OCC options-string format
// byte-for-byte.
const serverKM2Options = "V4,dev-type tun,link-mtu 1541,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth SHA1,keysize 256,key-method 2,tls-server"

// pushRequestLiteral is the exact string a real OpenVPN client sends
// (NUL-terminated on the wire, per readControlString/push.go) to request
// its tunnel configuration, unlike Key Method 2's own length-prefixed
// field framing (RESEARCH Pattern 6, push.c:567,1089).
const pushRequestLiteral = "PUSH_REQUEST"

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

	// handshakeWindow bounds how long a session may sit in an incomplete
	// handshake before enforceHandshakeWindow tears it down. It defaults to
	// reliable.HandshakeWindow (the reference's --hand-window, 60s) and
	// exists as a field only so tests can exercise the timeout-triggered
	// teardown path without waiting a real minute.
	handshakeWindow time.Duration

	// pool is this server's tunnel-IP and peer-id allocator, built from
	// Config.Network in Serve. nil if Config.Network was never set — a
	// session that reaches the PUSH_REQUEST/PUSH_REPLY exchange with a nil
	// pool fails and is closed before OnSession fires (see
	// performPushExchange).
	pool *ipPool

	mu       sync.Mutex
	pc       net.PacketConn
	closed   bool
	sessions map[sessionKey]*Session

	// dataSessions routes P_DATA_V1/P_DATA_V2 datagrams to their Session,
	// keyed on the 24-bit peer-id ipPool.allocate() hands out (D-16,
	// Pitfall 3) — data packets carry no 8-byte session ID at the offset
	// sessions above is keyed on, so they need their own routing table.
	// Guarded by mu, exactly like sessions. A peer-id is only ever a
	// routing hint here, never a trust signal: the packet is only treated
	// as that session's traffic once its own AEAD tag verifies (T-02-12).
	dataSessions map[uint32]*Session
}

// NewServer builds a Server from cfg. It does not start listening — call
// Serve to begin reading from a net.PacketConn.
func NewServer(cfg Config) *Server {
	return &Server{
		cfg:             cfg,
		handshakeWindow: reliable.HandshakeWindow,
		sessions:        make(map[sessionKey]*Session),
		dataSessions:    make(map[uint32]*Session),
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
	// Config.Network is intentionally not required here: a Server built
	// without it can still complete Phase 1's TLS handshake (existing
	// tests exercise exactly that). It is only needed once a session
	// reaches the PUSH_REQUEST/PUSH_REPLY exchange (performPushExchange),
	// where a nil pool fails that one session rather than refusing to
	// serve at all. A malformed (non-nil but invalid) Network fails fast
	// here, though, exactly like the TLSCryptKey check above.
	if s.cfg.Network != nil {
		pool, err := newIPPool(s.cfg.Network)
		if err != nil {
			return fmt.Errorf("ovpn: %w", err)
		}
		s.pool = pool
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

	// Data packets (P_DATA_V1/P_DATA_V2) carry a 3-byte peer-id at this
	// offset, not an 8-byte session ID — this branch MUST run before the
	// control-opcode parse below, which would otherwise splice peer-id
	// bytes together with packet-id/tag bytes into a sessionKey that can
	// never match any control-channel session (Pitfall 3, D-16).
	if opcode == wire.OpDataV1 || opcode == wire.OpDataV2 {
		s.handleDataDatagram(opcode, packet)
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

// handleDataDatagram routes an already-triaged (length-bounded,
// opcode-valid) P_DATA_V1/P_DATA_V2 datagram to its session's decrypt path,
// keyed on the 24-bit peer-id at bytes 1..3 (Pitfall 3, D-16) — never by
// the sessionKey{addr,sid} table above, which these packets have no
// session-ID field for. A miss (unknown peer-id, or a peer-id with no live
// data-channel wrapper yet) drops the packet before any allocation
// (T-02-17, mirroring handleDatagram's own cheap-rejection discipline for
// forged control packets). P_DATA_V1 is not implemented this phase
// (RESEARCH.md, out of scope) — dropped explicitly rather than mis-parsed
// as V2.
func (s *Server) handleDataDatagram(opcode wire.Opcode, packet []byte) {
	if opcode != wire.OpDataV2 {
		return
	}
	if len(packet) < 4 {
		return
	}
	peerID := uint32(packet[1])<<16 | uint32(packet[2])<<8 | uint32(packet[3])

	s.mu.Lock()
	sess, ok := s.dataSessions[peerID]
	s.mu.Unlock()
	if !ok {
		return
	}

	sess.handleDataPacket(packet)
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
// Conn, then continues the bring-up sequence on the same goroutine through
// Key Method 2 and the PUSH_REQUEST/PUSH_REPLY exchange before
// Config.OnSession is ever invoked (D-08). sess.doneCh — which
// enforceHandshakeWindow watches to decide whether to tear a stalled
// session down — is deliberately NOT closed until this whole sequence
// finishes (success or failure): the handshake window now covers the
// entire bring-up, not merely tls.Conn.Handshake() returning nil, so a
// client that completes TLS but never requests its configuration is still
// reaped. A session that cannot complete any step is dead: sess.Close is
// called and OnSession never fires for it.
func (s *Server) runHandshake(sess *Session) {
	tlsConn := tls.Server(sess.conn, s.cfg.TLSConfig)
	err := tlsConn.Handshake()
	if err != nil {
		close(sess.doneCh)
		_ = sess.Close()
		return
	}

	state := tlsConn.ConnectionState()
	sess.connState = state
	if len(state.PeerCertificates) > 0 {
		sess.PeerCN = state.PeerCertificates[0].Subject.CommonName
	}

	if err := s.performKeyMethod2Exchange(sess, tlsConn); err != nil {
		close(sess.doneCh)
		_ = sess.Close()
		return
	}

	if err := s.performPushExchange(sess, tlsConn); err != nil {
		close(sess.doneCh)
		_ = sess.Close()
		return
	}

	close(sess.doneCh)

	// D-08: OnSession fires only here — after Key Method 2 and the
	// PUSH_REQUEST/PUSH_REPLY exchange have both completed and
	// sess.assignedIP/sess.dataKeys are both live — so the Session handed
	// to the embedder is immediately usable.
	if s.cfg.OnSession != nil {
		s.callOnSession(sess)
	}
}

// performPushExchange answers the client's PUSH_REQUEST with a byte-exact
// PUSH_REPLY (Pattern 6), reading from the same sess.tlsReader plan
// 02-01's performKeyMethod2Exchange established (D-15) — a second
// bufio.Reader over tlsConn would lose whatever bytes are already
// buffered. It allocates the client's tunnel IP and peer-id from s.pool
// exactly once per session: if the client's own retransmit timer causes a
// second "PUSH_REQUEST" to already be sitting in sess.tlsReader's buffer
// by the time this function replies to the first one, it answers that
// retransmit with the SAME assigned IP and peer-id rather than allocating
// again (T-02-06, TestOnSessionFiresExactlyOnce/TestPerformPushExchange
// AnswersBufferedRetransmitWithSameIP) before returning — it never blocks
// waiting for a retransmit that isn't already buffered. w takes only the
// io.Writer subset of *tls.Conn (its only actual runHandshake calls this
// with) so the retransmit-loop behavior above is directly, deterministically
// unit-testable without a live network round trip.
func (s *Server) performPushExchange(sess *Session, w io.Writer) error {
	if s.pool == nil {
		return errors.New("ovpn: Config.Network is not set; cannot answer PUSH_REQUEST")
	}

	cipher := s.cfg.Cipher
	if cipher == "" {
		cipher = "AES-256-GCM"
	}

	for {
		req, err := readControlString(sess.tlsReader, maxControlStringLen)
		if err != nil {
			return fmt.Errorf("ovpn: read push request: %w", err)
		}
		if req != pushRequestLiteral {
			return fmt.Errorf("ovpn: unexpected control string %q, want %q", req, pushRequestLiteral)
		}
		sess.pushRequested.Store(true)

		if sess.assignedIP == nil {
			ip, peerID, err := s.pool.allocate()
			if err != nil {
				return fmt.Errorf("ovpn: allocate tunnel IP: %w", err)
			}
			sess.assignedIP = ip
			sess.peerID = peerID

			// The data-channel Wrapper is constructed here, at the same
			// point the tunnel IP/peer-id are assigned and before
			// PUSH_REPLY is written — so it is live before OnSession ever
			// fires (D-08) and before the peer-id this datagram was routed
			// on could possibly reach the client. sess.dataKeys.ServerSlots
			// already applies the data channel's own key-direction
			// inversion (Pitfall 1) — do not re-derive it here.
			dataWrapper, err := datachan.NewWrapper(sess.dataKeys.ServerSlots(), peerID, dataChannelKeyID)
			if err != nil {
				return fmt.Errorf("ovpn: build data-channel wrapper: %w", err)
			}
			sess.dataWrapper = dataWrapper
			sess.ipInbound = make(chan []byte, ipInboundQueueSize)

			s.mu.Lock()
			s.dataSessions[peerID] = sess
			s.mu.Unlock()

			// D-11: the keepalive goroutine starts here too — alongside
			// the data wrapper, before PUSH_REPLY is written and well
			// before OnSession fires — emitting on exactly the schedule
			// buildPushReply below pushes to the client.
			sess.startKeepalive()
		}

		reply := buildPushReply(sess.assignedIP, s.cfg.Network, sess.peerID, cipher)
		if _, err := w.Write(reply); err != nil {
			return fmt.Errorf("ovpn: write push reply: %w", err)
		}

		if sess.tlsReader.Buffered() == 0 {
			return nil
		}
		// More bytes are already buffered — a retransmitted PUSH_REQUEST
		// that arrived before this reply went out. Loop to answer it too,
		// without allocating again (the sess.assignedIP == nil guard above
		// no longer triggers).
	}
}

// performKeyMethod2Exchange runs the Key Method 2 exchange over tlsConn,
// matching the reference server's own state-machine branch (tls_process,
// ssl.c:3002-3031: server is "Receive Key" at S_START, "Send Key" at
// S_GOT_KEY — the opposite order from the client, which already wrote its
// own message immediately after its handshake completed, per 01-03's
// documented deferral). It wraps tlsConn in a bufio.Reader retained on
// sess.tlsReader (D-15) so plan 02-02's PUSH_REQUEST continuation reads
// from the same buffered stream rather than losing bytes to a second
// reader. On success, sess.dataKeys holds the derived 256-byte key
// expansion.
func (s *Server) performKeyMethod2Exchange(sess *Session, tlsConn *tls.Conn) error {
	sess.tlsReader = bufio.NewReader(tlsConn)

	clientKM, _, err := keyderiv.ReadClientKeyMethod2(sess.tlsReader)
	if err != nil {
		return fmt.Errorf("ovpn: read client Key Method 2: %w", err)
	}
	sess.clientKM = clientKM

	serverKM, err := keyderiv.WriteServerKeyMethod2(tlsConn, serverKM2Options)
	if err != nil {
		return fmt.Errorf("ovpn: write server Key Method 2: %w", err)
	}
	sess.serverKM = serverKM

	src := &keyderiv.KeySource2{
		Client: *clientKM,
		Server: *serverKM,
	}
	// wire.SessionID / Session.SessionID are the same 8-byte
	// control-channel session IDs DeriveKeys wants (server's own
	// perspective: clientSID = the client's session ID we received,
	// serverSID = our own — ssl.c:1586-1589); the pointer conversions
	// below are between types with identical underlying [8]byte layout,
	// no new session-ID concept is introduced.
	dataKeys, err := keyderiv.DeriveKeys(src, (*[8]byte)(&sess.clientSessionID), (*[8]byte)(&sess.SessionID))
	if err != nil {
		return fmt.Errorf("ovpn: derive data-channel keys: %w", err)
	}
	sess.dataKeys = dataKeys
	return nil
}

// callOnSession invokes Config.OnSession with panic recovery: this runs on
// a per-session goroutine (see runHandshake), so an unrecovered panic in
// caller-supplied code would otherwise propagate up and crash the entire
// embedding process, taking down every other in-flight session along with
// it. A panicking OnSession is a bug in the embedder's callback, not a
// reason to bring down the host process for a library explicitly designed
// to be embedded "in any Go program" — so it is recovered here rather than
// allowed to escape. The recovered value and a stack trace are handed to
// Config.OnSessionPanic (if set) so the embedder isn't left debugging a
// mysteriously-disappearing session with zero diagnostic trail.
func (s *Server) callOnSession(sess *Session) {
	defer func() {
		if r := recover(); r != nil {
			if s.cfg.OnSessionPanic != nil {
				s.cfg.OnSessionPanic(sess, r, debug.Stack())
			}
		}
	}()
	s.cfg.OnSession(sess)
}

// enforceHandshakeWindow tears sess down and releases its state if the
// handshake has not completed within reliable.HandshakeWindow (the
// reference's --hand-window default, 60 seconds).
func (s *Server) enforceHandshakeWindow(sess *Session) {
	select {
	case <-sess.doneCh:
		return
	case <-time.After(s.handshakeWindow):
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
