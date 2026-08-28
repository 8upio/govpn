package ovpn

import (
	"bufio"
	"bytes"
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
	"github.com/8upio/govpn/internal/reliable"
	"github.com/8upio/govpn/internal/tlscrypt"
	"github.com/8upio/govpn/internal/wire"
)

// occMagic is OpenVPN's explicit-exit-notify magic prefix (D-21): sent as
// an ordinary encrypted data-channel payload, indistinguishable from IP
// traffic at the wire level until decrypted.
// Source: occ.c:55-58.
var occMagic = []byte{
	0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
	0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
}

// occExit is the OCC_EXIT opcode byte that follows occMagic in an
// explicit-exit-notify payload (D-21).
// Source: occ.h:29-30,67 (OCC_STRING_SIZE=16, OCC_EXIT=6).
const occExit = 0x06

// isExitNotify reports whether plaintext is a decrypted data-channel
// explicit-exit-notify payload (D-21): occMagic followed by occExit. This
// is ONLY ever meaningful on AUTHENTICATED plaintext, after a successful
// datachan.Wrapper.Open — the data channel is always encrypted first, so a
// pre-decrypt check against raw or ciphertext bytes could never match, and
// would move an unauthenticated attacker's bytes into a teardown decision
// (04-RESEARCH.md Anti-Pattern: "checking for OCC_EXIT before decryption").
// A non-match is the overwhelmingly common case (every real IP packet) and
// must stay a cheap, silent, non-error branch — never logged, never
// counted as an anomaly (Anti-Pattern: "treating a non-match as an
// error"). bytes.Equal is the correct tool here, not crypto/subtle: this
// is a public 16-byte protocol constant, not a secret, and the reference's
// own buf_string_match_head is not constant-time either (RESEARCH's
// "Don't Hand-Roll", row 1).
func isExitNotify(plaintext []byte) bool {
	return len(plaintext) >= 17 && bytes.Equal(plaintext[:16], occMagic) && plaintext[16] == occExit
}

// keySlot holds one TLS key-id's live data-channel state — the reference's
// own two-slot key_state[KS_PRIMARY]/key_state[KS_LAME_DUCK] design
// (ssl_common.h:448-451), modeled here as two named Session fields
// (primary/lameDuck below) rather than a map (04-01-PLAN.md's
// Claude's-discretion note: the reference itself never holds more than two
// live slots per session).
type keySlot struct {
	// keyID is this slot's TLS key-id: 0 for a session's very first key,
	// nextKeyID's 1..7 range thereafter (ssl.c:990-1002).
	keyID uint8

	// conn is this slot's own control-channel Conn: for the primary slot,
	// the Conn its TLS handshake ran over; for the lame-duck slot, the
	// demoted former-primary Conn, kept alive only so any of its own
	// still-in-flight retransmits/ACKs can complete until it is closed.
	conn *ctrlconn.Conn

	// wrapper is this slot's AES-256-GCM data-channel Wrapper. nil for the
	// primary slot until ovpn.go's performPushExchange (or a later
	// runRenegotiation) publishes it; nil for the lame-duck slot whenever
	// there has been no renegotiation yet.
	wrapper *datachan.Wrapper

	// established is when this slot's keys went live — the reneg-sec
	// deadline base (ssl.c:3098-3114's ks->established).
	established time.Time

	// mustDie is the zero value for a slot that has never been demoted
	// ("never expires"); set only when this slot is demoted into lameDuck,
	// to now+transitionWindow (ssl.c:1932, ssl.c:1297-1322). Never extended
	// once set — a late-arriving or rejected renegotiation must not buy the
	// old key more time (Pitfall 5).
	mustDie time.Time
}

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
// inside the decrypt path and never reaches Read's caller (D-11).
//
// A Session ends in exactly one of three ways, all of which flow through
// the same Close()/stopOnce contract and leave both Read and Write
// returning io.EOF: the embedder calling Close directly, the client
// sending an explicit-exit-notify on the authenticated data channel
// (D-21), or the server's own idle-session reaper closing a session that
// has gone silent for the reap window (D-22). In every case, Close tears
// down this session's control channel and releases its tunnel IP and
// peer-id back to the pool.
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

	// mu guards assignedIP, peerID, primary, lameDuck, pendingReneg,
	// pendingRenegKeyID, lastRenegAccepted, lastAuthTraffic, and dataKeys
	// below (WR-03, extended by 04-01-PLAN.md Task 1 from the single
	// dataWrapper field it originally guarded to this phase's two-slot key
	// state, by 04-02-PLAN.md Task 2 to lastAuthTraffic, and by 04-REVIEW.md
	// WR-01 to dataKeys — no new mutex): ovpn.go's performPushExchange and
	// runRenegotiation (running on this session's own goroutines) write
	// them, while Close — which enforceHandshakeWindow's timeout goroutine
	// can invoke concurrently at any point — reads them, and the public
	// DebugDataKeys accessor can be called from an arbitrary embedder/test
	// goroutine at any time. Without this lock those are an unsynchronized
	// concurrent read/write of the same memory from two goroutines,
	// undefined under the Go memory model. Every other field in this
	// struct has its own, already-established discipline (stopCh/
	// stopOnce, srv.mu for dataSessions/sessions) and does not need this
	// mutex — this notably excludes clientKM/serverKM (WR-01): those are
	// written exactly once, unlocked, during the single-writer initial
	// handshake before OnSession ever publishes the *Session to the
	// embedder, and never rewritten by runRenegotiation.
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
	// table on this same value (D-16), and never changes across a
	// renegotiation (D-16 note in 04-01-PLAN.md: no dataSessions rewrite is
	// needed on rollover). Guarded by mu.
	peerID uint32

	// clock abstracts wall-clock time for this session's server-initiated
	// reneg-sec timer, the lame-duck mustDie deadline, and the
	// reneg-flood rate limit, so fast-tier tests can drive all three from
	// an injected fake clock instead of real sleeps — the same
	// internal/reliable.Clock interface internal/ctrlconn.Conn's own clock
	// parameter already uses. nil means reliable.SystemClock{} (see now()
	// below). Set once, at session construction (ovpn.go's
	// handleDatagram), from a test-only Server.clock field that defaults
	// to nil in production.
	clock reliable.Clock

	// primary is this session's currently-active key-id's data-channel
	// state: the slot Write/emitPing seal through, and the slot
	// handleDataPacket tries first on decrypt. Populated once, in ovpn.go's
	// performPushExchange (key-id 0), and re-published by runRenegotiation
	// on every subsequent successful renegotiation. Guarded by mu.
	primary keySlot

	// lameDuck is the just-demoted former-primary key-id's data-channel
	// state, kept decryptable until mustDie (D-18) so in-flight traffic
	// sealed under the old key during a rollover is never dropped. The
	// zero value (wrapper == nil) means "no lame duck" — true for the
	// whole life of a session that never renegotiates. Guarded by mu.
	lameDuck keySlot

	// pendingReneg is the new key-id's control-channel Conn while a
	// renegotiation handshake is in flight — published by
	// (*Server).startRenegotiation before the triggering (or
	// server-initiated) packet is even delivered to it, so pump can route
	// that key-id's control traffic correctly from the very first packet.
	// Cleared once runRenegotiation's atomic swap installs it as the new
	// primary, or abandons it on failure. nil when no renegotiation is in
	// progress. Guarded by mu, alongside pendingRenegKeyID.
	pendingReneg      *ctrlconn.Conn
	pendingRenegKeyID uint8

	// lastRenegAccepted is when this session last began (not necessarily
	// finished) a renegotiation, client- or server-initiated. Enforces
	// T-04-01's minimum-interval rate limit (Task 3): an otherwise-valid
	// SOFT_RESET_V1 arriving within renegMinInterval of this timestamp is
	// refused — defense in depth on top of tls-crypt's own replay window
	// (Phase 1) against a legitimate peer's SOFT_RESET_V1 replayed
	// rapidly. The zero value means "never renegotiated": the first one is
	// always allowed through this check. Guarded by mu.
	lastRenegAccepted time.Time

	// renegotiations counts how many soft-reset key rollovers this session
	// has completed — a diagnostic accessor in the PeerID()/PushRequestSeen()
	// family (04-03-PLAN.md Task 1): not part of the contract a production
	// embedder needs, but a test harness can assert a real rollover actually
	// happened rather than trusting a PASS line alone. Incremented exactly
	// once per completed rollover, inside ovpn.go's runRenegotiation, under
	// the same sess.mu critical section that publishes the new primary slot
	// (04-01-PLAN.md's atomic-swap point) — so a partially-failed
	// renegotiation (abandoned before that swap) never increments it.
	// Guarded by mu.
	renegotiations uint32

	// lastAuthTraffic is when this session last received AUTHENTICATED
	// traffic — a delivered control packet (ovpn.go's pump) or a
	// successfully-decrypted data packet, primary or lame-duck slot
	// (handleDataPacket) — mirroring the reference's own two reset sites
	// (Pattern 6: forward.c:1093-1103 control path, forward.c:1184 data
	// path). Session.runReap compares s.now() against this to decide
	// whether to reap (D-22). A packet that fails to authenticate never
	// touches this (T-04-07): an attacker cannot keep a dead session alive
	// with garbage. Initialized at the same publish point
	// startKeepalive/startReneg are (ovpn.go's performPushExchange).
	// Guarded by mu.
	lastAuthTraffic time.Time

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

// now returns the current time from s.clock, or reliable.SystemClock{} if
// no clock was injected — the same nil-defaulting convention
// internal/ctrlconn.Conn's own clock parameter already uses (New/
// NewWithKeyID).
func (s *Session) now() time.Time {
	if s.clock == nil {
		return reliable.SystemClock{}.Now()
	}
	return s.clock.Now()
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

// RenegotiationCount reports how many soft-reset key rollovers this session
// has completed (04-03-PLAN.md Task 1) — a diagnostic accessor in the same
// spirit as PeerID/PushRequestSeen above: an external package (the interop
// harness's PASS line) can report the value a test harness asserts against,
// but a production embedder has no reason to call it.
func (s *Session) RenegotiationCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renegotiations
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
//
// WR-01 (04-REVIEW.md): dataKeys is written under sess.mu by
// runRenegotiation's rollover swap (and, as of this fix, by
// performKeyMethod2Exchange's initial write too), so this read must take
// the same lock — an embedder or test harness can call this concurrently
// with a live renegotiation, with no other synchronization point in
// between.
func (s *Session) DebugDataKeys() (keys keyderiv.DataKeys, ok bool) {
	s.mu.Lock()
	dataKeys := s.dataKeys
	s.mu.Unlock()
	if dataKeys == nil {
		return keyderiv.DataKeys{}, false
	}
	return dataKeys.ServerSlots(), true
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
// matching io.Writer's contract for a full write. After this session has
// been torn down — by any of the three causes Session's own doc comment
// names (embedder Close, client exit-notify, idle reap) — Write returns
// io.EOF (D-22), distinct from the "data channel not yet established"
// error below, which is the genuinely-pre-tunnel-up case: a session that
// is merely still negotiating is not the same as one that has already
// ended.
func (s *Session) Write(p []byte) (int, error) {
	if s.closing() {
		return 0, io.EOF
	}

	s.mu.Lock()
	wrapper := s.primary.wrapper
	s.mu.Unlock()

	if wrapper == nil {
		return 0, errors.New("ovpn: data channel not yet established")
	}
	sealed, err := wrapper.Seal(nil, p)
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
	s.mu.Lock()
	primary := s.primary
	lameDuck := s.lameDuck
	s.mu.Unlock()

	if primary.wrapper == nil {
		return
	}
	plaintext, err := primary.wrapper.Open(nil, packet)
	if err != nil {
		// Includes datachan.ErrPingAbsorbed: a ping is absorbed inside
		// Open, never delivered, and never counts as a delivered IP
		// packet. Fall back to the lame-duck slot (D-18) ONLY if it is
		// still live: try primary first (the common case, cheapest),
		// lameDuck only on failure and only before its mustDie deadline
		// (Pitfall 5) — both failing is the existing silent drop (T-02-17):
		// no allocation, no logging, no per-attacker state, and — per
		// T-04-07 — no touch of lastAuthTraffic: an attacker cannot keep a
		// dead session alive with garbage that never authenticates.
		if lameDuck.wrapper == nil || !s.now().Before(lameDuck.mustDie) {
			return
		}
		plaintext, err = lameDuck.wrapper.Open(nil, packet)
		if err != nil {
			return
		}
	}

	// D-22/Pattern 6 (forward.c:1184): any successfully-decrypted data
	// packet — primary or lame-duck — resets the idle-reap timer, exactly
	// like a delivered control packet does (ovpn.go's pump).
	s.touchAuthTraffic()

	// D-21/Pattern 5 (forward.c:1196-1207): checked ONLY here, after a
	// successful Open, before ever reaching the ipInbound delivery select
	// below — never on raw or ciphertext bytes (isExitNotify's own doc
	// comment). A match tears the session down immediately through the
	// existing Close()/stopOnce path, adding no new teardown path; the
	// payload itself is never delivered to ipInbound and never treated as
	// an error.
	if isExitNotify(plaintext) {
		_ = s.Close()
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

// routeControlPacket returns the Conn that should receive an inbound
// control packet at the given key-id, or nil if none matches (in which
// case ovpn.go's pump silently drops it — the same "queue full / no match"
// drop discipline handleDatagram's own inbound-queue select already
// applies). Before ovpn.go's performPushExchange populates the primary
// slot, this session's only Conn is sess.conn at key-id 0 (the initial
// handshake's own control channel) — route there directly rather than
// through an as-yet-empty primary slot, so this migration changes nothing
// about a session's pre-push-exchange behavior. Once primary is populated,
// route by exact key-id match against primary, then lameDuck (only while
// its Conn is still live), then a renegotiation-in-flight Conn.
func (sess *Session) routeControlPacket(keyID uint8) *ctrlconn.Conn {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.primary.conn == nil {
		if keyID == 0 {
			return sess.conn
		}
		return nil
	}

	if keyID == sess.primary.keyID {
		return sess.primary.conn
	}
	if sess.lameDuck.conn != nil && keyID == sess.lameDuck.keyID {
		return sess.lameDuck.conn
	}
	if sess.pendingReneg != nil && keyID == sess.pendingRenegKeyID {
		return sess.pendingReneg
	}
	return nil
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

// startReneg starts this session's server-initiated reneg-sec timer
// goroutine (D-17, D-19): a real time.Ticker at renegPollInterval feeds
// runReneg below. Called once, from ovpn.go's performPushExchange, at the
// same point startKeepalive is (alongside the data wrapper going live) —
// so it arms without depending on any inbound client traffic (Pitfall 2).
func (s *Session) startReneg() {
	ticker := time.NewTicker(renegPollInterval)
	go func() {
		defer ticker.Stop()
		s.runReneg(ticker.C)
	}()
}

// runReneg is startReneg's own core loop, factored out — the same
// start*/run* split startKeepalive/runKeepalive already establish — so
// tests can drive it from an injected tick channel instead of a real
// renegPollInterval ticker. It selects on stopCh and exits on Close, with
// no second teardown signal, exactly like runKeepalive.
func (s *Session) runReneg(tickCh <-chan time.Time) {
	for {
		select {
		case <-tickCh:
			s.sweepLameDuck()
			s.checkReneg()
		case <-s.stopCh:
			return
		}
	}
}

// sweepLameDuck closes and clears the lame-duck slot once its mustDie
// deadline has passed (T-04-03, mirrors lame_duck_must_die,
// ssl.c:1297-1322): closing its Conn frees its retransmit goroutine.
// Runs on the SAME ticker startReneg already owns — not a third
// goroutine. This is a bound on the slot's Conn/goroutine LIFETIME,
// deliberately separate from handleDataPacket's own mustDie check, which
// bounds the old key's decrypt VALIDITY on a per-packet basis — dropping
// either check is exactly how a leaked retransmit goroutine or an "old
// key works forever" regression gets in (Pitfall 5). mustDie is never
// extended by this sweep or anything else: a late-arriving or rejected
// renegotiation never buys the old key more time.
func (s *Session) sweepLameDuck() {
	s.mu.Lock()
	conn := s.lameDuck.conn
	expired := s.lameDuck.wrapper != nil && !s.now().Before(s.lameDuck.mustDie)
	if expired {
		s.lameDuck = keySlot{}
	}
	s.mu.Unlock()

	if expired && conn != nil {
		_ = conn.Close()
	}
}

// checkReneg compares the elapsed time since the primary slot's
// established timestamp against the server's resolved reneg-sec interval
// (ssl.c:3098-3114's own trigger condition), and, on expiry, takes the
// SEND side of the same startRenegotiation path beginRenegotiation (the
// receive side, ovpn.go) already uses — so the two sides' key-id counters
// can never drift apart by growing separately-maintained copies. If a
// renegotiation is already in flight (startRenegotiation's own in-flight
// check), this tick is a no-op: the in-flight one wins (D-17 "first to
// fire wins").
func (s *Session) checkReneg() {
	if s.srv == nil {
		return
	}
	s.mu.Lock()
	established := s.primary.established
	s.mu.Unlock()
	if established.IsZero() {
		return
	}
	if s.now().Sub(established) < s.srv.renegSec {
		return
	}
	if s.srv.pc == nil {
		return
	}

	newConn, keyID, ok := s.srv.startRenegotiation(s, s.srv.pc, s.RemoteAddr, 0, false)
	if !ok {
		return
	}
	// Best-effort: if the transport write fails transiently, the entry is
	// already queued in newConn's own send-side reliability window and its
	// retransmit loop will retry it, exactly like emitPing's own ignored
	// WriteTo error below.
	_ = newConn.SendReset(wire.OpControlSoftResetV1)
	go s.srv.runRenegotiation(s, newConn, keyID)
}

// touchAuthTraffic stamps lastAuthTraffic with s.now() (D-22, Pattern 6:
// forward.c:1093-1103 control path, forward.c:1184 data path). Called only
// from a delivered control-packet path (ovpn.go's pump) or after a
// successful data-channel decrypt (handleDataPacket) — never for traffic
// that failed to authenticate (T-04-07). Guarded by mu, the same lock
// lastAuthTraffic itself is guarded by.
func (s *Session) touchAuthTraffic() {
	s.mu.Lock()
	s.lastAuthTraffic = s.now()
	s.mu.Unlock()
}

// startReap starts this session's idle-session reaper goroutine (D-22): a
// real time.Ticker at reapPollInterval feeds runReap below. Called once,
// from ovpn.go's performPushExchange, at the same point
// startKeepalive/startReneg are — alongside the data wrapper going live —
// so it arms without depending on any inbound client traffic ever having
// touched lastAuthTraffic (lastAuthTraffic is initialized at that same
// publish point).
func (s *Session) startReap() {
	ticker := time.NewTicker(reapPollInterval)
	go func() {
		defer ticker.Stop()
		s.runReap(ticker.C)
	}()
}

// runReap is startReap's own core loop, factored out — the same
// start*/run* split startKeepalive/runKeepalive and startReneg/runReneg
// already establish — so tests can drive it from an injected tick channel
// instead of a real reapPollInterval ticker. On each tick, if no
// authenticated traffic has arrived for at least the server's reap window
// (s.srv.reapWindow, server-authoritative and independent of what the
// client believes — D-22), this session is torn down through the existing
// Close()/stopOnce path: no new teardown path, and the netstack's read
// loop then observes io.EOF and detaches, with no new coupling in either
// direction. Exits on stopCh, the same discipline every other per-session
// goroutine already establishes. A hand-constructed Session with no srv
// (some fast-tier tests build one directly) never reaps — s.srv is always
// set for a real session, published before startReap is ever called.
func (s *Session) runReap(tickCh <-chan time.Time) {
	for {
		select {
		case <-tickCh:
			if s.srv == nil {
				continue
			}
			s.mu.Lock()
			last := s.lastAuthTraffic
			s.mu.Unlock()
			if s.now().Sub(last) >= s.srv.reapWindow {
				_ = s.Close()
				return
			}
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
	s.mu.Lock()
	wrapper := s.primary.wrapper
	s.mu.Unlock()

	if wrapper == nil {
		return
	}
	sealed, err := wrapper.SealPing(nil)
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
			dataWrapper := s.primary.wrapper
			primaryConn := s.primary.conn
			lameDuckConn := s.lameDuck.conn
			pendingRenegConn := s.pendingReneg

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

			// Close every control-channel Conn this session might have
			// owned beyond sess.conn (closed unconditionally below): the
			// current primary slot's Conn (identical to sess.conn until
			// the first renegotiation), any still-live lame-duck Conn, and
			// any renegotiation Conn still mid-handshake. ctrlconn.Conn's
			// own Close is idempotent (sync.Once), so closing the same
			// *ctrlconn.Conn more than once here — e.g. primaryConn ==
			// sess.conn on a session that never renegotiated — is
			// harmless; what matters is that none is ever left un-closed,
			// which would leak its retransmit goroutine (04-01-PLAN.md
			// Task 1 action 2).
			for _, c := range [...]*ctrlconn.Conn{primaryConn, lameDuckConn, pendingRenegConn} {
				if c != nil {
					_ = c.Close()
				}
			}
		}
	})
	if s.conn == nil {
		return nil
	}
	return s.conn.Close()
}

var _ io.ReadWriteCloser = (*Session)(nil)
