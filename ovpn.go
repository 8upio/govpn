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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// discardLogger is the resolved logger for a Server (or Session) built with
// no Config.Logger: slog.DiscardHandler reports Enabled(...) == false for
// every level, so every log site behind an Enabled guard costs nothing, and
// every unconditional Debug/Info/Warn call is dropped by the handler itself
// without ever allocating a record. Resolved once, package-level, so no log
// site anywhere needs to branch on nil (D-01).
var discardLogger = slog.New(slog.DiscardHandler)

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

	// RenegSec is this server's own renegotiation deadline (D-19): once a
	// session's active key has been established for at least this long,
	// the server starts its own soft-reset renegotiation with no inbound
	// client packet required — the server's own timer, independent of
	// whatever the client's own reneg-sec might be (D-17: both sides run
	// independent timers; whichever fires first wins, matching the
	// reference's own tls_process, ssl.c:3098-3114). 0 means the
	// reference's own reneg-sec default of 3600 seconds (options.c:878).
	// Deliberately never pushed to the client as a `reneg-sec` option — see
	// D-19.
	RenegSec time.Duration

	// OnSessionClosed, if set, is invoked at most once per session — ONLY
	// for a session that was actually handed to OnSession — after that
	// session's teardown has fully completed, with the CloseReason
	// distinguishing why: the embedder calling Session.Close directly
	// (CloseReasonEmbedder), an authenticated client-side
	// explicit-exit-notify (CloseReasonClientExitNotify), the server's own
	// idle-session reaper (CloseReasonIdleReap), Server.Close tearing down
	// every live session (CloseReasonServerClose), or Config.AuthUserPass
	// rejecting a renegotiation's credentials (CloseReasonAuthFailed —
	// note this reason only ever appears here for a renegotiation-time
	// rejection; an initial-handshake rejection never reaches OnSession in
	// the first place, so it never reaches OnSessionClosed either). It runs
	// on its own goroutine, separate from whatever goroutine performed the teardown,
	// so a slow or blocking OnSessionClosed never delays that teardown
	// itself — but Server.Close DOES wait for every OnSessionClosed
	// invocation it triggered to return before Server.Close itself
	// returns, so OnSessionClosed must never call Server.Close (that would
	// deadlock). Panics are recovered and routed to Config.OnSessionPanic,
	// exactly like OnSession's own panic-recovery contract.
	OnSessionClosed func(sess *Session, reason CloseReason)

	// PingInterval is how often this server emits its own data-channel
	// ping keepalive AND the value pushed to the client as `ping N`
	// (seconds, floored at 1). Zero means the reference's own 10-second
	// default (pingInterval). Server-authoritative: changing it changes
	// both what this server actually does and what it tells the client to
	// expect, so the two can never drift apart (the same property the
	// fixed pingIntervalSeconds constant used to guarantee by
	// construction).
	PingInterval time.Duration

	// ReapWindow is how long a session may go without any authenticated
	// traffic before the idle-session reaper (D-22) closes it, AND the
	// value pushed to the client as `ping-restart M` (seconds, floored at
	// 1). Zero means the reference's own 60-second default
	// (defaultReapWindow). Server-authoritative and independent of
	// whatever the client believes, exactly like the previous fixed
	// ping-restart 60 literal — only now derived from this field instead
	// of hardcoded. Serve rejects a configured ReapWindow smaller than
	// twice the resolved PingInterval.
	ReapWindow time.Duration

	// SessionInboundQueue overrides the per-session inbound raw-IP-packet
	// queue depth (D-14) a Session's Read drains from. Zero means the
	// reference's own default (ipInboundQueueSize, 32). A larger value
	// tolerates a bigger burst of inbound packets before the queue's
	// existing drop-newest overflow policy (D-06) kicks in — useful for a
	// bursty embedder (e.g. RTP) that can occasionally fall behind Read.
	SessionInboundQueue int

	// AuthUserPass, if set, authenticates a client's username/password
	// credentials from its Key Method 2 message. nil means today's
	// behaviour exactly: credentials are still parsed off the wire (they
	// have to be, to reach peer_info behind them — ssl.c:2420-2423) but
	// are otherwise ignored. When set, the hook runs on the INITIAL
	// handshake and on EVERY renegotiation (ssl.c:2426-2470's
	// verify_user_pass is reached from key_method_2_read, i.e. once per
	// key exchange — a real client re-sends its credentials in each Key
	// Method 2 message, so a client cannot authenticate once and then
	// rotate keys unauthenticated).
	//
	// A credential field that is empty, or whose on-wire length exceeds
	// USER_PASS_LEN (128 bytes, misc.h:65-70), is an auth failure the hook
	// never sees — never a panic, never a silent pass (D-02). A non-nil
	// error from the hook rejects the client: it receives the control
	// string AUTH_FAILED (or AUTH_FAILED,<reason> if the error implements
	// AuthClientReason) and the session is torn down with
	// CloseReasonAuthFailed. A panicking hook is recovered, routed to
	// Config.OnSessionPanic exactly like a panicking OnSession, and
	// treated as a rejection (fail closed).
	//
	// The hook must be safe for concurrent use across sessions (it may be
	// called from many session goroutines at once) and must not block for
	// long: it runs inside the session's handshake window
	// (Server.handshakeWindow), so a slow hook can starve that budget for
	// legitimate protocol work.
	AuthUserPass func(username, password string, cs tls.ConnectionState) error

	// Logger, if set, receives structured (log/slog) records for handshake
	// progress and failure, session lifecycle, authentication decisions,
	// renegotiation, and every datagram the dispatch silently drops. nil (the
	// default) means a no-op logger: nothing is emitted and nothing is
	// allocated for it — resolved once into a discard handler whose
	// Enabled() reports false for every level, so a nil Logger costs the
	// same as today's silence.
	//
	// Info carries one record per lifecycle event (server listening/
	// closing, session established/closed, auth rejected, renegotiation
	// started/completed). Warn carries failures worth investigating
	// (handshake/renegotiation failures, handshake/renegotiation window
	// timeouts, idle reaps, tunnel-IP pool exhaustion, recovered callback
	// panics). Debug carries every per-datagram drop and renegotiation
	// refusal — this is deliberate, not an oversight: an unauthenticated
	// peer can trigger these without limit, so keeping them at Debug (never
	// Info) is what keeps a forged-datagram flood from becoming a
	// disk-filling log-volume amplifier at the library's default log level.
	//
	// The library never logs passwords, tls-crypt or data-channel key
	// material, or packet payload bytes — see docs/CONFIGURATION.md's
	// "Logger" section for the full closed set of message strings and
	// attribute keys.
	Logger *slog.Logger
}

// AuthClientReason is the optional interface an error returned from
// Config.AuthUserPass may implement to supply a human-readable rejection
// reason sent to the client as AUTH_FAILED,<reason> instead of the plain
// AUTH_FAILED form (push.c:396-430 send_auth_failed, push.c:49-70
// receive_auth_failed). The reason is sanitized before it reaches the wire
// (control bytes stripped, capped at 128 bytes) so it cannot inject a NUL
// (which would truncate the control string) or a newline (which would
// corrupt the client's log parsing).
type AuthClientReason interface{ ClientReason() string }

// CloseReason distinguishes why a Session ended, reported to
// Config.OnSessionClosed and readable at any time via Session.CloseReason.
type CloseReason int

const (
	// CloseReasonUnknown is a still-live session's CloseReason (Done() has
	// not fired yet), and is also what a session torn down BEFORE it was
	// ever published to OnSession records — a handshake failure or
	// handshake-window timeout, for instance. Such a session never
	// triggers OnSessionClosed at all (see Session.published), so
	// CloseReasonUnknown is never itself the reason argument
	// OnSessionClosed observes; it is only ever visible through
	// CloseReason() called on a session that has not (yet, or ever)
	// completed teardown, or was never published.
	CloseReasonUnknown CloseReason = iota

	// CloseReasonEmbedder is recorded when the embedder calls
	// Session.Close directly.
	CloseReasonEmbedder

	// CloseReasonClientExitNotify is recorded when the client sends an
	// authenticated explicit-exit-notify on the data channel (D-21).
	CloseReasonClientExitNotify

	// CloseReasonIdleReap is recorded when the server's own idle-session
	// reaper closes a session that has gone silent for the reap window
	// (D-22).
	CloseReasonIdleReap

	// CloseReasonServerClose is recorded when Server.Close tears down
	// every still-live session.
	CloseReasonServerClose

	// CloseReasonReplaced is reserved for a future static-IP "replace the
	// existing session for this identity" teardown path. It is never
	// produced by this package today — declared now, ahead of that
	// feature, so the CloseReason enum's wire/API shape is stable across
	// the v0.1.0 -> v0.2.0 boundary rather than growing a new constant
	// value later that could renumber nothing (iota-based enums are
	// append-only safe) but would still be a mid-cycle behavioral surprise
	// for anyone switching exhaustively on CloseReason today.
	CloseReasonReplaced

	// CloseReasonAuthFailed is recorded when Config.AuthUserPass rejected
	// the client's credentials (a non-nil error, an empty or over-long
	// credential field, or a recovered hook panic). On the INITIAL
	// handshake the session was never published (Session.published), so
	// OnSessionClosed does NOT fire for it — same rule as any other
	// handshake-time failure. On a RENEGOTIATION the session was already
	// published, so OnSessionClosed DOES fire with this reason.
	CloseReasonAuthFailed
)

// String returns a lowercase-kebab token for r, or a numeric fallback for
// an unrecognized value.
func (r CloseReason) String() string {
	switch r {
	case CloseReasonUnknown:
		return "unknown"
	case CloseReasonEmbedder:
		return "embedder"
	case CloseReasonClientExitNotify:
		return "client-exit-notify"
	case CloseReasonIdleReap:
		return "idle-reap"
	case CloseReasonServerClose:
		return "server-close"
	case CloseReasonReplaced:
		return "replaced"
	case CloseReasonAuthFailed:
		return "auth-failed"
	default:
		return fmt.Sprintf("CloseReason(%d)", int(r))
	}
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

	// keyIDMask masks a TLS key-id to its 3-bit wire range (P_KEY_ID_MASK =
	// 0x07, ssl_pkt.h:38) before any comparison — a key-id is
	// attacker-supplied on the wire until validated against nextKeyID's own
	// local computation (Pitfall 4).
	keyIDMask = 0x07

	// transitionWindow is how long a demoted (lame-duck) key stays
	// decryptable after a renegotiation (D-18).
	// Source: options.c:881 (--tran-window default, o->transition_window
	// = 3600).
	transitionWindow = 3600 * time.Second

	// defaultRenegSec is Config.RenegSec's default when left at its zero
	// value (D-19).
	// Source: options.c:878 (--reneg-sec default, o->renegotiate_seconds
	// = 3600).
	defaultRenegSec = 3600 * time.Second

	// renegMinIntervalDivisor computes Server.renegMinInterval as a
	// fraction (1/60th) of s.renegSec — the ACTIVE reneg-sec value
	// (Config.RenegSec, possibly shortened by a test harness, D-19), not a
	// fixed floor derived from the reference's own 3600s default. This is
	// a bug fix (04-03-PLAN.md Task 2, Rule 1): the original 04-01 design
	// fixed this at defaultRenegSec/60 = 60s regardless of the configured
	// RenegSec, which silently refused EVERY renegotiation after the first
	// whenever a harness configured a reneg-sec shorter than 60s (exactly
	// what D-23's own "~20s on both sides" interop scenario needs to
	// observe multiple rollovers) — discovered running this plan's own
	// "reneg" scenario, which reported renegotiations=1 no matter how many
	// times the real client's own 15-second reneg-sec timer re-fired.
	// Scaling by the same 1/60 ratio to whatever reneg-sec IS configured
	// preserves the original design intent (defense in depth against a
	// legitimate but abusive peer forcing rapid, distinct, validly-signed
	// SOFT_RESET_V1 requests — tls-crypt's own replay window, Phase 1,
	// remains the PRIMARY defense against a byte-identical REPLAYED
	// packet) while no longer conflicting with a deliberately shortened
	// reneg-sec.
	renegMinIntervalDivisor = 60

	// renegPollInterval is how often each session's reneg-sec timer
	// (Session.startReneg/runReneg) checks whether it's due — a
	// poll-granularity constant, not a reference constant, mirroring
	// ctrlconn's own retransmitInterval precedent (a fixed poll standing
	// in for the reference's own exact-wakeup event loop).
	renegPollInterval = 1 * time.Second

	// pingIntervalSeconds/pingInterval are Config.PingInterval's DEFAULT
	// (D-11): Server.pingInterval resolves to this constant when
	// Config.PingInterval is left at its zero value (NewServer). Both
	// push.go's buildPushReply `ping N` and session.go's per-session
	// keepalive goroutine read the SAME resolved Server.pingInterval
	// field, never this constant directly once a Server exists — that is
	// what keeps the pushed schedule and the emitted schedule
	// structurally unable to drift apart, the same guarantee this
	// constant alone used to provide back when PingInterval was not yet
	// configurable (Welle-1 item 1e superseded that v1 restriction).
	pingIntervalSeconds = 10
	pingInterval        = pingIntervalSeconds * time.Second

	// defaultReapWindow is Config.ReapWindow's DEFAULT: how long a session
	// may go without any authenticated traffic (control or data, primary
	// or lame-duck) before the idle-session reaper (Session.startReap/
	// runReap) closes it (D-22) when Config.ReapWindow is left at its zero
	// value (NewServer). This is the ping-restart window 04-CONTEXT.md
	// originally locked at 60 seconds, server-authoritative and
	// deliberately independent of what the client believes — Welle-1 item
	// 1e made it configurable via Config.ReapWindow, but the DEFAULT
	// stays expressed as 6*pingInterval rather than a bare 60*time.Second
	// so the unconfigured relationship to the default pushed keepalive
	// schedule stays structural, not just documented.
	// Source: 04-CONTEXT.md D-22; forward.c:1093-1103/1184 (Pattern 6).
	defaultReapWindow = 6 * pingInterval

	// reapPollInterval is how often each session's idle-reap timer
	// (Session.startReap/runReap) checks whether it's due — a
	// poll-granularity constant, not a reference constant, mirroring
	// renegPollInterval's own precedent above.
	reapPollInterval = 1 * time.Second
)

// nextKeyID computes the next TLS key-id in the renegotiation sequence:
// incrementing mod 8 (keyIDMask), but skipping back to 1 rather than 0 — 0
// is reserved for a session's very first key.
// Source: ssl.c:990-1002 ("key_id increments to KEY_ID_MASK then recycles
// back to 1 ... if key_id is 0, it is the first key"), ssl_pkt.h:38
// (P_KEY_ID_MASK = 0x07).
func nextKeyID(current uint8) uint8 {
	next := (current + 1) & keyIDMask
	if next == 0 {
		next = 1
	}
	return next
}

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

	// reapWindow bounds how long a session may go without any
	// authenticated traffic before Session.runReap closes it (D-22). It
	// defaults to defaultReapWindow and exists as a field only so tests can
	// exercise idle-session reaping without waiting a real 60 seconds —
	// the same test-injectable-field precedent handshakeWindow above
	// already establishes.
	reapWindow time.Duration

	// pingInterval is Config.PingInterval resolved once in NewServer (0 ->
	// pingInterval constant), read by every session's keepalive goroutine
	// (Session.startKeepalive) and by buildPushReply's `ping N` value.
	// Resolved in NewServer rather than Serve so the existing
	// direct-field-override test precedent (srv.reapWindow set by hand
	// after NewServer) keeps working unchanged for this field too.
	pingInterval time.Duration

	// sessionInboundQueue is Config.SessionInboundQueue resolved once in
	// NewServer (0 -> ipInboundQueueSize), sized into each session's
	// ipInbound channel by performPushExchange.
	sessionInboundQueue int

	// cbMu/cbCount/cbDone track in-flight OnSessionClosed callback
	// goroutines so Server.Close can wait for all of them to return before
	// Close itself returns. Deliberately NOT a sync.WaitGroup: a
	// reap/exit-notify-driven cbBegin can land while Close is already
	// inside cbWait and the counter has fallen back to zero — exactly the
	// reuse-after-zero hazard sync.WaitGroup's own docs warn against
	// (calling Add concurrently with a Wait that could return). A
	// mutex-guarded counter plus a one-shot completion channel, created
	// fresh by cbWait itself, has no such restriction.
	cbMu    sync.Mutex
	cbCount int
	cbDone  chan struct{}

	// pool is this server's tunnel-IP and peer-id allocator, built from
	// Config.Network in Serve. nil if Config.Network was never set — a
	// session that reaches the PUSH_REQUEST/PUSH_REPLY exchange with a nil
	// pool fails and is closed before OnSession fires (see
	// performPushExchange).
	pool *ipPool

	// renegSec is Config.RenegSec resolved once in Serve (0 ->
	// defaultRenegSec), so every session's reneg-sec timer reads the same
	// already-defaulted value rather than re-resolving it per session.
	renegSec time.Duration

	// renegMinInterval is resolved once in Serve, alongside renegSec, as
	// renegSec/renegMinIntervalDivisor (04-03-PLAN.md Task 2 bug fix — see
	// renegMinIntervalDivisor's own doc comment). A hand-built *Server in a
	// test bypasses this resolution and must set it explicitly if the test
	// exercises rate-limiting behavior, mirroring handshakeWindow/
	// reapWindow's own established explicit-set-required precedent for
	// hand-built Servers.
	renegMinInterval time.Duration

	// clock is a test-only override for every new Session's own clock
	// field (Session.now, the reneg-sec timer, lame-duck mustDie, and the
	// reneg-flood rate limit). nil in production, meaning
	// reliable.SystemClock{}; only ever set directly by a test constructing
	// a *Server by hand (never via NewServer/Config).
	clock reliable.Clock

	// log is Config.Logger, copied as-is (no defaulting here — logger()
	// below is the single resolution point every log site reads through, so
	// nothing else ever branches on nil).
	log *slog.Logger

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
	reapWindow := cfg.ReapWindow
	if reapWindow == 0 {
		reapWindow = defaultReapWindow
	}
	pi := cfg.PingInterval
	if pi == 0 {
		pi = pingInterval
	}
	sessionInboundQueue := cfg.SessionInboundQueue
	if sessionInboundQueue == 0 {
		sessionInboundQueue = ipInboundQueueSize
	}
	return &Server{
		cfg:                 cfg,
		log:                 cfg.Logger,
		handshakeWindow:     reliable.HandshakeWindow,
		reapWindow:          reapWindow,
		pingInterval:        pi,
		sessionInboundQueue: sessionInboundQueue,
		sessions:            make(map[sessionKey]*Session),
		dataSessions:        make(map[uint32]*Session),
	}
}

// logger returns s.log, or discardLogger when s is nil or s.log is nil
// (F6: a hand-built *Server in a test may have no log field set at all) —
// the single resolution point every server-side log site reads through, so
// no call site anywhere branches on nil itself (D-01).
func (s *Server) logger() *slog.Logger {
	if s == nil || s.log == nil {
		return discardLogger
	}
	return s.log
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
	// D-07: an allow-list on the two ClientAuthType values that genuinely
	// make a client certificate mandatory — deliberately NOT a `<`
	// comparison. tls.ClientAuthType orders as NoClientCert=0,
	// RequestClientCert=1, RequireAnyClientCert=2,
	// VerifyClientCertIfGiven=3, RequireAndVerifyClientCert=4, so
	// VerifyClientCertIfGiven (3) sorts ABOVE RequireAnyClientCert (2) yet
	// does NOT require the client to present a certificate at all — an
	// ordering comparison (`ClientAuth < RequireAnyClientCert`) would wave
	// through exactly that one unauthenticated configuration
	// (T-m4e-01). Without a mandatory client certificate, TLS itself
	// authenticates nobody, so Config.AuthUserPass becomes the only
	// remaining authentication mechanism — Serve refuses to start rather
	// than silently accept any client.
	switch s.cfg.TLSConfig.ClientAuth {
	case tls.RequireAnyClientCert, tls.RequireAndVerifyClientCert:
		// A client certificate is mandatory, so the TLS handshake itself
		// authenticates every client.
	default:
		if s.cfg.AuthUserPass == nil {
			return errors.New("ovpn: Config.TLSConfig.ClientAuth does not require a client certificate and Config.AuthUserPass is nil: the server would accept any client without authenticating it; set Config.AuthUserPass or use tls.RequireAnyClientCert/tls.RequireAndVerifyClientCert")
		}
	}
	// Validated from s.cfg directly, never from the already-resolved
	// s.pingInterval/s.reapWindow/s.sessionInboundQueue fields NewServer
	// set: a test that overrides one of those resolved fields by hand
	// after NewServer (the same direct-field-override precedent
	// s.handshakeWindow already establishes) deliberately bypasses this
	// validation, exactly as it does today.
	if s.cfg.PingInterval < 0 {
		return errors.New("ovpn: Config.PingInterval must not be negative")
	}
	if s.cfg.ReapWindow < 0 {
		return errors.New("ovpn: Config.ReapWindow must not be negative")
	}
	if s.cfg.SessionInboundQueue < 0 {
		return errors.New("ovpn: Config.SessionInboundQueue must not be negative")
	}
	resolvedPing := s.cfg.PingInterval
	if resolvedPing == 0 {
		resolvedPing = pingInterval
	}
	resolvedReap := s.cfg.ReapWindow
	if resolvedReap == 0 {
		resolvedReap = defaultReapWindow
	}
	if resolvedReap < 2*resolvedPing {
		return fmt.Errorf("ovpn: Config.ReapWindow (%s) must be at least twice Config.PingInterval (%s)", resolvedReap, resolvedPing)
	}
	s.renegSec = s.cfg.RenegSec
	if s.renegSec == 0 {
		s.renegSec = defaultRenegSec
	}
	s.renegMinInterval = s.renegSec / renegMinIntervalDivisor
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

	networkAttr := "unset"
	if s.cfg.Network != nil {
		networkAttr = s.cfg.Network.String()
	}
	cipherAttr := s.cfg.Cipher
	if cipherAttr == "" {
		cipherAttr = "AES-256-GCM"
	}
	s.logger().Info("server listening",
		"addr", pc.LocalAddr(),
		"network", networkAttr,
		"cipher", cipherAttr,
		"ping", s.pingInterval,
		"reap", s.reapWindow,
		"reneg_sec", s.renegSec,
		"auth_user_pass", s.cfg.AuthUserPass != nil,
	)

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
			s.logger().Warn("read loop stopped", "err", err)
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

	s.logger().Info("server closing", "sessions", len(sessions))

	for _, sess := range sessions {
		_ = sess.closeWithReason(CloseReasonServerClose)
	}

	// Wait for every OnSessionClosed callback the loop above triggered to
	// return before this call returns, so an embedder that tears down
	// resources OnSessionClosed depends on, immediately after Close
	// returns, can never race a still-running callback (see cbWait's own
	// doc comment for why this is not a sync.WaitGroup).
	s.cbWait()

	if pc != nil {
		return pc.Close()
	}
	return nil
}

// cbBegin records one in-flight OnSessionClosed callback goroutine. Must
// be called on the goroutine that is about to spawn the callback, BEFORE
// the go statement — otherwise Server.Close's cbWait could observe a
// zero count and return before the callback goroutine has even
// registered itself.
func (s *Server) cbBegin() {
	s.cbMu.Lock()
	s.cbCount++
	s.cbMu.Unlock()
}

// cbEnd records that one in-flight OnSessionClosed callback goroutine has
// returned. If this was the last one AND Server.Close is currently waiting
// (cbDone non-nil), it wakes that wait.
func (s *Server) cbEnd() {
	s.cbMu.Lock()
	s.cbCount--
	if s.cbCount == 0 && s.cbDone != nil {
		close(s.cbDone)
		s.cbDone = nil
	}
	s.cbMu.Unlock()
}

// cbWait blocks until every OnSessionClosed callback goroutine currently
// in flight (per cbBegin/cbEnd) has returned. Deliberately not a
// sync.WaitGroup: a reap- or exit-notify-driven cbBegin can land
// concurrently while Close is already inside cbWait and the counter has
// fallen to zero — exactly the "Add concurrently with a possibly-returning
// Wait" reuse hazard sync.WaitGroup's own docs warn against. A one-shot
// completion channel created fresh here, under the same mutex the count
// itself is guarded by, has no such restriction.
func (s *Server) cbWait() {
	s.cbMu.Lock()
	if s.cbCount == 0 {
		s.cbMu.Unlock()
		return
	}
	ch := make(chan struct{})
	s.cbDone = ch
	s.cbMu.Unlock()
	<-ch
}

// packetConnTransport adapts a net.PacketConn to ctrlconn.Transport.
type packetConnTransport struct{ pc net.PacketConn }

func (t packetConnTransport) WriteTo(p []byte, addr net.Addr) (int, error) {
	return t.pc.WriteTo(p, addr)
}

func (s *Server) handleDatagram(pc net.PacketConn, addr net.Addr, packet []byte) {
	if len(packet) < 1 || len(packet) > maxDatagramSize {
		s.logger().Debug("datagram dropped", "reason", "bad-length", "remote", addr, "bytes", len(packet))
		return
	}

	opcode, keyID := wire.ParseHeaderByte(packet[0])
	if !wire.ValidOpcode(opcode) {
		s.logger().Debug("datagram dropped", "reason", "bad-opcode", "remote", addr, "opcode", int(opcode))
		return
	}

	// Data packets (P_DATA_V1/P_DATA_V2) carry a 3-byte peer-id at this
	// offset, not an 8-byte session ID — this branch MUST run before the
	// control-opcode parse below, which would otherwise splice peer-id
	// bytes together with packet-id/tag bytes into a sessionKey that can
	// never match any control-channel session (Pitfall 3, D-16).
	//
	// Data-channel packets are never tls-crypt wrapped and have a much
	// shorter minimum wire size than a control-channel packet (a 16-byte
	// ping keepalive seals to 40 bytes, well under minDatagramSize's
	// 49-byte tls-crypt prefix) — handleDataDatagram/datachan.Wrapper.Open
	// enforce their own, correctly-sized minimum, so minDatagramSize below
	// must not gate this branch (CR-01).
	if opcode == wire.OpDataV1 || opcode == wire.OpDataV2 {
		s.handleDataDatagram(opcode, packet)
		return
	}

	// minDatagramSize (the tls-crypt prefix) only applies to control-channel
	// packets, which are always tls-crypt wrapped.
	if len(packet) < minDatagramSize {
		s.logger().Debug("datagram dropped", "reason", "short-control", "remote", addr, "opcode", int(opcode), "bytes", len(packet))
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
			if lg := s.logger(); lg.Enabled(context.Background(), slog.LevelDebug) {
				lg.Debug("datagram dropped", "reason", "unknown-session", "remote", addr,
					"session_id", hex.EncodeToString(sid[:]), "opcode", int(opcode), "key_id", int(keyID))
			}
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
			// Not attacker-triggerable — Serve pre-validates the key —
			// so Warn is safe here.
			s.logger().Warn("tls-crypt wrapper init failed", "remote", addr, "err", err)
			return
		}
		var serverSID wire.SessionID
		if _, err := rand.Read(serverSID[:]); err != nil {
			s.logger().Warn("session id generation failed", "remote", addr, "err", err)
			return
		}
		sess = &Session{
			SessionID:       serverSID,
			RemoteAddr:      addr,
			clientSessionID: sid,
			wrapper:         wrapper,
			key:             key,
			srv:             s,
			clock:           s.clock,
			inbound:         make(chan wire.ControlPacket, inboundQueueSize),
			doneCh:          make(chan struct{}),
			stopCh:          make(chan struct{}),
		}
		justCreated = true
	}

	_, plaintext, err := sess.wrapper.Unwrap(nil, packet)
	if err != nil {
		if lg := s.logger(); lg.Enabled(context.Background(), slog.LevelDebug) {
			lg.Debug("datagram dropped", "reason", "tls-crypt-unwrap", "remote", addr,
				"session_id", hex.EncodeToString(sid[:]), "opcode", int(opcode), "err", err)
		}
		return
	}
	hdr := wire.Header{Opcode: opcode, KeyID: keyID, SessionID: sid}
	cp, err := wire.ParseControlPacket(plaintext, hdr)
	if err != nil {
		if lg := s.logger(); lg.Enabled(context.Background(), slog.LevelDebug) {
			lg.Debug("datagram dropped", "reason", "parse-control", "remote", addr,
				"session_id", hex.EncodeToString(sid[:]), "opcode", int(opcode), "err", err)
		}
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
		if lg := s.logger(); lg.Enabled(context.Background(), slog.LevelDebug) {
			lg.Debug("control channel opened", "remote", addr,
				"session_id", hex.EncodeToString(sess.SessionID[:]),
				"client_session_id", hex.EncodeToString(sess.clientSessionID[:]))
		}
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

	// A SOFT_RESET_V1 for an already-established session starts a
	// renegotiation instead of flowing through the ordinary inbound queue:
	// it must be intercepted here, before pump ever sees it, because
	// beginRenegotiation may need to publish a brand-new Conn for the new
	// key-id before pump can route to it (04-01-PLAN.md Task 1 action 6).
	//
	// BUT first check whether a renegotiation to this EXACT key-id is
	// already in flight (sess.routeControlPacket's existing pendingReneg
	// match) — if so, this is a RETRANSMISSION racing the OTHER side's own
	// independent initiation, not a fresh request (04-03-PLAN.md Task 2 bug
	// fix, discovered running this plan's own "reneg" scenario for real):
	// both sides run independent, symmetric reneg-sec timers (D-17), and
	// with a short reneg-sec they can fire within the same poll tick of
	// each other. When the SERVER's own checkReneg fires first (a bare,
	// payload-less SendReset) and the REAL CLIENT independently, at nearly
	// the same moment, sends ITS OWN SOFT_RESET_V1 carrying its actual
	// ClientHello, beginRenegotiation's own startRenegotiation call would
	// refuse it outright (sess.pendingReneg != nil, the in-flight-wins
	// guard, T-04-01) and silently drop the packet FOREVER — the
	// ClientHello inside it is never delivered anywhere, so the pending
	// Conn's tls.Server(...).Handshake() blocks forever waiting to read
	// one, and the client's own reliability layer just keeps retransmitting
	// the same now-permanently-dropped packet. Delivering it to the
	// ALREADY-pending Conn instead — exactly what routeControlPacket
	// already does for every OTHER kind of post-handshake control packet —
	// closes that gap: whichever side's SOFT_RESET_V1 arrives SECOND is
	// simply the other side's own ClientHello arriving at the Conn that is
	// already waiting for it.
	if opcode == wire.OpControlSoftResetV1 {
		if target := sess.routeControlPacket(cp.KeyID); target != nil {
			target.Deliver(cp)
			sess.touchAuthTraffic()
			return
		}
		s.beginRenegotiation(sess, cp, addr, pc)
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
		s.logger().Debug("datagram dropped", "reason", "session-closing", "key_id", int(cp.KeyID))
	default:
		// Queue full: drop this datagram exactly as a genuinely lost UDP
		// packet would be dropped — the reliability layer's own
		// retransmission (on both sides) is what recovers from this, not
		// a synchronous retry here.
		s.logger().Debug("datagram dropped", "reason", "control-queue-full", "key_id", int(cp.KeyID))
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
		s.logger().Debug("datagram dropped", "reason", "data-v1-unsupported", "opcode", int(opcode))
		return
	}
	if len(packet) < 4 {
		s.logger().Debug("datagram dropped", "reason", "short-data", "bytes", len(packet))
		return
	}
	peerID := uint32(packet[1])<<16 | uint32(packet[2])<<8 | uint32(packet[3])

	s.mu.Lock()
	sess, ok := s.dataSessions[peerID]
	s.mu.Unlock()
	if !ok {
		s.logger().Debug("datagram dropped", "reason", "unknown-peer-id", "peer_id", peerID)
		return
	}

	sess.handleDataPacket(packet)
}

// pump serializes delivery of this session's inbound control packets, one
// at a time, in the order handleDatagram enqueued them, until stopCh is
// closed by Session.Close. Each packet is routed to the Conn matching its
// own key-id (sess.routeControlPacket) — the initial handshake's Conn, the
// current primary slot's Conn, a still-live lame-duck Conn, or a
// renegotiation-in-flight Conn — so the old flight's ACKs still reach the
// old Conn during a lame-duck window (04-RESEARCH.md key_link). A packet
// whose key-id matches none of those is silently dropped, matching the
// non-blocking-queue drop discipline already used throughout this package
// (Pitfall 4: an unrecognized key-id is never trusted or acted on).
func (sess *Session) pump() {
	for {
		select {
		case cp := <-sess.inbound:
			// WR-02 (04-REVIEW.md): select has no priority between
			// sess.inbound and sess.stopCh, so a packet already sitting in
			// sess.inbound can still be selected on the same iteration
			// Close() closes stopCh — routing it to a Conn that Close() is
			// about to (or has just) called .Close() on. Checking
			// sess.closing() here closes that window: once Close() has
			// decided to tear the session down, no further packet is
			// dispatched to any Conn, matching the teardown discipline
			// Close's own WR-05 commentary establishes for
			// assignedIP/peerID/dataSessions.
			if sess.closing() {
				sess.logger().Debug("control packet dropped", "reason", "session-closing", "key_id", int(cp.KeyID))
				continue
			}
			if target := sess.routeControlPacket(cp.KeyID); target != nil {
				target.Deliver(cp)
				// D-22/Pattern 6 (forward.c:1093-1103): reset the idle-reap
				// timer only for a packet actually delivered to a slot's
				// Conn — never for one routeControlPacket found no match
				// for (mirrors the reference resetting only AFTER
				// tls_pre_decrypt succeeded).
				sess.touchAuthTraffic()
			} else {
				sess.logger().Debug("control packet dropped", "reason", "no-route-for-key-id", "key_id", int(cp.KeyID))
			}
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
		sess.logger().Warn("handshake failed", "stage", "tls", "err", err)
		close(sess.doneCh)
		_ = sess.closeWithReason(CloseReasonUnknown)
		return
	}

	state := tlsConn.ConnectionState()
	sess.connState = state
	if len(state.PeerCertificates) > 0 {
		sess.PeerCN = state.PeerCertificates[0].Subject.CommonName
	}

	if err := s.performKeyMethod2Exchange(sess, tlsConn); err != nil {
		var af *authFailure
		if errors.As(err, &af) {
			// close(sess.doneCh) deliberately stays AFTER
			// rejectAuthAfterPushRequest: enforceHandshakeWindow watches
			// doneCh to decide whether to tear a stalled session down, so
			// keeping it open through the whole rejection sequence means
			// the OUTER handshakeWindow bound (60s default) still covers
			// this path, with authFailedWindow (2s) as the tighter INNER
			// bound on the read-then-drain sequence itself.
			s.rejectAuthAfterPushRequest(sess, tlsConn, af.clientReason)
			sess.logger().Debug("auth failed sent to client", "has_client_reason", af.clientReason != "")
			close(sess.doneCh)
			_ = sess.closeWithReason(CloseReasonAuthFailed)
			return
		}
		sess.logger().Warn("handshake failed", "stage", "key-method-2", "err", err)
		close(sess.doneCh)
		_ = sess.closeWithReason(CloseReasonUnknown)
		return
	}

	if err := s.performPushExchange(sess, tlsConn); err != nil {
		if errors.Is(err, ErrPoolExhausted) {
			sess.logger().Warn("tunnel ip pool exhausted", "err", err)
		} else {
			sess.logger().Warn("handshake failed", "stage", "push", "err", err)
		}
		close(sess.doneCh)
		_ = sess.closeWithReason(CloseReasonUnknown)
		return
	}

	close(sess.doneCh)

	// WR-05: performPushExchange's own atomic publish (guarded by its
	// closing check) guarantees that if it returned nil here, either
	// nothing was published (session was already closing) or everything
	// was published consistently and any concurrent Close has already —
	// or will still correctly — clean it up. That leaves exactly one gap
	// this check closes: enforceHandshakeWindow's timeout goroutine can
	// still call Close() in the narrow window AFTER performPushExchange's
	// atomic publish committed but BEFORE control reaches here, which
	// performPushExchange's own return value can't observe (it already
	// returned nil). Re-check sess.stopCh once more, right before ever
	// invoking OnSession, so D-08's "the Session handed to OnSession is
	// immediately usable" contract holds even in that residual window —
	// an already-closing session is treated exactly like a failed
	// bring-up (Close is idempotent via stopOnce, so this second call is a
	// no-op) rather than handed to the embedder.
	if sess.closing() {
		sess.logger().Debug("session closed during bring-up")
		_ = sess.closeWithReason(CloseReasonUnknown)
		return
	}

	// E6: fires before Config.OnSession is ever invoked, so a nil or
	// blocking OnSession can never suppress this record (T-na1-07).
	sess.logger().Info("session established",
		"tls_version", state.Version,
		"tls_cipher", tls.CipherSuiteName(state.CipherSuite),
	)

	// D-08: OnSession fires only here — after Key Method 2 and the
	// PUSH_REQUEST/PUSH_REPLY exchange have both completed and
	// sess.assignedIP/sess.dataKeys are both live — so the Session handed
	// to the embedder is immediately usable.
	if s.cfg.OnSession != nil {
		// published means "was handed to the embedder": set even though
		// callOnSession may itself recover a panic below — the session
		// did reach OnSession, which is what gates OnSessionClosed
		// (Session.published's own doc comment).
		sess.published.Store(true)
		s.callOnSession(sess)
	}
}

// rejectAuthAfterPushRequest answers a Config.AuthUserPass rejection on the
// INITIAL handshake path: mirroring R4 (process_incoming_push_request,
// push.c:960-971), the reference still reads the client's PUSH_REQUEST
// before ever calling send_auth_failed — so this reads (and discards) one
// control string off sess.tlsReader, bounded by authFailedWindow, ignoring
// both the read error and whether the string actually was
// pushRequestLiteral: a client that never asks still gets the rejection,
// matching send_auth_failed's own unconditional dispatch (R5). It then
// sends AUTH_FAILED (or AUTH_FAILED,<clientReason>) via sendAuthFailed.
//
// This never allocates a tunnel IP from s.pool (R4: no tunnel IP is ever
// allocated for a failed auth) — doing so here would also trip
// TestPhase4TeardownAlwaysFlowsThroughClose's pool.release allow-list,
// which does not name this function.
func (s *Server) rejectAuthAfterPushRequest(sess *Session, w io.Writer, clientReason string) {
	_ = sess.conn.SetReadDeadline(sess.now().Add(authFailedWindow))
	_, _ = readControlString(sess.tlsReader, maxControlStringLen)
	_ = sess.conn.SetReadDeadline(time.Time{})

	s.sendAuthFailed(sess.conn, w, clientReason)
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

			// The data-channel Wrapper is constructed here, before the
			// atomic publish below, at the same point the tunnel IP/
			// peer-id are conceptually assigned — so it is live before
			// OnSession ever fires (D-08) and before the peer-id this
			// datagram was routed on could possibly reach the client.
			// sess.dataKeys.ServerSlots already applies the data channel's
			// own key-direction inversion (Pitfall 1) — do not re-derive
			// it here. Built before the closing check below (rather than
			// after, as pre-WR-05) so the fields, the data wrapper, and
			// the dataSessions routing entry can all be published in one
			// atomic step gated on that single check, instead of leaving
			// gaps between separately-published pieces of state for
			// enforceHandshakeWindow's Close to land in.
			// Key-id 0 is always this session's very first key
			// (ssl.c:990-1002: "if key_id is 0, it is the first key") —
			// D-25 retired the old dataChannelKeyID constant once
			// renegotiation (SESS-04) made the key-id a per-slot value
			// rather than a session-wide constant.
			dataWrapper, err := datachan.NewWrapper(sess.dataKeys.ServerSlots(), peerID, 0)
			if err != nil {
				s.pool.release(ip, peerID)
				return fmt.Errorf("ovpn: build data-channel wrapper: %w", err)
			}
			ipInbound := make(chan []byte, s.sessionInboundQueue)

			// WR-05: enforceHandshakeWindow's timeout goroutine can call
			// sess.Close() concurrently at any point until sess.doneCh
			// closes — i.e. for this entire function's duration — and
			// Close's stopOnce.Do body only ever runs once. If it already
			// ran (or is running right now), the IP/peer-id
			// s.pool.allocate() just handed out above, and the
			// dataSessions routing entry about to be published below,
			// would otherwise never be released or removed: Close already
			// snapshotted (empty) state and won't run its cleanup a second
			// time. sess.closing() checks sess.stopCh, which Close closes
			// as the very first thing inside stopOnce.Do, before anything
			// else.
			//
			// Publishing assignedIP/peerID/dataWrapper AND the
			// dataSessions entry as one atomic step gated on this check —
			// held under sess.mu with s.mu (dataSessions' own lock) nested
			// inside it, mirroring the identical nesting Close uses on its
			// cleanup path — is what closes the race completely. The
			// nesting matters, not just the check: releasing sess.mu
			// between the fields write and the dataSessions write would
			// let Close's own cleanup (guarded only by sess.mu, separately
			// from s.mu) observe the fields as already published, release
			// peerID back to the pool believing nothing else needs it, and
			// hand that same peerID to a brand-new concurrent session —
			// which this function would then clobber a moment later by
			// finishing its own (by-then-stale) dataSessions publish.
			sess.mu.Lock()
			if sess.closing() {
				sess.mu.Unlock()
				s.pool.release(ip, peerID)
				return errors.New("ovpn: session closed during push exchange")
			}
			// One clock read for the whole atomic publish below (D-22's
			// existing lastAuthTraffic requirement extended, by the
			// Welle-1 SessionStats plan, to establishedAt too: "do not add
			// a second critical section" — reusing a single sess.now()
			// reading is what makes that literal, not just adjacent in
			// time).
			now := sess.now()
			sess.assignedIP = ip
			sess.peerID = peerID
			sess.primary = keySlot{
				keyID:       0,
				conn:        sess.conn,
				wrapper:     dataWrapper,
				established: now,
			}
			sess.ipInbound = ipInbound
			// D-22: initialized here, at the same publish point the data
			// wrapper goes live, so the reaper (started right below) can
			// never observe a zero-value lastAuthTraffic and reap a
			// session that just this moment came up.
			sess.lastAuthTraffic = now
			// SessionStats.EstablishedAt: the same publish point, the
			// same clock reading.
			sess.establishedAt = now
			s.mu.Lock()
			s.dataSessions[peerID] = sess
			s.mu.Unlock()
			sess.mu.Unlock()

			// D-03: build and publish this session's enriched logger here,
			// immediately after the atomic publish above committed —
			// remote/session_id/peer_cn/ip/peer_id are all known at this
			// point, so this is the ONE place a per-session logger with the
			// full attribute set is ever constructed. Every hot-path log
			// site downstream (Session.logger()) then pays one atomic load
			// and builds zero attrs of its own.
			// sess.RemoteAddr is passed directly, never via .String(): some
			// tests construct a *Session by hand with a nil RemoteAddr
			// (F6), and RemoteAddr.String() on a nil net.Addr interface
			// panics — slog formats a nil interface value safely as
			// "<nil>" without ever calling its method.
			sess.log.Store(s.logger().With(
				"remote", sess.RemoteAddr,
				"session_id", hex.EncodeToString(sess.SessionID[:]),
				"peer_cn", sess.PeerCN,
				"peer_id", peerID,
				"ip", ip.String(),
			))

			// D-11: the keepalive goroutine starts here too — alongside
			// the data wrapper, before PUSH_REPLY is written and well
			// before OnSession fires — emitting on exactly the schedule
			// buildPushReply below pushes to the client. Only reached once
			// the atomic publish above has committed, so it can never
			// start for a session the closing check just decided is dead.
			sess.startKeepalive()

			// D-17/Pitfall 2: the server's own reneg-sec timer starts here
			// too, independent of any inbound client traffic, so a session
			// renegotiates on schedule even if the client never sends its
			// own SOFT_RESET_V1 first. Started at the same point
			// startKeepalive is, so it can never start for a session the
			// closing check just decided is dead.
			sess.startReneg()

			// D-22: the idle-session reaper starts here too, alongside the
			// data wrapper and lastAuthTraffic's own initialization above,
			// so it can never start for a session the closing check just
			// decided is dead.
			sess.startReap()
		}

		reply := buildPushReply(sess.assignedIP, s.cfg.Network, sess.peerID, cipher,
			durationToPushedSeconds(s.pingInterval), durationToPushedSeconds(s.reapWindow))
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

// userPassLen is USER_PASS_LEN for a non-PKCS11 build (misc.h:65-70) — the
// on-wire length of a Key Method 2 username/password field INCLUDES the
// trailing NUL (read_string, ssl.c:1991-2007, does str[len-1] = '\0'), so
// at most 127 bytes of actual credential text fit.
const userPassLen = 128

// km2Credential extracts a credential string from a raw Key Method 2 field
// (opts.Username or opts.Password, keymethod2.go's ClientOptions), mirroring
// read_string's own C-string semantics (ssl.c:1991-2007). It returns
// ("", false) if field's on-wire length exceeds userPassLen — an
// out-of-bounds field, checked BEFORE emptiness (R3's own ordering) — and
// otherwise cuts at the first 0x00 byte if present (reproducing
// str[len-1]='\0' for the normal trailing terminator, and matching C
// string truncation for any interior NUL). A nil/empty field (the
// "field not provided by peer" case — readLengthPrefixedString returns nil
// for a zero-length wire field) yields ("", true): empty but in-bounds,
// distinct from too-long.
func km2Credential(field []byte) (string, bool) {
	if len(field) > userPassLen {
		return "", false
	}
	if cut := bytes.IndexByte(field, 0); cut >= 0 {
		field = field[:cut]
	}
	return string(field), true
}

// authFailure is the typed error verifyUserPass/callAuthUserPass return for
// any auth rejection: a too-long or empty credential, a hook error, or a
// recovered hook panic. clientReason, if non-empty, is sent to the client
// as AUTH_FAILED,<clientReason> (D-04); otherwise the plain AUTH_FAILED
// form is sent. err carries the underlying (server-side-only) diagnostic.
type authFailure struct {
	clientReason string
	err          error
}

func (f *authFailure) Error() string {
	if f.err != nil {
		return f.err.Error()
	}
	return "ovpn: authentication failed"
}

func (f *authFailure) Unwrap() error { return f.err }

// callAuthUserPass invokes Config.AuthUserPass with the same panic-recovery
// contract callOnSession/callOnSessionClosed already establish (ovpn.go):
// this runs on a per-session goroutine, so an unrecovered panic in
// caller-supplied code would otherwise crash the entire embedding process
// (D-08). A panicking hook is treated as a rejection (fail closed) rather
// than letting the panic escape or silently admitting the client.
func (s *Server) callAuthUserPass(sess *Session, username, password string, cs tls.ConnectionState) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if s.cfg.OnSessionPanic != nil {
				s.cfg.OnSessionPanic(sess, r, debug.Stack())
			}
			sess.logger().Warn("callback panicked", "callback", "AuthUserPass", "panic", fmt.Sprint(r))
			err = fmt.Errorf("ovpn: Config.AuthUserPass panicked: %v", r)
		}
	}()
	return s.cfg.AuthUserPass(username, password, cs)
}

// verifyUserPass authenticates opts (the client's just-parsed Key Method 2
// ClientOptions) against Config.AuthUserPass, mirroring
// key_method_2_read's own validation order (ssl.c:2452-2470, R3): wire
// length first, emptiness second, then the hook. s.cfg.AuthUserPass == nil
// returns nil immediately without touching opts at all — today's
// behaviour, credentials parsed and ignored. Every other path either
// returns nil (hook accepted) or a non-nil *authFailure (T-m4e-02: no path
// returns nil without the hook itself having returned nil).
func (s *Server) verifyUserPass(sess *Session, opts *keyderiv.ClientOptions, cs tls.ConnectionState) error {
	if s.cfg.AuthUserPass == nil {
		return nil
	}
	if opts == nil {
		// Defensive: deriveKeyMethod2 always returns a non-nil opts
		// alongside a nil error, but never trust that invariant enough to
		// risk a nil-pointer panic on this security-critical path.
		return &authFailure{err: errors.New("ovpn: no Key Method 2 options to authenticate")}
	}

	username, usernameOK := km2Credential(opts.Username)
	password, passwordOK := km2Credential(opts.Password)
	if !usernameOK || !passwordOK {
		// F1: NO username attr here — the over-long field may BE the
		// username (T-na1-02).
		sess.logger().Info("auth rejected", "reason", "credential-too-long")
		// ssl.c:2456-2457's own client-facing text.
		return &authFailure{
			clientReason: "Username or password is too long. Maximum length is 128 bytes",
			err:          errors.New("ovpn: username or password exceeds userPassLen (128) on the wire"),
		}
	}
	if username == "" || password == "" {
		sess.logger().Info("auth rejected", "reason", "credential-empty")
		// ssl.c:2465's own log line; no client reason (the reference sends
		// none for this case either — ssl.c:2465-2469's goto error skips
		// auth_set_client_reason).
		return &authFailure{err: errors.New("ovpn: auth username/password was not provided by peer")}
	}

	if err := s.callAuthUserPass(sess, username, password, cs); err != nil {
		var reason string
		var ar AuthClientReason
		if errors.As(err, &ar) {
			reason = ar.ClientReason()
		}
		sess.logger().Info("auth rejected", "reason", "hook", "username", username, "err", err, "has_client_reason", reason != "")
		return &authFailure{clientReason: reason, err: err}
	}
	sess.logger().Debug("auth accepted", "username", username)
	return nil
}

// authFailedWindow bounds both rejectAuthAfterPushRequest's read of the
// client's PUSH_REQUEST and sendAuthFailed's own WaitDrained call — the
// inner budget inside runHandshake's outer enforceHandshakeWindow bound.
const authFailedWindow = 2 * time.Second

// authFailedLiteral is the reference's own AUTH_FAILED control string
// (push.c:396-430's static const char auth_failed[] = "AUTH_FAILED").
const authFailedLiteral = "AUTH_FAILED"

// maxAuthClientReasonLen caps the sanitized AuthClientReason text sent to
// the client (D-04) — an arbitrary but generous bound, well above any
// legitimate rejection message, that keeps a misbehaving embedder's hook
// from inflating the AUTH_FAILED control string without limit.
const maxAuthClientReasonLen = 128

// sanitizeAuthClientReason strips control bytes (< 0x20, or 0x7f) from
// reason — a NUL would truncate the AUTH_FAILED control string on the
// wire (writeControlString's own NUL terminator convention), a newline
// would corrupt the client's log parsing — and truncates the result to
// maxAuthClientReasonLen.
func sanitizeAuthClientReason(reason string) string {
	b := make([]byte, 0, len(reason))
	for i := 0; i < len(reason); i++ {
		c := reason[i]
		if c < 0x20 || c == 0x7f {
			continue
		}
		b = append(b, c)
	}
	if len(b) > maxAuthClientReasonLen {
		b = b[:maxAuthClientReasonLen]
	}
	return string(b)
}

// buildAuthFailed assembles the AUTH_FAILED control string body (without
// its NUL terminator, which writeControlString appends) exactly per
// push.c:396-430's send_auth_failed: the plain literal when clientReason
// sanitizes to empty, or "AUTH_FAILED,<reason>" otherwise. Factored out as
// a pure function, mirroring buildPushReply's own testable shape
// (push.go:97), so the wire format can be asserted without a live
// session.
func buildAuthFailed(clientReason string) string {
	reason := sanitizeAuthClientReason(clientReason)
	if reason == "" {
		return authFailedLiteral
	}
	return authFailedLiteral + "," + reason
}

// sendAuthFailed writes the AUTH_FAILED control string to w in
// writeControlString's exact framing (R5: the literal or
// "AUTH_FAILED,<reason>", plus exactly one NUL, no length prefix) and, if
// conn is non-nil, gives the reliable layer a bounded chance
// (authFailedWindow) to actually deliver it before the caller tears the
// session down. Errors are deliberately ignored: this always runs on a
// teardown path where the caller is already committed to closing the
// session regardless of whether the client ever receives this message.
func (s *Server) sendAuthFailed(conn *ctrlconn.Conn, w io.Writer, clientReason string) {
	_ = writeControlString(w, buildAuthFailed(clientReason))
	if conn != nil {
		_ = conn.WaitDrained(authFailedWindow)
	}
}

// deriveKeyMethod2 runs the Key Method 2 exchange over tlsConn and returns
// the resulting bufio.Reader (wrapping tlsConn, having consumed exactly the
// client's Key Method 2 message) and the derived key expansion, plus the
// raw client/server seed material for diagnostics, plus the client's
// parsed ClientOptions (opts.Username/opts.Password feed verifyUserPass) —
// the shared core both performKeyMethod2Exchange (initial handshake) and
// runRenegotiation (soft reset) call, so a renegotiation's key derivation
// (and the credentials it authenticates) can never subtly diverge from the
// initial handshake's own (04-01-PLAN.md Task 1 action 7; quick 260908-m4e
// key_links: "the credentials must come from the SAME parse both the
// initial handshake and the renegotiation use"). A six-value return is
// unlovely, but keeps this a mechanical, two-call-site change rather than
// introducing a new result struct.
// clientSID/serverSID are the SAME control-channel session IDs for both
// callers — they never change across a soft reset (04-RESEARCH.md
// Pattern 3). Matches the reference server's own state-machine branch
// (tls_process, ssl.c:3002-3031: server is "Receive Key" at S_START, "Send
// Key" at S_GOT_KEY — the opposite order from the client, which already
// wrote its own message immediately after its handshake completed).
func (s *Server) deriveKeyMethod2(tlsConn *tls.Conn, clientSID, serverSID wire.SessionID) (*bufio.Reader, *keyderiv.Key2, *keyderiv.KeySource, *keyderiv.KeySource, *keyderiv.ClientOptions, error) {
	tlsReader := bufio.NewReader(tlsConn)

	clientKM, clientOpts, err := keyderiv.ReadClientKeyMethod2(tlsReader)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ovpn: read client Key Method 2: %w", err)
	}

	serverKM, err := keyderiv.WriteServerKeyMethod2(tlsConn, serverKM2Options)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ovpn: write server Key Method 2: %w", err)
	}

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
	dataKeys, err := keyderiv.DeriveKeys(src, (*[8]byte)(&clientSID), (*[8]byte)(&serverSID))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ovpn: derive data-channel keys: %w", err)
	}
	return tlsReader, dataKeys, clientKM, serverKM, clientOpts, nil
}

// performKeyMethod2Exchange runs deriveKeyMethod2 for the initial handshake
// and writes its results onto sess: sess.tlsReader (D-15, so plan
// 02-02's PUSH_REQUEST continuation reads from the same buffered stream
// rather than losing bytes to a second reader), sess.dataKeys,
// sess.clientKM, and sess.serverKM. The renegotiation path
// (runRenegotiation) calls deriveKeyMethod2 directly instead and never
// touches sess.tlsReader (D-15's single-buffered-reader contract stays
// scoped to the initial handshake).
//
// The existing publishes above happen UNCONDITIONALLY, before
// verifyUserPass ever runs (quick 260908-m4e key_links): the AUTH_FAILED
// path in runHandshake must read the client's PUSH_REQUEST off
// sess.tlsReader (R4), so the reader has to be positioned even when
// authentication has already failed — and the reference itself completes
// the whole key exchange and only refuses at PUSH time (ssl.c:2414 sets
// KS_AUTH_FALSE but parsing continues regardless). Keeping the publishes
// unconditional also keeps this diff an appended block rather than a
// restructure.
func (s *Server) performKeyMethod2Exchange(sess *Session, tlsConn *tls.Conn) error {
	tlsReader, dataKeys, clientKM, serverKM, clientOpts, err := s.deriveKeyMethod2(tlsConn, sess.clientSessionID, sess.SessionID)
	if err != nil {
		return err
	}
	sess.tlsReader = tlsReader
	// WR-01 (04-REVIEW.md): dataKeys is a sess.mu-guarded field (see mu's
	// own doc comment) — this is its initial, single-writer publish, but
	// DebugDataKeys can be called concurrently from an arbitrary goroutine
	// at any time, so this write takes the same lock its reader does.
	sess.mu.Lock()
	sess.dataKeys = dataKeys
	sess.mu.Unlock()
	sess.clientKM = clientKM
	sess.serverKM = serverKM

	return s.verifyUserPass(sess, clientOpts, tlsConn.ConnectionState())
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
			sess.logger().Warn("callback panicked", "callback", "OnSession", "panic", fmt.Sprint(r))
		}
	}()
	s.cfg.OnSession(sess)
}

// callOnSessionClosed invokes Config.OnSessionClosed with the same
// panic-recovery contract callOnSession above already establishes: this
// runs on its own per-callback goroutine (see Session.closeWithReason), so
// an unrecovered panic in caller-supplied code would otherwise crash the
// entire embedding process. The recovered value and a stack trace are
// routed to Config.OnSessionPanic, exactly like a panicking OnSession.
func (s *Server) callOnSessionClosed(sess *Session, r CloseReason) {
	defer func() {
		if rec := recover(); rec != nil {
			if s.cfg.OnSessionPanic != nil {
				s.cfg.OnSessionPanic(sess, rec, debug.Stack())
			}
			sess.logger().Warn("callback panicked", "callback", "OnSessionClosed", "panic", fmt.Sprint(rec))
		}
	}()
	s.cfg.OnSessionClosed(sess, r)
}

// startRenegotiation validates it is safe to begin a new key-id's handshake
// (session not closing, primary slot fully established, no renegotiation
// already in flight — ssl.c:3882-3900's S_GENERATED_KEYS gate), builds the
// new key-id's ctrlconn.Conn over the SAME session-wide tls-crypt wrapper
// and session IDs (Pattern 3, Anti-Pattern 1: never a fresh
// tlscrypt.Wrapper), and publishes it into sess.pendingReneg so pump can
// route to it immediately. This is the shared body beginRenegotiation (the
// client-triggered receive path) and, from plan 04-01 Task 2 onward,
// runReneg (the server-initiated send path) both call, so the two sides'
// key-id counters can never drift apart by growing separately-maintained
// copies.
//
// If hasWantKeyID is true, wantKeyID must equal the locally-computed next
// key-id or startRenegotiation refuses (T-04-02, ssl.c:3983-3990) — the
// receive path has a peer-supplied key-id to validate; the send path
// (hasWantKeyID false) computes and uses the next key-id unconditionally,
// since it has no peer-supplied value to check.
func (s *Server) startRenegotiation(sess *Session, pc net.PacketConn, addr net.Addr, wantKeyID uint8, hasWantKeyID bool) (*ctrlconn.Conn, uint8, bool) {
	sess.mu.Lock()
	defer sess.mu.Unlock()

	if sess.closing() {
		sess.logger().Debug("renegotiation refused", "reason", "closing")
		return nil, 0, false
	}
	if sess.primary.conn == nil || sess.primary.established.IsZero() {
		// The reference only allows renegotiation once the previous key is
		// fully established (ssl.c:3882-3900, S_GENERATED_KEYS) — refuse
		// rather than renegotiate a session that hasn't finished its
		// initial handshake yet.
		sess.logger().Debug("renegotiation refused", "reason", "primary-not-established")
		return nil, 0, false
	}
	if sess.pendingReneg != nil {
		// A renegotiation is already in flight — the in-flight one wins
		// (D-17 "first to fire wins"); the timer tick or a second
		// SOFT_RESET_V1 is a no-op.
		sess.logger().Debug("renegotiation refused", "reason", "already-in-flight", "key_id", int(sess.pendingRenegKeyID))
		return nil, 0, false
	}
	if !sess.lastRenegAccepted.IsZero() && sess.now().Sub(sess.lastRenegAccepted) < s.renegMinInterval {
		// T-04-01: reneg-flood rate limit. This is defense in depth on top
		// of tls-crypt's own replay window (Phase 1), which already
		// rejects a byte-identical REPLAYED SOFT_RESET_V1 before it ever
		// reaches this code; this check instead bounds how often a
		// legitimate-looking but abusive peer can force a full new TLS
		// handshake with distinct, validly-signed requests.
		sess.logger().Debug("renegotiation refused", "reason", "rate-limited")
		return nil, 0, false
	}

	next := nextKeyID(sess.primary.keyID)
	if hasWantKeyID && wantKeyID != next {
		// Hard error, never trusted from the peer (T-04-02,
		// ssl.c:3983-3990: "local/remote key IDs out of sync ... goto
		// error"): the server computes the expected next key-id itself and
		// refuses anything else — drop and leave every field of the
		// session untouched, no partial state, no counter advance, no new
		// allocation, matching the forged-control-packet discipline
		// handleDatagram already applies elsewhere. Debug only, never Info —
		// an Info-level line here would be an attacker-controlled
		// log-volume amplifier.
		sess.logger().Debug("renegotiation refused", "reason", "key-id-mismatch", "key_id", int(wantKeyID))
		return nil, 0, false
	}

	transport := packetConnTransport{pc: pc}
	newConn := ctrlconn.NewWithKeyID(sess.SessionID, sess.clientSessionID, sess.wrapper, transport, addr, nil, next)
	sess.pendingReneg = newConn
	sess.pendingRenegKeyID = next
	sess.lastRenegAccepted = sess.now()
	initiator := "server"
	if hasWantKeyID {
		initiator = "peer"
	}
	sess.logger().Info("renegotiation started", "key_id", int(next), "initiator", initiator)
	return newConn, next, true
}

// beginRenegotiation is the receive-side half of D-17's bidirectional
// renegotiation: an incoming P_CONTROL_SOFT_RESET_V1 for an established
// session starts a new handshake at the locally-computed next key-id,
// mirroring the reference's own receive-side symmetric reset
// (ssl.c:3882-3900). The reply IS the ack for the client's request — the
// same single-atomic-step discipline the initial hard reset already uses
// (ovpn.go:429/DeliverAndRespond) — mirroring the reference's own
// session_move_pre_start, whose first outgoing packet for a new key-id
// carries the SAME opcode as the state transition that created it
// (ssl.c:989, 2594).
func (s *Server) beginRenegotiation(sess *Session, cp wire.ControlPacket, addr net.Addr, pc net.PacketConn) {
	newConn, keyID, ok := s.startRenegotiation(sess, pc, addr, cp.KeyID, true)
	if !ok {
		return
	}
	_ = newConn.DeliverAndRespond(cp, wire.OpControlSoftResetV1, nil)
	go s.runRenegotiation(sess, newConn, keyID)
}

// runRenegotiation drives one renegotiation's TLS handshake and Key
// Method 2 exchange to completion over newConn (built by
// startRenegotiation at keyID), then atomically swaps it in as the new
// primary slot — mirroring runHandshake but STOPPING after Key Method 2
// (Pattern 4/Anti-Pattern 2): no performPushExchange, no pool.allocate, no
// OnSession, no write to sess.assignedIP or sess.peerID. A failed handshake
// or a session that started closing mid-flight abandons the attempt: the
// OLD primary key stays live and usable, exactly as if the renegotiation
// had never been attempted (T-04-04).
func (s *Server) runRenegotiation(sess *Session, newConn *ctrlconn.Conn, keyID uint8) {
	// CR-01: bound this renegotiation's lifetime the same way
	// enforceHandshakeWindow bounds the initial handshake. Without this,
	// a stalled reneg (client goes silent mid-handshake) leaks this
	// goroutine and newConn's own retransmit goroutine forever, and never
	// clears sess.pendingReneg — permanently disabling all further
	// renegotiation for the session, since startRenegotiation's own
	// in-flight check (ovpn.go:1008-1013) then refuses every subsequent
	// attempt. done is closed on every return path below (success,
	// abandon, and the sess.closing() early-outs) so the watchdog
	// goroutine itself never leaks once this renegotiation finishes
	// normally.
	done := make(chan struct{})
	defer close(done)
	go s.enforceRenegotiationWindow(sess, newConn, done)

	abandon := func() {
		sess.mu.Lock()
		if sess.pendingReneg == newConn {
			sess.pendingReneg = nil
		}
		sess.mu.Unlock()
		_ = newConn.Close()
	}

	tlsConn := tls.Server(newConn, s.cfg.TLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		sess.logger().Warn("renegotiation failed", "stage", "tls", "key_id", int(keyID), "err", err)
		abandon()
		return
	}

	_, dataKeys, _, _, clientOpts, err := s.deriveKeyMethod2(tlsConn, sess.clientSessionID, sess.SessionID)
	if err != nil {
		sess.logger().Warn("renegotiation failed", "stage", "key-method-2", "key_id", int(keyID), "err", err)
		abandon()
		return
	}

	// R3/D-01: verify_user_pass is reached from key_method_2_read, i.e. it
	// runs on EVERY key exchange — a renegotiation re-verifies exactly
	// like the initial handshake did, so a client cannot authenticate once
	// and then rotate keys unauthenticated (T-m4e-03). Unlike the initial
	// handshake there is no PUSH_REQUEST to read first (R5: "send to any
	// active session" is unconditional on a renegotiation), so this goes
	// straight to sendAuthFailed.
	if authErr := s.verifyUserPass(sess, clientOpts, tlsConn.ConnectionState()); authErr != nil {
		var af *authFailure
		var clientReason string
		if errors.As(authErr, &af) {
			clientReason = af.clientReason
		}
		// Write and drain BEFORE abandon(), which calls newConn.Close() —
		// WaitDrained returns false immediately once closeCh is closed, so
		// the AUTH_FAILED delivery attempt has to happen first.
		s.sendAuthFailed(newConn, tlsConn, clientReason)
		// F3 (verifyUserPass) already logged the "auth rejected" record —
		// this Warn is the renegotiation-stage failure, not a duplicate of
		// that rejection.
		sess.logger().Warn("renegotiation failed", "stage", "auth", "key_id", int(keyID))
		abandon()
		_ = sess.closeWithReason(CloseReasonAuthFailed)
		return
	}

	sess.mu.Lock()
	// CR-03: re-check sess.pendingReneg == newConn here, symmetric with
	// enforceRenegotiationWindow's own compare-and-clear. Handshake()/
	// deriveKeyMethod2 above run without sess.mu held, so the watchdog can
	// win the race in the window between them succeeding and this Lock()
	// call: it observes sess.pendingReneg == newConn, clears it, and closes
	// newConn — all before this goroutine gets here. Without this check,
	// sess.closing() alone doesn't catch that case (the session itself
	// isn't closing, only this specific attempt was invalidated), and the
	// swap below would unconditionally publish the now-closed newConn as
	// sess.primary.conn, permanently breaking the control channel for this
	// key-id. Whichever side (this goroutine or the watchdog) observes the
	// mismatch first is the one that tears newConn down; the other becomes
	// a no-op.
	if sess.closing() || sess.pendingReneg != newConn {
		sess.mu.Unlock()
		sess.logger().Debug("renegotiation abandoned", "reason", "superseded", "key_id", int(keyID))
		_ = newConn.Close()
		return
	}

	newWrapper, err := datachan.NewWrapper(dataKeys.ServerSlots(), sess.peerID, keyID)
	if err != nil {
		// WR-03: clear pendingReneg on this failure path too, mirroring the
		// swap section's own guard below — otherwise every subsequent
		// renegotiation attempt is refused forever by startRenegotiation's
		// in-flight guard (sess.pendingReneg != nil), the same CR-01 failure
		// mode this function's other early-returns already avoid.
		if sess.pendingReneg == newConn {
			sess.pendingReneg = nil
		}
		sess.mu.Unlock()
		sess.logger().Warn("renegotiation failed", "stage", "data-wrapper", "key_id", int(keyID), "err", err)
		_ = newConn.Close()
		return
	}

	// Mirror ssl.c:1926-1945 exactly: free whatever is currently in the
	// lame-duck slot (its Close is idempotent even if the expiry sweep
	// already closed it) before the current primary takes its place —
	// never leave two live lame-duck generations dangling.
	oldLameDuckConn := sess.lameDuck.conn
	sess.lameDuck = sess.primary
	sess.lameDuck.mustDie = sess.now().Add(transitionWindow)
	if oldLameDuckConn != nil {
		_ = oldLameDuckConn.Close()
	}

	sess.primary = keySlot{
		keyID:       keyID,
		conn:        newConn,
		wrapper:     newWrapper,
		established: sess.now(),
	}
	// dataKeys backs DebugDataKeys, a debug-only accessor that should
	// reflect the newest key (04-01-PLAN.md Task 1 action 7).
	sess.dataKeys = dataKeys
	// RenegotiationCount (04-03-PLAN.md Task 1): incremented exactly once
	// per completed rollover, inside this same atomic-swap critical section
	// — a renegotiation abandoned before reaching here (failed handshake,
	// failed Key Method 2, session closing) never increments it.
	sess.renegotiations++
	renegotiations := sess.renegotiations
	if sess.pendingReneg == newConn {
		sess.pendingReneg = nil
	}
	sess.mu.Unlock()

	sess.logger().Info("renegotiation completed", "key_id", int(keyID), "renegotiations", renegotiations)

	// dataSessions is keyed on peerID, which does not change across a
	// renegotiation (D-16) — no routing-table write is needed here.
}

// enforceHandshakeWindow tears sess down and releases its state if the
// handshake has not completed within reliable.HandshakeWindow (the
// reference's --hand-window default, 60 seconds).
func (s *Server) enforceHandshakeWindow(sess *Session) {
	select {
	case <-sess.doneCh:
		return
	case <-time.After(s.handshakeWindow):
		sess.logger().Warn("handshake window expired", "window", s.handshakeWindow)
		_ = sess.closeWithReason(CloseReasonUnknown)
	}
}

// enforceRenegotiationWindow tears the in-flight renegotiation newConn down
// (mirroring abandon()'s own cleanup inside runRenegotiation) if it hasn't
// completed within the same handshake-window budget the initial handshake
// gets (CR-01). This is the renegotiation-scoped counterpart to
// enforceHandshakeWindow above: unlike a stalled initial handshake, a
// stalled renegotiation must NOT tear the session itself down (the old
// primary key is still live and usable, T-04-04) — it only needs to
// release the stuck newConn/goroutine and clear sess.pendingReneg so a
// future renegotiation attempt can re-arm.
func (s *Server) enforceRenegotiationWindow(sess *Session, newConn *ctrlconn.Conn, done <-chan struct{}) {
	select {
	case <-done:
		return
	case <-time.After(s.handshakeWindow):
		sess.mu.Lock()
		stillPending := sess.pendingReneg == newConn
		pendingKeyID := sess.pendingRenegKeyID
		if stillPending {
			sess.pendingReneg = nil
		}
		sess.mu.Unlock()
		if stillPending {
			sess.logger().Warn("renegotiation window expired", "key_id", int(pendingKeyID), "window", s.handshakeWindow)
		}
		// Only close newConn if this call is the one that actually cleared
		// pendingReneg (CR-02): if the check above is false, the
		// renegotiation already completed and swapped newConn in as
		// sess.primary.conn between the select's timer firing and done
		// being closed — closing it here would tear down the live,
		// just-negotiated control channel for a reneg that succeeded.
		if stillPending {
			_ = newConn.Close() // unblocks the stalled Handshake()/deriveKeyMethod2 call
		}
	}
}

func (s *Server) removeSession(sess *Session) {
	s.mu.Lock()
	if existing, ok := s.sessions[sess.key]; ok && existing == sess {
		delete(s.sessions, sess.key)
	}
	s.mu.Unlock()
}
