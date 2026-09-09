<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# API Reference

This is the library usage reference for `govpn` (module `github.com/8upio/govpn`,
package `ovpn`): how to construct a `Server`, start it, and work with the
`Session` your program receives for each connected OpenVPN client. Every
signature below is taken directly from `ovpn.go` and `session.go` — nothing
here is invented.

For field-by-field configuration details see [CONFIGURATION.md](CONFIGURATION.md).
For how these pieces fit into the rest of the library (control channel,
data channel, netstack) see [ARCHITECTURE.md](ARCHITECTURE.md) and
[NETSTACK.md](NETSTACK.md). For a first-run walkthrough see
[GETTING-STARTED.md](GETTING-STARTED.md) and the runnable
[`examples/tunnelweb`](../examples/tunnelweb/README.md) example, which this
page's snippets are drawn from.

## Overview

Embedding `govpn` is three steps:

1. Build an `ovpn.Config` — a `*tls.Config` for mutual certificate auth, a
   `tls-crypt` static key, the tunnel IP range, and an `OnSession` callback.
2. Pass it to `ovpn.NewServer` and call `Server.Serve` with a `net.PacketConn`.
3. For each client that completes the full OpenVPN bring-up sequence,
   `OnSession` is invoked with a `*ovpn.Session` — an `io.ReadWriteCloser` of
   that client's raw, decrypted IP packets.

```go
srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,        // mutual cert auth: ClientCAs, Certificates, MinVersion
    TLSCryptKey: tlsCryptKey,   // from ovpn.ParseStaticKeyV1
    Network:     tunnelNetwork, // *net.IPNet, e.g. 10.8.0.0/24 (topology subnet)
    Cipher:      "AES-256-GCM",
    OnSession: func(sess *ovpn.Session) {
        // sess is an io.ReadWriteCloser of raw, decrypted IP packets.
        // sess.AssignedIP() is already populated here.
    },
})

pc, err := net.ListenPacket("udp", "0.0.0.0:1194")
if err != nil {
    log.Fatal(err)
}
if err := srv.Serve(pc); err != nil {
    log.Fatal(err)
}
```

## `ovpn.Config`

```go
type Config struct {
    TLSConfig           *tls.Config
    TLSCryptKey         []byte
    Network             *net.IPNet
    Cipher              string
    OnSession           func(*Session)
    OnSessionPanic      func(sess *Session, recovered any, stack []byte)
    RenegSec            time.Duration
    OnSessionClosed     func(sess *Session, reason CloseReason)
    PingInterval        time.Duration
    ReapWindow          time.Duration
    SessionInboundQueue int
    AuthUserPass        func(username, password string, cs tls.ConnectionState) error
    AssignIP            func(peerCN string, cs tls.ConnectionState) (net.IP, error)
    Logger              *slog.Logger
}
```

Passed by value to `NewServer`. See [CONFIGURATION.md](CONFIGURATION.md) for
what each field controls, which are required, and their defaults. The
fields most relevant to the API surface on this page:

- **`OnSession func(*Session)`** — invoked exactly once per client, after Key
  Method 2 and the `PUSH_REQUEST`/`PUSH_REPLY` exchange have both completed
  and the data-channel keys and assigned tunnel IP are live — not merely
  after the TLS handshake returns. The `*Session` handed to `OnSession` is
  therefore immediately usable: `Session.AssignedIP()` is already populated
  and `Session.PeerCN` is the verified client CommonName.
- **`OnSessionPanic func(sess *Session, recovered any, stack []byte)`** — if
  set, called when `OnSession` (or `OnSessionClosed`) panics, instead of
  letting the panic crash the embedding process. It receives the `Session`,
  the recovered panic value, and a captured stack trace
  (`runtime/debug.Stack()`).
- **`OnSessionClosed func(sess *Session, reason CloseReason)`** — invoked at
  most once per session, only for a session that was actually handed to
  `OnSession`, after that session's teardown has fully completed. See
  [Lifecycle and `Close`](#lifecycle-and-close) and [`CloseReason`](#closereason)
  below.
- **`PingInterval` / `ReapWindow` / `SessionInboundQueue`** — see
  [`Session.Stats`](#other-accessors) and CONFIGURATION.md; these make the
  pushed `ping`/`ping-restart` schedule and the per-session inbound queue
  depth configurable instead of fixed.
- **`AuthUserPass func(username, password string, cs tls.ConnectionState) error`**
  — authenticates a client's Key Method 2 username/password, on the initial
  handshake and on every renegotiation. `nil` (the default) leaves
  credentials parsed and ignored. A non-nil error rejects the client with
  `AUTH_FAILED` and `CloseReasonAuthFailed`. `Server.Serve` returns an error
  if this is nil AND `TLSConfig.ClientAuth` does not mandate a client
  certificate — see [CONFIGURATION.md](CONFIGURATION.md#authuserpass) for the
  full validation order, panic-recovery contract, and the certificate-less
  operation pattern.
- **`AssignIP func(peerCN string, cs tls.ConnectionState) (net.IP, error)`**
  — chooses a client's tunnel IP instead of the default dynamic pool. `nil`
  (the default) leaves every session's tunnel IP coming from the dynamic
  pool, byte-for-byte the same as before this hook existed. Returning
  `(nil, nil)` falls back to the pool for that one session only. If the
  returned address is currently held by another live session, that older
  session is evicted with `CloseReasonReplaced` and the new session takes
  over the address — see [CONFIGURATION.md](CONFIGURATION.md#assignip) for
  the full validation list, the panic/error fail-closed contract, and the
  replace semantics' SIP-registrar rationale.
- **`Logger *slog.Logger`** — optional structured logging for handshake
  progress and failure, session lifecycle, authentication decisions,
  renegotiation, and per-datagram drops. `nil` (the default) costs nothing.
  See [CONFIGURATION.md#logger](CONFIGURATION.md#logger) for the level
  table, the closed set of message strings, and the attribute vocabulary.

## `ovpn.AuthClientReason`

```go
type AuthClientReason interface{ ClientReason() string }
```

An optional interface an error returned from `Config.AuthUserPass` may
implement to supply a human-readable rejection reason, sent to the client as
`AUTH_FAILED,<reason>` (sanitized: control bytes stripped, capped at 128
bytes) instead of the plain `AUTH_FAILED` form. See
[CONFIGURATION.md](CONFIGURATION.md#authclientreason).

## `ovpn.ParseStaticKeyV1`

```go
func ParseStaticKeyV1(data []byte) ([]byte, error)
```

Parses an OpenVPN "Static key V1" PEM-style envelope into its 256 raw bytes,
suitable for `Config.TLSCryptKey`:

```go
tlsCryptPEM, err := os.ReadFile(pkiDir + "/tls-crypt.key")
if err != nil {
    return err
}
tlsCryptKey, err := ovpn.ParseStaticKeyV1(tlsCryptPEM)
if err != nil {
    return err
}
```

## `ovpn.NewServer` and `*Server`

```go
func NewServer(cfg Config) *Server
```

Builds a `Server` from `cfg`. It does not start listening — call `Serve` to
begin reading from a `net.PacketConn`. `Server`'s fields are all unexported;
it is used entirely through the three methods below.

### `Server.Serve`

```go
func (s *Server) Serve(pc net.PacketConn) error
```

Runs the server's UDP read loop over `pc` until `pc` is closed or `Close` is
called. It returns an error immediately (before entering the read loop) if
`cfg.TLSCryptKey` is malformed or `cfg.TLSConfig` is nil. `cfg.Network` is
not required to start `Serve` — a server without it can still complete a
client's TLS handshake, but that client's session fails once it reaches the
`PUSH_REQUEST`/`PUSH_REPLY` exchange and never reaches `OnSession`.

Each accepted datagram is handled on its own goroutine, so datagrams
belonging to distinct client sessions are processed concurrently and
`Serve` itself never blocks on a single client. `Serve` blocks the calling
goroutine until the underlying `net.PacketConn` is closed (by `Close` or
externally), returning `nil` in that case, or a non-nil error for any other
read failure.

### `Server.Close`

```go
func (s *Server) Close() error
```

Unblocks `Serve`'s read loop by closing the underlying `net.PacketConn`
(making `Serve` return `nil`), and closes every in-flight session's control
channel (recording `CloseReasonServerClose` on each) so their handshake
goroutines and retransmit loops don't leak past server shutdown. `Close`
does not return until every `Config.OnSessionClosed` callback it triggered
has itself returned, so resources an embedder tears down immediately after
`Close` returns can never race a still-running callback.

```go
srv := ovpn.NewServer(cfg)
done := make(chan error, 1)
go func() { done <- srv.Serve(pc) }()

// ... later, e.g. on SIGTERM ...
_ = srv.Close()
```

### `Server.Sessions`

```go
func (s *Server) Sessions() []*Session
```

Returns a point-in-time, best-effort snapshot of every established,
not-yet-closing session, sorted ascending by `AssignedIP()` for
deterministic output. Non-empty even when `Config.OnSession` is nil — it
keys on internal established state, not on whether a session was ever
handed to `OnSession`. A session may close the instant after it is
returned in this slice, so treat every element as possibly-already-closed.
Safe to call concurrently with handshakes and teardowns.

### `Server.Stats`

```go
func (s *Server) Stats() ServerStats

type ServerStats struct {
    ActiveSessions       int
    HandshakesStarted    uint64
    HandshakesCompleted  uint64
    HandshakesFailed     uint64
    HandshakesTimedOut   uint64
    AuthFailed           uint64
    AssignIPRejected     uint64
    PoolExhausted        uint64
    DatagramsRejected    uint64
}
```

A point-in-time snapshot of session inventory and handshake/dispatch
counters. `ActiveSessions` is `len(Server.Sessions())` — the only gauge;
every other field is monotonic since server construction. The four
handshake-outcome counters (`HandshakesCompleted`/`HandshakesFailed`/
`HandshakesTimedOut`/`AuthFailed`) partition every settled initial
handshake: `HandshakesStarted == HandshakesCompleted + HandshakesFailed +
HandshakesTimedOut + AuthFailed`, except for a handshake still in flight
when `Server.Close` runs, which records no outcome at all.

| Field | Counts |
|---|---|
| `ActiveSessions` | `len(Server.Sessions())` at the moment `Stats()` ran. |
| `HandshakesStarted` | Every new control channel opened (one per session, initial handshakes only). |
| `HandshakesCompleted` | Every initial handshake that reached "session established". |
| `HandshakesFailed` | Every initial handshake that failed at the TLS, Key Method 2, or push stage, or was already closing during bring-up. |
| `HandshakesTimedOut` | Every initial handshake torn down by the handshake-window timeout. |
| `AuthFailed` | Every **initial-handshake** `Config.AuthUserPass` rejection. A renegotiation-time rejection is reported through `OnSessionClosed(CloseReasonAuthFailed)` instead, not counted here. |
| `AssignIPRejected` | Every `Config.AssignIP` rejection: invalid address, hook error, hook panic, or an unresolved replace-path conflict. |
| `PoolExhausted` | Every `ErrPoolExhausted` observed, from the dynamic pool or from `AssignIP`'s own reservation retry. |
| `DatagramsRejected` | Every datagram dropped before dispatch to a session's own routing (bad length/opcode, unknown session, tls-crypt/parse failure, session-closing, queue-full, unsupported/short data, unknown peer-id). |

## `Session`

`Session` represents an established, TLS-authenticated client connection —
the value `Config.OnSession` is invoked with, exactly once per client. It is
a full `io.ReadWriteCloser` for that client's raw, decrypted IP packets:

```go
var _ io.ReadWriteCloser = (*Session)(nil)
```

### Exported fields

```go
type Session struct {
    SessionID  [8]byte  // server-assigned control-channel session ID
    RemoteAddr net.Addr // the client's UDP address
    PeerCN     string   // verified client CommonName from the peer certificate
    // ... unexported fields
}
```

`PeerCN` is read from `tls.Conn.ConnectionState().PeerCertificates[0].Subject.CommonName`
only after the handshake succeeds — never from any client-supplied value
outside the CA-verified certificate chain.

### Read/Write semantics

```go
func (s *Session) Read(p []byte) (int, error)
func (s *Session) Write(p []byte) (int, error)
```

`Read` and `Write` are **datagram-shaped**, not stream-shaped: one full,
raw, decrypted IP packet per call. If `p` is too small to hold the next
packet, `Read` returns a descriptive error and *retains* the packet — it is
neither truncated nor discarded, and a subsequent `Read` with a large
enough buffer still receives it in full. `Read` blocks until a packet
arrives or the session closes, in which case it returns `io.EOF`.

`Write` encrypts `p` as one data-channel packet and sends it to the
client's UDP address, returning `len(p)` on success. After the session has
been torn down, `Write` returns `io.EOF`. If called before the data channel
is established (which should not happen for a `Session` obtained via
`OnSession`, since that only fires after the data channel is live), `Write`
returns a plain error.

A 16-byte ping keepalive received from the client is absorbed entirely
inside the decrypt path and never reaches `Read`'s caller.

**Ordering.** `Read` delivers a session's data packets in the order the
server socket received them. The server's read loop decrypts and enqueues
data-channel packets inline, on the same goroutine that reads the socket —
matching the reference implementation, which reads and processes each
datagram in one loop iteration on one thread. UDP itself can still reorder
packets in transit, and the session's inbound queue still drops the newest
packet on overflow (`Config.SessionInboundQueue`,
`SessionStats.InboundQueueDropped`), but the server never introduces
reordering of its own. This matters for latency-sensitive payloads such as
RTP, where reordering also interacts badly with the data channel's
64-packet anti-replay window.

### Concurrency

A single `Session`'s `Read`/`Write`/`Close` may each be called concurrently
with one another (mirroring the usual `io.ReadWriteCloser` convention), but
**concurrent calls to `Read` on the same `Session` are not supported** — the
doc comment notes `Read` assumes the single-reader-goroutine convention
ordinary `io.Reader` implementations rely on (the same contract
`bufio.Reader` has). All exported accessor methods below (`AssignedIP`,
`PeerID`, `PushRequestSeen`, `RenegotiationCount`, `ConnectionState`,
`DebugDataKeys`, `DebugKeyMethod2Material`) are safe to call from any
goroutine at any time. Control-channel work (handshake, renegotiation)
still runs on its own per-datagram goroutine, so a slow session's
handshake never delays another session's data.

### Lifecycle and `Close`

```go
func (s *Session) Close() error
func (s *Session) Done() <-chan struct{}
func (s *Session) CloseReason() CloseReason
```

A `Session` ends in exactly one of five ways, all flowing through the same
single internal teardown funnel (`closeWithReason`, of which the exported
`Close` is a thin wrapper), after which both `Read` and `Write` return
`io.EOF`:

1. The embedder calls `Close` directly (`CloseReasonEmbedder`).
2. The client sends an explicit-exit-notify on the authenticated data
   channel — the client disconnected cleanly
   (`CloseReasonClientExitNotify`).
3. The server's own idle-session reaper closes a session that has gone
   silent (no authenticated traffic, control or data) for the reap window
   (`CloseReasonIdleReap`).
4. `Server.Close` tears the session down along with every other live
   session (`CloseReasonServerClose`).
5. The session never completed its handshake (a failed TLS handshake, a
   handshake-window timeout) and is torn down before ever reaching
   `OnSession` (`CloseReasonUnknown` — see below; this session was never
   published, so it never triggers `OnSessionClosed`).

In every case, teardown tears down the session's control channel and
releases its assigned tunnel IP and peer-id back to the server's pool for
immediate reuse. `Close` is safe to call more than once and safe to call
concurrently — only the first call's reason is ever recorded.

`Done()` returns a channel closed once teardown has finished, regardless of
cause. `CloseReason()` reports why: it is `CloseReasonUnknown` before
`Done()` has fired.

If `Config.OnSessionClosed` is set, it fires once teardown has fully
completed, but ONLY for a session that was actually handed to `OnSession` —
see [`OnSessionClosed`](#ovpnconfig) above and `Server.Close`'s own
wait-for-callbacks contract.

### `CloseReason`

```go
type CloseReason int

const (
    CloseReasonUnknown CloseReason = iota
    CloseReasonEmbedder
    CloseReasonClientExitNotify
    CloseReasonIdleReap
    CloseReasonServerClose
    CloseReasonReplaced // Config.AssignIP evicted this session for another client
    CloseReasonAuthFailed
)

func (r CloseReason) String() string
```

| Constant | Produced by |
|---|---|
| `CloseReasonUnknown` | A still-live session, or one torn down before it was ever published to `OnSession` (never triggers `OnSessionClosed`). |
| `CloseReasonEmbedder` | `Session.Close` called directly. |
| `CloseReasonClientExitNotify` | An authenticated client-side explicit-exit-notify. |
| `CloseReasonIdleReap` | The server's own idle-session reaper. |
| `CloseReasonServerClose` | `Server.Close` tearing down every live session. |
| `CloseReasonReplaced` | `Config.AssignIP` handed this session's tunnel IP to a newly connecting client (mirrors the reference's default no-`--duplicate-cn` eviction); this session was already published, so `OnSessionClosed` DOES fire with this reason. |
| `CloseReasonAuthFailed` | `Config.AuthUserPass` rejected the client's credentials. **Only fires `OnSessionClosed` for a renegotiation-time rejection** — an initial-handshake rejection never reaches `OnSession` in the first place (same rule as `CloseReasonUnknown`), so it never reaches `OnSessionClosed` either. |

### Other accessors

```go
func (s *Session) AssignedIP() net.IP
func (s *Session) PeerID() uint32
func (s *Session) PushRequestSeen() bool
func (s *Session) RenegotiationCount() uint32
func (s *Session) ConnectionState() tls.ConnectionState
func (s *Session) RemoteAddress() net.Addr
func (s *Session) Stats() SessionStats
```

- **`AssignedIP`** — this session's tunnel address, allocated from
  `Config.Network` and pushed to the client in `PUSH_REPLY`. Always
  populated by the time `OnSession` is invoked. Returns a defensive copy.
- **`PeerID`** — this session's 24-bit peer-id, pushed to the client as
  `peer-id <n>`. 0 both before assignment and for the (valid, distinct)
  allocated peer-id 0 itself; use `AssignedIP() != nil` to check whether
  assignment has happened.
- **`PushRequestSeen`** — whether the client's `PUSH_REQUEST` has been
  answered with a `PUSH_REPLY`. `AssignedIP()` is populated at the same
  point and is generally the preferred check.
- **`RenegotiationCount`** — how many soft-reset key rollovers (TLS
  renegotiations) this session has completed. Diagnostic; not needed by a
  typical embedder.
- **`ConnectionState`** — the underlying `tls.Conn.ConnectionState()`
  (negotiated version, cipher suite, peer certificate chain), captured once
  immediately after the handshake completes. Calling it before `OnSession`
  has fired for this session returns the zero value.
- **`RemoteAddress`** — the client's UDP address; the same value the
  exported `RemoteAddr` field already holds, exposed as an accessor so a
  future storage-representation change doesn't break embedders using the
  method form (a method named `RemoteAddr` would collide with the field).
- **`Stats`** — a point-in-time snapshot of this session's traffic counters
  (`SessionStats`, below). Independently-sampled, not a consistent instant
  across every field — cheap enough to call from any goroutine at any time
  without contending the data path's own locking.

```go
type SessionStats struct {
    BytesIn, BytesOut             uint64
    PacketsIn, PacketsOut         uint64
    KeepalivesIn                  uint64
    InboundQueueDropped           uint64
    Renegotiations                uint32
    EstablishedAt, LastAuthTrafficAt time.Time
}
```

- **`BytesIn`/`BytesOut`** — decrypted IP-packet *payload* bytes seen by
  `Read`/`Write`, never wire bytes (AEAD tag, tls-crypt/UDP framing
  overhead excluded). **`PacketsIn`/`PacketsOut`** count the packets those
  bytes arrived/departed in. A ping keepalive — absorbed inside the
  decrypt path or emitted via a path that bypasses `Write` — increments
  `KeepalivesIn` instead, and still refreshes `LastAuthTrafficAt`.
- **`KeepalivesIn`** — inbound ping keepalives this session authenticated
  and absorbed. Excluded from `BytesIn`/`PacketsIn` (a ping is not tunnel
  payload) but counted here, and it DOES refresh `LastAuthTrafficAt` — a
  client sending nothing but keepalives is never idle-reaped.
- **`InboundQueueDropped`** — decrypted IP packets dropped because the
  session's inbound queue (`Config.SessionInboundQueue`) was full: a slow
  embedder falling behind `Read`.
- **`Renegotiations`** — the same value `RenegotiationCount()` returns.
- **`EstablishedAt`** — when this session's data channel went live (the
  same publish point `OnSession` fires from); zero before that.
- **`LastAuthTrafficAt`** — when this session last received authenticated
  traffic (control or data, primary or lame-duck slot); never advances for
  traffic that failed to authenticate. An absorbed ping keepalive counts as
  authenticated traffic for this field.

Two additional methods, `DebugKeyMethod2Material` and `DebugDataKeys`,
expose raw key-derivation material for test/interop harnesses that need to
independently reproduce this session's data-channel keys. They are
debug/test-only accessors — a production embedder has no reason to call
them.

## Errors

`ovpn.ErrPoolExhausted` (`errors.New("ovpn: tunnel IP pool exhausted")`) is
returned, wrapped, when `Config.Network` has no free host addresses left to
assign to a newly connecting client. Check for it with `errors.Is` if your
embedder needs to distinguish pool exhaustion from other session-setup
failures.

## Full example

The complete, runnable version of the pattern above — including PKI
loading, graceful shutdown, and attaching each `Session` to the userspace
netstack to serve HTTP through the tunnel — is
[`examples/tunnelweb/main.go`](../examples/tunnelweb/main.go):

```go
srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,
    TLSCryptKey: tlsCryptKey,
    Network:     tunnelNetwork,
    Cipher:      "AES-256-GCM",
    OnSession: func(sess *ovpn.Session) {
        // The embedder attaches; nothing in ovpn.Config knows the netstack
        // exists.
        if err := stack.Attach(sess, sess.AssignedIP()); err != nil {
            log.Printf("warning: netstack attach failed for %s: %v", sess.AssignedIP(), err)
        }
    },
})

ovpnDone := make(chan error, 1)
go func() { ovpnDone <- srv.Serve(pc) }()
```

See [examples/tunnelweb/README.md](../examples/tunnelweb/README.md) for the
full walkthrough, including PKI generation and connecting a real OpenVPN
client.
</content>
