<!-- generated-by: gsd-doc-writer -->
[← Back to README](../README.md)

# Netstack

Package `netstack` (`github.com/8upio/govpn/netstack`) is a privilege-free,
userspace IPv4 stack that terminates OpenVPN tunnel traffic entirely
in-process: no TUN device, no `CAP_NET_ADMIN`, no separate OS network
namespace. An embedder attaches an `ovpn.Session` (or anything else shaped
like `io.ReadWriteCloser`) to a `netstack.Stack`, and the stack parses,
dispatches, and answers IPv4/ICMP/UDP/TCP traffic for that session — including
handing back an ordinary `net.Listener` that `http.Serve` can run against,
with no OS socket involved.

It deliberately implements only the wire formats this project's scope
requires, each verified against its primary spec:

- RFC 791 §3.1 — IPv4 header format, IHL, fragmentation flags
- RFC 1071 — Internet checksum (16-bit one's-complement sum)
- RFC 792 — ICMP echo request/reply
- RFC 768 — UDP header and its IPv4 pseudo-header checksum
- RFC 9293 (obsoletes RFC 793) — TCP header and state machine

`netstack` imports nothing from `github.com/8upio/govpn`: it declares its own
minimal `Session` interface (below) rather than depending on `*ovpn.Session`
directly, so `*ovpn.Session` satisfies it structurally with no coupling in
either direction. See [ARCHITECTURE.md](ARCHITECTURE.md) for how this package
fits into the overall request pipeline.

## Scope: what this is and is not

This is **not** a general-purpose TCP/IP stack. There is no client-side TCP
(no outbound connect), no IP forwarding/routing between attached sessions, no
IPv6, no fragmentation/reassembly (fragments are dropped), and no ICMP error
generation (unreachable/TTL-exceeded messages are never sent). One `Stack`
terminates exactly one server tunnel endpoint (`ServerIP()`); it is a
terminator, not a router — a packet whose destination isn't the server's own
tunnel IP is dropped, never forwarded to another attached session.

What it does implement, on the server side only:

- IPv4 parsing/building with checksum validation
- A UDP port demux exposing the stdlib `net.PacketConn` interface
- A minimal, server-side-only TCP implementation (accept, not connect) exposing
  a stdlib `net.Listener` / `net.Conn`
- An ICMP echo (ping) responder
- Per-session and per-stack drop/delivery statistics

## Creating a Stack

```go
stack, err := netstack.New(serverIP)
if err != nil {
    // ...
}
defer stack.Close()
```

`New(serverIP net.IP, opts ...Option) (*Stack, error)` builds a `Stack`
terminating `serverIP` — the server's own tunnel address, the same value the
embedder assigns itself when constructing the tunnel network (see
[CONFIGURATION.md](CONFIGURATION.md)). `serverIP` must be non-nil and have a
usable IPv4 form; IPv6 is rejected. `New` returns `ErrNilServerIP` for a nil
address and `ErrNotIPv4Address` for a non-IPv4 one.

`ServerIP() net.IP` returns the stack's own tunnel address, as passed to `New`.

### Options

`New` accepts functional options of type `Option`:

- `WithClock(c Clock)` — overrides the `Stack`'s `Clock` (default
  `SystemClock{}`), which drives the TCP retransmit and TIME_WAIT timers.
  Tests can inject a fake clock to advance and fire timers deterministically
  without real sleeps; embedders generally never need this.

The `Clock` interface (`clock.go`) is:

```go
type Clock interface {
    Now() time.Time
    NewTimer(d time.Duration) Timer
}

type Timer interface {
    C() <-chan time.Time
    Reset(d time.Duration) bool
    Stop() bool
}
```

### Close

`Close() error` detaches every attached session and shuts the stack down.
It does **not** close any attached session itself — session lifetime belongs
to the embedder, not the stack.

## Attaching a session

```go
type Session interface {
    Read(p []byte) (int, error)
    Write(p []byte) (int, error)
    Close() error
}
```

`Attach(sess Session, ip net.IP) error` registers `sess` as the owner of
tunnel address `ip` and starts exactly one goroutine reading from it. `*ovpn.Session`
already satisfies `netstack.Session` structurally (it is an `io.ReadWriteCloser`),
so no adapter is needed — see the `examples/tunnelweb` walkthrough below.

Contract notes:

- `Read` is datagram-shaped: each call returns one full, decrypted IP packet,
  and is called from exactly one goroutine (the attachment's own read loop).
  Do not start a second reader goroutine against the same session.
- `Write` may be called concurrently from any number of goroutines — the
  netstack's own TCP retransmit-timer goroutine, TIME_WAIT timer, and any
  application-handler goroutine may all call `Write` on the same session.

`Attach` returns:

- `ErrInvalidAttachIP` — `ip` is nil or not a usable IPv4 address
- `ErrAttachServerIP` — `ip` equals the stack's own server tunnel IP; a
  session may not claim to be the server
- `ErrDuplicateAttach` — an attachment already exists for `ip`

`Detach(ip net.IP) bool` removes the route for `ip`, if one exists, and stops
its read loop; it returns whether a route was actually removed. It does not
close the underlying session — again, session lifetime belongs to the
embedder.

### Access control on attached traffic

Every inbound packet from an attachment is checked before any protocol
dispatch:

1. The packet's IPv4 source must equal the attachment's registered `ip` — a
   session sending packets claiming another session's tunnel IP (or the
   server's own) is spoofing and is dropped.
2. The packet's IPv4 destination must equal the server tunnel IP — the stack
   is a terminator, not a router, and never forwards a packet to another
   attached session.

Outbound packets are checked symmetrically: any packet a protocol handler
tries to send whose IPv4 source is not the server's own tunnel IP is dropped
and returns `ErrOutboundSourceMismatch`, fail-closed.

## ICMP echo

The server tunnel IP automatically answers ICMP echo requests (ping)
addressed to it — no separate API call is needed once a session is attached.
Every other ICMP type, and every malformed ICMP message, is dropped silently
with no reply and no generated ICMP error.

## UDP

```go
pc, err := stack.ListenUDP(port)
```

`ListenUDP(port uint16) (net.PacketConn, error)` opens a UDP listener bound
to `(serverIP, port)`. It returns the stdlib `net.PacketConn` interface, so
unmodified socket-based code can use it directly. Listeners can be opened at
any time after the stack is running.

- `port` must not be `0` — there is no ephemeral-port allocator; the embedder
  names the exact port it wants. `ListenUDP(0)` returns `ErrUDPPortZero`.
- A port that already has a live listener returns `ErrUDPPortInUse`.

The returned `net.PacketConn` implements the full standard contract —
`ReadFrom`, `WriteTo`, `Close`, `LocalAddr`, `SetDeadline`,
`SetReadDeadline`, `SetWriteDeadline` — safe for concurrent use from any
number of goroutines. Notable behavior:

- `WriteTo` requires `addr` to be a non-nil, IPv4 `*net.UDPAddr`
  (`ErrUDPInvalidAddr` otherwise), rejects payloads over 65507 bytes
  (`ErrUDPPayloadTooLarge`), and returns `ErrUDPNoRoute` if no session is
  currently attached at the destination IP.
- Inbound datagrams to a port with no listener are dropped silently (no ICMP
  port-unreachable is generated).
- Each listener's inbound queue is bounded (64 datagrams); once full, the
  newest datagram is dropped rather than blocking the stack's read loop.

## TCP

```go
ln, err := stack.ListenTCP(port)
httpSrv.Serve(ln)
```

`ListenTCP(port uint16) (net.Listener, error)` opens a TCP listener bound to
`(serverIP, port)`, returning the stdlib `net.Listener` interface — this is
what makes `http.Serve(ln)` work with zero adaptation. The first call to
`ListenTCP` on a `Stack` registers the shared TCP demux; every subsequent
`ListenTCP` call on the same `Stack` reuses it.

- `port` must not be `0` (`ErrTCPPortZero`).
- A port that already has a listener returns `ErrTCPPortInUse`.
- `Accept() (net.Conn, error)` blocks until a completed (fully-handshaked)
  connection is available, or the listener is closed (`ErrTCPListenerClosed`,
  which wraps `net.ErrClosed`).
- `Close() error` unblocks any goroutine blocked in `Accept` and resets every
  connection still sitting in the not-yet-accepted backlog.
- `Addr() net.Addr` returns the listener's `*net.TCPAddr`.

This is a **server-side-only** implementation: it accepts inbound
connections (SYN → SYN-ACK → ESTABLISHED) but never initiates one. Each
accepted connection is a `net.Conn` implementing the full standard
contract — `Read`, `Write`, `Close`, `CloseWrite`, `LocalAddr`, `RemoteAddr`,
`SetDeadline`, `SetReadDeadline`, `SetWriteDeadline`:

- `Read` delivers from an in-order byte-stream buffer with ordinary
  `io.Reader` streaming semantics — unlike `ovpn.Session.Read`'s
  datagram-shaped, retain-and-error contract, this is a byte stream, not
  one-packet-per-`Read`.
- A connection reset (by an inbound RST, by exceeding the retransmit limit,
  or by the owning session being detached) surfaces as `ErrTCPConnReset` from
  `Read`/`Write`.

Built-in denial-of-service bounds, applied per attached session (identified
by tunnel IP), not globally:

- **Accept backlog**: up to 16 completed connections queue per listener
  awaiting `Accept`; beyond that, a completed connection is reset rather than
  queued unboundedly.
- **Half-open cap**: at most 8 simultaneous half-open (`SYN_RCVD`)
  connections per attached session — a SYN flood from one client's tunnel
  cannot exhaust state that would affect other attached sessions.
- **Live connection cap**: at most 64 simultaneous non-`CLOSED` connections
  per attached session.
- A SYN to a port with no listener, or any segment addressed to no live
  connection (other than an RST, which is never answered with an RST), gets
  an RFC 9293 §3.5.2 RST reply.
- The advertised MSS defaults to 1460 and is capped at that value even if a
  peer requests a larger one; if a SYN carries no MSS option at all, RFC
  9293's own default of 536 is used.

## Statistics

`Stats() Stats` returns a point-in-time snapshot of the stack's own
drop/delivery counters:

```go
type Stats struct {
    ICMPEchoRequests         uint64
    ICMPEchoReplies          uint64
    PacketsReceived          uint64
    MalformedDropped         uint64
    FragmentsDropped         uint64
    SpoofedSourceDropped     uint64
    WrongDestinationDropped  uint64
    UnhandledProtocolDropped uint64
    OutboundSourceDropped    uint64
    ShortReadBufferGrown     uint64
}
```

`TCPStats() TCPStats` returns a separate snapshot of TCP-specific counters
(zero-valued if `ListenTCP` has never been called):

```go
type TCPStats struct {
    BacklogOverflow uint64
    HalfOpenCapHits uint64
    LiveConnCapHits uint64
    ReorderDropped  uint64
    RSTsSent        uint64
    RSTsReceived    uint64
}
```

Both are useful for observability (logging, health checks) and for detecting
whether a client is being throttled by one of the DoS bounds above.

## Composing with `ovpn.Session`

The canonical example, [`examples/tunnelweb`](../examples/tunnelweb/README.md),
shows the full composition: a real `ovpn.Server` handshakes clients over UDP,
and every established `*ovpn.Session` is attached to a `netstack.Stack` that
serves an HTTP site through the tunnel — with no TUN device and no OS socket
bound for HTTP. The load-bearing wiring is `Config.OnSession`:

```go
stack, err := netstack.New(serverIP)
// ...
ln, err := stack.ListenTCP(httpPort)
// ...
go httpSrv.Serve(ln)

srv := ovpn.NewServer(ovpn.Config{
    TLSConfig:   tlsCfg,
    TLSCryptKey: tlsCryptKey,
    Network:     tunnelNetwork,
    Cipher:      "AES-256-GCM",
    OnSession: func(sess *ovpn.Session) {
        // The embedder attaches; nothing in ovpn.Config knows the
        // netstack exists — netstack and ovpn are wired together only
        // here, in application code.
        if err := stack.Attach(sess, sess.AssignedIP()); err != nil {
            log.Printf("warning: netstack attach failed for %s: %v", sess.AssignedIP(), err)
        }
    },
})
```

`ovpn.Config` has no field or hook that references `netstack` at all — the
two packages are wired together entirely by the embedder's own code, inside
`OnSession`. An embedder that wants raw IP packets instead of an in-process
netstack can simply read/write `*ovpn.Session` directly and skip `netstack`
altogether; see [API.md](API.md) for the `Session` surface.

## Related documentation

- [README.md](../README.md) — project overview and quick start
- [ARCHITECTURE.md](ARCHITECTURE.md) — how `netstack` fits into the full
  connection pipeline
- [API.md](API.md) — the `ovpn.Server`/`Session`/`Config` surface `netstack`
  sessions come from
- [GETTING-STARTED.md](GETTING-STARTED.md) — first steps embedding the
  library
- [examples/tunnelweb/README.md](../examples/tunnelweb/README.md) — the full
  worked example combining `ovpn` and `netstack`
