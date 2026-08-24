---
phase: 01-handshake
reviewed: 2026-08-23T00:00:00Z
depth: standard
files_reviewed: 20
files_reviewed_list:
  - .dockerignore
  - .github/workflows/ci.yml
  - .gitignore
  - Makefile
  - cmd/gentestpki/main.go
  - go.mod
  - internal/ctrlconn/conn.go
  - internal/ctrlconn/conn_test.go
  - internal/reliable/reliable.go
  - internal/reliable/reliable_test.go
  - internal/tlscrypt/golden_test.go
  - internal/tlscrypt/keyfile.go
  - internal/tlscrypt/keyfile_test.go
  - internal/tlscrypt/tlscrypt.go
  - internal/tlscrypt/tlscrypt_test.go
  - internal/wire/golden_test.go
  - internal/wire/wire.go
  - internal/wire/wire_test.go
  - ovpn.go
  - ovpn_test.go
  - session.go
  - test/interop/Dockerfile
  - test/interop/capture_test.go
  - test/interop/decode.go
  - test/interop/docker-compose.lossy.yml
  - test/interop/docker-compose.yml
  - test/interop/entrypoint.sh
  - test/interop/golden_export.go
  - test/interop/interop_test.go
  - test/interop/pcap.go
  - test/interop/server/Dockerfile
  - test/interop/server/main.go
  - testdata/golden/README.md
  - testdata/golden/manifest.json
findings:
  critical: 1
  warning: 2
  info: 3
  total: 6
status: issues_found
---

# Phase 01: Code Review Report

**Reviewed:** 2026-08-23
**Depth:** standard
**Files Reviewed:** 33 (20 required-reading source files plus their directly-associated test/build files already covered by the same read)
**Status:** issues_found

## Summary

The wire/tlscrypt/reliable layers are careful, well-tested ports of the OpenVPN C reference — I cross-checked `internal/reliable/reliable.go`'s `Next`/`Ack`/`Due`/`Put`/`Get` and `internal/tlscrypt/tlscrypt.go`'s wrap/unwrap construction directly against `/Users/svenloth/dev/openvpn-reference/src/openvpn/reliable.c` and `tls_crypt.c` line-for-line, including the wraparound-unsafe `<` comparison in `Reliable.Ack` (this is *not* a bug — the C reference does the exact same non-wraparound-safe comparison at `reliable.c:437`). `internal/wire`'s parser never indexes without a length check first, and the golden-vector tests genuinely round-trip real captured client bytes.

The one real defect is architectural, not cryptographic: `ovpn.go`'s per-session `pump()` goroutine and `Server.sessions` map entry are never released for the ordinary lifetime of a session — `Session.Close()` (the library's own public teardown API) does not unwind either of them. For an embeddable, long-running library this is a genuine resource-leak/availability bug, not a mere inefficiency, because it defeats the documented contract of `Close()` and is triggerable by completely ordinary client connect/disconnect traffic (no attack required to hit it, though it also makes a trivial DoS lever). See CR-01.

Two further issues are secondary in severity: an unrecovered panic in the client-supplied `OnSession` callback can take down the whole embedding process (WR-01), and `internal/tlscrypt.Wrapper.Wrap` silently wraps its packet-ID sequence counter around 2^32 instead of erroring the way `tls_crypt_wrap` in the reference does (WR-02) — practically unreachable in a real session's lifetime, but a genuine spec-fidelity gap given how much the rest of this codebase prides itself on byte-exactness. A few Info-level items round out the findings.

## Critical Issues

### CR-01: `Session.Close()` does not remove the session from `Server.sessions` or stop the per-session `pump()` goroutine — every session leaks a goroutine and a map entry for the life of the process

**File:** `session.go:104-110`, `ovpn.go:196-329` (specifically `ovpn.go:249` and `ovpn.go:321-328`)

**Issue:**

`session.go`'s `Close()` is documented as "tears down this session's control channel":

```go
func (s *Session) Close() error {
    if s.conn == nil {
        return nil
    }
    return s.conn.Close()
}
```

It only closes the `ctrlconn.Conn` (which does correctly stop `Conn`'s own internal `retransmitLoop` via `closeCh` — that part is fine). It never:

1. Calls back into `Server.removeSession` to delete the entry from `Server.sessions` (`ovpn.go:374-380`) — `Session` doesn't even hold a reference to its owning `*Server` to be able to do so.
2. Closes or otherwise signals `sess.inbound` (`ovpn.go:249`, a `chan wire.ControlPacket`), which is what the per-session `pump()` goroutine ranges over forever:

```go
func (sess *Session) pump() {
    for cp := range sess.inbound {
        sess.conn.Deliver(cp)
    }
}
```

Nothing in the codebase ever calls `close(sess.inbound)` (confirmed by `grep -rn inbound`), so this `range` loop — and the goroutine running it — never terminates. It is started once per session in `ovpn.go:295` (`go sess.pump()`) for *every* session that completes the initial hard-reset exchange, whether the handshake subsequently succeeds, fails, times out, or the application later calls `Session.Close()`.

`Server.removeSession` (`ovpn.go:374-380`) is only ever invoked from two places: `runHandshake` on a *failed* `Handshake()` (`ovpn.go:345-349`) and `enforceHandshakeWindow` on a *timeout* (`ovpn.go:364-372`). There is no code path that removes a session from `Server.sessions` after a **successful** handshake, ever — not even when the application later calls `Session.Close()`. Combined with the goroutine leak above, a long-running embedding process that serves many short-lived clients (the exact deployment shape this library is designed for — see PROJECT.md's "embeddable in any Go program" core value) accumulates one live goroutine plus one retained `Session`/`*ctrlconn.Conn`/map-entry per client, forever, with no way for the application to reclaim it via the public API.

This is squarely a correctness bug (the documented behavior of `Close()` is not what the code does), and it is also a resource-exhaustion/availability concern distinct from an "inefficient algorithm": nothing bounds how many of these leak, and it is reachable by ordinary connect/disconnect churn, not just adversarial input.

**Fix:**

Give `Session` a way to signal its owning `Server` and unblock `pump` without racing a concurrent send on `sess.inbound` (closing a channel that other goroutines may still be sending on panics). A `stop` channel selected on both sides avoids that hazard:

```go
// session.go
type Session struct {
    ...
    srv    *Server
    stopCh chan struct{}
    stopOnce sync.Once
}

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
```

```go
// ovpn.go
sess = &Session{
    ...
    srv:     s,
    stopCh:  make(chan struct{}),
    inbound: make(chan wire.ControlPacket, inboundQueueSize),
}
...
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
```

And update `handleDatagram`'s enqueue to also select on `stopCh` so a send to a session mid-teardown doesn't block forever:

```go
select {
case sess.inbound <- cp:
case <-sess.stopCh:
default:
}
```

Also route `runHandshake`'s failure path and `enforceHandshakeWindow`'s timeout path through the same `Session.Close()` (or have them call `sess.stopOnce`/`removeSession` directly) so there is exactly one teardown path instead of two independent ones that both need to remember to do all three things (stop conn, stop pump, remove from map).

## Warnings

### WR-01: `Config.OnSession` is invoked without panic recovery, so a panicking caller callback crashes the entire embedding process

**File:** `ovpn.go:356-358`

**Issue:** `runHandshake` calls the user-supplied callback directly on a bare goroutine:

```go
if s.cfg.OnSession != nil {
    s.cfg.OnSession(sess)
}
```

There is no `recover()` around this call. Since this runs on a goroutine spawned per-session (`ovpn.go:296`, `go s.runHandshake(sess)`), an unrecovered panic inside `OnSession` (e.g. a nil-pointer dereference in application code reacting to a new session) will propagate up through the goroutine and crash the entire process — taking down every other in-flight session on the same embedding server, not just the one that triggered it. For a library explicitly designed to be embedded "in any Go program" (PROJECT.md), one caller mistake in a single connection callback should not be able to bring down the whole host process.

**Fix:**
```go
func (s *Server) runHandshake(sess *Session) {
    tlsConn := tls.Server(sess.conn, s.cfg.TLSConfig)
    err := tlsConn.Handshake()
    close(sess.doneCh)

    if err != nil {
        _ = sess.conn.Close()
        s.removeSession(sess)
        return
    }

    state := tlsConn.ConnectionState()
    sess.connState = state
    if len(state.PeerCertificates) > 0 {
        sess.PeerCN = state.PeerCertificates[0].Subject.CommonName
    }
    if s.cfg.OnSession != nil {
        func() {
            defer func() {
                if r := recover(); r != nil {
                    // log/route to an error handler; at minimum don't take
                    // the whole process down for one session's callback.
                }
            }()
            s.cfg.OnSession(sess)
        }()
    }
}
```

### WR-02: `tlscrypt.Wrapper.Wrap`'s packet-ID sequence counter silently wraps around instead of erroring, unlike the reference's `tls_crypt_wrap`

**File:** `internal/tlscrypt/tlscrypt.go:178-193`

**Issue:** The reference's `tls_crypt_wrap` (`tls_crypt.c:151-159`) explicitly checks for packet-ID rollover and fails the wrap (`"TLS-CRYPT ERROR: packet ID roll over."`) rather than emitting a wrapped packet with a wrapped-around, no-longer-monotonic sequence number:

```go
func (w *Wrapper) Wrap(dst, header, plaintext []byte) ([]byte, error) {
    ...
    w.mu.Lock()
    w.sendSeq++
    seq := w.sendSeq
    w.mu.Unlock()
    ...
}
```

`w.sendSeq` is a `uint32`; after `0xFFFFFFFF` it silently rolls over to `0` with no error returned, unlike every other place in this codebase (e.g. `writeStaticKeyV1`'s length check, `NewWrapper`'s key-length check) where the Go port deliberately preserves the reference's fail-closed behavior. In practice a control channel would need ~4 billion packets in one session's lifetime to hit this, so it's not currently exploitable, but it is a real, silent deviation from the reference's documented wire-safety guarantee (a wrapped-around sequence number breaks the receiver's replay-window assumptions), and this project's own stated correctness bar is byte- and behavior-exactness against the C reference.

**Fix:**
```go
func (w *Wrapper) Wrap(dst, header, plaintext []byte) ([]byte, error) {
    if len(header) != OffPID {
        return nil, errors.New("tlscrypt: header must be exactly 9 bytes (opcode+key-id byte + 8-byte session id)")
    }

    w.mu.Lock()
    if w.sendSeq == 0xFFFFFFFF {
        w.mu.Unlock()
        return nil, errors.New("tlscrypt: packet ID roll over")
    }
    w.sendSeq++
    seq := w.sendSeq
    w.mu.Unlock()
    ...
}
```

## Info

### IN-01: `cmd/gentestpki/main.go`'s `rootCert` variable is dead code

**File:** `cmd/gentestpki/main.go:100-171`

**Issue:** `rootCert` is declared, assigned in both the `profileSmall` and `profileLarge` branches (`rootCert = caCert`), and then only ever referenced via the blank-identifier discard `_ = rootCert` (line 171) to satisfy the compiler's unused-variable check. Every certificate-issuing call in both branches uses the locally-scoped `caCert`/`rootCert`-equivalent variable directly (e.g. `generateECDSALeaf("govpn-interop-server", caCert, caKey, ...)`), never `rootCert` itself.

**Fix:** Remove the `rootCert` variable and its assignments entirely; nothing reads it.

### IN-02: `test/interop/server/main.go`'s `loadConfig` builds paths with string concatenation instead of `filepath.Join`

**File:** `test/interop/server/main.go:132-184`

**Issue:** Every path in `loadConfig` is built as `pkiDir + "/ca.crt"`, `pkiDir + "/server.crt"`, etc., rather than `filepath.Join(pkiDir, "ca.crt")`. This is inconsistent with the rest of the codebase (e.g. `cmd/gentestpki/main.go` uses `filepath.Join` throughout) and is fragile if `pkiDir` is ever supplied with a trailing slash or on a platform where `/` isn't the path separator (not a real concern for this Linux-only Docker harness today, but a needless inconsistency).

**Fix:** Use `filepath.Join(pkiDir, "ca.crt")` etc. throughout.

### IN-03: `internal/ctrlconn/conn.go`'s `flushAckOnly` can emit a spurious empty ACK-only packet under a benign race

**File:** `internal/ctrlconn/conn.go:196-205`

**Issue:** `flushAckOnly` checks `c.acks.Peek()` (true) and then calls `buildControlPacket`, which internally calls `c.acks.Drain()`. Between the `Peek()` and the `Drain()`, a concurrent `Write`'s own call to `buildControlPacket` (piggybacking ACKs on outgoing data) can drain the same pending ACKs first, leaving `flushAckOnly`'s own `Drain()` to return an empty slice — resulting in a wire `P_ACK_V1` packet transmitted with a zero-length ack array, wasting a datagram. This is low-impact (documented as acceptable behavior in the surrounding comment) and does not violate correctness, but it's worth tightening for cleanliness: skip transmission entirely if `buildControlPacket`'s drained ack count is empty.

**Fix:**
```go
func (c *Conn) flushAckOnly() {
    if !c.acks.Peek() {
        return
    }
    wireBytes, acked, err := c.buildControlPacketN(wire.OpAckV1, 0, nil)
    if err != nil || acked == 0 {
        return
    }
    _ = c.transmit(wireBytes)
}
```
(or equivalent: have `buildControlPacket` report how many acks it actually drained, and skip the transmit if zero.)

---

_Reviewed: 2026-08-23_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
