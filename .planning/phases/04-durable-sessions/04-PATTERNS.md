# Phase 4: Durable Sessions - Pattern Map

**Mapped:** 2026-08-28
**Files analyzed:** 6 (existing files extended; no new packages/files per RESEARCH.md's "Recommended Project Structure")
**Analogs found:** 6 / 6 (this phase EXTENDS existing files — the "analog" for each new capability is a sibling mechanism already living in the same file)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog (same file, sibling mechanism) | Match Quality |
|--------------------|------|-----------|-------------------------------------------------|---------------|
| `ovpn.go` — `Config.RenegSec` field + soft-reset routing in `handleDatagram` | config + controller (demux) | event-driven | `Config` struct fields (existing) + `handleDatagram`'s existing session-lookup/key-id branch (`ovpn.go:295-447`) | exact |
| `ovpn.go` — `runRenegotiation` (new handshake driver, no PUSH) | controller (protocol state machine) | request-response | `runHandshake`/`performKeyMethod2Exchange` (`ovpn.go:503-559`, `697-728`) | exact |
| `session.go` — two-slot key-state (`primary`/`lameDuck`) replacing single `dataWrapper` | model (session state) | CRUD (key material lifecycle) | existing `dataWrapper *datachan.Wrapper` field + its mu-guarded publish/read pattern (`session.go:174-181`, `340-384`) | exact |
| `session.go` — `handleDataPacket` dual-key decrypt + OCC_EXIT check | service (data-path transform) | streaming / transform | existing `handleDataPacket` (`session.go:357-384`) | exact |
| `session.go` — reap timer goroutine (`startReap`/`runReap`) | service (background timer) | event-driven | existing `startKeepalive`/`runKeepalive` (`session.go:386-421`) | exact |
| `session.go` — server-side reneg-sec timer goroutine | service (background timer) | event-driven | existing `startKeepalive`/`runKeepalive` (`session.go:386-421`), `enforceHandshakeWindow` (`ovpn.go:751-761`) | exact |
| `internal/datachan/datachan.go` — `keyID` threading (no code change expected) | utility | CRUD | `NewWrapper(keys, peerID, keyID)` already takes `keyID uint8` (`datachan.go:117`) | exact (already built for this) |
| `test/interop/interop_test.go` — new reneg/soak scenario entries | test | request-response (integration) | existing `scenarios` slice + probe framework (03-06) | role-match |
| `test/interop/pki/client.conf` (or new variant) — `explicit-exit-notify 1`, `reneg-sec 20` | config | file-I/O | existing `client.conf` (`test/interop/pki/client.conf:1-16`) | exact |

## Pattern Assignments

### `ovpn.go`: `Config.RenegSec` field

**Analog:** existing `Config` fields (pattern already established for injectable timing, e.g. handshake window)

Read `Config` struct definition to find exact insertion point and existing `Duration`-typed fields' doc-comment style before adding `RenegSec time.Duration` (0 → default 3600s, per CONTEXT.md). Follow the same "0 means default X" doc-comment convention already used for other optional Config fields.

---

### `ovpn.go`: soft-reset routing in `handleDatagram` (existing-session branch)

**Analog:** `handleDatagram`'s existing session-lookup and key-id extraction

**Current key-id extraction** (`ovpn.go:300`):
```go
opcode, keyID := wire.ParseHeaderByte(packet[0])
if !wire.ValidOpcode(opcode) {
    return
}
```

**Current existing-session delivery path** (`ovpn.go:432-447`):
```go
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
    // packet would be dropped ...
}
```

**Pattern to apply (per RESEARCH Open Question 2):** BEFORE this unconditional `sess.inbound <-` send, branch on `keyID`:
- `keyID == sess.primary.keyID` (existing key) → current behavior, deliver to `sess.conn`/pump as today.
- `opcode == wire.OpControlSoftResetV1 && keyID == nextKeyID(sess.primary.keyID) && sess.primary established` → intercept: do NOT deliver to the current `sess.conn`; instead call into a new renegotiation-start path (spin up a second `ctrlconn.Conn` under the new key-id, same `sess.wrapper`/session IDs per Pattern 3 of RESEARCH.md, move current primary → lameDuck).
- any other key-id → reject/drop (Pitfall 4 — do not trust an arbitrary key-id).

`wire.ParseHeaderByte`/`AppendHeaderByte` already round-trip key-id end-to-end (`internal/wire/wire.go:104-112`) — no wire-format change needed, only new routing logic in this branch.

**Key-id increment helper to add** (verbatim from RESEARCH.md's Go translation):
```go
// Source: derived from ssl.c:990-1002, ssl_pkt.h:38 (P_KEY_ID_MASK = 0x07)
const keyIDMask = 0x07

func nextKeyID(current uint8) uint8 {
    next := (current + 1) & keyIDMask
    if next == 0 {
        next = 1
    }
    return next
}
```

---

### `ovpn.go`: `runRenegotiation` (new soft-reset handshake driver)

**Analog:** `runHandshake` + `performKeyMethod2Exchange`, WITHOUT `performPushExchange` (Pattern 4 of RESEARCH.md — reneg must not repeat PUSH)

**Structural analog** (`ovpn.go:503-528`, trimmed to the parts to mirror):
```go
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
    // reneg driver STOPS HERE — no performPushExchange call (Pattern 4)
}
```

**New renegotiation driver should:**
1. Build a new `*ctrlconn.Conn` via `ctrlconn.New(sess.SessionID, sess.clientSessionID, sess.wrapper, transport, sess.RemoteAddr, nil)` — reuse the SAME `sess.wrapper` (`*tlscrypt.Wrapper`), never allocate a fresh one (Pattern 3 / Anti-Pattern 1). Constructor signature: `internal/ctrlconn/conn.go:101`.
2. Run `tls.Server(newConn, s.cfg.TLSConfig).Handshake()` — same TLS config, unmodified `crypto/tls`.
3. Run a Key-Method-2-equivalent exchange under the new key-id — reuse `performKeyMethod2Exchange`'s structure (it already parameterizes over `sess`/`tlsConn`; consider extracting the KM2 body to accept a target key-slot instead of always writing to `sess.dataKeys`), calling `keyderiv.DeriveKeys` with the SAME `sess.clientSessionID`/`sess.SessionID` (session IDs never change across a soft reset — Pattern 3).
4. Build a new `datachan.Wrapper` via `datachan.NewWrapper(newDataKeys.ServerSlots(), sess.peerID, newKeyID)` — SAME `peerID`, NEW `keyID` (already threaded through `NewWrapper`'s third parameter, `internal/datachan/datachan.go:117`).
5. Atomically: move current `sess.primary` → `sess.lameDuck` (set `mustDie = clock.Now().Add(transitionWindow)`), install the new wrapper as `sess.primary`. Follow the EXACT `sess.mu`-then-`s.srv.mu` nesting discipline `performPushExchange` uses for its atomic publish (`ovpn.go:648-661`) — this is the established precedent for "publish new session-visible state without racing `Close`."
6. Do NOT call `performPushExchange` a second time (Anti-Pattern 2) — no re-allocation of `assignedIP`/`peerID`.

---

### `session.go`: two-slot key-state (primary/lameDuck)

**Analog:** existing single `dataWrapper *datachan.Wrapper` field and its `mu`-guarded read/write discipline

**Current field + guard comment** (`session.go:174-181`, `148-159`):
```go
// mu guards assignedIP, peerID, and dataWrapper below (WR-03): ...
mu sync.Mutex
...
// dataWrapper is this session's AES-256-GCM data-channel Wrapper, ...
// Guarded by mu.
dataWrapper *datachan.Wrapper
```

**Pattern to apply:** replace the single `dataWrapper` field with two named fields (per RESEARCH.md's explicit recommendation to avoid a generic map — mirrors the reference's own `KS_PRIMARY`/`KS_LAME_DUCK` two-slot design):
```go
type keySlot struct {
    keyID   uint8
    conn    *ctrlconn.Conn      // this slot's own control-channel Conn (for reneg in flight / just-completed)
    wrapper *datachan.Wrapper   // this slot's AES-256-GCM data-channel wrapper
    mustDie time.Time           // zero value == "not a lame-duck / never expires"; set only when demoted
}
```
Keep both slots guarded by the SAME `sess.mu` the single `dataWrapper` field already uses — no new lock. All existing call sites reading `sess.dataWrapper` (`Write`, `handleDataPacket`, `Close`'s snapshot block at `session.go:486-507`) must switch to reading `sess.primary.wrapper` (and, in `handleDataPacket`, also try `sess.lameDuck.wrapper`).

**Close's existing snapshot-then-cleanup pattern to extend** (`session.go:486-507`) — currently snapshots one `dataWrapper`; extend it to release BOTH `primary` and (if live) `lameDuck` cleanly, but note `dataSessions` is keyed by `peerID` which does not change across reneg — no double-`delete` risk, just ensure the snapshot reads `sess.primary.wrapper != nil` instead of the old field name.

---

### `session.go`: `handleDataPacket` dual-key decrypt + OCC_EXIT check

**Analog:** current `handleDataPacket` (`session.go:357-384`)

**Current code (single-key)**:
```go
func (s *Session) handleDataPacket(packet []byte) {
    if s.dataWrapper == nil {
        return
    }
    plaintext, err := s.dataWrapper.Open(nil, packet)
    if err != nil {
        // Includes datachan.ErrPingAbsorbed: a ping is absorbed inside
        // Open, never delivered, and never counts as a delivered IP
        // packet.
        return
    }
    select {
    case s.ipInbound <- plaintext:
    case <-s.stopCh:
    default:
        // Queue full: drop ...
    }
}
```

**Pattern to apply** (Pattern 5/6 + Pitfall 5 of RESEARCH.md — try primary first, cheapest; fall back to lameDuck only if not expired; check OCC_EXIT post-decrypt, pre-delivery; update `lastAuthTraffic` on any successful decrypt):
```go
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
        if lameDuck.wrapper == nil || s.clock.Now().After(lameDuck.mustDie) {
            return
        }
        plaintext, err = lameDuck.wrapper.Open(nil, packet)
        if err != nil {
            return
        }
    }

    s.touchLastAuthTraffic() // Pattern 6: any authenticated traffic resets the reap timer

    if isExitNotify(plaintext) { // Pattern 5
        _ = s.Close()
        return
    }

    select {
    case s.ipInbound <- plaintext:
    case <-s.stopCh:
    default:
    }
}
```

**OCC_EXIT detection helper (verbatim from RESEARCH.md's Go translation):**
```go
// Source: occ.c:55-58 (occ_magic), occ.h:29-30,67 (OCC_STRING_SIZE, OCC_EXIT)
var occMagic = []byte{
    0x28, 0x7f, 0x34, 0x6b, 0xd4, 0xef, 0x7a, 0x81,
    0x2d, 0x56, 0xb8, 0xd3, 0xaf, 0xc5, 0x45, 0x9c,
}

const occExit = 0x06

func isExitNotify(plaintext []byte) bool {
    return len(plaintext) >= 17 &&
        bytes.Equal(plaintext[:16], occMagic) &&
        plaintext[16] == occExit
}
```

---

### `session.go`: reap timer goroutine

**Analog:** `startKeepalive`/`runKeepalive` (`session.go:386-421`) — same shape, ticker + stopCh select, factored so tests can inject a tick channel

**Current pattern (verbatim, to mirror exactly)**:
```go
func (s *Session) startKeepalive() {
    ticker := time.NewTicker(pingInterval)
    go func() {
        defer ticker.Stop()
        s.runKeepalive(ticker.C)
    }()
}

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
```

**New reap timer — mirror exactly, checking elapsed-since-`lastAuthTraffic` against injectable clock instead of emitting**:
```go
func (s *Session) startReap() {
    ticker := time.NewTicker(reapCheckInterval) // e.g. 1s or 5s poll granularity
    go func() {
        defer ticker.Stop()
        s.runReap(ticker.C)
    }()
}

func (s *Session) runReap(tickCh <-chan time.Time) {
    for {
        select {
        case <-tickCh:
            if s.clock.Now().Sub(s.lastAuthTraffic()) >= s.reapWindow {
                _ = s.Close()
                return
            }
        case <-s.stopCh:
            return
        }
    }
}
```
Start this goroutine at the SAME point `startKeepalive` is started today — `performPushExchange`'s atomic-publish block (`ovpn.go:663-669`, `sess.startKeepalive()` call site) — so reap begins exactly when the data channel goes live, per the existing "alongside the data wrapper" precedent.

**Injectable clock:** reuse `internal/reliable.Clock` interface (`internal/reliable/reliable.go:81-89`) rather than inventing a third timer abstraction (RESEARCH.md's "Don't Hand-Roll" table, row 2):
```go
type Clock interface {
    Now() time.Time
}
type SystemClock struct{}
func (SystemClock) Now() time.Time { return time.Now() }
```
Add a `clock reliable.Clock` field to `Session` (nil → `reliable.SystemClock{}`, same nil-defaulting convention `ctrlconn.New`'s own `clock` parameter already uses, `internal/ctrlconn/conn.go:101`).

---

### `session.go` / `ovpn.go`: server-side reneg-sec timer goroutine

**Analog:** same `startKeepalive`/`runKeepalive` shape, AND `enforceHandshakeWindow` (`ovpn.go:751-761`) for the "single `time.After`-style deadline, fires `Close`/action on expiry" precedent:
```go
func (s *Server) enforceHandshakeWindow(sess *Session) {
    select {
    case <-sess.doneCh:
        return
    case <-time.After(s.handshakeWindow):
        _ = sess.Close()
    }
}
```
**Pattern to apply:** a per-session ticking goroutine (ticker-based like keepalive/reap, NOT a one-shot `time.After` like `enforceHandshakeWindow`, since reneg must re-arm after each successful rollover) that compares `s.clock.Now().Sub(sess.primary.established)` against `s.cfg.RenegSec` (0 → 3600s default) and, on expiry, invokes the `runRenegotiation` driver above — mirroring `key_state_soft_reset`'s trigger condition (RESEARCH Pattern 2) but from the timer side rather than the receive side. Must start independent of any inbound client traffic (Pitfall 2) — start it alongside `startKeepalive`/`startReap` at the same `performPushExchange` publish point.

---

## Shared Patterns

### Injectable clock (timer testing)
**Source:** `internal/reliable.Clock` interface (`internal/reliable/reliable.go:79-89`), already used by `internal/ctrlconn.New`'s `clock` parameter (`internal/ctrlconn/conn.go:101`)
**Apply to:** reap timer, server-side reneg-sec timer, lame-duck `mustDie` expiry check — all three new timer/deadline mechanisms in this phase, so fast-tier unit tests can drive them in milliseconds (RESEARCH.md's Validation Architecture: "clock-injected" is named explicitly for all three).

### Ticker + stopCh select goroutine shape
**Source:** `startKeepalive`/`runKeepalive` (`session.go:386-421`)
**Apply to:** `startReap`/`runReap` and the new server-side reneg-sec timer goroutine — both should split into a `start*` (real ticker) + `run*` (injectable channel parameter) pair, exactly like keepalive, so tests can inject a tick channel instead of waiting on real time.

### mu-then-srv.mu nested-lock atomic publish
**Source:** `performPushExchange`'s WR-05 atomic-publish block (`ovpn.go:648-661`) and `Close`'s mirrored cleanup (`session.go:486-507`)
**Apply to:** the renegotiation driver's primary→lameDuck slot swap — any code that publishes new session-visible state (here: the new `primary` wrapper/conn and the demoted `lameDuck`) while `Close` can race it must use this exact same lock-nesting discipline, not a novel one.

### Non-blocking select+default drop for inbound queues
**Source:** `handleDatagram`'s `sess.inbound <-` select (`ovpn.go:436-446`) and `handleDataPacket`'s `s.ipInbound <-` select (`session.go:376-383`)
**Apply to:** no new queue is introduced by this phase, but the soft-reset-routing branch in `handleDatagram` must preserve this exact "queue full → silent drop, rely on retransmission" policy rather than blocking, when routing a reneg-triggering control packet.

### `[VERIFIED: file:line]` citation discipline
**Source:** RESEARCH.md itself, and this project's own commenting convention (e.g. `ovpn.go`'s "D-11", "WR-05", "Pitfall N" inline references)
**Apply to:** every new function implementing a protocol rule from `ssl.c`/`occ.c`/`sig.c`/`forward.c` should carry a `// Source: <file>:<lines>` comment matching the style already used throughout `ovpn.go`/`session.go` (e.g. `session.go:751` `enforceHandshakeWindow`'s doc comment referencing "the reference's --hand-window default").

## No Analog Found

None — every new mechanism in this phase has a directly-analogous existing sibling in the same file (this phase is purely additive/extending, per RESEARCH.md's "Recommended Project Structure": no new packages or files).

## Metadata

**Analog search scope:** `ovpn.go`, `session.go`, `internal/datachan/datachan.go`, `internal/ctrlconn/conn.go`, `internal/reliable/reliable.go`, `internal/wire/wire.go`, `test/interop/pki/client.conf`
**Files scanned:** 7 (all read directly this session, no re-reads of overlapping ranges)
**Pattern extraction date:** 2026-08-28
